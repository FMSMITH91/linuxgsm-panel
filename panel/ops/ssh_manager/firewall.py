"""Remote firewall management (UFW) and static host specs.

Part of the SSH connection manager for remote LinuxGSM servers, which also supports local
execution for running on the panel's own machine (see the package docstring for how names
resolve across its submodules).
"""
import ipaddress
import json as _json
import re
from panel.ops.ssh_manager import (_core, hosts)  # noqa: E402,F401  (module objects: the
# reference resolves at CALL time, which is what keeps a stub on the definition site
# visible to every caller — see the package docstring.



# ─── Remote Firewall Management (UFW) ─────────────────────────


def _parse_ufw_rule(detail):
    """Parse one `ufw status numbered` rule line into structured fields.

    Structured so the UI can show clean columns instead of the raw string. Handles the optional
    `on <iface>` clause, the `# comment` suffix, and the `(v6)` family markers.
    """
    v6 = "(v6)" in detail
    s = detail.replace("(v6)", " ")
    comment = ""
    if "#" in s:
        s, comment = s.split("#", 1)
        comment = comment.strip()
    iface = ""
    m = re.search(r"\bon\s+(\S+)", s)
    if m:
        iface = m.group(1)
        s = s[:m.start()] + s[m.end():]
    toks = s.split()
    action = direction = ""
    ai = None
    for a in ("ALLOW", "DENY", "REJECT", "LIMIT"):
        if a in toks:
            action = a
            ai = toks.index(a)
            break
    if ai is not None:
        to = " ".join(toks[:ai])
        rest = toks[ai + 1:]
        if rest and rest[0] in ("IN", "OUT", "FWD"):
            direction = rest[0]
            rest = rest[1:]
        frm = " ".join(rest)
    else:
        to = " ".join(toks)
        frm = ""
    return {
        "v6": v6, "to": to.strip(), "action": action, "direction": direction,
        "from": frm.strip(), "iface": iface, "comment": comment,
    }


# ufw ships these as fixed app-profile names (`ufw app list`); they are what `ufw allow OpenSSH`
# puts in the To column. Lowercased for comparison.
_SSH_APP_PROFILES = frozenset({"openssh", "ssh"})


def _ufw_port_label(p):
    """The To column as the UI shows it: "All ports" for a bare interface rule."""
    to = p["to"]
    if p["iface"] and to.lower() in ("anywhere", ""):
        return "All ports"
    return to or "—"


def _split_ufw_proto(port_label):
    """Split the protocol out of a port label, returning (port_num, proto_label).

    So the UI can show it in its own column (e.g. "5000/tcp" -> port "5000", protocol "TCP"). A
    bare numeric port with no suffix means UFW allowed both TCP and UDP.
    """
    m_proto = re.match(r"^(.*)/(tcp|udp)$", port_label, re.IGNORECASE)
    if m_proto:
        return m_proto.group(1), m_proto.group(2).upper()
    if re.search(r"\d", port_label):
        return port_label, "BOTH"
    return port_label, "—"


def _ufw_scope(p):
    """Where a rule applies: its interface (tagged when Tailscale) or its source address."""
    iface = p["iface"]
    if iface:
        return iface + (" (Tailscale)" if iface.startswith("tailscale") else "")
    return "Any address" if p["from"].lower() == "anywhere" else (p["from"] or "—")


def _new_ufw_group(p, key):
    """Build the empty display group for one parsed rule, with its friendly derived fields."""
    iface = p["iface"]
    port_label = _ufw_port_label(p)
    port_num, proto_label = _split_ufw_proto(port_label)
    # A "deny/reject from <specific IP>" rule is an IP block (its own UI section), as opposed
    # to an open-port / access rule. Interface rules and "deny to a port" (no from-IP) aren't.
    from_ip = "" if p["from"].lower() == "anywhere" else (p["from"] or "")
    is_block = ((p["action"] or "").upper() in ("DENY", "REJECT")
                and bool(from_ip) and not iface)
    return {
        "nums": [], "families": [], "port_label": port_label,
        "port_num": port_num, "proto_label": proto_label,
        "comment": p["comment"], "scope": _ufw_scope(p), "iface": iface,
        "action": p["action"] or "ALLOW", "direction": p["direction"] or "IN",
        "is_iface": bool(iface), "is_block": is_block,
        "block_ip": from_ip if is_block else "",
        # WHICH rule this is, independent of where it sits. `nums` are positions and ufw
        # renumbers on every insert/delete (the hourly auto-block inserts at 1), so the
        # page re-finds a group by this before deleting rather than trusting a number
        # read when the table was drawn.
        "key": _json.dumps(list(key)),
        # The From column as ufw printed it. `scope` drops it for an interface rule, and a
        # source-only rule carries its protocol HERE (`ufw allow from <ip> proto udp` prints To
        # "Anywhere", From "<ip>/udp"), so the way-in tests below read it from this.
        "src": p["from"],
    }


def _group_ufw_rules(rules):
    """Collapse the raw numbered rules into user-friendly groups.

    Merges the separate IPv4 and IPv6 entries UFW keeps for the same rule into a single row (with
    the list of underlying rule numbers so a group can be deleted as a unit).
    """
    groups = []
    index = {}
    for r in rules:
        p = _parse_ufw_rule(r["detail"])
        key = (p["to"], p["action"], p["direction"], p["from"], p["iface"], p["comment"])
        g = index.get(key)
        if not g:
            g = _new_ufw_group(p, key)
            index[key] = g
            groups.append(g)
        g["nums"].append(int(r["num"]))
        fam = "IPv6" if p["v6"] else "IPv4"
        if fam not in g["families"]:
            g["families"].append(fam)
    # Stable, readable family label.
    for g in groups:
        fams = g["families"]
        g["family_label"] = " + ".join(sorted(fams)) if len(fams) > 1 else (fams[0] if fams else "")
        g["nums"].sort()
    return groups


def _ssh_ports(server):
    """Ports whose firewall rule keeps SSH reachable.

    Always includes 22 (the default) and the port the panel actually connects on — which covers a
    CUSTOM SSH port, since that's exactly what's stored on the remote.
    """
    ports = {22}
    try:
        if getattr(server, "port", None):
            ports.add(int(server.port))
    except (TypeError, ValueError):
        _core._log.debug("a non-numeric stored port just means there's no extra SSH port to track", exc_info=True)
    return ports


def _fwssh_served_ports(server):
    """The ports an SSH rule must name to be a WORKING way in: the ones sshd listens on.

    _ssh_ports always says 22, which is right for what it is also used for (ports no game may
    take) and wrong here. On a host whose sshd was moved to 2222 by hand, the stock `22/tcp ALLOW`
    (or `OpenSSH ALLOW`) left in UFW counted as a second way in, so the 2222 rule — the only one
    sshd answers on — came back warn ("another way in exists") instead of protected, and
    remote_ufw_delete_rule, which gates only on protected, deleted it. sshd's effective config
    (`sshd -T`) says what it serves; the port the panel connects on is kept beside it, because
    that connection is the proof it is served. A config that cannot be read keeps the old answer:
    a failed read must never leave a rule LESS protected than it was.
    """
    try:
        live = {int(p) for p in hosts._sshd_current_ports(server)}
    except Exception:
        _core._log.debug("firewall protection: sshd's ports could not be read", exc_info=True)
        live = set()
    if not live:
        return _ssh_ports(server)
    try:
        stored = {int(server.port)} if getattr(server, "port", None) else set()
    except (TypeError, ValueError):
        stored = set()
    return live | stored


def _last_parsed_panel_port():
    """The web port the RUNNING panel bound, for when config.json can no longer be parsed.

    Not a guess. load_config() caches the last parse it managed and, when a later read fails,
    drops only the cache KEY — the parsed data stays — so that dict is the file the live listener
    was started from. A config.json that was ALREADY unreadable at boot never populated it, and
    the boot path then read DEFAULT_CONFIG as well, so the default is the reading in that case
    rather than a guess. None when even that cannot be reached.
    """
    try:
        from panel.core import config as _cfg
        return int((_cfg._cfg_cache.get("data") or {}).get("port", _cfg.DEFAULT_CONFIG["port"]))
    except Exception:
        _core._log.debug("could not recover the last parsed panel web port", exc_info=True)
        return None


def _panel_web_port(server, ts_running=None):
    """The panel's public web port when it is the only way into the UI, else None.

    If `server` is the panel's OWN host and the panel UI isn't reachable over Tailscale right now,
    the public web port is the only way in — return it so its rule can be protected. Returns None
    for a remote, or once Tailscale Serve is actually serving the panel.

    Note: a `tailscale0` UFW rule (Tailscale SSH being reachable) is NOT enough to unprotect
    it — that's only a recovery path, not panel-UI access. The panel UI is only reachable over
    the tailnet once Serve is configured (tailscale_setup_done) AND the tailnet is actually up,
    so gate on both.

    `ts_running` is the caller's LIVE tailnet reading. It defaults to None — "nobody established
    that" — which keeps the port protected, because not knowing is not a route.
    """
    if not _core.is_local_server(server):
        return None
    # A config.json that is THERE and unparseable degrades to DEFAULT_CONFIG and says nothing —
    # the same trap _panel_served_over_tailscale below was written to close. `port` then answered
    # 5000 about a panel listening on 8443: the live 8443 rule came back is_panel=False,
    # protected=False AND warn=False (a plain delete × on the only route to the UI), while a
    # phantom protection was computed for a port with no rule behind it. Answer from what this
    # process actually parsed, and skip tailscale_setup_done entirely — it reads False out of
    # those same defaults, which would un-protect the rule a second time in one function.
    if _config_unreadable():
        return _last_parsed_panel_port()
    try:
        from panel.core.config import load_config
        cfg = load_config()
    except Exception:
        return None
    # `tailscale_setup_done` records that Serve was configured ONCE; it is not a statement about
    # the tailnet being up now. tailscaled can be stopped or logged out and node keys expire by
    # default, and nothing writes the flag back — only the panel's own disable button clears it.
    # So a stale True un-protected the panel host's only remaining way in, and left warn False
    # too: the UI drew an ordinary red × with no confirmation text. The live reading is the same
    # one the tailscale0 rule already insists on twenty lines below ("a lingering rule with
    # Tailscale down is no route at all"); this is that check on the other half of the pair.
    if cfg.get("tailscale_setup_done") and ts_running:
        return None  # served via Tailscale, and the tailnet is actually up
    try:
        return int(cfg.get("port", 5000))
    except (TypeError, ValueError):
        # Not a fallback port: a non-numeric `port` never reached socketio.run(), so there is no
        # listening panel for this to be about. Answer with the same default the boot path would
        # have read rather than a literal that can drift away from it.
        from panel.core.config import DEFAULT_CONFIG
        return DEFAULT_CONFIG["port"]


def _config_unreadable():
    """True when config.json EXISTS but cannot be parsed into an object.

    Deliberately not "load_config returned defaults": a host with no config.json yet is a normal,
    answerable state and defaults really are the answer. The dangerous case is narrower — a file
    that is there and unusable, where every setting silently reads as its default.

    The shared predicate, not a copy of it. This kept its own, which had already drifted: it read
    the file as UTF-8 while load_config reads it in the locale's encoding, so on a non-UTF-8
    locale the two could disagree about the very file whose defaults this guards against. Kept
    as a name because it is the stub seam the unit suite patches.
    """
    from panel.core.config import config_unreadable
    return config_unreadable()


def _panel_served_over_tailscale(server):
    """True when THIS host is the panel AND its web UI is published over Tailscale Serve.

    Read from tailscale_setup_done. In that case the *inbound* tailscale0 UFW rule is exactly what
    keeps the panel reachable over the tailnet — with UFW default-deny, deleting it drops
    inbound tailnet traffic to Serve and locks you out of the panel. It's the mirror image
    of _panel_web_port: once Serve is the way in, the public port is free to close BUT the
    tailscale0 rule becomes load-bearing and must be protected.
    """
    if not _core.is_local_server(server):
        return False
    # load_config() degrades a CORRUPT config.json to DEFAULT_CONFIG and says nothing — by design,
    # so one bad edit does not take every request down. But reading tailscale_setup_done out of
    # those defaults answers False, which un-protects the tailscale0 rule: the thing keeping the
    # panel reachable once Serve is the way in. A guard against locking yourself out must not be
    # switched off by a file it could not read.
    if _config_unreadable():
        return True
    try:
        from panel.core.config import load_config
        return bool(load_config().get("tailscale_setup_done"))
    except Exception:
        _core._log.warning("could not read the panel config; protecting the tailnet rule",
                           exc_info=True)
        return True


def _is_ssh_rule(g, pn, inbound, ts_iface, ssh_ports):
    """True when group `g` is an inbound ALLOW/LIMIT rule that keeps SSH reachable.

    An SSH rule the panel can recognise is one of three shapes, and it used to see only the
    first:
      22/tcp                     — a bare port number
      OpenSSH                    — ufw's APP PROFILE, which is the form Ubuntu's own docs and
                                   `ufw app list` steer people to. It prints the profile name
                                   in the To column, so pn.isdecimal() was False.
      22 on eth0                 — interface-scoped, which `not is_iface` threw away
    Both missed shapes came back is_ssh=False AND is_access=False, so protected and warn were
    both False and remote_ufw_delete_rule — which gates only on protected — deleted the
    host's only way in without a word. Reproduced against this module's own parser.
    A tailscale-scoped rule stays out of is_ssh so the two categories remain disjoint;
    is_tailscale already covers it and the messages below differ.
    """
    # Both profiles are port 22, so they are a way in only where sshd serves 22.
    words = pn.split()
    _named_ssh = bool(words) and words[-1].lower() in _SSH_APP_PROFILES and 22 in ssh_ports
    # sshd is TCP only: a UDP rule naming its port (`1:1024/udp`, `22/udp`) is no way in, and
    # counted as one it marked the host's only real `22/tcp` rule "another way in exists".
    # Nor is a rule that admits only this machine itself (_r14a_host_only): `ufw allow in on lo`
    # and a docker0 rule are on most hosts, and once an all-ports rule counted, either one made
    # the host's only public `22/tcp` deletable.
    return (g.get("action") in ("ALLOW", "LIMIT") and inbound and not ts_iface
            and not _r14a_udp_only(g) and not _r14a_host_only(g)
            and (_r12a_names_port(pn, ssh_ports) or _named_ssh or _r13a_every_port(g, pn)))


def _r14a_udp_only(g):
    """Whether rule `g` admits UDP alone, which sshd never reads.

    The protocol is printed beside the To column for a port rule, and beside the From column for a
    source-only one (ufw's get_status: `ufw allow from <ip> proto udp` is To "Anywhere", From
    "<ip>/udp"). Reading only the To column counted that one as every port, sshd's included.
    """
    return g.get("proto_label") == "UDP" or str(g.get("src") or "").lower().endswith("/udp")


# Interfaces that carry only this machine's own traffic or the NAT of its containers and VMs:
# loopback, and the bridges and veth ends Docker, libvirt, LXC/LXD, Podman and CNI create. Nothing
# from another machine arrives on one. A bridge the admin named (br0) is NOT here: on a KVM host it
# is commonly the public uplink itself, and Docker's own user networks are "br-<hex id>".
_R14A_HOST_ONLY_IFACE_RE = re.compile(
    r"(?:lo|docker\d*|docker_gwbridge|br-[0-9a-f]{12}|virbr\d+|veth\w+|lxcbr\d+|lxdbr\d+"
    r"|cni\d+|podman\d+)\Z")


def _r14a_loopback_addr(column):
    """Whether a To / From column's address is loopback (the v4 /8 or ::1), with or without a port."""
    words = str(column or "").split()
    addr = re.sub(r"/(?:tcp|udp)\Z", "", words[0], flags=re.I) if words else ""
    try:
        return ipaddress.ip_network(addr, strict=False).is_loopback
    except ValueError:
        return False


def _r14a_host_only(g):
    """Whether rule `g` admits only this machine itself, so it is no way in from anywhere else.

    On loopback or a local bridge (_R14A_HOST_ONLY_IFACE_RE), from a loopback source, or to a
    loopback destination: a packet from another machine can match none of them. A private source
    range (`ufw allow from <LAN>/24`) is still a way in: it is how a LAN admin keeps SSH.
    """
    return (bool(_R14A_HOST_ONLY_IFACE_RE.match(str(g.get("iface") or "")))
            or _r14a_loopback_addr(g.get("src")) or _r14a_loopback_addr(g.get("port_num")))


def _r13a_every_port(g, pn):
    """Whether a rule's To column names no port at all, so it admits EVERY port, sshd's included.

    `ufw allow from <admin ip>` (To "Anywhere"), `ufw allow in on eth0` ("All ports") and
    `ufw allow to <address>` (an address alone) are the common ways to keep SSH to one admin
    address or interface; none named a port, so the host's only way in got an ordinary delete ×.
    """
    if g.get("port_label") == "All ports":
        return True
    words = str(pn).split()
    last = words[-1] if words else ""
    if last.lower() == "anywhere":
        return True
    try:
        ipaddress.ip_network(last, strict=False)
    except ValueError:
        return False
    return True


def _r12a_names_port(pn, ports):
    """Whether a rule's To column names one of `ports`: alone, in a list or a range, after an address.

    `pn.isdecimal()` saw only a bare port, so `ufw allow 22,80,443/tcp` (To "22,80,443"), a range
    (`20:30/tcp`) and a destination-scoped rule (`ufw allow to 203.0.113.5 port 22`, To
    "203.0.113.5 22") were not SSH rules at all: no protection, no warning, and an ordinary delete
    took the host's only way in. hosts._rule_names_port_in's parse: the last word, split on ",".
    """
    words = str(pn).split()
    for item in (words[-1] if words else "").split(","):
        m = hosts._UFW_PORT_ITEM_RE.match(item)
        if m and any(int(m.group(1)) <= p <= int(m.group(2) or m.group(1)) for p in ports):
            return True
    return False


def _r14a_public_allow_in(rule):
    """Whether `rule` is an inbound ALLOW/LIMIT on no interface (a display group or a parsed row)."""
    return (not (rule.get("iface") or rule.get("is_iface"))
            and rule.get("action", "ALLOW") in ("ALLOW", "LIMIT")
            and (rule.get("direction") or "IN") == "IN")


def _r14a_panel_port_scope(rule, port):
    """How rule `rule` holds `port` open to the public: "only", "shared" or "" (it does not).

    `rule` is a display group, or a parsed row with its `port_num` added: inbound ALLOW/LIMIT on no
    interface, whose To column names `port` (_r12a_names_port: alone, after an address, in a list or
    a range). "only" when that port is all it opens; "shared" when the list or range opens others too
    (`80,443,5000/tcp`, `5000:5010/tcp`). The Network card (hosts.remote_public_ssh_status) and
    Close public panel port (remote_vps) both read it, so the card never calls open a port the close
    route calls already closed. The From column is not read: a rule from one address still leaves
    the port listening to it.
    """
    pn = str(rule.get("port_num", ""))
    if not _r14a_public_allow_in(rule) or not _r12a_names_port(pn, {int(port)}):
        return ""
    words = pn.split()
    items = (words[-1] if words else "").split(",")
    m = hosts._UFW_PORT_ITEM_RE.match(items[0]) if len(items) == 1 else None
    return "only" if m and int(m.group(1)) == int(m.group(2) or m.group(1)) else "shared"


def _classify_access_rule(g, ssh_ports):
    """Set is_ssh / is_tailscale / is_access on one group: is it a way into the host."""
    pn = str(g.get("port_num", ""))
    # Only an INCOMING rule is a "way in". An `allow out on tailscale0` rule (or any
    # OUT rule) must not count. A rate-limited SSH rule (`ufw limit`, action LIMIT) is
    # just as much a way in as an ALLOW — miss it and the panel would let you delete
    # your only SSH access.
    # IN only: a ROUTE rule (`ufw route allow 22/tcp`, printed ALLOW FWD) forwards to another
    # machine and admits nothing to this host's sshd, yet `!= "OUT"` counted it, so the host's
    # one real SSH rule read "another way in exists" and could be deleted.
    inbound = (g.get("direction") or "IN") == "IN"
    _iface = str(g.get("iface", "") or "")
    _ts_iface = _iface.startswith("tailscale")
    g["is_ssh"] = _is_ssh_rule(g, pn, inbound, _ts_iface, ssh_ports)
    # LIMIT here too, for the reason spelled out above: a rate-limited rule is a way in. And only
    # a rule that lets sshd in: the whole interface, or an SSH port on it. `5000/tcp on tailscale0`
    # (a service kept to the tailnet) carries no SSH, so it is not a way into the host.
    g["is_tailscale"] = (bool(g.get("is_iface")) and g.get("action") in ("ALLOW", "LIMIT")
                         and inbound and _ts_iface and _r11a_reaches_ssh(g, pn, ssh_ports))
    g["is_access"] = g["is_ssh"] or g["is_tailscale"]


def _r14a_admits(g, port):
    """Whether rule `g` matches TCP traffic to `port` (named alone, in a list or range, or every port)."""
    pn = str(g.get("port_num", ""))
    words = pn.split()
    named = bool(words) and words[-1].lower() in _SSH_APP_PROFILES and port == 22
    return not _r14a_udp_only(g) and (named or _r12a_names_port(pn, {port}) or _r13a_every_port(g, pn))


def _r14a_net(word):
    """The network a To / From address word names (its /tcp or /udp suffix dropped), else None."""
    try:
        return ipaddress.ip_network(re.sub(r"/(?:tcp|udp)\Z", "", word, flags=re.I), strict=False)
    except ValueError:
        return None


def _r14a_src_covers(deny_src, allow_src):
    """Whether every source a rule's From column `allow_src` admits is inside `deny_src`'s.

    "Anywhere" covers all. A network covers an address or network inside it, of the same family.
    A From with a source PORT matches only that port, so it covers only the very same column. An
    auto-block DENY from one attacker covers nothing an ALLOW from Anywhere admits.
    """
    d, a = str(deny_src or "Anywhere").split(), str(allow_src or "Anywhere").split()
    if len(d) > 1 or len(a) > 1:
        return d == a
    dn, an = _r14a_src_net(d), _r14a_src_net(a)
    if dn == "any":
        return True
    nets = (ipaddress.IPv4Network, ipaddress.IPv6Network)
    return (isinstance(dn, nets) and isinstance(an, nets) and an.version == dn.version
            and an.subnet_of(dn))


def _r14a_src_net(words):
    """A one-word From column as "any" (Anywhere), its network, or None when it is neither."""
    word = re.sub(r"/(?:tcp|udp)\Z", "", words[0], flags=re.I) if words else "Anywhere"
    return "any" if word.lower() == "anywhere" else _r14a_net(word)


def _r14a_dest_addr(g):
    """The destination address a rule's To column names ("<addr> 22" -> <addr>), else ""."""
    words = str(g.get("port_num", "")).split()
    return words[0] if words and _r14a_net(words[0]) is not None else ""


def _r14a_deny_covers(deny, allow, port):
    """Whether DENY/REJECT group `deny` blocks every packet ALLOW group `allow` admits on `port`."""
    return ((deny.get("direction") or "IN") == "IN"
            and (not deny.get("iface") or deny.get("iface") == allow.get("iface"))
            and _r14a_admits(deny, port)
            and _r14a_dest_addr(deny) in ("", _r14a_dest_addr(allow))
            and _r14a_src_covers(deny.get("src"), allow.get("src")))


def _r14a_mark_live_ssh(groups, ssh_ports):
    """Set ssh_live on each group: an SSH rule UFW actually lets act, read in UFW's order.

    UFW takes the first rule a packet matches (a group's place is its lowest number). An SSH ALLOW
    is live when, for at least one sshd port it admits, no DENY/REJECT above it blocks every packet
    it would let in. `22/tcp DENY IN Anywhere` above `22/tcp ALLOW IN Anywhere` leaves no way in, yet
    counted as one beside another rule it made that rule deletable. A DENY from one address (the
    hourly auto-block inserts those at 1) shadows nothing an ALLOW from Anywhere admits.
    """
    order = sorted((g for g in groups if g.get("nums")), key=lambda g: min(g["nums"]))
    for g in groups:
        g["ssh_live"] = bool(g.get("is_ssh"))   # a group with no number has no place to read
    for i, g in enumerate(order):
        if g.get("is_ssh"):
            g["ssh_live"] = _r14a_live(g, [d for d in order[:i] if d.get("action") in ("DENY", "REJECT")],
                                       ssh_ports)


def _r14a_live(g, denies, ssh_ports):
    """Whether SSH ALLOW `g` admits some sshd port that none of `denies` (the rules above it) blocks."""
    return any(_r14a_admits(g, p) and not any(_r14a_deny_covers(d, g, p) for d in denies)
               for p in ssh_ports)


def _r11a_reaches_ssh(g, pn, ssh_ports):
    """Whether interface rule `g` covers sshd: every port on it, or one of `ssh_ports` over TCP.

    Every port in any spelling (_r13a_every_port), not only the "All ports" label: `ufw allow in on
    tailscale0 proto tcp` prints To "Anywhere/tcp", and `... to <addr>` an address alone, so a
    tailnet-only host's one way in got an ordinary delete × with no warning. UDP alone, in either
    column (_r14a_udp_only), never reaches sshd.
    """
    return not _r14a_udp_only(g) and (_r12a_names_port(pn, ssh_ports) or _r13a_every_port(g, pn))


def _r11a_tailnet_ssh_iface(g, ssh_ports):
    """The tailscale interface of `g` when it is an inbound rule covering sshd there, else ""."""
    iface = str(g.get("iface") or "")
    if (not iface.startswith("tailscale") or (g.get("direction") or "IN") != "IN"
            or not _r11a_reaches_ssh(g, str(g.get("port_num", "")), ssh_ports)):
        return ""
    return iface


def _r11a_tailnet_ssh_open(groups, ssh_ports):
    """Whether UFW lets sshd in over a Tailscale interface, read the way UFW reads its rules.

    UFW takes the FIRST rule that matches, in rule order (a group's place is its lowest number).
    So per tailscale interface the first inbound rule covering sshd decides: an ALLOW/LIMIT lets it
    in, a DENY/REJECT keeps it out — `Anywhere on tailscale0 DENY IN` above the allow wins. This
    was any() over is_tailscale, which counted any allow on the interface wherever it sat, and so
    downgraded the host's only public SSH rule to deletable. hosts._tailnet_ssh_state asks the
    same question through system_ops.ufw_allows_iface_in; this one also accepts an SSH-port rule
    on the interface, which that one (deciding the "tailnet-only" lockdown) need not.
    """
    decided = {}
    for g in sorted((g for g in groups if g.get("nums")), key=lambda g: min(g["nums"])):
        iface = _r11a_tailnet_ssh_iface(g, ssh_ports)
        if not iface or iface in decided:
            continue
        if g.get("action") in ("DENY", "REJECT"):
            decided[iface] = False
        elif g.get("action") in ("ALLOW", "LIMIT"):
            decided[iface] = True
    return any(decided.values())


def _is_panel_rule(g, panel_port):
    """True when group `g` is the inbound ALLOW/LIMIT rule for the panel's own web port.

    ALLOW *or LIMIT*, and inbound — the same two corrections is_ssh already carries.
    `ufw limit 5000/tcp` on the panel's own web port is an ordinary thing to do and left the
    only route to the panel UI deletable; an `ALLOW OUT` rule on that port was conversely
    treated AS the panel rule and made undeletable.
    """
    # IN only: a forwarded (FWD) rule for the port is not the panel's way in. And the port in any
    # spelling (_r14a_panel_port_scope, the test the Network card and Close public panel port
    # read): this took only a bare `5000`, so `80,443,5000/tcp` or a range spanning the port —
    # while it was the only way into the UI — had an ordinary delete × here, and the card and the
    # close route said it held the port open. Deleting such a rule does close the panel's port, so
    # it is protected like the port's own rule; the reason says it opens other ports too.
    return panel_port is not None and bool(_r14a_panel_port_scope(g, panel_port))


def _r14a_ports_word(g):
    """The port part of a rule's To column: `22` of "<addr> 22", `47100:47199`, `22,80`."""
    words = str(g.get("port_num", "")).split()
    return words[-1] if words else ""


# Every protect_reason the Firewall page can show, as a fixed English template. The group carries
# the template (protect_reason_key) and its values (protect_reason_params) beside the English text,
# so the page renders it in the viewer's language: the catalogs translate the template, and the
# values (ports, never words) go in after. protect_reason itself, and every API refusal built from
# it, stays the English sentence it always was. The unit suite holds each one to both catalogs.
_R14A_SSH_TAIL = (" the SSH port used to reach this host, and there's no working Tailscale route to "
                  "fall back on — removing it would lock you out. Enable Tailscale SSH, or connect "
                  "Tailscale and allow the tailscale0 interface, first.")
_R14A_PANEL_TAIL = (" where this panel's own web interface listens, and it isn't reachable over "
                    "Tailscale — removing it would lock you out of the panel. Set up Tailscale first "
                    "if you want to close it.")
R14A_REASONS = {
    "panel_only": "Port {port} is" + _R14A_PANEL_TAIL,
    "panel_shared": "This rule opens ports {ports}, including port {port}," + _R14A_PANEL_TAIL,
    "ssh_every": "This rule lets every port in, including" + _R14A_SSH_TAIL,
    "ssh_profile": "The {ports} profile opens" + _R14A_SSH_TAIL,
    "ssh_ports": "This rule opens ports {ports}, including" + _R14A_SSH_TAIL,
    "ssh_port": "Port {ports} is" + _R14A_SSH_TAIL,
    "ts_serve": ("This Tailscale interface rule keeps the panel reachable over your tailnet "
                 "(Tailscale Serve). With the firewall's default-deny, removing it would drop "
                 "inbound tailnet traffic and lock you out of the panel — so it can't be "
                 "deleted here."),
    "ts_last": ("This is the Tailscale interface rule and currently the only way in — removing it "
                "would lock you out. Open your SSH port (or enable Tailscale SSH) first."),
    "warn": ("This keeps you connected (SSH or Tailscale). Another way in exists so it can be "
             "removed, but make sure you won't lock yourself out."),
}


def _r14a_set_reason(g, which, **params):
    """Set protect_reason (English), and the template + values the page translates it from."""
    template = R14A_REASONS[which]
    g["protect_reason_params"] = {k: str(v) for k, v in params.items()}
    g["protect_reason_key"] = template
    g["protect_reason"] = template.format_map(g["protect_reason_params"])


def r14a_reason_text(g, translate=None):
    """`g`'s protect_reason in the viewer's language.

    `translate` (the template's `t`) is applied to its template, then its values go in. The English
    text when there is no template, or when a translation's placeholders do not match its values.
    """
    key = g.get("protect_reason_key")
    if not key or translate is None:
        return g.get("protect_reason", "")
    try:
        return str(translate(key)).format_map(dict(g.get("protect_reason_params") or {}))
    except (KeyError, IndexError, ValueError):
        return g.get("protect_reason", "")


def _r14a_ssh_reason(g):
    """Which SSH lock-out reason names what `g` opens: the port, a range or list, a profile, all.

    "Port 47100:47199 is the SSH port" called a range the SSH port; "Port <addr> 22 is" read the
    address as part of the port.
    """
    if _r13a_every_port(g, g.get("port_num", "")):
        return "ssh_every"
    ports = _r14a_ports_word(g)
    if ports.lower() in _SSH_APP_PROFILES:
        return "ssh_profile"
    return "ssh_ports" if ("," in ports or ":" in ports) else "ssh_port"


def _r14a_protect_panel(g, panel_port):
    """Protect the rule holding the panel's public port open: with no Tailscale route, the only way in.

    A list or range that holds it open says it opens other ports too.
    """
    g["protected"] = True
    _r14a_set_reason(g, "panel_only" if _r14a_panel_port_scope(g, panel_port) == "only"
                     else "panel_shared", port=panel_port, ports=_r14a_ports_word(g))


def _protect_rule(g, panel_port, served_over_ts, ssh_count, ts_ssh_ok, ts_iface_ok):
    """Set protected / warn / protect_reason on one group of an ENABLED firewall."""
    if g["is_panel"]:
        _r14a_protect_panel(g, panel_port)
        return
    if not g["is_access"]:
        return
    if g["is_ssh"]:
        # Deleting this SSH rule is safe only if another way in remains: another SSH rule,
        # Tailscale SSH, or regular SSH over a running tailnet (Tailscale isn't affected).
        # `ssh_count` counts only the SSH rules UFW lets act (_r14a_mark_live_ssh); this one is
        # "another" way only to the others. A rule a DENY above it shadows is no way in itself, and
        # it stays protected while nothing else is (in doubt, protect).
        other_way = (ssh_count - int(bool(g.get("ssh_live"))) > 0) or ts_ssh_ok or ts_iface_ok
        reason_last = _r14a_ssh_reason(g)
    else:  # is_tailscale — deleting it drops regular SSH over the tailnet; Tailscale SSH is unaffected
        if served_over_ts:
            # This is the panel host and its UI is published over Tailscale Serve, so this
            # inbound tailscale0 rule is what keeps the PANEL reachable over the tailnet —
            # not just SSH. With UFW default-deny, removing it drops inbound tailnet traffic
            # to Serve and locks you out of the panel, and an available SSH path doesn't save
            # the UI. Protect it outright (blocks the UI's × and any direct delete API call).
            g["protected"] = True
            _r14a_set_reason(g, "ts_serve")
            return
        other_way = (ssh_count > 0) or ts_ssh_ok
        reason_last = "ts_last"
    g["protected" if not other_way else "warn"] = True
    _r14a_set_reason(g, reason_last if not other_way else "warn", ports=_r14a_ports_word(g))


def _live_tailscale_state(server, enabled, groups):
    """(ts_running, ts_ssh_enabled) from the live tailnet, probed only when it can matter.

    A Tailscale rule only counts as a real fallback when Tailscale is ACTUALLY running —
    a lingering `allow tailscale0` UFW rule with Tailscale down/uninstalled is no route at
    all. Query the live state once (only when it could change a decision).

    Hoisted ABOVE _panel_web_port because it decides that too. The panel port was unprotected
    by `tailscale_setup_done` alone — a flag saying Serve was configured at some point — so a
    stopped tailscaled or an expired node key left the panel's only remaining door with an
    ordinary delete ×. On the panel's own host the probe therefore runs even when no access
    rule is in the table, because there the web-port rule is the one at risk.
    """
    ts_running = ts_ssh_enabled = False
    if enabled and (any(g.get("is_access") for g in groups) or _core.is_local_server(server)):
        ts_running, ts_ssh_enabled = hosts._tailscale_conn_state(server)
    return ts_running, ts_ssh_enabled


def _r13a_tailnet_ssh_ok(server, groups, ssh_ports):
    """Whether regular SSH reaches this (tailnet-running) host over the tailnet.

    An interface rule UFW lets through, first match wins -- AND what hosts._tailnet_ssh_state asks
    of the same question: a Tailscale TUN interface to carry it (userspace networking has none) and
    sshd listening where tailnet traffic arrives (after the panel's own bind-address change it is
    the public address alone). Without them the host's only public SSH rule read "another way in
    exists" while Disable public SSH refused the same lockout. The host is probed only when the
    rule list already says yes.
    """
    return (_r11a_tailnet_ssh_open(groups, ssh_ports) and bool(hosts._tsiface_names(server))
            and not hosts._r11a_sshd_off_tailnet(server))


def _annotate_firewall_protection(server, enabled, groups):
    """Flag rules whose removal could LOCK YOU OUT.

    So the UI and API can refuse to delete the last way in. Access rules: the SSH-port ALLOW and
    the Tailscale-interface ALLOW — a rule is *blocked* only when it's the sole remaining one (no
    SSH and no Tailscale would be left); otherwise it's flagged to warn on. On the
    panel's OWN host, the panel's web port is also protected when Tailscale isn't an
    alternate route (otherwise you'd delete your only way into the panel UI). If UFW
    is disabled it isn't enforcing anything, so nothing is protected.
    """
    # Disabled, nothing is protected below, so sshd is not asked.
    ssh_ports = _fwssh_served_ports(server) if enabled else _ssh_ports(server)
    for g in groups:
        _classify_access_rule(g, ssh_ports)

    # An SSH rule counts only where UFW lets it act: a DENY/REJECT above it for the same traffic
    # wins (first match), as the tailnet side already reads it (_r11a_tailnet_ssh_open).
    _r14a_mark_live_ssh(groups, ssh_ports)
    ssh_count = sum(1 for g in groups if g.get("ssh_live"))

    ts_running, ts_ssh_enabled = _live_tailscale_state(server, enabled, groups)

    panel_port = _panel_web_port(server, ts_running=ts_running)
    served_over_ts = _panel_served_over_tailscale(server)
    ts_ssh_ok = ts_running and ts_ssh_enabled    # Tailscale SSH → a way in regardless of UFW
    ts_iface_ok = ts_running and _r13a_tailnet_ssh_ok(server, groups, ssh_ports)

    for g in groups:
        g["protected"] = False
        g["warn"] = False
        g["protect_reason"] = ""
        g["protect_reason_key"] = ""
        g["protect_reason_params"] = {}
        g["is_panel"] = _is_panel_rule(g, panel_port)
        if not enabled:
            continue
        _protect_rule(g, panel_port, served_over_ts, ssh_count, ts_ssh_ok, ts_iface_ok)
    return groups


def _ufw_is_active(status_out):
    """True when `ufw status` reports an active firewall.

    Was `ufw status | grep -q active && echo ACTIVE || echo INACTIVE`, read back with
    `"INACTIVE" not in out` — which needed a comment explaining that ACTIVE is a substring of
    INACTIVE. Reading the Status: line directly needs no such warning.

    ...in English. The line is translated (`Status: actief`), so the reading is shared with the
    panel host's own ufw code and falls back to the untranslated rules listing — see
    system_ops.ufw_status_active.
    """
    from panel.ops import system_ops as _so
    return _so.ufw_status_active(status_out)


# Lines that mean "this was refused for want of privilege", not "the host is down". Anchored to
# the line START and to the program's own prefix (`sudo:`, ufw's `ERROR:`, the helper's) on
# purpose: a bare substring over `out` would also be matching rule comments, which operators type
# on this page — the exact defect the "not installed" test below was fixed for. The prefix is what
# makes it unforgeable from there: the comment validator is `[A-Za-z0-9 _.-]{0,60}`, which has no
# colon, so no rule comment can begin a line with `sudo:` or `ERROR:`.
_SUDO_REFUSED_RE = re.compile(
    r"(?mi)^\s*(?:"
    r"sudo:\s*(?:a password is required"
    r"|a terminal is required to read the password"
    r"|no tty present"
    r"|sorry, you must have a tty"
    r"|\d+ incorrect password attempts?"
    r"|\S+ is not in the sudoers file"
    # sudo-rs, which is /usr/bin/sudo on Ubuntu 26.04, words every one of these differently.
    r"|interactive authentication is required"
    r"|a terminal is required to authenticate"
    r"|maximum \d+ incorrect authentication attempts?"
    r"|I'm sorry \S+\. I'm afraid I can't do that)"
    r"|ERROR:\s*You need to be root to run this script"
    r"|panel-helper:\s*\S+ failed \(PermissionError\)"
    r")")


# One row of `ufw status numbered`: "[ N] <to>  <action>  <from>". The detail starts on a
# non-blank, `(?:\S.*)?` rather than `.*`: a `.*` straight after `\s*` could split the blanks
# between the two every way before failing, which is quadratic. The groups are the ones
# `\s*(.*)$` gave.
_UFW_NUMBERED_RE = re.compile(r"^\s*\[\s*(\d+)\]\s*((?:\S.*)?)$")


def remote_ufw_status(server):
    """Get UFW status and rules from the remote server."""
    # sudo=None keeps a REMOTE's own sudo setting, as it always did — this is the one ufw read that
    # never forced escalation there. On the panel's own host it always escalates, whatever the row
    # says: the helper, or the pre-helper sudo form where there is none (see run_privileged).
    # `|| echo NOTINSTALLED` is gone with the shell; a missing tool is rc 127 from both
    # transports, which is what the check below now leads with.
    out, err, rc = _core.run_privileged(server, "ufw-status", ["numbered"], timeout=15, sudo=None)
    # rc 127 ALONE. The substring tests that stood beside it also read `out` — the whole
    # `ufw status numbered` listing, every rule's `# comment` included — and those comments are
    # typed into this very page's "Open a Port" box, where the validator accepts
    # `[A-Za-z0-9 _.-]{0,60}`: "plex not installed yet" is a legal comment. One of them made the
    # ENTIRE host read as "UFW is not installed" — empty rules table, "No IPs are blocked", every
    # delete refused with "there's no rule N to delete" — until someone removed that rule by hand
    # over SSH. Rule text is operator input, not a protocol signal; rc 127 is the protocol signal,
    # from the shell on the remote/no-helper paths and from the helper's own `resolve()` failure
    # on this one. Same rule _ufw_is_active exists to enforce, one line further down.
    if rc == 127:
        return {"installed": False, "enabled": False, "rules": [], "groups": []}
    # A failed call, or no answer at all, means the host is unreachable / the command errored —
    # don't claim UFW is installed (that would show a misleading empty-rules "installed" firewall
    # for a down remote). NOT a missing English "Status:": ufw translates that whole line, and a
    # French host prints `État : actif`, which read as unreachable here while hosts.py's two copies
    # of this gate were already fixed. Whether it is active, in any locale, is _ufw_is_active's.
    if rc != 0 or not (out or "").strip():
        # ...but "unreachable" is a claim about the NETWORK, and not every failure here is one.
        # This read is `sudo -n <helper> ufw-status` on the panel's own machine; when the sudoers
        # grant is wrong — a documented failure of this install, where a file sorting after the
        # narrow grant re-broadens it to password-required — sudo exits 1 with "a password is
        # required", merge_stderr folds that into `out`, and the single answer sent the operator
        # to debug connectivity to the host they were already connected to, with nothing anywhere
        # naming sudo. `unreachable` keeps the transport meaning it has always had; the privilege
        # refusal is reported as itself.
        res = {"installed": False, "enabled": False, "rules": [], "groups": [], "unreachable": True}
        if _SUDO_REFUSED_RE.search((out or "") + (err or "")):
            res["permission_denied"] = True
        return res

    # _ufw_is_active(), not a substring test — that helper exists in this file precisely so the
    # literal "Status: active" is not re-tested by hand, and a rule COMMENT carrying that text
    # would answer it. (It errs toward more protection, so this is consistency, not a live bug.)
    enabled = _ufw_is_active(out)
    rules = []
    # `ufw status numbered` prints each rule as "[ N] <to>  <action>  <from>".
    # Collapse runs of spaces so the detail reads cleanly.
    for line in out.split("\n"):
        m = _UFW_NUMBERED_RE.match(line)
        if m:
            detail = re.sub(r"\s{2,}", "  ", m.group(2).strip())
            rules.append({"num": m.group(1), "detail": detail})

    groups = _annotate_firewall_protection(server, enabled, _group_ufw_rules(rules))
    return {"installed": True, "enabled": enabled, "rules": rules, "groups": groups}


# Single shell script that prints static host specs as TAB-separated KEY<TAB>VALUE
# lines. POSIX-sh compatible (no sudo needed — everything read here is world-readable),
# with fallbacks so it works on x86 servers and ARM SBCs (Raspberry Pi) alike.
_SPECS_CMD = (
    r'''OS=$(. /etc/os-release 2>/dev/null; printf '%s' "$PRETTY_NAME"); '''
    r'''CPU=$(lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -1); '''
    r'''[ -z "$CPU" ] && CPU=$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1); '''
    r'''[ -z "$CPU" ] && CPU=$(sed -n 's/^Model[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1); '''
    r'''MAXMHZ=$(lscpu 2>/dev/null | sed -n 's/^CPU max MHz:[[:space:]]*//p' | head -1); '''
    r'''MEM=$(awk '/MemTotal/{printf "%.1f", $2/1048576}' /proc/meminfo); '''
    r'''DISK=$(df -hP / 2>/dev/null | awk 'NR==2{print $2}'); '''
    r'''VIRT=$(systemd-detect-virt 2>/dev/null || true); '''
    r'''printf 'OS\t%s\nKERNEL\t%s\nARCH\t%s\nHOST\t%s\nCPU\t%s\nCORES\t%s\nMAXMHZ\t%s\nMEM\t%s\nDISK\t%s\nVIRT\t%s\n' '''
    r'''"$OS" "$(uname -r)" "$(uname -m)" "$(hostname)" "$CPU" "$(nproc)" "$MAXMHZ" "$MEM" "$DISK" "$VIRT"'''
)


# Registered (see _core.register_remote_cache): this one has NO expiry — specs cannot change while
# the machine is up — so without forgetting a deleted host's id, the next host to take that id
# reports the deleted machine's CPU, RAM, disk and OS for the life of the process.
_specs_cache = _core.register_remote_cache({})   # remote id -> result


def host_specs(server, force=False):
    """Static hardware/OS specs for a host (OS, CPU, cores, RAM, disk, kernel, arch, virt).

    Probed ONCE and cached for the panel's whole lifetime — these don't change while the machine
    is up, and a reboot/resize restarts the panel anyway, so there's no periodic re-check.
    force=True re-probes (e.g. after resizing the box without a reboot).
    """
    key = hosts._pro_key(server)
    if not force and key in _specs_cache:
        return _specs_cache[key]
    result = _compute_host_specs(server)
    if not result.get("error"):     # cache only a good read; a transient failure retries next time
        _specs_cache[key] = result
    return result


def _compute_host_specs(server):
    """Probe hardware/OS specs (OS, CPU model, cores, RAM, disk, kernel, arch, virt)."""
    try:
        out, err, _ = _core.run_command(server, _SPECS_CMD, timeout=20, sudo=False)
    except Exception:
        # Never surface raw exception text — it flows to a JSON response (CodeQL
        # py/stack-trace-exposure). Log it server-side; the caller shows a generic message.
        _core._log.warning("host specs probe failed", exc_info=True)
        return {"error": "Could not read system specs"}
    if not out:
        _core._log.debug("host specs: empty output (stderr: %s)", (err or "")[:200])
        return {"error": "Could not read system specs"}
    d = {}
    for line in out.splitlines():
        if "\t" in line:
            k, v = line.split("\t", 1)
            d[k.strip()] = v.strip()
    return _host_specs_from_fields(d)


def _host_specs_from_fields(d):
    """Shape the probe's KEY -> VALUE fields into the specs dict the UI shows."""
    mhz = d.get("MAXMHZ", "")
    ghz = ""
    try:
        if mhz:
            ghz = f"{float(mhz) / 1000:.1f} GHz"
    except ValueError:
        ghz = ""
    mem = d.get("MEM", "")
    virt = d.get("VIRT", "")
    return {
        "os": d.get("OS", "") or "Unknown",
        "kernel": d.get("KERNEL", ""),
        "arch": d.get("ARCH", ""),
        "hostname": d.get("HOST", ""),
        "cpu": d.get("CPU", "") or "Unknown CPU",
        "cores": d.get("CORES", ""),
        "cpu_speed": ghz,
        "ram": (mem + " GB") if mem else "",
        "disk": d.get("DISK", ""),
        "virt": "" if virt in ("none", "") else virt,
    }
