"""Remote firewall management (UFW) and static host specs.

Part of the SSH connection manager for remote LinuxGSM servers, which also supports local
execution for running on the panel's own machine (see the package docstring for how names
resolve across its submodules).
"""
import ipaddress
import json as _json
import re
from panel.core import i18n
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


def _fwb_names_v6(p):
    """Whether parsed row `p` names an IPv6 address in its To or From column.

    ufw marks a row "(v6)" only where the address is ::/0 (get_status); `ufw allow from 2001:db8::/32`
    lists as "22/tcp  ALLOW IN  2001:db8::/32", which is an IPv6 rule all the same.
    """
    for col in (p["to"], p["from"]):
        words = col.split()
        net = _r14a_net(words[0]) if words else None
        if net is not None and net.version == 6:
            return True
    return False


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
        fam = "IPv6" if p["v6"] or _fwb_names_v6(p) else "IPv4"
        if fam not in g["families"]:
            g["families"].append(fam)
        # Each family's own places too: ufw keeps one list per family and takes the first match in
        # THAT list, so where a merged group sits for IPv6 is its IPv6 number (_fwb_family_view).
        g.setdefault("fam_nums", {}).setdefault(fam, []).append(int(r["num"]))
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
    # OverflowError too, as _panel_web_port catches: a port stored as REAL infinity (a hand-edited or
    # restored database; on-load only flags it) made int() raise that, past this except.
    except (TypeError, ValueError, OverflowError):
        _core._log.debug("a non-numeric stored port just means there's no extra SSH port to track", exc_info=True)
    return ports


def _fwssh_served_ports(server):
    """The ports an SSH rule must name to be a WORKING way in: the ones sshd listens on.

    _ssh_ports always says 22, which is right for what it is also used for (ports no game may
    take) and wrong here. On a host whose sshd was moved to 2222 by hand, the stock `22/tcp ALLOW`
    (or `OpenSSH ALLOW`) left in UFW counted as a second way in, so the 2222 rule — the only one
    sshd answers on — came back warn ("another way in exists") instead of protected, and
    remote_ufw_delete_rule, which gates only on protected, deleted it. What sshd serves is read by
    hosts._sshd_current_ports (ssh.socket's ports while it holds the socket, else `sshd -T`'s);
    the port the panel connects on is kept beside it, because that connection is the proof it is
    served. A config that cannot be read keeps the old answer:
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
    except (TypeError, ValueError, OverflowError):   # as _ssh_ports
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
        # Read as load_config reads it (_r26a_port): the raw cache holds the hand-edited value,
        # and the panel bound the corrected one.
        return _cfg._r26a_port(dict(_cfg._cfg_cache.get("data") or {}))["port"]
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
    except (TypeError, ValueError, OverflowError):    # OverflowError: a hand-edited `Infinity`
        # Not a fallback port: a non-numeric `port` never reached socketio.run(), so there is no
        # listening panel for this to be about. Answer with the same default the boot path would
        # have read rather than a literal that can drift away from it.
        from panel.core.config import DEFAULT_CONFIG
        return DEFAULT_CONFIG["port"]


def _r31a_panel_web_ports(server, ts_running=None):
    """Every port _panel_web_port's guard covers: the one this process serves on, then config.json's.

    _panel_web_port reads config.json, which is the port the NEXT start binds. After a port change
    whose restart could not be scheduled the panel still listened on the old port, and the rule
    holding that one open (the way in right now) was an ordinary delete ×, while the guard protected
    a port nothing listened on yet. Both are the panel's: the one in use now, and the one the restart
    moves to. [] where _panel_web_port answers None (a remote, or the UI served over a live tailnet).
    """
    stored = _panel_web_port(server, ts_running=ts_running)
    if stored is None:
        return []
    from panel.core.config import bound_port     # lazy, as every config read here
    bound = bound_port()
    return [stored] if bound in (None, stored) else [bound, stored]


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
    """Whether rule `g` admits only a protocol that cannot carry TCP, which sshd never reads.

    The protocol is printed beside the To column for a port rule, and beside the From column for a
    source-only one (ufw's get_status: `ufw allow from <ip> proto udp` is To "Anywhere", From
    "<ip>/udp"). Reading only the To column counted that one as every port, sshd's included. Not
    only udp: ufw's portless protocols print the same way (`ufw allow proto gre from <peer>` is From
    "<peer>/gre"), and a GRE, 6in4 or IPsec peer's allow made the host's only `22/tcp` deletable
    (system_ops._r15a_not_tcp, the test the tailscale0 reading shares).
    """
    from panel.ops import system_ops as _so
    return g.get("proto_label") == "UDP" or _so._r15a_not_tcp(g.get("src"))


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
        net = ipaddress.ip_network(last, strict=False)
    except ValueError:
        return False
    # A multicast or the limited-broadcast destination (`ufw allow to 224.0.0.251`, mDNS) takes no
    # TCP, so it never reaches sshd or the panel: counted as every port, it was "another way in"
    # beside the host's only public 22/tcp, which then had an ordinary delete x.
    _limited_broadcast = net.version == 4 and net.num_addresses == 1 and int(net.network_address) == 2 ** 32 - 1
    return not (net.is_multicast or _limited_broadcast)


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
    # The panel's web port is TCP, and a rule only this machine can match is no way in: the SSH
    # readers above skip both (_is_ssh_rule). Counted, a game's `5000:5010/udp` made Close public
    # panel port refuse with "take port 5000 out of that rule", `5000/udp` was force-deleted as
    # the panel's rule, and the Firewall page protected either as the panel's way in.
    if _r14a_udp_only(rule) or _r14a_host_only(rule):
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


def _r31a_panel_port_of(g, panel_ports):
    """The first of the panel's ports group `g` holds open (the reason names that one), or None."""
    return next((p for p in panel_ports if _is_panel_rule(g, p)), None)


def _r14a_ports_word(g):
    """The port part of a rule's To column: `22` of "<addr> 22", `47100:47199`, `22,80`."""
    words = str(g.get("port_num", "")).split()
    return words[-1] if words else ""


# Every protect_reason the Firewall page can show, as a fixed English template. The group carries
# the template (protect_reason_key) and its values (protect_reason_params) beside the English text,
# so the page renders it in the viewer's language (remote_firewall.js _fwReason): the catalogs
# translate the template, and the values (ports, never words) go in after. protect_reason itself stays the English sentence it always
# was; an API refusal built from it is an i18n.Sentence of the template (hosts._r16c_protect_refusal),
# the same English as a str, which the route translates. The unit suite holds each one to both catalogs.
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
    # From the connection itself (ufweval, _fwc_protect_paths): the rule the panel's own connection
    # gets in by, whatever other rules there are.
    "ssh_panel": ("This rule is the one letting the panel's own SSH connection in (from {src}) — removing it "
                  "would cut the panel off from this host. Add a rule that lets {src} in first, or have the "
                  "panel reach this host at its Tailscale address."),
    "ssh_unread": ("The panel couldn't read the address it connects to this host from, so it can't tell "
                   "whether this SSH rule is the one keeping its connection open. Refresh and try again "
                   "before removing it."),
    "web_viewer": ("This rule is the one letting your connection to the panel in (from {src}, port {port}/tcp) — "
                   "removing it would lock you out of the panel."),
}


def _r14a_set_reason(g, which, **params):
    """Set protect_reason (English), and the template + values the page translates it from."""
    template = R14A_REASONS[which]
    g["protect_reason_params"] = {k: str(v) for k, v in params.items()}
    g["protect_reason_key"] = template
    g["protect_reason"] = template.format_map(g["protect_reason_params"])


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


def _protect_rule(g, panel_port, served_over_ts, ssh, ts_ssh_ok, ts_iface_ok):
    """Set protected / warn / protect_reason on one group of an ENABLED firewall.

    `ssh` is (live SSH rules per family, the families the panel reaches the host in).
    """
    counts, in_use = ssh
    if g["is_panel"]:
        _r14a_protect_panel(g, panel_port)
        return
    if not g["is_access"]:
        return
    if g["is_ssh"]:
        # Deleting this SSH rule is safe only if another way in remains: another SSH rule,
        # Tailscale SSH, or regular SSH over a running tailnet (Tailscale isn't affected).
        # `counts` counts only the SSH rules UFW lets act, per family (_fwb_mark_live_by_family); this
        # one is "another" way only to the others, and only in the families it covers: beside a
        # v6-only rule the host's one IPv4 SSH rule is the last way in for an IPv4 panel. A rule a
        # DENY above it shadows is no way in itself, and it stays protected while nothing else is
        # (in doubt, protect).
        other_way = _fwb_other_ssh_way(g, counts, in_use) or ts_ssh_ok or ts_iface_ok
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
        other_way = _fwb_any_live(counts, in_use) or ts_ssh_ok
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


# ── address families ──
# ufw keeps one rule list per address family, and a connection meets only its own family's list: a
# rule written for IPv6 alone (Open a port's "IPv6 only") admits no IPv4 connection, and a DENY
# prepended for one family shadows nothing in the other. The way-in readers above were written
# family-blind (they read the merged display group), so the host's only IPv4 SSH rule could read
# "another way in exists" beside a v6-only one, and a default deny went through with only a v6 rule.
_FWB_FAMILY = {4: "IPv4", 6: "IPv6"}


def _fwb_unmapped(addr):
    """`addr` as the family it really travels in: an IPv4-mapped IPv6 address is the IPv4 one."""
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


def _fwb_family_pairs(groups, version):
    """(group, its copy at its place in family `version`'s list) for each group UFW holds for that family.

    A group read without per-family places (no fam_nums: built by hand) is taken as listed.
    """
    fam = _FWB_FAMILY[version]
    pairs = []
    for g in groups:
        places = g.get("fam_nums")
        if places is None:
            if fam in (g.get("families") or [fam]):
                pairs.append((g, dict(g)))
        elif places.get(fam):
            pairs.append((g, dict(g, nums=list(places[fam]))))
    return pairs


def _fwb_family_view(groups, version):
    """The groups as family `version`'s own list holds them (copies; the caller's are not touched)."""
    return [c for _g, c in _fwb_family_pairs(groups, version)]


def _fwb_mark_live_by_family(groups, ssh_ports):
    """Set ssh_live_v (the families an SSH rule is live in) and ssh_live on each group -> {4: n, 6: n}.

    _r14a_mark_live_ssh's reading, made once per family list: a DENY above an ALLOW shadows it only in
    the families both are in. `n` is how many SSH rules are live in that family.
    """
    for g in groups:
        g["ssh_live_v"] = []
    counts = {}
    for v in (4, 6):
        pairs = _fwb_family_pairs(groups, v)
        _r14a_mark_live_ssh([c for _g, c in pairs], ssh_ports)
        for g, c in pairs:
            if c.get("ssh_live"):
                g["ssh_live_v"].append(v)
        counts[v] = sum(1 for _g, c in pairs if c.get("ssh_live"))
    for g in groups:
        g["ssh_live"] = bool(g["ssh_live_v"])
    return counts


def _fwb_panel_viewer():
    """(the address the firewall sees this request come from, whether it came through a local proxy).

    The socket peer, when it is another machine: a viewer straight in, or a proxy elsewhere, either
    of which reaches the panel's own port. When the peer is this machine (a reverse proxy here, or
    Tailscale Serve), the viewer the proxy says it serves (client_ip, which believes only a proxy the
    panel trusts), who reached the PROXY's port. (None, False) outside a request, and when who is
    really on the other end is not known: a tunnel, or a local proxy the panel was not told to believe.
    IPv4-mapped addresses are read as IPv4.
    """
    from panel.core.validation import ip_address_or_none
    try:
        from flask import request
        from panel.security.auth import client_ip
        environ = request.environ
        peer = ip_address_or_none((environ.get("werkzeug.proxy_fix.orig") or {}).get("REMOTE_ADDR")
                                  or environ.get("REMOTE_ADDR"))
        if peer is not None and not _fwb_unmapped(peer).is_loopback:
            return _fwb_unmapped(peer), False
        addr = ip_address_or_none(client_ip())
    except Exception:
        _core._log.debug("firewall: the viewer's address could not be read", exc_info=True)
        return None, False
    addr = _fwb_unmapped(addr) if addr is not None else None
    if addr is None or addr.is_loopback or addr.is_unspecified:
        return None, False
    return addr, True


def _fwb_request_port():
    """The port this request's viewer asked for: its Host's port, else its scheme's (443, 80); None outside one.

    Behind a reverse proxy the panel trusts, Host and scheme are the forwarded ones (ProxyFix).
    """
    try:
        from flask import request
        host, scheme = request.host or "", request.scheme
    except Exception:
        return None
    m = re.search(r":(\d{1,5})\Z", host)
    if m:
        port = int(m.group(1))
        return port if 0 < port < 65536 else None
    return 443 if scheme == "https" else 80


def _fwb_in_use_versions(server, src=None):
    """The address families the panel reaches `server` in: {4}, {6}, or both when it cannot tell.

    `src`, when known, is the address that connection comes from (its family is the answer). Else a
    remote dialled at an address literal is reached in that address's family, and the panel's own
    host in every family it has a public address in (ufweval.host_families). A name is both: the
    delete guard then keeps the last way in of every family a rule is live in.
    """
    from panel.core.validation import ip_address_or_none
    from panel.ops.ssh_manager import ufweval
    if src is not None:
        return {_fwb_unmapped(src).version}
    if _core.is_local_server(server):
        # Whoever administers it over SSH, from wherever: every family the host has a public address in
        # (the web viewer's family says nothing about the admin's SSH, least of all through Serve).
        return ufweval.host_families(ufweval.local_addrs(), True)
    addr = ip_address_or_none(getattr(server, "host", None))
    return {_fwb_unmapped(addr).version} if addr is not None else {4, 6}


def _fwb_any_live(counts, in_use):
    """Whether some family the panel reaches the host in has a live SSH rule."""
    return any(counts.get(v, 0) > 0 for v in in_use)


def _fwb_other_ssh_way(g, counts, in_use):
    """Whether removing SSH rule `g` leaves another live SSH rule in every in-use family it is live in.

    A rule live in none of them (shadowed, or of a family the panel does not use) is "another way"
    only while some in-use family has a live SSH rule (in doubt, protect).
    """
    live = [v for v in in_use if v in g.get("ssh_live_v", ())]
    if live:
        return all(counts.get(v, 0) > 1 for v in live)
    return _fwb_any_live(counts, in_use)


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
    # ...and per address family (_fwb_mark_live_by_family): a rule is another way in only for the
    # families it covers, and only those the panel reaches this host in count (_fwb_in_use_versions).
    counts = _fwb_mark_live_by_family(groups, ssh_ports)

    ts_running, ts_ssh_enabled = _live_tailscale_state(server, enabled, groups)

    panel_ports = _r31a_panel_web_ports(server, ts_running=ts_running)
    served_over_ts = _panel_served_over_tailscale(server)
    ts_ssh_ok = ts_running and ts_ssh_enabled    # Tailscale SSH → a way in regardless of UFW
    ts_iface_ok = ts_running and _r13a_tailnet_ssh_ok(server, groups, ssh_ports)
    # The panel's own connections (the remote's SSH session, the panel host's viewer), read only where
    # something is enforced: each rule the panel's connection gets in by alone is protected below.
    paths = _fwc_paths(server, (ts_running, ts_ssh_ok, ts_iface_ok)) if enabled else None
    ssh = (counts, _fwc_annotated_families(server, paths))

    for g in groups:
        g["protected"] = False
        g["warn"] = False
        g["protect_reason"] = ""
        g["protect_reason_key"] = ""
        g["protect_reason_params"] = {}
        panel_port = _r31a_panel_port_of(g, panel_ports)
        g["is_panel"] = panel_port is not None
        if not enabled:
            continue
        _protect_rule(g, panel_port, served_over_ts, ssh, ts_ssh_ok, ts_iface_ok)
    if paths is not None:
        _fwc_protect_paths(groups, paths)
    return groups


def _fwc_annotated_families(server, paths):
    """The families the delete guard keeps a last SSH rule in (_fwb_in_use_versions; `paths` None: off).

    The panel's host: every family it is reached in. A remote: the family of the address it is dialled
    at, and both for a name — not the one session's measured family, since a name may move the panel to
    the other one next time; the panel's own measured connection is held on its own (_fwc_protect_paths).
    """
    from panel.ops.ssh_manager import ufweval
    if paths is None:
        return {4, 6}
    if _core.is_local_server(server):
        return ufweval.host_families(paths.get("addrs"), True)
    return _fwb_in_use_versions(server)


def _fwc_protect(g, which, **params):
    """Protect group `g` for the reason `which`, unless a reason of its own already protects it."""
    if g.get("protected"):
        return
    g["protected"], g["warn"] = True, False
    _r14a_set_reason(g, which, **params)


def _fwc_protect_paths(groups, paths):
    """Protect each rule a connection the panel depends on gets in by ALONE (ufweval, read per family).

    A rule is that when, with it deleted, the connection no longer surely gets in: the "tighten SSH to
    my home IP" sequence (allow from home, then delete Anywhere) is refused while the panel connects
    from elsewhere, and so is deleting the proxy port's allow the viewer came in on. Read under a
    default deny: the incoming policy is not in this listing, and in doubt the rule is kept. A remote
    whose SSH session could not be read keeps every SSH rule (unknown is not safe).
    """
    from panel.ops.ssh_manager import ufweval
    if paths["unread"]:
        for g in groups:
            if g.get("is_ssh"):
                _fwc_protect(g, "ssh_unread")
        return
    for conn in paths["conns"]:
        if not ufweval.exempt(conn, paths["ts"]):
            for g in _fwc_sole_ways(groups, conn, paths["apps"]):
                _fwc_protect_for(g, conn)


def _fwc_sole_ways(groups, conn, apps):
    """The groups `conn` gets in by ALONE in its family's list: with one deleted, it no longer surely gets in."""
    from panel.ops.ssh_manager import ufweval
    pairs = _fwb_family_pairs(groups, conn.version)
    view = [c for _g, c in pairs]
    return [g for g, c in pairs
            if c.get("action") in ("ALLOW", "LIMIT") and ufweval.match(ufweval.spec_of(c), conn, apps) != ufweval.NO
            and not ufweval.accepts(ufweval.ordered_specs(view, without=c), conn, False, apps)]


def _fwc_protect_for(g, conn):
    """Protect `g` as the way `conn` gets in: the panel's own SSH session, or this viewer's connection."""
    src = "?" if conn.src is None else str(conn.src)
    if conn.what == "ssh":
        _fwc_protect(g, "ssh_panel", src=src)
    else:
        _fwc_protect(g, "web_viewer", src=src, port="?" if conn.dport is None else conn.dport)


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


_R15C_DEFAULT_IN_RE = re.compile(r"^Default:\s*([a-z]+)\s*\(incoming\)", re.M | re.I)


def remote_ufw_default_allows_in(server):
    """True only when `ufw status verbose` SAYS the default incoming policy is allow.

    With that policy a port with no rule is open, so deleting the panel port's own rule closes
    nothing. False for deny/reject, and for a read that failed or a line it cannot find (a
    translated ufw prints its own words): only positive evidence answers True, so a host this
    cannot read is not refused what it was allowed before.
    """
    try:
        out, _err, rc = _core.run_privileged(server, "ufw-status", ["verbose"], timeout=15, sudo=None)
    except Exception:
        return False
    m = _R15C_DEFAULT_IN_RE.search(out or "") if rc == 0 else None
    return bool(m) and m.group(1).lower() == "allow"


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


# ─── Firewall settings: default policies, on/off, logging; and port blocks ──────────────────────
# The Network tab's settings row and Add a rule's Block. Every change here is one that can lock the
# panel out of a host, so each is decided from what UFW itself says, read under the host's
# ufw_lock, and a read that failed or came back empty refuses the change rather than reading as
# "nothing is configured" (an empty read is not a measurement). The policy strings are ufw's own.

FWA_POLICIES = ("allow", "deny", "reject")
FWA_DIRECTIONS = ("incoming", "outgoing", "routed")
FWA_LOG_LEVELS = ("off", "low", "medium", "high", "full")
FWA_FAMILIES = ("both", "v4", "v6")
# The words those values are shown as, each translated whole (i18n.tr reads a Sentence value).
_FWA_WORDS = {
    "incoming": i18n.Sentence("incoming"), "outgoing": i18n.Sentence("outgoing"),
    "routed": i18n.Sentence("routed"), "allow": i18n.Sentence("allow"), "deny": i18n.Sentence("deny"),
    "reject": i18n.Sentence("reject"), "disabled": i18n.Sentence("disabled"), "off": i18n.Sentence("off"),
    "low": i18n.Sentence("low"), "medium": i18n.Sentence("medium"), "high": i18n.Sentence("high"),
    "full": i18n.Sentence("full"), "both": i18n.Sentence("IPv4 + IPv6"), "v4": i18n.Sentence("IPv4 only"),
    "v6": i18n.Sentence("IPv6 only"),
}


def _fwa_word(value):
    """A setting's value as the viewer reads it; "unknown" for one nobody could read."""
    return _FWA_WORDS.get(value) or i18n.Sentence("unknown")


# `ufw status verbose`'s lines, in the C locale the privileged verbs run in (_R19A_C_LOCALE, the
# helper's _clean_env). "disabled (routed)" is ufw's word for a host that forwards nothing.
_FWA_LOGGING_RE = re.compile(r"^Logging: (?:(off)|on \((low|medium|high|full)\))$", re.M)
_FWA_DEFAULT_RE = re.compile(
    r"^Default: (allow|deny|reject) \(incoming\), (allow|deny|reject) \(outgoing\)"
    r"(?:, (allow|deny|reject|disabled) \(routed\))?$", re.M)
# /etc/default/ufw spells a policy the way iptables does; ufw reads any other value as deny
# (backend._get_default_policy), and so does this.
_FWA_FILE_POLICY = {"accept": "allow", "reject": "reject"}
# What ufw's own reader takes as a setting (backend.UFWBackend._get_defaults): a line that STARTS
# with NAME=value. A commented line does not match, so `#DEFAULT_INPUT_POLICY="ACCEPT"` is inert.
_FWA_DEFAULT_LINE_RE = re.compile(r'^\w+="?\w+"?')


def _fwa_split_stored(out):
    """ufw-stored-rules' output as {path: text}, or None unless every file is there, in order."""
    from panel.security import privileged as _priv
    text = out or ""
    found, pos = {}, 0
    marks = ["==> %s <==\n" % p for p in _priv.FWA_STORED_PATHS]
    # Each mark exactly once: a file that itself held another's mark line would otherwise move where
    # that file seems to start. Only root writes these files, and doubt still reads as unread.
    if any(text.count(mark) != 1 for mark in marks):
        return None
    for i, mark in enumerate(marks):
        at = text.find(mark, pos)
        if at != pos:
            return None
        start = at + len(mark)
        nxt = text.find(marks[i + 1], start) if i + 1 < len(marks) else len(text)
        if nxt < 0:
            return None
        found[_priv.FWA_STORED_PATHS[i]] = text[start:nxt]
        pos = nxt
    return found


def _fwa_defaults(*texts):
    """The settings ufw reads from /etc/default/ufw and ufw.conf, as ufw reads them: lowercased."""
    vals = {}
    for text in texts:
        for line in (text or "").splitlines():
            if _FWA_DEFAULT_LINE_RE.search(line):
                parts = line.strip().split("=")
                vals[parts[0].lower()] = parts[1].lower().strip("\"'")
    return vals


def _fwa_file_policy(vals, key):
    """One default policy from the stored settings, as ufw words it; None when it is not set."""
    if key not in vals:
        return None
    return _FWA_FILE_POLICY.get(vals[key], "deny")


def _fwa_read_stored(server):
    """Read the stored UFW files (ufw-stored-rules) as {path: text}; None when they could not be read."""
    try:
        out, _err, rc = _core.run_privileged(server, "ufw-stored-rules", [], timeout=15, sudo=None,
                                             merge_stderr=False)
    except Exception:
        _core._log.debug("ufw-stored-rules could not run", exc_info=True)
        return None
    return _fwa_split_stored(out) if rc == 0 else None


# ── ufw's stored tuples as the rows `ufw status numbered` would list ──
def _fwa_tuple_ifaces(t, last):
    """A tuple's last field into `t`: its direction, and the interfaces "in_eth0!out_eth1" names."""
    t["direction"] = last.split("_")[0]
    for part in last.split("!"):
        kind, _, name = part.partition("_")
        if name:
            t["iface_" + ("in" if kind == "in" else "out")] = name


def _fwa_tuple(line):
    """One `### tuple ###` line of user.rules as ufw's reader takes it, or None when ufw skips it.

    backend_iptables._read_rules: the comment is hex after " comment=", 6 to 9 fields, the last of
    a 7 or 9 field tuple the direction with its interface, "route:" before a forwarded rule's
    action and "_log" / "_log-all" after a logged one's.
    """
    comment = ""
    if " comment=" in line:
        line, hexed = line.split(" comment=", 1)
        try:
            comment = bytes.fromhex(hexed.strip()).decode("utf-8", "replace")
        except ValueError:
            comment = ""
    fields = re.split(r"\s+", line[len("### tuple ###"):].strip())
    if not 6 <= len(fields) <= 9:
        return None
    t = {"comment": comment, "direction": "in", "iface_in": "", "iface_out": "", "dapp": "", "sapp": ""}
    if len(fields) in (7, 9):
        _fwa_tuple_ifaces(t, fields[-1])
    action = fields[0]
    t["forward"] = ":" in action
    action = action.split(":")[-1]
    t["action"], _, t["logtype"] = action.partition("_")
    t["proto"], t["dport"], t["dst"], t["sport"], t["src"] = fields[1:6]
    if len(fields) >= 8:
        t["dapp"] = "" if fields[6] == "-" else fields[6].replace("%20", " ")
        t["sapp"] = "" if fields[7] == "-" else fields[7].replace("%20", " ")
    return t


def _fwa_location(t, v6, loc):
    """One column (To or From) of rule `t`, as ufw's get_status prints it (numbered, not verbose)."""
    dst = loc == "dst"
    addr, port, app = (t["dst"], t["dport"], t["dapp"]) if dst else (t["src"], t["sport"], t["sapp"])
    if app:
        port = app + (" (v6)" if v6 and addr == "::/0" else "")
    col = _fwa_col_port(t, v6, addr, port) if port != "any" else _fwa_col_any(t, addr)
    return col + _fwa_col_iface(t, dst)


# ufw's "any" networks, which it prints as Anywhere.
_FWA_ANY_NETS = ("0.0.0.0/0", "::/0")      # NOSONAR(S1313) - ufw's "any" networks, not hosts


def _fwa_show_proto(t):
    """Whether ufw prints `t`'s protocol: it has one, and the rule is not an app profile's."""
    return t["proto"] != "any" and not (t["dapp"] or t["sapp"])


def _fwa_col_port(t, v6, addr, port):
    """A column that names a port (or an app profile): "[<addr> ]<port>[/proto][ (v6)]"."""
    col = port if addr in _FWA_ANY_NETS else addr + " " + port
    if _fwa_show_proto(t):
        col += "/" + t["proto"]
    if v6 and t["src"] == "::/0" and t["dst"] == "::/0" and " (v6)" not in col:
        col += " (v6)"
    return col


def _fwa_col_any(t, addr):
    """A column with no port: its address, or Anywhere (with the protocol where ufw shows it)."""
    if addr not in _FWA_ANY_NETS:
        same_ports = t["dport"] == t["sport"]
        return addr + ("/" + t["proto"] if _fwa_show_proto(t) and same_ports else "")
    col = "Anywhere"
    if _fwa_show_proto(t) and t["dst"] == t["src"] and t["dport"] == t["sport"]:
        col += "/" + t["proto"]
    return col + (" (v6)" if addr == "::/0" else "")


def _fwa_col_iface(t, dst):
    """Name the interface (" on <iface>") in the column ufw prints it in, else "".

    A route rule names its incoming interface under From and its outgoing one under To; any other
    rule names the incoming one under To and the outgoing one under From.
    """
    if t["forward"]:
        on = t["iface_out"] if dst else t["iface_in"]
    else:
        on = t["iface_in"] if dst else t["iface_out"]
    return " on " + on if on else ""


def _fwa_tuple_detail(t, v6):
    """Rule `t` as one row of `ufw status numbered`, without its "[ n]"."""
    attribs = [t["logtype"].lower()] if t["logtype"] else []
    if t["direction"] == "out" and not t["forward"]:
        attribs.append("out")
    word = "FWD" if t["forward"] else t["direction"].upper()
    # ufw's own fixed-width row, then collapsed the way remote_ufw_status collapses a listed one.
    detail = "%-26s %-12s%-26s%s%s" % (
        _fwa_location(t, v6, "dst"), t["action"].upper() + " " + word, _fwa_location(t, v6, "src"),
        " (%s)" % ", ".join(attribs) if attribs else "", " # " + t["comment"] if t["comment"] else "")
    return re.sub(r"\s{2,}", "  ", detail.strip())


def _fwa_stored_rows(stored, with_v6=True):
    """The stored rules as remote_ufw_status's `rules`: IPv4's first, then IPv6's, as ufw numbers them.

    An app rule ufw stores as one tuple per port is listed once, as `ufw status numbered` does.
    `with_v6` False leaves out user6.rules, which ufw does not load unless IPV6=yes.
    """
    rows, seen = [], set()
    files = (("/etc/ufw/user.rules", False), ("/etc/ufw/user6.rules", True))
    for path, v6 in files if with_v6 else files[:1]:
        for line in (stored.get(path) or "").splitlines():
            if not line.startswith("### tuple ###"):
                continue
            t = _fwa_tuple(line)
            if t is None:
                continue
            if t["dapp"] or t["sapp"]:
                key = (v6, t["action"], t["direction"], t["dapp"], t["dst"], t["sapp"], t["src"],
                       t["iface_in"], t["iface_out"], t["forward"])
                if key in seen:
                    continue
                seen.add(key)
            rows.append({"num": str(len(rows) + 1), "detail": _fwa_tuple_detail(t, v6)})
    return rows


# ── the settings read ──
def remote_ufw_settings(server):
    """Read UFW's default policies, whether it is on, its logging level and IPv6 switch, for the card.

    {"read_ok", "installed", "enabled", "incoming", "outgoing", "routed", "logging", "ipv6"}. While
    UFW is on the loaded values come from `ufw status verbose`; while it is off that lists none of
    them, and they come from the files ufw will load (ufw-stored-rules). A value nobody could read
    is None, never a guess: the card shows it as unknown and offers no change to it. read_ok False
    (with `unreachable`, as remote_ufw_status says it) when the status itself could not be read.
    """
    out, err, rc = _core.run_privileged(server, "ufw-status", ["verbose"], timeout=15, sudo=None)
    failed = _fwa_status_failed(out, err, rc)
    if failed is not None:
        return failed
    enabled = _ufw_is_active(out)
    stored = _fwa_read_stored(server)
    res = dict(_fwa_stored_values(stored), read_ok=True, installed=True, enabled=enabled,
               stored_ok=stored is not None)
    if enabled:
        _fwa_loaded_values(res, out)
    return res


def _fwa_status_failed(out, err, rc):
    """The settings answer for a status read that is not a reading (as remote_ufw_status words it)."""
    if rc == 127:
        return {"read_ok": True, "installed": False, "enabled": False}
    if rc != 0 or not (out or "").strip():
        res = {"read_ok": False, "installed": False, "enabled": False, "unreachable": True}
        if _SUDO_REFUSED_RE.search((out or "") + (err or "")):
            res["permission_denied"] = True
        return res
    return None


def _fwa_stored_values(stored):
    """The settings the stored files hold (every one None when they could not be read)."""
    vals = (_fwa_defaults(stored["/etc/default/ufw"], stored["/etc/ufw/ufw.conf"])
            if stored is not None else {})
    return {"incoming": _fwa_file_policy(vals, "default_input_policy"),
            "outgoing": _fwa_file_policy(vals, "default_output_policy"),
            "routed": _fwa_file_policy(vals, "default_forward_policy"),
            "logging": vals.get("loglevel") if vals.get("loglevel") in FWA_LOG_LEVELS else None,
            "ipv6": {"yes": True, "no": False}.get(vals.get("ipv6"))}


def _fwa_loaded_values(res, out):
    """What is LOADED, from `ufw status verbose`, over the stored values while UFW is on.

    A line it cannot find (a ufw that words it otherwise) leaves the stored value, or None.
    """
    m = _FWA_DEFAULT_RE.search(out)
    if m:
        res["incoming"], res["outgoing"] = m.group(1), m.group(2)
        res["routed"] = m.group(3) or res["routed"]
    lm = _FWA_LOGGING_RE.search(out)
    if lm:
        res["logging"] = lm.group(1) or lm.group(2)


# ── what an ENABLED firewall would let in, and out ──
def _fwa_rule_groups(server, st=None):
    """The rules as groups an ENABLED firewall would protect, or None when they cannot be read.

    While UFW is on, remote_ufw_status's own groups. While it is off `ufw status` lists nothing,
    and turning it on is exactly the change that needs them: the stored rules (ufw-stored-rules),
    read into the rows ufw would list and annotated as an enabled firewall's. The IPv6 ones only
    where the settings read `st` says IPV6=yes: ufw loads user6.rules only then.
    """
    status = remote_ufw_status(server)
    if status.get("unreachable") or not status.get("installed"):
        return None
    if status.get("enabled"):
        return status.get("groups") or []
    stored = _fwa_read_stored(server)
    if stored is None:
        return None
    with_v6 = (st or {}).get("ipv6") is True
    return _annotate_firewall_protection(server, True, _group_ufw_rules(_fwa_stored_rows(stored, with_v6)))


def _fwa_ordered(groups):
    return sorted((g for g in groups if g.get("nums")), key=lambda g: min(g["nums"]))


def _fwa_port_open(groups, port, pick):
    """Whether a rule `pick` chooses lets TCP to `port` in, with no DENY/REJECT above it blocking it.

    UFW takes the first rule a packet matches; the shadowing test is the SSH guard's own.
    """
    order = _fwa_ordered(groups)
    for i, g in enumerate(order):
        if pick(g) and _r14a_admits(g, port):
            denies = [d for d in order[:i] if d.get("action") in ("DENY", "REJECT")]
            if not any(_r14a_deny_covers(d, g, port) for d in denies):
                return True
    return False


def _fwa_tailnet_iface_open(groups):
    """Whether an inbound rule lets EVERY port in on a Tailscale interface, read first match first."""
    decided = {}
    for g in _fwa_ordered(groups):
        iface = str(g.get("iface") or "")
        if (not iface.startswith("tailscale") or (g.get("direction") or "IN") != "IN"
                or _r14a_udp_only(g) or not _r13a_every_port(g, str(g.get("port_num", "")))):
            continue
        decided.setdefault(iface, g.get("action") in ("ALLOW", "LIMIT"))
    return any(decided.values())


def _fwa_is_tailnet_host(host):
    """Whether the address the panel dials is on the tailnet: a Tailscale address or MagicDNS name."""
    from panel.ops import system_ops as _so
    h = str(host or "").strip().lower().rstrip(".")
    if h.endswith(".ts.net"):
        return True
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n) for n in _so._TAILNET_RANGES
               if ipaddress.ip_network(n).version == addr.version)


def _fwb_src_admits(g, src):
    """Whether ALLOW rule `g`'s From column surely admits a connection from address `src`.

    `src` None is a source nobody knows, which only a rule from Anywhere surely admits. A From that
    names a source port admits only that port, so it does not surely admit anything.
    """
    words = str(g.get("src") or "Anywhere").split()
    if len(words) > 1:
        return False
    net = _r14a_src_net(words)
    if net == "any":
        return True
    return (src is not None and isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network))
            and net.version == src.version and src in net)


def _fwb_deny_may_hit(g, src):
    """Whether DENY/REJECT rule `g` may drop a connection from address `src` (None: a source not known).

    In doubt it may: a From it cannot parse or that names a source port, and any interface but a
    tailscale one (the panel's connection over the tailnet is decided before this is asked). A From of
    one address or network drops only what is inside it, so for a source nobody knows it is not
    counted: the hourly auto-block's deny of one attacker cuts nobody else off. A rule only this
    machine can match (_r14a_host_only) drops nothing from another.
    """
    if _r14a_host_only(g) or str(g.get("iface") or "").startswith("tailscale"):
        return False
    words = str(g.get("src") or "Anywhere").split()
    if len(words) > 1:
        return True
    net = _r14a_src_net(words)
    if net == "any" or net is None:
        return True
    return src is not None and net.version == src.version and src in net


def _fwb_first_decides(view, port, src, pick, default_allow):
    """Whether TCP from `src` to `port` gets in under one family's rule list, read as UFW reads it.

    The first rule the connection matches decides. A DENY/REJECT decides no when it may match
    (_fwb_deny_may_hit); an ALLOW/LIMIT that `pick` chooses decides yes when its From surely admits
    `src` (_fwb_src_admits). An allow it cannot be sure of decides nothing. When no rule decides, the
    default incoming policy does: `default_allow`.
    """
    for g in _fwa_ordered(view):
        if (g.get("direction") or "IN") != "IN" or not _r14a_admits(g, port):
            continue
        action = g.get("action")
        if action in ("DENY", "REJECT") and _fwb_deny_may_hit(g, src):
            return False
        if action in ("ALLOW", "LIMIT") and pick(g) and _fwb_src_admits(g, src):
            return True
    return default_allow


def _fwb_ssh_open(view, ssh_ports, default_allow):
    """Whether SSH stays reachable for whoever administers the host, in one family's list.

    A live SSH rule (_r14a_mark_live_ssh, run on this view: a LAN-only rule is a LAN admin's way in);
    or, under a default incoming allow, no deny from everywhere ahead of every rule for an sshd port.
    """
    if any(c.get("ssh_live") for c in view):
        return True
    return default_allow and any(_fwb_first_decides(view, p, None, lambda g: g.get("is_ssh"), True)
                                 for p in ssh_ports)


def _fwb_family_refusal(version, st):
    """Why family `version` has no way in at all whatever the rules say, or None (st: the settings read).

    ufw handles IPv6 only with IPV6=yes in /etc/default/ufw; with anything else its init script sets
    ip6tables to DROP everything but loopback while it is on (ufw-init-functions), so no IPv6 rule
    is loaded and no IPv6 connection gets in.
    """
    if version != 6 or st.get("ipv6") is True:
        return None
    if not st.get("stored_ok"):
        return i18n.Sentence("Couldn't read whether UFW handles IPv6 (its settings files), and the panel reaches "
                             "this host over IPv6.")
    return i18n.Sentence("UFW is set not to handle IPv6 (IPV6=no in /etc/default/ufw), so while it is on it drops "
                         "every IPv6 connection, and the panel reaches this host over IPv6.")


def _fwb_dialled_port(server):
    """The SSH port the panel dials `server` on, or None when the stored one is not a number."""
    try:
        return int(getattr(server, "port", None))
    except (TypeError, ValueError, OverflowError):
        return None


_FWB_TAILNET_GAP = i18n.Sentence("The panel reaches this host over Tailscale, and neither Tailscale SSH nor "
                                 "a rule letting the tailscale0 interface in would keep that open.")


def _fwb_tailnet_way(server, ts):
    """(whether the panel reaches `server` over Tailscale, whether a Tailscale way keeps that open).

    Tailscale SSH answers port 22 only (tailscaled intercepts 22 on its own addresses), so it is the
    panel's way in only where the panel dials 22; on another port the connection is sshd's. Or a
    tailnet interface rule that carries sshd (_r13a_tailnet_ssh_ok, `ts`'s third reading).
    """
    _running, ts_ssh_ok, ts_iface_ok = ts
    tailnet = getattr(server, "auth_method", None) == "tailscale" or _fwa_is_tailnet_host(getattr(server, "host", None))
    return tailnet, tailnet and ((ts_ssh_ok and _fwb_dialled_port(server) == 22) or ts_iface_ok)


_FWB_SOURCE_UNREAD = i18n.Sentence("Couldn't read the address the panel connects to this host from, so whether a "
                                   "rule keeps that connection open is not known.")
_FWB_VIEWER_UNKNOWN = i18n.Sentence("Couldn't tell which address you reach the panel from: this request came from the "
                                    "panel's own machine, from a proxy the panel was not told to believe. If a reverse "
                                    "proxy here serves the panel, set \"trust_proxy\": true in config.json (and add its "
                                    "account to \"trusted_proxy_users\" if the panel does not already believe it); until "
                                    "then whether a rule keeps the panel reachable cannot be checked.")


# ── the connections the panel depends on (ufweval's tuples) ──
# A remote: the panel's own SSH session, as the host meets it ($SSH_CONNECTION, after any NAT). The
# panel's host: this viewer's way into the web interface — straight in, through a reverse proxy here,
# through Tailscale Serve, or (needing no inbound port) through a Cloudflare Tunnel. Each guard asks
# ufweval whether those still get in, before and after the change it is deciding.
def _fwc_paths(server, ts):
    """{"conns": [ufweval.Conn], "why": a refusal when they cannot be known, "ts": Tailscale facts,
    "apps": a profile resolver, "unread": True when a remote's SSH session could not be read}.

    `ts` is (Tailscale running, Tailscale SSH on, regular SSH over the tailnet let in), read live.
    "conns" empty with "why" None means nothing needs to stay open (Tailscale SSH answers the panel,
    or the viewer comes through a tunnel).
    """
    from panel.ops.ssh_manager import ufweval
    paths = {"conns": [], "why": None, "ts": {"ssh": bool(ts[1]), "netfilter_on": False},
             "apps": ufweval.app_lookup(server), "unread": False}
    if _core.is_local_server(server):
        paths["addrs"] = ufweval.local_addrs()
        paths["conns"], paths["why"] = _fwc_web_conns(server, ts[0], paths["addrs"])
    else:
        _fwc_ssh_conns(server, ts, paths)
    if ts[0] and any(c.iface and c.iface.startswith("tailscale") for c in paths["conns"]):
        paths["ts"]["netfilter_on"] = ufweval.ts_netfilter_on(server)
    return paths


def _fwc_ssh_conns(server, ts, paths):
    """_fwc_paths for a remote: the panel's SSH session, unless Tailscale already answers for it."""
    from panel.ops.ssh_manager import ufweval
    tailnet, ts_way = _fwb_tailnet_way(server, ts)
    if ts_way:
        return
    try:
        conn = hosts._fwb_ssh_conn(server)
    except Exception:            # a host gone since its rules were read: not read, so not safe
        _core._log.debug("the panel's SSH session to the host could not be read", exc_info=True)
        conn = None
    if conn is None:
        paths["unread"] = True
        paths["why"] = _FWB_TAILNET_GAP if tailnet else _FWB_SOURCE_UNREAD
        return
    paths["addrs"] = conn.get("addrs")
    paths["conns"] = [ufweval.Conn(conn["client"].version, conn["client"], conn["server"], conn["port"],
                                   conn.get("iface"), "ssh")]


def _fwc_web_conns(server, ts_running, addrs):
    """_fwc_paths for the panel's host -> (conns, why): this viewer's way into the web interface."""
    if _panel_served_over_tailscale(server) and ts_running:
        return _fwc_serve_conns(addrs), None
    viewer, via_proxy = _fwb_panel_viewer()
    if viewer is None:
        return [], _FWB_VIEWER_UNKNOWN
    if not via_proxy:
        return _fwc_direct_conns(server, ts_running, viewer, addrs), None
    return _fwc_proxy_conns(server, viewer, addrs)


def _fwc_serve_conns(addrs):
    """Tailscale Serve's way in: a tailnet peer to 443 on the tailnet interface (IPv4: every tailnet has it)."""
    from panel.ops.ssh_manager import ufweval
    ends = [(a, i) for i, a, _s in addrs or () if "tailscale" in i and a.version == 4] or [(None, "tailscale0")]
    return [ufweval.Conn(4, None, a, 443, i, "web") for a, i in ends]


def _fwc_request_end():
    """(the address, the port) this request's socket was accepted on: eventlet's SERVER_NAME/SERVER_PORT
    are the accepted socket's own name. (None, None) outside a request; a name is no address."""
    from panel.core.validation import ip_address_or_none
    try:
        from flask import request
        env = request.environ
        orig = env.get("werkzeug.proxy_fix.orig") or {}
        addr = ip_address_or_none(orig.get("SERVER_NAME") or env.get("SERVER_NAME"))
        port = int(orig.get("SERVER_PORT") or env.get("SERVER_PORT") or 0) or None
    except Exception:
        return None, None
    return (_fwb_unmapped(addr) if addr is not None else None), port


def _fwc_direct_conns(server, ts_running, viewer, addrs):
    """A viewer straight in: from its address to the panel's own port, on the address it reached.

    The port the socket was accepted on when it is one the panel serves (it always is, in the panel),
    else each of them; the address likewise, else each the viewer may have reached (ufweval.candidate_ends).
    """
    from panel.ops.ssh_manager import ufweval
    ports = _r31a_panel_web_ports(server, ts_running=ts_running) or [None]
    here, port = _fwc_request_end()
    if port in ports:
        ports = [port]
    iface = ufweval.iface_of(addrs, here)
    ends = [(here, iface)] if iface else ufweval.candidate_ends(addrs, viewer, viewer.version)
    return [ufweval.Conn(viewer.version, viewer, a, p, i, "web") for p in ports for a, i in ends]


def _fwc_proxy_conns(server, viewer, addrs):
    """A viewer through a proxy here -> (conns, why): the connection it has open to the proxy, as the
    kernel holds it (ufweval.inbound_from): which address and port it really came in on. None open: a
    Cloudflare Tunnel (cloudflared runs here) needs no inbound port; anything else is not known.
    """
    from panel.ops.ssh_manager import ufweval
    seen = _fwc_seen(server, viewer)
    ports = sorted({p for _a, p in seen})
    pick = _fwc_pick_port(ports)
    if pick is not None:
        return [ufweval.Conn(viewer.version, viewer, a, pick, ufweval.iface_of(addrs, a), "web")
                for a, p in seen if p == pick], None
    if seen:
        return [], i18n.Sentence("Your address ({ip}) has connections open to this host on ports {ports}, so which "
                                 "one reaches the panel's proxy is not known. Have the proxy send X-Forwarded-Port "
                                 "(nginx: proxy_set_header X-Forwarded-Port $server_port;).",
                                 ip=str(viewer), ports=", ".join(str(p) for p in ports))
    if ufweval.tunnel_running():
        return [], None
    return [], i18n.Sentence(
        "You reach the panel through a proxy on this machine, but no connection from your address ({ip}) to "
        "this host is open, so the port you come in on is not known (a tunnel the panel does not recognise, or "
        "a proxy that passes on another address than the one it accepted). Whether a rule keeps the panel "
        "reachable cannot be checked.", ip=str(viewer))


def _fwc_seen(server, viewer):
    """The viewer's open connections to this host (ufweval.inbound_from), less any to sshd's ports."""
    from panel.ops.ssh_manager import ufweval
    ssh = _fwssh_served_ports(server)
    return [(a, p) for a, p in ufweval.inbound_from(viewer) or () if p not in ssh]


def _fwc_pick_port(ports):
    """Of the ports the viewer has open to this host, the one its request came in on, or None.

    One alone is it. Of several, the one the proxy names in X-Forwarded-Port, else the one its Host
    (or scheme) names.
    """
    if len(ports) == 1:
        return ports[0]
    try:
        from flask import request
        named = request.headers.get("X-Forwarded-Port", "")
        fwd = int(named) if named.strip().isdecimal() else None
    except Exception:
        fwd = None
    for want in (fwd, _fwb_request_port()):
        if want in ports:
            return want
    return None


def _fwc_shown(conn):
    """`conn`'s fields as a message names them ("?" for one nobody could read)."""
    return {"src": "?" if conn.src is None else str(conn.src), "dst": "?" if conn.dst is None else str(conn.dst),
            "port": "?" if conn.dport is None else conn.dport, "iface": conn.iface or "?"}


def _fwc_conn_gap(server, conn, denied):
    """Why `conn` would not get in, the connection named as the firewall meets it: `denied` when a deny or
    reject (one that may match it) comes before any allow, else because no rule lets it in."""
    shown = _fwc_shown(conn)
    if conn.what == "web":
        if conn.src is None:
            return (i18n.Sentence("The panel is published over Tailscale Serve, and a deny or reject rule comes "
                                  "before any allow for the tailscale0 interface (port {port}/tcp, on {iface}).",
                                  **shown) if denied else
                    i18n.Sentence("The panel is published over Tailscale Serve, and no rule lets the tailscale0 "
                                  "interface in (port {port}/tcp, on {iface}).", **shown))
        return (i18n.Sentence("A deny or reject rule comes before any allow for your connection to the panel (from "
                              "{src} to {dst}, port {port}/tcp, on {iface}).", **shown) if denied else
                i18n.Sentence("No rule lets your connection to the panel in (from {src} to {dst}, port {port}/tcp, "
                              "on {iface}), and the panel is not published over Tailscale.", **shown))
    gap = (i18n.Sentence("A deny or reject rule comes before any allow for the panel's own SSH connection to this "
                         "host (from {src} to {dst}, port {port}/tcp, on {iface}).", **shown) if denied else
           i18n.Sentence("No rule lets the panel's own SSH connection to this host in (from {src} to {dst}, port "
                         "{port}/tcp, on {iface}).", **shown))
    from panel.core.validation import ip_address_or_none
    if ip_address_or_none(getattr(server, "host", None)) is None:
        return i18n.Sentences(gap, i18n.Sentence(
            "That was measured over {family}: the panel dials {host} by name, so a connection over the other "
            "family is not checked.", family=_FWB_FAMILY[conn.version], host=str(server.host)))
    return gap


def _fwc_specs(views, conn):
    """The specs of `conn`'s family list in ufw's order, or None when that family has no list."""
    from panel.ops.ssh_manager import ufweval
    view = views.get(conn.version)
    return None if view is None else ufweval.ordered_specs(view)


def _fwc_path_gaps(server, views, paths, default_allow):
    """What the panel's own connections would lack under the rules in `views` -> [why]."""
    from panel.ops.ssh_manager import ufweval
    if paths["why"] is not None:
        return [paths["why"]]
    gaps = []
    for conn in paths["conns"]:
        specs = None if ufweval.exempt(conn, paths["ts"]) else _fwc_specs(views, conn)
        if specs is None:               # let in ahead of ufw, or a family whose own refusal is listed
            continue
        if not ufweval.accepts(specs, conn, default_allow, paths["apps"]):
            gap = _fwc_conn_gap(server, conn, ufweval.decide(specs, conn, paths["apps"]) == "deny")
            if str(gap) not in (str(g) for g in gaps):
                gaps.append(gap)
    return gaps


def _fwc_in_use(server, paths, st):
    """(the families views are needed for, the families SSH must stay open in for whoever administers it).

    A remote: the panel's session's family (else _fwb_in_use_versions'). The panel's host: SSH in every
    family the host has a public address in that ufw handles (the web viewer's family says nothing
    about the admin's SSH), and the viewer's connections' families.
    """
    from panel.ops.ssh_manager import ufweval
    conn_fams = {c.version for c in paths["conns"]}
    if _core.is_local_server(server):
        ssh_fams = ufweval.host_families(paths.get("addrs"), st.get("ipv6") is True)
    else:
        ssh_fams = conn_fams or _fwb_in_use_versions(server)
        if not conn_fams and st.get("ipv6") is not True:
            ssh_fams = (ssh_fams - {6}) or {4}
    return ssh_fams | conn_fams, ssh_fams


def _fwb_family_views(versions, groups, st, ssh_ports):
    """({family: its rule list, live SSH marked}, [why a family has no way in]) for `versions`.

    A family ufw drops whole (_fwb_family_refusal) has no view, and its reason is returned instead.
    """
    views, gaps = {}, []
    for v in sorted(versions):
        why = _fwb_family_refusal(v, st)
        if why:
            gaps.append(why)
            continue
        views[v] = _fwb_family_view(groups, v)
        _r14a_mark_live_ssh(views[v], ssh_ports)
    return views, gaps


def _fwb_ts_ways(server, groups, ssh_ports):
    """(Tailscale running, Tailscale SSH on, regular SSH over the tailnet let in), read live."""
    ts_running, ts_ssh = hosts._tailscale_conn_state(server)
    if not ts_running:
        return False, False, False
    return True, bool(ts_ssh), bool(_r13a_tailnet_ssh_ok(server, groups, ssh_ports))


def _fwa_inbound_gaps(server, groups, st, default_allow=False):
    """What a default incoming deny/reject (or turning UFW on) would cut off: [] when nothing.

    Two things must stay open: SSH, for whoever administers the host, in every family it is reached in
    (_fwc_in_use: a live SSH rule, Tailscale SSH or a tailnet interface rule that carries sshd, as the
    delete guard counts them); and the panel's own connections (_fwc_paths), each of which ufweval must
    say gets in. `st` is the settings read (whether ufw handles IPv6); `default_allow` is True when the
    incoming policy in force afterwards is allow (turning UFW on with it stored), where only a deny can
    cut a way off. The Tailscale reading fails safe to "not running", which here is the refusing side.
    """
    ssh_ports = _fwssh_served_ports(server)
    ts = _fwb_ts_ways(server, groups, ssh_ports)
    paths = _fwc_paths(server, ts)
    versions, ssh_fams = _fwc_in_use(server, paths, st)
    views, gaps = _fwb_family_views(versions, groups, st, ssh_ports)
    ssh_views = [views[v] for v in sorted(ssh_fams) if v in views]
    ssh_ok = ts[1] or ts[2] or all(_fwb_ssh_open(view, ssh_ports, default_allow) for view in ssh_views)
    if ssh_views and not ssh_ok:
        gaps.append(i18n.Sentence("No rule lets SSH in (port {ports}/tcp), and Tailscale is no other way in.",
                                  ports=", ".join(str(p) for p in sorted(ssh_ports))))
    gaps.extend(_fwc_path_gaps(server, views, paths, default_allow))
    return gaps


# What a host needs to reach out to keep working under a default outgoing deny: names resolved,
# packages and game downloads fetched (apt's mirrors are http), and Tailscale's control and relay
# servers (443). Each must be an allow OUT from this host to anywhere.
_FWA_OUT_NEEDED = ((53, "udp", "DNS"), (53, "tcp", "DNS"), (80, "tcp", "HTTP"), (443, "tcp", "HTTPS"))


def _fwa_out_admits(g, port, proto):
    """Whether OUT rule `g` matches `proto` traffic to `port` at ANY destination."""
    from panel.ops import system_ops as _so
    label = g.get("proto_label")
    if label not in ("BOTH", "—", proto.upper()) or (proto == "tcp" and _so._r15a_not_tcp(g.get("src"))):
        return False
    words = str(g.get("port_num", "")).split()
    if len(words) != 1:
        return False                   # a destination address: to that one only
    return words[0].lower() == "anywhere" or _r12a_names_port(words[0], {port})


def _fwa_out_open(groups, port, proto, iface=None):
    """Whether this host may connect out to `port`/`proto`: the first OUT rule matching it allows it.

    `iface` None: a rule on no interface. A tailscale name: a rule on that interface too. A rule on
    any other interface is not counted (it may not be the way out), nor is one to one destination;
    a DENY/REJECT OUT above that matches decides first.
    """
    for g in _fwa_ordered(groups):
        if not _fwa_out_matches(g, port, proto, iface):
            continue
        if g.get("action") in ("DENY", "REJECT"):
            return False
        if g.get("action") in ("ALLOW", "LIMIT"):
            return True
    return False


def _fwa_out_matches(g, port, proto, iface):
    """Whether OUT rule `g` is about `proto` to `port` on no interface, or on `iface`."""
    if (g.get("direction") or "IN") != "OUT" or not _fwa_out_admits(g, port, proto):
        return False
    on = str(g.get("iface") or "")
    return not on or on == (iface or "")


def _fwa_outbound_gaps(server, groups):
    """What a default outgoing deny/reject would cut off: [] when every way out it needs is allowed.

    Every host: DNS, HTTP and HTTPS (_FWA_OUT_NEEDED). The panel's host also connects OUT to every
    remote it manages: over the tailnet interface for one it reaches over Tailscale, to the SSH port
    it dials otherwise.
    """
    gaps = [i18n.Sentence("Nothing allows {name} out ({port}/{proto}).", name=name, port=port, proto=proto)
            for port, proto, name in _FWA_OUT_NEEDED if not _fwa_out_open(groups, port, proto)]
    if _core.is_local_server(server):
        from panel.db.models import RemoteServer
        for r in RemoteServer.query.filter(RemoteServer.is_local.is_(False)).order_by(RemoteServer.id).all():
            gap = _fwa_remote_out_gap(groups, r)
            if gap:
                gaps.append(gap)
    return gaps


def _fwa_remote_out_gap(groups, r):
    """What the panel host would lack to keep reaching remote `r` under an outgoing deny, or None."""
    try:
        port = int(r.port or 22)
    except (TypeError, ValueError, OverflowError):
        port = 22
    if r.auth_method == "tailscale" or _fwa_is_tailnet_host(r.host):
        if _fwa_out_open(groups, port, "tcp", iface="tailscale0"):
            return None
        return i18n.Sentence("Nothing allows the panel out to {host} over Tailscale.", host=r.name)
    if _fwa_out_open(groups, port, "tcp"):
        return None
    return i18n.Sentence("Nothing allows the panel out to {host} on SSH port {port}/tcp.", host=r.name, port=port)


_FWA_UNREAD = i18n.Sentence("Couldn't read the firewall, so nothing was changed — the panel will not change a "
                            "firewall it cannot see. Check the host is reachable and try again.")
_FWA_NOT_INSTALLED = i18n.Sentence("UFW is not installed on this host.")
_FWA_LOCKOUT_LEAD = i18n.Sentence("Not changed, because this could lock the panel or SSH out of the host:")
_FWA_OUT_LEAD = i18n.Sentence("Not changed, because this host would lose connections it needs:")


def _fwa_checked_settings(server):
    """remote_ufw_settings, or (None, the refusal) when it cannot be acted on."""
    st = remote_ufw_settings(server)
    if not st.get("read_ok"):
        return None, _FWA_UNREAD
    if not st.get("installed"):
        return None, _FWA_NOT_INSTALLED
    return st, None


def _fwa_policy_refusal(server, direction, policy, confirm, st):
    """Why setting `direction` to `policy` is refused, or None. Caller holds the ufw_lock; `st` is its read."""
    if policy == "allow" or direction == "routed":
        return None              # opens, or governs only traffic passing THROUGH the host
    if direction == "outgoing" and confirm is not True:
        return i18n.Sentence("Blocking outgoing connections needs your confirmation.")
    groups = _fwa_rule_groups(server, st)
    if groups is None:
        return _FWA_UNREAD
    if direction == "incoming":
        gaps = _fwa_inbound_gaps(server, groups, st)
        return i18n.Sentences(_FWA_LOCKOUT_LEAD, *gaps) if gaps else None
    gaps = _fwa_outbound_gaps(server, groups)
    return i18n.Sentences(_FWA_OUT_LEAD, *gaps) if gaps else None


def remote_ufw_set_default(server, direction, policy, confirm=False):
    """Set UFW's default policy for `direction` -> (ok, message, settings read after, or None).

    Incoming deny/reject is refused unless SSH and the panel's own way in stay open
    (_fwa_inbound_gaps); outgoing deny/reject unless confirmed AND every way out the host needs is
    allowed (_fwa_outbound_gaps). Decided from the rules UFW would enforce, and checked again after:
    ufw's exit status alone is not the policy in force.
    """
    if direction not in FWA_DIRECTIONS or policy not in FWA_POLICIES:
        return False, i18n.Sentence("That is not a firewall policy."), None
    with _core.ufw_lock(server):
        st, why = _fwa_checked_settings(server)
        if st is None:
            return False, why, None
        if st.get(direction) == policy:
            return True, i18n.Sentence("The default {direction} policy is already {policy}.",
                                       direction=_fwa_word(direction), policy=_fwa_word(policy)), st
        why = _fwa_policy_refusal(server, direction, policy, confirm, st)
        if why:
            return False, why, st
        out, err, rc = _core.run_privileged(server, "ufw-default", [policy, direction], timeout=20)
        after = remote_ufw_settings(server)
        if rc != 0:
            return False, _fwa_tool_said(out, err, rc), after
        # Routed reads "disabled" on a host that forwards nothing, whatever its policy says.
        if after.get(direction) != policy and not (direction == "routed" and after.get(direction) == "disabled"):
            return False, i18n.Sentence("UFW answered, but the default {direction} policy still reads {now}.",
                                        direction=_fwa_word(direction), now=_fwa_word(after.get(direction))), after
        return True, i18n.Sentence("Default {direction} policy set to {policy}.", direction=_fwa_word(direction),
                                   policy=_fwa_word(policy)), after


def _fwa_tool_said(out, err, rc):
    """A failed command's own words, one line, cut; or a fixed sentence when it said nothing."""
    said = (out or err or "").replace("\n", " ").strip()[:200]
    return said or i18n.Sentence("The firewall command failed (exit {rc}).", rc=rc)


def _fwa_enable_refusal(server, st):
    """Why turning UFW on is refused, or None: the default deny's own checks, on the stored rules.

    Under the incoming policy it stores: with allow, a port no rule names stays open, so only a deny
    can cut SSH or the panel off, and "no rule lets SSH in" is no reason to refuse.
    """
    groups = _fwa_rule_groups(server, st)
    if groups is None:
        return _FWA_UNREAD
    gaps = _fwa_inbound_gaps(server, groups, st, default_allow=st.get("incoming") == "allow")
    if gaps:
        return i18n.Sentences(_FWA_LOCKOUT_LEAD, *gaps)
    if st.get("outgoing") != "allow":
        # A stored outgoing deny (or one nobody could read) takes effect with the switch.
        out_gaps = _fwa_outbound_gaps(server, groups)
        if out_gaps:
            return i18n.Sentences(_FWA_OUT_LEAD, *out_gaps)
    return None


def remote_ufw_set_enabled(server, on, confirm=False):
    """Turn UFW on or off -> (ok, message, settings read after, or None).

    On is refused when the rules it would enforce lock the panel or SSH out (the same checks as a
    default deny, made on UFW's stored rules while it is off). Off needs `confirm`: from then on the
    host accepts every connection.
    """
    with _core.ufw_lock(server):
        st, why = _fwa_checked_settings(server)
        if st is None:
            return False, why, None
        if bool(st.get("enabled")) == bool(on):
            return True, (i18n.Sentence("The firewall is already on.") if on
                          else i18n.Sentence("The firewall is already off.")), st
        why = _fwa_enable_refusal(server, st) if on else (
            None if confirm is True else i18n.Sentence("Turning the firewall off needs your confirmation."))
        if why:
            return False, why, st
        out, err, rc = _core.run_privileged(server, "ufw-enable" if on else "ufw-disable", [], timeout=30)
        after = remote_ufw_settings(server)
        return _fwa_switched(on, out, err, rc, after)


def _fwa_switched(on, out, err, rc, after):
    """The answer once ufw-enable / ufw-disable ran: its exit, then what the firewall reads now."""
    if rc != 0:
        return False, _fwa_tool_said(out, err, rc), after
    if not after.get("read_ok") or bool(after.get("enabled")) != bool(on):
        return False, (i18n.Sentence("UFW answered, but the firewall does not read as on now.") if on else
                       i18n.Sentence("UFW answered, but the firewall does not read as off now.")), after
    return True, (i18n.Sentence("The firewall is on.") if on else
                  i18n.Sentence("The firewall is off: this host now accepts every connection.")), after


def remote_ufw_set_logging(server, level):
    """Set UFW's logging level -> (ok, message, settings read after, or None)."""
    if level not in FWA_LOG_LEVELS:
        return False, i18n.Sentence("That is not a logging level."), None
    with _core.ufw_lock(server):
        st, why = _fwa_checked_settings(server)
        if st is None:
            return False, why, None
        if st.get("logging") == level:
            return True, i18n.Sentence("Firewall logging is already {level}.", level=_fwa_word(level)), st
        out, err, rc = _core.run_privileged(server, "ufw-logging", [level], timeout=20)
        after = remote_ufw_settings(server)
        if rc != 0:
            return False, _fwa_tool_said(out, err, rc), after
        if after.get("logging") != level:
            return False, i18n.Sentence("UFW answered, but logging still reads {now}.",
                                        now=_fwa_word(after.get("logging"))), after
        return True, i18n.Sentence("Firewall logging set to {level}.", level=_fwa_word(level)), after


# ── blocking a port or a range ──
# tailscaled's default UDP port: blocking the one it listens on drops this host's direct tailnet
# connections (they fall back to Tailscale's relays over 443/tcp, which is slower, not a lock-out).
_FWA_TAILSCALE_UDP = 41641
# What the packaged tailscaled unit passes as --port=${PORT} $FLAGS (Debian/Ubuntu's /etc/default/tailscaled),
# with or without `export`; a --port in FLAGS comes after, and tailscaled's flag parser takes the last.
_FWB_TAILSCALED_PORT_RE = re.compile(r"""^\s*(?:export\s+)?PORT=["']?(\d{1,5})["']?\s*(?:#.*)?$""")
_FWC_TAILSCALED_FLAGS_RE = re.compile(r"""^\s*(?:export\s+)?FLAGS=(.*)$""")
_FWC_FLAG_PORT_RE = re.compile(r"""(?:^|[\s"'])--?port[=\s]+["']?(\d{1,5})\b""")


def _fwb_tailscaled_port(server):
    """The UDP port tailscaled listens on: /etc/default/tailscaled's PORT, else its default 41641.

    PORT=0 (tailscaled picks one) cannot be known from here and keeps the default, as does a file
    that is not there or could not be read; the last PORT= line wins, as the shell that reads it
    takes it, and a --port in FLAGS wins over it (the unit passes FLAGS after --port=${PORT}). Not
    known either: a port tailscaled falls back to when its own is taken. Readable by any account
    (0644), so no sudo. A host that is down raises (paramiko).
    """
    out, _err, rc = _core.run_command(server, "cat /etc/default/tailscaled", timeout=10, sudo=False)
    port = flag = None
    for line in (out or "").splitlines() if rc == 0 else ():
        m = _FWB_TAILSCALED_PORT_RE.match(line)
        if m:
            port = int(m.group(1))
        f = _FWC_TAILSCALED_FLAGS_RE.match(line)
        if f:
            found = _FWC_FLAG_PORT_RE.findall(f.group(1))
            flag = int(found[-1]) if found else None
    port = flag if flag is not None else port
    return port if port and port < 65536 else _FWA_TAILSCALE_UDP


def _fwb_proxy_ports():
    """Where a proxy on this machine serves the panel, as far as the panel knows.

    80 and 443 when it was told it sits behind a reverse proxy (trust_proxy: the README's nginx and
    Caddy setups); 443 when it is published over Tailscale Serve (the panel configures Serve on 443).
    A config.json that cannot be read counts as both: in doubt, protect. A proxy on any other port is
    found from the viewer's own connection (_fwc_block_refusal), not guessed from Host: with nginx's
    `proxy_set_header Host $host` an 8443 proxy read as 443 and its own port was blockable.
    """
    from panel.core.config import load_config
    try:
        cfg = {"trust_proxy": True, "tailscale_setup_done": True} if _config_unreadable() else load_config()
    except Exception:
        cfg = {"trust_proxy": True, "tailscale_setup_done": True}
    ports = set()
    if cfg.get("trust_proxy"):
        ports |= {80, 443}
    if cfg.get("tailscale_setup_done"):
        ports.add(443)
    return ports


def _fwa_panel_ports(server):
    """The ports the panel's web interface may be reached on, on its own host -> (direct, proxy).

    `direct`: config.json's port and the one this process is bound to. `proxy`: a proxy's here
    (_fwb_proxy_ports), outside `direct`. Both empty for a remote. Not narrowed by Tailscale: a deny
    prepended on the port blocks it on the tailnet interface too.
    """
    if not _core.is_local_server(server):
        return set(), set()
    from panel.core.config import bound_port, load_config
    ports = set()
    if _config_unreadable():
        ports.add(_last_parsed_panel_port())
    else:
        try:
            ports.add(int(load_config().get("port", 5000)))
        except (TypeError, ValueError, OverflowError):
            ports.add(None)
    ports.add(bound_port())
    direct = {p for p in ports if isinstance(p, int)}
    return direct, _fwb_proxy_ports() - direct


def _fwa_port_block_refusal(server, lo, hi, protos, family="both"):
    """Why blocking ports lo..hi for `protos` (in `family`) is refused, or None. Caller holds the ufw_lock.

    Not a port SSH listens on, the port the panel dials, or the panel's own web port or its proxy's
    (all TCP), nor tailscaled's UDP port (_fwb_tailscaled_port). sshd's ports are READ: a read that
    fails refuses, since the port SSH is really on may be inside the range. And then the panel's own
    connections, read as ufw reads them before and after the block goes on top (_fwc_block_refusal).
    """
    from panel.ops.ssh_manager import ufweval
    if "tcp" in protos:
        why = _fwa_tcp_block_refusal(server, lo, hi) or _fwc_block_refusal(
            server, [ufweval.deny_spec(lo, hi, "tcp")], _fwc_block_families(family), True)
        if why:
            return why
    if "udp" in protos:
        ts_port = _fwb_tailscaled_port(server)
        if lo <= ts_port <= hi:
            return i18n.Sentence("Port {port}/udp is Tailscale's own; blocking it cuts this host's direct "
                                 "tailnet connections.", port=ts_port)
    return None


def _fwc_block_families(family):
    """The address families a block written for `family` ("both", "v4", "v6") goes into."""
    return {"v4": {4}, "v6": {6}}.get(family, {4, 6})


def _fwc_default_allows(server):
    """Whether the incoming policy may be allow: False only where `ufw status verbose` says deny/reject.

    For a before/after reading, where taking "allow" in doubt is the side that refuses more.
    """
    try:
        out, _err, rc = _core.run_privileged(server, "ufw-status", ["verbose"], timeout=15, sudo=None)
    except Exception:
        return True
    m = _R15C_DEFAULT_IN_RE.search(out or "") if rc == 0 else None
    return not (m and m.group(1).lower() in ("deny", "reject"))


def _fwc_block_refusal(server, top, families, port_known_needed):
    """Why a block of rules `top` put at the TOP of `families`' lists would cut the panel off, or None.

    Each connection the panel depends on (_fwc_paths) that gets in now and would not with `top` first
    refuses, named as the firewall meets it. UFW off: the block is only stored, and turning it on is
    checked then. The rules unread refuses. Where the connections cannot be known: a remote's SSH
    session is already covered by the refusal for every port sshd serves; the panel's host refuses
    when the block needs the port (`port_known_needed`) and it is not known.
    """
    groups, why = _fwc_enforced(server)
    if groups is None:
        return why
    paths = _fwc_paths(server, _fwb_ts_ways(server, groups, _fwssh_served_ports(server)))
    if paths["why"] is not None:
        return paths["why"] if port_known_needed and _core.is_local_server(server) else None
    allow_default = _fwc_default_allows(server)
    cut = next((c for c in paths["conns"] if c.version in families
                and _fwc_cuts(groups, c, top, allow_default, paths)), None)
    return None if cut is None else _fwc_cut_answer(cut)


def _fwc_enforced(server):
    """(the rules UFW enforces now, None) -> or (None, why not to read on): unread refuses, off has none."""
    status = remote_ufw_status(server)
    if status.get("unreachable") or not status.get("installed"):
        return None, _FWA_UNREAD
    if not status.get("enabled"):
        return None, None
    return status.get("groups") or [], None


def _fwc_cuts(groups, conn, top, allow_default, paths):
    """Whether `conn` gets in now and would not with rules `top` first in its family's list."""
    from panel.ops.ssh_manager import ufweval
    if ufweval.exempt(conn, paths["ts"]):
        return False
    specs = ufweval.ordered_specs(_fwb_family_view(groups, conn.version))
    return (ufweval.accepts(specs, conn, allow_default, paths["apps"])
            and not ufweval.accepts(list(top) + specs, conn, allow_default, paths["apps"]))


def _fwc_cut_answer(conn):
    """The refusal for a block that would cut `conn` off, the connection named as the firewall meets it."""
    shown = _fwc_shown(conn)
    if conn.what == "ssh":
        return i18n.Sentence("Blocking that would cut the panel's own SSH connection to this host off (from {src} to "
                             "{dst}, port {port}/tcp, on {iface}).", **shown)
    return i18n.Sentence("Blocking that would lock you out of the panel: your connection to it comes in from {src} "
                         "to {dst}, port {port}/tcp, on {iface}.", **shown)


def fwc_block_ip_refusal(server, target):
    """Why blocking `target` (an address or network, fwa_block_target's text) on every port would cut the
    panel's own connection to `server` off (ufweval, read before and after the deny goes on top), or None.
    """
    from panel.ops.ssh_manager import ufweval
    net = ipaddress.ip_network(target, strict=False)
    return _fwc_block_refusal(server, [ufweval.deny_spec(src=net)], {net.version}, False)


def _fwa_ssh_ports_read(server):
    """The ports sshd serves, with the one the panel dials; an empty set when sshd's could not be read."""
    try:
        ssh = {int(p) for p in hosts._sshd_current_ports(server)}
    except Exception:
        _core._log.debug("port block: sshd's ports could not be read", exc_info=True)
        return set()
    if not ssh:
        return ssh
    try:
        ssh.add(int(server.port))
    except (TypeError, ValueError, OverflowError):
        _core._log.debug("port block: the stored SSH port is not a number")
    return ssh


def _fwa_tcp_block_refusal(server, lo, hi):
    """_fwa_port_block_refusal's TCP half: SSH's ports and the panel's own web ports."""
    ssh = _fwa_ssh_ports_read(server)
    if not ssh:
        return i18n.Sentence("Couldn't read which ports SSH listens on, so no port block was added.")
    hit = sorted(p for p in ssh if lo <= p <= hi)
    if hit:
        return i18n.Sentence("Port {port} is SSH's on this host; blocking it would lock you out.", port=hit[0])
    return _fwb_panel_port_refusal(server, lo, hi)


def _fwb_panel_port_refusal(server, lo, hi):
    """_fwa_tcp_block_refusal's panel half: the panel's own web ports, then a proxy's that serves it."""
    direct, proxy = _fwa_panel_ports(server)
    hit = sorted(p for p in direct if lo <= p <= hi)
    if hit:
        return i18n.Sentence("Port {port} is this panel's own web port; blocking it would lock you "
                             "out of the panel.", port=hit[0])
    hit = sorted(p for p in proxy if lo <= p <= hi)
    if hit:
        return i18n.Sentence("Port {port} is where a proxy on this host (a reverse proxy, or Tailscale Serve) "
                             "serves this panel; blocking it would lock you out of the panel.", port=hit[0])
    return None


def _fwa_block_args(spec, protocol, family, action):
    """(the protocols a block of `spec` writes, or None, and why not)."""
    from panel.security import privileged as _priv
    try:
        _priv._fwa_port_range(spec)
    except _priv.VerbError:
        return None, i18n.Sentence("Port must be a number from 1 to 65535, or a range like 27015:27020.")
    proto = hosts._ufw_proto(protocol)
    if proto is None or family not in FWA_FAMILIES or action not in ("deny", "reject"):
        return None, i18n.Sentence("That is not a protocol, address family and action the panel can block with.")
    return (["tcp", "udp"] if proto == "both" else [proto]), None


def remote_ufw_block_port(server, spec, protocol="tcp", family="both", action="deny", comment=""):
    """Deny or reject a port or range (`spec`, "27015" or "27015:27020") -> (ok, message).

    At the TOP of the rule list, so it beats an allow for the same port. "both" protocols is two
    rules, one per protocol (ufw needs one for a range). Decided and written under one hold of the
    host's ufw_lock. All or nothing: when a write fails, or ufw skips one because a rule with the same
    addresses (an allow) is already there, every rule THIS call added is taken out again, and the
    answer says what was left if any could not be.
    """
    spec = str(spec or "").strip()
    protos, why = _fwa_block_args(spec, protocol, family, action)
    if protos is None:
        return False, why
    lo, _sep, hi = spec.partition(":")
    cmt = re.sub(r"[^A-Za-z0-9 _.-]", "", comment or "")[:60]
    with _core.ufw_lock(server):
        why = _fwa_port_block_refusal(server, int(lo), int(hi or lo), protos, family)
        if why:
            return False, why
        res = _fwa_write_blocks(server, [action, spec, family, cmt], protos)
    return _fwb_block_answer(res, spec, protos, action, family)


def _fwb_rule_lines(out):
    """What one ufw add said for each family it wrote -> {"v4"|"v6": "added" | "skipped"}.

    ufw prints a line per family (backend_iptables.set_rule), " (v6)" on the IPv6 one: "Rule inserted"
    or "Rule added" while it is on, "Rules updated" while it is off (stored, not loaded), and "Skipping
    inserting existing rule" when a rule with the same addresses, ports and protocol is already there
    -- a deny, or an ALLOW: its match compares everything but the action. In the C locale the
    privileged verbs run in.
    """
    said = {}
    for line in (out or "").splitlines():
        line = line.strip()
        fam = "v6" if "(v6)" in line else "v4"
        if line.startswith(("Rule inserted", "Rule added", "Rules updated")):
            said[fam] = "added"
        elif line.startswith("Skipping"):
            said[fam] = "skipped"
    return said


def _fwa_write_blocks(server, how, protos):
    """Write one block rule per protocol, undoing what THIS call added when it cannot finish.

    -> {"added": [(proto, family)], "already": [...], "allowed": [...], "unknown": [...], "failed": why or
        None, "stored_only": bool, "left": [(proto, family) an undo could not remove], "unverified": bool}.
    Tracked per family line (_fwb_rule_lines): with both families ufw may skip the IPv4 half (already
    there) and insert the IPv6 one, and only the half it inserted is this call's to undo. A skip is
    "already" where a deny or reject from anywhere for exactly that port was listed BEFORE the write
    (_fwb_has_block), "allowed" where it was not (an allow with the same addresses made ufw skip it,
    and nothing was blocked), and "unknown" where the rules could not be read. A failed write is read
    back too: when ufw's IPv6 half fails after its IPv4 half went in, it prints only "ERROR:", and the
    IPv4 rule stays (_fwc_read_back).
    """
    res = {"added": [], "already": [], "allowed": [], "unknown": [], "failed": None, "stored_only": False,
           "left": [], "unverified": False, "tried": []}
    before = _fwb_listed_groups(server)
    skipped = _fwb_write_each(server, how, protos, res)
    if res["failed"]:
        _fwc_read_back(server, how, before, skipped, res)
    for p, fam in skipped:
        res["unknown" if before is None else "already" if _fwb_has_block(before, how[1], p, fam)
            else "allowed"].append((p, fam))
    if res["failed"] or res["allowed"] or res["unknown"]:
        _fwb_undo(server, how, res)
    return res


def _fwc_read_back(server, how, before, skipped, res):
    """After a failed write: each half of the protocols tried that is listed now and was not before is
    this call's (added, so the undo takes it out). Unread on either side: res["unverified"]."""
    after = _fwb_listed_groups(server)
    if before is None or after is None:
        res["unverified"] = True
        return
    for p in res["tried"]:
        for fam in sorted(_FWC_FAMILY_WORDS[how[2]]):
            pair = (p, fam)
            if (pair not in res["added"] and pair not in skipped and _fwb_has_block(after, how[1], p, fam)
                    and not _fwb_has_block(before, how[1], p, fam)):
                res["added"].append(pair)


# A block's family as the per-family lines name its halves.
_FWC_FAMILY_WORDS = {"both": {"v4", "v6"}, "v4": {"v4"}, "v6": {"v6"}}


def _fwb_write_each(server, how, protos, res):
    """_fwa_write_blocks' writes, one per protocol, into `res`; stops at a failure -> [(proto, family) skipped]."""
    action, spec, family, cmt = how
    skipped = []
    for p in protos:
        res["tried"].append(p)
        out, err, rc = _core.run_privileged(server, "ufw-block-port", [action, spec, p, family, cmt], timeout=20)
        for fam, what in sorted(_fwb_rule_lines(out).items()):
            (res["added"] if what == "added" else skipped).append((p, fam))
        res["stored_only"] = res["stored_only"] or "Rules updated" in (out or "")
        if rc != 0:
            res["failed"] = _fwa_tool_said(out, err, rc)
            break
    return skipped


def _fwb_undo(server, how, res):
    """Take out each rule this call added (res["added"]), one family at a time; what stays is res["left"]."""
    for p, fam in res["added"]:
        urc = _core.run_privileged(server, "ufw-delete-block-port", [how[0], how[1], p, fam], timeout=20)[2]
        if urc != 0:
            res["left"].append((p, fam))


def _fwb_listed_groups(server):
    """The rules as display groups, unannotated: listed while UFW is on, stored while off; None unread."""
    out, _err, rc = _core.run_privileged(server, "ufw-status", ["numbered"], timeout=15, sudo=None)
    if rc != 0 or not (out or "").strip():
        return None
    if _ufw_is_active(out):
        rows = [{"num": m.group(1), "detail": re.sub(r"\s{2,}", "  ", m.group(2).strip())}
                for m in map(_UFW_NUMBERED_RE.match, out.split("\n")) if m]
    else:
        stored = _fwa_read_stored(server)
        if stored is None:
            return None
        rows = _fwa_stored_rows(stored)
    return _group_ufw_rules(rows)


def _fwb_from_anywhere_in(g):
    """Whether group `g` is an inbound rule on no interface, from anywhere."""
    return ((g.get("direction") or "IN") == "IN" and not g.get("iface")
            and str(g.get("src") or "").lower() == "anywhere")


def _fwb_has_block(groups, spec, proto, fam):
    """Whether `groups` list an inbound DENY/REJECT from anywhere, on no interface, for `spec`/`proto` in `fam`."""
    want = "IPv6" if fam == "v6" else "IPv4"
    # As ufw stores and lists it: `0443` is 443, and a range is lo:hi in numbers.
    label = "%s/%s" % (":".join(str(int(x)) for x in str(spec).split(":")), proto)
    return any(g.get("action") in ("DENY", "REJECT") and _fwb_from_anywhere_in(g)
               and g.get("port_label") == label and want in (g.get("families") or ()) for g in groups or ())


def _fwb_rules_text(pairs, spec):
    """(proto, family) pairs as the answer names them: "27015/tcp (IPv4), 27015/udp (IPv6)"."""
    return ", ".join("%s/%s (%s)" % (spec, p, "IPv6" if f == "v6" else "IPv4") for p, f in pairs)


def _fwc_undo_said(res, spec, shown):
    """What the answer says about the rules THIS call added and took out again (None: nothing to say)."""
    undo = None
    if res["added"] and (res["failed"] or res["allowed"] or res["unknown"]):
        undo = (i18n.Sentence("These rules it had added could not be taken out again, so the block is partly "
                              "in place: {rules}.", rules=_fwb_rules_text(res["left"], spec)) if res["left"]
                else i18n.Sentence("The rules it had added were taken out again."))
    if res["failed"] and res["unverified"]:
        undo = i18n.Sentences(undo, i18n.Sentence(
            "The firewall could not be read back to see whether UFW wrote part of the block before it failed: "
            "check the rules for {spec}.", spec=shown))
    return undo


def _fwb_block_answer(res, spec, protos, action, family):
    """remote_ufw_block_port's (ok, message) from what _fwa_write_blocks did, said as it is."""
    shown = "%s/%s" % (spec, "+".join(protos))
    undo = _fwc_undo_said(res, spec, shown)
    if res["failed"]:
        return False, i18n.Sentences(res["failed"], undo)
    if res["allowed"]:
        return False, i18n.Sentences(i18n.Sentence(
            "Not blocked: UFW already has a rule for {rules} from anywhere that is not a block (an allow), and "
            "skipped the block for it. Delete that rule first.", rules=_fwb_rules_text(res["allowed"], spec)), undo)
    if res["unknown"]:
        return False, i18n.Sentences(i18n.Sentence(
            "Not blocked: UFW skipped the block for {rules} because a rule with the same addresses is already there, "
            "and the firewall could not be read to say whether that rule is a block or an allow.",
            rules=_fwb_rules_text(res["unknown"], spec)), undo)
    if not res["added"]:
        return True, i18n.Sentence("{spec} was already blocked; nothing was changed.", spec=shown)
    done = i18n.Sentence("Blocked {spec} ({action}, {family}).", spec=shown, action=_fwa_word(action),
                         family=_fwa_word(family))
    if res["stored_only"]:
        return True, i18n.Sentences(done, i18n.Sentence("UFW is off, so the block is stored and takes effect when "
                                                        "the firewall is turned on."))
    return True, done


def fwb_open_shadow_note(server, port, protocol, family):
    """After Open a port: a note when a block above the new allow still drops that port, else None.

    UFW takes the first rule a connection matches, and a port block goes to the TOP (prepend), so an
    allow added after it for the same port (`ufw allow 27015` beside `deny proto tcp ... 27015`, or a
    port inside a blocked range) is listed and does nothing. Read from the rules as listed; nothing
    to say when they cannot be read, or UFW is off.
    """
    groups = _fwb_listed_groups(server)
    if not groups:
        return None
    protos = ["tcp", "udp"] if protocol in ("both", "any", "", None) else [protocol]
    versions = (4, 6) if family == "both" else ((6,) if family == "v6" else (4,))
    hit = [(q, v) for q in protos for v in versions if _fwb_blocked_first(_fwb_family_view(groups, v), port, q)]
    if not hit:
        return None
    return i18n.Sentence("A block above it still drops {rules}: UFW takes the first rule that matches, so "
                         "delete that block for the port to be open.",
                         rules=", ".join("%s/%s (%s)" % (port, q, _FWB_FAMILY[v]) for q, v in hit))


def _fwb_blocked_first(view, port, proto):
    """Whether, from anywhere, the first inbound rule on no interface naming `port`/`proto` is a DENY/REJECT."""
    for g in _fwa_ordered(view):
        if _fwb_from_anywhere_in(g) and _fwb_names_port_proto(g, port, proto):
            return g.get("action") in ("DENY", "REJECT")
    return False


def _fwb_names_port_proto(g, port, proto):
    """Whether rule `g`'s To column admits `proto` ("tcp"/"udp") traffic to `port`."""
    from panel.ops import system_ops as _so
    label = g.get("proto_label")
    if label in ("TCP", "UDP") and label.lower() != proto:
        return False
    pn = str(g.get("port_num", ""))
    if not (_r12a_names_port(pn, {int(port)}) or _r13a_every_port(g, pn)):
        return False
    return not (proto == "tcp" and _so._r15a_not_tcp(g.get("src")))


# Single shell script that prints static host specs as TAB-separated KEY<TAB>VALUE
# lines. POSIX-sh compatible (no sudo needed — everything read here is world-readable),
# with fallbacks so it works on x86 servers and ARM SBCs (Raspberry Pi) alike.
# lscpu in the C locale: its "Model name:" and "CPU max MHz:" labels are translated, and the clock
# was blank on a German host. The RAM awk and df too: mawk (Ubuntu's default awk) and df print a
# number in the host's decimal comma, and the card read "7,6 GB" in an English page.
_SPECS_CMD = (
    r'''OS=$(. /etc/os-release 2>/dev/null; printf '%s' "$PRETTY_NAME"); '''
    r'''CPU=$(LC_ALL=C lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -1); '''
    r'''[ -z "$CPU" ] && CPU=$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1); '''
    r'''[ -z "$CPU" ] && CPU=$(sed -n 's/^Model[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1); '''
    r'''MAXMHZ=$(LC_ALL=C lscpu 2>/dev/null | sed -n 's/^CPU max MHz:[[:space:]]*//p' | head -1); '''
    r'''MEM=$(LC_ALL=C awk '/MemTotal/{printf "%.1f", $2/1048576}' /proc/meminfo); '''
    r'''DISK=$(LC_ALL=C df -hP / 2>/dev/null | awk 'NR==2{print $2}'); '''
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
