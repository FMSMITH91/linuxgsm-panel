"""Would UFW accept THIS connection? One answer, read the way ufw itself decides.

Part of the SSH connection manager for remote LinuxGSM servers, which also supports local
execution for running on the panel's own machine (see the package docstring for how names
resolve across its submodules).

Every firewall lock-out guard asks the same question about a different change: before the change,
and after it, does the connection the panel depends on still get in? Two review rounds of #460 found
the same class of bug each time the guards answered it field by field (the address family, then the
From column, then the interface and the To address), so the answer lives here, once:

* ufw keeps one rule list per address family, and a connection meets only its own family's list.
* In that list the FIRST rule the connection matches decides (ufw-user-input, in rule order; a
  prepended rule is first). ALLOW and LIMIT accept (a LIMIT refuses only the 7th connection in 30 s,
  so for the one connection in question it accepts); DENY and REJECT do not.
* A rule matches when its direction is IN (not OUT, not a forwarded route rule), its interface (if
  any) is the one the connection arrives on, its protocol carries TCP, its From admits the source
  address, its To admits the destination address, and its port, list, range or application profile
  (resolved from /etc/ufw/applications.d) names the destination port. A source PORT names one
  ephemeral client port, which a new connection will not reuse: it never surely matches.
* When nothing matches, the default incoming policy decides.
* Before ufw's own rules: loopback is accepted (ufw's before.rules), and in tailscaled's default
  netfilter mode its ts-input chain accepts tailscale0 (tailscale's util/linuxfw); Tailscale SSH and
  Serve are answered by tailscaled itself.

What is not known is not guessed. A connection field nobody could read, or a rule column this
cannot parse, makes the match MAYBE: a MAYBE allow does not count as the way in, and a MAYBE deny
counts as a block. So a connection is "accepted" only when every reading of the unknowns accepts it.
"""
import collections
import configparser
import ipaddress
import re
from panel.ops.ssh_manager import (_core, hosts)  # noqa: E402,F401  (module objects: the
# reference resolves at CALL time, which is what keeps a stub on the definition site
# visible to every caller — see the package docstring.


YES, NO, MAYBE = "yes", "no", "maybe"
ANY = "any"

# One connection as the firewall meets it. `src`/`dst` ip_address objects (None: not known), `dport`
# an int (None: not known), `iface` the interface it arrives on (None: not known). `what` is "ssh" (the
# panel's own SSH session to a remote) or "web" (a viewer's way into the panel's web interface).
Conn = collections.namedtuple("Conn", "version src dst dport iface what")

# A column's trailing protocol (`22/tcp`, `192.0.2.0/24/udp`, `Anywhere/gre`): ufw's supported ones.
_PROTO_SUFFIX_RE = re.compile(r"/(tcp|udp|ipv6|esp|ah|igmp|gre|vrrp)\Z", re.I)
# The attributes `ufw status numbered` prints after the From column: "(log)", "(log-all)", "(out)".
_ATTRIBS_RE = re.compile(r"\s*\((?:log|log-all|out)(?:,\s*(?:log|log-all|out))*\)\s*\Z", re.I)
# What `ufw allow OpenSSH` resolves to when the profile files themselves could not be read: the
# profile openssh-server ships (/etc/ufw/applications.d/openssh-server).
_KNOWN_APPS = {"openssh": [([(22, 22)], "tcp")]}


def _strip_proto(word):
    """(`word` without its protocol suffix, that protocol lowercased or None)."""
    m = _PROTO_SUFFIX_RE.search(word)
    return (word[:m.start()], m.group(1).lower()) if m else (word, None)


def _net(word):
    """The network an address word names (an address is its /32 or /128), else None. Mapped is IPv4."""
    try:
        net = ipaddress.ip_network(word, strict=False)
    except ValueError:
        return None
    if net.version == 6 and net.prefixlen >= 96 and net.subnet_of(ipaddress.ip_network("::ffff:0:0/96")):
        return ipaddress.ip_network((int(net.network_address) & 0xFFFFFFFF, net.prefixlen - 96))
    return net


def _ranges(text):
    """`22`, `22,80`, `6000:6007` as [(lo, hi)], or None when it is not a port list."""
    out = []
    for item in text.split(","):
        m = hosts._UFW_PORT_ITEM_RE.match(item)
        if not m:
            return None
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        out.append((min(lo, hi), max(lo, hi)))
    return out


def column(text):
    """One To / From column -> (address, ports, protocol), as ufw's get_status prints it.

    address: ANY, a network, or None (could not be read). ports: ANY, [(lo, hi)], ("app", name), or
    None. protocol: the suffix it carries, or None when it shows none. The forms are "Anywhere[/p]",
    "<port>[/p]", "<addr>[/p]", "<addr> <port>[/p]", "<app>" and "<addr> <app>"; an app's protocol
    comes from its profile, so ufw prints none.
    """
    words = str(text or "").split()
    if not words:
        return ANY, ANY, None
    first, proto = _strip_proto(words[0])
    if first.lower() == "anywhere":
        return (ANY, ANY, proto) if len(words) == 1 else (None, None, None)
    net = _net(first)
    if net is not None:
        if len(words) == 1:
            return net, ANY, proto
        rest = words[1:]
    else:
        net, rest = ANY, words
    port_text, proto = _strip_proto(" ".join(rest))
    ports = _ranges(port_text) if len(port_text.split()) == 1 else None
    if ports is not None:
        return net, ports, proto
    return net, ("app", " ".join(rest)), None


def row_spec(p):
    """What one listed rule matches (`p`: firewall._parse_ufw_rule's fields): a dict the matcher reads."""
    dst_addr, dports, dproto = column(p.get("to"))
    src_addr, sports, sproto = column(_ATTRIBS_RE.sub("", str(p.get("from") or "")))
    action = str(p.get("action") or "").upper()
    return {"action": action if action in ("ALLOW", "LIMIT", "DENY", "REJECT") else "",
            "direction": str(p.get("direction") or "IN").upper(), "iface": str(p.get("iface") or ""),
            "dst": dst_addr, "dports": dports, "src": src_addr, "sports": sports,
            "proto": dproto or sproto or ANY}


def spec_of(g):
    """A display group's rule spec: the one it was built with, or one rebuilt from its own fields."""
    spec = g.get("spec")
    if spec is not None:
        return spec
    label = str(g.get("port_label") or "")
    to = "Anywhere" if label in ("All ports", "", "—") else label
    return row_spec({"to": to, "from": g.get("src") or "Anywhere", "iface": g.get("iface"),
                     "action": g.get("action"), "direction": g.get("direction")})


def _worst(*answers):
    """NO if any is NO, else MAYBE if any is MAYBE, else YES."""
    return NO if NO in answers else (MAYBE if MAYBE in answers else YES)


def _addr_match(rule_addr, addr):
    if rule_addr == ANY:
        return YES
    if rule_addr is None or addr is None:
        return MAYBE
    if rule_addr.version != addr.version:
        return NO
    return YES if addr in rule_addr else NO


def _in_ranges(port, ranges):
    return any(lo <= port <= hi for lo, hi in ranges)


def _port_match(ports, proto, port, apps):
    """Whether TCP to `port` is named by a rule's ports (+ its protocol)."""
    if proto not in (ANY, "tcp"):
        return NO
    if ports == ANY:
        return YES
    if ports is None or port is None:
        return MAYBE
    if isinstance(ports, tuple):          # an application profile
        return _app_match(ports[1], port, apps)
    return YES if _in_ranges(port, ports) else NO


def _app_match(name, port, apps):
    """Whether application profile `name` (resolved by `apps`) names TCP to `port`; MAYBE unresolved."""
    entries = apps(name) if apps is not None else None
    if entries is None:
        return MAYBE
    return YES if any(p in (ANY, "tcp") and _in_ranges(port, r) for r, p in entries) else NO


def _iface_match(rule_iface, iface):
    """Whether a rule's interface names `iface`: exactly, or as iptables' `eth+` (every name it starts)."""
    if rule_iface.endswith("+"):
        return iface.startswith(rule_iface[:-1])
    return iface == rule_iface


def match(spec, conn, apps=None):
    """YES / NO / MAYBE: does rule `spec` match TCP connection `conn`? (`apps`: name -> entries or None)."""
    if spec["direction"] != "IN":
        return NO
    iface = YES
    if spec["iface"]:
        iface = MAYBE if conn.iface is None else (YES if _iface_match(spec["iface"], conn.iface) else NO)
    sport = YES if spec["sports"] == ANY else MAYBE
    return _worst(iface, _addr_match(spec["src"], conn.src), _addr_match(spec["dst"], conn.dst),
                  _port_match(spec["dports"], spec["proto"], conn.dport, apps), sport)


def decide(specs, conn, apps=None):
    """What decides `conn` under `specs` (ONE family's rules, in ufw's order): "allow", "deny" or "default".

    The first rule that matches decides. A rule that MAY match: a deny decides "deny" (it may be the one
    that applies), an allow decides nothing (it may not apply). Nothing decided: the default policy.
    """
    for spec in specs:
        m = match(spec, conn, apps)
        if m == NO:
            continue
        allow = spec["action"] in ("ALLOW", "LIMIT")
        if m == YES and allow:
            return "allow"
        if not allow:
            return "deny"
    return "default"


def accepts(specs, conn, default_allow=False, apps=None):
    """Whether ufw surely accepts `conn` under `specs` (decide), `default_allow` being the incoming policy."""
    how = decide(specs, conn, apps)
    return how == "allow" or (how == "default" and bool(default_allow))


def ordered_specs(view, without=None):
    """The specs of family view `view` in ufw's order (a group's place is its lowest number in it).

    `without` is a group to leave out (compared by its key): the rule list once it is deleted.
    """
    rows = sorted((g for g in view if g.get("nums")), key=lambda g: min(g["nums"]))
    if without is not None:
        key = without.get("key")
        rows = [g for g in rows if not (g is without or (key is not None and g.get("key") == key))]
    return [spec_of(g) for g in rows]


def deny_spec(lo=None, hi=None, proto=ANY, src=ANY):
    """The rule a port block (`lo`..`hi`) or an IP block (`src`, every port) puts at the top."""
    ports = ANY if lo is None else [(lo, hi if hi is not None else lo)]
    return {"action": "DENY", "direction": "IN", "iface": "", "dst": ANY, "dports": ports, "src": src,
            "sports": ANY, "proto": proto}


def exempt(conn, ts):
    """Whether `conn` is accepted before ufw's own rules are read (`ts`: the Tailscale facts, or None).

    Loopback (ufw's before.rules accept `-i lo`); tailscale0 in tailscaled's default netfilter mode,
    whose ts-input chain is jumped to ahead of ufw's; and Tailscale SSH, which tailscaled answers on its
    own addresses' port 22 before the kernel sees the packet.
    """
    if conn.iface == "lo":
        return True
    if ts is None:
        return False
    if conn.iface and conn.iface.startswith("tailscale") and ts.get("netfilter_on"):
        return True
    return bool(ts.get("ssh") and conn.dport == 22 and conn.dst is not None and in_tailnet(conn.dst))


def in_tailnet(addr):
    """Whether `addr` is in Tailscale's own ranges (100.64.0.0/10, fd7a:115c:a1e0::/48)."""
    from panel.ops import system_ops as _so
    return any(addr.version == n.version and addr in n
               for n in (ipaddress.ip_network(r) for r in _so._TAILNET_RANGES))


# ── what the host says about itself ──
# Interfaces that carry only this machine's own traffic or the NAT of its containers (as
# firewall._R14A_HOST_ONLY_IFACE_RE): a connection from another machine never arrives on one.
_HOST_ONLY_IFACE_RE = re.compile(
    r"(?:lo|docker\d*|docker_gwbridge|br-[0-9a-f]{12}|virbr\d+|veth\w+|lxcbr\d+|lxdbr\d+|cni\d+|podman\d+)\Z")


def parse_ip_addr(out):
    """`ip -o addr show` (C locale) -> [(interface, ip_address, scope)]; None when it lists nothing.

    Each line is "N: <iface>    inet[6] <addr>/<len> ... scope <scope> ..."; a VLAN or veth name
    printed "<name>@<link>" is the name. Every Linux host lists lo, so a listing without it is no reading.
    """
    rows = [row for row in map(_ip_addr_row, (out or "").splitlines()) if row is not None]
    return rows if any(r[0] == "lo" for r in rows) else None


def _ip_addr_row(line):
    """One `ip -o addr` line -> (interface, ip_address, scope), else None."""
    parts = line.split()
    if len(parts) < 4 or not parts[0].endswith(":"):
        return None
    kind = next((i for i, w in enumerate(parts[:-1]) if w in ("inet", "inet6")), None)
    if kind is None:
        return None
    try:
        addr = ipaddress.ip_interface(parts[kind + 1]).ip
    except ValueError:
        return None
    scope = parts[parts.index("scope") + 1] if "scope" in parts[:-1] else ""
    return parts[1].split("@")[0].rstrip(":"), addr, scope


def iface_of(addrs, addr):
    """The interface that holds address `addr` in `addrs` (parse_ip_addr's rows), else None."""
    if addrs is None or addr is None:
        return None
    return next((iface for iface, a, _scope in addrs if a == addr), None)


def local_addrs():
    """The panel host's own addresses (parse_ip_addr), read here; None when `ip` could not be read."""
    from panel.ops import system_ops as _so
    try:
        out, _err, rc = _so._run("export LC_ALL=C.UTF-8 LANG=C.UTF-8; unset LANGUAGE; ip -o addr show", timeout=8)
    except Exception:
        _core._log.debug("the panel host's addresses could not be read", exc_info=True)
        return None
    return parse_ip_addr(out) if rc == 0 else None


def host_families(addrs, ipv6_on):
    """The address families SSH may reach a host in.

    Those of its global addresses on an interface that takes connections from other machines (not loopback or a container bridge, not Tailscale's, which
    the Tailscale checks answer). IPv6 only where ufw handles it (`ipv6_on`). Unread: both.
    """
    if addrs is None:
        fams = {4, 6}
    else:
        fams = {a.version for iface, a, scope in addrs
                if scope == "global" and not _HOST_ONLY_IFACE_RE.match(iface) and "tailscale" not in iface}
    if not ipv6_on:
        fams.discard(6)
    return fams or {4}


def candidate_ends(addrs, src, version):
    """[(address, interface)] a connection from `src` may arrive at, when the address is not known.

    The host's addresses of that family on interfaces another machine reaches: Tailscale's alone for a
    tailnet source, and never Tailscale's for any other. [(None, None)] when there is nothing to read.
    """
    tailnet = src is not None and in_tailnet(src)
    ends = [(a, iface) for iface, a, scope in addrs or ()
            if a.version == version and scope == "global" and not _HOST_ONLY_IFACE_RE.match(iface)
            and ("tailscale" in iface) == tailnet]
    return ends or [(None, None)]


# /proc/net/tcp{,6}: the kernel's TCP sockets, readable by every account. State 01 is ESTABLISHED.
_PROC_TCP = {4: "/proc/net/tcp", 6: "/proc/net/tcp6"}


def _proc_addr(text):
    """A /proc/net/tcp "ADDR:PORT" (host-order 32-bit words in hex) -> (ip_address, port), else None."""
    import struct
    addr, _, port = text.partition(":")
    try:
        words = [int(addr[i:i + 8], 16) for i in range(0, len(addr), 8)]
        packed = struct.pack("=%dI" % len(words), *words)
        ip = ipaddress.ip_address(packed)
        return ((ip.ipv4_mapped or ip) if ip.version == 6 else ip), int(port, 16)
    except (ValueError, struct.error):
        return None


def inbound_from(peer):
    """[(local address, local port)] of the ESTABLISHED TCP connections from address `peer` to this host.

    The connection a viewer has open to a reverse proxy here while this request is being answered:
    where it arrived (the proxy's address and port) as the kernel holds it. Loopback ends are not
    counted. None when the tables could not be read.
    """
    found = []
    try:
        for table in _PROC_TCP.values():
            with open(table) as fh:
                next(fh, None)
                for line in fh:
                    cols = line.split()
                    if len(cols) < 4 or cols[3] != "01":
                        continue
                    local, remote = _proc_addr(cols[1]), _proc_addr(cols[2])
                    if local and remote and remote[0] == peer and not local[0].is_loopback:
                        found.append(local)
    except OSError:
        return None
    return sorted(set(found), key=lambda x: (x[0].version, int(x[0]), x[1]))


def tunnel_running():
    """Whether a Cloudflare Tunnel connector (a `cloudflared` process) runs on this machine.

    A tunnel connects OUT to Cloudflare and reaches the panel over loopback, so it needs no inbound
    port. Read from /proc/<pid>/comm, which every account may read (a `hidepid` /proc hides other
    accounts' processes, and then this answers False: the refusing side).
    """
    import os
    try:
        pids = [p for p in os.listdir("/proc") if p.isdecimal()]
    except OSError:
        return False
    for pid in pids:
        try:
            with open("/proc/%s/comm" % pid) as fh:
                if fh.read().strip() == "cloudflared":
                    return True
        except OSError:
            continue
    return False


def parse_app_profiles(text):
    """Read ufw application profiles (INI, /etc/ufw/applications.d) -> {name lowercased: [(ranges, proto)]}.

    A profile's `ports` is items joined by "|", each "<port>[,<port>|:<range>][/<proto>]" (no protocol:
    both). None when the text is not profiles at all.
    """
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        cp.read_string(text or "")
    except configparser.Error:
        return None
    apps = {}
    for name in cp.sections():
        entries = []
        for item in str(cp[name].get("ports", "")).split("|"):
            ports, proto = _strip_proto(item.strip())
            ranges = _ranges(ports)
            if ranges is None:
                entries = None
                break
            entries.append((ranges, proto or ANY))
        if entries:
            apps[name.lower()] = entries
    return apps


def app_profiles(server):
    """The host's application profiles (parse_app_profiles), or None when they could not be read.

    Readable by any account (0644), so no sudo; the files ufw itself reads.
    """
    try:
        out, _err, rc = _core.run_command(server, "cat /etc/ufw/applications.d/* 2>/dev/null", timeout=10, sudo=False)
    except Exception:
        _core._log.debug("ufw application profiles could not be read", exc_info=True)
        return None
    return parse_app_profiles(out) if rc == 0 else None


def app_lookup(server):
    """A name -> entries resolver for match(), reading the host's profiles once, on first use."""
    cache = {}

    def lookup(name):
        if "apps" not in cache:
            cache["apps"] = app_profiles(server)
        found = (cache["apps"] or {}).get(str(name).lower())
        return found if found is not None else _KNOWN_APPS.get(str(name).lower())
    return lookup


def ts_netfilter_on(server):
    """Whether tailscaled runs in its default netfilter mode ("on": its chains are jumped to first).

    From `tailscale debug prefs` (NetfilterMode 2; 1 is nodivert, whose chains nothing calls, and 0
    is off). False when it could not be read: then a tailscale0 rule is what lets the tailnet in.
    """
    import json
    try:
        out, _err, rc = _core.run_command(server, "tailscale debug prefs", timeout=10, sudo=False)
        return rc == 0 and json.loads(out or "{}").get("NetfilterMode") == 2
    except Exception:
        _core._log.debug("tailscale's netfilter mode could not be read", exc_info=True)
        return False
