"""Part 137 of the unit suite: the second adversarial review of #460 — one evaluator for every lock-out guard.

Two review rounds found the same class: the guards compared rule fields one at a time against
assumptions (the family, then the From column; never the interface or the To address), and the delete
guard never looked at where the panel connects from. ufweval answers the one question each guard
asks — would ufw accept THIS connection? — and each guard asks it before and after its change.

* A: the evaluator against ufw's documented behaviour (first match wins, LIMIT accepts one connection,
  interface / source / destination / protocol / port, list, range, app profile, a source port never
  surely matches, OUT and FWD never match, the default policy, a family's own list), both directions,
  and the unknowns (an unread interface: a deny may hit, an allow does not count).
* B: the readers it is given: $SSH_CONNECTION + `ip -o addr`, /proc/net/tcp, app profiles, tailscaled's
  netfilter mode and port.
* C: every guard through the evaluator, with the reviews' probe cases (HIGH-1 interface / destination,
  HIGH-2 "tighten SSH to my home IP", MEDIUM-1..5) refused, and the usability cases set (a public IP
  straight in, nginx on 443 and on 8443, Tailscale Serve, a Cloudflare Tunnel, a port-forwarded remote).
* D: the LOW findings (canonical auto-block, a half-written block read back, truthful skip answers,
  trust_proxy named, tailscaled's FLAGS port, Serve under the default netfilter mode).

HOW IT RUNS. On part135's stand-in host and patcher (part12's tripwire armed), routes on part12's app.
Nothing reaches a host, sudo, ufw or data/.
"""
import ipaddress as _ip137
import json as _json137
import os as _os137
import subprocess as _sp137
import sys as _sys137
import tempfile as _tf137
from types import SimpleNamespace as _NS137

from unit.part01 import check
from unit.part12 import (P9_ADMIN, P9_HOST, P9_LOCAL, _P9_TRIPPED, _p9_arm, _p9_client, _p9_patch,
                         _p9_restore_all)
from unit import part135 as _p135
from panel.ops.ssh_manager import _core as _core137, firewall as _fw137, hosts as _hosts137, ufweval as _ue137
from panel.routes import remote_security as _rs137
from panel.security import auth as _auth137
from panel.services import monitoring as _mon137

_TRIP137_START = len(_P9_TRIPPED)
_ROOT137 = _os137.path.dirname(_os137.path.dirname(_os137.path.dirname(_os137.path.abspath(__file__))))
_Host135, _LOCAL135, _REMOTE135, _SSH22 = _p135._Host135, _p135._LOCAL135, _p135._REMOTE135, _p135._SSH22
_SSH22V6 = "22/tcp (v6)  ALLOW IN  Anywhere (v6)"
_PANEL137 = "203.0.113.50"     # NOSONAR(S1313) - documentation addresses throughout, never dialled
_HOME137 = "192.0.2.7"         # NOSONAR(S1313)
_DST137 = "198.51.100.20"      # NOSONAR(S1313)
_HOST4 = _p135._HOST_ADDR135
_VIEWER137 = "198.51.100.7"    # NOSONAR(S1313)


def _a(text):
    return _ip137.ip_address(text)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# A. The evaluator, against ufw's own behaviour
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _groups137(rows):
    return _fw137._group_ufw_rules([{"num": str(i + 1), "detail": d} for i, d in enumerate(rows)])


def _specs137(rows, v=4):
    return _ue137.ordered_specs(_fw137._fwb_family_view(_groups137(rows), v))


def _conn137(src=_PANEL137, dst=_DST137, port=22, iface="eth0"):
    s = None if src is None else _a(src)
    d = None if dst is None else _a(dst)
    return _ue137.Conn((s or d).version if (s or d) else 4, s, d, port, iface, "ssh")


_APPS137 = _ue137.parse_app_profiles("[Nginx Full]\ntitle=Web\nports=80,443/tcp\n\n[OpenSSH]\nports=22/tcp\n"
                                     "[Mixed]\nports=6000:6007/udp|8080\n")


def _apps137(name):
    return (_APPS137 or {}).get(name.lower())


_EVAL137 = {
    # name: (rows, conn, default_allow, apps, ufw accepts it)
    "allow from anywhere": ([_SSH22], _conn137(), False, None, True),
    "first match: a deny above the allow": (["22/tcp  DENY IN  Anywhere", _SSH22], _conn137(), False, None, False),
    "first match: the allow above a deny": ([_SSH22, "22/tcp  DENY IN  Anywhere"], _conn137(), False, None, True),
    "a LIMIT accepts the one connection": (["22/tcp  LIMIT IN  Anywhere"], _conn137(), False, None, True),
    "nothing matches: default deny": (["80/tcp  ALLOW IN  Anywhere"], _conn137(), False, None, False),
    "nothing matches: default allow": (["80/tcp  ALLOW IN  Anywhere"], _conn137(), True, None, True),
    "default allow, a deny of another port": (["80/tcp  DENY IN  Anywhere"], _conn137(), True, None, True),
    "default allow, a deny of everything on eth0": (["Anywhere on eth0  DENY IN  Anywhere"], _conn137(), True, None,
                                                    False),
    "interface: a rule on eth1, the connection on eth0": (["22/tcp on eth1  ALLOW IN  Anywhere"], _conn137(), False,
                                                          None, False),
    "interface: a rule on the connection's own eth0": (["22/tcp on eth0  ALLOW IN  Anywhere"], _conn137(), False,
                                                       None, True),
    "interface: a wildcard eth+ names eth0 (iptables' +)": (["Anywhere on eth+  DENY IN  Anywhere", _SSH22],
                                                            _conn137(), False, None, False),
    "interface: ...and not tailscale0": (["Anywhere on eth+  DENY IN  Anywhere", _SSH22],
                                         _conn137(dst="100.100.1.1", iface="tailscale0"), False, None, True),  # NOSONAR(S1313)
    "interface unknown: an allow on eth0 does not count": (["22/tcp on eth0  ALLOW IN  Anywhere"],
                                                           _conn137(iface=None), False, None, False),
    "interface unknown: a deny on eth1 above may hit": (["Anywhere on eth1  DENY IN  Anywhere", _SSH22],
                                                        _conn137(iface=None), False, None, False),
    "interface known: that deny on eth1 does not hit eth0": (["Anywhere on eth1  DENY IN  Anywhere", _SSH22],
                                                             _conn137(), False, None, True),
    "loopback rule, connection on eth0": (["Anywhere on lo  ALLOW IN  Anywhere"], _conn137(), False, None, False),
    "destination: another address of the host": (["198.51.100.99 22/tcp  ALLOW IN  Anywhere"], _conn137(), False,  # NOSONAR(S1313)
                                                  None, False),
    "destination: the address it reached": (["198.51.100.20 22/tcp  ALLOW IN  Anywhere"], _conn137(), False, None,  # NOSONAR(S1313)
                                            True),
    "destination: a multicast group": (["224.0.0.251  ALLOW IN  Anywhere"], _conn137(), False, None, False),  # NOSONAR(S1313)
    "destination unknown: an address rule does not count": (["198.51.100.20 22/tcp  ALLOW IN  Anywhere"],  # NOSONAR(S1313)
                                                            _conn137(dst=None), False, None, False),
    "source: a LAN /24 the panel is outside": (["22/tcp  ALLOW IN  192.0.2.0/24"], _conn137(), False, None, False),  # NOSONAR(S1313)
    "source: the LAN /24 the panel is inside": (["22/tcp  ALLOW IN  192.0.2.0/24"], _conn137(src="192.0.2.9"),  # NOSONAR(S1313)
                                                False, None, True),
    "source: a deny of the panel's /16 above": (["Anywhere  DENY IN  203.0.0.0/16", _SSH22], _conn137(), False,  # NOSONAR(S1313)
                                                None, False),
    "source: an auto-block of another address above": (["Anywhere  DENY IN  198.51.100.9", _SSH22], _conn137(),  # NOSONAR(S1313)
                                                       False, None, True),
    "source port: one client port is no way in": (["22/tcp  ALLOW IN  203.0.113.50 51515"], _conn137(), False,  # NOSONAR(S1313)
                                                  None, False),
    "source port: a deny from it above may hit": (["22/tcp  DENY IN  203.0.113.50 51515", _SSH22], _conn137(),  # NOSONAR(S1313)
                                                  False, None, False),
    "protocol: UDP": (["22/udp  ALLOW IN  Anywhere"], _conn137(), False, None, False),
    "protocol: a source-only gre rule": (["Anywhere  ALLOW IN  203.0.113.50/gre"], _conn137(), False, None, False),  # NOSONAR(S1313)
    "every port from the panel's own address": (["Anywhere  ALLOW IN  203.0.113.50"], _conn137(), False, None, True),  # NOSONAR(S1313)
    "a port list": (["22,80,443/tcp  ALLOW IN  Anywhere"], _conn137(), False, None, True),
    "a range over the port": (["20:30/tcp  ALLOW IN  Anywhere"], _conn137(), False, None, True),
    "a range beside it": (["2000:3000/tcp  ALLOW IN  Anywhere"], _conn137(), False, None, False),
    "OUT": (["22/tcp  ALLOW OUT  Anywhere  (out)"], _conn137(), False, None, False),
    "FWD (a route rule)": (["22/tcp  ALLOW FWD  Anywhere"], _conn137(), False, None, False),
    "a logged allow": (["22/tcp  ALLOW IN  Anywhere  (log)"], _conn137(), False, None, True),
    "app: OpenSSH from the profile files": (["OpenSSH  ALLOW IN  Anywhere"], _conn137(), False, _apps137, True),
    "app: OpenSSH with the profiles unread (the shipped profile)": (["OpenSSH  ALLOW IN  Anywhere"], _conn137(),
                                                                    False, _ue137.app_lookup(None), True),
    "app: Nginx Full on 443": (["Nginx Full  ALLOW IN  Anywhere"], _conn137(port=443), False, _apps137, True),
    "app: Nginx Full on 8443": (["Nginx Full  ALLOW IN  Anywhere"], _conn137(port=8443), False, _apps137, False),
    "app: a profile's UDP range is no TCP way in": (["Mixed  ALLOW IN  Anywhere"], _conn137(port=6003), False,
                                                    _apps137, False),
    "app: a profile's port with no protocol is TCP too": (["Mixed  ALLOW IN  Anywhere"], _conn137(port=8080), False,
                                                          _apps137, True),
    "app: a profile nobody could read does not count": (["Nginx Full  ALLOW IN  Anywhere"], _conn137(port=443),
                                                        False, lambda n: None, False),
    "a row that cannot be read does not count": (["what  ALLOW IN  is this"], _conn137(), False, None, False),
}
_eval137 = {k: _ue137.accepts(_specs137(r), c, d, a) for k, (r, c, d, a, _w) in _EVAL137.items()}
check("ufweval: each connection is accepted exactly where ufw accepts it, read first match first (%d cases: %s)"
      % (len(_EVAL137), "; ".join(_EVAL137)),
      all(_eval137[k] is w for k, (_r, _c, _d, _ap, w) in _EVAL137.items()),
      repr({k: v for k, v in _eval137.items() if v is not _EVAL137[k][4]}))
_v6c = _conn137(src="2001:db8::50", dst="2001:db8::20")
_fam137 = {
    "v6 rule, v4 connection": _ue137.accepts(_specs137([_SSH22V6], 4), _conn137()),
    "v6 rule, v6 connection": _ue137.accepts(_specs137([_SSH22V6], 6), _v6c),
    "v4 rule, v6 connection": _ue137.accepts(_specs137([_SSH22], 6), _v6c),
    "IPv6 network rule (no (v6) mark), v6 connection": _ue137.accepts(
        _specs137(["22/tcp  ALLOW IN  2001:db8::/32"], 6), _v6c),
    "a v6 deny above the both-family allow, v4 connection": _ue137.accepts(
        _specs137([_SSH22, "22/tcp (v6)  DENY IN  Anywhere (v6)", _SSH22V6], 4), _conn137()),
    "...and the v6 connection": _ue137.accepts(
        _specs137(["22/tcp (v6)  DENY IN  Anywhere (v6)", _SSH22, _SSH22V6], 6), _v6c),
}
check("ufweval: a connection meets only its own family's list (a v6 rule admits no v4 connection, a v6 deny "
      "shadows nothing in v4; a rule from an IPv6 network is IPv6 without the mark)",
      _fam137 == {"v6 rule, v4 connection": False, "v6 rule, v6 connection": True, "v4 rule, v6 connection": False,
                  "IPv6 network rule (no (v6) mark), v6 connection": True,
                  "a v6 deny above the both-family allow, v4 connection": True, "...and the v6 connection": False},
      repr(_fam137))
_TS137 = {"ssh": True, "netfilter_on": True}
_ex137 = {
    "loopback": _ue137.exempt(_conn137(iface="lo"), None),
    "tailscale0, netfilter on": _ue137.exempt(_conn137(dst="100.100.1.1", iface="tailscale0"), {"netfilter_on": True}),  # NOSONAR(S1313)
    "tailscale0, netfilter off": _ue137.exempt(_conn137(dst="100.100.1.1", iface="tailscale0"), {}),  # NOSONAR(S1313)
    "Tailscale SSH, its address, 22": _ue137.exempt(_conn137(dst="100.100.1.1", iface=None), {"ssh": True}),  # NOSONAR(S1313)
    "Tailscale SSH, a public address": _ue137.exempt(_conn137(), {"ssh": True}),
    "Tailscale SSH, its address, 2222": _ue137.exempt(_conn137(dst="100.100.1.1", port=2222, iface=None),  # NOSONAR(S1313)
                                                      {"ssh": True}),
    "eth0": _ue137.exempt(_conn137(), _TS137),
}
check("ufweval: accepted ahead of ufw — loopback (before.rules), tailscale0 in tailscaled's netfilter mode \"on\" "
      "(ts-input), Tailscale SSH on its own addresses' port 22; not tailscale0 with netfilter off, not a public "
      "address or another port for Tailscale SSH, not eth0",
      _ex137 == {"loopback": True, "tailscale0, netfilter on": True, "tailscale0, netfilter off": False,
                 "Tailscale SSH, its address, 22": True, "Tailscale SSH, a public address": False,
                 "Tailscale SSH, its address, 2222": False, "eth0": False}, repr(_ex137))
_dec137 = (_ue137.decide(_specs137(["22/tcp  DENY IN  Anywhere", _SSH22]), _conn137()),
           _ue137.decide(_specs137(["80/tcp  ALLOW IN  Anywhere"]), _conn137()),
           _ue137.decide(_specs137([_SSH22]), _conn137()))
check("ufweval: what decides is told (a deny first, the default, an allow) so a refusal says which",
      _dec137 == ("deny", "default", "allow"), repr(_dec137))
_cols137 = [_ue137.column(t) for t in ("Anywhere", "Anywhere/tcp", "22/tcp", "192.0.2.0/24/udp",  # NOSONAR(S1313)
                                       "198.51.100.20 22,80/tcp", "Nginx Full", "198.51.100.20 OpenSSH",  # NOSONAR(S1313)
                                       "203.0.113.50 51515", "6000:6007/udp")]  # NOSONAR(S1313)
check("ufweval: get_status's column forms read back (Anywhere[/p], port[/p], addr[/p], addr port[/p], app, "
      "addr app, a source port, a range)",
      [(str(c[0]), c[1] if not isinstance(c[1], list) else [tuple(x) for x in c[1]], c[2]) for c in _cols137] == [
          ("any", "any", None), ("any", "any", "tcp"), ("any", [(22, 22)], "tcp"), ("192.0.2.0/24", "any", "udp"),  # NOSONAR(S1313)
          ("198.51.100.20/32", [(22, 22), (80, 80)], "tcp"), ("any", ("app", "Nginx Full"), None),  # NOSONAR(S1313)
          ("198.51.100.20/32", ("app", "OpenSSH"), None), ("203.0.113.50/32", [(51515, 51515)], None),  # NOSONAR(S1313)
          ("any", [(6000, 6007)], "udp")], repr(_cols137))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# B. What it is given, read from the host
# ════════════════════════════════════════════════════════════════════════════════════════════════
_IPADDR137 = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"  # NOSONAR(S1313)
              "2: eth0    inet 198.51.100.20/24 brd 198.51.100.255 scope global eth0\\       valid_lft forever\n"  # NOSONAR(S1313)
              "2: eth0    inet6 2001:db8::20/64 scope global \\       valid_lft forever\n"
              "3: tailscale0    inet 100.100.1.1/32 scope global tailscale0\\       valid_lft forever\n"  # NOSONAR(S1313)
              "4: eth0.10@eth0    inet 10.0.10.2/24 scope global eth0.10\\       valid_lft forever\n")  # NOSONAR(S1313)
_rows137 = _ue137.parse_ip_addr(_IPADDR137)
check("readers: `ip -o addr` reads as (interface, address, scope), a VLAN's @link dropped; a listing without lo "
      "is no reading",
      [(i, str(a), s) for i, a, s in _rows137 or ()] == [
          ("lo", "127.0.0.1", "host"), ("eth0", "198.51.100.20", "global"), ("eth0", "2001:db8::20", "global"),  # NOSONAR(S1313)
          ("tailscale0", "100.100.1.1", "global"), ("eth0.10", "10.0.10.2", "global")]  # NOSONAR(S1313)
      and _ue137.parse_ip_addr(_IPADDR137.split("\n", 1)[1]) is None
      and _ue137.iface_of(_rows137, _a(_DST137)) == "eth0"
      and _ue137.host_families(_rows137, True) == {4, 6} and _ue137.host_families(_rows137, False) == {4},
      repr(_rows137))


def _conn_read137(out, rc=0):
    try:
        _p9_arm(who="part137")
        _p9_patch(_core137, "run_command", lambda s, cmd, **k: (out, "", rc) if "SSH_CONNECTION" in cmd else ("", "", 1))
        return _hosts137._fwb_ssh_conn(_REMOTE135)
    finally:
        _p9_restore_all()


_cr137 = {
    "forwarded": _conn_read137("conn 203.0.113.50 51515 198.51.100.20 22\n" + _IPADDR137),  # NOSONAR(S1313)
    "mapped": _conn_read137("conn ::ffff:203.0.113.50 51515 ::ffff:198.51.100.20 22\n" + _IPADDR137),  # NOSONAR(S1313)
    "no session var": _conn_read137("conn \n" + _IPADDR137),
    "failed": _conn_read137("", -1),
    "no ip": _conn_read137("conn 203.0.113.50 51515 198.51.100.20 22\n"),  # NOSONAR(S1313)
}
check("readers: $SSH_CONNECTION is the session as sshd met it (a 2222 -> 22 forward reads port 22), on the "
      "interface holding that address; mapped addresses are IPv4; no variable or no answer is unread; no `ip` "
      "leaves the interface unknown",
      (str(_cr137["forwarded"]["client"]), str(_cr137["forwarded"]["server"]), _cr137["forwarded"]["port"],
       _cr137["forwarded"]["iface"]) == (_PANEL137, _DST137, 22, "eth0")
      and str(_cr137["mapped"]["client"]) == _PANEL137 and _cr137["mapped"]["iface"] == "eth0"
      and _cr137["no session var"] is None and _cr137["failed"] is None
      and _cr137["no ip"]["iface"] is None and _cr137["no ip"]["addrs"] is None, repr(_cr137))


def _proc_row(local, remote, state="01"):
    return "   0: %s %s %s 00000000:00000000 00:00000000 00000000  1000        0 12345 1\n" % (local, remote, state)


with _tf137.TemporaryDirectory(prefix="p137-") as _tcpdir137:
    _t4, _t6 = _os137.path.join(_tcpdir137, "tcp"), _os137.path.join(_tcpdir137, "tcp6")
    _hdr = "  sl  local_address rem_address   st\n"
    _addr = _auth137._proc_net_address
    with open(_t4, "w") as _fh:
        _fh.write(_hdr + _proc_row(_addr(_HOST4, 443), _addr(_VIEWER137, 50001))
                  + _proc_row(_addr(_HOST4, 443), _addr("198.51.100.8", 50002))  # NOSONAR(S1313)
                  + _proc_row(_addr(_HOST4, 9443), _addr(_VIEWER137, 50003), "06")
                  + _proc_row(_addr("127.0.0.1", 5000), _addr(_VIEWER137, 50004)))  # NOSONAR(S1313)
    with open(_t6, "w") as _fh:
        _fh.write(_hdr + _proc_row(_addr("::ffff:" + _HOST4, 8443), _addr("::ffff:" + _VIEWER137, 50005)))
    _saved137 = dict(_ue137._PROC_TCP)
    _ue137._PROC_TCP.update({4: _t4, 6: _t6})
    try:
        _seen137 = _ue137.inbound_from(_a(_VIEWER137))
    finally:
        _ue137._PROC_TCP.clear()
        _ue137._PROC_TCP.update(_saved137)
check("readers: the viewer's open connections to this host from /proc/net/tcp{,6}: ESTABLISHED only, its address "
      "only, never a loopback end, a v4-mapped row in tcp6 as the IPv4 one",
      [(str(a), p) for a, p in _seen137 or ()] == [(_HOST4, 443), (_HOST4, 8443)], repr(_seen137))
def _linear137(timeout=10):
    """ufweval's column and attribute readers against long adversarial text, in a child with a time limit."""
    code = "\n".join([
        "import json, sys, warnings", "warnings.simplefilter('ignore')", "sys.path.insert(0, sys.argv[1])",
        "from panel.ops.ssh_manager import ufweval as U",
        "for t in (' ' * 300000 + 'x', '(log,' * 60000 + 'x', '/' * 300000 + 'tcpx', 'Anywhere' + ' ' * 300000 + ')',"
        " '(' * 300000 + 'log', 'a/' * 150000 + 'tcp ' * 50000):",
        "    U.row_spec({'to': t, 'from': t, 'action': 'ALLOW', 'direction': 'IN'})",
        "print(json.dumps([U._strip_attribs('Anywhere  (log, out)'), U._strip_proto('192.0.2.0/24/udp')]))"])
    try:
        p = _sp137.run([_sys137.executable, "-c", code, _ROOT137], capture_output=True, text=True,  # nosec B603
                       timeout=timeout, check=False)
        return _json137.loads(p.stdout.strip().splitlines()[-1]) if p.returncode == 0 else p.stderr[-300:]
    except Exception as ex:  # noqa: BLE001 - TimeoutExpired, of whichever subprocess module ran it
        if type(ex).__name__ != "TimeoutExpired":
            raise
        return "timed out after %ss" % timeout


_lin137 = _linear137()
check("readers: the column, protocol and attribute readers answer 300000-character runs of spaces, slashes and "
      "\"(log,\" at once in a child with a time limit (no super-linear backtracking, Sonar S8786), and still read "
      "\"(log, out)\" and \"/udp\" (controls)",
      _lin137 == ["Anywhere", ["192.0.2.0/24", "udp"]], repr(_lin137))  # NOSONAR(S1313)


_nf137 = {}
for _k, _out, _rc in (("on", '{"NetfilterMode": 2, "RunSSH": true}', 0), ("nodivert", '{"NetfilterMode": 1}', 0),
                      ("off", '{"NetfilterMode": 0}', 0), ("unread", "", 1), ("garbage", "not json", 0)):
    try:
        _p9_arm(who="part137")
        _p9_patch(_core137, "run_command", lambda s, cmd, _o=_out, _r=_rc, **k: (_o, "", _r))
        _nf137[_k] = _ue137.ts_netfilter_on(_REMOTE135)
    finally:
        _p9_restore_all()
check("readers: tailscaled's netfilter mode is \"on\" only for NetfilterMode 2 (nodivert's chains are called by "
      "nothing); unread is not on",
      _nf137 == {"on": True, "nodivert": False, "off": False, "unread": False, "garbage": False}, repr(_nf137))
check("readers: application profiles read as ufw reads them (ports joined by |, no protocol = both); text that is "
      "not profiles is unread",
      _APPS137 == {"nginx full": [([(80, 80), (443, 443)], "tcp")], "openssh": [([(22, 22)], "tcp")],
                   "mixed": [([(6000, 6007)], "udp"), ([(8080, 8080)], "any")]}
      and _ue137.parse_app_profiles("ports=22\n[x") is None, repr(_APPS137))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# C. Every guard through the evaluator
# ════════════════════════════════════════════════════════════════════════════════════════════════
_REMOTE_ADDR = _p135._REMOTE_ADDR135
_SRV137 = _NS137(is_local=False, auth_method="key", host=_REMOTE_ADDR, port=22, id=None, name="h137")


def _rconn137(src=_PANEL137, port=22, iface="eth0", dst=_REMOTE_ADDR):
    """The remote's reading of the panel's session (hosts._fwb_ssh_conn)."""
    return {"client": _a(src), "server": _a(dst), "port": port, "iface": iface,
            "addrs": _p135._addrs135(("eth0", dst), ("eth1", "10.0.0.2"))}   # NOSONAR(S1313)


def _on137(host, fn, *a, conn=None, patches=(), **kw):
    """Run fn on part135's stand-in `host`, the remote's session read as `conn` and `patches` applied last."""
    def run(*x, **y):
        _p9_patch(_hosts137, "_fwb_ssh_conn", lambda s: conn)
        for owner, name, value in patches:
            _p9_patch(owner, name, value)
        return fn(*x, **y)
    return _p135._on135(host, run, *a, **kw)


def _deny137(rows, conn=None, patches=(), server=_SRV137, **kw):
    """Default incoming deny -> (ok, message, what was sent)."""
    host = _Host135(rules=rows, incoming="allow", ts=kw.pop("ts", (False, False)), sshd=kw.pop("sshd", ("22",)))
    res = _on137(host, _fw137.remote_ufw_set_default, server, "incoming", "deny", conn=conn, patches=patches, **kw)
    return res[0], str(res[1]), host.changes()


def _guard137(rows, conn=None, patches=(), server=_SRV137, **kw):
    """The delete guard's reading -> {(port label, scope): "PROTECTED" | "warn" | "-"}, and the groups."""
    st = _on137(_Host135(rules=rows), _fw137.remote_ufw_status, server, conn=conn, patches=patches, **kw)
    return ({(g["port_label"], g["scope"]): "PROTECTED" if g["protected"] else ("warn" if g["warn"] else "-")
             for g in st["groups"]}, st["groups"])


# HIGH-1: a rule kept to another interface or another of the host's addresses is no way in for the panel.
_h1 = {
    "eth1 interface rule": _deny137(["22/tcp on eth1  ALLOW IN  Anywhere"], _rconn137()),
    "a rule to another address": _deny137(["198.51.100.99 22/tcp  ALLOW IN  Anywhere"], _rconn137()),  # NOSONAR(S1313)
}
_h1ok = {
    "eth0 interface rule": _deny137(["22/tcp on eth0  ALLOW IN  Anywhere"], _rconn137()),
    "a rule to the address it reached": _deny137(["%s 22/tcp  ALLOW IN  Anywhere" % _REMOTE_ADDR], _rconn137()),
}
check("HIGH-1: a default incoming deny is refused where the panel's SSH session (from %s, on eth0) is let in "
      "only by a rule on ANOTHER interface (eth1) or to ANOTHER address of the host — nothing sent, the "
      "connection named" % _PANEL137,
      all(r[0] is False and r[2] == [] and "panel's own SSH connection to this host in (from 203.0.113.50 to "  # NOSONAR(S1313)
          "192.0.2.10, port 22/tcp, on eth0)" in r[1] for r in _h1.values()),  # NOSONAR(S1313)
      repr({k: r[:2] for k, r in _h1.items()}))
check("HIGH-1: ...and set where that rule is on the interface (eth0) or to the address the session reached",
      all(r[0] is True and r[2] == [("ufw-default", ["deny", "incoming"])] for r in _h1ok.values()),
      repr({k: r[:2] for k, r in _h1ok.items()}))
_ST_ETH1 = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in_eth1\n"  # NOSONAR(S1313)
_ST_ETH0 = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in_eth0\n"  # NOSONAR(S1313)
_en137 = {k: _on137(_Host135(enabled=False, stored_rules=t), _fw137.remote_ufw_set_enabled, _SRV137, True,
                    conn=_rconn137()) for k, t in (("eth1", _ST_ETH1), ("eth0", _ST_ETH0))}
check("HIGH-1 (turn on): the STORED rules are read the same way — an SSH allow kept to eth1 refuses turning UFW "
      "on, one on eth0 (where the panel's session arrives) lets it on",
      _en137["eth1"][0] is False and "on eth0" in str(_en137["eth1"][1]) and _en137["eth0"][0] is True,
      repr({k: (v[0], str(v[1])[:160]) for k, v in _en137.items()}))
# MEDIUM-5: a port-forwarded remote. The panel dials 2222; the router forwards to 22, which sshd sees.
_FWD137 = _NS137(is_local=False, auth_method="key", host=_REMOTE_ADDR, port=2222, id=None, name="f137")
_m5 = {
    "22/tcp from anywhere": _deny137([_SSH22], _rconn137(port=22), server=_FWD137, sshd=("22",)),
    "only 2222/tcp": _deny137(["2222/tcp  ALLOW IN  Anywhere"], _rconn137(port=22), server=_FWD137),
}
check("MEDIUM-5: a port-forwarded remote (dialled on 2222, sshd seeing 22) is set with 22/tcp allowed — the port the "
      "host's firewall meets — and refused with only 2222/tcp, naming port 22",
      _m5["22/tcp from anywhere"][0] is True and _m5["only 2222/tcp"][0] is False
      and "port 22/tcp" in _m5["only 2222/tcp"][1], repr({k: v[:2] for k, v in _m5.items()}))
# LOW-2: a remote dialled by name: the message says which family was measured.
_NAMED137 = _NS137(is_local=False, auth_method="key", host="box.example.net", port=22, id=None, name="n137")
_l2 = _deny137(["22/tcp  ALLOW IN  192.0.2.0/24"], _rconn137(), server=_NAMED137)  # NOSONAR(S1313)
check("LOW-2: refused for a host dialled by name, the refusal says it was measured over IPv4 and the other family "
      "is not checked",
      _l2[0] is False and "measured over IPv4" in _l2[1] and "box.example.net by name" in _l2[1], repr(_l2[:2]))

# HIGH-2: the delete guard keeps the rule the panel's own session gets in by.
_D1 = [_SSH22, "22/tcp  ALLOW IN  %s" % _HOME137, _SSH22V6]
_d1, _d1g = _guard137(_D1, _rconn137())
_d2, _ = _guard137([_SSH22, "22/tcp on eth1  ALLOW IN  Anywhere"], _rconn137())
_d_home, _ = _guard137(_D1, _rconn137(src=_HOME137))
check("HIGH-2: \"tighten SSH to my home IP\" — with an allow from %s beside the allow from Anywhere, the Anywhere one "
      "is PROTECTED while the panel connects from %s (its reason names the source); the home-IP one only warns; "
      "an eth1 rule beside it likewise" % (_HOME137, _PANEL137),
      _d1[("22/tcp", "Any address")] == "PROTECTED" and _d1[("22/tcp", _HOME137)] == "warn"
      and any("from %s" % _PANEL137 in g["protect_reason"] for g in _d1g if g["protected"])
      and _d2[("22/tcp", "Any address")] == "PROTECTED" and _d2[("22/tcp", "eth1")] == "warn",
      repr((_d1, _d2)))
check("HIGH-2: ...and once the panel itself connects from the home address, the Anywhere rule only warns (control)",
      _d_home[("22/tcp", "Any address")] == "warn" and _d_home[("22/tcp", _HOME137)] == "warn", repr(_d_home))


def _del137(rows, num, conn):
    """remote_ufw_delete_rule(num) on a stand-in with `rows` -> (ok, message, deletes sent)."""
    host = _Host135(rules=rows)
    res = _on137(host, _hosts137.remote_ufw_delete_rule, _SRV137, num, conn=conn)
    return res[0], str(res[1]), [c for c in host.changes() if c[0].startswith("ufw-delete")]


_del_any = _del137(_D1, 1, _rconn137())
_del_home = _del137(_D1, 2, _rconn137())
_del_unread = _del137(_D1, 2, None)
check("HIGH-2 (the delete itself): deleting the Anywhere rule is refused with nothing sent; the home-IP rule is "
      "deleted; with the panel's session unread every SSH rule is kept, saying so",
      _del_any[0] is False and _del_any[2] == [] and "panel's own SSH connection" in _del_any[1]
      and _del_home[0] is True and _del_home[2] != []
      and _del_unread[0] is False and "couldn't read the address" in _del_unread[1], repr((_del_any, _del_home,
                                                                                          _del_unread)))

# ── the panel's own host ──
_DUAL137 = (_ue137, "local_addrs", lambda: _p135._addrs135(("eth0", _HOST4), ("eth0", "2001:db8::1")))
_ONLY_V4 = (_ue137, "local_addrs", lambda: _p135._addrs135(("eth0", _HOST4)))


def _viewer137(addr, via_proxy, seen=()):
    """The viewer as _fwb_panel_viewer reads it, and the connections it has open to this host."""
    return [(_fw137, "_fwb_panel_viewer", lambda: (_a(addr), via_proxy)),
            (_ue137, "inbound_from", lambda peer: [(_a(x), p) for x, p in seen])]


_STD = [_SSH22, "5000/tcp  ALLOW IN  Anywhere", _SSH22V6, "5000/tcp (v6)  ALLOW IN  Anywhere (v6)"]
_m2 = _deny137(["5000/tcp  ALLOW IN  Anywhere", _SSH22V6, "5000/tcp (v6)  ALLOW IN  Anywhere (v6)"],
               server=_LOCAL135, patches=[_DUAL137] + _viewer137("2001:db8::7", False))
_m2ok = _deny137(_STD, server=_LOCAL135, patches=[_DUAL137] + _viewer137("2001:db8::7", False))
_m2v4 = _deny137([_SSH22, "5000/tcp  ALLOW IN  Anywhere"], server=_LOCAL135, patches=[_ONLY_V4])
check("MEDIUM-2: on a dual-stack panel host, SSH must stay open in BOTH families whatever the web viewer's: an IPv6 "
      "viewer with only a v6 SSH rule is refused (\"No rule lets SSH in\"); both families set; an IPv4-only host "
      "needs only the IPv4 rule",
      _m2[0] is False and "No rule lets SSH in" in _m2[1] and _m2ok[0] is True and _m2v4[0] is True,
      repr((_m2[:2], _m2ok[:2], _m2v4[:2])))
_l8, _ = _guard137(["22/tcp  ALLOW IN  203.0.113.0/24", "5000/tcp  ALLOW IN  Anywhere", _SSH22V6], server=_LOCAL135,  # NOSONAR(S1313)
                   patches=[_DUAL137] + _viewer137("2001:db8::7", False))
check("MEDIUM-2 (delete): beside a v6-only SSH rule, the panel host's only IPv4 SSH rule is PROTECTED for an IPv6 "
      "viewer too (the viewer's family says nothing about the admin's SSH)",
      _l8[("22/tcp", "203.0.113.0/24")] == "PROTECTED", repr(_l8))  # NOSONAR(S1313)

_NGX443 = [_SSH22, "443/tcp  ALLOW IN  Anywhere"]
_m1, _m1g = _guard137(_NGX443 + ["5000/tcp  ALLOW IN  Anywhere"], server=_LOCAL135, panel_ports=(5000,),
                      patches=_viewer137(_VIEWER137, True, [(_HOST4, 443)]))
check("MEDIUM-1: behind nginx on 443 the allow that serves the viewer is PROTECTED (its reason names the viewer and "
      "443), as the panel's own 5000 rule is",
      _m1[("443/tcp", "Any address")] == "PROTECTED" and _m1[("5000/tcp", "Any address")] == "PROTECTED"
      and any("port 443/tcp" in g["protect_reason"] and _VIEWER137 in g["protect_reason"] for g in _m1g),
      repr(_m1))
_m3 = {
    "Cloudflare Tunnel (cloudflared here, no inbound connection)": _deny137(
        [_SSH22], server=_LOCAL135, patches=_viewer137(_VIEWER137, True) + [(_ue137, "tunnel_running", lambda: True)]),
    "Nginx Full (the app profile)": _deny137(
        [_SSH22, "Nginx Full  ALLOW IN  Anywhere"], server=_LOCAL135,
        patches=_viewer137(_VIEWER137, True, [(_HOST4, 443)]) + [(_ue137, "app_profiles", lambda s: _APPS137)]),
    "every port from the viewer's address": _deny137(
        [_SSH22, "Anywhere  ALLOW IN  %s" % _VIEWER137], server=_LOCAL135, patches=_viewer137(_VIEWER137, False)),
}
_m3no = _deny137([_SSH22], server=_LOCAL135, patches=_viewer137(_VIEWER137, True))
check("MEDIUM-3: the normal proxy setups are set — a Cloudflare Tunnel needs no inbound port, `ufw allow 'Nginx Full'` "
      "is read through its profile, an every-port allow from the viewer counts; a local proxy with no connection "
      "from the viewer and no tunnel refuses, saying why (control)",
      all(r[0] is True for r in _m3.values()) and _m3no[0] is False and "no connection from your address" in _m3no[1],
      repr(({k: r[:2] for k, r in _m3.items()}, _m3no[:2])))
_m4 = _deny137(_NGX443, server=_LOCAL135, patches=_viewer137(_VIEWER137, True, [(_HOST4, 8443)]))
_m4ok = _deny137([_SSH22, "8443/tcp  ALLOW IN  Anywhere"], server=_LOCAL135,
                 patches=_viewer137(_VIEWER137, True, [(_HOST4, 8443)]))
_m4amb = _deny137(_NGX443, server=_LOCAL135, patches=_viewer137(_VIEWER137, True, [(_HOST4, 8443), (_HOST4, 27015)]))


def _blk137(spec, proto="tcp", server=_LOCAL135, patches=(), host=None, conn=None):
    host = host or _Host135(rules=[_SSH22, "8443/tcp  ALLOW IN  Anywhere", "27015/tcp  ALLOW IN  Anywhere"])
    res = _on137(host, _fw137.remote_ufw_block_port, server, spec, proto, "both", "deny", "", conn=conn,
                 patches=patches)
    return res[0], str(res[1]), [c for c in host.changes() if c[0] == "ufw-block-port"]


_m4b = _blk137("8443", patches=_viewer137(_VIEWER137, True, [(_HOST4, 8443)]))
_m4b_other = _blk137("27015", patches=_viewer137(_VIEWER137, True, [(_HOST4, 8443)]))
check("MEDIUM-4: nginx on 8443 (Host $host carries no port) is found from the viewer's own connection: with only 443 "
      "open the deny is refused naming 8443, with 8443 open it is set; two candidate connections refuse naming "
      "X-Forwarded-Port",
      _m4[0] is False and "port 8443/tcp" in _m4[1] and _m4ok[0] is True
      and _m4amb[0] is False and "X-Forwarded-Port" in _m4amb[1], repr((_m4[:2], _m4ok[:2], _m4amb[:2])))
check("MEDIUM-4 (port block): blocking 8443 is refused as the viewer's way in (nothing sent); 27015 is blocked "
      "(control)",
      _m4b[0] is False and _m4b[2] == [] and "lock you out of the panel" in _m4b[1] and "8443" in _m4b[1]
      and _m4b_other[0] is True and _m4b_other[2] != [], repr((_m4b, _m4b_other[:2])))
_l5 = _deny137(_STD, server=_LOCAL135, patches=[(_fw137, "_fwb_panel_viewer", lambda: (None, False))])
check("LOW-5: a viewer the panel cannot see behind a local proxy is refused, and the refusal names trust_proxy and "
      "trusted_proxy_users",
      _l5[0] is False and "trust_proxy" in _l5[1] and "trusted_proxy_users" in _l5[1], repr(_l5[:2]))
_SERVE_ADDRS = (_ue137, "local_addrs", lambda: _p135._addrs135(("eth0", _HOST4), ("tailscale0", "100.100.1.1")))  # NOSONAR(S1313)
_l8s = {
    "netfilter on, no tailscale0 rule": _deny137(
        [_SSH22], server=_LOCAL135, served=True, ts=(True, False),
        patches=[_SERVE_ADDRS, (_ue137, "ts_netfilter_on", lambda s: True)]),
    "netfilter off, no tailscale0 rule": _deny137(
        [_SSH22], server=_LOCAL135, served=True, ts=(True, False), patches=[_SERVE_ADDRS]),
    "netfilter off, 443 on tailscale0": _deny137(
        [_SSH22, "443/tcp on tailscale0  ALLOW IN  Anywhere"], server=_LOCAL135, served=True, ts=(True, False),
        patches=[_SERVE_ADDRS]),
}
check("LOW-8: published over Tailscale Serve, tailscaled's default netfilter mode lets tailscale0 in ahead of ufw, so "
      "no tailscale0 rule is demanded; with that mode not read as on it still is, and an allow of 443 on tailscale0 "
      "satisfies it",
      _l8s["netfilter on, no tailscale0 rule"][0] is True and _l8s["netfilter off, no tailscale0 rule"][0] is False
      and "Tailscale Serve" in _l8s["netfilter off, no tailscale0 rule"][1]
      and _l8s["netfilter off, 443 on tailscale0"][0] is True, repr({k: v[:2] for k, v in _l8s.items()}))
_use = {
    "a public IP straight in": _deny137(_STD[:2], server=_LOCAL135, patches=_viewer137(_VIEWER137, False)),
    "nginx on 443 with trust_proxy": _deny137(_NGX443, server=_LOCAL135,
                                             patches=_viewer137(_VIEWER137, True, [(_HOST4, 443)])),
    "nginx on 8443": _m4ok,
    "Tailscale Serve": _l8s["netfilter on, no tailscale0 rule"],
    "Cloudflare Tunnel": _m3["Cloudflare Tunnel (cloudflared here, no inbound connection)"],
    "a port-forwarded remote": _m5["22/tcp from anywhere"],
    "a remote over the tailnet, netfilter on": _deny137(
        [], _rconn137(src="100.100.9.9", dst="100.100.5.5", iface="tailscale0"),  # NOSONAR(S1313)
        server=_NS137(is_local=False, auth_method="key", host="100.100.5.5", port=22, id=None, name="t137"),  # NOSONAR(S1313)
        ts=(True, False), patches=[(_ue137, "ts_netfilter_on", lambda s: True)]),
}
check("usability: no false refusal for the setups people run (%s)" % "; ".join(_use),
      all(r[0] is True for r in _use.values()), repr({k: r[:2] for k, r in _use.items() if r[0] is not True}))

# Block IP: what only the evaluator sees. A proxy on ANOTHER machine: the viewer's address (client_ip) is not
# what the firewall meets — the proxy's is.
_ipb137 = {}
try:
    _p9_arm(who="part137")
    _p9_patch(_rs137, "tailnet_exempt_ips", lambda remote, ips: set())
    _p9_patch(_rs137, "_whitelist_networks", lambda: [])
    _p9_patch(_rs137, "_whitelisted", lambda ip: False)
    _p9_patch(_rs137, "client_ip", lambda: "203.0.113.20")   # NOSONAR(S1313) - the viewer, past the proxy
    _p9_patch(_rs137, "remote_ufw_deny_ip", lambda r, ip: (True, "ok"))
    _p9_patch(_rs137, "_follow_in_panel_gate", lambda remote, ok: None)
    _p9_patch(_rs137, "_fwb_panel_host_addrs", set)
    _p9_patch(_core137, "run_privileged", _Host135(rules=[_SSH22, "5000/tcp  ALLOW IN  Anywhere"]).run)
    _p9_patch(_core137, "run_command", lambda *a, **k: ("", "", 1))
    _p9_patch(_hosts137, "_fwb_ssh_conn", lambda s: _rconn137())
    _p9_patch(_fw137, "_fwb_panel_viewer", lambda: (_a("198.51.100.30"), False))   # NOSONAR(S1313) - the proxy
    _p9_patch(_fw137, "_r31a_panel_web_ports", lambda s, ts_running=None: [5000])
    _p9_patch(_fw137, "_panel_served_over_tailscale", lambda s: False)
    _p9_patch(_ue137, "local_addrs", lambda: _p135._addrs135(("eth0", _HOST4)))
    _p9_patch(_hosts137, "_tailscale_conn_state", lambda s: (False, False))
    _p9_patch(_hosts137, "_sshd_current_ports", lambda s: ["22"])
    _A137 = _p9_client(P9_ADMIN)
    for _k, _rid, _ip in (("proxy's /24, panel host", P9_LOCAL, "198.51.100.0/24"),   # NOSONAR(S1313)
                          ("elsewhere, panel host", P9_LOCAL, "203.0.113.128/25"),   # NOSONAR(S1313)
                          ("panel's source, remote", P9_HOST, "203.0.113.0/24")):   # NOSONAR(S1313)
        _ipb137[_k] = _A137.post("/api/remote/%d/security/block" % _rid, json={"ip": _ip}).get_json(silent=True) or {}
finally:
    _p9_restore_all()
check("IP block: on the panel host behind a proxy on ANOTHER machine, blocking that proxy's range is refused (the "
      "evaluator meets the address the firewall sees, which the viewer's own-address check cannot); another range "
      "is blocked; a remote's range over the panel's source is refused",
      _ipb137["proxy's /24, panel host"].get("success") is False
      and "lock you out of the panel" in str(_ipb137["proxy's /24, panel host"].get("message"))
      and _ipb137["elsewhere, panel host"].get("success") is True
      and _ipb137["panel's source, remote"].get("success") is False, repr(_ipb137))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# D. The LOW findings
# ════════════════════════════════════════════════════════════════════════════════════════════════
try:
    _p9_arm(who="part137")
    _p9_patch(_mon137, "tailnet_exempt_ips", lambda remote, ips: set())
    _p9_patch(_mon137, "_whitelist_networks", lambda: [_ip137.ip_network("198.51.100.5/32")])   # NOSONAR(S1313)
    _l1 = _mon137._autoblock_offenders(_REMOTE135, {"::ffff:198.51.100.5": 9, "::ffff:203.0.113.60": 3,   # NOSONAR(S1313)
                                                    "203.0.113.60": 3, "bogus": 9}, 5)   # NOSONAR(S1313)
finally:
    _p9_restore_all()
check("LOW-1: auto-block reads each offender in the form the deny is written in: a mapped spelling of a whitelisted "
      "IPv4 address is not blocked, and two spellings of one address add up (and match the blocked list's key)",
      _l1 == {"203.0.113.60"}, repr(_l1))  # NOSONAR(S1313)


class _HalfHost137(_Host135):
    """ufw-block-port: the tcp half writes its IPv4 rule into the listing, then fails with only "ERROR:"."""

    def __init__(self, readback=True, **k):
        super().__init__(**k)
        self.readback = readback

    def run(self, server, verb, args=(), **k):
        a = list(args)
        if verb == "ufw-block-port":
            self.sent.append((verb, a))
            self.rules.insert(0, "27015/tcp  DENY IN  Anywhere")
            return ("ERROR: Could not update running firewall", "", 1)
        if verb == "ufw-delete-block-port":
            self.sent.append((verb, a))
            return ("Rule deleted", "", 0)
        if verb == "ufw-status" and not self.readback and any(s[0] == "ufw-block-port" for s in self.sent):
            return ("", "SSH command timed out", -1)
        return super().run(server, verb, args, **k)


_l3 = _blk137("27015", "tcp", server=_REMOTE135, host=_HalfHost137(rules=[_SSH22]), conn=_rconn137())
_l3u = _blk137("27015", "tcp", server=_REMOTE135, host=_HalfHost137(readback=False, rules=[_SSH22]), conn=_rconn137())
check("LOW-3: a block whose IPv4 half went in before ufw failed with only \"ERROR:\" is read back, that half taken "
      "out, and the answer says so; when it cannot be read back the answer says to check, never that it was undone",
      _l3[0] is False and "taken out again" in _l3[1] and "ERROR:" in _l3[1]
      and _l3u[0] is False and "could not be read back" in _l3u[1] and "taken out again" not in _l3u[1],
      repr((_l3, _l3u)))


class _SkipHost137(_Host135):
    """ufw-block-port answers "Skipping" for both families.

    With `unread`, every listing after the guard's own first read (the one the write is judged from,
    before and after) does not answer.
    """

    def __init__(self, unread=False, **k):
        super().__init__(**k)
        self.unread, self.listed = unread, 0

    def run(self, server, verb, args=(), **k):
        if verb == "ufw-block-port":
            self.sent.append((verb, list(args)))
            return ("Skipping inserting existing rule\nSkipping inserting existing rule (v6)\n", "", 0)
        if verb == "ufw-status" and list(args)[:1] == ["numbered"]:
            self.listed += 1
            if self.unread and self.listed > 1:
                return ("", "SSH command timed out", -1)
        return super().run(server, verb, args, **k)


_l4z = _blk137("07015", "tcp", server=_REMOTE135, conn=_rconn137(), host=_SkipHost137(
    rules=[_SSH22, "7015/tcp  DENY IN  Anywhere", "7015/tcp (v6)  DENY IN  Anywhere (v6)"]))
_l7 = _blk137("27015", "tcp", server=_REMOTE135, conn=_rconn137(), host=_SkipHost137(unread=True, rules=[_SSH22]))
check("LOW-4/LOW-7: a skip of `07015` over a listed 7015 block reads \"already blocked\"; a skip the listing could "
      "not explain says it could not be read, never \"an allow\"",
      _l4z[0] is True and "already blocked" in _l4z[1]
      and _l7[0] is False and "could not be read" in _l7[1] and "(an allow)" not in _l7[1], repr((_l4z[:2], _l7[:2])))
_tsf137 = {}
for _k, _txt in (("FLAGS --port=", 'PORT="41641"\nFLAGS="--port=41700"\n'), ("FLAGS --port N", 'FLAGS="--port 41710"\n'),
                 ("export PORT", "export PORT=41720\n"), ("FLAGS without a port", 'PORT=41730\nFLAGS="--tun=x"\n')):
    try:
        _p9_arm(who="part137")
        _p9_patch(_core137, "run_command", lambda s, cmd, _t=_txt, **k: (_t, "", 0))
        _tsf137[_k] = _fw137._fwb_tailscaled_port(_REMOTE135)
    finally:
        _p9_restore_all()
check("LOW-6: tailscaled's port is read from FLAGS' --port (it comes after --port=${PORT}) and from `export PORT=`",
      _tsf137 == {"FLAGS --port=": 41700, "FLAGS --port N": 41710, "export PORT": 41720, "FLAGS without a port": 41730},
      repr(_tsf137))

check("part137: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP137_START, repr(_P9_TRIPPED[_TRIP137_START:][:3]))
