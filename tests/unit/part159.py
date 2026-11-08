"""Part 159 of the unit suite: review 1108's firewall and lock-out findings (builder A).

* MEDIUM (F1): a remote dialled by NAME is held to an IPv6 SSH way in only when the name resolves to
  IPv6 here: a provider's default global IPv6 on eth0 under an A-only name is never dialled.
* LOW (P5): a panel host booted with IPv6 off (no /proc/net/tcp6) still reads sshd's sessions, so a
  loopback viewer's IP block is decided rather than refused as unread.

HOW IT RUNS. The firewall module over part135's stand-in hosts, on part12's patcher with its
transport tripwire armed. Nothing reaches a host, sudo, ufw, a resolver or data/.
"""
import ipaddress as _ip159
import os
import struct as _st159
import tempfile as _tf159
from types import SimpleNamespace as _NS159

from unit.part01 import check
from unit.part12 import _P9_TRIPPED, _p9, _p9_patch, _p9_restore_all
from unit import part135 as _p135
from unit.part136 import _OUT136, _deny136
from unit.part154 import _proc154
from panel.ops.ssh_manager import firewall as _fw159, hosts as _hosts159, ufweval as _ue159

_TRIP159_START = len(_P9_TRIPPED)

# ════════════════════════════════════════════════════════════════════════════════════════════════
# MEDIUM (F1): a named remote's families are the ones its name resolves to
# ════════════════════════════════════════════════════════════════════════════════════════════════
_NAMED159 = _NS159(is_local=False, auth_method="key", host="h159.example.net", port=22, id=None, name="n159")
_A159 = "192.0.2.10"               # NOSONAR(S1313) - the name's A record (part135's remote address)
_AAAA159 = "2001:db8::10"          # its AAAA record, where it has one
_ULA159 = "fd00:159::10"           # a LAN host's ULA, which `ip` reports as scope global
_ADMIN_SSH159 = "22/tcp  ALLOW IN  " + _OUT136      # the hardened single-source IPv4 SSH rule
_V6_SSH159 = "22/tcp (v6)  ALLOW IN  Anywhere (v6)"


def _named159(rows, resolves, v6=("eth0", _AAAA159)):
    """_deny136 on the named remote: its name resolves to `resolves`, its session read finds `v6` on it too."""
    real = _p135._conn135

    def conn(src, server, *a, **k):
        res = real(src, server, *a, **k)
        if res is not None:
            res["addrs"] = res["addrs"] + [(v6[0], _ip159.ip_address(v6[1]), "global")]
        return res
    return _deny136(rows, server=_NAMED159,
                    extra=[(_p135, "_conn135", conn), (_hosts159, "_r28b_resolve", lambda name: list(resolves))])


_SET159 = [("ufw-default", ["deny", "incoming"])]
_f1_ok = {
    "global IPv6 on eth0, A-only name": _named159([_ADMIN_SSH159], [_A159]),
    "a ULA on eth0, A-only name": _named159([_ADMIN_SSH159], [_A159], v6=("eth0", _ULA159)),
    "an IPv4-mapped spelling of the A record only": _named159([_ADMIN_SSH159], ["::ffff:" + _A159]),
    "AAAA and A, both families let in": _named159([_ADMIN_SSH159, _V6_SSH159], [_A159, _AAAA159]),
}
check("1108 F1: on a remote dialled by a name with only an A record, a global IPv6 (or ULA) address on its "
      "interface no longer holds it to an IPv6 SSH way in: a default incoming deny beside the single-source IPv4 "
      "SSH rule is set (%s)" % ", ".join(_f1_ok),
      all(r[0] is True and r[2] == _SET159 for r in _f1_ok.values()),
      repr({k: (r[0], r[1][:160]) for k, r in _f1_ok.items()}))
_f1_cut = {
    "AAAA and A": _named159([_ADMIN_SSH159], [_A159, _AAAA159]),
    "AAAA only": _named159([_ADMIN_SSH159], [_AAAA159]),
    "IPv4-mapped AAAA beside a real AAAA": _named159([_ADMIN_SSH159], ["::ffff:" + _A159, _AAAA159]),
    "the name does not resolve here": _named159([_ADMIN_SSH159], []),
}
check("1108 F1: ...and still refused, nothing sent, where the name resolves to IPv6 (beside IPv4, alone, or "
      "beside an IPv4-mapped spelling) or does not resolve here at all, while the IPv6 list has no way in (%s)"
      % ", ".join(_f1_cut),
      all(r[0] is False and r[2] == [] and "No rule lets SSH in" in r[1] for r in _f1_cut.values()),
      repr({k: (r[0], r[1][:160]) for k, r in _f1_cut.items()}))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LOW (P5): /proc/net/tcp6 missing (IPv6 disabled in the kernel) is not "sessions unread"
# ════════════════════════════════════════════════════════════════════════════════════════════════
_HERE159 = _p135._HOST_ADDR135
_TUNNEL159 = "198.51.100.9"        # NOSONAR(S1313) - the admin's SSH session's source
_TUNNEL6_159 = "2001:db8:5::9"     # an IPv6 session, in the tcp6 table where there is one
_RANGE159 = "198.51.100.0/24"      # NOSONAR(S1313) - holds _TUNNEL159
_ELSE_RANGE159 = "203.0.113.0/24"  # NOSONAR(S1313) - holds no session


def _proc6_159(rows):
    """A /proc/net/tcp6 body: rows [(local addr, local port, remote addr, remote port, state)]."""
    def end(a, port):
        return "".join("%08X" % w for w in _st159.unpack("=4I", _ip159.ip_address(a).packed)) + ":%04X" % port
    return "  sl  local_address rem_address   st\n" + "".join(
        "   %d: %s %s %s 00000000:00000000 00:00000000 00000000  1000 0 1 1\n" % (n, end(la, lp), end(ra, rp), st)
        for n, (la, lp, ra, rp, st) in enumerate(rows))


def _tables159(fn, v4=True, v6=None):
    """fn() with _PROC_TCP pointed at a tcp table holding one SSH session (False: absent) and a tcp6
    table holding rows `v6` (None: absent, as on a kernel booted with ipv6.disable=1)."""
    with _tf159.TemporaryDirectory() as d:
        t4, t6 = os.path.join(d, "tcp"), os.path.join(d, "tcp6")
        if v4:
            with open(t4, "w") as fh:
                fh.write(_proc154([(_HERE159, 22, _TUNNEL159, 50000, "01")]))
        if v6 is not None:
            with open(t6, "w") as fh:
                fh.write(_proc6_159(v6))
        try:
            _p9_patch(_ue159, "_PROC_TCP", {4: t4, 6: t6})
            return fn()
        finally:
            _p9_restore_all()


def _inbound159(**kw):
    return _tables159(lambda: _ue159.inbound_to(frozenset({22})), **kw)


_S4_159 = (_ip159.ip_address(_TUNNEL159), _ip159.ip_address(_HERE159), 22)
_S6_159 = (_ip159.ip_address(_TUNNEL6_159), _ip159.ip_address("2001:db8::1"), 22)
_in = {
    "no tcp6 table": _inbound159(),
    "both tables": _inbound159(v6=[("2001:db8::1", 22, _TUNNEL6_159, 50001, "01")]),
    "no table at all": _inbound159(v4=False),
}
check("1108 P5: ufweval.inbound_to reads the tcp table alone where the kernel has no tcp6 one (IPv6 disabled), "
      "reads both where both exist, and is None (unread) only when no table can be opened",
      _in == {"no tcp6 table": [_S4_159], "both tables": [_S4_159, _S6_159], "no table at all": None}, repr(_in))


def _lo159(target):
    """fwc_block_ip_refusal of `target` on the panel host, from a loopback viewer, with no tcp6 table -> text."""
    host = _p135._Host135(rules=[_p135._SSH22, "5000/tcp  ALLOW IN  Anywhere"], incoming="allow")

    def run():
        with _p9.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}):  # NOSONAR(S1313)
            why = _fw159.fwc_block_ip_refusal(_p135._LOCAL135, target)
        return None if why is None else str(why)

    # _tables159's restore, once run() has answered, also ends _on135's patches: both scopes end there.
    return _p135._on135(host, lambda: _tables159(run))


_lo_else, _lo_hit = _lo159(_ELSE_RANGE159), _lo159(_RANGE159)
check("1108 P5: on a panel host with no /proc/net/tcp6, a loopback viewer may block a range none of sshd's "
      "sessions comes from, and a block of the range holding one is refused naming that session (not refused "
      "as \"can't read sshd's sessions\")",
      _lo_else is None and _lo_hit is not None and _TUNNEL159 in _lo_hit, repr((_lo_else, _lo_hit)))
