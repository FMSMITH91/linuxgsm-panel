"""Part 159 of the unit suite: review 1108's firewall and lock-out findings (builder A).

* MEDIUM (F1): a remote dialled by NAME is held to an IPv6 SSH way in only when the name resolves to
  IPv6 here: a provider's default global IPv6 on eth0 under an A-only name is never dialled.

HOW IT RUNS. The firewall module over part135's stand-in hosts, on part12's patcher with its
transport tripwire armed. Nothing reaches a host, sudo, ufw, a resolver or data/.
"""
import ipaddress as _ip159
from types import SimpleNamespace as _NS159

from unit.part01 import check
from unit.part12 import _P9_TRIPPED
from unit import part135 as _p135
from unit.part136 import _OUT136, _deny136
from panel.ops.ssh_manager import hosts as _hosts159

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
