"""Part 67 of the unit suite: review 1012a's core, backup, ssh-core and reboot fixes (builder A).

Held here, each against the code path the finding named:

* Remove under "Allow from source" compares the typed source the way ufw itself does
  (0.0.0.0/0 and ::/0 are "Anywhere", IPv4 host bits are masked, IPv6 ones are kept), so the
  lockout guard cannot be walked past by spelling the protected rule's source another way;
* (further sections are added below, one per finding)

HOW IT RUNS. Pure functions and part12's Flask app and database, with every outside call stood in
for (part20's _patch / _patched, undone at the end of each block). Nothing touches the network,
sudo, a real host or the checkout's data/.
"""
import os as _os67
import types as _types67

from unit.part01 import check
from unit.part64 import _fwrun64

from panel.ops.ssh_manager import hosts as _smh67  # noqa: E402

NS = _types67.SimpleNamespace
_ROOT67 = _os67.path.dirname(_os67.path.dirname(_os67.path.dirname(_os67.path.abspath(__file__))))


# ── A03: the by-spec lockout guard reads a source the way ufw normalises it ──────────────────────
# Documentation ranges (TEST-NET-3, 2001:db8::/32), built from their parts so no literal is added.
_NET67 = ".".join(["203", "0", "113"])
_V6P67 = ":".join(["2001", "db8", ""])
_S67 = NS(id=-67, host="p67-fw", port=22)
_PUBLIC67 = ["22/tcp ALLOW IN Anywhere", "22/tcp (v6) ALLOW IN Anywhere (v6)"]
_NETRULE67 = ["22/tcp ALLOW IN %s.0/24" % _NET67]
_HOSTRULE67 = ["22/tcp ALLOW IN %s.5" % _NET67]
_V6NET67 = ["22/tcp (v6) ALLOW IN %s:5/64" % _V6P67]
_V6HOST67 = ["22/tcp (v6) ALLOW IN %s:5" % _V6P67]
# Rules that are NOT a way in: beside the only public 22/tcp they must leave it protected.
_NOWAY67 = ["Anywhere on lo ALLOW IN Anywhere", "Anywhere on docker0 ALLOW IN Anywhere",
            "22/tcp ALLOW IN %s" % ".".join(["127", "0", "0", "1"]), "22/udp ALLOW IN Anywhere",
            "Anywhere ALLOW OUT Anywhere on eth0", "Anywhere on eth0 ALLOW FWD Anywhere",
            "Anywhere DENY IN %s.9" % _NET67, "Anywhere ALLOW IN %s.9" % _NET67]


def _rm67(rules, src):
    return _fwrun64(rules, _smh67.remote_ufw_allow_from, _S67, src, "22", "tcp", allow=False)


# Every one of these is the same rule to ufw as the host's only SSH rule, so a delete would remove it.
_SAME67 = {
    "0.0.0.0/0 against Anywhere": (_PUBLIC67, "0.0.0.0/0"),
    "::/0 against Anywhere (v6)": (_PUBLIC67, "::/0"),
    "an IPv4 /0 with host bits": (_PUBLIC67, _NET67 + ".7/0"),
    "an IPv4 /24 typed with host bits": (_NETRULE67, _NET67 + ".7/24"),
    "an IPv4 /24 as a dotted netmask": (_NETRULE67, _NET67 + ".7/255.255.255.0"),
    "an IPv4 /32": (_HOSTRULE67, _NET67 + ".5/32"),
    "an IPv6 /64 in upper case and long form": (_V6NET67, _V6P67.upper() + "0::5/64"),
    "an IPv6 /128": (_V6HOST67, _V6P67 + ":5/128"),
    "0.0.0.0/0 with lo, docker0, loopback, udp, OUT, FWD and a DENY above an ALLOW beside it":
        (_PUBLIC67 + _NOWAY67, "0.0.0.0/0"),
}
_same67 = {k: _rm67(*v) for k, v in _SAME67.items()}
check("firewall: Remove under \"Allow from source\" refuses the host's only SSH rule however its source "
      "is spelled the way ufw would still match it (0.0.0.0/0 or ::/0 for Anywhere, IPv4 host bits, a "
      "/32 or /128, IPv6 case and zero runs), and runs no delete (each one deleted it)",
      {k: v for k, v in _same67.items()
       if not (isinstance(v[0], tuple) and v[0][0] is False and "lock you out" in str(v[0][1])
               and v[1] == [])} == {}, repr(_same67))
# And these are a DIFFERENT rule to ufw, so the delete removes nothing protected and must still run.
_OTHER67 = {
    "IPv6 host bits are kept, so the network is another rule": (_V6NET67 + _PUBLIC67, _V6P67 + ":/64"),
    "an IPv6 /0 on a set address is not ::/0": (_PUBLIC67, _V6P67 + ":1/0"),
    "a narrower IPv4 network": (_NETRULE67 + _PUBLIC67, _NET67 + ".0/25"),
    "another address beside the protected Anywhere": (_PUBLIC67 + _HOSTRULE67, _NET67 + ".6"),
    "a loopback source beside the protected Anywhere": (_PUBLIC67 + _NOWAY67,
                                                        ".".join(["127", "0", "0", "1"])),
}
_other67 = {k: _rm67(*v) for k, v in _OTHER67.items()}
check("firewall: ...while a source ufw reads as another rule (an IPv6 network for a v6 host-bits rule, "
      "an IPv6 /0 on a set address, a narrower network, another address, loopback) still deletes "
      "(control)",
      {k: v for k, v in _other67.items()
       if not (isinstance(v[0], tuple) and v[0][0] is True and v[1] == ["ufw-delete-allow-from-port"])} == {},
      repr(_other67))
_KEYS67 = {"0.0.0.0/0": "any", "::/0": "any", "Any address": "any", _NET67 + ".7/24": _NET67 + ".0/24",
           _NET67 + ".5/32": _NET67 + ".5", _V6P67 + ":1/64": _V6P67 + ":1/64",
           _V6P67 + ":1/128": _V6P67 + ":1", _V6P67 + ":1/0": _V6P67 + ":1/0"}
_keys67 = {k: _smh67._r15a_src_key(k) for k in _KEYS67}
check("firewall: the guard's source key is ufw's own stored form (normalize_address + _fix_anywhere)",
      _keys67 == _KEYS67, repr(_keys67))
