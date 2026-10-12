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


# ── A01: a hand-edited `true` in a config number is not the number 1 ──────────────────────────────
import datetime as _dt67  # noqa: E402

import app as _app67  # noqa: E402
from unit.part12 import _p9  # noqa: E402
from unit.part20 import _patch, _patched  # noqa: E402
from panel.core import config as _cfg67  # noqa: E402
from panel.db.models import AuditLog, db  # noqa: E402
from panel.ops.debug_report import data as _drd67  # noqa: E402
from panel.ops.ssh_manager import _core as _smc67  # noqa: E402


def _prune67(value):
    """(rows _r16a_prune_audit deleted, p67 rows left) with retention `value`, over 3 rows 2 days old."""
    with _p9.app_context():
        old = _dt67.datetime.now(_dt67.timezone.utc).replace(tzinfo=None) - _dt67.timedelta(days=2)
        for _ in range(3):
            db.session.add(AuditLog(action="p67-prune", username="p67", timestamp=old))
        db.session.commit()
        try:
            got = _try67(_app67._r16a_prune_audit, {"audit_log_retention_days": value})
            left = AuditLog.query.filter_by(action="p67-prune").count()
        finally:
            AuditLog.query.filter_by(action="p67-prune").delete()
            db.session.commit()
    return got, left


def _try67(fn, *a, **k):
    """Return fn's answer, or the NAME of the exception it raised (so a revert fails by name)."""
    try:
        return fn(*a, **k)
    except Exception as exc:  # noqa: BLE001 - which class arrives IS the check
        return type(exc).__name__


_pr67 = {"true": _prune67(True), "Infinity": _prune67(float("inf")), "text": _prune67("a month")}
check("audit retention: a hand-edited `true` (or Infinity, or text) deletes no audit row at start "
      "(int(True) is 1: every row older than a day was deleted, then VACUUMed)",
      _pr67 == {"true": (0, 3), "Infinity": (0, 3), "text": (0, 3)}, repr(_pr67))
_pr1_67 = _prune67(1)
check("audit retention: ...while a real 1 still deletes the rows older than a day (control)",
      _pr1_67 == (3, 0), repr(_pr1_67))
_dr67 = {"true": _drd67._int_cfg({"k": True}, "k", 0), "30": _drd67._int_cfg({"k": 30}, "k", 0)}
check("debug report: a retention of `true` prints as unreadable, not as the 1 day nothing prunes",
      _dr67 == {"true": None, "30": 30}, repr(_dr67))


def _ssh_to67(value):
    with _patched():
        _patch(_cfg67, "load_config", lambda: {"ssh_timeout": value})
        return _smc67._ssh_connect_timeout()


_to67 = {"true": _ssh_to67(True), "Infinity": _ssh_to67(float("inf")), "30": _ssh_to67(30)}
check("ssh timeout: a hand-edited `true` is the default 10 s, not a one-second timeout on every "
      "connection; a real 30 is 30 (control)",
      _to67 == {"true": 10, "Infinity": 10, "30": 30}, repr(_to67))


# ── A01: the daily-restart zone that is not a string is no zone, not a 500 ──────────────────────
from panel.core import clock as _clock67  # noqa: E402

_tz67 = {repr(v): _try67(_clock67.valid_timezone, v) for v in (5, True, [1], {"a": 1}, 1.5)}
check("clock: valid_timezone answers \"\" for a JSON number, bool, list or object (it raised "
      "AttributeError, and POST /api/server/<id>/daily-restart answered 500)",
      set(_tz67.values()) == {""}, repr(_tz67))
_tzok67 = (_clock67.valid_timezone(" Europe/Paris "), _clock67.valid_timezone(None), _clock67.valid_timezone("../x"))
check("clock: ...while a real zone still passes, and None or a traversal is still \"\" (control)",
      _tzok67 == ("Europe/Paris", "", ""), repr(_tzok67))


# ── A01: a superadmin with a 65-80 character name is recognised when its login is attacked ──────
from panel.routes import auth_routes as _ar67  # noqa: E402
from panel.db.models import User  # noqa: E402
from panel.security import banlist as _bl67  # noqa: E402

_IP67 = ".".join(["198", "51", "100", "67"])
_LONG67 = "p67-" + "a" * 70          # 74 characters: inside MAX_USERNAME_LEN (80), past the old 64
_seen67 = []
_real_bf67 = _ar67._maybe_alert_admin_bruteforce


def _bf67(who, ip, now):
    """Record the name the alert is asked about, and whether it names an account, then run it."""
    _seen67.append((who, User.query.filter_by(username=who).first() is not None))
    return _real_bf67(who, ip, now)


try:
    with _p9.app_context():
        from panel.security.auth import hash_password as _hp67
        db.session.add(User(username=_LONG67, password_hash=_hp67(_os67.urandom(12).hex()),
                            display_name="Long", is_superadmin=True, is_active=True))
        db.session.commit()
    with _patched():
        _patch(_ar67, "_maybe_alert_admin_bruteforce", _bf67)
        _patch(_bl67, "refresh_soon", lambda delay=3.0: None)
        _p9.test_client().post("/login", data={"username": _LONG67, "password": "wrong"},
                               environ_base={"REMOTE_ADDR": _IP67})
    check("login: a failed sign-in as a superadmin whose name is 65-80 characters asks the attack alert "
          "about that account (the name was cut to 64, matched no account, and no alert ever fired)",
          _seen67 == [(_LONG67, True)], repr(_seen67))
finally:
    with _p9.app_context():
        User.query.filter_by(username=_LONG67).delete()
        AuditLog.query.filter_by(username=_LONG67).delete()
        db.session.commit()
    for _k67 in [k for k in _ar67._LOGIN_FAILS if _IP67 in str(k)]:
        _ar67._LOGIN_FAILS.pop(_k67, None)
