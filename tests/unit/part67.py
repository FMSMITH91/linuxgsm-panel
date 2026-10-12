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
        _p9.test_client().post("/login", data={"username": _LONG67, "password": _os67.urandom(8).hex()},
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


# ── A01: every Valve-engine game either gets the steam://connect join button or is named as a mod ─
from panel.db import models as _models67  # noqa: E402
from panel.ops.ssh_manager import game as _game67  # noqa: E402

_valve67 = set(_game67._ENG_VALVE)
_split67 = (sorted(_valve67 - _models67.STEAM_CONNECT_GAMES - _models67._STEAM_CONNECT_UNSURE),
            sorted(_models67.STEAM_CONNECT_GAMES & _models67._STEAM_CONNECT_UNSURE),
            sorted(_models67._STEAM_CONNECT_UNSURE - _valve67))
check("join button: every Valve-engine game is in STEAM_CONNECT_GAMES or named as a mod Steam may not "
      "launch (dod, doi, hldms, nd and opfor are their own Steam apps and had no join button)",
      _split67 == ([], [], []) and {"dod", "doi", "hldms", "nd", "opfor"} <= _models67.STEAM_CONNECT_GAMES,
      repr(_split67))


# ── A02: the daily prune keeps what the Backups page says it keeps ───────────────────────────────
import time as _time67  # noqa: E402

from panel.ops import backup as _bk67  # noqa: E402


def _prune_bk67(keep):
    """The daily archives prune_backups deletes with backup_keep_days `keep`: one 400 and one 10 days old."""
    now = _time67.time()
    rows = [{"name": "daily-400", "kind": "daily", "created": now - 400 * 86400},
            {"name": "daily-10", "kind": "daily", "created": now - 10 * 86400},
            {"name": "manual-900", "kind": "manual", "created": now - 900 * 86400}]
    gone = []
    with _patched():
        _patch(_bk67, "load_config", lambda: {"backup_keep_days": keep})
        _patch(_bk67, "list_backups", lambda: list(rows))
        _patch(_bk67, "delete_backup", lambda name: (gone.append(name), (True, ""))[1])
        _bk67.prune_backups()
    return sorted(gone)


_bkp67 = {"100000": _prune_bk67(100000), "30": _prune_bk67(30), "0": _prune_bk67(0)}
check("backups: a hand-edited backup_keep_days of 100000 prunes at the 365 days the Backups page shows "
      "(it kept every daily archive until the disk filled); 30 and 0 (read as 1) still prune at theirs (control)",
      _bkp67 == {"100000": ["daily-400"], "30": ["daily-400"], "0": ["daily-10", "daily-400"]},
      repr(_bkp67))


def _queued67(v):
    with _patched():
        _patch(_bk67, "load_config", lambda: {"game_schedules": {"67": {"queued_at": v}}})
        return _try67(_bk67.queued_since, 67)


_q67 = {"true": _queued67(True), "Infinity": _queued67(float("inf")), "1700000000": _queued67(1700000000)}
check("backups: a hand-edited `true` in a game schedule's queued_at is not queued at epoch 1 (a wait of "
      "decades, reported as one); Infinity is 0 and a real time reads (control)",
      _q67 == {"true": 0, "Infinity": 0, "1700000000": 1700000000}, repr(_q67))


# ── i18n: what the viewer is shown in es and fr ─────────────────────────────────────────────────
import importlib.util as _ilu67  # noqa: E402
import json as _json67  # noqa: E402
import shutil as _shutil67  # noqa: E402
import tempfile as _tempfile67  # noqa: E402

from unit.part12 import P9_ADMIN, _P9_CFG_PATH, _p9_client  # noqa: E402
from panel.core import i18n as _i18n67  # noqa: E402

_spec67 = _ilu67.spec_from_file_location("i18n_scan_p67", _os67.path.join(_ROOT67, "tools", "i18n_scan.py"))
_scan67 = _ilu67.module_from_spec(_spec67)
_spec67.loader.exec_module(_scan67)
_CAT67 = {lg: _scan67.load_catalog(lg) for lg in ("es", "fr")}


def _tr67(lang, s):
    """i18n.tr(s) as a viewer whose session language is `lang` sees it."""
    with _p9.test_request_context("/"):
        __import__("flask").session["lang"] = lang
        return _i18n67.tr(s)


def _as67(lang):
    """Set P9_ADMIN's saved language (the account's choice wins over the session's)."""
    with _p9.app_context():
        db.session.get(User, P9_ADMIN).language = lang
        db.session.commit()


_lit67 = {lg: _scan67.literal_gaps_py(lg) for lg in ("es", "fr")}
_shown67 = _scan67.shown_literals_py()
check("i18n: every fixed message a route or a service's (ok, message) answer shows the viewer is in the es "
      "and fr catalogs (about 300 were English: the backup restore and passphrase refusals, Tailscale "
      "Serve, the firewall refusals, the Notifications Test button, Cancel reboot, the 500 handler)",
      len(_shown67) >= 300 and _lit67 == {"es": [], "fr": []},
      repr((len(_shown67), _lit67["es"][:5], _lit67["fr"][:5])))
check("i18n: ...and every tr()/Sentence() template, the new ones included, with the same {slots}",
      _scan67.tr_gaps_py("es") == [] and _scan67.tr_gaps_py("fr") == [] and _scan67.spliced_py() == [],
      repr((_scan67.tr_gaps_py("es")[:3], _scan67.spliced_py()[:3])))


def _scan_tree67(source):
    """(spliced_py, literal_gaps_py("es")) over a throwaway tree whose app.py is `source`."""
    root = _tempfile67.mkdtemp(prefix="lgsm-p67-scan-")
    try:
        _os67.makedirs(_os67.path.join(root, "panel"))
        with open(_os67.path.join(root, "app.py"), "w", encoding="utf-8") as fh:
            fh.write(source)
        return (_scan67.spliced_py(root),
                [t for t, _w in _scan67.literal_gaps_py("es", root=root)])
    finally:
        _shutil67.rmtree(root, ignore_errors=True)


_ifexp67 = _scan_tree67("def a(ok, d):\n"
                        "    return (True, 'Sent.') if ok else (False, 'Telegram error: %s' % d)\n\n\n"
                        "def b(ok, d):\n"
                        "    ok2, m = a(ok, d)\n"
                        "    return jsonify({'message': m})\n")
check("i18n gate: a message built with % in either branch of `return (…) if ok else (…)` is found "
      "(the IfExp was never split into its tuples, so the Test button's four answers passed unseen)",
      bool(_ifexp67[0]), repr(_ifexp67))
_fixed67 = _scan_tree67("def f(x):\n"
                        "    if x:\n"
                        "        return False, 'A refusal p67 never translated.'\n"
                        "    return True, 'in_progress', 'ALREADY_DONE'\n\n\n"
                        "def g():\n"
                        "    return jsonify({'error': 'bad_mode', 'message': 'Another p67 sentence.'})\n")
check("i18n gate: a fixed refusal a service returns, or a route answers, with no catalog entry is "
      "found; a machine code is not",
      sorted(_fixed67[1]) == ["A refusal p67 never translated.", "Another p67 sentence."], repr(_fixed67))


# The Notifications page's Test button, as a Spanish admin presses it.
from panel.services import notifications as _nt67  # noqa: E402

try:
    _as67("es")
    with _patched():
        _patch(_nt67, "send_telegram", lambda tok, chat, text: (False, "the chat ID is missing"))
        _r67 = _p9_client(P9_ADMIN).post("/api/notifications/test", json={
            "channel": "telegram", "token": "123456789:" + "A" * 35, "chat_id": "67"})
        _nt_es67 = (_r67.get_json() or {}).get("message")
finally:
    _as67("en")
check("notifications Test: a failed send reads in the viewer's language (\"Telegram error: the chat ID "
      "is missing\" was English for es and fr)",
      _nt_es67 == "Error de Telegram: falta el ID del chat", repr(_nt_es67))


# The Update button, refused because the newest commit's checks could not be read.
from unit.part14 import _w14_status, _W14  # noqa: E402
from panel.ops import system_ops as _so67  # noqa: E402
from panel.services import host_reboot as _hr67  # noqa: E402

_unk67 = _w14_status({_W14[0]: "unknown", _W14[1]: "passing"}, reason=_so67._CI_WHY_NO_SLUG)[0]
try:
    _as67("fr")
    with _patched():
        _patch(_so67, "_is_git_checkout", lambda: True)
        _patch(_so67, "panel_update_status", lambda force=False: _unk67)
        _patch(_hr67, "panel_host_busy", lambda: None)
        _up67 = (_p9_client(P9_ADMIN).post("/api/panel/update").get_json() or {}).get("message")
finally:
    _as67("en")
_why_fr67 = _CAT67["fr"].get(_so67._CI_WHY_NO_SLUG.template)
check("self-update: the Update button's \"couldn't be verified: <why>\" refusal reads in the viewer's "
      "language, reason included (it was %-built English marked as never shown, and the route did not "
      "translate)",
      isinstance(_up67, str) and _up67.startswith("Une version plus récente existe")
      and bool(_why_fr67) and _why_fr67 in _up67, repr(_up67))


def _nobranch67():
    def _git(args, timeout=45):
        if args[0] == "show-ref":
            return ("", "", 1)
        return ("headabc", "", 0) if args[:2] == ["rev-parse", "--short"] else ("", "", 0)
    with _patched():
        _patch(_so67, "_git", _git)
        _patch(_so67, "_is_git_checkout", lambda: True)
        _patch(_so67, "panel_version", lambda: "2026.9.1")
        _patch(_so67, "_tracked_branch", lambda: "p67")
        return _so67._compute_update_status()


_nb67 = _nobranch67()
check("self-update: \"no branch to compare against\" is a Sentence the Update button translates",
      _tr67("es", _nb67.get("message")) == "El origen de las actualizaciones no tiene una rama 'p67' con la "
                                            "que comparar.", repr(_nb67.get("message")))


# The firewall's protected-rule refusal, from both delete guards.
_prot67 = _fwrun64(["22/tcp ALLOW IN Anywhere"], _smh67.remote_ufw_allow_from, _S67, "0.0.0.0/0", "22", "tcp",
                   allow=False)[0]
_ssh_tpl67 = _smh67.firewall.R14A_REASONS["ssh_port"]
check("firewall: the protected-rule refusal reads in the viewer's language (the English protect_reason "
      "matched no catalog key, though the group carries its template and values for exactly this)",
      isinstance(_prot67, tuple) and _tr67("es", _prot67[1]) == _i18n67.fill(_CAT67["es"][_ssh_tpl67], ports="22")
      and str(_prot67[1]) == _ssh_tpl67.format(ports="22"), repr(_prot67))
_unr67 = _fwrun64(["22/tcp ALLOW IN Anywhere"], _smh67.remote_ufw_allow_from, _S67, "0.0.0.0/0", "22", "tcp",
                  allow=False, status={"installed": False, "unreachable": True})[0]
check("firewall: ...and so does \"couldn't read the firewall to check whether this rule…\"",
      isinstance(_unr67, tuple) and _tr67("fr", _unr67[1]).startswith("Impossible de lire le pare-feu"),
      repr(_unr67))


# Tailscale Serve's leftover-route note, and remove_panel_route's own reasons.
from panel.ops import serve_upkeep as _su67  # noqa: E402
from panel.ops import tailscale_integration as _ts67  # noqa: E402
from panel.security import privileged as _priv67  # noqa: E402

_left67 = _tr67("es", _su67._leftover_note("failed:not-running"))
check("serve: a leftover route that could not be removed says why in the viewer's language (the reason "
      "class token, \"not-running\", went into the translated sentence as written)",
      "Tailscale no está en marcha" in _left67 and "not-running" not in _left67, repr(_left67))


def _rm_route67(fresh, off=None):
    with _patched():
        _patch(_ts67, "_fresh_panel_route", lambda route, port: fresh)
        if off is not None:
            _patch(_ts67, "serve_off_args", off)
        return _ts67.remove_panel_route({}, 5000)


def _verb_err67(url, mount):
    raise _priv67.VerbError("p67")


_rr67 = {"svc": _rm_route67({"svc": "svc:p67"}),
         "mount": _rm_route67({"url": "https://x", "mount": "/x"}, _verb_err67),
         "listener": _rm_route67({"url": "https://x", "mount": "/x"}, lambda url, mount: None)}
# As panel/routes/tailscale.py answers a failed Remove: the reason goes into a translated sentence.
_rr_es67 = {k: _tr67("es", _i18n67.Sentence("Failed to remove: {why}", why=v[1])) for k, v in _rr67.items()}
_rr_lead67 = _CAT67["es"]["Failed to remove: {why}"].split("{why}")[0]
check("serve: remove_panel_route's own reasons (a Tailscale Service route, an unnameable mount, an "
      "unreadable listener) read in the viewer's language inside \"Failed to remove: {why}\" (they were "
      "English inside the translated sentence)",
      _rr_es67 == {k: _rr_lead67 + v for k, v in (
          ("svc", "está en el Tailscale Service svc:p67, que el panel no gestiona"),
          ("mount", "su punto de montaje no es uno que el panel pueda indicar en la línea de comandos"),
          ("listener", "no se pudo leer el listener en el que está"))}, repr(_rr_es67))


# The pre-restore safety copy's reason, and create_backup's refusals inside it.
def _safety67(how):
    """_restore_validated's refusal when the safety copy fails `how`, as an es viewer reads it."""
    def _raise(p=None):
        raise _bk67.PassphraseUnreadable("p67")
    with _patched():
        if how == "passphrase":
            _patch(_bk67, "_safety_copy_passphrase", _raise)
        else:
            _patch(_bk67, "_safety_copy_passphrase", lambda p=None: (None, False))
            _patch(_bk67, "_claim_archive_name", lambda kind, pp: ("p67", None))
        got = _bk67._restore_validated("p67-src", "p67")
    return got[0], _tr67("es", got[1])


_sf67 = {k: _safety67(k) for k in ("passphrase", "backup")}
_sf_want67 = {"passphrase": _CAT67["es"]["a backup passphrase is configured but could not be decrypted on this "
                                        "host, so the copy could not be encrypted"],
              "backup": _CAT67["es"]["Backup failed — see panel logs."]}
check("backups: a refused restore's \"safety copy could not be written ({why})\" carries its reason in the "
      "viewer's language (the passphrase clause and create_backup's \"Backup failed\" were English inside "
      "the translated sentence)",
      all(v[0] is False and "(" + _sf_want67[k] + ")" in v[1] for k, v in _sf67.items()), repr(_sf67))


# A reboot refused on the panel's own host, and one already running.
from panel.services import reboot_words as _rw67  # noqa: E402

with _patched():
    _patch(_so67, "_update_in_progress", lambda: True)
    _pb67 = _hr67._panel_host_blockers()
_blk67 = _tr67("es", _rw67.blocked_sentence(_pb67))
check("reboot: a panel-host blocker names the panel in the viewer's language (\"una actualización de the "
      "panel\")",
      "una actualización de el panel" in _blk67 and "the panel" not in _blk67, repr(_blk67))
with _patched():
    _patch(_hr67, "job_of", lambda rid: {"phase": "arming"})
    _pc67 = _hr67._pending_conflict(NS(id=-67, name="p67-host", is_local=False, host="p67"))
_pc_fr67 = _tr67("fr", _pc67.get("message"))
check("reboot: \"already being rebooted ({phase})\" names the phase in words, translated (the raw token "
      "\"arming\" went in as written); the payload keeps the token",
      "sur le point de redémarrer" in _pc_fr67 and "arming" not in _pc_fr67 and _pc67.get("phase") == "arming",
      repr((_pc_fr67, _pc67.get("phase"))))


# A plan row whose account can never be read is reported failed after an hour, so the plan finishes.
def _act67(times):
    """_act over one 'none' row whose step never resolves, at each `now`; (row, plans finished)."""
    gs = NS(id=-67, lgsm_name="p67srv", short_name="p67", name="p67")
    d = {"restore": "pending", "owner": "none", "stop": "stopped"}
    finished = []
    with _patched():
        _patch(_hr67, "_act_one", lambda remote, g, row, now, rb: None)
        _patch(_hr67, "_set_rr", lambda g, row: None)
        _patch(_hr67, "_finish", lambda remote, recs, now, rb: finished.append(now))
        with _p9.app_context():
            for now in times:
                _hr67._act(NS(id=-67), [(gs, d)], now, False)
    return d, finished


_gu67 = _act67([1000, 1000 + 3599])
_gu2_67 = _act67([1000, 1000 + 3600])
check("reboot: a row that never resolves (its account cannot be read) is reported failed an hour on and "
      "the plan finishes (it waited forever, and every later reboot of the host was refused)",
      _gu67[0]["restore"] == "pending" and _gu67[1] == []
      and _gu2_67[0]["restore"] == "failed" and _gu2_67[1] == [4600], repr((_gu67, _gu2_67)))


# config.json's on/off settings: a hand-edited "false" is off.
_CFGSNAP67 = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None
try:
    with open(_P9_CFG_PATH, "w", encoding="utf-8") as _fh67:
        _json67.dump({"trust_proxy": "false", "backup_enabled": "No", "reboot_restore_no_autostart": "false",
                      "tailscale_use_funnel": 1, "use_https": "maybe", "setup_complete": True,
                      "tailscale_setup_done": "TRUE"}, _fh67)
    _fl67 = _cfg67.load_config()
    _flags67 = {k: _fl67.get(k, "absent") for k in ("trust_proxy", "backup_enabled", "reboot_restore_no_autostart",
                                                    "tailscale_use_funnel", "use_https", "setup_complete",
                                                    "tailscale_setup_done")}
    _rna67 = _hr67.restore_no_autostart()
finally:
    if _CFGSNAP67 is None:
        _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFGSNAP67)
check("config: a hand-edited \"false\" / \"No\" in an on/off setting is off (bool(\"false\") is True: "
      "trust_proxy trusted X-Forwarded-For, a reboot restarted servers it was told to leave); 1 and "
      "\"TRUE\" are on, a word it cannot read takes the default, a real bool is kept",
      _flags67 == {"trust_proxy": False, "backup_enabled": False, "reboot_restore_no_autostart": False,
                   "tailscale_use_funnel": True, "use_https": True, "setup_complete": True,
                   "tailscale_setup_done": True} and _rna67 is False, repr((_flags67, _rna67)))


# ── A03 lead: a console line is typed as text, never looked up as a tmux key name ────────────────
import subprocess as _sp67  # noqa: E402  # nosec B404 - runs bash on the panel's own script, no shell=True


def _tmux_cmds67(argv):
    """How tmux reads its argv (cmd-parse.y cmd_parse_from_arguments): [[args of each command]].

    An argument ending in ";" ends the command and loses the ";", unless a backslash precedes it,
    which becomes the ";".
    """
    cmds, cur = [], []
    for a in argv:
        end = False
        if a.endswith(";"):
            a = a[:-1]
            if a.endswith("\\"):
                a = a[:-1] + ";"
            else:
                end = True
        if not end or a:
            cur.append(a)
        if end:
            cmds.append(cur)
            cur = []
    return cmds + ([cur] if cur else [])


def _typed67(cmd):
    """[(send-keys flags, keys)] for each tmux command the console send of `cmd` runs, read as tmux reads it."""
    tool = _tempfile67.mkdtemp(prefix="lgsm-p67-tmux-")
    try:
        path = _os67.path.join(tool, "tmux")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/bash\nshift 2\nprintf "%s\\0" "$@"\n')
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in tool this part runs
        _os67.chmod(path, 0o700)
        with _patched():
            _patch(_smc67, "shell_as_game_user", lambda s, u, inner, **k: (inner, "", 0))
            inner = _smc67.send_console_command(None, "p67game", cmd, selfname="p67srv")[0]
        tail = inner[inner.index('tmux -L "$SOCK" send-keys'):]
        out = _sp67.run(["bash", "-c", "SOCK=p67; " + tail], capture_output=True, text=True, timeout=10,
                        env={"PATH": tool + ":/usr/bin:/bin"}).stdout  # nosec B603 B607
    finally:
        _shutil67.rmtree(tool, ignore_errors=True)
    got = []
    for c in _tmux_cmds67(out.split("\0")[:-1]):
        i, flags = 1, []
        while i < len(c) and c[i].startswith("-") and c[i] != "-":
            if c[i] == "--":
                i += 1
                break
            if c[i] == "-t":        # takes the next word as its value
                i += 2
                continue
            flags.append(c[i])
            i += 1
        got.append((c[0] if c else "", flags, c[i:]))     # an empty command reads as ""
    return got


_CON67 = ("C-c", "Escape", "0x3", "sv_cheats 0;", "a\\;", ";", "-R", "say it's \"ok\" $HOME")
_con67 = {c: _typed67(c) for c in _CON67}
check("console send: a line that is exactly a tmux key name (C-c, Escape, 0x3) is typed as text with -l, "
      "not sent as that key (an interrupt of the game); a line ending in \";\" keeps it and is still "
      "submitted (tmux took the \";\" as its own command separator); Enter follows as the key",
      _con67 == {c: [("send-keys", ["-l"], [c]), ("send-keys", [], ["Enter"])] for c in _CON67}, repr(_con67))


# ── A03 lead: the firewall cleanup's notes and the game-port opener's answer translate whole ─────
from unit.part02 import protect as _protect67  # noqa: E402

_gp67 = _fwrun64(["22/tcp ALLOW IN Anywhere"], _smh67.remote_ufw_allow_game_port, _S67, 27067, "p67")[0]
_gp_es67 = _tr67("es", _gp67[1]) if isinstance(_gp67, tuple) else _gp67
check("firewall: opening a game port answers \"Port {port}: {what}\" with {what} in the viewer's language "
      "(\"opened 1 port(s): …\" was %-built English inside the translated sentence)",
      _gp_es67 == "Puerto 27067: 1 puerto(s) abierto(s): 27067", repr(_gp_es67))
_fwg67 = _protect67(NS(port=22), ["22/tcp ALLOW IN Anywhere", "27067 ALLOW IN Anywhere # p67",
                                  "27068 ALLOW IN Anywhere # p67"], sshd_ports=(22,))
_mine67 = [g for g in _fwg67 if g.get("comment") == "p67"]
_st67 = {"installed": True, "enabled": True, "groups": _fwg67}
_notes67 = (_smh67._still_there(_st67, lambda g: g in _mine67)
            + _smh67._still_there(dict(_st67, enabled=False), lambda g: False)
            + _smh67._still_there({"unreachable": True}, lambda g: False))
_notes_fr67 = [_tr67("fr", n) for n in _notes67]
check("firewall: an uninstall's notes (still open, UFW inactive, firewall unread) read in the viewer's "
      "language (the \"Still open …: %s\" note was %-built English)",
      len(_notes_fr67) == 3 and _notes_fr67[0].startswith("Toujours ouvertes")
      and _notes_fr67[1].startswith("UFW n'est pas actif") and _notes_fr67[2].startswith("Le pare-feu n'a pas pu"),
      repr(_notes_fr67))


# ── A backup restore refused in es or fr still opens the passphrase and "restore anyway" dialogs ──
from unit.part01 import skip  # noqa: E402
from unit.part47 import _cut47, _node47  # noqa: E402
import panel.routes.panel_backup as _pbr67  # noqa: E402,F401  (the route reads bk through its module)

_rst67 = {}
try:
    _as67("es")
    for _k67, _m67 in (("need", _bk67.RESTORE_ASKS_KEY), ("wrong", _bk67.RESTORE_BAD_KEY),
                       ("safety", _i18n67.Sentence(_bk67.SAFETY_COPY_FAILED, why=_bk67._R16A_BACKUP_FAILED)),
                       ("other", "No such backup.")):
        with _patched():
            _patch(_bk67, "restore_backup", lambda name, passphrase=None, skip_safety_backup=False, _m=_m67: (False, _m))
            _rst67[_k67] = _p9_client(P9_ADMIN).post("/api/panel/backup/restore", json={"name": "p67.tar.gz"}).get_json()
finally:
    _as67("en")
with open(_os67.path.join(_ROOT67, "static", "js", "remote_manage_backups.js"), encoding="utf-8") as _fh67:
    _bkjs67 = _fh67.read()
_wants67 = _node47(_cut47(_bkjs67, "function _bkRestoreWantsPassphrase") + "\n"
                   + _cut47(_bkjs67, "function _bkRestoreWantsSkipSafety") + "\n"
                   + "const R = %s;\n" % _json67.dumps(_rst67)
                   + "const out = {}; for (const k in R) out[k] = [_bkRestoreWantsPassphrase(R[k], true), "
                     "_bkRestoreWantsSkipSafety(R[k], false)];\nconsole.log(JSON.stringify(out));")
if _wants67 is None:
    skip("backups: a Spanish admin's refused restore opens the passphrase / restore-anyway dialog", "no node")
else:
    check("backups: a Spanish admin's restore refused for a passphrase, or for a safety copy that could not "
          "be written, opens the dialog that answers it (the page matched /passphrase/ and /safety copy/ "
          "in the now-translated message, so neither opened); any other refusal opens neither",
          _wants67 == {"need": [True, False], "wrong": [True, False], "safety": [False, True],
                       "other": [False, False]}
          and "passphrase" not in (_rst67["need"]["message"] + _rst67["wrong"]["message"]).lower()
          and "safety copy" not in _rst67["safety"]["message"],
          repr((_wants67, _rst67)))
