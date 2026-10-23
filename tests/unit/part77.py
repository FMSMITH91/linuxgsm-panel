"""Part 77 of the unit suite: the ninth review's fixes (review 1012d, builder B).

Game files, the debug report, system_ops and routes:

* Kick/Ban by name: a name holding `;`, `"` or a backtick (or a tab inside it) is refused, not
  stripped — "Bob;" stripped is "Bob", and the kick hit the innocent "Bob" while the griefer stayed.

* A console send that failed says what failed: the live console's send box and moderation answered
  every failure "is the server running?" — a timeout, a refused `sudo -u` and a missing tmux too.

* system_ops as root with no helper: a verb the helper performs itself runs its shell form (it
  handed Popen an empty list), or says it needs the helper.

* Debug report: a hand-edited non-numeric `port` in config.json prints as its type, not verbatim.

* The TLS-expiry notice for a certificate already past its date says it has expired.

* Files & Config for a server still installing sends a member to the dashboard, not through a
  page whose permission gate they fail.

HOW IT RUNS. On part12's Flask app and stubs, as part74 does; nothing reaches a transport.
"""
import datetime as _dt77
import json as _json77
import os
import pathlib as _pl77
import shutil as _shutil77
import tempfile as _tf77
from types import SimpleNamespace as NS
from urllib.parse import urlsplit as _urlsplit77

from flask import url_for as _url_for77

from unit.part01 import check
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_sf, _p9_so)
from panel.db.models import AuditLog, GameServer, RemoteServer, User, db
from panel.ops.debug_report import process as _proc77
from panel.ops.debug_report._base import Result as _Result77
from panel.ops.ssh_manager import game as _game77
from panel.security import auth as _auth77, privileged as _priv77
from panel.services import certs as _certs77

_TRIP77_START = len(_P9_TRIPPED)
_mine77 = {"hosts": [], "servers": [], "users": []}
_TMP77 = os.path.realpath(_tf77.mkdtemp(prefix="lgsm-unit-p77-"))
_ROOT77 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _cat77(lang):
    out = {}
    folder = os.path.join(_ROOT77, "translations", lang)
    for name in sorted(os.listdir(folder)):
        if name.endswith(".json"):
            with open(os.path.join(folder, name), encoding="utf-8") as fh:
                out.update(_json77.load(fh))
    return out


_CAT77 = {lg: _cat77(lg) for lg in ("es", "fr")}


def _setup77():
    with _p9.app_context():
        r = RemoteServer(name="p77-host", host="p77.example.invalid", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p77-css", short_name="p77css", game_type="css",
                        port=27077, installed=True, status="online")
        busy = GameServer(remote_id=r.id, name="p77-busy", short_name="p77busy", game_type="css",
                          port=27078, installed=False, status="installing")
        admin = User(username="p77_admin", password_hash=_auth77.hash_password("Str0ng!passw0rd-p77"),
                     display_name="p77 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gs, busy, admin])
        db.session.commit()
        _mine77["hosts"].append(r.id)
        _mine77["servers"] += [gs.id, busy.id]
        _mine77["users"].append(admin.id)
        return gs.id, busy.id, admin.id


def _cleanup77():
    with _p9.app_context():
        for i in _mine77["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
        AuditLog.query.filter(AuditLog.username.like("p77%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine77[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()
    _shutil77.rmtree(_TMP77, ignore_errors=True)


def _as_lang77(lang, call):
    """`call()` with the admin's UI language set to `lang`, then English again."""
    def _set(lg):
        with _p9.app_context():
            db.session.get(User, _ADMIN77).language = lg
            db.session.commit()
    _set(lang)
    try:
        return call()
    finally:
        _set("en")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Kick/Ban by name: a name the console cannot be given as it is
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _mod77(game_type, action, sent, result=("", "", 0), **kw):
    _p9_patch(_p9_core, "send_console_command",
              lambda s, u, cmd, **k: sent.append(cmd) or result)
    _p9_patch(_game77, "_resolve_from_console", lambda *a, **k: None)
    return _game77.moderate(None, "p77u", game_type, action, selfname="p77srv", **kw)


def _names77():
    sent = []
    got = {nm: _mod77("css", "kick", sent, target=nm) for nm in ("Bob;", 'Bo"b', "Bo`b", "Bo\tb")}
    mc = _mod77("mc", "kick", sent, target="Steve;")
    want = _game77.R19B_NAME_UNTYPABLE
    check("moderation: a Kick by a name holding `;`, `\"` or a backtick is refused, and nothing is "
          "typed (stripped, \"Bob;\" was kicked as \"Bob\": the innocent player went, the griefer "
          "stayed); a tab inside the name is the control-character refusal; Minecraft likewise",
          got == {"Bob;": (False, want), 'Bo"b': (False, want), "Bo`b": (False, want),
                  "Bo\tb": (False, _game77.R18A_NAME_CONTROL)}
          and mc == (False, want) and sent == [], repr((got, mc, sent)))
    ok = _mod77("css", "kick", sent, target="  Bob ")
    check("moderation: ...while an ordinary name, its ends trimmed as the lists trim them, is "
          "still kicked as it is (control)", ok == (True, "Done.") and sent == ['kick "Bob"'],
          repr((ok, sent)))
    check("moderation: ...and the new refusal is in the es and fr catalogs",
          all(_CAT77[lg].get(want) for lg in ("es", "fr")))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A failed console send says what failed
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _send_failures77(client, sid):
    sent = []
    timed = _mod77("css", "kick", sent, ("", "SSH command timed out", -1), target="Bob")
    gone = _mod77("css", "kick", sent, ("", "NO_SESSION", 3), target="Bob")
    banned = _mod77("rtcw", "ban", sent, ("", "sudo: a password is required", 1), num="2")
    check("moderation: a send that failed says what failed — a transport timeout or a refused "
          "sudo is the host, not \"is the server running?\"; rc 3 (no tmux session) still is the "
          "server not running",
          timed == (False, "The panel could not run that on the host: SSH command timed out")
          and banned == (False, "The panel could not run that on the host: sudo: a password is "
                                "required")
          and gone == (False, "That server isn't running, so there's no console session to send to."),
          repr((timed, gone, banned)))

    answer = [("", "sudo: a password is required", 1)]
    _p9_patch(_p9_sf, "send_console_command", lambda *a, **k: answer[0])
    fr = _as_lang77("fr", lambda: client.post("/api/command/%d" % sid, json={"command": "status"}))
    answer[0] = ("", "", 3)
    off = client.post("/api/command/%d" % sid, json={"command": "status"})
    want_fr = _CAT77["fr"]["The panel could not run that on the host: {why}"].replace(
        "{why}", "sudo: a password is required")
    check("live console send box: a refused sudo is answered with the host's own reason, in the "
          "viewer's language (it said \"Console (tmux) not accessible. Is the server running?\" for "
          "every failure, in English); no tmux session still says the server isn't running",
          fr.status_code == 200 and _p9_json(fr).get("error") == want_fr
          and off.status_code == 200 and _p9_json(off).get("error")
          == "That server isn't running, so there's no console session to send to.",
          repr((fr.status_code, _p9_json(fr), off.status_code, _p9_json(off))))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. system_ops as root, with no helper: a verb with no tool to run
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Os77(object):
    """os, with geteuid answering 0."""

    def __getattr__(self, name):
        if name == "geteuid":
            return lambda: 0
        return getattr(os, name)


def _root_verbs77():
    shells = []
    _p9_patch(_p9_so, "_helper_present", lambda: False)
    _p9_patch(_p9_so, "os", _Os77())
    _p9_patch(_p9_so, "_run_verb_shell",
              lambda cmd, timeout=30, sudo=False, whole=False: shells.append((cmd, whole))
              or ("p77-row 9", "", 0))
    f2b = _p9_so._run_verb_once("f2b-log-lines", ["2026-09-01"], 25, False)
    want_cmd = _priv77.remote_command("f2b-log-lines", ["2026-09-01"], merge_stderr=False)
    ts = _p9_so._run_verb_once("tailscale-install", [], 180, False)
    check("system_ops as root with no helper: a verb the helper performs itself runs its shell "
          "form, all-or-nothing as before (it handed Popen an empty list and answered \"command "
          "execution error\" — the fail2ban card and the auto-block read nothing)",
          f2b == ("shell", ("p77-row 9", "", 0)) and shells[:1] == [(want_cmd, True)],
          repr((f2b, shells)))
    check("system_ops as root with no helper: ...and one with no shell form says it needs the "
          "helper, running nothing (its rendering is an empty command, which exits 0)",
          ts[1][2] == -1 and "helper" in ts[1][1] and len(shells) == 1, repr((ts, shells)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Debug report: config.json's port, printed only as a number
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _port77():
    lines = {}
    for label, port in (("text", "hunter2-not-a-port"), ("number", 8443)):
        _p9_patch(_proc77, "_load_cfg", lambda _p=port: ({"port": _p, "bind_host": ""}, True))
        res = _Result77()
        _proc77._listen_lines(NS(app=None, memo=lambda key, fn: []), res, {})
        lines[label] = next((ln for ln in res.lines if ln.startswith("- **Bind**")), "")
    check("debug report: a hand-edited non-numeric port in config.json prints as its type, not "
          "verbatim (the report goes to a public issue); a number still prints as it is",
          "hunter2" not in lines["text"] and "port: config (a str value)" in lines["text"]
          and "port: config 8443 " in lines["number"], repr(lines))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The TLS-expiry notice for a certificate already expired
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cert77(days):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "p77")])
    now = _dt77.datetime.now(_dt77.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt77.timedelta(days=400))
            .not_valid_after(now + _dt77.timedelta(days=days, hours=12)).sign(key, hashes.SHA256()))
    os.makedirs(os.path.join(_TMP77, "ssl"), exist_ok=True)
    with open(os.path.join(_TMP77, "ssl", "cert.pem"), "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))


def _cert_notice77():
    said = {}
    _p9_patch(_certs77, "DATA_DIR", _pl77.Path(_TMP77))
    _p9_patch(_certs77.notifications, "notify", lambda kind, title, body: said.__setitem__("body", body))
    _at77 = _certs77._CERT_ALERTED["at"]
    for label, days in (("expired", -3), ("soon", 10)):
        said.pop("body", None)
        _cert77(days)
        _certs77._CERT_ALERTED["at"] = 0
        _certs77._maybe_alert_cert_expiring()
        said[label] = said.get("body")
    _certs77._CERT_ALERTED["at"] = _at77    # as found, not 0 (review 1022c lead)
    check("TLS expiry notice: a certificate already past its date says it has expired (it said "
          "\"expires in 0 day(s)\"); one with days left still counts them",
          said.get("expired") == "The panel's TLS certificate has expired — renew it."
          and said.get("soon") == "The panel's TLS certificate expires in 10 day(s) — renew it.",
          repr(said))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. Files & Config for a server still installing
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _installing77(client, busy):
    resp = client.get("/server/%d/files" % busy)
    loc = resp.headers.get("Location", "")
    with _p9.test_request_context("/"):
        index = _url_for77("index")
    check("Files & Config for a server still installing sends the viewer to the dashboard, not to "
          "/servers/manage, whose MANAGE_SERVERS/INSTALL_SERVER gate a member with access to the "
          "server can fail (a red \"You do not have permission\" beside the notice)",
          resp.status_code == 302 and _urlsplit77(loc).path == index, repr((resp.status_code, loc, index)))


try:
    _p9_arm(who="part77")
    _GS77, _BUSY77, _ADMIN77 = _setup77()
    _A77 = _p9_client(_ADMIN77)
    _names77()
    _send_failures77(_A77, _GS77)
    _root_verbs77()
    _port77()
    _cert_notice77()
    _installing77(_A77, _BUSY77)
finally:
    _p9_restore_all()
    _cleanup77()

check("part77: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP77_START, repr(_P9_TRIPPED[_TRIP77_START:][:6]))
