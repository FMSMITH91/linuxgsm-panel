"""Part 69 of the unit suite: the sixth review's routes, tools, page and i18n fixes (builder C).

Held here, each against the code path the finding named:

* a restore whose safety copy cannot be written reaches "Restore anyway" in Spanish and French:
  the page reads a machine-readable `needs`, never the (translated) message's words.
* every message a route answers — a literal, a module constant, or a service's (ok, message) — is
  in both catalogs, and the gate that says so is shown to catch what it used to miss.
* routes, tools and pages, each shown to catch the shape it missed.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on this part's own fixtures.
"""
import json as _json69
import os
import pathlib as _pl69

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_trip)
from unit.part47 import _cut47, _node47
from panel.db.models import User as _User69, db as _db69
from panel.ops import backup as _bk69, system_ops as _so69

_JS69 = os.path.join(_root, "static", "js")


_TRIP69_START = len(_P9_TRIPPED)


def _arm69():
    """part12's transport tripwire, armed at the top of every block below that drives a route.

    part12 disarmed its own when it ended, and each block stubs only the leaf it names: one more
    host call on a passing path (paramiko to P9_HOST, a local shell on the panel host, as root on
    CI's root leg) would have run for real with this part green (review 1012b; part68 does this).
    Undone by each block's _p9_restore_all().
    """
    _p9_arm(who="part69")
    for _n69 in ("run_command", "shell_as_game_user", "run_privileged"):
        _p9_patch(_p9_core, _n69, _p9_trip(_n69))



def _read69(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _node69(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _lang69(lang):
    """The admin's saved language (the account's choice wins over the session's)."""
    with _p9.app_context():
        _db69.session.get(_User69, P9_ADMIN).language = lang
        _db69.session.commit()


# The admin's language as the part found it (it may be None): put back after each block, not "en"
# (review 1012b), so a later part reading it sees what it left.
with _p9.app_context():
    _LANG69_WAS = _db69.session.get(_User69, P9_ADMIN).language


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Restore, in Spanish: the safety copy fails, and "Restore anyway" still opens
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #423 translated the restore route's message. The page found the safety-copy refusal with
# /safety copy/i and the passphrase refusal with /passphrase/i — English words a Spanish or French
# message does not have — so the "Restore anyway" dialog (the only way to send skip_safety_backup)
# never opened, and each retry got the same refusal. The route now answers `needs`.
_PLAIN69 = "panel-backup-20260101-000000-manual.tar.gz"
_ENC69 = _PLAIN69 + ".enc"
_said69 = {}
try:
    _arm69()
    _p9_patch(_bk69, "_safe_path", lambda name: _pl69.Path("/nonexistent-r16c") / str(name))
    _p9_patch(_bk69, "_archive_members_refusal", lambda src: "")
    _p9_patch(_bk69, "_restore_db_refusal", lambda src: "")
    _p9_patch(_bk69, "_take_safety_copy", lambda pp: (False, "No space left on device", False))
    _p9_patch(_bk69, "_stage_archive", lambda src: None)
    _p9_patch(_bk69, "get_passphrase", lambda: "")
    _p9_patch(_so69, "_update_in_progress", lambda: False)

    def _decrypt69(src, dest, pp):
        """No passphrase: required; any other: it opens (the archive is the stand-in path)."""
        if not pp:
            return False, _bk69._R16C_LOCKED_NO_KEY
        return True, ""
    _p9_patch(_bk69, "_decrypt_archive", _decrypt69)
    for _L69 in ("es", "fr", "en"):
        _lang69(_L69)
        _c69 = _p9_client(P9_ADMIN)
        _said69[_L69] = {
            "safety": _p9_json(_c69.post("/api/panel/backup/restore", json={"name": _PLAIN69})),
            "skipped": _p9_json(_c69.post("/api/panel/backup/restore",
                                          json={"name": _PLAIN69, "skip_safety_backup": True})),
            "pass": _p9_json(_c69.post("/api/panel/backup/restore", json={"name": _ENC69})),
            "pass_ok": _p9_json(_c69.post("/api/panel/backup/restore",
                                          json={"name": _ENC69, "passphrase": "x" * 12})),
        }
finally:
    _lang69(_LANG69_WAS)
    _p9_restore_all()

_es69 = _said69.get("es", {})
check("restore (es): the safety-copy refusal is Spanish and says `needs: skip_safety`; the passphrase "
      "refusal says `needs: passphrase`; the restore that skipped the copy, and one that is not a "
      "refusal the page asks about, say neither",
      _es69.get("safety", {}).get("needs") == "skip_safety"
      and "safety copy" not in _es69.get("safety", {}).get("message", "safety copy")
      and _es69.get("pass", {}).get("needs") == "passphrase"
      and "passphrase" not in _es69.get("pass", {}).get("message", "passphrase")
      and _es69.get("pass_ok", {}).get("needs") == "skip_safety"
      and _es69.get("skipped", {}).get("needs") == ""
      and _es69.get("skipped", {}).get("success") is False, repr(_es69)[:900])
check("restore (fr, en): the same `needs` whatever the language (it is decided before translation)",
      all(_said69.get(_L69, {}).get(k, {}).get("needs") == _es69.get(k, {}).get("needs", "?")
          for _L69 in ("fr", "en") for k in ("safety", "skipped", "pass", "pass_ok")),
      repr({_L69: {k: v.get("needs") for k, v in _said69.get(_L69, {}).items()} for _L69 in _said69}))

# ...and the page, driven with those very answers: Restore → "No safety copy" → Restore anyway posts
# skip_safety_backup; an encrypted archive → "Passphrase needed" → the copy fails → "No safety copy"
# → Restore anyway posts the passphrase that worked AND the skip.
_BK69 = _read69(_JS69, "remote_manage_backups.js")
_name69 = "restore page (es): the refusals open their dialogs"
_prog69 = (
    "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = '';\n"
    "var dialogs = [], posted = [], answers = [], msgs = [];\n"
    "global.bkMsg = (m) => msgs.push(m);\n"
    "global.fetch = (url, o) => { posted.push(JSON.parse(o.body));\n"
    "  return Promise.resolve({json: () => Promise.resolve(answers.shift() || {success: false, message: 'x'})}); };\n"
    "global.confirmDialog = (o) => { dialogs.push(o.title);\n"
    "  o.onConfirm(TYPED, {close(){}, error(m){ dialogs.push('error:' + m); }}); };\n"
    "global.setTimeout = () => 0; global.location = {reload(){}};\n"
    + "".join(_cut47(_BK69, h) + "\n" for h in (
        "function _bkRestore(", "function _bkRestoreWantsPassphrase(", "function _bkRestoreWantsSkipSafety(",
        "function _bkRestoreDone(", "function _bkAskSkipSafety(", "function _bkAskPassphrase("))
    + "(async () => { const out = {};\n"
    "  answers = [A.safety, A.skipped]; _bkRestore('p.tar.gz', null, null, false); await settle();\n"
    "  out.plain = {dialogs: dialogs.slice(), posted: posted.slice()}; dialogs = []; posted = [];\n"
    "  answers = [A.pass, A.pass_ok, A.skipped]; _bkRestore('p.tar.gz.enc', null, null, true); await settle();\n"
    "  out.enc = {dialogs: dialogs.slice(), posted: posted.slice()};\n"
    "  console.log(JSON.stringify(out)); })();\n")
_typed69 = "-".join(("pw", "typed"))     # what the stand-in operator types into the dialog
_got69 = _node69(_name69, "var A = %s, TYPED = %s;\n%s" % (_json69.dumps(_es69), _json69.dumps(_typed69), _prog69)) \
    if _es69 else {"error": "no answers"}
if _got69 is not None:
    check("restore page (es): a refused restore whose safety copy failed opens \"No safety copy\", and "
          "Restore anyway posts skip_safety_backup (the Spanish message has no \"safety copy\" in it)",
          (_got69.get("plain") or {}).get("dialogs") == ["No safety copy"]
          and (_got69.get("plain") or {}).get("posted") == [{"name": "p.tar.gz"},
                                                            {"name": "p.tar.gz", "skip_safety_backup": True}],
          repr(_got69)[:900])
    check("restore page (es): an encrypted archive asks for its passphrase, and when the copy then fails "
          "the same dialog takes over, carrying the passphrase that worked",
          (_got69.get("enc") or {}).get("dialogs") == ["Passphrase needed", "No safety copy"]
          and (_got69.get("enc") or {}).get("posted") == [
              {"name": "p.tar.gz.enc"}, dict(name="p.tar.gz.enc", passphrase=_typed69),
              dict(name="p.tar.gz.enc", passphrase=_typed69, skip_safety_backup=True)],
          repr(_got69)[:900])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Every sentence a route answers is a key: the gate, shown on fixtures, then the tree
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The catalog gates read only the literal first argument of tr()/Sentence(). close_port22 answered
# a module constant (_NO_WAY_BACK) and the (ok, message) of remote_ufw_close_port_22, and
# /firewall/close handed tr() the lockout guard's refusal from two calls down in hosts.py: no
# gate saw any of them, and 259 such sentences had no es/fr entry. i18n_scan.route_answer_keys
# follows them; step_name_keys / step_names_built do the same for a job's progress text, which
# install-status and bootstrap-status translate but no gate read (every step was English).
import shutil as _shutil69  # noqa: E402
import tempfile as _tf69  # noqa: E402
import importlib.util as _ilu69  # noqa: E402

_spec69 = _ilu69.spec_from_file_location("i18n_scan_p69", os.path.join(_root, "tools", "i18n_scan.py"))
_scan69 = _ilu69.module_from_spec(_spec69)
_spec69.loader.exec_module(_scan69)

_td69 = os.path.realpath(_tf69.mkdtemp(prefix="lgsm-unit-p69-"))
try:
    for _d69 in (("panel", "routes"), ("panel", "ops"), ("translations", "es")):
        os.makedirs(os.path.join(_td69, *_d69))
    with open(os.path.join(_td69, "app.py"), "w") as _fh69:
        _fh69.write("")
    with open(os.path.join(_td69, "translations", "es", "x.json"), "w") as _fh69:
        _fh69.write('{"Already here.": "Ya está."}')
    with open(os.path.join(_td69, "panel", "routes", "r.py"), "w") as _fh69:
        _fh69.write(
            "_REFUSED = ('No way back, so this '\n"
            "            'was refused.')\n"
            "def a():\n"
            "    return jsonify({'message': _REFUSED})\n"                         # a module constant
            "def b(h):\n"
            "    ok, msg = svc_close(h)\n"
            "    return jsonify({'message': msg})\n"                               # a service's answer
            "def c(h):\n"
            "    ok, msg = svc_guarded(h)\n"
            "    return jsonify({'message': i18n.tr(msg)})\n"                      # two calls down
            "def d(h):\n"
            "    return jsonify({'message': 'Already here.', 'error': 'bad_code'})\n"  # keyed; a code
            "def e(h):\n"
            "    return jsonify({'message': 'Not for the page.'})  # i18n-ignore\n"
            "def f(h):\n"
            "    why = classify(h)\n"
            "    return jsonify({'message': why[1] if why else 'Generic reason.'})\n")
    with open(os.path.join(_td69, "panel", "ops", "s.py"), "w") as _fh69:
        _fh69.write(
            "def svc_close(h):\n"
            "    if not h:\n"
            "        return False, 'Rule removed from UFW'\n"
            "    return svc_relay(h)\n"
            "def svc_relay(h):\n"
            "    return False, 'Failed to remove it'\n"
            "def _guard(h):\n"
            "    return ('Could not read the firewall, so this refuses.', '', '', None)\n"
            "def svc_guarded(h):\n"
            "    refusal, out, err, rc = _guard(h)\n"
            "    if refusal:\n"
            "        return False, refusal\n"
            "    return True, i18n.Sentence('Port {port} closed', port=h)\n"
            "def classify(h):\n"
            "    return ('code_x', 'Classified reason.')\n"
            # a job's progress text
            "def run(job, tz, user, j):\n"
            "    job._p(3, 'Downloading things')\n"
            "    emit(f'Setting timezone to {tz}')\n"
            "    note('NOT DONE: %s.' % user)\n"
            "    note(i18n.Sentence('User {user} made', user=user))\n"
            "    j['step_name'], j['message'] = 'Complete', user\n"
            "    return {'step_name': 'Queued'}\n")
    _gaps69 = sorted(k for k, _w in _scan69.route_answer_gaps("es", root=_td69,
                                                            translation_dir=os.path.join(_td69, "translations")))
    _steps69 = sorted(_scan69.step_name_keys(root=_td69))
    _built69 = _scan69.step_names_built(root=_td69)
finally:
    _shutil69.rmtree(_td69, ignore_errors=True)
check("i18n gate: a route's answer is a key — a module constant, a service's (ok, message) through "
      "`return other()`, a refusal unpacked two calls down and handed to tr(), item 1 of a classifier's "
      "tuple — and a keyed sentence, a code and an i18n-ignore'd line are not reported",
      _gaps69 == sorted(["No way back, so this was refused.", "Rule removed from UFW", "Failed to remove it",
                         "Could not read the firewall, so this refuses.", "Classified reason.",
                         "Generic reason."]), repr(_gaps69))
check("i18n gate: a job's progress text — a writer's literal, a job's step_name stored by a tuple "
      "assignment or a dict — is a key, and one built in plain English (f-string, %) is reported "
      "(a Sentence is not)",
      _steps69 == ["Complete", "Downloading things", "Queued"]
      and [ln for _f, ln in _built69] == [18, 19], repr((_steps69, _built69)))

_rk69 = _scan69.route_answer_keys()
_sk69 = _scan69.step_name_keys()
_rgaps69 = [(_L69, k) for _L69 in ("es", "fr") for k, _w in _scan69.route_answer_gaps(_L69)]
_cat69 = {_L69: _scan69.load_catalog(_L69) for _L69 in ("es", "fr")}
_sgaps69 = [(_L69, k) for _L69 in ("es", "fr") for k in _sk69 if k not in _cat69[_L69]]
check("i18n gate: every sentence a route can answer, followed into its services, is in the es and fr "
      "catalogs (259 were in neither on main, among them close-port-22's every answer and the lockout guard's)",
      len(_rk69) >= 450 and not _rgaps69, repr((len(_rk69), _rgaps69[:6])))
check("i18n gate: every install and bootstrap step name is in the es and fr catalogs, and none is built "
      "in plain English (48 of 51 were in neither; 19 were f-strings or %)",
      len(_sk69) >= 45 and not _sgaps69 and _scan69.step_names_built() == [],
      repr((len(_sk69), _sgaps69[:6], _scan69.step_names_built()[:6])))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. ...and as a Spanish viewer reads them: close port 22, the lockout guard, install/bootstrap steps
# ════════════════════════════════════════════════════════════════════════════════════════════════
import time as _time69  # noqa: E402
from unit.part12 import P9_GS, P9_HOST  # noqa: E402
from panel.core import i18n as _i18n69  # noqa: E402
from panel.core.panel_state import _install_jobs as _ijobs69, _install_lock as _ilock69  # noqa: E402
from panel.ops.ssh_manager import firewall as _fwmod69, hosts as _hosts69  # noqa: E402
from panel.routes import close_port22 as _cp69  # noqa: E402

_es3 = {}
_ijob_was69 = _ijobs69.get(P9_GS)
try:
    _arm69()
    _lang69("es")
    _c69 = _p9_client(P9_ADMIN)
    _p9_patch(_cp69, "_tailnet_ssh_state", lambda remote: (False, False, False))
    _es3["no_way_back"] = _p9_json(_c69.post("/api/remote/%d/close-port-22" % P9_HOST)).get("message")
    _p9_patch(_cp69, "_tailnet_ssh_state", lambda remote: (True, True, True))
    _p9_patch(_cp69, "remote_ufw_close_port_22", lambda remote: (True, _i18n69.Sentence(
        "Public SSH rules removed from UFW (port {ports})", ports="22")))
    _p9_patch(_cp69, "_r28b_panel_way_in_refusal", lambda remote: None)   # reached over the tailnet
    _es3["closed"] = _p9_json(_c69.post("/api/remote/%d/close-port-22" % P9_HOST)).get("message")
    # The lockout guard, for real: remote_ufw_close_port → _r15a_guarded_spec_delete, whose firewall
    # read answers nothing.
    _p9_patch(_fwmod69, "remote_ufw_status", lambda server: None)
    _es3["guard"] = _p9_json(_c69.post("/api/remote/%d/firewall/close" % P9_HOST,
                                       json={"port": "22", "protocol": "tcp"})).get("message")
    with _ilock69:
        _ijobs69[P9_GS] = {"status": "running", "step": 3, "total": 8, "step_name": "Downloading LinuxGSM",
                           "message": "", "log": [], "started": _time69.time(), "updated": _time69.time()}
    _es3["install"] = _p9_json(_c69.get("/api/server/%d/install-status" % P9_GS)).get("step_name")
    # A bootstrap note from the real writer: what it hands progress(), read back in Spanish.
    _noted69 = []
    _hosts69._r11a_step_failed(_noted69.append, [], ("", "no space", 1),
                               _i18n69.Sentence("the timezone was not set to {tz}", tz="UTC"))
    with _p9.test_request_context("/"):
        __import__("flask").session["lang"] = "es"
        _es3["note"] = [_i18n69.tr(n) for n in _noted69]
finally:
    with _ilock69:
        # Put back what was there (part66 does), not only pop: a job an earlier part left would
        # be gone for the parts after.
        _ijobs69.pop(P9_GS, None)
        if _ijob_was69 is not None:
            _ijobs69[P9_GS] = _ijob_was69
    _lang69(_LANG69_WAS)
    _p9_restore_all()
check("close port 22 (es): the no-way-back refusal and the removed-rule answer are Spanish (both were "
      "English in every language)",
      (_es3.get("no_way_back") or "").startswith("Rechazado: no hay una vía de vuelta por Tailscale")
      and _es3.get("closed") == "Reglas de SSH público eliminadas de UFW (puerto 22)", repr(_es3))
check("firewall close (es): the lockout guard's \"couldn't read the firewall\" refusal is Spanish",
      (_es3.get("guard") or "").startswith("No se pudo leer el cortafuegos para comprobar si esta regla"),
      repr(_es3.get("guard")))
check("install/bootstrap progress (es): an install step and a bootstrap NOT DONE note read in Spanish",
      _es3.get("install") == "Descargando LinuxGSM"
      and _es3.get("note") == ["NO HECHO: no se configuró la zona horaria UTC (no space)."], repr(_es3))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Sign-out's retry clears the session rows the epoch bump just signed out
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The retry (a momentary SQLite lock on the first attempt) bumped the global auth_epoch — every
# device signed out — and left every UserSession row, so the account page listed them as live
# sessions with Revoke buttons until they idled out. The legacy branch clears them since #423.
from panel.db.models import UserSession as _US69  # noqa: E402
from panel.security import auth as _auth69  # noqa: E402


class _FlakyRows69:
    """UserSession.query whose first `fails` filter_by() calls raise, as a locked database does."""

    def __init__(self, fails):
        self.fails, self.calls = fails, 0

    def filter_by(self, **kw):
        self.calls += 1
        if self.calls <= self.fails:
            raise RuntimeError("database is locked")
        return _db69.session.query(_US69).filter_by(**kw)


def _lo_user69(name):
    with _p9.app_context():
        u = _User69(username=name, password_hash=_auth69.hash_password("Str0ng!passw0rd-p69"),
                    display_name=name, is_superadmin=False, is_active=True)
        _db69.session.add(u)
        _db69.session.commit()
        for k in range(2):
            _db69.session.add(_US69(user_id=u.id, sid="p69-%s-%d" % (name, k)))
        _db69.session.commit()
        return u.id


def _lo_state69(uid):
    with _p9.app_context():
        u = _db69.session.get(_User69, uid)
        return _US69.query.filter_by(user_id=uid).count(), (u.auth_epoch or 0) if u else None


_lo69 = {}
try:
    _arm69()
    for _case69, _fails69 in (("retry", 1), ("retry_rows_locked", 2)):
        _uid69 = _lo_user69("p69_" + _case69)
        _flaky69 = _FlakyRows69(_fails69)
        _US69.query = _flaky69          # a class attribute over the model's query property
        try:
            _r69 = _p9_client(_uid69).post("/logout", follow_redirects=True)
        finally:
            del _US69.query             # the property answers again
        _lo69[_case69] = (_lo_state69(_uid69), _flaky69.calls,
                          "You have been logged out." in _r69.get_data(as_text=True))
finally:
    with _p9.app_context():
        for _u69 in _User69.query.filter(_User69.username.like("p69_retry%")).all():
            _US69.query.filter_by(user_id=_u69.id).delete()
            _db69.session.delete(_u69)
        _db69.session.commit()
    _p9_restore_all()
check("logout: when the first attempt fails, the retry's epoch bump (every device) clears every "
      "session row too, and says signed out",
      _lo69.get("retry") == ((0, 1), 2, True), repr(_lo69))
check("logout: ...and when the rows cannot be cleared either, the epoch bump is still committed (the "
      "revocation is never lost to the cleanup)",
      _lo69.get("retry_rows_locked") == ((2, 1), 2, True), repr(_lo69))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The terminal's closing reason, in Spanish
# ════════════════════════════════════════════════════════════════════════════════════════════════
# term_exit's reason (and term_error's message) come from a worker with no viewer — the idle
# sweeper, a shell that exited — and the page put that English into its translated sentence:
# "Sesión cerrada — the shell exited." The server now sends the template and values too
# (host_terminal._r16c_said), and the page translates them.
from panel.routes import host_terminal as _ht69  # noqa: E402
from panel.ops import terminal_session as _tsx69  # noqa: E402

_ES69 = _scan69.load_catalog("es")


def _es69(*keys):
    """i18n.js in node with only `keys` of the Spanish catalog (the whole one is past `node -e`'s limit)."""
    return ("global.window = global;\nglobal.document = {readyState: 'complete', body: null};\n"
            "window.I18N = " + _json69.dumps({_k: _ES69[_k] for _k in keys if _k in _ES69}) + ";\n"
            "window.LANG = 'es';\n" + _read69(_JS69, "i18n.js") + "\n")


try:
    _idle69 = _i18n69.Sentence("closed after {n} minutes with no input", n=_tsx69._IDLE_TIMEOUT // 60)
    _many69 = _tsx69.TerminalError(_i18n69.Sentence("You already have {n} terminals open. Close one and "
                                                     "try again.", n=3))
    _pay69 = {"idle": _ht69._r16c_said("reason", _idle69), "exited": _ht69._r16c_said("reason", "the shell exited"),
              "none": {}, "many": _ht69._r16c_said("message", _many69.args[0])}
except Exception as _e69:     # a missing helper is a failed check below, not a crashed part
    _pay69 = {"error": repr(_e69)}
_HT69 = _read69(_JS69, "host_terminal.js")
_name69 = "terminal (es): the closing reason and an open refusal"
_prog69 = (_es69("Session closed — {why}. Reload the page to start another.", "the session ended",
                 "the shell exited", "closed after {n} minutes with no input",
                 "You already have {n} terminals open. Close one and try again.",
                 "The terminal could not be opened.")
           + "var P = " + _json69.dumps(_pay69) + ", status = [], wrote = [], on = {};\n"
           "var sock = {on: (ev, fn) => { on[ev] = fn; }}, term = {write: s => wrote.push(s)};\n"
           "function _status(m){ status.push(m); }\n"
           + ("" if "function _said(" not in _HT69 else _cut47(_HT69, "function _said(") + "\n")
           # the handlers write through it (review 1012b: a host name's control characters)
           + ("" if "function _r17cTermText(" not in _HT69 else _cut47(_HT69, "function _r17cTermText(") + "\n")
           + _cut47(_HT69, "sock.on('term_exit'") + ");\n"
           + _cut47(_HT69, "sock.on('term_error'") + ");\n"
           "on.term_exit(P.idle); on.term_exit(P.exited); on.term_exit(P.none); on.term_error(P.many);\n"
           "console.log(JSON.stringify({status: status, wrote: wrote}));\n")
_got69 = _node69(_name69, _prog69)
if _got69 is not None:
    check("terminal (es): the closing reason is Spanish inside the Spanish sentence — the idle timeout with "
          "its minutes, a shell that exited, and no reason at all — on the status line and in the terminal",
          (_got69.get("status") or [])[:3] == [
              "Sesión cerrada — cerrada tras 15 minutos sin entrada. Recarga la página para iniciar otra.",
              "Sesión cerrada — la shell terminó. Recarga la página para iniciar otra.",
              "Sesión cerrada — " + _ES69.get("the session ended", "?") + ". Recarga la página para iniciar otra."]
          and "[la shell terminó]" in "".join(_got69.get("wrote") or []), repr(_got69)[:900])
    check("terminal (es): a refusal to open (a built sentence with a count) is Spanish too",
          (_got69.get("status") or [None] * 4)[3:] == ["Ya tienes 3 terminales abiertas. Cierra una e inténtalo de nuevo."],
          repr(_got69)[:900])

# ...and the server half, through the real socket handler: what term_exit and term_error carry.
_sock69 = {}
_exit69 = {}
try:
    _arm69()

    def _open69(sid, remote, is_local, **k):
        _exit69["sid"], _exit69["on_exit"] = sid, k.get("on_exit")
    _p9_patch(_ht69._ts, "open_session", _open69)
    _sio69 = _p9.socketio.test_client(_p9, flask_test_client=_p9_client(P9_ADMIN))
    _sio69.emit("term_open", {"remote_id": P9_HOST, "cols": 80, "rows": 24})
    if _exit69.get("on_exit"):
        _exit69["on_exit"](_exit69["sid"], _idle69)        # the idle sweeper's close, as it calls it

    def _refuse69(sid, remote, is_local, **k):
        raise _tsx69.TerminalError(_i18n69.Sentence("You already have {n} terminals open. Close one and "
                                                    "try again.", n=3))
    _p9_patch(_ht69._ts, "open_session", _refuse69)
    _sio69.emit("term_open", {"remote_id": P9_HOST, "cols": 80, "rows": 24})
    for _ev69 in _sio69.get_received():
        if _ev69["name"] in ("term_exit", "term_error"):
            _sock69.setdefault(_ev69["name"], []).append((_ev69["args"] or [{}])[0])
finally:
    if "_sio69" in globals() and _sio69.is_connected():
        _sio69.disconnect()         # in the finally: a raise above left the client connected
    _p9_restore_all()
    with _ht69._sid_lock:
        _ht69._sid_host.pop(_exit69.get("sid"), None)
        _ht69._sid_owner.pop(_exit69.get("sid"), None)
check("terminal: term_exit and term_error carry the template and values with the English (an idle close, "
      "a refusal with a count), so the page can say them in the viewer's language",
      {"reason": "closed after 15 minutes with no input", "reason_key": "closed after {n} minutes with no input",
       "reason_vals": {"n": "15"}} in _sock69.get("term_exit", [])
      and {"message": "You already have 3 terminals open. Close one and try again.",
           "message_key": "You already have {n} terminals open. Close one and try again.",
           "message_vals": {"n": "3"}} in _sock69.get("term_error", []), repr(_sock69)[:900])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. "N players are connected to NAME." and "HOST needs to reboot…" are whole sentences
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Built from fragments around the count and the name ("players are connected to", "needs to
# reboot to finish applying system updates."), the translator had pieces with nothing to place,
# and a language that puts the name or the count elsewhere could not be written. #423 made its
# sibling in manage_remotes one template; these three are too. Each is driven in Spanish, on a
# stand-in DOM, and what reached the page read back.
_FAKEDOM69 = (
    "function El(tag){ this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {};\n"
    "  this.style = {}; this._html = null; this.textContent = ''; this.className = ''; }\n"
    "El.prototype.appendChild = function(c){ this.children.push(c); return c; };\n"
    "El.prototype.insertBefore = function(c){ this.children.unshift(c); return c; };\n"
    "El.prototype.setAttribute = function(k, v){ this.attrs[k] = v; };\n"
    "El.prototype.addEventListener = function(){}; El.prototype.remove = function(){};\n"
    "El.prototype.querySelector = function(){ return null; }; El.prototype.querySelectorAll = function(){ return []; };\n"
    "Object.defineProperty(El.prototype, 'innerHTML', {set(v){ this._html = v; this.children = []; },\n"
    "  get(){ return this._html; }});\n"
    "function Txt(s){ this.text = s; }\n"
    "global.document.createElement = t => new El(t); global.document.createTextNode = s => new Txt(s);\n"
    "global.document.body = new El('body');\n"
    # What the page would hold, as markup: an element's tag and attributes, text escaped.
    "function render(e){ if (e instanceof Txt) return escapeHtml(e.text); if (e._html !== null) return e._html;\n"
    "  var inner = e.children.length ? e.children.map(render).join('') : escapeHtml(e.textContent);\n"
    "  var a = Object.keys(e.attrs).map(k => ' ' + k + (e.attrs[k] ? '=\"' + e.attrs[k] + '\"' : '')).join('');\n"
    "  var tg = e.tagName.toLowerCase(); return '<' + tg + a + '>' + inner + '</' + tg + '>'; }\n"
    "function said(e){ return e.children.map(render).join(''); }\n")
_name69 = "players / reboot sentences in Spanish"
_SA69, _NG69 = _read69(_JS69, "server_actions.js"), _read69(_JS69, "nags.js")
_prog69 = (_es69("{n} player is connected to {name}.", "{n} players are connected to {name}.",
                 "{n} players are connected to {count} servers: {list}.",
                 "{n} player is connected to {count} server: {list}.",
                 "{host} needs to reboot to finish applying system updates.", "the panel host")
           + "window.escapeHtml = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');\n"
           + _FAKEDOM69
           + "var SERVER_NAME = 'Mi<Srv>', MOUNT = '', serverId = 1; function _esc(s){ return escapeHtml(s); }\n"
           + _cut47(_SA69, "function _r12c_el(") + "\n" + _cut47(_SA69, "function actionPlayersDialog(") + "\n"
           + _cut47(_BK69, "function _discT(") + "\n" + _cut47(_BK69, "function fbPlayersDialog(") + "\n"
           + "".join(_cut47(_NG69, h) + "\n" for h in ("function _rbEl(", "function _rbName(", "function _rbHost("))
           + _cut47(_NG69, "window.rebootNagRender = function(") + "\n"
           "function _rbButton(){ return new El('button'); }\nwindow.LOCAL_HOST_ID = 7;\n"
           "function whoOf(){ var ov = document.body.children.pop(); var body = ov.children[0].children[1];\n"
           "  return said(body.children[0]); }\n"
           "var out = {};\n"
           "actionPlayersDialog('stop', 3, null); out.three = whoOf();\n"
           "actionPlayersDialog('stop', 1, null); out.one = whoOf();\n"
           "fbPlayersDialog([{name: 'A<b>', players: 2}, {name: 'B', players: 1}]); out.backup = whoOf();\n"
           "fbPlayersDialog([{name: 'C', players: 1}]); out.backup1 = whoOf();\n"
           "var nag = new El('div'); rebootNagRender(nag, 5, 'vps<1>', {packages: []}); out.nag = said(nag.children[1]);\n"
           "var nag2 = new El('div'); rebootNagRender(nag2, 6, t('the panel host'), {packages: []}); out.nag2 = said(nag2.children[1]);\n"
           "console.log(JSON.stringify(out));\n")
_got69 = _node69(_name69, _prog69)
if _got69 is not None:
    # Each sentence inside the one <span> tfNodes hands back (review 1012b: so a live language switch
    # can build it again).
    check("players dialog (es): \"3 jugadores están conectados a NAME.\" is one translated sentence, the "
          "count and the name escaped and guarded",
          (_got69.get("three") or "").startswith('<span><strong data-no-i18n>3</strong> jugadores están conectados a '
                                                 '<strong data-no-i18n>Mi&lt;Srv&gt;</strong>.</span>')
          and (_got69.get("one") or "").startswith('<span><strong data-no-i18n>1</strong> jugador está conectado a '),
          repr(_got69)[:900])
    check("backup players dialog (es): the counts and the server list sit in one translated sentence",
          _got69.get("backup") == '<span><strong data-no-i18n>3</strong> jugadores están conectados a <strong '
                                  'data-no-i18n>2</strong> servidores: <span data-no-i18n>A&lt;b&gt; (2), B (1)</span>.'
                                  '</span>'
          and (_got69.get("backup1") or "").startswith('<span><strong data-no-i18n>1</strong> jugador está conectado a '
                                                       '<strong data-no-i18n>1</strong> servidor: '),
          repr(_got69)[:900])
    check("reboot banner (es): \"HOST necesita reiniciarse…\" is one sentence with the host in it, and the "
          "panel host handed over already translated is written as the phrase the page translates",
          "<strong data-no-i18n>vps&lt;1&gt;</strong> necesita reiniciarse para terminar de aplicar" in (_got69.get("nag") or "")
          and "<strong>the panel host</strong> necesita reiniciarse" in (_got69.get("nag2") or ""),
          repr(_got69)[:900])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. A protected rule's refusal, from /firewall/close and /firewall/delete-rule, in Spanish
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Both handed tr() the protect reason with its ports already filled in — never a key — so the
# refusal was English while the Firewall page showed the same reason translated.
_tmpl69 = _fwmod69.R14A_REASONS["panel_only"]
_grp69 = {"nums": [1], "protected": True, "protect_reason_key": _tmpl69,
          "protect_reason_params": {"port": "5000"}, "protect_reason": _tmpl69.format(port="5000"),
          "port_num": "5000", "port_label": "5000", "scope": "Any address", "proto": "tcp",
          "action": "ALLOW IN", "key": "k1"}
_prot69 = {}
try:
    _arm69()
    _lang69("es")
    _c69 = _p9_client(P9_ADMIN)
    _p9_patch(_fwmod69, "remote_ufw_status", lambda server: {"installed": True, "active": True,
                                                              "groups": [dict(_grp69)]})
    _p9_patch(_hosts69, "_r15a_spec_names", lambda g, port, label: True)
    _prot69["delete"] = _p9_json(_c69.post("/api/remote/%d/firewall/delete-rule" % P9_HOST,
                                           json={"num": 1})).get("message")
    _prot69["close"] = _p9_json(_c69.post("/api/remote/%d/firewall/close" % P9_HOST,
                                          json={"port": "5000", "protocol": "tcp"})).get("message")
finally:
    _lang69(_LANG69_WAS)
    _p9_restore_all()
_want69 = _scan69.load_catalog("es").get(_tmpl69, "?").replace("{port}", "5000")
check("firewall (es): deleting or closing a protected rule is refused in Spanish, with its port in it "
      "(the reason was handed to tr() with the port already filled in, so it stayed English)",
      _prot69.get("delete") == _want69 and _prot69.get("close") == _want69 and "5000" in _want69,
      repr((_prot69, _want69)))


# ── the spliced-message gate: a keyword-only wrapper, and an item of a held answer ───────────────
# _py_wrapped_params read only positional parameters, and a sink fed `res[1]` (res = svc(…)) was
# not followed. Neither shape is in today's tree; each is a way the next one would pass unread.
_td69b = os.path.realpath(_tf69.mkdtemp(prefix="lgsm-unit-p69b-"))
try:
    os.makedirs(os.path.join(_td69b, "panel", "routes"))
    with open(os.path.join(_td69b, "app.py"), "w") as _fh69:
        _fh69.write("")
    with open(os.path.join(_td69b, "panel", "routes", "r.py"), "w") as _fh69:
        _fh69.write(
            "def _reply(*, text):\n"
            "    return jsonify({'success': False, 'message': text})\n"
            "def a(port):\n"
            "    return _reply(text='Port %d is busy.' % port)\n"                    # 4 kw-only wrapper
            "def svc_plain(ip):\n"
            "    return True, 'Blocked %s.' % ip\n"
            "def b(ip):\n"
            "    res = svc_plain(ip)\n"
            "    flash(res[1], 'info')\n"                                           # 9 item of a held answer
            "def c(ip):\n"
            "    res = svc_plain(ip)\n"
            "    flash(res[0], 'info')\n")                                          # item 0 is not built
    _sp69 = sorted(line for _f, line, _w in _scan69.spliced_py(_td69b))
finally:
    _shutil69.rmtree(_td69b, ignore_errors=True)
check("i18n gate: a message built in English and handed to a keyword-only wrapper, or an item of a "
      "service's answer held whole (`res = svc(); flash(res[1])`), is reported; an unbuilt item is not",
      _sp69 == [4, 9], repr(_sp69))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 8. Console: Clear while the first window's catch-up is still unanswered, then the re-prime
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Review lead (not a defect, held here): the re-prime's _startResync ends the catch-up still running,
# which shows the panel pushes it held and raises _lastPanelT before showPanelBacklog runs — would the
# backlog rows between Clear's cut and those pushes be filtered out? No: while a catch-up runs every
# panel push is held (_resyncTake), so the pushes since Clear are exactly the ones it shows.
_SD69 = _read69(_JS69, "server_detail.js")
_CON69 = (
    "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = ''; global.serverId = 1; global.toast = () => 0;\n"
    "var shown = [], _consoleLines = [], _consolePrimed = false, _consoleSig = null, _lastPanelT = 0;\n"
    "var _returnOwed = false, _panelBacklogShown = false, _r13c_panelPushes = [], _R13C_PANEL_KEEP = 200;\n"
    "var _r15c_clearedAt = null, _resync = null, _shownOnReturn = {}, _primeOwed = false, _logAt = null;\n"
    "var _resyncSeq = 0, _RESYNC_MAX_MS = 45000;\n"
    "var consoleEl = {set innerHTML(v){ shown.length = 0; }};\nvar socket = {connected: true};\n"
    "function _rebuildMark(){ return 0; } function _rebuildRestore(){} function updateTsNotice(){}\n"
    "function _showTsOffNote(){} function stickConsole(){} function consoleAtBottom(){ return true; }\n"
    "function _notePanelMarker(){} function _newConsoleRows(){ return []; } function _resyncAsk(){}\n"
    "global.setTimeout = () => 0; global.clearTimeout = () => 0;\n"
    "function _appendConsoleRows(rows){ (rows || []).forEach(r => shown.push(r.line)); }\n"
    "function appendConsole(text){ shown.push(text); }\n"
    "function _panelShownAt(t){ if (Number(t) > _lastPanelT) _lastPanelT = Number(t); }\n"
    "function _renderPanelLines(rows){ rows.forEach(r => { shown.push(r.line); _panelShownAt(r.t); }); }\n"
    + "".join(_cut47(_SD69, h) + "\n" for h in (
        "function _r13c_notePanelPush(", "function _r13c_reshowPanelPushes(", "function refreshConsole(",
        "function showPanelBacklog(", "function _newerPanelRows(", "function _panelLinesWiped(",
        "function _r13c_primeWipesPushes(", "function clearConsole(", "function _primeAt(",
        "function _primeCatchUp(", "function _startResync(", "function _endResync(", "function _showPanelPush(",
        "function _resyncTake(", "function _notePanelPush("))
    + "var backlog = [], logN = 0;\n"
    "global.fetch = () => { logN++; return Promise.resolve({ok: true, json: () => Promise.resolve(\n"
    "  {lines: [{line: 'log' + logN}], panel_lines: backlog.slice(), at: ['c', 1, logN * 10]})}); };\n"
    "function push(ts, data){ const d = {panel: true, ts: ts, data: data};\n"
    "  if (!_notePanelPush(d)) return; if (_resyncTake(d)) return; appendConsole(d.data); _r13c_notePanelPush(d); }\n"
    "(async () => { const out = {};\n"
    "  backlog = [{t: 100, line: '[panel] old'}]; refreshConsole(true); await settle();\n"
    "  out.running = !!_resync;\n"
    "  clearConsole(); push(110, '[panel] u1'); push(115, '[panel] u2');\n"
    "  backlog.push({t: 110, line: '[panel] u1'}, {t: 115, line: '[panel] u2'});\n"
    "  refreshConsole(false); await settle(); out.after = shown.slice();\n"
    "  push(120, '[panel] u3'); out.later = shown.slice();\n"
    "  console.log(JSON.stringify(out)); })();\n")
_name69 = "console: Clear during an unanswered catch-up, then the re-prime"
_got69 = _node69(_name69, _CON69)
if _got69 is not None:
    check("console: Clear while the first window's catch-up is unanswered, then the re-prime — the panel "
          "lines pushed since Clear are shown once each, none lost to the held pushes the re-prime releases",
          _got69.get("running") is True and _got69.get("after") == ["log2", "[panel] u1", "[panel] u2"]
          and _got69.get("later") == ["log2", "[panel] u1", "[panel] u2"], repr(_got69))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 9. At 375px (builder U): toasts, the firewall's scope and source words, and row buttons in reach
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Measured in a rendered panel at 375px: every toast was 188px wide (x 94..281) — a fixed box at
# left:50% shrink-wraps into the half of the viewport right of centre, so its max-width never
# applied, and a Spanish lockout refusal stood 188x257 over the header for 7 s. The firewall's
# Scope column said "Any address" in Spanish and French, the source field's placeholder was marked
# data-no-i18n, and the rules and backups tables slid their Delete buttons under the scroll edge.
_PJS_r16u = _read69(_JS69, "panel.js")
_TOAST_r16u = (
    "global.window = global;\n"
    "const made = [];\n"
    "global.document = {body: {appendChild(){}}, getElementById(){ return null; },\n"
    "  createElement(){ const el = {style: {}, children: [], appendChild(c){ this.children.push(c); }};\n"
    "    made.push(el); return el; }};\n"
    "global.escapeHtml = s => String(s); global.setTimeout = () => 0;\n"
    + _cut47(_PJS_r16u, "window.toast = function(") + "\n"
    "toast('El puerto 22 es el puerto SSH que se usa para llegar a este host.', 'danger');\n"
    "const area = made[0];\n"
    "console.log(JSON.stringify({area: area.style.cssText, toast: area.children[0].style.cssText}));\n")
_name_r16u = "toast: the area spans the capped width, centred by margin"
_got_r16u = _node69(_name_r16u, _TOAST_r16u)
if _got_r16u is not None:
    _a_r16u = (_got_r16u.get("area") or "").replace(" ", "")
    _t_r16u = (_got_r16u.get("toast") or "").replace(" ", "")
    check("toast: the area is centred by left:0/right:0/margin:auto with a width of its own, not placed "
          "at left:50% (where a fixed box shrink-wraps to the right half: 188px of a 375px phone)",
          "left:50%" not in _a_r16u and "translateX" not in _a_r16u and "left:0;" in _a_r16u
          and "right:0;" in _a_r16u and "margin:0auto;" in _a_r16u and "width:min(92vw,520px)" in _a_r16u,
          repr(_got_r16u))
    check("toast: the full-width area lets clicks through, and each toast takes them back",
          "pointer-events:none" in _a_r16u and "pointer-events:auto" in _t_r16u, repr(_got_r16u))

# The Scope column. The words stay ENGLISH at the source — hosts.py's lockout guard compares
# g["scope"] == "Any address" — and the page's catalog walker translates the cell, so the entry
# must be in each catalog. Every literal _ufw_scope can return is checked, not just the one found.
_scopes_r16u = {_fwmod69._ufw_scope({"iface": "", "from": "Anywhere"}),
                _fwmod69._ufw_scope({"iface": "", "from": "anywhere"})}
check("firewall: the Scope column's 'Any address' stays English at the source (the lockout guard "
      "matches it)", _scopes_r16u == {"Any address"}, repr(_scopes_r16u))
for _L_r16u in ("es", "fr"):
    _cat_r16u = _i18n69.catalog(_L_r16u)
    _miss_r16u = [s for s in _scopes_r16u if _cat_r16u.get(s, s) == s]
    check("firewall (%s): every scope word _ufw_scope returns has a translation" % _L_r16u,
          not _miss_r16u, repr(_miss_r16u))

# The source field's placeholder: translated, addresses literal.
import re as _re_r16u  # noqa: E402
_FWT_r16u = _read69(_root, "templates", "remote_firewall.html")
_cidr_r16u = _re_r16u.search(r'<input\b[^>]*\bid="src-cidr"[^>]*>', _FWT_r16u, _re_r16u.S)
_ph_r16u = _re_r16u.search(r'placeholder="([^"]*)"', _cidr_r16u.group(0)).group(1) if _cidr_r16u else ""
check("firewall: the 'Restrict a port' source field is not data-no-i18n, so its placeholder translates",
      _cidr_r16u is not None and "data-no-i18n" not in _cidr_r16u.group(0),
      _cidr_r16u.group(0) if _cidr_r16u else "no #src-cidr input")
# The addresses are read from the English placeholder itself, not written here a second time.
_addrs_r16u = [a for a in _re_r16u.findall(r"[0-9][0-9./]+", _ph_r16u) if "." in a]
for _L_r16u in ("es", "fr"):
    _v_r16u = _i18n69.catalog(_L_r16u).get(_ph_r16u, "")
    check("firewall (%s): the source placeholder %r has a translation that keeps the addresses literal"
          % (_L_r16u, _ph_r16u),
          bool(_v_r16u) and _v_r16u != _ph_r16u and _addrs_r16u
          and all(a in _v_r16u for a in _addrs_r16u),
          repr(_v_r16u))

# The protocol select had a col-3: 66px at 375px, "Les deu…" in French and "Both (TC" in English
# on the desktop column too. It needs at least half the row.
_proto_r16u = _re_r16u.search(r'<div class="col-(\d+)">\s*<select id="new-proto"', _FWT_r16u)
check("firewall: the Open-a-port protocol select gets at least half its row",
      _proto_r16u is not None and int(_proto_r16u.group(1)) >= 6,
      _proto_r16u.group(0) if _proto_r16u else "no col-N directly around #new-proto")

# Row buttons in reach: each table whose last column is its row buttons is pinned, in the
# template AND in the script that repaints it, and the rule that pins it exists at phone width.
_RM_r16u = _read69(_root, "templates", "remote_manage.html")
_pins_r16u = {
    "firewall rules (template)": (_FWT_r16u, "<th>Scope</th>"),
    "firewall rules (repaint)": (_read69(_JS69, "remote_firewall.js"), "<th>Port</th><th>Protocol</th>"),
    "panel backups": (_RM_r16u, "<th>When</th><th>Type</th>"),
    "game backups": (_read69(_JS69, "remote_manage_backups.js"), "<th>Backup file</th>"),
    "host game servers": (_RM_r16u, "<th>Name</th><th>Type</th><th>Connect</th>"),
    "users": (_read69(_root, "templates", "manage_users.html"), "<th>Username</th>"),
}
for _what_r16u, (_src_r16u, _head_r16u) in _pins_r16u.items():
    _at_r16u = _src_r16u.find(_head_r16u)
    _tbl_r16u = _src_r16u.rfind("<table", 0, _at_r16u) if _at_r16u >= 0 else -1
    _tag_r16u = _src_r16u[_tbl_r16u:_src_r16u.find(">", _tbl_r16u)] if _tbl_r16u >= 0 else ""
    check("375px: the %s table pins its row buttons (table-pin-actions)" % _what_r16u,
          "table-pin-actions" in _tag_r16u, _tag_r16u or "table not found")
_CSS_r16u = _read69(_root, "static", "css", "panel.css")
_PIN_RULE_r16u = r"\.table-pin-actions\s*>\s*tbody\s*>\s*tr\s*>\s*:last-child\s*\{([^}]*)\}"


def _r17d_media_bodies(css, head):
    """The text inside each `<head> { ... }` block of `css` (comments out), by brace matching."""
    css = _re_r16u.sub(r"/\*.*?\*/", "", css, flags=_re_r16u.S)
    out, at = [], css.find(head)
    while at >= 0:
        open_at = css.find("{", at)
        depth, k = 1, open_at + 1
        while k < len(css) and depth:
            depth += {"{": 1, "}": -1}.get(css[k], 0)
            k += 1
        out.append(css[open_at + 1:k - 1])
        at = css.find(head, k)
    return out


def _r17d_pinned_on_phones(css):
    """Is the pinned table's last cell position:sticky at right:0 INSIDE a phone-width block?

    Searched from the block's head to the end of the file, a rule moved into the desktop block or
    to top level after it passed (review 1012b).
    """
    for _body in _r17d_media_bodies(css, "@media (width <= 767.98px)"):
        _rule = _re_r16u.search(_PIN_RULE_r16u, _body)
        if (_rule and _re_r16u.search(r"position:\s*sticky", _rule.group(1))
                and _re_r16u.search(r"right:\s*0", _rule.group(1))):
            return True
    return False


_pinrule_r16u = _re_r16u.search(_PIN_RULE_r16u, _CSS_r16u)
# The control: the same rule moved out of the phone block into a desktop-width one.
_pin_moved_r16u = (_CSS_r16u.replace(_pinrule_r16u.group(0), "") + "\n@media (width >= 768px) {\n"
                   + _pinrule_r16u.group(0) + "\n}\n") if _pinrule_r16u else ""
check("375px: inside the phone-width block, a pinned table's last cell is position:sticky at right:0",
      _r17d_pinned_on_phones(_CSS_r16u), repr(_pinrule_r16u.group(0)[:200] if _pinrule_r16u else None))
check("375px: ...and the same rule moved into the desktop block is not read as the phone's (control)",
      bool(_pin_moved_r16u) and not _r17d_pinned_on_phones(_pin_moved_r16u)
      and _r17d_pinned_on_phones("@media (width <= 767.98px) {\n.x { a: b; }\n" + _pinrule_r16u.group(0) + "\n}"))
# The dashboard's 120px name-column floor was written for every wrapped table and reached the
# backups table's one-word Type column, which alone pushed it to 323px in a 309px box.
check("375px: the dashboard's server-name width floor is scoped to the dashboard table, not every "
      "wrapped table's second column",
      _re_r16u.search(r"\.table-responsive\s+\.table\s+(thead|tbody)\s+t[hd]:nth-child\(2\)", _CSS_r16u) is None
      and "dash-srv-table" in _read69(_root, "templates", "dashboard.html"),
      "an unscoped `.table-responsive .table … :nth-child(2)` rule is back")

# A heading that names a host or a server: measured at 375px with a 45-char host name, the Firewall
# page's name was a 93px column 7 lines tall (French split "Pare-/feu :") and the page scrolled
# sideways (381px); a 41-char unbroken server name pushed /server/N to 487px. The heading row may
# wrap, its items may shrink below their longest word, and the name may break inside a word. The
# rule is read with its comments stripped, and only from outside any @media block, since every
# page at every width needs it.
_css_top_r16u = _re_r16u.sub(r"/\*.*?\*/", "", _CSS_r16u, flags=_re_r16u.S)


def _top_rules_r16u(pattern):
    """The bodies of rules matching `pattern` that sit at brace depth 0 (inside no @media block)."""
    return " ".join(m.group(1) for m in _re_r16u.finditer(pattern, _css_top_r16u)
                    if _css_top_r16u.count("{", 0, m.start()) == _css_top_r16u.count("}", 0, m.start()))


_pt_r16u = _top_rules_r16u(r"(?<![\w-])\.page-title\s*\{([^}]*)\}")
_ptk_r16u = _top_rules_r16u(r"\.page-title\s*>\s*\*\s*\{([^}]*)\}")
# The wrap is scoped to a heading that carries a name (review 1012b, part72): on every heading it
# left a long translated title's icon alone on its own line.
_ptn_r16u = _top_rules_r16u(r"\.page-title:has\(>\s*\[data-no-i18n\]\)\s*\{([^}]*)\}")
check("375px: a page heading wraps its label and name onto separate lines and breaks a long name "
      "inside the word (flex-wrap:wrap, overflow-wrap:anywhere, items min-width:0)",
      _re_r16u.search(r"flex-wrap:\s*wrap", _ptn_r16u) is not None
      and _re_r16u.search(r"overflow-wrap:\s*anywhere", _pt_r16u) is not None
      and _re_r16u.search(r"min-width:\s*0", _ptk_r16u) is not None,
      "page-title: %r / with a name: %r / children: %r" % (_pt_r16u.strip(), _ptn_r16u.strip(),
                                                           _ptk_r16u.strip()))
for _tpl_r16u in ("remote_firewall.html", "remote_manage.html"):
    _h1_r16u = _re_r16u.search(r'<h1 class="page-title[^"]*">(.*?)</h1>',
                               _read69(_root, "templates", _tpl_r16u), _re_r16u.S)
    check("375px: %s's heading carries the host name as its own item (a direct child the rule reaches)"
          % _tpl_r16u,
          _h1_r16u is not None and ("<span data-no-i18n>{{ remote.display_name }}</span>" in _h1_r16u.group(1)
                                    # review 1015a: one span, data-host-name, the local label unguarded
                                    or "{{ host_label(remote) }}" in _h1_r16u.group(1)),
          _h1_r16u.group(1).strip()[:200] if _h1_r16u else "no page-title h1")

check("part69: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP69_START, repr(_P9_TRIPPED[_TRIP69_START:][:6]))
