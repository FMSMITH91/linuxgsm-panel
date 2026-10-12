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
from unit.part12 import P9_ADMIN, _p9, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from unit.part47 import _cut47, _node47
from panel.db.models import User as _User69, db as _db69
from panel.ops import backup as _bk69, system_ops as _so69

_JS69 = os.path.join(_root, "static", "js")


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
            return False, _bk69._R16C_PASSPHRASE_REQUIRED
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
    _lang69("en")
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
    "  o.onConfirm('pw-typed', {close(){}, error(m){ dialogs.push('error:' + m); }}); };\n"
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
_got69 = _node69(_name69, "var A = %s;\n%s" % (_json69.dumps(_es69), _prog69)) if _es69 else {"error": "no answers"}
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
              {"name": "p.tar.gz.enc"}, {"name": "p.tar.gz.enc", "passphrase": "pw-typed"},
              {"name": "p.tar.gz.enc", "passphrase": "pw-typed", "skip_safety_backup": True}],
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
try:
    _lang69("es")
    _c69 = _p9_client(P9_ADMIN)
    _p9_patch(_cp69, "_tailnet_ssh_state", lambda remote: (False, False, False))
    _es3["no_way_back"] = _p9_json(_c69.post("/api/remote/%d/close-port-22" % P9_HOST)).get("message")
    _p9_patch(_cp69, "_tailnet_ssh_state", lambda remote: (True, True, True))
    _p9_patch(_cp69, "remote_ufw_close_port_22", lambda remote: (True, "Port 22 rule removed from UFW"))
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
        _ijobs69.pop(P9_GS, None)
    _lang69("en")
    _p9_restore_all()
check("close port 22 (es): the no-way-back refusal and the removed-rule answer are Spanish (both were "
      "English in every language)",
      (_es3.get("no_way_back") or "").startswith("Rechazado: no hay una vía de vuelta por Tailscale")
      and _es3.get("closed") == "Regla del puerto 22 eliminada de UFW", repr(_es3))
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
    _sio69.disconnect()
finally:
    _p9_restore_all()
    with _ht69._sid_lock:
        for _s69 in [_exit69.get("sid")]:
            _ht69._sid_host.pop(_s69, None)
            _ht69._sid_owner.pop(_s69, None)
check("terminal: term_exit and term_error carry the template and values with the English (an idle close, "
      "a refusal with a count), so the page can say them in the viewer's language",
      {"reason": "closed after 15 minutes with no input", "reason_key": "closed after {n} minutes with no input",
       "reason_vals": {"n": "15"}} in _sock69.get("term_exit", [])
      and {"message": "You already have 3 terminals open. Close one and try again.",
           "message_key": "You already have {n} terminals open. Close one and try again.",
           "message_vals": {"n": "3"}} in _sock69.get("term_error", []), repr(_sock69)[:900])
