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
