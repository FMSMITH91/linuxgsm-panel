"""Part 277 of the unit suite: test-only fixes of review pass 34.

1. The js-coverage walk answers a typed or password confirm dialog through the field panel.js
   really builds (its own id per dialog, data-cd="input"), instead of cancelling every one.
2. run_game_backup keeps the name of the archive it proved it wrote (last_backup_made), which a
   restore names its undo archive by.
3. A workflow job's block runs past a comment at column 0.
4. Disable Serve sends the mount its button names.
5. A queued stop/restart does not run while its server is being uninstalled.
6. A status-marked tooltip or placeholder is translated as a marked text is.

Nothing here reaches a host.
"""
import os

from unit.part01 import check, eq
from unit.part05 import _root
from unit.part12 import (P9_HOST, _p9, _p9_arm, _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm,
                         _p9_restore_all, _p9_row, _p9_set)
from unit.part29 import _job29
from unit.part47 import _cut47, _node47


def _read277(*parts):
    """The text of a file under the checkout."""
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The js-coverage walk types into the confirm dialog panel.js builds
# ════════════════════════════════════════════════════════════════════════════════════════════════
_PANEL277 = _read277("panel", "static", "js", "panel.js")
_HELP277 = _read277("tools", "js_coverage", "helpers.js")
# The field is panel.js's own _cdInputHtml output, parsed into elements; the card answers the
# selectors helpers.js asks (#id, [attr="v"], tag[attr="v"]) from those elements only.
_CD_PROG277 = (
    "global.window = global; global.HTMLInputElement = function () {};\n"
    "function escapeHtml(s){ return String(s).replace(/[&<>\"']/g, c => '&#' + c.charCodeAt(0) + ';'); }\n"
    + _cut47(_PANEL277, "function _cdInputHtml(") + "\n"
    + _cut47(_HELP277, "function setValue(") + "\n"
    + _cut47(_HELP277, "function key(") + "\n"
    + _cut47(_HELP277, "function confirmAnswer(") + "\n"
    + _cut47(_HELP277, "function settleDialogs(") + "\n"
    "function els(html){ const out = []; const re = /<(label|input)\\b([^>]*)>([^<]*)/g; let m;\n"
    "  while ((m = re.exec(html))) { const a = {}; m[2].replace(/([\\w-]+)=\"([^\"]*)\"/g, (x, k, v) => { a[k] = v; });\n"
    "    out.push({tagName: m[1].toUpperCase(), id: a.id || '', type: a.type || '', attrs: a,\n"
    "              textContent: m[3], value: '', dispatchEvent(){}}); }\n"
    "  return out; }\n"
    "function match(el, sel){ let m;\n"
    "  if ((m = /^#([\\w-]+)$/.exec(sel))) return el.id === m[1];\n"
    "  if ((m = /^(\\w*)\\[([\\w-]+)=\"([^\"]*)\"\\]$/.exec(sel)))\n"
    "    return (!m[1] || el.tagName === m[1].toUpperCase()) && el.attrs[m[2]] === m[3];\n"
    "  return false; }\n"
    "let pressed, dialogOk;\n"
    "global.document = {querySelectorAll: s => s === '[data-cd=\"ok\"]' ? [dialogOk] : [],\n"
    "  getElementById: () => null, dispatchEvent(){}};\n"
    "function run(opts){ pressed = []; const fields = els(_cdInputHtml(opts));\n"
    "  const inp = fields.find(e => e.tagName === 'INPUT');\n"
    "  const cancel = {attrs: {'data-cd': 'cancel'}, click: () => pressed.push('cancel')};\n"
    "  const card = {querySelector: s => fields.concat([dialogOk, cancel]).find(e => match(e, s)) || null};\n"
    "  dialogOk = {attrs: {'data-cd': 'ok'}, closest: () => card, get disabled(){ return !inp.value; },\n"
    "    click: () => pressed.push('ok')};\n"
    "  settleDialogs(true, 'pw'); return [inp.id, inp.value, pressed]; }\n"
    "console.log(JSON.stringify({pw: run({requirePassword: true}),\n"
    "  text: run({requireText: 'srv1', requireLabel: 'Type the server name (srv1) to confirm'})}));\n")
_cd277 = _node47(_CD_PROG277)
if _cd277 is None:
    from unit.part01 import skip
    skip("js coverage: confirm dialogs answered", "node is not installed here")
else:
    check("js coverage: the confirming pass types the account password into a password confirm dialog built "
          "by panel.js and presses OK (it looked up a #cd-input that no longer exists and cancelled)",
          _cd277.get("pw") == ["cd-input-1", "pw", ["ok"]], repr(_cd277))
    check("js coverage: ...and types the name a typed-confirmation dialog's own label quotes, found by that "
          "dialog's own field id",
          _cd277.get("text") == ["cd-input-2", "srv1", ["ok"]], repr(_cd277))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. run_game_backup keeps the name of the archive it proved it wrote, for a restore's undo
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _backup277(made_name, user="p277gs"):
    """The answer of one forced run_game_backup whose verify step names `made_name` (None: no name).

    Every step that would reach a host is stood in; LinuxGSM's run "succeeds" and the real
    _bk_after_run passes its `made` list to the stood-in verify, which fills it.
    """
    from panel.ops.ssh_manager import cron as _cron277
    from panel.ops.ssh_manager import game as _game277

    def _verify(server, user, selfname, before, out, keep, headroom_note, made=None):
        if made is not None and made_name:
            made.append(made_name)
        return True, "done", False
    swaps = [(_game277, "_lg264_bk_before", lambda *a, **k: None),
             (_game277, "_lg264_bk_after", lambda *a, **k: None),
             (_game277._core, "shell_as_game_user", lambda *a, **k: ("", "", 0)),
             (_cron277, "_ensure_backup_headroom", lambda *a, **k: ""),
             (_game277, "_backup_space_refusal", lambda *a, **k: None),
             (_game277, "_bkpart_listing", lambda *a, **k: []),
             (_game277, "_run_linuxgsm_backup", lambda *a, **k: (True, False, "", "", 0)),
             (_game277, "_bkverify_success", _verify)]
    saved = [(m, n, getattr(m, n)) for m, n, _f in swaps]
    try:
        for m, n, f in swaps:
            setattr(m, n, f)
        server = type("S277", (), {"id": 277})()
        got = _game277.run_game_backup(server, user, force=True)
        return got, _game277.last_backup_made(server, user), _game277.last_backup_made(server, "p277other")
    finally:
        for m, n, f in saved:
            setattr(m, n, f)


_bk277 = _backup277("p277gs-2026-11-19-120000.tar.zst")
check("game backup: the archive a backup proved it wrote is what last_backup_made names for that server and "
      "account (a restore names its undo archive by it), and no other account's",
      _bk277 == ((True, "done", False), "p277gs-2026-11-19-120000.tar.zst", None), repr(_bk277))
_bk277b = _backup277(None)
check("game backup: ...and the next run starts with no name, so a run that names no archive leaves none "
      "(control)", _bk277b == ((True, "done", False), None, None), repr(_bk277b))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A workflow job's block runs past a comment at column 0
# ════════════════════════════════════════════════════════════════════════════════════════════════
_WF277 = ("jobs:\n  a:\n    steps:\n      - run: one\n# a note at column 0\n      - run: two\n"
          "  # a note at the jobs' indent\n      - run: three\n"
          "  # a comment before the next job\n  b:\n    runs-on: x\nenv:\n  k: 1\n")
eq("workflow reader: a job's block keeps the steps after a comment at column 0 or at the jobs' indent "
   "(review 1123), and still ends at the next job and at a top-level key",
   [_job29(_WF277, j) for j in ("a", "b")],
   [("  a:\n    steps:\n      - run: one\n# a note at column 0\n      - run: two\n  # a note at the jobs' indent\n"
     "      - run: three\n  # a comment before the next job\n"), "  b:\n    runs-on: x\n"])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Disable Serve sends the mount its button names
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TS277 = _read277("panel", "static", "js", "tailscale.js")
_ts277 = _node47(
    "var window = {}; var MOUNT = ''; const bodies = [];\n"
    "const chain = {then: () => chain, catch: () => chain, finally: () => chain};\n"
    "function fetch(url, init){ bodies.push(JSON.parse(init.body)); return chain; }\n"
    "function confirmDialog(o){ o.onConfirm(); }\n"
    + _cut47(_TS277, "function _tsStepUp(") + "\n" + _cut47(_TS277, "function disableServe(") + "\n"
    "disableServe({dataset: {mount: '/p277/panel'}}); disableServe({dataset: {}});\n"
    "console.log(JSON.stringify(bodies.map(b => [b.action, b.mount])));\n")
if _ts277 is None:
    from unit.part01 import skip
    skip("tailscale.js: Disable Serve's mount", "node is not installed here")
else:
    check("tailscale.js: Disable Serve sends the mount its button's data-mount names (a hardcoded '/' removes "
          "no mapping on a host proxying the panel at another route), and '/' only when the button names none",
          _ts277 == [["disable", "/p277/panel"], ["disable", "/"]], repr(_ts277))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. A queued stop/restart does not run while the server is being uninstalled
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _queued277(during_uninstall):
    """Settle a queued restart of an online, empty server: (LinuxGSM commands run, restart still queued)."""
    from panel.core import panel_state as _ps277
    from panel.db.models import GameServer, db
    from panel.routes import _shared as _sh277
    from panel.services import monitoring as _mon277
    sid, runs = _p9_new_server(P9_HOST, "rustp277", "rust", 28277, name="p277-queued"), []
    try:
        _p9_set(sid, restart_pending=True)
        _p9_arm(who="part277")
        _p9_patch(_sh277, "get_server_status", lambda *a, **k: "online")
        _p9_patch(_sh277, "sm_player_count", lambda *a, **k: 0)
        _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: runs.append(action) or ("", "", 0))
        _p9_patch_sm("set_game_priority", lambda *a, **k: None)
        with _p9.app_context():
            gs = db.session.get(GameServer, sid)
            if during_uninstall:
                with _ps277.r36j_route_job(sid, _sh277.UNINSTALL_KIND):
                    _sh277._settle_queued_action(_p9, gs)
            else:
                _sh277._settle_queued_action(_p9, gs)
        return runs, _p9_row(sid).restart_pending
    finally:
        _p9_restore_all()
        _sh277._queued_action_failures.pop(sid, None)
        _mon277._end_offline_window(sid)
        _p9_delete_server(sid)


_q277 = {"uninstall": _queued277(True), "free": _queued277(False)}
check("queued restart: one whose server is being uninstalled is not run (nothing reaches LinuxGSM) and stays "
      "queued; with no uninstall it runs (control)",
      _q277 == {"uninstall": ([], True), "free": (["restart"], False)}, repr(_q277))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. A status-marked attribute is translated as a marked text is
# ════════════════════════════════════════════════════════════════════════════════════════════════
# i18n.js runs whole, over one element whose attributes are the page; the catalog holds the
# unmarked keys only, which is what the i18n gates (in_catalog) accept for a marked text.
_I18N277 = _read277("panel", "static", "js", "i18n.js")
_attr277 = _node47(
    "const attrs = {title: '✓ Saved', placeholder: '❌ Port required', 'aria-label': '✓ Unknown'};\n"
    "const el = {nodeType: 1, tagName: 'BUTTON', firstChild: null, nextSibling: null, parentNode: null,\n"
    "  getAttribute: a => (a in attrs ? attrs[a] : null), setAttribute: (a, v) => { attrs[a] = v; },\n"
    "  hasAttribute: a => a in attrs};\n"
    "global.window = global;\n"
    "global.document = {body: el, documentElement: {}, querySelectorAll: () => [], addEventListener(){},\n"
    "  readyState: 'complete'};\n"
    "global.MutationObserver = class { observe(){} };\n"
    + _I18N277 + "\n"
    "window.setLang('es', {'Saved': 'Guardado', 'Port required': 'Puerto obligatorio'});\n"
    "console.log(JSON.stringify(attrs));\n")
if _attr277 is None:
    from unit.part01 import skip
    skip("i18n.js: marked attributes", "node is not installed here")
else:
    check("i18n.js: a status-marked tooltip or placeholder whose unmarked text is in the catalog is translated "
          "with its mark kept (the gates accept it through the unmarked key), and one with no key stays English",
          _attr277 == {"title": "✓ Guardado", "placeholder": "❌ Puerto obligatorio",
                       "aria-label": "✓ Unknown"}, repr(_attr277))
