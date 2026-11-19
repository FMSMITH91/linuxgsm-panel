"""Part 249 of the unit suite: uploads stay signed in and never block the next one; dialogs over modals.

* backupUpload (panel.js) marks every request as the person's own (X-Panel-Background: 0), through
  the page's fetch wrapper, long after the last click; a piece that never answers is cancelled. The
  Databases manager's dump upload and the file tree upload send the same mark.
* The upload routes (game, panel, database) let the same user's new start replace an upload of
  theirs that has gone quiet, removing its part file; a live one, one with a request running, or
  another user's still refuses. A piece marks its upload busy while it runs.
* The Databases manager drops a tables or rows reply that is no longer the latest, so Delete acts
  on the table whose rows are shown; an upload keeps the database it started for.
* confirmDialog opens inside an open Bootstrap modal (its focus trap), and Escape there closes only
  the dialog.
* A cancelled step-up leaves Auto-block, "Link this machine" and a firewall rule's Remove as they
  were; Uninstall confirms the password in place.
* Templates: every form posting to a step_up_required route carries data-step-up; no field that
  takes a backup code asks for a numeric keypad; the Databases page links a name to Files & Config
  only for a viewer who may open it.

Nothing reaches a host.
"""
import os
import re as _re249
import time as _time249
from types import SimpleNamespace as _NS249

from unit.part01 import check, eq, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch, _p9_patch_sm,
                         _p9_restore_all)
from unit.part47 import _cut47, _node47
from unit.part226 import _db_setup226, _db_teardown226
from panel.db import models as _m249
from panel.ops import backup as _bk249
from panel.routes import _shared as _shr249, backup_upload as _bu249, databases_files as _dfr249
from panel.security import auth as _auth249
from panel.services import game_restore as _grs249

_TRIP249 = len(_P9_TRIPPED)
_TPL249 = os.path.join(_root, "panel", "templates")


def _read249(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _js249(name):
    return _read249("panel", "static", "js", name)


def _cut249(src, head):
    """The statement starting `head`, or a comment naming it (the check then fails by name)."""
    return _cut47(src, head) if head in src else "/* MISSING %s */" % head


def _run249(name, prog):
    """Node's JSON answer for `prog`, or None after a named skip when node is missing."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


_PANEL249 = _js249("panel.js")
_SETTLE249 = "const settle = async () => { for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r)); };\n"

# A small stand-in DOM: enough of an element for the dialog and the Databases manager.
_DOM249 = r"""
class El {
  constructor(tag){ this.tagName = String(tag || 'div').toUpperCase(); this.children = []; this.attrs = {};
    this.className = ''; this._text = ''; this.hidden = false; this.disabled = false; this.value = '';
    this.parent = null; this.listeners = {}; this.style = {}; this._q = {};
    this.classList = {toggle(){}, add(){}, remove(){}}; }
  appendChild(c){ if (c.parent) c.parent.children.splice(c.parent.children.indexOf(c), 1);
    c.parent = this; this.children.push(c); return c; }
  insertBefore(c){ return this.appendChild(c); }
  remove(){ if (this.parent) { this.parent.children.splice(this.parent.children.indexOf(this), 1); this.parent = null; }
    this.removed = true; }
  set textContent(v){ this._text = String(v); this.children = []; }
  get textContent(){ return this._text; }
  set innerHTML(v){ this._html = String(v); }
  get innerHTML(){ return this._html || ''; }
  setAttribute(k, v){ this.attrs[k] = String(v); }
  getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; }
  hasAttribute(k){ return k in this.attrs; }
  removeAttribute(k){ delete this.attrs[k]; }
  addEventListener(t, f){ (this.listeners[t] = this.listeners[t] || []).push(f); }
  removeEventListener(){}
  querySelector(sel){ return this._q[sel] = this._q[sel] || new El('x'); }
  querySelectorAll(){ return []; }
  focus(){}
  click(){}
}
const ids = {};
global.window = global;
global.document = {body: new El('body'), modals: [],
  createElement: t => new El(t), createTextNode: t => { const e = new El('#text'); e.textContent = t; return e; },
  getElementById: id => ids[id] = ids[id] || new El('div'),
  querySelectorAll: sel => sel === '.modal.show' ? document.modals : [],
  querySelector: () => null, addEventListener(){}, removeEventListener(){}};
"""


def _resp249():
    """JS: an answer object as fetch gives it, from a status and a JSON body."""
    return ("function answer(body, status){ status = status || 200; const r = {ok: status < 400, status,\n"
            "  headers: {get: () => null}, json: () => Promise.resolve(body), clone(){ return r; }}; return r; }\n")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. backupUpload through the page's fetch wrapper: marked as the person's own; a dropped piece cancels
# ════════════════════════════════════════════════════════════════════════════════════════════════
_WRAP249 = _cut249(_PANEL249, "(function(){\n  var _fetch = window.fetch.bind(window);")
_name249 = "backup upload: pieces through the fetch wrapper long after the click"
_up249 = _run249(_name249, (
    _SETTLE249 + _resp249() +
    "global.window = global; window.MOUNT = ''; window.CSRF = 'c'; window.SIGNED_IN = true;\n"
    "global.addEventListener = () => {};\n"
    # A lost piece is sent again after pauses (part261 drives those): no real wait here.
    "global.setTimeout = (f) => setImmediate(f);\n"
    "global.location = {pathname: '/s', search: ''};\n"
    "global.document = {addEventListener(){}, querySelectorAll(){ return []; }, querySelector(){ return null; }};\n"
    "const sent = []; let drop = -1;\n"
    "window.fetch = function(url, init){\n"
    "  sent.push({url: String(url), bg: new Headers(init.headers).get('X-Panel-Background')});\n"
    "  const m = /offset=(\\d+)/.exec(url);\n"
    "  if (/cancel$/.test(url)) return Promise.resolve(answer({success: true}));\n"
    "  if (/finish$/.test(url)) return Promise.resolve(answer({success: true, name: 'a.tar.gz'}));\n"
    "  if (m) { const at = Number(m[1]); if (at === drop) return Promise.reject(new TypeError('Failed to fetch'));\n"
    "    return Promise.resolve(answer({success: true, received: Math.min(at + 4, 10)})); }\n"
    "  if (/\\/upload$/.test(url)) return Promise.resolve(answer({success: true, id: 'u1', chunk: 4}));\n"
    "  return Promise.resolve(answer({}));\n"
    "};\n"
    + _WRAP249 + ")();\n"
    "const t0 = Date.now(); Date.now = () => t0 + 600000;\n"
    + _cut249(_PANEL249, "window.backupUpload = function(") + "\n"
    "const file = {size: 10, slice: (a, b) => 'x'.repeat(b - a)};\n"
    "(async () => {\n"
    "  const ok = await window.backupUpload(file, '/x/upload', null);\n"
    "  const okSent = sent.splice(0);\n"
    "  await window.fetch('/api/poll', {});\n"
    "  const poll = sent.splice(0);\n"
    "  drop = 4; let err = null;\n"
    "  try { await window.backupUpload(file, '/x/upload', null); } catch (e) { err = String(e.message || e); }\n"
    "  console.log(JSON.stringify({ok, okSent, poll, dropSent: sent, err}));\n"
    "})();\n"))
if _up249 is not None:
    _okb249 = sorted({s.get("bg") for s in _up249.get("okSent") or [{}]}, key=str)
    check("backup upload: ten minutes after the last click every request of an upload (start, pieces, finish) "
          "reaches the server marked X-Panel-Background: 0 through the page's fetch wrapper — it was marked 1 "
          "from 10 s on, so the session ran out part way", _okb249 == ["0"] and len(_up249.get("okSent") or []) == 5
          and (_up249.get("ok") or {}).get("success") is True, repr(_up249))
    eq("backup upload: ...while a poll sent at the same moment is still marked background (control)",
       [s.get("bg") for s in _up249.get("poll") or []], ["1"])
    _ds249 = [s.get("url") for s in _up249.get("dropSent") or []]
    check("backup upload: a piece that never answers sends the upload's cancel (marked as the person's own), "
          "then fails as before — the server held the upload for two hours and refused a retry",
          _ds249[-1:] == ["/x/upload/u1/cancel"] and "/x/upload/u1?offset=4" in _ds249
          and (_up249.get("dropSent") or [{}])[-1].get("bg") == "0" and _up249.get("err") == "Failed to fetch",
          repr(_up249))
    check("backup upload: ...and a whole upload sends no cancel (control)",
          not [s for s in _up249.get("okSent") or [] if s.get("url", "").endswith("/cancel")], repr(_up249))

_SFJS249 = _js249("server_files.js")
_doup249 = _cut249(_SFJS249, "function _doUpload(")
check("file tree upload: each file's request is marked as the person's own (X-Panel-Background: 0), so a tree "
      "that takes longer than the idle timeout keeps the sign-in",
      "fetch(MOUNT+'/api/server/'+serverId+'/upload',{method:'POST',body:fd,headers:{'X-Panel-Background':'0'}})"
      in _doup249, _doup249[:200])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The Databases manager: stale replies dropped, the upload keeps its database
# ════════════════════════════════════════════════════════════════════════════════════════════════
_DBM249 = _js249("databases_manager.js")
_TABLES249 = ("{tables: [{name: 'players', columns: [{name: 'id', type: 'int', nullable: false, key: 'PRI', "
              "default: null, extra: ''}]}, {name: 'bans', columns: [{name: 'id', type: 'int', nullable: false, "
              "key: 'PRI', default: null, extra: ''}]}], can_edit: true}")
_name249 = "databases manager: replies that land out of order"
_dbm249 = _run249(_name249, (
    _SETTLE249 + _DOM249 + _resp249() +
    "window.MOUNT = ''; const pend = []; const posts = [];\n"
    "window.fetch = function(url, init){ init = init || {};\n"
    "  let body = null; try { body = JSON.parse(init.body); } catch (e) { body = null; }\n"
    "  if ((init.method || 'GET') === 'POST') posts.push({url, body,\n"
    "    bg: (init.headers || {})['X-Panel-Background'] || null});\n"
    "  return new Promise(res => pend.push({url, res})); };\n"
    "function reply(part, body){ const i = pend.findIndex(p => p.url.indexOf(part) >= 0);\n"
    "  if (i < 0) return false; pend.splice(i, 1)[0].res(answer(body)); return true; }\n"
    "let dialog = null; window.confirmDialog = o => { dialog = o; };\n"
    + _DBM249 + "\n"
    "(async () => {\n"
    "  dbmOpen(5, 7, 'gs5_db', '127.0.0.1', 3306);\n"
    "  dbmLoadTables(); await settle();\n"
    "  reply('/databases/7/tables', " + _TABLES249 + "); await settle();\n"
    "  ids['dbm-table'].value = 'bans'; dbmPickTable(); await settle();\n"
    "  const rowsOf = id => ({columns: ['id'], rows: [{key: {id}, cells: [{text: id}]}], more: false});\n"
    "  reply('table=bans', rowsOf('17')); await settle();\n"
    "  reply('table=players', rowsOf('99')); await settle();\n"
    "  const st = dbmCtx.st, shown = st.rowsOf && st.rowsOf.name, rowKey = st.rows && st.rows.rows[0].key;\n"
    "  dbmDeleteRow(0); if (dialog) dialog.onConfirm(); await settle();\n"
    "  const del = posts.filter(p => /\\/row$/.test(p.url)).map(p => p.body);\n"
    # a tables reply for the database the dialog was open on before
    "  dbmLoadTables(); await settle(); dbmOpen(5, 8, 'gs5_other', '127.0.0.1', 3306);\n"
    "  reply('/databases/7/tables', " + _TABLES249 + "); await settle();\n"
    "  const staleTables = dbmCtx.st.tables;\n"
    # an upload started on 7 keeps going to 7 after 8 is opened
    "  dbmOpen(5, 7, 'gs5_db', '127.0.0.1', 3306);\n"
    "  const dump = {name: 'd.sql', size: 6, slice: (a, b) => 'x'.repeat(b - a)};\n"
    "  document.getElementById('dbm-upload-file').files = [dump];\n"
    "  dialog = null; dbmUpload(); dialog.onConfirm(); await settle();\n"
    "  dbmOpen(5, 8, 'gs5_other', '127.0.0.1', 3306);\n"
    "  reply('/databases/7/upload', {success: true, id: 'ab', chunk: 4}); await settle();\n"
    "  const piece = pend.filter(p => /offset=/.test(p.url)).map(p => p.url);\n"
    "  const upPosts = posts.filter(p => /\\/upload/.test(p.url)).map(p => [p.url, p.bg]);\n"
    "  console.log(JSON.stringify({shown, rowKey, del, staleTables, piece, upPosts}));\n"
    "})();\n"))
if _dbm249 is not None:
    eq("databases manager: players picked, then bans, and players' rows land last — the rows kept and shown "
       "are bans', and Delete on the first row deletes bans id 17 (it deleted bans' row by players' key)",
       (_dbm249.get("shown"), _dbm249.get("rowKey"), _dbm249.get("del")),
       ("bans", {"id": "17"}, [{"op": "delete", "table": "bans", "key": {"id": "17"}}]))
    eq("databases manager: a tables reply for the database open before is dropped once another is opened",
       _dbm249.get("staleTables"), None)
    check("databases manager: an upload started on one database sends its pieces to that database after another "
          "is opened, and its requests are marked as the person's own",
          _dbm249.get("piece") == ["/api/server/5/databases/7/upload/ab?offset=0"]
          and _dbm249.get("upPosts") == [["/api/server/5/databases/7/upload", "0"],
                                         ["/api/server/5/databases/7/upload/ab?offset=0", "0"]], repr(_dbm249))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. confirmDialog inside an open Bootstrap modal
# ════════════════════════════════════════════════════════════════════════════════════════════════
_name249 = "confirm dialog: where it is put, and Escape"
_cd249 = _run249(_name249, (
    _DOM249 + "global.escapeHtml = s => String(s); global.t = s => s;\n"
    + "".join(_cut249(_PANEL249, h) + "\n" for h in (
        "function _cdInputHtml(", "function _cdFillBody(", "function _cdGateConfirm(", "function _cdHost(",
        "window.confirmDialog = function("))
    + "const page = document.body.children;\n"
    "confirmDialog({title: 'x', requireText: 'gs5_db'});\n"
    "const plain = [page.length, page[0] && page[0].className];\n"
    "page[0].remove();\n"
    "const modal = new El('div'); modal.className = 'modal show'; document.body.appendChild(modal);\n"
    "document.modals = [modal];\n"
    "confirmDialog({title: 'x', requireText: 'gs5_db'});\n"
    "const ov = modal.children[0], inModal = [modal.children.length, ov && ov.className, page.length];\n"
    "let stopped = false;\n"
    "(ov.listeners.keydown || []).forEach(f => f({key: 'Escape', stopPropagation(){ stopped = true; }}));\n"
    "console.log(JSON.stringify({plain, inModal,\n"
    "                            esc: [stopped, !!ov.removed]}));\n"))
if _cd249 is not None:
    eq("confirm dialog: with a Bootstrap modal open it is put inside the modal (in its focus trap), so its field "
       "takes the typed name or the step-up password — outside it the modal took focus back on every key",
       _cd249.get("inModal"), [1, "dialog-overlay", 1])
    eq("confirm dialog: ...with none open it goes on the page as before (control)", _cd249.get("plain"),
       [1, "dialog-overlay"])
    eq("confirm dialog: Escape inside it closes the dialog and stops there, so the modal under it stays open",
       _cd249.get("esc"), [True, True])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. A cancelled step-up changes nothing; Uninstall confirms in place
# ════════════════════════════════════════════════════════════════════════════════════════════════
_RM249 = _js249("remote_manage.js")
_name249 = "auto-block: a cancelled or passed step-up"
_ab249 = _run249(_name249, (
    _SETTLE249 + _resp249() +
    "global.window = global; const posts = []; let pass = false;\n"
    "global.toast = () => {}; global.secBase = () => '/sec'; global.loadSecurityTopIps = () => {};\n"
    "global.setTimeout = () => {};\n"
    "global.fetch = (u, i) => { posts.push(JSON.parse(i.body)); return Promise.resolve(answer({success: true})); };\n"
    "function _secStepUp(go){ if (pass) go(); }\n"
    + _cut249(_RM249, "function toggleAutoblock(") + "\n" + _cut249(_RM249, "function _toggleAutoblockNow(") + "\n"
    "(async () => {\n"
    "  const cb = {checked: true};          // the click turned it on\n"
    "  toggleAutoblock(cb); await settle();\n"
    "  const cancelled = [cb.checked, posts.length];\n"
    "  pass = true; cb.checked = true; toggleAutoblock(cb); await settle();\n"
    "  console.log(JSON.stringify({cancelled, passed: [cb.checked, posts]}));\n"
    "})();\n"))
if _ab249 is not None:
    eq("auto-block: a cancelled password dialog leaves the switch as the host has it (off) and sends nothing — "
       "it stayed on, and the next threshold Save posted that unconfirmed state", _ab249.get("cancelled"),
       [False, 0])
    eq("auto-block: ...confirmed, the switch reads on and that is what is sent (control)", _ab249.get("passed"),
       [True, [{"enabled": True}]])

_TS249 = _js249("tailscale.js")
_FW249 = _js249("remote_firewall.js")
_name249 = "cancelled step-up: Link this machine and a firewall rule's Remove"
_btn249 = _run249(_name249, (
    "global.window = global; let pass = false; const ups = [];\n"
    "const btn = {disabled: false, listeners: {}, addEventListener(t, f){ this.listeners[t] = f; }};\n"
    "global.document = {getElementById: id => ({'ts-connect-btn': btn, 'ts-connect-out': {}})[id] || null};\n"
    "function _tsStepUp(go){ if (pass) go(); }\n"
    "function _tsUpNow(out, b){ ups.push(!!(b && b.disabled)); }\n"
    + "".join(_cut249(_TS249, h) + "\n"
              for h in ("function _r34c_tsOnce(", "function wireTsButtons(", "function tsUp("))
    + "wireTsButtons();\n"
    "btn.listeners.click(); const tsCancelled = btn.disabled;\n"
    "pass = true; btn.listeners.click(); const tsPassed = [btn.disabled, ups];\n"
    # the firewall rule's Remove
    "pass = false; global.MOUNT = ''; global.remoteId = 1; global.t = s => s; global.toast = () => {};\n"
    "global.refreshFirewall = () => {}; global._fwReason = () => '';\n"
    "global.fetch = () => new Promise(() => {});\n"
    "global.confirmDialog = o => o.onConfirm();\n"
    "function _fwStepUp(go){ if (pass) go(); }\n"
    + _cut249(_FW249, "function deleteGroup(") + "\n"
    "const x = {disabled: false, innerHTML: '<i class=\"bi bi-x\"></i>'};\n"
    "deleteGroup([3], x, false, '', 'k1'); const fwCancelled = [x.disabled, x.innerHTML];\n"
    "pass = true; deleteGroup([3], x, false, '', 'k1');\n"
    "const fwPassed = [x.disabled, x.innerHTML.indexOf('spinner') >= 0];\n"
    "console.log(JSON.stringify({tsCancelled, tsPassed, fwCancelled, fwPassed}));\n"))
if _btn249 is not None:
    eq("Link this machine: a cancelled password dialog leaves the button usable — it was disabled before the "
       "dialog and stayed dead until a reload", _btn249.get("tsCancelled"), False)
    eq("Link this machine: ...confirmed, it is disabled while Tailscale comes up (control)",
       _btn249.get("tsPassed"), [True, [True]])
    eq("firewall rule Remove: a cancelled password dialog leaves the row's button as it was, not a dead spinner",
       _btn249.get("fwCancelled"), [False, '<i class="bi bi-x"></i>'])
    eq("firewall rule Remove: ...confirmed, it shows the spinner while the rule goes (control)",
       _btn249.get("fwPassed"), [True, True])

_name249 = "uninstall: the password confirmed in place"
_un249 = _run249(_name249, (
    "global.window = global; global.escapeHtml = s => s; global.tf = s => s; global.tfHtml = s => s;\n"
    "let dlg = null; global.confirmDialog = o => { dlg = o; };\n"
    "const asked = []; let goNow = null; window.stepUpThen = (go, totp) => { asked.push(totp); goNow = go; };\n"
    "let sent = 0; const attrs = {'data-step-up': '', 'data-step-up-totp': '1'};\n"
    "const form = {hasAttribute: k => k in attrs, getAttribute: k => attrs[k], submit: () => { sent++; }};\n"
    + _cut249(_PANEL249, "function _uninstallDialog(") + "\n"
    "_uninstallDialog(form, 'Srv', 'srvuser', []); dlg.onConfirm();\n"
    "const before = sent; if (goNow) goNow();\n"
    "console.log(JSON.stringify({asked, before, after: sent}));\n"))
if _un249 is not None:
    eq("uninstall: after the typed name, a form with data-step-up asks for the password in place first "
       "(with the 2FA code when the form says so) and is submitted only once that passes — it went to the "
       "confirm page and back", _un249, {"asked": [True], "before": 0, "after": 1})


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The templates: data-step-up on every step-up form, keypads, the Databases page's links
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _step_up_endpoints249():
    """Every endpoint whose view is step_up_required (its decorator marks the view _step_up)."""
    return {ep for ep, fn in _p9.view_functions.items() if getattr(fn, "_step_up", False)}


def _forms249():
    """(template, endpoint or None, form tag, form body) for every POST form in panel/templates."""
    out = []
    for f in sorted(os.listdir(_TPL249)):
        if not f.endswith(".html"):
            continue
        text = _read249("panel", "templates", f)
        for m in _re249.finditer(r"<form\b[^>]*>", text):
            tag = m.group(0)
            if 'method="POST"' not in tag:
                continue
            ep = _re249.search(r"url_for\('(\w+)'", tag)
            end = text.find("</form>", m.end())
            out.append((f, ep.group(1) if ep else None, tag, text[m.end():end if end >= 0 else len(text)]))
    return out


_SU249 = _step_up_endpoints249()
_FORMS249 = _forms249()
# The edit-user form's action is filled in by manage_users.js (openEditUser) with edit_user's URL.
_ACTION_BY_ID249 = {"edit-user-form": "edit_user"}


def _form_ep249(tag, ep):
    if ep:
        return ep
    m = _re249.search(r'\bid="([\w-]+)"', tag)
    return _ACTION_BY_ID249.get(m.group(1)) if m else None


# The attribute itself (step_up_form.js and panel.js ask hasAttribute('data-step-up')), not the -totp one.
_HAS_SU249 = _re249.compile(r"\sdata-step-up(?=[\s>])")
_su_forms249 = [(f, _form_ep249(tag, ep), tag) for f, ep, tag, _b in _FORMS249 if _form_ep249(tag, ep) in _SU249]
_missing249 = [(f, ep) for f, ep, tag in _su_forms249 if not _HAS_SU249.search(tag)]
check("templates: every POST form whose route is step_up_required carries data-step-up (the user, group and "
      "invite forms and Uninstall did not: a stale sign-in lost what was typed on the confirm page)",
      len(_su_forms249) >= 18 and not _missing249
      and {"add_user", "edit_user", "delete_user", "create_invite", "revoke_invite", "add_group", "edit_group",
           "delete_group", "uninstall_server"} <= {ep for _f, ep, _t in _su_forms249},
      repr(_missing249 or len(_su_forms249)))
_totp_tag249 = [(f, tag) for f, _ep, tag, _b in _FORMS249 if _HAS_SU249.search(tag)
                and "data-step-up-totp=\"{{ '1' if current_user.totp_enabled else '0' }}\"" not in tag]
check("templates: ...each says whether the account has 2FA (data-step-up-totp), so the dialog asks for the code",
      not _totp_tag249, repr(_totp_tag249))

# A code field may ask for a numeric keypad only where the route takes an authenticator code alone.
_TOTP_ONLY249 = {"account_owner_transfer", "account_2fa_enable"}
_codes249 = []
for _f249, _ep249, _tag249, _body249 in _FORMS249:
    for _mt249 in _re249.finditer(r'<input\b[^>]*name="totp_code"[^>]*>', _body249):
        _codes249.append((_f249, _ep249, 'inputmode="numeric"' in _mt249.group(0)))
_root_cron249 = _read249("panel", "templates", "root_cron.html")
_rc_inputs249 = _re249.findall(r'<input\b[^>]*name="totp_code"[^>]*>', _root_cron249)
_bad249 = [(f, ep) for f, ep, numeric in _codes249 if numeric and ep not in _TOTP_ONLY249]
check("templates: no 2FA field whose route also takes a backup code (step-up confirm, Schedules' root cron "
      "switch, the root cron page) sets inputmode=numeric, whose phone keypad has no letters or dash",
      len(_codes249) >= 6 and not _bad249 and _rc_inputs249
      and not [i for i in _rc_inputs249 if "inputmode" in i], repr(_bad249 or _codes249))
check("templates: ...the authenticator-only fields (owner transfer, turning 2FA on) keep it (control)",
      {ep for f, ep, numeric in _codes249 if numeric} == _TOTP_ONLY249, repr(_codes249))
_withcode249 = _cut249(_js249("step_up_form.js"), "function withCode(")
check("step-up dialog: its code field sets no numeric keypad (it takes a backup code too)",
      "autocomplete = 'one-time-code'" in _withcode249 and "inputMode" not in _withcode249, _withcode249[:300])


def _overview249():
    """The Databases page for a View-servers-only viewer and for a superadmin: (status, text) each."""
    from werkzeug.security import generate_password_hash
    sid, _api, name = _db_setup226()
    try:
        with _p9.app_context():
            grp = _m249.Group(name="p249_vs", description="", is_default=False)
            grp.set_permissions([_auth249.VIEW_SERVERS])
            grp.servers.append(_m249.db.session.get(_m249.RemoteServer, P9_HOST))
            u = _m249.User(username="p249_vs", password_hash=generate_password_hash(os.urandom(12).hex()),
                           display_name="p249", is_superadmin=False, is_active=True)
            u.groups.append(grp)
            _m249.db.session.add_all([grp, u])
            _m249.db.session.commit()
            uid, gid = u.id, grp.id
        try:
            out = {}
            for who, c in (("viewer", _p9_client(uid)), ("admin", _p9_client(P9_ADMIN))):
                r = c.get("/databases")
                out[who] = (r.status_code, r.get_data(as_text=True))
            return name, sid, out
        finally:
            with _p9.app_context():
                _m249.User.query.filter_by(id=uid).delete()
                _m249.Group.query.filter_by(id=gid).delete()
                _m249.db.session.commit()
    finally:
        _db_teardown226(sid)


_p9_arm()
try:
    _ovn249, _ovs249, _ov249 = _overview249()
finally:
    _p9_restore_all()
_files249 = "/server/%d/files" % _ovs249
_vtext249 = _ov249["viewer"][1]
check("Databases page: a viewer with View servers alone sees the database's name as text, not a link to Files & "
      "Config (which refuses that permission with a red error)",
      _ov249["viewer"][0] == 200 and _ovn249 in _vtext249 and _files249 not in _vtext249,
      repr((_ov249["viewer"][0], _ovn249 in _vtext249, _files249 in _vtext249)))
check("Databases page: ...a viewer who may open Files & Config gets the link (control)",
      _ov249["admin"][0] == 200 and _files249 + "#databases" in _ov249["admin"][1],
      repr((_ov249["admin"][0], _files249)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. The upload routes: a quiet upload of the same user's is replaced; anything else still refuses
# ════════════════════════════════════════════════════════════════════════════════════════════════
_OLD249 = "a" * 32
_MARKS249 = _NS249(game=_grs249._M, db=_dfr249._M)


def _plant249(table, entry):
    table.clear()
    table[entry["uid"]] = entry


def _game_entry249(user, age, busy=0):
    return {"uid": _OLD249, "kind": "game", "sid": P9_GS, "user": user, "size": 10, "got": 0,
            "ts": _time249.time() - age, "busy": busy}


def _game_starts249(user_of_old):
    """Start a game upload over each planted old one: {case: (status, the old id still listed, commands)}."""
    cmds = []

    def _run(*a, **k):
        cmds.append(a[1])
        return _MARKS249.game["UPREADY"], "", 0
    _p9_patch(_bu249, "_sm", _NS249(game_user_cmd=lambda user, inner: inner, _fmt_size=str,
                                    run_command=_run))
    _p9_patch(_shr249, "game_account_write_refusal", lambda *a, **k: None)
    c, out = _p9_client(P9_ADMIN), {}
    for case, entry in (("stalled", _game_entry249(P9_ADMIN, 600)), ("live", _game_entry249(P9_ADMIN, 5)),
                        ("busy", _game_entry249(P9_ADMIN, 600, busy=1)),
                        ("other user", _game_entry249(user_of_old, 600))):
        _plant249(_bu249._uploads, entry)
        del cmds[:]
        r = c.post("/api/panel/backup/game/%d/upload" % P9_GS, json={"size": 10})
        out[case] = (r.status_code, _OLD249 in _bu249._uploads,
                     [x for x in cmds if _OLD249 in x and "rm -f" in x])
    return out


def _piece_busy249():
    """A piece's command sees its upload busy; afterwards it is not, and its quiet time starts again."""
    seen = []
    entry = _game_entry249(P9_ADMIN, 600)

    def _run(*a, **k):
        seen.append(entry.get("busy"))
        entry["ts"] = _time249.time() - 600     # a command that ran ten minutes after the request began
        return _MARKS249.game["UPSIZE"] + " 4", "", 0
    _p9_patch(_bu249, "_sm", _NS249(game_user_cmd=lambda user, inner: inner, _fmt_size=str,
                                    run_command=_run))
    _plant249(_bu249._uploads, entry)
    r = _p9_client(P9_ADMIN).post("/api/panel/backup/game/%d/upload/%s?offset=0" % (P9_GS, _OLD249), data=b"abcd",
                                  content_type="application/octet-stream")
    return r.status_code, seen, entry.get("busy"), _time249.time() - entry["ts"] < 30


def _panel_start249():
    """Start a panel upload over the admin's quiet one: (status, the ids discarded)."""
    gone = []
    _p9_patch(_bu249, "bk", _NS249(UPLOAD_MAX=_bk249.UPLOAD_MAX, UPLOAD_CHUNK=_bk249.UPLOAD_CHUNK,
                                   upload_begin=lambda uid, size: "", upload_discard=gone.append))
    old = dict(_game_entry249(P9_ADMIN, 600), kind="panel", sid=0)
    _plant249(_bu249._uploads, old)
    r = _p9_client(P9_ADMIN).post("/api/panel/backup/upload", json={"size": 10})
    return r.status_code, gone


def _db_starts249():
    """Start a database upload over the admin's quiet one, with the host's cancel answering and not."""
    sid, api, _name = _db_setup226()
    cmds, answer = [], {"cancel": _MARKS249.db["READY"]}

    def _cmd(server, cmd, timeout=30, sudo=True, **kw):
        cmds.append(cmd)
        if _OLD249 in cmd:
            return answer["cancel"], "", 0
        return _MARKS249.db["READY"], "", 0
    try:
        _p9_patch_sm("run_command", _cmd)
        _p9_patch(_dfr249, "game_account_write_refusal", lambda remote, user, **k: None)
        with _p9.app_context():
            dbid = _m249.GameDatabase.query.filter_by(game_server_id=sid).first().id
        out, c = {}, _p9_client(P9_ADMIN)
        for case, said in (("cancelled", _MARKS249.db["READY"]), ("cancel unanswered", "")):
            answer["cancel"] = said
            _plant249(_dfr249._UPLOADS, {"uid": _OLD249, "db": dbid, "user": P9_ADMIN, "size": 10,
                                         "ts": _time249.time() - 600})
            del cmds[:]
            r = c.post(api + "/upload", json={"size": 10})
            out[case] = (r.status_code, _OLD249 in _dfr249._UPLOADS, len(_dfr249._UPLOADS),
                         bool([x for x in cmds if _OLD249 in x]))
        return out
    finally:
        _db_teardown226(sid)


_p9_arm()
try:
    _gs249 = _game_starts249(P9_ADMIN + 100000)
    _pb249 = _piece_busy249()
    _ps249 = _panel_start249()
    _dbs249 = _db_starts249()
finally:
    _p9_restore_all()
    _bu249._uploads.clear()
    _dfr249._UPLOADS.clear()
eq("game upload: the same user's upload with nothing running and nothing for a minute is replaced by a new start "
   "(its part file removed on the host) — it was refused for two hours", _gs249["stalled"][:2], (200, False))
check("game upload: ...and the old upload's part file is removed by its cancel command", bool(_gs249["stalled"][2]),
      repr(_gs249["stalled"]))
eq("game upload: a live upload (a request a few seconds ago) still refuses a second start", _gs249["live"][:2],
   (409, True))
eq("game upload: ...so does one with a request still running, however long ago it began",
   _gs249["busy"][:2], (409, True))
eq("game upload: ...and another user's quiet upload is never replaced", _gs249["other user"][:2], (409, True))
eq("game upload: a piece's command runs with its upload marked busy; after it the upload is not busy and its "
   "quiet time starts from the answer, not from when a long command began", _pb249, (200, [1], 0, True))
eq("panel backup upload: the admin's quiet upload is replaced and its part file discarded", _ps249,
   (200, [_OLD249]))
eq("database upload: the user's quiet upload is cancelled on the host (the earlier dump put back) and replaced",
   _dbs249["cancelled"], (200, False, 1, True))
eq("database upload: ...when that cancel does not answer (its finish still holds the host's lock) the new upload "
   "is refused and the old one stays listed", _dbs249["cancel unanswered"], (409, True, 1, True))

eq("part249: no check reached a real transport", _P9_TRIPPED[_TRIP249:], [])
