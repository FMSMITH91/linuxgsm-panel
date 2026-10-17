"""Part 106 of the unit suite: the seventeenth review's page and script fixes (builder C).

Held here, each against the code path the finding named:

* the Backups card (Server Management): a refresh no longer wipes what the operator is typing. The
  passphrase box was cleared on EVERY refresh (a dozen land in the two minutes after "Back up now");
  a Keep box or the interval select rewritten while focused lost the typed value and its `change`; a
  per-server Schedule/Keep field was rebuilt under the cursor.
* the Live Resources card: a /live request with no JSON answer (the panel restarting behind a proxy,
  a phone off its network) shows the stale note on the second miss in a row; only an `error` reply did.
* the GMod install box says what the content scan does since #439: a copy only a panel game server
  holds is downloaded again, not reused (rendered, in English and through the es/fr catalogs).
* the Raw config editor (integrator, from A11's lead): a box typed into while a settings save's
  re-read came back is not saved over that save.
* the Add Remote form and the wizard's remote step (integrator, from A12's lead): an auth select a
  browser restored to Password brings the credential field's password type with it.

HOW IT RUNS. Scripts in node on part87's DOM, with the few element methods these need added in the
setup; the install page through part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally.
"""
import json as _json106
import os
import re as _re106

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _SETTLE47, _cut47, _node47
from unit.part87 import _DOM87
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9_arm, _p9_client, _p9_restore_all

_TRIP106_START = len(_P9_TRIPPED)


def _read106(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _piece106(src, head):
    """`head`'s statement: a braced one whole (_cut47), else its one line; a comment naming it if absent.

    A statement that is missing becomes that comment, so the check that runs it fails BY NAME.
    """
    if head not in src:
        return "/* MISSING %s */" % head
    line = src[src.index(head):].split("\n", 1)[0]
    return _cut47(src, head) if "{" in line else line


def _js106(name, setup, src, cuts, body):
    """Run part87's DOM + the element methods below + `setup` + the cut statements + `body` in node."""
    prog = (_DOM87 + _SETTLE47
            # contains: an element is inside `box` when it was made with `_in = box`.
            + "E87.prototype.contains = function(x){ return !!x && (x === this || x._in === this); };\n"
            + "E87.prototype.addEventListener = function(ev, fn){ (this._on = this._on || {})[ev] = fn; };\n"
            + "E87.prototype.focus = function(){ document.activeElement = this; };\n"
            + "document.activeElement = null;\n"
            + "const wait = () => new Promise(r => setTimeout(r, 5));\n"
            + setup + "".join(_piece106(src, h) + "\n" for h in cuts)
            + "(async () => {\n" + body + "})();\n")
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A Backups-card refresh keeps what the operator is typing
# ════════════════════════════════════════════════════════════════════════════════════════════════
_BK106 = _read106("static", "js", "remote_manage_backups.js")
_LIST106 = {"settings": {"enabled": True, "keep_days": 5, "encrypt": True},
            "full": {"interval_days": 7, "keep": 2}, "games": [{"id": 4, "name": "p106"}], "backups": []}
_name106 = "Backups card: a refresh under the operator's typing"
_out106 = _js106(_name106, (
    "let sent = [];\n"
    "global.fetch = (u, o) => { sent.push(u); const d = (o && o.body) ? JSON.parse(o.body) : null;\n"
    "  return Promise.resolve({json: () => Promise.resolve(\n"
    "    u.endsWith('/schedule') ? {success: true, schedule: {interval_set: true, interval_days: 3,\n"
    "                                                         keep_set: true, keep: 6}}\n"
    "    : u.endsWith('/backup/settings') ? {success: true} : " + _json106.dumps(_LIST106) + ")}); };\n"
    "global.confirmDialog = o => o.onConfirm();\n"
    "global.bkMsg = () => {}; global.bkApplyLimits = () => {}; global.bkRenderDisk = () => {};\n"
    "global.fbSummary = () => {}; global.bkRenderFullStatus = () => {}; global.bkRenderAutoStatus = () => {};\n"
    "global.bkGameRows = () => ''; global.bkGameStatus = () => ''; global.bkGameDisk = () => '';\n"
    "global.schedNote = () => '';\n"
    "global.gameSchedule = g => '<row ' + g.id + ' ' + (++drawn) + '>'; let drawn = 0;\n"
    "global.bkRenderList = () => {};\n"
    "const fi = document.getElementById('fb-interval');\n"
    "fi.options = [{value: '1'}, {value: '3'}, {value: '7'}];\n"
    "fi.appendChild = o => fi.options.push(o);\n"
    "const fg = document.getElementById('fb-games'); fg.innerHTML = 'before';\n"
    "const field = tag => { const e = new E87(tag); e._in = fg; return e; };\n"), _BK106,
    ("function _r29c_bkEditing(", "function _r29c_bkSetIdle(", "var _r29j_bkUntyped", "function _r29c_bkFieldIn(",
     "function _r25c_bkUnread(",
     "function loadBackups(", "function bkRenderGames(", "function bkRenderFullSchedule(",
     "function _r20cIntervalOption(", "function bkShowEncState(", "function _r29c_bkPassDone(",
     "function saveBackupPassphrase(", "function clearBackupPassphrase(", "function setGameSchedule("), (
    "  const out = {}, $ = id => document.getElementById(id);\n"
    "  const pass = $('bk-pass'), kp = $('bk-keep'), fk = $('fb-keep');\n"
    "  const refresh = async (focus) => { document.activeElement = focus || null; loadBackups(); await settle(); };\n"
    # the passphrase: kept while focused AND after focus left it (typed, then Save pressed)
    "  pass.value = 'typed-in-p106'; await refresh(pass); out.passFocused = pass.value;\n"
    "  await refresh(null); out.passBlurred = pass.value;\n"
    "  saveBackupPassphrase(null); await settle(); out.passSaved = pass.value;\n"
    "  pass.value = 'typed-again'; clearBackupPassphrase(null); await settle(); out.passCleared = pass.value;\n"
    # the two Keep boxes and the interval select: kept while focused, rewritten when not (control)
    "  kp.value = '9'; fk.value = '8'; fi.value = '1';\n"
    "  await refresh(kp); out.keepFocused = kp.value; await refresh(null); out.keepBlurred = kp.value;\n"
    "  fk.value = '8'; await refresh(fk); out.fbKeepFocused = fk.value;\n"
    "  await refresh(null); out.fbKeepBlurred = fk.value;\n"
    "  fi.value = '1'; await refresh(fi); out.fbIvFocused = fi.value;\n"
    "  await refresh(null); out.fbIvBlurred = fi.value;\n"
    # the per-server rows: held back under a field, read again once focus leaves them
    # focus leaving: the handler the page bound, or nothing when it bound none (a crash names no check)
    "  const leave = () => { if (fg._on && fg._on.focusout) fg._on.focusout(); };\n"
    "  fg.innerHTML = 'before'; const box = field('INPUT');\n"
    "  sent = []; await refresh(box); out.rowsFocused = fg.innerHTML;\n"
    "  document.activeElement = field('TEXTAREA'); leave(); await wait(); await settle();\n"
    "  out.rowsStillIn = [fg.innerHTML, sent.length];\n"
    "  document.activeElement = null; leave(); await wait(); await settle();\n"
    "  out.rowsLeft = [fg.innerHTML, sent.length];\n"
    "  fg.innerHTML = 'before'; await refresh(field('BUTTON')); out.rowsButton = fg.innerHTML;\n"
    # a committed pick holds nothing back: the interval select, a checkbox (focus stays on them)
    "  const pick = (tag, type) => { const e = field(tag); if (type) e.type = type; return e; };\n"
    "  out.rowsPicked = [];\n"
    "  for (const [tag, type] of [['SELECT'], ['INPUT', 'checkbox'], ['INPUT', 'number'], ['TEXTAREA']]) {\n"
    "    fg.innerHTML = 'before'; await refresh(pick(tag, type));\n"
    "    out.rowsPicked.push(fg.innerHTML.startsWith('<div') ? 'drawn' : fg.innerHTML); }\n"
    "  document.activeElement = null; fg._r29cPending = false;\n"
    # a schedule saved: written into the row on the page now, not the element read before the save
    "  const oldKp = new E87('input'); oldKp.value = '6'; oldKp.validity = {}; els['gsk-4'] = oldKp;\n"
    "  const iv = $('gsi-4'); iv.value = '3'; iv.options = [{value: 'default'}, {value: '3'}, {value: '7'}];\n"
    "  global._bkSched = {4: {interval_set: false, keep_set: false}};\n"
    "  const save = setGameSchedule(4);\n"
    "  const newKp = new E87('input'); newKp.value = ''; els['gsk-4'] = newKp; iv.value = 'default';\n"
    "  await settle(); out.saved = [newKp.value, iv.value];\n"
    "  console.log(JSON.stringify(out));\n"))
if _out106 is not None:
    check("Backups card: a refresh leaves the passphrase being typed alone, focused or not (every refresh "
          "cleared it, a dozen in the two minutes after Back up now); saving it, or turning encryption "
          "off, still clears the box",
          _out106.get("passFocused") == "typed-in-p106" and _out106.get("passBlurred") == "typed-in-p106"
          and _out106.get("passSaved") == "" and _out106.get("passCleared") == "", repr(_out106))
    check("Backups card: the global Keep box, the game-backup Keep box and the interval select keep a "
          "typed value while focused (rewritten, no `change` fired and the value was not saved); "
          "unfocused, the stored value is written (control)",
          _out106.get("keepFocused") == "9" and _out106.get("keepBlurred") == "5"
          and _out106.get("fbKeepFocused") == "8" and _out106.get("fbKeepBlurred") == "2"
          and _out106.get("fbIvFocused") == "1" and _out106.get("fbIvBlurred") == "7", repr(_out106))
    check("Backups card: the per-server rows are not rebuilt under a Schedule/Keep field being edited; "
          "the card is read again once focus leaves the rows (not while it moves between them), and a "
          "focused Back up now button holds nothing back (control)",
          _out106.get("rowsFocused") == "before"
          and _out106.get("rowsStillIn") == ["before", 1]
          and isinstance(_out106.get("rowsLeft"), list) and _out106["rowsLeft"][1] == 2
          and _out106["rowsLeft"][0].startswith("<div") and _out106.get("rowsButton", "").startswith("<div"),
          repr(_out106))
    check("Backups card: a focused per-server interval select or checkbox holds no refresh back (its pick "
          "is already sent, and Chrome keeps focus on it: every refresh after Back up now froze until "
          "something else was tapped); a number box or textarea still does",
          _out106.get("rowsPicked") == ["drawn", "drawn", "before", "before"], repr(_out106))
    check("Backups card: a saved per-server schedule is written into the row now on the page (looked up "
          "by id), so a row redrawn meanwhile from an older read shows what was stored",
          _out106.get("saved") == ["6", "3"], repr(_out106))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The Live Resources card says it is stale when /live gets no answer at all
# ════════════════════════════════════════════════════════════════════════════════════════════════
_RM106 = _read106("static", "js", "remote_manage.js")
_name106 = "Live Resources: a /live request with no JSON answer"
_out106 = _js106(_name106, (
    "var REMOTE_ID = 1; let painted = 0;\n"
    "global._r18cPaintHostBadge = () => {}; global._livePaintCpu = () => { painted++; };\n"
    "global._livePaintMemory = () => {}; global._livePaintDisk = () => {};\n"
    # how: 'reject' — the fetch itself fails; 'text' — a reply whose body is not JSON (a 502 page).
    "const reply = how => { global.fetch = () => how === 'reject' ? Promise.reject(new Error('x'))\n"
    "  : Promise.resolve({json: () => how === 'text' ? Promise.reject(new SyntaxError('x'))\n"
    "                                               : Promise.resolve(how)}); };\n"), _RM106,
    ("var _r29c_liveMiss", "function pollLive("), (
    "  const st = document.getElementById('live-stale'), out = {};\n"
    "  const poll = async how => { reply(how); pollLive(); await settle();\n"
    "    return [st.style.display, st.textContent]; };\n"
    "  st.style.display = 'none';\n"
    "  out.oneMiss = await poll('reject');\n"
    "  out.twoMiss = await poll('reject');\n"
    "  out.good = await poll({cpu: 1});\n"
    "  out.textOnce = await poll('text');\n"
    "  out.textTwice = await poll('text');\n"
    "  out.error = await poll({error: 'x'});\n"
    "  out.painted = painted;\n"
    "  console.log(JSON.stringify(out));\n"))
if _out106 is not None:
    _PAUSED106 = "Live figures are paused — the last read failed."
    check("Live Resources: a /live request that fails outright, or answers a body that is not JSON (the "
          "panel restarting behind a proxy), shows the stale note on the second miss in a row (the empty "
          ".catch kept the last figures beside the 'realtime' dot)",
          _out106.get("twoMiss") == ["", _PAUSED106] and _out106.get("textTwice") == ["", _PAUSED106],
          repr(_out106))
    check("Live Resources: ...a single miss does not flicker the note, a good reading clears it and "
          "restarts the count, and an `error` reply still shows its own note (controls)",
          _out106.get("oneMiss") == ["none", ""] and _out106.get("good") == ["none", ""]
          and _out106.get("textOnce") == ["none", ""] and _out106.get("error", [None])[0] == ""
          and _out106.get("painted") == 1, repr(_out106))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The GMod install box says what the content scan does since #439
# ════════════════════════════════════════════════════════════════════════════════════════════════
_KEY106 = ("GMod needs another game's content to draw its maps and props — without it you get "
           "missing-texture ERROR signs. The panel reuses a copy already on the host that no panel game "
           "server owns; otherwise it downloads the content into a shared content account. A panel game "
           "server's own files are never shared, so a copy only one of them holds is downloaded again.")
_page106 = ""
try:
    _p9_arm(who="part106")
    _r106 = _p9_client(P9_ADMIN).get("/servers/install")
    _page106 = _r106.get_data(as_text=True) if _r106.status_code == 200 else "HTTP %d" % _r106.status_code
finally:
    _p9_restore_all()
_m106 = _re106.search(r'id="gmod-content-opt".*?(GMod needs .*?)</div>', _page106, _re106.S)
_said106 = " ".join(_m106.group(1).split()) if _m106 else ""
_cats106 = {lang: _json106.loads(_read106("translations", lang, "r29c.json")) for lang in ("es", "fr")}
check("GMod install box: it says a copy only a panel game server holds is downloaded again (it said "
      "content already on the host is reused, false since #439 for a server's account), and es/fr "
      "carry that sentence",
      _said106 == _KEY106 and "reuses content already on the host" not in _page106
      and all(_KEY106 in c and c[_KEY106] for c in _cats106.values()), repr((_said106, _page106[:200])))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The Raw config editor is not saved over a settings save it never showed (integrator, A11 lead)
# ════════════════════════════════════════════════════════════════════════════════════════════════
# After a settings save, refreshRawConfig re-reads the cfg but leaves a FOCUSED Raw box alone, and it
# left the box marked 'ok'. An operator who had clicked into the box before the re-read came back
# (a slow host) and typed, then pressed Raw Save, wrote the pre-save text back over the settings just
# saved. Now: typed into and behind the file, its Save is refused with a note; focused but untouched,
# it is refilled; typed into while the file did not change, it saves as before.
_SF106 = _read106("static", "js", "server_files.js")
_name106r = "Raw config editor: a re-read under the operator's typing"
_outr106 = _js106(_name106r, (
    "var serverId = 1; function _tr(s){ return s; }\n"
    "let sent = [];\n"
    "const reply = d => { global.fetch = (u, o) => { sent.push(o && o.body ? JSON.parse(o.body) : null);\n"
    "  return Promise.resolve({ok: true, status: 200, json: () => Promise.resolve(d)}); }; };\n"
    # a textarea's value: CR and CRLF read back as LF (the HTML spec's API value)
    "Object.defineProperty(document.getElementById('cfg-raw'), 'value', {get(){ return this._v; },\n"
    "  set(v){ this._v = String(v).replace(/\\r\\n?/g, '\\n'); }});\n"), _SF106, (
    "var _r26c_rawRead", "var _r29j_rawShown", "function _r29j_rawText(", "function loadConfig(", "function refreshRawConfig(",
    "function _r26c_rawStale(", "function _r29j_rawBehind(", "function saveRaw("), (
    "  const out = {}, ta = document.getElementById('cfg-raw'), msg = document.getElementById('cfg-raw-msg');\n"
    "  const save = async () => { sent = []; reply({success: true}); saveRaw(); await settle();\n"
    "    return sent.filter(Boolean).map(b => b.raw); };\n"
    "  const run = async (focus, typed, after, first) => {\n"
    "    msg.textContent = ''; msg.className = '';\n"
    "    reply({groups: [], raw: first || 'a=1\\n'}); loadConfig(); await settle();\n"
    "    document.activeElement = focus ? ta : null;\n"
    "    if (typed) ta.value = 'a=1\\nb=9\\n';\n"
    "    reply({groups: [], raw: after}); refreshRawConfig(); await settle();\n"
    "    const text = ta.value, posted = await save(), r = {text, msg: msg.className, posted};\n"
    "    document.activeElement = null; return r; };\n"
    "  out.behind = await run(true, true, 'a=2\\n');\n"
    "  out.untouched = await run(true, false, 'a=2\\n');\n"
    "  out.same = await run(true, true, 'a=1\\n');\n"
    "  out.blurred = await run(false, false, 'a=2\\n');\n"
    # a cfg with CR line ends: the box holds it with LF, so an untouched focused box is still untouched
    "  out.crUntouched = await run(true, false, 'a=2\\r\\n', 'a=1\\r\\n');\n"
    "  out.crSame = await run(true, false, 'a=1\\r\\n', 'a=1\\r\\n');\n"
    "  out.crBehind = await run(true, true, 'a=2\\r\\n', 'a=1\\r\\n');\n"
    "  out.crTypedSame = await run(true, true, 'a=1\\r\\n', 'a=1\\r\\n');\n"
    # a box a re-read refilled (unfocused) from a CR file, then focused untouched for the next re-read
    "  msg.textContent = ''; msg.className = '';\n"
    "  reply({groups: [], raw: 'a=1\\n'}); loadConfig(); await settle();\n"
    "  reply({groups: [], raw: 'a=2\\r\\n'}); refreshRawConfig(); await settle();\n"
    "  document.activeElement = ta; reply({groups: [], raw: 'a=3\\r\\n'}); refreshRawConfig(); await settle();\n"
    "  out.crTwice = {text: ta.value, posted: await save(), msg: msg.className}; document.activeElement = null;\n"
    "  console.log(JSON.stringify(out));\n"))
if _outr106 is not None:
    check("Raw config editor: a box typed into while a settings save's re-read came back keeps the "
          "typing but refuses its Save with a warning (it wrote the pre-save text back over the "
          "settings just saved)",
          _outr106.get("behind", {}).get("text") == "a=1\nb=9\n"
          and _outr106["behind"].get("msg") == "small ms-2 text-danger"
          and _outr106["behind"].get("posted") == [], repr(_outr106))
    check("Raw config editor: ...while a focused box nobody typed in is refilled and saves, a typed box "
          "whose file did not change saves the typing, and an unfocused box is refilled (controls)",
          _outr106.get("untouched") == {"text": "a=2\n", "msg": "small ms-2 text-success", "posted": ["a=2\n"]}
          and _outr106.get("same") == {"text": "a=1\nb=9\n", "msg": "small ms-2 text-success",
                                       "posted": ["a=1\nb=9\n"]}
          and _outr106.get("blurred") == {"text": "a=2\n", "msg": "small ms-2 text-success",
                                          "posted": ["a=2\n"]}, repr(_outr106))
    check("Raw config editor: a cfg with CR line ends does not mark a focused, untouched box 'behind' "
          "(the box holds it with LF, so it never equalled the reply and its Save was refused); it is "
          "refilled and saves, and a box typed into while that file changed is still refused",
          _outr106.get("crUntouched") == {"text": "a=2\n", "msg": "small ms-2 text-success", "posted": ["a=2\n"]}
          and _outr106.get("crSame") == {"text": "a=1\n", "msg": "small ms-2 text-success", "posted": ["a=1\n"]}
          and _outr106.get("crBehind", {}).get("posted") == []
          and _outr106["crBehind"].get("msg") == "small ms-2 text-danger", repr(_outr106))
    check("Raw config editor: ...with CR line ends, a box typed into while the file did not change saves "
          "the typing, and a box a re-read refilled is still untouched at the next re-read (the stored "
          "text is what the box holds, not the reply)",
          _outr106.get("crTypedSame") == {"text": "a=1\nb=9\n", "msg": "small ms-2 text-success",
                                          "posted": ["a=1\nb=9\n"]}
          and _outr106.get("crTwice") == {"text": "a=3\n", "posted": ["a=3\n"], "msg": "small ms-2 text-success"},
          repr(_outr106))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. A restored auth select brings its credential field with it (integrator, A12 lead)
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The Add Remote form and the setup wizard's remote step switch the credential field to a password
# box only on the select's `change`. A browser that restores form state (Firefox on reload, a
# back/forward page) puts the select back on Password with no `change`, and the field stayed a
# visible text box. On `pageshow` the field is now matched to the select; a restored "SSH Key" is left.


def _ps106(src):
    """The `window.addEventListener('pageshow', …)` statement of `src`, or a comment naming it."""
    head = "window.addEventListener('pageshow'"
    if head not in src:
        return "/* MISSING pageshow */"
    i = src.index(head)
    return src[i:src.index("\n});", i) + 4]


_name106p = "credential field after a restored auth select"
_MR106 = _read106("static", "js", "manage_remotes.js")
_outp106 = _js106(_name106p, (
    "const on = []; window.addEventListener = (ev, fn) => { if (ev === 'pageshow') on.push(fn); };\n"
    "global.Event = function(t){ this.type = t; };\n"
    "E87.prototype.removeAttribute = function(k){ delete this.attrs[k]; };\n"
    "const $ = id => document.getElementById(id);\n"
    # the Add form, one host's Edit form (id 7) and the wizard's step, each select with its field
    "const field = () => { const e = new E87('input'); e.type = 'text'; e.value = ''; return e; };\n"
    "const addIn = field(), edIn = field(), wizIn = field();\n"
    "const addSel = $('manage-remotes-auth_method'), edSel = $('manage-remotes-auth_method-7');\n"
    "edSel.id = 'manage-remotes-auth_method-7';\n"
    "addSel.form = {querySelector: () => addIn}; addSel.closest = () => addSel.form;\n"
    "edSel.closest = () => ({querySelector: () => edIn});\n"
    "document.querySelectorAll = q => q === '[id^=\"manage-remotes-auth_method-\"]' ? [edSel] : [];\n"
    "document.querySelector = q => q === '[name=\"credential\"]' ? wizIn : null;\n"
    "const wizSel = $('auth-method');\n"
    "wizSel.addEventListener = (ev, fn) => { wizSel._change = fn; };\n"
    "wizSel.dispatchEvent = e => wizSel._change.call(wizSel, e);\n"), "", (), (
    "  const out = {};\n"
    + "\n".join("  " + _piece106(_MR106, h) for h in (
        "function toggleCreds(", "function toggleEditCreds(", "function _r29j_credsOff(")) + "\n"
    + "  " + _ps106(_MR106) + "\n"
    + "  " + _read106("static", "js", "setup_remote.js") + "\n"
    # set: [select value, field type, field value, group hidden] per form; then the page is shown
    "  const show = (sel, grp, inp, st) => { sel.value = st[0]; inp.type = st[1]; inp.value = st[2];\n"
    "    grp.style.display = st[3] ? 'none' : ''; };\n"
    "  const read = (grp, inp) => [inp.type, inp.value, grp.style.display === 'none'];\n"
    "  const forms = {add: [addSel, $('credential-group'), addIn], edit: [edSel, $('edit-cred-group-7'), edIn],\n"
    "                 wizard: [wizSel, $('credential-field'), wizIn]};\n"
    "  const cases = {\n"
    "    reloadPassword: ['password', 'text', 'typed-in-clear', false],\n"
    "    cachedPassword: ['password', 'password', 'typed-p106', false],\n"
    "    reloadTailscale: ['tailscale', 'text', 'kept-p106', false],\n"
    "    cachedTailscale: ['tailscale', 'text', '', true],\n"
    "    offTailscale: ['password', 'password', 'typed-p106', true],\n"
    "    key: ['key', 'text', '/k/p106', false] };\n"
    "  for (const [f, [sel, grp, inp]] of Object.entries(forms)) for (const [c, st] of Object.entries(cases)) {\n"
    "    const st2 = f === 'edit' ? [st[0], 'password', st[2], st[3]] : st;\n"
    "    show(sel, grp, inp, st2); on.forEach(fn => fn()); out[f + '.' + c] = read(grp, inp); }\n"
    "  edSel.value = 'key'; edIn.value = ''; $('edit-cred-group-7').style.display = 'none';\n"
    "  on.forEach(fn => fn()); out['edit.keyHidden'] = read($('edit-cred-group-7'), edIn);\n"
    "  console.log(JSON.stringify(out));\n"))
if _outp106 is not None:
    _o106 = _outp106
    check("credential field: a page shown with its auth select restored to Password or Tailscale SSH "
          "(no `change` fired) sets the field for that method, on the Add Remote form and the setup "
          "wizard alike; a restored SSH Key is left alone",
          all(_o106.get(f + ".reloadPassword") == ["password", "", False]
              and _o106.get(f + ".reloadTailscale") == ["text", "", True]
              and _o106.get(f + ".key") == ["text", "/k/p106", False] for f in ("add", "wizard")), repr(_o106))
    check("credential field: each host's Edit form follows a restored auth select too (onto Tailscale SSH "
          "the box stayed shown and its text was stored for a transport that never reads it; off it, "
          "the box stayed hidden)",
          _o106.get("edit.reloadTailscale") == ["password", "", True]
          and _o106.get("edit.offTailscale") == ["password", "typed-p106", False]
          and _o106.get("edit.keyHidden") == ["password", "", False]
          and _o106.get("edit.key") == ["password", "/k/p106", False], repr(_o106))
    check("credential field: a page shown with the field already matching its select (a back/forward "
          "page from the cache) is left as it is: a password typed before leaving it is not emptied, on "
          "the Add form, the Edit form and the wizard",
          all(_o106.get(f + ".cachedPassword") == [("password"), "typed-p106", False]
              and _o106.get(f + ".cachedTailscale", [None, None, None])[2] is True
              for f in ("add", "edit", "wizard"))
          and _o106.get("add.offTailscale") == ["password", "", False]
          and _o106.get("wizard.offTailscale") == ["password", "", False], repr(_o106))

check("part106: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP106_START, repr(_P9_TRIPPED[_TRIP106_START:][:6]))
