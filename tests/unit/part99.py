"""Part 99 of the unit suite: the fifteenth review's page and script fixes (builder C).

Held here, each against the code path the finding named:

* the Raw config editor after a settings save whose re-read failed: the last good text stays,
  marked stale, and its Save refuses a box that is stale or was never read (it wrote "" over the
  instance cfg).
* the install progress poll's page-load read: a failed one still arms the poll.
* the reboot banner: a wait or job banner goes when a reply the host did not answer says both are
  over; a "reboot needed" one stays.
* the panel's diagnostics card: an error reply is a failed run, not "1 problem(s)" over nothing.
* the Mods card: a failed re-list after an Install or Remove is said, and the spinner comes off.
* the OS Updates card: a failed page-load fill leaves Install updates usable, not "Checking…".

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on this part's own fixtures. app.py's catch-all
lives inside create_app, which this suite must not build (part12's note): its 500 body is
_r23c_error_json's, built here in a request context.
"""
import json as _json99
import os
import re as _re99

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _SETTLE47, _cut47, _node47
from unit.part87 import _DOM87
from unit.part12 import (P9_ADMIN, P9_GS, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core,
                         _p9_json, _p9_patch, _p9_restore_all)
from panel.core.http import _r23c_error_json as _err99
from panel.ops import system_ops as _so99

_TRIP99_START = len(_P9_TRIPPED)


def _read99(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _node99(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _cut_or99(src, head):
    """_cut47's statement, or a comment naming it, so the check that runs it fails BY NAME."""
    return _cut47(src, head) if head in src else "/* MISSING %s */" % head


def _line_or99(src, head):
    """The one source line that starts with `head`, or a comment naming it."""
    m = _re99.search(r"^" + _re99.escape(head) + r".*$", src, _re99.M)
    return m.group(0) if m else "/* MISSING %s */" % head


with _p9.test_request_context("/"):
    _E99 = _err99("MSG-500").get_json()
# The fetch stand-in: `reply(d, ok)` sets what the next fetch resolves with (ok false: a rejected
# request when d is undefined), and every request is recorded in `sent`.
_ANS99 = ("let sent = [];\n"
          "const reply = (d, ok) => { global.fetch = (u, o) => {\n"
          "  sent.push([u, o && o.body ? JSON.parse(o.body) : null]);\n"
          "  if (d === undefined) return Promise.reject(new Error('x'));\n"
          "  return Promise.resolve({ok: ok !== false, status: ok === false ? 500 : 200,\n"
          "    json: () => Promise.resolve(d)}); }; };\n")


def _js99(name, setup, cuts, body, src):
    """Run part87's DOM + `setup` + the cut statements of `src` + `body` in node; its JSON, or None."""
    return _node99(name, _DOM87 + _SETTLE47 + _ANS99 + setup
                   + "".join(_cut_or99(src, h) + "\n" for h in cuts) + "(async () => {\n" + body + "})();\n")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The Raw config editor: a failed re-read is not the file's text
# ════════════════════════════════════════════════════════════════════════════════════════════════
# After a settings save, refreshRawConfig re-read the config and took `raw` whenever it was present.
# A read that did not happen answers {raw: "", error: ...}, so the box emptied, and the Raw tab's
# Save wrote "" over the instance cfg. The body fed below is the route's own, from a read whose
# transport returned nothing (the tailscale and local transports do not raise).
_R99 = {}


def _raise99(*_a, **_k):
    raise RuntimeError("unit p99 read failed")


try:
    _p9_arm(who="part99")
    _p9_patch(_p9_core, "shell_as_game_user", lambda *a, **k: ("", "", -1))
    _r = _p9_client(P9_ADMIN).get("/api/server/%d/config" % P9_GS)
    _R99["cfg"] = (_r.status_code, _p9_json(_r))
    _p9_patch(_so99, "panel_diagnostics", _raise99)
    _r = _p9_client(P9_ADMIN).get("/api/panel/diagnostics")
    _R99["diag"] = (_r.status_code, _p9_json(_r))
finally:
    _p9_restore_all()
check("config read: a read that did not happen answers raw \"\" with an error (the body fed below)",
      _R99.get("cfg", (0, {}))[1].get("raw") == "" and _R99["cfg"][1].get("error"), repr(_R99))
_SF99 = _read99("static", "js", "server_files.js")
_name99 = "raw config editor: a failed re-read after a settings save"
_out99 = _js99(_name99, (
    "var serverId = 1; function _tr(s){ return s; }\n"
    + _line_or99(_SF99, "var _r26c_rawRead") + "\n"), (
    "function loadConfig(", "function refreshRawConfig(", "function _r26c_rawStale(", "function saveRaw("), (
    "  const out = {}, ta = document.getElementById('cfg-raw'), msg = document.getElementById('cfg-raw-msg');\n"
    "  const good = {groups: [], raw: 'port=\"27015\"\\n'};\n"
    "  const save = async () => { sent = []; reply({success: true}); saveRaw(); await settle();\n"
    "    return sent.filter(s => s[1]).map(s => s[1].raw); };\n"
    "  for (const [k, d, ok] of [['route', " + _json99.dumps(_R99.get("cfg", (0, {}))[1]) + "],\n"
    "                            ['500', " + _json99.dumps(_E99) + ", false], ['rejected', undefined]]) {\n"
    "    _r26c_rawRead = 'unread'; msg.textContent = '';\n"
    "    reply(good); loadConfig(); await settle();\n"
    "    reply(d, ok); refreshRawConfig(); await settle();\n"
    "    out[k] = {text: ta.value, msg: msg.className, posted: await save()}; }\n"
    "  _r26c_rawRead = 'unread'; ta.value = '';\n"
    "  reply(" + _json99.dumps(_R99.get("cfg", (0, {}))[1]) + "); loadConfig(); await settle();\n"
    "  out.unread = {text: ta.value, posted: await save()};\n"
    "  _r26c_rawRead = 'unread';\n"
    "  reply(good); loadConfig(); await settle(); reply({groups: [], raw: 'b=2\\n'});\n"
    "  refreshRawConfig(); await settle(); out.good = {text: ta.value, posted: await save()};\n"
    "  reply({groups: [], raw: ''}); loadConfig(); await settle(); out.empty = await save();\n"
    "  console.log(JSON.stringify(out));\n"), _SF99)
if _out99 is not None:
    _was99 = 'port="27015"\n'
    check("raw config editor: a failed re-read after a settings save (the route's own failure answer, "
          "the catch-all's 500, a rejected request) keeps the last good text, marks it stale, and its "
          "Save sends nothing (it emptied the box, and Save wrote \"\" over the cfg)",
          all(_out99.get(k) == {"text": _was99, "msg": "small ms-2 text-warning", "posted": []}
              for k in ("route", "500", "rejected")), repr(_out99))
    check("raw config editor: ...and a box no read ever filled (the first load failed) is not saved",
          _out99.get("unread") == {"text": "", "posted": []}, repr(_out99))
    check("raw config editor: ...while a good re-read still fills the box and saves it, and a real "
          "empty cfg (a read that worked) still saves",
          _out99.get("good") == {"text": "b=2\n", "posted": ["b=2\n"]} and _out99.get("empty") == [""],
          repr(_out99))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The install progress poll's load read
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The page-load read of /api/installs had its own fetch, which armed the poll only on a reply listing
# jobs: a failed request or an error reply armed nothing, so an install already running showed no
# progress until it ended. The whole script runs here, its DOMContentLoaded handler fired by hand.
_IP99 = _read99("static", "js", "install_progress.js")
_name99 = "install progress: the page-load read"
_out99 = _node99(_name99, _SETTLE47 + _ANS99 + (
    "let onload = null, timers = {}, nextId = 1;\n"
    "global.window = global; global.MOUNT = '';\n"
    "global.document = {addEventListener: (k, f) => { if (k === 'DOMContentLoaded') onload = f; },\n"
    "  getElementById: () => null, querySelector: () => null, querySelectorAll: () => [],\n"
    "  createElement: () => ({style: {}, setAttribute(){}, appendChild(){}})};\n"
    "global.setInterval = f => { const id = nextId++; timers[id] = f; return id; };\n"
    "global.clearInterval = id => { delete timers[id]; };\n"
    "const live = () => Object.keys(timers).length;\n"
    "const fire = async () => { for (const f of Object.values(timers)) f(); await settle(); };\n")
    + _IP99 + "\n(async () => {\n"
    "  const out = {};\n"
    "  for (const [k, d, ok] of [['500', " + _json99.dumps(_E99) + ", false], ['rejected', undefined]]) {\n"
    "    timers = {}; sent = []; reply(d, ok); onload(); await settle();\n"
    "    const armed = live(); reply({installs: []}); await fire();\n"
    "    out[k] = {armed, after: live(), reads: sent.length}; }\n"
    "  timers = {}; sent = []; reply({installs: []}); onload(); await settle();\n"
    "  out.idle = {live: live(), reads: sent.length};\n"
    "  timers = {}; sent = []; reply({installs: [{id: 7, name: 'x', percent: 5}]}); onload(); await settle();\n"
    "  out.busy = {live: live(), reads: sent.length};\n"
    "  console.log(JSON.stringify(out));\n"
    "})();\n")
if _out99 is not None:
    check("install progress: a page-load read that fails (the catch-all's 500, a rejected request) "
          "still arms the poll, and the next answer is read (it armed nothing, so a running install "
          "showed no progress until it ended)",
          all(_out99.get(k) == {"armed": 1, "after": 0, "reads": 2} for k in ("500", "rejected")),
          repr(_out99))
    check("install progress: ...while an idle page still makes one read and keeps no timer, and a "
          "page with an install running keeps polling",
          _out99.get("idle") == {"live": 0, "reads": 1} and _out99.get("busy") == {"live": 1, "reads": 1},
          repr(_out99))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The reboot banner after a read the host did not answer
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #436 kept the banner on `known: false`, unless the reply had a wait or a job. But `pending_empty`
# and `job` are the panel's own state, so that same reply says a wait or job is over: a wait banner
# kept after its Cancel (the host down) contradicted the Power card. Only "reboot needed" stays.
_NG99 = _read99("static", "js", "nags.js")
_name99 = "reboot banner: a wait or job the same reply says is over"
_out99 = _js99(_name99, (
    "const nags = {}; let removed = [];\n"
    "const _gid = document.getElementById, _ce = document.createElement;\n"
    "document.getElementById = id => id.startsWith('reboot-nag-') ? (nags[id] || null) : _gid(id);\n"
    "document.createElement = tag => { const e = _ce(tag);\n"
    "  e.remove = () => { removed.push(e.id); delete nags[e.id]; }; return e; };\n"
    "const box = _gid('reboot-nag'), _ap = box.appendChild.bind(box);\n"
    "box.appendChild = c => { if (c.id) nags[c.id] = c; return _ap(c); };\n"
    "function _rbEl(tag){ return document.createElement(tag); }\n"
    "function _rbButton(){ return document.createElement('button'); }\n"
    "function _rbHost(){ return document.createElement('span'); }\n"
    "var _RB_PHASE = {};\n"), (
    "function _r26c_rbUnread(", "window.rebootNagRender = function(", "window.rebootNagCheck = function("), (
    "  const out = {}, gone = {required: false, known: false, pending_empty: false, job: null};\n"
    "  const states = [['wait', {required: false, known: true, pending_empty: true, job: null}],\n"
    "    ['job', {required: true, known: true, pending_empty: false, job: {phase: 'waiting', sent: false}}],\n"
    "    ['required', {required: true, known: true, packages: [], pending_empty: false, job: null}]];\n"
    "  for (const [k, d] of states) {\n"
    "    removed = []; reply(d); window.rebootNagCheck(1, 'h'); await settle();\n"
    "    const shown = !!nags['reboot-nag-1']; reply(null, false); window.rebootNagCheck(1, 'h'); await settle();\n"
    "    const afterFail = !!nags['reboot-nag-1']; reply(gone); window.rebootNagCheck(1, 'h'); await settle();\n"
    "    out[k] = {shown, afterFail, afterUnknown: !!nags['reboot-nag-1']};\n"
    "    if (nags['reboot-nag-1']) nags['reboot-nag-1'].remove(); }\n"
    "  console.log(JSON.stringify(out));\n"), _NG99)
if _out99 is not None:
    check("reboot banner: a wait or reboot-job banner goes when a reply the host did not answer "
          "(known: false) says no wait and no job, as after its Cancel (it stayed, contradicting the "
          "Power card); a failed request still keeps it",
          all(_out99.get(k) == {"shown": True, "afterFail": True, "afterUnknown": False}
              for k in ("wait", "job")), repr(_out99))
    check("reboot banner: ...while a \"reboot needed\" banner, the host's own reading, stays on that reply",
          _out99.get("required") == {"shown": True, "afterFail": True, "afterUnknown": True}, repr(_out99))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The panel's diagnostics card on an error reply
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The route's own failure answer is {checks: [], summary: "fail", fail: 1, error}: the card emptied
# its list, put "1 problem(s)" over nothing and cleared the line that would have said why (the
# catch-all's 500 read "undefined problem(s)"). Found by the repo-wide search for this class.
check("diagnostics: the route's failure answer carries `error` and no checks (the body fed below)",
      _R99.get("diag", (0, {}))[1].get("error") and _R99["diag"][1].get("checks") == [], repr(_R99))
_RH99 = _read99("static", "js", "remote_manage_host.js")
_name99 = "diagnostics: an error reply"
_out99 = _js99(_name99, (
    "const DIAG_ICON = {warn: 'w', ok: 'o', fail: 'f'}, DIAG_BADGE = {ok: 'g', warn: 'y', fail: 'r'};\n"
    "function loadIntegrity(){} function loadDbStats(){} function loadAutoUpd(){}\n"), (
    "function _r26c_diagBadge(", "function runDiagnostics("), (
    "  const out = {}, list = document.getElementById('diag-list'), msg = document.getElementById('diag-msg'),\n"
    "    badge = document.getElementById('diag-summary');\n"
    "  for (const [k, d, ok] of [['route', " + _json99.dumps(_R99.get("diag", (0, {}))[1]) + "],\n"
    "                            ['500', " + _json99.dumps(_E99) + ", false],\n"
    "                            ['run', {checks: [{name: 'db', level: 'ok', detail: ''}], summary: 'ok'}]]) {\n"
    "    list.textContent = ''; list.appendChild(document.createElement('div')); badge.textContent = 'before';\n"
    "    reply(d, ok); runDiagnostics(); await settle();\n"
    "    out[k] = {rows: list.children.length, badge: badge.textContent, msg: msg.innerHTML, text: msg.textContent};\n"
    "    msg.innerHTML = ''; }\n"
    "  console.log(JSON.stringify(out));\n"), _RH99)
if _out99 is not None:
    _said99 = '<span class="text-danger">Diagnostics failed — check the panel logs.</span>'
    check("diagnostics: the route's failure answer and the catch-all's 500 say diagnostics failed and "
          "keep the list and badge as they were (they read as a run with one problem and no list)",
          all(_out99.get(k, {}).get("msg") == _said99
              and (_out99[k]["rows"], _out99[k]["badge"]) == (1, "before") for k in ("route", "500")),
          repr(_out99))
    check("diagnostics: ...while a real run still replaces the list and the badge",
          (_out99.get("run") or {}).get("text") == ""
          and (_out99["run"]["rows"], _out99["run"]["badge"]) == (1, "all healthy"), repr(_out99))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The Mods card's re-list after an Install or Remove
# ════════════════════════════════════════════════════════════════════════════════════════════════
# modAction re-lists with loadMods(false). A failed re-list wrote its error into the hidden loading
# line, so the rows stayed as before the action and the pressed button kept its spinner for good.
_name99 = "mods: a failed re-list after an action"
_out99 = _js99(_name99, (
    "var serverId = 1; function _tr(s){ return s; } function esc(s){ return escapeHtml(s); }\n"
    "function modsMsg(t, cls){ const m = document.getElementById('mods-msg'); m.textContent = t || ''; }\n"
    "let queue = []; global.fetch = () => { const d = queue.shift();\n"
    "  return d === undefined ? Promise.reject(new Error('x'))\n"
    "    : Promise.resolve({json: () => Promise.resolve(d)}); };\n"),
    ("function modLabel(", "function modRow(", "function _r26c_modsDraw(", "function loadMods(",
     "function modAction("), (
    "  const out = {}, msg = document.getElementById('mods-msg'), list = document.getElementById('mods-list');\n"
    "  const done = {success: true, message: 'Installed'};\n"
    "  const good = {available: [{id: 'm1', name: 'M'}], installed: []};\n"
    "  for (const [k, relist] of [['route', {error: 'Could not list mods'}], ['500', " + _json99.dumps(_E99) + "],\n"
    "                             ['rejected', undefined], ['ok', good]]) {\n"
    "    const btn = document.createElement('button'); btn.innerHTML = 'Install'; list.innerHTML = 'before';\n"
    "    queue = [done]; if (relist !== undefined) queue.push(relist);\n"
    "    modAction('install', 'm1', btn); await settle(); await settle();\n"
    "    out[k] = {label: btn.innerHTML, disabled: btn.disabled, msg: msg.textContent,\n"
    "              redrawn: list.innerHTML !== 'before'}; }\n"
    "  console.log(JSON.stringify(out));\n"), _SF99)
if _out99 is not None:
    _note99 = ("✓ Installed The mod list could not be re-read, so these rows may be out of date. "
               "Reload the page to see them.")
    check("mods: a re-list that fails after an Install (an error reply, the catch-all's 500, a rejected "
          "request) says the rows may be out of date and takes the spinner off the button, which stays "
          "disabled (the rows silently kept the old state and the spinner spun for good)",
          all(_out99.get(k) == {"label": "Install", "disabled": True, "msg": _note99, "redrawn": False}
              for k in ("route", "500", "rejected")), repr(_out99))
    check("mods: ...while a re-list that works redraws the rows and adds no note",
          (_out99.get("ok") or {}).get("redrawn") is True and _out99["ok"]["msg"] == "✓ Installed",
          repr(_out99))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. The OS Updates card's page-load fill on an error reply
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #436 left the card empty on an error reply, but Install updates kept the template's state:
# disabled, titled "Checking for updates…", while nothing was checking. Now it is usable, as after a
# Check that failed and on a host never checked.
_RM99 = _read99("static", "js", "remote_manage.js")
_fill99 = "(function(){\n  if(!document.getElementById('update-info')) return;"
_name99 = "OS updates card: the page-load fill's error reply"
_out99 = _js99(_name99, (
    "var REMOTE_ID = 1, _updatesAsked = false; let states = [];\n"
    "function setInstallUpdatesState(s){ states.push(s); } function renderUpdates(){ states.push('render'); }\n"
    "window.agoText = () => '';\n"
    "const fill = () => {\n" + (_cut47(_RM99, _fill99) + ")();" if _fill99 in _RM99 else "/* MISSING fill */")
    + "\n};\n"), (), (
    "  const out = {}, el = document.getElementById('update-info');\n"
    "  for (const [k, d, ok] of [['500', " + _json99.dumps(_E99) + ", false], ['rejected', undefined],\n"
    "                            ['never', {known: false}], ['known', {known: true, at: 1}]]) {\n"
    "    states = []; el.innerHTML = ''; reply(d, ok); fill(); await settle();\n"
    "    out[k] = {states, card: el.innerHTML}; }\n"
    "  _updatesAsked = true; states = []; reply(undefined); fill(); await settle(); out.asked = states;\n"
    "  console.log(JSON.stringify(out));\n"), _RM99)
if _out99 is not None:
    check("OS updates card: an error reply or a failed request to the page-load fill leaves the card "
          "empty and Install updates usable (it stayed disabled as \"Checking for updates…\")",
          all(_out99.get(k) == {"states": ["unknown"], "card": ""} for k in ("500", "rejected")),
          repr(_out99))
    check("OS updates card: ...while a never-checked host and a known reading are unchanged, and a "
          "Check already pressed is not overridden",
          (_out99.get("never") or {}).get("states") == ["unknown"]
          and (_out99.get("known") or {}).get("states") == ["render"] and _out99.get("asked") == [],
          repr(_out99))

check("part99: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP99_START, repr(_P9_TRIPPED[_TRIP99_START:][:6]))
