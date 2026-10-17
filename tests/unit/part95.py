"""Part 95 of the unit suite: the fourteenth review's page and script fixes (builder C).

Held here, each against the code path the finding named:

* a dropped folder of which NOTHING could be read: the status line says so, rather than "no files in
  what you dropped" beside a toast saying they could not be read.
* a page read answered with an error reply (`error`, since #435 on every one) is not "nothing there":
  the install progress poll, the Security tab's events, the account's sessions, and every reader of
  the same shape found by a repo-wide search (the panel's backups and their players pre-check, the
  backup settings save, the OS-updates card on load, the history charts, the Players card, the panel
  branch picker, the reboot and OS-updates banners, the upload pre-check).

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on this part's own fixtures. app.py's catch-all
lives inside create_app, which this suite must not build (part12's note): its 500 body is
_r23c_error_json's, built here in a request context.
"""
import json as _json95
import os

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _SETTLE47, _cut47, _node47
from unit.part87 import _DOM87
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json,
                         _p9_patch, _p9_restore_all)
from panel.core.http import _r23c_error_json as _err95
from panel.db.models import AuditLog as _Audit95
from panel.ops import system_ops as _so95
from panel.routes import panel_backup as _pb95, remote_vps as _rv95

_TRIP95_START = len(_P9_TRIPPED)


def _read95(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _node95(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _cut_or95(src, head):
    """_cut47's statement, or a comment naming it, so the check that runs it fails BY NAME."""
    return _cut47(src, head) if head in src else "/* MISSING %s */" % head


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A dropped folder of which nothing could be read
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #434 counted what could not be read and toasted it, then handed the empty list to uploadEntries,
# whose empty branch says "Nothing to upload — no files in what you dropped." The drop HAD files.
_SF95 = _read95("static", "js", "server_files.js")
_drop95 = "card.addEventListener('drop', function(ev){"
_name95 = "file drop: nothing in a dropped folder could be read"
_out95 = _node95(_name95, _SETTLE47 + (
    "global.window = global; let toasts = [], status = [], uploaded = [], curDir = 'here';\n"
    "global.toast = (m, k) => toasts.push([m, k]);\n"
    "global.tfn = (n, one, many) => (n === 1 ? one : many).replace('{n}', n);\n"
    "global._uploadStatus = (t, c) => status.push([t, c || '']); global.uploadFiles = () => {};\n"
    "global.uploadEntries = (list, base) => { uploaded.push([list.length, base]); };\n"
    "global.setTimeout = () => 0;\n"
    "const file = (name, ok) => ({isFile: true, name, file: (y, n) => ok ? y({name}) : n(new Error('x'))});\n"
    "const dir = (name, batches) => ({isDirectory: true, name, createReader: () => {\n"
    "  let i = 0; return {readEntries: (y, n) => { const b = batches[i++];\n"
    "    if (b === 'ERR') n(new Error('x')); else y(b || []); }}; }});\n"
    + _cut_or95(_SF95, "function _walkEntry(") + "\n"
    + _cut_or95(_SF95, "function _dropRoots(") + "\n"
    "let handler = null; const card = {addEventListener: (k, f) => { if (k === 'drop') handler = f; }};\n"
    + (_cut47(_SF95, _drop95) + ");" if _drop95 in _SF95 else "/* MISSING drop handler */") + "\n"
    "const drop = async root => { toasts = []; status = []; uploaded = [];\n"
    "  handler({dataTransfer: {items: [{kind: 'file', webkitGetAsEntry: () => root}]}});\n"
    "  await settle(); await settle();\n"
    "  return {toasts, status: status.slice(1), uploaded}; };\n"
    "(async () => {\n"
    "  const out = {};\n"
    "  out.locked = await drop(dir('addon', [[file('a.bin', false), file('b.bin', false)]]));\n"
    "  out.unlisted = await drop(dir('addon', ['ERR']));\n"
    "  out.partial = await drop(dir('addon', [[file('a.txt', true), file('b.bin', false)]]));\n"
    "  out.empty = await drop(dir('addon', [[]]));\n"
    "  console.log(JSON.stringify(out));\n"
    "})();\n"))
if _out95 is not None:
    _two95 = "2 dropped items could not be read and are not uploaded."
    _one95 = "1 dropped item could not be read and is not uploaded."
    check("file drop: a folder whose every file is unreadable says so on the status line too, and "
          "uploads nothing (it said \"no files in what you dropped\" beside the toast)",
          _out95.get("locked") == {"toasts": [[_two95, "warning"]], "status": [[_two95, "text-warning"]],
                                   "uploaded": []}, repr(_out95))
    check("file drop: ...as does a folder whose listing fails outright",
          _out95.get("unlisted") == {"toasts": [[_one95, "warning"]], "status": [[_one95, "text-warning"]],
                                     "uploaded": []}, repr(_out95))
    check("file drop: ...while a partly readable folder still uploads what was read, and a truly "
          "empty one still reaches the \"nothing to upload\" branch",
          _out95.get("partial") == {"toasts": [[_one95, "warning"]], "status": [], "uploaded": [[1, "here"]]}
          and _out95.get("empty") == {"toasts": [], "status": [], "uploaded": [[0, "here"]]},
          repr(_out95))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. An error reply is not "nothing there"
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #435 put `error` on every error body so a page's read can tell the two apart; these readers never
# looked. The bodies fed below are the real ones: the catch-all's 500 (_r23c_error_json), and each
# route's own failure answer, driven on part12's app with the read inside it made to raise.
with _p9.test_request_context("/"):
    _E95 = _err95("MSG-500").get_json()


def _raise95(*_a, **_k):
    raise RuntimeError("unit p95 read failed")


class _NoQuery95:
    """AuditLog.query for one request: every use raises, as a locked database does.

    Each method is found and raises when CALLED (query.filter(...), .count()), as SQLAlchemy raises
    on a locked database. The lookup itself raised RuntimeError before, which CodeQL flags
    (py/unexpected-raise-in-special-method: a failing lookup should be AttributeError), and an
    AttributeError would read to getattr/hasattr callers as "no such method" rather than a failure.
    """

    @staticmethod
    def _fail(*_a, **_k):
        raise RuntimeError("unit p95 audit read failed")

    def __getattr__(self, _name):
        return self._fail


_R95 = {}
# AuditLog.query is Flask-SQLAlchemy's class-level property, inherited: shadowed on AuditLog for one
# request and the shadow deleted again (a value put back with setattr would pin one session's query).
_q_own95 = "query" in _Audit95.__dict__
_q_was95 = _Audit95.__dict__.get("query")


def _r95_unshadow():
    """Put AuditLog.query back as it was (safe to call twice)."""
    if _q_own95:
        _Audit95.query = _q_was95
    elif "query" in _Audit95.__dict__:
        del _Audit95.query


try:
    _p9_arm(who="part95")
    _c95 = _p9_client(P9_ADMIN)
    _Audit95.query = _NoQuery95()
    _r = _c95.get("/api/panel/security/events")
    _R95["events"] = (_r.status_code, _p9_json(_r))
    _r95_unshadow()
    _p9_patch(_pb95, "_fetch_backup_listings", _raise95)
    _r = _c95.get("/api/panel/backups")
    _R95["backups"] = (_r.status_code, _p9_json(_r))
    _r = _c95.post("/api/panel/backup/settings", json={"enabled": "yes"})
    _R95["settings"] = (_r.status_code, _p9_json(_r))
    _p9_patch(_so95, "list_panel_branches", _raise95)
    _r = _c95.get("/api/panel/branches")
    _R95["branches"] = (_r.status_code, _p9_json(_r))
    _p9_patch(_rv95, "remote_reboot_required", _raise95)
    _r = _c95.get("/api/remote/%d/reboot-required" % P9_HOST)
    _R95["reboot"] = (_r.status_code, _p9_json(_r))
finally:
    _r95_unshadow()
    _p9_restore_all()
check("error replies: each route's own failure answer, as these checks feed it, carries `error` "
      "(the reboot read says known: false)",
      _R95.get("events", (0, {}))[1].get("error") and _R95.get("events", (0, {}))[1].get("events") == []
      and _R95.get("backups", (0, {}))[1].get("error")
      and _R95.get("settings", (0, {}))[0] == 400 and _R95["settings"][1].get("success") is False
      and _R95.get("branches", (0, {}))[1].get("error")
      and _R95.get("reboot", (0, {}))[0] == 200
      and _R95["reboot"][1].get("required") is False and _R95["reboot"][1].get("known") is False,
      repr(_R95))
_J95 = {k: _json95.dumps(v[1]) for k, v in _R95.items()}
_J95["500"] = _json95.dumps(_E95)
# The fetch stand-in: `reply(d, ok)` sets what the next fetch resolves with.
_ANS95 = ("const reply = (d, ok) => { global.fetch = () => Promise.resolve({ok: ok !== false,\n"
          "  status: ok === false ? 500 : 200, json: () => Promise.resolve(d)}); };\n")


def _js95(name, setup, cuts, body, src):
    """Run part87's DOM + `setup` + the cut statements of `src` + `body` in node; its JSON, or None."""
    return _node95(name, _DOM87 + _SETTLE47 + _ANS95 + setup
                   + "".join(_cut_or95(src, h) + "\n" for h in cuts) + "(async () => {\n" + body + "})();\n")


# ── 2a. The install progress poll ─────────────────────────────────────────────────────────────
# One failed poll answered by the catch-all became "nothing is installing": every live row settled
# (a still-running install's was dropped) and stop() ended the poll until the install finished.
_IP95 = _read95("static", "js", "install_progress.js")
_name95 = "install progress: an error reply to the poll"
_out95 = _js95(_name95, (
    "var MOUNT = '', missed = 0, applied = [], stops = 0, stale = [];\n"
    "function apply(j){ applied.push(j.length); } function stop(){ stops++; }\n"
    "function markStale(on){ stale.push(!!on); }\n"), ("function tick(",), (
    "  const out = {};\n"
    "  reply(" + _J95["500"] + ", false); tick(); await settle(); tick(); await settle();\n"
    "  out.err = {applied, stops, stale, missed};\n"
    "  applied = []; stops = 0; stale = []; reply({installs: []}); tick(); await settle();\n"
    "  out.none = {applied, stops, stale, missed};\n"
    "  console.log(JSON.stringify(out));\n"), _IP95)
if _out95 is not None:
    check("install progress: two error replies to the poll are two misses (stale on the second), "
          "never \"nothing installing\" — no row settled, the poll not stopped",
          _out95.get("err") == {"applied": [], "stops": 0, "stale": [True], "missed": 2}, repr(_out95))
    check("install progress: ...and a real answer that nothing is installing still applies it and stops",
          _out95.get("none") == {"applied": [0], "stops": 1, "stale": [False], "missed": 0}, repr(_out95))

# ── 2b. The Security tab's events, and the account's sessions ─────────────────────────────────
_RM95 = _read95("static", "js", "remote_manage.js")
_name95 = "security events: the route's failure answer"
_out95 = _js95(_name95, "", ("function loadSecurityEvents(",), (
    "  const out = {}, el = document.getElementById('sec-events');\n"
    "  for (const [k, d] of [['route', " + _J95["events"] + "], ['500', " + _J95["500"] + "],\n"
    "                        ['none', {events: []}]]) {\n"
    "    reply(d); el.innerHTML = ''; loadSecurityEvents(); await settle(); out[k] = el.innerHTML; }\n"
    "  console.log(JSON.stringify(out));\n"), _RM95)
if _out95 is not None:
    check("security events: the route's own failure answer (200, events [], error) and the catch-all's "
          "500 read \"Could not load events.\", not \"No security events yet.\"",
          all("Could not load events." in (_out95.get(k) or "") for k in ("route", "500"))
          and "No security events yet." in (_out95.get("none") or ""), repr(_out95))

_AS95 = _read95("static", "js", "account_sessions.js")
_name95 = "account sessions: an error reply"
_out95 = _js95(_name95, (
    "const box = document.getElementById('sessions-list'); function mp(){ return ''; }\n"
    "function row(){ return {}; }\n"), ("function load(",), (
    "  const out = {};\n"
    "  for (const [k, d] of [['500', " + _J95["500"] + "], ['none', {sessions: []}]]) {\n"
    "    reply(d); box.innerHTML = ''; load(); await settle(); out[k] = box.innerHTML; }\n"
    "  console.log(JSON.stringify(out));\n"), _AS95)
if _out95 is not None:
    check("account sessions: an error reply reads \"Couldn't load sessions.\", not \"No active "
          "sessions.\" while you are signed in; an empty list still says none",
          "Couldn\\'t load sessions." in _AS95 and "load sessions." in (_out95.get("500") or "")
          and "No active sessions." in (_out95.get("none") or ""), repr(_out95))

# ── 2c. The panel's backups card: the listing, the players pre-check, the settings save ───────
_RB95 = _read95("static", "js", "remote_manage_backups.js")
_name95 = "panel backups: error replies"
_out95 = _js95(_name95, (
    "let listed = 0, dialogs = [], players = [];\n"
    "function bkRenderList(){ listed++; } function bkApplyLimits(){} function bkShowEncState(){}\n"
    "function bkRenderFullSchedule(){} function bkRenderDisk(){} function fbSummary(){}\n"
    "function bkRenderFullStatus(){} function bkRenderAutoStatus(){} function bkRenderGames(){}\n"
    "function bkRefreshDefaultNotes(){} function fbStart(){}\n"
    "global.confirmDialog = o => dialogs.push(o.title); function fbPlayersDialog(b){ players.push(b.length); }\n"
    "['bk-tbody', 'bk-enabled', 'bk-keep', 'fb-auto-enabled', 'fb-interval', 'fb-keep']\n"
    "  .forEach(id => { const e = document.getElementById(id); e.value = '7'; e.checked = true; });\n"
    # the card's in-flight save counter (review 1017a): loadBackups and the saves read it
    + _RB95[_RB95.index("var _r30c_bkSaving"):].split("\n", 1)[0] + "\n"),
    ("function bkMsg(", "function bkReconcile(", "function _r25c_bkUnread(", "function _r30c_bkSave(",
     "function loadBackups(", "function runFullBackup(", "function saveBackupSettings("), (
    "  const out = {}, l = document.getElementById('bk-loading'), m = document.getElementById('bk-msg');\n"
    "  reply(" + _J95["backups"] + "); loadBackups(); await settle();\n"
    "  out.list = {loading: l.innerHTML || '', listed};\n"
    "  reply(" + _J95["500"] + "); runFullBackup(null); await settle();\n"
    "  out.pre = {msg: m.textContent, dialogs: dialogs.slice(), players: players.slice()};\n"
    "  dialogs = []; reply({total: 2, busy: []}); runFullBackup(null); await settle(); out.preOk = dialogs.slice();\n"
    "  reply(" + _J95["settings"] + "); saveBackupSettings(); await settle();\n"
    "  out.save = [m.textContent, m.className];\n"
    "  reply({success: true, settings: {keep_days: 7}, full: {keep: 7}}); saveBackupSettings(); await settle();\n"
    "  out.saveOk = [m.textContent, m.className];\n"
    "  console.log(JSON.stringify(out));\n"), _RB95)
if _out95 is not None:
    _o95 = _out95
    check("panel backups: the route's failure answer (200, error) reads \"Could not load backups.\" and "
          "fills no list (it said \"No backups yet.\" and \"No installed game servers.\")",
          "Could not load backups." in (_o95.get("list") or {}).get("loading", "")
          and (_o95.get("list") or {}).get("listed") == 0, repr(_o95))
    check("panel backups: an error reply to the players pre-check is \"Could not check players\", "
          "not nobody online (the confirm without the players warning); an empty busy list still asks",
          _o95.get("pre") == {"msg": "✗ Could not check players", "dialogs": [], "players": []}
          and _o95.get("preOk") == ["Back up all servers"], repr(_o95))
    check("panel backups: a refused settings save says the route's sentence in red, not \"✓ Saved\"; "
          "a saved one still says Saved",
          _o95.get("save") == ["✗ enabled must be true or false.", "small text-danger"]
          and (_o95.get("saveOk") or [""])[0].startswith("✓ Saved"), repr(_o95))

# ── 2d. The OS-updates card on load, the panel branch picker ───────────────────────────────────
_cached95 = "(function(){\n  if(!document.getElementById('update-info')) return;"
_name95 = "OS updates card on load: an error reply"
_out95 = _js95(_name95, (
    "var REMOTE_ID = 1, _updatesAsked = false, states = [];\n"
    "global.setInstallUpdatesState = s => states.push(s); global.renderUpdates = () => states.push('render');\n"
    "const runCached = () => { " + (_cut47(_RM95, _cached95) + ")();" if _cached95 in _RM95
                                    else "/* MISSING updates-cached loader */") + " };\n"), (), (
    "  const out = {}, el = document.getElementById('update-info');\n"
    "  for (const [k, d] of [['500', " + _J95["500"] + "], ['never', {known: false}]]) {\n"
    "    reply(d); el.innerHTML = ''; states = []; runCached(); await settle(); out[k] = [el.innerHTML, states]; }\n"
    "  console.log(JSON.stringify(out));\n"), _RM95)
if _out95 is not None:
    check("OS updates card on load: an error reply leaves the card empty, as a failed request does — "
          "not \"Not checked yet\"; a host never checked still says so",
          # The button half: since review 1016c an error reply sets Install updates usable
          # ('unknown'), as a failed Check does; part99 holds that change.
          _out95.get("500") == ["", ["unknown"]] and "Not checked yet" in (_out95.get("never") or [""])[0],
          repr(_out95))

_RMH95 = _read95("static", "js", "remote_manage_host.js")
_name95 = "panel branch picker: the route's failure answer"
_out95 = _js95(_name95, "", ("function loadPanelBranches(",), (
    "  const cur = document.getElementById('pu-branch-current'), sel = document.getElementById('pu-branch-select');\n"
    "  cur.textContent = '…'; sel.innerHTML = 'KEPT';\n"
    "  reply(" + _J95["branches"] + "); loadPanelBranches(); await settle();\n"
    "  const out = {err: [cur.textContent, sel.innerHTML]};\n"
    "  reply({branches: ['main', 'dev'], current: 'dev'}); loadPanelBranches(); await settle();\n"
    "  out.ok = [cur.textContent, sel.children.length];\n"
    "  console.log(JSON.stringify(out));\n"), _RMH95)
if _out95 is not None:
    check("panel branch picker: the route's failure answer (its fallback current \"main\") names no "
          "branch and leaves the picker; a reading still fills both",
          _out95.get("err") == ["…", "KEPT"] and _out95.get("ok") == ["dev", 2], repr(_out95))

# ── 2e. The server page: history charts, the Players card ──────────────────────────────────────
_SD95 = _read95("static", "js", "server_detail.js")
_name95 = "server page: error replies to history and the player list"
_out95 = _js95(_name95, (
    "var serverId = 1, _histRange = '24h', drawn = 0, wanted = 'before';\n"
    "function _histChart(){ drawn++; } function _histLbl(){ return ''; } function _ds(){ return {}; }\n"
    "function _histXScale(){ return {}; } var _histTimes = {}, _histX = {};\n"
    "global.applyPlayersVisibility = () => { wanted = 'applied'; };\n"
    "var _CAN_MODERATE = true;\n"),
    ("function _r25c_histUnread(", "window.loadHistory = function(", "function renderPlayers("), (
    "  const empty = document.getElementById('hist-empty'), out = {};\n"
    "  document.getElementById('players-card').style.display = '';\n"
    "  empty.style.display = 'none'; reply(" + _J95["500"] + "); window.loadHistory(); await settle();\n"
    "  out.hist = [empty.style.display, drawn];\n"
    "  reply({server: [], host: []}); window.loadHistory(); await settle(); out.histNone = empty.style.display;\n"
    "  renderPlayers(" + _J95["500"] + "); out.players = wanted;\n"
    "  console.log(JSON.stringify(out));\n"), _SD95)
if _out95 is not None:
    check("server page: an error reply to the history read is not \"No history yet\" (charts kept); "
          "an empty reading still says it",
          _out95.get("hist") == ["none", 0] and _out95.get("histNone") == "", repr(_out95))
    check("server page: an error reply to the player list leaves the Players card as it is (it was "
          "painted as a game that cannot be queried)",
          _out95.get("players") == "before", repr(_out95))

# ── 2f. The reboot and OS-updates banners ───────────────────────────────────────────────────────
_NG95 = _read95("static", "js", "nags.js")
_name95 = "banners: a failed read keeps what a good one put up"
_out95 = _js95(_name95, (
    "let removed = 0, cleared = 0, rendered = 0;\n"
    # A "reboot needed" banner (review 1016c: a wait or job banner is taken down on known: false).
    "const nag = {remove(){ removed++; }, getAttribute(k){ return k === 'data-rb' ? 'required' : null; }};\n"
    "const _gid = document.getElementById; document.getElementById = id => id === 'reboot-nag-1' ? nag : _gid(id);\n"
    "window.rebootNagRender = () => { rendered++; };\n"
    "function _osNagClear(){ cleared++; }\n"
    "global.sessionStorage = {getItem(){ return null; }};\n"),
    ("function _r26c_rbUnread(", "window.rebootNagCheck = function(", "window.osUpdatesNagCheck = function("), (
    "  const out = {};\n"
    "  reply(" + _J95["reboot"] + "); window.rebootNagCheck(1, 'h'); await settle(); out.rbErr = removed;\n"
    "  reply(null, false); window.rebootNagCheck(1, 'h'); await settle(); out.rbFail = removed;\n"
    "  reply({required: false, known: true, pending_empty: false, job: null}); window.rebootNagCheck(1, 'h');\n"
    "  await settle(); out.rbNone = removed;\n"
    "  reply({required: false, known: false, pending_empty: true, job: null}); window.rebootNagCheck(1, 'h');\n"
    "  await settle(); out.rbWait = rendered;\n"
    "  reply(" + _J95["500"] + ", false); window.osUpdatesNagCheck(); await settle(); out.osErr = cleared;\n"
    "  reply({hosts: []}); window.osUpdatesNagCheck(); await settle(); out.osNone = cleared;\n"
    "  console.log(JSON.stringify(out));\n"), _NG95)
if _out95 is not None:
    check("reboot banner: the route's failure answer (known: false) and a failed request leave the "
          "banner up; a read that says no reboot is needed takes it down; a pending wait still shows",
          _out95.get("rbErr") == 0 and _out95.get("rbFail") == 0 and _out95.get("rbNone") == 1
          and _out95.get("rbWait") == 1, repr(_out95))
    check("OS-updates banner: a failed read leaves it up; an answer with nothing waiting clears it",
          _out95.get("osErr") == 0 and _out95.get("osNone") == 1, repr(_out95))

# ── 2g. The upload pre-check ──────────────────────────────────────────────────────────────────
_SF95 = _read95("static", "js", "server_files.js")
_name95 = "upload pre-check: an error reply"
_out95 = _js95(_name95, (
    "var serverId = 1, curDir = 'here', calls = [];\n"
    "function _flat(f){ return {file: f, dir: ''}; } function _doUpload(e, o, b, checked){ calls.push(checked); }\n"), (
    "function uploadFiles(",), (
    "  const out = {};\n"
    "  for (const [k, d] of [['400', {error: 'Invalid request'}], ['500', " + _J95["500"] + "],\n"
    "                        ['ok', {existing: [], checked: true}], ['unread', {existing: [], checked: false}]]) {\n"
    "    calls = []; reply(d); uploadFiles([{name: 'a.txt'}], 'here'); await settle(); out[k] = calls[0]; }\n"
    "  console.log(JSON.stringify(out));\n"), _SF95)
if _out95 is not None:
    check("upload pre-check: an error reply is a check that did not happen (the clash summary says the "
          "host could not be checked first), as the route's own checked:false is; a real check is one",
          _out95 == {"400": False, "500": False, "ok": True, "unread": False}, repr(_out95))

check("part95: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP95_START, repr(_P9_TRIPPED[_TRIP95_START:][:6]))
