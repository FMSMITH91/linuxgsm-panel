"""Part 157 of the unit suite: the twenty-fifth review's page-script and test-gate fixes (builder D).

Held here, each against the code path the finding named:

* the Mods section of Files & Config for a game with no LinuxGSM mods: it says so, instead of
  "Loading mods…" for good under its own tab.
* the console's command history: keyed by the account and the server's own row, dropped on any page
  drawn signed out, and a "fills the box" quick command ends Up/Down browsing.
* the console's coloured lines in the light theme, and the charts after a live change of scheme.
* the install page's tiles after Refresh list or Retry, and its greyed-out note on a non-Ubuntu host.
* the suite time limit's report during a unit part; the branch switch's signed-release walk; the update
  card's count and list on both paths; a stored first-Thursday wipe; the unit tailscale guard reading
  the script file a nested shell's -c script runs.

HOW IT RUNS. Scripts in node on this part's own fixtures (part87's DOM stand-in, part99's runner);
pages on part12's Flask app and client (part12 has run), every stub through _p9_patch and undone in
the finally.
"""
import datetime as _dt157
import json as _json157
import os
import re as _re157
import shutil as _shutil157
import tempfile as _tf157

from unit.part01 import check
from unit.part12 import P9_ADMIN, P9_GS, P9_VIEWER, _p9_arm, _p9_client, _p9_patch, _p9_restore_all
from unit.part143 import _SD143_PATH, _fire143
from unit.part99 import _SF99, _cut_or99, _js99, _line_or99, _read99
from unit import ts_nested as _tn157
from panel.ops import system_ops as _so157
from panel.ops.ssh_manager import _core as _smc157
from panel.routes import server_detail as _sd157
from panel.services import wipe_schedule as _ws157


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The Mods section for a game with no LinuxGSM mods installer
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #483 split Files & Config into sections: _uis_sfShow sets the chosen section's cards to
# display:''. The unsupported answer hid the whole card with the same property, so opening the
# Mods tab (always there) showed the card again with "Loading mods…", and nothing replaced it.
_name157 = "mods: a game with no LinuxGSM mods"
_out157 = _js99(_name157, (
    "var serverId = 1; function _tr(s){ return s; } function esc(s){ return escapeHtml(s); }\n"
    "function modsMsg(){}\n"), ("function modLabel(", "function modRow(", "function _r26c_modsDraw(",
                                "function loadMods("), (
    "  const out = {}, card = document.getElementById('mods-card');\n"
    "  const load = document.getElementById('mods-loading'), body = document.getElementById('mods-body'),\n"
    "    uns = document.getElementById('mods-unsupported');\n"
    "  for (const [k, d] of [['none', {supported: false}], ['some', {available: [{id: 'm1', name: 'M'}],\n"
    "                                                                installed: []}]]) {\n"
    "    card.style.display = ''; load.style.display = ''; body.style.display = 'none';\n"
    "    uns.style.display = 'none';\n"
    "    reply(d); const drew = await loadMods(true);\n"
    "    out[k] = {drew, card: card.style.display, load: load.style.display, body: body.style.display,\n"
    "              uns: uns.style.display}; }\n"
    "  console.log(JSON.stringify(out));\n"), _SF99)
if _out157 is not None:
    check("mods: a game with no LinuxGSM mods installer gets the card's own \"doesn't have any mods\" "
          "line, the loading line hidden, and the card left to the section tabs (it hid the card, which "
          "the Mods tab showed again with \"Loading mods…\" for good)",
          _out157.get("none") == {"drew": True, "card": "", "load": "none", "body": "none", "uns": ""},
          repr(_out157))
    check("mods: ...while a game with mods still draws its rows",
          _out157.get("some") == {"drew": True, "card": "", "load": "none", "body": "", "uns": "none"},
          repr(_out157))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The console's command history: whose it is, and how long it lasts
# ════════════════════════════════════════════════════════════════════════════════════════════════
# It was localStorage['sd.cmdHistory.' + serverId]: any account signed in on the same browser got the
# last account's commands (rcon and server passwords among them) on Up, sign-out left them there,
# and a re-created server with a reused id inherited them.
_pages157 = {}
try:
    _p9_arm(who="part157")
    _p9_patch(_sd157, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd157, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch(_smc157, "run_command", lambda *a, **k: ("", "", 1))
    for _who157, _uid157 in (("admin", P9_ADMIN), ("viewer", P9_VIEWER)):
        _r157 = _p9_client(_uid157).get("/server/%d" % P9_GS)
        _m157 = _re157.search(r"var _CMPA_HIST_SCOPE = (\S+);", _r157.get_data(as_text=True))
        _pages157[_who157] = (_r157.status_code, _json157.loads(_m157.group(1)) if _m157 else None)
finally:
    _p9_restore_all()
_sa157, _sv157 = (_pages157.get(k, (0, None))[1] or "" for k in ("admin", "viewer"))
check("console history: the server page keys it by the account, the server and the row's creation "
      "time (it named only the server id, so every account on the browser shared it)",
      _sa157.startswith("%d.%d." % (P9_ADMIN, P9_GS)) and _sv157.startswith("%d.%d." % (P9_VIEWER, P9_GS))
      and _sa157.split(".")[2] == _sv157.split(".")[2] and _sa157.split(".")[2].isdigit()
      and _sa157.split(".")[2] != "0", repr(_pages157))

_SD157 = _read99("panel", "static", "js", "server_detail.js")
_LS157 = ("const store = {}; global.localStorage = {\n"
          "  getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); },\n"
          "  removeItem: k => { delete store[k]; }, key: i => Object.keys(store)[i] || null,\n"
          "  get length(){ return Object.keys(store).length; } };\n")
_name157 = "console history: the storage key"
_out157 = _js99(_name157, _LS157 + (
    "var serverId = 7; var _CMPA_HIST_SCOPE = '3.7.100';\n"
    "store['sd.cmdHistory.7'] = JSON.stringify(['kick bob']); store['sd.consoleTs'] = '0';\n"
    + "".join(_line_or99(_SD157, h) + "\n" for h in (
        "var _CMPA_HIST_MAX", "var _cmpaHistMem", "var _cmpaBrowse", "var _cmpaHistIdx", "var _cmpaDraft",
        "try { localStorage.removeItem('sd.cmdHistory.' + serverId)"))), (
    "function _cmpaHistStoreKey(", "function _cmpaHistLoad(", "function _cmpaHistPush("), (
    "  const out = {legacy: store['sd.cmdHistory.7'] === undefined, ts: store['sd.consoleTs']};\n"
    "  _cmpaHistPush('kick alice');\n"
    "  out.mine = _cmpaHistLoad(); out.keys = Object.keys(store).sort();\n"
    "  _CMPA_HIST_SCOPE = '4.7.100'; out.other = _cmpaHistLoad();\n"
    "  _CMPA_HIST_SCOPE = '3.7.200'; out.reborn = _cmpaHistLoad();\n"
    "  _CMPA_HIST_SCOPE = undefined; const before = Object.keys(store).length;\n"
    "  _cmpaHistPush('say hi'); out.unscoped = [_cmpaHistLoad(), Object.keys(store).length - before];\n"
    "  console.log(JSON.stringify(out));\n"), _SD157)
if _out157 is not None:
    check("console history: another account, or a re-created server with the same id, does not get "
          "this account's commands; the old server-id-only key is removed when the page loads",
          _out157.get("mine") == ["kick alice"] and _out157.get("other") == []
          and _out157.get("reborn") == [] and _out157.get("legacy") is True
          and _out157.get("keys") == ["sd.cmdHistory.3.7.100", "sd.consoleTs"], repr(_out157))
    check("console history: ...and with no scope on the page it stays in the page, never under a key "
          "every account would share",
          _out157.get("unscoped") == [["kick alice", "say hi"], 0], repr(_out157))

_PJ157 = _read99("panel", "static", "js", "panel.js")
_name157 = "console history: dropped on a page drawn signed out"
_out157 = _js99(_name157, _LS157, (), (
    "  const out = {};\n"
    "  for (const signed of [true, false]) {\n"
    "    for (const k of Object.keys(store)) delete store[k];\n"
    "    store['sd.cmdHistory.3.7.100'] = '[\"a\"]'; store['sd.cmdHistory.4.8.1'] = '[\"b\"]';\n"
    "    store['sd.cmdHistory.9'] = '[\"c\"]'; store['sd.consoleTs'] = '0';\n"
    "    window.SIGNED_IN = signed;\n"
    "    " + _cut_or99(_PJ157, "function _r37d_dropCmdHistory(").replace("\n", "\n    ") + "\n"
    "    " + _line_or99(_PJ157, "if (window.SIGNED_IN !== true) _r37d_dropCmdHistory();") + "\n"
    "    out[signed ? 'in' : 'out'] = Object.keys(store).sort(); }\n"
    "  console.log(JSON.stringify(out));\n"), _PJ157)
if _out157 is not None:
    check("console history: a page drawn signed out (after Sign Out, or an expired or revoked session) "
          "removes every account's command history and nothing else (it outlived sign-out)",
          _out157.get("out") == ["sd.consoleTs"], repr(_out157))
    check("console history: ...while a signed-in page keeps it",
          _out157.get("in") == ["sd.cmdHistory.3.7.100", "sd.cmdHistory.4.8.1", "sd.cmdHistory.9",
                                "sd.consoleTs"], repr(_out157))

# A chip that fills the box sets its value from script, which fires no `input` event: browsing went
# on, and the next Down put the draft from before browsing over the chip's text.
_name157 = "console history: a quick command that fills the box"
_out157 = _js99(_name157, _LS157 + (
    "var serverId = 7; var _CMPA_HIST_SCOPE = '3.7.100';\n"
    "const input = document.getElementById('command-input'); input.focus = () => {};\n"
    "input.setSelectionRange = () => {}; document.activeElement = input;\n"
    + "".join(_line_or99(_SD157, h) + "\n" for h in (
        "var _CMPA_HIST_MAX", "var _cmpaHistMem", "var _cmpaBrowse", "var _cmpaHistIdx", "var _cmpaDraft"))), (
    "function _cmpaHistStoreKey(", "function _cmpaHistLoad(", "function _cmpaHistPush(",
    "function _cmpaHistStep(", "function cmpaQuickCommand("), (
    "  _cmpaHistPush('status'); input.value = 'half';\n"
    "  input.value = _cmpaHistStep(-1, input.value);\n"
    "  const chip = document.createElement('button'); chip.attrs = {'data-cmd': 'say', 'data-fill': '1'};\n"
    "  cmpaQuickCommand(chip); const filled = input.value;\n"
    "  console.log(JSON.stringify({browsed: 'status', filled, down: _cmpaHistStep(1, input.value)}));\n"),
    _SD157)
if _out157 is not None:
    check("console history: a quick command that fills the box ends Up/Down browsing, so the next Down "
          "leaves the chip's text alone (it put back the draft from before browsing)",
          _out157 == {"browsed": "status", "filled": "say ", "down": None}, repr(_out157))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The console's coloured lines in the light theme
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The console stays near-black in both schemes, but the light theme's `.text-warning` (#92400e, for a
# white page) also recoloured the console's "Some output … is not shown" line: about 2.7:1. Every
# semantic text colour the light theme darkens must keep its dark-scheme value inside the console.
_CSS157 = _read99("panel", "static", "css", "panel.css")
_dark157 = dict(_re157.findall(r"^\s+\.text-(\w+)\s*\{\s*color:\s*(#[0-9a-f]{6}) !important;", _CSS157,
                               _re157.M))
_light157 = _re157.findall(r'^\[data-bs-theme="light"\] \.text-(\w+) \{', _CSS157, _re157.M)
_inside157 = dict(_re157.findall(r'^\[data-bs-theme="light"\] \.console-output \.text-(\w+) \{ color: '
                                 r'(#[0-9a-f]{6}) !important; \}', _CSS157, _re157.M))
_miss157 = [_c for _c in _light157 if _c in _dark157 and _inside157.get(_c) != _dark157[_c]]
check("light theme: every semantic text colour it darkens for the white page keeps the dark scheme's "
      "colour inside the always-dark console (the console's gap notice was dark brown on near-black)",
      {"success", "danger", "warning", "info"} <= set(_light157) & set(_dark157) and not _miss157,
      repr((_light157, _dark157, _inside157, _miss157)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The server page's charts follow a live change of colour scheme
# ════════════════════════════════════════════════════════════════════════════════════════════════
# app_shell.js flips <html data-bs-theme> live when "System" follows the device. The charts took their
# ink when built (History refreshes in place, and the 7-day x axis was computed once at load), so they
# kept the old scheme's ticks, grid and legend until a reload.
_name157 = "charts: a live change of colour scheme"
_out157 = _js99(_name157, (
    "let scheme = 'dark', watched = null;\n"
    "document.documentElement = {getAttribute: k => (k === 'data-bs-theme' ? scheme : null)};\n"
    "global.MutationObserver = class { constructor(cb){ this.cb = cb; }\n"
    "  observe(el, o){ watched = {el: el === document.documentElement, o, cb: this.cb}; } };\n"
    "let updates = 0;\n"
    "const mk = () => ({update: () => { updates++; }, options: {\n"
    "  scales: {y: {ticks: {color: 'old'}, grid: {color: 'old'}}, y1: {ticks: {color: 'old'}, grid: {display: false}},\n"
    "           x: {ticks: {color: 'old'}, grid: {display: false}}},\n"
    "  plugins: {legend: {labels: {color: 'old'}}}}});\n"
    "var statsChart = mk(); var _histCharts = {'hist-host': mk()};\n"
    + _line_or99(_SD157, "var _r37d_inkWatch") + "\n"), (
    "function _cmpbInk(", "function _histX(", "function _r37d_inkChart(", "function _r37d_inkCharts(",
    "if (_r37d_inkWatch && document.documentElement)"), (
    "  const x7 = _histX().ticks.color; scheme = 'light';\n"
    "  if (watched) watched.cb();\n"
    "  const ink = c => [c.options.scales.y.ticks.color, c.options.scales.y.grid.color, c.options.scales.y1.ticks.color,\n"
    "    c.options.scales.y1.grid.color, c.options.scales.x.ticks.color, c.options.plugins.legend.labels.color];\n"
    "  console.log(JSON.stringify({x7, x7light: _histX().ticks.color, live: ink(statsChart),\n"
    "    hist: ink(_histCharts['hist-host']), updates, watch: watched && [watched.el, watched.o]}));\n"), _SD157)
if _out157 is not None:
    _light_ink157 = ["#4b5563", "rgba(0,0,0,.08)", "#4b5563", None, "#4b5563", "#1f2937"]
    check("charts: a change of colour scheme on <html> repaints the live CPU chart's and every History "
          "chart's ticks, grid lines and legend in the new scheme, and leaves a hidden grid hidden (they "
          "kept the old scheme's ink until a reload)",
          _out157.get("live") == _light_ink157 and _out157.get("hist") == _light_ink157
          and _out157.get("updates") == 2
          and _out157.get("watch") == [True, {"attributes": True, "attributeFilter": ["data-bs-theme"]}],
          repr(_out157))
    check("charts: ...and the 7-day x axis is drawn in the scheme in force when a chart is built (it was "
          "taken once, when the script loaded)",
          (_out157.get("x7"), _out157.get("x7light")) == ("#8b98a5", "#4b5563"), repr(_out157))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The install page's game tiles after Refresh list or Retry
# ════════════════════════════════════════════════════════════════════════════════════════════════
# refreshSection swaps #game-picker's contents: a new grid whose <img>s carry only data-icon-script.
# startGameIcons ran once, on load, its observer rooted at the old grid, so every tile kept its
# initials until a reload. And with no list on first render there was no #game-picker at all, so a
# Retry that loaded one never showed the picker.
_MS157 = _read99("panel", "static", "js", "manage_servers.js")
_name157 = "install page: the tiles after a refreshed game list"
_out157 = _js99(_name157, (
    "global.window = global; global.MOUNT = '/p'; let synced = 0; function syncGameTiles(){ synced++; }\n"
    "function img(u) { const a = {'data-icon-script': u};\n"
    "  return {src: '', getAttribute: k => (k in a ? a[k] : null), removeAttribute: k => { delete a[k]; },\n"
    "    has: () => 'data-icon-script' in a}; }\n"
    "const mkGrid = names => { const imgs = names.map(img);\n"
    "  return {imgs, querySelectorAll: () => imgs.filter(i => i.has())}; };\n"
    "const picker = {hidden: true}; let grid = null;\n"
    "document.getElementById = id => (id === 'game-grid' ? grid : id === 'game-picker' ? picker : null);\n"
    "const obs = [];\n"
    "global.IntersectionObserver = function (cb, opts) { const me = {cb, root: opts.root, seen: [], off: false};\n"
    "  obs.push(me); this.observe = el => me.seen.push(el); this.unobserve = () => {};\n"
    "  this.disconnect = () => { me.off = true; }; };\n"
    + _line_or99(_MS157, "var _r37d_iconWatch") + "\n"), (
    "function _loadGameIcon(", "function startGameIcons(", "function _r37d_gameTilesRefreshed("), (
    "  const out = {};\n"
    "  grid = mkGrid(['rustserver']); startGameIcons();\n"
    "  grid = mkGrid(['csgoserver', 'gmodserver']); _r37d_gameTilesRefreshed();\n"
    "  const io = obs[obs.length - 1];\n"
    "  io.cb(io.seen.map(t => ({target: t, isIntersecting: true})));\n"
    "  out.refresh = {observers: obs.length, oldOff: obs[0].off, root: io.root === grid,\n"
    "    src: grid.imgs.map(i => i.src), synced, shown: !picker.hidden};\n"
    "  grid = null; picker.hidden = true; _r37d_gameTilesRefreshed(); out.empty = picker.hidden;\n"
    "  console.log(JSON.stringify(out));\n"), _MS157)
if _out157 is not None:
    check("install page: after Refresh list or a Retry swaps the picker in, the new tiles' icons load "
          "(observed in the new grid, the old grid's observer dropped), the tiles are synced and the "
          "picker is shown (the icons never loaded again, and a Retry from an empty list showed no picker)",
          _out157.get("refresh") == {"observers": 2, "oldOff": True, "root": True,
                                     "src": ["/p/game-icon/csgoserver", "/p/game-icon/gmodserver"],
                                     "synced": 1, "shown": True}, repr(_out157))
    check("install page: ...and a swap that brought no list leaves the picker hidden",
          _out157.get("empty") is True, repr(_out157))
_IS157 = _read99("panel", "templates", "install_server.html")
check("install page: the picker is on the page even with no game list (hidden), so a Retry that "
      "loads one has a picker to fill",
      _re157.search(r'<div class="col-12 order-md-last" id="game-picker"\{% if not games %\} hidden'
                    r'\{% endif %\}>\s*\{% if games %\}', _IS157) is not None, "")
# #469 caps a Debian host by Debian releases (_capForHost); the note under the select said Ubuntu.
_fg157 = _cut_or99(_MS157, "function filterGamesForHost(")
_note157 = _re157.findall(r"why\.textContent = t\((\"[^\"]*\"|'[^']*')\)", _fg157)
check("install page: the greyed-out games note names no one distro (it said \"an older Ubuntu\" on a "
      "Debian host)", len(_note157) == 1 and "Ubuntu" not in _note157[0] and "Debian" not in _note157[0],
      repr(_note157))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. The suite time limit's report during a unit part
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The unit runner arms the limit with its own globals, but binds part01's `results` there only after
# the part loop, so a hang inside a part (the 22.04 freeze the limit was written for) printed the part
# and never "the last one recorded". part143's child planted `results` in its own globals, so its
# check passed on a shape the real runner does not have. Fired here with the runner's real shape:
# `_part` in the globals, the checks only in another module.
_NORES157 = (
    "import importlib.util, sys, threading, types\n"
    "s = importlib.util.spec_from_file_location('suite_deadline', %r)\n"
    "sd = importlib.util.module_from_spec(s); s.loader.exec_module(sd)\n"
    "m = types.ModuleType('standin157'); m.results = [(True, 'the check before the hang', '')]\n"
    "sys.modules['standin157'] = m\n"
    "_part = 'part99'\n"
    "sd.arm(globals()%s)\n"
    "def _stuck_157():\n"
    "    lk = threading.Lock(); lk.acquire(); lk.acquire()\n"
    "_stuck_157()\n")
_dl157 = {_k: _fire143(_NORES157 % (_SD143_PATH, _arg), "nores" + _k)
          for _k, _arg in (("named", ", results_from='standin157'"), ("unnamed", ""))}
check("suite deadline: a runner whose checks live in a part's module (no `results` in its own globals) "
      "still gets the count and the last check recorded in the report",
      _dl157["named"][0] == 124 and "in part: part99" in _dl157["named"][1]
      and "checks recorded so far: 1" in _dl157["named"][1]
      and "the check before the hang" in _dl157["named"][1], repr(_dl157["named"][1][-1500:]))
check("suite deadline: ...and without naming that module the report has only the part (control: the "
      "unit runner's report until now)",
      _dl157["unnamed"][0] == 124 and "in part: part99" in _dl157["unnamed"][1]
      and "checks recorded so far" not in _dl157["unnamed"][1], repr(_dl157["unnamed"][1][-800:]))
_arms157 = {}
for _rn157, _pkg157 in (("unit_test.py", "unit"), ("smoke_test.py", "smoke")):
    _src157 = _read99("tests", _rn157)
    _arms157[_rn157] = (_re157.findall(r"\barm\(globals\(\)(?:, results_from=\"([\w.]+)\")?\)", _src157),
                        _re157.search(r"^results = \[\]$", _read99("tests", _pkg157, "part01.py"), _re157.M)
                        is not None)
check("suite deadline: the unit and smoke runners, which bind `results` from part01 only after running "
      "it, name part01's module for the report, and that module holds `results`",
      _arms157 == {"unit_test.py": (["unit.part01"], True), "smoke_test.py": (["smoke.part01"], True)},
      repr(_arms157))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. The branch SWITCH walk skips a commit that is not a signed release
# ════════════════════════════════════════════════════════════════════════════════════════════════
# part03 answers "signed" for every commit suite-wide, and part142 drives the real gate only through
# the update card, so `if not signed(sha): continue` in _verified_branch_target could go and every
# check stayed green: a switch would pin a CI-passing but UNSIGNED commit. Driven here with the gate
# answering for a set, git and the CI state stubbed (the walk's newest first: C3, C2, C1).
_C157 = ("c3" * 20, "c2" * 20, "c1" * 20)


def _git157(args, timeout=45):
    del timeout
    return ((" ".join(_C157), "", 0) if args[:2] == ["rev-list", "--first-parent"] else ("", "", 0))


def _gate157(signed):
    """A _release_gate_for stand-in: a commit is a signed release when it is in `signed`."""
    return lambda branch: (lambda sha: sha in signed)


_sw157 = {}
try:
    _p9_patch(_so157, "_git", _git157)
    _p9_patch(_so157, "_remote_ci_state", lambda sha: "passing")
    for _k157, _signed157 in (("newest unsigned", {_C157[1], _C157[2]}), ("none signed", set()),
                              ("newest signed", set(_C157))):
        _p9_patch(_so157, "_release_gate_for", _gate157(frozenset(_signed157)))
        _sha157, _why157 = _so157._verified_branch_target("main")
        _sw157[_k157] = (_sha157, str(_why157))
finally:
    _p9_restore_all()
check("branch switch: the walk skips a newest commit that passed CI but is not a signed release and "
      "takes the newest signed one (nothing tested the switch walk with an unsigned commit)",
      _sw157.get("newest unsigned") == (_C157[1], ""), repr(_sw157))
check("branch switch: ...with no signed commit it switches to nothing and says none passed",
      _sw157.get("none signed", ("x",))[0] == "" and "passed its automated checks" in _sw157["none signed"][1],
      repr(_sw157))
check("branch switch: ...and a signed newest commit is taken (positive control)",
      _sw157.get("newest signed") == (_C157[0], ""), repr(_sw157))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 8. The update card counts and lists the same commits, on both of its paths
# ════════════════════════════════════════════════════════════════════════════════════════════════
# An update made only of test or tooling commits said "1 commit behind" over an empty list. part06's
# gates for that read the text of system_ops.py from `def _compute_update_status` to the END of the
# file and took the first match, which is the non-default-branch path: reverting the verified path's
# fallback (`shown_log = rc_log`) left them green. Driven here on both paths, with every read the
# function makes stubbed: the filtered changelog is empty, the unfiltered one holds one commit.
_TIP157 = "ab" * 20
_ONE157 = "ab12345 Tooling only (#1)"


def _git_uc157(args, timeout=45):
    del timeout
    if args[:3] == ["rev-list", "--first-parent", "--count"]:
        return "1\n", "", 0
    if args[:3] == ["rev-list", "--first-parent", "-n"]:
        return _TIP157 + "\n", "", 0
    if args[:1] == ["rev-parse"]:
        return (_TIP157[:7] if "--short" in args else _TIP157) + "\n", "", 0
    return "", "", 0   # fetch, show-ref and merge-base --is-ancestor: all succeed


def _changelog157(rev_range, runtime_only=True):
    del rev_range
    return [] if runtime_only else [_ONE157]


_uc157 = {}
try:
    for _n157, _v157 in (("_git", _git_uc157), ("_is_git_checkout", lambda: True),
                         ("panel_version", lambda: "1.0"), ("_release_gate_for", _gate157(frozenset([_TIP157]))),
                         ("_remote_ci_state", lambda sha: "passing"), ("_update_touches_runtime", lambda ref: True),
                         ("_runtime_changelog", _changelog157), ("version_for_commit", lambda commit="HEAD": "2.0"),
                         ("_release_notes_fields", lambda target: {}), ("github_repo_url", lambda: ""),
                         ("_ci_note_walk", lambda started, commits, offered: None)):
        _p9_patch(_so157, _n157, _v157)
    for _br157 in ("main", "dev"):
        _p9_patch(_so157, "_tracked_branch", lambda _b=_br157: _b)
        _st157 = _so157._compute_update_status()
        _uc157[_br157] = {_k: _st157.get(_k) for _k in ("update_available", "behind", "changes", "target_sha")}
finally:
    _p9_restore_all()
_want157 = {"update_available": True, "behind": 1, "changes": [_ONE157], "target_sha": _TIP157}
check("update card: an update made only of tooling commits lists the commit it counts, on the default "
      "branch's verified path (part06's text gates read the other path and missed it)",
      _uc157.get("main") == _want157, repr(_uc157))
check("update card: ...and on a tracked non-default branch", _uc157.get("dev") == _want157, repr(_uc157))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 9. A stored first-Thursday wipe fires on the first Thursday only
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The preset is stored as the cron line `0 19 1-7 * 4`, which cron reads as the 1st-7th OR any
# Thursday. wipe_schedule.due, which the sweep and the card both use, re-parses that line and sets
# "both" again from the entry's preset; part152 tested only spec_for's own spec, so losing that line
# (a Rust wipe on every day 1-7 and every Thursday, up to ten a month) failed nothing.
def _utc157(*a):
    return _dt157.datetime(*a, tzinfo=_dt157.timezone.utc).timestamp()


_ft157 = dict(preset="first-thursday", cron="0 19 1-7 * 4", tz="UTC", anchor=_utc157(2026, 11, 1))
_due157 = {_k: _ws157.due(_ft157, now=_t) for _k, _t in (
    ("mon 2nd", _utc157(2026, 11, 2, 19, 1)), ("thu 5th", _utc157(2026, 11, 5, 19, 1)))}
check("wipe: a stored first-Thursday schedule is not due on another of the 1st-7th, and is due on the "
      "first Thursday (the sweep's due() must keep the AND, which cron's line alone reads as OR)",
      _due157 == {"mon 2nd": (None, _utc157(2026, 11, 5, 19)), "thu 5th": ("run", _utc157(2026, 11, 5, 19))},
      repr(_due157))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 10. The unit tailscale guard reads the script file a nested shell's -c script runs
# ════════════════════════════════════════════════════════════════════════════════════════════════
# ts_nested answered a nested shell with -c as "read already": its -c script was part of the outer
# text, but a script FILE it ran was never read, so `bash -c 'bash -c "sh f.sh"'` with a tailscale in
# f.sh ran the machine's binary unshimmed and unjudged (the dev machine has one; CI does not). Written
# in '…' it was lost earlier still: the single-quote stripper empties '…' before the split. Driven on
# the runner's own bound reader (unit_test.py imports it as unit.ts_nested and binds it).
_tnd157 = _tf157.mkdtemp(prefix="lgsm-unit-p157-")
try:
    _tnf157 = os.path.join(_tnd157, "inner-157.sh")
    with open(_tnf157, "w", encoding="utf-8") as _fh157:
        _fh157.write("tailscale version\n")
    _nested157 = [_tn157.shell_text(["bash", "-c", _s % _tnf157], {}) for _s in (
        'bash -c "sh %s"', "bash -c 'sh %s'", "true; sudo -u x bash -ec 'exec sh %s'")]
finally:
    _shutil157.rmtree(_tnd157, ignore_errors=True)
check("unit suite guard: a script file a nested shell's -c script runs is read with it, the -c in double "
      "quotes, in single quotes, or behind sudo",
      [(_t or "").count("tailscale version") for _t in _nested157] == [1] * 3, repr(_nested157))
