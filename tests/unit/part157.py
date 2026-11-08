"""Part 157 of the unit suite: the twenty-fifth review's page-script and test-gate fixes (builder D).

Held here, each against the code path the finding named:

* the Mods section of Files & Config for a game with no LinuxGSM mods: it says so, instead of
  "Loading mods…" for good under its own tab.
* the console's command history: keyed by the account and the server's own row, dropped on any page
  drawn signed out, and a "fills the box" quick command ends Up/Down browsing.

HOW IT RUNS. Scripts in node on this part's own fixtures (part87's DOM stand-in, part99's runner);
pages on part12's Flask app and client (part12 has run), every stub through _p9_patch and undone in
the finally.
"""
import json as _json157
import re as _re157

from unit.part01 import check
from unit.part12 import P9_ADMIN, P9_GS, P9_VIEWER, _p9_arm, _p9_client, _p9_patch, _p9_restore_all
from unit.part99 import _SF99, _cut_or99, _js99, _line_or99, _read99
from panel.ops.ssh_manager import _core as _smc157
from panel.routes import server_detail as _sd157


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
    "store['sd.cmdHistory.7'] = JSON.stringify(['rcon_password old']); store['sd.consoleTs'] = '0';\n"
    + "".join(_line_or99(_SD157, h) + "\n" for h in (
        "var _CMPA_HIST_MAX", "var _cmpaHistMem", "var _cmpaBrowse", "var _cmpaHistIdx", "var _cmpaDraft",
        "try { localStorage.removeItem('sd.cmdHistory.' + serverId)"))), (
    "function _cmpaHistStoreKey(", "function _cmpaHistLoad(", "function _cmpaHistPush("), (
    "  const out = {legacy: store['sd.cmdHistory.7'] === undefined, ts: store['sd.consoleTs']};\n"
    "  _cmpaHistPush('rcon_password secret');\n"
    "  out.mine = _cmpaHistLoad(); out.keys = Object.keys(store).sort();\n"
    "  _CMPA_HIST_SCOPE = '4.7.100'; out.other = _cmpaHistLoad();\n"
    "  _CMPA_HIST_SCOPE = '3.7.200'; out.reborn = _cmpaHistLoad();\n"
    "  _CMPA_HIST_SCOPE = undefined; const before = Object.keys(store).length;\n"
    "  _cmpaHistPush('say hi'); out.unscoped = [_cmpaHistLoad(), Object.keys(store).length - before];\n"
    "  console.log(JSON.stringify(out));\n"), _SD157)
if _out157 is not None:
    check("console history: another account, or a re-created server with the same id, does not get "
          "this account's commands; the old server-id-only key is removed when the page loads",
          _out157.get("mine") == ["rcon_password secret"] and _out157.get("other") == []
          and _out157.get("reborn") == [] and _out157.get("legacy") is True
          and _out157.get("keys") == ["sd.cmdHistory.3.7.100", "sd.consoleTs"], repr(_out157))
    check("console history: ...and with no scope on the page it stays in the page, never under a key "
          "every account would share",
          _out157.get("unscoped") == [["rcon_password secret", "say hi"], 0], repr(_out157))

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
