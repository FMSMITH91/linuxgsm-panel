"""Part 66 of the unit suite: the fifth 2026-10-11 review's routes, tools, page and i18n fixes (builder C).

Held here, each against the code path the finding named:

* the console: output the panel pushes after Clear survives the next poll's re-prime, and what
  Clear took off the page stays off.
* routes, tools, pages and catalogs, each shown to catch the shape it missed.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on this part's own fixtures.
"""
import ast as _ast66
import html as _html66
import importlib.util as _ilu66
import json as _json66
import os
import re as _re66
import shutil as _shutil66
import tempfile as _tf66

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _cut47, _node47

_JS66 = os.path.join(_root, "static", "js")
_TPL66 = os.path.join(_root, "templates")


def _read66(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _node66(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. the console: Clear, then panel output, then the 30 s re-prime
# ════════════════════════════════════════════════════════════════════════════════════════════════
# refreshConsole, clearConsole and the backlog helpers, cut from the real file, against a page of
# stand-ins: `shown` is what the console holds, in order.
_SD66 = _read66(_JS66, "server_detail.js")
_CON66 = (
    "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = ''; global.serverId = 1; global.toast = () => 0;\n"
    "var shown = [], _consoleLines = [], _consolePrimed = false, _consoleSig = null, _lastPanelT = 0;\n"
    "var _returnOwed = false, _panelBacklogShown = false, _r13c_panelPushes = [], _R13C_PANEL_KEEP = 200;\n"
    "var _r15c_clearedAt = null;\n"
    "var consoleEl = {set innerHTML(v){ shown.length = 0; }};\n"
    "var socket = {connected: true};\n"
    "function _rebuildMark(){ return 0; } function _primeAt(){} function updateTsNotice(){}\n"
    "function _showTsOffNote(){} function stickConsole(){} function consoleAtBottom(){ return true; }\n"
    "function _notePanelMarker(){} function _newConsoleRows(){ return []; }\n"
    "function _appendConsoleRows(rows){ (rows || []).forEach(r => shown.push(r.line)); }\n"
    "function appendConsole(text){ shown.push(text); }\n"
    "function _panelShownAt(t){ if (Number(t) > _lastPanelT) _lastPanelT = Number(t); }\n"
    "function _renderPanelLines(rows){ rows.forEach(r => { shown.push(r.line); _panelShownAt(r.t); }); }\n"
    + "".join(_cut47(_SD66, h) + "\n" for h in (
        "function _r13c_notePanelPush(", "function _r13c_reshowPanelPushes(", "function refreshConsole(",
        "function showPanelBacklog(", "function _newerPanelRows(", "function _panelLinesWiped(",
        "function _r13c_primeWipesPushes(", "function clearConsole("))
    + "var backlog = [], logN = 0;\n"
    "global.fetch = () => { logN++; return Promise.resolve({ok: true, json: () => Promise.resolve(\n"
    "  {lines: [{line: 'log' + logN}], panel_lines: backlog.slice(), at: null})}); };\n"
    "function push(ts, data){ const d = {panel: true, ts: ts, data: data}; appendConsole(d.data);\n"
    "  _panelShownAt(d.ts); _r13c_notePanelPush(d); }\n")
_name66 = "console: Clear, then panel output, then the re-prime"
_out66 = _node66(_name66, _CON66 + (
    "(async () => { const out = {};\n"
    # the finding: a backlog shown at load, Clear, then an update's lines, then the 30 s poll
    "  backlog = [{t: 100, line: '[panel] old'}]; refreshConsole(true); await settle();\n"
    "  clearConsole(); push(110, '[panel] u1'); push(115, '[panel] u2');\n"
    "  backlog.push({t: 110, line: '[panel] u1'});\n"     # u2 pushed after the server read its backlog
    "  refreshConsole(false); await settle(); out.after = shown.slice();\n"
    "  push(120, '[panel] u3'); backlog.push({t: 115, line: '[panel] u2'}, {t: 120, line: '[panel] u3'});\n"
    "  refreshConsole(false); await settle(); out.later = shown.slice();\n"
    # #422's case: an empty backlog at load, an update's lines pushed, then Clear
    "  shown.length = 0; _consolePrimed = false; _consoleSig = null; _lastPanelT = 0; logN = 0;\n"
    "  _panelBacklogShown = false; _r13c_panelPushes = []; _r15c_clearedAt = null; backlog = [];\n"
    "  refreshConsole(true); await settle(); push(200, '[panel] a'); push(205, '[panel] b');\n"
    "  backlog = [{t: 200, line: '[panel] a'}, {t: 205, line: '[panel] b'}];\n"
    "  clearConsole(); refreshConsole(false); await settle(); out.cleared = shown.slice();\n"
    # the same with a backlog that lacks them (the server keeps a bounded one): the kept pushes
    "  shown.length = 0; _consolePrimed = false; _consoleSig = null; _lastPanelT = 0; logN = 0;\n"
    "  _panelBacklogShown = false; _r13c_panelPushes = []; _r15c_clearedAt = null; backlog = [];\n"
    "  refreshConsole(true); await settle(); push(200, '[panel] a'); push(205, '[panel] b');\n"
    "  clearConsole(); refreshConsole(false); await settle(); out.unkept = shown.slice();\n"
    # Clear pressed before the first window came back: the backlog was never on the page
    "  shown.length = 0; _consolePrimed = false; _consoleSig = null; _lastPanelT = 0; logN = 0;\n"
    "  _panelBacklogShown = false; _r13c_panelPushes = []; _r15c_clearedAt = null;\n"
    "  backlog = [{t: 300, line: '[panel] before reload'}];\n"
    "  clearConsole(); refreshConsole(true); await settle(); out.early = shown.slice();\n"
    "  console.log(JSON.stringify(out)); })();\n"))
if _out66 is not None:
    check("console: panel output pushed after Clear is still there after the next poll's re-prime (the "
          "re-prime wiped it and nothing put it back: an update's output vanished 30 s after Clear)",
          _out66.get("after") == ["log2", "[panel] u1", "[panel] u2"], repr(_out66))
    check("console: ...and the poll after that adds only the new line, none twice",
          _out66.get("later") == ["log2", "[panel] u1", "[panel] u2", "[panel] u3"], repr(_out66))
    check("console: ...while the panel lines Clear took off the page stay off (#422: an update's output "
          "came back on the next poll after Clear)", _out66.get("cleared") == ["log2"], repr(_out66))
    check("console: ...even when the backlog the re-prime reads lacks them (the kept pushes are cut at Clear "
          "too)", _out66.get("unkept") == ["log2"], repr(_out66))
    check("console: ...and Clear pressed before the first window came back does not hide a backlog that "
          "was never on the page", _out66.get("early") == ["log1", "[panel] before reload"], repr(_out66))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. translations the gate could not see
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Loaded from its file: the runner fails any part that leaves sys.path changed.
_i18n_spec66 = _ilu66.spec_from_file_location("i18n_scan_p66", os.path.join(_root, "tools", "i18n_scan.py"))
_i18n66 = _ilu66.module_from_spec(_i18n_spec66)
_i18n_spec66.loader.exec_module(_i18n66)
_ES66, _FR66 = _i18n66.load_catalog("es"), _i18n66.load_catalog("fr")

_td66 = os.path.realpath(_tf66.mkdtemp(prefix="lgsm-unit-p66-i18n-"))
try:
    _js66 = os.path.join(_td66, "js")
    _tr66 = os.path.join(_td66, "translations")
    _tpl66 = os.path.join(_td66, "templates")
    for _d66 in (_js66, os.path.join(_tr66, "es"), _tpl66):
        os.makedirs(_d66)
    with open(os.path.join(_tr66, "es", "x.json"), "w", encoding="utf-8") as _fh66:
        _fh66.write("{}")
    _long66 = "Upload one file of {size} into the folder {dir} and replace anything there by the same name " * 2
    with open(os.path.join(_js66, "a.js"), "w", encoding="utf-8") as _fh66:
        _fh66.write(
            "toast(tfn(n, 'Upload 1 file ({size}) into {dir}?', 'Upload {n} files ({size}) into {dir}?', {size: s}));\n"
            "toast(tf(stop ? 'Stop \"{name}\"?' : 'Restart \"{name}\"?', {name: n}));\n"
            "toast(tf('Widget {n} ready', {n: base || 'nothing here'}));\n"
            "toast(tfn(n, '" + _long66.strip() + "', 'Upload {n} widgets into {dir} now', {dir: d}));\n"
            "el.innerHTML = '<span>Widget tool is installed and running on</span> <strong data-no-i18n>' + safe + '</strong>.';\n"
            "el.innerHTML = n + ' <span>banned</span>';\n"
            "el.textContent = n + /* the count */ ' widgets left to sort';\n"
            "el.textContent = `Saved ${n} widgets to the shelf`;\n"
            "el.textContent = n /* a+b */ ;\n")
    _miss66 = _i18n66.missing_js("es", js_dir=_js66, translation_dir=_tr66)
    _spl66 = _i18n66.spliced_js(js_dir=_js66)
    with open(os.path.join(_tpl66, "t.html"), "w", encoding="utf-8") as _fh66:
        _fh66.write(
            "<p><span>{% if a %}Super Widget{% else %}Plain{% endif %} · Account</span></p>\n"
            "<div>No widget list yet.\n{% if b %}{% if c %}Press refresh.{% endif %}{% else %}Install first.{% endif %}</div>\n"
            "<div>{% if d %}<b>Alone</b>{% endif %}</div><p>{% if e %}Own node{% else %}Other node{% endif %}</p>\n"
            "<select><option>{% if f %}Pick one (n/a){% else %}Pick one{% endif %}</option></select>\n")
    _tpl_found66, _tpl_dyn66 = _i18n66.scan_template(os.path.join(_tpl66, "t.html"))
finally:
    _shutil66.rmtree(_td66, ignore_errors=True)
check("i18n scan: a tfn plural and the second branch of a ternary template are asked for (a {placeholder} "
      "in the template before them read as tf's values object, so neither was claimed)",
      {"Upload {n} files ({size}) into {dir}?", 'Restart "{name}"?'} <= set(_miss66), repr(sorted(_miss66)))
check("i18n scan: ...a VALUE of tf() is still not (control)", "nothing here" not in _miss66, repr(sorted(_miss66)))
check("i18n scan: ...nor is a plural lost behind a singular longer than the old 160-character lookback",
      "Upload {n} widgets into {dir} now" in _miss66, repr(sorted(_miss66)))
check("i18n scan: prose in a bare <span> right before a spliced value is reported as split (the join's own "
      "text node was the blank after </span>, so the Tailscale sentences passed)",
      "Widget tool is installed and running on" in [x[2] for x in _spl66], repr(_spl66))
check("i18n scan: a splice whose `+` has a /* */ comment beside it is reported (only // was read at a "
      "run's edges), and so is the prose around a ${} in a backtick literal (invisible to every check)",
      sorted(x[2] for x in _spl66) == sorted(["Widget tool is installed and running on", "widgets left to sort",
                                              "Saved", "widgets to the shelf"]), repr(_spl66))
check("i18n scan: an {% if %} welded to the text around it is looked up as the node each branch renders "
      "(read as a split, both halves were in the catalog and the whole node never was)",
      {"Super Widget · Account", "Plain · Account", "No widget list yet. Press refresh.", "No widget list yet. Install first.",
       "No widget list yet."} <= set(_tpl_found66) and "Super Widget" not in _tpl_found66, repr(sorted(_tpl_found66)))
check("i18n scan: ...a branch that is a node of its own is still asked for alone, and an option's two "
      "whole texts each",
      {"Alone", "Own node", "Other node", "Pick one (n/a)", "Pick one"} <= set(_tpl_found66),
      repr(sorted(_tpl_found66)))

# ── the panel chips of one page are told apart in every language ────────────────────────────────
# A page's hidden-panel chips are labelled from its {% set …_LABELS %} table: two labels that
# translate to the same words make two identical chips (fr "Controls" and "Commands" were both
# "Commandes" on the server page).
_dup66 = []
for _f66 in sorted(os.listdir(_TPL66)):
    for _m66 in _re66.finditer(r"\{%\s*set\s+([A-Z_]*LABELS)\s*=\s*(\{.*?\})\s*%\}",
                               _read66(_TPL66, _f66), _re66.S):
        _vals66 = list(_ast66.literal_eval(_m66.group(2)).values())
        for _L66, _cat66 in (("es", _ES66), ("fr", _FR66)):
            _tr66v = [_cat66.get(_v66, _v66) for _v66 in _vals66]
            if len(set(_tr66v)) != len(_tr66v):
                _dup66.append((_f66, _m66.group(1), _L66, _tr66v))
check("i18n: the labels of a page's panel table translate to different words in es and fr (two panels' "
      "chips both read \"Commandes\" in French)", not _dup66, repr(_dup66))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. pages, run in Spanish
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _es66(*keys):
    """i18n.js in node with only `keys` of the Spanish catalog (the whole one is past `node -e`'s limit)."""
    return ("global.window = global;\nglobal.document = {readyState: 'complete', body: null};\n"
            "window.I18N = " + _json66.dumps({_k: _ES66[_k] for _k in keys}) + ";\nwindow.LANG = 'es';\n"
            + _read66(_JS66, "i18n.js") + "\n"
            "window.escapeHtml = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');\n")


# ── the Restart/Stop confirm is one sentence ───────────────────────────────────────────────────
_SA66 = _read66(_JS66, "server_actions.js")
_name66 = "server page: the Restart confirm in Spanish"
_out66 = _node66(_name66, _es66("{action} {name}?", "Restart") + (
    "var SERVER_NAME = 'Mi<Srv>', got;\nfunction _esc(s){ return escapeHtml(s); }\n"
    "function confirmDialog(o){ got = o.body; }\nfunction _doServerAction(){}\n"
    + _cut47(_SA66, "function _cap(") + "\n" + _cut47(_SA66, "function confirmActionDialog(") + "\n"
    "confirmActionDialog('restart', null, 'Nobody is online.');\nconsole.log(JSON.stringify(got));\n"))
if _out66 is not None:
    check("server page: the Restart confirm (nobody online) is one translated question with the name in it "
          "(verb, bold name and \"?\" were pieces: Spanish lost its opening \"¿\")",
          _out66 == '¿Reiniciar <strong data-no-i18n>Mi&lt;Srv&gt;</strong>? '
                    '<span class="text-secondary">Nobody is online.</span>', repr(_out66))

_PJ66 = _read66(_JS66, "palette.js")
_name66 = "palette: the Stop confirm in Spanish"
_ab66 = _cut47(_PJ66, "function _actionBody(")
_out66 = _node66(_name66, _es66("{action} {name}?", "Stop") + (
    "function el(tag){ return {tag: tag, kids: [], innerHTML: '', textContent: '',\n"
    "  appendChild(c){ this.kids.push(c); }}; }\n"
    "global.document.createElement = el; global.document.createTextNode = s => ({text: s});\n"
    "var ACTION_LABEL = { start: 'Start', restart: 'Restart', stop: 'Stop' };\n"
    "function _tr(s) { return window.t ? window.t(s) : s; }\n" + _ab66 + "\n"
    "var w = _actionBody('stop', 'A&B');\n"
    "console.log(JSON.stringify(w.kids.map(k => k.innerHTML || k.textContent || k.text)));\n"))
if _out66 is not None:
    check("palette: the Stop/Restart confirm is one translated question, the name escaped inside it (built "
          "as verb, name and \"?\" nodes, Spanish read \"Detener X?\")",
          _out66 == ["¿Detener <strong data-no-i18n>A&amp;B</strong>?", " ", "Anyone playing will be disconnected."],
          repr(_out66))

# ── "just now" inside a translated sentence ─────────────────────────────────────────────────────
_name66 = "just now in a sentence"
_out66 = _node66(_name66, _es66("just now", "Last checked {when}", "active {when}") + (
    _cut47(_read66(_JS66, "panel.js"), "window.agoText = function(") + "\n"
    + _cut47(_read66(_JS66, "account_sessions.js"), "function rel(") + "\n"
    "console.log(JSON.stringify([tf('Last checked {when}', {when: agoText(Date.now()/1000 - 5)}),\n"
    "  tf('active {when}', {when: rel(new Date().toISOString())})]));\n"))
if _out66 is not None:
    check("i18n: a check under a minute old reads \"just now\" in Spanish inside its sentence, on the OS "
          "Updates card and the Account page (it went in as a tf value, which is never translated)",
          _out66 == [_ES66["Last checked {when}"].replace("{when}", _ES66["just now"]),
                     _ES66["active {when}"].replace("{when}", _ES66["just now"])], repr(_out66))


# ── the panel's own messages, rendered as whole text nodes ──────────────────────────────────────
# A route's flash (base.html's flash container) or its JSON `message` (a toast) reaches the page as
# one text node, so the walker translates it if the catalog has it; 64 of 69 literal ones were in
# neither catalog, so saving /settings flashed "Settings saved." in English to a Spanish viewer.
# The same for the invite form's errors (invite.html), the username/password/group-name rules
# every account form answers with, and the Discord gateway's refusal line on /notifications.
# ── a page's tab title is translated too ────────────────────────────────────────────────────────
_td66 = os.path.realpath(_tf66.mkdtemp(prefix="lgsm-unit-p66-title-"))
try:
    with open(os.path.join(_td66, "a.html"), "w", encoding="utf-8") as _fh66:
        _fh66.write("{% block title %}Widget Admin{% endblock %}\n<p>x</p>")
    with open(os.path.join(_td66, "b.html"), "w", encoding="utf-8") as _fh66:
        _fh66.write("{% block title %}{{ t('%s — Widget')|format(w.name) }}{% endblock %}\n<p>x</p>")
    _ta66, _tad66 = _i18n66.scan_template(os.path.join(_td66, "a.html"))
    _tb66, _tbd66 = _i18n66.scan_template(os.path.join(_td66, "b.html"))
finally:
    _shutil66.rmtree(_td66, ignore_errors=True)
check("i18n scan: literal words in a page's title block are reported (the block was dropped as untranslatable, "
      "and every tab title stayed English), a t() call there is asked for",
      _tad66.get("Widget Admin") == {"title"} and "%s — Widget" in _tb66 and not _tbd66, repr((_tad66, _tb66, _tbd66)))

# ── the backup schedule note is markup, built escaped ───────────────────────────────────────────
_name66 = "backups: the schedule note escapes its values"
_out66 = _node66(_name66, _es66("Custom — {every}, keep {n}.", "Custom — no automatic backups.") + (
    _cut47(_read66(_JS66, "remote_manage_backups.js"), "function schedNote(") + "\n"
    "console.log(JSON.stringify([schedNote({interval_days: 9, keep: '<b>x</b>', keep_set: true}),\n"
    "  schedNote({interval_days: 0, keep: 1, keep_set: true})]));\n"))
if _out66 is not None:
    check("backups: the schedule note every caller writes with innerHTML escapes its values (it was tf(): "
          "safe only while every value stayed a number or a catalog string)",
          isinstance(_out66, list) and "&lt;b&gt;x&lt;/b&gt;" in _out66[0] and "<b>" not in _out66[0]
          and _out66[1] == _ES66["Custom — no automatic backups."], repr(_out66))

# ── the dashboard's hide chip carries the English label ─────────────────────────────────────────
_name66 = "dashboard: the hide chip's label"
_out66 = _node66(_name66, (
    "global.window = global; var chips = [];\n"
    "function el(tag){ return {tag: tag, attrs: {}, kids: [], setAttribute(k, v){ this.attrs[k] = v; },\n"
    "  appendChild(c){ this.kids.push(c); chips.push(c); } }; }\n"
    "var bar = el('div');\n"
    "global.document = {createElement: el, getElementById: () => bar};\n"
    "function saveHostOrder(){}\n"
    "var region = {id: 'dash-tiles', getAttribute: () => 'dash_tiles', parentNode: {insertBefore(){}}};\n"
    "var panel = {getAttribute: k => ({'data-panel': 'online', 'data-label': 'Online'})[k] || null,\n"
    "  querySelector: () => ({textContent: 'En línea'}), closest: () => region, remove(){}};\n"
    + _cut47(_read66(_JS66, "dashboard.js"), "window.hidePanel = function(") + "\n"
    "hidePanel({closest: () => panel});\nconsole.log(JSON.stringify(chips.map(c => c.textContent)));\n"))
check("dashboard: a hidden tile's restore chip is labelled from the tile's English label, so the walker "
      "translates it and a live language switch follows (it copied the tile's already-translated text)",
      _out66 == ["Online"] or _out66 is None, repr(_out66))
check("dashboard: ...every tile carries that label", 'data-panel="{{ key }}" data-label="{{ TILE_LABELS[key] }}"'
      in _read66(_TPL66, "dashboard.html"), "no data-label on the tile")

# ── install.sh: an update honours PANEL_NO_REBOOT ───────────────────────────────────────────────
# The update path's reboot spot, cut from install.sh and run in bash with every power command a
# stand-in (a function AND a refusing script first on PATH, as reboot41 does).
import subprocess as _sp66  # nosec B404 - runs this repository's own install.sh block on stand-ins  # noqa: E402
_ins66 = _read66(_root, "install.sh")
_i66 = _ins66.index('                if [[ ! -f /var/run/reboot-required ]]; then\n'
                    '                    ok "System updated')
_upd66 = _ins66[_i66:_ins66.index("\n                fi\n", _i66) + len("\n                fi\n")]
_td66 = os.path.realpath(_tf66.mkdtemp(prefix="lgsm-unit-p66-reboot-"))
_nr66 = {}
try:
    _bin66 = os.path.join(_td66, "bin")
    os.makedirs(_bin66)
    for _cmd66 in ("reboot", "sudo", "shutdown", "systemctl", "loginctl"):
        with open(os.path.join(_bin66, _cmd66), "w", encoding="utf-8") as _fh66:
            _fh66.write("#!/bin/sh\necho REFUSED %s\nexit 1\n" % _cmd66)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in tool this part runs
        os.chmod(os.path.join(_bin66, _cmd66), 0o700)  # nosec B103 - a stand-in tool in this part's own temp dir
    _marker66 = os.path.join(_td66, "reboot-required")
    open(_marker66, "w").close()
    _prog66 = ("ok(){ echo \"OK $*\"; }\nwarn(){ echo \"WARN $*\"; }\n"
               "game_sessions_running(){ return 1; }\nsleep(){ :; }\nreboot(){ echo REBOOTING; }\n"
               "UPG_SUDO=\n" + _upd66.replace("/var/run/reboot-required", _marker66))
    _power66 = sorted(set(_re66.findall(r"\b(?:shutdown|systemctl|loginctl|/sbin/\w+|/usr/sbin/\w+)\b", _upd66)))
    if not _power66 and "${UPG_SUDO} reboot" in _upd66:
        for _k66, _v66 in (("unset", None), ("set", "1")):
            _env66 = dict(os.environ, PATH=_bin66 + os.pathsep + os.environ.get("PATH", ""))
            _env66.pop("PANEL_NO_REBOOT", None)
            if _v66:
                _env66["PANEL_NO_REBOOT"] = _v66
            _nr66[_k66] = _sp66.run(["bash", "-c", _prog66], env=_env66, capture_output=True, text=True,  # nosec B603 B607
                                    timeout=30, check=False).stdout
finally:
    _shutil66.rmtree(_td66, ignore_errors=True)
check("install.sh: an update whose OS upgrade needs a reboot does not reboot with PANEL_NO_REBOOT=1, and "
      "says so (only PANEL_NO_UPGRADE stopped it, while a first install honoured both); unset, it still "
      "reboots (control)",
      "REBOOTING" not in _nr66.get("set", "REBOOTING") and "PANEL_NO_REBOOT=1" in _nr66.get("set", "")
      and "REBOOTING" in _nr66.get("unset", ""), repr((_power66, _nr66)))

# ROUTES-START: below here needs the app (part12 has imported it).
from panel.core import validation as _val66  # noqa: E402
from panel.services.bots import discord as _dc66  # noqa: E402


def _py_files66():
    """app.py and every .py under panel/."""
    paths = [os.path.join(_root, "app.py")]
    for _dir, _sub, _files in os.walk(os.path.join(_root, "panel")):
        paths += [os.path.join(_dir, _f) for _f in _files if _f.endswith(".py")]
    return sorted(paths)


def _literal66(node):
    """A str constant's value, else None."""
    return node.value if isinstance(node, _ast66.Constant) and isinstance(node.value, str) else None


def _flashed66(tree):
    """(message, line) for each literal first argument of flash / _form_err / _form_ok."""
    for _n in _ast66.walk(tree):
        if isinstance(_n, _ast66.Call) and _n.args \
                and (getattr(_n.func, "id", None) or getattr(_n.func, "attr", None)) in (
                    "flash", "_form_err", "_form_ok") and _literal66(_n.args[0]) is not None:
            yield _n.args[0].value, _n.lineno


def _invite_errors66(tree):
    """The literal refusals _invite_form returns as its tuple's last item."""
    for _f in (n for n in _ast66.walk(tree) if isinstance(n, _ast66.FunctionDef) and n.name == "_invite_form"):
        for _r in _ast66.walk(_f):
            if isinstance(_r, _ast66.Return) and isinstance(_r.value, _ast66.Tuple) \
                    and _literal66(_r.value.elts[-1]) is not None:
                yield _r.value.elts[-1].value


def _route_messages66():
    """{message: where} for every literal message a route flashes or answers a form with."""
    out = {}
    for _p in _py_files66():
        _tree = _ast66.parse(_read66(_p))
        for _m, _line in _flashed66(_tree):
            out.setdefault(_m, "%s:%d" % (os.path.relpath(_p, _root), _line))
        for _m in _invite_errors66(_tree):
            out.setdefault(_m, "_invite_form")
    return out


_msgs66 = _route_messages66()
for _bad66 in ("", "a b c", "a\tb c", "x" * 200, "ab\u200bcd"):
    _msgs66.setdefault(_val66.username_problem(_bad66), "username_problem")
    _msgs66.setdefault(_val66.group_name_problem(_bad66), "group_name_problem")
for _bad66 in ("", "aaaaaaaaaaaa", "AAAAAAAAAAAA", "aaaaaaAAAAAA", "aaaaaAAAAA11"):
    _msgs66.setdefault(_val66.password_problem(_bad66), "password_problem")
for _v66 in _dc66._DC_FATAL_CLOSE.values():
    _msgs66.setdefault(_v66, "discord _DC_FATAL_CLOSE")
_msgs66.pop(None, None)
_mmiss66 = sorted((_L66, _k66) for _L66, _cat66 in (("es", _ES66), ("fr", _FR66))
                  for _k66 in _msgs66 if _k66 not in _cat66)
check("i18n: every literal message a route flashes or answers a form with, the account-form rules, the "
      "invite form's errors and the Discord gateway's refusal lines are in both catalogs (64 of 69 were "
      "in neither: a Spanish viewer read \"Settings saved.\")",
      len(_msgs66) >= 80 and not _mmiss66, repr((len(_msgs66), _mmiss66[:6])))


# ── ...and rendered: the tab reads in the viewer's language ─────────────────────────────────────
from unit.part12 import P9_ADMIN, _p9, _p9_client  # noqa: E402
from panel.db.models import User as _User66, db as _db66  # noqa: E402


def _lang66(lang):
    """The admin's saved language (the account's choice wins over the session's)."""
    with _p9.app_context():
        _db66.session.get(_User66, P9_ADMIN).language = lang
        _db66.session.commit()


_titles66 = {}
try:
    for _L66 in ("es", "fr"):
        _lang66(_L66)
        for _u66 in ("/", "/logs"):
            _h66 = _p9_client(P9_ADMIN).get(_u66).get_data(as_text=True)
            _m66 = _re66.search(r"<title>(.*?)</title>", _h66, _re66.S)
            _titles66[(_L66, _u66)] = _html66.unescape(_m66.group(1).strip()) if _m66 else None
finally:
    _lang66("en")
_want66 = {(_L66, _u66): _cat66[_k66] for _L66, _cat66 in (("es", _ES66), ("fr", _FR66))
           for _u66, _k66 in (("/", "Dashboard"), ("/logs", "Audit Logs"))}
check("i18n: a page's tab title is in the viewer's language (\"<site> - Dashboard\" and \"- Audit Logs\" "
      "read in English on every page)",
      all(_t66 and _t66.endswith(" - " + _want66[_k66]) for _k66, _t66 in _titles66.items()),
      repr((_titles66, _want66)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Close public panel port and the panel-port rule test
# ════════════════════════════════════════════════════════════════════════════════════════════════
from unit.part12 import _P9_CFG_PATH, _p9_cfg, _p9_json  # noqa: E402
from unit.part20 import _patch, _patched  # noqa: E402
from unit.part61 import _close61, _fwm61, _panel_open61, _rv61  # noqa: E402
from unit.part12 import P9_LOCAL  # noqa: E402

_CFG66_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None
_LO66 = ".".join(["127", "0", "0", "1"])
# Both directions: what must count as holding the panel's (TCP) port open, and what must not.
_ROWS66 = {
    "5000/tcp ALLOW IN Anywhere": "only",
    "5000 ALLOW IN Anywhere": "only",                       # both protocols: TCP among them
    "5000:5010/tcp ALLOW IN Anywhere": "shared",
    "5000/udp ALLOW IN Anywhere": "",                       # a game's UDP port that shares the number
    "5000:5010/udp ALLOW IN Anywhere": "",                  # a game's UDP range
    "5000/tcp ALLOW IN %s" % _LO66: "",                     # only this machine can match it
    "%s 5000/tcp ALLOW IN Anywhere" % _LO66: "",            # to a loopback address
    "5000/tcp on lo ALLOW IN Anywhere": "",
    "5000/tcp on docker0 ALLOW IN Anywhere": "",
    "5000/udp DENY IN Anywhere": "",
    "5000/tcp DENY IN Anywhere": "",
    "5000/tcp ALLOW OUT Anywhere": "",
}
try:
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), port=5000, tailscale_setup_done=True,
                             tailscale_use_funnel=False))
    _scope66, _route66, _card66, _page66 = {}, {}, {}, {}
    for _row66 in _ROWS66:
        _g66 = _fwm61._group_ufw_rules([{"num": "1", "detail": _row66}])[0]
        _scope66[_row66] = _fwm61._r14a_panel_port_scope(_g66, 5000)
        _page66[_row66] = _fwm61._is_panel_rule(_g66, 5000)
        _body66, _del66 = _close61(_row66)
        _msg66 = _body66.get("message", "")
        _route66[_row66] = ("closed" if _del66 and _body66.get("success") else
                            "refused" if "opens other ports too" in _msg66 and not _del66 else
                            "already" if "already closed" in _msg66 else repr((_body66, _del66)))
        _card66[_row66] = _panel_open61(" ".join(_row66.replace(" IN ", " ").split()))
    check("panel port: a UDP-only rule naming the panel's port number, or one only this machine can match "
          "(loopback source or address, lo, docker0), does not hold the panel's TCP port open; TCP and "
          "both-protocol rules still do (both directions)", _scope66 == _ROWS66,
          repr({k: v for k, v in _scope66.items() if v != _ROWS66[k]}))
    _wroute66 = {k: {"only": "closed", "shared": "refused", "": "already"}[v] for k, v in _ROWS66.items()}
    check("close panel port: a game's 5000:5010/udp is not refused as sharing the panel port, and 5000/udp "
          "is not force-deleted as the panel's rule", _route66 == _wroute66,
          repr({k: v for k, v in _route66.items() if v != _wroute66[k]}))
    check("panel port: ...the Network card agrees, row by row",
          {k: v is True for k, v in _card66.items()} == {k: bool(v) for k, v in _ROWS66.items()},
          repr(_card66))
    check("panel port: ...and the Firewall page protects only the rules that hold it open",
          _page66 == {k: bool(v) for k, v in _ROWS66.items()}, repr(_page66))

    def _ufw66(enabled, groups=(), default_allow=False):
        """The close route's answer and the rules it deleted, against a firewall holding `groups`."""
        _deleted, _held = [], list(groups)

        def _delete(*a, **k):
            _deleted.append(a)
            _held.clear()                 # the one rule is gone: the verify read finds none
            return True, ""
        with _patched():
            _patch(_rv61, "remote_ufw_status", lambda remote: {"installed": True, "enabled": enabled,
                                                               "rules": [], "groups": list(_held)})
            _patch(_fwm61, "remote_ufw_default_allows_in", lambda remote: default_allow)
            _patch(_rv61, "remote_ufw_delete_rule", _delete)
            _resp = _p9_client(P9_ADMIN).post("/api/remote/%d/close-panel-port" % P9_LOCAL)
        return _p9_json(_resp), _deleted
    _off66, _offdel66 = _ufw66(False)
    _on66, _ = _ufw66(True)
    check("close panel port: with UFW installed but not active it refuses, saying nothing keeps the port "
          "closed (it answered 'Public port 5000 is already closed.' with the port open to the internet)",
          _off66.get("success") is False and "UFW is not active" in _off66.get("message", "")
          and not _offdel66, repr(_off66))
    check("close panel port: ...an active UFW with no rule for the port is still 'already closed' (control)",
          _on66 == {"success": True, "message": "Public port 5000 is already closed."}, repr(_on66))
    _rule66 = _fwm61._group_ufw_rules([{"num": "1", "detail": "5000/tcp ALLOW IN Anywhere"}])
    _da66 = [_ufw66(True, _rule66, True), _ufw66(True, (), True)]
    check("close panel port: with UFW's default incoming policy allow it refuses and deletes nothing, rule "
          "or no rule (it deleted the rule and said 'reachable only over your tailnet', or said 'already "
          "closed', with every port still open)",
          all(_b.get("success") is False and "default policy" in _b.get("message", "") and not _d
              for _b, _d in _da66), repr(_da66))
    _okdel66 = _ufw66(True, _rule66, False)
    check("close panel port: ...a default deny with the panel port's rule still closes it (control)",
          _okdel66[0].get("success") is True and len(_okdel66[1]) == 1, repr(_okdel66))

    # the reader: only a line saying allow answers True
    from unit.part01 import _sm_core as _core66  # noqa: E402
    _dai66 = {}
    for _k66, _ans66 in {
            "allow": ("Status: active\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n", "", 0),
            "deny": ("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n", "", 0),
            "reject": ("Status: active\nDefault: reject (incoming), allow (outgoing)\n", "", 0),
            "translated": ("État : actif\nPar défaut : allow (entrant)\n", "", 0),
            "failed": ("Default: allow (incoming)\n", "sudo: a password is required", 1),
            "raised": None}.items():
        with _patched():
            _patch(_core66, "run_privileged", (lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
                   if _ans66 is None else (lambda *a, _r=_ans66, **k: _r))
            _dai66[_k66] = _fwm61.remote_ufw_default_allows_in(object())
    check("firewall: the default-policy reader answers True only for a read that says allow (incoming); "
          "deny, reject, a translated ufw, a failed read and a raise are all False",
          _dai66 == {"allow": True, "deny": False, "reject": False, "translated": False, "failed": False,
                     "raised": False}, repr(_dai66))
finally:
    if _CFG66_SNAPSHOT is None:
        if _P9_CFG_PATH.exists():
            _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFG66_SNAPSHOT)

# ── Close port 22 on a firewall that is off ─────────────────────────────────────────────────────
from unit.part11 import _H as _H66, _p8_srv as _p8_srv66, _wire as _wire66  # noqa: E402
_c22 = {}
_core22 = {n: getattr(_core66, n) for n in ("run_privileged", "run_command", "write_root_file")}
try:
    for _k66, _st66 in {"inactive": ("Status: inactive\n", "", 0), "unread": ("", "", 1),
                        "active": ("Status: active\n\nTo  Action  From\n--  ------  ----\n"
                                   "22/tcp  ALLOW  Anywhere\n", "", 0)}.items():
        _w66 = _wire66(verbs={"ufw-status": _st66, "ufw-delete-allow-port": ("", "", 0)})
        _c22[_k66] = (_H66.remote_ufw_close_port_22(_p8_srv66())[0],
                      [v for v, _a in _w66.verbs_called() if v == "ufw-delete-allow-port"])
finally:
    for _n66, _v66 in _core22.items():
        setattr(_core66, _n66, _v66)
check("close port 22: on a UFW that is not active, or not read, it refuses and deletes nothing (it said "
      "\"Port 22 rule removed from UFW\" with port 22 still open); an active one still closes it",
      _c22 == {"inactive": (False, []), "unread": (False, []), "active": (True, ["ufw-delete-allow-port"])},
      repr(_c22))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. a fraction sent into a whole-number field is refused, not truncated
# ════════════════════════════════════════════════════════════════════════════════════════════════
import app as _app66  # noqa: E402
from unit.part12 import P9_GS, P9_HOST, _p9_patch, _p9_restore_all  # noqa: E402
from panel.ops import backup as _bk66  # noqa: E402

_A66 = _p9_client(P9_ADMIN)
try:
    _calls66 = []
    _p9_patch(_bk66, "set_game_schedule", lambda *a, **k: (_calls66.append(("game", a, k)) or
                                                          {"interval_days": 1, "keep": 1}))
    _p9_patch(_bk66, "set_settings", lambda **k: (_calls66.append(("settings", k)) or {}))
    _p9_patch(_bk66, "set_full_settings", lambda **k: (_calls66.append(("full", k)) or {}))
    _frac66 = [_A66.post("/api/panel/backup/game/%d/schedule" % P9_GS, json={"keep": 2.5}).status_code,
               _A66.post("/api/panel/backup/game/%d/schedule" % P9_GS, json={"interval": 1.5}).status_code,
               _A66.post("/api/panel/backup/settings", json={"full_keep": 2.5}).status_code,
               _A66.post("/api/panel/backup/settings", json={"keep_days": 6.9}).status_code]
    check("backups: a fraction in a whole-number field is a 400 and nothing is stored ({\"keep\": 2.5} kept "
          "two archives, int() truncating a number nobody sent)", _frac66 == [400] * 4 and _calls66 == [],
          repr((_frac66, _calls66)))
    _whole66 = [_A66.post("/api/panel/backup/game/%d/schedule" % P9_GS, json={"keep": 3.0}).status_code,
                _A66.post("/api/panel/backup/settings", json={"full_keep": 3.0}).status_code]
    check("backups: ...a whole number sent as 3.0 still saves (control)", _whole66 == [200, 200]
          and _calls66[0][0] == "game" and _calls66[0][1][-1] == 3 and len(_calls66) == 3, repr((_whole66, _calls66)))

    _calls66.clear()
    _p9_patch(_app66, "update_config", lambda fn: _calls66.append(("update_config", fn)))
    for _mod66 in ("remote_security", "host_local"):
        _m66 = __import__("panel.routes." + _mod66, fromlist=["x"])
        _p9_patch(_m66, "_set_autoblock_host", lambda *a, **k: None)
        _p9_patch(_m66, "_run_autoblock_now", lambda *a, **k: None)
    _sec66 = ("/api/remote/%d/security/autoblock" % P9_HOST, "/api/panel/security/autoblock")
    _tc66 = [_A66.post(_u, json={"enabled": False, "threshold": 2.5}).status_code for _u in _sec66]
    check("auto-block: a fractional threshold is ignored on both hosts, as \"many\" is (2.5 set it to 2)",
          _calls66 == [] and _tc66 == [200, 200], repr((_tc66, _calls66)))
    _A66.post(_sec66[1], json={"enabled": False, "threshold": 7.0})
    check("auto-block: ...7.0 is still stored (control)", len(_calls66) == 1, repr(_calls66))
finally:
    _p9_restore_all()
