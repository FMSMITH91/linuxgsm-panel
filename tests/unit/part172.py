"""Part 172 of the unit suite: the console's timestamp gutter takes space only when a line has a time.

Held here:
* The gutter collapses (`ts-none` on #console-output) while no line on screen carries a stamp: the
  server-rendered page starts that way, a window of history leaves it so, and a trim, a Clear or a
  Load older that leaves no stamped line collapses it again.
* The first stamped line opens it, whichever path wrote it: a push, the panel's own backlog, a
  Load older that put stamped lines back.
* The Times switch stays the viewer's: switched off, `ts-hidden` hides the column whatever the
  collapse decides, and the "no times yet" notice behaves as before.
* panel.css: `ts-none` removes the placeholder and the indent exactly as `ts-hidden` does, and the
  narrow-screen gutter keeps the stamp, its placeholder and the hanging indent the same width.

HOW IT RUNS. The page's own functions cut out of server_detail.js and run in node against a small
DOM (part47's cutter and runner); the stylesheet read as text; the server page rendered through
part12's app with its transport tripwire armed and every host call stubbed. Nothing reaches a host
or data/.
"""
import os as _os172
import re as _re172

from unit.part01 import _root, check, skip
from unit.part12 import P9_ADMIN, P9_HOST, _p9_arm, _p9_client, _p9_delete_server, _p9_new_server, _p9_patch
from unit.part12 import _p9_restore_all
from unit.part47 import R37E_STUBS47, _cut47, _node47
from panel.ops.ssh_manager import _core as _smc172
from panel.routes import server_detail as _sd172


def _cgm_read(*parts):
    with open(_os172.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


_cgm_sd = _cgm_read("panel", "static", "js", "server_detail.js")
_cgm_css = _cgm_read("panel", "static", "css", "panel.css")

# ── 1. the page's console functions, in node ─────────────────────────────────────────────────────
_cgm_dom = r"""
class Txt { constructor(t){ this.data = String(t); } get textContent(){ return this.data; } }
class El {
  constructor(tag){ this.tag = tag; this.children = []; this.className = ''; this.dataset = {};
                    this.attrs = {}; this.hidden = false; this.title = ''; this._t = ''; this.style = {}; }
  get classList(){
    const el = this, has = c => el.className.split(/\s+/).indexOf(c) >= 0;
    return { contains: has,
      add(c){ if (!has(c)) el.className = (el.className + ' ' + c).trim(); },
      remove(c){ el.className = el.className.split(/\s+/).filter(x => x && x !== c).join(' '); },
      toggle(c, on){ if (on === undefined) on = !has(c); if (on) this.add(c); else this.remove(c); return on; } };
  }
  appendChild(c){ for (const x of (c.tag === '#frag' ? c.children.splice(0) : [c])) this.children.push(x); return c; }
  removeChild(c){ const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); return c; }
  get firstChild(){ return this.children[0] || null; }
  get childElementCount(){ return this.children.filter(c => c instanceof El).length; }
  set innerHTML(v){ this.children = []; }
  get innerHTML(){ return ''; }
  set textContent(v){ this.children = []; this._t = String(v); }
  get textContent(){ return this._t + this.children.map(c => c.textContent).join(''); }
  setAttribute(k, v){ this.attrs[k] = String(v); }
  querySelector(sel){
    if (sel !== '.console-line[data-ts]') throw new Error('unexpected selector ' + sel);
    return this.children.find(c => c instanceof El && c.classList.contains('console-line') && 'ts' in c.dataset) || null;
  }
}
global.window = global; global.MOUNT = ''; global.serverId = 1;
global.localStorage = { setItem(){}, getItem(){ return null; } };
// Without the template's ts-none, so the first check sees updateTsNotice set it.
var consoleEl = new El('div'); consoleEl.className = 'console-output';
var notice = new El('div'), toggleBtn = new El('button');
global.document = { createElement: t => new El(t), createDocumentFragment: () => new El('#frag'),
  getElementById: id => ({'console-output': consoleEl, 'console-ts-notice': notice,
                          'console-ts-toggle': toggleBtn})[id] || null };
var _tsOn = true, _consoleLines = [], _consolePrimed = false, _consoleSig = null, _lastPanelT = 0;
var _r15c_clearedAt = null, CONSOLE_MAX_LINES = 4;
function renderAnsi(el, line){ el.appendChild(new Txt(line)); }
function consoleAtBottom(){ return true; } function stickConsole(){}
function _panelShownAt(){} function _rebuildMark(){ return 0; } function _rebuildRestore(){}
function _r13c_reshowPanelPushes(){} function _r11c_resyncFrom(){}
function toast(){} function tf(s){ return s; }
var _fetchAnswer = null;
global.fetch = () => Promise.resolve({ok: true, json: () => Promise.resolve(_fetchAnswer)});
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };
const state = () => ({none: consoleEl.classList.contains('ts-none'),
                      hidden: consoleEl.classList.contains('ts-hidden'), notice: notice.hidden});
"""

_cgm_funcs = ("function stampLine(", "function applyTsVisible(", "function updateTsNotice(",
              "window.toggleConsoleTs = function", "function _consoleLineEl(", "function _appendConsoleRows(",
              "function _appendConsole(", "function appendConsole(", "function _trimConsole(",
              "function clearConsole(", "function _renderPanelLines(", "function _loadOlderRows(",
              "function loadMoreConsole(")

_cgm_run = r"""
(async () => {
  const out = {}, T = 1700000000;
  // An idle server's page: the priming window is history, appended the way refreshConsole does.
  _appendConsoleRows([{t: null, line: 'Steve joined the game'}, {t: null, line: '<Steve> hello'}]);
  updateTsNotice();
  out.rest = state();
  // A watched line arrives (the socket handler's appendConsole, with the poller's time).
  appendConsole('Alex joined the game', T);
  out.arrive = state();
  // Four more unstamped lines push the stamped one past CONSOLE_MAX_LINES.
  appendConsole('a\nb\nc\nd', null, false);
  out.trimmed = state();
  // The Times switch off, with a stamped line on screen: ts-hidden is set, the collapse lifts.
  appendConsole('Alex left the game', T + 5);
  toggleConsoleTs();
  out.switchedOff = state();
  // ...and Clear with the switch still off: collapsed AND hidden, the switch still the viewer's.
  clearConsole();
  out.clearedOff = state();
  toggleConsoleTs();
  out.clearedOn = state();
  // The panel's backlog alone, with no notice update after it: the stamp opens the gutter itself.
  _renderPanelLines([{t: T + 9, line: '[panel] backup finished'}]);
  out.panelLine = state();
  // Load older over a stamped console: a window of history and no backlog collapses it...
  _fetchAnswer = {lines: [{t: null, line: 'old 1'}, {t: null, line: 'old 2'}], at: null};
  loadMoreConsole(null); await settle();
  out.olderPlain = state();
  // ...and one whose backlog carries the panel's times leaves it open.
  _fetchAnswer = {lines: [{t: null, line: 'old 1'}], panel_lines: [{t: T + 20, line: '[panel] update done'}], at: null};
  loadMoreConsole(null); await settle();
  out.olderBacklog = state();
  console.log(JSON.stringify(out));
})().catch(e => console.log(JSON.stringify({error: String(e && e.stack || e)})));
"""

_cgm_name = "console gutter: collapsed with no stamp on screen, opened by the first"
_cgm_missing = [h for h in _cgm_funcs if h not in _cgm_sd]
check("console gutter: every console function the node run cuts is in server_detail.js", not _cgm_missing,
      repr(_cgm_missing))
_cgm_out = (_node47(_cgm_dom + R37E_STUBS47 + "\n".join(_cut47(_cgm_sd, h) for h in _cgm_funcs) + _cgm_run)
            if not _cgm_missing else {"error": "functions missing"})
if _cgm_out is None:
    skip(_cgm_name, "node is not installed here")
else:
    _o = _cgm_out
    _off = {"none": True, "hidden": False, "notice": False}
    check("console gutter: a console of history only (no line stamped) has the gutter collapsed, the "
          "notice saying why", _o.get("rest") == _off, repr(_o))
    check("console gutter: a watched line arriving with a time opens the gutter and drops the notice",
          _o.get("arrive") == {"none": False, "hidden": False, "notice": True}, repr(_o))
    check("console gutter: once the stamped line is trimmed off the console, the gutter collapses again",
          _o.get("trimmed") == _off, repr(_o))
    check("console gutter: the Times switch turned off hides the column (ts-hidden) with stamps on screen",
          _o.get("switchedOff") == {"none": False, "hidden": True, "notice": True}, repr(_o))
    check("console gutter: Clear leaves no stamp, so the gutter collapses; the switch stays off",
          _o.get("clearedOff") == {"none": True, "hidden": True, "notice": True}, repr(_o))
    check("console gutter: ...and the switch turned back on shows the notice again, gutter still collapsed",
          _o.get("clearedOn") == _off, repr(_o))
    check("console gutter: a line stamped on a path with no notice update (the panel backlog) opens the "
          "gutter itself", _o.get("panelLine", {}).get("none") is False, repr(_o))
    check("console gutter: Load older that replaces a stamped console with history collapses the gutter",
          _o.get("olderPlain", {}).get("none") is True, repr(_o))
    check("console gutter: Load older whose backlog carries the panel's times leaves the gutter open",
          _o.get("olderBacklog", {}).get("none") is False, repr(_o))


# ── 2. panel.css ─────────────────────────────────────────────────────────────────────────────────
def _cgm_rule(css, selector):
    """The declarations of the rule whose selector list includes `selector`, as {prop: value}."""
    for m in _re172.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        sels = [s.strip() for s in _re172.sub(r"/\*.*?\*/", "", m.group(1), flags=_re172.S).split(",")]
        if selector in sels:
            body = _re172.sub(r"/\*.*?\*/", "", m.group(2), flags=_re172.S)
            return {k.strip(): v.strip() for k, v in
                    (d.split(":", 1) for d in body.split(";") if ":" in d)}
    return None


def _cgm_media(css, query):
    """The text inside every `@media <query> { … }` block, joined."""
    out = []
    for m in _re172.finditer(r"@media\s*" + _re172.escape(query) + r"\s*\{", css):
        depth, k = 1, m.end()
        while depth and k < len(css):
            depth += {"{": 1, "}": -1}.get(css[k], 0)
            k += 1
        out.append(css[m.end():k - 1])
    return "\n".join(out)


_cgm_before = _cgm_rule(_cgm_css, ".console-output.ts-none .console-line::before") or {}
_cgm_line = _cgm_rule(_cgm_css, ".console-output.ts-none .console-line") or {}
check("console gutter css: with ts-none the unstamped line's placeholder takes no space",
      _cgm_before.get("content") == "none", repr(_cgm_before))
check("console gutter css: ...and the hanging indent is gone, so text starts at the console's edge",
      _cgm_line.get("padding-left") == "0" and _cgm_line.get("text-indent") == "0", repr(_cgm_line))

_cgm_mob = _cgm_media(_cgm_css, "(width <= 767.98px)")
_cgm_ts = _cgm_rule(_cgm_mob, ".console-ts") or {}
_cgm_ph = _cgm_rule(_cgm_mob, ".console-line:not([data-ts])::before") or {}
_cgm_ml = _cgm_rule(_cgm_mob, ".console-line") or {}
_cgm_margin = (_cgm_rule(_cgm_css, ".console-ts") or {}).get("margin-right")
_cgm_w = _cgm_ts.get("width")
check("console gutter css: on a phone the stamp is narrower than the desktop 4.6rem, and its placeholder "
      "is the same width", bool(_cgm_w) and _cgm_w != "4.6rem" and _cgm_ph.get("width") == _cgm_w,
      repr((_cgm_ts, _cgm_ph)))
check("console gutter css: ...and the phone's hanging indent is that width plus the stamp's margin, "
      "both ways", bool(_cgm_w) and bool(_cgm_margin)
      and _cgm_ml.get("padding-left") == "calc(%s + %s)" % (_cgm_w, _cgm_margin)
      and _cgm_ml.get("text-indent") == "calc(-%s - %s)" % (_cgm_w, _cgm_margin), repr((_cgm_ml, _cgm_margin)))

# ── 3. the server page, rendered ─────────────────────────────────────────────────────────────────
_cgm_sid = _p9_new_server(P9_HOST, "cgmserver", "mc", 25571, name="p172-mc", status="online")
_cgm_page = (0, "")
try:
    _p9_arm(who="part172")
    _p9_patch(_sd172, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd172, "_host_timezone_cached", lambda *a, **k: "")
    # The console tail the page is rendered with: history, which never carries a stamp.
    _p9_patch(_smc172, "run_command", lambda *a, **k: ("Steve joined the game\nAlex joined the game\n", "", 0))
    _cgm_r = _p9_client(P9_ADMIN).get("/server/%d" % _cgm_sid)
    _cgm_page = (_cgm_r.status_code, _cgm_r.get_data(as_text=True))
finally:
    _p9_restore_all()
    _p9_delete_server(_cgm_sid)
_cgm_div = _re172.search(r'<div class="([^"]*)" id="console-output">', _cgm_page[1])
check("console gutter: the server page renders its console with the gutter collapsed (ts-none), so a "
      "phone never sees the blank column before the script runs",
      _cgm_page[0] == 200 and _cgm_div is not None and "ts-none" in _cgm_div.group(1).split(),
      repr((_cgm_page[0], _cgm_div and _cgm_div.group(0))))
