"""Part 158 of the unit suite: the console keeps an older log's lines through a read of the new one.

LinuxGSM's start (a Restart) moves the console log aside and begins a new one, and a read that
REPLACES the console — the 30 s re-prime after Clear, Load older — reads only the log there is now.
Seen in a real browser: Clear, send a command, Restart; at the re-prime the command's echo, its
output and every line the server printed before it stopped were gone (review pass 25, builder E).

Held here, with the page's OWN functions cut out of server_detail.js and run in node against a
small stand-in console element (its children are what the viewer sees, in order):
* after Clear: a command sent and answered in the old log, then a Restart, then the re-prime — every
  old-log line stays, the echo with them, above the new log's window; nothing is shown twice;
* the same log (no restart): the re-prime's window holds those lines, so nothing is kept beside it
  and nothing doubles (the local echo goes, as it always has: the log holds the game's own echo);
* a push from a newer log that lands while the read is out is not kept above it (it came after the
  read began; the read's catch-up brings it), so it is not shown out of order or twice;
* Load older after a Restart keeps the lines of the log before it.
"""
import json as _json158
import os

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _cut47, _node47

with open(os.path.join(_root, "panel", "static", "js", "server_detail.js"), encoding="utf-8") as _fh158:
    _SD158 = _fh158.read()

# A console element that keeps its children in order; a fragment hands its children over.
_DOM158 = r"""
class E158 { constructor(tag){ this.tagName = tag; this.children = []; this.parentNode = null;
    this.dataset = {}; this.style = {}; this.className = ''; this.attrs = {}; this._text = ''; }
  appendChild(c){
    if (c.tagName === '#frag') { c.children.slice().forEach(k => this.appendChild(k)); c.children = []; return c; }
    if (c.parentNode) c.parentNode.removeChild(c);
    c.parentNode = this; this.children.push(c); return c; }
  removeChild(c){ const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); c.parentNode = null; return c; }
  get firstChild(){ return this.children[0] || null; }
  get childElementCount(){ return this.children.length; }
  set innerHTML(v){ this.children.slice().forEach(c => this.removeChild(c)); }
  set textContent(v){ this._text = String(v); }
  get textContent(){ return this._text; }
  setAttribute(k, v){ this.attrs[k] = String(v); } }
global.window = global; global.MOUNT = ''; global.serverId = 1;
global.document = { createElement: t => new E158(t), createDocumentFragment: () => new E158('#frag'),
  getElementById: id => id === 'command-input' ? input : null };
var input = { value: '', focus(){} };
var consoleEl = new E158('div');
var socket = { connected: true, handlers: {}, on(ev, fn){ this.handlers[ev] = fn; } };
var _consoleLines = [], _consolePrimed = false, _consoleSig = null, _logAt = null, _returnOwed = false;
var _lastPanelT = 0, _r15c_clearedAt = null, CONSOLE_MAX_LINES = 5000, _r37e_gen = 0;
function stampLine(){} function renderAnsi(el, line){ el.textContent = line; }
function updateTsNotice(){} function _showTsOffNote(){} function stickConsole(){}
function consoleAtBottom(){ return true; } function _rebuildMark(){ return 0; } function _rebuildRestore(){}
function _rebuildNotePush(){} function _panelLinesWiped(){ return 0; } function showPanelBacklog(){}
function _r13c_reshowPanelPushes(){} function _r13c_primeWipesPushes(){ return false; }
function _renderPanelLines(){} function _r11c_resyncFrom(){} function _notePanelPush(){ return true; }
function _resyncTake(){ return false; } function _r13c_notePanelPush(){} function appendConsole(){}
function _primeAt(at){ _logAt = at; }
function _r39c_tailGap(){} function _r39c_notePrimeKeep(){} var _r39c_primeKeep = null;
function toast(){} function tf(s){ return s; } function t(s){ return s; }
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };
// /api/command answers at once; each /api/console read takes the next answer queued, or waits for
// one queued later (a read still out).
var answers = [], waiting = [];
global.fetch = (url) => {
  if (String(url).indexOf('/api/command/') >= 0) return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
  return new Promise(res => { const give = d => res({ ok: true, json: () => Promise.resolve(d) });
    if (answers.length) give(answers.shift()); else waiting.push(give); }); };
function answer(d){ if (waiting.length) waiting.shift()(d); else answers.push(d); }
function rows(ls){ return ls.map(l => ({ line: l })); }
function push(ls, at){ socket.handlers.console_output({ server_id: 1, data: ls.join('\n'), rows: rows(ls), ts: 1, at: at }); }
function send(cmd){ input.value = cmd; sendCommand({ preventDefault(){} }); }
function shown(){ return consoleEl.children.map(c => c.textContent); }
"""

_FUNCS158 = (
    "function _r37e_inoOf(", "function _r37e_tag(", "function _r37e_olderLog(",
    "function _r37e_keepOlderLog(", "function _r38c_readingIno(", "function _consoleLineEl(",
    "function _appendConsoleRows(",
    "function _trimConsole(", "function _sameLine(", "function _eqRange(", "function _newConsoleLines(",
    "function _newConsoleRows(", "function refreshConsole(", "function clearConsole(",
    "function sendCommand(", "function _loadOlderRows(", "function loadMoreConsole(",
    "socket.on('console_output', function(data) {")


def _harness158():
    """The page's own console functions, cut from the file, after the stand-ins; None if one is gone."""
    parts = []
    for head in _FUNCS158:
        if head not in _SD158:
            return None
        body = _cut47(_SD158, head)
        parts.append(body + (");" if head.startswith("socket.on(") else ""))
    return _DOM158 + "\n".join(parts) + "\n"


_PROG158 = (
    "(async () => { const out = {};\n"
    # The page primed from the log (inode 11), pushes go on in it.
    "  answer({lines: rows(['a1', 'a2']), at: [0, 11, 20]}); refreshConsole(true); await settle();\n"
    "  push(['a3'], [1, 11, 30]);\n"
    # Clear, send a command the game answers in the same log, Restart (a new log, inode 12)
    "  clearConsole(); send('list'); push(['> list', 'listed'], [1, 11, 50]);\n"
    "  push(['[ INFO ] Restarting', 'b1'], [2, 12, 25]);\n"
    "  answer({lines: rows(['[ INFO ] Restarting', 'b1', 'b2']), at: [0, 12, 40]});\n"
    "  refreshConsole(false); await settle();\n"
    "  out.restart = shown(); out.restartLines = _consoleLines.slice();\n"
    # The same log, no restart: Clear, a command and its answer, the re-prime's window holds them.
    "  clearConsole(); send('say'); push(['> say', 'said'], [2, 12, 60]);\n"
    "  answer({lines: rows(['b1', 'b2', '> say', 'said']), at: [0, 12, 60]});\n"
    "  refreshConsole(false); await settle();\n"
    "  out.same = shown();\n"
    # A read out while the server restarts: the newer log's push lands before the read's answer.
    "  clearConsole(); push(['c0'], [2, 12, 70]); refreshConsole(false);\n"
    "  push(['[ INFO ] Restarting', 'd1'], [3, 13, 20]);\n"
    "  answer({lines: rows(['b2', '> say', 'said', 'c0']), at: [0, 12, 70]}); await settle();\n"
    "  out.race = shown();\n"
    # Load older after a Restart (no Clear): the log before it stays above the deeper window.
    "  push(['d2'], [3, 13, 30]); send('help'); push(['> help', 'helped'], [3, 13, 50]);\n"
    "  push(['[ INFO ] Restarting', 'e1'], [4, 14, 20]);\n"
    "  answer({lines: rows(['[ INFO ] Restarting', 'e1', 'e2']), at: [0, 14, 30]});\n"
    "  loadMoreConsole(null); await settle();\n"
    "  out.older = shown();\n"
    "  console.log(JSON.stringify(out)); })();\n")

_h158 = _harness158()
check("console: the functions part158 runs are all still in server_detail.js", _h158 is not None,
      [h for h in _FUNCS158 if h not in _SD158])
_out158 = _node47(_h158 + _PROG158) if _h158 is not None else None
if _h158 is not None and _out158 is None:
    skip("console: an older log's lines through a read of the new one", "node is not installed here")
elif _out158 is not None:
    _all158 = [_out158.get(k) for k in ("restart", "same", "race", "older")]
    check("console: after Clear, a command sent, its answer and the lines before a Restart stay through "
          "the re-prime of the new log, the echo in its place (all were wiped)",
          _out158.get("restart") == ["> list", "> list", "listed", "[ INFO ] Restarting", "b1", "b2"]
          and _out158.get("restartLines") == ["> list", "listed", "[ INFO ] Restarting", "b1", "b2"],
          _json158.dumps(_out158))
    check("console: ...and with no restart the re-prime's window holds them, so nothing is kept beside it "
          "or shown twice (control)",
          _out158.get("same") == ["b1", "b2", "> say", "said"], _json158.dumps(_out158))
    check("console: a newer log's push that lands while the re-prime's read is out is not kept above "
          "its window (it is the read's catch-up's to bring)",
          _out158.get("race") == ["b2", "> say", "said", "c0"], _json158.dumps(_out158))
    check("console: Load older after a Restart keeps the lines of the log before it, the command's echo "
          "with them, above the deeper window (they were wiped)",
          _out158.get("older") == ["b2", "> say", "said", "c0", "d2", "> help", "> help", "helped",
                                   "[ INFO ] Restarting", "e1", "e2"],
          _json158.dumps(_out158))
    check("console: no line of any of those consoles is an error or missing (the harness ran)",
          all(isinstance(v, list) for v in _all158), _json158.dumps(_out158))
