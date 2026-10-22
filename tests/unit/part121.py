"""Part 121 of the unit suite: an install's ending on the dashboard survives a swap of its cards.

An install that ends "Installed, with a warning" (its port collides with another server's, or it
installed and did not start) says so in a row under its server, and only there. That row lives
inside #server-cards, which the dashboard swaps wholesale when another server appears or goes or
another install fails, and nothing rebuilt it: /api/installs lists only running jobs, and the poll
has stopped once nothing runs. The caveat vanished without being dismissed. Likewise an install
that ended between a swap (which took its live row) and the next poll had no row left to settle.

Also held here, from the same review's leads:

* the Tailscale page's direct listeners are wired once per element: refreshSection runs its
  after-hook even when the page it fetched had nothing to swap in (a 502, the login page), and
  Enter in the peer box then pinged the peer twice.
* Files & Config's backup card: a read sent while another schedule save was unanswered is not
  drawn (it put the old Keep back in the select after a quick second pick).

HOW IT RUNS. The whole of install_progress.js in node, on a small DOM of this part's own (rows,
attribute selectors, insertBefore), with fetch and the timers stood in; dashboard.js's
afterDashRefresh and tailscale.js's wiring cut out, their neighbours stood in; server_files.js's
backup card through part106's harness with fetch answered by hand (part109's). Nothing reaches a
server or the data dir.
"""
import os

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _SETTLE47, _cut47, _node47
from unit.part106 import _js106
from unit.part109 import _PEND109


def _read121(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _node121(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


# A DOM just big enough for install_progress.js: elements with attributes, children, parentNode and
# siblings; querySelector(All) over `tag#id.cls[attr="v"][attr]:not([attr])`, descendant and comma lists.
_DOM121 = r"""
class N {
  constructor(tag){ this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {};
    this.parentNode = null; this._t = ''; this.className = ''; this.style = {}; this.on = {};
    this.classList = {toggle(){}}; }
  appendChild(c){ return this.insertBefore(c, null); }
  insertBefore(c, ref){ if (c.parentNode) c.parentNode.removeChild(c);
    const i = ref ? this.children.indexOf(ref) : -1;
    if (i < 0) this.children.push(c); else this.children.splice(i, 0, c);
    c.parentNode = this; return c; }
  removeChild(c){ const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1);
    c.parentNode = null; return c; }
  get firstChild(){ return this.children[0] || null; }
  get lastChild(){ return this.children[this.children.length - 1] || null; }
  get nextSibling(){ const p = this.parentNode; return p ? (p.children[p.children.indexOf(this) + 1] || null) : null; }
  set textContent(v){ this.children.forEach(c => { c.parentNode = null; }); this.children = []; this._t = String(v); }
  get textContent(){ return this._t + this.children.map(c => c.textContent).join(''); }
  setAttribute(k, v){ this.attrs[k] = String(v); }
  getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; }
  hasAttribute(k){ return k in this.attrs; }
  removeAttribute(k){ delete this.attrs[k]; }
  addEventListener(k, f){ this.on[k] = f; }
  querySelector(s){ return this.querySelectorAll(s)[0] || null; }
  querySelectorAll(s){ const out = [];
    const walk = n => n.children.forEach(c => { if (matches(c, s)) out.push(c); walk(c); });
    walk(this); return out; }
}
function simple(el, s){
  const m = s.match(/^([a-z]*)(#[\w-]+)?((?:\.[\w-]+)*)((?:\[[^\]]+\])*)((?::not\(\[[^\]]+\]\))*)$/);
  if (!m) throw new Error('selector ' + s);
  if (m[1] && el.tagName !== m[1].toUpperCase()) return false;
  if (m[2] && el.attrs.id !== m[2].slice(1)) return false;
  const cls = String(el.className).split(/\s+/);
  if (m[3] && !m[3].slice(1).split('.').every(c => cls.indexOf(c) !== -1)) return false;
  for (const a of (m[4].match(/\[[^\]]+\]/g) || [])) {
    const kv = a.slice(1, -1).split('=');
    if (!(kv[0] in el.attrs)) return false;
    if (kv.length > 1 && el.attrs[kv[0]] !== JSON.parse(kv[1])) return false; }
  for (const a of (m[5].match(/\[[^\]]+\]/g) || [])) if (a.slice(1, -1) in el.attrs) return false;
  return true;
}
function matches(el, sel){
  return sel.split(',').some(p => { const parts = p.trim().split(/\s+/);
    if (!simple(el, parts[parts.length - 1])) return false;
    let a = el.parentNode, i = parts.length - 2;
    while (i >= 0 && a) { if (simple(a, parts[i])) i--; a = a.parentNode; }
    return i < 0; });
}
const root = new N('html'), cardsBox = new N('div');
cardsBox.setAttribute('id', 'server-cards'); root.appendChild(cardsBox);
let onload = null;
global.window = global; global.MOUNT = '';
global.document = {
  addEventListener: (k, f) => { if (k === 'DOMContentLoaded') onload = f; },
  createElement: tag => new N(tag),
  getElementById: id => root.querySelector('#' + id),
  querySelector: s => root.querySelector(s), querySelectorAll: s => root.querySelectorAll(s) };
// What the dashboard's swap of #server-cards leaves: fresh server rows, and nothing else.
const swap = ids => { cardsBox.textContent = ''; const tb = new N('tbody');
  ids.forEach(id => { const tr = new N('tr'); tr.setAttribute('data-server-id', String(id));
    tr.appendChild(new N('td')); tr.appendChild(new N('td')); tb.appendChild(tr); });
  cardsBox.appendChild(tb); };
let ivals = {}, nextIv = 1, touts = [];
global.setInterval = f => { const i = nextIv++; ivals[i] = f; return i; };
global.clearInterval = i => { delete ivals[i]; };
global.setTimeout = f => { touts.push(f); return touts.length; };
let installs = [], status = {}, sent = [];
global.fetch = u => { sent.push(u);
  const m = /\/api\/server\/(\d+)\/install-status$/.exec(u);
  const d = m ? (status[m[1]] || {status: 'none'}) : {installs: installs};
  return Promise.resolve({ok: true, json: () => Promise.resolve(d)}); };
const row = id => root.querySelector('tr[data-progress-for="' + id + '"]');
const seen = id => { const r = row(id); if (!r) return null;
  const b = r.querySelector('button');
  return {settled: r.getAttribute('data-settled'), text: r.firstChild.firstChild.textContent,
          dismiss: !!b, under: r.parentNode.children.indexOf(r) - 1 ===
            r.parentNode.children.indexOf(root.querySelector('tr[data-server-id="' + id + '"]'))}; };
"""

_IP121 = _read121("static", "js", "install_progress.js")
_name121 = "install progress: an ending on the dashboard after a swap of its cards"
_out121 = _node121(_name121, _DOM121 + _SETTLE47 + _IP121 + r"""
const poll = async () => { window.watchInstallsNow(); await settle(); await settle(); };
const redraw = () => { if (window._r34c_ipRedraw) window._r34c_ipRedraw(); };
(async () => {
  const out = {};
  swap([7, 8, 9, 10]); onload(); await settle();
  // 7: a caveat, then two swaps of the cards.
  installs = [{id: 7, name: 'a', percent: 50}]; await poll();
  installs = []; status['7'] = {status: 'done', warn: true, message: 'Port 27015 is in use'}; await poll();
  out.warn = {before: seen(7), polling: Object.keys(ivals).length};
  swap([7, 8, 9, 10]); redraw(); out.warn.after = seen(7);
  swap([7, 8, 9, 10]); redraw(); out.warn.again = seen(7);
  row(7).querySelector('button').on.click();
  swap([7, 8, 9, 10]); redraw(); out.warn.dismissed = seen(7);
  // 8: running when a swap took its row, ended before the next poll rebuilt it.
  installs = [{id: 8, name: 'b', percent: 10}]; await poll();
  const live8 = seen(8); swap([7, 8, 9, 10]); redraw();
  installs = []; status['8'] = {status: 'done', warn: true, message: 'Installed but did not start'}; await poll();
  out.ended = {live: !!live8 && live8.settled === null, after: seen(8)};
  // 9: a failure is the card region's to show (its banner): a swap still takes the row.
  installs = [{id: 9, name: 'c', percent: 10}]; await poll();
  installs = []; status['9'] = {status: 'failed', message: 'Download failed'}; await poll();
  out.bad = {before: (seen(9) || {}).settled}; swap([7, 8, 9, 10]); redraw(); out.bad.after = seen(9);
  // 10: a clean ending until its own timer, then gone for good.
  installs = [{id: 10, name: 'd', percent: 10}]; await poll(); touts = [];
  installs = []; status['10'] = {status: 'done'}; await poll();
  swap([7, 8, 9, 10]); redraw(); out.ok = {after: seen(10)};
  touts.forEach(f => f()); swap([7, 8, 9, 10]); redraw(); out.ok.timedOut = seen(10);
  // 7 again: a retry is live progress, not its last ending.
  installs = [{id: 7, name: 'a', percent: 5}]; status['7'] = {status: 'done', warn: true, message: 'w'};
  await poll(); installs = []; await poll(); installs = [{id: 7, name: 'a', percent: 5}]; await poll();
  swap([7, 8, 9, 10]); redraw(); out.retry = seen(7);
  // A server that is gone takes its ending with it.
  swap([7, 9, 10]); redraw(); swap([7, 8, 9, 10]); redraw(); out.gone = seen(8);
  // Install a Server has no server rows: a job that left the list there asks no install-status.
  swap([]); installs = [{id: 11, name: 'e', percent: 5}]; await poll(); sent = [];
  installs = []; await poll(); out.page = sent.filter(u => u.indexOf('/install-status') !== -1);
  console.log(JSON.stringify(out));
})();
""")
if _out121 is not None:
    _w121 = {"settled": "warn", "text": "Port 27015 is in use", "dismiss": True, "under": True}
    check("install progress: an \"Installed, with a warning\" row comes back, under its server with its "
          "Dismiss, after each swap of the dashboard's cards (another server added, removed or failed) "
          "with no poll running (it vanished undismissed: /api/installs lists only running jobs)",
          _out121.get("warn") == {"before": _w121, "polling": 0, "after": _w121, "again": _w121,
                                  "dismissed": None}, repr(_out121))
    check("install progress: ...an install that ended after a swap took its live row, before the next "
          "poll rebuilt it, still has its ending read and shown (it had no row left to settle)",
          _out121.get("ended") == {"live": True, "after": {"settled": "warn", "dismiss": True, "under": True,
                                                           "text": "Installed but did not start"}},
          repr(_out121))
    check("install progress: ...while a failure is still left to the card region's banner, a clean "
          "ending still goes on its own timer and stays gone, a retry is live progress again, and a "
          "server that is gone drops its ending",
          _out121.get("bad") == {"before": "bad", "after": None}
          and (_out121.get("ok") or {}).get("timedOut") is None
          and ((_out121.get("ok") or {}).get("after") or {}).get("text") == "Installed"
          and _out121.get("retry") is None and _out121.get("gone") is None, repr(_out121))
    check("install progress: ...and on Install a Server (no server rows) a job leaving the list asks for "
          "no install-status (its answer empties the page panel of jobs still running)",
          _out121.get("page") == [], repr(_out121))

# dashboard.js puts the endings back after every swap of #server-cards, before the filter runs (the
# filter hides a progress row with its server, so a row added after it would show under a hidden one).
_DB121 = _read121("static", "js", "dashboard.js")
_head121 = "window.afterDashRefresh = function("
_name121 = "dashboard: the after-swap hook puts install endings back"
_out121 = _node121(_name121, (
    "global.window = global; const calls = [];\n"
    "for (const f of ['restoreBulkSelection', 'filterServers', '_r20cIdsLanded', 'refreshStatus',\n"
    "                 'bindDragRegions', '_r34c_ipRedraw']) global[f] = () => calls.push(f);\n"
    + (_cut47(_DB121, _head121) if _head121 in _DB121 else "/* MISSING afterDashRefresh */") + "\n"
    "window.afterDashRefresh(); console.log(JSON.stringify(calls));\n"))
if _out121 is not None:
    check("dashboard: afterDashRefresh (run after every swap of #server-cards) puts install endings "
          "back, before the search filter runs",
          isinstance(_out121, list) and "_r34c_ipRedraw" in _out121
          and _out121.index("_r34c_ipRedraw") < _out121.index("filterServers"), repr(_out121))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# The Tailscale page's direct listeners, once per element
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TS121 = _read121("static", "js", "tailscale.js")
_name121 = "tailscale page: an after-hook with nothing swapped in"
_out121 = _node121(_name121, (
    "global.window = global; global.MOUNT = ''; let els = {};\n"
    "const mk = () => ({n: 0, addEventListener(){ this.n++; }});\n"
    "global.document = {getElementById: id => els[id] || null};\n"
    "const ids = ['ts-install-btn', 'ts-connect-btn', 'peer-host'];\n"
    "const fresh = () => { els = {'ts-install-out': {}, 'ts-connect-out': {}};\n"
    "  ids.forEach(i => { els[i] = mk(); }); };\n"
    + "".join((_cut47(_TS121, h) if h in _TS121 else "/* MISSING %s */" % h) + "\n"
              for h in ("function _r34c_tsOnce(", "function wireTsButtons("))
    + "const out = {};\n"
    "fresh(); wireTsButtons(); wireTsButtons(); out.same = ids.map(i => els[i].n);\n"
    "fresh(); wireTsButtons(); out.fresh = ids.map(i => els[i].n);\n"
    "console.log(JSON.stringify(out));\n"))
if _out121 is not None:
    check("tailscale page: wiring the same Install, Link and peer-box elements again (refreshSection's "
          "after-hook when the fetched page had no #ts-page: a 502, the login page) adds no second "
          "listener (Enter pinged the peer twice); a page really swapped in is wired",
          _out121 == {"same": [1, 1, 1], "fresh": [1, 1, 1]}, repr(_out121))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# Files & Config's backup card: a read sent while another schedule save is unanswered
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SF121 = _read121("static", "js", "server_files.js")
_name121 = "Files & Config backup card: a second pick before the first save answers"
_out121 = _js106(_name121, _PEND109 + (
    "var serverId = 1;\n"
    "global._bkRenderDisk = () => {}; global._bkRenderStatus = () => {}; global._bkRenderRows = () => {};\n"
    "global._bkPollWhileRunning = () => {};\n"
    "const iv = document.getElementById('bk-interval'), kp = document.getElementById('bk-keep');\n"
    "for (const s of [iv, kp]) { s.options = [{value: 'default'}, {value: '1'}, {value: '3'}, {value: '7'}];\n"
    "  s.appendChild = o => { s.options.push(o); return o; }; }\n"
    "const info = (days, keep) => ({schedule: {interval_set: true, interval_days: days, keep_set: true, keep},\n"
    "                               status: null, backups: []});\n"), _SF121, (
    "var _bkPoll", "var _bkShown", "function _bkShow(", "var _r30c_sfBkSaves", "function loadBackups(",
    "function renderBackups(", "function saveBkSchedule(", "function _r32c_sfBkPutBack("), (
    "  const out = {};\n"
    "  loadBackups(); reply('/info', info(7, 3)); await settle();\n"
    # Every 3 days (save a), then Keep 7 (save b) before a answers; the Keep select keeps focus
    "  iv.value = '3'; iv.focus(); saveBkSchedule(); const a = take('/schedule');\n"
    "  kp.value = '7'; kp.focus(); saveBkSchedule(); const b = take('/schedule');\n"
    "  if (!a || !b) { console.log(JSON.stringify({sent: 'not two saves'})); return; }\n"
    # a's re-read is served before b commits: the stored Keep is still 3
    "  a.ok({success: true}); await settle(); reply('/info', info(3, 3)); await settle();\n"
    "  out.between = [iv.value, kp.value];\n"
    "  b.ok({success: true}); await settle(); reply('/info', info(3, 7)); await settle();\n"
    "  out.end = [iv.value, kp.value];\n"
    # control: a lone save's re-read still draws what is stored, even into the focused select
    "  iv.value = '1'; iv.focus(); saveBkSchedule(); const c = take('/schedule');\n"
    "  if (c) { c.ok({success: true}); await settle(); reply('/info', info(7, 7)); await settle(); }\n"
    "  out.lone = iv.value;\n"
    "  console.log(JSON.stringify(out));\n"))
if _out121 is not None:
    check("Files & Config backup card: the re-read a schedule save sends while another save is still "
          "unanswered is not drawn (it put the old Keep back in the focused select after a quick second "
          "pick); the last save's re-read draws what is stored",
          _out121.get("between") == ["3", "7"] and _out121.get("end") == ["3", "7"], repr(_out121))
    check("Files & Config backup card: ...while a lone save's re-read still draws the stored value into "
          "the focused select (control)", _out121.get("lone") == "7", repr(_out121))
