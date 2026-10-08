"""Part 38 of the unit suite: console-idle — a tab that stays hidden leaves its console.

A console someone has joined costs the panel one privileged read of its log every two seconds (the
poller in panel/routes/server_files.py): about 1,800 sudo calls an hour per watched console, for as
long as the tab stays open, looked at or not. static/js/server_detail.js now leaves the console's
room once its tab has stayed hidden for 30 s, and on the way back rejoins, asking with its join to be
caught up from its own place in the log; the poller answers on its next pass with the lines written
since, cut exactly where its own pushes go on from, and every push says where in the log it ends.
Every check below is judged on the console's own job — output prompt, in order, complete and
unduplicated — and what holds it up is, one section each:

* A. THE PAGE. server_detail.js run WHOLE in node (a small DOM, a virtual clock, a fake socket that
     buffers as socket.io-client 4.8.4 does and carries acks, a fetch the check answers, panel.js's
     own pollWhenVisible) against a model of the server's half of the console with the semantics B
     pins: a pass forgets a console nobody watches; it answers a catch-up a join asked for, then
     ticks; a first look records where the log ends and reads nothing; each later tick pushes what was
     written since, with where it ends, to whoever is in the room right then; a leave is answered with
     where the poller stands; the window is the log's last lines at the moment it is read. Fixed
     orderings first — the console repeating lines word for word among them, and the ways a page
     still has to place a read by its text — then random schedules, with a control proving they catch
     what a plain rejoin gets wrong, and schedules of a console that repeats itself held to what the
     page that never leaves shows.
* B. THE SERVER. Through flask-socketio's test client and the real console poller loop, reading a
     real file with bash: a room left empty is not read at all and its offset is forgotten; a rejoin
     is a first look, with no replay; a second tab keeps the reads going; a socket that never joined
     is never read; the panel backlog carries each push's time, the key the page dedupes by; an
     update that runs while nobody watches is read to its end, in one read, when it ends; a tick
     or an action that overlaps that end neither repeats its output nor loses its own; and a catch-up
     is answered exactly from the page's place to where the poller stands, whole lines only, with a
     line the log ends inside of carried whole by the next push.
* C. BOTH. Payloads the real server produced — the poller's pushes, its catch-up answers and leave
     answers, /api/console's windows — fed to the real page in the order the server produced them.

Nothing here reaches a real transport: the console's reads go to the rig, the rest to a tripwire.
"""
import json as _json38
import os
import re as _re38
import shutil as _shutil38
import subprocess as _sp38  # nosec B404 - runs node and bash on this part's own fixtures
import tempfile as _tf38
import time as _time38
from types import SimpleNamespace as NS

from werkzeug.security import generate_password_hash as _hash38

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import _p9, _p9_client
from unit.part34 import _as_account34, _bash34
from panel.core import panel_state as _ps38
from panel.db.models import GameServer, RemoteServer, User, db
from panel.ops.ssh_manager import _core as _core38
from panel.routes import _shared as _sh38
from panel.routes import server_files as _sf38

_TMP38 = _tf38.mkdtemp(prefix="lgsm-unit-p38-")
_ABSENT38 = object()
_SAVED38 = {}
_TRIP38 = []
_SRC38 = os.path.join(_root, "static", "js", "server_detail.js")
_PANEL38 = os.path.join(_root, "static", "js", "panel.js")


def _set38(owner, name, value):
    """owner.name = value, the original saved the first time (restored by _restore38)."""
    if (owner, name) not in _SAVED38:
        _SAVED38[(owner, name)] = owner.__dict__.get(name, _ABSENT38)
    setattr(owner, name, value)


def _restore38():
    for (owner, name), value in list(_SAVED38.items()):
        if value is _ABSENT38:
            owner.__dict__.pop(name, None)
        else:
            setattr(owner, name, value)
    _SAVED38.clear()


def _arm38():
    """Every real transport raises; the console's reads are stubbed above them."""
    for name in ("_run_via_ssh_cli", "get_connection", "_exec_local_shell", "_exec_local_argv"):
        def _tripped(*_a, _n=name, **_k):
            _TRIP38.append(_n)
            raise ConnectionError("part38 tripwire: a test reached the real %s" % _n)
        _set38(_core38, name, _tripped)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# A: the page, run whole in node
# ════════════════════════════════════════════════════════════════════════════════════════════════
_HARNESS38 = r"""'use strict';
// server_detail.js, run WHOLE in node, against a model of the server's half of the live console.
// stdin: {"src", "panel", "mode": "checks"|"replay", "runs", "steps"}. stdout: one JSON object.
const fs = require('fs'), vm = require('vm');

// ── a page: a small DOM, a virtual clock, a fake socket, a fetch the caller answers ──────────────
class Txt { constructor(t) { this.data = String(t); } get textContent() { return this.data; } }
class Frag { constructor() { this.children = []; } appendChild(c) { this.children.push(c); return c; } }
class El {
  constructor(tag) {
    this.tagName = String(tag || 'div').toUpperCase(); this.children = []; this.className = '';
    this.dataset = {}; this.style = {}; this._t = ''; this.attrs = {}; this.hidden = false;
    this.scrollTop = 0; this.clientHeight = 200; this.listeners = {};
  }
  get classList() {
    const el = this, has = c => el.className.split(/\s+/).indexOf(c) >= 0;
    return {
      contains: has,
      add(c) { if (!has(c)) el.className = (el.className + ' ' + c).trim(); },
      remove(c) { el.className = el.className.split(/\s+/).filter(x => x && x !== c).join(' '); },
      toggle(c, on) { if (on === undefined) on = !has(c); if (on) this.add(c); else this.remove(c); return on; },
    };
  }
  appendChild(c) { for (const x of (c instanceof Frag ? c.children.splice(0) : [c])) this.children.push(x); return c; }
  removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); return c; }
  get firstChild() { return this.children[0] || null; }
  get childElementCount() { return this.children.filter(c => c instanceof El).length; }
  set innerHTML(v) { this.children = []; this._t = ''; }
  get innerHTML() { return ''; }
  get textContent() { return this._t + this.children.map(c => c.textContent).join(''); }
  set textContent(v) { this.children = []; this._t = String(v); }
  get scrollHeight() { return this.children.length * 20 + this.clientHeight; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(e, f) { (this.listeners[e] = this.listeners[e] || []).push(f); }
  querySelectorAll(sel) {
    const m = /^\.([\w-]+)(?:\[data-([\w-]+)\])?$/.exec(sel), out = [];
    const walk = n => n.children.forEach(c => {
      if (!(c instanceof El)) return;
      if (m && c.classList.contains(m[1]) && (!m[2] || m[2] in c.dataset)) out.push(c);
      walk(c);
    });
    walk(this);
    return out;
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}

function makePage(o) {
  let now = 1700000000000, tid = 0;
  const timers = [], fetches = [], emitted = [], sock = {}, docL = {}, winL = {};
  const consoleEl = new El('div'), wsEl = new El('span');
  const els = {'ws-status': wsEl, 'game-version': new El('span')};
  if (o.console !== false) els['console-output'] = consoleEl;
  const document = {
    hidden: !!o.hidden, visibilityState: o.hidden ? 'hidden' : 'visible', readyState: 'complete',
    getElementById: id => els[id] || null, createElement: t => new El(t), createTextNode: t => new Txt(t),
    createDocumentFragment: () => new Frag(), createRange: () => ({selectNodeContents() {}}),
    querySelectorAll: () => [], querySelector: () => null,
    addEventListener: (e, f) => (docL[e] = docL[e] || []).push(f),
    removeEventListener: (e, f) => { const l = docL[e] || [], i = l.indexOf(f); if (i >= 0) l.splice(i, 1); },
  };
  // socket.io-client 4.8.4 as static/vendor/socketio has it: a packet emitted while the socket is not
  // connected — or is, but its engine's ping deadline has passed (_hasPingExpired, a page woken from
  // a long sleep) — goes to sendBuffer, and is sent on the next connect BEFORE the 'connect'
  // listeners run (onconnect: emitBuffered, then emitReserved('connect')). An expired ping also
  // closes the socket on the next microtask, which fires 'disconnect'.
  const socket = {
    connected: false, pingExpired: false, sendBuffer: [],
    on(e, f) { (sock[e] = sock[e] || []).push(f); return socket; },
    emit(e, d, cb) {
      const pkt = [e, JSON.parse(JSON.stringify(d === undefined ? null : d)), typeof cb === 'function' ? cb : null];
      let live = socket.connected;
      if (live && socket.pingExpired) {
        live = false;
        socket.pingExpired = false;
        Promise.resolve().then(() => { if (socket.connected) { socket.connected = false; fire('disconnect', 'ping timeout'); } });
      }
      if (live) emitted.push([pkt[0], pkt[1], now, pkt[2]]); else socket.sendBuffer.push(pkt);
      return socket;
    },
    connect() {}, disconnect() {},
  };
  class FakeDate extends Date {
    constructor(...a) { if (a.length) super(...a); else super(now); }
    static now() { return now; }
  }
  const later = (fn, ms, every) => { const id = ++tid; timers.push({id, at: now + (ms || 0), fn, every}); return id; };
  const cancel = id => { const i = timers.findIndex(t => t.id === id); if (i >= 0) timers.splice(i, 1); };
  const ctx = {
    document, console, Date: FakeDate, JSON, Math, Intl, Promise, Number, String, Array, Object,
    setTimeout: (fn, ms) => later(fn, ms), clearTimeout: cancel,
    setInterval: (fn, ms) => later(fn, ms, ms), clearInterval: cancel,
    fetch: url => new Promise((resolve, reject) => fetches.push({url: String(url), at: now, resolve, reject, done: false})),
    localStorage: {getItem: () => null, setItem: () => {}}, history: {replaceState() {}},
    location: {hash: '', pathname: '/server/' + (o.serverId || 7)},
    getSelection: () => ({removeAllRanges() {}, addRange() {}}),
    serverId: o.serverId || 7, MOUNT: '', SERVER_NAME: 'srv', _CAN_MODERATE: false, _CAN_KICK: false,
    _CAN_BAN: false, _CAN_SAY: false, _CAN_VIEW_CONSOLE: o.canView !== false,
    t: s => s, toast: () => {}, confirmDialog: () => {}, escapeHtml: s => String(s), _da: () => '',
    copyText: () => {}, ensureSocket: () => socket,
    addEventListener: (e, f) => (winL[e] = winL[e] || []).push(f),
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  // panel.js's own pollWhenVisible, cut out of it, so the 30 s console poll runs as on a page.
  const panel = fs.readFileSync(o.panel, 'utf8');
  vm.runInContext(panel.slice(panel.indexOf('var _visPolls = {};'), panel.indexOf('window.stopPolling')), ctx);
  let loadError = null;
  try { vm.runInContext(o.code || fs.readFileSync(o.src, 'utf8'), ctx, {filename: 'server_detail.js'}); }
  catch (e) { loadError = String(e && e.stack || e); }
  const flush = async () => { for (let k = 0; k < 6; k++) await new Promise(r => setImmediate(r)); };
  async function advance(ms) {
    const end = now + ms;
    for (;;) {
      timers.sort((a, b) => a.at - b.at || a.id - b.id);
      const t = timers[0];
      if (!t || t.at > end) break;
      now = t.at;
      if (t.every) t.at += t.every; else timers.shift();
      try { t.fn(); } catch (e) { /* a page timer that throws is the page's own business */ }
      await flush();
    }
    now = end;
    await flush();
  }
  function fire(e, d) { (sock[e] || []).slice().forEach(f => f(d)); }
  const lineText = d => d._t + d.children.filter(c => !(c instanceof El && c.className === 'console-ts')).map(c => c.textContent).join('');
  const isGap = c => /\bconsole-gap\b/.test(c.className);
  return {
    ctx, socket, consoleEl, wsEl, emitted, fetches, loadError, document, flush, advance,
    get now() { return now; },
    nextTimerAt: () => timers.reduce((m, t) => Math.min(m, t.at), Infinity),
    async connect() {
      socket.connected = true;
      socket.pingExpired = false;            // a new engine, with a fresh ping deadline
      for (const [e, d, cb] of socket.sendBuffer.splice(0)) emitted.push([e, d, now, cb]);
      fire('connect');
      await flush();
    },
    async disconnect() { socket.connected = false; fire('disconnect', 'transport close'); await flush(); },
    async push(d) { fire('console_output', d); await flush(); },
    async event(e, d) { fire(e, d); await flush(); },
    // A browser runs the microtasks between one listener and the next (each is its own callback),
    // so a socket that closes on the first one's emit is closed when the second runs.
    async setHidden(h, quiet) {
      document.hidden = !!h; document.visibilityState = h ? 'hidden' : 'visible';
      if (!quiet) for (const f of (docL.visibilitychange || []).slice()) { f(); await flush(); }
      await flush();
    },
    async winEvent(e) { for (const f of (winL[e] || []).slice()) f({persisted: false}); await flush(); },
    async respond(f, body) { if (f.done) return; f.done = true; f.resolve({ok: true, status: 200, json: () => Promise.resolve(body)}); await flush(); },
    // Every line on the page, the "not everything is shown" notice included unless `gaps` is false.
    lines: gaps => consoleEl.children.filter(c => c instanceof El && (gaps !== false || !isGap(c))).map(lineText),
    gaps: () => consoleEl.children.filter(c => c instanceof El).map((c, i) => isGap(c) ? i : -1).filter(i => i >= 0),
    // Every line with the time in its gutter (data-ts), or null where it has none.
    stamped: () => consoleEl.children.filter(c => c instanceof El && !isGap(c)).map(c => [lineText(c), c.dataset.ts || null]),
  };
}


// ── the server's half: the poller, the room, the log, the backlog, the catch-up ─────────────────
// As panel/routes/server_files.py and _shared.py have it: a pass first forgets a console nobody
// watches. For a watched console it first answers a catch-up a join asked for (the page's own
// place in the log as `since`): the lines written since that place, cut where the poller stands —
// or, with no read state yet, at the log's end, which becomes where it stands (the first look). Then
// its tick: with no state, a FIRST SIGHT (the end recorded, nothing read); else the whole lines
// written since, pushed to whoever is in the room right then, each push with `at` = [chain, inode,
// position] (positions here are line counts). A log rotation starts a new chain. The window
// (/api/console) is the log's last N lines at the moment it is read, with the backlog; a panel push
// goes to the backlog and to the room; a leave is answered with where the poller stands.
// `manual`: nothing happens until the caller says so.
function rng(seed) {
  let s = (seed * 2654435761) >>> 0 || 1;
  return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 4294967296; };
}

const REACH = 8000;       // how far back (in lines, here) a catch-up from `since` reaches

function makeWorld(o) {
  const rand = rng(o.seed || 1), between = (a, b) => a + Math.floor(rand() * (b - a + 1));
  const page = makePage(o);
  const lat = Object.assign({join: [5, 150], push: [5, 200], read: [5, 600], resp: [5, 600], pass: [0, 900]}, o.lat || {});
  let log = [], lineNo = 0, offset = null, ino = 1, connected = false, seenFetch = 0, seenEmit = 0;
  let pushFree = 0, sockFree = 0, seq = 0, lastT = 0, chains = 0, catchup = null;
  const backlog = [], room = new Set(), events = [], readsAt = [], served = [];
  const stats = {reads: 0, firstSights: 0, pushes: 0, windowReads: 0, catchups: 0, waits: 0};
  const at = (t, fn) => events.push({at: t, seq: ++seq, fn});
  const nowS = () => page.now / 1000;
  const W = {page, log: () => log, backlog, room, stats, readsAt, rand, between, served, lastAt: null,
             failReads: 0, serveOff: false, answers: []};

  // What the server sends this page's socket, in the order it sends it (pushes, answers, acks).
  function send(fn) {
    if (!connected) return null;
    if (o.manual) return fn();
    pushFree = Math.max(page.now + between(...lat.push), pushFree);
    at(pushFree, async () => { if (connected) await fn(); });
    return null;
  }
  function deliver(payload) {
    if (!room.has('page')) return null;
    if (payload.at) W.lastAt = payload.at;
    return send(() => page.push(payload));
  }
  const backlogRows = () => backlog.map(b => ({t: b.t, line: b.line}));
  // A catch-up's answer: `since` honoured when it is in this log and within reach.
  function answer(req) {
    const C = offset.pos, s = req.since;
    let lines, since = false, gap = false;
    if (Array.isArray(s) && s[1] === offset.ino && s[2] <= C && C - s[2] <= REACH) { lines = log.slice(s[2], C); since = true; }
    else { lines = log.slice(Math.max(0, C - 2000), C); gap = Array.isArray(s); }
    if (lines.length > 2000) { lines = lines.slice(-2000); gap = true; }
    const body = {server_id: page.ctx.serverId, id: req.id, readable: true, lines: lines.map(l => ({t: null, line: l})),
                  at: [offset.chain, offset.ino, C], since, gap, now: nowS(), log_timestamps: false, panel_lines: backlogRows()};
    W.answers.push(body);
    return send(() => page.event('console_catchup', body));
  }
  // _serve_console_catchups: what it sent. A read that fails is tried on two more passes, then answered
  // `readable: false`; the tick goes on meanwhile.
  function serve() {
    const req = catchup;
    catchup = null;
    // _catchup_ahead: the page's place past where the poller stands in this log — it waits for the ticks.
    const s = req.since;
    if (!W.noWait && offset && Array.isArray(s) && s[1] === offset.ino && s[2] > offset.pos && (req.waits || 0) < 30) {
      catchup = Object.assign({}, req, {waits: (req.waits || 0) + 1});
      stats.waits++;
      return null;
    }
    stats.catchups++;
    if (W.failReads > 0 || (offset !== null && offset.ino !== ino)) {   // not read, or the log moved under it
      if (W.failReads > 0) W.failReads--;
      if (req.tries + 1 < 3) {
        if (!catchup) catchup = Object.assign({}, req, {tries: req.tries + 1});
        return null;
      }
      const body = {server_id: page.ctx.serverId, id: req.id, readable: false, lines: [], panel_lines: backlogRows()};
      W.answers.push(body);
      return send(() => page.event('console_catchup', body));
    }
    if (offset === null) offset = {ino, pos: log.length, chain: ++chains};
    return answer(req);
  }
  function tick() {
    if (offset === null) { offset = {ino, pos: log.length, chain: ++chains}; stats.firstSights++; return null; }
    if (offset.ino !== ino) offset = {ino, pos: 0, chain: ++chains};    // rotated: a new log, a new chain
    const lines = log.slice(offset.pos);
    offset.pos = log.length;
    if (!lines.length) return null;
    stats.pushes++;
    return deliver({server_id: page.ctx.serverId, data: lines.join('\n'), rows: lines.map(l => ({t: null, line: l})),
                    ts: nowS(), at: [offset.chain, offset.ino, offset.pos]});
  }
  const settle = list => { const p = list.filter(x => x && typeof x.then === 'function'); return p.length ? Promise.all(p) : null; };
  // One pass: the catch-ups asked for, then the tick. `serve: false` is a pass that had already gone
  // past this console's catch-ups when the join landed (the join came in during the pass).
  W.pass = function (opts) {
    if (room.size === 0) { offset = null; catchup = null; return null; }
    stats.reads++; readsAt.push(page.now);
    const sent = [];
    if (catchup && !W.serveOff && !(opts && opts.serve === false)) sent.push(serve());
    sent.push(tick());
    return settle(sent);
  };
  W.tick = () => W.pass({serve: false});
  W.body = function (url) {
    const m = /lines=(\d+)/.exec(url), n = m ? Number(m[1]) : 250;
    stats.windowReads++;
    if (/[?&]place=1/.test(url)) {        // a return's read with the socket down: from the page's place, to the end
      const sm = /since=(\d+)-(\d+)/.exec(url), C = log.length;
      const s = sm ? [Number(sm[1]), Number(sm[2])] : null;
      let lines, since = false, gap = false;
      if (s && s[0] === ino && s[1] <= C && C - s[1] <= REACH) { lines = log.slice(s[1], C); since = true; }
      else { lines = log.slice(Math.max(0, C - 2000), C); gap = !!s; }
      if (lines.length > 2000) { lines = lines.slice(-2000); gap = gap || since; }
      return {lines: lines.map(l => ({t: null, line: l})), at: [0, ino, C], since, gap, now: nowS(), readable: true,
              log_timestamps: false, panel_lines: backlogRows()};
    }
    return {lines: log.slice(-n).map(l => ({t: null, line: l})), now: nowS(), readable: true,
            log_timestamps: false, panel_lines: backlogRows()};
  };
  function onEmit(ev, d, cb) {
    if (!connected) return;
    if (ev === 'join_console') {
      room.add('page');
      // _catchup_request: an id that is not a positive whole number is no request at all.
      const c = d && d.catchup;
      if (c && Number.isInteger(c.id) && c.id > 0) {
        catchup = {id: c.id, since: c.since || null, tries: 0};
        if (W.serveOnJoin) { W.serveOnJoin = false; W.pass(); }   // a pass that ran just after this join
      }
    }
    if (ev === 'leave_console') {
      const was = room.has('page');
      room.delete('page');
      catchup = null;
      const ack = was && offset ? [offset.chain, offset.ino, offset.pos] : null;
      if (cb) send(() => { cb(ack); return page.flush(); });
    }
  }
  function scan() {
    for (; seenEmit < page.emitted.length; seenEmit++) {
      const [ev, d, sentAt, cb] = page.emitted[seenEmit];
      if (o.manual) { onEmit(ev, d, cb); continue; }
      sockFree = Math.max(sentAt + between(...lat.join), sockFree);
      at(sockFree, () => onEmit(ev, d, cb));
    }
    if (o.manual) return;
    for (; seenFetch < page.fetches.length; seenFetch++) {
      const f = page.fetches[seenFetch];
      if (f.url.indexOf('/api/console/') < 0) continue;     // stats, version…: never answered
      at(f.at + between(...lat.read), () => {
        const body = W.body(f.url);
        at(page.now + between(...lat.resp), () => page.respond(f, body));
      });
    }
  }
  function schedulePass() { at(page.now + 2000 + between(...lat.pass), () => { W.pass(); schedulePass(); }); }
  W.step = async function (ms) {
    const end = page.now + ms;
    for (;;) {
      scan();
      events.sort((a, b) => a.at - b.at || a.seq - b.seq);
      const e = events[0], tPage = page.nextTimerAt(), tWorld = e ? Math.max(e.at, page.now) : Infinity;
      if (Math.min(tPage, tWorld) > end) break;
      if (tPage <= tWorld) { await page.advance(Math.max(0, tPage - page.now)); continue; }
      events.shift();
      if (e.at > page.now) await page.advance(e.at - page.now);
      await e.fn();
    }
    if (end > page.now) await page.advance(end - page.now);
    scan();
  };
  W.write = k => { for (let i = 0; i < k; i++) log.push('L' + String(++lineNo).padStart(5, '0') + ' line'); };
  // Lines a real console repeats word for word ("Saving chunks", "Player count: 0"): no number.
  W.say = (...texts) => { for (const t of texts) log.push('L00000 ' + t); };
  W.rotate = k => { log = []; ino++; W.write(k); };
  W.panelPush = function (text) {
    lastT = Math.max(nowS(), lastT + 0.0001);    // time.time(): later pushes, later times
    const t = lastT;
    for (const ln of text.split('\n')) if (ln.trim()) backlog.push({t, line: ln});
    return deliver({server_id: page.ctx.serverId, data: text, ts: t, panel: true});
  };
  W.start = async function () {
    if (!o.manual) schedulePass();
    connected = true;
    await page.connect();
    scan();
    if (o.manual) { const f = W.pending()[0]; if (f) await W.answer(f); } else await W.step(3000);
  };
  W.disconnect = async () => { connected = false; room.delete('page'); catchup = null; await page.disconnect(); scan(); };
  W.reconnect = async () => { connected = true; await page.connect(); scan(); };
  // The server dropped the page's socket while the page was frozen (a phone asleep past the ping
  // timeout): out of the room, while the page — which has not run since — still thinks it is
  // connected, until its next emit finds the ping expired.
  W.expire = () => { connected = false; room.delete('page'); catchup = null; page.socket.pingExpired = true; };
  W.hide = async (h, quiet) => { await page.setHidden(h, quiet); scan(); };
  W.advance = async ms => { await page.advance(ms); scan(); };
  W.other = (on) => { if (on) room.add('other'); else room.delete('other'); };
  // manual mode: the window reads, one by one, in the order the test says
  W.pending = re => page.fetches.filter(f => !f.done && f.url.indexOf('/api/console/') >= 0 && (!re || re.test(f.url)));
  W.read = f => { const b = W.body(f.url); served.push(f.url); return {f, b}; };
  W.reply = async (rd) => { await page.respond(rd.f, rd.b); scan(); };
  W.answer = async f => W.reply(W.read(f));
  // The 30 s console poll, which pollWhenVisible also runs on a return: its 250-line window, answered.
  W.settlePolls = async () => { for (const f of W.pending()) if (f.url === '/api/console/' + page.ctx.serverId) await W.answer(f); };
  // Every read the page has asked for answered, and the poller's pass: as a page that comes back
  // (with either way of catching up) finds it.
  W.settle = async (rounds) => {
    for (let i = 0; i < (rounds || 3); i++) { for (const f of W.pending()) await W.answer(f); await W.pass(); await W.advance(7000); }
  };
  // Every read the page has asked for answered, then a pass: whichever way the page catches up.
  W.passAll = async () => { for (const f of W.pending()) await W.answer(f); return W.pass(); };
  W.pageLog = () => page.lines(false).filter(l => /^L\d{5}/.test(l));
  W.pagePanel = () => page.lines(false).filter(l => !/^L\d{5}/.test(l));
  W.exact = () => JSON.stringify(W.pageLog()) === JSON.stringify(log);
  W.emits = name => page.emitted.filter(e => e[0] === name).length;
  W.asks = () => page.emitted.filter(e => e[0] === 'join_console' && e[1] && e[1].catchup).map(e => e[1].catchup);
  W.atNow = () => offset && [offset.chain, offset.ino, offset.pos];
  return W;
}

// ── checks ───────────────────────────────────────────────────────────────────────────────────────
const results = [];
const check = (name, ok, detail) => results.push({name, ok: !!ok, detail: ok ? '' : String(detail || '').slice(0, 600)});
const GRACE = 30000;

async function manualWorld(cfg, extra) {
  const w = makeWorld(Object.assign({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code}, extra || {}));
  w.write(20);
  await w.start();
  return w;
}

// Away for longer than the grace while the log grows; back in view. Returns the world.
async function awayAndBack(cfg, extra, whileAway) {
  const w = await manualWorld(cfg, extra);
  w.pass(); w.write(2); await w.pass();
  await w.hide(true); await w.advance(GRACE);
  w.pass();
  w.write(5);
  if (whileAway) await whileAway(w);
  await w.hide(false);
  await w.settlePolls();
  return w;
}

async function checkLoad(cfg) {
  const w = await manualWorld(cfg);
  check('the page script runs whole in the harness, joins its console on connect and primes from the window',
        !w.page.loadError && w.emits('join_console') === 1 && w.exact(), w.page.loadError || JSON.stringify(w.pageLog()));
}

async function checkGrace(cfg) {
  const w = await manualWorld(cfg);
  const fetched = w.page.fetches.length;
  await w.hide(true);
  await w.advance(GRACE - 100);
  const early = w.emits('leave_console');
  await w.advance(100);
  const leaves = w.page.emitted.filter(e => e[0] === 'leave_console');
  check('a tab hidden for the 30 s grace leaves its console ONCE, with its server id — and not a moment before',
        early === 0 && leaves.length === 1 && leaves[0][1].server_id === 7 && w.page.fetches.length === fetched,
        JSON.stringify({early, leaves: leaves.map(e => e[1]), fetched: w.page.fetches.slice(fetched).map(f => f.url)}));
  w.pass();
  const reads = w.stats.reads;
  w.write(3); w.pass(); w.pass();
  check('...and the server reads nothing more for it (its room is empty)', w.stats.reads === reads && w.room.size === 0,
        JSON.stringify({reads, after: w.stats.reads, room: [...w.room]}));
}

async function checkAltTab(cfg) {
  const w = await manualWorld(cfg);
  w.pass();
  const emitted = w.page.emitted.length, fetched = w.page.fetches.length;
  await w.hide(true); await w.advance(20000); await w.hide(false);
  w.write(3); await w.pass();
  check('hidden for less than the grace (an alt-tab, a notification): nothing is sent, no catch-up is asked or read, and '
        + 'pushes go on landing as before', w.page.emitted.length === emitted
        && !w.page.fetches.slice(fetched).some(f => /lines=2000/.test(f.url)) && w.exact() && w.room.has('page'),
        JSON.stringify({emits: w.page.emitted.slice(emitted).map(e => e[0]), fetches: w.page.fetches.slice(fetched).map(f => f.url)}));
}

async function checkReturn(cfg) {
  const w = await awayAndBack(cfg);
  const joins = w.page.emitted.filter(e => e[0] === 'join_console'), asks = w.asks();
  check('back in view: ONE join_console, asking with it to be caught up from where the page\'s last pushed line ends in '
        + 'the log — and the page reads nothing from the log itself',
        joins.length === 2 && asks.length === 1 && JSON.stringify(asks[0].since) === JSON.stringify(w.lastAt)
        && w.pending(/lines=2000/).length === 0,
        JSON.stringify({joins: joins.map(e => e[1]), lastAt: w.lastAt, pending: w.pending().map(f => f.url)}));
  await w.pass();
  check('...which the poller answers on its next pass: everything written while the tab was away, after what it '
        + 'already showed, each line once — and the catch-up is over', w.exact() && !w.page.ctx._resync
        && !w.page.ctx._returnOwed, JSON.stringify({got: w.pageLog().slice(-8), want: w.log().slice(-8)}));
}

// The poller's stream goes on from exactly where the answer was cut: lines written before the pass,
// at it and after it each show once, however the writes and passes fall.
async function checkStreamFromCut(cfg) {
  for (const [label, before, after] of [['nothing more written before the pass', 0, 2], ['lines written before the pass', 3, 2],
                                        ['a quiet console after the answer', 3, 0]]) {
    const w = await awayAndBack(cfg);
    w.write(before);
    await w.pass();                            // the answer, cut at the end: the poller's first look
    w.write(after); await w.pass();
    await w.advance(60000);
    w.write(1); await w.pass();
    check('back in view, ' + label + ': every line once, in order, the stream going on from the answer\'s cut',
          w.exact() && !w.page.ctx._resync, JSON.stringify({got: w.pageLog().slice(-8), want: w.log().slice(-8)}));
  }
}

// Another tab keeps the console watched, so the poller's place and its stream go on: a push to the
// room can reach the page after its join and BEFORE the answer (the join landed in a pass that had
// already gone past this console's catch-ups). It lies before the answer's cut, so it is dropped.
async function checkOtherTab(cfg) {
  const w = await manualWorld(cfg);
  w.other(true);
  w.pass(); w.write(2); await w.pass();
  await w.hide(true); await w.advance(GRACE);
  const reads = w.stats.reads;
  w.write(4); w.pass(); w.write(3); w.pass();
  check('another tab still watching: the server goes on reading for it, and the tab that left receives nothing',
        w.stats.reads === reads + 2 && w.pageLog().length === 22, JSON.stringify({reads, now: w.stats.reads, shown: w.pageLog().length}));
  await w.hide(false);
  w.write(2); await w.tick();                // reaches the page before the answer: held
  const held = w.page.ctx._resync ? w.page.ctx._resync.held.length : -1;
  w.write(1); await w.pass();                // the answer, cut where the poller stands (past that push), then a push
  w.write(1); await w.pass();
  check('...and back in view it rejoins mid-stream: a push that came before the answer lies before its cut and is '
        + 'dropped; everything, once, in order', held === 1 && w.exact(),
        JSON.stringify({held, got: w.pageLog().slice(-9), want: w.log().slice(-9)}));
  w.other(false);
}

// No one else watching, and the join lands while a pass is under way: that pass takes the first look
// (the page asked too late for it to be caught up there), and the next one answers from it.
async function checkFirstLookFirst(cfg) {
  const w = await awayAndBack(cfg);
  w.write(2);
  await w.tick();                            // a first look: records the end, nothing pushed
  w.write(3);
  await w.pass();                            // the answer cut at that first look, then the three pushed
  w.write(1); await w.pass();
  check('the join landing after a pass had gone past its catch-ups: that pass\'s first look is where the next pass '
        + 'answers from, and every line shows once, in order', w.exact() && !w.page.ctx._resync,
        JSON.stringify({got: w.pageLog().slice(-8), want: w.log().slice(-8)}));
}

async function checkDropWhileCatchingUp(cfg) {
  for (const back of [true, false]) {
    const w = await awayAndBack(cfg);
    await w.panelPush('[panel] backup finished successfully.');   // held, with the answer still to come
    await w.disconnect();                       // the link drops before the poller's pass answers
    w.write(3);
    if (back) {
      await w.reconnect();
      await w.pass();
      w.write(2); await w.pass();
    } else {
      await w.advance(GRACE);                   // still down at the next 30 s console poll
      for (const f of w.pending()) await w.answer(f);
    }
    check('a socket that drops before the catch-up\'s answer abandons that catch-up: '
          + (back ? 'the reconnect asks to be caught up again' : 'still down, the 30 s console poll reads the log')
          + ', and the console shows everything, once — the panel line it held among it',
          !w.page.ctx._resync && w.exact() && w.pagePanel().indexOf('[panel] backup finished successfully.') >= 0,
          JSON.stringify({resync: !!w.page.ctx._resync, got: w.pageLog().slice(-8), want: w.log().slice(-8),
                          panel: w.pagePanel()}));
  }
}

// An answer that never comes (the poller stuck on this console's host): the console is not held forever.
async function checkGiveUp(cfg) {
  const w = await awayAndBack(cfg);
  w.serveOff = true;
  w.pass(); w.write(2); await w.pass();     // held, behind an answer that never comes
  await w.advance(44000);
  const held = w.pageLog().length;
  await w.advance(1000);
  w.write(1); await w.pass();
  const got = w.pageLog(), gaps = w.page.gaps(), lines = w.page.lines();
  check('a catch-up whose answer never comes is given up after 45 s: what it held is shown, once, under a notice that '
        + 'the time away is missing, and pushes land as they come again', held === 22 && !w.page.ctx._resync
        && JSON.stringify(got.slice(-3)) === JSON.stringify(w.log().slice(-3)) && new Set(got).size === got.length
        && gaps.length === 1 && lines[gaps[0] + 1] === w.log()[w.log().length - 3],
        JSON.stringify({held, resync: !!w.page.ctx._resync, gaps, got: got.slice(-5), want: w.log().slice(-5)}));
}

async function checkHiddenAgain(cfg) {
  const w = await awayAndBack(cfg);
  await w.panelPush('[panel] validate finished successfully.');   // held until the answer
  await w.hide(true); await w.advance(GRACE);
  check('hidden again before the catch-up\'s answer: the panel line it was holding is shown, not lost, and the tab '
        + 'leaves again', w.pagePanel().indexOf('[panel] validate finished successfully.') >= 0
        && w.emits('leave_console') === 2 && !w.page.ctx._resync,
        JSON.stringify({panel: w.pagePanel(), leaves: w.emits('leave_console')}));
  w.write(4);
  await w.hide(false); await w.settlePolls();
  await w.pass(); w.write(1); await w.pass();
  check('...and back in view again it is caught up from the same place as before, every line once',
        w.exact() && JSON.stringify(w.asks()[1].since) === JSON.stringify(w.asks()[0].since),
        JSON.stringify({asks: w.asks(), got: w.pageLog().slice(-6), want: w.log().slice(-6)}));
}

async function checkReconnectWhilePaused(cfg) {
  let joinsAway = -1, inRoom = true;
  const w = await awayAndBack(cfg, null, async x => {
    await x.disconnect();
    x.write(2);
    await x.reconnect();
    x.write(1); x.pass();
    joinsAway = x.emits('join_console'); inRoom = x.room.has('page');
  });
  check('a socket that drops and comes back while the tab is away does NOT rejoin (that read is what leaving stopped)',
        joinsAway === 1 && !inRoom, JSON.stringify({joinsAway, inRoom}));
  await w.pass(); w.write(2); await w.pass();
  check('...and back in view it joins once and shows everything, once, in order', w.emits('join_console') === 2 && w.exact(),
        JSON.stringify({got: w.pageLog().slice(-8), want: w.log().slice(-8)}));
}

async function checkDropBeforeGrace(cfg) {
  const w = await manualWorld(cfg);
  await w.hide(true);
  await w.advance(10000);
  await w.disconnect();
  await w.advance(GRACE);
  const leaves = w.emits('leave_console');
  await w.reconnect();
  check('the grace running out while the socket is down sends nothing, and the reconnect while still hidden does '
        + 'not rejoin', leaves === 0 && w.emits('join_console') === 1 && !w.room.has('page'),
        JSON.stringify(w.page.emitted.map(e => e[0])));
  w.write(3); w.pass();
  await w.hide(false);
  await w.settle();
  w.write(1); await w.pass();
  check('...and back in view it joins and shows everything, once', w.emits('join_console') === 2 && w.exact(),
        JSON.stringify({got: w.pageLog().slice(-6), want: w.log().slice(-6)}));
}

async function checkAction(cfg) {
  const w = await manualWorld(cfg);
  await w.panelPush('[panel] update started — its output follows.');
  await w.hide(true);
  await w.advance(4 * GRACE);
  const during = w.emits('leave_console');
  await w.panelPush('ACT downloading');
  await w.panelPush('[panel] update finished successfully.');
  await w.advance(GRACE);
  check('a long action this page saw start keeps a hidden tab in its console (its output stays live and dated as it '
        + 'is written); once it has ended the tab leaves within one more grace',
        during === 0 && w.emits('leave_console') === 1, JSON.stringify({during, after: w.emits('leave_console')}));
  const v = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code});
  v.write(5); await v.start();
  await v.panelPush('[panel] validate started — its output follows.');
  await v.advance(6 * 3600 * 1000 + 1000);
  await v.hide(true); await v.advance(GRACE);
  check('...but a start older than six hours whose end never arrived no longer holds it in', v.emits('leave_console') === 1,
        JSON.stringify(v.page.emitted.map(e => e[0])));
}

async function checkFinishedAway(cfg) {
  const w = await awayAndBack(cfg, null, async x => {
    x.panelPush('[panel] update started — its output follows.');
    x.panelPush('ACT line one\nACT line two');
    x.panelPush('[panel] update finished successfully.');
  });
  const v0 = versions(w);
  await w.panelPush('[panel] backup started — its output follows.');   // after the rejoin: on the socket, held…
  await w.pass();                                                      // …and in the answer's backlog too
  await w.advance(600);
  check('an update that ran and finished while the tab was away: its lines appear once, in order, the version is '
        + 're-read, and a panel push that came after the return lands after them',
        JSON.stringify(w.pagePanel()) === JSON.stringify(w.backlog.map(b => b.line)) && versions(w) === v0 + 1,
        JSON.stringify({got: w.pagePanel(), versions: versions(w) - v0}));
  const dup = w.backlog[w.backlog.length - 2];
  await w.page.push({server_id: 7, data: dup.line, ts: dup.t, panel: true});
  check('...and a push of a line already shown from the backlog is not shown again',
        w.pagePanel().length === w.backlog.length, JSON.stringify(w.pagePanel()));
}

async function checkBackground(cfg) {
  const w = await manualWorld(cfg, {hidden: true});
  await w.advance(GRACE);
  check('a page opened in a background tab leaves its console after the grace, with no visibility event at all',
        w.emits('leave_console') === 1, JSON.stringify(w.page.emitted.map(e => e[0])));
}

// The grace timer must fire BETWEEN two ticks of the 30 s console poll: a tick that runs while the
// tab is in view clears a pending timer itself, and would hide what this check is for.
async function checkLateTimer(cfg) {
  const w = await manualWorld(cfg);
  await w.advance(5000);
  await w.hide(true);                       // the timer is due at 35 s; the poll ticks at 30 s and 60 s
  await w.advance(26000);                   // 31 s: the 30 s tick has passed, the tab still hidden
  await w.page.setHidden(false, true);      // visible again, but the page was frozen: no event
  await w.advance(4000);                    // 35 s: the frozen page's timer fires late
  check('a grace timer a frozen page fires after it is visible again leaves nothing',
        w.emits('leave_console') === 0 && w.room.has('page'), JSON.stringify(w.page.emitted.map(e => e[0])));
}

async function checkFocusFallback(cfg) {
  const w = await manualWorld(cfg);
  await w.hide(true); await w.advance(GRACE);
  await w.hide(false, true);                  // visible again, but no visibilitychange reached the page
  const quiet = w.emits('join_console');
  await w.page.winEvent('focus');
  check('a return the browser reports only as focus (no visibilitychange) still rejoins and asks to be caught up',
        w.emits('leave_console') === 1 && quiet === 1 && w.emits('join_console') === 2 && w.asks().length === 1,
        JSON.stringify({emits: w.page.emitted.map(e => e[0]), asks: w.asks()}));
}

async function checkSilentReturn(cfg) {
  const w = await manualWorld(cfg);
  await w.hide(true); await w.advance(GRACE);
  await w.hide(false, true);                  // in view, but neither visibilitychange nor focus came
  await w.advance(GRACE - 1);
  const before = w.emits('join_console');
  await w.advance(1);
  check('a return no event announced is noticed by the 30 s console poll, which rejoins and asks to be caught up',
        w.emits('leave_console') === 1 && before === 1 && w.emits('join_console') === 2 && w.asks().length === 1,
        JSON.stringify({emits: w.page.emitted.map(e => [e[0], e[2]]), asks: w.asks()}));
}

async function checkNoConsole(cfg) {
  const w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code, console: false});
  w.write(3); await w.start();
  await w.hide(true); await w.advance(GRACE);
  const left = w.emits('leave_console');
  await w.hide(false);
  check('a page with its console panel hidden (in the room only for the update marker) leaves too, and back in view '
        + 'rejoins — asking for no catch-up — and re-reads the game version instead of reading the log',
        left === 1 && w.emits('join_console') === 2 && w.asks().length === 0
        && w.page.fetches.filter(f => /\/version$/.test(f.url)).length === 2
        && w.page.fetches.filter(f => /\/api\/console\//.test(f.url)).length === 0,
        JSON.stringify({emits: w.page.emitted.map(e => e[0]), fetches: w.page.fetches.map(f => f.url)}));
}

async function checkNoView(cfg) {
  const w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code, canView: false});
  await w.start();
  await w.hide(true); await w.advance(GRACE); await w.hide(false);
  check('a viewer without view_console never joins, so never leaves or rejoins', w.page.emitted.length === 0,
        JSON.stringify(w.page.emitted.map(e => e[0])));
}

async function checkIndicator(cfg) {
  const w = await manualWorld(cfg);
  const seen = [w.page.wsEl.textContent];
  await w.hide(true); await w.advance(GRACE); seen.push(w.page.wsEl.textContent);
  await w.hide(false); seen.push(w.page.wsEl.textContent);
  await w.disconnect(); seen.push(w.page.wsEl.textContent);
  await w.reconnect(); seen.push(w.page.wsEl.textContent);
  check('the console\'s connection indicator is the socket\'s, as before: leaving and rejoining the room does not '
        + 'change it, a dropped socket still reads (disconnected)',
        JSON.stringify(seen) === JSON.stringify(['(connected)', '(connected)', '(connected)', '(disconnected)', '(connected)']),
        JSON.stringify(seen));
}

async function checkBacklogOnce(cfg) {
  const w = await manualWorld(cfg);
  await w.panelPush('[panel] update started — its output follows.');
  await w.panelPush('ACT Downloading\nACT Done');
  await w.panelPush('[panel] update finished successfully.');
  w.write(1); await w.pass();
  await w.advance(30000);
  for (const f of w.pending()) await w.answer(f);
  check('a page opened while the panel backlog was EMPTY shows an update\'s lines once: the next 30 s poll, whose '
        + 'backlog holds them, does not append the whole update again',
        JSON.stringify(w.pagePanel()) === JSON.stringify(w.backlog.map(b => b.line)), JSON.stringify(w.pagePanel()));
}

async function checkRotation(cfg) {
  const w = await awayAndBack(cfg, null, async x => { x.rotate(6); });
  await w.pass(); w.write(2); await w.pass();
  const got = w.pageLog(), fresh = w.log(), gaps = w.page.gaps(), lines = w.page.lines();
  check('a server restarted while the tab was away (LinuxGSM rotated the log): the new log follows what was shown, '
        + 'every line once and in order, under a notice that the old log\'s last lines are not shown',
        JSON.stringify(got.slice(-fresh.length)) === JSON.stringify(fresh) && new Set(got).size === got.length
        && gaps.length === 1 && lines[gaps[0] + 1] === fresh[0],
        JSON.stringify({got: got.slice(-10), fresh, gaps}));
}

// ── review round 2 ───────────────────────────────────────────────────────────────────────────────
// A page opened during an update, the poller's push arriving BEFORE the first /api/console answer:
// that answer's wipe takes the push off the page, and the backlog must then be rendered whole.
async function checkPrimeAfterPush(cfg) {
  for (const startPushed of [false, true]) {
    const w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code});
    w.write(20);
    if (!startPushed) { w.panelPush('[panel] update started — its output follows.'); w.panelPush('ACT early 1\nACT early 2'); }
    await w.reconnect();                       // the page's first connect: it joins
    await w.panelPush(startPushed ? '[panel] update started — its output follows.' : 'ACT live 3');
    for (const f of w.pending()) await w.answer(f);
    const panel = w.pagePanel();
    await w.hide(true); await w.advance(GRACE + 1000);
    const during = w.emits('leave_console');
    await w.panelPush('[panel] update finished successfully.');
    await w.advance(GRACE);
    const what = startPushed ? 'its start marker' : 'a line of its output';
    check('a page opened mid-update, with ' + what + ' pushed before the first window answered: the update\'s '
          + 'lines all show, once, in order, and a hidden tab stays in until the update ends, then leaves',
          JSON.stringify(panel) === JSON.stringify(w.backlog.slice(0, -1).map(b => b.line))
          && during === 0 && w.emits('leave_console') === 1,
          JSON.stringify({panel, backlog: w.backlog.map(b => b.line), during, after: w.emits('leave_console'),
                          starts: w.page.ctx._actionStarts}));
  }
}

// Away past the grace while the log grows by `n` lines and an update runs start to end; the
// socket alive. Returns the world, just before the return.
async function awayLong(cfg, n) {
  const w = await manualWorld(cfg);
  w.panelPush('[panel] backup started — its output follows.'); w.panelPush('[panel] backup finished successfully.');
  await w.advance(30000);                       // the 30 s poll: the backlog shown, as on any page
  for (const f of w.pending()) await w.answer(f);
  w.pass(); w.write(2); await w.pass();
  await w.hide(true); await w.advance(GRACE);
  w.pass();
  w.write(n);
  w.panelPush('[panel] update started — its output follows.'); w.panelPush('ACT got it'); w.panelPush('[panel] update finished successfully.');
  return w;
}
const versions = w => w.page.fetches.filter(f => /\/version$/.test(f.url)).length;

// A phone unlocked after a long sleep: the server dropped the socket meanwhile, the page's first emit
// (the return's join) finds socket.io's ping expired, is kept for the reconnect, and the socket closes.
async function checkUnlockExpired(cfg) {
  const w = await awayLong(cfg, 300);
  w.expire();
  const v0 = versions(w);
  await w.hide(false);
  for (const f of w.pending()) await w.answer(f);
  await w.advance(600);
  const down = {connected: w.page.socket.connected, exact: w.exact(), panel: w.pagePanel(), versions: versions(w) - v0};
  check('unlocked after the server dropped the socket (socket.io keeps the return\'s join and closes): with the '
        + 'socket still down, the time away — 300 lines and an update — is filled in once, and the version re-read',
        !down.connected && down.exact && JSON.stringify(down.panel) === JSON.stringify(w.backlog.map(b => b.line))
        && down.versions === 1,
        JSON.stringify({down: Object.assign({}, down, {panel: down.panel.length}), got: w.pageLog().slice(-4), backlog: w.backlog.length}));
  const still = [];
  for (let k = 0; k < 2; k++) {               // the socket stays down: each 30 s poll reads the log on
    w.write(40);
    await w.advance(GRACE);
    for (const f of w.pending()) await w.answer(f);
    still.push(w.exact());
  }
  check('...and while it stays down, each 30 s console poll goes on filling in from the log',
        JSON.stringify(still) === '[true,true]' && !w.page.socket.connected,
        JSON.stringify({still, got: w.pageLog().slice(-3), want: w.log().slice(-3)}));
  await w.reconnect();
  await w.settle();
  w.write(2); await w.pass();
  check('...and once it reconnects, the kept join is sent, the page is caught up, and the console goes on from there, '
        + 'each line once', w.room.has('page') && w.exact() && w.page.ctx._resync === null && !w.page.ctx._returnOwed,
        JSON.stringify({room: [...w.room], got: w.pageLog().slice(-5), want: w.log().slice(-5)}));
}

// The same, with the host slow: the read asked with the socket down never answers, and is given up
// after 45 s — while the socket is still down, so the return is still owed to the reconnect.
async function checkGiveUpWhileDown(cfg) {
  const w = await awayLong(cfg, 300);
  w.expire();
  await w.hide(false);
  const hung = w.pending();
  await w.advance(46000);
  const gaveUp = w.page.ctx._resync === null;
  const asked = w.asks().length;
  await w.reconnect();
  const asks = w.asks().slice(asked);
  for (const f of w.pending()) if (hung.indexOf(f) < 0) await w.answer(f);
  await w.pass(); w.write(2); await w.pass();
  check('a read of the time away that never answers while the socket is down is given up, and the reconnect still '
        + 'asks to be caught up from the page\'s own place: 300 lines and an update, each once', gaveUp
        && asks.length >= 1 && JSON.stringify(asks[asks.length - 1].since) === JSON.stringify(w.asks()[0].since)
        && w.exact() && JSON.stringify(w.pagePanel()) === JSON.stringify(w.backlog.map(b => b.line)),
        JSON.stringify({gaveUp, asks, shown: w.pageLog().length, want: w.log().length}));
}

// Once a return has caught up and the page is back in step, the console is the one it always was: a
// socket that drops and comes back afterwards gets the plain reconnect catch-up, as before.
async function checkInStepAfterReturn(cfg) {
  const w = await awayAndBack(cfg);
  await w.pass(); w.write(2); await w.pass();
  w.write(1); await w.pass();
  const inStep = !w.page.ctx._resync && !w.page.ctx._returnOwed && w.exact();
  const joined = w.page.emitted.length;
  const place = w.page.ctx._logAt;
  await w.disconnect(); w.pass(); w.write(2);
  await w.reconnect();
  const reads = w.pending().map(f => f.url), joins = w.page.emitted.slice(joined).map(e => e[1]);
  await w.pass(); w.write(1); await w.pass();
  check('a return that has caught up leaves the console in step: a later reconnect is caught up as any reconnect is, '
        + 'from the end of the last push the page showed, with no window read — and shows what was written meanwhile, once',
        inStep && reads.length === 0 && joins.length === 2 && JSON.stringify(joins[0]) === JSON.stringify({server_id: 7})
        && JSON.stringify(joins[1].catchup.since) === JSON.stringify(place) && w.exact(),
        JSON.stringify({inStep, reads, joins, place, exact: w.exact()}));
}

// The socket drops after the return's join but before its answer (and the 30 s poll's own window
// answers while it is down): the reconnect owes the return's catch-up, not a plain one.
async function checkDropBeforeAnswer(cfg) {
  const w = await awayLong(cfg, 300);
  const v0 = versions(w);
  await w.hide(false);
  const polls = w.pending();
  await w.disconnect();
  for (const f of polls) await w.answer(f);     // the 30 s poll's window, answered with the socket down
  await w.reconnect();
  const asks = w.asks();
  await w.pass(); w.write(2); await w.pass();
  await w.advance(600);
  check('a socket that drops before the return\'s answer: the reconnect asks to be caught up again, from the same '
        + 'place — 300 lines and an update, each once, in order, the version re-read — not the plain 250-line catch-up',
        asks.length === 2 && JSON.stringify(asks[1].since) === JSON.stringify(asks[0].since) && w.exact()
        && JSON.stringify(w.pagePanel()) === JSON.stringify(w.backlog.map(b => b.line)) && versions(w) - v0 === 1,
        JSON.stringify({asks, exact: w.exact(), shown: w.pageLog().length, want: w.log().length,
                        panel: w.pagePanel().length, backlog: w.backlog.length, versions: versions(w) - v0}));
}

// A plain reconnect, the tab in view the whole time: lines written while the socket was down, then a
// push that reaches the page BEFORE the reconnect's catch-up is answered (another tab kept the
// poller reading, or a slow read). Caught up with the 250-line window and the push appended as it
// came, the window no longer stitched to the page's end and was appended whole a second time.
// `other`: a second tab keeps the poller's place; without one the poller starts again from "now".
async function checkReconnectPushFirst(cfg) {
  for (const other of [true, false]) {
    const w = await manualWorld(cfg);
    w.other(other);
    w.pass(); w.write(2); await w.pass();
    await w.disconnect();
    w.write(5); w.pass();                          // written while the socket was down
    await w.reconnect();
    w.write(1); await w.tick();                    // pushed before the catch-up is answered
    for (const f of w.pending()) await w.answer(f);
    await w.pass(); w.write(1); await w.pass();
    const got = w.pageLog();
    check('a reconnect with the tab in view, a push arriving before its catch-up is answered (' + (other ? 'another '
          + 'tab keeping the poller\'s place' : 'nobody else watching') + '): the lines written while the socket was '
          + 'down show once, in order, and nothing twice', w.exact() && new Set(got).size === got.length
          && w.page.gaps().length === 0 && !w.page.ctx._resync && !w.page.ctx._returnOwed,
          JSON.stringify({got: got.slice(-10), want: w.log().slice(-10), shown: got.length, n: w.log().length,
                          gaps: w.page.gaps().length}));
    w.other(false);
  }
  // No answer ever comes: given up, under a notice that names the dropped connection — this tab was
  // in view the whole time, so the hidden-tab wording would be false here.
  const w = await manualWorld(cfg);
  w.pass(); w.write(2); await w.pass();
  await w.disconnect();
  w.write(3);
  w.serveOff = true;
  await w.reconnect();
  w.write(1); await w.pass();
  await w.advance(46000);
  const notice = w.page.lines().filter((l, i) => w.page.gaps().indexOf(i) >= 0);
  check('a reconnect\'s catch-up never answered: given up under a notice that says the connection dropped, not that '
        + 'the tab was in the background', notice.length === 1 && /connection/.test(notice[0])
        && !/background/.test(notice[0]) && !w.page.ctx._resync, JSON.stringify(notice));
}

// The first window is read, then a line is written and pushed, and the push reaches the page before
// the window's answer does (a phone: the bigger HTTP answer lands later). Adopting the window wiped
// the pushed line and nothing brought it back. And the other order: the push's line is IN the window
// (the read came after it was written) — it must not show twice.
async function checkPrimePushFirst(cfg) {
  for (const inWindow of [false, true]) {
    const w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code});
    w.write(20);
    await w.reconnect();                           // the page's first connect: it joins
    w.pass();                                      // the poller's first look
    let rd = null;
    if (!inWindow) rd = w.read(w.pending()[0]);    // the window read now...
    w.write(2); await w.pass();                    // ...two lines written and pushed...
    if (inWindow) rd = w.read(w.pending()[0]);
    await w.reply(rd);                             // ...and then the window's answer arrives
    w.write(1); await w.pass();
    const got = w.pageLog();
    check('a push that reaches the page before its first window does, ' + (inWindow ? 'its lines in that window'
          : 'written after the window was read') + ': every line shows, once, in order', w.exact()
          && new Set(got).size === got.length, JSON.stringify({got: got.slice(-6), want: w.log().slice(-6)}));
  }
  // Pushed, then a line more written (not pushed yet), then the window read: the window holds the
  // pushed lines but does not END with them. They are shown already, and must not be put back again.
  const w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code});
  w.write(20);
  await w.reconnect();
  w.pass();
  w.write(2); await w.pass();
  w.write(1);
  await w.reply(w.read(w.pending()[0]));
  const got = w.pageLog(), pushed = w.log().slice(20, 22);
  check('a push that reaches the page before its first window does, its lines inside that window with more after '
        + 'them: the pushed lines show once', pushed.every(l => got.filter(x => x === l).length === 1),
        JSON.stringify({got: got.slice(-6), pushed}));
}

// Clear, then Load older: the 2000-line history it shows must not be swapped for the 250-line window
// by the next 30 s poll, which took the cleared console as never primed.
async function checkLoadOlderAfterClear(cfg) {
  const w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code});
  w.write(400);
  await w.start();
  w.page.ctx.clearConsole();
  w.page.ctx.loadMoreConsole(null);
  for (const f of w.pending(/lines=2000/)) await w.answer(f);
  const loaded = w.pageLog().length;
  await w.advance(30000);
  for (const f of w.pending()) await w.answer(f);
  w.pass(); w.write(1); await w.pass(); w.write(1); await w.pass();
  check('Clear, then Load older: the 30 s poll keeps the history it loaded, and what follows shows after it',
        loaded === 400 && w.exact(), JSON.stringify({loaded, shown: w.pageLog().length, want: w.log().length}));
}

// Unlocked (the join kept for the reconnect), then locked again past the grace before the socket is
// back: on the reconnect socket.io sends the kept join first, so the paused tab must leave again.
async function checkReplayedJoin(cfg) {
  const w = await manualWorld(cfg);
  await w.hide(true); await w.advance(GRACE);
  w.pass();
  w.expire();
  await w.hide(false);
  await w.hide(true); await w.advance(GRACE);
  await w.reconnect();
  const reads = w.stats.reads;
  for (let i = 0; i < 4; i++) { w.write(1); w.pass(); }
  check('a join socket.io kept while the ping had expired, sent on reconnecting after the tab went back out of '
        + 'view: the paused tab leaves again, and nothing is read for it — its catch-up is not answered either',
        !w.room.has('page') && w.stats.reads === reads && w.page.ctx._consolePaused && w.stats.catchups === 0,
        JSON.stringify({room: [...w.room], reads: w.stats.reads - reads, catchups: w.stats.catchups,
                        emits: w.page.emitted.map(e => e[0])}));
  await w.hide(false);
  await w.settle();
  w.write(1); await w.pass();
  check('...and back in view it catches up exactly', w.exact() && w.room.has('page'),
        JSON.stringify({got: w.pageLog().slice(-6), want: w.log().slice(-6)}));
}

// Away for more lines than a return shows (2000): say so where they are missing.
async function checkLongAway(cfg) {
  const w = await awayAndBack(cfg, null, async x => { x.write(2100); });
  await w.pass();
  const want = w.log().slice(0, 22).concat(w.log().slice(-2000));
  const gaps = w.page.gaps(), lines = w.page.lines();
  check('away for more than the 2000 lines a return shows: one notice says some output is not shown, between what '
        + 'was shown and the 2000 lines that follow, and it is not part of the log copy',
        JSON.stringify(w.pageLog()) === JSON.stringify(want) && gaps.length === 1
        && /^L\d{5}/.test(lines[gaps[0] - 1] || '') && lines[gaps[0] + 1] === w.log()[w.log().length - 2000]
        && w.page.ctx._consoleLines.length === w.pageLog().length,
        JSON.stringify({gaps, around: lines.slice(Math.max(0, gaps[0] - 1), gaps[0] + 2), shown: w.pageLog().length}));
  const v = await awayAndBack(cfg);
  await v.pass();
  check('...and a return that reaches back far enough shows no such notice', v.page.gaps().length === 0 && v.exact(),
        JSON.stringify(v.page.gaps()));
}

// The page holds a HOLE: its socket dropped, and the reconnect's catch-up (as before this change)
// could not bring every line — more than its 250 written while down (a `seam`), or some written
// between its window and the poller's first look. Then the tab goes away and comes back: it is caught
// up from its own place, after the hole, and the hole changes nothing.
async function checkHoleThenAway(cfg) {
  for (const [label, down, between, after] of [['more than 250 lines while the socket was down', 400, 0, 0],
                                                ['3 lines lost to the reconnect\'s race, 30 shown since', 10, 3, 30],
                                                ['3 lines lost to the reconnect\'s race, 5 shown since', 10, 3, 5]]) {
    const w = await manualWorld(cfg);
    w.pass(); w.write(2); await w.pass();
    await w.disconnect(); w.pass(); w.write(down); await w.reconnect();
    for (const f of w.pending()) await w.answer(f);      // the reconnect's catch-up, as before
    w.write(between);
    w.pass();
    for (let i = 0; i < after; i++) { w.write(1); await w.pass(); }
    const lost = w.log().filter(l => w.pageLog().indexOf(l) < 0);
    await w.hide(true); await w.advance(GRACE);
    w.pass(); w.write(5);
    await w.hide(false); await w.settlePolls();
    await w.settle();
    w.write(1); await w.pass();
    const got = w.pageLog(), missing = w.log().filter(l => got.indexOf(l) < 0);
    check('a page with a hole in it (' + label + ') goes away and comes back: nothing is shown twice, and every '
          + 'line written since the hole is shown', new Set(got).size === got.length
          && JSON.stringify(missing) === JSON.stringify(lost) && w.page.gaps().length === 0,
          JSON.stringify({dups: got.length - new Set(got).size, missing: missing.length, lost: lost.length, gaps: w.page.gaps().length}));
  }
}

// A console repeats lines word for word. Nothing about a catch-up is decided by that text any more:
// the answer starts at the page's place in the log, and the stream goes on from the answer's cut.
// Matched by text (as before), a push that began with a line the time away had ended on was taken
// for the overlap, and every line of it before that line went unshown. Each step answers whatever
// read the page has asked for, so a page that catches up by reading the log is judged the same way.
async function awayQuiet(cfg, away) {
  const w = await manualWorld(cfg);
  w.pass(); w.write(2); await w.pass();
  await w.hide(true); await w.advance(GRACE);
  w.pass(); away(w);
  await w.hide(false); await w.settlePolls();
  await w.passAll();                                         // the time away shown; the poller has looked
  await w.advance(6000); await w.passAll();                  // quiet since: nothing more to read
  return w;
}

async function checkRepeats(cfg) {
  const SAVE = 'Saved the world.', CHAT = ['<Alice> anyone on?', '<Bob> yes, building the bridge'];
  for (const late of [15000, 0]) {
    const w = await awayQuiet(cfg, x => x.say(SAVE));
    await w.advance(late);
    w.say(...CHAT, SAVE); await w.passAll();
    w.write(1); await w.passAll();
    check('away while the game wrote one line it repeats ("' + SAVE + '"); ' + late / 1000 + ' s after it caught up a '
          + 'push of two chat lines and that line again: all three show, once each', w.exact() && !w.page.ctx._resync,
          JSON.stringify({got: w.pageLog().slice(-6), want: w.log().slice(-6)}));
  }
  const H = 'heartbeat: no players, skipping save';
  const w = await awayQuiet(cfg, x => { x.write(4); x.say(H); });
  await w.advance(15000);
  w.say(H); await w.passAll();
  w.write(1); await w.passAll();
  check('the time away ending on a heartbeat, and the next push that heartbeat again: it shows', w.exact(),
        JSON.stringify({got: w.pageLog().slice(-5), want: w.log().slice(-5)}));
  const v = await manualWorld(cfg);
  const block = ['Saving chunks', 'Saved the game', 'Player count: 0'];
  v.pass(); v.say(...block); await v.pass();
  await v.hide(true); await v.advance(GRACE);
  v.pass(); v.say(...block); v.say(...block);
  await v.hide(false); await v.settlePolls();
  v.say(...block); await v.tick();                           // the poller's first look comes first
  v.say(...block); await v.passAll();                        // the answer, cut at that look, then a push
  await v.advance(6000); await v.passAll();
  v.say(...block); v.write(1); await v.passAll();
  check('a periodic block written before, while and after the tab was away, the poller\'s first look between two '
        + 'copies of it: every copy shows, once', v.exact() && !v.page.ctx._resync,
        JSON.stringify({got: v.pageLog().slice(-8), want: v.log().slice(-8), shown: v.pageLog().length, log: v.log().length}));
}

// The same chat lines, held when the catch-up is given up: the page went on with the stream as it was,
// and matched what it held against what it had appended — losing the lines before the repeated one.
async function checkGiveUpHeld(cfg) {
  const SAVE = 'Saved the world.';
  const w = await manualWorld(cfg);
  w.pass(); w.write(2); await w.pass();
  await w.hide(true); await w.advance(GRACE);
  w.pass(); w.say(SAVE);
  await w.hide(false); await w.settlePolls();
  w.serveOff = true;                                         // no answer to the catch-up ever comes…
  for (const f of w.pending(/lines=2000/)) await w.answer(f);   // (…though a first read of the time away does)
  w.pass();
  await w.advance(6000);                                     // anything asked after this never answers
  await w.advance(15000);
  w.say('<Alice> anyone on?', '<Bob> yes, building the bridge', SAVE); await w.pass();
  await w.advance(30000);                                    // given up
  w.write(1); await w.pass();
  const got = w.pageLog(), tail = w.log().slice(-4);
  check('a catch-up given up while holding a push of two chat lines and a line the time away ended on: the push '
        + 'shows whole, then what follows', JSON.stringify(got.slice(-4)) === JSON.stringify(tail) && !w.page.ctx._resync,
        JSON.stringify({got: got.slice(-5), want: tail}));
}

// The leave is answered with where the poller stands. A page whose last lines came from a read and
// not a push — a quiet console, nothing pushed since the page opened — has no place of its own, and
// that answer is it: back in view it is caught up from there, not placed by its text (a console of
// nothing but a heartbeat could not be placed by text at all).
async function checkLeaveAnswer(cfg) {
  const H = 'heartbeat: 0 players online';
  const w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code});
  for (let i = 0; i < 30; i++) w.say(H);
  await w.start();
  w.pass();                                                  // the first look: nothing pushed, ever
  const before = w.page.ctx._logAt;
  await w.hide(true); await w.advance(GRACE);
  const at = w.page.ctx._logAt;
  w.pass(); w.say(H, H, H);
  await w.hide(false); await w.settlePolls();
  await w.pass();
  w.say(H); await w.pass();
  check('a quiet console of nothing but a heartbeat, no line pushed since the page opened: the leave\'s answer is its '
        + 'place in the log, and back in view the three heartbeats written while away show, then the next',
        before === null && JSON.stringify(at) === JSON.stringify([1, 1, 30]) && w.exact(),
        JSON.stringify({before, at, shown: w.pageLog().length, log: w.log().length, asks: w.asks()}));
  // ...but not while a return is still owed. A page with no place of its own — nothing pushed since it
  // opened, and its leave unanswered (the socket dropped first) — comes back asking with no place; gone
  // again before the answer, it has not shown what lies before the poller's place, so that leave's
  // answer is not its place.
  const v = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code});
  v.write(20);
  await v.start();
  v.pass();
  await v.hide(true); await v.advance(10000);
  await v.disconnect(); await v.advance(GRACE);               // the grace ran out with the socket down
  await v.reconnect();                                        // still hidden: it leaves again, unanswered
  v.pass();                                                   // nobody watching: forgotten
  v.write(3);
  await v.hide(false); await v.settlePolls();                 // asks to be caught up, with no place
  await v.tick();                                             // a first look, past those three
  const noPlace = v.asks().slice(-1)[0].since;
  await v.hide(true); await v.advance(GRACE);                 // gone again before the answer
  const kept = v.page.ctx._logAt;
  v.pass(); v.write(2);
  await v.hide(false); await v.settlePolls();
  await v.settle();
  v.write(1); await v.pass();
  check('...and a page gone again before the answer to a catch-up it asked for with no place takes no place from '
        + 'that leave\'s answer — the lines before it were never shown — and is placed by its text: every line once',
        noPlace === null && kept === null && v.exact(),
        JSON.stringify({noPlace, kept, got: v.pageLog().slice(-9), want: v.log().slice(-9)}));
}

// The page's place in the log is kept for a return that gets no leave answered — its socket dropped
// before the grace ran out, so no leave was sent — on a console whose last 250 lines are one heartbeat
// over and over, which no text can place. The place is a push's, or the one a catch-up's answer gave
// it when that answer was itself placed by its text.
async function checkPlaceKept(cfg) {
  const H = 'heartbeat: 0 players online';
  const awayUnanswered = async (w, whileAway) => {
    await w.hide(true); await w.advance(10000);
    await w.disconnect(); await w.advance(GRACE);            // the grace ran out with the socket down
    await w.reconnect();                                     // still hidden: it leaves again, unanswered
    w.pass();                                                // nobody watching: the poller forgets this console
    whileAway(w);
    await w.hide(false); await w.settlePolls();
  };
  for (const how of ['a push', 'a catch-up\'s answer placed by its text']) {
    const w = await manualWorld(cfg);
    w.pass();
    if (how === 'a push') { for (let i = 0; i < 300; i++) w.say(H); await w.pass(); }
    else {
      await awayUnanswered(w, x => { for (let i = 0; i < 300; i++) x.say(H); });
      await w.pass();                                        // no place: the log's last lines, placed by text
    }
    const place = w.page.ctx._logAt;
    await awayUnanswered(w, x => x.say(H, H, H));
    await w.pass();
    w.write(1); await w.pass();
    check('a console of nothing but a heartbeat for its last 300 lines, its place in the log from ' + how + ', away '
          + 'with no leave answered (the socket dropped first): back in view it is caught up from that place, and '
          + 'the three heartbeats written while away show', Array.isArray(place) && w.exact(),
          JSON.stringify({place, shown: w.pageLog().length, log: w.log().length, asks: w.asks().slice(-1)}));
  }
}

// A phone unlocked after a long sleep, its join kept by socket.io (with the place it had then) while the
// time away is read with the socket down and placed by its text. On reconnecting the kept join goes
// first, then a new one with no place; a pass that answers the kept one before the new one arrives
// answers a catch-up the page no longer asks for, from a place it has moved past. It is not shown.
async function checkKeptJoinAnswered(cfg) {
  const w = await awayLong(cfg, 300);
  w.expire();
  await w.hide(false);
  for (const f of w.pending()) await w.answer(f);            // the time away, read with the socket down
  w.write(3);
  w.serveOnJoin = true;                                      // the kept join is answered before the next arrives
  await w.reconnect();
  const answered = w.answers.length;
  await w.pass(); w.write(1); await w.pass();
  check('a phone woken after its socket was dropped: the answer to the join socket.io kept from before the reconnect '
        + 'is not shown — the page asked again with its new place — and every line shows once',
        answered === 1 && w.answers.length === 2 && w.exact() && !w.page.ctx._resync,
        JSON.stringify({answered, answers: w.answers.length, shown: w.pageLog().length, log: w.log().length}));
}

// A page whose first window never came back (the host was unreachable when it opened): nothing on it
// is the log. Away and back, it rejoins and catches up the way a reconnect does.
async function checkNeverPrimed(cfg) {
  const w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code});
  w.write(5);
  await w.reconnect();
  for (const f of w.pending()) await w.reply(Object.assign(w.read(f), {b: {lines: [], readable: false, panel_lines: []}}));
  await w.hide(true); await w.advance(GRACE);
  const left = !w.room.has('page');
  w.write(2);
  await w.hide(false);
  w.pass();                                                  // the poller's first look at the rejoined console
  for (const f of w.pending()) await w.answer(f);            // the window, as a reconnect reads it
  w.write(1); await w.pass(); w.write(1); await w.pass();
  check('a page whose first window never came back, away and back: it rejoins and shows the log, then what follows',
        left && w.room.has('page') && w.exact(), JSON.stringify({left, room: [...w.room], got: w.pageLog(), want: w.log()}));
}

// An update that started while the tab was away and ends while it is catching up: its end is pushed
// before the answer that brings its start in the backlog. Noted in the order they came, that end closed
// nothing, the start then counted as an action still running, and the tab stayed in for six hours.
async function checkMarkerOrder(cfg) {
  const w = await manualWorld(cfg);
  w.pass(); w.write(2); await w.pass();
  await w.hide(true); await w.advance(GRACE);
  w.pass();
  w.panelPush('[panel] update started — its output follows.');      // while away: in the backlog only
  await w.hide(false); await w.settlePolls();
  await w.panelPush('[panel] update finished successfully.');        // before the answer: held
  await w.pass();                                                    // the answer, the start in its backlog
  const running = w.page.ctx._actionRunning();
  await w.hide(true); await w.advance(GRACE);
  check('an update started while the tab was away and finished while it was catching up (its end pushed before the '
        + 'answer that brings its start): it is not taken for one still running, and hidden again the tab leaves',
        !running && w.emits('leave_console') === 2 && JSON.stringify(w.pagePanel()) === JSON.stringify(w.backlog.map(b => b.line)),
        JSON.stringify({running, leaves: w.emits('leave_console'), starts: w.page.ctx._actionStarts, panel: w.pagePanel()}));
}

// With the socket down there is no stream to cut the time away for, but the page still has a place in
// the log, and /api/console's return read starts from it: a console of nothing but a heartbeat, which
// no text can place, comes back exact while the socket stays down, and after it reconnects.
async function checkDownPlaced(cfg) {
  const H = 'heartbeat: 0 players online';
  const w = await manualWorld(cfg);
  w.pass(); for (let i = 0; i < 300; i++) w.say(H); await w.pass();
  await w.hide(true); await w.advance(GRACE);
  w.pass(); w.say(H, H, H);
  w.expire();
  await w.hide(false);
  for (const f of w.pending()) await w.answer(f);            // the time away, from the page's place
  const down = w.exact();
  w.say(H, H);
  await w.advance(GRACE);
  for (const f of w.pending()) await w.answer(f);            // the next 30 s poll, from where that left it
  const still = w.exact();
  w.say(H);
  await w.reconnect();
  await w.pass(); w.say(H); await w.pass();
  check('a console of nothing but a heartbeat, back in view with the socket dropped: the time away is read from the '
        + 'page\'s place in the log, so every heartbeat shows — while the socket stays down, and after it reconnects',
        down && still && w.exact() && !w.page.ctx._resync,
        JSON.stringify({down, still, shown: w.pageLog().length, log: w.log().length, asks: w.asks().slice(-1)}));
}

// The socket down at the return and another tab keeping the poller's stream: the page's read of the
// time away reaches further than the poller has. Its catch-up, asked from there on reconnecting, is
// answered only once the poller has passed that place — answered from where the poller stood, the
// pushes after would begin with lines the page already has.
async function checkAheadOfPoller(cfg) {
  const w = await manualWorld(cfg);
  w.other(true);
  w.pass(); w.write(2); await w.pass();
  await w.hide(true); await w.advance(GRACE);
  w.write(3); w.pass();                                      // the other tab's stream
  w.write(4);                                                // not read by the poller yet
  w.expire();
  await w.hide(false);
  for (const f of w.pending()) await w.answer(f);            // the page's read reaches past the poller
  await w.reconnect();
  await w.pass();                                            // too early: it waits; the tick reads on
  const waited = w.stats.waits;
  w.write(1); await w.pass();                                // the answer, then a push
  w.write(1); await w.pass();
  check('the page\'s read of the time away reaching further than the poller (another tab keeps it): its catch-up is '
        + 'answered once the poller has passed the page\'s place, and every line shows once, with no notice',
        waited >= 1 && w.exact() && w.page.gaps().length === 0 && !w.page.ctx._resync,
        JSON.stringify({waited, gaps: w.page.gaps(), got: w.pageLog().slice(-8), want: w.log().slice(-8)}));
  w.other(false);
}

// ── placed by text: a page with no place in the log ───────────────────────────────────────────────
// Its last lines came from a read and not from a push, and its leave went unanswered (the socket had
// dropped): it has no place to be caught up from (_logAt is null — set so here, as those make it).
// Back in view with its socket dropped (a phone unlocked), the time away is read from /api/console and
// placed by its text (_appendReturnRows, _returnOverlap); that read gives it a place, from which the
// reconnect is caught up.
async function backDown(w) {
  w.page.ctx._logAt = null;
  w.expire();
  await w.hide(false);
  for (let i = 0; i < 2; i++) { for (const f of w.pending()) await w.answer(f); await w.advance(1000); }
  await w.reconnect();
  await w.settle();
  w.write(1); await w.pass();
}
// A hole of `lost` lines in what the page shows: its lines replaced by a window read before they were
// written, with the poller's first look after them, so no push brings them either. A reconnect's
// 250-line window used to leave one this way; reconnects are now caught up from the page's place, so
// it is made the way a page still meets it — the window that primes a console (here a Cleared one,
// which a reconnect primes again) read before the poller's first look at the console it rejoined.
async function holeByWindow(w, down, lost) {
  w.page.ctx.clearConsole();
  await w.disconnect(); w.pass(); w.write(down); await w.reconnect();
  const rd = w.read(w.pending()[0]);
  w.write(lost); w.pass();
  await w.reply(rd);
}
const PIECE = 'L00020 ine';     // the end of a line, as a read that landed inside it shows it
const pushPiece = w => w.page.push({server_id: 7, data: PIECE, rows: [{t: null, line: PIECE}], ts: 1700000001});
const minus = (log, gone) => log.filter(l => gone.indexOf(l) < 0);
// The page's lines with the `n` it shows twice in a row (the load race's) taken out where they first repeat.
function withoutRepeat(got, log, n) {
  let i = 0;
  while (i < got.length && got[i] === log[i]) i++;
  return got.slice(0, i).concat(got.slice(i + n));
}

// A break in the page's last 250 lines, so base's rule finds nothing — a line lost 33 back (the
// priming window's race, holeByWindow), or a piece of a line 30 back — and the page's last line one the game repeats.
// While away the game writes on and repeats it. The copy written last is not the page's place: taken
// for it, everything written before it was a "hole" the page lacked, none of it shown, with no notice.
async function checkRepeatAfterBreak(cfg) {
  const X = 'L99999 No players online, skipping autosave';
  for (const [label, shape, away] of [['a line lost 33 back', 'lost', 10], ['a piece of a line 30 back', 'piece', 10],
                                      ['a piece of a line 30 back', 'piece', 200]]) {
    const w = await manualWorld(cfg);
    w.pass();
    if (shape === 'lost') {
      w.write(2); await w.pass();
      await holeByWindow(w, 5, 3);             // a window read before 3 lines and the poller's first look
    } else await pushPiece(w);
    w.write(29); w.log().push(X); await w.pass();
    const lost = w.log().filter(l => w.pageLog().indexOf(l) < 0);
    await w.hide(true); await w.advance(GRACE);
    w.pass(); w.write(away); w.log().push(X);
    await backDown(w);
    const got = w.pageLog().filter(l => l !== PIECE);
    check('placed by its text: a page with ' + label + ', its last line one the game repeats, away while ' + away
          + ' lines and that line again are written: back in view every one of them shows, once, and no notice',
          JSON.stringify(got) === JSON.stringify(minus(w.log(), lost)) && w.page.gaps().length === 0
          && (shape === 'piece' ? lost.length === 0 : lost.length === 3),
          JSON.stringify({lost: lost.length, shown: got.length, want: w.log().length - lost.length, gaps: w.page.gaps(),
                          tail: got.slice(-4)}));
  }
}

// The priming window's race lost lines just before the page's last line — one line came after them, then the console
// went quiet — and the game repeats that line while away. The break is right at the page's end, and
// the page's own place, the EARLIEST that fits across it, is taken: every line written while away
// shows, and nothing says output is missing.
async function checkBreakBeforeLast(cfg) {
  const X = 'L99999 Server empty for 60 seconds, pausing';
  const w = await manualWorld(cfg);
  w.pass(); w.write(30); await w.pass();
  await holeByWindow(w, 2, 3);                 // lost: after the priming window, before the first look
  w.log().push(X); await w.pass();             // one line, then quiet
  const lost = w.log().filter(l => w.pageLog().indexOf(l) < 0);
  await w.hide(true); await w.advance(GRACE);
  w.pass(); w.write(10); w.log().push(X);
  await backDown(w);
  const got = w.pageLog();
  check('placed by its text: lines lost to a window\'s race just before the page\'s last line, a line the game repeats '
        + 'while the tab is away: back in view everything written since shows, once, and no notice',
        lost.length === 3 && JSON.stringify(got) === JSON.stringify(minus(w.log(), lost)) && w.page.gaps().length === 0,
        JSON.stringify({lost: lost.length, shown: got.length, want: w.log().length - lost.length, gaps: w.page.gaps(),
                        tail: got.slice(-4)}));
}

// The page holds lines the log does not, near its end: a piece of a line 5 back, or — the page load's
// own race (its window read after the poller's first look, the same lines then pushed) — the last
// lines twice. A return must not take them for "the log moved on": it showed a notice that output was
// missing and appended its whole read again, every line of the console twice. And on an idle console
// the read can begin with the very heartbeat the page ended on: base's rule then "agreed" on that one
// line, at the read's start, and the whole read was shown again with no notice at all.
async function checkPageOnlyLines(cfg) {
  let w = await manualWorld(cfg);
  w.pass(); await pushPiece(w);
  w.write(5); await w.pass();
  await w.hide(true); await w.advance(GRACE);
  w.pass(); w.write(3);
  await backDown(w);
  let got = w.pageLog().filter(l => l !== PIECE);
  check('placed by its text: a piece of a line 5 lines before the tab went away: back in view each line shows once, '
        + 'nothing is missing, and no notice', JSON.stringify(got) === JSON.stringify(w.log()) && w.page.gaps().length === 0,
        JSON.stringify({shown: got.length, want: w.log().length, gaps: w.page.gaps()}));
  const H = 'heartbeat: 0 players online';
  for (const [n, firstIsH, down] of [[1, false, true], [6, false, true], [1, true, true], [1, true, false]]) {
    w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code});
    if (firstIsH) w.say(H);
    w.write(firstIsH ? 37 : 38);
    await w.reconnect();                       // the page's first connect: it joins
    w.pass(); w.write(n);                      // the poller's first look, then n lines…
    await w.answer(w.pending()[0]);            // …which the load's window, read after both, shows
    await w.pass();                            // …and the first push shows again
    if (firstIsH) { w.say(H); await w.pass(); }        // an idle console's heartbeat
    const twice = w.pageLog().length - w.log().length;
    await w.hide(true); await w.advance(GRACE);
    w.pass(); w.write(firstIsH ? 3 : 40);
    if (firstIsH) w.say(H);
    if (down) await backDown(w);
    else { await w.hide(false); await w.settlePolls(); await w.settle(); w.write(1); await w.pass(); }
    got = w.pageLog();
    check((down ? 'placed by its text' : 'caught up by position') + ': the page load showing its last ' + n
          + ' line(s) twice (its own race)' + (firstIsH ? ', on an idle console whose log begins with the heartbeat the '
          + 'page ends on' : '') + ', then away: back in view what was written while away shows once, nothing else twice, '
          + 'and no notice', twice === n && got.length === w.log().length + n
          && JSON.stringify(withoutRepeat(got, w.log(), n)) === JSON.stringify(w.log()) && w.page.gaps().length === 0,
          JSON.stringify({twice, shown: got.length, want: w.log().length + n, gaps: w.page.gaps()}));
  }
}

// A break in the page's last 250 lines and its last 25 lines a block it ALSO showed earlier: the page's
// place is the block's latest copy that stands unbroken, as base's rule takes the latest. The earlier
// copy would show everything after it again.
async function checkUnbrokenLatest(cfg) {
  const block = Array.from({length: 25}, (_, i) => 'status row ' + String(i + 1).padStart(2, '0'));
  const w = await manualWorld(cfg);
  w.pass(); w.say(...block); w.write(5); await w.pass();
  await holeByWindow(w, 2, 3);
  w.write(5); w.say(...block); await w.pass();
  const lost = w.log().filter(l => w.pageLog().indexOf(l) < 0);
  await w.hide(true); await w.advance(GRACE);
  w.pass(); w.write(5);
  await backDown(w);
  const got = w.pageLog();
  check('placed by its text: a page with a break in its last 250 lines whose last 25 lines are a block it showed '
        + 'before too: back in view it is placed at the block\'s latest unbroken copy, so nothing shows twice',
        lost.length === 3 && JSON.stringify(got) === JSON.stringify(minus(w.log(), lost)) && w.page.gaps().length === 0,
        JSON.stringify({lost: lost.length, shown: got.length, want: w.log().length - lost.length, gaps: w.page.gaps()}));
}

// The same hole, by text: the priming window's race lost 3 lines, 5 shown since, and the console an idle
// one whose log begins with the heartbeat the page ends on.
async function checkHoleByText(cfg) {
  const H = 'heartbeat: 0 players online';
  const w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code});
  w.say(H); w.write(19);
  await w.start();
  w.pass(); w.write(2); await w.pass();
  await holeByWindow(w, 10, 3);                // lost to the priming window's race
  for (let i = 0; i < 4; i++) { w.write(1); await w.pass(); }
  w.say(H); await w.pass();
  const lost = w.log().filter(l => w.pageLog().indexOf(l) < 0);
  await w.hide(true); await w.advance(GRACE);
  w.pass(); w.write(5); w.say(H);
  await backDown(w);
  const got = w.pageLog(), dups = got.length - (w.log().length - lost.length);
  check('placed by its text: a page with a hole (3 lines lost to a window\'s race, 5 shown since) on an idle '
        + 'console whose log begins with the heartbeat the page ends on: back in view nothing shows twice, nothing '
        + 'written since the hole is missing, and no notice', lost.length === 3 && dups === 0
        && JSON.stringify(got) === JSON.stringify(minus(w.log(), lost)) && w.page.gaps().length === 0,
        JSON.stringify({lost: lost.length, dups, shown: got.length, gaps: w.page.gaps()}));
}

// An answer the host could not give (`readable: false`: the poller's read failed on three passes) is not
// an empty log. The catch-up asks again; one never given is given up with a notice where the time away is.
async function checkUnreadable(cfg) {
  for (const [label, away, fails] of [['the poller\'s read failing three passes, 40 lines away', 40, 3],
                                      ['...400 lines away', 400, 3],
                                      ['the poller\'s read failing twice (then answered on its third pass)', 40, 2],
                                      ['no read answered at all, 40 lines away', 40, 99]]) {
    const w = await manualWorld(cfg);
    w.pass(); w.write(2); await w.pass();
    await w.hide(true); await w.advance(GRACE);
    w.pass(); w.write(away);
    w.failReads = fails;
    await w.hide(false); await w.settlePolls();
    for (let i = 0; i < 9; i++) { await w.pass(); await w.advance(6000); w.write(1); }
    w.failReads = 0;
    await w.pass();
    const got = w.pageLog(), gaps = w.page.gaps(), lines = w.page.lines();
    const missing = w.log().filter(l => got.indexOf(l) < 0), never = fails > 20;
    const ok = never
      ? JSON.stringify(missing) === JSON.stringify(w.log().slice(22, 22 + away)) && gaps.length === 1
        && lines[gaps[0] - 1] === w.log()[21] && lines[gaps[0] + 1] === w.log()[22 + away]
      : w.exact() && gaps.length === 0;
    check('a return, ' + label + ': ' + (never ? 'given up after 45 s with a notice where the time away is missing, '
          + 'and everything since shown once' : 'the catch-up is asked again and the time away shows, once, in order'),
          ok && !w.page.ctx._resync && !w.page.ctx._returnOwed && new Set(got).size === got.length,
          JSON.stringify({missing: missing.length, gaps, shown: got.length, want: w.log().length, asks: w.asks().length,
                          resync: !!w.page.ctx._resync, owed: w.page.ctx._returnOwed}));
  }
  // No read of the log answers, and an update ran start to end while the tab was away: the panel's own
  // lines come from the panel, not the host, so they show all the same — and the version is re-read.
  const u = await awayLong(cfg, 40);
  const v0 = versions(u);
  u.failReads = 99;
  await u.hide(false); await u.settlePolls();
  for (let i = 0; i < 9; i++) { await u.pass(); await u.advance(6000); }
  check('a return no read of the log answers, an update having run while the tab was away: its lines still show, '
        + 'once, in order, and the game version is re-read', !u.page.ctx._resync && versions(u) - v0 === 1
        && JSON.stringify(u.pagePanel()) === JSON.stringify(u.backlog.map(b => b.line)),
        JSON.stringify({panel: u.pagePanel(), versions: versions(u) - v0}));
  // With the socket down there is no stream to wait on: an unanswered read is left to the 30 s console
  // poll (and the reconnect), as any read made with the socket down is — not asked again every 6 s.
  const w = await awayLong(cfg, 40);
  w.expire();
  await w.hide(false);
  const first = w.pending(/lines=2000/);
  for (const f of first) await w.reply(Object.assign(w.read(f), {b: {lines: [], readable: false}}));
  const reads = () => w.page.fetches.filter(f => /\/api\/console\//.test(f.url)).length, asked = reads();
  await w.advance(GRACE - 1000);
  const early = reads() - asked;
  await w.advance(1000);
  for (const f of w.pending()) await w.answer(f);
  check('a read of the time away unanswered while the socket is down is not asked again every 6 s: the next 30 s '
        + 'console poll reads it, which then shows, once', first.length >= 1 && early === 0 && w.exact()
        && w.page.ctx._returnOwed && !w.page.socket.connected,
        JSON.stringify({first: first.length, early, exact: w.exact(), owed: w.page.ctx._returnOwed}));
}

// A catch-up given up before any answer came back, holding a push that begins with the line the page
// ended on — the game repeats it. The push is all new: it is shown whole.
async function checkGiveUpRepeat(cfg) {
  const w = await manualWorld(cfg);
  w.pass(); w.say('heartbeat: no players, skipping save'); await w.pass();
  await w.hide(true); await w.advance(GRACE);
  w.pass();
  await w.hide(false); await w.settlePolls();
  w.serveOff = true;                              // the answer never comes
  w.pass();
  w.say('heartbeat: no players, skipping save'); w.write(1); await w.pass();   // held
  await w.advance(46000);
  w.write(1); await w.pass();
  check('a catch-up given up whose held push begins with the line the page ended on (the game repeats it): the '
        + 'push shows whole', JSON.stringify(w.pageLog().slice(-3)) === JSON.stringify(w.log().slice(-3))
        && !w.page.ctx._resync && w.page.gaps().length === 1,
        JSON.stringify({got: w.pageLog().slice(-4), want: w.log().slice(-4)}));
}

// Clear, then the 30 s poll primes the console again from the window: the panel lines the viewer
// cleared stay cleared — and do not come back with a later return either.
async function checkClearThenReturn(cfg) {
  const w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code});
  w.write(20);
  w.panelPush('[panel] update started — its output follows.');
  w.panelPush('ACT one\nACT two');
  w.panelPush('[panel] update finished successfully.');
  await w.start();
  w.pass();
  const shown = w.pagePanel().length;
  w.page.ctx.clearConsole();
  w.write(2); await w.pass();
  await w.advance(30000);
  for (const f of w.pending()) await w.answer(f);    // the 30 s poll primes the cleared console
  const cleared = w.pagePanel().length;
  await w.hide(true); await w.advance(GRACE);
  w.pass(); w.write(3);
  await w.hide(false); await w.settlePolls(); await w.settle(); w.write(1); await w.pass();
  check('panel lines the viewer cleared stay cleared after the console is primed again and the tab goes away '
        + 'and comes back', shown === 4 && cleared === 0 && w.pagePanel().length === 0 && w.exact(),
        JSON.stringify({shown, cleared, after: w.pagePanel()}));
}

// When each line came. The answer's lines were written at some point the panel did not see, so they get
// no time, as the window a page opens with gets none; a push the panel watched arrive has its time.
async function checkAwayStamps(cfg) {
  const w = await awayAndBack(cfg);              // 5 lines written while away
  await w.pass();
  w.write(2); await w.pass();
  w.write(1); await w.pass();
  const stamps = () => { const st = w.page.stamped(); return l => (st.find(([x]) => x === l) || [])[1]; };
  let at = stamps();
  const away = w.log().slice(22, 27), after = w.log().slice(27);
  check('lines the catch-up\'s answer shows have no time beside them; pushed lines do', w.exact()
        && away.every(l => at(l) === null) && after.length === 3 && after.every(l => at(l)),
        JSON.stringify({away: away.map(l => [l, at(l)]), after: after.map(l => [l, at(l)])}));
  await w.hide(true); await w.advance(GRACE);    // and away again
  w.pass(); w.write(3);
  await w.hide(false); await w.settlePolls(); await w.settle();
  at = stamps();
  const again = w.log().slice(30, 33);
  check('...and so do the answer\'s lines on the next return too', w.exact() && again.every(l => at(l) === null),
        JSON.stringify(again.map(l => [l, at(l)])));
}

// The log rotates between the rejoin and the answer, while another tab keeps the poller's stream: a
// push from the old log reaches the page before the answer, and the answer is from the new log.
async function checkRotatedBeforeAnswer(cfg) {
  const w = await manualWorld(cfg);
  w.other(true);
  w.pass(); w.write(2); await w.pass();
  await w.hide(true); await w.advance(GRACE);
  w.write(3); w.pass();
  await w.hide(false);
  w.write(2); await w.tick();                  // the old log's last lines: pushed before the answer, held
  w.rotate(4); await w.pass();                 // the poller finds the log moved: no answer, its tick reads the new log
  w.write(1); await w.pass();                  // the answer, from the new log
  w.write(1); await w.pass();
  const got = w.pageLog(), fresh = w.log(), gaps = w.page.gaps(), lines = w.page.lines();
  check('the log rotating between the rejoin and the answer: the answer is the new log\'s, under a notice that the '
        + 'old one\'s last lines are not shown, and the new log shows once, in order, with no old line after it',
        JSON.stringify(got.slice(-fresh.length)) === JSON.stringify(fresh) && new Set(got).size === got.length
        && gaps.length === 1 && lines[gaps[0] + 1] === fresh[0] && !w.page.ctx._resync,
        JSON.stringify({got: got.slice(-9), fresh, gaps}));
  w.other(false);
}

// A short log, placed by its text: the server restarted and the page shows the new log's few lines.
// The read is shorter than the run the later tiers need, so base's rule agreeing on all of the page's
// lines it can is the place — taken as it stands, not "no place" (the whole log again under a notice).
async function checkShortLogByText(cfg) {
  const w = await manualWorld(cfg);
  w.pass(); w.write(2); await w.pass();
  w.rotate(5); await w.pass();                               // a restart: the new log, pushed whole
  await w.hide(true); await w.advance(GRACE);
  w.pass(); w.write(2);
  await backDown(w);
  const got = w.pageLog(), fresh = w.log();
  check('placed by its text: a log only a few lines long since the server restarted, away and back: the new lines '
        + 'show once, nothing twice, and no notice', JSON.stringify(got.slice(-fresh.length)) === JSON.stringify(fresh)
        && new Set(got).size === got.length && w.page.gaps().length === 0,
        JSON.stringify({got: got.slice(-10), fresh, gaps: w.page.gaps()}));
}

// ── random schedules ─────────────────────────────────────────────────────────────────────────────
// `repeats`: the console also writes lines word for word again — a heartbeat in a third of its lines,
// a three-line autosave block in a tenth — and its socket never drops, so a page that never leaves
// (the console before this change) shows the log exactly: every schedule must end that way here too.
const HEART = 'L00000 heartbeat: 0 players online', SAVES = ['L00000 Autosave started', 'L00000 Saved 4 chunks', 'L00000 Autosave done'];
function writeSome(w, repeats) {
  const n = w.between(1, 6);
  for (let k = 0; k < n; k++) {
    const r = repeats ? w.rand() : 1;
    if (r < 0.33) w.log().push(HEART);
    else if (r < 0.43) w.log().push(...SAVES);
    else w.write(1);
  }
}

async function schedule(cfg, seed, code, repeats) {
  const w = makeWorld({src: cfg.src, panel: cfg.panel, code, seed});
  w.write(30);
  await w.start();
  let hidden = false, acting = false, quietFrom = null, other = false, expires = 0, keptJoins = 0;
  const spans = [];
  const mark = () => {
    const want = hidden && !acting && !other;
    if (want && quietFrom === null) quietFrom = w.page.now;
    if (!want && quietFrom !== null) { spans.push([quietFrom, w.page.now]); quietFrom = null; }
  };
  for (let i = 0; i < 40; i++) {
    // A socket that closed itself (its ping had expired) comes back sooner or later — sometimes only
    // after the tab has gone out of view again.
    if (!w.page.socket.connected && w.rand() < 0.5) {
      keptJoins += w.page.socket.sendBuffer.filter(p => p[0] === 'join_console').length && hidden ? 1 : 0;
      await w.reconnect();
    }
    const r = w.rand();
    if (r < 0.35) writeSome(w, repeats);
    else if (r < 0.55) { hidden = !hidden; await w.hide(hidden); }
    else if (r < 0.62) {
      w.panelPush(acting ? '[panel] update finished successfully.' : '[panel] update started — its output follows.');
      acting = !acting;
    } else if (r < 0.66 && acting) w.panelPush('ACT out ' + i);
    else if (r < 0.70) { other = !other; w.other(other); }
    else if (!repeats && r < 0.73 && hidden && w.page.ctx._consolePaused && w.page.socket.connected) {
      await w.disconnect(); await w.step(w.between(0, 5000)); await w.reconnect();
    }
    else if (!repeats && r < 0.77 && hidden && w.page.ctx._consolePaused && w.page.socket.connected) { w.expire(); expires++; }
    mark();
    await w.step(w.between(0, 40000));
  }
  if (acting) { w.panelPush('[panel] update finished successfully.'); acting = false; }
  if (hidden) { hidden = false; await w.hide(false); }
  mark();
  await w.step(5000);
  if (!w.page.socket.connected) await w.reconnect();
  await w.step(20000);
  // A span can start while the page waits out an action's end, so it may take two graces to leave.
  const idle = w.readsAt.filter(t => spans.some(([a, b]) => t >= a + 2 * GRACE + 3100 && t < b)).length;
  return {seed, log: w.exact(), panel: JSON.stringify(w.pagePanel()) === JSON.stringify(w.backlog.map(b => b.line)),
          track: JSON.stringify(w.page.ctx._consoleLines) === JSON.stringify(w.pageLog()), idle,
          leaves: w.emits('leave_console'), expires, keptJoins, placed: w.answers.filter(a => a.since).length,
          shown: w.pageLog().length, want: w.log().length};
}

async function checkSchedules(cfg) {
  const runs = cfg.runs || 150, bad = [];
  let leaves = 0, expires = 0, keptJoins = 0;
  for (let s = 1; s <= runs; s++) {
    const r = await schedule(cfg, s);
    leaves += r.leaves; expires += r.expires; keptJoins += r.keptJoins;
    if (!r.log || !r.panel || !r.track || r.idle) bad.push(r);
  }
  check(runs + ' random schedules (writes, hiding and showing, long actions, a second tab, a socket dropped while '
        + 'away, a phone woken after its socket was dropped — the return\'s join kept and sent on reconnecting, '
        + 'sometimes after the tab went out of view again): every console ends showing the log and the panel\'s '
        + 'lines complete, in order, each once — and no log read happens once a tab has been hidden past the grace',
        bad.length === 0 && leaves > runs && expires * 5 > runs && keptJoins > 0,
        JSON.stringify({leaves, expires, keptJoins, bad: bad.slice(0, 3)}));
  // The same schedules against the catch-up a reconnect does (one window, pushes appended as they
  // come): if this passed, the schedules would not be exercising what catching up exists for.
  const src = fs.readFileSync(cfg.src, 'utf8');
  const naive = src.replace(/\n {2}_startResync\(\);\n/, '\n  _rejoinConsole(); refreshConsole(false, null, true);\n');
  let wrong = 0;
  if (naive !== src) for (let s = 1; s <= runs; s++) { const r = await schedule(cfg, s, naive); if (!r.log) wrong++; }
  check('(control) the same schedules against a plain rejoin with the reconnect\'s one-window catch-up get the log '
        + 'wrong — duplicated or missing lines — in at least a tenth of them', naive !== src && wrong * 10 >= runs,
        JSON.stringify({substituted: naive !== src, wrong, runs}));
}

// A console that repeats itself — the case placing lines by their text got wrong (a heartbeat or an
// autosave block taken for one already shown, and lost) — against the console as it was before this
// change, which never leaves: with no socket dropped, that one shows the log exactly in every schedule,
// and so must this one.
async function checkRepeatSchedules(cfg) {
  const runs = cfg.runs || 150, bad = [], src = fs.readFileSync(cfg.src, 'utf8');
  const stays = src.replace(/\n {2}var inStep = !_returnOwed;\n/, '\n  return;\n');
  let placed = 0, baseBad = 0;
  for (let s = 1; s <= runs; s++) {
    const r = await schedule(cfg, 1000 + s, null, true);
    placed += r.placed;
    if (!r.log || !r.panel || !r.track || r.idle) bad.push(r);
    if (stays !== src && !(await schedule(cfg, 1000 + s, stays, true)).log) baseBad++;
  }
  check(runs + ' random schedules on a console that repeats itself (a heartbeat in a third of its lines, an '
        + 'autosave block in a tenth), with no socket dropped: every console ends showing the log and the panel\'s '
        + 'lines complete, in order, each once, and no log read once hidden past the grace — as the console that never '
        + 'leaves (the oracle, built from this page by taking its leave out) does in every one of them',
        bad.length === 0 && stays !== src && baseBad === 0 && placed > runs,
        JSON.stringify({substituted: stays !== src, baseBad, placed, bad: bad.slice(0, 3)}));
}

// ── replay: real server payloads, in an order the server really produced them ───────────────────
async function replay(cfg) {
  const p = makePage({src: cfg.src, panel: cfg.panel, serverId: cfg.serverId});
  const errors = [];
  for (const s of cfg.steps) {
    if (s.op === 'connect') await p.connect();
    else if (s.op === 'hide') await p.setHidden(s.v);
    else if (s.op === 'advance') await p.advance(s.ms);
    else if (s.op === 'push') await p.push(s.data);
    else if (s.op === 'event') await p.event(s.name, s.data);
    else if (s.op === 'ack') {
      const e = p.emitted.filter(x => x[0] === s.name && x[3]).pop();
      if (!e) { errors.push('no ' + s.name + ' with an ack to answer'); continue; }
      e[3](s.value);
      e[3] = null;
      await p.flush();
    } else if (s.op === 'respond') {
      const f = p.fetches.find(x => !x.done && x.url === s.url);
      if (!f) { errors.push('no pending fetch of ' + s.url + '; pending: ' + p.fetches.filter(x => !x.done).map(x => x.url).join(', ')); continue; }
      await p.respond(f, s.body);
    } else if (s.op === 'emits') {
      const got = p.emitted.slice(s.from).map(e => e[0]);
      if (JSON.stringify(got) !== JSON.stringify(s.want)) errors.push('emits after ' + s.from + ': ' + JSON.stringify(got) + ' != ' + JSON.stringify(s.want));
      const sent = s.data !== undefined ? JSON.stringify(p.emitted[p.emitted.length - 1][1]) : null;
      if (s.data !== undefined && sent !== JSON.stringify(s.data)) errors.push('sent ' + sent + ' != ' + JSON.stringify(s.data));
    }
  }
  return {loadError: p.loadError, errors, lines: p.lines(), gaps: p.gaps().length, emitted: p.emitted.map(e => e[0]),
          pending: p.fetches.filter(x => !x.done && x.url.indexOf('/api/console/') >= 0).map(x => x.url)};
}

(async () => {
  const cfg = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (cfg.mode === 'replay') { process.stdout.write(JSON.stringify(await replay(cfg))); return; }
  const only = cfg.only ? new RegExp(cfg.only) : null;
  for (const fn of [checkLoad, checkGrace, checkAltTab, checkReturn, checkStreamFromCut, checkOtherTab,
                    checkFirstLookFirst, checkDropWhileCatchingUp, checkGiveUp, checkHiddenAgain, checkReconnectWhilePaused,
                    checkDropBeforeGrace, checkAction, checkFinishedAway, checkBackground, checkLateTimer,
                    checkFocusFallback, checkSilentReturn, checkNoConsole, checkNoView, checkIndicator, checkBacklogOnce,
                    checkRotation, checkPrimeAfterPush, checkUnlockExpired, checkGiveUpWhileDown, checkInStepAfterReturn,
                    checkDropBeforeAnswer, checkReconnectPushFirst, checkPrimePushFirst, checkLoadOlderAfterClear,
                    checkReplayedJoin, checkLongAway, checkHoleThenAway, checkRepeats, checkGiveUpHeld,
                    checkLeaveAnswer, checkRepeatAfterBreak, checkBreakBeforeLast, checkPageOnlyLines, checkUnbrokenLatest,
                    checkHoleByText, checkUnreadable, checkGiveUpRepeat, checkClearThenReturn, checkAwayStamps,
                    checkRotatedBeforeAnswer, checkPlaceKept, checkKeptJoinAnswered, checkNeverPrimed,
                    checkShortLogByText, checkMarkerOrder, checkDownPlaced, checkAheadOfPoller, checkSchedules,
                    checkRepeatSchedules]) {
    if (only && !only.test(fn.name)) continue;
    try { await fn(cfg); } catch (e) { check(fn.name + ' ran to its end', false, e && e.stack || e); }
  }
  process.stdout.write(JSON.stringify({results}));
})();
"""


def _node38(cfg):
    """Run the harness with `cfg` on its stdin: its JSON answer, {"error": …}, or None (no node)."""
    node = _shutil38.which("node")
    if not node:
        return None
    path = os.path.join(_TMP38, "harness.js")
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_HARNESS38)
    r = _sp38.run([node, path], input=_json38.dumps(cfg),  # nosec B603 - node on this part's harness
                  capture_output=True, text=True, timeout=600, check=False)
    try:
        return _json38.loads(r.stdout)
    except ValueError:
        return {"error": (r.stdout + r.stderr)[-1500:]}


def _section_page38():
    out = _node38({"src": _SRC38, "panel": _PANEL38, "mode": "checks", "runs": 150})
    if out is None:
        skip("A page: server_detail.js run whole in node", "no node on this host")
        return
    results = out.get("results") or []
    check("A page: the harness ran server_detail.js whole and reported every check",
          len(results) >= 89 and not out.get("error"), repr(out)[:1500])
    for r in results:
        check("A page: " + r["name"], r["ok"], r.get("detail", ""))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# B: the server's half, through the real socket handlers and the real poller loop
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Rig38:
    """_core.read_as_game_user on a REAL file: each console command built as for the host, run by bash.

    The row's console_log is the /home path LinuxGSM uses; the command is quoted by game_user_cmd and
    unwrapped by bash exactly as on a host, with only that path pointed at this part's file.
    """

    def __init__(self, real, sub="log"):
        self.real, self.calls, self.lines = real, [], []
        self.path = os.path.join(_TMP38, sub, "console", os.path.basename(real))
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8"):
            pass

    def __call__(self, server, user, sh, timeout=30, selfname=None):
        self.calls.append(sh)
        return _bash34(_as_account34(user, sh, selfname).replace(self.real, self.path))

    def write(self, k):
        new = ["[p38] line %04d" % (len(self.lines) + i + 1) for i in range(k)]
        self.lines.extend(new)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write("".join(x + "\n" for x in new))
        return new


class _Stop38(Exception):
    """Raised by the fake sleep at the end of one poller pass."""


def _poller38():
    """The console poller's loop, as register() hands it to the supervisor, bound to part12's app."""
    got = {}
    _sf38._start_console_poller(_p9, _p9.socketio, got.__setitem__)
    return got.get("console-poller")


def _pass38(loop):
    """One pass of the real loop: it runs until its two-second sleep, which ends it."""
    def _sleep(_s):
        raise _Stop38()
    saved = _sf38.time
    _sf38.time = NS(time=_time38.time, sleep=_sleep, monotonic=_time38.monotonic)
    try:
        loop()
    except _Stop38:
        return True
    finally:
        _sf38.time = saved
    return False


def _sio38(uid):
    return _p9.socketio.test_client(_p9, flask_test_client=_p9_client(uid))


def _payloads38(sio):
    return [(m.get("args") or [{}])[0] for m in sio.get_received() if m.get("name") == "console_output"]


def _pushed38(sio):
    """The log lines the poller pushed to this socket since the last look."""
    return [r["line"] for p in _payloads38(sio) for r in (p.get("rows") or [])]


def _rows38():
    """A host, a game server whose console the rig reads, and an administrator to watch it."""
    host = RemoteServer(name="p38-host", host="192.0.2.38", username="p38", auth_credential="")
    db.session.add(host)
    db.session.flush()
    gs = GameServer(remote_id=host.id, name="p38-mc", short_name="mcsrv38", game_type="mc",
                    port=25638, installed=True, status="online")
    admin = User(username="p38_admin", password_hash=_hash38(os.urandom(16).hex()),
                 display_name="p38", is_superadmin=True, is_active=True)
    db.session.add_all([gs, admin])
    db.session.commit()
    return host.id, gs.id, admin.id, gs.console_log


class _Drains38:
    """shell_as_game_user for the action-output drain: records each call, answers 'nothing new'."""

    def __init__(self):
        self.calls = []

    def __call__(self, server, user, sh, timeout=30, selfname=None):
        self.calls.append(user)
        return "0", "", 0


def _server_join_leave38(loop, rig, gs_id, sio):
    drains = _Drains38()
    _set38(_core38, "shell_as_game_user", drains)
    _sh38._action_output[gs_id] = {"action": "update", "path": "/home/mcsrv38/.panel-update.log",
                                   "user": "mcsrv38", "pos": 0, "prev": None}
    sio.emit("join_console", {"server_id": gs_id})
    n = len(rig.calls)
    _pass38(loop)
    first = len(rig.calls) - n
    new = rig.write(3)
    _pass38(loop)
    check("B server: joined, the first pass takes the console's first look and the next pushes what was written "
          "since, from a real file read by bash — and drains the running action's output (both live)",
          first == 1 and _pushed38(sio) == new and len(drains.calls) == 2, repr((first, new, drains.calls)))
    sio.emit("leave_console", {"server_id": gs_id})
    n, d = len(rig.calls), len(drains.calls)
    rig.write(4)
    _pass38(loop)
    _pass38(loop)
    check("B server: left, so its room is empty: the passes make NO host call for that console — no stat, no read, "
          "no action-output drain — and the poller forgets its offset",
          len(rig.calls) == n and len(drains.calls) == d and gs_id not in _ps38._console_offsets,
          repr((rig.calls[n:], drains.calls[d:], _ps38._console_offsets.get(gs_id))))
    _sh38._action_output.pop(gs_id, None)
    sio.emit("join_console", {"server_id": gs_id})
    n = len(rig.calls)
    _pass38(loop)
    look = (len(rig.calls) - n, _pushed38(sio))
    new = rig.write(2)
    _pass38(loop)
    got = _pushed38(sio)
    check("B server: rejoined as its only viewer, the first pass is a first look again — nothing written while the "
          "tab was away is pushed (the page reads that from the window) — and the next pushes only what came after",
          look == (1, []) and got == new, repr((look, got, new)))
    sio.emit("leave_console", {"server_id": gs_id})


def _server_two_tabs38(loop, rig, gs_id, a, b):
    for s in (a, b):
        s.emit("join_console", {"server_id": gs_id})
    _pass38(loop)
    rig.write(1)
    _pass38(loop)
    _pushed38(a)
    _pushed38(b)
    a.emit("leave_console", {"server_id": gs_id})
    n = len(rig.calls)
    new = rig.write(2)
    _pass38(loop)
    got = (len(rig.calls) - n, _pushed38(b), _pushed38(a))
    check("B server: two tabs on one console and one leaves: the passes go on reading for the other, which gets the "
          "push, and the tab that left gets nothing", got == (1, new, []), repr((got, new)))
    a.emit("join_console", {"server_id": gs_id})
    new = rig.write(2)
    _pass38(loop)
    got = (_pushed38(a), _pushed38(b))
    check("B server: ...and rejoining mid-stream it takes no first look of its own: the next push reaches it, "
          "starting where the poller stood", got == (new, new), repr((got, new)))
    for s in (a, b):
        s.emit("leave_console", {"server_id": gs_id})


def _server_never_joined38(loop, rig, admin):
    c = _sio38(admin)
    try:
        n = len(rig.calls)
        rig.write(1)
        _pass38(loop)
        _pass38(loop)
        check("B server: a socket that connected but never joined — a tab that came back while still hidden — is "
              "never read for", c.is_connected() and len(rig.calls) == n and _pushed38(c) == [],
              repr((c.is_connected(), rig.calls[n:])))
    finally:
        c.disconnect()


def _server_backlog_key38(gs_id, admin, sio):
    sio.emit("join_console", {"server_id": gs_id})
    sio.get_received()
    ts = 1700000123.456789
    _sh38._console_push(_p9, gs_id, "[panel] p38 marker\np38 second line", ts=ts)
    sent = [p.get("ts") for p in _payloads38(sio)]
    body = _p9_client(admin).get("/api/console/%d" % gs_id).get_json() or {}
    rows = [r for r in body.get("panel_lines") or [] if "p38" in r.get("line", "")]
    check("B server: a panel push's own time comes back as `t` on each of its lines in /api/console's backlog — the "
          "key the page matches a late push by, so a line it showed from the backlog is not shown twice",
          sent == [ts] and [r.get("t") for r in rows] == [ts, ts], repr((sent, rows)))
    sio.emit("leave_console", {"server_id": gs_id})
    _sh38._console_backlog.pop(gs_id, None)


class _ActRig38:
    """shell_as_game_user for an action's output drain, run on REAL files.

    The command is built as for the host and unwrapped and run by bash, with only the output files'
    paths pointed at this part's copies. `hook`, when set, runs once inside the next call, after its
    read and before it returns: what another greenlet does while this one waits on the host.
    """

    def __init__(self, *reals):
        self.calls, self.hook, self.paths = [], None, {}
        for real in reals:
            self.paths[real] = os.path.join(_TMP38, "action", os.path.basename(real))
            os.makedirs(os.path.dirname(self.paths[real]), exist_ok=True)
            with open(self.paths[real], "w", encoding="utf-8"):
                pass

    def __call__(self, server, user, sh, timeout=30, selfname=None):
        self.calls.append(sh)
        cmd = _as_account34(user, sh, selfname)
        for real, path in self.paths.items():
            cmd = cmd.replace(real, path)
        out = _bash34(cmd)
        hook, self.hook = self.hook, None
        if hook:
            hook()
        return out

    def write(self, n, tag, real=None, width=64):
        """Append n lines of exactly `width` bytes to `real`'s copy (the first one's by default)."""
        new = ["%s %06d %s" % (tag, i, "x" * (width - 12)) for i in range(n)]
        with open(self.paths[real or next(iter(self.paths))], "a", encoding="utf-8") as fh:
            fh.write("".join(x + "\n" for x in new))
        return new


def _end_pushes38(gs_id, remote, action="update"):
    """End `action`'s tail as its worker does; return the lines each _console_push carried, per push."""
    pushes = []
    push = _sh38._console_push

    def _seen(app, server_id, text, ts=None):
        pushes.append([ln for ln in str(text).split("\n") if ln.strip()])
        push(app, server_id, text, ts)
    _sh38._console_push = _seen
    try:
        _sh38._end_action_tail(_p9, gs_id, remote, action, 0)
    finally:
        _sh38._console_push = push
    return pushes


_NOTICE38 = "(earlier output of this update is not shown here; all of it is in /home/mcsrv38/.panel-update.log)"


def _unwatched_update38(loop, gs_id, admin, sio, n, label, width=64, cut=True):
    """An update writing n lines of `width` bytes that runs start to end while its only tab is away."""
    real = _sh38._action_log_path("mcsrv38", "update")
    act = _ActRig38(real)
    _set38(_core38, "shell_as_game_user", act)
    _sh38._console_backlog.pop(gs_id, None)
    sio.emit("join_console", {"server_id": gs_id})
    _pass38(loop)
    sio.emit("leave_console", {"server_id": gs_id})      # the only tab, hidden past the grace
    _pass38(loop)
    _sh38._begin_action_tail(_p9, gs_id, "update", real, "mcsrv38")
    out = act.write(n, "UPD", width=width)
    for _ in range(3):
        _pass38(loop)
    drained = len(act.calls)
    pushes = _end_pushes38(gs_id, NS(host="192.0.2.38", name="p38-host"))
    sio.emit("join_console", {"server_id": gs_id})        # back in view: the page reads the backlog
    body = _p9_client(admin).get("/api/console/%d" % gs_id).get_json() or {}
    rows = [r.get("line") for r in body.get("panel_lines") or []]
    end = pushes[0] if len(pushes) == 2 else []
    told = [ln for ln in end if ln.startswith("UPD ")]
    # What a page coming back replays: the notice (when lines were left out) right above them.
    head = [_NOTICE38] if cut else []
    check("B server: an update writing %s of output while its only tab is away: nothing is drained while "
          "nobody watches, and its end makes ONE read, of the update's last whole lines — no more than the "
          "backlog keeps beside the end marker, every one kept — so the returning page shows them, in "
          "order, then how it ended%s" % (label, ", under a line that says the rest is in the output file"
                                           if cut else ", every line, and nothing said to be missing"),
          (drained, len(act.calls) - drained, pushes[-1:], end == head + told, told == out[-len(told):],
           len(told) >= 100, (len(told) == n) != cut, rows[-len(end) - 1:] == end + pushes[-1],
           gs_id in _sh38._action_output)
          == (0, 1, [["[panel] update finished successfully."]], True, True, True, True, True, False),
          repr((drained, len(act.calls) - drained, len(told), n, end[:1], rows[-len(end) - 1:][:2], rows[-1:],
                out[-1][:20])))
    sio.emit("leave_console", {"server_id": gs_id})


def _watched_end38(gs_id):
    """A WATCHED update's end, its last lines short and many: every one of them goes to the page."""
    remote = NS(host="192.0.2.38", name="p38-host")
    real = _sh38._action_log_path("mcsrv38", "update")
    act = _ActRig38(real)
    _set38(_core38, "shell_as_game_user", act)
    _sh38._console_backlog.pop(gs_id, None)
    _sh38._begin_action_tail(_p9, gs_id, "update", real, "mcsrv38")
    act.write(200, "OLD", width=49)
    _sh38._drain_action_output(_p9, remote, gs_id)        # the poller's tick, two seconds ago
    out = act.write(700, "FIN", width=49)                  # 34 KB in its last two seconds, then it exits
    pushes = _end_pushes38(gs_id, remote)
    check("B server: a watched update whose last two seconds print 700 short lines (34 KB, one drain's worth): its "
          "end pushes all 700 to the console being watched, in order, and says nothing is missing",
          pushes == [out, ["[panel] update finished successfully."]],
          repr(([len(p) for p in pushes], pushes[0][:1] if pushes else None)))
    _sh38._console_backlog.pop(gs_id, None)


# LinuxGSM's colour, an erase-line, a window title (OSC) and a progress line redrawn with \r.
_COLOUR38 = "\x1b[0;32m[  OK  ]\x1b[0m Starting\x1b[K\n\x1b]0;steamcmd\x07done\nProgress 10%\rProgress 20%\rProgress 100%\n"


def _end_colour38(gs_id):
    """The end read's push is rendered as the drain's is: colour canonical, every other escape gone."""
    remote = NS(host="192.0.2.38", name="p38-host")
    real = _sh38._action_log_path("mcsrv38", "update")
    for label, before in (("a watched action's end", 0), ("an unwatched action's end (its last lines)", 300 * 1024)):
        act = _ActRig38(real)
        _set38(_core38, "shell_as_game_user", act)
        _sh38._console_backlog.pop(gs_id, None)
        _sh38._begin_action_tail(_p9, gs_id, "update", real, "mcsrv38")
        act.write(before // 64, "PRE")
        with open(act.paths[real], "a", encoding="utf-8") as fh:
            fh.write(_COLOUR38)
        _end_pushes38(gs_id, remote)
        sent = "\n".join(r["line"] for r in _sh38._console_backlog.get(gs_id, []))
        bare = _re38.sub(r"\x1b\[[0-9;]*m", "", sent)
        check("B server: " + label + " reaches the console coloured as LinuxGSM wrote it — [  OK  ] still green — "
              "and nothing else of the terminal's: no erase-line, no window title, no carriage return of a redrawn "
              "progress line, and no control byte but the colour's own",
              all(("\x1b[32m[  OK  ]\x1b[0m Starting" in sent, "\x1b[K" not in sent, "\x1b]" not in sent,
                   "steamcmd" not in sent, "\ndone\n" in sent, "\nProgress 100%\n" in sent,
                   not [ch for ch in bare if ord(ch) < 32 and ch != "\n"])),
              repr(sent[-160:]))
    _sh38._console_backlog.pop(gs_id, None)


def _server_ended_entry38(loop, gs_id, sio):
    """A pass while an action's own worker is reading the rest: the poller leaves that entry alone."""
    real = _sh38._action_log_path("mcsrv38", "update")
    act = _ActRig38(real)
    _set38(_core38, "shell_as_game_user", act)
    _sh38._action_output[gs_id] = {"action": "update", "path": real, "user": "mcsrv38", "pos": 0,
                                   "prev": None, "ended": True}
    act.write(10, "END")
    sio.emit("join_console", {"server_id": gs_id})
    _pass38(loop)
    _pass38(loop)
    check("B server: a watched console whose action has ended (its worker drains the rest): the poller does not "
          "drain it too, which would push the same bytes twice", act.calls == [],
          repr(act.calls[:2]))
    sio.emit("leave_console", {"server_id": gs_id})
    _sh38._action_output.pop(gs_id, None)
    _sh38._console_backlog.pop(gs_id, None)


def _inflight_end38(gs_id):
    """A poller tick whose read is still out when the action ends: that read is dropped, not pushed."""
    remote = NS(host="192.0.2.38", name="p38-host")
    real = _sh38._action_log_path("mcsrv38", "update")
    act = _ActRig38(real)
    _set38(_core38, "shell_as_game_user", act)
    _sh38._console_backlog.pop(gs_id, None)
    _sh38._begin_action_tail(_p9, gs_id, "update", real, "mcsrv38")
    out = act.write(10, "INF")

    def _ends():
        out.extend(act.write(2, "INF"))        # the update's last words, then it exits
        _sh38._end_action_tail(_p9, gs_id, remote, "update", 0)
    act.hook = _ends                           # …while the tick below is still waiting on its read
    _sh38._drain_action_output(_p9, remote, gs_id)
    rows = [r["line"] for r in _sh38._console_backlog.get(gs_id, [])]
    check("B server: a poller tick whose read is still out when the action ends: the end's own read shows the "
          "output once, and the tick's stale copy is dropped — nothing after '[panel] update finished'",
          rows == ["[panel] update started — its output follows."] + out + ["[panel] update finished successfully."]
          and gs_id not in _sh38._action_output, repr((len(rows), rows[-3:])))
    _sh38._console_backlog.pop(gs_id, None)
    # The server deleted while a tick's read is out (forget_rows drops its registration): its id may be
    # another server's by the time the read answers, so nothing of it may land in that console.
    _sh38._begin_action_tail(_p9, gs_id, "update", real, "mcsrv38")
    _sh38._console_backlog.pop(gs_id, None)
    act.write(3, "DEL")
    act.hook = lambda: _ps38.forget_rows(server_ids=[gs_id])
    _sh38._drain_action_output(_p9, remote, gs_id)
    check("B server: ...and a tick whose read is still out when the server is deleted pushes nothing into what "
          "may by then be another server's console", gs_id not in _sh38._console_backlog,
          repr(_sh38._console_backlog.get(gs_id, [])[-2:]))
    _sh38._end_action_tail(_p9, gs_id, remote, "update", 0)      # its worker ends it: says nothing
    _sh38._console_backlog.pop(gs_id, None)


def _begun_during_end38(gs_id):
    """An action begun while another's end is reading: it stays tailed, and its own end shows its output."""
    remote = NS(host="192.0.2.38", name="p38-host")
    ru, rv = (_sh38._action_log_path("mcsrv38", a) for a in ("update", "validate"))
    act = _ActRig38(ru, rv)
    _set38(_core38, "shell_as_game_user", act)
    _sh38._console_backlog.pop(gs_id, None)
    _sh38._begin_action_tail(_p9, gs_id, "update", ru, "mcsrv38")
    act.write(5, "UPD", ru)
    act.hook = lambda: _sh38._begin_action_tail(_p9, gs_id, "validate", rv, "mcsrv38")
    _sh38._end_action_tail(_p9, gs_id, remote, "update", 0)
    reg = (_sh38._action_output.get(gs_id) or {}).get("action")
    val = act.write(50, "VAL", rv)
    _sh38._end_action_tail(_p9, gs_id, remote, "validate", 0)
    rows = [r["line"] for r in _sh38._console_backlog.get(gs_id, [])]
    check("B server: Validate clicked while Update's end is reading: Validate stays tailed, and its end shows all "
          "of its output, then how it ended", (reg, [r for r in rows if r.startswith("VAL ")] == val, rows[-1:],
                                               gs_id in _sh38._action_output)
          == ("validate", True, ["[panel] validate finished successfully."], False),
          repr((reg, len([r for r in rows if r.startswith("VAL ")]), rows[-2:])))
    _sh38._console_backlog.pop(gs_id, None)


def _recv38(sio):
    """(pushes, answers) this socket received since the last look: console_output and console_catchup payloads."""
    got = sio.get_received()
    return ([(m.get("args") or [{}])[0] for m in got if m.get("name") == "console_output"],
            [(m.get("args") or [{}])[0] for m in got if m.get("name") == "console_catchup"])


def _rows_of38(payloads):
    return [r["line"] for p in payloads for r in (p.get("rows") or [])]


def _lines_of38(answer):
    return [r["line"] for r in (answer or {}).get("lines") or []]


_FIRST_LOOK38 = "stat -c '%i %s' "     # the poller's plain first look (_console_log_stat)


def _server_catchup38(loop, rig, gs_id, sio):
    """Leave, write, come back asking to be caught up: the answer is exactly the lines since the page's place."""
    sio.emit("join_console", {"server_id": gs_id})
    _pass38(loop)
    new = rig.write(2)
    _pass38(loop)
    pushes, _ = _recv38(sio)
    ino, size = os.stat(rig.path).st_ino, os.path.getsize(rig.path)
    at = pushes[-1].get("at") if pushes else None
    check("B catch-up: each push says where in the log its lines end — [chain, inode, byte offset], the offset the "
          "file's own size after them", _rows_of38(pushes) == new and isinstance(at, list) and at[1:] == [ino, size],
          repr((at, ino, size)))
    ack = sio.emit("leave_console", {"server_id": gs_id}, callback=True)
    check("B catch-up: the leave is answered with where the poller stands, the same place the last push ended",
          ack == at, repr((ack, at)))
    _pass38(loop)
    away = rig.write(5)
    n = len(rig.calls)
    sio.emit("join_console", {"server_id": gs_id, "catchup": {"id": 1, "since": at}})
    _pass38(loop)
    pushes, answers = _recv38(sio)
    a = answers[0] if len(answers) == 1 else {}
    size = os.path.getsize(rig.path)
    check("B catch-up: rejoined asking to be caught up from that place, the next pass answers with exactly the lines "
          "written since — from the log itself, matched by nothing — cut at the log's end, which is where the poller "
          "goes on from (no first look of its own)",
          (a.get("id"), _lines_of38(a), a.get("since"), a.get("gap"), a.get("readable"), (a.get("at") or [None])[1:],
           pushes, any(c.startswith(_FIRST_LOOK38) for c in rig.calls[n:]))
          == (1, away, True, False, True, [ino, size], [], False), repr((a, pushes, rig.calls[n:])))
    more = rig.write(2)
    _pass38(loop)
    pushes, _ = _recv38(sio)
    check("B catch-up: ...and the next push starts right after the answer's cut, in the same chain",
          _rows_of38(pushes) == more and (pushes[-1].get("at") or [None, 0, 0])[0::2] == [(a.get("at") or [0])[0],
                                                                                  os.path.getsize(rig.path)],
          repr(pushes))
    sio.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)


def _server_since_midline38(loop, rig, gs_id, sio):
    """The page's place lies inside a line — its last push's read ended there — and it is caught up from it whole."""
    sio.emit("join_console", {"server_id": gs_id})
    _pass38(loop)
    first = rig.write(1)
    with open(rig.path, "a", encoding="utf-8") as fh:
        fh.write("[p38] Loading map... ")
    _pass38(loop)                       # pushes the whole line and holds the rest: its place is past that half
    pushes, _ = _recv38(sio)
    at = pushes[-1]["at"] if pushes else [0, 0, 0]
    half = os.path.getsize(rig.path)
    sio.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)
    with open(rig.path, "a", encoding="utf-8") as fh:
        fh.write("done\n")
    away = rig.write(2)
    sio.emit("join_console", {"server_id": gs_id, "catchup": {"id": 12, "since": at}})
    _pass38(loop)
    _, answers = _recv38(sio)
    a = answers[0] if answers else {}
    check("B catch-up: the page's place inside a line (the read that brought its last push ended halfway through "
          "one, held back): caught up from there, that line comes whole, then what followed",
          (_rows_of38(pushes), at[2] == half, _lines_of38(a), a.get("since"))
          == (first, True, ["[p38] Loading map... done"] + away, True), repr((at, half, a)))
    sio.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)


def _server_midline38(loop, rig, gs_id, a, b):
    """The log ends inside a line when the page is caught up: that line is shown once, whole (F3)."""
    for label, other in (("nobody else watching: the answer makes the poller's first look", False),
                         ("another tab's join took a first look there just before", True)):
        start = rig.write(1)
        with open(rig.path, "a", encoding="utf-8") as fh:
            fh.write("[p38] Loading map... ")
        if other:
            b.emit("join_console", {"server_id": gs_id})
            _pass38(loop)                                   # b's first look: the offset lies inside the line
        a.emit("join_console", {"server_id": gs_id, "catchup": {"id": 2, "since": None}})
        _pass38(loop)
        _, answers = _recv38(a)
        with open(rig.path, "a", encoding="utf-8") as fh:
            fh.write("done\n")
        rig.lines.append("[p38] Loading map... done")
        more = rig.write(1)
        _pass38(loop)
        pushes, _ = _recv38(a)
        last = _lines_of38(answers[0] if answers else {})[-1:]
        check("B catch-up: the log ending inside a line at the answer (" + label + "): the answer stops before that "
              "line, and the next push carries it whole — never a piece of it on a line of its own",
              last == start and _rows_of38(pushes) == ["[p38] Loading map... done"] + more,
              repr((last, start, _rows_of38(pushes))))
        for s in (a, b):
            s.emit("leave_console", {"server_id": gs_id})
        _pass38(loop)
        _recv38(b)


def _server_snapshot38(loop, rig, gs_id, a, b):
    """Another tab keeps the stream going: the answer is cut where the POLLER stands, not where the file ends."""
    b.emit("join_console", {"server_id": gs_id})
    _pass38(loop)
    rig.write(2)
    _pass38(loop)
    pushes, _ = _recv38(b)
    since = pushes[-1]["at"]
    away = rig.write(3)
    _pass38(loop)                                          # pushed to b only
    with open(rig.path, "a", encoding="utf-8") as fh:
        fh.write("[p38] half a li")                        # the poller reads this and holds it
    _pass38(loop)
    unread = rig.write(2)                                  # written after the poller's last read
    rig.lines[-2] = "[p38] half a li" + rig.lines[-2]      # the half line and the first of these are one line
    a.emit("join_console", {"server_id": gs_id, "catchup": {"id": 3, "since": since}})
    _pass38(loop)
    pa, answers = _recv38(a)
    ans = answers[0] if answers else {}
    check("B catch-up: another tab keeping the stream: the answer is cut where the poller stands — the lines it has "
          "pushed since the page's place, not the line it holds half of, nor what it has not read yet — and the "
          "pass's push then brings those, starting with the held line whole",
          (_lines_of38(ans), ans.get("since"), ans.get("at", [None])[0] == since[0], _rows_of38(pa))
          == (away, True, True, ["[p38] half a li" + unread[0]] + unread[1:]), repr((ans, _rows_of38(pa))))
    for s in (a, b):
        s.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)
    _recv38(b)


def _server_since_out38(loop, rig, gs_id, sio):
    """A place the answer cannot start from: another log (a restart), or further back than it reaches."""
    sio.emit("join_console", {"server_id": gs_id})
    _pass38(loop)
    rig.write(1)
    _pass38(loop)
    pushes, _ = _recv38(sio)
    since = pushes[-1]["at"]
    sio.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)
    rig.write(2100)
    sio.emit("join_console", {"server_id": gs_id, "catchup": {"id": 4, "since": since}})
    _pass38(loop)
    _, answers = _recv38(sio)
    a = answers[0] if answers else {}
    check("B catch-up: more than 2000 lines written since the page's place: the answer is their last 2000, and says "
          "the rest is not shown", (len(_lines_of38(a)), _lines_of38(a)[-1:], a.get("since"), a.get("gap"))
          == (2000, rig.lines[-1:], True, True), repr({k: a.get(k) for k in ("since", "gap", "at")}))
    sio.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)
    sio.emit("join_console", {"server_id": gs_id, "catchup": {"id": 9, "since": None}})
    _pass38(loop)
    _, answers = _recv38(sio)
    a = answers[0] if answers else {}
    check("B catch-up: a page with no place of its own is sent the log's last 2000 lines, to place by their text — "
          "nothing said to be missing, as it had no place for anything to be missing from",
          (len(_lines_of38(a)), _lines_of38(a)[-1:], a.get("since"), a.get("gap"))
          == (2000, rig.lines[-1:], False, False), repr({k: a.get(k) for k in ("since", "gap", "at")}))
    sio.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)
    far = [since[0], since[1], 0]                         # the start of the log: more than the reach behind
    _set38(_sf38, "_CATCHUP_REACH", 4096)
    sio.emit("join_console", {"server_id": gs_id, "catchup": {"id": 5, "since": far}})
    _pass38(loop)
    _, answers = _recv38(sio)
    a = answers[0] if answers else {}
    _set38(_sf38, "_CATCHUP_REACH", _SAVED38[(_sf38, "_CATCHUP_REACH")])
    check("B catch-up: a place further back than the answer reaches: the log's last lines within the reach, whole, "
          "and it says the rest is not shown", (a.get("since"), a.get("gap"), bool(_lines_of38(a)),
                                                set(_lines_of38(a)) <= set(rig.lines), _lines_of38(a)[-1:])
          == (False, True, True, True, rig.lines[-1:]), repr({k: a.get(k) for k in ("since", "gap", "at")}))
    sio.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)
    _server_since_rotated38(loop, rig, gs_id, sio, since)


def _server_since_rotated38(loop, rig, gs_id, sio, since):
    """The page's place is in a log the server has since rotated away (it restarted while the page was away)."""
    os.rename(rig.path, rig.path + ".old")                 # LinuxGSM's start: mv the log away, then a new one
    with open(rig.path, "w", encoding="utf-8"):
        pass
    fresh = rig.write(4)
    sio.emit("join_console", {"server_id": gs_id, "catchup": {"id": 6, "since": since}})
    _pass38(loop)
    _, answers = _recv38(sio)
    a = answers[0] if answers else {}
    check("B catch-up: the server restarted while the page was away (a new log): the answer is the new log, and says "
          "what came before it is not shown", (_lines_of38(a), a.get("since"), a.get("gap"),
                                               (a.get("at") or [0, 0])[1] == os.stat(rig.path).st_ino)
          == (fresh, False, True, True), repr(a))
    sio.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)
    os.remove(rig.path + ".old")


def _server_unread38(loop, rig, gs_id, sio):
    """The host does not answer the catch-up's read: asked again on two more passes, then the page is told."""
    real = rig.__call__

    def _fails(server, user, sh, timeout=30, selfname=None):
        if "exec 3<" in sh:
            rig.calls.append(sh)
            return "", "SSH command timed out", -1         # tailscale/local: no raise, no frame
        return real(server, user, sh, timeout, selfname)
    _set38(_core38, "read_as_game_user", _fails)
    sio.emit("join_console", {"server_id": gs_id, "catchup": {"id": 7, "since": None}})
    told = []
    for _ in range(3):
        _pass38(loop)
        told.append([x.get("readable") for x in _recv38(sio)[1]])
    _set38(_core38, "read_as_game_user", rig)
    check("B catch-up: a read the host does not answer is not an answer: tried on the next two passes, then the page "
          "is told the log was not read (it asks again itself)", told == [[], [], [False]], repr(told))
    sio.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)


def _server_ack_scope38(loop, rig, gs_id, admin, b):
    """The leave's answer, and the catch-up, only for a socket that watches this console."""
    c = _sio38(admin)
    try:
        b.emit("join_console", {"server_id": gs_id})          # someone else watches: the poller has a place
        _pass38(loop)
        held = gs_id in _ps38._console_offsets
        ack = c.emit("leave_console", {"server_id": gs_id}, callback=True)
        b.emit("leave_console", {"server_id": gs_id})
        c.emit("join_console", {"server_id": gs_id, "catchup": {"id": 8, "since": None}})
        c.emit("leave_console", {"server_id": gs_id})
        n = len(rig.calls)
        _pass38(loop)
        check("B catch-up: a socket that was not watching the console gets no place from leaving it, and a catch-up "
              "asked by a socket that left before the pass is neither read for nor answered",
              held and not ack and len(rig.calls) == n and _recv38(c) == ([], []), repr((held, ack, rig.calls[n:])))
        c.emit("join_console", {"server_id": gs_id, "catchup": {"id": 14, "since": None}})
        c.emit("leave_console", {"server_id": gs_id})
        c.emit("join_console", {"server_id": gs_id})          # back before any pass, asking nothing this time
        _pass38(loop)
        check("B catch-up: ...nor when that socket joins again, before a pass, asking for none: the catch-up went with "
              "its leave", not [x for x in rig.calls[n:] if "exec 3<" in x] and _recv38(c)[1] == [], repr(rig.calls[n:]))
        c.emit("leave_console", {"server_id": gs_id})
        _pass38(loop)
    finally:
        c.disconnect()


def _server_rotated_before_serve38(loop, rig, gs_id, a, b):
    """The log rotates after the poller's last tick and before the pass that answers: no answer from the old place."""
    b.emit("join_console", {"server_id": gs_id})
    _pass38(loop)
    rig.write(2)
    _pass38(loop)
    pushes, _ = _recv38(b)
    old = pushes[-1]["at"]
    os.rename(rig.path, rig.path + ".old")                 # LinuxGSM's start: mv the log away, then a new one
    with open(rig.path, "w", encoding="utf-8"):
        pass
    fresh = rig.write(3)
    a.emit("join_console", {"server_id": gs_id, "catchup": {"id": 10, "since": old}})
    _pass38(loop)                                          # the log moved under the poller's place: no answer
    first = _recv38(a)
    _pass38(loop)                                          # its tick saw the rotation; now the answer
    pushes, answers = _recv38(a)
    ans = answers[0] if answers else {}
    check("B catch-up: the log rotated after the poller's last read and before the pass that would answer: that pass "
          "answers nothing (the place it stands is in the old log) and its tick reads the new one; the next answers "
          "from there — the new log's lines in it, none of them pushed again, and a later chain",
          (first[1], _rows_of38(first[0]), _lines_of38(ans), ans.get("gap"), pushes, (ans.get("at") or [0])[0] > old[0])
          == ([], fresh, fresh, True, [], True), repr((first, ans, pushes)))
    for s in (a, b):
        s.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)
    _recv38(b)
    os.remove(rig.path + ".old")


def _server_long_line38(loop, rig, gs_id, a, b):
    """A line longer than the poller holds (64 KB): pushed on its own, it is a line in an answer too, and once."""
    b.emit("join_console", {"server_id": gs_id})
    _pass38(loop)
    _recv38(b)
    rig.write(1)
    _pass38(loop)
    since = _recv38(b)[0][-1]["at"]
    blob = "B" * 70000
    with open(rig.path, "a", encoding="utf-8") as fh:
        fh.write(blob)                                     # no newline: held, then pushed on its own
    _pass38(loop)
    _pass38(loop)
    flushed = _rows_of38(_recv38(b)[0])
    a.emit("join_console", {"server_id": gs_id, "catchup": {"id": 11, "since": since}})
    _pass38(loop)
    _, answers = _recv38(a)
    with open(rig.path, "a", encoding="utf-8") as fh:
        fh.write("tail\n")
    more = rig.write(1)
    _pass38(loop)
    pa, _ = _recv38(a)
    check("B catch-up: a line the game writes longer than the poller holds, pushed on its own: the answer has it, "
          "once, and the next push does not bring it again",
          flushed == [blob] and _lines_of38(answers[0] if answers else {}) == [blob] and _rows_of38(pa) == ["tail"] + more,
          repr(([len(x) for x in flushed], [len(x) for x in _lines_of38(answers[0] if answers else {})],
                [x[:20] for x in _rows_of38(pa)])))
    for s in (a, b):
        s.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)
    _recv38(b)


def _server_place_read38(loop, rig, gs_id, admin, sio):
    """/api/console's return read for a page whose socket is down: from its place, to the end, the poller untouched."""
    http = _p9_client(admin)
    sio.emit("join_console", {"server_id": gs_id})
    _pass38(loop)
    rig.write(1)
    _pass38(loop)
    at = (_recv38(sio)[0] or [{}])[-1].get("at") or [0, 0, 0]
    sio.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)
    away = rig.write(3)
    with open(rig.path, "a", encoding="utf-8") as fh:
        fh.write("[p38] Loading map... ")
    before = dict(_ps38._console_offsets.get(gs_id) or {})
    n = len(rig.calls)
    body = http.get("/api/console/%d?lines=2000&place=1&since=%d-%d" % (gs_id, at[1], at[2])).get_json() or {}
    size, ino = os.path.getsize(rig.path), os.stat(rig.path).st_ino
    check("B place read: /api/console asked for the time away from the page's place (its socket down) answers with "
          "exactly the lines written since — not the line the log ends inside of — and the log's end as the place it "
          "leaves the page at, in ONE read, the poller's own place untouched",
          ([r["line"] for r in body.get("lines") or []], body.get("since"), body.get("gap"), body.get("at"),
           len(rig.calls) - n, (_ps38._console_offsets.get(gs_id) or {}) == before)
          == (away, True, False, [0, ino, size], 1, True), repr((body, rig.calls[n:])))
    _server_place_read_on38(rig, gs_id, http, away, [0, ino, size])


def _server_place_read_on38(rig, gs_id, http, away, place):
    """The place read with no place, and again from the place the first one left the page at."""
    whole = http.get("/api/console/%d?lines=2000&place=1" % gs_id).get_json() or {}
    check("B place read: ...and asked with no place, the log's last lines, for the page to place by their text, with "
          "nothing said to be missing", ([r["line"] for r in whole.get("lines") or []][-3:], whole.get("since"),
                                         whole.get("gap")) == (away, False, False), repr(whole)[:300])
    with open(rig.path, "a", encoding="utf-8") as fh:
        fh.write("done\n")
    rig.lines.append("[p38] Loading map... done")
    on = http.get("/api/console/%d?lines=2000&place=1&since=%d-%d" % (gs_id, place[1], place[2])).get_json() or {}
    check("B place read: ...and from the place that read left the page at, the line it ended inside of, whole",
          [r["line"] for r in on.get("lines") or []] == ["[p38] Loading map... done"], repr(on)[:300])


def _server_ahead38(loop, rig, gs_id, a, b):
    """A page whose read of the time away went past where the poller stands is caught up once the poller passes it."""
    b.emit("join_console", {"server_id": gs_id})
    _pass38(loop)
    rig.write(2)
    _pass38(loop)
    _recv38(b)
    ahead = rig.write(3)                                   # written after the poller's last read
    place = [0, os.stat(rig.path).st_ino, os.path.getsize(rig.path)]
    a.emit("join_console", {"server_id": gs_id, "catchup": {"id": 13, "since": place}})
    _pass38(loop)                                          # its place is past the poller's: it waits; the tick reads on
    early = _recv38(a)
    more = rig.write(1)
    _pass38(loop)
    pushes, answers = _recv38(a)
    ans = answers[0] if answers else {}
    check("B catch-up: a page whose place is past where the poller stands (its own read of the time away went "
          "further): no answer until the poller's tick has passed it, then exactly what came after its place — "
          "the lines the tick pushed meanwhile dropped by the page as before the cut, nothing said to be missing",
          (early[1], _rows_of38(early[0]), _lines_of38(ans), ans.get("since"), ans.get("gap"), _rows_of38(pushes))
          == ([], ahead, [], True, False, more), repr((early, ans, pushes)))
    for s in (a, b):
        s.emit("leave_console", {"server_id": gs_id})
    _pass38(loop)
    _recv38(b)


def _report_label38():
    """The debug report names the catch-up's read as such among a game account's sudo calls."""
    from panel.ops.debug_report import logs as _lg38
    bodies = [_sf38._catchup_cmd("/home/mcsrv38/log/console/mcserver-console.log", cut, since, "n" * 24)
              for cut, since in ((None, None), ((7, 99), (7, 50)))]
    lines = ["Oct 04 12:00:0%d host sudo[%d]: " % (i, 3800 + i) + "  ubuntu : PWD=/home/ubuntu ; USER=mcsrv38 ; "
             "COMMAND=/usr/bin/bash -c %s" % b for i, b in enumerate(bodies)]
    _kept, verbs, _s = _lg38._split_priv(lines)
    check("B catch-up: the debug report counts the catch-up's read as 'console catch-up' among a game account's "
          "calls, not as some other console read", verbs.get(_lg38.GAME_ACCOUNT) == {"console catch-up": 2},
          repr(verbs))


def _section_server38(rig, gs_id, admin):
    loop = _poller38()
    check("B server: register() hands the console poller to its supervisor (so a pass can be driven)",
          loop is not None, "")
    if loop is None:
        return
    a, b = _sio38(admin), _sio38(admin)
    try:
        check("B server: an administrator's test sockets connect", a.is_connected() and b.is_connected(), "")
        _server_join_leave38(loop, rig, gs_id, a)
        _server_two_tabs38(loop, rig, gs_id, a, b)
        _server_never_joined38(loop, rig, admin)
        _server_backlog_key38(gs_id, admin, a)
        _unwatched_update38(loop, gs_id, admin, a, 3000, "192 KB")
        _unwatched_update38(loop, gs_id, admin, a, 16384, "1 MB")
        _unwatched_update38(loop, gs_id, admin, a, 600, "600 KB in 1 KB lines", width=1000)
        _unwatched_update38(loop, gs_id, admin, a, 150, "300 KB in lines of 2047 characters", width=2048)
        _unwatched_update38(loop, gs_id, admin, a, 300, "80 KB in 300 lines", width=270, cut=False)
        _watched_end38(gs_id)
        _end_colour38(gs_id)
        _server_ended_entry38(loop, gs_id, a)
        _inflight_end38(gs_id)
        _begun_during_end38(gs_id)
        # The catch-up's own log: thousands of lines, which C's page (primed from 250) does not want.
        cu = _Rig38(rig.real, "catchup")
        _set38(_core38, "read_as_game_user", cu)
        try:
            _server_catchup38(loop, cu, gs_id, a)
            _server_since_midline38(loop, cu, gs_id, a)
            _server_midline38(loop, cu, gs_id, a, b)
            _server_snapshot38(loop, cu, gs_id, a, b)
            _server_since_out38(loop, cu, gs_id, a)
            _server_unread38(loop, cu, gs_id, a)
            _server_ack_scope38(loop, cu, gs_id, admin, b)
            _server_rotated_before_serve38(loop, cu, gs_id, a, b)
            _server_long_line38(loop, cu, gs_id, a, b)
            _server_place_read38(loop, cu, gs_id, admin, a)
            _server_ahead38(loop, cu, gs_id, a, b)
            _report_label38()
        finally:
            _set38(_core38, "read_as_game_user", rig)
    finally:
        for s in (a, b):
            s.disconnect()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# C: the real server's payloads, replayed into the real page
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Tape38:
    """What the real server did, as steps for the page, in the order it did them."""

    def __init__(self, rig, gs_id, admin):
        self.rig, self.gs_id, self.steps = rig, gs_id, []
        self.loop, self.sio, self.http = _poller38(), _sio38(admin), _p9_client(admin)
        self.url = "/api/console/%d" % gs_id

    def window(self, query=""):
        return self.http.get(self.url + query).get_json()

    def answer(self, body, query=""):
        self.steps.append({"op": "respond", "url": self.url + query, "body": body})

    def tick(self):
        _pass38(self.loop)

    def tick_only(self):
        """The tick of a pass that had already gone past this console's catch-ups when the join landed."""
        with _p9.app_context():
            _sf38._console_tick(_p9, _p9.socketio, db.session.get(GameServer, self.gs_id), self.gs_id)

    def record(self):
        """What the socket received, in order, as steps; the `at` of the last push, if any."""
        at = None
        for m in self.sio.get_received():
            data = (m.get("args") or [{}])[0]
            if m.get("name") == "console_output":
                self.steps.append({"op": "push", "data": data})
                at = data.get("at") or at
            elif m.get("name") == "console_catchup":
                self.steps.append({"op": "event", "name": "console_catchup", "data": data})
        return at

    def page(self, *steps):
        self.steps.extend(steps)

    def away(self, emitted):
        """The tab hidden past the grace; it leaves, and the server's answer to the leave reaches it."""
        self.page({"op": "hide", "v": True}, {"op": "advance", "ms": 30000},
                  {"op": "emits", "from": emitted, "want": ["leave_console"]})
        ack = self.sio.emit("leave_console", {"server_id": self.gs_id}, callback=True)
        self.page({"op": "ack", "name": "leave_console", "value": ack})
        self.tick()
        return ack

    def back(self, emitted, catchup):
        """Back in view: it joins, asking to be caught up as `catchup` says, and its 30 s poll reads the window."""
        join = {"server_id": self.gs_id, "catchup": catchup}
        self.page({"op": "hide", "v": False}, {"op": "emits", "from": emitted, "want": ["join_console"], "data": join})
        self.sio.emit("join_console", join)
        self.answer(self.window())


def _tape38(rig, gs_id, admin):
    t = _Tape38(rig, gs_id, admin)
    other = _sio38(admin)
    try:
        t.page({"op": "connect"})
        t.answer(t.window())
        t.sio.emit("join_console", {"server_id": gs_id})
        t.tick()
        rig.write(2)
        t.tick()
        at = t.record()
        # 1. Nobody else watching: back in view, caught up from its place; lines before and after the pass.
        t.away(1)
        rig.write(5)
        t.back(2, {"id": 1, "since": at})
        rig.write(3)
        t.tick()                    # the answer (cut at the log's end: the poller's first look), then its tick
        rig.write(2)
        t.tick()
        at = t.record()
        # 2. Another tab keeps the stream: a push reaches the page after its join and BEFORE the answer.
        other.emit("join_console", {"server_id": gs_id})
        t.tick()
        t.away(3)
        rig.write(4)
        t.tick()                    # to the other tab only
        t.back(4, {"id": 2, "since": at})
        rig.write(2)
        t.tick_only()               # this push lies before the answer's cut
        rig.write(1)
        t.tick()                    # the answer, cut where the poller stands, then its push
        rig.write(1)
        t.tick()
        t.record()
        t.sio.emit("leave_console", {"server_id": gs_id})
        other.emit("leave_console", {"server_id": gs_id})
        t.tick()
    finally:
        t.sio.disconnect()
        other.disconnect()
    return t.steps


def _section_replay38(rig, gs_id, admin):
    steps = _tape38(rig, gs_id, admin)
    out = _node38({"src": _SRC38, "panel": _PANEL38, "mode": "replay", "serverId": gs_id, "steps": steps})
    if out is None:
        skip("C replay: the real server's payloads into the real page", "no node on this host")
        return
    shown = [ln for ln in out.get("lines") or [] if ln.startswith("[p38] line")]
    check("C replay: the real server's pushes, answers and windows, in the order it produced them, reach the real page "
          "as the file: each line once, in order, none missing — across a return caught up with nobody else "
          "watching, and one with another tab keeping the stream and a push arriving before the answer",
          not out.get("loadError") and not out.get("errors") and shown == rig.lines and not out.get("pending")
          and out.get("gaps") == 0,
          repr({k: out.get(k) for k in ("loadError", "errors", "pending", "gaps")})
          + " shown %d of %d; tail %r" % (len(shown), len(rig.lines), shown[-6:]))
    check("C replay: ...and the page left and rejoined exactly twice, asking each time to be caught up from its own "
          "place", out.get("emitted") == ["join_console", "leave_console", "join_console", "leave_console",
                                          "join_console"], repr(out.get("emitted")))


# ════════════════════════════════════════════════════════════════════════════════════════════════
def _run38():
    _section_page38()
    _arm38()
    _set38(_sf38, "_host_timezone_cached", lambda *a, **k: "")
    with _p9.app_context():
        host_id, gs_id, admin, real = _rows38()
    rig = _Rig38(real)
    _set38(_core38, "read_as_game_user", rig)
    try:
        _section_server38(rig, gs_id, admin)
        _section_replay38(rig, gs_id, admin)
    finally:
        _ps38.forget_rows(remote_ids=[host_id], server_ids=[gs_id])
        with _p9.app_context():
            for model, row_id in ((GameServer, gs_id), (User, admin), (RemoteServer, host_id)):
                row = db.session.get(model, row_id)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()
    check("console-idle: nothing in this part reached a real SSH or local transport", _TRIP38 == [], repr(_TRIP38))


try:
    _run38()
except Exception as _e38:  # noqa: BLE001 - a harness failure must fail by name, not end the suite
    import traceback as _tb38
    check("console-idle: the part ran to the end", False,
          "raised %s: %s\n%s" % (type(_e38).__name__, _e38, _tb38.format_exc()[-1500:]))
finally:
    _restore38()
    _shutil38.rmtree(_TMP38, ignore_errors=True)
