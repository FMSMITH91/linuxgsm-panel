"""Part 38 of the unit suite: console-idle — a tab that stays hidden leaves its console.

A console someone has joined costs the panel one privileged read of its log every two seconds (the
poller in panel/routes/server_files.py): about 1,800 sudo calls an hour per watched console, for as
long as the tab stays open, looked at or not. static/js/server_detail.js now leaves the console's
room once its tab has stayed hidden for 30 s, and on the way back rejoins and catches up from the log
itself. Every check below is judged on the console's own job — output prompt, in order, complete and
unduplicated — and what holds it up is, one section each:

* A. THE PAGE. server_detail.js run WHOLE in node (a small DOM, a virtual clock, a fake socket that
     buffers as socket.io-client 4.8.4 does, a fetch the check answers, panel.js's own
     pollWhenVisible) against a model of the server's half
     of the console with the semantics B pins: a pass forgets a console nobody watches; a first look
     records where the log ends and reads nothing; each later pass pushes what was written since, to
     whoever is in the room right then; the window is the log's last lines at the moment it is read.
     Fixed orderings of the two feeds first, then random schedules, with a control proving those
     schedules catch what a plain rejoin (one window, pushes appended as they come) gets wrong.
* B. THE SERVER. Through flask-socketio's test client and the real console poller loop, reading a
     real file with bash: a room left empty is not read at all and its offset is forgotten; a rejoin
     is a first look, with no replay; a second tab keeps the reads going; a socket that never joined
     is never read; the panel backlog carries each push's time, the key the page dedupes by; and an
     update that runs while nobody watches is read to its end when it ends.
* C. BOTH. Payloads the real server produced — the poller's pushes, /api/console's windows — fed to
     the real page in the order the server produced them, for the two orderings a plain rejoin gets
     wrong.

Nothing here reaches a real transport: the console's reads go to the rig, the rest to a tripwire.
"""
import json as _json38
import os
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
    emit(e, d) {
      const pkt = [e, JSON.parse(JSON.stringify(d === undefined ? null : d))];
      let live = socket.connected;
      if (live && socket.pingExpired) {
        live = false;
        socket.pingExpired = false;
        Promise.resolve().then(() => { if (socket.connected) { socket.connected = false; fire('disconnect', 'ping timeout'); } });
      }
      if (live) emitted.push([pkt[0], pkt[1], now]); else socket.sendBuffer.push(pkt);
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
      for (const [e, d] of socket.sendBuffer.splice(0)) emitted.push([e, d, now]);
      fire('connect');
      await flush();
    },
    async disconnect() { socket.connected = false; fire('disconnect', 'transport close'); await flush(); },
    async push(d) { fire('console_output', d); await flush(); },
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
  };
}

// ── the server's half: the poller, the room, the log, the backlog, the window ───────────────────
// As panel/routes/server_files.py and _shared.py have it: a pass first forgets a console nobody
// watches; a watched console with no offset gets a FIRST SIGHT (its end recorded, nothing read);
// after that each pass pushes the whole lines written since, to whoever is in the room right then;
// the window is the log's last N lines at the moment it is read, with the backlog; a panel push
// goes to the backlog and to the room. `manual`: nothing happens until the caller says so.
function rng(seed) {
  let s = (seed * 2654435761) >>> 0 || 1;
  return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 4294967296; };
}

function makeWorld(o) {
  const rand = rng(o.seed || 1), between = (a, b) => a + Math.floor(rand() * (b - a + 1));
  const page = makePage(o);
  const lat = Object.assign({join: [5, 150], push: [5, 200], read: [5, 600], resp: [5, 600], pass: [0, 900]}, o.lat || {});
  let log = [], lineNo = 0, offset = null, ino = 1, connected = false, seenFetch = 0, seenEmit = 0;
  let pushFree = 0, sockFree = 0, seq = 0, lastT = 0;
  const backlog = [], room = new Set(), events = [], readsAt = [], served = [];
  const stats = {reads: 0, firstSights: 0, pushes: 0, windowReads: 0};
  const at = (t, fn) => events.push({at: t, seq: ++seq, fn});
  const nowS = () => page.now / 1000;
  const W = {page, log: () => log, backlog, room, stats, readsAt, rand, between, served};

  let deferNext = false;
  function deliver(payload) {
    if (!room.has('page') || !connected) return null;
    if (o.manual && deferNext) return () => page.push(payload);   // read now, arrives when called
    if (o.manual) return page.push(payload);
    pushFree = Math.max(page.now + between(...lat.push), pushFree);
    at(pushFree, async () => { if (connected) await page.push(payload); });
    return null;
  }
  W.passDeferred = function () { deferNext = true; try { return W.pass(); } finally { deferNext = false; } };
  W.pass = function () {
    if (room.size === 0) { offset = null; return null; }
    stats.reads++; readsAt.push(page.now);
    if (offset === null) { offset = {ino, pos: log.length}; stats.firstSights++; return null; }
    if (offset.ino !== ino) offset = {ino, pos: 0};      // rotated: the new log from its first line
    const lines = log.slice(offset.pos);
    offset.pos = log.length;
    if (!lines.length) return null;
    stats.pushes++;
    return deliver({server_id: page.ctx.serverId, data: lines.join('\n'), rows: lines.map(l => ({t: null, line: l})), ts: nowS()});
  };
  W.body = function (url) {
    const m = /lines=(\d+)/.exec(url), n = m ? Number(m[1]) : 250;
    stats.windowReads++;
    return {lines: log.slice(-n).map(l => ({t: null, line: l})), now: nowS(), readable: true,
            log_timestamps: false, panel_lines: backlog.map(b => ({t: b.t, line: b.line}))};
  };
  function onEmit(ev) {
    if (!connected) return;
    if (ev === 'join_console') room.add('page');
    if (ev === 'leave_console') room.delete('page');
  }
  function scan() {
    for (; seenEmit < page.emitted.length; seenEmit++) {
      const [ev, , sentAt] = page.emitted[seenEmit];
      if (o.manual) { onEmit(ev); continue; }
      sockFree = Math.max(sentAt + between(...lat.join), sockFree);
      at(sockFree, () => onEmit(ev));
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
  W.disconnect = async () => { connected = false; room.delete('page'); await page.disconnect(); scan(); };
  W.reconnect = async () => { connected = true; await page.connect(); scan(); };
  // The server dropped the page's socket while the page was frozen (a phone asleep past the ping
  // timeout): out of the room, while the page — which has not run since — still thinks it is
  // connected, until its next emit finds the ping expired.
  W.expire = () => { connected = false; room.delete('page'); page.socket.pingExpired = true; };
  W.hide = async (h, quiet) => { await page.setHidden(h, quiet); scan(); };
  W.advance = async ms => { await page.advance(ms); scan(); };
  W.other = (on) => { if (on) room.add('other'); else room.delete('other'); };
  // manual mode: the window reads, one by one, in the order the test says
  W.pending = re => page.fetches.filter(f => !f.done && f.url.indexOf('/api/console/') >= 0 && (!re || re.test(f.url)));
  W.read = f => { const b = W.body(f.url); served.push(f.url); return {f, b}; };
  W.reply = async (rd) => { await page.respond(rd.f, rd.b); scan(); };
  W.answer = async f => W.reply(W.read(f));
  // The 30 s console poll, which pollWhenVisible also runs on a return — made at the same moment as
  // the catch-up's first read. Answered at once, so what is left pending is the catch-up's own reads.
  W.settlePolls = async () => {
    const first = page.fetches.filter(f => !f.done && /lines=2000/.test(f.url));
    for (const f of page.fetches) {
      if (!f.done && f.url === '/api/console/' + page.ctx.serverId && first.some(g => g.at === f.at)) await W.answer(f);
    }
  };
  W.pageLog = () => page.lines(false).filter(l => /^L\d{5}/.test(l));
  W.pagePanel = () => page.lines(false).filter(l => !/^L\d{5}/.test(l));
  W.exact = () => JSON.stringify(W.pageLog()) === JSON.stringify(log);
  W.emits = name => page.emitted.filter(e => e[0] === name).length;
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
        JSON.stringify({early, leaves, fetched: w.page.fetches.slice(fetched).map(f => f.url)}));
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
  check('hidden for less than the grace (an alt-tab, a notification): nothing is sent, no catch-up is read, and '
        + 'pushes go on landing as before', w.page.emitted.length === emitted
        && !w.page.fetches.slice(fetched).some(f => /lines=2000/.test(f.url)) && w.exact() && w.room.has('page'),
        JSON.stringify({emits: w.page.emitted.slice(emitted), fetches: w.page.fetches.slice(fetched).map(f => f.url)}));
}

async function checkReturn(cfg) {
  const w = await awayAndBack(cfg);
  const joins = w.page.emitted.filter(e => e[0] === 'join_console');
  const first = w.pending();
  check('back in view: ONE join_console, and one read of the window reaching back as far as it can (?lines=2000)',
        joins.length === 2 && first.length === 1 && /\?lines=2000$/.test(first[0].url),
        JSON.stringify({joins: joins.length, pending: first.map(f => f.url)}));
  await w.answer(first[0]);
  check('...which shows at once everything written while the tab was away, after what it already showed, each line once',
        w.exact(), JSON.stringify({got: w.pageLog().slice(-8), want: w.log().slice(-8)}));
}

// The window answered BEFORE the poller's first look at the console, with lines written between:
// they are in neither the window nor any push, and only the second read can bring them.
async function checkOrderReadFirst(cfg) {
  const w = await awayAndBack(cfg);
  const w1 = w.read(w.pending()[0]);
  w.write(3);                 // between the window's read and the poller's first look
  w.pass();                   // first sight: records the end, reads nothing
  w.write(2);
  await w.reply(w1);
  await w.pass();             // pushes the two
  const anchor = w.pending();
  if (anchor[0]) await w.answer(anchor[0]);
  w.write(2); await w.pass();
  check('the window read BEFORE the poller\'s first look, with lines written in between: those lines are shown — '
        + 'once, in order — by the second read the first push asks for', anchor.length === 1 && w.exact(),
        JSON.stringify({anchor: anchor.map(f => f.url), got: w.pageLog().slice(-10), want: w.log().slice(-10)}));
}

// The second read answered AFTER more was written: the window holds lines the poller's stream has
// not reached yet, and its next push starts with them.
async function checkAhead(cfg) {
  const w = await awayAndBack(cfg);
  await w.answer(w.pending()[0]);
  w.pass();
  w.write(2); await w.pass();               // held; asks for the second read
  w.write(3);                               // written before that read…
  await w.answer(w.pending()[0]);
  w.write(1); await w.pass();               // …so this push starts with three lines already shown
  w.write(1); await w.pass();
  check('the second read reaching further than the poller had pushed: the lines it showed early are dropped from '
        + 'the next push, which shows only what follows them', w.exact() && !w.page.ctx._resync,
        JSON.stringify({got: w.pageLog().slice(-8), want: w.log().slice(-8)}));
}

async function checkDropWhileCatchingUp(cfg) {
  for (const back of [true, false]) {
    const w = await awayAndBack(cfg);
    await w.answer(w.pending()[0]);
    w.pass(); w.write(2); await w.pass();     // held, the second read asked for…
    const stuck = w.pending();                 // the second read, which never answers…
    await w.disconnect();                     // …because the socket (and the link) dropped under it
    w.write(3);
    const fresh = () => w.pending().filter(f => stuck.indexOf(f) < 0);
    if (back) {
      await w.reconnect();
      for (const f of fresh()) await w.answer(f);   // the reconnect: the return's catch-up, still owed
      w.pass(); w.write(2); await w.pass();
      for (const f of fresh()) await w.answer(f);
      w.write(1); await w.pass();
    } else {
      await w.advance(GRACE);                    // still down at the next 30 s console poll
      for (const f of fresh()) await w.answer(f);
    }
    check('a socket that drops while catching up abandons that catch-up, never waiting on the read that will not '
          + 'answer: ' + (back ? 'the reconnect catches up afresh' : 'still down, the 30 s console poll reads the log')
          + ', and the console shows everything, once',
          !w.page.ctx._resync && w.exact(),
          JSON.stringify({resync: !!w.page.ctx._resync, got: w.pageLog().slice(-8), want: w.log().slice(-8)}));
  }
}

// A push read BEFORE the second window but delivered after it: it lies wholly inside what that
// window already showed, so none of it is new.
async function checkInsideWindow(cfg) {
  const w = await awayAndBack(cfg);
  await w.answer(w.pending()[0]);
  w.pass();
  w.write(2); await w.pass();               // held; asks for the second read
  w.write(3);
  const late = w.passDeferred();            // read now, delivered after the second read answers
  w.write(1);
  await w.answer(w.pending()[0]);           // the window ends one line past that push
  if (late) await late();
  w.write(1); await w.pass();
  check('a push read before the second window but arriving after it shows nothing twice: its lines were all in '
        + 'the window, and what follows them shows once', w.exact() && !w.page.ctx._resync,
        JSON.stringify({got: w.pageLog().slice(-8), want: w.log().slice(-8)}));
}

// A catch-up read that never answers (no disconnect): the console is not held forever.
async function checkGiveUp(cfg) {
  const w = await awayAndBack(cfg);
  w.pass(); w.write(2); await w.pass();     // held, behind a first read that never answers
  await w.advance(44000);
  const held = w.pageLog().length;
  await w.advance(1000);
  w.write(1); await w.pass();
  check('a catch-up whose window read never answers is given up after 45 s: what it held is shown, once, and pushes '
        + 'land as they come again', held === 22 && !w.page.ctx._resync
        && JSON.stringify(w.pageLog().slice(-3)) === JSON.stringify(w.log().slice(-3))
        && new Set(w.pageLog()).size === w.pageLog().length,
        JSON.stringify({held, resync: !!w.page.ctx._resync, got: w.pageLog().slice(-5), want: w.log().slice(-5)}));
}

async function checkHiddenAgain(cfg) {
  const w = await awayAndBack(cfg);
  w.pass();
  await w.panelPush('[panel] validate finished successfully.');   // held until the first read
  await w.hide(true); await w.advance(GRACE);
  check('hidden again before the catch-up\'s first read answered: the panel line it was holding is shown, not lost, '
        + 'and the tab leaves again', w.pagePanel().indexOf('[panel] validate finished successfully.') >= 0
        && w.emits('leave_console') === 2 && !w.page.ctx._resync,
        JSON.stringify({panel: w.pagePanel(), leaves: w.emits('leave_console')}));
}

async function checkOrderPushFirst(cfg) {
  for (const pushFirst of [true, false]) {
    const w = await awayAndBack(cfg);
    w.pass();                 // the first look comes first
    w.write(3);
    const w1 = w.read(w.pending()[0]);   // the window has the three…
    if (pushFirst) { await w.pass(); await w.reply(w1); } else { await w.reply(w1); await w.pass(); }   // …and so does the push
    for (const f of w.pending()) await w.answer(f);
    w.write(2); await w.pass();
    check('the window read AFTER the poller\'s first look, the same lines in the window and in the push, the push '
          + (pushFirst ? 'arriving first' : 'arriving second') + ': each line shown once, in order', w.exact(),
          JSON.stringify({got: w.pageLog().slice(-10), want: w.log().slice(-10)}));
  }
}

async function checkQuiet(cfg) {
  const w = await awayAndBack(cfg);
  const w1 = w.read(w.pending()[0]);
  w.write(2);                 // the console's last words, between the read and the first look
  w.pass();
  await w.reply(w1);
  const before = w.pending().length;
  await w.advance(5900);
  const early = w.pending().length;
  await w.advance(100);
  const anchor = w.pending();
  if (anchor[0]) await w.answer(anchor[0]);
  check('a console that goes quiet after the return: what it wrote between the window and the poller\'s first look '
        + 'is shown by a second read 6 s later, once', before === 0 && early === 0 && anchor.length === 1 && w.exact(),
        JSON.stringify({before, early, anchor: anchor.map(f => f.url), got: w.pageLog().slice(-6), want: w.log().slice(-6)}));
  w.write(2); await w.pass();
  check('...and the next push after it is shown once', w.exact(), JSON.stringify(w.pageLog().slice(-6)));
}

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
  w.write(2);
  const w1 = w.read(w.pending()[0]);
  await w.pass();             // mid-stream: no first look, the two lines pushed
  await w.reply(w1);
  for (const f of w.pending()) await w.answer(f);
  w.write(1); await w.pass();
  check('...and back in view it rejoins mid-stream: everything, once, in order', w.exact(),
        JSON.stringify({got: w.pageLog().slice(-9), want: w.log().slice(-9)}));
  w.other(false);
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
  const w1 = w.read(w.pending()[0]);
  w.pass(); w.write(2); await w.reply(w1); await w.pass();
  for (const f of w.pending()) await w.answer(f);
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
  w.pass();
  for (const f of w.pending()) await w.answer(f);
  w.write(1); await w.pass();
  for (const f of w.pending()) await w.answer(f);
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
  check('a long action this page saw start keeps a hidden tab in its console (its last lines are drained only for a '
        + 'watched one); once it has ended the tab leaves within one more grace',
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
  const versions = () => w.page.fetches.filter(f => /\/version$/.test(f.url)).length;
  const v0 = versions();
  w.pass();
  await w.panelPush('[panel] backup started — its output follows.');   // after the rejoin: on the socket, held…
  const w1 = w.read(w.pending()[0]);                                   // …and in the read's backlog too
  await w.reply(w1);
  await w.advance(600);
  check('an update that ran and finished while the tab was away: its lines appear once, in order, the version is '
        + 're-read, and a panel push that came after the return lands after them',
        JSON.stringify(w.pagePanel()) === JSON.stringify(w.backlog.map(b => b.line)) && versions() === v0 + 1,
        JSON.stringify({got: w.pagePanel(), versions: versions() - v0}));
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
  check('a return the browser reports only as focus (no visibilitychange) still rejoins and catches up',
        w.emits('leave_console') === 1 && quiet === 1 && w.emits('join_console') === 2 && w.pending().length === 1,
        JSON.stringify({emits: w.page.emitted.map(e => e[0]), pending: w.pending().map(f => f.url)}));
}

async function checkSilentReturn(cfg) {
  const w = await manualWorld(cfg);
  await w.hide(true); await w.advance(GRACE);
  await w.hide(false, true);                  // in view, but neither visibilitychange nor focus came
  await w.advance(GRACE - 1);
  const before = w.emits('join_console');
  await w.advance(1);
  check('a return no event announced is noticed by the 30 s console poll, which rejoins and catches up',
        w.emits('leave_console') === 1 && before === 1 && w.emits('join_console') === 2
        && w.pending(/lines=2000/).length === 1,
        JSON.stringify({emits: w.page.emitted.map(e => [e[0], e[2]]), pending: w.pending().map(f => f.url)}));
}

async function checkNoConsole(cfg) {
  const w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code, console: false});
  w.write(3); await w.start();
  await w.hide(true); await w.advance(GRACE);
  const left = w.emits('leave_console');
  await w.hide(false);
  check('a page with its console panel hidden (in the room only for the update marker) leaves too, and back in view '
        + 'rejoins and re-reads the game version instead of reading the log',
        left === 1 && w.emits('join_console') === 2 && w.page.fetches.filter(f => /\/version$/.test(f.url)).length === 2
        && w.page.fetches.filter(f => /\/api\/console\//.test(f.url)).length === 0,
        JSON.stringify({emits: w.page.emitted.map(e => e[0]), fetches: w.page.fetches.map(f => f.url)}));
}

async function checkNoView(cfg) {
  const w = makeWorld({manual: true, src: cfg.src, panel: cfg.panel, code: cfg.code, canView: false});
  await w.start();
  await w.hide(true); await w.advance(GRACE); await w.hide(false);
  check('a viewer without view_console never joins, so never leaves or rejoins', w.page.emitted.length === 0,
        JSON.stringify(w.page.emitted));
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
  const w1 = w.read(w.pending()[0]);
  w.pass(); w.write(2); await w.reply(w1); await w.pass();
  for (const f of w.pending()) await w.answer(f);
  const got = w.pageLog(), fresh = w.log();
  check('a server restarted while the tab was away (LinuxGSM rotated the log): the new log follows what was shown, '
        + 'every line once and in order', JSON.stringify(got.slice(-fresh.length)) === JSON.stringify(fresh)
        && new Set(got).size === got.length, JSON.stringify({got: got.slice(-10), fresh}));
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
  for (const f of w.pending()) await w.answer(f);
  w.pass(); w.write(2); await w.pass();
  for (const f of w.pending()) await w.answer(f);
  check('...and once it reconnects, the kept join is sent and the console goes on from there, each line once',
        w.room.has('page') && w.exact() && w.page.ctx._resync === null,
        JSON.stringify({room: [...w.room], got: w.pageLog().slice(-5), want: w.log().slice(-5)}));
}

// The same, with the host slow: the catch-up read asked with the socket down never answers, and is
// given up after 45 s — while the socket is still down, so the return is still owed to the reconnect.
async function checkGiveUpWhileDown(cfg) {
  const w = await awayLong(cfg, 300);
  w.expire();
  await w.hide(false);
  const hung = w.pending();
  await w.advance(46000);
  const gaveUp = w.page.ctx._resync === null;
  await w.reconnect();
  const owed = w.pending(/lines=2000/).filter(f => hung.indexOf(f) < 0);
  for (const f of w.pending()) if (hung.indexOf(f) < 0) await w.answer(f);
  w.pass(); w.write(2); await w.pass();
  for (const f of w.pending()) if (hung.indexOf(f) < 0) await w.answer(f);
  check('a catch-up read that never answers while the socket is down is given up, and the reconnect still reads '
        + 'the time away back: 300 lines and an update, each once', gaveUp && owed.length === 1 && w.exact()
        && JSON.stringify(w.pagePanel()) === JSON.stringify(w.backlog.map(b => b.line)),
        JSON.stringify({gaveUp, owed: owed.map(f => f.url), shown: w.pageLog().length, want: w.log().length}));
}

// Once a return has caught up and the page is back in step, the console is the one it always was: a
// socket that drops and comes back afterwards gets the plain reconnect catch-up, as before.
async function checkInStepAfterReturn(cfg) {
  const w = await awayAndBack(cfg);
  await w.answer(w.pending()[0]);
  w.pass(); w.write(2); await w.pass();
  for (const f of w.pending()) await w.answer(f);
  w.write(1); await w.pass();
  const inStep = !w.page.ctx._resync && !w.page.ctx._returnOwed && w.exact();
  await w.disconnect(); w.pass(); w.write(2);
  await w.reconnect();
  const reads = w.pending().map(f => f.url);
  check('a return that has caught up leaves the console as it always was: a later reconnect reads the one plain '
        + '250-line window a reconnect always read', inStep && JSON.stringify(reads) === JSON.stringify(['/api/console/7']),
        JSON.stringify({inStep, reads}));
}

// The socket drops after the return's join but before its first read answered (and the 30 s poll's
// own window answers while it is down): the reconnect owes the return's catch-up, not a plain one.
async function checkDropBeforeFirstRead(cfg) {
  const w = await awayLong(cfg, 300);
  const v0 = versions(w);
  await w.hide(false);
  const first = w.pending(/lines=2000/), polls = w.pending().filter(f => first.indexOf(f) < 0);
  await w.disconnect();
  for (const f of polls) await w.answer(f);     // the 30 s poll's window, answered with the socket down
  for (const f of first) await w.answer(f);     // the abandoned read
  await w.reconnect();
  const owed = w.pending(/lines=2000/);
  for (const f of w.pending()) await w.answer(f);
  w.pass(); w.write(2); await w.pass();
  for (const f of w.pending()) await w.answer(f);
  await w.advance(600);
  check('a socket that drops before the return\'s first read answers: the reconnect reads the time away back '
        + '(2000 lines and the backlog) — 300 lines and an update, each once, in order, the version re-read — not '
        + 'the plain 250-line catch-up',
        owed.length === 1 && w.exact() && JSON.stringify(w.pagePanel()) === JSON.stringify(w.backlog.map(b => b.line))
        && versions(w) - v0 === 1,
        JSON.stringify({owed: owed.map(f => f.url), exact: w.exact(), shown: w.pageLog().length, want: w.log().length,
                        panel: w.pagePanel().length, backlog: w.backlog.length, versions: versions(w) - v0}));
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
        + 'view: the paused tab leaves again, and nothing is read for it',
        !w.room.has('page') && w.stats.reads === reads && w.page.ctx._consolePaused,
        JSON.stringify({room: [...w.room], reads: w.stats.reads - reads, emits: w.page.emitted.map(e => e[0])}));
  await w.hide(false);
  for (const f of w.pending()) await w.answer(f);
  w.pass(); w.write(1); await w.pass();
  for (const f of w.pending()) await w.answer(f);
  check('...and back in view it catches up exactly', w.exact() && w.room.has('page'),
        JSON.stringify({got: w.pageLog().slice(-6), want: w.log().slice(-6)}));
}

// The second window read AHEAD of the stream (it shows lines the next push will start with), and the
// poller's next pass slower than the 45 s give-up — and the same with nothing held (`next`).
async function checkSlowPassAfterPlacement(cfg) {
  for (const held of [true, false]) {
    for (const slow of [1000, 50000]) {
      const w = await awayAndBack(cfg);
      await w.answer(w.pending()[0]);
      w.pass();
      if (held) { w.write(2); await w.pass(); }      // held; asks for the second read
      else await w.advance(6000);                    // quiet: the second read 6 s on
      w.write(3);                                    // written before the second read…
      await w.answer(w.pending()[0]);
      await w.advance(slow);                         // …and pushed only by a pass this much later
      await w.pass();
      const got = w.pageLog();
      check('the second window ahead of the stream (' + (held ? 'lines held' : 'nothing held') + ') and the '
            + 'poller\'s next pass ' + slow / 1000 + ' s later: the lines it shows early are not shown twice',
            w.exact() && new Set(got).size === got.length,
            JSON.stringify({got: got.slice(-7), want: w.log().slice(-7)}));
    }
  }
}

// Away for more lines than the return's first read reaches back (2000): say so where they are missing.
async function checkLongAway(cfg) {
  const w = await awayAndBack(cfg, null, async x => { x.write(2100); });
  await w.answer(w.pending()[0]);
  const want = w.log().slice(0, 22).concat(w.log().slice(-2000));
  const gaps = w.page.gaps(), lines = w.page.lines();
  check('away for more than the 2000 lines a return reads back: one notice says some output is not shown, '
        + 'between what was shown and the 2000 lines that follow, and it is not part of the log copy',
        JSON.stringify(w.pageLog()) === JSON.stringify(want) && gaps.length === 1
        && /^L\d{5}/.test(lines[gaps[0] - 1] || '') && lines[gaps[0] + 1] === w.log()[w.log().length - 2000]
        && w.page.ctx._consoleLines.length === w.pageLog().length,
        JSON.stringify({gaps, around: lines.slice(Math.max(0, gaps[0] - 1), gaps[0] + 2), shown: w.pageLog().length}));
  const v = await awayAndBack(cfg);
  await v.answer(v.pending()[0]);
  check('...and a return that reaches back far enough shows no such notice', v.page.gaps().length === 0 && v.exact(),
        JSON.stringify(v.page.gaps()));
}

// The page holds a HOLE: its socket dropped, and the reconnect's catch-up (as before this change)
// could not bring every line — more than its 250 written while down (a `seam`), or some written
// between its window and the poller's first look. Then the tab goes away and comes back: the 2000-line
// read must still find where the page stands, not append itself whole.
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
    for (const f of w.pending()) await w.answer(f);
    w.pass(); w.write(1); await w.pass();
    for (const f of w.pending()) await w.answer(f);
    const got = w.pageLog(), missing = w.log().filter(l => got.indexOf(l) < 0);
    check('a page with a hole in it (' + label + ') goes away and comes back: nothing is shown twice, and every '
          + 'line written since the hole is shown', new Set(got).size === got.length
          && JSON.stringify(missing) === JSON.stringify(lost) && w.page.gaps().length === 0,
          JSON.stringify({dups: got.length - new Set(got).size, missing: missing.length, lost: lost.length, gaps: w.page.gaps().length}));
  }
}

// ...and the same hole, the page's last lines a block the server prints again and again (a status
// table): the window holds that block more than once, and only the page's last 250 lines — what any
// catch-up's window is matched by — tell its first copy from the later ones.
async function checkHoleThenRepeats(cfg) {
  const block = Array.from({length: 25}, (_, i) => 'status row ' + String(i + 1).padStart(2, '0'));
  const w = await manualWorld(cfg);
  w.pass(); w.write(2); await w.pass();
  await w.disconnect(); w.pass(); w.write(400); await w.reconnect();
  for (const f of w.pending()) await w.answer(f);        // the reconnect's catch-up: a hole before it
  w.pass();
  w.write(30); w.say(...block); await w.pass();
  const lost = w.log().filter(l => w.pageLog().indexOf(l) < 0);
  await w.hide(true); await w.advance(GRACE);
  w.pass();
  w.write(3); w.say(...block); w.write(2); w.say(...block); w.write(4);
  await w.hide(false); await w.settlePolls();
  await w.answer(w.pending()[0]);
  const got = w.pageLog(), missing = w.log().length - got.length;
  check('a page with a hole in it whose last lines are a block the server repeats while the tab is away: back in '
        + 'view, it is placed by the page\'s last 250 lines at the block\'s first copy, so the copies after it show',
        missing === lost.length && JSON.stringify(got.slice(-60)) === JSON.stringify(w.log().slice(-60)),
        JSON.stringify({missing, lost: lost.length, got: got.slice(-6), want: w.log().slice(-6)}));
}

// A console repeats lines word for word. Where the held lines sit in the second window is decided by
// text, so a repeated line offers more than one place: the LATEST is taken, as _newConsoleLines takes
// the latest occurrence — the held lines were read just before the window was.
async function checkRepeatsPlacement(cfg) {
  // 1. a periodic block: the held block is also the block before it in the window
  let w = await awayAndBack(cfg);
  await w.answer(w.pending()[0]);
  w.say('Saving chunks', 'Saved the game', 'Player count: 0');
  w.pass();                                                    // the first look, after that block
  w.say('Saving chunks', 'Saved the game', 'Player count: 0'); await w.pass();   // held, the second read asked
  await w.answer(w.pending()[0]);
  w.say('Saving chunks', 'Saved the game', 'Player count: 0'); w.write(1); await w.pass();
  check('a periodic block around the return, the held block repeated earlier in the window: it is placed at the '
        + 'LATEST fit, and the next block (the same words) is shown, once', w.exact() && !w.page.ctx._resync,
        JSON.stringify({got: w.pageLog().slice(-8), want: w.log().slice(-8)}));
  // 2. one repeated line: the held line also stands earlier in the window, and the lines after it
  //    there are the very ones the next push starts with
  w = await awayAndBack(cfg);
  await w.answer(w.pending()[0]);
  w.say('tick'); w.say('tock');
  w.pass();
  w.say('tick'); await w.pass();                               // held: ['tick'], the second read asked
  await w.answer(w.pending()[0]);
  w.say('tock', 'tick'); w.write(1); await w.pass();
  check('a held line repeated earlier in the window, followed there by the lines the next push starts with: '
        + 'placed at the latest fit, every line shown, once', w.exact() && !w.page.ctx._resync,
        JSON.stringify({got: w.pageLog().slice(-7), want: w.log().slice(-7)}));
  // 3. `next`: nothing held, the window's last line a repeated one the stream has not pushed yet
  w = await awayAndBack(cfg);
  await w.answer(w.pending()[0]);
  w.pass();
  await w.advance(6000);                                       // quiet: the second read 6 s on
  w.say('tick');
  await w.answer(w.pending()[0]);                              // shows that 'tick'…
  w.say('tick'); w.write(1); await w.pass();                   // …and the push brings it, a new one, a line
  check('nothing held (a quiet return), the window ending in a repeated line the stream had not reached: the next '
        + 'push is matched against the page, so the line the window showed is not shown twice, and the new one is',
        w.exact() && !w.page.ctx._resync, JSON.stringify({got: w.pageLog().slice(-5), want: w.log().slice(-5)}));
}

// ── random schedules ─────────────────────────────────────────────────────────────────────────────
async function schedule(cfg, seed, code) {
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
    if (r < 0.35) w.write(w.between(1, 6));
    else if (r < 0.55) { hidden = !hidden; await w.hide(hidden); }
    else if (r < 0.62) {
      w.panelPush(acting ? '[panel] update finished successfully.' : '[panel] update started — its output follows.');
      acting = !acting;
    } else if (r < 0.66 && acting) w.panelPush('ACT out ' + i);
    else if (r < 0.70) { other = !other; w.other(other); }
    else if (r < 0.73 && hidden && w.page.ctx._consolePaused && w.page.socket.connected) {
      await w.disconnect(); await w.step(w.between(0, 5000)); await w.reconnect();
    }
    else if (r < 0.77 && hidden && w.page.ctx._consolePaused && w.page.socket.connected) { w.expire(); expires++; }
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
          leaves: w.emits('leave_console'), expires, keptJoins};
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
  // come): if this passed, the schedules would not be exercising the race the two reads exist for.
  const src = fs.readFileSync(cfg.src, 'utf8');
  const naive = src.replace(/\n {2}_startResync\(\);\n/, '\n  refreshConsole(false, null, true);\n');
  let wrong = 0;
  if (naive !== src) for (let s = 1; s <= runs; s++) { const r = await schedule(cfg, s, naive); if (!r.log) wrong++; }
  check('(control) the same schedules against a plain rejoin with the reconnect\'s one-window catch-up get the log '
        + 'wrong — duplicated or missing lines — in at least a tenth of them', naive !== src && wrong * 10 >= runs,
        JSON.stringify({substituted: naive !== src, wrong, runs}));
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
    else if (s.op === 'respond') {
      const f = p.fetches.find(x => !x.done && x.url === s.url);
      if (!f) { errors.push('no pending fetch of ' + s.url + '; pending: ' + p.fetches.filter(x => !x.done).map(x => x.url).join(', ')); continue; }
      await p.respond(f, s.body);
    } else if (s.op === 'emits') {
      const got = p.emitted.slice(s.from).map(e => e[0]);
      if (JSON.stringify(got) !== JSON.stringify(s.want)) errors.push('emits after ' + s.from + ': ' + JSON.stringify(got) + ' != ' + JSON.stringify(s.want));
    }
  }
  return {loadError: p.loadError, errors, lines: p.lines(), emitted: p.emitted.map(e => e[0]),
          pending: p.fetches.filter(x => !x.done && x.url.indexOf('/api/console/') >= 0).map(x => x.url)};
}

(async () => {
  const cfg = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (cfg.mode === 'replay') { process.stdout.write(JSON.stringify(await replay(cfg))); return; }
  for (const fn of [checkLoad, checkGrace, checkAltTab, checkReturn, checkOrderReadFirst, checkAhead,
                    checkDropWhileCatchingUp, checkInsideWindow, checkGiveUp, checkHiddenAgain, checkOrderPushFirst,
                    checkQuiet, checkOtherTab, checkReconnectWhilePaused, checkDropBeforeGrace, checkAction,
                    checkFinishedAway, checkBackground, checkLateTimer, checkFocusFallback, checkSilentReturn, checkNoConsole,
                    checkNoView, checkIndicator, checkBacklogOnce, checkRotation, checkPrimeAfterPush,
                    checkUnlockExpired, checkGiveUpWhileDown, checkInStepAfterReturn, checkDropBeforeFirstRead, checkReplayedJoin, checkSlowPassAfterPlacement,
                    checkLongAway, checkHoleThenAway, checkHoleThenRepeats, checkRepeatsPlacement, checkSchedules]) {
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
          len(results) >= 61 and not out.get("error"), repr(out)[:1500])
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

    def __init__(self, real):
        self.real, self.calls, self.lines = real, [], []
        self.path = os.path.join(_TMP38, "log", "console", os.path.basename(real))
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
    """shell_as_game_user for an action's output drain, run on a REAL file.

    The command is built as for the host and unwrapped and run by bash, with only the output file's
    path pointed at this part's copy.
    """

    def __init__(self, real):
        self.real, self.calls = real, []
        self.path = os.path.join(_TMP38, "action", os.path.basename(real))
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8"):
            pass

    def __call__(self, server, user, sh, timeout=30, selfname=None):
        self.calls.append(sh)
        return _bash34(_as_account34(user, sh, selfname).replace(self.real, self.path))

    def write(self, n, tag):
        """Append n lines of exactly 64 bytes, so a 64 KB chunk ends on a line's end."""
        new = ["%s %06d %s" % (tag, i, "x" * 52) for i in range(n)]
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write("".join(x + "\n" for x in new))
        return new


def _unwatched_update38(loop, gs_id, admin, sio, n, label):
    """An update writing n lines that runs start to end while its only tab is away."""
    real = _sh38._action_log_path("mcsrv38", "update")
    act = _ActRig38(real)
    _set38(_core38, "shell_as_game_user", act)
    _sh38._console_backlog.pop(gs_id, None)
    sio.emit("join_console", {"server_id": gs_id})
    _pass38(loop)
    sio.emit("leave_console", {"server_id": gs_id})      # the only tab, hidden past the grace
    _pass38(loop)
    _sh38._begin_action_tail(_p9, gs_id, "update", real, "mcsrv38")
    out = act.write(n, "UPD")
    for _ in range(3):
        _pass38(loop)
    drained = len(act.calls)
    _sh38._end_action_tail(_p9, gs_id, NS(host="192.0.2.38", name="p38-host"), "update", 0)
    sio.emit("join_console", {"server_id": gs_id})        # back in view: the page reads the backlog
    body = _p9_client(admin).get("/api/console/%d" % gs_id).get_json() or {}
    rows = [r.get("line") for r in body.get("panel_lines") or []]
    tail = [r for r in rows if r.startswith("UPD ")]
    check("B server: an update writing %s of output while its only tab is away: nothing is drained while "
          "nobody watches, and its end reads on to the end — the backlog the returning page shows ends "
          "with the update's last lines, in order, then how it ended" % label,
          (drained, rows[-1:], len(tail) >= 100, tail == out[-len(tail):], gs_id in _sh38._action_output)
          == (0, ["[panel] update finished successfully."], True, True, False),
          repr((drained, len(act.calls), len(tail), rows[-2:], out[-1])))
    sio.emit("leave_console", {"server_id": gs_id})


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
        _server_ended_entry38(loop, gs_id, a)
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

    def socket(self, event):
        self.sio.emit(event, {"server_id": self.gs_id})

    def tick(self):
        _pass38(self.loop)

    def pushes(self):
        self.steps.extend({"op": "push", "data": p} for p in _payloads38(self.sio))

    def page(self, *steps):
        self.steps.extend(steps)

    def away(self, emitted):
        """The tab hidden past the grace; it leaves (and the server sees the leave)."""
        self.page({"op": "hide", "v": True}, {"op": "advance", "ms": 30000},
                  {"op": "emits", "from": emitted, "want": ["leave_console"]})
        self.socket("leave_console")
        self.tick()

    def back(self, emitted):
        self.page({"op": "hide", "v": False}, {"op": "emits", "from": emitted, "want": ["join_console"]})
        self.socket("join_console")


def _tape38(rig, gs_id, admin):
    t = _Tape38(rig, gs_id, admin)
    try:
        t.page({"op": "connect"})
        t.answer(t.window())
        t.socket("join_console")
        t.tick()
        rig.write(2)
        t.tick()
        t.pushes()
        # 1. Back in view, its window read BEFORE the poller's first look, lines written between.
        t.away(1)
        rig.write(5)
        t.back(2)
        first, poll = t.window("?lines=2000"), t.window()
        rig.write(3)
        t.tick()                # the first look: records the end, reads nothing
        rig.write(2)
        t.tick()
        t.answer(poll)
        t.answer(first, "?lines=2000")
        t.pushes()              # held; the page asks for its second read…
        t.answer(t.window())    # …which shows the three
        rig.write(1)
        t.tick()
        t.pushes()
        # 2. Back again, the window read AFTER the first look; the same lines pushed, the push first.
        t.away(3)
        rig.write(4)
        t.back(4)
        t.tick()
        rig.write(3)
        first, poll = t.window("?lines=2000"), t.window()
        t.tick()
        t.pushes()
        t.answer(poll)
        t.answer(first, "?lines=2000")
        t.answer(t.window())
        rig.write(1)
        t.tick()
        t.pushes()
        t.socket("leave_console")
    finally:
        t.sio.disconnect()
    return t.steps


def _section_replay38(rig, gs_id, admin):
    steps = _tape38(rig, gs_id, admin)
    out = _node38({"src": _SRC38, "panel": _PANEL38, "mode": "replay", "serverId": gs_id, "steps": steps})
    if out is None:
        skip("C replay: the real server's payloads into the real page", "no node on this host")
        return
    shown = [ln for ln in out.get("lines") or [] if ln.startswith("[p38] line")]
    check("C replay: the real server's pushes and windows, in the order it produced them, reach the real page as "
          "the file: each line once, in order, none missing — across a return whose window was read before the "
          "poller's first look, and one read after it with the same lines pushed first",
          not out.get("loadError") and not out.get("errors") and shown == rig.lines and not out.get("pending"),
          repr({k: out.get(k) for k in ("loadError", "errors", "pending")})
          + " shown %d of %d; tail %r" % (len(shown), len(rig.lines), shown[-6:]))
    check("C replay: ...and the page left and rejoined exactly twice", out.get("emitted") == [
        "join_console", "leave_console", "join_console", "leave_console", "join_console"], repr(out.get("emitted")))


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
