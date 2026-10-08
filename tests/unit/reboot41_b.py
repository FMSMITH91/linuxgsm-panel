"""Part 41's sections U to AD (clean host reboots); part41 runs them."""
import json as _json41
import math as _math41
import shutil as _shutil41
import sys
from types import SimpleNamespace as NS

from unit.part01 import eq, skip
from unit.part20 import _patched
from unit.reboot41_fixtures import (
    GameServer, HR, RemoteServer, _CLOCK41, _NOTES41, _REAL_PARAMIKO41,
    _REAL_SSHCLI41, _ROOT41, _STAMPS41, _TMP41, _all41, _app41,
    _audit41, _core41, _events41, _fresh41, _gs41, _lockfile41,
    _mon41, _notif41, _patch, _ps41, _remote41, _rr41, _run41,
    _shlex41, _sm41, _so41, _std_host41, _tf41, _th41,
    _write_exec41, check, db, os)
from unit.reboot41_a import (
    _ADMIN41, _AN41, _SD41, _WAITER41, _actions41, _as_admin41, _asides41,
    _bodies41, _bounce_stubs41, _lines41, _monitor_cron41, _noted41, _pass41,
    _rapp41, _restore_until41, _stamp_stops41, _trace41, _wait_entry41, _wpass41)

# ════════════════════════════════════════════════════════════════════════════════════════════════
# U. The plan's edges: a server that starts mid-plan, a lock left aside, a queued stop, an idle
#    host, a lock that cannot be moved
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _rescan_checks41():
    """A server not in the plan starts during the stop phase (a cron, someone at a shell)."""
    _fresh41()
    r, h, rows = _std_host41()
    real = _core41.run_as_game_user

    def _cod_wakes(server, user, action, timeout=30, selfname=None, **kw):
        out = real(server, user, action, timeout=timeout, selfname=selfname, **kw)
        if (action, selfname) == ("stop", "gmodserver"):
            h.run("codserver", True)
        return out
    _patch(_core41, "run_as_game_user", _cod_wakes)
    _patch(HR, "STOP_WORKERS", 1)
    HR.request_reboot(r, "now", None, "web")
    rec = _rr41(rows["cod"].id) or {}
    check("re-scan: a server that started during the stops is found before the reboot, stopped, and "
          "put in the plan (the panel brings it back: it has no lock for the monitor)",
          _all41(_lines41(h, "stop codserver") == ["stop codserver starting_lock=0"],
                 (rec.get("owner"), rec.get("stop")) == ("panel", "stopped"), not h.running("codserver"),
                 _trace41().count("reboot") == 1), repr((h.events(), rec)))


def _leftover_checks41():
    """A lock an interrupted plan left aside is put back before a new plan reads the server."""
    _fresh41()
    r, h, rows = _std_host41()
    os.rename(h.lock("gmodserver"), h.lock("gmodserver") + ".panel-reboot")
    HR.request_reboot(r, "now", None, "web")
    rec = _rr41(rows["gmod"].id) or {}
    rolled = [d for a, _s, d in _audit41("remote_reboot_rollback")]
    check("leftover lock: put back first — the server is the monitor's again, as it was before the "
          "interrupted plan, and its lock is in place for the reboot",
          _all41(rec.get("owner") == "monitor", _lockfile41(h, "gmodserver") is not None,
                 any("left aside by an earlier plan" in d for d in rolled)), repr((rec, rolled)))


def _stop_pending_checks41():
    """A queued "stop when empty": the reboot's stop honours it, and nothing brings it back."""
    _fresh41()
    r, h, rows = _std_host41()
    rows["gmod"].stop_pending = True
    rows["mc"].restart_pending = True
    db.session.commit()
    _code, body = HR.request_reboot(r, "now", None, "web")
    check("queued stop: the answer to the request promises no blanket return",
          _all41("come back after" not in body.get("message", ""),
                 "stopped cleanly first" in body.get("message", "")), repr(body))
    db.session.expire_all()
    check("queued stop: honoured by the reboot — stopped, the flag cleared, and its lock NOT put back "
          "(so LinuxGSM's monitor leaves it stopped)",
          _all41(db.session.get(GameServer, rows["gmod"].id).stop_pending is False,
                 (_rr41(rows["gmod"].id) or {}).get("owner") == "none",
                 _lockfile41(h, "gmodserver") is None, _asides41(h) == []), repr(h.events()))
    told = _bodies41("Rebooting vps")
    check("queued stop: the 'Rebooting' notice says which come back and which stay stopped — not "
          "'they come back' for all of them",
          told == ["Stopped 3 game servers cleanly (0 players disconnected). 2 come back after the "
                   "reboot. 1 stays stopped (a queued stop, or no Autostart with restoring turned off "
                   "in Settings)."], repr(told))
    h.reboot_now()
    _CLOCK41.sleep(120)
    _restore_until41(r.id, between=_monitor_cron41(h, {}))
    db.session.expire_all()
    check("queued stop: ...after the boot it stays stopped, and the summary says so, naming its own "
          "reason only",
          _all41(not h.running("gmodserver"),
                 "1 stayed stopped, as planned (a queued stop)." in "".join(_bodies41("Host reboot")),
                 "as before" not in "".join(_bodies41("Host reboot"))),
          repr(_NOTES41))
    check("queued restart: the restore's start does the restart that was waiting, and clears it",
          db.session.get(GameServer, rows["mc"].id).restart_pending is False)


def _bare_job_checks41():
    """A host with no game server running: rebooted at once, and its return reported."""
    _fresh41()
    r, h, _rows = _std_host41()
    for s_ in ("gmodserver", "mcserver", "fctrserver"):
        h.run(s_, False)
    code, _body = HR.request_reboot(r, "now", None, "web")
    check("idle host: nothing to stop — no plan rows, the reboot sent, the job waiting for it",
          _all41(code == 202, not HR.plan_rows(r.id), _trace41().count("reboot") == 1,
                 (HR.job_of(r.id) or {}).get("phase") == "rebooting"))
    eq("idle host: the 'Rebooting' notice says no running server was found (not 'stopped 0 ... they come "
       "back')", _bodies41("Rebooting vps"), ["No running game server was found, so none were stopped."])
    sent = (HR.job_of(r.id) or {}).get("sent") or 0
    _CLOCK41.sleep(9.5)                       # the host takes a few seconds to go down and boot
    h.reboot_now()
    booted = h.booted_at
    _CLOCK41.sleep(30)
    _pass41()
    check("idle host: its return is reported once, and the job ends",
          _all41(_noted41("no running game server was found"), HR.job_of(r.id) is None), repr(_NOTES41))
    eq("idle host: the report says when the host's new boot started (from its own uptime, rounded up) "
       "— not 'back after 0 min'", _bodies41("Host reboot"),
       ["vps rebooted: its new boot started within %d s of the reboot being sent (no running game server "
        "was found before it)." % _math41.ceil(booted - sent)])


def _bare_silent_checks41():
    """An idle host that never answers after its reboot: the alert hold ends with the day's notice."""
    _fresh41()
    r, h, _rows = _std_host41()
    for s_ in ("gmodserver", "mcserver", "fctrserver"):
        h.run(s_, False)
    HR.request_reboot(r, "now", None, "web")
    h.down = True
    _CLOCK41.sleep(700)
    _pass41()
    early = _mon41._reboot_alerts_muted(r.id, now=_CLOCK41.time())
    _CLOCK41.sleep(86400)
    _pass41()
    late = _mon41._reboot_alerts_muted(r.id, now=_CLOCK41.time())
    check("idle host that never comes back: its unreachable alerts are held while it may be "
          "rebooting, and the hold ends with the 'not back after a day' notice, so a later outage "
          "alerts again", _all41(early is True, late is False, HR.job_of(r.id) is None,
                                 _noted41("has not come back after a day")), repr((early, late, _NOTES41)))


def _disarm_fail_checks41():
    """A lock that cannot be moved aside: the stop will delete it, so the panel brings it back."""
    _fresh41()
    r, _h, rows = _std_host41()
    real = HR.disarm
    _patch(HR, "disarm", lambda remote, ident: None if _ident41(ident) == "gmodserver" else real(remote, ident))
    HR.request_reboot(r, "now", None, "web")
    check("disarm failed: the server becomes the panel's to start (its lock went with the stop)",
          (_rr41(rows["gmod"].id) or {}).get("owner") == "panel")


def _settings_post41(c, saved, form):
    saved.clear()
    resp = c.post("/settings/save", data=form)
    return resp.status_code, saved.get("reboot_wait_max_hours"), saved.get("reboot_restore_no_autostart")


def _settings_checks41():
    """The Settings page's two reboot fields: saved under the keys the reboot code reads."""
    _as_admin41()
    _patch(_AN41, "current_user", _ADMIN41)
    _patch(_AN41, "log_action", lambda *a, **k: None)
    saved = {}
    _patch(_AN41, "update_config", lambda mutate: mutate(saved))
    c = _rapp41.test_client()
    got = [_settings_post41(c, saved, f) for f in (
        {"reboot_wait_max_hours": "48", "reboot_restore_no_autostart": "on"},
        {"reboot_wait_max_hours": "9999"}, {"reboot_wait_max_hours": "-3"},
        {"reboot_wait_max_hours": "soon", "reboot_restore_no_autostart": "on"})]
    eq("settings: the wait limit and the restore switch are saved; the limit is held to 0-720 h, "
       "an unreadable one is the 24 h default, and an unticked switch is off",
       got, [(302, 48, True), (302, 720, False), (302, 0, False), (302, 24, True)])
    _patch(HR, "load_config", lambda: {"reboot_wait_max_hours": 48, "reboot_restore_no_autostart": False})
    a = (HR.wait_max_hours(), HR.restore_no_autostart())
    _patch(HR, "load_config", dict)
    b = (HR.wait_max_hours(), HR.restore_no_autostart())
    check("settings: ...the reboot code reads those same keys, and an install that never saved "
          "them waits 24 h and restores the servers without Autostart", (a, b) == ((48, False), (24, True)),
          repr((a, b)))


def _debug_report_checks41():
    """The debug report's server line while a plan holds the server (an infinite hold)."""
    from panel.ops.debug_report import servers as _dbs41
    gs = NS(id=4141, restart_pending=False)
    now = _CLOCK41.time()
    st = {"expected": {4141: float("inf")}, "cron_restart": {}}
    try:
        held = _dbs41._flags(gs, st, now, False)
    except (OverflowError, ValueError, TypeError) as exc:
        held = "raised %r" % exc
    st["expected"][4141] = now - 40
    st["stop"] = {4141: now - 40}
    stopped = _dbs41._flags(gs, st, now, False)
    st["stop"] = {}
    restarted = _dbs41._flags(gs, st, now, False)
    check("debug report: a server held by a host reboot says so (an infinite hold is not 'a panel "
          "stop -inf ago'), a panel stop still reads as one, and any other window (a restart) as "
          "one the server is expected back from — the monitor pages it if it is not",
          (held, stopped, restarted) == (["expected offline (host reboot)"],
                                         ["expected offline (panel stop 40 s ago)"],
                                         ["expected offline (back expected, 2 m left)"]),
          repr((held, stopped, restarted)))


def _ident41(ident):
    return ident["selfname"] if isinstance(ident, dict) else ident.lgsm_name


# ════════════════════════════════════════════════════════════════════════════════════════════════
# W. The page: the reboot dialog, the Power card's state and the banner, run in node on a small DOM
# ════════════════════════════════════════════════════════════════════════════════════════════════
_NODE41 = r'''// node harness.js <nags.js>: drive the reboot dialog, the Power card and the banner on a small DOM.
const fs = require('fs'), vm = require('vm');
class N { constructor(){ this.childNodes = []; this.parentNode = null; } }
class T extends N { constructor(t){ super(); this.nodeType = 3; this.data = String(t); }
  get textContent(){ return this.data; } }
class E extends N {
  constructor(tag){ super(); this.nodeType = 1; this.tagName = tag.toUpperCase(); this.className = '';
    this.attrs = {}; this.style = {}; this.ls = {}; this.disabled = false; this.id = ''; this.type = ''; }
  get children(){ return this.childNodes.filter(c => c.nodeType === 1); }
  get firstChild(){ return this.childNodes[0] || null; }
  _rm(c){ const i = this.childNodes.indexOf(c); if (i >= 0) this.childNodes.splice(i, 1); c.parentNode = null; }
  appendChild(c){ if (c.parentNode) c.parentNode._rm(c); c.parentNode = this; this.childNodes.push(c); return c; }
  insertBefore(c, ref){ if (c.parentNode) c.parentNode._rm(c); c.parentNode = this;
    const i = ref ? this.childNodes.indexOf(ref) : -1; if (i < 0) this.childNodes.push(c); else this.childNodes.splice(i, 0, c); return c; }
  remove(){ if (this.parentNode) this.parentNode._rm(this); }
  get textContent(){ return this.childNodes.map(c => c.textContent).join(''); }
  set textContent(v){ this.childNodes.forEach(c => { c.parentNode = null; }); this.childNodes = [];
    if (v != null && v !== '') this.appendChild(new T(v)); }
  set innerHTML(v){ this.textContent = ''; }
  setAttribute(k, v){ this.attrs[k] = String(v); if (k === 'id') this.id = String(v); }
  getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, f){ (this.ls[t] = this.ls[t] || []).push(f); }
  removeEventListener(t, f){ this.ls[t] = (this.ls[t] || []).filter(x => x !== f); }
  fire(t, ev){ (this.ls[t] || []).slice().forEach(f => f(Object.assign({type: t, target: this}, ev || {}))); }
  click(){ if (!this.disabled) this.fire('click'); }
  focus(){ doc.activeElement = this; }
  _all(){ const out = []; const walk = n => n.children.forEach(c => { out.push(c); walk(c); }); walk(this); return out; }
  _is(sel){ if (sel[0] === '.') return this.className.split(/\s+/).includes(sel.slice(1));
    if (sel[0] === '#') return this.id === sel.slice(1); return this.tagName === sel.toUpperCase(); }
  querySelectorAll(sel){ return this._all().filter(e => e._is(sel)); }
  querySelector(sel){ return this.querySelectorAll(sel)[0] || null; }
}
const doc = new E('#document');
doc.body = doc.appendChild(new E('body'));
doc.createElement = t => new E(t);
doc.createTextNode = t => new T(t);
doc.getElementById = id => doc.body._all().find(e => e.id === id) || null;
doc.hidden = false;
const calls = [], toasts = [], refreshed = [];
let answers = {};
global.window = global; global.document = doc; global.MOUNT = '';
global.toast = (m, k) => toasts.push([m, k]);
global.fetch = (url, opt) => {
  const method = (opt && opt.method) || 'GET';
  calls.push({method, url, body: opt && opt.body ? JSON.parse(opt.body) : null});
  const a = answers[method + ' ' + url];
  if (a === undefined) return Promise.reject(new Error('no answer for ' + method + ' ' + url));
  const [status, body] = a;
  return Promise.resolve({ok: status < 400, status, json: () => Promise.resolve(body)});
};
vm.runInThisContext(fs.readFileSync(process.argv[2], 'utf8'), {filename: 'nags.js'});
const realRefresh = window.rebootStateRefresh;
window.rebootStateRefresh = id => { refreshed.push(id); };
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setTimeout(r, 0)); };
const overlay = () => doc.body.querySelector('.rb-overlay');
const buttons = el => (el ? el.querySelectorAll('button') : []).map(b => b.textContent);
const press = (el, text) => { const b = (el ? el.querySelectorAll('button') : []).find(x => x.textContent === text);
  if (!b) return false; b.click(); return true; };
const posts = path => calls.filter(c => c.method === 'POST' && c.url.endsWith(path)).map(c => c.body);
const P = '/api/remote/7';
const census = {
  busy: {state: 'busy', busy: [{id: 1, name: 'gmod', players: 3}], unknown: [], blockers: []},
  unknown: {state: 'unknown', busy: [], unknown: [{id: 2, name: 'fctr', reason: 'not_queryable'}], blockers: []},
  idle: {state: 'idle', busy: [], unknown: [], blockers: []},
  blocked: {state: 'blocked', busy: [], unknown: [], blockers: [{kind: 'backup', name: 'gmod'}]},
  unreachable: {state: 'unreachable', busy: [], unknown: [], blockers: []},
};
const plan = {servers: [{name: 'gmod', text: 'LinuxGSM’s monitor starts it again (Autostart)'}], wait_hours: 24};
async function dialog(state, opts, postAnswer, planBody){
  doc.body.querySelectorAll('.rb-overlay').forEach(o => o.remove());   // one dialog at a time
  doc.ls = {};
  calls.length = 0; toasts.length = 0; refreshed.length = 0;
  answers = {['GET ' + P + '/players']: state === null ? [500, {}] : [200, census[state]],
             ['GET ' + P + '/reboot-plan?preview=1']: [200, planBody || plan],
             ['POST ' + P + '/reboot']: postAnswer || [202, {success: true, message: 'Rebooting vps'}]};
  window.rebootHost(7, 'vps', false, opts);
  await settle();
  return overlay();
}
(async () => {
  const out = {};
  let ov = await dialog('busy');
  const wrapped = el => el.querySelectorAll('button').every(b => b.className.split(/\s+/).includes('text-wrap'));
  out.busy = {buttons: buttons(ov), primary: (ov.querySelector('.btn-primary') || {}).textContent,
              text: ov.textContent, posted_before: posts('/reboot').length, wrapped: wrapped(ov)};
  press(ov, 'Wait: reboot when everyone has left'); await settle();
  out.busy.posted = posts('/reboot'); out.busy.closed = overlay() === null;
  out.busy.toasts = toasts.slice(); out.busy.refreshed = refreshed.slice();

  ov = await dialog('busy', {prefer: 'now'});
  out.prefer_now = {buttons: buttons(ov)};
  press(ov, 'Reboot now: disconnect them'); await settle();
  out.prefer_now.posted = posts('/reboot');

  ov = await dialog('unknown');
  out.unknown = {buttons: buttons(ov), text: ov.textContent};

  ov = await dialog('idle');
  out.idle = {buttons: buttons(ov), text: ov.textContent};
  press(ov, 'Reboot now'); await settle();
  out.idle.posted = posts('/reboot'); out.idle.closed = overlay() === null;

  ov = await dialog('blocked');
  out.blocked = {buttons: buttons(ov), text: ov.textContent, wrapped: wrapped(ov)};
  press(ov, 'Wait: reboot when it’s finished and everyone has left'); await settle();
  out.blocked.posted = posts('/reboot');

  ov = await dialog('unreachable');
  out.unreachable = {buttons: buttons(ov)};
  press(ov, 'Close'); await settle();
  out.unreachable.closed = overlay() === null; out.unreachable.posted = posts('/reboot').length;

  ov = await dialog(null);
  out.no_census = {buttons: buttons(ov), text: ov.textContent, posted: posts('/reboot').length};
  press(ov, 'Cancel'); await settle();
  out.no_census.closed = overlay() === null;

  // Someone joined between opening and pressing: the 409 re-renders the choice, nothing closes.
  ov = await dialog('idle', null, [409, {success: false, needs_choice: true, players: census.busy}]);
  press(ov, 'Reboot now'); await settle();
  out.joined = {open: overlay() !== null, buttons: buttons(overlay()), posted: posts('/reboot')};
  overlay().remove();

  ov = await dialog('idle', null, [409, {success: false, error: 'in_progress', message: 'vps is already being rebooted (stopping).'}]);
  press(ov, 'Reboot now'); await settle();
  const err = overlay() && overlay().querySelector('.rb-error');
  out.refused = {open: overlay() !== null, error: err ? err.textContent : null,
                 enabled: overlay().querySelectorAll('button').every(b => !b.disabled)};
  overlay().remove();

  ov = await dialog('busy', null, null, {servers: [], wait_hours: 0});
  out.no_limit = ov.textContent; overlay().remove();
  ov = await dialog('busy', null, null, {servers: [], wait_hours: 48});
  out.limit = ov.textContent;
  doc.fire('keydown', {key: 'Escape'}); await settle();
  out.escape_closed = overlay() === null;

  // The Power card's #power-state, from GET /reboot-plan.
  const box = doc.body.appendChild(new E('div')); box.setAttribute('id', 'power-state');
  window.rebootStateRefresh = realRefresh;
  const card = async st => {
    calls.length = 0;
    answers = {['GET ' + P + '/reboot-plan']: [200, st], ['POST ' + P + '/reboot-cancel']: [200, {success: true, message: 'Canceled'}]};
    window.rebootStateWatch(7, 'vps', false); await settle();
    return {text: box.textContent, buttons: buttons(box)};
  };
  const now = Date.now() / 1000;
  out.clock = {near: _rbClock(now + 60), far: _rbClock(now + 86400 * 1.5)};
  doc.documentElement = {lang: 'fr'};
  out.clock.far_fr = _rbClock(now + 86400 * 1.5);
  doc.documentElement = {lang: 'en'};
  out.clock.far_en = _rbClock(now + 86400 * 1.5);
  delete doc.documentElement;
  out.card_wait = await card({wait: {by: 'admin', since: now - 60, expires: now + 3600,
                                     waiting_on: {busy: [{name: 'gmod', players: 2}], unknown: []}}, job: null, rows: []});
  calls.length = 0; press(box, 'Cancel'); await settle();
  out.card_wait.cancel_posted = calls.filter(c => c.method === 'POST' && c.url === P + '/reboot-cancel').length;
  out.card_job = await card({wait: null, job: {phase: 'stopping', done: 2, total: 4, left: null, sent: null}, rows: []});
  out.card_warn = await card({wait: null, job: {phase: 'warning', done: null, total: null, left: 30, sent: null}, rows: []});
  out.card_sent = await card({wait: null, job: {phase: 'rebooting', done: null, total: null, left: null, sent: now}, rows: []});
  out.card_rows = await card({wait: null, job: null, rows: [{restore: 'done'}, {restore: 'pending'}]});
  out.card_idle = await card({wait: null, job: null, rows: [], last: {text: 'vps is back', ok: true}});

  // The banner.
  const nag = doc.body.appendChild(new E('div'));
  window.rebootNagRender(nag, 7, 'vps', {required: true, packages: ['libc6']});
  out.nag_required = buttons(nag);
  let opened = [];
  const realHost = window.rebootHost;
  window.rebootHost = (id, label, local, opts) => opened.push([id, opts && opts.prefer]);
  press(nag, 'Reboot now'); press(nag, 'Reboot when empty');
  out.nag_opened = opened;
  window.rebootHost = realHost;
  window.rebootNagRender(nag, 7, 'vps', {required: false, pending_empty: true});
  out.nag_wait = {text: nag.textContent, buttons: buttons(nag)};
  window.rebootNagRender(nag, 7, 'vps', {required: false, job: {phase: 'stopping', sent: null}});
  out.nag_job = {text: nag.textContent, buttons: buttons(nag)};
  window.rebootNagRender(nag, 7, 'vps', {required: false, job: {phase: 'rebooting', sent: now}});
  out.nag_sent = buttons(nag);
  window.rebootNagRender(nag, 7, 'the panel host', {required: true, packages: []});
  const ph = nag.querySelectorAll('strong').find(e => e.textContent === 'the panel host');
  window.rebootNagRender(nag, 7, 'vps', {required: true, packages: []});
  const nm = nag.querySelectorAll('strong').find(e => e.textContent === 'vps');
  out.nag_label = {phrase: ph ? ph.getAttribute('data-no-i18n') : 'missing', name: nm ? nm.getAttribute('data-no-i18n') : 'missing'};
  console.log(JSON.stringify(out));
  process.exit(0);                  // the Power card keeps a 10 s poll scheduled
})().catch(e => { console.log(JSON.stringify({error: String(e && e.stack || e)})); process.exit(0); });
'''


def _node_run41():
    """static/js/nags.js under _NODE41; None without node, else its JSON (or {"error": ...})."""
    node = _shutil41.which("node")
    if not node:
        return None
    harness = os.path.join(_TMP41, "nags-harness.js")
    with open(harness, "w", encoding="utf-8") as fh:
        fh.write(_NODE41)
    r = _run41([node, harness, os.path.join(_ROOT41, "static", "js", "nags.js")], timeout=60)
    try:
        return _json41.loads((r.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": (r.stdout + r.stderr)[-600:]}


_CHOICE41 = ["Wait: reboot when everyone has left", "Reboot now: disconnect them", "Cancel"]


def _dialog_checks41(out):
    busy, now = out.get("busy") or {}, out.get("prefer_now") or {}
    check("dialog: players on — Wait (the primary) / Reboot now / Cancel, and nothing is sent "
          "until one is pressed", _all41(busy.get("buttons") == _CHOICE41,
                                          busy.get("primary") == _CHOICE41[0],
                                          busy.get("posted_before") == 0), repr(busy))
    check("dialog: its buttons wrap their text (panel.css keeps .btn on one line, and the long labels "
          "overran a 375 px phone, in French by 125 px)",
          _all41(busy.get("wrapped") is True, (out.get("blocked") or {}).get("wrapped") is True),
          repr((busy.get("wrapped"), (out.get("blocked") or {}).get("wrapped"))))
    check("dialog: Wait sends mode when_empty, then closes, says so and refreshes the host's state",
          _all41(busy.get("posted") == [{"mode": "when_empty"}], busy.get("closed") is True,
                 busy.get("toasts") == [["Rebooting vps", "info"]], busy.get("refreshed") == [7]),
          repr(busy))
    check("dialog: opened from a 'Reboot now' button, Reboot now leads, and it sends mode now",
          _all41(now.get("buttons") == [_CHOICE41[1], _CHOICE41[0], _CHOICE41[2]],
                 now.get("posted") == [{"mode": "now"}]), repr(now))
    unk, nc = out.get("unknown") or {}, out.get("no_census") or {}
    check("dialog: a count that can't be read, or no census at all, is the same choice — never a "
          "plain Reboot now", _all41(unk.get("buttons") == _CHOICE41, nc.get("buttons") == _CHOICE41,
                                    "can’t be read" in unk.get("text", ""),
                                    "could not check" in nc.get("text", ""), nc.get("posted") == 0),
          repr((unk, nc)))
    idle = out.get("idle") or {}
    check("dialog: nobody on — Reboot now / Cancel, and it sends mode now",
          _all41(idle.get("buttons") == ["Reboot now", "Cancel"], idle.get("posted") == [{"mode": "now"}],
                 idle.get("closed") is True), repr(idle))
    check("dialog: what comes back is the plan list's to say — no blanket 'they come back' (a setting "
          "keeps a server without Autostart stopped)",
          _all41("Running game servers are stopped cleanly first." in idle.get("text", ""),
                 "come back after the reboot" not in idle.get("text", ""),
                 "After the reboot:" in idle.get("text", "")), repr(idle.get("text")))
    blk, unr = out.get("blocked") or {}, out.get("unreachable") or {}
    check("dialog: work running — no Reboot now; Wait (when it's finished) sends when_empty",
          _all41(blk.get("buttons") == ["Wait: reboot when it’s finished and everyone has left", "Close"],
                 blk.get("posted") == [{"mode": "when_empty"}], "a backup is running" in blk.get("text", "")),
          repr(blk))
    check("dialog: a host that does not answer — Close only, nothing sent",
          _all41(unr.get("buttons") == ["Close"], unr.get("posted") == 0, unr.get("closed") is True),
          repr(unr))


def _dialog_answer_checks41(out):
    j, ref = out.get("joined") or {}, out.get("refused") or {}
    check("dialog: someone joined after it opened (409 needs_choice) — it stays open and offers the "
          "choice", _all41(j.get("open") is True, j.get("buttons") == _CHOICE41), repr(j))
    check("dialog: a refusal (409 in progress) is shown in the dialog, its buttons usable again",
          _all41(ref.get("open") is True, ref.get("error") == "vps is already being rebooted (stopping).",
                 ref.get("enabled") is True), repr(ref))
    check("dialog: the wait limit is the configured one (48 h), or 'no time limit' for 0",
          _all41("The wait gives up after 48 h" in out.get("limit", ""),
                 "The wait has no time limit." in out.get("no_limit", ""),
                 "24 h" not in out.get("limit", "")), repr((out.get("limit"), out.get("no_limit"))))
    check("dialog: Escape closes it", out.get("escape_closed") is True)


def _card_checks41(out):
    w, jb, sent = out.get("card_wait") or {}, out.get("card_job") or {}, out.get("card_sent") or {}
    check("Power card: a pending wait shows who it waits on, Reboot now instead and Cancel; Cancel "
          "POSTs reboot-cancel", _all41(w.get("buttons") == ["Reboot now instead", "Cancel"],
                                       "Waiting on:" in w.get("text", ""), "gmod" in w.get("text", ""),
                                       w.get("cancel_posted") == 1), repr(w))
    check("Power card: a job shows its phase and can be cancelled until the reboot is sent, not after",
          _all41(jb.get("buttons") == ["Cancel the reboot"], "Stopping game servers" in jb.get("text", ""),
                 sent.get("buttons") == [], "waiting for the host to come back" in sent.get("text", "")),
          repr((jb, sent)))
    warn = out.get("card_warn") or {}
    check("Power card: a job's numbers come as numbers (2/4 stopped, 30 s left) beside its translated "
          "phase — no English sentence from the server in an untranslated span",
          _all41("Stopping game servers…" in jb.get("text", ""), "2/4" in jb.get("text", ""),
                 "Warning players in-game…" in warn.get("text", ""), "30 s" in warn.get("text", "")),
          repr((jb, warn)))
    clock = out.get("clock") or {}
    check("Power card: a time that is not today carries its day (a 24 h wait gives up at the same "
          "clock time it was asked)", len(clock.get("far") or "") > len(clock.get("near") or "") + 4,
          repr(clock))
    check("Power card: ...in the page's language, not the browser's (English day names were on a "
          "Spanish page)", _all41(bool(clock.get("far_fr")), clock.get("far_fr") != clock.get("far_en")),
          repr(clock))
    check("Power card: a restore shows how many are back, and the last outcome once it is over",
          _all41((out.get("card_rows") or {}).get("text", "").startswith("Coming back: 1/2"),
                 (out.get("card_idle") or {}).get("text") == "vps is back"), repr(out.get("card_rows")))


def _banner_checks41(out):
    check("banner: a host that needs a reboot offers Reboot now and Reboot when empty, each opening "
          "the dialog with that choice first",
          _all41(out.get("nag_required") == ["Reboot now", "Reboot when empty"],
                 out.get("nag_opened") == [[7, "now"], [7, "when_empty"]]), repr(out.get("nag_opened")))
    lbl = out.get("nag_label") or {}
    check("banner: 'the panel host' is a phrase the page translates (es/fr have it); a host's own "
          "name is never handed to the translator", (lbl.get("phrase"), lbl.get("name")) == (None, ""),
          repr(lbl))
    check("banner: it stays while a wait or a job is under way, with Cancel (not once the reboot "
          "is sent)", _all41((out.get("nag_wait") or {}).get("buttons") == ["Reboot now instead", "Cancel"],
                             (out.get("nag_job") or {}).get("buttons") == ["Cancel"],
                             out.get("nag_sent") == []), repr(out))


def _power_card_copy41():
    with open(os.path.join(_ROOT41, "templates", "remote_manage.html"), encoding="utf-8") as fh:
        src = fh.read()
    card = src[src.index('id="sec-power"'):src.index('id="power-state"')]
    check("Power card: its help text promises no blanket 'they come back' on either host — it points "
          "at the dialog's list", _all41(card.count("the reboot dialog lists which come back after it") == 2,
                                         "come back after the reboot" not in card), card[:600])


def _page_checks41():
    _power_card_copy41()
    out = _node_run41()
    if out is None:
        skip("reboot dialog (node)", "node is not installed here")
        return
    check("reboot dialog (node): the harness ran", "error" not in out, repr(out)[:600])
    if "error" in out:
        return
    _dialog_checks41(out)
    _dialog_answer_checks41(out)
    _card_checks41(out)
    _banner_checks41(out)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# X. "Is apt running?" on a remote: the REAL rendering, a sudo that forks and waits, the real pgrep
# ════════════════════════════════════════════════════════════════════════════════════════════════
# sudo(8) with pam_session (Ubuntu's default) forks the command and the main sudo process WAITS, so
# a `pgrep -f <pattern>` run under `sudo bash -c` sees that sudo's own command line, which holds the
# pattern. This stand-in sudo does exactly that. The pgrep shim keeps the REAL pgrep to this check's
# own session (setsid), so an apt-get running elsewhere on the machine cannot change the answer.
_FORK_SUDO41 = '#!/bin/bash\n"$@"\nexit $?\n'
_FAKE_APT41 = '#!/bin/bash\nsleep 30 & c=$!\ntrap \'kill $c; exit 0\' TERM\nwait $c\n'
_APT_DRIVER41 = r'''#!/bin/bash
# <with|without> <file holding the command the remote's login shell is given> <dir of a fake apt-get>
bg=""
if [ "$1" = with ]; then "$3/apt-get" upgrade -y & bg=$!; sleep 0.3; fi
bash -c "$(cat "$2")"; rc=$?
[ -n "$bg" ] && kill "$bg" 2>/dev/null
echo "RC=$rc"
'''


def _apt_capture41(auth, verb):
    """The command line a remote's login shell is given for `verb`, over the REAL transport."""
    _fresh41()
    r, _h = _remote41("apt", auth=auth)
    got = []

    def _exec(_client, full_cmd, *_a, **_k):
        got.append(full_cmd)
        raise RuntimeError("captured")

    def _popen(argv, **_kw):
        got.append(argv[-1])
        raise RuntimeError("captured")
    _patch(_core41, "_run_via_paramiko", _REAL_PARAMIKO41)
    _patch(_core41, "_run_via_ssh_cli", _REAL_SSHCLI41)
    _patch(_core41, "get_connection", lambda server, **_k: NS())
    _patch(_core41, "exec_bounded", _exec)
    _patch(_core41, "subprocess", NS(Popen=_popen, PIPE=-1, DEVNULL=-3))
    _patch(_core41, "_ssh_mux_opts", lambda: [])
    try:
        _sm41.run_privileged(r, verb, [], timeout=10, merge_stderr=False)
    except ConnectionError:
        pass                      # paramiko's: the capture raised inside the exec
    return got[-1] if got else None


def _apt_rc41(remote_cmd, mode):
    """The exit status `remote_cmd` gives on a host with (`with`) or without a real apt-get running."""
    d = _tf41.mkdtemp(prefix="aptrun-", dir=_TMP41)
    shim, fake = os.path.join(d, "bin"), os.path.join(d, "fake")
    os.makedirs(shim)
    os.makedirs(fake)
    _write_exec41(os.path.join(shim, "sudo"), _FORK_SUDO41)
    _write_exec41(os.path.join(shim, "pgrep"), '#!/bin/bash\nexec %s -s 0 "$@"\n'
                  % _shlex41.quote(_shutil41.which("pgrep")))
    _write_exec41(os.path.join(fake, "apt-get"), _FAKE_APT41)
    _write_exec41(os.path.join(d, "drive"), _APT_DRIVER41)
    with open(os.path.join(d, "cmd"), "w", encoding="utf-8") as fh:
        fh.write(remote_cmd)
    p = _run41(["setsid", "-w", "bash", os.path.join(d, "drive"), mode, os.path.join(d, "cmd"), fake],
               env={"PATH": shim + ":/usr/bin:/bin", "LC_ALL": "C"}, timeout=30)
    rcs = [ln[3:] for ln in p.stdout.splitlines() if ln.startswith("RC=")]
    return rcs[-1] if rcs else "no answer: %r" % (p.stdout + p.stderr)[-200:]


def _apt_checks41():
    if not (_shutil41.which("setsid") and _shutil41.which("pgrep")):
        skip("apt probe through a forking sudo", "setsid or pgrep is not installed here")
        return
    for auth in ("key", "tailscale"):
        for verb in ("apt-any-running", "apt-upgrade-running"):
            cmd = _apt_capture41(auth, verb)
            got = (_apt_rc41(cmd, "without"), _apt_rc41(cmd, "with")) if cmd else (None, None)
            check("apt probe (%s, %s): the REAL remote command, run by a login shell through a sudo "
                  "that forks and waits (as sudo does with pam_session), answers 1 with no apt-get "
                  "running — though that sudo's own command line is on the host — and 0 with one"
                  % (auth, verb), got == ("1", "0"), repr((got, cmd)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# Y. A Cancel is never followed by a reboot
# ════════════════════════════════════════════════════════════════════════════════════════════════
_OPS41 = NS(id=None, username="ops")


def _rescan_cancel41(woken):
    """Reboot now, cancelled while the re-scan reads the host (with `woken` a server it would re-stop)."""
    with _patched():
        return _rescan_cancel_run41(woken)


def _rescan_cancel_run41(woken):
    """_rescan_cancel41's body."""
    _fresh41()
    r, h, _rows = _std_host41()
    answers = []
    real_probe = HR._probe_rows
    real_run = _core41.run_as_game_user

    def _probe(remote, rows):
        if _sys_caller41() == "_rescan" and not answers:
            answers.append(HR.cancel(remote, _OPS41))
        return real_probe(remote, rows)

    def _wakes(server, user, action, timeout=30, selfname=None, **kw):
        out = real_run(server, user, action, timeout=timeout, selfname=selfname, **kw)
        if woken and (action, selfname) == ("stop", "fctrserver"):
            h.run(woken, True)         # a monitor run brought it back during the stops
        return out
    _patch(HR, "_probe_rows", _probe)
    _patch(_core41, "run_as_game_user", _wakes)
    _patch(HR, "STOP_WORKERS", 1)
    HR.request_reboot(r, "now", None, "web")
    return r, h, answers


def _sys_caller41():
    """The name of the function that called the caller (a stub's caller)."""
    return sys._getframe(2).f_code.co_name  # pylint: disable=protected-access


def _rescan_cancel_checks41():
    r, h, answers = _rescan_cancel41(woken=None)
    check("cancel during the re-scan: accepted ('Cancelling'), and then NO reboot — the job's send "
          "sees it — but a rollback and the 'did not happen (cancelled by ops)' notice",
          _all41([a[0] for a in answers] == [200], "Cancelling" in (answers[0][1]["message"] if answers else ""),
                 "reboot" not in _events41(h), not HR.plan_rows(r.id),
                 _noted41("did not happen (cancelled by ops)"),
                 not _bodies41("Rebooting vps")), repr((answers, _events41(h), _NOTES41)))
    _r, h, answers = _rescan_cancel41(woken="gmodserver")
    check("cancel during the re-scan: a server it found running again is not stopped after the "
          "cancel", _all41(bool(answers), _lines41(h, "stop gmodserver") == ["stop gmodserver starting_lock=0"],
                           "reboot" not in _events41(h)), repr(h.events()))


def _fired_wait41(where):
    """A wait whose job is cancelled in its census (a player is back) or at its preflight (refused)."""
    with _patched():                          # its stubs end here: the passes after it are real
        return _fired_wait_run41(where)


def _fired_wait_run41(where):
    """_fired_wait41's body."""
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": 2})
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    _wpass41()
    h.players.update({"gmodserver": 0})
    answers = []
    real_census, real_pre = HR.host_player_state, HR.preflight

    def _census(remote, probes=None):
        if where == "census" and HR.job_of(remote.id) and not answers:
            h.players.update({"gmodserver": 2})          # the player came back
            answers.append(HR.cancel(remote, _OPS41))
        return real_census(remote, probes)

    def _pre(remote, census=None):
        if where == "preflight" and HR.job_of(remote.id) and not answers:
            answers.append(HR.cancel(remote, _OPS41))
            return False, "vps did not answer the boot check."
        return real_pre(remote, census)
    _patch(HR, "host_player_state", _census)
    _patch(HR, "preflight", _pre)
    _wpass41()
    return r, h, answers


def _fired_wait_cancel_checks41():
    for where, what in (("census", "its census (players back)"), ("preflight", "a preflight refusal")):
        r, h, answers = _fired_wait41(where)
        cancelled = _audit41("reboot_when_empty_cancel")
        h.players.update({"gmodserver": 0})
        for _i in range(3):
            _CLOCK41.sleep(700)
            _wpass41()
        check("wait: cancelled while its job ran %s — the Cancel was accepted, the wait is NOT put "
              "back, the cancel is audited, and the host is never rebooted once it empties" % what,
              _all41([a[0] for a in answers] == [200], _wait_entry41(r.id) is None,
                     len(cancelled) == 1, "reboot" not in _events41(h),
                     not _events41(h, ("stop", "disarm"))),
              repr((answers, cancelled, _events41(h))))


def _fire_race41():
    """A Cancel exactly when the wait is handed to its job: the hand-over is one step."""
    _fresh41()
    r, h, _rows = _std_host41()
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    answers, real_uuid, rid = [], HR.uuid, r.id

    def _cancel_now():
        with _app41.test_request_context():
            answers.append(HR.cancel(db.session.get(RemoteServer, rid), _OPS41))
            db.session.remove()

    def _uuid4():
        t = _th41.Thread(target=_cancel_now)
        t.start()
        _join41(t, 2)
        return real_uuid.uuid4()
    _patch(HR, "uuid", NS(uuid4=_uuid4))
    _wpass41()
    _patch(HR, "uuid", real_uuid)
    _CLOCK41.sleep(5)
    msgs = [a[1].get("message") for a in answers]
    check("wait: a Cancel at the moment the wait becomes a job finds the wait (and nothing runs), "
          "never 'Nothing was scheduled' followed by a reboot",
          _all41(msgs == ["Auto-reboot canceled."], "reboot" not in _events41(h),
                 not _events41(h, ("stop", "disarm")), HR.job_of(r.id) is None),
          repr((msgs, _events41(h))))


def _join41(t, timeout):
    """Thread.join with a timeout, under eventlet too: its green join RAISES its Timeout instead."""
    try:
        t.join(timeout)
    except BaseException as exc:  # noqa: BLE001 - eventlet.timeout.Timeout is not an Exception
        if type(exc).__name__ != "Timeout":
            raise


def _census_cancel_checks41():
    """Reboot now (nobody on), cancelled while the job reads the host: nothing is moved at all."""
    _fresh41()
    r, h, _rows = _std_host41()
    answers = []
    real = HR.host_player_state

    def _census(remote, probes=None):
        c = real(remote, probes)
        if HR.job_of(remote.id) and not answers:
            answers.append(HR.cancel(remote, _OPS41))
        return c
    _patch(HR, "host_player_state", _census)
    HR.request_reboot(r, "now", None, "web")
    check("cancel while the job reads the host (no countdown to catch it): no lock is moved and "
          "nothing stopped — the plan is never made — and the operator is told nothing had been stopped",
          _all41(bool(answers), not _events41(h, ("disarm", "stop", "reboot", "rearm")),
                 _noted41("nothing had been stopped yet")), repr((answers, _events41(h), _NOTES41)))


def _bounce_cancel41(when):
    """A wait's job bounces; the operator cancels `before` the bounce's rollback or `after` it."""
    with _patched():                          # each variant's stubs end with it
        return _bounce_cancel_run41(when)


def _bounce_cancel_run41(when):
    """_bounce_cancel41's body (`first`: the very first server bounces, before any stop)."""
    _fresh41()
    r, h, _rows = _std_host41()
    seen = {"n": 0, "stopping": when == "first"}
    _bounce_stubs41(seen)
    if when == "first":
        # Someone is on every server once the stop phase has begun: the first one bounces.
        _patch(_mon41, "_server_slots", lambda gs, allow_console=False, primary=None:
               (1 if (HR.job_of(r.id) or {}).get("total") is not None else 0, 16, None))
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    real_slots, real_rollback = _mon41._server_slots, HR.rollback
    if when == "before":
        def _slots(gs, allow_console=False, primary=None):
            out = real_slots(gs, allow_console=allow_console, primary=primary)
            if out[0] and HR.job_of(r.id):
                HR.cancel(r, _OPS41)          # the join, and the Cancel, in the same moment
            return out
        _patch(_mon41, "_server_slots", _slots)
    else:
        def _rollback(remote_id, reason, wait=75, quiet=False):
            real_rollback(remote_id, reason, wait=wait, quiet=quiet)
            HR.cancel(r, _OPS41)              # just after the bounce undid the stops
        _patch(HR, "rollback", _rollback)
    _wpass41()
    told = [b for b in _bodies41(key="host_reboot") if "ops" in b]
    return r, h, told


def _bounce_cancel_checks41():
    r, h, told = _bounce_cancel41("before")
    check("bounce + Cancel before its rollback: the rollback is the operator's — ONE notice that the "
          "reboot did not happen (cancelled by ops) — and the wait is not put back",
          _all41(len(told) == 1, "did not happen (cancelled by ops)" in "".join(told),
                 _wait_entry41(r.id) is None, "reboot" not in _events41(h)), repr((told, _NOTES41)))
    r, h, told = _bounce_cancel41("first")
    check("bounce on the very first server + Cancel after its rollback: nothing had been stopped, and "
          "the notice says so — not 'the 0 game servers it had stopped'",
          _all41(len(told) == 1, "nothing had been stopped yet" in "".join(told), not _lines41(h, "stop ")),
          repr((told, h.events())))
    r, h, told = _bounce_cancel41("after")
    check("bounce + Cancel just after its (quiet) rollback: ONE notice that the reboot was cancelled "
          "and the stopped servers are coming back — not 'nothing had been stopped' — and the wait "
          "is not put back",
          _all41(len(told) == 1, "The 2 game servers it had stopped are being brought back" in "".join(told),
                 _wait_entry41(r.id) is None,
                 "nothing had been stopped" not in "".join(told)), repr((told, _NOTES41)))


def _lock_order41():
    """cancel() racing the job putting its wait back: a real job, a real put-back, two threads."""
    _fresh41()
    r, _h, _rows = _std_host41()
    rid, info = r.id, {"by": "admin", "since": _CLOCK41.time(), "origin": "web", "expires": None}
    job = {"phase": "preflight", "mode": "when_empty", "sent": None, "cancel": None, "by": "admin"}
    with _ps41._hr_lock:
        _ps41._host_reboots[rid] = job
    runner = HR._Job(_app41, r, job, "admin", info)
    put_back = []

    def _job_puts_back():
        try:
            runner._back_to_waiting(None, bounce=False)  # pylint: disable=protected-access
            put_back.append("back")
        except HR._Cancelled:  # pylint: disable=protected-access
            put_back.append("cancelled")
        with _ps41._hr_lock:
            if _ps41._host_reboots.get(rid) is job:
                _ps41._host_reboots.pop(rid, None)   # what run()'s finally does as the job ends

    class _HookedLock:
        """_rwe_lock, which starts the job's put-back as cancel() lets go of it."""

        def __init__(self, lock):
            self.lock, self.fired = lock, False

        def __enter__(self):
            return self.lock.__enter__()

        def __exit__(self, *exc):
            out = self.lock.__exit__(*exc)
            if not self.fired and _th41.current_thread().name == "p41-cancel":
                self.fired = True
                t = _th41.Thread(target=_job_puts_back)
                t.start()
                _join41(t, 1.0)        # it runs to its end now unless cancel() still holds _hr_lock
                self.thread = t
            return out
    hooked = _HookedLock(_ps41._rwe_lock)
    _patch(HR, "_rwe_lock", hooked)
    answers = []

    def _cancel():
        try:
            with _app41.test_request_context():
                answers.append(HR.cancel(db.session.get(RemoteServer, rid), _OPS41))
                db.session.remove()
        except Exception as exc:  # noqa: BLE001 - shown by the check
            answers.append((0, {"message": "raised %r" % exc}))
    t = _th41.Thread(target=_cancel, name="p41-cancel")
    t.start()
    _join41(t, 10)
    _join41(getattr(hooked, "thread", t), 10)
    return answers, put_back, _wait_entry41(rid)


def _lock_order_checks41():
    answers, put_back, left = _lock_order41()
    msgs = [a[1].get("message", "") for a in answers]
    check("cancel(): it holds _hr_lock across reading the wait AND the job, so a job putting its wait "
          "back cannot slip between them — the Cancel finds the job (and the put-back sees it), never "
          "'Nothing was scheduled' with the wait back in place",
          _all41(len(msgs) == 1, msgs[0].startswith("Cancelling") if msgs else False,
                 put_back == ["cancelled"], left is None), repr((msgs, put_back, left)))


def _job_numbers_checks41():
    _fresh41()
    r, _h, _rows = _std_host41()
    seen = []
    real = _core41.run_as_game_user

    def _peek(server, user, action, timeout=30, selfname=None, **kw):
        if action == "stop":
            seen.append(dict(HR.job_of(r.id) or {}))
        return real(server, user, action, timeout=timeout, selfname=selfname, **kw)
    _patch(_core41, "run_as_game_user", _peek)
    _patch(HR, "STOP_WORKERS", 1)
    HR.request_reboot(r, "now", None, "web")
    got = [(j.get("phase"), j.get("done"), j.get("total")) for j in seen]
    check("job state: the stop phase carries its progress as numbers (done/total), and no English "
          "sentence for the page to show untranslated",
          _all41(got == [("stopping", 0, 3), ("stopping", 1, 3), ("stopping", 2, 3)],
                 not any("msg" in j for j in seen)), repr(seen))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# Z. A wait that goes back, a wait that cannot succeed, and what a restart says about them
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _restart_drops41(rid):
    """The panel restarted: the waits in memory are gone; what does the restart announce?"""
    with _ps41._rwe_lock:
        _ps41._reboot_when_empty.clear()
    del _NOTES41[:]
    HR.announce_dropped_waits(_app41)
    return [b for b in _bodies41("Reboot wait cancelled")], _wait_entry41(rid)


def _back_to_waiting_restart41():
    # A bounce: its fire was audited, then it went back to waiting.
    _fresh41()
    r, _h, _rows = _std_host41()
    _bounce_stubs41({"n": 0, "stopping": False})
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    _wpass41()
    bounced = (_wait_entry41(r.id) or {}).get("bounces")
    told, _w = _restart_drops41(r.id)
    check("restart: a wait that went back to waiting after a bounce is announced as dropped",
          _all41(bounced == 1, len(told) == 1, "vps" in "".join(told)), repr((bounced, _NOTES41, _audit41())))


def _busy_at_job_restart41():
    """The job's own census saw players: the wait went back without a fire ever being audited."""
    _fresh41()
    r, h, _rows = _std_host41()
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    real = HR.host_player_state
    in_job = []

    def _busy_in_job(remote, probes=None):
        if HR.job_of(remote.id):
            in_job.append(1)
        h.players.update({"gmodserver": 2 if HR.job_of(remote.id) else 0})
        return real(remote, probes)
    _patch(HR, "host_player_state", _busy_in_job)
    _wpass41()
    back = _wait_entry41(r.id) is not None
    fires, auto = _actions41("reboot_when_empty_fire"), _bodies41(key="auto_reboot")
    told, _w = _restart_drops41(r.id)
    check("restart: a wait whose job ran, found players and went back is announced as dropped, and "
          "no fire was audited (nor 'auto-rebooting' sent) for a reboot that never started",
          _all41(in_job == [1], back, fires == [], not auto, len(told) == 1),
          repr((in_job, back, fires, auto, _audit41(), _NOTES41)))


def _refused_wait41():
    """A wait armed while the host could reboot, whose job then cannot (sudo stops working)."""
    _fresh41()
    r, h, _rows = _std_host41()
    asked = []
    real = HR.escalation
    _patch(HR, "escalation", lambda remote: (asked.append(1), real(remote))[1])
    code, _body = HR.request_reboot(r, "when_empty", _WAITER41, "web")
    h.root_refused = True
    for _i in range(30):
        _wpass41()
        _CLOCK41.sleep(60)
    return r, h, code, len(asked)


def _refused_wait_checks41():
    r, h, code, asked = _refused_wait41()
    could = [b for b in _bodies41("Host reboot still waiting") if "could not run" in b]
    check("wait refused at its job (sudo stopped working): over 30 min, ONE notice that it could "
          "not run, no 'auto-rebooting' notice and no fire audited, the wait kept, and its job "
          "retried every 10 min — not every minute",
          _all41(code == 200, len(could) == 1, "sudo is refused" in "".join(could),
                 not _bodies41(key="auto_reboot"), _actions41("reboot_when_empty_fire") == [],
                 _wait_entry41(r.id) is not None, "reboot" not in _events41(h), asked <= 4),
          repr((code, asked, _NOTES41)))
    _fresh41()
    r, h, _rows = _std_host41()
    h.root_refused = True
    code, body = HR.request_reboot(r, "when_empty", _WAITER41, "web")
    check("wait: one that could never reboot the host (sudo refused) is refused when it is asked "
          "for (409), not armed for 24 h of retries",
          _all41(code == 409, body.get("error") == "preflight", "sudo is refused" in body.get("message", ""),
                 _wait_entry41(r.id) is None, _actions41("reboot_when_empty_arm") == []), repr((code, body)))
    for auth, silent in (("tailscale", -1), ("tailscale", 255), ("key", "raise")):
        _fresh41()
        r, h, _rows = _std_host41(auth=auth)
        h.sudo_silent = silent
        code, body = HR.request_reboot(r, "now", None, "web")
        check("preflight: a host whose sudo check got no answer (%s %s: a timeout, ssh unable to "
              "connect, paramiko raising) is 'did not answer' — not 'sudo is refused'" % (auth, silent),
              _all41(code == 409, "did not answer" in body.get("message", ""),
                     "sudo is refused" not in body.get("message", "")), repr((code, body)))


def _arm_race_checks41():
    """A second 'when empty' request that saw the wait armed, then lost it to a Cancel."""
    _fresh41()
    r, h, _rows = _std_host41()
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    real_hours = HR.wait_max_hours
    raced = []

    def _hours():
        if not raced:
            raced.append(HR.cancel(r, _OPS41))     # between its look and its write
        return real_hours()
    _patch(HR, "wait_max_hours", _hours)
    code, _body = HR.request_reboot(r, "when_empty", _WAITER41, "web")
    w = _wait_entry41(r.id) or {}
    check("wait: a request that saw the wait armed and then lost it to a Cancel arms a new one only "
          "after the host's checks (its boot is recorded), never blind",
          _all41(code == 200, bool(raced), w.get("boot") == h.boot,
                 _actions41("reboot_when_empty_arm") == ["reboot_when_empty_arm"] * 2), repr((code, w, raced)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# AA. The window, where the job calls it, and the in-flight read of every plan server
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _armed_at41(start_sec, stop_running=()):
    """Reboot now from second `start_sec` of the minute: [(event, second)] of the re-arms and reboot."""
    _fresh41()
    r, h, _rows = _std_host41()
    for s_ in stop_running:
        h.run(s_, False)
    _CLOCK41.t = 1791000000.0 + start_sec
    HR.request_reboot(r, "now", None, "web")
    return h, [(e, sec) for hn, e, sec in _STAMPS41 if hn == h.name and e in ("rearm", "reboot")]


def _window_job_checks41():
    hi = 40 - 2 * 2                      # two accounts' locks go back: gmodserver and fctrserver
    for start in (45, 3):
        _h, got = _armed_at41(start)
        check("window (job, from second %d): the locks go back, and the reboot is sent, only at a "
              "second of the minute in [10, %d] — never where a */5 monitor run could read them"
              % (start, hi), _all41(bool(got), [e for e, _s in got].count("reboot") == 1,
                                    all(10 <= sec <= hi for _e, sec in got)), repr(got))
    for start in (55, 0):
        _h, got = _armed_at41(start, stop_running=("gmodserver", "fctrserver"))
        check("window (job, only a panel-started server, from second %d): no lock goes back, and the "
              "reboot still waits for a read in [2, 50] of the minute it is sent in, which sees "
              "whatever cron started at :00" % start,
              _all41([e for e, _s in got] == ["reboot"], all(2 <= sec <= 50 for _e, sec in got)), repr(got))


def _inflight_panel_owned_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    for s_ in ("gmodserver", "fctrserver"):
        h.run(s_, False)                 # only mc runs: no Autostart, nothing to put back
    real_census, real_send, real_sleep = HR.host_player_state, HR.send_reboot, _CLOCK41.sleep
    marks = {}

    def _update_starts(remote, probes=None):
        c = real_census(remote, probes)
        h.setn("inflight", "mcserver", 1)      # a cron'd update starts on it after the census...
        marks["census"] = _CLOCK41.time()
        return c

    def _sleep(sec):
        real_sleep(sec)
        if "census" in marks and _CLOCK41.time() - marks["census"] >= 100:
            h.setn("inflight", "mcserver", 0)  # ...and ends 100 s later
    _patch(HR, "host_player_state", _update_starts)
    _patch(HR, "send_reboot", lambda remote: (marks.setdefault("sent", _CLOCK41.time()), real_send(remote))[1])
    _patch(_CLOCK41, "sleep", _sleep)
    HR.request_reboot(r, "now", None, "web")
    _patch(_CLOCK41, "sleep", real_sleep)
    check("window: a LinuxGSM command in flight on a server the PANEL brings back (no lock to put "
          "back at all) holds the reboot too — it is sent only once the command has ended",
          _all41(_trace41().count("reboot") == 1, marks.get("sent", 0) - marks.get("census", 0) >= 100),
          repr(marks))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# AB. A rollback of a server the plan keeps stopped; the warning; the re-scan's budget
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _none_rollback_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    _patch(HR, "restore_no_autostart", lambda: False)        # mc: no Autostart, not restored
    before = _lockfile41(h, "mcserver")
    real = _core41.run_as_game_user

    def _cancel_after_first(server, user, action, timeout=30, selfname=None, **kw):
        out = real(server, user, action, timeout=timeout, selfname=selfname, **kw)
        if action == "stop":
            HR.cancel(r, _OPS41)
        return out
    _patch(_core41, "run_as_game_user", _cancel_after_first)
    _patch(HR, "STOP_WORKERS", 1)
    HR.request_reboot(r, "now", None, "web")
    summary = "".join(_bodies41("Host reboot"))
    check("rollback: a server the plan would keep stopped, but whose stop never ran, is still "
          "running with ITS lock back (the same file) — and the summary says it kept running, not "
          "that it 'stayed stopped'",
          _all41(h.running("mcserver"), _lockfile41(h, "mcserver") == before,
                 not _lines41(h, "stop mcserver"), "2 kept running" in summary,
                 "stayed stopped" not in summary, "1 server coming back" in summary),
          repr((h.events(), summary)))


def _none_stopped_rollback41(queued):
    """The mc server (no Autostart, restoring off) is stopped, then the reboot is cancelled.

    Returns (host, summary).

    Its stubs end with it (_patched): the two variants run back to back, and the first one's hook
    left in place cancelled the FIRST host from inside the second's stop.
    """
    _fresh41()
    r, h, rows = _std_host41()
    with _patched():
        _patch(HR, "restore_no_autostart", lambda: False)
        if queued:
            rows["mc"].stop_pending = True
            db.session.commit()
        real = _core41.run_as_game_user

        def _cancel_after_mc(server, user, action, timeout=30, selfname=None, **kw):
            out = real(server, user, action, timeout=timeout, selfname=selfname, **kw)
            if action == "stop" and (selfname or user) == "mcserver":
                HR.cancel(r, _OPS41)
            return out
        _patch(_core41, "run_as_game_user", _cancel_after_mc)
        _patch(HR, "STOP_WORKERS", 1)
        HR.request_reboot(r, "now", None, "web")
        return h, "".join(_bodies41("Host reboot"))


def _none_stopped_rollback_checks41():
    h, summary = _none_stopped_rollback41(queued=False)
    check("rollback: a server restoring would have left stopped (no Autostart, restoring off) whose "
          "stop DID run is started again when the reboot is cancelled — it is put back as it was",
          _all41(_lines41(h, "stop mcserver"), _lines41(h, "start mcserver"), h.running("mcserver"),
                 "cancel" in summary.lower()),
          repr((h.events(), summary)))
    h, summary = _none_stopped_rollback41(queued=True)
    check("rollback: ...but a server with a queued stop stays stopped (its stop was due)",
          _all41(_lines41(h, "stop mcserver"), not _lines41(h, "start mcserver"),
                 not h.running("mcserver"), "cancel" in summary.lower()),
          repr((h.events(), summary)))
    check("rollback: ...and its summary gives the queued stop as the reason, and only that — a rollback "
          "restarts a server with no Autostart, so that reason would be false here",
          _all41("1 stayed stopped, as planned (a queued stop)." in summary, "no Autostart" not in summary,
                 "restoring" not in summary), summary)


def _unknown_warning_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": None, "fctrserver": 0, "mcserver": 0})
    t0 = _CLOCK41.time()
    stamps = {}
    _stamp_stops41(stamps)
    HR.request_reboot(r, "now", None, "web")
    says = _lines41(h, "say gmodserver")
    check("countdown: a server whose count can't be read may have players on it — on a game that "
          "can show a message it is warned too, and the stops wait the minute",
          _all41(len(says) == 3, stamps.get("stop", 0) - t0 >= 60), repr((says, stamps)))
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"fctrserver": 2})
    t0 = _CLOCK41.time()
    stamps = {}
    _stamp_stops41(stamps)
    HR.request_reboot(r, "now", None, "web")
    check("countdown: players only on a game with no console message — nothing to warn, so no "
          "minute's wait either (they stop normally)",
          _all41(not _lines41(h, "say "), stamps.get("stop", t0 + 99) - t0 < 60), repr(stamps))


def _warning_text_checks41():
    _fresh41()
    r, h, rows = _std_host41()
    rows["mc"].stop_pending = True                 # a queued stop: it does not come back
    db.session.commit()
    h.players.update({"gmodserver": 1, "mcserver": 1})
    _code, body = HR.request_reboot(r, "now", None, "web")
    gm, mc = _lines41(h, "say gmodserver"), _lines41(h, "say mcserver")
    check("countdown: 'It will be back in a few minutes' only on a server that comes back — not on "
          "one a queued stop keeps stopped",
          _all41(len(gm) == 3, len(mc) == 3, all("will be back" in ln for ln in gm),
                 not any("will be back" in ln for ln in mc)), repr((gm, mc)))
    check("countdown: the answer to the request says the warning is in-game only where the game "
          "can show one", "whose game can show one" in body.get("message", ""),
          repr(body))


def _local_warning_text_checks41():
    """On the panel's own host, when the panel does not start at boot, the servers it starts don't."""
    _fresh41()
    r, h, _rows = _std_host41(local=True)
    _patch(_so41, "panel_starts_at_boot", lambda: False)
    h.players.update({"gmodserver": 1, "mcserver": 1})
    HR.request_reboot(r, "now", None, "web")
    gm, mc = _lines41(h, "say gmodserver"), _lines41(h, "say mcserver")
    check("countdown (panel host, the panel not started at boot): 'back in a few minutes' on the "
          "Autostart server, not on the one the panel would start",
          _all41(len(gm) == 3, len(mc) == 3, all("will be back" in ln for ln in gm),
                 not any("will be back" in ln for ln in mc)), repr((gm, mc)))


def _rescan_budget_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    real = _core41.run_as_game_user

    def _slow_stop(server, user, action, timeout=30, selfname=None, **kw):
        if action == "stop":
            _CLOCK41.sleep(400)             # each stop runs long
        out = real(server, user, action, timeout=timeout, selfname=selfname, **kw)
        if (action, selfname) == ("stop", "fctrserver"):
            h.run("codserver", True)        # and something starts another server meanwhile
        return out
    _patch(_core41, "run_as_game_user", _slow_stop)
    _patch(HR, "STOP_WORKERS", 1)
    HR.request_reboot(r, "now", None, "web")
    rec = _rr41(_rows["cod"].id) or {}
    check("re-scan: past the stop phase's 15-min budget, a server found running is not stopped "
          "again — recorded as still running (the shutdown ends it) and still in the plan",
          _all41(not _lines41(h, "stop codserver"), (rec.get("owner"), rec.get("stop")) == ("panel", "still_running"),
                 _trace41().count("reboot") == 1), repr((h.events(), rec)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# AC. The reboot command's connection; the panel's own account
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _paramiko_drop41(fail_at):
    """The REAL paramiko transport, failing at `fail_at` ('connect' or 'exec'): what it raises."""
    _fresh41()
    r, _h = _remote41("drop", auth="key")

    def _conn(server, **_k):
        if fail_at == "connect":
            raise ConnectionRefusedError(111, "Connection refused")
        return NS()

    def _exec(*_a, **_k):
        raise EOFError("the session closed")
    _patch(_core41, "get_connection", _conn)
    _patch(_core41, "exec_bounded", _exec)
    try:
        _REAL_PARAMIKO41(r, "true", 10, True, None)
    except Exception as exc:  # noqa: BLE001 - the check is which one
        return exc
    return None


def _connect_fail_checks41():
    # (Run first: _paramiko_drop41 below stubs exec_bounded for the rest of the section.)
    # Failures BEFORE the exec request — through the real exec_bounded — are not "started" either:
    # the pooled transport gone (get_transport() is None), or the session refused (MaxSessions).
    # Marked started, a reboot that was never sent was waited on for a boot that never came.
    _pm = _core41.paramiko
    _no_transport = _pm.SSHClient()
    _no_transport.get_transport = lambda: None

    class _RefusingTransport41:
        def open_session(self, timeout=None):
            raise _pm.ChannelException(1, "Administratively prohibited")
    _refused = _pm.SSHClient()
    _refused.get_transport = _RefusingTransport41
    _pre = []
    for _cli41 in (_no_transport, _refused):
        _fresh41()
        r, _h = _remote41("drop", auth="key")
        _patch(_core41, "get_connection", lambda server, _c=_cli41, **_k: _c)
        try:
            _REAL_PARAMIKO41(r, "true", 10, True, None)
            _pre.append(None)
        except Exception as exc:  # noqa: BLE001 - the check is which one
            _pre.append(exc)
    check("paramiko: a failure before the exec request (no transport; session refused) raises a "
          "ConnectionError NOT marked command_started",
          _all41(all(e.__class__ is ConnectionError for e in _pre),
                 not any(getattr(e, "command_started", False) for e in _pre)), repr(_pre))
    on_exec, on_connect = _paramiko_drop41("exec"), _paramiko_drop41("connect")
    check("paramiko: a command that fails once the connection is open raises a ConnectionError marked "
          "command_started (its type unchanged for every caller and message); one that never "
          "connected is not marked",
          # exactly ConnectionError: a subclass broke two callers. (The middle condition had been
          # swallowed into this comment, so the check no longer read the mark it names.)
          _all41(on_exec.__class__ is ConnectionError,
                 getattr(on_exec, "command_started", False) is True,
                 not getattr(on_connect, "command_started", False)), repr((on_exec, on_connect)))
    _fresh41()
    r, _h, _rows = _std_host41(auth="key")
    real = _core41.run_privileged

    def _no_connect(server, verb, args=(), **kw):
        if verb == "reboot-delayed":
            raise ConnectionRefusedError(111, "Connection refused")
        return real(server, verb, args, **kw)
    _patch(_core41, "run_privileged", _no_connect)
    t0 = _CLOCK41.time()
    HR.request_reboot(r, "now", None, "web")
    check("send: a reboot whose connection never opened sent nothing — rolled back at once (not 5 "
          "min later as 'did not happen' on the same boot), saying it could not connect",
          _all41(not HR.plan_rows(r.id), _CLOCK41.time() - t0 < 300,
                 _noted41("could not connect to send the reboot"), HR.job_of(r.id) is None),
          repr((_CLOCK41.time() - t0, _NOTES41)))


def _own_account_checks41():
    _fresh41()
    r, h = _remote41("panel", local=True)
    h.own, h.no_sudo_self = "panelacct", True
    h.add("panelacct", "gmodserver", running=True, lock="monitoring", autostart=True)
    gs = _gs41(r, "panelacct", "gmod", 27015)
    _patch(HR, "_own_account", lambda: "panelacct")
    _patch(_core41, "helper_present", lambda recheck=False: True)
    before = _lockfile41(h, "gmodserver")
    HR.request_reboot(r, "now", None, "web")
    rec = _rr41(gs.id) or {}
    check("own account: a game the panel runs under its OWN account (where `sudo -u <itself>` is "
          "refused) is read and planned like any other — stopped through the helper, its lock put "
          "back, the reboot sent — not left unread for the shutdown to kill",
          _all41((rec.get("owner"), rec.get("stop")) == ("monitor", "stopped"),
                 "helper:stop" in _trace41(), _lockfile41(h, "gmodserver") == before,
                 _trace41().count("reboot") == 1), repr((rec, _trace41())))




def _idle_tick_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": 0, "mcserver": 0, "fctrserver": None})
    HR.request_reboot(r, "now", None, "web")
    h.reboot_now()
    _CLOCK41.sleep(120)
    monitor = _monitor_cron41(h, {})
    ticks = []
    for n in range(30):
        monitor(n)
        ticks.append(_pass41())
        if not HR.plan_rows(r.id):
            break
        _CLOCK41.sleep(15.0)
    check("restore: the worker polls fast while a row still waits, and the pass that resolves the last "
          "one asks for the idle tick — not another fast one",
          _all41(not HR.plan_rows(r.id), HR.BUSY_TICK in ticks[:-1], ticks[-1:] == [HR.IDLE_TICK]),
          repr(ticks))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# AD. The monitor's own server alerts around a plan, through its REAL sweep; the summary's words
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _mon_stubs41(h, rows):
    """The REAL monitor sweep, reading this stand-in host: its port scan is the sessions running.

    Plain values only in the probe: it runs on the sweep's pool threads, which must not touch a row.
    """
    ports = {g.lgsm_name: g.port for g in rows.values()}
    _patch(_mon41, "time", _CLOCK41)
    _patch(_mon41, "_lgsm_maintenance_running", lambda remote, g: False)
    _patch(_notif41, "alerts_muted", lambda g: False)
    _patch(_mon41, "_probe_host", lambda remote, read_flags=True: (remote.id, {
        "reachable": not h.down, "disk": 10, "load_mem": (1, 1), "restart_flagged": None,
        "ports": {p for s_, p in ports.items() if h.running(s_)}}))


def _sweep41():
    """One REAL monitor sweep (_monitor_pass), the rows read afresh as its own thread would."""
    db.session.expire_all()
    _mon41._monitor_pass()
    db.session.expire_all()


def _server_pages41():
    """(event, server) of every 'went offline' / 'back online' page so far."""
    return [(k, b.split(" ")[0]) for k, _t, b in _NOTES41 if k in ("server_down", "server_up")]


def _plan_with_sweeps41(r, h, passes=60, between=None):
    """The host reboots and the restore runs, the monitor sweeping once a minute meanwhile."""
    between = between or _monitor_cron41(h, {})

    def _tick(n):
        between(n)
        if n % 4 == 0:
            _sweep41()
    h.reboot_now()
    _CLOCK41.sleep(60)
    return _restore_until41(r.id, passes=passes, between=_tick)


def _sweeps_after41(n=12):
    """`n` more sweeps a minute apart: well past every window a plan leaves behind."""
    for _i in range(n):
        _CLOCK41.sleep(60)
        _sweep41()


def _restart_mid_plan41():
    """The panel restarts while a plan holds its servers (the VPS proof's run 2b).

    Returns (rows resolved, the pages sent, the host).
    """
    _fresh41()
    r, h, rows = _std_host41()
    _mon_stubs41(h, rows)
    _sweep41()
    _sweep41()
    HR.request_reboot(r, "now", None, "web")
    for m in _ps41._monitor_state.values():
        m.clear()
    _ps41._expected_offline.clear()
    _ps41._reboot_awaiting.clear()
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()
    HR.resume_reboot_state(_app41)
    del _NOTES41[:]
    done = _plan_with_sweeps41(r, h)
    _sweeps_after41()
    return done, sorted(_server_pages41()), h


def _crash_and_back41(h, selfname):
    """A real crash of `selfname`, confirmed by the sweeps, then its return: the pages it sent."""
    del _NOTES41[:]
    h.run(selfname, False)
    for _i in range(_mon41._DOWN_CONFIRM_SWEEPS):
        _CLOCK41.sleep(60)
        _sweep41()
    h.run(selfname, True)
    _CLOCK41.sleep(60)
    _sweep41()
    return _server_pages41()


def _restart_mid_plan_checks41():
    done, held, h = _restart_mid_plan41()
    crash = _crash_and_back41(h, "fctrserver")
    check("alerts (real sweeps): after a panel restart mid-plan, the servers the plan brings back do "
          "not page 'back online', during the plan or after it ends (control: a real crash after it "
          "pages 'went offline' and 'back online')",
          _all41(done is not None, held == [],
                 crash == [("server_down", "fctrserver"), ("server_up", "fctrserver")]),
          repr((done, held, crash)))


def _kept_down41():
    """Down on purpose through a plan: one the operator stopped just before it, one with a queued stop.

    Then a real crash after the plan. Returns (rows resolved, pages during and after the plan,
    pages for the crash).
    """
    _fresh41()
    r, h, rows = _std_host41()
    h.run("codserver", True)
    rows["gmod"].stop_pending = True
    db.session.commit()
    _mon_stubs41(h, rows)
    _sweep41()
    _sweep41()
    _SD41._mark_expected_offline(rows["cod"].id, "stop")  # what the Stop button marks, then its stop
    h.run("codserver", False)
    _CLOCK41.sleep(60)
    _sweep41()
    HR.request_reboot(r, "now", None, "web")
    done = _plan_with_sweeps41(r, h)
    _sweeps_after41()
    quiet = sorted(_server_pages41())
    return done, quiet, _crash_and_back41(h, "fctrserver")


def _kept_down_checks41():
    done, quiet, crash = _kept_down41()
    check("alerts (real sweeps): a server the operator stopped just before the plan, and one whose "
          "queued stop the plan honoured, stay down without ever paging 'went offline unexpectedly' "
          "— not during the plan, not when its window ends", _all41(done is not None, quiet == []),
          repr((done, quiet)))
    check("alerts (real sweeps): ...while a real crash after the plan pages 'went offline' once, and "
          "its return 'back online' (control: these sweeps do page)",
          crash == [("server_down", "fctrserver"), ("server_up", "fctrserver")], repr(crash))


def _kept_down_unscanned_checks41():
    """A queued stop the plan honoured, on a host whose port scan fails from the plan to past its window."""
    _fresh41()
    r, h, rows = _std_host41()
    rows["gmod"].stop_pending = True
    db.session.commit()
    _mon_stubs41(h, rows)
    _sweep41()
    _sweep41()
    scanning, probe = [False], _mon41._probe_host
    _patch(_mon41, "_probe_host", lambda remote, read_flags=True: (
        remote.id, dict(probe(remote, read_flags)[1], ports=None) if not scanning[0]
        else probe(remote, read_flags)[1]))
    HR.request_reboot(r, "now", None, "web")
    done = _plan_with_sweeps41(r, h)
    _sweeps_after41(5)
    scanning[0] = True
    _sweeps_after41()
    check("alerts (real sweeps): a queued stop the plan honoured pages nothing even when no sweep saw it "
          "down while the plan held it — the restore records it down itself, so the window's end is not "
          "'went offline unexpectedly'",
          _all41(done is not None, not h.running("gmodserver"), _server_pages41() == []),
          repr((done, _server_pages41(), _ps41._monitor_state["servers"].get(rows["gmod"].id))))
    h.run("gmodserver", True)                    # the operator starts it again, later
    _sweeps_after41(1)
    check("alerts (real sweeps): ...nor 'back online' when the operator starts it again — the summary "
          "said it stayed stopped, and nobody was told it went down",
          _server_pages41() == [], repr(_server_pages41()))


def _failed_row_back_checks41():
    """A server the summary reported as not back: its later return is news, and pages."""
    _fresh41()
    r, h, rows = _std_host41()
    _mon_stubs41(h, rows)
    _sweep41()
    _sweep41()
    HR.request_reboot(r, "now", None, "web")
    h.flag("fail_start", "mcserver")
    done = _plan_with_sweeps41(r, h, passes=80,
                               between=lambda n: h.run("gmodserver", True) if n == 10 else None)
    summary = "".join(_bodies41("Host reboot"))
    during = _server_pages41()
    del _NOTES41[:]
    h.run("fctrserver", True)
    _CLOCK41.sleep(60)
    _sweep41()
    check("alerts (real sweeps): a server the summary said did not come back pages 'back online' when "
          "it does (the summary told the operator it was down); the plan's held servers did not",
          _all41(done is not None, "fctrserver didn't come back" in summary, during == [],
                 _server_pages41() == [("server_up", "fctrserver")]), repr((done, summary, during, _NOTES41)))


_VPS41 = NS(display_name="vps-test")
_T41 = 1791000000.0


def _said41(rows, now, rollback_=False, **meta):
    """HR._summary's text for rows given as (name, result, queued), each carrying `meta`."""
    recs = [(NS(name=n), dict(meta, result=res, queued=q,
                             restore="failed" if res.startswith("FAIL") else "done"))
            for n, res, q in rows]
    return HR._summary(_VPS41, recs, now, rollback_)[0]


_BACK41 = [("mc", "panel", False), ("gmod", "autostart", False), ("fctr", "autostart", False)]


def _summary_time_checks41():
    fast = _said41(_BACK41, _T41 + 299.5, sent=_T41, boot_seen=_T41 + 9.4)
    slow = _said41(_BACK41, _T41 + 400, sent=_T41, boot_seen=_T41 + 150)
    unsent = _said41(_BACK41, _T41 + 400, sent=None, boot_seen=_T41 + 150)
    eq("summary: the host's new boot and the servers' return are each said as what they measure, "
       "rounded UP so 'within' is true — not 'back after 4 min' for a host that booted in seconds", fast,
       "vps-test rebooted: its new boot started within 10 s of the reboot being sent. 3/3 running again "
       "within 5 min of the reboot being sent (2 by Autostart, 1 started by the panel).")
    eq("summary: ...a host slow to boot is said in minutes, rounded up too", slow,
       "vps-test rebooted: its new boot started within 3 min of the reboot being sent. 3/3 running again "
       "within 7 min of the reboot being sent (2 by Autostart, 1 started by the panel).")
    eq("summary: ...and with no send time on record it claims no time at all", unsent,
       "vps-test rebooted. 3/3 running again (2 by Autostart, 1 started by the panel).")


def _summary_reason_checks41():
    rollback = _said41([("mc", "panel", False), ("cod", "stopped", True)], _T41 + 60, rollback_=True,
                       reason="cancelled by ops", sent=None)
    eq("summary: a rollback's server that stayed stopped is explained by its own reason only — the "
       "rollback restarts one with no Autostart, so a queued stop is all it can be", rollback,
       "Reboot of vps-test did not happen (cancelled by ops): 1 server coming back. 1 started by the "
       "panel, 0 by Autostart within 5 min. 1 stayed stopped, as planned (a queued stop).")
    failed = _said41([("mc", "FAIL: no tmux session", False), ("gmod", "autostart", False)], _T41 + 200,
                     rollback_=True, reason="cancelled by ops", sent=None)
    eq("summary: a rollback counts as coming back only the servers that are — one whose start failed "
       "is named as not back, not counted among them too", failed,
       "Reboot of vps-test did not happen (cancelled by ops): 1 server coming back. 0 started by the "
       "panel, 1 by Autostart within 5 min. mc didn't come back: FAIL: no tmux session.")
    only_off = _said41([("mc", "stopped", False)], _T41 + 300, sent=_T41, boot_seen=_T41 + 20)
    eq("summary: after a reboot, one kept down because restoring is off says that, and no 'running "
       "again' when nothing was to come back", only_off,
       "vps-test rebooted: its new boot started within 20 s of the reboot being sent. 1 stayed stopped, "
       "as planned (no Autostart, and restoring is turned off).")
    mixed = _said41([("a", "stopped", True), ("b", "stopped", False), ("c", "stopped", None)],
                    _T41 + 300, sent=_T41, boot_seen=_T41 + 20)
    check("summary: ...mixed reasons are each counted, and a plan from before the reason was recorded "
          "keeps the either/or", mixed.endswith(
              " 3 stayed stopped, as planned (1: a queued stop; 1: no Autostart, and restoring is turned "
              "off; 1: a queued stop, or no Autostart with restoring turned off)."), mixed)
