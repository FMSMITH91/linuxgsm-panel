"""Part 270 of the unit suite: the browser side of review pass 33.

1. The Databases tab on a host with no database server yet: a super admin's "Use a database server on
   another machine" is shown (the host line was hidden before its links were added), and the same
   for a server the panel cannot sign in to yet.
2. Two password dialogs open at once (the step-up password over a backup passphrase): each field has
   its own id, so each label names its own field; the passphrase field is not offered the sign-in
   password; each dialog still finds its own field.
3. An ajax data-step-up form with fields to fill in (Add user, Edit group) gets the step-up dialog's
   form-save words; a button-only one (Delete, Revoke) keeps the action words.
4. The Account page's alerts card reads the browser again when the page comes back into view or the
   notification setting changes, and its two posts (alerts on this device, Telegram link) ask for the
   password in place on a page left open past the recent-sign-in window.

Scripts run in node on stand-in DOMs; nothing reaches a host.
"""
import hashlib as _hashlib270
import json as _json270

from unit.part01 import eq
from unit.part221 import _node221
from unit.part249 import _DOM249, _SETTLE249, _cut249, _js249

# Text read the way a browser reads it: an element's own text and its children's.
_TEXT270 = r"""
Object.defineProperty(El.prototype, 'textContent', {
  get(){ return this._text + this.children.map(c => c.textContent).join(''); },
  set(v){ this._text = String(v); this.children = []; }});
"""


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The Databases tab's host line: a super admin's remote choice on a host with no database server
# ════════════════════════════════════════════════════════════════════════════════════════════════
_DB_CASES270 = [
    ("none, super admin", {"state": "none", "can": {"su": True, "setup": True, "manage": True}}),
    ("needs_login, super admin", {"state": "needs_login", "can": {"su": True, "setup": True, "manage": True}}),
    ("none, admin", {"state": "none", "can": {"su": False, "setup": True, "manage": True}}),
    ("ready, admin", {"state": "ready", "can": {"su": False, "setup": True, "manage": True},
                      "host": {"version": "10.11.2", "flavor": "mariadb", "warnings": []}}),
]


def _db_host270():
    """Draw the tab from each load answer; what #db-host shows and which actions its buttons hold."""
    prog = (_DOM249 + _TEXT270 + _SETTLE249 + r"""
global.MOUNT = ''; global.serverId = 5; window.addEventListener = () => {};
const cases = """ + _json270.dumps(_DB_CASES270) + r""";
let answer = null;
window.fetch = () => Promise.resolve({ok: true, json: () => Promise.resolve(answer)});
""" + _js249("server_databases.js") + r"""
(async () => {
  const out = {};
  for (const [name, d] of cases) {
    answer = Object.assign({host: null, endpoint: null, databases: [], prefix: 'gs5_', suggest: '', used: 0, cap: 5}, d);
    await window.dbLoad(true); await settle();
    const h = ids['db-host'];
    out[name] = [h.style.display !== 'none', h.children.filter(c => c.tagName === 'BUTTON').map(c => c.attrs['data-action'])];
  }
  console.log(JSON.stringify(out));
})();
""")
    return _node221("databases tab (node): host line", prog)


_DBH270 = _db_host270()
if _DBH270 is not None:
    eq("databases tab (node): a host with no database server shows a super admin 'Use a database server on "
       "another machine', and so does one the panel cannot sign in to yet; an admin's empty line stays hidden; "
       "a ready host's line shows",
       _DBH270, {"none, super admin": [True, ["dbRemoteShow"]], "needs_login, super admin": [True, ["dbRemoteShow"]],
                 "none, admin": [False, []], "ready, admin": [True, []]})


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The step-up password dialog over the backup passphrase dialog
# ════════════════════════════════════════════════════════════════════════════════════════════════
_PANEL270 = _js249("panel.js")
_CD270 = "\n".join(_cut249(_PANEL270, head) for head in (
    "function _cdInputHtml(", "function _cdFillBody(", "function _cdGateConfirm(", "function _cdHost(",
    "window.confirmDialog = function("))
# An overlay finds only what its own markup holds (an id, a data-… value), as querySelector does.
_FIND270 = r"""
function escapeHtml(s){ return String(s); }
const _qs270 = El.prototype.querySelector;
El.prototype.querySelector = function(sel){
  if (!this._html) return _qs270.call(this, sel);
  const pair = /^\[([\w-]+)="([^"]*)"\]$/.exec(sel), bare = /^\[([\w-]+)\]$/.exec(sel);
  const has = sel[0] === '#' ? this._html.includes('id="' + sel.slice(1) + '"')
    : pair ? this._html.includes(pair[1] + '="' + pair[2] + '"') : bare ? this._html.includes(bare[1]) : true;
  return has ? _qs270.call(this, sel) : null;
};
"""
_PHRASE270 = "the-other-panels-phrase"   # typed into the backup passphrase field


def _stacked270():
    """Open the passphrase dialog, confirm it, and let the real step-up dialog open over it."""
    bk = _js249("remote_manage_backups.js")
    prog = (_DOM249 + _SETTLE249 + _FIND270 + _CD270 + r"""
global.MOUNT = ''; global.t = s => s; window.STEP_UP_TOTP = false; function bkMsg(){}
global.fetch = url => /step_up=1/.test(url)
  ? Promise.resolve({ok: true, json: () => Promise.resolve({step_up: true})}) : new Promise(() => {});
""" + _js249("step_up_form.js") + "\n" + _cut249(bk, "function _bkStepUp(") + "\n"
            + _cut249(bk, "function _bkAskPassphrase(") + r"""
(async () => {
  _bkAskPassphrase('other.tar.gz', null);
  const first = document.body.children[document.body.children.length - 1];
  const input = first.querySelector('[data-cd="input"]'), ok = first.querySelector('[data-cd="ok"]');
  const found = !!input && !!first.querySelector('[data-cd="err"]');
  if (input) { input.value = '""" + _PHRASE270 + r"""'; (input.listeners.input || []).forEach(f => f()); }
  ok.onclick(); await settle();
  const second = document.body.children[document.body.children.length - 1];
  const read = ov => {
    const h = ov._html || '';
    return {label: (/<label[^>]* for="([^"]+)"/.exec(h) || [])[1], field: (/<input[^>]* id="([^"]+)"/.exec(h) || [])[1],
            auto: (/<input[^>]* autocomplete="([^"]+)"/.exec(h) || [])[1]};
  };
  const a = read(first), b = read(second);
  console.log(JSON.stringify({two: document.body.children.length, found, foundTop: !!second.querySelector('[data-cd="input"]'),
    distinct: !!a.field && a.field !== b.field, own: a.label === a.field && b.label === b.field, auto: [a.auto, b.auto]}));
})();
""")
    return _node221("stacked dialogs (node)", prog)


_ST270 = _stacked270()
if _ST270 is not None:
    eq("confirm dialog (node): the step-up password dialog over the backup passphrase dialog: two fields with "
       "their own ids, each label naming its own field, each dialog finding its own field and message",
       {k: _ST270.get(k) for k in ("two", "found", "foundTop", "distinct", "own")},
       {"two": 2, "found": True, "foundTop": True, "distinct": True, "own": True})
    eq("confirm dialog (node): ...the passphrase field is autocomplete new-password (no sign-in password filled "
       "into it) and the account-password field keeps current-password",
       _ST270.get("auto"), ["new-password", "current-password"])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. An ajax data-step-up form's words: a form with fields saves, a button-only form acts
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _ajax_words270():
    """Send two ajax data-step-up forms through panel.js's _ajaxStepUp and the real step_up_form.js."""
    prog = (_DOM249 + _SETTLE249 + r"""
global.MOUNT = ''; global.t = s => s; const opened = [];
window.confirmDialog = o => { opened.push(o.confirmLabel); };
global.fetch = () => Promise.resolve({ok: true, json: () => Promise.resolve({step_up: true})});
function _submitAjaxForm(){}
// A form's fields, matched against the selector the way querySelector would (tag, :not([type=…])).
function makeForm(fields){
  const hit = (f, part) => f.tag === (/^[a-z]+/.exec(part) || [''])[0]
    && ![...part.matchAll(/:not\(\[type="(\w+)"\]\)/g)].some(m => m[1] === f.type);
  return {hasAttribute: k => k === 'data-step-up', getAttribute: k => k === 'data-step-up-totp' ? '0' : null,
          querySelector: sel => fields.find(f => sel.split(',').some(p => hit(f, p.trim()))) || null};
}
""" + _js249("step_up_form.js") + "\n" + _cut249(_PANEL270, "function _ajaxStepUp(") + r"""
(async () => {
  _ajaxStepUp(makeForm([{tag: 'input', type: 'hidden'}, {tag: 'input', type: 'text'}, {tag: 'button', type: 'submit'}]));
  await settle();
  _ajaxStepUp(makeForm([{tag: 'input', type: 'hidden'}, {tag: 'button', type: 'submit'}]));
  await settle();
  console.log(JSON.stringify(opened));
})();
""")
    return _node221("ajax step-up words (node)", prog)


_AW270 = _ajax_words270()
if _AW270 is not None:
    eq("step-up (node): an ajax data-step-up form with a field to fill in (Add user) is confirmed with 'Confirm and "
       "save'; a button-only one (Delete user, Revoke) with 'Confirm'", _AW270, ["Confirm and save", "Confirm"])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The alerts card: read again when the page comes back; its posts ask for the password in place
# ════════════════════════════════════════════════════════════════════════════════════════════════
_EP270 = "https://push.example/ep1"   # this browser's subscription endpoint (a stand-in)
_PUSH_DOM270 = r"""
class E {
  constructor(id){ this.id = id; this.cls = new Set(); this.attrs = {}; this.listeners = {}; this.disabled = false;
    const c = this.cls;
    this.classList = {toggle(k, on){ if (on === undefined) on = !c.has(k); if (on) c.add(k); else c.delete(k); },
                      add: k => c.add(k), remove: k => c.delete(k), contains: k => c.has(k)}; }
  getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; }
  setAttribute(k, v){ this.attrs[k] = String(v); }
  addEventListener(t, f){ (this.listeners[t] = this.listeners[t] || []).push(f); }
  fire(t, e){ (this.listeners[t] || []).forEach(f => f(e || {})); }
  querySelector(sel){ return this.q ? this.q[sel] || null : null; }
  querySelectorAll(sel){ return (this.all && this.all[sel]) || []; }
}
const card = new E('sec-push');
Object.assign(card.attrs, {'data-key': 'BAAA', 'data-reauth': '0', 'data-sw': '/static/push/sw.js', 'data-scope': '/static/push/',
  'data-reauth-url': '/account/reauth?next=%2Faccount', 'data-subscribe-url': '/account/push/subscribe',
  'data-unsubscribe-url': '/account/push/unsubscribe', 'data-test-url': '/account/push/test'});
const msgs = ['checking', 'on', 'off', 'blocked', 'denied', 'failed', 'pushsvc'].map(m => { const s = new E(m); s.attrs['data-push-msg'] = m; return s; });
const li = new E('dev'); li.attrs['data-push-hash'] = HASH; const badge = new E('badge'); badge.cls.add('d-none'); li.q = {'[data-push-this]': badge};
card.all = {'[data-push-msg]': msgs, '[data-push-hash]': [li]};
const tg = new E('tg-link'); Object.assign(tg.attrs, {'data-link-url': '/account/telegram/link', 'data-check-url': '/account/telegram/check'});
tg.all = {'[data-tg-msg]': []};
const els = {'sec-push': card, 'push-enable': new E('on'), 'push-disable': new E('off'), 'push-test': new E('test'),
  'tg-link': tg, 'tg-link-btn': new E('tgbtn'), 'tg-link-open': new E('tgopen'), 'tg-link-msg': new E('tgmsg')};
els['push-disable'].cls.add('d-none'); els['push-test'].cls.add('d-none');
const docL = {}, winL = {};
global.window = global;
global.document = {visibilityState: 'visible', getElementById: id => els[id] || null,
  addEventListener: (t, f) => { (docL[t] = docL[t] || []).push(f); }};
window.addEventListener = (t, f) => { (winL[t] = winL[t] || []).push(f); };
const state = {sub: null, unsubs: 0, reloads: 0}, posts = [], asks = [];
function makeSub(){ return {endpoint: EP, options: {}, toJSON(){ return {endpoint: EP}; },
  unsubscribe(){ state.unsubs++; state.sub = null; return Promise.resolve(true); }}; }
const reg = {active: {}, pushManager: {getSubscription: () => Promise.resolve(state.sub),
  subscribe: () => { state.sub = makeSub(); return Promise.resolve(state.sub); }}};
const perm = new E('perm');
Object.defineProperty(globalThis, 'navigator', {configurable: true, writable: true, value: {userAgent: 'x', platform: 'x', maxTouchPoints: 0,
  serviceWorker: {getRegistration: () => Promise.resolve(reg), register: () => Promise.resolve(reg)},
  permissions: {query: () => Promise.resolve(perm)}}});
window.isSecureContext = true; window.PushManager = function(){};
window.Notification = {permission: 'granted', requestPermission: () => Promise.resolve('granted')};
window.location = {href: 'https://panel.example/account', origin: 'https://panel.example',
  reload(){ state.reloads++; }, assign(){}};
window.STEP_UP_TOTP = false;
let held = null;
window.stepUpThen = (go, totp, cancelled) => { asks.push(totp); held = {go, cancelled}; };
window.fetch = (url, init) => { posts.push(url); return Promise.resolve({status: 200, json: () => Promise.resolve({success: true, url: ''})}); };
const shown = () => msgs.filter(s => !s.cls.has('d-none')).map(s => s.id).join(',');
const btns = () => ['push-enable', 'push-disable', 'push-test'].filter(id => !els[id].cls.has('d-none')).join(',');
"""


def _push_card270():
    """Run push_alerts.js's card: state changes after it was drawn, then each post with the dialog held."""
    prog = ("const HASH = %s, EP = %s;\n" % (_json270.dumps(_hashlib270.sha256(_EP270.encode()).hexdigest()),
                                           _json270.dumps(_EP270))
            + _PUSH_DOM270 + _SETTLE249 + _js249("push_alerts.js") + r"""
(async () => {
  const seen = {};
  const back = async () => { (docL.visibilitychange || []).forEach(f => f()); await settle(); };
  state.sub = makeSub(); await settle(); seen.drawn = [shown(), btns()];
  state.sub = null; await back(); seen.offElsewhere = [shown(), btns()];
  Notification.permission = 'denied'; perm.fire('change'); await settle(); seen.blocked = [shown(), btns()];
  Notification.permission = 'default'; (winL.pageshow || []).forEach(f => f({persisted: true})); await settle();
  seen.allowed = [shown(), btns()];
  els['push-enable'].fire('click'); await settle();
  seen.asked = [asks.length, posts.slice()];
  held.cancelled(); await settle(); seen.cancelled = [state.unsubs, els['push-enable'].disabled, shown(), posts.slice()];
  els['push-enable'].fire('click'); await settle(); held.go(); await settle();
  seen.sent = [posts.slice(), state.reloads];
  posts.length = 0; asks.length = 0;
  els['tg-link-btn'].fire('click'); await settle(); seen.tgAsked = [asks.length, posts.slice()];
  held.go(); await settle(); seen.tgSent = posts.slice();
  console.log(JSON.stringify(seen));
})();
""")
    return _node221("push card (node)", prog)


_PC270 = _push_card270()
if _PC270 is not None:
    eq("push card (node): drawn on, then read again when the page comes back (alerts turned off elsewhere), when "
       "notifications are blocked (no buttons) and when they are allowed again (Turn on alerts back)",
       [_PC270.get(k) for k in ("drawn", "offElsewhere", "blocked", "allowed")],
       [["on", "push-disable,push-test"], ["off", "push-enable"], ["blocked", ""], ["off", "push-enable"]])
    eq("push card (node): Turn on alerts on a page left open past the recent-sign-in window asks for the password "
       "before the subscription is posted; closing that dialog takes the browser's half back and sends nothing",
       [_PC270.get("asked"), _PC270.get("cancelled")], [[1, []], [1, False, "off", []]])
    eq("push card (node): ...confirmed, the subscription is posted and the page reloads",
       _PC270.get("sent"), [["/account/push/subscribe"], 1])
    eq("push card (node): Link my Telegram asks for the password before its post, and posts once confirmed",
       [_PC270.get("tgAsked"), _PC270.get("tgSent")], [[1, []], ["/account/telegram/link"]])
