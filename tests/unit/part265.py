"""Part 265 of the unit suite: the browser side of review pass 32.

1. A backup passphrase dialog whose step-up password dialog is cancelled can be sent again: its
   Restore comes back from busy with the passphrase kept (confirmDialog's api.ready()).
2. The step-up password dialog closed while its password is being checked runs nothing when the
   check answers; and its words follow what is confirmed (a form's save, or any other action).
3. The "outside OWASP's recommendation" notes under Settings and Schedules follow the field or
   switch on load and on pageshow too, not only when it is changed.
4. Files & Config: the Databases or Add-ons section a viewer lands on with no #hash (no VIEW_FILES)
   loads, and a section shown any other way (a click, a hash) loads too.
5. The JS catalog gate judges a status-marked message ('✗ Use at least 15 characters') by the text
   i18n.js looks up, without the mark, and the Backups card's messages are in both catalogs.

Scripts run in node on stand-in DOMs; nothing reaches a host.
"""
import json as _json265
import os
import shutil as _shutil265
import subprocess as _sp265  # nosec B404 - node on this part's own fixtures
import sys as _sys265
import tempfile as _tf265

from unit.part01 import check, eq, skip
from unit.part05 import _root
from unit.part221 import _node221
from unit.part249 import _DOM249, _SETTLE249, _cut249, _js249

_PANEL265 = _js249("panel.js")
_CD265 = "\n".join(_cut249(_PANEL265, head) for head in (
    "function _cdHost(", "function _cdGateConfirm(", "window.confirmDialog = function("))
_CD_STUBS265 = r"""
function escapeHtml(s){ return String(s); } function _cdInputHtml(){ return ''; } function _cdFillBody(){}
// Markup and text replace each other, as in a browser; the dialog's OK button starts with its label.
Object.defineProperty(El.prototype, 'innerHTML', {get(){ return this._html || ''; }, set(v){ this._html = String(v); this._text = ''; }});
Object.defineProperty(El.prototype, 'textContent', {get(){ return this._text; }, set(v){ this._text = String(v); this._html = ''; this.children = []; }});
const _q265 = El.prototype.querySelector;
El.prototype.querySelector = function(sel){ const had = sel in this._q, e = _q265.call(this, sel);
  if (!had && sel === '[data-cd="ok"]') e.textContent = 'OK-LABEL'; return e; };
"""
_TYPED265 = "the-other-panels-phrase"   # what the node test types into the backup passphrase field


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The passphrase dialog under a cancelled step-up dialog: Restore comes back, the field is kept
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _passphrase_cancel265():
    """Drive _bkAskPassphrase through the real confirmDialog: cancel the step-up, then confirm it."""
    bk = _js249("remote_manage_backups.js")
    prog = (_DOM249 + _CD265 + "\n" + _CD_STUBS265 + r"""
var MOUNT = '', sent = [], mode = {go: false};
function bkMsg(){}
window.STEP_UP_TOTP = false;
window.stepUpThen = function(go, totp, cancelled){ if (mode.go) go(); else if (cancelled) cancelled(); };
global.fetch = function(url, init){ sent.push([url, JSON.parse(init.body)]); return new Promise(function(){}); };
""" + _cut249(bk, "function _bkStepUp(") + "\n" + _cut249(bk, "function _bkAskPassphrase(") + r"""
_bkAskPassphrase('other.tar.gz', null);
const ov = document.body.children[document.body.children.length - 1];
const input = ov.querySelector('#cd-input'), ok = ov.querySelector('[data-cd="ok"]');
input.value = '""" + _TYPED265 + r"""'; (input.listeners.input || []).forEach(f => f());
const typed = !ok.disabled;
ok.onclick();
const after = {disabled: ok.disabled, spinner: /spinner/.test(ok.innerHTML), label: ok.textContent, value: input.value,
               open: !ov.removed, sent: sent.length};
mode.go = true; ok.onclick();
console.log(JSON.stringify({typed, after, sent}));
""")
    return _node221("backup passphrase dialog (node): step-up cancelled", prog)


_pc265 = _passphrase_cancel265()
if _pc265 is not None:
    eq("backup passphrase (node): cancelling the step-up password dialog leaves the passphrase dialog open with "
       "Restore pressable again (not disabled, no spinner) and the typed passphrase kept, nothing sent; confirming "
       "then sends the restore with that passphrase",
       (_pc265.get("typed"), _pc265.get("after"), _pc265.get("sent")),
       (True, {"disabled": False, "spinner": False, "label": "OK-LABEL", "value": _TYPED265, "open": True, "sent": 0},
        [["/api/panel/backup/restore", {"name": "other.tar.gz", "passphrase": _TYPED265}]]))


def _ready_empty265():
    """Api.ready() on a password dialog whose field is empty keeps Confirm disabled (the gate's own rule)."""
    prog = (_DOM249 + _CD265 + "\n" + _CD_STUBS265 + r"""
let api = null;
confirmDialog({title: 'x', requirePassword: true, onConfirm: function(v, a){ api = a; }});
const ov = document.body.children[document.body.children.length - 1];
const input = ov.querySelector('#cd-input'), ok = ov.querySelector('[data-cd="ok"]');
input.value = 'x'; (input.listeners.input || []).forEach(f => f()); ok.onclick();
input.value = ''; api.ready();
console.log(JSON.stringify({disabled: ok.disabled, spinner: /spinner/.test(ok.innerHTML), label: ok.textContent}));
""")
    return _node221("confirm dialog (node): ready with an empty field", prog)


_re265 = _ready_empty265()
if _re265 is not None:
    eq("confirm dialog (node): api.ready() with the field emptied meanwhile drops the spinner but keeps Confirm "
       "disabled, as typing nothing would", _re265, {"disabled": True, "spinner": False, "label": "OK-LABEL"})


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The step-up dialog: closed while checking runs nothing; its words follow the caller
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _step_up_dismiss265():
    """Run step_up_form.js on the real confirmDialog: Cancel mid-check, a plain confirm, and a form's submit."""
    prog = (_DOM249 + _SETTLE249 + _CD265 + "\n" + _CD_STUBS265 + r"""
global.MOUNT = ''; global.t = s => s;
const opened = [], real = window.confirmDialog;
window.confirmDialog = function(o){ opened.push(o); return real(o); };
let pending = null;
global.fetch = (url) => /step_up=1/.test(url)
  ? Promise.resolve({ok: true, json: () => Promise.resolve({step_up: true})})
  : new Promise(r => { pending = () => r({ok: true, json: () => Promise.resolve({success: true})}); });
const docL = {}; document.addEventListener = (tp, f) => { (docL[tp] = docL[tp] || []).push(f); };
""" + _js249("step_up_form.js") + r"""
(async () => {
  let went = 0, cancels = 0;
  async function run(cancelMidway){
    window.stepUpThen(() => { went++; }, false, () => { cancels++; }); await settle();
    const ov = document.body.children[document.body.children.length - 1];
    const input = ov.querySelector('#cd-input'), ok = ov.querySelector('[data-cd="ok"]');
    input.value = 'pw'; (input.listeners.input || []).forEach(f => f()); ok.onclick();
    if (cancelMidway) ov.querySelector('[data-cd="cancel"]').onclick();
    pending(); await settle();
  }
  await run(true); const cancelled = {went, cancels};
  await run(false); const confirmed = {went, cancels};
  const form = {attrs: {'data-step-up': '', 'data-step-up-totp': '0'}, classList: {contains: () => false},
    hasAttribute(k){ return k in this.attrs; }, getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; },
    removeAttribute(k){ delete this.attrs[k]; }};
  (docL.submit || []).forEach(f => f({target: form, preventDefault(){}})); await settle();
  console.log(JSON.stringify({cancelled, confirmed,
    words: opened.map(o => [o.confirmLabel, o.bodyNode.children[0].textContent])}));
})();
""")
    return _node221("step-up dialog (node): dismissed mid-check", prog)


_sd265 = _step_up_dismiss265()
if _sd265 is not None:
    eq("step-up (node): Cancel pressed while the password is being checked tells the caller it was cancelled and "
       "the check's success answer then runs nothing; a dialog left open runs the action once",
       (_sd265.get("cancelled"), _sd265.get("confirmed")), ({"went": 0, "cancels": 1}, {"went": 1, "cancels": 1}))
    _act265 = "This action needs your password again because you signed in a while ago."
    _chg265 = "This change needs your password again because you signed in a while ago. Nothing you typed is lost."
    eq("step-up (node): a page's own action (stepUpThen) is confirmed with 'Confirm' and no claim about typed "
       "values; a data-step-up form's save keeps 'Confirm and save' and 'Nothing you typed is lost'",
       _sd265.get("words"), [["Confirm", _act265], ["Confirm", _act265], ["Confirm and save", _chg265]])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The OWASP notes follow a restored field or switch: on load and on pageshow
# ════════════════════════════════════════════════════════════════════════════════════════════════
_NOTE_DOM265 = r"""
function El(id){ this.id = id; this.checked = true; this.value = ''; this.attrs = {}; this.cls = {'d-none': true};
  const self = this;
  this.classList = {toggle(c, on){ self.cls[c] = !!on; }, contains(c){ return !!self.cls[c]; }};
}
El.prototype.getAttribute = function(k){ return k in this.attrs ? this.attrs[k] : null; };
El.prototype.addEventListener = function(){};
const els = {}, winL = {};
function mk(id){ return els[id] = new El(id); }
global.window = global; window.addEventListener = (tp, f) => { (winL[tp] = winL[tp] || []).push(f); };
global.t = s => s;
global.document = {getElementById: id => els[id] || null,
  querySelectorAll: sel => sel.indexOf('data-confirm-off') >= 0 ? Object.values(els).filter(e => e.attrs.off) : []};
const hidden = id => els[id].cls['d-none'];
const pageshow = () => (winL.pageshow || []).forEach(f => f({persisted: false}));
"""


def _notes265():
    """Settings and Schedules notes: a field and switches already holding a restored value at load."""
    prog = _NOTE_DOM265 + r"""
const idle = mk('s-idle'); idle.value = '45'; idle.attrs['data-owasp-max'] = '30'; mk('s-idle-note');
const upd = mk('s-upd'); upd.checked = false; upd.attrs.off = 1; upd.attrs['data-confirm-off'] = 'x'; mk('s-upd-owasp');
const os_ = mk('sch-os'); os_.checked = false; mk('sch-os-owasp');
""" + _js249("settings.js") + "\n" + _js249("schedules.js") + r"""
const atLoad = [hidden('s-idle-note'), hidden('s-upd-owasp'), hidden('sch-os-owasp')];
idle.value = '10'; upd.checked = true; os_.checked = true; pageshow();
const atShow = [hidden('s-idle-note'), hidden('s-upd-owasp'), hidden('sch-os-owasp')];
console.log(JSON.stringify({atLoad, atShow}));
"""
    return _node221("owasp notes (node): restored values", prog)


_no265 = _notes265()
if _no265 is not None:
    eq("settings + schedules (node): a session field restored past OWASP's limit, and an Outside services switch "
       "and the OS update check restored Off, show their notes once the page loads; restored back on pageshow, "
       "the notes hide again", (_no265.get("atLoad"), _no265.get("atShow")),
       ([False, False, False], [True, True, True]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Files & Config: the lazy Databases and Add-ons sections load whichever way they are shown
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TABS_HARNESS265 = r"""'use strict';
const fs = require('fs'), vm = require('vm');
const cfg = JSON.parse(fs.readFileSync(0, 'utf8'));
function El(name){ this.attrs = {}; this.children = []; this.style = {}; this.className = ''; this.value = '';
  this.textContent = ''; this.innerHTML = ''; this.disabled = false; this.hidden = false; this.listeners = {};
  this.on = false; const self = this;
  this.classList = {toggle(c, v){ if (c === 'active') self.on = !!v; }, add(){}, remove(){},
                    contains(c){ return c === 'active' && self.on; }};
  if (name) this.attrs['data-sfsub-btn'] = name; }
El.prototype.getAttribute = function(k){ return k in this.attrs ? this.attrs[k] : null; };
El.prototype.setAttribute = function(k, v){ this.attrs[k] = String(v); };
El.prototype.removeAttribute = function(k){ delete this.attrs[k]; };
El.prototype.hasAttribute = function(k){ return k in this.attrs; };
El.prototype.addEventListener = function(t, f){ (this.listeners[t] = this.listeners[t] || []).push(f); };
El.prototype.appendChild = function(c){ this.children.push(c); return c; };
El.prototype.querySelector = function(){ return null; };
El.prototype.querySelectorAll = function(){ return []; };
El.prototype.closest = function(sel){ const m = /data-sfsub-btn(?:="(\w+)")?/.exec(sel);
  return m && this.attrs['data-sfsub-btn'] && (!m[1] || m[1] === this.attrs['data-sfsub-btn']) ? this : null; };
const btns = cfg.tabs.map(n => new El(n)), secs = cfg.tabs.map(n => { const e = new El(); e.attrs['data-sfsub'] = n; return e; });
const nav = new El(), ids = {'sfsub-nav': nav}, docL = {}, winL = {}, got = [];
const document = {
  getElementById: id => ids[id] = ids[id] || new El(),
  querySelectorAll: sel => sel === '[data-sfsub-btn]' ? btns : sel === '[data-sfsub]' ? secs : [],
  querySelector: sel => { const m = /data-sfsub-btn="(\w+)"/.exec(sel); return m ? btns.filter(b => b.attrs['data-sfsub-btn'] === m[1])[0] || null : null; },
  createElement: () => new El(), createTextNode: t => ({textContent: String(t)}),
  addEventListener: (t, f) => { (docL[t] = docL[t] || []).push(f); },
  dispatchEvent: e => { (docL[e.type] || []).forEach(f => f(e)); return true; }};
function CustomEvent(type, init){ this.type = type; this.detail = (init || {}).detail; }
const loc = {hash: cfg.hash || ''};
const ctx = {document, location: loc, CustomEvent, MOUNT: '', serverId: 7, JSON, Promise, Number, Date, Math, String, Array, Object,
  history: {replaceState: (a, b, h) => { loc.hash = h; }}, setTimeout: () => 0, setInterval: () => 0, clearInterval(){},
  fetch: url => { got.push(url); return new Promise(() => {}); }};
ctx.window = ctx; ctx.addEventListener = (t, f) => { (winL[t] = winL[t] || []).push(f); };
vm.createContext(ctx);
cfg.srcs.forEach(s => vm.runInContext(s, ctx));
const atLoad = got.slice();
const click = n => { const b = btns.filter(x => x.attrs['data-sfsub-btn'] === n)[0];
  (nav.listeners.click || []).forEach(f => f({target: b})); (docL.click || []).forEach(f => f({target: b})); };
(cfg.then || []).forEach(step => { if (step[0] === 'click') click(step[1]);
  else { loc.hash = step[1]; (winL.hashchange || []).forEach(f => f()); } });
process.stdout.write(JSON.stringify({atLoad, after: got.slice(atLoad.length)}));
"""


def _tabs265(tabs, hash_="", then=()):
    """Run server_files.js's section code, then server_databases.js and server_addons.js -> fetched URLs."""
    node = _shutil265.which("node")
    if not node:
        skip("files & config sections (node)", "node is not installed here")
        return None
    sf = _js249("server_files.js")
    srcs = [sf[:sf.index("var curDir")], _js249("server_databases.js"), _js249("server_addons.js")]
    cfg = {"tabs": list(tabs), "hash": hash_, "then": [list(s) for s in then], "srcs": srcs}
    with _tf265.TemporaryDirectory(prefix="p265-") as td:
        path = os.path.join(td, "harness.js")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_TABS_HARNESS265)
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
        r = _sp265.run([node, path], input=_json265.dumps(cfg), capture_output=True, text=True,  # nosec B603
                       timeout=60, check=False)
    try:
        return _json265.loads(r.stdout)
    except ValueError:
        return {"error": (r.stdout + r.stderr)[-600:]}


_DB265, _AD265 = "/api/server/7/databases", "/api/server/7/addons"
_t1 = _tabs265(("databases", "addons"))
_t2 = _tabs265(("addons",))
_t3 = _tabs265(("config", "databases", "addons"), then=(("click", "addons"), ("hash", "#databases")))
_t4 = _tabs265(("databases", "addons"), then=(("click", "addons"), ("hash", "#nothing")))
if None not in (_t1, _t2, _t3, _t4):
    eq("files & config (node): a viewer whose first section is Databases (no VIEW_FILES) and no #hash: the "
       "Databases section loads at once, Add-ons not until shown", _t1, {"atLoad": [_DB265], "after": []})
    eq("files & config (node): ...a viewer whose only section is Add-ons: it loads at once", _t2,
       {"atLoad": [_AD265], "after": []})
    eq("files & config (node): ...a viewer with Config: nothing lazy loads with the page; a click on Add-ons loads "
       "it, and a link to #databases loads that (control: the click and hash paths still work)", _t3,
       {"atLoad": [], "after": [_AD265, _DB265]})
    eq("files & config (node): ...a hash naming no section of this page falls back to the first one, which loads "
       "although the hash does not name it", _t4, {"atLoad": [_DB265], "after": [_AD265]})


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The JS catalog gate reads a status-marked message the way i18n.js looks it up
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _marked_gate265():
    """The gate over a fixture: a marked literal is asked for without its mark; a whole marked key also counts."""
    _sys265.path.insert(0, os.path.join(_root, "tools"))
    try:
        import i18n_scan as _scan265
    finally:
        _sys265.path.remove(os.path.join(_root, "tools"))
    with _tf265.TemporaryDirectory(prefix="p265i-") as td:
        js, tr = os.path.join(td, "js"), os.path.join(td, "tr")
        os.makedirs(js)
        os.makedirs(os.path.join(tr, "es"))
        with open(os.path.join(js, "a.js"), "w", encoding="utf-8") as fh:
            fh.write("msg('✗ Use at least fifteen characters','x');\n"
                     "msg(ok ? '✓ Encryption is now off' : '✗ Could not save it','x');\n"
                     "msg(t('✓ Schedule was saved'));\n")
        with open(os.path.join(tr, "es", "a.json"), "w", encoding="utf-8") as fh:
            _json265.dump({"Could not save it": "x", "✓ Schedule was saved": "x"}, fh)
        return sorted(_scan265.missing_js("es", js_dir=js, translation_dir=tr))


eq("i18n gate: a status-marked JS message is asked for by the text after its mark (what i18n.js looks up); one "
   "held by that text, or by its whole marked self, passes (it was never asked for, so five Backups card "
   "messages were English in es/fr with the gate green)",
   _marked_gate265(), ["Encryption is now off", "Use at least fifteen characters"])


def _backup_msgs265():
    """The Backups card's status messages, each looked up in the es and fr catalogs."""
    out = {}
    for lang in ("es", "fr"):
        cat = {}
        tdir = os.path.join(_root, "panel", "translations", lang)
        for name in sorted(os.listdir(tdir)):
            if name.endswith(".json"):
                with open(os.path.join(tdir, name), encoding="utf-8") as fh:
                    cat.update(_json265.load(fh))
        out[lang] = [m for m in ("Use at least 15 characters", "New backups will be encrypted", "Encryption off",
                                 "Could not start", "Could not check players") if not cat.get(m)]
    return out


check("i18n: the Backups card's passphrase and start messages are in the es and fr catalogs",
      _backup_msgs265() == {"es": [], "fr": []}, repr(_backup_msgs265()))
