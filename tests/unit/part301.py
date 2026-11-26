"""Part 301 of the unit suite: the Websites tab's pages, translations and docs.

1. The pages through part12's app: the list and the site page for a superadmin, an administrator, a
   customer and a viewer. A control the viewer may not use is not rendered at all (no Settings panel,
   Delete, Update, raw proxy lines or proxy card for a customer); the sidebar shows Websites only when
   websites_nav() answers a URL, as "Hosting" for a user with no server entries.
2. The strict policy: every rendered Websites page has no style attribute, no inline handler and no
   inline script (each <script> has the nonce and a src).
3. The scripts in node, over the REAL rendered page (its markup parsed into a small DOM): a hostile site
   name or domain stays text; a server-sent link is used only when it is http(s); the Advanced php.ini
   box refuses extensions, files from outside the site and managed keys; the exposure choice shows the
   allow list or the token field and never sends an empty token; the add dialog's missing precondition
   offers the one fix to a superadmin and only "ask" to anyone else, with Create on screen but
   unavailable; an install's steps are labelled; a saved environment variable left empty is kept, a
   removed one is dropped; a value above OWASP's PHP figure gets a note.
4. Text and docs: every new string in Spanish and French; the docs page exists and is linked, and the
   permissions page says what edit_website_files amounts to.

HOW IT RUNS. part12's app renders the templates in a request context with a user signed in; nothing
reaches a host. The node checks run the panel's own files (panel/static/js/websites*.js, website*.js)
in a vm context with a stand-in fetch that answers from this file.
"""
import json as _json301
import os
import re as _re301
import shutil as _shutil301
import subprocess as _sp301  # nosec B404 - node over the panel's own scripts
import sys as _sys301
import tempfile as _tf301
from html.parser import HTMLParser as _HTMLParser301

from flask import g as _g301, render_template as _render301
from flask_login import login_user as _login301

from unit import REPO_ROOT as _ROOT301
from unit.part01 import check, eq
from unit.part12 import P9_ADMIN, _p9
from panel.db.models import User as _User301, db as _db301
from panel.security import auth as _auth301

_JS301 = os.path.join(_ROOT301, "panel", "static", "js")
_NONCE301 = "p301-nonce"
_SITE301 = type("Site301", (), {"id": 7, "name": "shop", "kind": "wordpress"})()


def _read301(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _customer301():
    """A signed-in-able user with no group at all (a customer's sidebar has no server entry). -> id."""
    with _p9.app_context():
        u = _User301(username="p301_cust", password_hash=_auth301.hash_password(os.urandom(16).hex()),
                     display_name="Cust", is_superadmin=False, is_active=True)
        _db301.session.add(u)
        _db301.session.commit()
        return u.id


def _drop301(uid):
    with _p9.app_context():
        u = _db301.session.get(_User301, uid)
        if u is not None:
            _db301.session.delete(u)
            _db301.session.commit()


def _page301(tpl, uid, nav="/websites", **ctx):
    """`tpl` rendered for user `uid`, with websites_nav() answering `nav` (None: not registered)."""
    globs = _p9.jinja_env.globals
    had, old = "websites_nav" in globs, globs.get("websites_nav")
    try:
        if nav is None:
            globs.pop("websites_nav", None)
        else:
            globs["websites_nav"] = lambda: nav
        with _p9.test_request_context("/websites"):
            _g301.csp_nonce = _NONCE301          # what the app's before_request sets on a real request
            _login301(_db301.session.get(_User301, uid))
            return _render301(tpl, **ctx)
    finally:
        if had:
            globs["websites_nav"] = old
        else:
            globs.pop("websites_nav", None)


_CUST301 = _customer301()
try:
    _list_sa301 = _page301("websites.html", P9_ADMIN, can_add=True, site_admin=True)
    _list_cu301 = _page301("websites.html", _CUST301, can_add=False, site_admin=False)
    _list_cq301 = _page301("websites.html", _CUST301, can_add=True, site_admin=False)
    _site_ad301 = _page301("website.html", P9_ADMIN, site=_SITE301, can_manage=True, can_files=True, site_admin=True)
    _site_cu301 = _page301("website.html", _CUST301, site=_SITE301, can_manage=True, can_files=True, site_admin=False)
    _site_vw301 = _page301("website.html", _CUST301, site=_SITE301, can_manage=False, can_files=False, site_admin=False)
    # As the routes pass them: can_create / is_admin, and the site as its JSON (remote_id for an administrator only).
    _list_rt301 = _page301("websites.html", P9_ADMIN, can_create=True, is_admin=True)
    _site_rta301 = _page301("website.html", P9_ADMIN, site=dict(id=7, name="shop", kind="php", remote_id=1),
                            can_manage=True, can_files=True)
    _site_rtc301 = _page301("website.html", _CUST301, site=dict(id=7, name="shop", kind="php"), can_manage=True, can_files=True)
    _nav_none301 = _page301("websites.html", _CUST301, nav=None, can_add=False)
    _nav_empty301 = _page301("websites.html", _CUST301, nav="", can_add=False)
finally:
    _drop301(_CUST301)


# ── 1. who sees what ──────────────────────────────────────────────────────────────────────────────
def _has301(page, *needles):
    return tuple(n in page for n in needles)


eq("list: a superadmin has Add a website, the add dialog and the web proxy card (exposure, token, OWASP settings)",
   _has301(_list_sa301, 'id="ws-add-open"', 'id="ws-add-modal"', 'id="wp-card"', 'id="wp-token"', 'id="wp-hsts"'),
   (True, True, True, True, True))
eq("list: a customer without the right to add has no Add button, no dialog, no proxy card",
   _has301(_list_cu301, 'id="ws-add-open"', 'id="ws-add-modal"', 'id="wp-card"'), (False, False, False))
eq("list: a customer who may add gets Add and the dialog, but no customer picker and no proxy card",
   _has301(_list_cq301, 'id="ws-add-open"', 'id="ws-add-modal"', 'id="ws-add-customer-id"', 'id="wp-card"'),
   (True, True, False, False))
eq("site: an administrator has Settings, Delete, Update, the raw proxy lines and Open in Databases",
   _has301(_site_ad301, 'data-ws-pane="settings"', 'data-action="wsDelete"', 'id="ws-update"', 'id="wr-raw"',
           "Open in Databases"), (True, True, True, True, True))
eq("site: a customer who runs the site has none of the administrator's controls, not even disabled",
   _has301(_site_cu301, 'data-ws-pane="settings"', 'data-ws-tab="settings"', 'data-action="wsDelete"',
           'id="ws-update"', 'id="wr-raw"', "Open in Databases", 'id="wset-egress"'),
   (False, False, False, False, False, False, False))
eq("site: ...and keeps the main button and the panels manage_website gives (PHP, Performance, Rules, Files)",
   _has301(_site_cu301, 'id="ws-main"', 'data-ws-pane="php"', 'data-ws-pane="performance"', 'data-ws-pane="rules"',
           'data-ws-pane="files"'), (True, True, True, True, True))
eq("site: a viewer has no main button and no panel that changes anything",
   _has301(_site_vw301, 'id="ws-main"', 'data-ws-pane="files"', 'data-ws-pane="php"', 'data-ws-pane="rules"',
           'data-ws-pane="backups"', 'data-ws-pane="domains"', 'id="wd-add"'), (False, False, False, False, False, True, False))
eq("routes' names: can_create and is_admin give the Add button and the customer picker",
   _has301(_list_rt301, 'id="ws-add-open"', 'id="ws-add-customer-id"'), (True, True))
eq("routes' names: a site answer with its host (an administrator's) gives Settings and the PHP version choice; "
   "one without it (a runner's) shows the version as text and no Settings",
   (_has301(_site_rta301, 'data-ws-pane="settings"', 'id="wphp-version"', 'id="wperf-obj"'),
    _has301(_site_rtc301, 'data-ws-pane="settings"', 'id="wphp-version"', 'id="wphp-version-text"', 'id="wperf-obj"')),
   ((True, True, True), (False, False, True, False)))
_side_re301 = _re301.compile(r'<a href="/websites" class="[^"]*">\s*<i class="bi bi-globe2"></i> Websites</a>')
eq("sidebar: Websites appears when websites_nav() answers a URL, under 'Hosting' for a user with no server entry",
   (bool(_side_re301.search(_list_cu301)), '<div class="sidebar-section">Hosting</div>' in _list_cu301),
   (True, True))
eq("sidebar: no entry (and no empty section) when websites_nav() answers '' or is not registered",
   (bool(_side_re301.search(_nav_empty301)), "Hosting" in _nav_empty301,
    bool(_side_re301.search(_nav_none301)), "Hosting" in _nav_none301), (False, False, False, False))
_srv301 = _list_sa301.find('<div class="sidebar-section">Servers</div>')
_wsl301 = _list_sa301.find('<a href="/websites"')
check("sidebar: a superadmin's entry sits in the Servers section, with Install a Server (and Databases when there is one)",
      0 <= _srv301 < _wsl301 and "</ul>" not in _list_sa301[_srv301:_wsl301] and "Hosting" not in _list_sa301,
      _list_sa301[_srv301:_srv301 + 600])


# ── 2. the strict policy ──────────────────────────────────────────────────────────────────────────
class _Tags301(_HTMLParser301):
    """Every start tag's attributes, and each <script>'s own body."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.scripts, self._in = [], [], None

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "script":
            self._in = [dict(attrs), ""]

    def handle_data(self, data):
        if self._in is not None:
            self._in[1] += data

    def handle_endtag(self, tag):
        if tag == "script" and self._in is not None:
            self.scripts.append(self._in)
            self._in = None


def _handlers301(tags):
    """Every (tag, on* attribute) pair: an inline event handler, which the page's policy refuses."""
    return [(t, k) for t, a in tags for k in a if k.startswith("on")]


def _ours301(attrs):
    """Is this <script> one of the Websites scripts?"""
    return "/js/website" in (attrs.get("src") or "")


def _csp301(page):
    """(style attributes, on* attributes, how many Websites scripts, those without the nonce or a src) in `page`."""
    p = _Tags301()
    p.feed(page)
    styles = [t for t, a in p.tags if "style" in a]
    ours = [a for a, _body in p.scripts if _ours301(a)]
    return styles, _handlers301(p.tags), len(ours), [a for a in ours if a.get("nonce") != _NONCE301 or not a.get("src")]


for _nm301, _pg301 in (("list (superadmin)", _list_sa301), ("site (administrator)", _site_ad301),
                       ("site (customer)", _site_cu301)):
    _st301, _hd301, _n301, _bad301 = _csp301(_pg301)
    eq("csp: the %s page has no style attribute, no inline handler, and loads its scripts as nonce'd files" % _nm301,
       (_st301, _hd301, _n301 >= 2, _bad301), ([], [], True, []))
_tpl_src301 = "".join(_read301(os.path.join(_ROOT301, "panel", "templates", f))
                      for f in sorted(os.listdir(os.path.join(_ROOT301, "panel", "templates")))
                      if f.startswith(("_website", "website")))
check("csp: no Websites template writes an inline <script> body or a style attribute (the policy refuses both)",
      not _re301.search(r"<script(?![^>]*\bsrc=)[^>]*>", _tpl_src301) and " style=" not in _tpl_src301,
      _re301.findall(r"<script(?![^>]*\bsrc=)[^>]*>", _tpl_src301)[:3])


# ── 3. the scripts, in node, over the rendered page ───────────────────────────────────────────────
class _Tree301(_HTMLParser301):
    """The page as nested [tag, attrs, children] lists (text as strings), script and style bodies left out."""

    VOID = {"input", "br", "hr", "img", "meta", "link", "source", "area", "col", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = ["#root", {}, []]
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = [tag, {k: ("" if v is None else v) for k, v in attrs}, []]
        self.stack[-1][2].append(node)
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.stack[-1][2].append([tag, {k: ("" if v is None else v) for k, v in attrs}, []])

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if self.stack[-1][0] not in ("script", "style") and data.strip():
            self.stack[-1][2].append(data)


def _tree301(page):
    t = _Tree301()
    t.feed(page)
    return t.root


_HARNESS301 = r"""'use strict';
const fs = require('fs'), vm = require('vm');
const cfg = JSON.parse(fs.readFileSync(0, 'utf8'));
function kebab(k) { return 'data-' + k.replace(/[A-Z]/g, function (c) { return '-' + c.toLowerCase(); }); }
function Text(t) { this.nodeType = 3; this.textContent = String(t); this.parentNode = null; }
function El(tag) { this.tagName = String(tag).toUpperCase(); this.attrs = {}; this.children = []; this.parentNode = null;
  this.style = {}; this.disabled = false; this._value = null; this._checked = null; this.nodeType = 1;
  const self = this;
  this.dataset = new Proxy({}, {get: function (o, k) { return typeof k === 'string' ? self.getAttribute(kebab(k)) || undefined : undefined; },
    set: function (o, k, v) { self.setAttribute(kebab(k), v); return true; }});
  this.classList = {add: function (c) { self.className = (self.className + ' ' + c).trim(); },
    remove: function (c) { self.className = self.className.split(/\s+/).filter(function (x) { return x !== c; }).join(' '); },
    contains: function (c) { return self.className.split(/\s+/).indexOf(c) >= 0; },
    toggle: function (c, on) { if (on === undefined) on = !this.contains(c); if (on) this.add(c); else this.remove(c); return on; }}; }
['id', 'className:class', 'type', 'name', 'href', 'title', 'placeholder', 'target', 'rel', 'htmlFor:for'].forEach(function (p) {
  const parts = p.split(':'), prop = parts[0], attr = parts[1] || parts[0];
  Object.defineProperty(El.prototype, prop, {get: function () { return this.attrs[attr] || ''; },
    set: function (v) { this.attrs[attr] = String(v); }});
});
Object.defineProperty(El.prototype, 'hidden', {get: function () { return 'hidden' in this.attrs; },
  set: function (v) { if (v) this.attrs.hidden = ''; else delete this.attrs.hidden; }});
Object.defineProperty(El.prototype, 'checked', {get: function () { return this._checked === null ? 'checked' in this.attrs : this._checked; },
  set: function (v) { this._checked = !!v; }});
Object.defineProperty(El.prototype, 'options', {get: function () { return this.children.filter(function (c) { return c.tagName === 'OPTION'; }); }});
Object.defineProperty(El.prototype, 'value', {
  get: function () {
    if (this.tagName === 'SELECT') { const o = this.options; const v = this._value;
      if (v !== null && o.some(function (x) { return x.value === v; })) return v; return o.length ? o[0].value : ''; }
    if (this.tagName === 'OPTION') return 'value' in this.attrs ? this.attrs.value : this.textContent;
    if (this._value !== null) return this._value;
    if (this.tagName === 'TEXTAREA') return this.textContent;
    return this.attrs.value || ''; },
  set: function (v) { if (this.tagName === 'OPTION') this.attrs.value = String(v); else this._value = String(v); }});
Object.defineProperty(El.prototype, 'textContent', {
  get: function () { return this.children.map(function (c) { return c.textContent; }).join(''); },
  set: function (v) { this.children = []; if (String(v) !== '') this.appendChild(new Text(v)); }});
Object.defineProperty(El.prototype, 'firstChild', {get: function () { return this.children[0] || null; }});
Object.defineProperty(El.prototype, 'lastChild', {get: function () { return this.children[this.children.length - 1] || null; }});
El.prototype.setAttribute = function (k, v) { this.attrs[k] = String(v); };
El.prototype.getAttribute = function (k) { return k in this.attrs ? this.attrs[k] : null; };
El.prototype.hasAttribute = function (k) { return k in this.attrs; };
El.prototype.removeAttribute = function (k) { delete this.attrs[k]; };
El.prototype.appendChild = function (c) { if (c.parentNode) c.parentNode.removeChild(c); this.children.push(c); c.parentNode = this; return c; };
El.prototype.removeChild = function (c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); c.parentNode = null; return c; };
El.prototype.remove = function () { if (this.parentNode) this.parentNode.removeChild(this); };
El.prototype.click = function () { clicked.push(this.id); };
function matches(el, sel) {
  if (!(el instanceof El)) return false;
  const m = /^([a-z]*)((?:\[[^\]]+\]|\.[\w-]+|#[\w-]+)*)$/.exec(sel.trim());
  if (!m) throw new Error('selector ' + sel);
  if (m[1] && el.tagName !== m[1].toUpperCase()) return false;
  const parts = m[2].match(/\[[^\]]+\]|\.[\w-]+|#[\w-]+/g) || [];
  return parts.every(function (p) {
    if (p[0] === '.') return el.classList.contains(p.slice(1));
    if (p[0] === '#') return el.id === p.slice(1);
    const a = /^\[([\w-]+)(?:="([^"]*)")?\]$/.exec(p);
    return a[2] === undefined ? el.hasAttribute(a[1]) : el.getAttribute(a[1]) === a[2]; });
}
function all(root, sel, out) {
  root.children.forEach(function (c) { if (c instanceof El) { if (matches(c, sel)) out.push(c); all(c, sel, out); } });
  return out; }
El.prototype.querySelectorAll = function (sel) { return all(this, sel, []); };
El.prototype.querySelector = function (sel) { return all(this, sel, [])[0] || null; };
El.prototype.closest = function (sel) { let e = this; while (e && e instanceof El) { if (matches(e, sel)) return e; e = e.parentNode; } return null; };
function build(n) { if (typeof n === 'string') return new Text(n); const e = new El(n[0]);
  Object.keys(n[1]).forEach(function (k) { e.attrs[k] = n[1][k]; }); n[2].forEach(function (c) { e.appendChild(build(c)); }); return e; }
const root = build(cfg.tree), clicked = [], calls = [], dialogs = [];
const document = {createElement: function (t) { return new El(t); }, createTextNode: function (t) { return new Text(t); },
  getElementById: function (id) { return all(root, '#' + id, [])[0] || null; },
  querySelector: function (s) { return root.querySelector(s); }, querySelectorAll: function (s) { return root.querySelectorAll(s); },
  addEventListener: function () {}, body: root};
function answer(url) { const path = url.replace(/^\/m/, '').split('?')[0]; return cfg.routes[path] || {success: false, message: 'no stand-in for ' + path}; }
const ctx = {document: document, MOUNT: '/m', JSON: JSON, Promise: Promise, Number: Number, Array: Array, Object: Object, String: String,
  Math: Math, RegExp: RegExp, Infinity: Infinity, encodeURIComponent: encodeURIComponent, location: {search: cfg.search || '', href: ''},
  history: {replaceState: function () {}}, setTimeout: function () { return 0; }, clearTimeout: function () {},
  FormData: function () { this.parts = []; this.append = function (k, v) { this.parts.push([k, String(v)]); }; },
  bootstrap: {Modal: {getOrCreateInstance: function () { return {show: function () {}}; }}},
  confirmDialog: function (o) { dialogs.push(o); }, stepUpThen: function (go) { go(); }, toast: function () {},
  t: function (s) { return s; }, tf: function (s, v) { return s.replace(/\{(\w+)\}/g, function (m, k) { return v && k in v ? String(v[k]) : m; }); },
  fetch: function (url, init) { calls.push([init && init.method || 'GET', url, init && typeof init.body === 'string' ? JSON.parse(init.body) : null]);
    return Promise.resolve({ok: true, json: function () { return Promise.resolve(answer(url)); }}); }};
ctx.window = ctx;
vm.createContext(ctx);
cfg.scripts.forEach(function (f) { vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, {filename: f}); });
ctx.tick = function () { return new Promise(function (r) { setImmediate(r); }); };
ctx.$ = function (id) { return document.getElementById(id); };
function every(e, out) { e.children.forEach(function (c) { if (c instanceof El) { out.push(c); every(c, out); } }); return out; }
ctx.html = function (e) { return every(e, []).map(function (x) { return x.tagName; }); };
ctx.calls = calls; ctx.dialogs = dialogs; ctx.clicked = clicked;
(async function () {
  for (let i = 0; i < 8; i++) await ctx.tick();
  const out = await vm.runInContext('(async function () {' + cfg.scenario + '})()', ctx);
  process.stdout.write(JSON.stringify(out));
})().catch(function (e) { process.stdout.write(JSON.stringify({error: String(e && e.stack || e)})); });
"""


def _ran301(what, res):
    """Name the harness run itself, so a script that threw reads as that, not as every check after it failing."""
    check("node: the %s harness ran" % what, isinstance(res, (dict, list)) and not (isinstance(res, dict) and "error" in res),
          res.get("error") if isinstance(res, dict) else repr(res))
    return res


def _node301(page, scripts, scenario, routes=None, search=""):
    """Run `scenario` (an async function body returning JSON) in node over `page`'s markup with `scripts`."""
    node = _shutil301.which("node")
    if not node:
        return {"error": "node is not installed"}
    tmp = _tf301.mkdtemp(prefix="p301-")
    try:
        path = os.path.join(tmp, "harness.js")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_HARNESS301)
        cfg = {"tree": _tree301(page), "scripts": [os.path.join(_JS301, s) for s in scripts], "scenario": scenario,
               "routes": routes or {}, "search": search}
        r = _sp301.run([node, path], input=_json301.dumps(cfg),  # nosec B603 - node on this part's harness
                       capture_output=True, text=True, timeout=120, check=False)
        try:
            return _json301.loads(r.stdout)
        except ValueError:
            return {"error": (r.stdout + r.stderr)[-1200:]}
    finally:
        _shutil301.rmtree(tmp, ignore_errors=True)


_EVIL301 = '<img src=x onerror="alert(1)">'
_LIST301 = {"success": True, "sites": [{"id": 3, "name": _EVIL301, "kind": "constructor", "state": "running", "enabled": True,
                                        "domain": "<b>x</b>.example.org", "cert_state": "issued"}],
            "ports": {"mode": "public", "open": True, "sites_enabled": 2, "firewall": "off"}, "missing": [],
            "php_versions": ["8.4"], "runtimes": {"node": ["22"]}, "hosts": [{"id": 1, "name": "h"}],
            "apps": [{"key": "wordpress", "name": "WordPress", "version": "6.8.3"}], "customers": []}
_COMMON301 = ["websites_common.js"]
_lst301 = _ran301('list', _node301(_list_sa301, _COMMON301 + ["websites.js"], r"""
  const box = $('ws-list'); const tags = html(box);
  const name = box.querySelector('.ws-card-name'), dom = box.querySelector('.ws-card-domain');
  return {tags: tags.filter(function (t) { return ['IMG', 'B', 'SCRIPT'].indexOf(t) >= 0; }), name: name.textContent,
          nameRaw: name.hasAttribute('data-no-i18n'), dom: dom.textContent, href: box.querySelector('a').href,
          kind: box.querySelector('.ws-chip').textContent, ports: $('ws-ports').textContent, portsShown: !$('ws-ports').hidden,
          safe: [WS.safeUrl('javascript:alert(1)'), WS.safeUrl('https://a.example/x'), WS.safePath('//evil.example/'),
                 WS.safePath('/settings#outside')]};
""", routes={"/api/websites": _LIST301}))
eq("node: a hostile site name and domain stay text (no element made from them), marked for the translator to leave",
   (_lst301.get("tags"), _lst301.get("name"), _lst301.get("nameRaw"), _lst301.get("dom")),
   ([], _EVIL301, True, "<b>x</b>.example.org"))
eq("node: the card links to the site's page by number; a kind the page does not know reads 'Website', not a function",
   (_lst301.get("href"), _lst301.get("kind")), ("/m/websites/3", "Website"))
eq("node: an administrator's list says the ports are open and that a firewall that is off does not close them",
   (_lst301.get("portsShown"), _lst301.get("ports")),
   (True, "Public: ports 80 and 443 are open for 2 sites.Firewall is off: 80 and 443 are reachable regardless."))
eq("node: only an http(s) address becomes a link, and only a same-origin path a fix button (no javascript:, no //host)",
   _lst301.get("safe"), ["", "https://a.example/x", "", "/settings#outside"])

_cust_list301 = _ran301('customer list', _node301(_list_cq301, _COMMON301 + ["websites.js"], r"""
  return {portsShown: !$('ws-ports').hidden, quota: $('ws-quota').textContent, quotaShown: !$('ws-quota').hidden};
""", routes={"/api/websites": dict(_LIST301, quota={"used": 2, "max": 3})}))
eq("node: a customer is not told how many sites are online on the host, and sees their own quota",
   (_cust_list301.get("portsShown"), _cust_list301.get("quota"), _cust_list301.get("quotaShown")),
   (False, "2 of 3 websites used", True))

_MISSING301 = dict(_LIST301, missing=[{"key": "proxy", "text": "The web proxy is not installed on this host yet."}])
_MISS_SCN301 = r"""
  window.wsOpenAdd();
  const fix = $('ws-missing-fix');
  const b = fix.querySelector('button');
  return {shown: !$('ws-missing').hidden, text: $('ws-missing-text').textContent, fix: fix.textContent.trim(),
          action: b ? b.getAttribute('data-action') : null, create: !!$('ws-add-create'), disabled: $('ws-add-create').disabled,
          createInBody: !!$('ws-add-form').querySelector('#ws-add-create')};
"""
_miss_sa301 = _ran301('missing (superadmin)', _node301(_list_sa301, _COMMON301 + ["websites.js"], _MISS_SCN301, routes={"/api/websites": _MISSING301}))
_miss_cu301 = _ran301('missing (customer)', _node301(_list_cq301, _COMMON301 + ["websites.js"], _MISS_SCN301, routes={"/api/websites": _MISSING301}))
eq("node: a missing web proxy is the dialog's first line with ONE fix for a superadmin; Create stays, unavailable, "
   "in the footer outside the scrolling form",
   tuple(_miss_sa301.get(k) for k in ("shown", "text", "fix", "action", "create", "disabled", "createInBody")),
   (True, "The web proxy is not installed on this host yet.", "Install the web proxy", "wsProxyInstall", True, True, False))
eq("node: ...and anyone else is told to ask, with no button to press",
   tuple(_miss_cu301.get(k) for k in ("shown", "fix", "action", "create", "disabled")),
   (True, "Ask a superadmin to set this up.", None, True, True))

_INST_SCN301 = r"""
  window.wsOpenAdd();
  $('ws-kind-install').checked = true; window.wsKind('install'); window.wsPickApp('wordpress');
  $('ws-add-name').value = 'blog'; $('ws-add-domain').value = 'blog.example.org';
  $('ws-add-admin-user').value = 'boss'; $('ws-add-admin-email').value = 'boss@example.org';
  window.wsAddSubmit({preventDefault: function () {}});
  for (let i = 0; i < 8; i++) await tick();
  const post = calls.filter(function (c) { return c[0] === 'POST'; })[0];
  const labels = $('ws-progress').querySelectorAll('.ws-step-label');
  const code = $('ws-result').querySelector('code');
  return {post: post, labels: labels.map(function (l) { return [l.textContent, l.hasAttribute('data-no-i18n')]; }),
          polled: calls.filter(function (c) { return c[1] === '/m/websites/5/install'; }).length,
          result: $('ws-result').textContent, password: code ? code.textContent : null,
          formHidden: $('ws-add-form').hidden, footerHidden: $('ws-add-footer').hidden, passField: $('ws-add-admin-pass').value};
"""
_INST_ROUTES301 = {"/api/websites": _LIST301, "/websites/install-app": {"success": True, "id": 5}}
_FAILED301 = {"state": "failed", "step": "download", "error": "The download's checksum did not match.",
              "steps": [{"key": "account", "state": "undone"}, {"key": "download", "state": "failed"},
                        {"key": "fetch-<i>x</i>", "label": "<i>x</i>", "state": "pending"}]}
_inst301 = _ran301("install (failed)", _node301(_list_sa301, _COMMON301 + ["websites.js"], _INST_SCN301,
                                                routes=dict(_INST_ROUTES301, **{"/websites/5/install": _FAILED301})))
_done301 = _ran301("install (done)", _node301(_list_sa301, _COMMON301 + ["websites.js"], _INST_SCN301, routes=dict(
    _INST_ROUTES301, **{"/websites/5/install": {"state": "done", "step": "", "admin_password": "Gen-erated-0ne"}})))
_gone301 = _ran301("install (undone, site gone)", _node301(_list_sa301, _COMMON301 + ["websites.js"], _INST_SCN301,
                                                           routes=_INST_ROUTES301))
eq("node: Install an app posts the app, domain, host and admin account, an empty password so the panel makes one",
   _inst301.get("post"), ["POST", "/m/websites/install-app",
                          {"name": "blog", "domain": "blog.example.org", "remote_id": "1", "group_id": None, "app": "wordpress",
                           "admin_user": "boss", "admin_email": "boss@example.org", "admin_password": ""}])
eq("node: the progress view follows the install job, labels its steps in plain words, leaves a step it does not "
   "know as text, and says why the install failed",
   (_inst301.get("polled", 0) >= 1, _inst301.get("labels"), "checksum did not match" in (_inst301.get("result") or ""),
    _inst301.get("password")),
   (True, [["Create the site account", False], ["Download and check the app", False], ["<i>x</i>", True]], True, None))
eq("node: a finished install shows the generated password once, as text; the form and its Create button give way",
   (_done301.get("password"), "Done." in (_done301.get("result") or ""), _done301.get("formHidden"),
    _done301.get("footerHidden"), _done301.get("passField")), ("Gen-erated-0ne", True, True, True, ""))
check("node: an install whose site is gone (undone after a failure) reads as failed and undone, not as running",
      "every step done before it was undone" in (_gone301.get("result") or ""), _gone301.get("result"))

_INI_SCN301 = r"""
  const t = function (s) { return WS.iniProblems(s).map(function (p) { return [p.line, p.problem]; }); };
  return {ok: t('; a comment\nmemory_limit = 256M\nopcache.jit = tracing\n\nsession.cookie_secure=1'),
          bad: t('extension=/tmp/evil.so\nauto_prepend_file = /etc/passwd\n[PHP]\nnovalue\nEXPOSE_PHP = On\nallow_url_include=On\nok.key = \u0007'),
          big: t(new Array(8194).join('x')), proto: t('constructor = 1')};
"""
_ini301 = _ran301('php.ini', _node301(_site_cu301, _COMMON301, _INI_SCN301))
eq("node: the Advanced php.ini box takes key = value lines and comments",
   _ini301.get("ok"), [])
eq("node: ...and refuses loading an extension, a prepended file, managed keys (any case), sections, bare words, "
   "control characters, and more than 8192 characters",
   (_ini301.get("bad"), _ini301.get("big")),
   ([[1, "This setting is managed by the panel and cannot be set here."],
     [2, "This setting is managed by the panel and cannot be set here."],
     [3, "Sections are not used here: write key = value lines only."], [4, "Each line is key = value."],
     [5, "This setting is managed by the panel and cannot be set here."],
     [6, "This setting is managed by the panel and cannot be set here."],
     [7, "The value is too long or has control characters."]],
    [[0, "The box holds at most 8192 characters."]]))
eq("node: a key named like an object property is an ordinary setting, not a managed one", _ini301.get("proto"), [])

_PROXY_D301 = dict(_LIST301, proxies=[{"host_id": 1, "host_name": "h", "installed": True, "version": "2.10",
                                       "exposure_mode": "public", "allow_cidrs": [], "allow_presets": [],
                                       "tunnel_token_set": True}],
                   options={"hsts_max_age": 86400, "tls_min": "1.2", "require_2fa": False})
_exp301 = _ran301('exposure', _node301(_list_sa301, _COMMON301 + ["websites.js", "websites_proxy.js"], r"""
  const vis = function () { return [$('wp-restricted').hidden, $('wp-tunnel').hidden]; };
  const start = vis();
  $('wp-mode-restricted').checked = true; window.wsExposure('restricted'); const r = vis();
  window.wsCfPreset(); $('wp-cidrs').value = ' 203.0.113.0/24 \n\n2001:db8::/32 ';
  const rb = WS.exposureBody();
  $('wp-mode-restricted').checked = false; $('wp-mode-tunnel').checked = true; window.wsExposure('tunnel'); const tv = vis();
  const tb = WS.exposureBody();
  $('wp-token').value = 'tok-123'; const tb2 = WS.exposureBody();
  window.wsSaveExposure({preventDefault: function () {}});
  for (let i = 0; i < 4; i++) await tick();
  const sent = calls.filter(function (c) { return c[0] === 'POST'; }).map(function (c) { return c[2]; });
  return {start: start, r: r, rb: rb, tv: tv, tb: tb, tb2: tb2, sent: sent, tokenAfter: $('wp-token').value,
          saved: !$('wp-token-state').hidden,
          notes: [!$('wp-hsts-note').hidden, !$('wp-tls-note').hidden, !$('wp-2fa-note').hidden],
          summary: $('wp-mode-summary').textContent};
""", routes={"/api/websites": _PROXY_D301, "/websites/proxy/settings": {"success": True}}))
eq("node: exposure: Public shows neither list nor token; Restricted shows the allow list; Tunnel shows the token field",
   (_exp301.get("start"), _exp301.get("r"), _exp301.get("tv")), ([True, True], [False, True], [True, False]))
eq("node: Restricted sends the Cloudflare preset and the typed networks, trimmed, blank lines dropped",
   _exp301.get("rb"), {"exposure_mode": "restricted", "allow_presets": ["cloudflare"],
                       "allow_cidrs": ["203.0.113.0/24", "2001:db8::/32"]})
eq("node: Tunnel with nothing typed keeps the saved token (sends none); a typed one is sent once and the box emptied",
   (_exp301.get("tb"), _exp301.get("tb2"), _exp301.get("sent"), _exp301.get("tokenAfter"), _exp301.get("saved")),
   ({"exposure_mode": "tunnel", "tunnel_provider": "cloudflare"},
    {"exposure_mode": "tunnel", "tunnel_provider": "cloudflare", "tunnel_token": "tok-123"},
    [{"remote_id": 1, "exposure_mode": "tunnel", "tunnel_provider": "cloudflare", "tunnel_token": "tok-123"}],
    "", True))
eq("node: an HSTS max-age under two years, TLS 1.2 and 2FA off for customers each show OWASP's note (saved anyway)",
   (_exp301.get("notes"), _exp301.get("summary")), ([True, True, True], "How visitors reach your sites: Public"))

_pst301 = _ran301("proxy status", _node301(_list_sa301, _COMMON301 + ["websites.js", "websites_proxy.js"], r"""
  for (let i = 0; i < 6; i++) await tick();
  return {asked: calls.filter(function (c) { return c[1].indexOf('/websites/proxy/status') >= 0; }).map(function (c) { return c[1]; }),
          state: $('wp-state').textContent, install: !$('wp-install').hidden, mode: $('wp-mode-tunnel').checked,
          saved: !$('wp-token-state').hidden};
""", routes={"/api/websites": dict(_LIST301, hosts=[], sites=[dict(_LIST301["sites"][0], remote_id=4)]),
             "/websites/proxy/status": {"exposure_mode": "tunnel", "allow_cidrs": [], "allow_presets": [],
                                        "tunnel_token_set": True, "installed_version": "", "last_error": ""}}))
eq("node: with no proxy rows in the list, the card reads each host's GET /websites/proxy/status (the sites' host), "
   "and a host without the proxy offers Install, keeps its mode, and says a token is saved",
   (_pst301.get("asked"), _pst301.get("install"), _pst301.get("mode"), _pst301.get("saved"),
    (_pst301.get("state") or "").startswith("The web proxy is not installed")),
   (["/m/websites/proxy/status?remote_id=4"], True, True, True, True))

# The site's answer as the routes give it: the site's own fields flat, an administrator's limits among them,
# and the host's probe; each panel reads its own part.
_FLAT301 = {"id": 7, "name": "shop", "kind": "php", "state": "failed", "state_reason": "exited", "enabled": False,
            "domain": "x.example.org", "php_version": "8.4", "runtime": "", "app_recipe": "", "mem_mb": 512, "cpu_milli": 1000,
            "pids": 256, "disk_mb": 2048, "max_body_mb": 64, "remote_id": 1, "access_log": True, "full_egress": False,
            "backup_keep": 9, "customer_note": "n", "probe": {"ok": True, "facts": {"mem_mb": 100}}}
_FLAT_ROUTES301 = {
    "/api/websites/7": _FLAT301,
    "/websites/7/logs": {"success": True, "lines": "\n".join("l%d" % i for i in range(30)) + "\n"},
    "/websites/7/domains": {"domains": [{"domain": "x.example.org", "primary": True, "dns_state": "mismatch", "cert_state": "pending",
                                         "cert_error": "", "records": [{"type": "A", "value": "198.51.100.7"}]}]},
    "/websites/7/databases": {"databases": [{"id": 9, "name": "ws7_main", "user": "ws7_main", "host": "127.0.0.1", "port": 3306}],
                              "max": 5, "prefix": "ws7_"},
    "/websites/7/databases/9/reveal": {"success": True, "password": "db-pw"},
    "/websites/7/domains/check": {"success": True, "dns_state": "mismatch"},
    "/websites/7/php": {"version": "8.4", "versions": ["8.4", "8.3"], "advanced": "x.y = 1", "effective": {},
                        "values": {"memory_limit": "256M", "display_errors": "On", "opcache.memory_consumption": "128"}}}
_flat301 = _ran301("site page (route shapes)", _node301(_site_ad301, _COMMON301 + ["website_site.js", "website_tuning.js"], r"""
  for (let i = 0; i < 6; i++) await tick();
  const recs = $('wd-records').querySelectorAll('tr').map(function (tr) { return tr.children.map(function (td) { return td.textContent; }); });
  const check = $('wd-list').querySelector('button');
  window.wsDomain('check', JSON.parse(check.getAttribute('data-args'))[1]);
  window.wsDbReveal(9);
  for (let i = 0; i < 6; i++) await tick();
  const posts = calls.filter(function (c) { return c[0] === 'POST'; }).map(function (c) { return [c[1], c[2]]; });
  const body1 = WS.phpBody();
  $('wphp-version').value = '8.3';
  const body2 = WS.phpBody();
  return {log: $('ws-failed-log').textContent.split('\n').length, logLast: $('ws-failed-log').textContent.split('\n').pop(),
          recs: recs, posts: posts, conn: $('wdb-conn-9').textContent, mem: $('ws-mem').value, keep: $('wset-keep').value,
          body1: body1, v2: body2.php_version, opmem: $('wperf-op-mem').value, ini: $('wphp-ini').value,
          bodies: WS.settingsBodies()};
""", routes=_FLAT_ROUTES301))
eq("node: route shapes: a failed site's log (one text) shows its last 20 lines; the probe's memory and the limits fill "
   "the page", (_flat301.get("log"), _flat301.get("logLast"), _flat301.get("mem"), _flat301.get("keep")), (20, "l29", "100", "9"))
eq("node: route shapes: the records to create come from the domain's own list, and a domain is acted on by its name",
   (_flat301.get("recs"), (_flat301.get("posts") or [[None]])[0]),
   ([["A", "x.example.org", "198.51.100.7"]], ["/m/websites/7/domains/check", {"domain": "x.example.org"}]))
eq("node: route shapes: Show connection settings asks the reveal route and shows the row's host, port, name and user "
   "with the password", ((_flat301.get("posts") or [None, [None]])[1][0], _flat301.get("conn")),
   ("/m/websites/7/databases/9/reveal", "Host: 127.0.0.1Port: 3306Database: ws7_mainUser: ws7_mainPassword: db-pw"))
eq("node: route shapes: the PHP form posts each field by its php.ini name (display_errors as On), the version only "
   "when changed; OPcache's memory and the Advanced box come from the same answer",
   (_flat301.get("body1"), _flat301.get("v2"), _flat301.get("opmem"), _flat301.get("ini")),
   ({"memory_limit": "256M", "display_errors": "On"}, "8.3", "128", "x.y = 1"))
eq("node: route shapes: Settings sends the limits to /limits and backups-to-keep, the access log, the note and (a "
   "superadmin's page) full internet access to /settings",
   _flat301.get("bodies"), {"limits": {"mem_mb": 512, "cpu_milli": 1000, "pids": 256, "disk_mb": 2048, "max_body_mb": 64},
                            "settings": {"access_log": True, "customer_note": "n", "backup_keep": 9, "full_egress": False}})

_SITE_D301 = {"success": True, "site": {"id": 7, "name": "shop", "kind": "wordpress", "state": "failed",
                                        "state_reason": "<script>bad()</script>", "enabled": False,
                                        "open_url": "javascript:alert(1)", "limits": {"mem_mb": 512, "disk_mb": 2048}},
              "logs": ["l%d" % i for i in range(30)], "domains": [], "dns": {},
              "php": {"versions": [{"version": "8.4"}], "version": "8.4",
                      "settings": {"memory_limit": "256M", "upload_max_filesize": "1M", "display_errors": True}, "custom": ""},
              "app": {"versions": ["22"], "version": "22", "port": 3000, "env_names": ["DB_URL", "OLD"]}}
_site301 = _ran301('site page', _node301(_site_ad301, _COMMON301 + ["website_site.js", "website_tuning.js"], r"""
  const notes = WS.phpNotes();
  const env = $('wapp-env');
  return {main: [$('ws-main-label').textContent, $('ws-main').disabled], failed: !$('ws-failed').hidden,
          reason: $('ws-failed-reason').textContent, log: $('ws-failed-log').textContent.split('\n').length,
          open: $('ws-open').hidden, notes: notes, envRows: env ? env.children.length : -1};
""", routes={"/api/websites/7": _SITE_D301}))
eq("node: a failed site leads with its reason (as text), its last 20 log lines, and Retry as the main button",
   (_site301.get("main"), _site301.get("failed"), _site301.get("reason"), _site301.get("log")),
   (["Retry", False], True, "<script>bad()</script>", 20))
eq("node: a javascript: address from the server never becomes the Open site link", _site301.get("open"), True)
eq("node: memory_limit above OWASP's 50M and display_errors on each get a note; a value under the figure gets none",
   _site301.get("notes"), ["memory_limit is above OWASP's 50M. It is still saved.",
                           "display_errors is on: visitors can see error details. OWASP recommends Off. It is still saved."])

_APP_SITE301 = type("Site301b", (), {"id": 7, "name": "api", "kind": "app"})()
_app_page301 = _page301("website.html", P9_ADMIN, site=_APP_SITE301, can_manage=True, can_files=False, site_admin=False)
_env301 = _ran301('environment', _node301(_app_page301, _COMMON301 + ["website_site.js", "website_tuning.js"], r"""
  const rows = $('wapp-env').children;
  rows[0].querySelector('[data-env="value"]').value = '';
  rows[1].remove();
  window.wsEnvAdd();
  const added = $('wapp-env').lastChild;
  added.querySelector('[data-env="name"]').value = 'NEW_ONE'; added.querySelector('[data-env="value"]').value = 's3cret';
  return WS.envBody();
""", routes={"/api/websites/7": dict(_SITE_D301, site=dict(_SITE_D301["site"], kind="app", state="running"))}))
eq("node: env vars: a saved value left empty is kept (null), a removed saved one is dropped, a new one is sent",
   _env301, {"env": {"DB_URL": None, "NEW_ONE": "s3cret"}, "env_remove": ["OLD"]})


# ── 4. text and docs ──────────────────────────────────────────────────────────────────────────────
_tools301 = os.path.join(_ROOT301, "tools")
_path301, _mods301 = list(_sys301.path), set(_sys301.modules)
_sys301.path.insert(0, _tools301)
try:
    import i18n_scan as _scan301  # noqa: E402
finally:
    _sys301.path[:] = _path301
    for _m301 in set(_sys301.modules) - _mods301:
        del _sys301.modules[_m301]
_tdir301 = os.path.join(_ROOT301, "panel", "translations")
_mine301 = ("websites.html", "website.html", "websites_common.js", "websites.js", "websites_proxy.js", "website_site.js",
            "website_files.js", "website_tuning.js")
_gaps301 = {}
for _lang301 in ("es", "fr"):
    _gap301 = dict(_scan301.missing(_lang301, template_dir=os.path.join(_ROOT301, "panel", "templates"), translation_dir=_tdir301))
    _gap301.update(_scan301.missing_js(_lang301, js_dir=_JS301, translation_dir=_tdir301))
    _gaps301[_lang301] = sorted(k for k, files in _gap301.items()
                                if any(f.startswith("_website") or f in _mine301 for f in files))
eq("i18n: every string the Websites pages and scripts show is in the Spanish and the French catalog", _gaps301,
   {"es": [], "fr": []})


def _cat301(lang):
    with open(os.path.join(_tdir301, lang, "websites_ui.json"), encoding="utf-8") as fh:
        return _json301.load(fh)


_es301, _fr301 = _cat301("es"), _cat301("fr")
check("i18n: websites_ui.json has the same keys in both languages, every value translated (not empty)",
      set(_es301) == set(_fr301) and len(_es301) > 200 and all(_es301.values()) and all(_fr301.values()),
      repr(sorted(set(_es301) ^ set(_fr301))[:5]))


def _doc301(*parts):
    """A doc's text, or "" when it is missing (its checks then fail by name)."""
    path = os.path.join(_ROOT301, *parts)
    return _read301(path) if os.path.isfile(path) else ""


_wdoc301 = _doc301("docs", "websites.md")
eq("docs: the websites page covers exposure modes, PHP, caching, Node.js apps, one-click apps and no-outbound",
   tuple(w in _wdoc301 for w in ("Restricted", "Tunnel", "php.ini", "OPcache", "Node.js", "WordPress", "Drupal",
                                 "MyBB", "SMF", "outbound")), (True,) * 10)
eq("docs: linked from the README (docs/README.md), the features page and the HTTPS page",
   tuple("(websites.md)" in _doc301("docs", f) for f in ("README.md", "features.md", "https.md")), (True, True, True))
_perm301 = _doc301("docs", "permissions.md")
check("docs: permissions.md says edit_website_files amounts to running code in that site's container",
      bool(_re301.search(r"edit_website_files.{0,600}running code in that site's container", _perm301, _re301.S)),
      _perm301[_perm301.find("edit_website_files"):][:400])
