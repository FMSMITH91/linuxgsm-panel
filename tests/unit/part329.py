"""Part 329 of the unit suite: settings are never tucked away.

1. Every fold that holds a setting or a control that changes something starts open, panel-wide: the pages as their
   routes draw them (Websites and its web proxy card, a website's PHP and Rules, Settings, Updates, the dashboard,
   Account, Notifications), and a gate over every template so a new closed one cannot come back. Folds
   holding only read-outs (a log, a list, help text) may stay closed.
2. A viewer's own close of a fold is kept in their browser (js/fold_memory.js): restored on the next visit, forgotten
   when it matches the page's default, never recorded for a script's open, ignored when the address links into it,
   and the page draws its defaults when storage is refused.
3. A setting that does not apply is shown greyed with the reason, never removed: a site without PHP keeps OPcache and
   the object cache on its Performance tab, disabled, reading off, and never sent on Save.
5. The Blocked visitors label says on or off and how many settings, so a closed one still says what is inside.

HOW IT RUNS. part12's app and its database (tripwire armed): pages through their routes with the host's probe stood in;
fold_memory.js in node over a small DOM of this part's own; the website pages' scripts over part301's harness.
"""
import json as _json329
import os
import re as _re329
import shutil as _shutil329
import subprocess as _sp329  # nosec B404 - node on this part's own harness
import tempfile as _tf329

from flask import g as _g329

from unit.part01 import _root, check, eq, skip
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_restore_all
from unit.part47 import _cut47
from unit.part221 import _node221
from unit.part301 import _COMMON301, _node301, _page301
from panel.core import config as _cfg329
from panel.db.models import RemoteServer as _Remote329, Website as _Site329, db as _db329
from panel.routes import websites as _w329

_ROWS329 = {"sites": [], "remotes": []}


def _get329(path):
    _g329.pop("_login_user", None)
    return _p9_client(P9_ADMIN).get(path)


def _fold_tag329(page, name):
    """The opening <details ...> tag of the fold whose id or data-fold is `name` ("" when the page has none)."""
    m = _re329.search(r'<details\b[^>]*\b(?:id|data-fold)="%s"[^>]*>' % _re329.escape(name), page)
    return m.group(0) if m else ""


def _open329(page, name):
    tag = _fold_tag329(page, name)
    return bool(tag) and _re329.search(r"\sopen[\s>]", tag) is not None and 'data-fold="' in tag


# ── 1. the pages, as their routes draw them ──────────────────────────────────────────────────────────
_PAGE_FOLDS329 = (
    ("/websites", ("wc-box", "wp-mode-box", "wp-url-box", "wp-guard-box", "wp-opts-box")),
    ("/settings", ("sec-outside", "sec-schedules", "tls-change", "sftp-change")),
    ("/updates", ("upd-window",)),
    ("/", ("sec-tags",)),
    ("/account", ("acct-default-layout", "push-devices", "sftp-key-add")),
    ("/notifications", ("tg-commands", "dc-bot")),
)


def _s1_pages(st):
    for path, names in _PAGE_FOLDS329:
        r = _get329(path)
        page = r.get_data(as_text=True)
        eq("open folds: %s draws every fold that holds a setting open, each named for the viewer's own close (%s)"
           % (path, ", ".join(names)), (r.status_code, [n for n in names if not _open329(page, n)]), (200, []))
    site = _site329(st, "p329-shop", "wordpress", app_version="7.1.5", php_version="8.4")
    page = _get329("/websites/%d" % site.id).get_data(as_text=True)
    eq("open folds: a website's Advanced php.ini and Raw web proxy lines start open",
       [n for n in ("wphp-adv", "wr-raw-box") if not _open329(page, n)], [])
    page = _get329("/updates").get_data(as_text=True)
    eq("open folds: a read-out may stay closed (the Updates page's History, control)",
       (bool(_fold_tag329(page, "upd-history")), _open329(page, "upd-history")), (True, False))


# Folds that hold a control and stay closed on purpose, each a read-out or a per-row editor: (template, id or label).
_READOUTS329 = {
    ("_server_databases.html", "db-grant-box"): "statements to copy, read once",
    ("_website_overview.html", "ws-logs-box"): "the site's log lines, read when opened",
    ("_website_php.html", "wphp-eff"): "PHP's effective values, read when opened",
    ("remote_manage.html", "sec-rawlogs-card"): "raw logs: the buttons only pick which log to read",
    ("root_cron.html", "Edit or delete"): "one per job: an editor of the values its row already shows",
    ("server_files.html", "cron-help"): "help for writing a schedule (quick picks fill the field)",
    ("updates.html", "upd-history"): "the History list (its one button shows more of it)",
}
_TOK329 = _re329.compile(r'<details\b[^>]*>|</details>|\{%-?\s*call\b.*?%\}|\{%-?\s*endcall\s*-?%\}', _re329.S)
_CTL329 = _re329.compile(r'<(?:input|select|textarea|button)\b(?![^>]*type="hidden")|data-action=', _re329.I)


def _folds329(text):
    """[(head, body)] of every <details> and fold() call in a template's text."""
    out, stack = [], []
    for m in _TOK329.finditer(text):
        s = m.group(0)
        if s.startswith("<details") or (s.startswith("{%") and "endcall" not in s):
            stack.append(m)
            continue
        want = "<details" if s == "</details>" else "{%"
        for i in range(len(stack) - 1, -1, -1):
            if stack[i].group(0).startswith(want):
                start = stack.pop(i)
                if want == "<details" or "fold(" in start.group(0):
                    out.append((start.group(0), text[start.end():m.start()]))
                break
    return out


def _fold_name329(head, body):
    m = _re329.search(r'\bid=["\']([\w-]+)["\']', head)
    if m:
        return m.group(1)
    m = _re329.search(r"fold\('([^']*)'", head) or _re329.search(r'<summary[^>]*>\s*(?:\{%[^%]*%\})?([^<{]+)', body)
    return m.group(1).strip() if m else head


def _starts_open329(head):
    if head.startswith("<details"):
        return "{%" not in head and _re329.search(r"\sopen[\s>]", head) is not None and "data-fold=" in head
    return "open_=True" in head and "remember=" in head


def _s1_gate():
    tdir = os.path.join(_root, "panel", "templates")
    closed, readouts_seen = [], set()
    for name in sorted(os.listdir(tdir)):
        if not name.endswith(".html") or name == "_fold.html":
            continue
        with open(os.path.join(tdir, name), encoding="utf-8") as fh:
            text = fh.read()
        for head, body in _folds329(text):
            if not _CTL329.search(body) or _starts_open329(head):
                continue
            key = (name, _fold_name329(head, body))
            if key in _READOUTS329:
                readouts_seen.add(key)
            else:
                closed.append(key)
    eq("open folds (every template): no fold that holds a setting or a control starts closed, or opens only "
       "sometimes, outside the listed read-outs", closed, [])
    eq("open folds: each listed read-out still exists (a stale entry would hide a new closed fold of the same name)",
       sorted(set(_READOUTS329) - readouts_seen), [])


# ── 2. a viewer's own close is kept (js/fold_memory.js, in node) ─────────────────────────────────────
_HARNESS329 = r"""'use strict';
const fs = require('fs'), vm = require('vm');
const cfg = JSON.parse(fs.readFileSync(0, 'utf8'));
function El(tag, attrs, kids) { this.tagName = tag.toUpperCase(); this.attrs = attrs || {}; this.children = [];
  this.parentNode = null; (kids || []).forEach(k => { k.parentNode = this; this.children.push(k); }); }
Object.defineProperty(El.prototype, 'open', {get() { return 'open' in this.attrs; },
  set(v) { if (v) this.attrs.open = ''; else delete this.attrs.open; }});
El.prototype.getAttribute = function (k) { return k in this.attrs ? this.attrs[k] : null; };
El.prototype.setAttribute = function (k, v) { this.attrs[k] = String(v); };
El.prototype.hasAttribute = function (k) { return k in this.attrs; };
El.prototype.contains = function (o) { for (let e = o; e; e = e.parentNode) if (e === this) return true; return false; };
El.prototype.closest = function (t) { for (let e = this; e; e = e.parentNode) if (e.tagName === t.toUpperCase()) return e; return null; };
function walk(e, f) { e.children.forEach(c => { f(c); walk(c, f); }); }
El.prototype.querySelectorAll = function (sel) { const out = [];
  walk(this, c => { if (sel === 'details[data-fold]' ? c.tagName === 'DETAILS' && c.hasAttribute('data-fold')
                                                     : c.tagName === sel.toUpperCase()) out.push(c); }); return out; };
El.prototype.querySelector = function (sel) { return this.querySelectorAll(sel)[0] || null; };
function page() {
  return new El('body', {}, [
    new El('details', {id: 'f-set', 'data-fold': 'f-set', open: ''}, [new El('summary', {}, []), new El('input', {id: 'in-set'}, [])]),
    new El('details', {id: 'f-help'}, [new El('summary', {}, [])]),
    new El('details', {id: 'f-closed', 'data-fold': 'f-closed'}, [new El('summary', {}, [])])]);
}
const store = {}, out = {};
let refuse = false;
const localStorage = {getItem(k) { if (refuse) throw new Error('refused'); return k in store ? store[k] : null; },
  setItem(k, v) { if (refuse) throw new Error('refused'); store[k] = String(v); },
  removeItem(k) { if (refuse) throw new Error('refused'); delete store[k]; }};
function load(hash) {
  const body = page(), listeners = [];
  const document = {getElementById(id) { let f = null; walk(body, c => { if (!f && c.attrs.id === id) f = c; }); return f; },
    querySelectorAll(s) { return body.querySelectorAll(s); }, addEventListener(k, fn) { if (k === 'click') listeners.push(fn); }};
  const ctx = {document, location: {hash: hash || ''}, decodeURIComponent, setTimeout(fn) { fn(); return 0; }, String};
  ctx.window = ctx; ctx.window.localStorage = localStorage;
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(cfg.script, 'utf8'), ctx);
  return {body, document, ctx, click(id) {      // a tap on the summary: listeners first, then the browser's toggle
    const d = document.getElementById(id), sum = d.children[0];
    listeners.forEach(fn => fn({target: sum}));
    d.open = !d.open; }};
}
// setTimeout runs at once here, before the toggle: defer the listener's read until after it, as the browser does.
function loadDeferred(hash) {
  const p = load(hash), q = [];
  p.ctx.setTimeout = function (fn) { q.push(fn); return 0; };
  const click = p.click; p.click = function (id) { click(id); q.splice(0).forEach(fn => fn()); };
  return p;
}
let p = loadDeferred();
out.drawn = [p.document.getElementById('f-set').open, p.document.getElementById('f-closed').open];
p.click('f-set');
out.stored = Object.assign({}, store);
p = loadDeferred();
out.restored = p.document.getElementById('f-set').open;
p.click('f-set');
out.forgotten = Object.assign({}, store);
p = loadDeferred();
p.click('f-help');
out.unnamed = Object.assign({}, store);
p.document.getElementById('f-closed').open = true;
out.scripted = Object.assign({}, store);
p.click('f-set');
p = loadDeferred('#in-set');
out.linked = p.document.getElementById('f-set').open;
refuse = true;
let threw = '', openAfter = null;
try { p = loadDeferred(); p.click('f-set'); openAfter = load().document.getElementById('f-set').open; }
catch (e) { threw = String(e).split('\n')[0]; }
out.refused = {threw, open: openAfter};
process.stdout.write(JSON.stringify(out));
"""


def _node329(name):
    node = _shutil329.which("node")
    if not node:
        skip(name, "node is not installed here")
        return None
    tmp = _tf329.mkdtemp(prefix="p329-")
    try:
        path = os.path.join(tmp, "harness.js")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_HARNESS329)
        cfg = {"script": os.path.join(_root, "panel", "static", "js", "fold_memory.js")}
        r = _sp329.run([node, path], input=_json329.dumps(cfg),  # nosec B603 - node on this part's harness
                       capture_output=True, text=True, timeout=60, check=False)
        try:
            return _json329.loads(r.stdout)
        except ValueError:
            return {"error": (r.stdout + r.stderr)[-1200:]}
    finally:
        _shutil329.rmtree(tmp, ignore_errors=True)


def _s2_memory():
    got = _node329("fold memory: the node harness")
    if got is None:
        return
    check("fold memory: the node harness ran", "error" not in got, got.get("error"))
    eq("fold memory: with nothing kept, each fold is drawn as the page draws it (control)", got.get("drawn"), [True, False])
    eq("fold memory: a viewer's close of an open settings fold is kept in their browser", got.get("stored"),
       {"uis.fold.f-set": "0"})
    eq("fold memory: ...and the next visit draws that fold closed", got.get("restored"), False)
    eq("fold memory: opening it again matches the page's default, so the kept choice is forgotten", got.get("forgotten"), {})
    eq("fold memory: a fold without a name (help text) keeps nothing", got.get("unnamed"), {})
    eq("fold memory: a script opening a fold is never recorded as the viewer's choice", got.get("scripted"), {})
    eq("fold memory: a link to a setting inside a fold the viewer closed draws it open", got.get("linked"), True)
    eq("fold memory: with storage refused the page draws its defaults and nothing throws",
       got.get("refused"), {"threw": "", "open": True})


def _s2_wiring():
    with open(os.path.join(_root, "panel", "templates", "base.html"), encoding="utf-8") as fh:
        base = fh.read()
    with open(os.path.join(_root, "panel", "static", "js", "panel.js"), encoding="utf-8") as fh:
        js = fh.read()
    at, panel = base.find("js/fold_memory.js"), base.find("js/panel.js")
    eq("fold memory: base.html loads fold_memory.js at the end of <body>, before panel.js, so a closed fold is closed "
       "before the first paint; a section swapped in from the server is put back as the viewer left it",
       (0 < at < panel, base.find("</main>") < at, "window.restoreFolds(cur)" in js[js.find("function _sectionSwapped"):]),
       (True, True, True))


# ── 3. a setting that does not apply is greyed, not removed ──────────────────────────────────────────
def _site329(st, name, kind, **kw):
    s = _Site329(remote_id=st["remote"], name=name, kind=kind, state="running", enabled=True,
                 proxy_secret=_cfg329.encrypt_secret("p" * 40), **kw)
    _db329.session.add(s)
    _db329.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    _db329.session.commit()
    _ROWS329["sites"].append(s.id)
    return s


def _fieldset329(page):
    m = _re329.search(r'<fieldset id="wperf-php"[^>]*>', page)
    return m.group(0) if m else ""


def _s3_perf_pages(st):
    static = _site329(st, "p329-docs", "static")
    php = _site329(st, "p329-blog", "php", php_version="8.4")
    sp = _get329("/websites/%d" % static.id).get_data(as_text=True)
    pp = _get329("/websites/%d" % php.id).get_data(as_text=True)
    eq("greyed, not removed: a site without PHP keeps OPcache and the object cache on its Performance tab, in a "
       "disabled fieldset with the reason",
       ("disabled" in _fieldset329(sp), 'id="wperf-opcache"' in sp, 'id="wperf-obj"' in sp,
        "Only for PHP sites: this website runs no PHP." in sp), (True, True, True, True))
    eq("greyed, not removed: a PHP site's caches are live, with no reason line (control)",
       (bool(_fieldset329(pp)), "disabled" in _fieldset329(pp), "Only for PHP sites" in pp), (True, False, False))


_PERF329 = r"""
  for (let i = 0; i < 4; i++) await tick();
  window.wsTab('performance');
  window.wsPerfSave();
  for (let i = 0; i < 4; i++) await tick();
  const post = calls.filter(function (c) { return c[0] === 'POST' && c[1].indexOf('/performance') >= 0; })[0];
  return {op: $('wperf-opcache').checked, body: post ? post[2] : null};
"""


def _perf_answer329(kind):
    perf = {"opcache": True, "opcache_memory_mb": 128, "opcache_revalidate_s": 2, "object_cache": False,
            "page_cache": False, "page_cache_ttl": 300, "static_cache": True, "page_cache_ready": True, "page_cache_why": ""}
    return {"success": True, "site": {"id": 7, "name": "docs", "kind": kind, "state": "running"}, "domains": [],
            "perf": perf, "rules": []}


def _s3_perf_save():
    site = type("Site329", (), {"id": 7, "name": "docs", "kind": "static"})()
    page = _page301("website.html", P9_ADMIN, site=site, can_manage=True, can_files=False, site_admin=True)
    got = _node301(page, _COMMON301 + ["website_site.js", "website_tuning.js"], _PERF329,
                   routes={"/api/websites/7": _perf_answer329("static")})
    body = got.get("body") or {}
    eq("greyed, not removed: on a site without PHP the greyed OPcache reads off and Save sends neither PHP cache",
       (got.get("error"), got.get("op"), "opcache" in body, "object_cache" in body, "page_cache" in body),
       (None, False, False, False, True))
    site.kind = "php"
    page = _page301("website.html", P9_ADMIN, site=site, can_manage=True, can_files=False, site_admin=True)
    got = _node301(page, _COMMON301 + ["website_site.js", "website_tuning.js"], _PERF329,
                   routes={"/api/websites/7": _perf_answer329("php")})
    body = got.get("body") or {}
    eq("greyed, not removed: a PHP site's Save sends OPcache and the object cache as set (control)",
       (got.get("op"), body.get("opcache"), body.get("object_cache")), (True, True, False))


# ── 4. the Overview's software line ──────────────────────────────────────────────────────────────────


# ── 5. links to the host-wide settings; a closed fold's label ────────────────────────────────────────


_GUARD329 = r"""
  for (let i = 0; i < 6; i++) await tick();
  return {sum: $('wp-guard-sum').textContent};
"""


def _s5_guard_label():
    from unit.part301 import _LIST301, _list_sa301
    sums = []
    for enabled in (True, False):
        answer = dict(_LIST301, proxies=[{"host_id": 1, "host_name": "h", "installed": True, "version": "2.11.9",
                                          "exposure_mode": "public", "allow_cidrs": [], "allow_presets": [],
                                          "guard": {"enabled": enabled}}], options={})
        got = _node301(_list_sa301, _COMMON301 + ["websites.js", "websites_proxy.js"], _GUARD329,
                       routes={"/api/websites": answer})
        sums.append(got.get("sum") or got.get("error"))
    eq("labels: Blocked visitors says on or off and how many settings, so a closed one still says what is inside",
       sums, ["Blocked visitors: on, 8 settings", "Blocked visitors: off, 8 settings"])


def _s1_b3_fold():
    with open(os.path.join(_root, "panel", "static", "js", "server_addons.js"), encoding="utf-8") as fh:
        src = fh.read()
    prog = ("var folds = [], restored = [];\n"
            "var window = {restoreFolds: function (r) { restored.push(r.tag); }};\n"
            "function node(t) { var n = {tag: t, attrs: {}, appendChild: function () {}, insertBefore: function () {},"
            " lastChild: null, setAttribute: function (k, v) { this.attrs[k] = v; }};"
            " if (t === 'details') folds.push(n); return n; }\n"
            "function button() { return {}; } function T(s) { return s; } function geoSelect() { return node('div'); }\n"
            "function ownPlugins() {}\n"
            + _cut47(src, "function settingsFold(") + "\n"
            "var box = node('div'); box.tag = 'box';\n"
            "settingsFold({id: 'b3', update: ''}, box, node('div'));\n"
            "console.log(JSON.stringify({open: folds[0].open === true, name: folds[0].attrs['data-fold'] || null,"
            " restored: restored}));\n")
    got = _node221("open folds: the add-ons card's B3 settings", prog)
    if got is not None:
        eq("open folds: an add-on's B3 settings are drawn open, named for the viewer's own close, and put back as the "
           "viewer left them each time the card is drawn", got, {"open": True, "name": "ad-b3-settings", "restored": ["box"]})


def _ran329(step, *args):
    import traceback
    try:
        step(*args)
        return ""
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db329.session.rollback()
        return traceback.format_exc()[-1500:]


_trips329 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part329")
        _r329 = _Remote329(name="p329-host", host="127.0.0.1", port=22, username="u", auth_method="key",
                           auth_credential="", is_local=False, public_ip="198.51.100.29")
        _db329.session.add(_r329)
        _db329.session.commit()
        _ROWS329["remotes"].append(_r329.id)
        _st329 = {"remote": _r329.id}
        _plain329 = (_s1_gate, _s1_b3_fold, _s2_memory, _s2_wiring, _s3_perf_save, _s5_guard_label)
        for _sec329, _args329 in ([(s, (_st329,)) for s in (_s1_pages, _s3_perf_pages)]
                                  + [(s, ()) for s in _plain329]):
            _err329 = _ran329(_sec329, *_args329)
            check("part329: %s ran to the end" % _sec329.__name__, not _err329, _err329)
        eq("part329: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips329:], [])
    finally:
        _p9_restore_all()
        _w329._STATUS.clear()
        _db329.session.rollback()
        for _sid329 in _ROWS329["sites"]:
            _row329 = _db329.session.get(_Site329, _sid329)
            if _row329 is not None:
                _db329.session.delete(_row329)
        for _rid329 in _ROWS329["remotes"]:
            _row329 = _db329.session.get(_Remote329, _rid329)
            if _row329 is not None:
                _db329.session.delete(_row329)
        _db329.session.commit()
