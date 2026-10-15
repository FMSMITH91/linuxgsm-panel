"""Part 84 of the unit suite: the eleventh review's routes, tools, page and i18n fixes (builder C).

Held here, each against the code path the finding named:

* the i18n gates: a lambda whose parameter's default carries the enclosing message
  (`lambda msg=msg: flash(msg)`), and t() rendered where the translator skips with no key named
  for a live switch (templates and scripts).
* pages: a same-folder refresh the host did not answer while a rename is open, a language save
  that never answers, a live switch re-rendering a guarded placeholder and the security log's notes.
* the panel host's label "Panel Server" in the viewer's language on every page that names it, in a
  sentence the server words around it, and in the OS-updates banner.
* the panel host's OS-update reads are superadmin-only, as its OS-update actions are.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on this part's own fixtures.
"""
import html as _html84
import importlib.util as _ilu84
import json as _json84
import os
import re as _re84
import shutil as _shutil84
import tempfile as _tf84
import time as _time84

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _SETTLE47, _cut47, _node47
from unit.part72 import _DOM72
from unit.part12 import (P9_ADMIN, P9_HOST, P9_LOCAL, _P9_TRIPPED, _p9, _p9_arm, _p9_client,
                         _p9_delete_server, _p9_json, _p9_new_server, _p9_patch, _p9_restore_all)
from panel.core import i18n as _i18n84
from panel.core import panel_state as _ps84
from panel.db.models import (Group as _G84, RemoteServer as _RS84, User as _U84, db as _db84)
from panel.ops import system_ops as _so84
from panel.routes import remote_vps as _rv84
from panel.security import auth as _auth84
from panel.services import reboot_words as _rw84

_TRIP84_START = len(_P9_TRIPPED)
_spec84 = _ilu84.spec_from_file_location("i18n_scan_p84", os.path.join(_root, "tools", "i18n_scan.py"))
_scan84 = _ilu84.module_from_spec(_spec84)
_spec84.loader.exec_module(_scan84)
_ES84, _FR84 = _scan84.load_catalog("es"), _scan84.load_catalog("fr")


def _read84(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _node84(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _cut_or84(src, head):
    """_cut47's statement, or a comment naming it, so the check that runs it fails BY NAME."""
    return _cut47(src, head) if head in src else "/* MISSING %s */" % head


def _line84(src, head):
    """The one line of `src` that starts at `head` (a `var …;` declaration), or a comment naming it."""
    i = src.find(head)
    return src[i:src.index("\n", i)] if i >= 0 else "/* MISSING %s */" % head


def _lang84(lang):
    with _p9.app_context():
        _db84.session.get(_U84, P9_ADMIN).language = lang
        _db84.session.commit()


# The account's language as this part found it, put back after each block that switches it.
with _p9.app_context():
    _LANG84_WAS = _db84.session.get(_U84, P9_ADMIN).language


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A lambda parameter's default is the enclosing message, and the gates read it
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #429's _r20c_lambda_view renamed every use of a lambda's parameter out of reach, a defaulted one
# too: `lambda msg=msg: flash(msg)` flashes the enclosing built `msg`, and `lambda text=text:
# jsonify(text)` makes its function a wrapper. Both passed spliced_py.
_td84 = os.path.realpath(_tf84.mkdtemp(prefix="lgsm-unit-p84-"))
try:
    os.makedirs(os.path.join(_td84, "panel", "routes"))
    with open(os.path.join(_td84, "app.py"), "w") as _fh84:
        _fh84.write("")
    with open(os.path.join(_td84, "panel", "routes", "r.py"), "w") as _fh84:
        _fh84.write(
            "def route_a(y):\n"
            "    msg = f'Built for {y}'\n"
            "    return later(lambda msg=msg: flash(msg))\n"
            "def _reply(text):\n"
            "    return later(lambda text=text: jsonify({'message': text}))\n"
            "def route_c(y):\n"
            "    return _reply(f'Also built {y}')\n"
            # A lambda inside it that names the parameter again is its own: not the default.
            "def route_d(y):\n"
            "    msg = f'Built {y}'\n"
            "    return later(lambda msg=msg: later(lambda msg: flash(msg)))\n"
            "def route_e(y, cb=None):\n"
            "    return later(lambda *, note=f'Kw built {y}': flash(note))\n")
    _wr84 = sorted(_scan84._py_wrappers(_scan84._py_trees(_td84)))
    _spl84 = sorted((f, line) for f, line, _w in _scan84.spliced_py(root=_td84))
finally:
    _shutil84.rmtree(_td84, ignore_errors=True)
_rf84 = os.path.join("panel", "routes", "r.py")
check("i18n gate: a lambda whose parameter's default is the enclosing built message "
      "(lambda msg=msg: flash(msg), and a keyword-only default) has that message reported by "
      "spliced_py (it passed: the use was renamed away from its default)",
      (_rf84, 3) in _spl84 and (_rf84, 12) in _spl84, repr(_spl84))
check("i18n gate: ...and lambda text=text: jsonify(text) makes its function a wrapper, so the message "
      "built for it is reported; an inner lambda's own parameter of the same name is not the default",
      "_reply" in _wr84 and (_rf84, 7) in _spl84 and (_rf84, 10) not in _spl84, repr((_wr84, _spl84)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. t() rendered where the translator skips names its key for a live switch
# ════════════════════════════════════════════════════════════════════════════════════════════════
# guarded_attrs read literal text only, so a placeholder="{{ … or t('value') }}" on a data-no-i18n
# input and a <code>{{ … or t('this host') }}</code> passed it; the script side wrote
# t('Enter SSH password') into a guarded field. Each stayed in the old language after a switch.
_td84 = os.path.realpath(_tf84.mkdtemp(prefix="lgsm-unit-p84-"))
try:
    os.makedirs(os.path.join(_td84, "tpl"))
    os.makedirs(os.path.join(_td84, "js"))
    with open(os.path.join(_td84, "tpl", "a.html"), "w") as _fh84:
        _fh84.write(
            '<input data-no-i18n placeholder="{{ c.label or t(\'value\') }}">\n'
            '<code>{{ r.host or t(\'this host\') }}</code>\n'
            '<div data-no-i18n><span title="{{ t(\'Click to copy\') }}">x</span></div>\n'
            # Named for setLang, or outside the skip: not reported.
            '<input data-no-i18n placeholder="{{ t(\'value\') }}" data-i18n-placeholder="value">\n'
            '<pre data-i18n-text="Loading…">{{ t(\'Loading…\') }}</pre>\n'
            '<span title="{{ t(\'Click to copy\') }}">{{ t(\'value\') }}</span>\n'
            '<code>{{ r.host }}</code>\n'
            '<input id="cred" data-no-i18n>\n')
    with open(os.path.join(_td84, "js", "a.js"), "w") as _fh84:
        _fh84.write(
            "function a(){ var input = document.getElementById('cred');\n"
            "  input.placeholder = t('Enter SSH password'); }\n"
            "function b(){ var inp = document.getElementById('cred');\n"
            "  inp.setAttribute('data-i18n-placeholder', 'Enter SSH password');\n"
            "  inp.placeholder = t('Enter SSH password'); }\n")
    _gt84 = _scan84.guarded_tcalls(template_dir=os.path.join(_td84, "tpl"))
    _gw84 = _scan84.guarded_tcall_writes(js_dir=os.path.join(_td84, "js"),
                                         template_dir=os.path.join(_td84, "tpl"))
finally:
    _shutil84.rmtree(_td84, ignore_errors=True)
check("i18n gate: a t() call in a skipped placeholder, a <code>'s text or a title inside a guard is "
      "reported unless the element names its key (data-i18n-placeholder / -text) — guarded_attrs "
      "read literals only",
      _gt84 == [("a.html", "@placeholder", "input"), ("a.html", "text", "code"), ("a.html", "@title", "span")],
      repr(_gt84))
check("i18n gate: ...a script's t() write into a guarded field is reported unless it names the key "
      "with setAttribute('data-i18n-placeholder', …)",
      [(f, ln) for f, ln, _w in _gw84] == [("a.js", 2)], repr(_gw84))
check("i18n gate: the templates and scripts have none (a custom command's \"value\", the local "
      "firewall's \"this host\", the credential field's placeholders)",
      _scan84.guarded_tcalls() == [] and _scan84.guarded_tcall_writes() == [],
      repr((_scan84.guarded_tcalls(), _scan84.guarded_tcall_writes())))

# setLang renders a data-i18n-placeholder again; the security log's notes are named, the log is not.
_PKEYS84 = ("value", "Loading…", "(log is empty)", "Could not read the log.")
_live_prog84 = _DOM72 + (
    "const ES = %s, FR = %s;\n"
    "const all = (n, out) => { (n.childNodes || []).forEach(c => { if (c.nodeType === 1) { out.push(c); all(c, out); } });"
    " return out; };\n"
    "document.querySelectorAll = sel => all(document.body, []).filter(e => e.hasAttribute(sel.slice(1, -1)));\n"
    "window.LANG = 'es'; window.I18N = ES;\n"
    "require('vm').runInThisContext(%s);\n"
    "E72.prototype.removeAttribute = function(k){ delete this.attrs[k]; };\n"
    "const b = document.body, mk = (tag, attrs) => { const e = b.appendChild(document.createElement(tag));\n"
    "  Object.keys(attrs).forEach(k => e.setAttribute(k, attrs[k])); return e; };\n"
    "const arg = mk('input', {'data-no-i18n': '', placeholder: ES['value'], 'data-i18n-placeholder': 'value'});\n"
    "const own = mk('input', {'data-no-i18n': '', placeholder: 'Map'});\n"
    "window.setLang('fr', FR); const ph = [arg.getAttribute('placeholder'), own.getAttribute('placeholder')];\n"
    "const pre = mk('pre', {}); document.getElementById = id => id === 'sec-log' ? pre : null;\n"
    "let answer; global.MOUNT = ''; global.secBase = () => '/x';\n"
    "global.fetch = () => Promise.resolve({json: () => Promise.resolve(answer)});\n"
    "%s\n%s\n"
    "const run = async a => { answer = a; loadSecurityLog('ssh'); await settle(); window.setLang('es', ES);"
    " const r = pre.textContent; window.setLang('fr', FR); return r; };\n"
    "(async () => {\n"
    "  const empty = await run({text: ''}); const emptyFr = pre.textContent;\n"
    "  const failed = await run({error: 'x'}); const failedFr = pre.textContent;\n"
    "  const log = await run({text: 'sshd: Accepted publickey'}); const logFr = pre.textContent;\n"
    "  console.log(JSON.stringify({ph, empty, emptyFr, failed, failedFr, log, logFr}));\n"
    "})();\n"
) % (_json84.dumps({k: _ES84[k] for k in _PKEYS84}), _json84.dumps({k: _FR84[k] for k in _PKEYS84}),
     _json84.dumps(_read84("static", "js", "i18n.js")),
     _SETTLE47.replace("const settle", "global.settle"),
     _cut_or84(_read84("static", "js", "remote_manage.js"), "function loadSecurityLog(") + "\n"
     + _cut_or84(_read84("static", "js", "remote_manage.js"), "function _r21cLogNote("))
_live84 = _node84("i18n.js: data-i18n-placeholder and the security log's notes", _live_prog84)
if _live84 is not None:
    check("i18n.js: a live switch re-renders a guarded field's placeholder named in "
          "data-i18n-placeholder (a custom command's \"value\" stayed Spanish); a command author's own "
          "placeholder is untouched",
          _live84.get("ph") == [_FR84["value"], "Map"], repr(_live84))
    check("security log: \"(log is empty)\" and \"Could not read the log.\" follow a live switch (they "
          "stayed in the first language); a log that arrived is never overwritten",
          _live84.get("empty") == _ES84["(log is empty)"] and _live84.get("emptyFr") == _FR84["(log is empty)"]
          and _live84.get("failed") == _ES84["Could not read the log."]
          and _live84.get("failedFr") == _FR84["Could not read the log."]
          and _live84.get("log") == _live84.get("logFr") == "sshd: Accepted publickey", repr(_live84))

# The Add form's credential field: the password placeholder is named, a key path is not.
_cred_prog84 = (
    "global.window = global; global.t = s => 'T:' + s;\n"
    "const input = {attrs: {}, setAttribute(k, v){ this.attrs[k] = v; }, removeAttribute(k){ delete this.attrs[k]; }};\n"
    "const form = {querySelector: () => input}, els = {'credential-group': {style: {}}, 'cred-label': {}};\n"
    "global.document = {getElementById: id => els[id] || null};\n"
    "%s\n"
    "toggleCreds({value: 'password', closest: () => form});\n"
    "const pw = [input.placeholder, input.attrs['data-i18n-placeholder']];\n"
    "toggleCreds({value: 'key', closest: () => form});\n"
    "const key = [input.placeholder, input.attrs['data-i18n-placeholder'] || null];\n"
    "toggleCreds({value: 'password', closest: () => form}); toggleCreds({value: 'tailscale', closest: () => form});\n"
    "const ts = input.attrs['data-i18n-placeholder'] || null;\n"
    "console.log(JSON.stringify({pw, key, ts}));\n") % _cut_or84(_read84("static", "js", "manage_remotes.js"),
                                                                 "function toggleCreds(")
_cred84 = _node84("manage_remotes.js: the credential field's placeholder key", _cred_prog84)
if _cred84 is not None:
    check("Remote Servers: choosing Password names \"Enter SSH password\" for a live switch; a key path "
          "or Tailscale takes the name off (a switch would have written the sentence over the path)",
          _cred84 == {"pw": ["T:Enter SSH password", "Enter SSH password"], "key": ["~/.ssh/id_rsa", None],
                      "ts": None}, repr(_cred84))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A same-folder refresh the host did not answer keeps a half-typed rename
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #429 kept an open field through a refresh that answered {error}; the Tailscale and local
# transports answer a host that did not reply as {entries: [], unreadable: true}, no error, so the
# rename box and its text were still thrown away.
_SF84 = _read84("static", "js", "server_files.js")
_br_prog84 = (
    _SETTLE47 + "global.window = global; global.MOUNT = ''; global.serverId = 1; const toasts = [];\n"
    "window.toast = (m, k) => toasts.push([m, k]); global.esc = s => s; global.t = s => 'T:' + s;\n"
    "const list = {innerHTML: 'LISTED', insertAdjacentHTML(p, h){ this.innerHTML += h; }, appendChild(){},\n"
    "  querySelector(){ return null; }, insertBefore(){}, firstChild: null};\n"
    "global.document = {getElementById: id => id === 'file-list' ? list : null, activeElement: null};\n"
    "let answer; global.fetch = () => Promise.resolve({json: () => Promise.resolve(answer)});\n"
    "let curDir = 'cfg', curFile = null, _creating = null, _renaming = null;\n"
    "function renderBreadcrumb(){} function mkRow(){ return {}; }\n"
    "%s\n%s\n%s\n%s\n%s\n%s\n%s\n"
    "(async () => {\n"
    "  answer = {entries: [], unreadable: true};\n"
    "  _renaming = {path: 'cfg/server.cfg', input: {}}; browse('cfg'); await settle();\n"
    "  const open = {list: list.innerHTML, kept: _renaming !== null, toasts: toasts.slice()};\n"
    "  _renaming = null; browse('cfg'); await settle();\n"
    "  const none = list.innerHTML.indexOf('Could not read this folder') >= 0;\n"
    "  list.innerHTML = 'LISTED'; answer = {entries: [{name: 'a.cfg', size: 1}], unreadable: false};\n"
    "  _renaming = {path: 'cfg/a', input: {}}; browse('cfg'); await settle();\n"
    "  console.log(JSON.stringify({open, none, fine: list.innerHTML, toasts}));\n"
    "})();\n") % (_line84(_SF84, "var _browseSeq"), _line84(_SF84, "var _browseWant"),
                  _cut_or84(_SF84, "function browse("), _cut_or84(_SF84, "function _r14c_openEditors("),
                  _cut_or84(_SF84, "function _r14c_restoreEditors("),
                  _cut_or84(_SF84, "function _r20cKeptOnError("), _cut_or84(_SF84, "function _r20cEmptyNote("))
_br84 = _node84("server_files.js: an unanswered same-folder refresh with a rename open", _br_prog84)
_UNREAD84 = "Could not read this folder — the host did not answer. This is not the same as it being empty."
if _br84 is not None:
    check("file browser: a same-folder refresh the host did not answer ({unreadable: true}, no error: "
          "Tailscale and the panel host) keeps the list and the open rename, and says why in the "
          "viewer's language (the rename and its text were thrown away)",
          _br84.get("open") == {"list": "LISTED", "kept": True, "toasts": [["T:" + _UNREAD84, "danger"]]},
          repr(_br84))
    check("file browser: ...with no field open the note replaces the list as before, and a refresh "
          "that answered is not a failure (controls)",
          _br84.get("none") is True and _br84.get("fine") == "" and len(_br84.get("toasts") or []) == 1,
          repr(_br84))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. A language save that never answers does not hold the next one forever
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Saves are chained so the server's last write is the last pick (#429); a save on a stalled
# connection (fetch has no timeout) held every later save behind it for the life of the page.
_PJ84 = _read84("static", "js", "panel.js")
_HANDLER84 = ("document.addEventListener('change', function(e){\n  var el = e.target;\n"
              "  if (!el || !el.matches || !el.matches('select[data-lang-select]')")
_lang_prog84 = (
    _SETTLE47 + "global.window = global; global.MOUNT = '';\n"
    "const handlers = [], pickers = [{value: 'en'}], posts = [], timers = [];\n"
    "global.setTimeout = (f, ms) => { timers.push([f, ms]); return timers.length; }; global.clearTimeout = () => {};\n"
    "global.document = {addEventListener: (t, f) => handlers.push(f), querySelectorAll: () => pickers};\n"
    # A POST that never answers, unless its signal aborts it; the catalog answers at once.
    "global.fetch = (url, opts) => {\n"
    "  if (!(opts && opts.method === 'POST')) return Promise.resolve({json: () => Promise.resolve({})});\n"
    "  posts.push(url);\n"
    "  return new Promise((res, rej) => { const s = opts.signal;\n"
    "    if (s) s.addEventListener('abort', () => rej(new Error('aborted'))); }); };\n"
    "window.setLang = () => {};\n"
    "%s\n%s);\n"
    "const pick = lang => handlers[0]({target: {value: lang, matches: () => true, getAttribute: () => '/lang/LANGCODE'}});\n"
    "(async () => {\n"
    "  pick('fr'); pick('es'); await settle();\n"
    "  const before = posts.slice(), waits = timers.map(x => x[1]);\n"
    "  timers.slice().forEach(x => x[0]()); await settle();\n"
    "  console.log(JSON.stringify({before, waits, after: posts}));\n"
    "})();\n") % (_line84(_PJ84, "var _r20cLangSeq"), _cut_or84(_PJ84, _HANDLER84))
_lang84r = _node84("panel.js: a language save that never answers", _lang_prog84)
if _lang84r is not None:
    check("language picker: fr's save never answering, the es pick's save is still sent once fr's is "
          "given up after 15 s (it waited for the life of the page), and not before",
          _lang84r == {"before": ["/lang/fr?ajax=1"], "waits": [15000],
                       "after": ["/lang/fr?ajax=1", "/lang/es?ajax=1"]}, repr(_lang84r))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. "Panel Server" is said in the viewer's language
# ════════════════════════════════════════════════════════════════════════════════════════════════
# display_name is the fixed label for the panel's own host, an es/fr key, but every page wrapped
# it in data-no-i18n (meant for a remote's own name), so the H1, the dashboard card, the host
# picker, the Groups page and the server page said "Panel Server" under a nav that did not.
def _reached84(page):
    """The text the page's translator reads (what is NOT behind data-no-i18n or in a <code>)."""
    w = _scan84._Walker()
    w.feed(page)
    w.close()
    return set(w.strings)


_pages84 = {}
_lgs84 = None
_aria84 = []
try:
    _lgs84 = _p9_new_server(P9_LOCAL, "p84local", "csgo", 27984)
    _p9_arm(who="part84")
    _p9_patch(_so84, "get_server_status", lambda: {})
    _lang84("es")
    _c84 = _p9_client(P9_ADMIN)
    for _k84, _url84 in (("dashboard", "/"), ("host page", "/server-management"),
                         ("install", "/servers/install"), ("groups", "/groups")):
        _r84 = _c84.get(_url84)
        _pages84[_k84] = (_r84.status_code, _r84.get_data(as_text=True))
    _aria84 = sorted(_html84.unescape(a) for a in _re84.findall(
        r'data-action="moveHostCard" data-args=\'\[-1,"@self"\]\'\s+title="[^"]*" aria-label="([^"]*)"',
        _pages84["dashboard"][1]))
finally:
    _lang84(_LANG84_WAS)
    _p9_restore_all()
    if _lgs84 is not None:
        _p9_delete_server(_lgs84)
# Read per site, not per page: base.html's sidebar link says "Panel Server" unguarded on every page.
_reach84 = {k: (v[0], _re84.search(r"data-no-i18n[^>]*>\s*Panel Server\s*<", v[1]) is None
                and (_re84.search(r'<span data-host-name>Panel Server</span>|<option value="%d"(?: selected)?>'
                                  r'Panel Server</option>' % P9_LOCAL, v[1]) is not None),
                "p9-host" in _reached84(v[1]))
            for k, v in _pages84.items()}
check("pages: the panel host's label is read by the translator on the dashboard, its own page, the "
      "install host picker and Groups (it was behind data-no-i18n: English on an es page); a remote's "
      "name on them is still guarded",
      _reach84 == {"dashboard": (200, True, False), "host page": (200, True, False),
                   "install": (200, True, False), "groups": (200, True, False)}, repr(_reach84))
check("pages: ...and the dashboard's move button names it in Spanish (\"Move %s up\" was filled with "
      "\"Panel Server\")",
      _ES84["Move %s up"] % _ES84["Panel Server"] in _aria84 and _ES84["Move %s up"] % "p9-host" in _aria84
      and _ES84["Move %s up"] % "Panel Server" not in _aria84,
      repr(_aria84))

# The templates that name a host: none renders display_name raw, in or out of a guard.
_raw84 = sorted(f for f in os.listdir(os.path.join(_root, "templates")) if f.endswith(".html")
                and _re84.search(r"\{\{\s*(?:remote|r|s)\.display_name\s*\}\}", _read84("templates", f))
                and f != "install_server.html")
_inst84 = _read84("templates", "install_server.html")
check("templates: a host's name is rendered through host_label / host_text everywhere (the install "
      "picker's <option> guards a remote's only)",
      _raw84 == [] and "{% if not r.is_local %} data-no-i18n{% endif %}>{{ r.display_name }}</option>" in _inst84,
      repr(_raw84))

# A page heading wraps where it carries a name (part69): the label, now unguarded, still says so.
with _p9.app_context():
    _hl84 = (str(_p9.jinja_env.globals["host_label"](_db84.session.get(_RS84, P9_LOCAL))),
             str(_p9.jinja_env.globals["host_label"](_db84.session.get(_RS84, P9_HOST))))
check("pages: host_label renders the panel host's label unguarded and a remote's name guarded, each "
      "one span marked data-host-name, which the heading's wrap rule reads",
      _hl84 == ("<span data-host-name>Panel Server</span>", "<span data-host-name data-no-i18n>p9-host</span>")
      and ".page-title:has(> [data-host-name]) { flex-wrap: wrap; }" in _read84("static", "css", "panel.css"),
      repr(_hl84))

# A sentence the server words around a host name: the label is translated with it.
with _p9.test_request_context():
    from flask import session as _session84
    _session84["lang"] = "es"
    with _p9.app_context():
        _loc84 = _db84.session.get(_RS84, P9_LOCAL)
        _rem84 = _db84.session.get(_RS84, P9_HOST)
        _busy_loc84 = _i18n84.tr(_rw84.busy_message(_loc84.display_name))
        _busy_rem84 = _i18n84.tr(_rw84.busy_message(_rem84.display_name))
        _en84 = (_loc84.display_name == "Panel Server", str(_rw84.busy_message(_loc84.display_name)))
_BUSY84 = "{host} is being rebooted: its game servers are being stopped first. Try again once it is back."
check("messages: \"{host} is being rebooted…\" for the panel host reads \"Servidor del panel\" to an es "
      "viewer (the label stayed English inside the Spanish sentence); a remote's name is kept as typed",
      _busy_loc84 == _ES84[_BUSY84].replace("{host}", _ES84["Panel Server"])
      and _busy_rem84 == _ES84[_BUSY84].replace("{host}", "p9-host"), repr((_busy_loc84, _busy_rem84)))
check("messages: ...and what is recorded is still the English (the label equals \"Panel Server\")",
      _en84 == (True, _BUSY84.replace("{host}", "Panel Server")), repr(_en84))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. The panel host's OS-update reads are superadmin-only, as its OS-update actions are
# ════════════════════════════════════════════════════════════════════════════════════════════════
# check-updates and os-update/start were get_host_remote; updates-cached, os-update/status, the
# reboot banner's /reboot-required and the login banner's summary were not, so a MANAGE_REMOTES
# group covering the panel host read its pending packages, its running apt output, its patch count
# and its reboot state — reachable through nothing else (the cards are hidden from them).
_mine84 = {"users": [], "groups": []}
_os84 = {}
_seen_was84 = dict(_ps84._os_update_seen)
try:
    with _p9.app_context():
        _g84 = _G84(name="p84_hosts", description="", is_default=False)
        _g84.set_permissions([_auth84.MANAGE_REMOTES])
        _g84.servers.extend([_db84.session.get(_RS84, P9_LOCAL), _db84.session.get(_RS84, P9_HOST)])
        _v84 = _U84(username="p84_hostadmin", password_hash=_auth84.hash_password("Str0ng!passw0rd-p84"),
                    display_name="p84 host admin", is_superadmin=False, is_active=True)
        _v84.groups.append(_g84)
        _db84.session.add_all([_g84, _v84])
        _db84.session.commit()
        _mine84["users"].append(_v84.id)
        _mine84["groups"].append(_g84.id)
        _born84 = {rid: _db84.session.get(_RS84, rid).created_at for rid in (P9_LOCAL, P9_HOST)}
    for _rid84 in (P9_LOCAL, P9_HOST):
        _ps84._os_update_seen[_rid84] = {"name": "x", "count": 2, "security": 1, "packages": ["a", "b"],
                                         "at": _time84.time(), "created": _born84[_rid84]}
    _p9_arm(who="part84")
    _p9_patch(_rv84, "remote_os_update_status", lambda remote: {"running": False, "done": True, "rc": 0,
                                                                "log": "apt output"})
    _p9_patch(_rv84, "remote_reboot_required",
              lambda remote: {"required": True, "packages": ["linux-image-x"], "known": True})
    _dc84 = _p9_client(_mine84["users"][0])
    for _rid84 in (P9_LOCAL, P9_HOST):
        _os84[("cached", _rid84)] = _dc84.get("/api/remote/%d/updates-cached" % _rid84).status_code
        _os84[("status", _rid84)] = _dc84.get("/api/remote/%d/os-update/status" % _rid84).status_code
        _os84[("reboot", _rid84)] = _dc84.get("/api/remote/%d/reboot-required" % _rid84).status_code
    _os84["summary"] = sorted(h["id"] for h in _p9_json(_dc84.get("/api/os-updates/summary"))["hosts"])
    _lang84("es")
    _sa84 = _p9_json(_p9_client(P9_ADMIN).get("/api/os-updates/summary"))["hosts"]
    _os84["admin"] = sorted((h["id"], h["name"]) for h in _sa84)
    _os84[("admin cached", P9_LOCAL)] = _p9_client(P9_ADMIN).get(
        "/api/remote/%d/updates-cached" % P9_LOCAL).status_code
    _os84[("admin reboot", P9_LOCAL)] = _p9_client(P9_ADMIN).get(
        "/api/remote/%d/reboot-required" % P9_LOCAL).status_code
finally:
    _lang84(_LANG84_WAS)
    _p9_restore_all()
    _ps84._os_update_seen.clear()
    _ps84._os_update_seen.update(_seen_was84)
    with _p9.app_context():
        for _uid84 in _mine84["users"]:
            _db84.session.delete(_db84.session.get(_U84, _uid84))
        for _gid84 in _mine84["groups"]:
            _db84.session.delete(_db84.session.get(_G84, _gid84))
        _db84.session.commit()
check("OS updates: a host admin whose group covers the panel host does not read its cached package "
      "list or its running apt output (403); the remote's they do",
      _os84.get(("cached", P9_LOCAL)) == 403 and _os84.get(("status", P9_LOCAL)) == 403
      and _os84.get(("cached", P9_HOST)) == 200 and _os84.get(("status", P9_HOST)) == 200, repr(_os84))
check("OS updates: ...nor, through the two banners, its update count (the summary lists only the "
      "remote) or its reboot state and pending packages (/reboot-required is 403 there, 200 on the "
      "remote)",
      _os84.get("summary") == [P9_HOST]
      and _os84.get(("reboot", P9_LOCAL)) == 403 and _os84.get(("reboot", P9_HOST)) == 200, repr(_os84))
check("OS updates: ...a superadmin still reads it, and the banner names the panel host in their "
      "language (it said \"Panel Server\" to an es viewer)",
      _os84.get(("admin cached", P9_LOCAL)) == 200 and _os84.get(("admin reboot", P9_LOCAL)) == 200
      and _os84.get("admin") == sorted([(P9_LOCAL, _ES84["Panel Server"]), (P9_HOST, "x")]), repr(_os84))


# ...and the pages do not ask for it: base.html's reboot banner ran /reboot-required for the panel
# host for any host admin (LOCAL_HOST_ID), and the panel host's manage page did again on an update.
_NAGS84 = _read84("static", "js", "nags.js")
_mark84 = "window.rebootNagCheck(window.LOCAL_HOST_ID, 'the panel host'); }"
_at84 = _NAGS84.find(_mark84)
_iife84 = (_NAGS84[_NAGS84.rfind("(function(){", 0, _at84):_NAGS84.index("})();", _at84) + 5]
           if _at84 >= 0 else "/* the panel host's reboot-banner start-up block was not found */")
_name84 = "reboot banner: the panel host's is not asked for by a delegated host admin"
_out84 = _node84(_name84, (
    "global.window = global; const asked = [];\n"
    "window.rebootNagCheck = (id) => asked.push(id);\n"
    "const run = (ctl) => { asked.length = 0; window.LOCAL_HOST_ID = 5; window.LOCAL_HOST_CTL = ctl;\n"
    + _iife84 + "\n return asked.slice(); };\n"
    "console.log(JSON.stringify({delegate: run(false), admin: run(true)}));\n"))
if _out84 is not None:
    check("reboot banner: base.html does not ask /reboot-required about the panel host for a delegated "
          "host admin (LOCAL_HOST_CTL false); a superadmin's page still does",
          _out84 == {"delegate": [], "admin": [5]}, repr(_out84))
check("reboot banner: ...nor does the panel host's manage page after an update, unless the viewer may "
      "act on it",
      "if(IS_LOCAL && window.LOCAL_HOST_ID!=null && window.LOCAL_HOST_CTL) rebootNagCheck"
      in _read84("static", "js", "remote_manage.js"), "remote_manage.js's post-update banner check")

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. Every key a data-i18n-placeholder names is in both catalogs
# ════════════════════════════════════════════════════════════════════════════════════════════════
_named84 = set()
for _dir84, _ext84 in (("templates", ".html"), (os.path.join("static", "js"), ".js")):
    for _fn84 in sorted(os.listdir(os.path.join(_root, _dir84))):
        if _fn84.endswith(_ext84):
            _src84 = _read84(_dir84, _fn84)
            _named84 |= {(_html84.unescape(m.group(2)), _fn84) for m in _re84.finditer(
                r"""data-i18n-placeholder(?:=|',\s*)(["'])((?:(?!\1).)+)\1""", _src84)}
_unknown84 = sorted((k, f) for k, f in _named84 if k not in _ES84 or k not in _FR84)
check("i18n gate: every data-i18n-placeholder names an es and fr catalog key (the four sites are read)",
      len(_named84) >= 4 and not _unknown84, repr((_unknown84, sorted(_named84))))

check("part84: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP84_START, repr(_P9_TRIPPED[_TRIP84_START:][:6]))
