"""Part 236 of the unit suite: the strict style policy (no style attributes anywhere).

The page policy is style-src 'self' + the nonce, style-src-elem the same, style-src-attr 'none' (OWASP
Content Security Policy Cheat Sheet, "Strict Policy"; CSP Level 3 style-src-attr). A browser refuses
every style attribute on such a page: in a template, in markup a script builds, and from
setAttribute('style', ...) or .style.cssText. A property set through the CSSOM (el.style.width = ...)
is not governed by CSP and stays.

1. The gate: no template holds a style attribute, and no script under panel/static/js puts one in a
   string, calls setAttribute('style'), assigns .cssText or the whole .style. Comments are not code
   and are not read. The scanner is held to known samples both ways.
2. The header: the policy app.py's _csp builds carries the strict style directives with the request's
   nonce, and no 'unsafe-inline' at all (smoke reads it off a real response).
3. The readers of what moved: a data-start-hidden element in a section refreshSection re-renders is
   converted before the after-hook runs; the dashboard paints each tag chip's colour on load and after
   every refresh; the confirm dialog's error line starts hidden and api.error shows it; the terminal
   gives xterm's 24-bit cell colours to the CSSOM, and the vendored bundle still has that shape.

HOW IT RUNS. Files are read as text; the scripts' functions run in node against small stand-ins; the
policy is app.py's own _csp, run from its text. Nothing reaches a host.
"""
import os as _os236
import re as _re236
import shutil as _shutil236
import subprocess as _sp236  # nosec B404 - runs node on fixed test scripts only

from unit import REPO_ROOT as _ROOT236
from unit.part01 import check, eq, skip
from unit.part12 import _P9_TRIPPED, _p9_arm, _p9_restore_all

_trips236 = len(_P9_TRIPPED)
_TPL236 = _os236.path.join(_ROOT236, "panel", "templates")
_JS236 = _os236.path.join(_ROOT236, "panel", "static", "js")

def _read236(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ── 1. The gate ──────────────────────────────────────────────────────────────────────────────────
_REGEX_BEFORE236 = set("(,=:[!&|?{};+-*%<>~^")
_LIT236, _RX236 = "\x00", "\x01"      # what a string literal and a regex literal become in the code
# A regex literal: a slash, then escapes, [classes] (where a slash is literal) or any other character up
# to the closing slash on the same line, then its flags.
_REGEX_LIT236 = _re236.compile(r"/(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\[\n])+/[A-Za-z]*")
_REGEX_WORDS236 = ("return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "else", "do")


def _skip_quoted236(src, i):
    """Return the index just past the string or template literal that starts at src[i]."""
    q, n, i = src[i], len(src), i + 1
    while i < n and src[i] != q:
        i += 2 if src[i] == "\\" else 1
    return i + 1


def _skip_regex236(src, i):
    """Return the index just past the regex literal that starts at src[i] (a slash), flags included."""
    m = _REGEX_LIT236.match(src, i)
    return m.end() if m else i + 1


def _regex_starts236(code):
    """Whether a slash after `code` (the code so far, comments out) opens a regex literal."""
    tail = code.rstrip()
    if not tail or tail[-1] in _REGEX_BEFORE236:
        return True
    word = _re236.search(r"[A-Za-z_$][\w$]*$", tail)
    return bool(word) and word.group(0) in _REGEX_WORDS236


def _js_split236(src):
    """Split JavaScript into (code with comments out and each literal as _LIT236, [(line, literal text)]).

    A small lexer, not a parser: strings, template literals, comments and regex literals are told apart,
    which is all the gate needs (a style attribute in a comment is prose; one in a string is markup).
    """
    code, strings, i, n = [], [], 0, len(src)
    while i < n:
        c, two = src[i], src[i:i + 2]
        if c in "'\"`":
            j = _skip_quoted236(src, i)
            strings.append((src.count("\n", 0, i) + 1, src[i:j]))
            code.append(_LIT236)
        elif two in ("//", "/*"):
            j = _skip_comment236(src, i)
            code.append("\n" * src.count("\n", i, j))
        elif c == "/" and _regex_starts236("".join(code[-40:])):
            j = _skip_regex236(src, i)
            code.append(_RX236)
        else:
            j = i + 1
            code.append(c)
        i = j
    return "".join(code), strings


def _skip_comment236(src, i):
    """Return the index just past the // or /* comment that starts at src[i] (a // stops at its newline)."""
    end = "\n" if src[i + 1] == "/" else "*/"
    j = src.find(end, i + 2)
    return len(src) if j < 0 else (j if end == "\n" else j + 2)


_ATTR_IN_STRING236 = _re236.compile(r"(?<![\w.:-])style\s*=")
_CSSTEXT236 = _re236.compile(r"\.cssText\b")
_WHOLE_STYLE236 = _re236.compile(r"\.style\s*=(?!=)")
_TPL_ATTR236 = _re236.compile(r"(?<![\w.:$-])style\s*=\s*[\"'{]", _re236.I)


def _js_findings236(src):
    """Every style attribute a script would write: (line, what) for each."""
    code, strings = _js_split236(src)
    out = [(line, "style attribute in a string") for line, text in strings if _ATTR_IN_STRING236.search(text)]
    # setAttribute / jQuery's attr with the name 'style': each literal is one _LIT236 in the code, in order.
    for k, m in enumerate(_re236.finditer(_LIT236, code)):
        before = code[max(0, m.start() - 20):m.start()]
        if strings[k][1][1:-1] == "style" and _re236.search(r"(setAttribute|\.attr)\(\s*$", before):
            out.append((strings[k][0], "a style attribute set by name"))
    out += [(code.count("\n", 0, m.start()) + 1, ".cssText") for m in _CSSTEXT236.finditer(code)]
    out += [(code.count("\n", 0, m.start()) + 1, "the whole .style assigned") for m in _WHOLE_STYLE236.finditer(code)]
    return sorted(set(out))


def _tpl_findings236(src):
    """Every style attribute a template renders, Jinja and HTML comments left out: (line, what)."""
    bare = _re236.sub(r"\{#.*?#\}|<!--.*?-->", lambda m: "\n" * m.group(0).count("\n"), src, flags=_re236.S)
    out = [(bare.count("\n", 0, m.start()) + 1, "style attribute") for m in _TPL_ATTR236.finditer(bare)]
    out += [(bare.count("\n", 0, m.start()) + 1, what) for what, rx in
            (("setAttribute('style')", _re236.compile(r"setAttribute\(\s*['\"]style['\"]")),
             (".cssText", _CSSTEXT236)) for m in rx.finditer(bare)]
    return out


def _scan236():
    """{file name: findings} for every template and every script of ours that has any."""
    found = {}
    for name in sorted(_os236.listdir(_TPL236)):
        if name.endswith(".html"):
            hits = _tpl_findings236(_read236(_os236.path.join(_TPL236, name)))
            if hits:
                found[name] = hits
    for name in sorted(_os236.listdir(_JS236)):
        if name.endswith(".js"):
            hits = _js_findings236(_read236(_os236.path.join(_JS236, name)))
            if hits:
                found[name] = hits
    return found


def _s236_scanner_controls():
    js_bad = ["x.innerHTML = '<b style=\"color:red\">';", "el.style.cssText = 'a:b';",
              "el.setAttribute('style', v);", "el.setAttribute(\"style\", 'a:b');", "$(el).attr('style', v);",
              "el.style = 'color:red';", "var s = `<i style='x'>`;"]
    js_ok = ["el.style.width = '40%';", "el.style.setProperty('color', c);", "// a style=\"x\" comment",
             "/* style=\"x\" */ var a = 1;", "if (el.style.display === 'none') go();", "var r = /style=\"/g;",
             "el.setAttribute('data-style', v);", "x.innerHTML = '<b data-start-hidden>';",
             "var u = 'https://x/'; el.className = 'a'; // style=\"x\"", "var t = a / b; var s = 'ok';"]
    eq("gate: the script scanner finds each way a script writes a style attribute, and none of the allowed ones",
       ([bool(_js_findings236(s)) for s in js_bad], [_js_findings236(s) for s in js_ok]),
       ([True] * len(js_bad), [[] for _ in js_ok]))
    tpl_bad = ['<div class="a" style="x">', "{% if c %}style=\"background: {{ c }}\"{% endif %}", "<i STYLE='x'>",
               "<script nonce=\"n\">el.style.cssText = 'a';</script>"]
    tpl_ok = ['<div data-start-hidden>', '{# style="x" #}', '<!-- <b style="x"> -->', '<style nonce="n">a{b:c}</style>',
              '<div class="list-style">', "<p>Use {{ t('style') }}=</p>"]
    eq("gate: the template scanner finds a style attribute (one a condition renders too), and not a comment, a "
       "<style> block, data-start-hidden or a class name",
       ([bool(_tpl_findings236(s)) for s in tpl_bad], [_tpl_findings236(s) for s in tpl_ok]),
       ([True] * len(tpl_bad), [[] for _ in tpl_ok]))


def _s236_gate():
    found = _scan236()
    check("gate: no template and no script of ours writes a style attribute (the page policy refuses every "
          "one: style-src-attr 'none')", not found, repr({k: v[:3] for k, v in found.items()})[:1500])


# ── 2. The header ────────────────────────────────────────────────────────────────────────────────
def _s236_header():
    """The policy _csp builds, read from app.py's own source: its string literals in order, nonce filled in."""
    import ast
    src = _read236(_os236.path.join(_ROOT236, "panel", "install", "app.py"))
    body = src[src.index("    def _csp():"):src.index("    @app.after_request")]
    tree = ast.parse("if True:\n" + body)
    consts = [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
              and n.value not in ("csp_nonce", "")]
    parts = [n.value for n in sorted(consts, key=lambda n: (n.lineno, n.col_offset))]
    csp = "".join(parts).replace("%s", "n236")
    eq("header: a page's policy allows styles from the panel and this request's nonce only, and no style "
       "attribute at all (no 'unsafe-inline' or 'unsafe-hashes' anywhere)",
       ["style-src 'self' 'nonce-n236'; " in csp, "style-src-elem 'self' 'nonce-n236'; " in csp,
        "style-src-attr 'none'; " in csp, "script-src 'self' 'nonce-n236'; " in csp, "unsafe-inline" in csp,
        "unsafe-hashes" in csp], [True, True, True, True, False, False])


# ── 3. The readers of what moved ─────────────────────────────────────────────────────────────────
def _node236(name, script):
    """Run `script` in node; its last stdout line as JSON, or None (with a skip) when node is absent."""
    import json as _json236
    if not _shutil236.which("node"):
        skip(name, "no node on this machine")
        return None
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp236.run(["node", "-"], input=script, capture_output=True, text=True, timeout=30, check=False)  # nosec B603 B607
    try:
        return _json236.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"node failed": r.stderr[-600:]}


def _between236(text, start, end):
    """The text from `start` up to and including the first `end` after it ("" when absent)."""
    i = text.find(start)
    j = text.find(end, i + len(start)) if i >= 0 else -1
    return text[i:j + len(end)] if j >= 0 else ""


def _s236_refresh_converts():
    panel = _read236(_os236.path.join(_JS236, "panel.js"))
    fn = (_between236(panel, "function _sectionSwapped(cur){", "\n}") + "\n"
          + _between236(panel, "window.refreshSection = function(sel, afterName){", "\n};"))
    hidden = _read236(_os236.path.join(_JS236, "start_hidden.js"))
    prog = r"""
var calls = [];
function El(marked){ this.style = {}; this.attrs = marked ? {'data-start-hidden': ''} : {}; this.innerHTML = ''; }
El.prototype.hasAttribute = function(a){ return a in this.attrs; };
El.prototype.removeAttribute = function(a){ delete this.attrs[a]; };
var kid = new El(true), cur = new El(false);
cur.querySelectorAll = function(sel){ calls.push('convert'); return 'data-start-hidden' in kid.attrs ? [kid] : []; };
global.window = global; global.location = {href: '/'};
global.document = {querySelectorAll: function(){ return []; }, querySelector: function(){ return cur; }};
""" + hidden + r"""
global.DOMParser = function(){ this.parseFromString = function(){ return {querySelector: function(){ return {innerHTML: '<i>'}; }}; }; };
global.fetch = function(){ return Promise.resolve({text: function(){ return '<html>'; }}); };
global._actionFn = function(name){ return function(){ calls.push('after:' + kid.style.display + ':' + ('data-start-hidden' in kid.attrs)); }; };
""" + fn + r"""
window.refreshSection('#x', 'hook');
setTimeout(function(){ console.log(JSON.stringify({calls: calls, display: kid.style.display, mark: 'data-start-hidden' in kid.attrs})); }, 50);
"""
    got = _node236("refresh converts", prog)
    if got is None:
        return
    eq("readers: refreshSection converts a data-start-hidden element in the swapped-in section to an inline "
       "display:none (the mark dropped) before the after-hook shows or hides it",
       got, {"calls": ["convert", "after:none:false"], "display": "none", "mark": False})


def _s236_tag_chips():
    dash = _read236(_os236.path.join(_JS236, "dashboard.js"))
    paint = _between236(dash, "function paintTagChips() {", "\n}")
    after = _between236(dash, "window.afterDashRefresh = function(){", "\n};")
    prog = r"""
var chips = [{c: '#3ba55d', style: {}}, {c: '#d29922', style: {}}];
chips.forEach(function(x){ x.getAttribute = function(a){ return a === 'data-tag-color' ? x.c : null; }; });
var asked = [];
global.document = {querySelectorAll: function(sel){ asked.push(sel); return chips; }};
""" + paint + r"""
var onRefresh = (function(){ var restoreBulkSelection = function(){}, _r20cIdsLanded = function(){},
    refreshStatus = function(){}, bindDragRegions = function(){}; var window = {};
""" + after.replace("window.afterDashRefresh = function(){", "return function(){", 1) + r"""
})();
paintTagChips(); var onLoad = chips.map(function(x){ return x.style.backgroundColor; });
chips.forEach(function(x){ x.style = {}; }); onRefresh();
console.log(JSON.stringify({load: onLoad, refresh: chips.map(function(x){ return x.style.backgroundColor; }), asked: asked[0]}));
"""
    got = _node236("tag chips", prog)
    if got is None:
        return
    eq("readers: the dashboard paints each tag chip's colour from data-tag-color through the CSSOM, on load "
       "and again after a refresh of the server cards",
       got, {"load": ["#3ba55d", "#d29922"], "refresh": ["#3ba55d", "#d29922"],
             "asked": ".tag-chip[data-tag-color]"})
    check("readers: dashboard.js paints the chips once when it loads", "\npaintTagChips();\n" in dash, "")


def _s236_confirm_error_line():
    panel = _read236(_os236.path.join(_JS236, "panel.js"))
    fns = "\n".join(_between236(panel, "function %s(" % f, "\n}") for f in ("_cdInputHtml", "_cdFillBody",
                                                                            "_cdGateConfirm", "_cdHost"))
    dialog = _between236(panel, "window.confirmDialog = function(opts){", "\n};")
    prog = r"""
function El(id){ this.id = id; this.style = {}; this.classList = {list: [], add: function(c){ this.list.push(c); },
  remove: function(c){ this.list = this.list.filter(function(x){ return x !== c; }); }};
  this.listeners = {}; this.innerHTML = ''; this.textContent = ''; }
El.prototype.addEventListener = function(t, f){ this.listeners[t] = f; };
El.prototype.focus = function(){}; El.prototype.remove = function(){};
El.prototype.appendChild = function(n){ this.child = n; };
var parts = {'#cd-input': new El('cd-input'), '[data-cd="ok"]': new El('ok'), '#cd-err': new El('cd-err'),
             '[data-cd="cancel"]': new El('cancel'), '[data-cd-body]': new El('body')};
var ov = new El('ov'); ov.querySelector = function(s){ return parts[s] || null; };
global.window = global; global.setTimeout = function(){};
global.document = {createElement: function(){ return ov; }, body: {appendChild: function(){}},
                   querySelectorAll: function(){ return []; },
                   addEventListener: function(){}, removeEventListener: function(){}};
global.escapeHtml = function(s){ return String(s); }; global.t = function(s){ return s; };
""" + fns + "\n" + dialog + r"""
var api = null;
confirmDialog({title: 'x', requirePassword: true, onConfirm: function(v, a){ api = a; }});
var start = parts['#cd-err'].style.display, html = ov.innerHTML;
parts['#cd-input'].value = 'pw'; parts['#cd-input'].listeners.input(); parts['[data-cd="ok"]'].onclick();
api.error('Wrong password');
var shown = parts['#cd-err'].style.display, text = parts['#cd-err'].textContent;
confirmDialog({title: 'y', bodyNode: {}});
console.log(JSON.stringify({start: start, shown: shown, text: text,
  attr: /style=/.test(html), overlay: ov.className, body: parts['[data-cd-body]'].classList.list}));
"""
    got = _node236("confirm error line", prog)
    if got is None:
        return
    eq("readers: the confirm dialog's error line starts hidden through the CSSOM and api.error shows it; its "
       "markup has no style attribute; a node body takes the capped class in place of pre-line",
       got, {"start": "none", "shown": "", "text": "Wrong password", "attr": False, "overlay": "dialog-overlay",
             "body": ["cd-body-node"]})


def _s236_terminal_colours():
    term = _read236(_os236.path.join(_JS236, "host_terminal.js"))
    fn = _between236(term, "function cssomCellColours(t) {", "\n}")
    prog = fn + r"""
var set = [], el = {style: {setProperty: function(k, v){ set.push([k, v]); }}};
var factory = {_addStyle: function(){ set.push('attribute'); }};
var ok = cssomCellColours({_core: {_renderService: {_renderer: {value: {_rowFactory: factory}}}}});
factory._addStyle(el, 'color:#112233'); factory._addStyle(el, 'background-color:#0a0b0c');
var none = cssomCellColours({_core: {}});
console.log(JSON.stringify({ok: ok, none: none, set: set}));
"""
    got = _node236("terminal colours", prog)
    if got is None:
        return
    eq("readers: the terminal sets xterm's 24-bit cell colours through the CSSOM (setProperty), not a style "
       "attribute, and leaves a terminal without that internal path alone",
       got, {"ok": True, "none": False, "set": [["color", "#112233"], ["background-color", "#0a0b0c"]]})
    check("readers: the terminal patches its row factory right after open()",
          "withStyleNonce(function () { term.open(host); });\n  cssomCellColours(term);\n" in term, "")
    xterm = _read236(_os236.path.join(_ROOT236, "panel", "static", "vendor", "xterm", "xterm.min.js"))
    eq("readers: the vendored xterm still reaches its row factory by _core._renderService._renderer.value."
       "_rowFactory and colours a cell with _addStyle(element, declaration)",
       ["this._core=this.register(new " in xterm,
        "this._renderService=this.register(this._instantiationService.createInstance(" in xterm,
        "setRenderer(e){this._renderer.value=e" in xterm, "this._rowFactory=" in xterm,
        '_addStyle(e,t){e.setAttribute("style"' in xterm], [True] * 5)


def _s236_start_hidden_readers():
    install = _read236(_os236.path.join(_TPL236, "install_server.html"))
    dash = _read236(_os236.path.join(_TPL236, "dashboard.html"))
    ms = _read236(_os236.path.join(_JS236, "manage_servers.js"))
    eq("readers: the GMod content option, the bulk bars and the no-match card start hidden by data-start-hidden, "
       "which their scripts show with style.display",
       ['id="gmod-content-opt" data-start-hidden>' in install, ms.count("contentOpt.style.display = ") == 2,
        'id="srv-none" class="card" data-start-hidden>' in dash, 'card shadow-lg" data-start-hidden>' in dash],
       [True] * 4)


try:
    for _fn236 in (_s236_scanner_controls, _s236_gate, _s236_header, _s236_refresh_converts, _s236_tag_chips,
                   _s236_confirm_error_line, _s236_terminal_colours, _s236_start_hidden_readers):
        _p9_arm(who="part236")
        try:
            _fn236()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()

check("part236: nothing reached a real transport", len(_P9_TRIPPED) == _trips236, repr(_P9_TRIPPED[_trips236:]))
