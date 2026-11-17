"""Part 234 of the unit suite: the server page, Files & Config and Databases under a strict style policy.

The page policy's style-src-attr is moving to 'none': a style="" attribute, in a template or in markup a
script builds, is refused by the browser and the element loses that look. Held here, for the server page
(server_detail.html), Files & Config (server_files.html, _server_databases.html), the Databases page
(databases_overview.html) and the five scripts that draw on them:

1. No style attribute in those templates, and none in a string those scripts build; no style.cssText
   and no setAttribute('style').
2. The pages as the app renders them: no styled element that the shared chrome does not also carry.
3. Starting hidden without a style attribute: base.html loads js/start_hidden.js before panel.js and
   every page script; run in node, it turns each data-start-hidden mark into style.display 'none' and
   drops the mark. Every element the scripts show with style.display that renders hidden carries the
   mark, and none carries d-none or hidden, which no style.display can undo.
4. What replaced the attributes: every class those templates and scripts use from the panel.css section
   exists there; the status badge's first colour is the one the script recolours it with; a closed
   config group is hidden through the CSSOM and read back by its toggle; the action-output dialog, in
   node, is a classed overlay with no inline style.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed and every host call stubbed; the
scripts in node on small DOMs of their own. Nothing reaches a host or data/.
"""
import os
import re as _re234

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import P9_ADMIN, P9_GS, _P9_TRIPPED, _p9_arm, _p9_client, _p9_patch, _p9_restore_all
from unit.part47 import _cut47, _node47
from panel.ops.ssh_manager import _core as _core234

_TRIP234 = len(_P9_TRIPPED)
_TPL234 = ("server_files.html", "_server_databases.html", "databases_overview.html", "server_detail.html")
_JS234 = ("server_files.js", "server_detail.js", "server_actions.js", "lgsm_update.js", "databases_manager.js")


def _read234(*parts):
    """Return a repository file's text."""
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _js_code234(src):
    """Return `src` with its // line comments and /* */ blocks blanked (strings kept)."""
    src = _re234.sub(r"/\*.*?\*/", " ", src, flags=_re234.S)
    return _re234.sub(r"(?m)^\s*//.*$|\s//\s.*$", " ", src)


_STYLE_ATTR234 = _re234.compile(r"""<[a-zA-Z][^<>]*?\sstyle\s*=""", _re234.S)
_JS_STYLE234 = _re234.compile(r"""style\s*=\s*\\?["']|\.cssText\b|setAttribute\(\s*["']style["']"""
                              r"""|\.attr\(\s*["']style["']""")


def _tpl_styles234(text):
    """Return each start tag in template `text` that carries a style attribute."""
    return [m.group(0)[:90] for m in _STYLE_ATTR234.finditer(text)]


def _js_styles234(text):
    """Return each line of script `text` that writes a style attribute or cssText."""
    return [ln.strip()[:90] for ln in _js_code234(text).splitlines() if _JS_STYLE234.search(ln)]


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The sources: no style attribute, no cssText
# ════════════════════════════════════════════════════════════════════════════════════════════════
check("strict style policy: (control) the template reader finds a style attribute across lines and in "
      "a Jinja branch, and the script reader a cssText and a built style=, not one in a comment",
      len(_tpl_styles234('<div id="a"\n     style="x"></div><p{% if b %} style="display:none;"{% endif %}>')) == 2
      and len(_js_styles234("el.style.cssText = 'a';\nh = '<b style=\"c\">';\n// a style=\"x\" note\n"
                            "el.style.width = '1px';\n")) == 2, "")
_tpl_bad234 = {n: _tpl_styles234(_read234("panel", "templates", n)) for n in _TPL234}
check("strict style policy: the server page, Files & Config and Databases templates hold no style "
      "attribute", not any(_tpl_bad234.values()), repr({k: v for k, v in _tpl_bad234.items() if v}))
_js_bad234 = {n: _js_styles234(_read234("panel", "static", "js", n)) for n in _JS234}
check("strict style policy: the five scripts on those pages build no style attribute and set no "
      "cssText or style attribute", not any(_js_bad234.values()), repr({k: v for k, v in _js_bad234.items() if v}))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The pages as rendered: only the shared chrome may still carry a style attribute
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TAG234 = _re234.compile(r"<[a-zA-Z][^<>]*>", _re234.S)


def _styled234(html):
    """Return the set of rendered start tags that carry a style attribute, whitespace collapsed."""
    return {" ".join(t.split()) for t in _TAG234.findall(html or "") if _re234.search(r"\sstyle\s*=", t)}


_pages234 = {}
try:
    _p9_arm(who="part234")
    _p9_patch(_core234, "run_command", lambda *a, **k: ("", "", 1))
    _cl234 = _p9_client(P9_ADMIN)
    for _k234, _u234 in (("chrome", "/account"), ("detail", "/server/%d" % P9_GS),
                         ("files", "/server/%d/files" % P9_GS), ("dbs", "/databases")):
        _r234 = _cl234.get(_u234)
        _pages234[_k234] = (_r234.status_code, _r234.get_data(as_text=True))
finally:
    _p9_restore_all()
check("strict style policy: (control) the four pages render for a superadmin",
      [_pages234.get(k, (0,))[0] for k in ("chrome", "detail", "files", "dbs")] == [200] * 4,
      repr({k: v[0] for k, v in _pages234.items()}))
_chrome234 = _styled234(_pages234.get("chrome", (0, ""))[1])
for _k234, _what234 in (("detail", "the server page"), ("files", "Files & Config"), ("dbs", "the Databases page")):
    _own234 = sorted(_styled234(_pages234.get(_k234, (0, ""))[1]) - _chrome234)
    check("strict style policy: %s, as rendered, has no styled element the shared chrome does not also "
          "carry" % _what234, not _own234, repr(_own234[:5]))
check("strict style policy: (control) Files & Config renders sections marked data-start-hidden",
      _pages234.get("files", (0, ""))[1].count("data-start-hidden") >= 10, "")

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Starting hidden without a style attribute
# ════════════════════════════════════════════════════════════════════════════════════════════════
_base234 = _read234("panel", "templates", "base.html")
_sh_at234 = _base234.find("js/start_hidden.js")
check("start hidden: base.html loads start_hidden.js before panel.js and before the page's own scripts",
      0 <= _sh_at234 < _base234.find("js/panel.js') }}") < _base234.find("{% block scripts %}"),
      "start_hidden.js at %d" % _sh_at234)
_css234 = _read234("panel", "static", "css", "panel.css")
_sfjs234_full = _read234("panel", "static", "js", "server_files.js")
check("start hidden: panel.css hides a data-start-hidden element from the first paint",
      _re234.search(r"\[data-start-hidden\]\s*\{\s*display:\s*none;\s*\}", _css234) is not None, "")
_SH_PROG234 = (
    "global.window = global;\n"
    "function mk(i){ return {i, attrs: {'data-start-hidden': ''}, style: {display: ''}, kids: [],\n"
    "  hasAttribute(n){ return n in this.attrs; }, removeAttribute(n){ delete this.attrs[n]; },\n"
    "  querySelectorAll(sel){ return sel === '[data-start-hidden]'\n"
    "    ? this.kids.filter(e => 'data-start-hidden' in e.attrs) : []; }}; }\n"
    "const els = [mk(0), mk(1), mk(2)];\n"
    "global.document = {querySelectorAll(sel){\n"
    "  return sel === '[data-start-hidden]' ? els.filter(e => 'data-start-hidden' in e.attrs) : []; }};\n"
    + _read234("panel", "static", "js", "start_hidden.js") + "\n"
    "const at_load = els.map(e => [e.style.display, 'data-start-hidden' in e.attrs]);\n"
    "const root = mk(9); root.kids = [mk(10), mk(11)];\n"
    "window.applyStartHidden(root);\n"
    "console.log(JSON.stringify({at_load, later: [root].concat(root.kids).map(e => [e.style.display,\n"
    "  'data-start-hidden' in e.attrs])}));\n")
_sh234 = _node47(_SH_PROG234)
if _sh234 is None:
    skip("start hidden: the script turns every mark into style.display 'none' and drops it", "no node")
else:
    check("start hidden: at load the script turns every mark into style.display 'none' and drops it, so "
          "a page script's style.display = '' shows the element again",
          (_sh234 or {}).get("at_load") == [["none", False]] * 3, repr(_sh234))
    check("start hidden: window.applyStartHidden(root) does the same for markup put in after load, the "
          "root included", (_sh234 or {}).get("later") == [["none", False]] * 3, repr(_sh234))


def _shown_ids234(src):
    """Return the ids a script reads or writes through style.display (a direct lookup or a bound var)."""
    code = _js_code234(src)
    ids = set(_re234.findall(r"getElementById\(\s*'([\w-]+)'\s*\)\.style\.display", code))
    for var, el_id in _re234.findall(r"\b(\w+)\s*=\s*document\.getElementById\(\s*'([\w-]+)'\s*\)", code):
        if _re234.search(r"\b%s\.style\.display" % _re234.escape(var), code):
            ids.add(el_id)
    return ids


_shown234 = set()
for _n234 in ("server_files.js", "server_detail.js"):
    _shown234 |= _shown_ids234(_read234("panel", "static", "js", _n234))
check("start hidden: (control) the reader finds the ids the scripts show by style.display",
      {"cfg-form", "editor-wrap", "pl-empty", "connect-join", "cron-cancel"} <= _shown234,
      repr(sorted(_shown234)[:12]))
_bad_hide234, _marked234 = [], []
for _k234 in ("detail", "files"):
    for _tag234 in _TAG234.findall(_pages234.get(_k234, (0, ""))[1]):
        _id234 = _re234.search(r'\bid="([\w-]+)"', _tag234)
        if not _id234 or _id234.group(1) not in _shown234:
            continue
        _cls234 = (_re234.search(r'\bclass="([^"]*)"', _tag234) or [None, ""])[1]
        if _re234.search(r"\bd-none\b", _cls234) or _re234.search(r"\shidden(?:[\s>=]|$)", _tag234):
            _bad_hide234.append(_id234.group(1))
        if "data-start-hidden" in _tag234:
            _marked234.append(_id234.group(1))
check("start hidden: no element the scripts show by style.display is hidden by d-none or the hidden "
      "attribute (both are !important, so style.display = '' would never show it)", not _bad_hide234,
      repr(_bad_hide234))
check("start hidden: the elements those scripts reveal start hidden by the mark: the config form, the "
      "editor, the players' empty line, the Join button and the cron edit's Cancel",
      {"cfg-form", "editor-wrap", "pl-empty", "connect-join", "cron-cancel"} <= set(_marked234),
      repr(sorted(_marked234)))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. What replaced the attributes
# ════════════════════════════════════════════════════════════════════════════════════════════════
_B1_CLASS234 = _re234.compile(r"^(?:fs-r\d+|fx\d?-\d+|hs-r\d+|minh-\d+em|minw-0|w-1p|w-r\d+|mw-[\w]+|wb-all|"
                              r"pre-wrap-all|cursor-pointer|chart-box-\d+|status-badge-\w+|cron-explain-box|"
                              r"cron-err|fb-row-name|cmp-line-label|gmc-label|sv-[\w-]+|dbm-pre-\w+)$")
_used234 = set()
for _src234 in ([_read234("panel", "templates", n) for n in _TPL234]
                + [_read234("panel", "static", "js", n) for n in _JS234]):
    for _cl234 in _re234.findall(r"""class=\\?["']([^"'{}]*)""", _src234) + _re234.findall(
            r"""(?:className\s*=|_el\(\s*'\w+',|el\(\s*'\w+',|node\(\s*'\w+',)\s*'([^']*)'""", _src234):
        _used234 |= {c for c in _cl234.split() if _B1_CLASS234.match(c)}
_undefined234 = sorted(c for c in _used234 if not _re234.search(r"\.%s\s*[,{]" % _re234.escape(c), _css234))
check("classes: (control) the reader finds the replacement classes in use", len(_used234) >= 40,
      repr(sorted(_used234)))
check("classes: every replacement class the templates and scripts use is defined in panel.css",
      not _undefined234, repr(_undefined234))

# A script that sets an element's className whole drops any class the template gave it, where the
# style attribute it replaced stayed. So no element carrying a replacement class has its className
# rewritten by any script (the cron line, a Minecraft card's world line and the Workshop message keep
# their size by an id rule instead), and the config badge's rewrite keeps its size class.
_classed234 = set()
for _n234 in _TPL234:
    for _tag234 in _TAG234.findall(_read234("panel", "templates", _n234)):
        _id234 = _re234.search(r'\bid="([\w-]+)"', _tag234)
        _cls234 = (_re234.search(r'\bclass="([^"]*)"', _tag234) or [None, ""])[1]
        if _id234 and any(_B1_CLASS234.match(c) for c in _cls234.split()):
            _classed234.add(_id234.group(1))
_rewrites234 = []
_jsdir234 = os.path.join(_root, "panel", "static", "js")
for _n234 in sorted(os.listdir(_jsdir234)):
    if not _n234.endswith(".js"):
        continue
    _code234 = _js_code234(_read234("panel", "static", "js", _n234))
    for _m234 in _re234.finditer(r"\b(\w+)\s*=\s*(?:document\.getElementById|el|\$)\(\s*'([\w-]+)'\s*\)", _code234):
        _var234, _id234 = _m234.groups()
        if _id234 not in _classed234:
            continue
        # Only until the name is bound again: `var box` is a different element in another function.
        _rest234 = _code234[_m234.end():]
        _next234 = _re234.search(r"\b%s\s*=(?!=)" % _re234.escape(_var234), _rest234)
        if _re234.search(r"\b%s\.className\s*=" % _re234.escape(_var234), _rest234[:_next234.start() if _next234 else None]):
            _rewrites234.append("%s: %s" % (_n234, _id234))
check("classes: (control) the classed-element reader finds the replacement classes on ids",
      {"cfg-raw", "mcl-box", "cmpc-filter"} <= _classed234, repr(sorted(_classed234)[:8]))
check("classes: no script rewrites the whole className of an element that carries a replacement class",
      not _rewrites234, repr(_rewrites234))
check("classes: the cron line, a Minecraft card's world line and the Workshop message keep their size "
      "by id, whatever class their scripts set",
      _re234.search(r"#cron-desc\s*\{\s*font-size:\s*\.8rem", _css234) is not None
      and _re234.search(r"#gm-mc-world,\s*#gm-mcb-world,\s*#wsc-msg\s*\{\s*min-height:\s*1\.5em", _css234) is not None
      and "b.className='badge cfg-set-badge fs-r55 " in _sfjs234_full, "")

_sdjs234 = _read234("panel", "static", "js", "server_detail.js")
_live234 = _re234.search(r"badge\.style\.background = status === 'online' \? '(#\w+)' : \(status === 'offline' \? "
                         r"'(#\w+)' : '(#\w+)'\)", _sdjs234)
_first234 = [(_re234.search(r"\.status-badge-%s\s*\{\s*background:\s*(#\w+);" % s, _css234) or [None, None])[1]
             for s in ("online", "offline", "other")]
check("status badge: its first colour per status is the one the script recolours it with live",
      _live234 is not None and list(_live234.groups()) == _first234, repr((_live234 and _live234.groups(), _first234)))
_sd_html234 = _pages234.get("detail", (0, ""))[1]
check("status badge: the page draws an online server's badge with the online class",
      _re234.search(r'<span class="badge status-badge-online" id="status-badge">', _sd_html234) is not None,
      _sd_html234[_sd_html234.find('id="status-badge"') - 80:][:120])

_sfjs234 = _js_code234(_read234("panel", "static", "js", "server_files.js"))
check("config groups: a closed group is hidden through the CSSOM after it is inserted, and its toggle "
      "reads the same style.display",
      "if(!open) g.lastElementChild.querySelector('[data-accbody]').style.display='none';" in _sfjs234
      and "if(body.style.display==='none'){ body.style.display='';" in _sfjs234, "")

_AO_PROG234 = (
    "const made = [];\n"
    "function mk(tag){ const e = {tag, className: '', style: {}, innerHTML: '', attrs: {},\n"
    "  setAttribute(n, v){ this.attrs[n] = v; }, addEventListener(){}, remove(){}};\n"
    "  made.push(e); return e; }\n"
    "global.document = {createElement: mk, addEventListener(){}, removeEventListener(){},\n"
    "  body: {appendChild(e){ this.last = e; }}};\n"
    "global.escapeHtml = s => String(s);\n"
    + _cut47(_read234("panel", "static", "js", "server_actions.js"), "function showActionOutput(") + "\n"
    "showActionOutput('Out', 'a<b', true);\n"
    "const ov = document.body.last;\n"
    "console.log(JSON.stringify({cls: ov.className, style: Object.keys(ov.style), attr: ov.attrs,\n"
    "  styled: /style=/.test(ov.innerHTML), pre: /<pre class=\"sv-output-pre\">a<b<\\/pre>/.test(ov.innerHTML)}));\n")
_ao234 = _node47(_AO_PROG234)
if _ao234 is None:
    skip("action output: the dialog is a classed overlay with no inline style", "no node")
else:
    check("action output: the dialog is a classed overlay above the server page's others, with no inline "
          "style and no style attribute in its markup",
          _ao234 == {"cls": "sv-overlay sv-overlay-top", "style": [], "attr": {}, "styled": False, "pre": True},
          repr(_ao234))

check("part234: no host call left the process", len(_P9_TRIPPED) == _TRIP234, repr(_P9_TRIPPED[_TRIP234:]))
