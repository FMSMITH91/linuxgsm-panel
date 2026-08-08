#!/usr/bin/env python3
"""Static lint of every data-action control in the templates.

base.html's dispatcher calls ``window[data-action](...data-args)``, resolving ``"@self"`` to the
clicked element. Two ways a button silently breaks, both invisible until someone clicks it:

  1. the handler doesn't exist  -> ``typeof fn !== 'function'`` -> the click does NOTHING;
  2. the handler takes a DOM-element param (btn/cb/el/...) but the button's data-args omit ``"@self"``
     -> the param is ``undefined`` and the handler throws on ``.innerHTML``/``.disabled`` before doing
     anything (exactly the "Send test" bug: data-args=["telegram"] for testChannel(channel, btn)).

This test fails on either across every template, so a mis-wired button can't ship. Static-only (no
browser); run directly:  python tests/template_actions_test.py
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"

# Param names that, by this codebase's convention, are a DOM element passed via "@self".
ELEMENT_PARAMS = {"btn", "cb", "el", "elem", "checkbox", "input", "button", "target", "chk", "node", "link"}
# DOM-node methods/props — used to confirm a param is really treated as an element.
_ELEM_MEMBER = (r"\.(innerHTML|outerHTML|disabled|checked|value|closest|classList|dataset|"
                r"getAttribute|setAttribute|removeAttribute|querySelector|querySelectorAll|"
                r"appendChild|focus|blur|remove|style|textContent|parentNode|children)\b")

results = []


def check(cond, name, detail=""):
    results.append((bool(cond), name, detail))


# base.html's dispatcher and most of its handlers now live in a cacheable static file rather than
# inline, so the handler definitions this test resolves against are in static/js as well as in the
# templates. Both are searched; the filename is only ever used for reporting.
STATIC_JS = ROOT / "static" / "js"
srcs = {p.name: p.read_text(encoding="utf-8") for p in sorted(TEMPLATES.glob("*.html"))}
srcs.update({p.name: p.read_text(encoding="utf-8") for p in sorted(STATIC_JS.glob("*.js"))})

# ── 0. inline <script> blocks must still be JavaScript ────────────────────────────────────────
# Jinja strips {# … #} before the browser ever sees it, so a comment inside a <script> renders
# fine and looks harmless. Static analysers read the TEMPLATE, though, and to a JS parser "{#" is
# a private-field sigil: CodeQL raised two js/syntax-error alerts on exactly this. A whole file
# that fails to parse is a file nothing is checking, which is the real cost.
_INLINE_SCRIPT = re.compile(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)
_jinja_in_js = []
for _name, _src in srcs.items():
    if not _name.endswith(".html"):
        continue
    for _m in _INLINE_SCRIPT.finditer(_src):
        for _c in re.finditer(r"\{#.*?#\}|\{%.*?%\}", _m.group(1), re.S):
            _line = _src[:_m.start(1) + _c.start()].count("\n") + 1
            _jinja_in_js.append("%s:%d %s" % (_name, _line, " ".join(_c.group(0).split())[:48]))
check(not _jinja_in_js,
      "templates: no Jinja statement/comment tags inside an inline <script> (they break JS parsers)",
      "; ".join(_jinja_in_js[:4]))

# ── 0b. the server tab bar is the SAME set of destinations on both pages ──────────────────────
# server_detail.html and server_files.html each render the tab strip, and server_files.html even
# documents the rule ("same set as the server detail page"). It drifted anyway: History was on the
# detail page only, so from Files & Config there was no way to reach it. Prose does not enforce
# itself, so compare the two.
def _tab_labels(src, nav_id):
    m = re.search(r'<ul[^>]*id="%s"[^>]*>(.*?)</ul>' % nav_id, src, re.S)
    if not m:
        return None
    out = []
    for li in re.findall(r"<li\b.*?</li>", m.group(1), re.S):
        if "toggleLayoutEdit" in li:
            continue      # a control, not a destination — the detail page alone can rearrange
        text = re.sub(r"<[^>]+>", "", li)
        text = re.sub(r"\s+", " ", text).replace("&amp;", "&").strip()
        if text:
            out.append(text)
    return out


_detail_tabs = _tab_labels(srcs.get("server_detail.html", ""), "sdtab-nav")
_files_tabs = _tab_labels(srcs.get("server_files.html", ""), "sftab-nav")
check(_detail_tabs and _files_tabs and _detail_tabs == _files_tabs,
      "templates: Files & Config offers the same server tabs, in the same order, as the detail page",
      "detail=%s files=%s" % (_detail_tabs, _files_tabs))

# ── 0c. confirmDialog's raw `body:` may only carry markup the panel itself wrote ───────────────
# The dialog has three body options: bodyText (assigned via textContent — safe for anything),
# bodyNode (a DOM node, appended), and body (interpolated straight into innerHTML). Only the last
# is an HTML sink, and it exists so a caller can bold a word. Today both callers escape their one
# dynamic value with escapeHtml(); this makes that a rule rather than a habit, because the day one
# does not is an XSS carrying the server's own data.
def _direct_body_args(src):
    """Every `body:` that is a DIRECT key of a confirmDialog({...}) call, with its expression.

    Walks brace/paren depth rather than pattern-matching: the onConfirm callbacks are full of
    fetch(..., {body: JSON.stringify(...)}), which is a different `body` entirely."""
    out = []
    for m in re.finditer(r"confirmDialog\s*\(\s*\{", src):
        i, depth, key_start = m.end(), 1, m.end()
        while i < len(src) and depth:
            ch = src[i]
            if ch in "\'\"":                       # skip over a string literal wholesale
                q, i = ch, i + 1
                while i < len(src) and src[i] != q:
                    i += 2 if src[i] == "\\" else 1
            elif ch in "{([":
                depth += 1
            elif ch in "})]":
                depth -= 1
                if not depth:
                    break
            elif ch == "," and depth == 1:
                key_start = i + 1
            elif depth == 1 and src.startswith("body", i) and re.match(r"body\s*:", src[i:]):
                if src[key_start:i].strip() in ("", ","):      # a key, not part of another word
                    j, d2 = i + src[i:].index(":") + 1, 0
                    val = []
                    while j < len(src):
                        c = src[j]
                        if c in "\'\"":
                            q = c; val.append(c); j += 1
                            while j < len(src) and src[j] != q:
                                val.append(src[j]); j += 2 if src[j] == "\\" else 1
                            val.append(q)
                        elif c in "{([":
                            d2 += 1; val.append(c)
                        elif c in "})]":
                            if d2 == 0:
                                break
                            d2 -= 1; val.append(c)
                        elif c == "," and d2 == 0:
                            break
                        else:
                            val.append(c)
                        j += 1
                    out.append((src[:i].count("\n") + 1, "".join(val).strip()))
            i += 1
    return out


_raw_body = []
for _name, _src in srcs.items():
    for _line, _expr in _direct_body_args(_src):
        # Strip the literal text so only the code skeleton is left.
        _bare = re.sub(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", "", _expr)
        # escapeHtml(x) is the sanctioned wrapper — remove the whole call, argument included. _esc
        # is server_detail.html's one-line alias for it. Named explicitly, so the allow-list stays a
        # short reviewable list rather than "anything that looks like a call".
        _bare = re.sub(r"(?:escapeHtml|_esc)\s*\((?:[^()]|\([^()]*\))*\)", "", _bare)
        # Only CONCATENATION injects. `body: body` hands over a string built (and escaped) above,
        # and `note ? … : …` is a truthiness test — neither puts the identifier into the markup.
        # `'<b>' + name` does, and that is the shape this looks for.
        _dyn = (re.findall(r"\+\s*([A-Za-z_$][\w$.]*)", _bare)
                + re.findall(r"([A-Za-z_$][\w$.]*)\s*\+", _bare))
        if _dyn:
            _raw_body.append("%s:%d %s" % (_name, _line, ", ".join(sorted(set(_dyn)))[:48]))
check(not _raw_body,
      "confirmDialog: a raw body: interpolates nothing but escapeHtml() output (bodyText is the safe one)",
      "; ".join(_raw_body[:3]))

# ── 0d. no NEW unescaped value may reach an HTML sink in static/js ────────────────────────────
# Moving the page scripts out of the templates put 306KB of JavaScript in front of the analysers
# for the first time, and ~200 innerHTML findings appeared — on code that had not changed. Reading
# them found one that mattered: the map name, which the QUERIED GAME SERVER supplies, went into
# innerHTML raw on two pages. That is fixed; this stops the next one.
#
# Of 258 HTML sinks, 219 are provably static or escaped. The remainder are numbers from our own
# API and markup fragments composed a few lines above, which this cannot follow — so they are
# recorded in tests/html_sink_baseline.json by the NAMES they interpolate. A new unescaped value
# is a new name, and fails. Shrinking the baseline is always welcome; growing it needs a reason.
_ESCAPERS = ("escapeHtml", "_esc", "esc", "e")
_SINK = re.compile(r"(\.innerHTML|\.outerHTML)\s*=\s*|insertAdjacentHTML\s*\(")


def _js_expr_at(src, i):
    """One JS expression from i, stopping at a statement end outside any bracket or string."""
    out, depth = [], 0
    while i < len(src):
        c = src[i]
        if c in "'\"`":
            q = c; out.append(c); i += 1
            while i < len(src) and src[i] != q:
                out.append(src[i]); i += 2 if src[i] == "\\" else 1
            out.append(q)
        elif c in "([{":
            depth += 1; out.append(c)
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1; out.append(c)
        elif c == ";" and depth == 0:
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


_found = {}
for _p in sorted((ROOT / "static" / "js").glob("*.js")):
    _src = _p.read_text(encoding="utf-8")
    for _m in _SINK.finditer(_src):
        _expr = _js_expr_at(_src, _m.end())
        _bare = re.sub(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|`(?:[^`\\]|\\.)*`", "", _expr)
        for _fn in _ESCAPERS:
            _bare = re.sub(r"\b%s\s*\((?:[^()]|\([^()]*\))*\)" % _fn, "", _bare)
        _dyn = sorted(set(re.findall(r"\+\s*([A-Za-z_$][\w$.]*)", _bare)
                          + re.findall(r"([A-Za-z_$][\w$.]*)\s*\+", _bare)))
        if _dyn:
            _found.setdefault(_p.name, set()).add(",".join(_dyn))

_baseline = json.loads((ROOT / "tests" / "html_sink_baseline.json").read_text(encoding="utf-8"))
_new = sorted("%s: %s" % (f, sig) for f, sigs in _found.items()
              for sig in sigs if sig not in _baseline.get(f, []))
check(not _new,
      "static/js: no NEW unescaped value reaches innerHTML (wrap it in escapeHtml, or explain it "
      "in tests/html_sink_baseline.json)",
      "; ".join(_new[:3]))

# ── 1. gather every global function definition: name -> (params, body) ──
_DEFS = [
    re.compile(r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{"),
    re.compile(r"(?:window\.)?([A-Za-z_$][\w$]*)\s*=\s*function\s*\(([^)]*)\)\s*\{"),
    re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\(([^)]*)\)\s*=>"),
]
defs = {}
for src in srcs.values():
    for pat in _DEFS:
        for m in pat.finditer(src):
            name = m.group(1)
            params = [p.strip().split("=")[0].strip() for p in m.group(2).split(",") if p.strip()]
            defs.setdefault(name, (params, src[m.end():m.end() + 3000]))
defined = set(defs)

# Actions a template wires up with its OWN delegated listener (closest('[data-action="x"]'))
# instead of the global window[name] dispatcher — those don't need a global function.
_DELEGATED = re.compile(r"""\[data-action=["']([A-Za-z_$][\w$]*)["']\]""")
delegated = {m.group(1) for src in srcs.values() for m in _DELEGATED.finditer(src)}
handled = defined | delegated

# ── 2. gather every data-action usage: (name, parsed_args_or_None, where) ──
_STATIC = re.compile(r'data-action="([A-Za-z_$][\w$]*)"([^>]*)')
_DATA_ARGS = re.compile(r"data-args='(\[.*?\])'")
_DA = re.compile(r"_da\(\s*'([A-Za-z_$][\w$]*)'\s*(?:,\s*(\[[^\]]*\]))?\s*\)")
uses = []


def _is_real_attr(src, start):
    """True when this data-action match is a real HTML attribute — not a `[data-action=...]` selector
    string, and not inside a // comment (both appear in the templates' inline JS)."""
    if start > 0 and src[start - 1] == "[":
        return False
    line_start = src.rfind("\n", 0, start) + 1
    return "//" not in src[line_start:start]


def _parse_args(raw):
    """Best-effort JSON parse of a simple args array; None if it holds JS expressions we can't
    statically resolve (those still get the handler-exists check, just not the @self check)."""
    if raw is None:
        return None
    try:
        return json.loads(raw.replace("&#39;", "'").replace("'", '"'))
    except (ValueError, TypeError):
        return None


for fname, src in srcs.items():
    for m in _STATIC.finditer(src):
        if not _is_real_attr(src, m.start()):
            continue
        am = _DATA_ARGS.search(m.group(2))
        uses.append((m.group(1), _parse_args(am.group(1) if am else None), fname))
    for m in _DA.finditer(src):
        uses.append((m.group(1), _parse_args(m.group(2)), fname))

# ── Check 1: every referenced handler is actually defined (or template-delegated) ──
missing = sorted({n for n, _, _ in uses if n not in handled})
check(not missing, "every data-action handler is defined",
      "undefined handler(s): %s" % ", ".join(missing))

# ── Check 2: a handler's DOM-element param is passed "@self" ──
mismatches = []
for name, args, where in uses:
    if name not in defs or args is None:
        continue
    params, body = defs[name]
    for i, p in enumerate(params):
        if p not in ELEMENT_PARAMS:
            continue
        if not re.search(r"\b" + re.escape(p) + _ELEM_MEMBER, body):
            continue   # the param isn't actually used as a DOM node here
        got = args[i] if i < len(args) else "<missing>"
        if got != "@self":
            mismatches.append("%s (%s): element arg '%s' (position %d) must be \"@self\", got %r"
                              % (name, where, p, i, got))
check(not mismatches, "element-arg handlers receive @self", "; ".join(mismatches))

# ── report ──
passed = sum(1 for c, _, _ in results if c)
for c, name, detail in results:
    print("%s  %s%s" % ("PASS" if c else "FAIL", name, "" if c else "  -> " + detail))
print("\n%d / %d checks passed" % (passed, len(results)))
sys.exit(0 if passed == len(results) else 1)
