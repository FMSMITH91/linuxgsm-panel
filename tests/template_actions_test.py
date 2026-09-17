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


def skip(name, reason):
    """Record a check that did NOT run, as a SKIP — never as a pass.

    The JS-parse gate needs esprima, which is optional locally and installed in CI. Recording that
    as `check(True, "… (SKIPPED)")` printed PASS: a green line for a gate that parsed nothing, and
    the one time it mattered would be the time someone trusted it. Counted apart and printed
    loudly instead."""
    results.append((None, name, reason))


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
# Only script elements a JS parser actually reads: no src=, and either no type or a JS one.
# A <script type="application/json"> data island is not JavaScript — nothing parses it as JS,
# so Jinja inside it cannot produce the syntax error this check exists to prevent.
_INLINE_SCRIPT = re.compile(
    r"<script\b(?![^>]*\bsrc=)(?![^>]*\btype=\"(?:application|text)/(?!javascript)[\w.+-]+\")"
    r"[^>]*>(.*?)</script>", re.S)
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

# ── 0a. every static/js file must actually be JavaScript ──────────────────────────────────────
# Nothing here ever parsed the JS. Python tests render the pages but never execute a line of it,
# so a syntax error ships silently and the whole file is simply dead in the browser — which is
# exactly what happened: a trailing comment appended to a one-line if() swallowed the rest of the
# statement, dashboard.js stopped parsing, and 294 smoke checks stayed green.
try:
    import esprima
except ImportError:
    esprima = None
    skip("static/js: every file parses as JavaScript", "esprima not installed (pip install esprima)")
if esprima:
    _broken = []
    for _p in sorted((ROOT / "static" / "js").glob("*.js")):
        try:
            esprima.parseScript(_p.read_text(encoding="utf-8"))
        except Exception as _e:
            _broken.append("%s: %s" % (_p.name, _e))
    check(not _broken, "static/js: every file parses as JavaScript", "; ".join(_broken[:3]))

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
        # Comments are SKIPPED, not read. A trailing `// …` on a sink line is prose, and prose
        # contains semicolons and apostrophes — which this loop would otherwise treat as "the
        # statement ended" and "a string opened". Both make the scanned expression SHORTER, i.e.
        # fewer interpolated names flagged, which is the one direction a gate must never fail in.
        # Demonstrated while annotating tailscale.js: a `// nosemgrep - …; the latency is Number()`
        # cut the line-77 expression off at the semicolon and its signature silently lost two names.
        if src[i:i + 2] == "//":
            i = src.find("\n", i)
            if i == -1:
                break
            continue
        if src[i:i + 2] == "/*":
            j = src.find("*/", i + 2)
            i = len(src) if j == -1 else j + 2
            continue
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


_ESC_ALIAS_FN = (r"function\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{\s*"
                 r"return\s+(?:window\.)?(?:%s)\s*\(\s*\2\s*\)\s*;?\s*\}")
_ESC_ALIAS_VAR = r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:window\.)?(?:%s)\s*;"


def _escapers_in(src):
    """_ESCAPERS plus this file's own one-line pass-through aliases.

    `function tsEsc(s){ return window.escapeHtml(s); }` is an escaper by any reading, but the scan
    below only knew the names in _ESCAPERS — so the moment the Tailscale pages' scripts moved out
    of a <script> block and into static/js, four provably-escaped sinks read as unescaped and
    wanted twelve baseline entries. Detecting the alias keeps the baseline a reviewable list.

    Deliberately exact: same single parameter, handed straight back out, nothing else in the body.
    Anything that transforms its argument is not a pass-through and does not count."""
    names = set(_ESCAPERS)
    for _ in range(3):                      # aliases of aliases; `var escA = esc` is one already
        alt = "|".join(re.escape(n) for n in sorted(names))
        grew = False
        for pat in (_ESC_ALIAS_FN % alt, _ESC_ALIAS_VAR % alt):
            for m in re.finditer(pat, src):
                if m.group(1) not in names:
                    names.add(m.group(1))
                    grew = True
        if not grew:
            break
    return tuple(sorted(names))


_found = {}
for _p in sorted((ROOT / "static" / "js").glob("*.js")):
    _src = _p.read_text(encoding="utf-8")
    for _m in _SINK.finditer(_src):
        _expr = _js_expr_at(_src, _m.end())
        # Drop comments first: a trailing "// nosemgrep" would otherwise read as an interpolation.
        _expr_nc = re.sub(r"//[^\n]*|/\*.*?\*/", "", _expr, flags=re.S)
        _bare = re.sub(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|`(?:[^`\\]|\\.)*`", "", _expr_nc)
        for _fn in _escapers_in(_src):
            _bare = re.sub(r"\b%s\s*\((?:[^()]|\([^()]*\))*\)" % _fn, "", _bare)
        # The \(* / \)* matter: `'…' + (d.url || '') + '…'` is the single most common way a value
        # is interpolated here, and without them the identifier is never adjacent to the `+` —
        # the whole expression reads as "nothing dynamic". That blind spot hid a real unescaped
        # remote-host value (s.tailscale_ip, manage_remotes.js) through a review that was
        # explicitly looking for it. Cheap to allow; it costs some ternary CONDITIONS showing up
        # as names, which is the safe direction for a gate that only has to notice a NEW one.
        _dyn = sorted(set(re.findall(r"\+\s*\(*\s*([A-Za-z_$][\w$.]*)", _bare)
                          + re.findall(r"([A-Za-z_$][\w$.]*)\s*\)*\s*\+", _bare)))
        if _dyn:
            _found.setdefault(_p.name, set()).add(",".join(_dyn))

# ── 0d-ii. ...including markup ACCUMULATED into a variable first ───────────────────────────────
# The scan above only reads the expression sitting directly at a sink. That is a real blind spot,
# and it hid a real bug: manage_remotes.js builds `html` across a dozen `html += '<…>' + value`
# lines and then hands it to setModalBody(), which does `el.innerHTML = html`. At the sink the
# expression is the bare identifier `html` — nothing dynamic, nothing to report — so four
# remote-host-controlled values (tailscale_ip, dns_name, old_host, new_host) walked straight past
# the gate that exists to catch exactly them.
#
# This does the one extra hop, and ONLY for the shape that shipped that bug:
#
#   1. find the variables handed to a sink as a bare name — `x.innerHTML = name`,
#      `insertAdjacentHTML(…, name)`, or a call to a helper that assigns its own parameter to
#      innerHTML (setModalBody is the one here; detected, not hardcoded);
#   2. of those, keep the ones BUILT BY APPENDING MARKUP (`name += '…<tag…'`) — that is what makes
#      the variable an HTML buffer rather than a coincidence of naming;
#   3. report a dynamic value only where it is interpolated DIRECTLY ADJACENT to a markup literal,
#      which is the thing that actually injects.
#
# Deliberately narrow. A wider version (any `+` anywhere in any statement building any sink-bound
# name) was tried first and produced a long tail of false positives — reused local names across
# functions, ternary CONDITIONS, helpers that escape internally — which would have had to be
# absorbed into the baseline, and a baseline that large stops being a reviewable list of
# exceptions. Catching the shipped bug shape with no noise beats catching everything with 8.
# Deliberately NOT anchored to the start of a statement. The line that shipped the bug is
#   `if (status.tailscale_ip) html += '<code>' + status.tailscale_ip + '</code>';`
# — the append sits after an `if (…)`, so a start-of-line anchor misses it entirely. Precision
# comes from the `_bound` filter below (the name must actually reach a sink), not from position.
_ACCUM_MARKUP = re.compile(r"""\b([A-Za-z_$][\w$]*)\s*\+=""")

# A dynamic name interpolated straight onto a markup literal: `'…<b>' + value` / `value + '</b>…'`.
# The trailing (?!\s*\?) matters: in `'<td>' + (g.protected ? '<button…' : '<button…')` the name
# is the ternary's CONDITION — it decides which literal is used, it is never itself interpolated.
_ADJACENT = (r"""'[^'\n]*<[A-Za-z/][^'\n]*'\s*\+\s*\(*\s*([A-Za-z_$][\w$.]*)(?![\w$.])(?!\s*\?)""",
             r"""([A-Za-z_$][\w$.]*)\s*\)*\s*\+\s*'[^'\n]*<[A-Za-z/][^'\n]*'""")


def _html_sink_helpers(src):
    """Function names whose single parameter is assigned to .innerHTML/.outerHTML inside them."""
    out = set()
    for name, params, body in _fn_bodies(src):
        param = params.strip()
        if not re.fullmatch(r"[A-Za-z_$][\w$]*", param):
            continue
        if re.search(r"\.(?:inner|outer)HTML\s*=\s*%s\b" % re.escape(param), body):
            out.add(name)
    return out


def _sink_bound_names(src, helpers):
    """Identifiers handed to an HTML sink as a bare name — the ones worth tracing back."""
    names = set()
    for m in re.finditer(r"\.(?:inner|outer)HTML\s*=\s*([A-Za-z_$][\w$]*)\s*;", src):
        names.add(m.group(1))
    for m in re.finditer(r"insertAdjacentHTML\s*\([^,]+,\s*([A-Za-z_$][\w$]*)\s*\)", src):
        names.add(m.group(1))
    for fn in helpers:
        for m in re.finditer(r"\b%s\s*\(\s*([A-Za-z_$][\w$]*)\s*\)" % re.escape(fn), src):
            names.add(m.group(1))
    return names


# Calls that neutralise their argument for the context they land in: the escapers, plus
# encodeURIComponent (a URL-context escaper, and the only thing in an href here) and the byte/date
# formatters, which return digits and units from a number.
# NOT String(): it is a cast, not an escaper — String('<img>') is still '<img>'. Number/parseInt/
# parseFloat are here because they can only ever produce digits, '.', '-', 'e', NaN or Infinity.
_NEUTRAL = _ESCAPERS + ("tsEsc", "specEsc", "escA", "_da", "Number", "parseInt",
                        "parseFloat", "encodeURIComponent", "bkFmtBytes", "bkFmt", "bkAgo",
                        "fmtBytes", "plTime")
# Panel-authored globals rendered into the page by base.html — the mount prefix, the CSRF token,
# the current language, the ids of the thing being viewed. Not request input, and interpolated
# into nearly every URL the JS builds.
_PANEL_GLOBALS = {"MOUNT", "CSRF", "LANG", "I18N", "LOCAL_HOST_ID", "REMOTE_ID", "SERVER_ID",
                  "SERVER_NAME", "IS_LOCAL"}


def _strip_neutral(expr, extra=()):
    """`expr` with every neutralising call replaced by a blank literal."""
    out = re.sub(r"//[^\n]*", "", expr)
    for fn in tuple(_NEUTRAL) + tuple(extra):
        out = re.sub(r"\b%s\s*\((?:[^()]|\([^()]*\))*\)" % fn, "''", out)
    return out


_FN_HEAD = re.compile(r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{")


def _fn_bodies(src):
    """(name, params, body) for every `function name(...) {…}`, bodies brace-balanced.

    A lazy brace-to-newline-brace pattern looks equivalent and is not: re.finditer is
    non-overlapping, so one long
    function whose body has no closing brace in column 0 until much later swallows every definition
    after it. That silently hid protoBadge and cronLastRun from the helper detection below."""
    for m in _FN_HEAD.finditer(src):
        i, depth = m.end(), 1
        while i < len(src) and depth:
            c = src[i]
            if c in "'\"`":
                q, i = c, i + 1
                while i < len(src) and src[i] != q:
                    i += 2 if src[i] == "\\" else 1
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        yield m.group(1), m.group(2), src[m.end():i - 1]


def _safe_markup_helpers(src):
    """Local functions whose every `return` is a string built without an unescaped dynamic value.

    Two shapes, both common here and both safe to call from inside markup:
      * markup fragments — `protoBadge(p)` returns one of four static badges, `blockBadge(c)`
        escapes its argument on the one path that interpolates it, `cronLastRun(j)` formats a date;
      * plain values — `fileIcon(name)` maps a filename to a fixed Bootstrap icon class and never
        puts the name in its output at all.

    The second kind has no '<' in it, which is why "returns markup" was the wrong test: it left
    `'<i class="bi '+fileIcon(e.name)+'">'` reading as an unescaped e.name."""
    out = set()
    for name, _params, body in _fn_bodies(src):
        rets = re.findall(r"\breturn\s+([^\n;]+)", body)
        if not rets or not any("'" in r or '"' in r for r in rets):
            continue
        if all(not {d for pat in _ADJACENT for d in re.findall(pat, _strip_neutral(r))}
               for r in rets):
            out.add(name)
    return out


def _safe_locals(src):
    """Locals that hold markup which is already safe, to a fixed point.

    Two kinds, and both are used constantly in this codebase:
      * escaper output — `var safe = escapeHtml(name)`;
      * a markup FRAGMENT built from literals and other safe locals — `var kind = cond ? '<span
        class="badge">daily</span>' : '<span class="badge">manual</span>'`.

    Without this the scan reports the safe variable exactly as if it were the raw value. Iterated
    rather than done in one pass because fragments nest: server_files.js builds `actions` out of
    `runBtn`, which is itself literal-only."""
    safe = set()
    for fn in _ESCAPERS + ("tsEsc", "specEsc", "escA"):
        for m in re.finditer(
                r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*%s\s*\(" % re.escape(fn), src):
            safe.add(m.group(1))
    decls = [(m.group(1), _js_expr_at(src, m.end()))
             for m in re.finditer(r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*", src)]
    for _ in range(6):                      # a fixed point; 6 is far more nesting than exists here
        grew = False
        for name, expr in decls:
            if name in safe:
                continue
            clean = _strip_neutral(expr)
            dyn = {d for pat in _ADJACENT for d in re.findall(pat, clean)}
            # Also anything concatenated with a safe fragment, not just with a literal.
            if dyn - safe:
                continue
            if "<" in expr:                 # it is markup, and nothing unescaped reaches it
                safe.add(name)
                grew = True
        if not grew:
            break
    return safe


for _p in sorted((ROOT / "static" / "js").glob("*.js")):
    _src = _p.read_text(encoding="utf-8")
    _bound = _sink_bound_names(_src, _html_sink_helpers(_src))
    _helpers = _safe_markup_helpers(_src)
    _safe = _safe_locals(_src)
    # Case A: the markup is passed straight to a sink helper as an EXPRESSION, not via a
    # variable — `setModalBody('<p>Old host: <code>' + data.old_host + '</code>' + …)`. The bare-name
    # scan above cannot see this one, and it is where two of the four shipped values lived.
    for _fn in sorted(_html_sink_helpers(_src)):
        for _m in re.finditer(r"\b%s\s*\(" % re.escape(_fn), _src):
            _expr = _js_expr_at(_src, _m.end())
            if not re.search(r"'[^'\n]*<[A-Za-z/]", _expr):
                continue
            _clean = _strip_neutral(_expr, _helpers)
            _dyn = sorted({d for pat in _ADJACENT for d in re.findall(pat, _clean)}
                          - set(_safe) - _PANEL_GLOBALS)
            if _dyn:
                _found.setdefault(_p.name, set()).add(",".join(_dyn))

    # Case B: the markup is accumulated into a variable that later reaches a sink.
    for _m in _ACCUM_MARKUP.finditer(_src):
        _name = _m.group(1)
        if _name not in _bound:
            continue                     # not an HTML buffer that reaches a sink
        _expr = _js_expr_at(_src, _m.end())
        _clean = _strip_neutral(_expr, _helpers)
        _pats = _ADJACENT + (r"\+\s*\(*\s*([A-Za-z_$][\w$.]*)(?![\w$.])(?!\s*\?)",
                             r"([A-Za-z_$][\w$.]*)\s*\)*\s*\+")
        _dyn = sorted({d for pat in _pats for d in re.findall(pat, _clean)}
                      - set(_safe) - _PANEL_GLOBALS)
        if _dyn:
            _found.setdefault(_p.name, set()).add(",".join(_dyn))

_baseline = json.loads((ROOT / "tests" / "html_sink_baseline.json").read_text(encoding="utf-8"))
_new = sorted("%s: %s" % (f, sig) for f, sigs in _found.items()
              for sig in sigs if sig not in _baseline.get(f, []))
check(not _new,
      "static/js: no NEW unescaped value reaches innerHTML (wrap it in escapeHtml, or explain it "
      "in tests/html_sink_baseline.json)",
      "; ".join(_new[:3]))

# ── 0e. no template renders the same id= twice ────────────────────────────────────────────────
# getElementById returns the FIRST match, so a duplicate id does not fail loudly — it silently
# points every handler at the wrong element. remote_manage.html carried id="diag-repair-btn" on
# BOTH the panel-file restore button and the database repair button, inside the same
# {% if remote.is_local %} block, so checkDbHealth() hid the file-restore button, repairDb()
# relabelled it, and the real "Repair database" button could never be shown at all.
#
# Ids in MUTUALLY EXCLUSIVE Jinja branches are fine and common here (the local-host and remote-host
# variants of the SSH panel use the same ids on purpose), so a flat count over-reports. Track the
# branch path instead: two occurrences collide only when one's branch path is a prefix of the
# other's — i.e. they can both be rendered by the same request.
_ID_ATTR = re.compile(r'\sid="([A-Za-z][\w:.-]*)"')
_JINJA_TAG = re.compile(r"\{%-?\s*(if|elif|else|endif|for|endfor)\b")


def _branch_paths(src):
    """(id, branch-path) for every id= in `src`, where the path identifies the Jinja arm it sits in.

    A new arm at the same depth gets a fresh serial, so `if`-arm 1 and `else`-arm 2 differ at that
    position and can never both render; nesting deeper appends, so an outer arm is a PREFIX of the
    arms inside it — which is exactly the "can both render" relation."""
    out, stack, serial = [], [], [0]
    pos = 0
    for m in _JINJA_TAG.finditer(src):
        for im in _ID_ATTR.finditer(src, pos, m.start()):
            out.append((im.group(1), tuple(stack)))
        kw = m.group(1)
        if kw in ("if", "for"):
            serial.append(0)
            stack.append((len(stack), serial[-1]))
        elif kw in ("elif", "else"):
            if stack:
                serial[-1] += 1
                stack[-1] = (len(stack) - 1, serial[-1])
        elif kw in ("endif", "endfor"):
            if stack:
                stack.pop()
            if len(serial) > 1:
                serial.pop()
        pos = m.end()
    for im in _ID_ATTR.finditer(src, pos):
        out.append((im.group(1), tuple(stack)))
    return out


# Ids that only ever exist inside an inline <script> are built at RUNTIME, and which of them is
# in the DOM is decided by JavaScript control flow this gate cannot model — setup_tailscale.html
# emits id="ts-out" in three branches of one function, each of which returns. Blank the script
# bodies out (keeping the byte count, so offsets and the Jinja scan stay aligned) and judge only
# the markup the template actually renders.
_SCRIPT_BODY = re.compile(r"(<script\b[^>]*>)(.*?)(</script>)", re.S)


def _without_scripts(src):
    return _SCRIPT_BODY.sub(lambda m: m.group(1) + (" " * len(m.group(2))) + m.group(3), src)


_dupe_ids = []
for _tpl in sorted(TEMPLATES.glob("*.html")):
    _seen = {}
    for _id, _path in _branch_paths(_without_scripts(_tpl.read_text(encoding="utf-8"))):
        for _other in _seen.get(_id, []):
            # Both can render iff neither branch path excludes the other.
            _n = min(len(_other), len(_path))
            if _other[:_n] == _path[:_n]:
                _dupe_ids.append("%s: id=%s" % (_tpl.name, _id))
                break
        _seen.setdefault(_id, []).append(_path)
check(not _dupe_ids,
      "templates: no id= is rendered twice in the same page (getElementById takes the first)",
      "; ".join(sorted(set(_dupe_ids))[:5]))

# ── 0f. no JS dereferences an element id that no template renders ─────────────────────────────
# getElementById returns NULL for an id that is not on the page, and `null.value = ''` throws —
# which kills the rest of the handler silently. Removing the password field from the Edit User
# form left manage_users.js still clearing it by id, so opening the edit dialog threw before it
# reached `.show()` and the pencil icon simply did nothing. No test noticed: the route was fine,
# the template was fine, and the two were only wrong about each other.
#
# Deliberately narrow: only the UNGUARDED form, `getElementById('x').something`. The guarded
# `var el = getElementById('x'); if (el) …` is how a script written for several pages checks
# whether it is on the right one — manage_remotes.js does exactly that for four ids belonging to
# a page that no longer has them. Dead, but it cannot crash, and flagging it would push people to
# delete a null check rather than a stale id.
_TPL_IDS = set()
for _tpl in sorted((ROOT / "templates").glob("*.html")):
    _TPL_IDS |= set(re.findall(r'\sid="([A-Za-z][\w:.-]*)"', _tpl.read_text(encoding="utf-8")))
_JS_MADE_IDS = set()
for _js in sorted((ROOT / "static" / "js").glob("*.js")):
    _jsrc = _js.read_text(encoding="utf-8")
    _JS_MADE_IDS |= set(re.findall(r"""\.id\s*=\s*['"]([A-Za-z][\w:.-]*)['"]""", _jsrc))
    _JS_MADE_IDS |= set(re.findall(r"""id=["']([A-Za-z][\w:.-]*)["']""", _jsrc))
_KNOWN_IDS = _TPL_IDS | _JS_MADE_IDS
_DEREF_ID = re.compile(
    r"""(?:getElementById\(\s*['"]|querySelector\(\s*['"]#)([A-Za-z][\w:.-]*)['"]\s*\)\s*[.\[]""")
_dangling = []
for _js in sorted((ROOT / "static" / "js").glob("*.js")):
    for _id in sorted(set(_DEREF_ID.findall(_js.read_text(encoding="utf-8")))):
        if _id not in _KNOWN_IDS:
            _dangling.append("%s: #%s" % (_js.name, _id))
check(not _dangling,
      "static/js: no unguarded getElementById()/querySelector('#id') names an id no template renders",
      "; ".join(_dangling[:5]))

# ── 0g. every Bootstrap toggle points at something that exists ────────────────────────────────
# data-bs-target="#x" with no #x on the page is the other way a button does nothing: Bootstrap
# finds no element, opens no modal, and raises nothing. Same failure the user sees — a click that
# goes nowhere — from the opposite direction to the dangling-id check above.
_bad_targets = []
for _tpl in sorted((ROOT / "templates").glob("*.html")):
    _src = _tpl.read_text(encoding="utf-8")
    for _m in re.finditer(r'data-bs-target="#([A-Za-z][\w:.-]*)"', _src):
        if _m.group(1) not in _KNOWN_IDS:
            _bad_targets.append("%s: #%s" % (_tpl.name, _m.group(1)))
check(not _bad_targets,
      "templates: every data-bs-target names an element that exists",
      "; ".join(_bad_targets[:5]))

# ── 0h. nothing the Content-Security-Policy silently kills ────────────────────────────────────
# script-src is 'self' plus a per-request nonce, with NO 'unsafe-inline'. Two things therefore do
# not run, and neither reports anything a user would see:
#
#   * an inline handler — onclick="foo()". A nonce does not help; inline handlers need
#     'unsafe-inline' specifically. THE bug: the GMod "Apply mounts" button carried an inline
#     onclick and clicking it did nothing (the Settings accent-colour picker's oninput too).
#   * a <script> block with no nonce="{{ csp_nonce }}" — the browser refuses to execute it, so
#     every handler and poller it defines is simply absent.
#
# Both are what a person writes by habit, both look completely normal in review, and both fail
# silently at runtime. The codebase is clean of both today (0 inline handlers, 39/39 scripts
# nonce'd), which is what makes this a gate rather than a baseline.
_ON_ATTR = re.compile(r"""\son(?:click|change|submit|input|keydown|keyup|focus|blur|load|error|"""
                      r"""mouseover|mouseout|dblclick|paste|drop|dragover)\s*=\s*["']""")
_csp_dead = []
for _tpl in sorted((ROOT / "templates").glob("*.html")):
    _src = _tpl.read_text(encoding="utf-8")
    for _m in _ON_ATTR.finditer(_src):
        _csp_dead.append("%s:%d inline %s" % (_tpl.name, _src[:_m.start()].count("\n") + 1,
                                              _m.group(0).strip()))
# `el.onclick = fn` is a PROPERTY assignment and runs fine — the regex needs whitespace before
# `on`, and a property access has a dot there, so those are not matched. Only the attribute shape
# inside JS-built markup is.
for _js in sorted((ROOT / "static" / "js").glob("*.js")):
    _src = _js.read_text(encoding="utf-8")
    for _m in _ON_ATTR.finditer(_src):
        _csp_dead.append("%s:%d inline %s" % (_js.name, _src[:_m.start()].count("\n") + 1,
                                              _m.group(0).strip()))
check(not _csp_dead,
      "CSP: no inline on*= handler anywhere (the policy blocks them; the click does nothing)",
      "; ".join(_csp_dead[:5]))

_SCRIPT_TAG = re.compile(r"<script\b[^>]*>")
_unnonced = []
for _tpl in sorted((ROOT / "templates").glob("*.html")):
    _src = _tpl.read_text(encoding="utf-8")
    for _m in _SCRIPT_TAG.finditer(_src):
        if "nonce=" not in _m.group(0):
            _unnonced.append("%s:%d %s" % (_tpl.name, _src[:_m.start()].count("\n") + 1,
                                           " ".join(_m.group(0).split())[:70]))
check(not _unnonced,
      "CSP: every <script> in a template carries the nonce (without it the browser refuses it)",
      "; ".join(_unnonced[:5]))

# ── 0i. every in-page fetch goes through the mount prefix ─────────────────────────────────────
# The panel can be served under a sub-path (Tailscale Serve at /lgsm), and window.MOUNT carries it.
# A fetch written as '/api/...' instead of MOUNT + '/api/...' hits the site ROOT — a different
# application — so the call 404s and whatever it fed shows nothing. It works perfectly on a direct
# bind, which is where it gets written and reviewed, and only breaks for mount-prefixed installs.
# 132 call sites use MOUNT today and none skip it.
_ABS_FETCH = re.compile(r"""fetch\(\s*['"]/""")
_unmounted = []
for _f in sorted((ROOT / "static" / "js").glob("*.js")) + sorted((ROOT / "templates").glob("*.html")):
    _src = _f.read_text(encoding="utf-8")
    for _m in _ABS_FETCH.finditer(_src):
        _unmounted.append("%s:%d" % (_f.name, _src[:_m.start()].count("\n") + 1))
check(not _unmounted,
      "every fetch() uses window.MOUNT, not a root-absolute path (breaks a sub-path install)",
      "; ".join(_unmounted[:5]))

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

# ── Check 3: no page script is loaded BEFORE panel.js ──────────────────────────────────────────
# base.html renders {% block content %} at line ~300 and loads panel.js at ~324, so a <script src>
# placed inside a page's content block executes FIRST — before panel.js has defined window.toast,
# escapeHtml, confirmDialog, pollWhenVisible and the rest.
#
# This is not theoretical. manage_remotes.html loaded its script that way, and the top-level
# `pollWhenVisible(...)` call at manage_remotes.js:95 threw ReferenceError during evaluation. Every
# top-level STATEMENT after it was skipped — including the delegated click handler that wires the
# Tailscale check / bootstrap / install and Delete-remote buttons. Those four controls silently did
# nothing on /remotes. (Function DECLARATIONS are hoisted, so the page looked fine and the console
# showed one error most people would scroll past.)
#
# Page scripts belong in {% block scripts %}, which base.html renders after panel.js.
_early = []
for _tpl in sorted(TEMPLATES.glob("*.html")):
    if _tpl.name == "base.html":
        continue                     # base owns the ordering; it is the thing being ordered around
    _src = _tpl.read_text(encoding="utf-8")
    if "{% block content %}" not in _src:
        continue
    _seg = _src[_src.index("{% block content %}"):]
    _cut = _seg.find("{% block scripts %}")
    if _cut != -1:
        _seg = _seg[:_cut]           # only what precedes the scripts block can be early
    for _m in re.finditer(r"<script[^>]*\ssrc=", _seg):
        _ln = _src[:_src.index("{% block content %}") + _m.start()].count("\n") + 1
        _early.append("%s:%d" % (_tpl.name, _ln))
check(not _early, "no page loads a script before panel.js (must use {% block scripts %})",
      "; ".join(_early))

# ── the host tile carries two values and must be sized so they fit on one line ───────────
# Every other dashboard tile shows ONE number; #host-summary shows "52.6% · 14.6%". Measured, it
# did not fit at either width: 181px needed against 132px at 375px, and 220px against 143px at
# 1280px where five tiles share the row. It broke after the separator, leaving a dangling "·" and
# a card taller than the four beside it. Dropping the decimals does not fix it (173px at 1280px)
# — it is a width problem.
#
# Two rules carry the fix and BOTH must stay: mobile gives the tile the whole row (it already sits
# alone there in the default order) so the number keeps full size, and ≥768px shrinks the number,
# with a line-height that keeps the card the same height as its neighbours.
_tile_css = (ROOT / "static" / "css" / "panel.css").read_text(encoding="utf-8")
# Matched on the PROPERTY, not one spelling of it. This was `width: 100%` and is now
# `flex: 0 0 100%; max-width: 100%` — a full-row tile either way, but a literal-string gate failed
# the refactor while the thing it protects still held. Accept either, and require a 100% so a rule
# that merely mentions the selector cannot pass.
_host_tile_rule = re.search(
    r'#dash-tiles\s*>?\s*\.col\[data-panel="host"\]\s*\{([^}]*)\}', _tile_css)
check(bool(_host_tile_rule) and "100%" in _host_tile_rule.group(1),
      "dashboard: the host tile takes the full row on mobile",
      "without it the two values wrap mid-number in a half-width tile")
check(re.search(r"#host-summary\s*\{[^}]*font-size[^}]*line-height", _tile_css, re.S) is not None,
      "dashboard: the host tile's value is sized to fit, with the card height preserved",
      "#host-summary needs BOTH a smaller font-size (to fit five-across) and a line-height "
      "(or the smaller number leaves this card shorter than the others)")

# ── the sticky Actions column must take its colour FROM the row, not a fixed value ────────
# On mobile the Actions column is position:sticky so the controls stay reachable while the table
# scrolls sideways. A sticky cell is lifted out of the row's paint order, so it needs an opaque
# background of its own and cannot inherit one — and it was given a hardcoded var(--bg-card).
#
# That is the CARD's colour, not the ROW's: Bootstrap paints cells --bs-table-bg (#212529), which
# is LIGHTER than the card (#111827). So on every row the highlight visibly stopped where the
# Actions column began. Reported from a phone as "the gray doesn't go all the way across".
#
# The fix is to read Bootstrap's own variables, so the column tracks the row through hover and
# striping without this file knowing what those states look like. Anything hardcoded here is the
# bug coming back, so the gate is "derives from the table variables", not "is some colour".
_css = (ROOT / "static" / "css" / "panel.css").read_text(encoding="utf-8")
_m = re.search(r"\.table-responsive\s+\.table\s+th\.col-actions\s*,\s*"
               r"\.table-responsive\s+\.table\s+td\.col-actions\s*\{(.*?)\}", _css, re.S)
check(_m is not None, "mobile: the sticky Actions column rule is still there to check",
      "the .col-actions sticky block was renamed — re-point this gate at it")
if _m:
    # Strip /* ... */ as a BLOCK, not per line. The rule's own comment names the variables it
    # uses, and a per-line strip left those words in — so the gate read its own explanation as the
    # declaration and passed with the hardcoded colour restored. Verified by mutation after fixing.
    _code = re.sub(r"/\*.*?\*/", "", _m.group(1), flags=re.S)
    check("var(--bs-table-bg)" in _code and "var(--bs-table-accent-bg)" in _code
          and "--bg-card" not in _code,
          "mobile: the sticky Actions column paints the ROW's background, not a fixed colour",
          "it must use var(--bs-table-bg) + var(--bs-table-accent-bg) so it tracks the row; "
          "a hardcoded colour leaves the column a different shade from the row it sits in")

# ── every asset_url()/static file a template names must actually exist ─────────────────────────
# A <script src> pointing at a file that is not there fails SILENTLY: the browser logs one 404 and
# the page renders perfectly, minus every behaviour that script was carrying. No route test, no
# template test and no render notices, because each side is individually fine.
#
# This became a live risk when the pages' inline <script> blocks moved into static/js: a rename or
# a dropped file is now a dead page rather than a syntax error. asset_url() also content-hashes
# what it finds, so a missing file loses the cache-busting query too.
_missing = []
for _tpl in sorted(TEMPLATES.rglob("*.html")):
    _src = _tpl.read_text(encoding="utf-8")
    for _m in re.finditer(r"(?:asset_url|url_for)\s*\(\s*(?:'static'\s*,\s*filename\s*=\s*)?"
                          r"['\"]([^'\"]+)['\"]", _src):
        _rel = _m.group(1)
        if "{" in _rel or not re.search(r"\.(js|css)$", _rel):
            continue                     # a Jinja-built path, or not an asset this can resolve
        if not (ROOT / "static" / _rel).is_file():
            _missing.append("%s -> static/%s" % (_tpl.name, _rel))
check(not _missing, "every js/css asset a template names exists in static/", "; ".join(_missing))

# ── upload drop zone: the browser's own drop handler must stay suppressed ─────────────────────
# THE bug this guards: anything dropped on a page that has not called preventDefault() on dragover
# is handled by the BROWSER, which navigates the tab to the dropped file. The drop target used to
# be the file-list panel alone — a few centimetres tall when the listing is short — so a near miss
# opened the file in a new tab and the panel looked like it did not support drag and drop at all.
# It was reported as "on linux i cant drag and drop my files into the file browser", and the Linux
# part was a red herring: it behaves the same everywhere.
#
# Static, because the real proof is a browser dropping a real folder, and there is no JS test
# runner here. This only refuses the specific silent regression: losing the document-level
# suppression, or shrinking the target back to the list.
_sf = (STATIC_JS / "server_files.js").read_text(encoding="utf-8")
# Scope the assertions to the drop-wiring block. `document.addEventListener` appears elsewhere in
# this file, so a whole-file substring test passed even with the suppression deleted — it has to be
# THIS block that registers it.
_dropwire = ""
_dw_start = _sf.find("// Drag & drop upload")
if _dw_start != -1:
    _dw_end = _sf.find("\n})();", _dw_start)
    _dropwire = _sf[_dw_start:_dw_end if _dw_end != -1 else len(_sf)]
check(bool(_dropwire), "uploads: the drag & drop wiring block is still identifiable",
      "the '// Drag & drop upload' block is gone or was renamed")
check("document.addEventListener" in _dropwire and "dragover" in _dropwire,
      "uploads: the page suppresses the browser's default drop (a near miss must not navigate)",
      "the drop wiring no longer registers a DOCUMENT-level dragover/drop handler")
check("getElementById('file-browser')" in _dropwire,
      "uploads: the drop target is the whole File Browser card, not just the file list",
      "the drop wiring no longer resolves #file-browser")
# readEntries() returns at most 100 children per call and ends with an empty batch, so it has to be
# called in a loop. Reading once truncates any real addon tree to its first 100 files, silently.
check(_sf.count("readEntries") >= 1 and "kids = kids.concat" in _sf,
      "uploads: directory reads loop until the batch is empty (readEntries caps at 100)",
      "the recursive folder walk no longer accumulates batches")
# confirmDialog REMOVES its overlay before calling onConfirm, so any state the dialog collected has
# to be read out of the node the caller passed as bodyNode — a document-wide query matches nothing
# by then and silently reads as "unticked". Both upload dialogs got this wrong: the per-file
# "Replace existing file?" ticks never replaced anything, and neither did the folder dialog's
# "Replace files that already exist". Reported as "i check overwrite files...it doesnt overrite
# them". The tags dialog in manage_servers.html had it right all along (body.querySelectorAll).
for _bad, _what in (("document.querySelectorAll('[data-ovw]')", "per-file conflict state"),
                    ("getElementById('fb-ovw-all')", "folder replace-all state")):
    check(_bad not in _sf,
          "uploads: %s comes from the dialog node, not the document" % _what,
          "confirmDialog has already removed the overlay when onConfirm runs, so %r finds nothing "
          "and every tick is silently discarded" % _bad)
check("webkitGetAsEntry" in _sf and "webkitRelativePath" in _sf,
      "uploads: folders arrive by both routes — dropped (webkitGetAsEntry) and picked (webkitRelativePath)",
      "one of the two folder-upload paths is gone")

# ── dashboard: destructive actions must confirm, as the detail page has always done ────────────
# Restart and Stop disconnect players. The server detail page confirms them; the dashboard did not,
# which is the dangerous direction for the inconsistency to point — the dashboard is where the rows
# sit side by side and you click fastest. Reported as "on the game server page ... restart ... showed
# me a confirm box ... on the overall gameservers dashboard ... there was no confirm box". Stop had
# none either, and bulk restart skipped it while bulk stop did not.
_dash = (STATIC_JS / "dashboard.js").read_text(encoding="utf-8")
_da_start = _dash.find("function doAction(")
_da = _dash[_da_start:_dash.find("function _runAction(", _da_start)] if _da_start != -1 else ""
check(bool(_da) and "confirmDialog" in _da and "'restart'" in _da and "'stop'" in _da,
      "dashboard: per-row restart/stop ask before firing",
      "doAction no longer confirms — a row click would stop a populated server with no prompt")
check("_runAction" in _dash and _dash.count("function _runAction(") == 1,
      "dashboard: the unconfirmed request path is reachable only through doAction",
      "_runAction is missing or duplicated")
_bulk_start = _dash.find("function bulkAction(")
_bulk = _dash[_bulk_start:] if _bulk_start != -1 else ""
check("action === 'restart'" in _bulk and "confirmDialog" in _bulk,
      "dashboard: bulk restart confirms too (bulk stop always did)",
      "bulk restart no longer joins stop/update in the confirm branch")

# ── console scrollback: three separate limits used to throw history away ───────────────────────
# Reported as "the console sometimes clears out a lot of the old console". There were three causes,
# and fixing any one alone would not have been noticeable: the API only tailed 100 lines, the poll
# REBUILT the console from that window every time (innerHTML = ''), and the websocket handler —
# the path that actually runs on a busy server — carried its own 500-line cap and its own
# rendering. Both append paths share one buffer and one cap now.
_sd = (STATIC_JS / "server_detail.js").read_text(encoding="utf-8")
check("consoleEl.children.length > 500" not in _sd and "> 500" not in _sd,
      "console: the websocket path no longer caps the scrollback at 500 lines",
      "a second, smaller cap is back in server_detail.js — it silently truncates the history")
check("_appendConsole" in _sd and _sd.count("function _appendConsole(") == 1,
      "console: one append path, so the buffer and the DOM cannot drift",
      "_appendConsole is missing or duplicated")
# refreshConsole DOES wipe once, deliberately: the first poll adopts its (deeper) window in place
# of the server-rendered seed. What must not come back is wiping on EVERY poll, so the assertion is
# that the steady-state path goes through the overlap check and that the wipe stays behind the
# one-shot primed flag.
_rc = _sd[_sd.find("function refreshConsole("):_sd.find("function loadMoreConsole(")]
check("_newConsoleLines(_consoleLines, lines)" in _rc and "_consolePrimed" in _rc,
      "console: a poll appends what is new instead of rebuilding from its window",
      "refreshConsole no longer diffs against the scrollback — it is back to wiping every poll")

# ── the shared control bar must not assume the detail page's globals ──────────────────────────
# server_actions.js is loaded by BOTH the server detail page and Files & Config, but pollStats is
# defined only in server_detail.js — which Files & Config does not load. `setTimeout(pollStats, …)`
# evaluates the identifier immediately, so on that page a successful restart threw ReferenceError
# inside the .then, the trailing .catch reported it as "Action failed — connection error", and the
# operator saw a success toast and a failure toast for one restart that had actually worked.
_sa_js = (STATIC_JS / "server_actions.js").read_text(encoding="utf-8")
check("typeof pollStats === 'function'" in _sa_js,
      "control bar: pollStats is guarded, since Files & Config never loads it",
      "server_actions.js references pollStats unguarded again — a successful action on Files & "
      "Config will throw and be reported as a connection error")
# The structural half. A trailing .catch also catches whatever the SUCCESS handler threw, which is
# what let a missing function masquerade as a network failure. The connection-error toast belongs
# to .then's second argument, where only upstream failures reach it.
check(".catch(() => toast('Action failed" not in _sa_js and ".catch(()=>toast('Action failed" not in _sa_js,
      "control bar: a handler bug cannot be reported as a connection error",
      "the connection-error toast is back in a trailing .catch, so any bug in the success handler "
      "will tell the operator their action failed when it succeeded")

# ── console: select-all is scoped, and the log is downloadable ────────────────────────────────
# Ctrl+A in the console used to select the WHOLE PAGE, because the console is a plain <div> and the
# browser hands select-all to the document. Reported as "i try to do ctrl + a in the console it
# tries to copy the entire page when i just want to copy the console". Scoping it needs BOTH parts:
# the element has to be focusable for a keydown handler to reach it at all.
# Scoped to the select-all block: "tabindex" appears elsewhere in this file, so a whole-file
# substring test passed even with the console's own setAttribute deleted.
_sa = _sd[_sd.find("// Ctrl/Cmd+A inside the console"):_sd.find("function clearConsole(")]
check(bool(_sa) and "setAttribute('tabindex'" in _sa and "selectNodeContents" in _sa,
      "console: Ctrl+A is scoped to the console (focusable element + its own handler)",
      "the console is no longer focusable or no longer scopes the selection — Ctrl+A will take "
      "the whole page again")
check("metaKey" in _sd,
      "console: ...on a Mac too (Cmd+A, not just Ctrl+A)",
      "only ctrlKey is handled, so Cmd+A still selects the page on macOS")
# api_console answers an unreachable host with an empty list. Priming on that blanks the
# server-rendered console the moment you open the page of a server that is down.
check("!_consolePrimed && lines.length" in _sd,
      "console: an empty response does not wipe the server-rendered console",
      "the first-poll prime no longer checks it got any lines")
_sdh = (TEMPLATES / "server_detail.html").read_text(encoding="utf-8")
check("server_file_download" in _sdh and "console_log_rel" in _sdh,
      "console: the log download reuses the file browser's download route",
      "the console log download button is gone, or no longer points at the shared route")

# ── editor line numbers: the two halves must stay metrically identical ────────────────────────
# The gutter is a separate element beside the textarea, so alignment depends entirely on both
# having the same font, size and line-height — and on the textarea not soft-wrapping, since a
# wrapped line occupies several rows and every number below it drifts. Both facts are easy to
# break from a distance (a tweak to one selector, or dropping wrap="off"), and the failure is
# visual and gradual rather than an error.
_sfh = (TEMPLATES / "server_files.html").read_text(encoding="utf-8")
check(".editor-wrap #editor, .editor-gutter" in _sfh,
      "editor: the gutter and the textarea take their metrics from ONE shared rule",
      "they are styled separately now, so the line numbers will drift from their lines")
check('wrap="off"' in _sfh,
      "editor: the textarea does not soft-wrap, so one line is one row",
      'wrap="off" is gone — a wrapped long line pushes every number below it out of alignment')
check("translateY" in _sf and "g.scrollTop = ta.scrollTop" not in _sf,
      "editor: the gutter is translated, not scrolled",
      "scrolling the gutter clamps at its own maximum, which is a line short of the textarea's "
      "whenever a horizontal scrollbar is present")

# ── a password field must not be capped in the markup ────────────────────────────────────────
# The panel deliberately has no maximum password length: hash_password() SHA-256s the password to a
# fixed 44 bytes before bcrypt, so any length works, and password_problem() sets no upper bound.
# A `maxlength` on the input undoes all of that from the one place no test would look — the browser
# silently stops accepting keystrokes, so a passphrase is truncated before it is ever submitted and
# the person ends up with a different password than the one they typed. Worse on a CHANGE form:
# they set a truncated password, and the manager that stored the full one can no longer sign in.
#
# Every `type="password"` input in every template, including ones added later.
_PW_INPUT = re.compile(r'<input\b[^>]*\btype="password"[^>]*>', re.I)
_pw_capped = []
_pw_seen = 0
for _tpl in sorted(TEMPLATES.glob("*.html")):
    for _tag in _PW_INPUT.findall(_tpl.read_text(encoding="utf-8")):
        _pw_seen += 1
        if re.search(r'\bmaxlength\s*=', _tag, re.I):
            _name = (re.search(r'\bname="([^"]*)"', _tag) or [None, "?"])[1]
            _pw_capped.append("%s:%s" % (_tpl.name, _name))
check(_pw_seen >= 10, "password: the scan actually found the password inputs",
      "only %d matched — the regex stopped matching the markup, so the gate below proves nothing"
      % _pw_seen)
check(not _pw_capped, "password: no password field caps what can be typed into it",
      "maxlength on " + ", ".join(_pw_capped))

# ── autoescape bypasses are enumerated, and the one that takes a parameter takes only literals ──
# Jinja escapes everything by default, so the only way a template emits raw HTML is `|safe` or a
# Markup() from Python. Those two sites are the entire XSS surface of the rendering layer, and both
# are safe today: the Markup interpolates only datetime-derived strings, and logs.html's `extra` is
# a macro parameter whose every call site passes a quoted literal.
#
# "Safe today, by convention" is the same state _run()'s shell=True was in before it was gated, and
# the argument for gating it is the same: a `|safe` is one edit away from an attribute-context XSS
# — `sort_th(col, label, extra=request.args.get(...))` would do it — and nothing would object.
# Adding a bypass should require adding it here, with a reason.
# logs.html  — `extra` is a macro parameter; every call site passes a quoted literal (checked below).
# account_2fa.html — the TOTP QR code. qrcode's SvgPathImage emits GEOMETRY, not text: rendering a
#   provisioning URI containing <script>/onerror/quote-breakouts produces only <svg> and <path>,
#   with no part of the input reflected. Verified by feeding it exactly that before allowing it
#   here — the username is in that URI, so "it is generated by a library" was not enough on its own.
_SAFE_BYPASS_FILES = {"logs.html", "account_2fa.html"}
_MARKUP_FILES = {"app.py"}                  # Python modules allowed a Markup()

_bypass_found = set()
for _p in sorted(TEMPLATES.glob("*.html")):
    if re.search(r"\|\s*safe\b", _p.read_text(encoding="utf-8")):
        _bypass_found.add(_p.name)
check(_bypass_found == _SAFE_BYPASS_FILES,
      "xss: only the enumerated templates bypass autoescaping with |safe",
      "new: %s; gone: %s" % (sorted(_bypass_found - _SAFE_BYPASS_FILES),
                             sorted(_SAFE_BYPASS_FILES - _bypass_found)))

_markup_found = set()
for _p in sorted(list((ROOT / "panel").rglob("*.py")) + [ROOT / "app.py"]):
    if re.search(r"\bMarkup\s*\(", _p.read_text(encoding="utf-8")):
        _markup_found.add(_p.name)
check(_markup_found == _MARKUP_FILES,
      "xss: only the enumerated Python modules emit Markup()",
      "new: %s; gone: %s" % (sorted(_markup_found - _MARKUP_FILES),
                             sorted(_MARKUP_FILES - _markup_found)))

# The property that actually makes logs.html's bypass safe: `extra` lands in an ATTRIBUTE position
# (`<th {{ extra|safe }}>`), so a non-literal there is an attribute-context injection, which no
# amount of escaping downstream would catch.
_logs = (TEMPLATES / "logs.html").read_text(encoding="utf-8")
_sort_calls = re.findall(r"sort_th\(([^)]*)\)", _logs)
_nonliteral = []
for _call in _sort_calls:
    _args = [a.strip() for a in _call.split(",")]
    if len(_args) >= 3:
        _third = _args[2].split("=", 1)[-1].strip() if "=" in _args[2] else _args[2]
        if not (_third[:1] in ("'", '"')):
            _nonliteral.append(_call.strip()[:60])
check(len(_sort_calls) >= 4, "xss: the sort_th() scan found the call sites",
      "only %d matched — the gate below proves nothing" % len(_sort_calls))
check(not _nonliteral,
      "xss: every sort_th() passes a literal for the |safe attribute slot",
      "non-literal `extra` at: " + "; ".join(_nonliteral))

# ── every palette section points at an anchor that exists ────────────────────────────────────
# The palette deep-links into a page (/account#sec-2fa). Nothing about a `hash` string in
# palette.js is checked by the browser: rename the card's id and the link still "works" — it lands
# on the right page at the top, and the user is back to scrolling for the thing they searched for,
# which is the exact problem the sections were added to solve. Silent, and only noticed by someone
# who already knew where it used to go.
#
# So: parse the SECTIONS table and require each entry's id to exist in the template its page
# renders, with the page->template map spelled out here because there is no way to derive it.
_SECTION_PAGE_TEMPLATE = {
    "/account": "account.html",
    "/settings": "settings.html",
    "/users": "manage_users.html",
    "/servers/manage": "manage_servers.html",
    "/servers/install": "install_server.html",
}
_pal_src = (ROOT / "static" / "js" / "palette.js").read_text(encoding="utf-8")
_sec_block = re.search(r"var SECTIONS = \[(.*?)\n  \];", _pal_src, re.S)
_sections = re.findall(r"page:\s*'([^']+)'\s*,\s*hash:\s*'([^']+)'",
                       _sec_block.group(1) if _sec_block else "")
check(len(_sections) >= 10, "palette: the SECTIONS table was found and parsed",
      "%d entries parsed — the gate below proves nothing if this is 0" % len(_sections))

_dead, _unmapped = [], []
for _page, _hash in _sections:
    _tpl = _SECTION_PAGE_TEMPLATE.get(_page)
    if not _tpl:
        _unmapped.append(_page)
        continue
    _html = (TEMPLATES / _tpl).read_text(encoding="utf-8")
    if not re.search(r'id="%s"' % re.escape(_hash), _html):
        _dead.append("%s#%s (not in %s)" % (_page, _hash, _tpl))
check(not _unmapped,
      "palette: every section's page is in the page->template map",
      "unmapped pages: %s — add them above or the ids behind them are unchecked"
      % sorted(set(_unmapped)))
check(not _dead, "palette: every section anchor exists in the page it points at",
      "dead anchors: " + "; ".join(_dead))

# HOST_SECTIONS are expanded per host at runtime, so their page is always remote_manage.html.
# Same rot, same gate: a renamed card id there breaks every host's entry at once.
_host_block = re.search(r"var HOST_SECTIONS = \[(.*?)\n  \];", _pal_src, re.S)
_host_hashes = re.findall(r"hash:\s*'([^']+)'", _host_block.group(1) if _host_block else "")
check(len(_host_hashes) >= 5, "palette: the HOST_SECTIONS table was found and parsed",
      "%d entries parsed" % len(_host_hashes))
_rm_html = (TEMPLATES / "remote_manage.html").read_text(encoding="utf-8")
_host_dead = [h for h in _host_hashes if not re.search(r'id="%s"' % re.escape(h), _rm_html)]
check(not _host_dead,
      "palette: every per-host section anchor exists in remote_manage.html",
      "dead anchors: " + ", ".join(_host_dead))

# ...and the way a host link is RECOGNISED has to match the real route. Not theoretical: it
# shipped matching '/remote/<id>' with no '/manage', found no host at all, and every per-host
# section vanished from the results with every other check green. Nothing in the palette fails
# when its matcher matches nothing — it just quietly finds less.
#
# Reads the prefix and suffix out of palette.js and rebuilds a URL from them, then compares
# against a concrete instance of the real remote_manage rule. Parsing the two literals rather
# than a regex keeps the gate honest now that the matcher is string comparison.
_prefix_m = re.search(r"var hostPrefix = \(window\.MOUNT \|\| ''\) \+ '([^']+)';", _pal_src)
# [^']* not [^']+ : an EMPTY suffix is exactly the regression this gate exists for, and a
# pattern that refuses to parse it fails on the wrong check with a less useful message.
_suffix_m = re.search(r"var HOST_SUFFIX = '([^']*)';", _pal_src)
check(bool(_prefix_m) and bool(_suffix_m),
      "palette: the host-link prefix and suffix were found in palette.js",
      "prefix=%s suffix=%s — the check below proves nothing without both"
      % (bool(_prefix_m), bool(_suffix_m)))
if _prefix_m and _suffix_m:
    _rule = next((r for r, v in json.loads(
        (ROOT / "tests" / "url_map_baseline.json").read_text(encoding="utf-8")).items()
        if v.get("endpoint") == "remote_manage"), None)
    check(_rule is not None, "palette: the remote_manage route is in the url-map baseline",
          "no remote_manage rule found")
    _built = _prefix_m.group(1) + "7" + _suffix_m.group(1)
    _concrete = re.sub(r"<[^>]+>", "7", _rule or "")
    check(_built == _concrete,
          "palette: the host-link prefix+suffix rebuild the real remote_manage URL",
          "palette builds %r, the route is %r — per-host sections would silently find nothing"
          % (_built, _concrete))

# ── a page's data-action handlers must be defined in a script THAT PAGE LOADS ─────────────────
# The existing dispatcher check asks whether a handler exists ANYWHERE in static/js. That is not
# the question a click asks. install_server.html was split out of manage_servers.html carrying
# updatePort, suggestFreePort and refreshGameList — and none of the JS: the page loaded no script
# at all, so picking a game did not set its port, the free-port hint never appeared, and the Retry
# button for a failed game list did nothing. Every handler existed; none was reachable. Nothing
# failed, on any page, in any suite.
#
# base.html's own scripts count for every page that extends it (panel.js, the dispatcher itself).
_BASE_JS = set(re.findall(r"asset_url\('js/([\w.-]+)'\)",
                          (TEMPLATES / "base.html").read_text(encoding="utf-8")))
_defs = {}                       # function name -> set of js files defining it
for _js in sorted(STATIC_JS.glob("*.js")):
    _src = _js.read_text(encoding="utf-8")
    for _fn in re.findall(r"^\s*(?:window\.)?function\s+([A-Za-z_$][\w$]*)", _src, re.M):
        _defs.setdefault(_fn, set()).add(_js.name)
    for _fn in re.findall(r"^\s*window\.([A-Za-z_$][\w$]*)\s*=\s*function", _src, re.M):
        _defs.setdefault(_fn, set()).add(_js.name)

# A PARTIAL loads no scripts — its includer does. So a partial's handlers are checked against
# each page that includes it, and the partial itself is not checked standalone. Without this the
# gate reports _server_actions.html's own buttons as unreachable on every run, which would teach
# whoever sees it to ignore the check.
_includes = {}
for _tpl in sorted(TEMPLATES.glob("*.html")):
    for _inc in re.findall(r'\{%-?\s*include\s+[\'"]([\w./-]+)[\'"]', _tpl.read_text(encoding="utf-8")):
        _includes.setdefault(_tpl.name, set()).add(_inc)
_included_by = {}
for _page, _incs in _includes.items():
    for _i in _incs:
        _included_by.setdefault(_i, set()).add(_page)

_unreachable = []
for _tpl in sorted(TEMPLATES.glob("*.html")):
    _src = _tpl.read_text(encoding="utf-8")
    if _tpl.name in _included_by:
        continue                 # checked through its includers below
    _loaded = set(re.findall(r"asset_url\('js/([\w.-]+)'\)", _src)) | _BASE_JS
    _actions = set(re.findall(r'data-action="([A-Za-z_$][\w$]*)"', _src))
    # {% with show_clear_console = True %}{% include ... %} — a partial's button can be behind a
    # flag the includer sets. server_files.html includes _server_actions.html but never sets
    # show_clear_console, so its Clear Console button does not render there and its handler is
    # not needed. Demanding the script anyway would report a button that does not exist.
    _set_here = set(re.findall(r"\{%-?\s*with\s+([A-Za-z_]\w*)\s*=", _src))
    for _inc in _includes.get(_tpl.name, ()):
        _ip = TEMPLATES / _inc
        if not _ip.exists():
            continue
        _isrc = _ip.read_text(encoding="utf-8")
        _loaded |= set(re.findall(r"asset_url\('js/([\w.-]+)'\)", _isrc))
        # A STACK, not a count: {% if %} tags carrying an expression ("{% if a == 'b' %}") do not
        # match a bare-variable pattern, so counting matches against endifs desynchronises and the
        # wrong guard gets attributed. Walk every if/endif in order instead and read the innermost
        # still-open one.
        _toks = [(m.start(), m.group(0), m.group(1))
                 for m in re.finditer(r"\{%-?\s*(?:(?:el)?if\s+([^%]*?)|endif)\s*-?%\}", _isrc)]
        for _m in re.finditer(r'data-action="([A-Za-z_$][\w$]*)"', _isrc):
            _stack = []
            for _pos, _raw, _expr in _toks:
                if _pos >= _m.start():
                    break
                if "endif" in _raw:
                    if _stack:
                        _stack.pop()
                elif _raw.lstrip("{%- ").startswith("elif"):
                    if _stack:
                        _stack[-1] = (_expr or "").strip()
                else:
                    _stack.append((_expr or "").strip())
            _guard = _stack[-1] if _stack else None
            # Only a BARE variable is treated as a page-supplied flag; an expression is about the
            # loop or the data, not about which page included the partial.
            if _guard and re.fullmatch(r"[A-Za-z_]\w*", _guard) and _guard not in _set_here:
                continue        # cannot render on this page
            _actions.add(_m.group(1))
    for _act in sorted(_actions):
        _where = _defs.get(_act)
        if not _where:
            continue             # "does it exist at all" is the dispatcher check's job, above
        if not (_where & _loaded):
            _unreachable.append("%s: %s (defined in %s, not loaded)"
                                % (_tpl.name, _act, ",".join(sorted(_where))))
check(len(_included_by) >= 1, "js: the include map found at least one partial",
      "no {% include %} resolved — partials would be checked as if they were pages")
check(len(_defs) >= 50, "js: the handler-definition scan found the functions",
      "only %d found — the check below proves nothing" % len(_defs))
check(not _unreachable,
      "js: every page's data-action handlers live in a script that page loads",
      "; ".join(_unreachable[:5]))

# ── report ──
# c is True (pass), False (fail) or None (skipped — the check did not run; see skip()).
passed = sum(1 for c, _, _ in results if c is True)
failed = sum(1 for c, _, _ in results if c is False)
skipped = [(name, detail) for c, name, detail in results if c is None]
for c, name, detail in results:
    label = "PASS" if c is True else "FAIL" if c is False else "SKIP"
    print("%s  %s%s" % (label, name, "" if c is True else "  -> " + detail))
print("\n%d / %d checks passed" % (passed, len(results) - len(skipped)))
if skipped:
    print("\n%d CHECK(S) DID NOT RUN:" % len(skipped))
    for name, detail in skipped:
        print("  SKIP  %s   [%s]" % (name, detail))
sys.exit(0 if failed == 0 else 1)
