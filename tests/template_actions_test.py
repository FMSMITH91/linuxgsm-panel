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
    check(True, "static/js: JavaScript parses (SKIPPED — pip install esprima to enable)")
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
        # Drop comments first: a trailing "// nosemgrep" would otherwise read as an interpolation.
        _expr_nc = re.sub(r"//[^\n]*|/\*.*?\*/", "", _expr, flags=re.S)
        _bare = re.sub(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|`(?:[^`\\]|\\.)*`", "", _expr_nc)
        for _fn in _ESCAPERS:
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

# ── report ──
passed = sum(1 for c, _, _ in results if c)
for c, name, detail in results:
    print("%s  %s%s" % ("PASS" if c else "FAIL", name, "" if c else "  -> " + detail))
print("\n%d / %d checks passed" % (passed, len(results)))
sys.exit(0 if passed == len(results) else 1)
