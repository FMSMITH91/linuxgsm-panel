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

# ── the sweeps have to find their subject ─────────────────────────────────────────────────────
# Almost every gate in this file is "no bad pattern anywhere in `srcs`". Fed an EMPTY srcs they
# all pass: `not []` is True, `x not in ""` is True, `all(... for x in [])` is True. Measured by
# forcing both globs to return nothing — the suite reported 95/100 and 97/100, i.e. only the few
# gates with their own positive control noticed. The trigger is not exotic: templates/ or
# static/js/ moving is exactly the kind of change the panel/routes split already made once.
#
# The counts are floors, not inventories — they exist to catch "the sweep found nothing", not to
# be maintained. tests/unit/part01._modpath does the same job by raising.
_n_tpl = sum(1 for n in srcs if n.endswith(".html"))
_n_js = sum(1 for n in srcs if n.endswith(".js"))
check(_n_tpl >= 20, "sweep: the templates/ scan found files to read",
      "%d .html — every template gate below would pass vacuously" % _n_tpl)
check(_n_js >= 20, "sweep: the static/js/ scan found files to read",
      "%d .js — every JS gate below would pass vacuously" % _n_js)

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

# ── Every swap of one region has to re-arm it the SAME way ────────────────────────────────────
# refreshSection(sel, afterName) replaces a region's innerHTML with freshly server-rendered markup.
# The elements inside are new objects, so anything bound to the old ones is gone; afterName is the
# hook that puts it back. Two call sites swapped #server-cards and only one named the hook, so
# which of the two fired decided whether a filter the user had typed kept applying and whether
# host-card dragging still worked. Nothing looked broken — the region re-rendered correctly.
#
# So: for any region that names a hook ANYWHERE, every call site must name it. Read from the AST
# and not from the text, because `refreshSection('#servers-list')` also appears in a COMMENT in
# manage_servers.js, and a regex over the source reports that as a second, non-existent bug.
if not esprima:
    skip("static/js: every refreshSection of one region re-arms it the same way",
         "esprima not installed")
else:
    _rs = {}          # selector -> {afterName or None}
    _rs_where = {}    # selector -> [file:line]

    def _walk_calls(node, fname, out, where):
        if isinstance(node, dict):
            if node.get("type") == "CallExpression":
                _c = node.get("callee") or {}
                _name = (_c.get("name") if _c.get("type") == "Identifier"
                         else (_c.get("property") or {}).get("name"))
                if _name == "refreshSection":
                    _args = node.get("arguments") or []
                    _sel = (_args[0] or {}).get("value") if _args else None
                    _after = (_args[1] or {}).get("value") if len(_args) > 1 else None
                    if isinstance(_sel, str):
                        out.setdefault(_sel, set()).add(_after if isinstance(_after, str) else None)
                        where.setdefault(_sel, []).append(
                            "%s:%s" % (fname, ((node.get("loc") or {}).get("start") or {}).get("line")))
            for _v in node.values():
                _walk_calls(_v, fname, out, where)
        elif isinstance(node, list):
            for _v in node:
                _walk_calls(_v, fname, out, where)

    for _p in sorted((ROOT / "static" / "js").glob("*.js")):
        try:
            _ast = esprima.parseScript(_p.read_text(encoding="utf-8"), {"loc": True}).toDict()
        except Exception:
            continue      # the parse gate above is what reports an unparseable file
        _walk_calls(_ast, _p.name, _rs, _rs_where)

    check(len(_rs) >= 4, "sweep: the refreshSection scan found call sites to check",
          "found %d" % len(_rs))
    _mixed = {k: sorted(x or "(no hook)" for x in v) for k, v in _rs.items() if len(v) > 1}
    check(not _mixed,
          "static/js: every refreshSection of one region re-arms it the same way",
          "; ".join("%s %s at %s" % (k, v, _rs_where[k]) for k, v in sorted(_mixed.items())))

# ── a FAILED poll is not the answer "nothing is installing" ──────────────────────────────────
# install_progress.js polled /api/installs and, on any error, called stop() — which clears the
# interval. Nothing re-arms it: watchInstallsNow is called only from the servers_changed socket
# event and the install/retry form hooks, and servers_changed fires at the START and END of an
# install, never per step. So one dropped request ended progress for the rest of the page's life,
# and the bar stayed on screen showing the last step it received — a frozen reading presented as
# a live one, which is the worst of the three possible outcomes.
if not esprima:
    skip("install_progress: a failed poll does not stop the poller", "esprima not installed")
else:
    _ip_src = (ROOT / "static" / "js" / "install_progress.js").read_text(encoding="utf-8")
    _ip_ast = esprima.parseScript(_ip_src, {"loc": True}).toDict()

    def _calls_named(node, name):
        found = []

        def walk(n):
            if isinstance(n, dict):
                if (n.get("type") == "CallExpression"
                        and (n.get("callee") or {}).get("type") == "Identifier"
                        and (n.get("callee") or {}).get("name") == name):
                    found.append(((n.get("loc") or {}).get("start") or {}).get("line"))
                for v in n.values():
                    walk(v)
            elif isinstance(n, list):
                for v in n:
                    walk(v)
        walk(node)
        return found

    _catch_stops, _catches = [], 0

    def _scan_catches(n):
        global _catches
        if isinstance(n, dict):
            if (n.get("type") == "CallExpression"
                    and (n.get("callee") or {}).get("type") == "MemberExpression"
                    and ((n.get("callee") or {}).get("property") or {}).get("name") == "catch"):
                _catches += 1
                for _a in (n.get("arguments") or []):
                    _catch_stops.extend(_calls_named(_a, "stop"))
            for v in n.values():
                _scan_catches(v)
        elif isinstance(n, list):
            for v in n:
                _scan_catches(v)

    _scan_catches(_ip_ast)
    check(_catches >= 2, "install_progress: the poll's error handlers were found",
          "found %d .catch handlers" % _catches)
    check(not _catch_stops,
          "install_progress: a failed poll does not stop the poller",
          "stop() is called from a .catch at line(s) %s — one dropped request then ends progress "
          "for the life of the page" % ", ".join(str(x) for x in _catch_stops))
    # ...and the frozen bar must say it is frozen, rather than looking like a live reading.
    check("markStale" in _ip_src and "ip-stale" in _ip_src,
          "install_progress: ...and a row it has stopped getting readings for is marked stale")
    _css = (ROOT / "static" / "css" / "panel.css").read_text(encoding="utf-8")
    check(".ip-stale{" in _css,
          "install_progress: ...with a style, so 'stale' is visible and not just a class name")

# ── how an install ENDED: four answers, not "failed" and "everything else" ────────────────────
# settle() split endings into failed/interrupted and the rest, and showed the rest as a green
# "Installed" that removed itself after 8 s. A `done` job with warn=true (the game took a port
# another server uses; it installed but did not start) is shown nowhere else, so its caveat read
# as a success and vanished. `{"status":"none"}` and a non-2xx error body were "Installed" too.
# The classifier is DRIVEN here, through a small evaluator for pure functions over esprima's AST:
# there is no JS runtime on the runners, and a text search for 'warn' passed with it unread.
_JS_UNDEF = object()


class _JsReturn(Exception):
    pass


def _js_truthy(v):
    if v is _JS_UNDEF or v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v != ""
    return True


def _js_eval(n, env):
    """Evaluate the expression subset a pure classifier uses. Anything else raises, so a function
    that grows beyond it fails the gate loudly instead of being evaluated wrongly."""
    t = n.get("type")
    if t == "Literal":
        return n.get("value")
    if t == "Identifier":
        return env.get(n["name"], _JS_UNDEF)
    if t == "MemberExpression" and not n.get("computed"):
        o = _js_eval(n["object"], env)
        return o.get(n["property"]["name"], _JS_UNDEF) if isinstance(o, dict) else _JS_UNDEF
    if t == "UnaryExpression" and n.get("operator") == "!":
        return not _js_truthy(_js_eval(n["argument"], env))
    if t == "LogicalExpression":
        left = _js_eval(n["left"], env)
        if n["operator"] == "||":
            return left if _js_truthy(left) else _js_eval(n["right"], env)
        if n["operator"] == "&&":
            return _js_eval(n["right"], env) if _js_truthy(left) else left
    if t == "BinaryExpression" and n.get("operator") in ("===", "!=="):
        a, b = _js_eval(n["left"], env), _js_eval(n["right"], env)
        same = type(a) is type(b) and a == b
        return same if n["operator"] == "===" else not same
    if t == "ConditionalExpression":
        return _js_eval(n["consequent"] if _js_truthy(_js_eval(n["test"], env)) else n["alternate"],
                        env)
    raise ValueError("unsupported JS expression %s" % t)


def _js_run(stmts, env):
    for s in stmts:
        if s.get("type") == "ReturnStatement":
            raise _JsReturn(_js_eval(s["argument"], env) if s.get("argument") else _JS_UNDEF)
        if s.get("type") == "IfStatement":
            br = s["consequent"] if _js_truthy(_js_eval(s["test"], env)) else s.get("alternate")
            if br:
                _js_run(br["body"] if br.get("type") == "BlockStatement" else [br], env)
            continue
        raise ValueError("unsupported JS statement %s" % s.get("type"))


def _js_call(fn, *args):
    env = {p["name"]: a for p, a in zip(fn["params"], args)}
    try:
        _js_run(fn["body"]["body"], env)
    except _JsReturn as r:
        return r.args[0]
    return _JS_UNDEF


def _js_find_fn(tree, name):
    """The FunctionDeclaration called `name`, found anywhere in the tree."""
    hit = []

    def walk(n):
        if isinstance(n, dict):
            if n.get("type") == "FunctionDeclaration" and (n.get("id") or {}).get("name") == name:
                hit.append(n)
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for v in n:
                walk(v)
    walk(tree)
    return hit[0] if hit else None


if not esprima:
    skip("install_progress: a finished install is classified four ways", "esprima not installed")
else:
    _ipo_ast = esprima.parseScript(
        (ROOT / "static" / "js" / "install_progress.js").read_text(encoding="utf-8"),
        {"loc": True}).toDict()
    _ipo_fn = _js_find_fn(_ipo_ast, "outcome")
    _ipo_cases = [
        ((True, {"status": "done"}), "ok"),
        ((True, {"status": "done", "warn": True}), "warn"),
        ((True, {"status": "failed"}), "bad"),
        ((True, {"status": "interrupted"}), "bad"),
        ((True, {"status": "none"}), "unknown"),
        ((True, {"error": "Permission denied"}), "unknown"),
        ((False, {"status": "done"}), "unknown"),
    ]
    _ipo_wrong = []
    try:
        for _a, _want in _ipo_cases:
            _got = _js_call(_ipo_fn, *_a) if _ipo_fn else "<no outcome() function>"
            if _got != _want:
                _ipo_wrong.append("%r -> %r, want %r" % (_a, _got, _want))
    except ValueError as _e:
        _ipo_wrong.append(str(_e))
    check(not _ipo_wrong,
          "install_progress: a finished install is classified four ways — clean, caveat, failed, "
          "and no verdict",
          "; ".join(_ipo_wrong) + " — a done job's warning, or an answer that is not a job at all, "
          "is shown as a green 'Installed'")

    # SETTLED is data: which endings remove themselves, and in what colour.
    _ipo_settled = {}

    def _scan_settled(n):
        if isinstance(n, dict):
            if (n.get("type") == "VariableDeclarator" and (n.get("id") or {}).get("name") == "SETTLED"
                    and (n.get("init") or {}).get("type") == "ObjectExpression"):
                for _p in n["init"]["properties"]:
                    _k = _p["key"].get("name") or _p["key"].get("value")
                    _ipo_settled[_k] = {(_q["key"].get("name") or _q["key"].get("value")):
                                        _q["value"].get("value") for _q in _p["value"]["properties"]}
            for v in n.values():
                _scan_settled(v)
        elif isinstance(n, list):
            for v in n:
                _scan_settled(v)
    _scan_settled(_ipo_ast)
    _ipo_dropping = sorted(k for k, v in _ipo_settled.items() if v.get("drop"))
    check(set(_ipo_settled) >= {"ok", "warn", "bad"} and _ipo_dropping == ["ok"],
          "install_progress: only a clean install removes its own row",
          "endings %r; auto-removed: %r — a caveat that disappears after 8 s was never read"
          % (sorted(_ipo_settled), _ipo_dropping))
    check((_ipo_settled.get("warn") or {}).get("cls") == "text-warning"
          and (_ipo_settled.get("warn") or {}).get("dismiss") is True,
          "install_progress: ...and a caveat is shown as a warning that stays until dismissed",
          "warn renders as %r" % (_ipo_settled.get("warn"),))

    # ...and settle() actually uses them: the verdict comes from outcome(), and the only timer it
    # arms is the one SETTLED says to.
    _ipo_settle = _js_find_fn(_ipo_ast, "settle")
    _ipo_timers = []

    def _scan_timers(n):
        if isinstance(n, dict):
            if (n.get("type") == "CallExpression"
                    and (n.get("callee") or {}).get("name") == "setTimeout"):
                _d = (n.get("arguments") or [{}, {}])[1:2]
                _ipo_timers.append(((_d[0].get("property") or {}).get("name")) if _d else None)
            for v in n.values():
                _scan_timers(v)
        elif isinstance(n, list):
            for v in n:
                _scan_timers(v)
    if _ipo_settle:
        _scan_timers(_ipo_settle)
    check(_ipo_settle is not None and bool(_calls_named(_ipo_settle, "outcome"))
          and _ipo_timers and all(_t == "drop" for _t in _ipo_timers),
          "install_progress: settle() takes its verdict from outcome() and times out only what "
          "SETTLED says to",
          "settle found=%s, calls outcome=%s, setTimeout delays=%r"
          % (_ipo_settle is not None, bool(_ipo_settle and _calls_named(_ipo_settle, "outcome")),
             _ipo_timers))

    # ── a settled row is settled ONCE ─────────────────────────────────────────────────────────
    # The settled row keeps data-progress-for, and apply() settled every such row not in the live
    # list — so while any other install kept the timer alive, each 3 s poll fetched install-status
    # again for it (for a lost job, one more SSH probe of a host that may be down) and rewrote it.
    # And if that server went live again, fill() found the settled .ip-step, skipped building the
    # bar and threw on it, aborting apply() for every other job. Structural, from the AST: the
    # settle() call in apply() must sit under a test that reads data-settled, settle() must set
    # it, and dashRow() must clear a settled row before filling it.
    def _member_calls(node, method, first_literal):
        found = []

        def walk(n):
            if isinstance(n, dict):
                c = n.get("callee") or {}
                if (n.get("type") == "CallExpression" and c.get("type") == "MemberExpression"
                        and (c.get("property") or {}).get("name") == method
                        and (n.get("arguments") or [{}])[0].get("value") == first_literal):
                    found.append(((n.get("loc") or {}).get("start") or {}).get("line"))
                for v in n.values():
                    walk(v)
            elif isinstance(n, list):
                for v in n:
                    walk(v)
        walk(node)
        return found

    def _guarded_calls(node, name, tests=()):
        """(line, [enclosing if-tests]) for every call to `name` under `node`."""
        out = []
        if isinstance(node, dict):
            if (node.get("type") == "CallExpression"
                    and (node.get("callee") or {}).get("name") == name):
                out.append((((node.get("loc") or {}).get("start") or {}).get("line"), list(tests)))
            if node.get("type") == "IfStatement":
                out += _guarded_calls(node.get("test"), name, tests)
                out += _guarded_calls(node.get("consequent"), name, tests + (node.get("test"),))
                out += _guarded_calls(node.get("alternate"), name, tests)
            else:
                for v in node.values():
                    out += _guarded_calls(v, name, tests)
        elif isinstance(node, list):
            for v in node:
                out += _guarded_calls(v, name, tests)
        return out

    _ipa_apply = _js_find_fn(_ipo_ast, "apply")
    _ipa_calls = _guarded_calls(_ipa_apply, "settle") if _ipa_apply else []
    _ipa_unguarded = [ln for ln, tests in _ipa_calls
                      if not any(_member_calls(t, "hasAttribute", "data-settled") for t in tests)]
    check(bool(_ipa_calls) and not _ipa_unguarded,
          "install_progress: a row that has already settled is not settled again on every poll",
          "settle() calls in apply(): %r; not guarded by data-settled at line(s) %r"
          % ([ln for ln, _ in _ipa_calls], _ipa_unguarded))
    check(_ipo_settle is not None
          and bool(_member_calls(_ipo_settle, "setAttribute", "data-settled")),
          "install_progress: ...because settle() marks the row it has settled",
          "settle() never sets data-settled, so the guard above never holds")
    _ipa_dash = _js_find_fn(_ipo_ast, "dashRow")
    _ipa_clears = []

    def _scan_settled_branch(n):
        if isinstance(n, dict):
            if (n.get("type") == "IfStatement"
                    and _member_calls(n.get("test"), "hasAttribute", "data-settled")):
                def _cl(m):
                    if isinstance(m, dict):
                        if (m.get("type") == "AssignmentExpression"
                                and ((m.get("left") or {}).get("property") or {}).get("name")
                                == "textContent"
                                and (m.get("right") or {}).get("value") == ""):
                            _ipa_clears.append(True)
                        for v in m.values():
                            _cl(v)
                    elif isinstance(m, list):
                        for v in m:
                            _cl(v)
                _cl(n.get("consequent"))
            for v in n.values():
                _scan_settled_branch(v)
        elif isinstance(n, list):
            for v in n:
                _scan_settled_branch(v)
    if _ipa_dash:
        _scan_settled_branch(_ipa_dash)
    check(_ipa_dash is not None
          and bool(_member_calls(_ipa_dash, "removeAttribute", "data-settled")) and _ipa_clears,
          "install_progress: ...and a settled row that goes live again is rebuilt, not filled",
          "dashRow() fills a settled row as it stands: fill() finds its .ip-step, skips building "
          "the bar and throws on it")

# ── a filter that only runs on `change` does not run on the common setup ─────────────────────
# The install picker greys out the games LinuxGSM caps below the host's release, from the host
# selector's change event. With ONE host the select is rendered already selected and never fires
# one, so on the setup most panels have, nothing filtered anything: reported from the panel with
# a screenshot of BATTALION listed and selectable after the feature shipped. Reproduced in a
# browser — disabled:false on all four, empty note — and fixed by calling it at load too.
#
# From the AST, because "filterGamesForHost" appears in this file's own comments.
if not esprima:
    skip("manage_servers: the game filter runs on page LOAD, not only on host change",
         "esprima not installed")
else:
    _ms_ast = esprima.parseScript(
        (ROOT / "static" / "js" / "manage_servers.js").read_text(encoding="utf-8"),
        {"loc": True}).toDict()
    _dcl_bodies = []

    def _scan_dcl(n):
        if isinstance(n, dict):
            if (n.get("type") == "CallExpression"
                    and ((n.get("callee") or {}).get("property") or {}).get("name") == "addEventListener"
                    and (n.get("arguments") or [{}])[0].get("value") == "DOMContentLoaded"):
                _dcl_bodies.extend((n.get("arguments") or [])[1:2])
            for v in n.values():
                _scan_dcl(v)
        elif isinstance(n, list):
            for v in n:
                _scan_dcl(v)

    _scan_dcl(_ms_ast)
    check(bool(_dcl_bodies),
          "manage_servers: a DOMContentLoaded handler was found to check",
          "none — the check below would pass vacuously")
    _at_load = []
    for _b in _dcl_bodies:
        for _nm in ("filterGamesForHost", "hostChanged"):
            _at_load.extend(_calls_named(_b, _nm))
    check(bool(_at_load),
          "manage_servers: the game filter runs on page LOAD, not only on host change",
          "nothing calls filterGamesForHost/hostChanged at load — with a single host the select "
          "never fires `change`, so every capped game stays selectable")

# ── A form that appears AFTER page load carries no CSRF token ─────────────────────────────────
# panel.js gives every POST form a hidden csrf_token, once, on DOMContentLoaded, and wraps fetch()
# so every mutating fetch carries the header. A form submitted with form.submit() has neither:
# it is a native POST, so no wrapper runs, and form.submit() fires no 'submit' event either, so a
# delegated listener could not stand in. refreshSection() re-fetches the page and swaps a
# container's innerHTML — the SERVER's markup, without the field panel.js added to the live DOM.
#
# The host page's uninstall form sits in #host-servers-card and is submitted that way, and
# importExisting() refreshes exactly that card: after importing discovered servers, Uninstall
# posted with no token. Measured in a browser against the real panel.js — token present on load,
# null after the swap, present again after ensureCsrfFields().
if not esprima:
    # SKIPPED, not silently absent. These four sat inside `if esprima:` and simply stopped
    # existing without it: the tally is len(results), so the suite reported "95 / 95 checks
    # passed" with four CSRF gates gone and exited 0. A check that did not run has to appear in
    # the count as a check that did not run.
    for _n in ("panel.js exports ensureCsrfFields for markup that arrives after load",
               "panel.js: refreshSection re-arms the token on the markup it swaps in",
               "static/js: a native form.submit() re-arms its CSRF token first",
               "static/js: the submit()-site walk found call sites at all"):
        skip(_n, "esprima not installed (pip install esprima)")
if esprima:
    _csrf_js = (ROOT / "static" / "js" / "panel.js").read_text(encoding="utf-8")
    check("window.ensureCsrfFields = function" in _csrf_js,
          "panel.js exports ensureCsrfFields for markup that arrives after load", "not exported")
    # It must run at the end of refreshSection, or every swapped-in form loses its token.
    _rs = _csrf_js[_csrf_js.index("window.refreshSection ="):]
    _rs = _rs[:_rs.index("function _submitAjaxForm")]
    check("window.ensureCsrfFields(cur)" in _rs,
          "panel.js: refreshSection re-arms the token on the markup it swaps in", _rs[:300])

    # The general invariant, over the AST rather than the text: every CallExpression of the form
    # <x>.submit() must sit inside a function that also calls ensureCsrfFields. A native submit is
    # the one path the fetch wrapper cannot cover, and form.submit() fires no 'submit' event, so a
    # delegated listener could not stand in for it either.
    def _walk(node, fn_stack, hits):
        t = getattr(node, "type", None)
        pushed = False
        if t in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
            fn_stack.append({"node": node, "submits": [], "armed": False})
            pushed = True
        if t == "CallExpression":
            callee = getattr(node, "callee", None)
            prop = getattr(getattr(callee, "property", None), "name", None)
            name = getattr(callee, "name", None) or getattr(
                getattr(callee, "property", None), "name", None)
            if prop == "submit":
                _submit_sites[0] += 1
                if fn_stack:
                    fn_stack[-1]["submits"].append(getattr(node.loc, "start", None))
            if name == "ensureCsrfFields":
                for fr in fn_stack:
                    fr["armed"] = True
        for k in list(getattr(node, "__dict__", {})):
            v = getattr(node, k)
            if isinstance(v, list):
                for e in v:
                    if hasattr(e, "type"):
                        _walk(e, fn_stack, hits)
            elif hasattr(v, "type"):
                _walk(v, fn_stack, hits)
        if pushed:
            fr = fn_stack.pop()
            if fr["submits"] and not fr["armed"]:
                hits.extend(fr["submits"])
        return hits

    _submit_sites = [0]

    def _csrf_submit_sites():
        return _submit_sites[0]

    _naked_submit = []
    for _p in sorted((ROOT / "static" / "js").glob("*.js")):
        _text = _p.read_text(encoding="utf-8")
        if ".submit()" not in _text:
            continue
        for _loc in _walk(esprima.parseScript(_text, options={"loc": True}), [], []):
            _naked_submit.append("%s:%s" % (_p.name, getattr(_loc, "line", "?")))
    # The positive control: an AST walk that matches nothing passes vacuously.
    check(_csrf_submit_sites() > 0, "static/js: the submit()-site walk found call sites at all",
          "found none, so the gate below proves nothing")
    check(not _naked_submit, "static/js: a native form.submit() re-arms its CSRF token first",
          "form.submit() with no ensureCsrfFields in the same function at: %s" % _naked_submit[:4])

# ── data-no-i18n has to survive a JS write ────────────────────────────────────────────────────
# `walk()` consults the attribute only on the node it is ENTERED at, and the MutationObserver
# enters at the freshly added TEXT node (which has no attributes) or at an appended child — never
# at the guarded ancestor. `el.textContent = x` replaces the children with a brand-new Text node,
# so `<span data-no-i18n>` above it was never read: measured in a browser with LANG='es', a
# guarded span written with textContent 'Online' displayed 'En línea', indistinguishable from an
# unguarded one. Every template-side guard of that shape — #tag-list, #game-version,
# #acct-username, #eu-name — was decorative, and a username called Admin rendered as
# "Administrador".
#
# Structural, because this suite parses JavaScript and cannot execute it. Measured in a browser
# against the real i18n.js before and after: guarded text now stays 'Online' and 'Status' while an
# unguarded control still becomes 'Copias de seguridad'.
_i18n_src = (ROOT / "static" / "js" / "i18n.js").read_text(encoding="utf-8")
check("function guardedAbove(" in _i18n_src and "el.parentNode" in _i18n_src,
      "i18n: there is a guardedAbove() that walks up the ancestors", "no ancestor check")
_obs = _i18n_src[_i18n_src.index("new MutationObserver"):]
_obs = _obs[:_obs.index(".observe(")]
_obs_walks = [ln for ln in _obs.splitlines() if "walk(" in ln]
check(bool(_obs_walks) and all("guardedAbove" in ln for ln in _obs_walks),
      "i18n: every walk() the observer starts is gated on guardedAbove first",
      "ungated: %s" % [ln.strip()[:60] for ln in _obs_walks if "guardedAbove" not in ln])

# ── the flash sweep must not close a standing warning ─────────────────────────────────────────
# chrome.js selected every `.alert-dismissible` in the document at T+6s, and nags.js gives the
# OS-updates banner that class to park its close button — so the panel's "System updates waiting /
# N security" warning erased itself six seconds after every page load, recorded no dismissal, and
# flickered back on the next visibility poll. A flash is a transient reply to something the user
# just did; a standing warning is not. Measured in a browser: banner still there, flash dismissed.
_chrome_src = (ROOT / "static" / "js" / "chrome.js").read_text(encoding="utf-8")
check("'.flash-container .alert-dismissible'" in _chrome_src
      or '".flash-container .alert-dismissible"' in _chrome_src,
      "chrome: the 6s auto-dismiss is scoped to the flash container",
      "it still sweeps every .alert-dismissible on the page")

# ── the tag chips are repainted into an element that exists ───────────────────────────────────
# `msrv-tags-<id>` was the container on the deleted /servers/manage page, so the lookup had been
# returning null ever since: the row kept its old chips after a save, and the dashboard's tag
# FILTER reads its truth from those very chips, so filtering by a tag just added hid the server
# that now carries it.
_tags_src = (ROOT / "static" / "js" / "server_tags.js").read_text(encoding="utf-8")
_dash_tpl = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
check("getElementById('srv-tags-' + serverId)" in _tags_src
      and "getElementById('msrv-tags-" not in _tags_src,
      "tags: the chip repaint targets the id the dashboard actually renders",
      "still looking up msrv-tags-<id>")
check('id="srv-tags-{{ srv.id }}"' in _dash_tpl,
      "tags: ...and the dashboard renders it", "no srv-tags-<id> container")

# ── a file called "Backups" must not be renamed by the translator ─────────────────────────────
# A directory can legitimately be called Backups, Console, Status or Log — all keys in
# translations/*/ — and without a guard the browser renders the name of a directory that does not
# exist under that name, in the listing, the breadcrumb, the upload-destination label and the
# editor header. `backups/` is a standard LinuxGSM directory. The file already knew: _conflictNode
# guards the overwrite label for exactly this reason.
_sf_src = (ROOT / "static" / "js" / "server_files.js").read_text(encoding="utf-8")
_sf_missing = []
for _label, _needle in (
        ("the row's name span", "font-size:.85rem;\" data-no-i18n>'+esc(opts.name)"),
        ("each breadcrumb segment", "'+esc(acc)+'\" data-no-i18n>'+esc(p)+'"),
        ("the upload destination", "dest.setAttribute('data-no-i18n','')"),
        ("the editor header", "_ep.setAttribute('data-no-i18n','')")):
    if _needle not in _sf_src:
        _sf_missing.append(_label)
check(not _sf_missing, "files: every element holding a path segment is marked do-not-translate",
      "unguarded: %s" % _sf_missing)

# ── the document-wide drop suppression must not take the textareas with it ────────────────────
# preventDefault() on a bubbled event still cancels the default action, so suppressing the
# browser's own file-drop handler document-wide also cancelled drops into this page's three
# textareas: dragging a selection into the raw config editor did nothing, on this page only.
check("closest('textarea, input" in _sf_src,
      "files: the drop suppression exempts form controls", "a drop into the editor is cancelled")

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

# ── 0d-bis. the console line renderer builds NODES, never markup ──────────────────────────────
# The scanner above only claims a sink whose expression contains markup (a `'…<tag` literal) or an
# accumulated HTML buffer. `span.innerHTML = text` has neither, so it sails straight through — and
# that is the single most dangerous shape in this file. A console line is the GAME's output: player
# names and chat arrive in it verbatim, so it is attacker-authored end to end, with no markup
# literal anywhere for the other gate to notice.
#
# It used to be one `div.textContent = line`, which made the question moot. Rendering ANSI colour
# means splitting the line into runs and building a <span> per run, and the tempting way to write
# that is a string of spans — which would be an XSS hole with a player name as the payload. So the
# two functions that put console text into the DOM are gated directly: no HTML sink, and the run
# must be written with textContent. (Verified by mutation: swapping textContent for innerHTML in
# _ansiRun passed every other suite.)
def _js_function_body(src, name):
    """The body of `function name(...) { ... }`, by brace matching."""
    m = re.search(r"\bfunction\s+%s\s*\([^)]*\)\s*\{" % re.escape(name), src)
    if not m:
        return None
    i, depth = m.end() - 1, 0
    for j in range(m.end() - 1, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i + 1:j]
    return None


_sd_js = (ROOT / "static" / "js" / "server_detail.js").read_text(encoding="utf-8")
for _fn in ("_ansiRun", "renderAnsi"):
    _body = _js_function_body(_sd_js, _fn)
    # Vacuity guard: a renamed function would make every check below pass by finding nothing.
    check(_body is not None and len(_body) > 80,
          "console render: %s() was found in server_detail.js" % _fn,
          "extractor got %r — the checks below would prove nothing" % (_body or "")[:60])
    check(not _SINK.search(_body or ""),
          "console render: %s() uses no HTML sink (a player name would be the payload)" % _fn,
          "found an innerHTML/outerHTML/insertAdjacentHTML in it")
check(".textContent = text" in (_js_function_body(_sd_js, "_ansiRun") or ""),
      "console render: _ansiRun writes its run with textContent",
      "it no longer assigns textContent — the run is reaching the DOM some other way")
# renderAnsi APPENDS; assigning el.textContent replaces every child the line already has — which
# is how the timestamp gutter came to vanish from every line without colour (the majority of real
# console output), while the coloured ones kept theirs and made it look like a colour bug.
check(not re.search(r"\bel\.textContent\s*=", _js_function_body(_sd_js, "renderAnsi") or ""),
      "console render: renderAnsi appends to the line, never replaces its contents",
      "it assigns el.textContent, which wipes the timestamp gutter put there before it")


# ── 0d-bis. the console's scrollback must not re-append the log after an update + start ─────
# The page keeps its own copy of the log (_consoleLines) and stitches each /api/console window
# onto it by matching that copy's newest lines against the window. Any line the copy holds that
# the FILE does not (the panel's "[panel] update …" markers), any line that differs by a space,
# and any gap the poller left makes the match miss — and a miss appends the WHOLE window again,
# beneath the live output. Reported as "after I update then start the server the live console
# stops responding till I load more of the old log"; measured on the test VPS at +82, +29 and
# +33 repeated lines on three consecutive polls with the websocket connected throughout.
def _js_code_only(body):
    """`body` with // comments removed, so an explanation of a fix cannot satisfy its own gate."""
    return re.sub(r"(?m)(^|[^:'\"\\])//.*$", r"\1", body or "")


def _js_block_after(src, anchor):
    """The brace-matched block that opens at the first `{` after `anchor`, or None."""
    i = src.find(anchor)
    if i < 0:
        return None
    j = src.index("{", i)
    depth = 0
    for k in range(j, len(src)):
        depth += {"{": 1, "}": -1}.get(src[k], 0)
        if depth == 0:
            return src[j + 1:k]
    return None


_co_handler = _js_code_only(_js_block_after(_sd_js, "socket.on('console_output', function(data)"))
check(len(_co_handler) > 200 and "_appendConsoleRows(" in _co_handler,
      "console stitch: (setup) found the socket handler that renders console output",
      "extractor got %r" % _co_handler[:80])
check(re.search(r"var fromLog = Array\.isArray\(data\.rows\) && !data\.panel;", _co_handler)
      and re.search(r"if \(fromLog && data\.rows\.length\)", _co_handler)
      and "appendConsole(data.data, data.ts, fromLog)" in _co_handler,
      "console stitch: a push that is not from the log is rendered but not tracked",
      "panel/system pushes reach _consoleLines, and the next poll's overlap match cannot find them")
check("if (track !== false) _consoleLines = _consoleLines.concat(lines);"
      in _js_code_only(_js_function_body(_sd_js, "_appendConsole")),
      "console stitch: _appendConsole leaves untracked lines out of the overlap copy",
      "every rendered line is still concatenated onto _consoleLines")
_rc_body = _js_code_only(_js_function_body(_sd_js, "refreshConsole"))
_rc_delta = _js_block_after(_rc_body, "} else if (!socket.connected || catchUp)") or ""
check("_newConsoleRows(" in _rc_delta and _rc_body.count("_newConsoleRows(") == 1,
      "console stitch: the poll appends a delta ONLY while the socket is down (or to catch up)",
      "a poll delta is appended with the websocket live — a missed overlap re-appends the window")
# ...and a RE-connect catches up once from the log. The poller forgets a console nobody watches,
# so a socket that dropped for a moment rejoins at "now", and what was written in the gap is only
# in the file.
_cn_handler = _js_code_only(_js_block_after(_sd_js, "socket.on('connect', function()"))
check(re.search(r"if \(_socketEverConnected\) refreshConsole\(false, null, true\);", _cn_handler)
      and "_socketEverConnected = true;" in _cn_handler,
      "console stitch: a reconnect catches up the gap from the log",
      "a socket that dropped and rejoined silently loses whatever was written while it was down")
_lm_body = _js_code_only(_js_function_body(_sd_js, "loadMoreConsole"))
check(0 <= _lm_body.find("data.readable === false") < _lm_body.find("consoleEl.innerHTML = ''"),
      "console stitch: Load older does not wipe the scrollback for a log it could not read",
      "it empties the console (the only copy of what was pushed) before checking readable")
check("_renderPanelLines(" in _lm_body,
      "console stitch: Load older puts the panel's own lines back after rebuilding",
      "an update's output is lost for good the first time Load older is pressed")
check("a.trim() === b.trim()" in _js_code_only(_js_function_body(_sd_js, "_sameLine"))
      and "_sameLine(" in _js_code_only(_js_function_body(_sd_js, "_eqRange"))
      and "_sameLine(incoming[k], lastHave)" in _js_code_only(_js_function_body(_sd_js,
                                                                                 "_newConsoleLines")),
      "console stitch: the overlap match ignores surrounding whitespace",
      "an exact compare turns one trailing space into 'no overlap' and a whole re-appended window")

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

    # ── ...and it must not be WIDER than the row it is pinned over ────────────────────────────
    # Sticky + opaque means this column is painted ON TOP of the cells it scrolls over, so its
    # width is how much of the row it hides. Seven buttons at 33px made it 270px of a 341px
    # viewport: measured at 375px in a rendered panel, elementFromPoint over the server name
    # returned the Start button and 31px of the row was readable. "CS2 Public" showed as "CS2 Pub".
    #
    # The fix is a bounded width that makes the buttons wrap instead of pushing sideways — 190px
    # is the measured point where seven fall into two rows (160px takes three and grows the row
    # from 80px to 115px). Both halves are needed: a width with no wrap just clips, and a wrap
    # with no width lets the column keep its full 270px. So gate both.
    _w = re.search(r"(?:^|\s)width:\s*(\d+)px", _code)
    check(_w is not None and int(_w.group(1)) <= 200,
          "mobile: the sticky Actions column has a bounded width",
          "it is %s — unbounded, it grows with every button added and is painted over the name, "
          "status, players and address of the row it is pinned to"
          % (_w.group(0).strip() if _w else "not set at all"))
    check(re.search(r"white-space:\s*normal\s*!important", _code) is not None,
          "mobile: ...and its buttons WRAP rather than widening it",
          "without white-space:normal the width above just clips the buttons; it needs "
          "!important because the cell carries Bootstrap's .text-nowrap utility, which is itself "
          "!important")
    # The identity column needs a floor, or the table's auto layout leaves it at the 62px that
    # wrapped "CS2 Public" onto two lines even once the Actions column stopped covering it.
    _idcol = re.search(r"\.table-responsive\s+\.table\s+thead\s+th:nth-child\(2\)\s*,\s*"
                       r"\.table-responsive\s+\.table\s+tbody\s+td:nth-child\(2\)\s*\{(.*?)\}",
                       _css, re.S)
    _idcode = re.sub(r"/\*.*?\*/", "", _idcol.group(1), flags=re.S) if _idcol else ""
    _idw = re.search(r"min-width:\s*(\d+)px", _idcode)
    check(_idw is not None and int(_idw.group(1)) >= 100,
          "mobile: the server-name column has a width floor",
          "the column that says which server the row IS gets whatever the auto layout leaves it "
          "— 62px, measured — unless it is given a floor")

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
check("_newConsoleRows(_consoleLines, rows)" in _rc and "_consolePrimed" in _rc,
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
    "/": "dashboard.html",
    "/server-management": "remote_manage.html",   # the panel host reuses the host template
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

# ── ...and on a TABBED page, existing is not the same as reachable ────────────────────────────
# remote_manage.html hides every card whose data-mtab is not the open tab, so a link to a card on
# a closed tab scrolls to a display:none element — which does nothing, silently. The page routes
# a #hash to the right tab before scrolling, and USED to do it from a hand-written map naming four
# ids; everything else fell through to the Overview tab. Three palette entries shipped that way
# (Banned IPs, Top offenders, Recent security events): they opened the wrong tab and landed on a
# hidden card, with every other check green because the id was right there in the template.
#
# The fix reads the tab off the DOM, so this gate asks the same question the page now asks: is the
# id inside SOME data-mtab section? Div depth is tracked rather than parsed as HTML, because the
# file is a Jinja template — conditional attributes would defeat an HTML parser, while the
# {% if %} blocks here wrap whole <div>s and so leave div nesting balanced.
_TABBED = {"/server-management": "remote_manage.html", "/remote/manage": "remote_manage.html"}


def _mtab_owner_of(html, wanted):
    """id -> the data-mtab section enclosing it (or None), by walking div depth."""
    html = re.sub(r"\{#.*?#\}", "", html, flags=re.S)       # Jinja comments can contain markup
    html = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    out, stack = {}, []

    def _enclosing():
        return next((t for t in reversed(stack) if t), None)

    for m in re.finditer(r"<div\b[^>]*>|</div>|id=\"([\w-]+)\"", html):
        tok = m.group(0)
        if tok == "</div>":
            if stack:
                stack.pop()
        elif tok.startswith("<div"):
            mt = re.search(r'data-mtab="(\w+)"', tok)
            mt = mt.group(1) if mt else None
            # The id and the data-mtab are usually on the SAME div, and that tag is matched whole
            # — so the id has to be read out of it here. Reading only free-standing id= attributes
            # missed every card that carries both, which is all of them.
            did = re.search(r'\bid="([\w-]+)"', tok)
            if did and did.group(1) in wanted:
                out[did.group(1)] = mt or _enclosing()
            stack.append(mt)
        elif m.group(1) in wanted:
            out[m.group(1)] = _enclosing()     # an id on a non-div element, e.g. an <input>
    return out


_rm_src = (TEMPLATES / "remote_manage.html").read_text(encoding="utf-8")
_tabbed_hashes = [h for pg, h in _sections if pg in _TABBED]
_owners = _mtab_owner_of(_rm_src, set(_tabbed_hashes) | {"backups", "sec-bans"})
# Vacuity guard for the walker itself: two ids whose tabs are known independently — 'backups' sits
# on Maintenance and 'sec-bans' on Security. If the depth tracking ever desyncs these go wrong
# first, and the gate below would otherwise pass by finding nothing.
check(_owners.get("backups") == "maintenance" and _owners.get("sec-bans") == "security",
      "palette: the data-mtab walker agrees with two independently known cards",
      "backups=%r sec-bans=%r" % (_owners.get("backups"), _owners.get("sec-bans")))
check(len(_tabbed_hashes) >= 3, "palette: there are tabbed-page sections to check",
      "%d found — the gate below proves nothing if this is 0" % len(_tabbed_hashes))
_unreachable = [h for h in _tabbed_hashes if not _owners.get(h)]
check(not _unreachable,
      "palette: every section on a tabbed page sits in a tab the page can open",
      "not inside any data-mtab section, so the link lands on a hidden card: %s"
      % sorted(set(_unreachable)))

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

# ── The installed game version is readable WITHOUT opening a tab ──────────────────────────────
# server_detail.html filters its cards by data-mtab the same way remote_manage.html does, and the
# version was very nearly put in the Details tab. An element that exists in the template but sits
# inside a closed tab is not an answer to "show me the version" — it is one click away from being
# one, and nothing about its presence in the source says which.
#
# It is also the reason it lives on its own LINE rather than appended to the header's meta row:
# that row already wraps at phone widths, so growing it moves every card below — and /server/1 is
# audited with CLS as a hard failure. Both properties are asserted, because either one silently
# reverts the moment someone tidies the header.
_sd_src = (TEMPLATES / "server_detail.html").read_text(encoding="utf-8")
_sd_owner = _mtab_owner_of(_sd_src, {"game-version", "console-output"})
check(_sd_owner.get("console-output") == "console",
      "version: the data-mtab walker agrees about server_detail's own console card",
      "console-output=%r — the walker desynced, so the check below proves nothing"
      % _sd_owner.get("console-output"))
check("game-version" in _sd_owner,
      "version: the element the page fills is in server_detail.html", "no id=\"game-version\"")
check(_sd_owner.get("game-version") is None,
      "version: it is outside every tab, so it is readable without clicking one",
      "it sits in the %r tab" % _sd_owner.get("game-version"))
# Present from the first paint with a placeholder — an element that APPEARS once the fetch lands
# adds a line to the header and shifts the whole page down.
_sd_ver_tag = re.search(r'<span id="game-version"[^>]*>(.*?)</span>', _sd_src, re.S)
check(_sd_ver_tag and _sd_ver_tag.group(1).strip() != "",
      "version: it is rendered with a placeholder, not left empty until the fetch lands",
      "rendered as %r" % (_sd_ver_tag.group(1) if _sd_ver_tag else None))

# ── The console's poll delta is stamped, and an all-history console says why it is not ────────
# refreshConsole has two branches: the PRIMING pass (history — a window of a log file written
# before the panel looked, correctly unstamped) and the delta (new output the panel just watched
# arrive, which must be stamped exactly like a socket push). The first cut passed no timestamp on
# either, so an install whose websocket cannot connect got no times at all, and a quiet server's
# console showed an empty column that read as a broken feature.
_rc_body = _js_function_body(_sd_js, "refreshConsole") or ""
check(len(_rc_body) > 200, "console times: refreshConsole() was found",
      "extractor got %d chars — the checks below prove nothing" % len(_rc_body))
check(re.search(r"_appendConsoleRows\(_newConsoleRows\([^)]*\)\s*,\s*data\.now\s*\)", _rc_body),
      "console times: the poll DELTA is stamped with the panel's clock",
      "the delta is appended with no fallback timestamp — a socket-less install would never show one")
# The priming pass gets NO fallback clock. A row that carries LinuxGSM's OWN stamp still keeps it
# (that is a real time for a line written before the panel looked); what must never happen is the
# panel dating an unstamped history line to the moment the page opened.
check(re.search(r"_appendConsoleRows\(rows\)\s*;", _rc_body),
      "console times: ...and the priming window gets no fallback clock, because it is history",
      "the priming pass is being given data.now, which dates a week of history to right now")
# The notice that explains an empty column. Without it, "correct" and "broken" look identical.
check('id="console-ts-notice"' in _sd_src,
      "console times: an all-history console carries the notice explaining the empty column",
      "no #console-ts-notice in server_detail.html")
check("updateTsNotice" in _js_function_body(_sd_js, "applyTsVisible") or "",
      "console times: ...and the notice is re-evaluated when the column is toggled",
      "applyTsVisible does not call updateTsNotice")

# ── A card that every host has must be findable for every host ────────────────────────────────
# remote_manage.html serves BOTH /server-management (the panel host) and /remote/<id>/manage, and
# only some of its cards are gated on remote.is_local — the panel's own backups/updates/
# diagnostics, and the security events log. Everything else renders for every host.
#
# SECTIONS pins a section to ONE page; HOST_SECTIONS is expanded over every host the sidebar
# lists. So a card that is not is_local-gated but appears only in SECTIONS at /server-management
# is findable for the panel host and invisible for every remote one — which is how Banned IPs and
# Top offenders shipped: both render on every host page, and the palette offered them for exactly
# one. This asks the template which cards are panel-only rather than trusting a list.
_IS_LOCAL_GUARD = "is_local"


def _is_panel_host_only(html, anchor_id):
    """Is this id inside an {% if ... is_local ... %} block? Walks Jinja if/endif, tracking the
    conditions currently open — the same nesting question as the data-mtab walker above, over
    template tags instead of divs."""
    pos = html.find('id="%s"' % anchor_id)
    if pos < 0:
        return None
    stack = []
    for m in re.finditer(r"\{%-?\s*(if|elif|else|endif)\b([^%]*)%\}", html):
        if m.start() > pos:
            break
        kind, cond = m.group(1), m.group(2).strip()
        if kind == "if":
            stack.append(cond)
        elif kind == "endif":
            if stack:
                stack.pop()
        elif stack:
            stack[-1] = cond if kind == "elif" else ("not " + stack[-1])
    return any(_IS_LOCAL_GUARD in c for c in stack)


# Vacuity guard: two ids whose gating is known independently — the panel's self-update card is
# panel-only, the firewall card is on every host. If the Jinja walk desyncs these go first.
check(_is_panel_host_only(_rm_html, "updates") is True
      and _is_panel_host_only(_rm_html, "sec-firewall") is False,
      "palette: the is_local walker agrees with two independently known cards",
      "updates=%r sec-firewall=%r" % (_is_panel_host_only(_rm_html, "updates"),
                                      _is_panel_host_only(_rm_html, "sec-firewall")))
_pinned = [h for pg, h in _sections if pg == "/server-management"]
check(len(_pinned) >= 3, "palette: there are /server-management sections to check",
      "%d found — the gate below proves nothing if this is 0" % len(_pinned))
_host_only_missing = [h for h in _pinned
                      if _is_panel_host_only(_rm_html, h) is False and h not in _host_hashes]
check(not _host_only_missing,
      "palette: a card every host renders is offered for every host, not just the panel one",
      "renders on remote hosts too but is only in SECTIONS: %s — add to HOST_SECTIONS"
      % sorted(set(_host_only_missing)))

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

# ── every restore-a-hidden-panel path must DECLARE the key it is restoring ────────────────────
# collectPanels/collectLayout build the save payload FROM THE DOM, and the endpoint's merge rule is
# to keep every stored key the page did not declare (so one page cannot erase another page's
# layout). showPanel removed the restore chip first, so the key was in neither `panels` nor
# `hidden` and therefore not in `declared` — the server kept it hidden and the reload rendered it
# hidden. Verified by feeding the real payload through the real merge: the key comes back in
# `hidden` every time. Both pages have this shape; both are checked.
for _sf, _fn in (("dashboard.js", "showPanel"), ("server_detail.js", "showDetailPanel")):
    _src = (ROOT / "static" / "js" / _sf).read_text(encoding="utf-8")
    _body = _src[_src.index("window.%s = function" % _fn):]
    _body = _body[:_body.index("\n};")]
    check("setAttribute('data-panel'" in _body and "btn.remove()" in _body,
          "js: %s declares the key it restores before saving" % _fn,
          "the server's merge rule would put it straight back in hidden")

# ── a poll whose only exit is success runs until the page is closed ───────────────────────────
# Each of these polls an endpoint that costs an SSH round trip, and each had exactly one
# clearInterval, reachable only when the remote reported running:true. The ordinary path — open
# the login link in another tab and come back later, or close the modal — left it running, and
# every press of the button started another. Measured in a browser: three clicks and 13s gave four
# live intervals and nine requests.
for _sf, _needle in (("manage_remotes.js", "_tsUpPolls"), ("tailscale.js", "_tsUpPoll"),
                     ("setup_tailscale.js", "_tsPoll")):
    _src = (ROOT / "static" / "js" / _sf).read_text(encoding="utf-8")
    check(_needle in _src and "Date.now()" in _src,
          "js: %s's tailscale-up poll is deduped and has a deadline" % _sf,
          "no single-poll registry or no deadline")

# ── the bootstrap poll's teardown sat below the line that returned ────────────────────────────
_mr = (ROOT / "static" / "js" / "manage_remotes.js").read_text(encoding="utf-8")
check("if (!stepEl) { clearInterval(_bootstrapPoll)" in _mr,
      "js: the bootstrap poll stops when its modal is gone, instead of bailing forever",
      "showModal removes #ts-modal, and every clearInterval sits below the early return")

# ── the SSH card's live state is refilled after the section is swapped ────────────────────────
# refreshSection only re-runs a callback when one is NAMED, and loadSshStatus is the only thing
# that fills that card — it ran once, at load. So after any Tailscale-SSH action the swap brought
# back the server render and the card read "Currently: …", a literal ellipsis.
_rh = (ROOT / "static" / "js" / "remote_manage_host.js").read_text(encoding="utf-8")
check(_rh.count("refreshSection('#conn-ssh-card', 'loadSshStatus')") == 4
      and "refreshSection('#conn-ssh-card')" not in _rh,
      "js: every #conn-ssh-card refresh re-runs loadSshStatus",
      "%d of the call sites name the callback" % _rh.count("'loadSshStatus'"))

# ── ...and it must not call an INACTIVE firewall "tailnet only" ──────────────────────────────
# remote_public_ssh_status reads `mode` off UFW's rule list, so with UFW inactive (a fresh cloud
# VPS, or any `ufw disable`) there are no rows and mode is "off" — which the card printed as
# "disabled — tailnet only", marked "Disable (tailnet-only)" as the state in force and greyed it
# out, and disabled "Close public panel port" as "already closed", about a host with sshd and the
# panel on 0.0.0.0 and nothing in front of them. The mode means something only when active.
_sml = _js_code_only(_js_function_body(_rh, "sshModeLabel"))
_sml_i = [_sml.find(k) for k in ("d.installed === false", "d.active !== true", "SSH_LABELS[d.mode]")]
check(-1 not in _sml_i and _sml_i == sorted(_sml_i)
      and "'not filtered — UFW is inactive'" in _sml and "'not filtered — UFW is not installed'" in _sml,
      "js: the SSH card says 'not filtered' for an inactive or absent UFW before reading its mode",
      "positions %r — an inactive firewall is labelled from its (empty) rule list" % (_sml_i,))
_lss = _js_code_only(_js_function_body(_rh, "loadSshStatus"))
check("el.textContent = sshModeLabel(d)" in _lss
      and "var enforced = !d.error && d.active === true" in _lss and "isCur = enforced &&" in _lss,
      "js: ...and marks no public-SSH mode as current unless UFW is active",
      "loadSshStatus labels or marks a mode without asking whether the firewall enforces it")
_lss_i = [_lss.find(k) for k in ("d.unreachable", "d.active !== true", "d.panel_port_open === false")]
check(-1 not in _lss_i and _lss_i == sorted(_lss_i),
      "js: ...and never calls the panel port 'already closed' while UFW is off",
      "positions %r — panel_port_open === false is read before the firewall's state" % (_lss_i,))

# ── saving the auto-block threshold must not switch auto-block OFF ───────────────────────────
# saveThreshold posts the toggle's state as `enabled` ("preserve the on/off state"), but the toggle
# is rendered unchecked and repainted only when /top-ips answers — after several SSH reads. A Save
# pressed before that turned auto-block off for the host, and the toast said "auto-blocking IPs
# with N+ attempts" regardless — also for a non-superadmin, whose threshold the endpoint ignores.
_rmj = (ROOT / "static" / "js" / "remote_manage.js").read_text(encoding="utf-8")
_st_fn = _js_code_only(_js_function_body(_rmj, "saveThreshold"))
check(re.search(r"^var _autoblockKnown = false;", _rmj, re.M) is not None
      and "if(!_autoblockKnown){" in _st_fn and "return; }" in _st_fn.split("if(!_autoblockKnown){")[-1][:200]
      and _st_fn.find("if(!_autoblockKnown){") < _st_fn.find("fetch("),
      "js: the threshold Save refuses until the host's auto-block state has been read",
      "saveThreshold posts the toggle as `enabled` before anything has painted it")
_lst_fn = _js_code_only(_js_function_body(_rmj, "loadSecurityTopIps"))
check("if(tog && d && 'autoblock' in d){ tog.checked=!!d.autoblock; _autoblockKnown=true; }" in _lst_fn,
      "js: ...and it is 'read' only when a payload that carried `autoblock` painted the toggle",
      "_autoblockKnown is set somewhere other than the repaint that makes the toggle true")
_tst_fn = _js_code_only(_js_function_body(_rmj, "thresholdSaveToast"))
check("thresholdSaveToast(d, v)" in _st_fn and "!d.success" in _tst_fn
      and "Number(d.threshold)" in _tst_fn and "t !== asked" in _tst_fn and "!d.enabled" in _tst_fn,
      "js: ...and the toast says what the endpoint did — refused, ignored, saved with auto-block off",
      "the toast still says 'Threshold saved' whatever came back")

# ── the update card's changelog links each commit ─────────────────────────────────────────────
# "d456826 fix: a failed install was a dead end" told you a subject and a sha you then had to go
# and look up by hand. The sha is now a link to the commit, at the repo THIS checkout tracks (a
# fork links to the fork), which is where the changelog stops being a teaser.
#
# The href is assembled, so what matters is what it is assembled FROM. Both halves are pinned
# here: the sha comes out of a hex-only regex, and the repo URL is matched against an
# https://host/owner/repo shape before it is used at all. Anything else falls back to the plain
# text line — a link nobody vetted is worse than no link.
_upd = _rh[_rh.index("function renderUpdate"):]
_upd = _upd[:_upd.index("\n}")]
check("'/commit/'" in _upd or "'/commit/' +" in _upd or "/commit/" in _upd,
      "js: the update changelog builds a commit URL")
check("[0-9a-f]{7,40}" in _upd,
      "js: ...from a sha it has proved is hex, not from arbitrary text")
check("^https:" in _upd and "d.repo_url" in _upd,
      "js: ...and a repo URL it has matched against a repo-shaped https URL")
check("li.textContent = c" in _upd or "li.textContent=c" in _upd,
      "js: ...falling back to the plain line when either check fails",
      "no plain-text fallback — an unvetted link would render instead")
check("a.rel = 'noopener noreferrer'" in _upd,
      "js: ...and the new tab cannot reach back through window.opener")

# Two states, nothing in between. The "behind but nothing installable" branch is gone: the card is
# glanced at, and it appeared for a few minutes after every push saying nothing anyone could act on.
check(_upd.count("else if(d.message)") == 0,
      "js: the update card has no third 'behind but not installable' state",
      "a message-only branch is back")
check("You\\'re up to date" in _upd and "Update available:" in _upd,
      "js: ...just the two it is asked for")

# The "(#282)" at the end of a squash-merged subject is the part worth reading before taking an
# update — the PR says what changed and why. Same rule as the sha: the only interpolated piece is
# constrained (digits), the repo URL is the one the caller already vetted, and a missing repo URL
# falls back to plain text rather than to a half-built href.
_subj = _rh[_rh.index("function appendSubject"):]
_subj = _subj[:_subj.index("\n}")]
check("'/pull/'" in _subj, "js: a changelog subject links its PR number")
check("\\d{1,9}" in _subj, "js: ...from digits only, not from arbitrary text")
check("if(!repo)" in _subj and "createTextNode(text)" in _subj,
      "js: ...and renders plain text when there is no vetted repo URL")

# ── a top-level getElementById must never be dereferenced unguarded ───────────────────────────
# server_files.html stopped rendering the File Browser, Backups and Mods cards for a server whose
# install FAILED — there is no serverfiles to browse, back up or install a mod into. Two top-level
# listeners in server_files.js then dereferenced #file-list and #breadcrumb, which live inside the
# card that was gone. They ran BEFORE loadConfig/loadCron/loadAlerts, so the null threw and took
# the rest of the file with it: the page opened with "Loading config…", "Loading scheduled tasks…"
# and "Loading alert settings…" stuck forever — on the one page a failed install is fixed from.
#
# Every other top-level dereference in that file was already guarded, which is what made this easy
# to miss. So gate the shape rather than the two names: a statement at column 0 that reaches
# through getElementById without checking it is a page-wide crash waiting for a template change.
import re as _re_dom
for _js in ("server_files.js", "dashboard.js", "server_detail.js", "manage_servers.js"):
    _src = (ROOT / "static" / "js" / _js).read_text(encoding="utf-8")
    _bad = [ln for ln in _src.splitlines()
            if _re_dom.match(r"document\.getElementById\('[^']+'\)\s*\.", ln)]
    check(not _bad,
          "js: %s dereferences no element at top level without checking it" % _js,
          "; ".join(_bad)[:200])

# ── a failure that happens while you are LOOKING has to appear ────────────────────────────────
# The failed-install banner is rendered by the server, per host. When an install failed on a page
# already open, the status cell flipped to "Failed" (the poll writes that) and the explanation —
# the reason, Retry, Remove — did not appear until a manual reload. A row saying Failed with
# nothing to act on is the state this whole feature exists to remove.
#
# The poll compares the failed set the API reports against the banners on screen and re-renders
# the card region when they disagree. Verified in a rendered panel: installing -> failed, one
# poll, banner present with its three buttons, no page reload — and a second poll fetches nothing,
# because the sets now match.
_dashjs2 = (ROOT / "static" / "js" / "dashboard.js").read_text(encoding="utf-8")
check("failedShown" in _dashjs2 and "refreshSection('#server-cards'" in _dashjs2,
      "dashboard: a failure appearing while the page is open re-renders the card region")
# ...and re-arms it while it is at it. The call used to pass no after-hook, so this swap left the
# region rendered but un-bound: a typed filter stopped applying and host-card dragging died.
check(_dashjs2.count("refreshSection('#server-cards', 'afterDashRefresh')") == 2,
      "dashboard: ...with the same re-arm as every other swap of that region",
      "%d of the 2 call sites name the hook"
      % _dashjs2.count("refreshSection('#server-cards', 'afterDashRefresh')"))
check("failedNow !== failedShown" in _dashjs2,
      "dashboard: ...only when the banners disagree with the API, so it settles after one pass",
      "an unconditional refresh would re-fetch the page on every poll")
_dash_tpl2 = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
check('class="install-failed alert alert-warning mb-0 mx-2 mt-2 py-2 px-3"\n         data-server-id='
      in _dash_tpl2,
      "dashboard: ...and each banner carries the id the comparison reads")

# ── you have to be able to uninstall a server ─────────────────────────────────────────────────
# There was no way to, in practice. The servers live on the dashboard, and the dashboard offered
# start, restart, stop, console, files, tags and reorder — no remove. The only Uninstall in the
# panel sat on Remote Servers -> a host -> the Overview tab -> a table well down it, which is not
# somewhere anyone goes to manage a server.
#
# The gate is deliberately the SAME one, not a new weaker prompt: type the server's username, with
# the warning that this deletes every backup too. It moved from remote_manage_backups.js (host page
# only) into panel.js so both pages get it from one place, delegated on document so it survives a
# list re-render.
_pjs = (ROOT / "static" / "js" / "panel.js").read_text(encoding="utf-8")
check("uninstall-trigger" in _pjs and "requireText: short" in _pjs,
      "js: the uninstall gate lives in the shared script, so every page has it")
_rmb = (ROOT / "static" / "js" / "remote_manage_backups.js").read_text(encoding="utf-8")
check("uninstall-trigger" not in _rmb,
      "js: ...and is not a second copy left behind on the host page",
      "the host page still carries its own handler — two copies will drift")
_dash_tpl4 = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
check(_dash_tpl4.count("uninstall-trigger") == 2,
      "dashboard: a server can be uninstalled from the row AND from a failed install's banner",
      "found %d uninstall triggers" % _dash_tpl4.count("uninstall-trigger"))
check(_dash_tpl4.count('class="uninstall-form d-inline"') == 2
      and "data-confirm=\"Remove" not in _dash_tpl4,
      "dashboard: ...both through the type-the-username gate, not a plain yes/no",
      "one of them still takes a weaker confirmation for the same irreversible action")
check("{% if can_uninstall %}" in _dash_tpl4,
      "dashboard: ...and only for someone allowed to uninstall")

# ── the row's controls come back to life without a reload ─────────────────────────────────────
# The status poll re-enabled start/restart/stop (.srv-ctl) and the console (.srv-console) the
# moment an install finished — but the Files & Config link had no class to find it by, so it kept
# whatever state it was RENDERED with. Watch a server install and Files & Config stayed greyed out
# until a reload, while every control beside it came back on its own.
#
# It is not gated identically, either: a FAILED install keeps Files & Config reachable, because
# its LinuxGSM config is what survives and that page is where the usual causes are fixed.
_dash_tpl3 = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
check("btn btn-outline-secondary btn-sm srv-files" in _dash_tpl3,
      "dashboard: the Files & Config link carries a class the poll can find it by")
_dashjs4 = (ROOT / "static" / "js" / "dashboard.js").read_text(encoding="utf-8")
check("link('.srv-files', busy && s.status !== 'failed')" in _dashjs4,
      "dashboard: ...and the poll re-enables it, on the same rule the template renders with",
      "the poll still only touches .srv-console")
check("link('.srv-console', busy)" in _dashjs4,
      "dashboard: ...without changing when the console is available")

# ── the Offline tile counts failures, not installs ────────────────────────────────────────────
# It read "+1 installing or failed" in warning yellow for an install running perfectly normally,
# then "+1 installing" in grey — and then the install's progress moved inline, under the server
# itself, which made any mention here a second, vaguer version of something already on screen.
# What is left is the half worth surfacing: a failure is something to act on, and it is the other
# reason Online + Offline does not equal Total.
# Both windows start at the LINE THAT DECIDES THE COUNT, not at the element that renders it.
# Sliced from `id="offline-other"` the template window began at line 127 while the
# `{% set n_failed = ... %}` predicate is at 116; sliced from `var oo = ...` the JS window began
# one line after the filter. So the pair asserted that the RENDERING does not say "installing" —
# which it never would — and never looked at the predicate the change was about.
_dash_tpl = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
_tile = _dash_tpl[_dash_tpl.index("{% set n_failed"):]
_tile = _tile[:_tile.index('id="offline-other"') + _tile[_tile.index('id="offline-other"'):].index("</div>")]
check("{% set n_failed" in _tile and "selectattr('status', 'equalto', 'failed')" in _tile,
      "dashboard: the Offline tile's count is the one being checked",
      "the window missed the predicate, so the checks below prove nothing")
check("installing" not in _tile,
      "dashboard: the Offline tile does not mention installs at all",
      "the tile still counts or emits installs")
check("n_failed" in _tile,
      "dashboard: ...and still names failures, which are the reason the arithmetic does not close")
_dashjs = (ROOT / "static" / "js" / "dashboard.js").read_text(encoding="utf-8")
_oo = _dashjs[_dashjs.index("var failed = data.filter("):]
_oo = _oo[:_oo.index("// The failed-install banner")]
check("data.filter(" in _oo and "'failed'" in _oo,
      "dashboard: ...and so is the poll's",
      "the window missed the filter that decides what the poll counts")
check("installing" not in _oo,
      "dashboard: ...in the poll too, which rewrites this line every few seconds",
      "the poll counts or puts back an installing count")
check("textContent = 'failed'" in _oo or "word.textContent = 'failed'" in _oo,
      "dashboard: ...and the word keeps its own element, so it can be translated")
# ── install progress belongs where the server is ──────────────────────────────────────────────
# A game-server install runs for five to forty-five minutes, and its progress row lived on one
# page — so starting one from "Install a Server" showed a toast and nothing else, and the dashboard
# listed the server as installing with no progress at all.
#
# The first attempt was a dismissible card in the corner. Dismissing it lost it for good, which is
# the wrong shape for something you want to keep an eye on. It is inline now: a row directly UNDER
# the server on the dashboard, and a panel on the page you submitted from. It goes away when the
# install does, not when you close it.
_base_html = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
check("js/install_progress.js" in _base_html,
      "base: install progress is available on every page with chrome")
_inst_tpl = (ROOT / "templates" / "install_server.html").read_text(encoding="utf-8")
check('data-ajax-after="watchInstallsNow"' in _inst_tpl,
      "install page: the form opens the progress panel as soon as the install is accepted")
check('id="install-running"' in _inst_tpl and 'id="install-running-card"' in _inst_tpl,
      "install page: ...and the page it was submitted from has somewhere to show it")

_ip = (ROOT / "static" / "js" / "install_progress.js").read_text(encoding="utf-8")
check("install-progress-stack" not in _ip and "ipc-close" not in _ip,
      "js: the dismissible corner card is gone, not merely hidden",
      "the corner stack is still built")
check("data-progress-for" in _ip and "insertBefore(row, srvRow.nextSibling)" in _ip,
      "js: the dashboard row is inserted directly under the server it belongs to")
check("srvRow.children.length" in _ip,
      "js: ...spanning whatever columns that table actually has",
      "a hard-coded colspan breaks when can_control changes the column count")
check("innerHTML" not in _ip,
      "js: ...and it builds its DOM, never assembling a server name into markup")
check("data-no-i18n" in _ip,
      "js: ...with the server's own name exempt from the catalog walker")

# The two integration traps a row inside this table walks into. sortDashCol sorts every `tr`, and
# filterServers shows or hides each one on its own text and tags — a progress row carries neither,
# so unhandled it sorted away from its server and survived a filter that hid it.
_dashjs3 = (ROOT / "static" / "js" / "dashboard.js").read_text(encoding="utf-8")
check("tb.querySelectorAll('tr[data-server-id]')" in _dashjs3,
      "js: sorting sorts the SERVER rows, not every tr in the table")
# THREE paths reorder rows — the column sort, the up/down arrows and the drag handle — and only
# the first carried the progress row with it. The other two left the bar sitting under whichever
# server ended up above it, for the rest of the page's life: install_progress.js never moves an
# existing row, it only refills the one it finds by data-progress-for. So assert every reorder
# path goes through the one helper, counted from the AST — the identifier also appears in the
# comment that explains it.
if not esprima:
    skip("js: every path that reorders rows carries the progress row with them",
         "esprima not installed")
else:
    _d3_ast = esprima.parseScript(_dashjs3, {"loc": True}).toDict()
    _reattach = []

    def _count_reattach(n):
        if isinstance(n, dict):
            if (n.get("type") == "CallExpression"
                    and (n.get("callee") or {}).get("type") == "Identifier"
                    and (n.get("callee") or {}).get("name") == "reattachProgressRows"):
                _reattach.append(((n.get("loc") or {}).get("start") or {}).get("line"))
            for v in n.values():
                _count_reattach(v)
        elif isinstance(n, list):
            for v in n:
                _count_reattach(v)

    _count_reattach(_d3_ast)
    check(len(_reattach) >= 3,
          "js: every path that reorders rows carries the progress row with them",
          "reattachProgressRows is called from %d place(s) (lines %s); the column sort, the "
          "up/down arrows and the drag handle all need it"
          % (len(_reattach), ", ".join(str(x) for x in _reattach)))
check("if (tr.hasAttribute('data-progress-for')) return;" in _dashjs3
      and "prog.style.display = match" in _dashjs3,
      "js: filtering hides a progress row with its server, not on its own text")

# ── install progress has to be visible from wherever you are ──────────────────────────────────
# The progress row lives on the Game Servers page and nowhere else, so an install started from
# "Install a Server" showed a toast and then nothing at all, and the dashboard listed the server as
# installing with no progress. Three things had to line up, and all three are pinned: the widget is
# loaded on every chrome page, the install form names the hook that opens it immediately, and the
# shared ajax-form handler actually RUNS that hook.
_base_html = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
check("js/install_progress.js" in _base_html,
      "base: the install-progress widget is loaded on every page with chrome")
_inst_tpl = (ROOT / "templates" / "install_server.html").read_text(encoding="utf-8")
check('data-ajax-after="watchInstallsNow"' in _inst_tpl,
      "install page: the form opens the progress widget as soon as the install is accepted")

# data-ajax-after used to be handed ONLY to refreshSection, which runs only when data-ajax-refresh
# is set. The install form deliberately has no refresh target — the list it would refresh is on
# another page — so the attribute was silently ignored, which is the trap this pins shut.
_pj = (ROOT / "static" / "js" / "panel.js").read_text(encoding="utf-8")
_dr = _pj[_pj.index("var doRefresh = function()"):]
_dr = _dr[:_dr.index("};")]
check("else if (after &&" in _dr and "window[after]()" in _dr,
      "js: an ajax-form's after-hook runs even with no section to refresh",
      "data-ajax-after is dropped unless data-ajax-refresh is also set")

# ── the Ubuntu Pro card must not read "Not attached" off a host it could not reach ────────────
# _unreachable() answers a host that is off, rebooting or refusing SSH with 200
# {success:false, unreachable:true} — deliberately, so the UI can say "host unreachable". That
# payload carries no `installed` key at all, so UPro.render() fell past `d.installed === false`
# and `!d.attached` into the grey "Not attached" badge, the attach pitch and a live token field,
# about a machine that may be fully attached with ESM and Livepatch on. An operator who acts on
# it attaches a host twice.
#
# Asserted on the BRANCH ORDER in the AST, not on the text: the honest wording also appears in a
# comment beside it, so a string search would report the comment as the fix.
if not esprima:
    # Every name, not one: the tally is len(results), so a block that simply stops existing
    # without esprima reports "N / N passed" with these gates gone. Same reason as the CSRF
    # block near the top of this file.
    for _n in ("sweep: the Ubuntu Pro card's render/quietRefresh were found to check",
               "sweep: the Ubuntu Pro card reads its payload in more than one branch",
               "ubuntu pro card: an unreachable host is 'unknown', not 'Not attached'",
               "ubuntu pro card: ...and a host that DID answer is still rendered attached or not",
               "ubuntu pro card: a quiet re-read that failed keeps the status already painted"):
        skip(_n, "esprima not installed (pip install esprima)")
else:
    def _upro_fn(node, name, out):
        if isinstance(node, dict):
            if (node.get("type") == "FunctionDeclaration"
                    and (node.get("id") or {}).get("name") == name):
                out.append(node)
            for _v in node.values():
                _upro_fn(_v, name, out)
        elif isinstance(node, list):
            for _v in node:
                _upro_fn(_v, name, out)

    def _upro_reads(node, out):
        """Every property read off the payload `d` inside this node."""
        if isinstance(node, dict):
            if (node.get("type") == "MemberExpression"
                    and (node.get("object") or {}).get("type") == "Identifier"
                    and (node.get("object") or {}).get("name") == "d"):
                _n = (node.get("property") or {}).get("name")
                if _n:
                    out.add(_n)
            for _v in node.values():
                _upro_reads(_v, out)
        elif isinstance(node, list):
            for _v in node:
                _upro_reads(_v, out)

    _upro_ast = esprima.parseScript(_pj, {"loc": True}).toDict()
    _upro_render, _upro_quiet = [], []
    _upro_fn(_upro_ast, "render", _upro_render)
    _upro_fn(_upro_ast, "quietRefresh", _upro_quiet)
    # Anti-vacuity: without this every gate below passes on a rename or a refactor that left the
    # scan looking at nothing.
    check(len(_upro_render) == 1 and len(_upro_quiet) == 1,
          "sweep: the Ubuntu Pro card's render/quietRefresh were found to check",
          "render=%d quietRefresh=%d" % (len(_upro_render), len(_upro_quiet)))
    _upro_branches = []
    for _st in (_upro_render[0]["body"]["body"] if _upro_render else []):
        if _st.get("type") != "IfStatement":
            continue
        _seen = set()
        _upro_reads(_st["test"], _seen)
        if _seen:                      # skip `if(!EL) return;`, which reads nothing off d
            _upro_branches.append(_seen)
    check(len(_upro_branches) >= 3,
          "sweep: the Ubuntu Pro card reads its payload in more than one branch",
          "branches=%s" % _upro_branches)
    check(bool(_upro_branches) and {"unreachable", "success"} <= _upro_branches[0],
          "ubuntu pro card: an unreachable host is 'unknown', not 'Not attached'",
          "the first branch reads %s" % sorted(_upro_branches[0] if _upro_branches else []))
    # Positive control: the honest branch was ADDED in front, not substituted for the real
    # states — a card that answered "unknown" to everything would also pass the check above.
    _upro_rest = set().union(*_upro_branches[1:]) if len(_upro_branches) > 1 else set()
    check({"installed", "attached"} <= _upro_rest,
          "ubuntu pro card: ...and a host that DID answer is still rendered attached or not",
          "later branches read %s" % sorted(_upro_rest))
    # The background re-read must not overwrite a persisted, known-good status with that answer:
    # load() paints `initial` precisely so the card never blanks, and quietRefresh undid it.
    _upro_q = set()
    _upro_reads(_upro_quiet[0] if _upro_quiet else {}, _upro_q)
    check({"unreachable", "unreadable"} <= _upro_q,
          "ubuntu pro card: a quiet re-read that failed keeps the status already painted",
          "quietRefresh reads %s" % sorted(_upro_q))

# ── ...and the Banned IPs card must not call a failed read "fail2ban isn't installed" ─────────
# Both /bans routes answer a raised read with 200 {installed:false, jails:[], error:"…"}:
# installed:false is the FALLBACK SHAPE, not a measurement. loadSecurityBans read only
# `d.installed`, so a host whose SSH session was refused (key rotated, sshd restarting, tailscale
# timing out) was told it has no brute-force protection installed — on the page whose job is to
# say whether it is protected. Same branch-order gate as the Ubuntu Pro card above.
if not esprima:
    for _n in ("sweep: loadSecurityBans was found to check",
               "sweep: the Banned IPs card reads its payload in more than one branch",
               "banned IPs card: a failed read is not 'fail2ban isn't installed'",
               "banned IPs card: ...and a host that answered still reports its jails"):
        skip(_n, "esprima not installed (pip install esprima)")
else:
    def _f2b_ifs(node, out):
        if isinstance(node, dict):
            if node.get("type") == "IfStatement":
                out.append(node)
            for _v in node.values():
                _f2b_ifs(_v, out)
        elif isinstance(node, list):
            for _v in node:
                _f2b_ifs(_v, out)

    _rm_js = (ROOT / "static" / "js" / "remote_manage.js").read_text(encoding="utf-8")
    _f2b_fn = []
    _upro_fn(esprima.parseScript(_rm_js, {"loc": True}).toDict(), "loadSecurityBans", _f2b_fn)
    check(len(_f2b_fn) == 1, "sweep: loadSecurityBans was found to check",
          "found %d" % len(_f2b_fn))
    _f2b_raw = []
    _f2b_ifs(_f2b_fn[0] if _f2b_fn else {}, _f2b_raw)
    # Document order, not walk order — the branches are nested in the .then() callback.
    _f2b_raw.sort(key=lambda _s: ((_s["loc"]["start"]["line"]), (_s["loc"]["start"]["column"])))
    _f2b_branches = []
    for _st in _f2b_raw:
        _seen = set()
        _upro_reads(_st["test"], _seen)
        if _seen:
            _f2b_branches.append(_seen)
    check(len(_f2b_branches) >= 3,
          "sweep: the Banned IPs card reads its payload in more than one branch",
          "branches=%s" % _f2b_branches)
    check(bool(_f2b_branches) and {"error", "unreadable"} <= _f2b_branches[0],
          "banned IPs card: a failed read is not 'fail2ban isn't installed'",
          "the first branch reads %s" % sorted(_f2b_branches[0] if _f2b_branches else []))
    # Positive control: the two reassuring answers are still reachable for a host that DID
    # answer, so this cannot pass by the card refusing to render anything.
    _f2b_rest = set().union(*_f2b_branches[1:]) if len(_f2b_branches) > 1 else set()
    check({"installed", "jails"} <= _f2b_rest,
          "banned IPs card: ...and a host that answered still reports its jails",
          "later branches read %s" % sorted(_f2b_rest))

# The widget names a server, and a server name is user-supplied. It must never be concatenated
# into markup, and it must never be translated.
_ip = (ROOT / "static" / "js" / "install_progress.js").read_text(encoding="utf-8")
check("innerHTML" not in _ip,
      "js: the install widget builds its DOM, never assembling a server name into markup")
check("data-no-i18n" in _ip,
      "js: ...and a server's own name is exempt from the catalog walker")

# ── Ctrl/Cmd+K must not be cancelled on a page with no palette ────────────────────────────────
# palette.js is loaded unconditionally by base.html; #cmdk renders only under show_app_chrome. On
# login, force_password and the setup pages the shortcut was cancelled and nothing opened.
_pal = (ROOT / "static" / "js" / "palette.js").read_text(encoding="utf-8")
_kseg = _pal[_pal.index("e.key === 'k'"):]
_kseg = _kseg[:_kseg.index("\n    }")]          # the whole Ctrl/Cmd+K branch
check(_kseg.index("getElementById('cmdk')") < _kseg.index("e.preventDefault")
      and "if (!box) return;" in _kseg,
      "js: the palette looks for #cmdk before cancelling Ctrl/Cmd+K",
      "it still preventDefaults on pages that have no palette")

# ── the copy button on the backup-codes page must survive an insecure origin ──────────────────
# navigator.clipboard is undefined on http://, which the panel serves by default, so the property
# read threw before any promise existed and the rejection handler never ran: the click did nothing
# at all, silently, on the page whose whole point is getting the codes out of the browser.
_bc = (ROOT / "static" / "js" / "backup_codes.js").read_text(encoding="utf-8")
check("navigator.clipboard &&" in _bc and "execCommand" in _bc,
      "js: the backup-codes copy guards navigator.clipboard and falls back",
      "an http:// install gets a button that does nothing")

# ── a Jinja comment is invisible to the browser and NOT to the HTML scanner ───────────────────
# CodeQL parses the template as HTML, comments included, so prose describing a Flask route as
# "/remote/<local id>/manage" is read as a start tag `local` carrying a valueless `id` attribute
# and raises js/malformed-html-id — a red "Open code-scanning alerts" check on a pull request
# whose only change to that file was a comment. It cost a CI round trip here. Write route
# placeholders as /remote/.../manage, or name the parameter in words.
#
# Deliberately narrow: mentioning <span> or <option> in a comment is fine and several already do.
# What is flagged is only a tag-shaped run carrying a BARE `id` attribute, which is the shape the
# rule fires on.
_BARE_ID_IN_TAG = re.compile(r"<[A-Za-z][A-Za-z0-9-]*(?:\s+[^>]*?)?\s+id\s*(?:>|\s)")
_id_offenders = []
for _tpl in sorted((ROOT / "templates").rglob("*.html")):
    _s = _tpl.read_text(encoding="utf-8")
    for _m in re.finditer(r"\{#.*?#\}", _s, re.S):
        _hit = _BARE_ID_IN_TAG.search(_m.group(0))
        if _hit:
            _id_offenders.append("%s:%d %s" % (_tpl.name, _s[:_m.start()].count("\n") + 1,
                                               _hit.group(0)))
check(not _id_offenders,
      "templates: no Jinja comment holds a tag-shaped run with a bare id attribute",
      "; ".join(_id_offenders))


# ── a live page must not keep painting figures it can no longer measure ───────────────────────
# /api/dashboard/metrics omits a host it could not sample. Both pollers iterated the PAYLOAD's
# keys, so an omitted host was never reached: the dashboard's "CPU 12.5% · RAM 40.1% · Disk 55.2%"
# line and every Resources cell under it kept the last reading for as long as the page stayed
# open — with an uptime that had stopped advancing — under a header that says "Auto-refreshing",
# beside a summary tile that had ALREADY fallen back to "—". Measured in a rendered panel: a
# payload of {hosts:{},servers:{}} left all three frozen and only the tile told the truth.
#
# The loops are driven by the CELLS ON THE PAGE now, so a host the payload does not mention blanks
# instead of lying. Each window starts at the line that decides what is iterated, so a gate cannot
# pass by looking at rendering the change never touched.
#
# Every window below is sliced with _between, which ANSWERS "" when either marker is gone. Cut
# with a bare str.index these gates did not fail when the fix was reverted — they raised
# ValueError, and this suite prints its results only after the last check, so a crash here
# discarded all 172 of them and reported rc=1 with no FAIL line. A gate that cannot survive the
# absence of what it is looking for is not a gate.
def _between(text, first, last=None):
    i = text.find(first)
    if i < 0:
        return ""
    rest = text[i:]
    if last is None:
        return rest
    j = rest.find(last)
    return rest if j < 0 else rest[:j]


_dm_js = (ROOT / "static" / "js" / "dashboard.js").read_text(encoding="utf-8")
_dm_win = _between(_dm_js, "function refreshMetrics()", "refreshMetrics();")
check(bool(_dm_win),
      "dashboard: the metrics poll is where these checks think it is",
      "refreshMetrics() was not found — every check below proves nothing")
check('querySelectorAll(\'[id^="host-metrics-"]\')' in _dm_win,
      "dashboard: the host metrics line is repainted from the page's own cards",
      "the poll still only visits hosts the payload happened to carry")
check("Object.keys(hosts)" not in _dm_win,
      "dashboard: ...so a host missing from the payload is reached, not skipped",
      "iterating the payload's keys can never reach an omitted host")
check('querySelectorAll(\'[id^="res-"]\')' in _dm_win and "Object.keys(servers)" not in _dm_win,
      "dashboard: the Resources cells are repainted the same way",
      "a server whose host went quiet keeps the last CPU/RAM it was given")
# The EXACT expression that decides the text, not the identifier appearing anywhere in the window.
# `h.metrics` also sits on the next line (the summary pick), so a first version of this check read
# true with the decision itself mutated to `h && h.cpu` — a host reporting 0% would then have been
# blanked as unmeasured, and an unmeasured host with a stale cpu would have been painted.
check("el.textContent = (h && h.metrics)" in _dm_win,
      "dashboard: ...and 'no sample was taken' is what blanks them, not a falsy reading",
      "the host line is blanked on a figure's value rather than on whether one exists")
check("cell.innerHTML = (s && s.up)" in _dm_win,
      "dashboard: ...the same way for the per-server cells",
      "a server absent from the payload is not distinguished from one that is stopped")

_ms_js2 = (ROOT / "static" / "js" / "manage_servers.js").read_text(encoding="utf-8")
_ms_win = _between(_ms_js2, "function refreshMsrvMetrics()",
                   "// Same guard, and this is the expensive one")
check(bool(_ms_win),
      "game servers: the metrics poll is where this check thinks it is",
      "refreshMsrvMetrics() was not found")
check('querySelectorAll(\'[id^="msrv-res-"]\')' in _ms_win
      and "Object.keys(servers)" not in _ms_win,
      "game servers: the Resources column is repainted from the page's own rows",
      "the same freeze as the dashboard, on the page that lists every server")

# The reachability badge was rendered once by the server and never touched again, so a host that
# died while the dashboard was open went on reading "Reachable" until someone pressed F5 — the one
# fact on that card you would open the page to learn.
_dm_tpl = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
check('id="host-reach-{{ remote.id }}"' in _dm_tpl,
      "dashboard: the reachability badge carries an id the poll can find it by",
      "no id means the poll can never repaint it")
check("'host-reach-' + rid" in _dm_js,
      "dashboard: ...and the poll repaints it",
      "the badge has an id nothing uses")

# The JS now renders the same three states the template does. Two copies of one rule drift, so
# this asserts they still agree on the PAIRING — parsed out of the object literal, because a
# check that merely finds each word somewhere in the file would let the badge paint "Reachable"
# red. Reverting the pairing has to FAIL, not raise: hence _between and a regex over what it
# returns rather than an index into it.
_badge = _between(_dm_tpl, 'id="host-reach-{{ remote.id }}"', "</span>")
_reach_js = _between(_dm_js, "var HOST_REACH = {", "\n};")
_reach_pairs = dict((m.group(2), m.group(1)) for m in
                    re.finditer(r"\{cls:\s*'([^']+)',\s*text:\s*'([^']*)'", _reach_js))
_want_pairs = {"Reachable": "bg-success", "Unreachable": "bg-danger",
               "Checking\u2026": "bg-secondary"}
check(len(_reach_pairs) == 3,
      "dashboard: the poll declares exactly the three host states",
      "parsed %d state(s) from HOST_REACH: %s" % (len(_reach_pairs), sorted(_reach_pairs)))
_drift = ["%s wants %s, poll paints %s" % (_t, _c, _reach_pairs.get(_t, "nothing"))
          for _t, _c in _want_pairs.items() if _reach_pairs.get(_t) != _c]
check(not _drift,
      "dashboard: the poll pairs each host state with the class the template renders",
      "; ".join(_drift))
_tpl_drift = ["%s/%s" % (_c, _t) for _t, _c in _want_pairs.items()
              if not (_c in _badge and _t in _badge)]
check(_badge and not _tpl_drift,
      "dashboard: ...and those are the three the template itself renders",
      "the server-rendered badge no longer matches: " + ", ".join(_tpl_drift or ["badge not found"]))


# ── the firewall page must not report a firewall it never read ────────────────────────────────
# remote_ufw_status already refuses to guess: a host that did not answer comes back with
# unreachable:true rather than "installed, nothing open", and the ConnectionError branch answers
# the same shape. The TEMPLATE renders that carefully — badge "Unknown", plus a line saying the
# rules cannot be read. refreshFirewall() then threw all of it away: `enabled` is absent from that
# payload, so the badge became "Inactive" and the empty groups list became "No open ports yet."
#
# Measured against a down host: the page loaded honest and, one refresh later, reported an
# INACTIVE firewall with NOTHING OPEN. On this page that is the most alarming possible way to be
# wrong, and the template's own comment says so about the half that was already right.
_fw_js = (ROOT / "static" / "js" / "remote_firewall.js").read_text(encoding="utf-8")
_fw_win = _between(_fw_js, "function refreshFirewall()", "data.enabled ? 'Active' : 'Inactive'")
check(bool(_fw_win),
      "firewall: the refresh is where these checks think it is",
      "refreshFirewall() or its badge line was not found")
check("data.unreachable" in _fw_win,
      "firewall: the refresh checks whether the host was reachable BEFORE painting a verdict",
      "an unreachable host still repaints the badge from an absent `enabled`")
check("return;" in _fw_win,
      "firewall: ...and stops there rather than falling through to the rules table",
      "the unreachable branch carries on and renders an empty rule list")
_fw_tpl = (ROOT / "templates" / "remote_firewall.html").read_text(encoding="utf-8")
check("{% elif status.unreachable %}" in _fw_tpl,
      "firewall: the server-rendered rules list says the same, instead of 'No firewall rules yet.'",
      "the list contradicts the status card three lines above it")
# Both halves must say it the SAME way — the refresh replaces what the template rendered, and two
# wordings for one fact read as two different facts when the page swaps one for the other.
_fw_msg = "Rules can't be read while this host is unreachable."
check(_fw_msg in _fw_tpl and _fw_msg in _fw_js,
      "firewall: ...in the same words the refresh uses, since one replaces the other",
      "template and refresh word the same state differently")
# The count is an arithmetic claim. "0 rules" above "the rules cannot be read" is the same defect
# in miniature as an update card announcing a commit count it could not list.
check("rules-count" in _fw_win,
      "firewall: ...and the rule COUNT is cleared too, not left reading 0",
      "the page states a count for a firewall nothing read")

# ── a delete removes the rule that was clicked, not whatever now holds its old number ─────────
# ufw numbers are POSITIONS and renumber on every insert/delete; the hourly auto-block inserts its
# denies at 1 and releases them. deleteGroup posted the numbers read when the table was drawn, so
# after one such change a click deleted the neighbouring rule — another game's port, or the deny
# on an attacker's address. It must re-read the rules and find the group again by identity before
# EACH delete, and send that group's current number. Comments are stripped: they name the old way.
_fw_del = re.sub(r"//[^\n]*", "", _between(_fw_js, "function deleteGroup(", "\nfunction "))
check(bool(_fw_del),
      "firewall delete: deleteGroup is where these checks think it is", "not found")
_fw_next = _between(_fw_del, "(function next() {", "/firewall/delete-rule")
check("'/api/remote/' + remoteId + '/firewall')" in _fw_next and "/firewall/delete-rule" in _fw_del,
      "firewall delete: the rules are re-read before EVERY delete, not once",
      "no fresh read between the recursion point and the POST: %r" % _fw_next[:160])
check("x.key === key" in _fw_del,
      "firewall delete: ...and the group is found again by identity, not by position",
      "the clicked group is not re-resolved")
check("num: Math.max.apply(null, g.nums)" in _fw_del and "ordered[" not in _fw_del,
      "firewall delete: ...and the number sent is that group's CURRENT number",
      "a number captured at render time is still what gets deleted")
check("g.protected" in _fw_del,
      "firewall delete: ...and a group that has since become protected is not deleted",
      "the re-read does not look at protected")
# Both renderers hand the identity over, or every click refuses with "out of date".
_fw_tpl_btn = _between(_fw_tpl, 'data-action="deleteGroup"', ">")
check("{{ g.key|tojson }}" in _fw_tpl_btn,
      "firewall delete: the server-rendered × passes the group's identity",
      _fw_tpl_btn[:200])
_fw_js_btn = _between(_fw_js, "_da('deleteGroup'", "+ '><i")
check("(g.key || '')]" in _fw_js_btn,
      "firewall delete: ...and so does the × the refresh draws", _fw_js_btn[:200])

# ── the backups card must not say "none" about a host it could not read ───────────────────────
# Same family as the firewall page and the cron card: list_game_backups discarded the rc, an
# unreachable host parsed to [], and the card stated the alarming half of the pair — "nothing is
# protecting this server" — about a directory it had never reached. The endpoint reports
# backups_unreadable now, and the card branches on it.
#
# The PANEL backup list next door is deliberately untouched: it reads the panel's own data dir,
# which cannot be unreachable, so an empty list there really does mean none.
_bk_js = (ROOT / "static" / "js" / "server_files.js").read_text(encoding="utf-8")
_bk_win = _between(_bk_js, "var tb=document.getElementById('bk-rows');", "// Poll while a backup")
check(bool(_bk_win),
      "backups: the card's empty state is where this check thinks it is",
      "the bk-rows render was not found")
check("d.backups_unreadable" in _bk_win,
      "backups: the card asks whether the listing could be READ before saying there are none",
      "an unreachable host still renders 'No backups yet.'")
check("'No backups yet.'" in _bk_win,
      "backups: ...and still says that for a server that genuinely has none",
      "the real empty case lost its message")
_bk_py = (ROOT / "panel" / "routes" / "panel_backup.py").read_text(encoding="utf-8")
check(_bk_py.count('"backups_unreadable"') == 2,
      "backups: BOTH payloads carry it — the per-server card and the all-servers list",
      "found %d of the 2 places that list backups"
      % _bk_py.count('"backups_unreadable"'))
# ...and BOTH consumers branch on it. The count above is satisfied by a payload nobody reads,
# which is exactly what the all-servers Backups page was: /api/panel/backups reported the third
# state per server and this page rendered "no backups yet" regardless, next to a Files & Config
# card on the same server saying the host had not answered. One fact, two pages, opposite answers.
_bk_js2 = (ROOT / "static" / "js" / "remote_manage_backups.js").read_text(encoding="utf-8")
_bk_win2 = _between(_bk_js2, "var table = rows", "var st=g.status")
check(bool(_bk_win2),
      "backups: the all-servers page's empty state is where this check thinks it is",
      "the per-server table render was not found in remote_manage_backups.js")
check("g.backups_unreadable" in _bk_win2,
      "backups: the all-servers page asks whether the listing could be READ before saying none",
      "an unreachable host still renders 'no backups yet' for every server on it")
check(">no backups yet<" in _bk_win2,
      "backups: ...and still says that for a host that genuinely has none (positive control)",
      "the real empty case lost its message")

# ── a schedule change posts only the field that changed ──────────────────────────────────────
# Both schedule controls on each page fire one save, and it posted BOTH fields. Files & Config's
# keep <select> has no option for 9 or 11-30, so a stored keep of 14 left it with no selection and
# .value read '' — which the route takes as "clear the override". Changing only the interval
# therefore reset retention to the global 2, and the next backup deleted twelve archives. The
# route now leaves an absent field alone (smoke), and these pin the two halves in the browser.
_sbk = _js_code_only(_js_function_body(_bk_js, "saveBkSchedule"))
check("JSON.stringify(body)" in _sbk and "keep:kp" not in _sbk
      and "!==_bkShown[f[0]]" in _sbk and "el.value!==''" in _sbk,
      "backups: Files & Config posts only the schedule field that changed, never an empty one",
      "saveBkSchedule still posts {interval, keep} — a change to one resets the other")
_rbk = _js_code_only(_js_function_body(_bk_js, "renderBackups"))
_bks = _js_code_only(_js_function_body(_bk_js, "_bkShow"))
check(_rbk.count("_bkShow(") == 2 and not re.search(r"\b(?:iv|kp)\.value\s*=", _rbk)
      and "createElement('option')" in _bks and "_bkShown[field]=v" in _bks,
      "backups: ...and a stored value with no <option> gets one, so the select is never blank",
      "renderBackups assigns .value directly — a keep of 14 leaves the select with no selection")
_gss = _js_code_only(_js_function_body(_bk_js2, "setGameSchedule"))
check("JSON.stringify(body)" in _gss and "{interval:iv,keep:kp}" not in _gss.replace(" ", ""),
      "backups: the Backups page posts only the schedule field that changed, too",
      "setGameSchedule still posts {interval, keep} — a keep edit resets a 3-day interval")
_gsch = _js_code_only(_js_function_body(_bk_js2, "gameSchedule"))
check("['3','Every 3 days']" in _gsch and "ivOpts.push([ivVal" in _gsch,
      "backups: ...and its interval list offers every value Files & Config does, plus the stored one",
      "a 3-day override renders as 'Default' beside a note saying 'Custom — every 3 days'")
# The two buttons on a backup ROW read the listing too, and app.py's _find_game_backup iterates
# it — None included. Both answered a 500 with a traceback in the panel log for a host that
# simply did not answer.
check("unreadable" in _between(_bk_py, "def api_panel_backup_game_delete", "def api_panel_backup_game_schedule"),
      "backups: deleting/downloading one distinguishes 'no such backup' from 'no answer'",
      "the delete/download pair still treats an unreadable listing as 'Backup not found.'")
check("return sid, None" in _bk_py,
      "backups: ...and the all-servers worker reports a failed read as unknown, not as empty",
      "its except branch still answers [] for a host it could not reach")
# The delete path is the one that must never act on a listing it does not have.
_bk_cron = (ROOT / "panel" / "ops" / "ssh_manager" / "cron.py").read_text(encoding="utf-8")
_hr = _between(_bk_cron, "def _ensure_backup_headroom", "def run_game_backup")
check("if backups is None:" in _hr,
      "backups: the prune-to-make-room path refuses a listing it could not read",
      "the one path here that DELETES backups still acts on an unknown listing")

passed = sum(1 for c, _, _ in results if c is True)
failed = sum(1 for c, _, _ in results if c is False)
skipped = [(name, detail) for c, name, detail in results if c is None]
for c, name, detail in results:
    label = "PASS" if c is True else "FAIL" if c is False else "SKIP"
    # str(): a check that passed an int (or None) as its detail used to crash HERE, on the very
    # last loop of the suite, so a genuine FAIL was reported as a TypeError traceback and every
    # result after it was lost. The reporter must never be the thing that breaks.
    print("%s  %s%s" % (label, name, "" if c is True else "  -> " + str(detail)))
print("\n%d / %d checks passed" % (passed, len(results) - len(skipped)))
if skipped:
    print("\n%d CHECK(S) DID NOT RUN:" % len(skipped))
    for name, detail in skipped:
        print("  SKIP  %s   [%s]" % (name, detail))
# A SKIP fails the suite. The others treat a skip as "the environment is not the code's fault",
# but this one is invoked from CI where esprima IS installed, and its skips take the JS parse gate
# and four CSRF gates with them — exactly the "294 smoke checks stayed green" failure the parse
# check exists to catch. Red here says `pip install esprima`, which is a one-line fix; green here
# said nothing at all.
sys.exit(0 if (results and failed == 0 and not skipped) else 1)
