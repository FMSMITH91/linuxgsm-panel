"""Part 14 of the unit suite: the JavaScript coverage harness (tools/js_coverage) and its CI job.

The harness itself needs a browser and is run by CI's js-coverage job, not here. What is checked
here is everything that decides whether its number means anything without one: the V8 -> LCOV
conversion, the harness's refusal to run against a real data directory, what it imports (nothing
the panel does not already pin), and the CI job's wiring. The upload side — the LCOV check in
codacy-coverage.yml — is exercised with the Python report's, in part06.
"""
import ast
import importlib.util as _ilu14
import subprocess as _sp14
import tempfile as _tf14

from unit.part01 import check, os, re, sys  # noqa: F401,E402
from unit.part05 import _root  # noqa: E402

_JC_DIR = os.path.join(_root, "tools", "js_coverage")


def _jc_load(name):
    spec = _ilu14.spec_from_file_location("jscov_" + name, os.path.join(_JC_DIR, name + ".py"))
    mod = _ilu14.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_v8 = _jc_load("v8_lcov")


def _fn(*ranges):
    """A V8 function entry from (start, end, count) ranges, outermost first, as V8 lists them."""
    return {"functionName": "f", "isBlockCoverage": True,
            "ranges": [{"startOffset": a, "endOffset": b, "count": c} for a, b, c in ranges]}


# ── the innermost range decides ────────────────────────────────────────────────────────────────
# A function that ran twice with a branch inside it that never ran: the branch's offsets read 0,
# the rest of the function 2, and code outside it the script's 1. Given out of order, too: V8 lists
# functions by where they start, but nothing here may rely on that.
_v8_take = [_fn((0, 100, 1)), _fn((40, 60, 0)), _fn((10, 90, 2))]
check("js coverage: the count at an offset is its innermost range's — a branch not taken inside a "
      "function that ran reads 0",
      _v8.counts_at(_v8_take, [5, 15, 45, 59, 60, 95, 100]) == [1, 2, 0, 0, 2, 1, 0],
      repr(_v8.counts_at(_v8_take, [5, 15, 45, 59, 60, 95, 100])))
check("js coverage: ...ranges are half-open [start, end), and nesting that shares a start still "
      "resolves to the inner one",
      _v8.counts_at([_fn((0, 10, 5), (0, 4, 1))], [0, 3, 4, 9, 10]) == [1, 1, 5, 5, 0])

# ── lines: V8's own locations, summed over takes, and a line is hit if any location on it ran ──
_v8_src = ("function a() {\n"          # line 1
           "  // a comment\n"          # line 2: no location, so not a line
           "\n"                        # line 3: nor this
           "  if (x) { b(); }\n"       # line 4
           "}\n")                      # line 5
_v8_starts = _v8.line_starts(_v8_src)
_v8_locs = [(0, 13), (3, 2), (3, 11), (4, 0)]
_v8_off = [_v8_starts[ln] + c for ln, c in _v8_locs]
# take 1: the function ran once and its `if` body did not; take 2: it ran once more, body taken.
_v8_t1 = [_fn((0, len(_v8_src), 1)), _fn((0, _v8_starts[4] + 1, 1), (_v8_off[2] - 2, _v8_off[2] + 6, 0))]
_v8_t2 = [_fn((0, len(_v8_src), 0)), _fn((0, _v8_starts[4] + 1, 1))]
check("js coverage: only lines holding a V8 location are lines — a comment or a blank line is "
      "neither covered nor missed",
      sorted(_v8.line_hits(_v8_locs, _v8_src, [_v8_t1])) == [1, 4, 5],
      repr(_v8.line_hits(_v8_locs, _v8_src, [_v8_t1])))
check("js coverage: ...a line is hit when any location on it ran (the `if` did, its body not)",
      _v8.line_hits(_v8_locs, _v8_src, [_v8_t1]) == {1: 1, 4: 1, 5: 1},
      repr(_v8.line_hits(_v8_locs, _v8_src, [_v8_t1])))
check("js coverage: ...and every take counts: V8 resets its counters at each one, so they are summed",
      _v8.line_hits(_v8_locs, _v8_src, [_v8_t1, _v8_t2]) == {1: 2, 4: 2, 5: 2}
      and _v8.line_hits([(3, 11)], _v8_src, [_v8_t1, _v8_t2]) == {4: 1},
      repr(_v8.line_hits(_v8_locs, _v8_src, [_v8_t1, _v8_t2])))

# ── V8 measures a script in UTF-16 units, and ends lines where JavaScript does ─────────────────
# An emoji before an offset is TWO units to V8 and one character to Python; \r\n is one line end,
# and so is U+2028, which Python's splitlines agrees with but \x0c (form feed) it wrongly adds.
_v8_u = "var a = '\U0001F600';\nb();\r\nc();\u2028d();\x0ce();\n"
check("js coverage: line starts are in UTF-16 units, at JavaScript's line terminators only",
      _v8.line_starts(_v8_u) == [0, 14, 20, 25, 35],
      repr(_v8.line_starts(_v8_u)))
check("js coverage: ...so a location after a non-BMP character lands on the right range",
      _v8.line_hits([(1, 0)], _v8_u, [[_fn((0, 60, 1), (14, 18, 0))]]) == {2: 0}
      and _v8.line_hits([(1, 0)], _v8_u, [[_fn((0, 60, 1), (13, 14, 0))]]) == {2: 1})

# ── the LCOV written, and the summary's "largest missed runs" ─────────────────────────────────
check("js coverage: LCOV holds line records only, one file per record, files in order",
      _v8.to_lcov({"static/js/b.js": {3: 0, 1: 2}, "static/js/a.js": {7: 1}}) ==
      "TN:\nSF:static/js/a.js\nDA:7,1\nLF:1\nLH:1\nend_of_record\n"
      "TN:\nSF:static/js/b.js\nDA:1,2\nDA:3,0\nLF:2\nLH:1\nend_of_record\n"
      and _v8.to_lcov({}) == "")
check("js coverage: missed runs are consecutive executable lines with no hits, largest first",
      _v8.missed_spans({1: 1, 2: 0, 5: 0, 9: 0, 10: 3, 11: 0, 12: 1, 20: 0}) ==
      [(2, 9, 3), (11, 11, 1), (20, 20, 1)])

# ── what the harness produces, the upload accepts ─────────────────────────────────────────────
# codacy-coverage.yml refuses an LCOV with any file outside static/js/<name>.js, and run.py lists
# every static/js/*.js in its report. A file there whose name the upload would refuse would stop
# the whole JavaScript upload; one the harness's URL pattern would not match would read as never
# loaded. Both patterns, against every file actually there.
_run_src = open(os.path.join(_JC_DIR, "run.py"), encoding="utf-8").read()
_drv_src = open(os.path.join(_JC_DIR, "driver.py"), encoding="utf-8").read()
_cc_src7 = open(os.path.join(_root, ".github", "workflows", "codacy-coverage.yml"),
                encoding="utf-8").read()
_jc_up_re = re.search(r'path_re = re\.compile\(r"([^"]+)"\)', _cc_src7)
_jc_url_re = re.search(r'JS_URL_PATH = re\.compile\(r"([^"]+)"\)', _drv_src)
_jc_js = sorted(f for f in os.listdir(os.path.join(_root, "static", "js")) if f.endswith(".js"))
_jc_bad = [f for f in _jc_js
           if not (_jc_up_re and re.fullmatch(_jc_up_re.group(1), "static/js/" + f))
           or not (_jc_url_re and re.fullmatch(_jc_url_re.group(1), "/static/js/" + f))]
check("js coverage: every static/js file is named so the harness counts it and the upload accepts it",
      len(_jc_js) >= 20 and _jc_up_re is not None and _jc_url_re is not None and not _jc_bad,
      repr(_jc_bad))

# ── nothing to install: the harness imports the standard library, itself, and what the panel pins ─
# The CI job installs requirements.txt and nothing else. A harness that grew an import of its own
# would fail there (or, worse, get an unpinned install added to make it pass), so every import in
# tools/js_coverage/*.py is the standard library, a sibling module, a module of the panel's own
# tree (serve.py runs inside it), or a package requirements.in names.
_jc_reqs = {re.split(r"[^A-Za-z0-9_.-]", _l.strip(), maxsplit=1)[0].lower().replace("-", "_")
            for _l in open(os.path.join(_root, "requirements.in"), encoding="utf-8")
            if _l.strip() and not _l.lstrip().startswith("#")}
_jc_import_as = {"websocket_client": "websocket"}
_jc_allowed = ({_jc_import_as.get(_r, _r) for _r in _jc_reqs} | set(sys.stdlib_module_names)
               | {os.path.basename(_f)[:-3] for _f in os.listdir(_JC_DIR) if _f.endswith(".py")}
               | {"panel", "app", "db_maintenance"})
_jc_foreign = []
_jc_files = sorted(_f for _f in os.listdir(_JC_DIR) if _f.endswith(".py"))
for _f in _jc_files:
    for _n in ast.walk(ast.parse(open(os.path.join(_JC_DIR, _f), encoding="utf-8").read())):
        _mods = ([_a.name for _a in _n.names] if isinstance(_n, ast.Import)
                 else [_n.module] if isinstance(_n, ast.ImportFrom) and _n.module and not _n.level
                 else [])
        _jc_foreign += ["%s: %s" % (_f, _m) for _m in _mods if _m.split(".")[0] not in _jc_allowed]
_jc_manifests = [_f for _f in os.listdir(_JC_DIR)
                 if _f in ("package.json", "package-lock.json") or _f.startswith("requirements")]
check("js coverage: the harness imports only the standard library, itself, the panel, and what "
      "requirements.in pins, and brings no manifest of its own",
      {"run.py", "serve.py", "driver.py", "cdp.py", "v8_lcov.py", "fake_host.py"} <= set(_jc_files)
      and "websocket" in _jc_allowed and not _jc_foreign and not _jc_manifests,
      repr((_jc_foreign, _jc_manifests)))

# ── the harness never runs against a real data directory ─────────────────────────────────────
# serve.py boots a panel and writes its database, and DATA_DIR is a fixed path inside whatever tree
# it runs from. It refuses unless run.py's marker is at that tree's root — a copy run.py made — and
# says so BEFORE it imports anything of the panel's. Run here from a copy of the harness alone, so
# a guard that stopped working fails on a missing import instead of writing anything anywhere.
_jc_tmp = _tf14.mkdtemp(prefix="jscov-guard-")
try:
    os.makedirs(os.path.join(_jc_tmp, "tools", "js_coverage"))
    for _f in _jc_files:
        with open(os.path.join(_JC_DIR, _f), "rb") as _i, \
                open(os.path.join(_jc_tmp, "tools", "js_coverage", _f), "wb") as _o:
            _o.write(_i.read())
    _jc_p = _sp14.run([sys.executable, os.path.join(_jc_tmp, "tools", "js_coverage", "serve.py")],
                     capture_output=True, text=True, timeout=60, cwd=_jc_tmp,
                     env=dict(os.environ, JS_COVERAGE_USER="u", JS_COVERAGE_PASSWORD="p" * 20))
    check("js coverage: serve.py refuses to start in a tree run.py did not copy, before touching it",
          _jc_p.returncode == 2 and "refusing" in _jc_p.stdout and "not a throwaway copy" in _jc_p.stdout
          and sorted(os.listdir(_jc_tmp)) == ["tools"],
          "rc=%s out=%r err=%r" % (_jc_p.returncode, _jc_p.stdout[-200:], _jc_p.stderr[-300:]))
finally:
    import shutil as _sh7
    _sh7.rmtree(_jc_tmp, ignore_errors=True)

# run.py's copy leaves out the checkout's data/ (the real one, at the root only — lgsm/data is
# code), VCS and virtualenvs, and marks the copy as the throwaway it is.
_jc_run = _jc_load("run")
_jc_src_tree = _tf14.mkdtemp(prefix="jscov-src-")
_jc_dst_tree = os.path.join(_tf14.mkdtemp(prefix="jscov-dst-"), "tree")
try:
    for _rel in ("app.py", "data/panel.db", "data/config.json", "lgsm/data/serverlist.csv",
                 ".git/HEAD", ".venv/bin/python", "static/js/panel.js", "tools/x/.claude/a"):
        os.makedirs(os.path.dirname(os.path.join(_jc_src_tree, _rel)), exist_ok=True)
        open(os.path.join(_jc_src_tree, _rel), "w").close()
    _jc_saved_root = _jc_run.ROOT
    _jc_run.ROOT = _jc_src_tree
    try:
        _jc_run.copy_tree(_jc_dst_tree)
    finally:
        _jc_run.ROOT = _jc_saved_root
    _jc_got = sorted(os.path.relpath(os.path.join(_d, _f), _jc_dst_tree)
                     for _d, _ds, _fs in os.walk(_jc_dst_tree) for _f in _fs)
    check("js coverage: run.py's copy leaves out the real data/, .git and .venv, keeps lgsm/data, "
          "and carries the throwaway marker",
          _jc_got == [".js-coverage-throwaway", "app.py", "lgsm/data/serverlist.csv",
                      "static/js/panel.js"],
          repr(_jc_got))
finally:
    import shutil as _sh7b
    _sh7b.rmtree(_jc_src_tree, ignore_errors=True)
    _sh7b.rmtree(os.path.dirname(_jc_dst_tree), ignore_errors=True)

# ── the CI job ─────────────────────────────────────────────────────────────────────────────────
# It runs the harness and FAILS when there is nothing to report — no `|| true`, no
# continue-on-error — pins every action to a commit, reads the repository and nothing else,
# installs only the panel's hash-locked requirements, and hands its report on as the artifact
# codacy-coverage.yml downloads (the names are tied in part06).
_ci7 = open(os.path.join(_root, ".github", "workflows", "ci.yml"), encoding="utf-8").read()
_ci7_code = "\n".join(_l for _l in _ci7.splitlines() if not _l.lstrip().startswith("#"))
_jcj_at = _ci7_code.find("\n  js-coverage:\n")
_jcj = _ci7_code[_jcj_at:] if _jcj_at >= 0 else ""
_jcj_end = re.search(r"\n  [a-z][a-z0-9_-]*:\n", _jcj[1:])
_jcj = _jcj[:_jcj_end.start() + 1] if _jcj_end else _jcj
_jcj_uses = re.findall(r"uses: (\S+)", _jcj)
_jcj_pip = re.findall(r"pip install[^\n]*", _jcj)
check("js coverage (CI): the job pins every action to a commit, reads the repository only, and "
      "keeps no token in .git",
      len(_jcj_uses) == 3 and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", _u) for _u in _jcj_uses)
      and re.search(r"\n    permissions:\n      contents: read\n    steps:", _jcj) is not None
      and "secrets." not in _jcj and "persist-credentials: false" in _jcj,
      repr((_jcj_uses, _jcj[:200])))
check("js coverage (CI): ...installs only requirements.txt, hash-checked, and runs the harness "
      "with nothing that turns its failure into a pass",
      _jcj_pip == ["pip install --quiet --require-hashes --only-binary :all: -r requirements.txt"]
      and "python tools/js_coverage/run.py --chrome" in _jcj and "--out lcov.info" in _jcj
      and "|| true" not in _jcj and "continue-on-error" not in _jcj and "set -euo pipefail" in _jcj
      and "if-no-files-found: error" in _jcj,
      repr(_jcj_pip))
# run.py's own exits: a panel that did not boot, a sign-in that did not land, and a report with no
# line hit are all non-zero — read from the source, since running it needs a browser.
check("js coverage: run.py fails, rather than reporting, when the panel does not boot, the sign-in "
      "does not land, or no line ran",
      'fail("the panel did not boot' in _run_src and "except LoginFailed" in _run_src
      and re.search(r"if th == 0:\n\s+fail\(", _run_src) is not None
      and re.search(r"def fail\(msg, code=2\):\n[^\n]*\n\s+sys\.exit\(code\)", _run_src) is not None,
      "")
