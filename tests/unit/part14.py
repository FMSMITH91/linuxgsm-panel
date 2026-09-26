"""Part 14 of the unit suite: the JavaScript coverage harness (tools/js_coverage) and its CI job.

The harness itself needs a browser and is run by CI's js-coverage job, not here. What is checked
here is everything that decides whether its number means anything without one: the V8 -> LCOV
conversion, the harness's refusal to run against a real data directory, what it imports (nothing
the panel does not already pin), and the CI job's wiring. The upload side — the LCOV check in
codacy-coverage.yml — is exercised with the Python report's, in part06.
"""
import ast
import contextlib as _ctx14
import importlib.util as _ilu14
import io as _io14
import signal as _sig14
import subprocess as _sp14
import tempfile as _tf14
import time as _time14

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

# V8 also reports a location at the very end of a script, which in a file that ends with a newline
# is a line past the last one. It is not a line of the file and must not be reported as one: LCOV
# naming line 714 of a 713-line file is a line of "code" nobody can find.
check("js coverage: the script's end, on the line after a file's final newline, is not a line",
      _v8.line_hits([(0, 0), (1, 0), (2, 0)], "f();\ng();\n", [[_fn((0, 11, 1))]]) == {1: 1, 2: 1}
      and _v8.line_hits([(0, 0), (1, 3)], "f();\ng();", [[_fn((0, 9, 1))]]) == {1: 1, 2: 1},
      repr(_v8.line_hits([(0, 0), (1, 0), (2, 0)], "f();\ng();\n", [[_fn((0, 11, 1))]])))

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
_cc_src14 = open(os.path.join(_root, ".github", "workflows", "codacy-coverage.yml"),
                encoding="utf-8").read()
_jc_up_re = re.search(r'path_re = re\.compile\(r"([^"]+)"\)', _cc_src14)
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
    import shutil as _sh14
    _sh14.rmtree(_jc_tmp, ignore_errors=True)

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
    import shutil as _sh14b
    _sh14b.rmtree(_jc_src_tree, ignore_errors=True)
    _sh14b.rmtree(os.path.dirname(_jc_dst_tree), ignore_errors=True)

# ── the CI job ─────────────────────────────────────────────────────────────────────────────────
# It runs the harness and FAILS when there is nothing to report — no `|| true`, no
# continue-on-error — pins every action to a commit, reads the repository and nothing else,
# installs only the panel's hash-locked requirements, and hands its report on as the artifact
# codacy-coverage.yml downloads (the names are tied in part06).
_ci14 = open(os.path.join(_root, ".github", "workflows", "ci.yml"), encoding="utf-8").read()
_ci14_code = "\n".join(_l for _l in _ci14.splitlines() if not _l.lstrip().startswith("#"))
_jcj_at = _ci14_code.find("\n  js-coverage:\n")
_jcj = _ci14_code[_jcj_at:] if _jcj_at >= 0 else ""
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
# ── run.py's exits: no measurement is never a report ─────────────────────────────────────────
# Run, not read: the old check matched run.py's source for `fail("the panel did not boot` and
# `if th == 0:`, which a refactor removes without changing what happens — and a regression that
# kept the text would have passed it. Each exit below goes through main() itself, with the browser
# session replaced by a stand-in, and reads the exit status and what it printed.


class _JcDriver:
    """What main() and measure_and_report() read of a Driver, with the numbers given."""

    def __init__(self, hits, unreached=()):
        self._hits = hits
        self.loaded = set(hits)
        self.errors, self.held, self.unreached = [], 0, list(unreached)
        self.snapshots = 0

    def snapshot(self):
        self.snapshots += 1

    def hits(self):
        return self._hits


def _jc_main(session_enter, chrome="/usr/bin/chrome-stand-in"):
    """Run run.main() with Session and the walk stood in for; (exit status, output, out dir)."""
    _out_dir = _tf14.mkdtemp(prefix="jscov-main-")

    class _Session:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return session_enter()

        def __exit__(self, *_e):
            return False

    _saved = (_jc_run.Session, _jc_run.walk, _jc_run.find_chrome, _sig14.getsignal(_sig14.SIGTERM))
    _jc_run.Session, _jc_run.walk = _Session, (lambda _d, only=None: None)
    _jc_run.find_chrome = lambda _explicit: chrome
    _buf = _io14.StringIO()
    try:
        with _ctx14.redirect_stdout(_buf):
            try:
                _rc = _jc_run.main(["--out", os.path.join(_out_dir, "lcov.info"),
                                    "--summary", os.path.join(_out_dir, "summary.txt")])
            except SystemExit as _e:
                _rc = _e.code
    finally:
        _jc_run.Session, _jc_run.walk, _jc_run.find_chrome = _saved[:3]
        _sig14.signal(_sig14.SIGTERM, _saved[3])
    return _rc, _buf.getvalue(), _out_dir


def _jc_raise(msg, code=2):
    def _enter():
        raise _jc_run.Abort(msg, code)
    return _enter


_jc_good = {"static/js/a.js": {1: 2, 2: 0}, "static/js/b.js": {4: 0}}
_jc_cases = {
    "no browser": _jc_main(lambda: _JcDriver(_jc_good), chrome=None),
    "panel did not boot": _jc_main(_jc_raise("the panel did not boot (no /healthz on x)")),
    "sign-in did not land": _jc_main(_jc_raise("signing in did not land — every page would be "
                                               "measured as the login form")),
    "nothing ran": _jc_main(lambda: _JcDriver({"static/js/a.js": {1: 0}, "static/js/b.js": {}})),
    "a page not reached": _jc_main(lambda: _JcDriver(_jc_good, [("/servers/manage",
                                                                 "redirected to /")])),
    "measured": _jc_main(lambda: _JcDriver(_jc_good)),
}
try:
    _jc_want = {"no browser": (2, "no Chrome/Chromium found"),
                "panel did not boot": (2, "the panel did not boot"),
                "sign-in did not land": (2, "signing in did not land"),
                "nothing ran": (3, "the coverage is empty"),
                "a page not reached": (2, "did not reach 1 page(s) it names")}
    _jc_wrong = {_k: _jc_cases[_k][:2] for _k, (_rc, _msg) in _jc_want.items()
                 if not (_jc_cases[_k][0] == _rc and _msg in _jc_cases[_k][1]
                         and re.search(r"^(ERROR: |::error::).*" + re.escape(_msg),
                                       _jc_cases[_k][1], re.M))}
    check("js coverage: run.py exits non-zero, saying why, when there is no browser, the panel does "
          "not boot, the sign-in does not land, nothing ran, or a page it names was not reached",
          not _jc_wrong, repr(_jc_wrong))
    _jc_ok = _jc_cases["measured"]
    _jc_lcov = open(os.path.join(_jc_ok[2], "lcov.info")).read()
    check("js coverage: ...and a run that measured something exits 0 with both reports written "
          "(positive control)",
          _jc_ok[0] == 0 and "SF:static/js/a.js\nDA:1,2\nDA:2,0\nLF:2\nLH:1\n" in _jc_lcov
          and "SF:static/js/b.js\nDA:4,0\nLF:1\nLH:0\n" in _jc_lcov
          and "TOTAL" in open(os.path.join(_jc_ok[2], "summary.txt")).read(),
          repr((_jc_ok[0], _jc_ok[1][-300:], _jc_lcov[:200])))
    # The empty and the unreached runs must not leave a report that reads as a measurement.
    check("js coverage: ...and the unreached run names the page and why",
          "/servers/manage (redirected to /)" in _jc_cases["a page not reached"][1],
          _jc_cases["a page not reached"][1][-300:])
finally:
    for _c in _jc_cases.values():
        _sh14b.rmtree(_c[2], ignore_errors=True)

# A panel process that exits instead of serving is "did not boot" at once, with its log shown —
# not a 90-second wait and then a walk of connection errors. start_panel against a tree whose
# runner dies on start.
_jc_dead = _tf14.mkdtemp(prefix="jscov-dead-")
try:
    os.makedirs(os.path.join(_jc_dead, "tree", "tools"))
    with open(os.path.join(_jc_dead, "tree", "tools", "nosudo_runner.py"), "w") as _fh:
        _fh.write("print('refusing: stand-in panel'); raise SystemExit(2)\n")
    _jc_t0 = _time14.monotonic()
    _jc_buf = _io14.StringIO()
    try:
        with _ctx14.redirect_stdout(_jc_buf):
            _jc_run.start_panel(os.path.join(_jc_dead, "tree"), _jc_dead, "u", "p" * 20)
        _jc_abort = None
    except _jc_run.Abort as _e:
        _jc_abort = _e
    check("js coverage: start_panel says the panel did not boot as soon as it exits, and shows its "
          "log",
          _jc_abort is not None and "the panel did not boot" in str(_jc_abort)
          and _jc_abort.code == 2 and "refusing: stand-in panel" in _jc_buf.getvalue()
          and _time14.monotonic() - _jc_t0 < 30,
          repr((_jc_abort, _jc_buf.getvalue()[-200:])))
finally:
    _sh14b.rmtree(_jc_dead, ignore_errors=True)

# ── the driver: a leaving page's counts are kept, and a page the walk names must be reached ───
# V8 drops a document's scripts, and their counts, when the document goes; the driver pauses the
# page on its own `navigate` event, takes the counts, and resumes only from the take's reply. With
# a stand-in protocol client: what start() asks of the browser, the order of take and resume, and
# which scripts' counts are kept.


class _JcCDP:
    """Records calls and sends; hands back the replies the driver asks for."""

    def __init__(self):
        self.calls, self.sent, self.pending, self.events = [], [], [], []
        self.on_event = None

    def call(self, method, params=None, timeout=30):
        self.calls.append((method, params or {}))
        if method == "Runtime.compileScript":
            return {"scriptId": "9"}
        if method == "Debugger.getPossibleBreakpoints":
            return {"locations": [{"lineNumber": 0, "columnNumber": 0},
                                  {"lineNumber": 1, "columnNumber": 2}]}
        return {}

    def send(self, method, params=None, on_reply=None):
        self.sent.append(method)
        if on_reply is not None:
            self.pending.append(on_reply)

    def pump(self, _seconds):
        pass


_jc_cdp = _JcCDP()
_jc_drv = _jc_run.Driver(_jc_cdp, "http://127.0.0.1:1", "u", "p" * 20,
                         {"static/js/a.js": "f();\n  g();\n", "static/js/b.js": "h();\n"})
_jc_drv.start()
_jc_calls = dict(_jc_cdp.calls)
check("js coverage: the driver starts block coverage with call counts, breaks on `navigate`, and "
      "does not skip its own pauses",
      _jc_calls.get("Profiler.startPreciseCoverage") == {"callCount": True, "detailed": True}
      and _jc_calls.get("DOMDebugger.setEventListenerBreakpoint") == {"eventName": "navigate"}
      and _jc_calls.get("Debugger.setSkipAllPauses", {}).get("skip") is not True
      and "navigation.addEventListener('navigate'" in _jc_drv._helpers,
      repr(_jc_cdp.calls))
_jc_cdp.on_event({"method": "Debugger.paused", "params": {"reason": "EventListener"}})
_jc_before = (list(_jc_cdp.sent), len(_jc_cdp.pending))
if _jc_cdp.pending:
    _jc_cdp.pending.pop()({"id": 1, "result": {"result": [
        {"url": "http://127.0.0.1:1/static/js/a.js?v=1f2e",
         "functions": [{"ranges": [{"startOffset": 0, "endOffset": 12, "count": 3}]}]},
        {"url": "http://127.0.0.1:1/static/vendor/x/b.js",
         "functions": [{"ranges": [{"startOffset": 0, "endOffset": 5, "count": 1}]}]},
        {"url": "http://elsewhere.example/static/js/b.js",
         "functions": [{"ranges": [{"startOffset": 0, "endOffset": 5, "count": 1}]}]}]}})
check("js coverage: a page pausing to leave is resumed only after its counts are taken, and they "
      "are kept for its own static/js scripts alone",
      _jc_before == (["Profiler.takePreciseCoverage"], 1)
      and _jc_cdp.sent == ["Profiler.takePreciseCoverage", "Debugger.resume"]
      and _jc_drv.hits() == {"static/js/a.js": {1: 3, 2: 3}, "static/js/b.js": {1: 0}}
      and _jc_drv.loaded == {"static/js/a.js"} and _jc_drv.held == 1,
      repr((_jc_before, _jc_cdp.sent, _jc_drv.hits(), _jc_drv.loaded)))

# reached(): a page that answers an error or lands somewhere else is recorded — by exercise()
# itself, not only when reached() is called directly — except in the pass that confirms deletions,
# where a page an earlier OK removed is expected to be gone.
_jc_nav = {"status": 200, "path": "/users"}
_jc_drv.goto = lambda _p, settle=True: None
_jc_drv.path = lambda: _jc_nav["path"]
_jc_drv.doc_status = 200
_jc_seen = []
for _status, _landed, _accept in ((200, "/users", False), (404, "/users", False),
                                  (200, "/", False), (200, "/", True)):
    _jc_drv.unreached = []
    _jc_drv.doc_status, _jc_nav["path"] = _status, _landed
    _jc_drv.confirming = {"/users": {"BUTTON|x"}}
    _jc_drv.js = lambda _e, timeout=30: (list(_jc_nav.get("scripts", [])) if "document.scripts" in _e
                                         else {"dialogs": 0, "path": _jc_nav["path"], "sig": None})
    with _ctx14.redirect_stdout(_io14.StringIO()):
        _jc_drv.exercise("/users", accept=_accept)
    _jc_seen.append(list(_jc_drv.unreached))
check("js coverage: a page the walk names that answers an HTTP error or redirects is recorded as "
      "not reached, by the walk's own exercise() — but not in the confirming pass",
      _jc_seen == [[], [("/users", "HTTP 404")], [("/users", "redirected to /")], []],
      repr(_jc_seen))

# ...and so is one that renders but loads a panel script under a URL the counting would not match:
# walked in full and measured as nothing. A script under the panel's mount IS counted.
_jc_seen = []
for _scripts in (["http://127.0.0.1:1/static/js/users.js?v=3", "http://127.0.0.1:1/lgsm/static/js/panel.js"],
                 ["http://127.0.0.1:1/a/b/static/js/users.js"],
                 ["http://127.0.0.1:2/static/js/users.js"]):
    _jc_drv.unreached, _jc_drv.doc_status, _jc_nav["path"] = [], 200, "/users"
    _jc_nav["scripts"] = _scripts
    with _ctx14.redirect_stdout(_io14.StringIO()):
        _jc_drv.exercise("/users")
    _jc_seen.append([_w for _p, _w in _jc_drv.unreached])
check("js coverage: a page whose panel scripts would not be counted is recorded as not reached; one "
      "under the panel's mount is counted",
      _jc_seen[0] == [] and len(_jc_seen[1]) == 1 and "would not be counted" in _jc_seen[1][0]
      and "/a/b/static/js/users.js" in _jc_seen[1][0] and len(_jc_seen[2]) == 1
      and _jc_drv.repo_path("http://127.0.0.1:1/lgsm/static/js/panel.js") == "static/js/panel.js",
      repr(_jc_seen))
_jc_nav["scripts"] = []
