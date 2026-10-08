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
import subprocess as _sp14  # nosec B404 - runs this interpreter and bash on the suite's own files
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
    _jc_p = _sp14.run([sys.executable, os.path.join(_jc_tmp, "tools", "js_coverage", "serve.py")],  # nosec B603 - a fixed argv
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
      len(_jcj_uses) == 4 and _jcj_uses[0].startswith("step-security/harden-runner@")
      and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", _u) for _u in _jcj_uses)
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

# ...and the Measure step itself, RUN, with run.py stood in for by a `python` on PATH that exits as
# told: the step must leave with run.py's status (and so stop the upload after it), put the summary
# on the run page either way, and fail — saying so — on a runner with no Chrome. PATH holds nothing
# but the stand-ins, so a runner that does have Chrome cannot make the last case pass by accident.
_jcm = re.search(r"- name: Measure\n\s+run: \|\n((?:\s{10}.*\n|\s*\n)+)", _ci14)
_jcm_code = "\n".join(_l[10:] for _l in _jcm.group(1).splitlines()) if _jcm else ""
_jcm_sb = _tf14.mkdtemp(prefix="jscov-ci-")
try:
    _jcm_bin = os.path.join(_jcm_sb, "bin")
    os.makedirs(_jcm_bin)
    for _n, _body in (("python", "#!/bin/sh\necho \"$*\" > args\n"
                                 "[ -n \"$JC_SUMMARY\" ] && echo \"$JC_SUMMARY\" > js-coverage.txt\n"
                                 "exit \"$JC_RC\"\n"),
                      ("google-chrome", "#!/bin/sh\nexit 0\n")):
        # Created owner-only and executable in the one open: no window in which it is anyone else's.
        with os.fdopen(os.open(os.path.join(_jcm_bin, _n), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700),
                       "w") as _fh:
            _fh.write(_body)
    os.symlink("/bin/cat", os.path.join(_jcm_bin, "cat"))

    def _jcm_run(rc, summary="TOTAL 5216 4159 79.7%", chrome=True):
        _wd = _tf14.mkdtemp(dir=_jcm_sb)
        _path = _jcm_bin if chrome else os.path.join(_jcm_sb, "nochrome")
        if not chrome:
            os.makedirs(_path, exist_ok=True)
            for _n in ("python", "cat"):
                if not os.path.exists(os.path.join(_path, _n)):
                    os.symlink(os.path.join(_jcm_bin, _n), os.path.join(_path, _n))
        _summ = os.path.join(_wd, "step-summary")
        _p = _sp14.run(["/bin/bash", "-c", _jcm_code], cwd=_wd, capture_output=True, text=True,  # nosec B603 - ci.yml's own step
                       timeout=30, env={"PATH": _path, "JC_RC": str(rc), "JC_SUMMARY": summary,
                                        "GITHUB_STEP_SUMMARY": _summ})
        _read = (lambda _f: open(_f).read() if os.path.exists(_f) else "")
        return _p.returncode, _read(_summ), _read(os.path.join(_wd, "args")), _p.stdout + _p.stderr

    _jcm_cases = {"measured": _jcm_run(0), "empty": _jcm_run(3), "not reached": _jcm_run(2),
                  "no summary": _jcm_run(2, summary=""), "no chrome": _jcm_run(0, chrome=False)}
    check("js coverage (CI): the Measure step exits with run.py's own status, and shows the summary "
          "whether or not the run passed",
          _jcm_code != "" and _jcm_cases["measured"][0] == 0 and _jcm_cases["empty"][0] == 3
          and _jcm_cases["not reached"][0] == 2 and _jcm_cases["no summary"][0] == 2
          and all("TOTAL 5216" in _jcm_cases[_k][1] for _k in ("measured", "empty", "not reached"))
          and _jcm_cases["no summary"][1] == ""
          and "--out lcov.info --summary js-coverage.txt" in _jcm_cases["measured"][2]
          and "--chrome " + os.path.join(_jcm_bin, "google-chrome") in _jcm_cases["measured"][2],
          repr({_k: _v[:3] for _k, _v in _jcm_cases.items()}))
    check("js coverage (CI): ...and on a runner with no Chrome it fails, saying so, without running",
          _jcm_cases["no chrome"][0] != 0 and "no Chrome on this runner" in _jcm_cases["no chrome"][3]
          and _jcm_cases["no chrome"][2] == "",
          repr(_jcm_cases["no chrome"]))
finally:
    _sh14b.rmtree(_jcm_sb, ignore_errors=True)

# ── run.py's exits: no measurement is never a report ─────────────────────────────────────────
# Run, not read: the old check matched run.py's source for `fail("the panel did not boot` and
# `if th == 0:`, which a refactor removes without changing what happens — and a regression that
# kept the text would have passed it. Each exit below goes through main() itself, with the browser
# session replaced by a stand-in, and reads the exit status and what it printed.


class _JcDriver:
    """What main() and measure_and_report() read of a Driver, with the numbers given."""

    def __init__(self, hits, unreached=(), flow_errors=()):
        self._hits = hits
        self.loaded = set(hits)
        self.errors, self.held, self.unreached = [], 0, list(unreached)
        self.flow_errors = list(flow_errors)
        self.snapshots = 0

    def snapshot(self):
        self.snapshots += 1

    def hits(self):
        return self._hits


def _jc_main(session_enter, chrome="/usr/bin/chrome-stand-in", walk=None):
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
    _jc_run.Session, _jc_run.walk = _Session, (walk or (lambda _d, only=None: None))
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


def _jc_lost(_d, only=None):
    raise _jc_run.LoginFailed("signing in did not land: still at '/login'")


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
    "a flow broke": _jc_main(lambda: _JcDriver(_jc_good, flow_errors=[
        ("/users", "users", "CDPError: no reply")])),
    "session lost": _jc_main(lambda: _JcDriver(_jc_good), walk=_jc_lost),
}
try:
    _jc_want = {"no browser": (2, "no Chrome/Chromium found"),
                "panel did not boot": (2, "the panel did not boot"),
                "sign-in did not land": (2, "signing in did not land"),
                "nothing ran": (3, "the coverage is empty"),
                "a page not reached": (2, "did not reach 1 page(s) it names"),
                "session lost": (2, "the session was lost mid-walk")}
    _jc_wrong = {_k: _jc_cases[_k][:2] for _k, (_rc, _msg) in _jc_want.items()
                 if not (_jc_cases[_k][0] == _rc and _msg in _jc_cases[_k][1]
                         and re.search(r"^(ERROR: |::error::).*" + re.escape(_msg),
                                       _jc_cases[_k][1], re.M))}
    check("js coverage: run.py exits non-zero, saying why, when there is no browser, the panel does "
          "not boot, the sign-in does not land, the session is lost mid-walk, nothing ran, or a "
          "page it names was not reached",
          not _jc_wrong, repr(_jc_wrong))
    _jc_ok = _jc_cases["measured"]
    _jc_lcov = open(os.path.join(_jc_ok[2], "lcov.info")).read()
    check("js coverage: ...and a run that measured something exits 0 with both reports written "
          "(positive control)",
          _jc_ok[0] == 0 and "SF:static/js/a.js\nDA:1,2\nDA:2,0\nLF:2\nLH:1\n" in _jc_lcov
          and "SF:static/js/b.js\nDA:4,0\nLF:1\nLH:0\n" in _jc_lcov
          and "TOTAL" in open(os.path.join(_jc_ok[2], "summary.txt")).read(),
          repr((_jc_ok[0], _jc_ok[1][-300:], _jc_lcov[:200])))
    check("js coverage: ...and the unreached run names the page and why",
          "/servers/manage (redirected to /)" in _jc_cases["a page not reached"][1],
          _jc_cases["a page not reached"][1][-300:])
    # A flow is the harness's own code: one that broke costs the coverage it would have made,
    # which the report says, and does not fail a measurement of everything else.
    _jc_fb = _jc_cases["a flow broke"]
    check("js coverage: ...while a flow that broke is reported, in the summary too, and the run still "
          "exits 0",
          _jc_fb[0] == 0 and "flow users broke: CDPError: no reply" in _jc_fb[1]
          and "Flows that broke" in open(os.path.join(_jc_fb[2], "summary.txt")).read(),
          repr((_jc_fb[0], _jc_fb[1][-300:])))
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


def _jc_no_event(_msg):
    """Take an event and do nothing, as CDP does until the Driver sets its handler."""


class _JcCDP:
    """Records calls and sends; hands back the replies the driver asks for."""

    def __init__(self):
        self.calls, self.sent, self.pending, self.events = [], [], [], []
        self.on_event = _jc_no_event

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

# goto() signs in again when a page lands on /login — once. An account that can no longer sign
# in with the password (two-factor turned on at the end of the walk) must not recurse forever.
_jc_logins = []
_jc_saved = (_jc_drv.path, _jc_drv.login, _jc_drv._wait_load)
_jc_drv.path = lambda: "/login"
_jc_drv.login = lambda: _jc_logins.append(1)
_jc_drv._wait_load = lambda _before, timeout=30: True     # the stand-in never loads a page
try:
    with _ctx14.redirect_stdout(_io14.StringIO()):
        _jc_drv.goto("/users")
    _jc_goto_err = None
except RecursionError as _e:
    _jc_goto_err = _e
finally:
    _jc_drv.path, _jc_drv.login, _jc_drv._wait_load = _jc_saved
check("js coverage: a page that lands on /login signs in again once, not forever",
      _jc_goto_err is None and _jc_logins == [1], repr((_jc_goto_err, len(_jc_logins))))

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

# walk._run_flow: a flow that raises is recorded against its page and the walk goes on; one that
# does not leaves nothing behind. (Without the catch, the first broken flow ended the whole run.)
_jc_walk = sys.modules.get("walk")


def _jc_flow_boom(_d):
    raise RuntimeError("element gone")


_jc_fd = _JcDriver(_jc_good)
try:
    with _ctx14.redirect_stdout(_io14.StringIO()):
        _jc_walk._run_flow(_jc_fd, "/users", "fine", lambda _d: None)
        _jc_walk._run_flow(_jc_fd, "/users", "boom", _jc_flow_boom)
    _jc_fd_raised = None
except Exception as _e:  # noqa: BLE001 - the check below is about exactly this
    _jc_fd_raised = _e
check("js coverage: a flow that breaks is recorded against its page, and the walk goes on",
      _jc_walk is not None and _jc_fd_raised is None
      and _jc_fd.flow_errors == [("/users", "boom", "RuntimeError: element gone")],
      repr((_jc_fd_raised, _jc_fd.flow_errors)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# The self-update CI gate: what it may install, what it must see first, and what it may cost
# ════════════════════════════════════════════════════════════════════════════════════════════════
import http.client as _hc14  # noqa: E402
import json as _json14  # noqa: E402
import shutil as _shutil14  # noqa: E402
import threading as _thr14  # noqa: E402
import urllib.error as _ue14  # noqa: E402

from panel.ops import system_ops as _so14  # noqa: E402

_WF14 = os.path.join(_root, ".github", "workflows")


def _wf14(name):
    with open(os.path.join(_WF14, name), encoding="utf-8") as fh:
        return fh.read()


def _wf14_code(name):
    """The workflow's text with whole-line comments dropped (PyYAML is not a suite dependency)."""
    return "\n".join(_l for _l in _wf14(name).splitlines() if not _l.lstrip().startswith("#"))


def _indent14(ln):
    """How many columns `ln` is indented."""
    return len(ln) - len(ln.lstrip())


def _wf14_block(lines, j):
    """The lines under line `j` that are indented deeper than it (blank lines kept)."""
    body = []
    for ln in lines[j + 1:]:
        if ln.strip() and _indent14(ln) <= _indent14(lines[j]):
            break
        body.append(ln)
    return body


def _wf14_run(text, step_name):
    """The `run: |` body of the step named `step_name`, dedented."""
    lines = text.splitlines()
    i = next(n for n, ln in enumerate(lines) if ln.strip() == "- name: " + step_name)
    j = next(n for n in range(i + 1, len(lines)) if lines[n].strip() == "run: |")
    body = _wf14_block(lines, j)
    cut = min(_indent14(ln) for ln in body if ln.strip())
    return "\n".join(ln[cut:] for ln in body) + "\n"


class _Resp14:
    """A urlopen() result carrying `payload` as its JSON body."""

    def __init__(self, payload):
        self._b = _json14.dumps(payload).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _runs14(*pairs, status="completed"):
    return {"check_runs": [{"name": n, "status": status, "conclusion": c} for n, c in pairs]}


# Every check _CI_REQUIRED names, passing — the shape of a code commit whose suite has finished.
_FULL14 = [("checks (ubuntu-24.04 · py3.12)", "success"), ("coverage", "success"),
           ("js coverage", "success"), ("gamedig lockfile (node 22)", "success"),
           ("Analyze (python)", "success"), ("Open code-scanning alerts", "success"),
           ("Secret scanning (Gitleaks)", "success")]


def _ci14(payload_or_exc, sha="a" * 40, diff=None):
    """_remote_ci_state(sha) over a stubbed GitHub answer and (optionally) a stubbed diff.

    Returns (state, the unknown-reason it left).
    """
    saved = (_so14._repo_slug, _so14.urllib.request.urlopen, _so14._git)
    try:
        _so14._repo_slug = lambda: "o/r"

        def _open(req, timeout=8):
            if isinstance(payload_or_exc, BaseException):
                raise payload_or_exc
            return _Resp14(payload_or_exc)
        _so14.urllib.request.urlopen = _open
        if diff is not None:
            _so14._git = lambda args, timeout=45: diff if args[:1] == ["diff"] else ("", "", 1)
        return _so14._remote_ci_state(sha), _so14._ci_unknown_why["reason"]
    finally:
        _so14._repo_slug, _so14.urllib.request.urlopen, _so14._git = saved


# ── 1. _repo_slug recognises GitHub's SSH-over-443 origin ──────────────────────────────────────
# ssh://git@ssh.github.com:443/owner/repo.git is GitHub's documented form for hosts that block port
# 22. The pattern read "443/owner" as the owner and returned None — no repository to ask — so every
# commit was 'unknown', which was installable: the gate was off for good on such a host, silently.
_rs14_saved = _so14._git
_rs14_url = [""]
try:
    _so14._git = lambda args, timeout=45: (_rs14_url[0], "", 0)
    _rs14 = {}
    for _u in ("ssh://git@ssh.github.com:443/o/r.git", "https://github.com:443/o/r",
               "git@github.com:123/r.git", "https://github.com/o/r.git", "git@github.com:o/r",
               "https://ghe.example.com/o/r.git", "https://gitlab.com/o/r"):
        _rs14_url[0] = _u
        _rs14[_u] = (_so14._repo_slug(), _so14.github_repo_url())
finally:
    _so14._git = _rs14_saved
check("update gate: the ssh.github.com:443 origin (and a port on https) is recognised",
      _rs14["ssh://git@ssh.github.com:443/o/r.git"] == ("o/r", "https://github.com/o/r")
      and _rs14["https://github.com:443/o/r"][0] == "o/r", repr(_rs14))
check("update gate: ...while a scp-style owner made of digits is still the owner, and ordinary "
      "origins are unchanged (controls)",
      _rs14["git@github.com:123/r.git"][0] == "123/r"
      and _rs14["https://github.com/o/r.git"][0] == "o/r"
      and _rs14["git@github.com:o/r"][0] == "o/r", repr(_rs14))
check("update gate: ...and an origin that is not github.com (GHE, a mirror) has no slug",
      _rs14["https://ghe.example.com/o/r.git"][0] is None
      and _rs14["https://gitlab.com/o/r"][0] is None, repr(_rs14))

# ── 2. 'unknown' says why ──────────────────────────────────────────────────────────────────────
_sl14 = _so14._repo_slug
try:
    _so14._repo_slug = lambda: None
    _u14_noslug = (_so14._remote_ci_state("a" * 40), _so14._ci_unknown_why["reason"])
finally:
    _so14._repo_slug = _sl14
_u14_404 = _ci14(_ue14.HTTPError("u", 404, "Not Found", {}, None))
_u14_net = _ci14(_ue14.URLError("offline"))
_u14_trunc = _ci14(_hc14.IncompleteRead(b"{", 10))
check("update gate: an unreadable answer is 'unknown' with a reason — no slug, a 404 (private "
      "repository), the network",
      _u14_noslug == ("unknown", _so14._CI_WHY_NO_SLUG)
      and _u14_404 == ("unknown", _so14._CI_WHY_NOT_FOUND)
      and _u14_net == ("unknown", _so14._CI_WHY_UNREACHABLE)
      and _u14_trunc == ("unknown", _so14._CI_WHY_UNREACHABLE),
      repr((_u14_noslug, _u14_404, _u14_net, _u14_trunc)))
check("update gate: ...and a rate limit is still 'pending', with no unknown-reason left over",
      _ci14(_ue14.HTTPError("u", 403, "limit", {}, None)) == ("pending", ""))

# ── 3. the walk: 'unknown' is not installable, ends the walk, and the card says why ────────────
_W14 = ["a" * 40, "b" * 40, "c" * 40]      # tip first


def _w14_git(args, timeout=45):
    if args[0] == "fetch":
        return ("", "", 0)
    if args[:3] == ["rev-parse", "--short", "HEAD"]:
        return ("headabc", "", 0)
    if args[0] == "rev-list" and "--count" in args:
        return ("3", "", 0)
    if args[:3] == ["rev-parse", "--short", "refs/remotes/origin/main"]:
        return (_W14[0][:7], "", 0)
    if args[0] == "rev-list" and "-n" in args:
        return ("\n".join(_W14), "", 0)
    if args[0] == "diff":
        return ("app.py\n", "", 0)   # a change the panel runs: an empty diff is no update
    if args[0] == "log":
        return ("", "", 0)
    return ("", "", 0)


def _w14_status(states, reason=""):
    """_compute_update_status with each commit's CI state from `states`; (status, commits asked)."""
    asked = []
    saved = (_so14._git, _so14._is_git_checkout, _so14.panel_version, _so14._tracked_branch,
             _so14._remote_ci_state)

    def _ci(sha):
        asked.append(sha)
        st = states.get(sha, "pending")
        _so14._ci_unknown_why["reason"] = reason if st == "unknown" else ""
        return st
    try:
        _so14._git, _so14._is_git_checkout = _w14_git, (lambda: True)
        _so14.panel_version, _so14._tracked_branch = (lambda: "2026.9.1"), (lambda: "main")
        _so14._remote_ci_state = _ci
        return _so14._compute_update_status(), asked
    finally:
        (_so14._git, _so14._is_git_checkout, _so14.panel_version, _so14._tracked_branch,
         _so14._remote_ci_state) = saved


_w14_unk, _w14_unk_asked = _w14_status({_W14[0]: "unknown", _W14[1]: "passing"},
                                       reason=_so14._CI_WHY_NO_SLUG)
check("update gate: a tip whose checks cannot be read is NOT offered (it was: 'unknown' counted as "
      "installable, and the walk takes the tip first)",
      _w14_unk.get("update_available") is False and _w14_unk.get("ci_state") == "unknown",
      repr({k: _w14_unk.get(k) for k in ("update_available", "ci_state", "target_sha")}))
check("update gate: ...nor is anything below it: the walk stops there instead of asking again",
      _w14_unk_asked == [_W14[0]], repr([a[:7] for a in _w14_unk_asked]))
check("update gate: ...and the card is told why, in words (origin not recognised)",
      _w14_unk.get("unverified_reason") == _so14._CI_WHY_NO_SLUG
      and "couldn't be verified" in (_w14_unk.get("message") or "")
      and _so14._CI_WHY_NO_SLUG in (_w14_unk.get("message") or ""), repr(_w14_unk.get("message")))
_w14_mid, _w14_mid_asked = _w14_status({_W14[0]: "pending", _W14[1]: "unknown",
                                        _W14[2]: "passing"}, reason=_so14._CI_WHY_UNREACHABLE)
check("update gate: a pending tip over an unreadable commit offers nothing and says GitHub could "
      "not be read",
      _w14_mid.get("update_available") is False and _w14_mid_asked == _W14[:2]
      and _so14._CI_WHY_UNREACHABLE in (_w14_mid.get("message") or ""),
      repr((_w14_mid.get("update_available"), _w14_mid.get("message"))))
_w14_ok, _ = _w14_status({_W14[0]: "pending", _W14[1]: "passing"})
_w14_pend, _ = _w14_status({})
check("update gate: ...while a verified commit under a pending tip is still offered, and an "
      "all-pending range stays silent (controls)",
      _w14_ok.get("update_available") is True and _w14_ok.get("target_sha") == _W14[1]
      and _w14_pend.get("update_available") is False and not _w14_pend.get("message")
      and "unverified_reason" not in _w14_pend,
      repr((_w14_ok.get("target_sha"), _w14_pend.get("message"))))

# panel_self_update refuses it with that reason, and launches nothing.
_su14_saved = (_so14._is_git_checkout, _so14.panel_update_status, _so14._launch_installer)
_su14_launched = []
try:
    _so14._is_git_checkout = lambda: True
    _so14._launch_installer = lambda **k: (_su14_launched.append(k), (True, "started"))[1]
    _so14.panel_update_status = lambda force=False: _w14_unk
    _su14_r = _so14.panel_self_update()
finally:
    (_so14._is_git_checkout, _so14.panel_update_status, _so14._launch_installer) = _su14_saved
check("update gate: the self-update refuses an unverifiable update, with the reason, launching "
      "nothing", _su14_r[0] is False and _so14._CI_WHY_NO_SLUG in _su14_r[1] and not _su14_launched,
      repr((_su14_r, _su14_launched)))

# ── 4. a commit must CARRY the required checks, the late alerts check included ────────────────
_code14 = ("panel/ops/system_ops.py", "", 0)
_docs14 = ("README.md\ndocs/x.md\nLICENSE", "", 0)
_no_alerts = [p for p in _FULL14 if p[0] != "Open code-scanning alerts"]
check("update gate: a code commit whose every EXISTING check passed, but without the alerts check "
      "yet, is 'pending' (it was 'passing', for the minute before CodeQL finished)",
      _ci14(_runs14(*_no_alerts), diff=_code14)[0] == "pending")
check("update gate: ...and 'passing' once the alerts check is on it (control)",
      _ci14(_runs14(*_FULL14), diff=_code14)[0] == "passing")
check("update gate: ...a SKIPPED alerts check does not count as present (fork PRs file those on "
      "main's tip)",
      _ci14(_runs14(*(_no_alerts + [("Open code-scanning alerts", "skipped")])),
            diff=_code14)[0] == "pending")
_missing14 = {}
for _req in _so14._CI_REQUIRED:
    _without = [p for p in _FULL14 if not _so14._ci_name_matches(_req, p[0])]
    _missing14[_req] = _ci14(_runs14(*_without), diff=_code14)[0]
check("update gate: ...and each required check missing, alone, holds the commit at 'pending'",
      set(_missing14.values()) == {"pending"}, repr(_missing14))
check("update gate: a matrix job is matched by its prefix, so a new matrix entry does not strand "
      "panels on an old version",
      _ci14(_runs14(*([p for p in _FULL14 if not p[0].startswith("checks (")]
                      + [("checks (ubuntu-28.04 · py3.16)", "success")])), diff=_code14)[0]
      == "passing")
check("update gate: a docs-only commit (CI and CodeQL do not run for it) passes on what it has",
      _ci14(_runs14(("Secret scanning (Gitleaks)", "success")), diff=_docs14)[0] == "passing")
check("update gate: ...but a docs-only commit that DOES carry one suite check needs them all",
      _ci14(_runs14(("Secret scanning (Gitleaks)", "success"), ("coverage", "success")),
            diff=_docs14)[0] == "pending")
check("update gate: ...and a diff that cannot be read expects the whole suite (fails safe)",
      _ci14(_runs14(("Secret scanning (Gitleaks)", "success")), diff=("", "bad", 128))[0]
      == "pending")
check("update gate: the alerts workflow's own job run (filed on main's tip, about another commit) "
      "is ignored, failing or not",
      _ci14(_runs14(*(_FULL14 + [("Code-scanning alerts gate", "failure")])), diff=_code14)[0]
      == "passing")
check("update gate: ...while a failing alerts CHECK on the commit fails it (control)",
      _ci14(_runs14(*([p for p in _FULL14 if p[0] != "Open code-scanning alerts"]
                      + [("Open code-scanning alerts", "failure")])), diff=_code14)[0]
      == "failing")

# The names are the workflows' own. A renamed job would hold every installed panel back.
_ci_wf14 = _wf14_code("ci.yml")
_cq_wf14 = _wf14_code("codeql.yml")
_cqa_wf14 = _wf14_code("codeql-alerts.yml")
_names14 = re.findall(r"^    name: (.+)$", _ci_wf14 + "\n" + _cq_wf14, re.M)
_names14 = [re.sub(r"\$\{\{[^}]*\}\}", "", n).strip() for n in _names14]
_req_found = {r: any((n == r) if not r.endswith("(") else n.startswith(r) for n in _names14)
              for r in _so14._CI_REQUIRED if r != "Open code-scanning alerts"}
check("update gate: every required CI/CodeQL name is a job name in ci.yml or codeql.yml",
      all(_req_found.values()), repr((_req_found, _names14)))
_ci_jobs14 = re.findall(r"^    name: (.+)$", _ci_wf14, re.M)
_ci_jobs14 = [n.split("${{")[0].strip() for n in _ci_jobs14]
check("update gate: ...and every ci.yml job is required (none left for the gate to miss)",
      len(_ci_jobs14) == 4
      and all(any(_so14._ci_name_matches(r, n) for r in _so14._CI_REQUIRED) for n in _ci_jobs14),
      repr(_ci_jobs14))
check("update gate: the alerts workflow POSTS the required 'Open code-scanning alerts' check, and "
      "its own job name is the one the gate ignores",
      '-f name="Open code-scanning alerts"' in _cqa_wf14
      and re.search(r"^    name: Code-scanning alerts gate$", _cqa_wf14, re.M) is not None
      and "Code-scanning alerts gate" in _so14._CI_IGNORE, "")
_pi14 = {}
for _wfn in ("ci.yml", "codeql.yml", "security-code.yml", "zizmor.yml"):
    _t = _wf14(_wfn)
    _pi14[_wfn] = [sorted(re.findall(r"^      - '([^']+)'$", _blk, re.M))
                   for _blk in re.findall(r"    paths-ignore:\n((?:      - .*\n)+)", _t)]
_pi14_all = {tuple(b) for v in _pi14.values() for b in v}
# One block each, on `push`: their `pull_request` triggers have no path filter, because their jobs
# are checks a pull request must pass to merge (.github/required-checks.txt) and a required check
# whose workflow did not run would hold the pull request forever.
check("update gate: ci.yml, codeql.yml, security-code.yml and zizmor.yml share one paths-ignore list, "
      "on push",
      len(_pi14_all) == 1 and all(len(v) == 1 for v in _pi14.values()), repr(_pi14))
_pi14_list = list(next(iter(_pi14_all))) if len(_pi14_all) == 1 else []
check("update gate: ...and it is the list _ci_path_ignored applies",
      sorted(p for p in _pi14_list if "*" not in p) == sorted(_so14._CI_PATHS_IGNORED_FILES)
      and set(p for p in _pi14_list if "*" in p) == {"**/*.md", "docs/**"}
      and _so14._ci_path_ignored("a/b/README.md") and _so14._ci_path_ignored("docs/x.png")
      and not _so14._ci_path_ignored("docsx/y.py") and not _so14._ci_path_ignored("app.py"),
      repr(_pi14_list))

# ── 5. codeql-alerts.yml: the verdict lands on the commit it judged ───────────────────────────
_cqa_raw14 = _wf14("codeql-alerts.yml")
check("codeql-alerts: it waits for EVERY uploader (CodeQL, the Bandit/Semgrep workflow and zizmor's), "
      "and may post checks",
      'workflows: [ "CodeQL", "Security scan (code)", "Security scan (workflows)" ]' in _cqa_raw14
      and "checks: write" in _cqa_wf14 and "actions: read" in _cqa_wf14, "")
_sb14 = _tf14.mkdtemp(prefix="cqa14-")
try:
    _bin14 = os.path.join(_sb14, "bin")
    os.makedirs(_bin14)
    with open(os.path.join(_bin14, "gh"), "w") as _fh:
        # Answers each query the steps make from the environment, and logs every call.
        _fh.write('#!/bin/bash\necho "$*" >> "$GH_LOG"\n'
                  'case "$*" in\n'
                  '  *actions/workflows/codeql.yml/*) echo "${OPEN_CODEQL:-0}" ;;\n'
                  '  *actions/workflows/security-code.yml/*) echo "${OPEN_SEC:-0}" ;;\n'
                  '  *actions/workflows/zizmor.yml/*) echo "${OPEN_ZZ:-0}" ;;\n'
                  '  *code-scanning/alerts*) echo "${ALERTS:-[]}" ;;\n'
                  '  *check-runs*) : ;;\n'
                  'esac\n')
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
    os.chmod(os.path.join(_bin14, "gh"), 0o700)

    def _cqa14(step, **env):
        out = os.path.join(_sb14, "out")
        log = os.path.join(_sb14, "log")
        summ = os.path.join(_sb14, "summary")
        for p in (out, log, summ):
            open(p, "w").close()
        p = _sp14.run(["bash", "-c", _wf14_run(_cqa_raw14, step)], capture_output=True, text=True,  # nosec B603 B607 - the workflow's own step
                      env=dict(os.environ, PATH=_bin14 + os.pathsep + os.environ["PATH"],
                               GH_LOG=log, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summ,
                               GITHUB_REPOSITORY="o/r", **env))
        outs = dict(ln.split("=", 1) for ln in open(out).read().splitlines() if "=" in ln)
        return p.returncode, outs, open(log).read()

    _S14 = "d" * 40
    _wait_busy = _cqa14("Wait for the other uploaders", GITHUB_EVENT_NAME="workflow_run",
                        WR_SHA=_S14, WR_NAME="CodeQL", WR_EVENT="push", OPEN_SEC="1")
    # zizmor's run still going holds the verdict too, whichever uploader finished first.
    _wait_busy_zz = _cqa14("Wait for the other uploaders", GITHUB_EVENT_NAME="workflow_run",
                           WR_SHA=_S14, WR_NAME="Security scan (code)", WR_EVENT="push",
                           OPEN_ZZ="1")
    _wait_done = _cqa14("Wait for the other uploaders", GITHUB_EVENT_NAME="workflow_run",
                        WR_SHA=_S14, WR_NAME="CodeQL", WR_EVENT="push")
    _wait_man = _cqa14("Wait for the other uploaders", GITHUB_EVENT_NAME="workflow_dispatch",
                       WR_SHA="", WR_NAME="")
    check("codeql-alerts: an uploader that finishes posts nothing while another still runs (the "
          "Bandit/Semgrep workflow's run, or zizmor's)",
          _wait_busy[:2] == (0, {"judge": "false"}) and _wait_busy_zz[:2] == (0, {"judge": "false"})
          and "actions/workflows/zizmor.yml/runs?head_sha=%s&event=push" % _S14 in _wait_busy_zz[2],
          repr((_wait_busy, _wait_busy_zz)))
    check("codeql-alerts: ...with none of them running the last to finish judges, having asked about "
          "this commit; a manual run judges at once",
          _wait_done[:2] == (0, {"judge": "true"}) and "head_sha=%s" % _S14 in _wait_done[2]
          and _wait_man[:2] == (0, {"judge": "true"}), repr((_wait_done, _wait_man)))
    # The judge step (clean, open alerts, no analysis of this commit, moved on) is run in part26,
    # against the per-category analyses it now waits for (.github/scripts/code_scanning_analyses.py).
    _posts = {}
    for _oc, _vd in (("success", "success"), ("success", "skipped"), ("failure", "")):
        _r = _cqa14("Post the verdict on the judged commit", SHA=_S14, OUTCOME=_oc, VERDICT=_vd,
                    RUN_URL="https://x/run/1")
        _posts[_oc + ":" + _vd] = (_r[0], re.search(r"conclusion=(\w+)", _r[2]) and
                                   re.search(r"conclusion=(\w+)", _r[2]).group(1),
                                   "head_sha=%s" % _S14 in _r[2]
                                   and "name=Open code-scanning alerts" in _r[2])
    check("codeql-alerts: the verdict is posted on the judged commit as 'Open code-scanning "
          "alerts' — success, skipped (not judged) or failure",
          _posts == {"success:success": (0, "success", True), "success:skipped": (0, "skipped", True),
                     "failure:": (0, "failure", True)}, repr(_posts))
finally:
    _shutil14.rmtree(_sb14, ignore_errors=True)

# ── 6. deploy.yml waits for the same set before shipping ──────────────────────────────────────
_dep_raw14 = _wf14("deploy.yml")
_dep_verify14 = _wf14_run(_dep_raw14, "Verify the commit is on main, and take its installer")
_dep_req14 = re.search(r"^REQUIRED=\((.*)\)$", _dep_verify14, re.M)
_dep_ign14 = re.search(r"^IGNORED='(\[.*\])'$", _dep_verify14, re.M)
check("deploy: its required and ignored check lists are the panel gate's",
      _dep_req14 is not None and _dep_ign14 is not None
      and tuple(re.findall(r'"([^"]+)"', _dep_req14.group(1))) == _so14._CI_REQUIRED
      and set(_json14.loads(_dep_ign14.group(1))) == _so14._CI_IGNORE,
      repr((_dep_req14 and _dep_req14.group(1), _dep_ign14 and _dep_ign14.group(1))))
check("deploy: the job may read check runs and hands the verify step a token",
      "checks: read" in _dep_raw14 and "GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}" in
      _dep_raw14[_dep_raw14.index("- name: Verify the commit is on main"):
                 _dep_raw14.index("- name: Join the tailnet")], "")
# Drive the wait itself: the loop, cut out of the step, with no deadline and no sleep.
_dep_loop14 = _dep_verify14[_dep_verify14.index("REQUIRED=("):
                            _dep_verify14.index('echo "installer=')]
_dep_loop14 = _dep_loop14.replace("20 * 60", "0").replace("sleep 30", "sleep 0")
_dsb14 = _tf14.mkdtemp(prefix="dep14-")
try:
    _dbin = os.path.join(_dsb14, "bin")
    os.makedirs(_dbin)
    with open(os.path.join(_dbin, "gh"), "w") as _fh:
        _fh.write('#!/bin/sh\ncat "$RUNS"\n')      # the --jq result: one check run per line
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
    os.chmod(os.path.join(_dbin, "gh"), 0o700)

    def _dep14(runs):
        rf = os.path.join(_dsb14, "runs")
        with open(rf, "w") as fh:
            fh.write("".join(_json14.dumps({"name": n, "status": s, "conclusion": c}) + "\n"
                             for n, s, c in runs))
        p = _sp14.run(["bash", "-c", "set -euo pipefail\n" + _dep_loop14 + "echo WAITED-OK\n"],  # nosec B603 B607 - the workflow's own loop
                      capture_output=True, text=True,
                      env=dict(os.environ, PATH=_dbin + os.pathsep + os.environ["PATH"], RUNS=rf,
                               HEAD_SHA="f" * 40, GITHUB_REPOSITORY="o/r"))
        return p.returncode, p.stdout

    _all14 = [(n, "completed", c) for n, c in _FULL14]
    _d_ok = _dep14(_all14 + [("deploy", "in_progress", None),
                             ("Code-scanning alerts gate", "completed", "failure")])
    _d_bad = _dep14(_all14 + [("Python security lint (Bandit)", "completed", "failure")])
    _d_noalert = _dep14([r for r in _all14 if r[0] != "Open code-scanning alerts"])
    _d_skip = _dep14([r for r in _all14 if r[0] != "Open code-scanning alerts"]
                     + [("Open code-scanning alerts", "completed", "skipped")])
    _d_run = _dep14(_all14 + [("lighthouse", "in_progress", None)])
    check("deploy: a commit with every required check passed is deployed (its own run and the "
          "alerts job's misfiled run ignored)", _d_ok[0] == 0 and "WAITED-OK" in _d_ok[1],
          repr(_d_ok))
    check("deploy: ...a failed security check stops the deploy (it waited for CI alone)",
          _d_bad[0] == 1 and "failed a check (Python security lint (Bandit))" in _d_bad[1],
          repr(_d_bad))
    check("deploy: ...and so does a missing or merely skipped alerts check, or a check still "
          "running, once the wait runs out",
          _d_noalert[0] == 1 and "missing: Open code-scanning alerts" in _d_noalert[1]
          and _d_skip[0] == 1 and "missing: Open code-scanning alerts" in _d_skip[1]
          and _d_run[0] == 1 and "1 still running" in _d_run[1],
          repr((_d_noalert, _d_skip, _d_run)))
finally:
    _shutil14.rmtree(_dsb14, ignore_errors=True)

# ── 7. Semgrep gates, through code scanning (its docstring said it did; it did not) ───────────
_sc14 = _wf14("security-code.yml")
_sg14 = _sc14[_sc14.index("\n  sast-semgrep:\n"):]
_sg14_code = "\n".join(_l for _l in _sg14.splitlines() if not _l.lstrip().startswith("#"))
check("security-code: Semgrep writes SARIF and uploads it to code scanning (category semgrep), "
      "with the permission to, and fails when it wrote none",
      "--sarif-output=semgrep.sarif" in _sg14_code
      and "github/codeql-action/upload-sarif@" in _sg14_code
      and "sarif_file: semgrep.sarif" in _sg14_code and "category: semgrep" in _sg14_code
      and "security-events: write" in _sg14_code and "if [ ! -s semgrep.sarif ]; then" in _sg14_code
      and "|| true" not in _sg14_code, "")
check("security-code: ...pinned to the same upload-sarif commit Bandit's upload uses",
      len(set(re.findall(r"github/codeql-action/upload-sarif@([0-9a-f]{40})", _sc14))) == 1
      and _sc14.count("github/codeql-action/upload-sarif@") == 2, "")

# ── 8. one status computation at a time, and none while an update runs ───────────────────────
# Each computation is a `git fetch` of the ref install.sh fetches plus GitHub requests. The update
# card polled the status every 1.5s during the run, nothing serialised the computations, and a
# fetch that lost the race for the ref's lock aborted the UPDATE.
_ss14_saved = (_so14._compute_update_status, dict(_so14._update_cache), _so14.PANEL_DIR,
               dict(_so14._update_launched), _so14._git, _so14.panel_version,
               _so14._tracked_branch, _so14._update_lock)
_ss14_dir = _tf14.mkdtemp(prefix="upd14-")
try:
    # The panel creates this lock after eventlet.monkey_patch() (app.py patches first), so it is a
    # GREEN lock there, like the threads below. This suite imports system_ops before app patches,
    # so its module-level lock is a real one: a greenlet blocking on it would block the whole hub,
    # and the lock's holder with it. The test takes a lock of the same kind as its threads.
    _so14._update_lock = _thr14.Lock()
    os.makedirs(os.path.join(_ss14_dir, "data"))
    _so14.PANEL_DIR = _ss14_dir
    _so14._update_launched["ts"] = 0.0
    _ss14_calls = []
    _ss14_gate = _thr14.Event()

    def _slow_compute():
        _ss14_calls.append(1)
        _ss14_gate.wait(5)
        return {"git": True, "update_available": False, "n": len(_ss14_calls)}
    _so14._compute_update_status = _slow_compute
    _so14._update_cache.update({"ts": 0.0, "data": None})
    _ss14_out = []
    _ts14 = [_thr14.Thread(target=lambda f=f: _ss14_out.append(_so14.panel_update_status(force=f)))
             for f in (False, True, False, True, False)]
    for _t in _ts14:
        _t.start()
    _time14.sleep(0.3)
    _ss14_gate.set()
    for _t in _ts14:
        _t.join(10)
    check("update status: five concurrent requests (forced or not) run ONE computation and all get "
          "its answer", len(_ss14_calls) == 1 and len(_ss14_out) == 5
          and all(o.get("n") == 1 for o in _ss14_out), repr((len(_ss14_calls), _ss14_out)))
    _ss14_calls.clear()
    _so14.panel_update_status(force=True)
    check("update status: ...while a later forced request, with none in flight, computes afresh "
          "(control)", len(_ss14_calls) == 1, repr(_ss14_calls))

    # While an update runs: no computation, no fetch, update_available False, and what the
    # watcher compares after the restart.
    _ss14_git = []
    _so14._git = lambda args, timeout=45: (_ss14_git.append(args[0]),
                                           ("abc1234", "", 0) if args[0] == "rev-parse"
                                           else ("", "", 0))[1]
    _so14.panel_version, _so14._tracked_branch = (lambda: "2026.9.30"), (lambda: "main")
    _log14 = os.path.join(_ss14_dir, "data", "self-update.log")
    with open(_log14, "w") as fh:
        fh.write("=== panel self-update ===\n[2/6] Fetching the new version\n")
    _ss14_calls.clear()
    _run14 = _so14.panel_update_status(force=True)
    check("update status: while the run's log has no exit line, nothing is computed or fetched, "
          "and nothing is installable",
          not _ss14_calls and "fetch" not in _ss14_git and _run14.get("update_running") is True
          and _run14.get("update_available") is False and _run14.get("current_sha") == "abc1234"
          and _run14.get("branch") == "main" and _run14.get("message"),
          repr((_ss14_calls, _ss14_git, _run14)))
    check("update status: ...and the running sha is read with rev-parse only, never `git status` "
          "(which may take the index lock the installer's reset needs)",
          set(_ss14_git) <= {"rev-parse", "log"}, repr(_ss14_git))
    _su14b_saved = (_so14._launch_installer, _so14._is_git_checkout)
    _su14b = []
    try:
        _so14._launch_installer = lambda **k: (_su14b.append(k), (True, "x"))[1]
        _so14._is_git_checkout = lambda: True
        _su14b_r = _so14.panel_self_update()
    finally:
        _so14._launch_installer, _so14._is_git_checkout = _su14b_saved
    check("update status: ...so a second Update pressed during the run is refused, not launched",
          _su14b_r[0] is False and not _su14b, repr(_su14b_r))
    with open(_log14, "a") as fh:
        fh.write("=== installer exit 0 ===\n")
    _so14.panel_update_status(force=True)
    check("update status: once the log says the run ended, the next request computes (control)",
          len(_ss14_calls) == 1, repr(_ss14_calls))
    with open(_log14, "w") as fh:
        fh.write("=== panel self-update ===\n[3/6] Installing\n")
    _old14 = _time14.time() - _so14._UPDATE_STALE_LOG - 60
    os.utime(_log14, (_old14, _old14))
    _ss14_calls.clear()
    _so14.panel_update_status(force=True)
    check("update status: ...and a log with no exit line that has not moved in 20 minutes is a dead "
          "run, not a running one", len(_ss14_calls) == 1, repr(_ss14_calls))
    # Between the launch and the new log: the launch itself is the witness.
    os.unlink(_log14)
    _so14._mark_update_launched()
    _ss14_calls.clear()
    _gap14 = _so14.panel_update_status(force=True)
    check("update status: in the moment after a launch, before its log exists, nothing is computed "
          "either (the cache used to be emptied there, making the next poll a fetch)",
          not _ss14_calls and _gap14.get("update_running") is True
          and _so14._update_cache["ts"] == 0.0, repr((_ss14_calls, _gap14)))
    _so14._update_launched["ts"] = _time14.time() - _so14._UPDATE_LAUNCH_GRACE - 1
    _so14.panel_update_status(force=True)
    check("update status: ...for a bounded time only (a launch whose run never wrote a log)",
          len(_ss14_calls) == 1, repr(_ss14_calls))
finally:
    (_so14._compute_update_status, _cache14, _so14.PANEL_DIR, _launched14, _so14._git,
     _so14.panel_version, _so14._tracked_branch, _so14._update_lock) = _ss14_saved
    _so14._update_cache.clear()
    _so14._update_cache.update(_cache14)
    _so14._update_launched.clear()
    _so14._update_launched.update(_launched14)
    _shutil14.rmtree(_ss14_dir, ignore_errors=True)


# ── 9. a branch SWITCH to main goes through the same gate ─────────────────────────────────────
# It launched with an empty target, and install.sh resets an empty target to the branch's tip: so
# switching (back) to main installed main's newest commit, verified or not — the one way around the
# gate. Now: the newest verified commit of main's own line, or a refusal saying why. Another branch
# is still the testing escape hatch, and says it installs an unverified tip.
_sw14_saved = (_so14._git, _so14._is_git_checkout, _so14._remote_ci_state, _so14._launch_installer,
               _so14._update_in_progress)
_SW14 = ["1" * 40, "2" * 40, "3" * 40]     # main's first-parent line, tip first
_sw14_cfg = {}
from panel.core import config as _cfg14  # noqa: E402
_sw14_cfg_saved = (_cfg14.load_config, _cfg14.update_config)
try:
    _cfg14.load_config = lambda: dict(_sw14_cfg)
    _cfg14.update_config = lambda fn: fn(_sw14_cfg)
    _so14._is_git_checkout = lambda: True
    _so14._update_in_progress = lambda: False
    _sw14_git = []

    def _sw_git(args, timeout=45):
        _sw14_git.append(args)
        if args[0] == "ls-remote":
            return ("x\trefs/heads/%s" % args[-1].split("/")[-1], "", 0)
        if args[0] == "rev-list":
            return ("\n".join(_SW14), "", 0)
        return ("", "", 0)
    _so14._git = _sw_git
    _sw14_launch = []
    _so14._launch_installer = lambda target_ref="", branch="", started_msg=None: (
        _sw14_launch.append((target_ref, branch, started_msg)), (True, started_msg))[1]

    def _sw14_run(branch, states, reason=""):
        _sw14_launch.clear()
        _sw14_git.clear()
        _sw14_cfg.clear()

        def _ci(sha):
            st = states.get(sha, "pending")
            _so14._ci_unknown_why["reason"] = reason if st == "unknown" else ""
            return st
        _so14._remote_ci_state = _ci
        return _so14.panel_switch_branch(branch), list(_sw14_launch), dict(_sw14_cfg)

    _s_ok = _sw14_run("main", {_SW14[0]: "pending", _SW14[1]: "passing"})
    check("switch-branch: to main installs main's newest VERIFIED commit (pinned), not its tip",
          _s_ok[0][0] is True and _s_ok[1] and _s_ok[1][0][:2] == (_SW14[1], "main")
          and _SW14[1][:7] in _s_ok[0][1] and _s_ok[2].get("panel_branch") == "main",
          repr(_s_ok))
    check("switch-branch: ...having fetched main into its remote-tracking ref first",
          ["fetch", "--quiet", "--no-tags", "origin",
           "+refs/heads/main:refs/remotes/origin/main"] in _sw14_git, repr(_sw14_git[:3]))
    _s_pend = _sw14_run("main", {})
    _s_fail = _sw14_run("main", {s: "failing" for s in _SW14})
    _s_unk = _sw14_run("main", {_SW14[0]: "unknown"}, reason=_so14._CI_WHY_NO_SLUG)
    check("switch-branch: ...and refuses, launching nothing and keeping the tracked branch, when "
          "nothing is verified yet, everything failed, or the checks can't be read — saying which",
          all(r[0][0] is False and not r[1] and "panel_branch" not in r[2]
              for r in (_s_pend, _s_fail, _s_unk))
          and "finished its automated checks" in _s_pend[0][1]
          and "passed its automated checks" in _s_fail[0][1]
          and _so14._CI_WHY_NO_SLUG in _s_unk[0][1],
          repr((_s_pend[0], _s_fail[0], _s_unk[0])))
    _so14._update_in_progress = lambda: True
    _s_busy = _sw14_run("main", {_SW14[0]: "passing"})
    _so14._update_in_progress = lambda: False
    check("switch-branch: ...and never while an update is being installed",
          _s_busy[0][0] is False and not _s_busy[1] and "being installed" in _s_busy[0][1],
          repr(_s_busy[0]))
    _s_dev = _sw14_run("dev", {})
    check("switch-branch: another branch is still the testing escape hatch — its tip, unpinned — "
          "and the message says it is unverified",
          _s_dev[0][0] is True and _s_dev[1] and _s_dev[1][0][:2] == ("", "dev")
          and "unverified" in _s_dev[0][1] and not any(a[0] == "fetch" for a in _sw14_git),
          repr(_s_dev))
finally:
    (_so14._git, _so14._is_git_checkout, _so14._remote_ci_state, _so14._launch_installer,
     _so14._update_in_progress) = _sw14_saved
    _cfg14.load_config, _cfg14.update_config = _sw14_cfg_saved
_rmh14 = open(os.path.join(_root, "static", "js", "remote_manage_host.js"), encoding="utf-8").read()
check("switch-branch (UI): the confirm dialog says which it installs — main's newest verified "
      "version, or another branch's tip as UNVERIFIED",
      "It installs the newest version of main that has passed its automated checks." in _rmh14
      and "UNVERIFIED: this installs the newest commit on" in _rmh14, "")

# ── the DevTools endpoint: a slow answer is waited for, not a failed run ─────────────────────────
# main's js coverage job died on one 5 s read of Chrome's /json/version (the browser had accepted
# the connection and was still starting) on code its pull request had just measured green. run.py
# puts its own directory on sys.path and imports its siblings, so both are put back afterwards.
_dt14_path, _dt14_mods = list(sys.path), set(sys.modules)
try:
    _dt14_run = _jc_load("run")
finally:
    sys.path[:] = _dt14_path
    for _m14 in set(sys.modules) - _dt14_mods:
        if not _m14.startswith("jscov_"):
            del sys.modules[_m14]
_dt14_calls = []


class _DtAnswer14:
    def __enter__(self):
        return _io14.BytesIO(b'{"Browser": "Chrome/1"}')

    def __exit__(self, *_a):
        return False


def _dt14_urlopen(url, timeout=None):
    _dt14_calls.append(timeout)
    if len(_dt14_calls) <= 2:
        raise TimeoutError("timed out")
    return _DtAnswer14()


_dt14_real = _dt14_run.urllib.request.urlopen
_dt14_run.urllib.request.urlopen = _dt14_urlopen
try:
    try:
        _dt14_got = _dt14_run.devtools_json(1, "/json/version")
    except Exception as _e14:  # noqa: BLE001 - the check names what escaped
        _dt14_got = _e14
    _dt14_calls.clear()
    _dt14_late = None
    try:
        _dt14_run.devtools_json(1, "/json/version", wait=0)
    except _dt14_run.Abort as _e14:
        _dt14_late = str(_e14)
    except Exception:  # noqa: BLE001 - anything else is the failure this check names
        _dt14_late = None
finally:
    _dt14_run.urllib.request.urlopen = _dt14_real
check("js coverage: a DevTools read that times out is tried again until the browser answers "
      "(one slow /json/version failed main's run)",
      _dt14_got == {"Browser": "Chrome/1"}, repr(_dt14_got))
check("js coverage: ...and past its deadline it stops with a message naming the endpoint, not a "
      "traceback",
      _dt14_late is not None and "/json/version" in _dt14_late and len(_dt14_calls) == 1,
      repr((_dt14_late, _dt14_calls)))
