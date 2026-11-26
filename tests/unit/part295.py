"""Part 295 of the unit suite: the js coverage walk in parallel parts, and the merge of their reports.

1. run.py --part I/N walks part I of N (tools/js_coverage/walk.py part_units). Run through run.main() itself, with
   the browser session stood in for by a recording driver and the walk real: across the N parts of every N from 1
   to 8, each step of the whole walk (a page's first pass, its confirming pass, an i18n page, the end) is taken
   exactly once, none dropped and none doubled; inside a part the steps keep the whole walk's order, a page's
   confirming pass is in the part that walked the page first (it presses only what that pass found), and the end
   (two-factor, then the expiry, which signs out) is last. A malformed --part is refused. Controls: a split that
   drops a unit and one that doubles a unit are both caught by the same comparison.
2. tools/js_coverage/merge.py adds the parts' LCOV: per file, each line's hits summed and the lines' union, LF/LH
   counted again; FN/FNDA and BRDA summed when present; one report merged alone comes back unchanged; a missing
   or malformed report is refused.
3. ci.yml: the js-coverage parts are the four I/4, each id named in the verdict's loop; js-coverage-verdict (named
   `js coverage`) runs always(), reads the parts' result and fails unless it is success; its merge step, run by
   bash on made-up part reports, fails naming a missing part and otherwise writes the merged lcov.info.

HOW IT RUNS. run.py and merge.py loaded from tools/js_coverage (sys.path and module names put back after), and
bash over ci.yml's own step scripts in a scratch directory with a stand-in `python3` (this interpreter).
"""
import collections as _col295
import contextlib as _ctx295
import importlib.util as _ilu295
import io as _io295
import os
import re as _re295
import shutil as _sh295
import signal as _sig295
import subprocess as _sp295  # nosec B404 - bash over ci.yml's own step scripts, fixed argvs
import sys
import tempfile as _tf295

from unit.part01 import _root, check, eq
from unit.part06 import _wf_run_block
from unit.part29 import _job29, _wf29

_JC295 = os.path.join(_root, "tools", "js_coverage")


def _load295(name):
    spec = _ilu295.spec_from_file_location("jscov295_" + name, os.path.join(_JC295, name + ".py"))
    mod = _ilu295.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# run.py puts tools/js_coverage first on sys.path and imports its siblings as top-level modules: both are put
# back once it is loaded (part14 holds why), keeping the walk module it uses by reference.
_path295, _mods295 = list(sys.path), set(sys.modules)
try:
    _run295 = _load295("run")
    _merge295 = _load295("merge")
    _walk295 = sys.modules["walk"]
    _v8_295 = sys.modules["v8_lcov"]
finally:
    sys.path[:] = _path295
    for _m295 in set(sys.modules) - _mods295:
        if not _m295.startswith("jscov295_"):
            del sys.modules[_m295]


# ── 1. the walk in parts, through run.main() ─────────────────────────────────────────────────────
class _Rec295:
    """A signed-in Driver as the walk and main() use it, recording each step the walk takes."""

    def __init__(self):
        self.steps, self.at = [], "/"
        self.loaded, self.errors, self.held, self.unreached, self.flow_errors = set(), [], 0, [], []
        self.cdp = self

    def exercise(self, path, skip=(), accept=False, limit=250):
        self.steps.append(("confirm" if accept else "i18n" if limit != 250 else "page", path))
        return 1

    def path(self):
        return self.at

    def goto(self, path):
        self.at = path.split("?")[0]

    def run(self, *_a):
        return 1

    def call(self, *_a):
        return {}

    def wait(self, *_a):
        return None

    def snapshot(self):
        return None

    def hits(self):
        return {"panel/static/js/a.js": {1: 1}}


def _main295(argv, out_dir):
    """run.main(argv) with the session stood in for; (exit status, the recorded steps)."""
    rec = _Rec295()

    class _Session:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return rec

        def __exit__(self, *_e):
            return False

    saved = (_run295.Session, _run295.find_chrome, _sig295.getsignal(_sig295.SIGTERM),
             _walk295.FLOWS, _walk295.setup_wizard, _walk295.two_factor)
    _run295.Session, _run295.find_chrome = _Session, (lambda _e: "/usr/bin/chrome-stand-in")
    # The flows are the harness's own browser scripts: recorded as a step each, never run.
    _walk295.FLOWS = {}
    _walk295.setup_wizard = lambda d: d.steps.append(("wizard", ""))
    _walk295.two_factor = lambda d: d.steps.append(("end", ""))
    try:
        with _ctx295.redirect_stdout(_io295.StringIO()), _ctx295.redirect_stderr(_io295.StringIO()):
            try:
                rc = _run295.main(argv + ["--out", os.path.join(out_dir, "lcov.info"),
                                          "--summary", os.path.join(out_dir, "s.txt")])
            except SystemExit as e:
                rc = e.code
            except Exception as e:  # noqa: BLE001 - a run that raised is a result here, not the end of the part
                rc = "raised %s" % type(e).__name__
    finally:
        _run295.Session, _run295.find_chrome = saved[:2]
        _sig295.signal(_sig295.SIGTERM, saved[2])
        _walk295.FLOWS, _walk295.setup_wizard, _walk295.two_factor = saved[3:]
    return rc, rec.steps


def _subsequence295(part, whole):
    it = iter(whole)
    return all(any(s == w for w in it) for s in part)


def _part_bad295(i, p, whole):
    """What is wrong inside part `i`'s steps `p` ([] when nothing)."""
    bad = ["part %d does not start with the wizard" % i] * (p[:1] != [("wizard", "")])
    bad += ["part %d is out of the walk's order" % i] * (not _subsequence295(p, whole))
    bad += ["part %d confirms %s without its first pass" % (i, s[1])
            for s in p if s[0] == "confirm" and ("page", s[1]) not in p]
    return bad + ["part %d: the end is not last" % i] * (("end", "") in p and p[-1] != ("end", ""))


def _split_bad295(parts, whole):
    """What is wrong with the parts' steps against the whole walk's ([] when nothing)."""
    got = _col295.Counter(s for p in parts for s in p[1:])
    want = _col295.Counter(whole[1:])
    bad = ["dropped %r" % (s,) for s in want - got] + ["doubled %r" % (s,) for s in got - want]
    return bad + [b for i, p in enumerate(parts, 1) for b in _part_bad295(i, p, whole)]


_out295 = _tf295.mkdtemp(prefix="jscov295-")
try:
    _rc_whole295, _whole295 = _main295([], _out295)
    _kinds295 = _col295.Counter(k for k, _p in _whole295)
    check("js coverage parts: (control) the whole walk, recorded, is every page, each confirming page, the i18n "
          "pages and the end once",
          _rc_whole295 == 0 and _whole295[0] == ("wizard", "") and _whole295[-1] == ("end", "")
          and [p for k, p in _whole295 if k == "page"] == _walk295.PAGES
          and [p for k, p in _whole295 if k == "confirm"] == _walk295.ACCEPT_PAGES
          and [p for k, p in _whole295 if k == "i18n"] == _walk295.I18N_PAGES and _kinds295["end"] == 1,
          repr((_rc_whole295, _whole295[:4], _kinds295)))

    def _parts295(n):
        runs = [_main295(["--part", "%d/%d" % (i, n)], _out295) for i in range(1, n + 1)]
        return [rc for rc, _s in runs], [s for _rc, s in runs]

    _by_n295 = {n: _parts295(n) for n in range(1, 9)}
    _bad295 = {n: _split_bad295(steps, _whole295) + ["exit %r" % rc for rc in rcs if rc != 0]
               for n, (rcs, steps) in _by_n295.items()}
    check("js coverage parts: run.py --part I/N, for every N from 1 to 8, walks each step of the whole walk in "
          "exactly one part (none dropped, none doubled), in the walk's order, a page's confirming pass with its "
          "first pass, and the end last",
          not any(_bad295.values()), repr({n: b[:4] for n, b in _bad295.items() if b}))
    check("js coverage parts: ...and four parts each walk a share (no part is only the wizard)",
          all(len(s) > 3 for s in _by_n295[4][1]), repr([len(s) for s in _by_n295[4][1]]))

    # Controls: the same comparison catches a split that drops a unit, and one that doubles one.
    _real295 = _run295.part_units
    _ctl295 = {}
    for _name295, _bent295 in (
            ("drop", lambda i, n: _real295(i, n)[:-1] if i == n else _real295(i, n)),
            ("double", lambda i, n: _real295(i, n) + (_real295(1, n)[:1] if i == n else []))):
        _run295.part_units = _bent295
        try:
            _ctl295[_name295] = _split_bad295(_parts295(4)[1], _whole295)
        finally:
            _run295.part_units = _real295
    check("js coverage parts: (control) a split that drops a unit, and one that doubles a unit, are both caught",
          any(b.startswith("dropped") for b in _ctl295["drop"])
          and any(b.startswith("doubled") for b in _ctl295["double"]), repr(_ctl295))
    _refused295 = {a: _main295(["--part", a], _out295)[0] for a in ("5/4", "0/4", "4", "1/0", "a/4", "1/4/2")}
    eq("js coverage parts: a --part that is not I/N with 1 <= I <= N stops run.py before anything runs",
       _refused295, {a: 2 for a in _refused295})
finally:
    _sh295.rmtree(_out295, ignore_errors=True)

# ── 2. the merge ─────────────────────────────────────────────────────────────────────────────────
_P1_295 = ("TN:\nSF:panel/static/js/a.js\nDA:1,2\nDA:3,0\nLF:2\nLH:1\nend_of_record\n"
           "TN:\nSF:panel/static/js/b.js\nDA:5,0\nLF:1\nLH:0\nend_of_record\n")
_P2_295 = ("TN:\nSF:panel/static/js/a.js\nFN:1,f\nFNDA:0,f\nBRDA:3,0,0,-\nBRDA:3,0,1,2\nDA:1,1\nDA:3,4\nDA:4,0\n"
           "LF:99\nLH:99\nend_of_record\n")
_P3_295 = "SF:panel/static/js/a.js\nFN:1,f\nFNDA:3,f\nBRDA:3,0,0,1\nDA:4,0\nend_of_record\n"
_MERGED295 = ("TN:\nSF:panel/static/js/a.js\nFN:1,f\nFNDA:3,f\nFNF:1\nFNH:1\nBRDA:3,0,0,1\nBRDA:3,0,1,2\nBRF:2\n"
              "BRH:2\nDA:1,3\nDA:3,4\nDA:4,0\nLF:3\nLH:2\nend_of_record\n"
              "TN:\nSF:panel/static/js/b.js\nDA:5,0\nLF:1\nLH:0\nend_of_record\n")


def _read295(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _merge_run295(reports, tmp):
    """merge.main over `reports` (texts, or None for a file that is not there); (status, lcov.info, summary)."""
    tmp, paths = _tf295.mkdtemp(dir=tmp), []
    for i, text in enumerate(reports, 1):
        paths.append(os.path.join(tmp, "lcov.p%d.info" % i))
        if text is not None:
            with open(paths[-1], "w", encoding="utf-8") as fh:
                fh.write(text)
    out, summ = os.path.join(tmp, "lcov.info"), os.path.join(tmp, "summary.txt")
    return _merge_main295(tmp, ["--out", out, "--summary", summ] + paths), _read295(out), _read295(summ)


def _merge_main295(cwd, argv):
    """merge.main(argv) run in `cwd` (CI runs it in the workspace), its output kept off the test's; the status."""
    before = os.getcwd()
    os.chdir(cwd)
    try:
        with _ctx295.redirect_stdout(_io295.StringIO()), _ctx295.redirect_stderr(_io295.StringIO()):
            return _merge295.main(argv)
    finally:
        os.chdir(before)


_mt295 = _tf295.mkdtemp(prefix="jscov295-merge-")
try:
    # Every path merge.py is given must resolve inside the folder it runs in: a report outside it, a `..` out of it
    # and a link inside it that points out are refused (status 2) before anything is read or written.
    _jail295, _outside295 = os.path.join(_mt295, "ws"), os.path.join(_mt295, "elsewhere.info")
    os.makedirs(_jail295)
    with open(_outside295, "w", encoding="utf-8") as _fh295:
        _fh295.write(_P1_295)
    os.symlink(_outside295, os.path.join(_jail295, "link.info"))
    _esc295 = {_k: _merge_main295(_jail295, ["--out", "lcov.info"] + _v) for _k, _v in (
        ("absolute", [_outside295]), ("dotdot", [os.path.join("..", "elsewhere.info")]), ("link", ["link.info"]))}
    with open(os.path.join(_jail295, "lcov.p1.info"), "w", encoding="utf-8") as _fh295:
        _fh295.write(_P1_295)
    _esc295["out"] = _merge_main295(_jail295, ["--out", os.path.join("..", "x.info"), "lcov.p1.info"])
    check("js coverage merge: a report outside the folder it runs in, a `..` out of it, a link pointing out of it "
          "and an --out outside it are refused (status 2), and nothing is written",
          _esc295 == {"absolute": 2, "dotdot": 2, "link": 2, "out": 2}
          and not os.path.exists(os.path.join(_jail295, "lcov.info")) and not os.path.exists(os.path.join(_mt295, "x.info")),
          repr(_esc295))
    _m295 = _merge_run295([_P1_295, _P2_295, _P3_295], _mt295)
    check("js coverage merge: each file's line hits are summed over the parts and its lines are their union, "
          "LF/LH counted again (a part's own totals ignored); FN/FNDA and BRDA summed, '-' only where no part ran",
          _m295[0] == 0 and _m295[1] == _MERGED295, repr(_m295[:2]))
    check("js coverage merge: ...and the summary's TOTAL is the merged lines' (4 lines, 2 hit)",
          _m295[2] is not None and _re295.search(r"^TOTAL +4 +2 +50\.0%$", _m295[2], _re295.M) is not None,
          repr(_m295[2]))
    _one295 = _v8_295.to_lcov({"panel/static/js/a.js": {1: 2, 3: 0}, "panel/static/js/b.js": {5: 0}})
    _alone295 = _merge_run295([_one295], _mt295)
    check("js coverage merge: (control) one report run.py wrote, merged alone, comes back unchanged",
          _alone295[0] == 0 and _alone295[1] == _one295 == _P1_295, repr(_alone295[:2]))
    _ref295 = {"missing": _merge_run295([_P1_295, None], _mt295)[0],
               "a record outside SF": _merge_run295(["DA:1,1\n"], _mt295)[0],
               "not a record": _merge_run295(["SF:panel/static/js/a.js\nXX:1\nend_of_record\n"], _mt295)[0],
               "unterminated": _merge_run295(["SF:panel/static/js/a.js\nDA:1,1\n"], _mt295)[0],
               "bad number": _merge_run295(["SF:panel/static/js/a.js\nDA:1,x\nend_of_record\n"], _mt295)[0],
               "nothing ran": _merge_run295(["SF:panel/static/js/a.js\nDA:1,0\nend_of_record\n"], _mt295)[0]}
    eq("js coverage merge: a part's report that is missing or not LCOV stops it (2), and one where no line ran "
       "fails it (3)", _ref295, {"missing": 2, "a record outside SF": 2, "not a record": 2, "unterminated": 2,
                                 "bad number": 2, "nothing ran": 3})
finally:
    _sh295.rmtree(_mt295, ignore_errors=True)

# ── 3. ci.yml: the parts and their verdict ───────────────────────────────────────────────────────
_ci295 = _wf29("ci.yml")
_parts_job295 = _job29(_ci295, "js-coverage")
_verdict295 = _job29(_ci295, "js-coverage-verdict")
_matrix295 = _re295.findall(r"^          - part: (\S+)\n            id: (\w+)$", _parts_job295, _re295.M)
_add295 = _wf_run_block(_verdict295, "Add the parts' reports into one")
check("ci.yml: the js coverage parts are the four I/4, and the verdict's merge reads the report of each id",
      _matrix295 == [("1/4", "p1"), ("2/4", "p2"), ("3/4", "p3"), ("4/4", "p4")]
      and "for id in p1 p2 p3 p4; do" in _add295 and '--part "${PART}"' in _parts_job295,
      repr((_matrix295, _add295[:200])))
check("ci.yml: js-coverage-verdict is named `js coverage`, needs the parts, runs whatever happened and reads "
      "their result; its upload is the js-coverage artifact codacy-coverage.yml reads",
      all(t in _verdict295 for t in ("    name: js coverage\n", "    needs: js-coverage\n",
                                     "    if: ${{ always() }}\n", "RESULT: ${{ needs.js-coverage.result }}\n",
                                     "          name: js-coverage\n"))
      and "lcov.info" in _verdict295.split("name: js-coverage\n", 1)[-1], _verdict295[:300])


def _bash295(script, tmp, env):
    path = os.path.join(tmp, "step.sh")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(script)
    env = dict(env, PATH=os.path.join(tmp, "bin") + ":/usr/bin:/bin")
    return _sp295.run(["/bin/bash", "-e", path], cwd=tmp, capture_output=True, text=True,  # nosec B603 - ci.yml's step
                      timeout=60, check=False, env=env)


_vt295 = _tf295.mkdtemp(prefix="jscov295-ci-")
try:
    _vr295 = {r: _bash295(_wf_run_block(_verdict295, "Every part of the js coverage run passed"), _vt295,
                          {"RESULT": r}).returncode for r in ("success", "failure", "cancelled", "skipped", "")}
    eq("ci.yml: the js coverage verdict passes only when every part passed: failed, cancelled, skipped or no "
       "result fails it", _vr295, {"success": 0, "failure": 1, "cancelled": 1, "skipped": 1, "": 1})
    os.makedirs(os.path.join(_vt295, "bin"))
    os.symlink(sys.executable, os.path.join(_vt295, "bin", "python3"))
    os.makedirs(os.path.join(_vt295, "tools", "js_coverage"))
    for _f295 in ("merge.py", "v8_lcov.py"):
        _sh295.copy(os.path.join(_JC295, _f295), os.path.join(_vt295, "tools", "js_coverage", _f295))
    _parts_dir295 = os.path.join(_vt295, "js-coverage-parts")   # the workspace, where the download step puts them
    os.makedirs(_parts_dir295)
    for _i295, _t295 in enumerate((_P1_295, _P2_295, _P3_295, _P1_295), 1):
        with open(os.path.join(_parts_dir295, "lcov.p%d.info" % _i295), "w", encoding="utf-8") as _fh295:
            _fh295.write(_t295)
    _env295 = {"RUNNER_TEMP": os.path.join(_vt295, "rt"), "GITHUB_STEP_SUMMARY": os.path.join(_vt295, "summary")}
    _all295 = _bash295(_add295, _vt295, _env295)
    _lcov295 = _read295(os.path.join(_vt295, "lcov.info")) or ""
    os.remove(os.path.join(_parts_dir295, "lcov.p3.info"))
    _short295 = _bash295(_add295, _vt295, _env295)
    check("ci.yml: the verdict's merge step adds the four parts' reports into lcov.info, and the summary goes on "
          "the run page",
          _all295.returncode == 0 and "SF:panel/static/js/a.js\n" in _lcov295 and "DA:1,5\n" in _lcov295
          and "TOTAL" in (_read295(_env295["GITHUB_STEP_SUMMARY"]) or ""),
          repr((_all295.returncode, _all295.stderr[-300:], _lcov295[:200])))
    check("ci.yml: ...and with a part's report missing it fails, naming the part",
          _short295.returncode != 0 and "::error::no js coverage report from the p3 part" in _short295.stdout,
          repr((_short295.returncode, _short295.stdout[-300:])))
finally:
    _sh295.rmtree(_vt295, ignore_errors=True)
