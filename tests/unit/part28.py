"""Part 28 of the unit suite: the Codacy and SonarCloud gates judge what they claim to judge.

An audit of every CI configuration against its vendor's documentation (2026-10-03) found four gates
that passed while reading less than main carries. Each check here fails on the tree before the fix:

* codacy_open_errors.py read Codacy's Error level only, and the API has a High level too (CD4).
* codacy_open_errors.py reported green, every day, while its three accepted system_ops.py findings
  "no longer matched": system_ops.py had grown past 150 KB and Codacy Cloud stopped analysing it.
  An accepted entry Codacy stops reporting while its file is over 150 KB, or while its line is
  still there, now fails the run (CD2).
* complexity_gate.py now runs Prospector over every changed Python file over 150 KB, base and head,
  which Codacy's required pull-request check never reads (CD1, the pull-request side).
* nothing judged main's open SonarCloud issues, so an issue a pull request made on a line it did
  not change reached main with both Sonar checks green (SQ1). sonar_new_issues.py --branch and
  .github/workflows/sonar-main-issues.yml do.

HOW IT RUNS. The scripts are loaded from .github/scripts by path. Network calls are stubbed on the
loaded module and restored in a finally. complexity_gate.py imports Lizard, which the unit suite's
environment does not install, so a stand-in module is put in sys.modules for the load and taken out
again; its Prospector runs are stubbed at the module's subprocess.run, and its real Prospector run
is the --self-test the complexity job runs before its verdict (part19 holds that order). Workflow
files are read as text: PyYAML is not in the suite's environment on CI.
"""
import contextlib as _ctx28
import importlib.util as _ilu28
import io as _io28
import json as _json28
import os
import pathlib as _pl28
import re as _re28
import shutil as _sh28
import subprocess as _sp28  # nosec B404 - git in a throwaway repository, fixed argv
import sys
import tempfile as _tf28
import types as _types28

from unit.part01 import check

_R28 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_TMP28 = _tf28.mkdtemp(prefix="lgsm-unit-p28-")


def _load28(rel, name, stubs=None):
    """Load a script from the checkout by path, with `stubs` in sys.modules only while it loads."""
    saved = {k: sys.modules.get(k) for k in (stubs or {})}
    sys.modules.update(stubs or {})
    try:
        spec = _ilu28.spec_from_file_location(name, os.path.join(_R28, rel))
        mod = _ilu28.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


def _read28(rel):
    with open(os.path.join(_R28, rel), encoding="utf-8") as fh:
        return fh.read()


# ══ Codacy: the main gate reads High as well as Error (CD4) ═══════════════════════════════════════
_cg28 = _load28(".github/scripts/codacy_open_errors.py", "codacy_gate_p28")


class _Resp28:
    def __init__(self, body):
        self._b = body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _drive28(issues, accepted, checkout):
    """main()'s exit code, stdout+stderr and the request bodies, for one answer and one checkout."""
    sent, out = [], _io28.StringIO()
    acc = _pl28.Path(_tf28.mkdtemp(prefix="acc-", dir=_TMP28)) / "accepted.json"
    acc.write_text(_json28.dumps({"accepted": accepted}), encoding="utf-8")
    saved = (_cg28.urllib.request.urlopen, _cg28.ACCEPTED_FILE, _cg28.CHECKOUT,
             os.environ.pop("GITHUB_STEP_SUMMARY", None))

    def _urlopen(req, **_kw):
        sent.append(_json28.loads(req.data.decode()))
        return _Resp28(_json28.dumps({"data": issues, "pagination": {}}).encode())
    _cg28.urllib.request.urlopen, _cg28.ACCEPTED_FILE, _cg28.CHECKOUT = _urlopen, acc, checkout
    try:
        with _ctx28.redirect_stdout(out), _ctx28.redirect_stderr(out):
            rc = _cg28.main()
    finally:
        _cg28.urllib.request.urlopen, _cg28.ACCEPTED_FILE, _cg28.CHECKOUT = saved[:3]
        if saved[3] is not None:
            os.environ["GITHUB_STEP_SUMMARY"] = saved[3]
    return rc, out.getvalue(), sent


_co28 = _pl28.Path(_tf28.mkdtemp(prefix="checkout-", dir=_TMP28))
(_co28 / "pkg").mkdir()
_co28_line = "cmd, shell=True, capture_output=True, text=text, timeout=timeout,"
_co28_small = "def f(cmd):\n    r = run(\n        %s\n    )\n" % _co28_line
(_co28 / "pkg" / "small.py").write_text(_co28_small, encoding="utf-8")
(_co28 / "pkg" / "big.py").write_text("# %s\n" % ("x" * 70) * 2200, encoding="utf-8")   # 160 KB
(_co28 / "pkg" / "gone.py").write_text("X = 1\n", encoding="utf-8")


def _acc28(path, text=_co28_line, pattern="Semgrep_x.rule"):
    return {"filePath": path, "patternId": pattern, "lineText": text, "reason": "r",
            "acceptedOn": "2026-10-03"}


_cd4_rc, _cd4_out, _cd4_sent = _drive28([], [], _co28)
check("codacy gate: it asks Codacy for the Error AND High levels (High sat between Error and "
      "Warning, ungated)",
      _cd4_sent and all(_b == {"levels": ["Error", "High"]} for _b in _cd4_sent) and _cd4_rc == 0,
      repr((_cd4_sent, _cd4_rc)))
_cd4_high = {"filePath": "pkg/small.py", "patternInfo": {"id": "x.rule9"}, "lineText": "evil()",
             "lineNumber": 3, "toolInfo": {"name": "Semgrep"}, "message": "high one", "level": "High"}
_cd4_rc2, _cd4_out2, _ = _drive28([_cd4_high], [], _co28)
check("codacy gate: ...an unreviewed High-level issue fails the run, and the summary says which "
      "levels it read",
      _cd4_rc2 == 1 and "Critical- or High-level" in _cd4_out2 and "API levels: Error, High" in _cd4_out2
      and "`rule9`" in _cd4_out2, _cd4_out2[-600:])

# ══ Codacy: an accepted entry Codacy stops reporting is not "stale" while it stands (CD2) ═════════
_cd2_present = _drive28([], [_acc28("pkg/small.py")], _co28)
check("codacy gate: an accepted entry whose line is still in the file, with nothing reported, "
      "fails the run, named",
      _cd2_present[0] == 1 and "::error::Codacy reports nothing for pkg/small.py" in _cd2_present[1]
      and "the accepted line is still in the file" in _cd2_present[1]
      and "(remove them)" not in _cd2_present[1], _cd2_present[1][-700:])
_cd2_big = _drive28([], [_acc28("pkg/big.py", text="not in the file")], _co28)
check("codacy gate: ...as does one whose file is over 150 KB, even with its line not found",
      _cd2_big[0] == 1 and "::error::Codacy reports nothing for pkg/big.py" in _cd2_big[1]
      and "over the 150 KB Codacy Cloud analyses" in _cd2_big[1], _cd2_big[1][-700:])
_cd2_gone = _drive28([], [_acc28("pkg/gone.py"), _acc28("pkg/deleted.py")], _co28)
check("codacy gate: ...an entry whose line (or file) is really gone is only listed for removal",
      _cd2_gone[0] == 0 and "(remove them)" in _cd2_gone[1] and "pkg/gone.py" in _cd2_gone[1]
      and "pkg/deleted.py" in _cd2_gone[1] and "::error::" not in _cd2_gone[1], _cd2_gone[1][-700:])
_cd2_match = {"filePath": "pkg/small.py", "patternInfo": {"id": "Semgrep_x.rule"},
              "lineText": "  " + _co28_line, "lineNumber": 3}
_cd2_ok = _drive28([_cd2_match], [_acc28("pkg/small.py")], _co28)
check("codacy gate: ...and an accepted entry Codacy still reports passes, as before (control)",
      _cd2_ok[0] == 0 and "::error::" not in _cd2_ok[1], _cd2_ok[1][-500:])
_cd2_escape = _drive28([], [_acc28("../" + os.path.basename(_TMP28) + "/x.py")], _co28)
check("codacy gate: ...an accepted path outside the checkout is never read as the checkout's",
      _cd2_escape[0] == 0 and _cg28._checkout_file("/etc/passwd") is None, _cd2_escape[1][-300:])
# The live case: the real accepted list against the real checkout, with Codacy reporting nothing.
# system_ops.py is over 150 KB and holds every accepted line, so this is what the daily run sees.
_cd2_real_rc, _cd2_real_out, _ = _drive28(
    [], _json28.loads(_read28(".github/codacy-accepted-errors.json"))["accepted"], _cg28.CHECKOUT)
check("codacy gate: ...on this checkout, the accepted system_ops.py findings Codacy no longer "
      "reports fail the run (it is over 150 KB)",
      _cd2_real_rc == 1
      and _cd2_real_out.count("::error::Codacy reports nothing for panel/ops/system_ops.py") == 3,
      _cd2_real_out[-500:])
_ca28 = _read28(".github/workflows/codacy-alerts.yml")
check("codacy alerts workflow: checks the repository out before the gate reads it, and says it "
      "reads High",
      -1 < _ca28.find("uses: actions/checkout@") < _ca28.find("codacy_open_errors.py\n")
      and "Critical- or High-level" in _ca28 and "over 150 KB" in _ca28, _ca28[:400])

# ══ The complexity gate: Prospector over changed Python files over 150 KB (CD1, PR side) ═════════
_lizard28 = _types28.ModuleType("lizard")
# Lizard finds nothing here: its own checks are the self-test's, and what is under test is the run.
_lizard28.analyze_file = _types28.SimpleNamespace(
    analyze_source_code=lambda name, code: _types28.SimpleNamespace(function_list=[], nloc=0))
_cx28 = _load28(".github/scripts/complexity_gate.py", "complexity_gate_p28", {"lizard": _lizard28})
_GIT28 = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
              GIT_COMMITTER_EMAIL="t@t", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


def _repo28(before, after):
    """A throwaway repository with a base and a head commit: (its path, the base sha)."""
    d = _tf28.mkdtemp(prefix="cx-", dir=_TMP28)
    _sp28.run(["git", "init", "-q", "-b", "main", d], env=_GIT28, capture_output=True,  # nosec
              check=True)
    _cx28._test_commit(d, _GIT28, before, "base")
    base = _sp28.run(["git", "rev-parse", "HEAD"], cwd=d, env=_GIT28, capture_output=True,  # nosec
                     text=True, check=True).stdout.strip()
    _cx28._test_commit(d, _GIT28, after, "head")
    return d, base


_cx28_big = "# %s\n" % ("x" * 69) * 2100                     # 151,200 bytes
_cx28_prof = "inherits:\n  - default\n# the base's\n"
_cx28_d, _cx28_base = _repo28(
    {".prospector.yaml": _cx28_prof, "big.py": _cx28_big, "small.py": "X = 1\n",
     "tools/panel-helper": _cx28_big, "edge.py": "#" * 149999 + "\n",
     "old.py": "# old\n" + _cx28_big},
    {".prospector.yaml": "inherits:\n  - default\n# the head's, ignored\n",
     "big.py": _cx28_big + "Y = 2\n", "small.py": "X = 2\n", "tools/panel-helper": _cx28_big + "#\n",
     "edge.py": "#" * 149998 + "\n\n", "old.py": None, "new.py": "# old\n" + _cx28_big,
     "a.js": "//\n" + _cx28_big})
_cx28_files = _cx28.changed_files(_cx28_base, cwd=_cx28_d)
_cx28_big_files = _cx28.oversized(_cx28_base, _cx28_files, cwd=_cx28_d)
check("complexity gate: Prospector judges exactly the changed Python files over 150,000 bytes "
      "(panel-helper included, a rename against its old self)",
      sorted(_cx28_big_files) == [("big.py", "big.py"), ("new.py", "old.py"),
                                  ("tools/panel-helper", "tools/panel-helper")],
      repr((_cx28_files, _cx28_big_files)))


class _Run28:
    """A stand-in for subprocess.run that answers Prospector calls and passes git through."""

    def __init__(self, answer):
        self.answer, self.calls, self.profiles, self.real = answer, [], [], _cx28.subprocess.run

    def __call__(self, argv, **kw):
        if argv[1:3] != ["-m", "prospector"]:
            return self.real(argv, **kw)
        prof = os.path.join(kw["cwd"], ".prospector.yaml")
        self.calls.append((argv, kw.get("cwd"), sorted(
            os.path.relpath(os.path.join(_dp, _f), kw["cwd"])
            for _dp, _dns, _fns in os.walk(kw["cwd"]) for _f in _fns)))
        self.profiles.append(_pl28.Path(prof).read_text(encoding="utf-8")
                             if os.path.isfile(prof) else None)
        rc, out = self.answer(argv, kw["cwd"])
        return _sp28.CompletedProcess(argv, rc, out, "")


def _pmsg28(path, source, code, line, message="m"):
    return {"source": source, "code": code, "message": message,
            "location": {"path": path, "line": line, "function": None}}


_PTOOLS28 = ("dodgy", "mccabe", "profile-validator", "pycodestyle", "pydocstyle", "pyflakes")


def _answer28(head_extra=(), tools=_PTOOLS28, canary=True, rc=0, raw=None):
    """A Prospector stand-in: each file's own findings, plus `head_extra` on the HEAD side."""
    def _ans(argv, cwd):
        if raw is not None:
            return rc, raw
        msgs = [_pmsg28("zz_complexity_gate_canary.py", "pyflakes", "F401", 1)] if canary else []
        for name in argv[argv.index("--zero-exit") + 1:-1]:
            with open(os.path.join(cwd, name), encoding="utf-8") as fh:
                text = fh.read()
            msgs += [_pmsg28(name, "pyflakes", "F401", n + 1, "unused")
                     for n, ln in enumerate(text.splitlines()) if ln.startswith("import ")]
            if text.endswith("Y = 2\n"):
                msgs += [_pmsg28(name, *e) for e in head_extra]
        return rc, _json28.dumps({"summary": {"tools": list(tools)}, "messages": msgs})
    return _ans


def _px28(answer, pairs=(("big.py", "big.py"),), d=None, base=None):
    run = _Run28(answer)
    saved = _cx28.subprocess.run
    _cx28.subprocess.run = run
    try:
        return _cx28.prospector_violations(base or _cx28_base, list(pairs), cwd=d or _cx28_d), run
    finally:
        _cx28.subprocess.run = saved


_px28_new, _px28_run = _px28(_answer28(head_extra=[("pydocstyle", "D415", 5, "First line")]))
check("complexity gate: a Prospector finding the head adds to a file over 150 KB fails, named with "
      "its file, line, tool and code",
      len(_px28_new) == 1 and _px28_new[0][:2] == ("big.py", 5)
      and _px28_new[0][2].startswith("Prospector pydocstyle D415: First line (0 on the base, 1 now")
      and "Codacy Cloud skips this file" in _px28_new[0][2], repr(_px28_new))
check("complexity gate: ...Prospector runs on both sides, from a root holding the file at its own "
      "path, the BASE's profile and the canary",
      len(_px28_run.calls) == 2
      and all(_files == [".prospector.yaml", "big.py", "zz_complexity_gate_canary.py"]
              for _a, _cwd, _files in _px28_run.calls)
      and all("--profile" not in _a for _a, _cwd, _f in _px28_run.calls)
      and _px28_run.profiles == [_cx28_prof, _cx28_prof],
      repr((_px28_run.calls, _px28_run.profiles)))
_px28_same, _ = _px28(_answer28())
check("complexity gate: ...and nothing new on the head is no violation (control)",
      _px28_same == [], repr(_px28_same))
_px28_helper, _px28_hrun = _px28(_answer28(), pairs=(("tools/panel-helper", "tools/panel-helper"),))
check("complexity gate: ...tools/panel-helper is handed to Prospector as a .py file under tools/",
      _px28_helper == [] and all("tools/panel-helper.py" in _files
                                 for _a, _cwd, _files in _px28_hrun.calls), repr(_px28_hrun.calls))
# Moved code: the same finding at another line is the same finding, and a new one beside an old
# one of the same code is named by its own line, not the old one's. The stand-in gives every
# unused import the SAME message, as pydocstyle's D415 "(not 'n')" repeats across a file: told
# apart by message alone, the NEW finding above the old one matched the old one, and the old one
# was named instead (it named system_ops.py:58 for a D415 added at line 4499).
_px28_d2, _px28_b2 = _repo28({"m.py": _cx28_big + "import os\n"},
                             {"m.py": "import sys\n# moved\n" + _cx28_big + "import os\n"})
_px28_moved, _ = _px28(_answer28(), pairs=(("m.py", "m.py"),), d=_px28_d2, base=_px28_b2)
check("complexity gate: ...a finding that moved is matched, and the new one of the same code is "
      "the one named",
      [(_p, _l) for _p, _l, _m in _px28_moved] == [("m.py", 1)]
      and "(1 on the base, 2 now" in _px28_moved[0][2], repr(_px28_moved))
_px28_fails = {_label: _px28(_ans)[0] for _label, _ans in (
    ("crash", _answer28(rc=1, raw="Traceback (most recent call last): boom")),
    ("not json", _answer28(raw="<html>")),
    ("exit 1 with json", _answer28(rc=2)),
    ("no pydocstyle", _answer28(tools=[_t for _t in _PTOOLS28 if _t != "pydocstyle"])),
    ("no canary", _answer28(canary=False)),
    ("tool failed", _answer28(head_extra=[("prospector", "failure", 1, "pyflakes crashed")])))}
check("complexity gate: ...a Prospector run it cannot trust fails the check: a crash, output that is "
      "not its JSON, a non-zero exit, a missing tool, a missing canary, a tool failure",
      all(len(_v) == 1 and _v[0][0] == "big.py" and _v[0][2].startswith("Prospector")
          and "Codacy Cloud skips" not in _v[0][2] for _v in _px28_fails.values()),
      repr(_px28_fails))
# The caller: run() is what main() reports from, so the Prospector findings must reach ITS problems,
# for the files it found over 150 KB. Pylint is answered with nothing, as Lizard is.
_run28 = _Run28(_answer28(head_extra=[("pydocstyle", "D415", 5, "First line")]))
_run28_real, _cx28.subprocess.run = _cx28.subprocess.run, (
    lambda argv, **kw: _sp28.CompletedProcess(argv, 0, "", "") if argv[1:3] == ["-m", "pylint"]
    else _run28(argv, **kw))
try:
    _run28_problems, _run28_files, _run28_big = _cx28.run(_cx28_base, cwd=_cx28_d)
finally:
    _cx28.subprocess.run = _run28_real
check("complexity gate: run() reports Prospector's findings in the files over 150 KB it found, "
      "beside Lizard's and Pylint's",
      [(_p, _l) for _p, _l, _m in _run28_problems if _m.startswith("Prospector pydocstyle D415")]
      == [("big.py", 5)] and len(_run28_big) == 3 and "new.py" in _run28_files
      and len(_run28.calls) == 2, repr((_run28_problems, _run28_big)))
_px28_none, _px28_nrun = _px28(_answer28(), pairs=())
check("complexity gate: ...and with no file over 150 KB changed, Prospector is not run at all",
      _px28_none == [] and _px28_nrun.calls == [], repr(_px28_nrun.calls))
_cx28_src = _read28(".github/scripts/complexity_gate.py")
check("complexity gate: no longer claims .codacy.yaml makes Codacy read tools/panel-helper as Python",
      ".codacy.yaml says so" not in _cx28_src and "which Codacy reads as Python" not in _cx28_src
      and "does NOT make Codacy analyse" in _cx28_src, _cx28_src[:300])
_cxw28 = _read28(".github/workflows/complexity.yml")
_cxin28 = _read28(".github/ci-requirements/complexity.in")
_cxtxt28 = _read28(".github/ci-requirements/complexity.txt")
check("complexity job: Prospector pinned at Codacy's version with hashes, pylint-celery (sdist only) "
      "left out, the closure installed wheels-only with --no-deps",
      _re28.search(r"^prospector==1\.19\.1$", _cxin28, _re28.M) is not None
      and _re28.search(r"^prospector==1\.19\.1 \\\n    --hash=sha256:", _cxtxt28, _re28.M) is not None
      and _re28.search(r"^#    pip-compile (?!.*--allow-unsafe).*--unsafe-package=pylint-celery ",
                       _cxtxt28, _re28.M) is not None
      and _re28.search(r"^pylint-celery==", _cxtxt28, _re28.M) is None
      and _re28.search(r"--require-hashes --only-binary :all: --no-deps\s+-r \.github/ci-requirements/"
                       r"complexity\.txt", _cxw28) is not None, _cxw28[-900:])

# ══ SonarCloud: main's open issues are judged, with a positive control (SQ1) ═════════════════════
_sq28 = _load28(".github/scripts/sonar_new_issues.py", "sonar_gate_p28")
_SHA28 = "a" * 40
# The known issue's key comes from the script's own KNOWN_OPEN (pinned to its literal below):
# written here as a '"key": "<20 characters>"' pair, Gitleaks' generic-api-key rule reads a secret.
_sq28_known = {"key": next(iter(_sq28.KNOWN_OPEN)), "component": "P:.clusterfuzzlite/Dockerfile",
               "line": 10, "severity": "MINOR", "rule": "docker:S6471", "message": "root"}
_sq28_new = {"key": "NEW1", "component": "P:panel/x.py", "line": 3, "severity": "MAJOR",
             "rule": "python:S1481", "message": "Remove the unused local variable"}


def _sq28_drive(issues, analysed_after=0, total=None, sha=_SHA28):
    """run_branch with SonarCloud stubbed: (problems, judged, the calls made, sleeps)."""
    calls, sleeps, polls = [], [], []

    def _get(path, **params):
        calls.append((path, params))
        if path == "project_branches/list":
            return {"branches": [{"name": "main", "isMain": True, "commit": {"sha": _SHA28},
                                  "status": {"vulnerabilities": 1}}]}
        if path == "project_analyses/search":
            polls.append(1)
            revs = [{"revision": "b" * 40}] + ([{"revision": _SHA28}]
                                               if len(polls) > analysed_after else [])
            return {"analyses": revs}
        return {"issues": issues if params.get("p") == 1 else [],
                "paging": {"total": len(issues) if total is None else total}}
    saved = (_sq28._get, _sq28.time.sleep)
    _sq28._get, _sq28.time.sleep = _get, sleeps.append
    try:
        problems, judged = _sq28.run_branch("main", sha, 900)
    finally:
        _sq28._get, _sq28.time.sleep = saved
    return problems, judged, calls, sleeps


_sq1_ok = _sq28_drive([_sq28_known], analysed_after=2)
check("sonar main gate: waits until SonarCloud lists an analysis of this commit, then passes main "
      "holding only the known issue",
      _sq1_ok[0] == [] and _sq1_ok[1] == _SHA28 and len(_sq1_ok[3]) == 2
      and ("issues/search", {"componentKeys": "FMSMITH91_linuxgsm-panel", "branch": "main",
                             "resolved": "false", "ps": 500, "p": 1}) in _sq1_ok[2],
      repr(_sq1_ok))
_sq1_new = _sq28_drive([_sq28_known, _sq28_new])
check("sonar main gate: ...an open issue that is not known fails, named with its file, line, rule "
      "and key",
      _sq1_new[0] == ["panel/x.py:3 MAJOR python:S1481: Remove the unused local variable [NEW1]"],
      repr(_sq1_new[0]))
_sq1_empty = _sq28_drive([])
check("sonar main gate: ...the known issue missing fails (an empty read is not a clean main)",
      any("AaDejKLMfWz637hiAQny" in _p and "not in SonarCloud's list" in _p for _p in _sq1_empty[0]),
      repr(_sq1_empty[0]))
_sq1_short = _sq28_drive([_sq28_known], total=5)
check("sonar main gate: ...a list shorter than SonarCloud's own total fails",
      any("counts 5 open issue(s)" in _p for _p in _sq1_short[0]), repr(_sq1_short[0]))
_sq1_sched = _sq28_drive([_sq28_known], sha=None)
check("sonar main gate: ...with no commit given (the schedule) it judges the analysed commit at once",
      _sq1_sched[0] == [] and _sq1_sched[1] == _SHA28 and _sq1_sched[3] == []
      and not any(_c[0] == "project_analyses/search" for _c in _sq1_sched[2]), repr(_sq1_sched))
_sq28_out = _io28.StringIO()
with _ctx28.redirect_stdout(_sq28_out):
    _sq28_rcs = (_sq28.main(["x", "--self-test"]),
                 _sq28.main(["x", "--branch", "main", "--sha", "nope"]),
                 _sq28.main(["x", "--branch", "main;rm", "--sha", _SHA28]))
check("sonar main gate: ...the known issue is the owner's declined docker:S6471, the self-test "
      "passes, and a malformed branch or commit is refused",
      set(_sq28.KNOWN_OPEN) == {"AaDejKLMfWz637hiAQny"}
      and "S6471" in _sq28.KNOWN_OPEN["AaDejKLMfWz637hiAQny"] and _sq28_rcs == (0, 2, 2)
      and "self-test: " in _sq28_out.getvalue() and "SELF-TEST FAIL" not in _sq28_out.getvalue(),
      repr((_sq28_rcs, _sq28_out.getvalue()[-300:])))
_smw28 = _read28(".github/workflows/sonar-main-issues.yml")
_smw28_on = _smw28[:_smw28.index("\npermissions:")]
check("sonar main workflow: push to main and a schedule, never a pull request; no concurrency group; "
      "self-test first; a push judges its own commit",
      _re28.search(r"^  push:\n    branches: \[ main \]\n", _smw28_on, _re28.M) is not None
      and "\n  schedule:\n" in _smw28_on and "pull_request" not in _smw28_on
      and "\nconcurrency:" not in _smw28 and "\npermissions:\n  contents: read\n" in _smw28
      and "persist-credentials: false" in _smw28
      and -1 < _smw28.find("sonar_new_issues.py --self-test") < _smw28.find(
          "sonar_new_issues.py --branch main")
      and "SHA: ${{ github.event_name == 'push' && github.sha || '' }}" in _smw28
      and '${SHA:+--sha "$SHA"}' in _smw28 and "name: SonarCloud open issues (main)\n" in _smw28,
      _smw28[-800:])

_sh28.rmtree(_TMP28, ignore_errors=True)
