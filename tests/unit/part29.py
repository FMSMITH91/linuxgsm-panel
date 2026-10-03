"""Part 29 of the unit suite: the CI configuration a vendor audit found short of its vendor's docs.

ClusterFuzzLite (its corpus, coverage and builds as Actions artifacts, and where they may come
from; the PR run's fuzzing time and the harnesses' start-up), the root-only unit checks run as
root in ci.yml, actionlint's shellcheck pass and its `vars` list, the Tailscale client the deploy
job installs, and every `uses:` pinned to a commit.

HOW IT RUNS. The workflows are read as TEXT, as part06 and part19 read them: the checks job
installs no YAML parser. Where a workflow step's script can be run, it is: cut out of the file and
run by bash or python on fixtures in a temporary directory, with stand-ins for `gh`, `actionlint`
and `shellcheck` on PATH. One check imports panel.ops.ssh_manager in a child process, the way
the fuzz harnesses do. Nothing here touches the network or the checkout's data/.
"""
import ast as _ast29
import glob as _glob29
import json as _json29
import os
import re as _re29
import shutil as _shutil29
import subprocess as _sp29  # nosec B404 - runs bash and python on this part's own fixtures
import sys as _sys29
import tempfile as _tf29

from unit.part01 import check
from unit.part01 import skip as _skip29
from unit.part06 import _wf_run_block

_ROOT29 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_WF29 = os.path.join(_ROOT29, ".github", "workflows")


def _read29(*parts):
    with open(os.path.join(_ROOT29, *parts), encoding="utf-8") as fh:
        return fh.read()


def _wf29(name):
    return _read29(".github", "workflows", name)


def _job29(text, job):
    """A job's block: from its `  <job>:` line to the next line at the jobs' own indent."""
    m = _re29.search(r"^  %s:\n" % _re29.escape(job), text, _re29.M)
    if m is None:
        return ""
    nxt = _re29.search(r"^  \S", text[m.end():], _re29.M)
    return text[m.start():m.end() + nxt.start()] if nxt else text[m.start():]


def _steps29(job_text):
    """The job's steps, each as its text from its `- ` line, in order."""
    body = job_text[job_text.find("\n    steps:\n"):]
    return ["- " + s for s in body.split("\n      - ")[1:]]


def _name29(step):
    m = _re29.search(r"^-? *name: (.*)$", step, _re29.M)
    return m.group(1).strip() if m else ""


def _runbody29(step):
    """The `run: |` block of one step's text, dedented, and nothing after it."""
    lines = step.splitlines()
    at = next((i for i, ln in enumerate(lines) if ln.strip() == "run: |"), None)
    if at is None:
        return ""
    ind = len(lines[at]) - len(lines[at].lstrip())
    body = []
    for ln in lines[at + 1:]:
        if ln.strip() and len(ln) - len(ln.lstrip()) <= ind:
            break
        body.append(ln)
    while body and not body[-1].strip():
        body.pop()
    cut = min((len(ln) - len(ln.lstrip()) for ln in body if ln.strip()), default=0)
    return "\n".join(ln[cut:] for ln in body) + "\n"


def _code29(text):
    """A workflow's text without its comment lines."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def _run29(argv, **kw):
    kw.setdefault("timeout", 120)
    return _sp29.run(argv, capture_output=True, text=True, check=False, **kw)  # nosec B603 - fixed argvs


_TMP29 = _tf29.mkdtemp(prefix="lgsm-unit-p29-")
try:
    # ── ClusterFuzzLite, PR side: the vendor's 600s, split across the targets ─────────────────────
    # 180s over six targets was 30s each, shorter than the ssh_manager targets' start-up, and each
    # was killed as "process timed out" before libFuzzer finished (CF1).
    _pr29 = _wf29("cflite_pr.yml")
    _pr_job29 = _job29(_pr29, "code-change")
    _pr_steps29 = _steps29(_pr_job29)
    _pr_run29 = [s for s in _pr_steps29 if "clusterfuzzlite/actions/run_fuzzers@" in s]
    check("cflite_pr: the PR run fuzzes for the vendor's 600s in code-change mode",
          len(_pr_run29) == 1
          and _re29.search(r"^ +fuzz-seconds: 600$", _pr_run29[0], _re29.M) is not None
          and _re29.search(r"^ +mode: code-change$", _pr_run29[0], _re29.M) is not None,
          _pr_run29[0][-600:] if _pr_run29 else "no run_fuzzers step")

    # ── the four ssh_manager harnesses pre-load the heavy dependencies, uninstrumented ────────────
    # With only paramiko and eventlet pre-loaded, Atheris instrumented 280 modules per target, ~27s
    # on a runner before the first input. The list is the same in all four, and must hold what
    # ssh_manager pulls in.
    _hz29 = {}
    for _p in sorted(_glob29.glob(os.path.join(_ROOT29, "tests", "fuzz", "fuzz_*.py"))):
        _tree = _ast29.parse(open(_p, encoding="utf-8").read())
        for _n in _ast29.walk(_tree):
            if (isinstance(_n, _ast29.For) and isinstance(_n.target, _ast29.Name)
                    and _n.target.id == "_dep" and isinstance(_n.iter, _ast29.Tuple)):
                _hz29[os.path.basename(_p)] = tuple(_c.value for _c in _n.iter.elts
                                                    if isinstance(_c, _ast29.Constant))
    _hz_want29 = {"fuzz_config.py", "fuzz_cron.py", "fuzz_firewall.py", "fuzz_game_status.py"}
    _hz_lists29 = set(_hz29.values())
    _hz_list29 = next(iter(_hz_lists29)) if len(_hz_lists29) == 1 else ()
    check("fuzz harnesses: the four ssh_manager harnesses pre-load one list, SQLAlchemy and Flask in it",
          set(_hz29) == _hz_want29 and len(_hz_lists29) == 1
          and {"paramiko", "eventlet.tpool", "flask_sqlalchemy", "flask_login",
               "sqlalchemy.dialects.sqlite"} <= set(_hz_list29)
          and _hz_list29[-1] == "panel.core.config", repr(_hz29))
    # ...and the list is enough: importing ssh_manager after it loads nothing outside panel/ and the
    # standard library, so Atheris instruments the panel's own modules and nothing else. A child
    # process, because this one imported ssh_manager long ago. It also records any file it opens
    # under the checkout's data/, which must be none.
    _hz_code29 = (
        "import importlib, json, os, sys\n"
        "data = os.path.join(%r, 'data') + os.sep\n"
        "opened = []\n"
        "def _hook(ev, args):\n"
        "    if ev == 'open' and args and isinstance(args[0], (str, bytes, os.PathLike)):\n"
        "        p = os.path.abspath(os.fsdecode(args[0]))\n"
        "        if p.startswith(data):\n"
        "            opened.append(p)\n"
        "sys.addaudithook(_hook)\n"
        "for d in %r:\n"
        "    importlib.import_module(d)\n"
        "before = set(sys.modules)\n"
        "from panel.ops import ssh_manager\n"
        "new = sorted(set(sys.modules) - before)\n"
        "print(json.dumps({'new': new, 'opened': opened}))\n" % (_ROOT29, _hz_list29))
    _r = _run29([_sys29.executable, "-W", "ignore", "-c", _hz_code29], cwd=_TMP29,
                env=dict(os.environ, PYTHONPATH=_ROOT29))
    try:
        _hz_out29 = _json29.loads(_r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        _hz_out29 = {"new": [], "opened": [], "error": _r.stdout[-400:] + _r.stderr[-800:]}
    _hz_panel29 = [m for m in _hz_out29["new"] if m == "panel" or m.startswith("panel.")]
    # eventlet's patcher keeps the unpatched stdlib modules under __original_module_<name>.
    _hz_other29 = [m for m in _hz_out29["new"]
                   if m not in _hz_panel29 and m.split(".")[0] not in _sys29.stdlib_module_names
                   and not m.startswith("__original_module_")]
    check("fuzz harnesses: after the pre-load, importing ssh_manager loads only panel modules and "
          "the standard library (what Atheris instruments)",
          len(_hz_panel29) >= 10 and "panel.ops.ssh_manager.cron" in _hz_panel29
          and not _hz_other29 and not _hz_out29["opened"],
          repr({"outside panel and stdlib": _hz_other29, "panel": len(_hz_panel29),
                "opened under data/": _hz_out29["opened"], "error": _hz_out29.get("error")}))

    # ── ClusterFuzzLite keeps everything as Actions artifacts, and nothing waits on a secret ──────
    # Every batch, prune and coverage step waited on a CFL_STORAGE_REPO secret that was never set:
    # those jobs reported success for two months having fuzzed nothing (CF2). The storage repo is
    # optional; the artifacts route needs no secret, and is the one taken, end to end.
    _cfl29 = {os.path.basename(p): open(p, encoding="utf-8").read()
              for p in sorted(_glob29.glob(os.path.join(_WF29, "cflite_*.yml")))}
    _cfl_bad29 = ["%s: %s" % (n, w) for n, t in _cfl29.items()
                  for w in ("CFL_STORAGE_REPO", "storage-repo") if w in _code29(t)]
    _cfl_bad29 += ["%s: a step-level if: reads env or secrets" % n for n, t in _cfl29.items()
                   if _re29.search(r"^ {8}if: .*\b(env|secrets)\.", t, _re29.M)]
    check("cflite: no workflow names a storage repository or gates a step on a secret",
          set(_cfl29) >= {"cflite_pr.yml", "cflite_batch.yml", "cflite_cron.yml", "cflite_build.yml"}
          and not _cfl_bad29, repr(_cfl_bad29))
    # The jobs that make the artifacts run on this repository's main only: the provenance check
    # below refuses any cifuzz-* artifact made anywhere else, so a producer elsewhere would stop
    # every reader. And each job that reads them may (actions: read, the vendor's read-all).
    _cfl_prod29 = {"cflite_batch.yml": ("batch",), "cflite_cron.yml": ("prune", "coverage"),
                   "cflite_build.yml": ("build",)}
    _cfl_pbad29 = []
    for _n, _jobs in _cfl_prod29.items():
        _t = _cfl29.get(_n, "")
        _on = _t[_t.find("\non:\n"):_t.find("\npermissions:")]
        if "pull_request" in _on:
            _cfl_pbad29.append("%s: runs for pull requests" % _n)
        for _j in _jobs:
            _jt = _job29(_t, _j)
            _if = _re29.search(r"^    if: (.*)$", _jt, _re29.M)
            if (not _if or "github.repository == 'FMSMITH91/linuxgsm-panel'" not in _if.group(1)
                    or ("github.ref == 'refs/heads/main'" not in _if.group(1)
                        and _on.strip() != "on:\n  push:\n    branches: [ main ]")):
                _cfl_pbad29.append("%s/%s: job if: %r" % (_n, _j, _if and _if.group(1)))
            if _n != "cflite_build.yml" and not _re29.search(r"^      actions: read\b", _jt, _re29.M):
                _cfl_pbad29.append("%s/%s: no actions: read" % (_n, _j))
    if not _re29.search(r"^      actions: read\b", _pr_job29, _re29.M):
        _cfl_pbad29.append("cflite_pr.yml: no actions: read")
    _bld29 = _steps29(_job29(_cfl29.get("cflite_build.yml", ""), "build"))
    if not (len(_bld29) == 1 and "clusterfuzzlite/actions/build_fuzzers@" in _bld29[0]
            and _re29.search(r"^ +upload-build: true$", _bld29[0], _re29.M)):
        _cfl_pbad29.append("cflite_build.yml: not one build_fuzzers step with upload-build: true")
    check("cflite: batch, prune, coverage and the continuous build run only on this repository's "
          "main; every reader may read artifacts; the build uploads itself",
          not _cfl_pbad29, repr(_cfl_pbad29))

    # ── every cifuzz-* artifact a job reads was made on main here ─────────────────────────────────
    # The action takes the newest artifact of a name from ANY run in the repository and unpacks it
    # unchecked; a fork's pull request can upload one. So in every job, a guard step comes before
    # any step that can read one (run_fuzzers; build_fuzzers given a token), and the copies are one.
    _GUARD29 = "Every stored fuzz artifact was made on main here"
    _g_bodies29, _g_bad29, _g_jobs29 = set(), [], 0
    for _n, _t in _cfl29.items():
        for _jm in _re29.finditer(r"^  ([a-z][a-z-]*):\n", _t[_t.find("\njobs:\n"):], _re29.M):
            _steps = _steps29(_job29(_t, _jm.group(1)))
            _readers = [i for i, s in enumerate(_steps)
                        if "clusterfuzzlite/actions/run_fuzzers@" in s
                        or ("clusterfuzzlite/actions/build_fuzzers@" in s and "github-token:" in s)]
            if not _readers:
                continue
            _g_jobs29 += 1
            _guards = [i for i, s in enumerate(_steps) if _name29(s).startswith(_GUARD29)]
            if not _guards or _guards[0] > _readers[0]:
                _g_bad29.append("%s/%s: no guard before step %d" % (_n, _jm.group(1), _readers[0]))
            for _gi in _guards:
                _g_bodies29.add(_runbody29(_steps[_gi]))
                if "continue-on-error" in _steps[_gi]:
                    _g_bad29.append("%s/%s: the guard may fail without failing the job" % (_n, _jm.group(1)))
    _pr_last29 = _pr_steps29[-1] if _pr_steps29 else ""
    if not (_name29(_pr_last29).startswith(_GUARD29)
            and "if: always() && steps.scope.outputs.run == 'true'" in _pr_last29):
        _g_bad29.append("cflite_pr.yml: the guard does not run again, always, after fuzzing")
    check("cflite: every job that reads a stored fuzz artifact checks first where all of them came "
          "from (and the PR job again after fuzzing), with one copy of the check",
          _g_jobs29 >= 4 and len(_g_bodies29) == 1 and not _g_bad29,
          repr((_g_jobs29, len(_g_bodies29), _g_bad29)))

    # ...and the check works: run, as the step runs it, against a stand-in `gh` that applies the
    # step's own --jq filter (with jq) to pages of artifacts.
    if _shutil29.which("jq") is None:
        _skip29("cflite: the artifact check, driven", "no jq on this machine")
    else:
        _g_run29 = _wf_run_block(_cfl29["cflite_batch.yml"], _GUARD29)
        _gbin29 = os.path.join(_TMP29, "gbin")
        os.makedirs(_gbin29)
        with open(os.path.join(_gbin29, "gh"), "w") as fh:
            fh.write('#!/bin/bash\n'
                     '[ "$1" = api ] || exit 9\n'
                     '[ "$2" = "repos/o/r/actions/artifacts?per_page=100" ] || { echo "path $2" >&2; exit 7; }\n'
                     'f=""; p=0; a=("$@")\n'
                     'for ((i = 0; i < ${#a[@]}; i++)); do\n'
                     '  case "${a[i]}" in --jq) f="${a[i+1]}" ;; --paginate) p=1 ;; esac\n'
                     'done\n'
                     '[ -z "${GH_FAKE_FAIL:-}" ] || { echo "HTTP 502" >&2; exit 1; }\n'
                     '[ "$p" = 1 ] || { echo "not paginated" >&2; exit 8; }\n'
                     'exec jq -r "$f" "$GH_FAKE_PAGES"\n')
        os.chmod(os.path.join(_gbin29, "gh"), 0o755)

        def _art29(name, aid, branch="main", head=5, repo=5, expired=False, run=True):
            return {"name": name, "id": aid, "expired": expired,
                    "workflow_run": ({"id": aid * 10, "head_branch": branch,
                                      "head_repository_id": head, "repository_id": repo}
                                     if run else None)}

        _g_main29 = [_art29("cifuzz-corpus-fuzz_cron", 1), _art29("coverage", 2, "topic", 9),
                     _art29("cifuzz-build-address-abc", 3, "evil", 9, expired=True)]
        _g_page2_29 = [_art29("cifuzz-coverage-latest", 4)]

        def _guard29(extra, fail=False):
            pages = os.path.join(_TMP29, "pages.json")
            with open(pages, "w") as fh:
                fh.write(_json29.dumps({"total_count": 9, "artifacts": _g_main29}) + "\n"
                         + _json29.dumps({"total_count": 9, "artifacts": _g_page2_29 + extra}) + "\n")
            env = dict(os.environ, PATH=_gbin29 + os.pathsep + os.environ.get("PATH", ""),
                       REPO="o/r", GH_TOKEN="t", GH_FAKE_PAGES=pages)
            if fail:
                env["GH_FAKE_FAIL"] = "1"
            r = _run29(["bash", "--noprofile", "--norc", "-e", "-c", _g_run29], env=env)
            return r.returncode, r.stdout + r.stderr

        _g = {"main": _guard29([]),
              "fork": _guard29([_art29("cifuzz-corpus-fuzz_x", 7, "main", 9)]),
              "branch": _guard29([_art29("cifuzz-coverage-latest", 8, "topic")]),
              "no run": _guard29([_art29("cifuzz-build-address-def", 6, run=False)]),
              "api": _guard29([], fail=True)}
        check("cflite: the artifact check passes main's own (expired and non-cifuzz ones from "
              "elsewhere ignored), and says how many it read (control)",
              _g["main"][0] == 0 and "stored cifuzz-* artifacts: 2" in _g["main"][1], repr(_g["main"]))
        check("cflite: ...and fails on one from a fork, even on a branch the fork calls main",
              _g["fork"][0] != 0 and "cifuzz-corpus-fuzz_x\t7\t70\tmain\t9\t5" in _g["fork"][1]
              and "::error::" in _g["fork"][1], repr(_g["fork"]))
        check("cflite: ...and on one from another branch here, or with no run recorded",
              _g["branch"][0] != 0 and "cifuzz-coverage-latest\t8" in _g["branch"][1]
              and _g["no run"][0] != 0 and "cifuzz-build-address-def\t6" in _g["no run"][1],
              repr((_g["branch"], _g["no run"])))
        check("cflite: ...and when the artifacts cannot be listed",
              _g["api"][0] != 0, repr(_g["api"]))

    # ── the root-only unit checks run, as root, in every checks leg (CI1) ─────────────────────────
    # They skipped in every CI leg, and a skip does not fail the unit suite. The step runs the
    # suite again as root after run-tests.sh has kept the runner's run in UNIT_LOG, and judges the
    # checks that ran only as root.
    _ci29 = _wf29("ci.yml")
    _ci_steps29 = _steps29(_job29(_ci29, "checks"))
    _ci_names29 = [_name29(s) for s in _ci_steps29]
    _ci_root_name29 = "Run the root-only unit checks, as root"
    _ci_bad29 = []
    _ci_rt_at29 = next((i for i, n in enumerate(_ci_names29) if n.startswith("Run all checks")), None)
    if (_ci_root_name29 not in _ci_names29 or _ci_rt_at29 is None
            or _ci_names29.index(_ci_root_name29) < _ci_rt_at29):
        _ci_bad29.append("no root step after the run-tests step: %r" % _ci_names29)
    else:
        _ci_rs = _ci_steps29[_ci_names29.index(_ci_root_name29)]
        _ci_rt = _ci_steps29[_ci_rt_at29]
        if 'UNIT_LOG="${RUNNER_TEMP}/unit-user.txt" bash tools/run-tests.sh' not in _ci_rt:
            _ci_bad29.append("run-tests.sh is not given UNIT_LOG")
        if ("sudo -E env PATH=\"$PATH\" bash -c 'unset \"${!SUDO_@}\"; exec python tests/unit_test.py'"
                not in _ci_rs or '"${RUNNER_TEMP}/unit-user.txt" "${root_log}"' not in _ci_rs):
            _ci_bad29.append("the root step does not run the suite as root, SUDO_* unset, and "
                             "compare it with UNIT_LOG")
        if _re29.search(r"^ {8}(if|continue-on-error):", _ci_rs, _re29.M):
            _ci_bad29.append("the root step can be skipped or fail without failing the job")
    _rt29 = _read29("tools", "run-tests.sh")
    if ('"$PY" tests/unit_test.py | tee "${UNIT_LOG}"' not in _rt29
            or "set -euo pipefail" not in _rt29.splitlines()[:12]):
        _ci_bad29.append("run-tests.sh does not tee the unit run to UNIT_LOG under pipefail")
    check("ci: every checks leg runs the unit suite again as root, against the runner's own run",
          not _ci_bad29, repr(_ci_bad29))

    # ...and its verdict: the step's own python, cut out of the workflow, on made-up runs.
    _ci_src29 = _wf_run_block(_ci29, _ci_root_name29) if _ci_root_name29 in _ci_names29 else ""
    _ci_py29 = _ci_src29[_ci_src29.find("<<'EOF'\n") + 8:_ci_src29.rfind("\nEOF")] if _ci_src29 else ""
    _U29 = ("PASS  a\nPASS  b\nSKIP  root gate   [skipped: needs root and a daemon account]\n"
            "SKIP  zsh thing   [skipped: no zsh on this machine]\n\n2 / 2 checks passed\n\n"
            "2 CHECK(S) DID NOT RUN:\n  SKIP  root gate   [skipped: needs root and a daemon account]\n")
    _R_OK29 = ("PASS  a\nFAIL  b   [a detail\nthat spans lines]\nPASS  r1\nPASS  r2\n"
               "SKIP  zsh thing   [skipped: no zsh on this machine]\n\n3 / 4 checks passed\n")

    def _verdict29(user, root):
        u, r = os.path.join(_TMP29, "u.txt"), os.path.join(_TMP29, "r.txt")
        with open(u, "w") as fh:
            fh.write(user)
        with open(r, "w") as fh:
            fh.write(root)
        p = _run29([_sys29.executable, "-", u, r], input=_ci_py29)
        return p.returncode, p.stdout + p.stderr

    _v = {"ok": _verdict29(_U29, _R_OK29),
          "fail": _verdict29(_U29, _R_OK29.replace("PASS  r2\n", "FAIL  r2   [boom]\n")),
          "shut": _verdict29(_U29, _R_OK29 + "SKIP  root gate   [skipped: needs root and x]\n"),
          "tally": _verdict29(_U29, _R_OK29.replace("3 / 4 checks passed", "Traceback")),
          "none": _verdict29(_U29, _U29),
          "nogate": _verdict29(_U29.replace("needs root and", "needs"), _R_OK29)}
    check("ci root step: passes when every check that ran only as root passed, a check failing as "
          "root that also ran as the runner aside (control)",
          bool(_ci_py29) and _v["ok"][0] == 0 and "ran only as root: 2" in _v["ok"][1], repr(_v["ok"]))
    check("ci root step: ...fails on a root-only check that failed, naming it",
          _v["fail"][0] != 0 and "::error::failed as root: r2" in _v["fail"][1], repr(_v["fail"]))
    check("ci root step: ...and when a check skipped for want of root still skipped as root",
          _v["shut"][0] != 0 and "still skipped as root: root gate" in _v["shut"][1], repr(_v["shut"]))
    check("ci root step: ...and when a run left no tally, or nothing ran only as root, or nothing "
          "was skipped for want of root (it judged nothing)",
          _v["tally"][0] != 0 and "left no tally" in _v["tally"][1]
          and _v["none"][0] != 0 and "judged nothing" in _v["none"][1]
          and _v["nogate"][0] != 0 and "judged nothing" in _v["nogate"][1],
          repr((_v["tally"], _v["none"], _v["nogate"])))

    # ── actionlint finds shellcheck, or fails, and proves it uses it (SC5) ────────────────────────
    # actionlint skips the run: scripts in silence when it cannot find shellcheck, and exits 0.
    # The step's script after the download, run with stand-ins for actionlint and shellcheck.
    _al29 = _wf_run_block(_wf29("actionlint.yml"), "actionlint")
    _al_tail29 = _al29[_al29.find("/tmp/actionlint -version\n") + len("/tmp/actionlint -version\n"):]
    _abin29 = os.path.join(_TMP29, "abin")
    os.makedirs(_abin29)
    _fake_al29 = os.path.join(_TMP29, "fake-actionlint")
    with open(_fake_al29, "w") as fh:
        fh.write('#!/bin/bash\n'
                 'sc=""; files=()\n'
                 'for a in "$@"; do case "$a" in -shellcheck=*) sc="${a#-shellcheck=}" ;; -*) ;; '
                 '*) files+=("$a") ;; esac; done\n'
                 '[ "${FAKE_BLIND:-}" = 1 ] && exit 0\n'
                 'if [ "${#files[@]}" -gt 0 ]; then\n'
                 '  [ -x "$sc" ] && grep -q \'echo \\$1\' "${files[@]}" '
                 '&& { echo "control.yml:6:9: shellcheck reported issue in this script: SC2086:info"; exit 1; }\n'
                 '  exit 0\n'
                 'fi\n'
                 'echo "LINTED WITH ${sc}"\n')
    os.chmod(_fake_al29, 0o755)
    for _tool in ("mktemp", "mkdir", "grep", "cat", "rm"):
        _tp = _shutil29.which(_tool)
        if _tp:
            os.symlink(_tp, os.path.join(_abin29, _tool))
    _sc29 = os.path.join(_TMP29, "scbin")
    os.makedirs(_sc29)
    with open(os.path.join(_sc29, "shellcheck"), "w") as fh:
        fh.write("#!/bin/bash\necho 'ShellCheck - stand-in'\n")
    os.chmod(os.path.join(_sc29, "shellcheck"), 0o755)

    def _al_run29(with_sc, blind=False):
        path = _abin29 + (os.pathsep + _sc29 if with_sc else "")
        env = {"PATH": path, "HOME": _TMP29, "TMPDIR": _TMP29}
        if blind:
            env["FAKE_BLIND"] = "1"
        r = _run29(["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
                    _al_tail29.replace("/tmp/actionlint", _fake_al29)], env=env)
        return r.returncode, r.stdout + r.stderr

    _a = {"ok": _al_run29(True), "nosc": _al_run29(False), "blind": _al_run29(True, blind=True)}
    check("actionlint: with shellcheck there, the control is caught and the lint runs with it named "
          "(control)",
          _a["ok"][0] == 0 and "LINTED WITH %s" % os.path.join(_sc29, "shellcheck") in _a["ok"][1],
          repr(_a["ok"]))
    check("actionlint: ...without shellcheck the step fails, not lints YAML alone",
          _a["nosc"][0] != 0 and "shellcheck is not on this runner" in _a["nosc"][1]
          and "LINTED" not in _a["nosc"][1], repr(_a["nosc"]))
    check("actionlint: ...and an actionlint that does not run shellcheck fails the control",
          _a["blind"][0] != 0 and "did not report the control" in _a["blind"][1]
          and "LINTED" not in _a["blind"][1], repr(_a["blind"]))

    # ── actionlint checks vars.* strictly, against the variables the workflows read (SC9) ─────────
    _alc29 = _read29(".github", "actionlint.yaml")
    _alc_m29 = _re29.search(r"^config-variables:\n((?:  - \S+\n)+)", _alc29, _re29.M)
    _alc_vars29 = sorted(_re29.findall(r"  - (\S+)", _alc_m29.group(1))) if _alc_m29 else []
    _used29 = sorted({v for p in _glob29.glob(os.path.join(_WF29, "*.yml"))
                      for v in _re29.findall(r"\bvars\.([A-Za-z_][A-Za-z0-9_]*)",
                                             open(p, encoding="utf-8").read())})
    check("actionlint: config-variables lists exactly the vars.* the workflows read, so a typo fails",
          "DEPLOY_ENABLED" in _used29 and _alc_vars29 == _used29, repr((_alc_vars29, _used29)))
    check("actionlint: the runner-label override's removal note names the actionlint pinned now",
          "rhysd/actionlint (VERSION in .github/workflows/actionlint.yml)" in _alc29
          and "reviewdog" not in _alc29, _alc29[:900])

    # ── the deploy job's Tailscale client is pinned by version and digest, uncached (SC6) ─────────
    # Without sha256sum the action trusts a checksum fetched from the server the tarball comes
    # from; with the cache on, a hit installs binaries with no check at all. Each pair here was
    # cross-checked by hand: version = the action's default at that SHA (its action.yml); digest =
    # pkgs.tailscale.com's tarball, verified through Tailscale's distsign chain. A new action SHA
    # fails here until that is redone and the row added.
    _TS_PINS29 = {"d1b6cd204f8dceda5b3eaad7f1f767be390056cd":
                  ("1.94.2", "c6f99a5d774c7783b56902188d69e9756fc3dddfb08ac6be4cb2585f3fecdc32")}
    _dep29 = _wf29("deploy.yml")
    _ts29 = _dep29[_dep29.find("- name: Join the tailnet"):]
    _ts29 = _ts29[:_ts29.find("\n      - name: ", 1)]
    _ts_sha29 = _re29.search(r"uses: tailscale/github-action@([0-9a-f]{40})\b", _ts29)
    _ts_v29 = _re29.search(r"^ +version: '([^']+)'$", _ts29, _re29.M)
    _ts_d29 = _re29.search(r"^ +sha256sum: '([0-9a-f]{64})'$", _ts29, _re29.M)
    _ts_c29 = _re29.search(r"^ +use-cache: '(\w+)'$", _ts29, _re29.M)
    check("deploy: the Tailscale client is pinned to a version and its sha256 for the action's SHA, "
          "and never taken from the cache",
          _ts_sha29 is not None and _ts_sha29.group(1) in _TS_PINS29
          and _ts_v29 is not None and _ts_d29 is not None
          and (_ts_v29.group(1), _ts_d29.group(1)) == _TS_PINS29[_ts_sha29.group(1)]
          and _ts_c29 is not None and _ts_c29.group(1) == "false", _ts29)

    # ── every action is pinned to a full commit SHA (SC8) ─────────────────────────────────────────
    # The convention, never enforced: CodeQL's unpinned-tag query trusts actions/* and github/*, and
    # the repository does not require SHA pins. A local action (./) and a docker:// image are not
    # commits; every other `uses:` must end in @<40 hex>. Comment lines are not read.
    _uses29, _unpinned29 = [], []
    _act_files29 = (sorted(_glob29.glob(os.path.join(_WF29, "*.y*ml")))
                    + sorted(_glob29.glob(os.path.join(_ROOT29, ".github", "actions", "**", "action.y*ml"),
                                          recursive=True)))
    for _p in _act_files29:
        for _ln_no, _ln in enumerate(open(_p, encoding="utf-8").read().splitlines(), 1):
            if _ln.lstrip().startswith("#"):
                continue
            for _m in _re29.finditer(r"(?:^|[\s{,])uses:\s*(['\"]?)([^\s'\",}#]+)\1", _ln):
                _ref = _m.group(2)
                _uses29.append(_ref)
                if _ref.startswith(("./", "docker://")):
                    continue
                if not _re29.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", _ref):
                    _unpinned29.append("%s:%d %s" % (os.path.relpath(_p, _ROOT29), _ln_no, _ref))
    check("workflows: every action is pinned to a full-length commit SHA",
          len(_uses29) >= 40 and any(u.startswith("actions/checkout@") for u in _uses29)
          and not _unpinned29, repr((len(_uses29), _unpinned29)))
    # The ClusterFuzzLite actions run images they name by tag (the Dockerfile's header says so, of
    # "that SHA"): one SHA across every workflow, so the one note covers them all.
    _cfl_shas29 = {_re29.sub(r".*@", "", u) for u in _uses29 if u.startswith("google/clusterfuzzlite/")}
    _df29 = _read29(".clusterfuzzlite", "Dockerfile")
    check("cflite: every ClusterFuzzLite action is at one SHA, and the Dockerfile says its images "
          "are pulled by tag",
          len(_cfl_shas29) == 1 and "clusterfuzzlite-build-fuzzers:v1" in _df29
          and "clusterfuzzlite-run-fuzzers:v1" in _df29 and "scorecard-action" in _df29,
          repr(_cfl_shas29))
finally:
    _shutil29.rmtree(_TMP29, ignore_errors=True)
