"""Part 29 of the unit suite: the CI configuration a vendor audit found short of its vendor's docs.

ClusterFuzzLite (its corpus, coverage and builds as Actions artifacts, and where they may come
from; the PR run's fuzzing time and the harnesses' start-up), the root-only unit checks run as
root in ci.yml, actionlint's shellcheck pass and its `vars` list, the Tailscale client the deploy
job installs, and every `uses:` pinned to a commit.

HOW IT RUNS. The workflows are read as TEXT, as part06 and part19 read them: the checks job
installs no YAML parser. Where a workflow step's script can be run, it is: cut out of the file and
run by bash or python on fixtures in a temporary directory, with stand-ins for `gh`, `actionlint`
and `shellcheck` on PATH. One check imports panel.ops.ssh_manager in a child process, the way
the fuzz harnesses do. Nothing here touches the network or the checkout's data/. Each section is
a function, called in order at the bottom.
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
_GUARD29 = "Every stored fuzz artifact was made on main here"
_CI_ROOT29 = "Run the root-only unit checks, as root"
# The workflow's own path for the actionlint binary, which the driven step is pointed away from.
_AL_PATH29 = "/tmp/actionlint"  # nosec B108 - a string in the workflow, replaced, never opened


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


def _jobs29(text):
    """The names of a workflow's jobs."""
    return _re29.findall(r"^  ([a-z][a-z-]*):\n", text[text.find("\njobs:\n"):], _re29.M)


def _steps29(job_text):
    """The job's steps, each as its text from its `- ` line, in order."""
    body = job_text[job_text.find("\n    steps:\n"):]
    return ["- " + s for s in body.split("\n      - ")[1:]]


def _name29(step):
    m = _re29.search(r"^-? *name: (.*)$", step, _re29.M)
    return m.group(1).strip() if m else ""


def _runbody29(step):
    """The `run: |` block of one step's text, dedented, trailing blank lines dropped."""
    return _wf_run_block(step, _name29(step)).rstrip() + "\n" if "run: |" in step else ""


def _code29(text):
    """A workflow's text without its comment lines."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def _run29(argv, **kw):
    kw.setdefault("timeout", 120)
    return _sp29.run(argv, capture_output=True, text=True, check=False, **kw)  # nosec B603 - fixed argvs


def _write_exe29(path, text):
    with open(path, "w") as fh:
        fh.write(text)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- a stand-in program this part runs must be executable
    os.chmod(path, 0o755)  # nosec B103 - a stand-in program this part runs; it must be executable


# ── ClusterFuzzLite, PR side: the vendor's 600s, split across the targets ─────────────────────────
# 180s over six targets was 30s each, shorter than the ssh_manager targets' start-up, and each was
# killed as "process timed out" before libFuzzer finished (CF1).
def _cf1_seconds():
    runs = [s for s in _steps29(_job29(_wf29("cflite_pr.yml"), "code-change"))
            if "clusterfuzzlite/actions/run_fuzzers@" in s]
    check("cflite_pr: the PR run fuzzes for the vendor's 600s in code-change mode",
          len(runs) == 1
          and _re29.search(r"^ +fuzz-seconds: 600$", runs[0], _re29.M) is not None
          and _re29.search(r"^ +mode: code-change$", runs[0], _re29.M) is not None,
          runs[0][-600:] if runs else "no run_fuzzers step")


# ── the four ssh_manager harnesses pre-load the heavy dependencies, uninstrumented ────────────────
# With only paramiko and eventlet pre-loaded, Atheris instrumented 280 modules per target, ~27s on
# a runner before the first input. The list is the same in all four, and must hold what
# ssh_manager pulls in.
def _harness_lists():
    found = {}
    for p in sorted(_glob29.glob(os.path.join(_ROOT29, "tests", "fuzz", "fuzz_*.py"))):
        for n in _ast29.walk(_ast29.parse(open(p, encoding="utf-8").read())):
            if (isinstance(n, _ast29.For) and isinstance(n.target, _ast29.Name)
                    and n.target.id == "_dep" and isinstance(n.iter, _ast29.Tuple)):
                found[os.path.basename(p)] = tuple(c.value for c in n.iter.elts
                                                   if isinstance(c, _ast29.Constant))
    return found


def _cf1_preload():
    found = _harness_lists()
    lists = set(found.values())
    one = next(iter(lists)) if len(lists) == 1 else ()
    check("fuzz harnesses: the four ssh_manager harnesses pre-load one list, SQLAlchemy and Flask in it",
          set(found) == {"fuzz_config.py", "fuzz_cron.py", "fuzz_firewall.py", "fuzz_game_status.py"}
          and len(lists) == 1
          and {"paramiko", "eventlet.tpool", "flask_sqlalchemy", "flask_login",
               "sqlalchemy.dialects.sqlite"} <= set(one)
          and one[-1] == "panel.core.config", repr(found))
    return one


# ...and the list is enough: importing ssh_manager after it loads nothing outside panel/ and the
# standard library, so Atheris instruments the panel's own modules and nothing else. A child
# process, because this one imported ssh_manager long ago. It also records any file it opens under
# the checkout's data/, which must be none.
_IMPORT_PROBE29 = """import importlib, json, os, sys
data = os.path.join(%r, 'data') + os.sep
opened = []
def _hook(ev, args):
    if ev == 'open' and args and isinstance(args[0], (str, bytes, os.PathLike)):
        p = os.path.abspath(os.fsdecode(args[0]))
        if p.startswith(data):
            opened.append(p)
sys.addaudithook(_hook)
for d in %r:
    importlib.import_module(d)
before = set(sys.modules)
from panel.ops import ssh_manager
print(json.dumps({'new': sorted(set(sys.modules) - before), 'opened': opened}))
"""


def _foreign_module29(name):
    """Neither the panel's nor the standard library's.

    eventlet's patcher keeps the unpatched stdlib modules under __original_module_<name>.
    """
    top = name.split(".")[0]
    return top != "panel" and top not in _sys29.stdlib_module_names \
        and not name.startswith("__original_module_")


def _cf1_imports(preload, tmp):
    r = _run29([_sys29.executable, "-W", "ignore", "-c", _IMPORT_PROBE29 % (_ROOT29, preload)],
               cwd=tmp, env=dict(os.environ, PYTHONPATH=_ROOT29))
    try:
        out = _json29.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        out = {"new": [], "opened": [], "error": r.stdout[-400:] + r.stderr[-800:]}
    panel = [m for m in out["new"] if m.split(".")[0] == "panel"]
    other = [m for m in out["new"] if _foreign_module29(m)]
    check("fuzz harnesses: after the pre-load, importing ssh_manager loads only panel modules and "
          "the standard library (what Atheris instruments)",
          all([len(panel) >= 10, "panel.ops.ssh_manager.cron" in panel, not other, not out["opened"]]),
          repr({"outside panel and stdlib": other, "panel": len(panel),
                "opened under data/": out["opened"], "error": out.get("error")}))


# ── ClusterFuzzLite keeps everything as Actions artifacts, and nothing waits on a secret ──────────
# Every batch, prune and coverage step waited on a CFL_STORAGE_REPO secret that was never set: those
# jobs reported success for two months having fuzzed nothing (CF2). The storage repo is optional;
# the artifacts route needs no secret, and is the one taken, end to end.
def _cflite_files():
    return {os.path.basename(p): open(p, encoding="utf-8").read()
            for p in sorted(_glob29.glob(os.path.join(_WF29, "cflite_*.yml")))}


def _cf2_no_secret(cfl):
    bad = ["%s: %s" % (n, w) for n, t in cfl.items()
           for w in ("CFL_STORAGE_REPO", "storage-repo") if w in _code29(t)]
    bad += ["%s: a step-level if: reads env or secrets" % n for n, t in cfl.items()
            if _re29.search(r"^ {8}if: .*\b(env|secrets)\.", t, _re29.M)]
    check("cflite: no workflow names a storage repository or gates a step on a secret",
          set(cfl) >= {"cflite_pr.yml", "cflite_batch.yml", "cflite_cron.yml", "cflite_build.yml"}
          and not bad, repr(bad))


def _producer_bad(name, text, job):
    """What is wrong with one artifact-making job: it must run only on this repository's main."""
    # Comment lines dropped: a `# zizmor: ignore[...]` line sits in the `on:` block it is about.
    on = _code29(text[text.find("\non:\n"):text.find("\npermissions:")])
    jt = _job29(text, job)
    m = _re29.search(r"^    if: (.*)$", jt, _re29.M)
    cond = m.group(1) if m else ""
    bad = ["%s: runs for pull requests" % name] if "pull_request" in on else []
    main_only = ("github.ref == 'refs/heads/main'" in cond
                 or on.strip() == "on:\n  push:\n    branches: [ main ]")
    if "github.repository == 'FMSMITH91/linuxgsm-panel'" not in cond or not main_only:
        bad.append("%s/%s: job if: %r" % (name, job, cond))
    if name != "cflite_build.yml" and not _re29.search(r"^      actions: read\b", jt, _re29.M):
        bad.append("%s/%s: no actions: read" % (name, job))
    return bad


# The jobs that make the artifacts run on this repository's main only: the provenance check below
# refuses any cifuzz-* artifact made anywhere else, so a producer elsewhere would stop every
# reader. And each job that reads them may (actions: read, the vendor's read-all).
def _cf2_producers(cfl):
    bad = []
    for name, jobs in (("cflite_batch.yml", ("batch",)), ("cflite_cron.yml", ("prune", "coverage")),
                       ("cflite_build.yml", ("build",))):
        for job in jobs:
            bad += _producer_bad(name, cfl.get(name, ""), job)
    if not _re29.search(r"^      actions: read\b", _job29(cfl.get("cflite_pr.yml", ""), "code-change"),
                        _re29.M):
        bad.append("cflite_pr.yml: no actions: read")
    bld = [s for s in _steps29(_job29(cfl.get("cflite_build.yml", ""), "build"))
           if "clusterfuzzlite/actions/" in s]
    if not (len(bld) == 1 and "clusterfuzzlite/actions/build_fuzzers@" in bld[0]
            and _re29.search(r"^ +upload-build: true$", bld[0], _re29.M)):
        bad.append("cflite_build.yml: not one ClusterFuzzLite step, a build_fuzzers with "
                   "upload-build: true")
    check("cflite: batch, prune, coverage and the continuous build run only on this repository's "
          "main; every reader may read artifacts; the build uploads itself", not bad, repr(bad))


# ── every cifuzz-* artifact a job reads was made on main here ─────────────────────────────────────
# The action takes the newest artifact of a name from ANY run in the repository and unpacks it
# unchecked; a fork's pull request can upload one. So in every job, a guard step comes before any
# step that can read one (run_fuzzers; build_fuzzers given a token), and the copies are one.
def _reads_artifacts29(step):
    """run_fuzzers reads the corpus (and a build); build_fuzzers given a token reads coverage."""
    if "clusterfuzzlite/actions/run_fuzzers@" in step:
        return True
    return "clusterfuzzlite/actions/build_fuzzers@" in step and "github-token:" in step


def _guards_in_job(steps):
    """(index of the first reader or None, guard indexes, guard bodies, trouble) for one job."""
    readers = [i for i, s in enumerate(steps) if _reads_artifacts29(s)]
    guards = [i for i, s in enumerate(steps) if _name29(s).startswith(_GUARD29)]
    trouble = [i for i in guards if "continue-on-error" in steps[i]]
    return (readers[0] if readers else None), guards, {_runbody29(steps[i]) for i in guards}, trouble


def _pr_guard_after29(cfl):
    """The PR job's last step is the guard again, run even when fuzzing failed."""
    pr_steps = _steps29(_job29(cfl.get("cflite_pr.yml", ""), "code-change"))
    last = pr_steps[-1] if pr_steps else ""
    if _name29(last).startswith(_GUARD29) \
            and "if: always() && steps.scope.outputs.run == 'true'" in last:
        return []
    return ["cflite_pr.yml: the guard does not run again, always, after fuzzing"]


def _cf2_guard_placement(cfl):
    bodies, bad, jobs = set(), [], 0
    for name, text in cfl.items():
        for job in _jobs29(text):
            first, guards, found, trouble = _guards_in_job(_steps29(_job29(text, job)))
            if first is None:
                continue
            jobs += 1
            bodies |= found
            if not guards or guards[0] > first:
                bad.append("%s/%s: no guard before step %d" % (name, job, first))
            if trouble:
                bad.append("%s/%s: the guard may fail without failing the job" % (name, job))
    bad += _pr_guard_after29(cfl)
    check("cflite: every job that reads a stored fuzz artifact checks first where all of them came "
          "from (and the PR job again after fuzzing), with one copy of the check",
          all([jobs >= 4, len(bodies) == 1, not bad]), repr((jobs, len(bodies), bad)))


# ...and the check works: run, as the step runs it, against a stand-in `gh` that applies the step's
# own --jq filter (with jq) to pages of artifacts.
_FAKE_GH29 = """#!/bin/bash
[ "$1" = api ] || exit 9
[ "$2" = "repos/o/r/actions/artifacts?per_page=100" ] || { echo "path $2" >&2; exit 7; }
f=""; p=0; a=("$@")
for ((i = 0; i < ${#a[@]}; i++)); do
  case "${a[i]}" in --jq) f="${a[i+1]}" ;; --paginate) p=1 ;; esac
done
[ -z "${GH_FAKE_FAIL:-}" ] || { echo "HTTP 502" >&2; exit 1; }
[ "$p" = 1 ] || { echo "not paginated" >&2; exit 8; }
exec jq -r "$f" "$GH_FAKE_PAGES"
"""


def _art29(name, aid, branch="main", head=5, expired=False, run=True):
    return {"name": name, "id": aid, "expired": expired,
            "workflow_run": ({"id": aid * 10, "head_branch": branch, "head_repository_id": head,
                              "repository_id": 5} if run else None)}


def _guard_run29(script, tmp, extra, fail=False):
    pages = os.path.join(tmp, "pages.json")
    first = [_art29("cifuzz-corpus-fuzz_cron", 1), _art29("coverage", 2, "topic", 9),
             _art29("cifuzz-build-address-abc", 3, "evil", 9, expired=True)]
    with open(pages, "w") as fh:
        fh.write(_json29.dumps({"total_count": 9, "artifacts": first}) + "\n"
                 + _json29.dumps({"total_count": 9, "artifacts": [_art29("cifuzz-coverage-latest", 4)]
                                  + extra}) + "\n")
    env = dict(os.environ, PATH=os.path.join(tmp, "gbin") + os.pathsep + os.environ.get("PATH", ""),
               REPO="o/r", GH_FAKE_PAGES=pages)
    env["GH_TOKEN"] = "stand-in"  # nosec B105 - the stand-in gh reads no token
    if fail:
        env["GH_FAKE_FAIL"] = "1"
    r = _run29(["bash", "--noprofile", "--norc", "-e", "-c", script], env=env)
    return r.returncode, r.stdout + r.stderr


def _cf2_guard_driven(cfl, tmp):
    if _shutil29.which("jq") is None:
        _skip29("cflite: the artifact check, driven", "no jq on this machine")
        return
    os.makedirs(os.path.join(tmp, "gbin"))
    _write_exe29(os.path.join(tmp, "gbin", "gh"), _FAKE_GH29)
    script = _wf_run_block(cfl["cflite_batch.yml"], _GUARD29)
    g = {"main": _guard_run29(script, tmp, []),
         "fork": _guard_run29(script, tmp, [_art29("cifuzz-corpus-fuzz_x", 7, "main", 9)]),
         "branch": _guard_run29(script, tmp, [_art29("cifuzz-coverage-latest", 8, "topic")]),
         "no run": _guard_run29(script, tmp, [_art29("cifuzz-build-address-def", 6, run=False)]),
         "api": _guard_run29(script, tmp, [], fail=True)}
    check("cflite: the artifact check passes main's own (expired and non-cifuzz ones from "
          "elsewhere ignored), and says how many it read (control)",
          g["main"][0] == 0 and "stored cifuzz-* artifacts: 2" in g["main"][1], repr(g["main"]))
    check("cflite: ...and fails on one from a fork, even on a branch the fork calls main",
          g["fork"][0] != 0 and "cifuzz-corpus-fuzz_x\t7\t70\tmain\t9\t5" in g["fork"][1]
          and "::error::" in g["fork"][1], repr(g["fork"]))
    check("cflite: ...and on one from another branch here, or with no run recorded",
          g["branch"][0] != 0 and "cifuzz-coverage-latest\t8" in g["branch"][1]
          and g["no run"][0] != 0 and "cifuzz-build-address-def\t6" in g["no run"][1],
          repr((g["branch"], g["no run"])))
    check("cflite: ...and when the artifacts cannot be listed", g["api"][0] != 0, repr(g["api"]))


# ── the root-only unit checks run, as root, in every checks leg (CI1) ─────────────────────────────
# They skipped in every CI leg, and a skip does not fail the unit suite. The step runs the suite
# again as root after run-tests.sh has kept the runner's run in UNIT_LOG, and judges the checks
# that ran only as root.
def _ci1_root_step_bad(steps):
    names = [_name29(s) for s in steps]
    rt = next((i for i, n in enumerate(names) if n.startswith("Run all checks")), None)
    if any([_CI_ROOT29 not in names, rt is None]) or names.index(_CI_ROOT29) < rt:
        return ["no root step after the run-tests step: %r" % names]
    bad, rs = [], steps[names.index(_CI_ROOT29)]
    if 'UNIT_LOG="${RUNNER_TEMP}/unit-user.txt" bash tools/run-tests.sh' not in steps[rt]:
        bad.append("run-tests.sh is not given UNIT_LOG")
    wants = ("sudo -E env PATH=\"$PATH\" bash -c 'unset \"${!SUDO_@}\"; exec python tests/unit_test.py'",
             '"${RUNNER_TEMP}/unit-user.txt" "${root_log}"')
    if not all(w in rs for w in wants):
        bad.append("the root step does not run the suite as root, SUDO_* unset, and compare it "
                   "with UNIT_LOG")
    # One `if:` is allowed, and only this one, on both steps: a documentation-only pull request
    # skips them together (.github/scripts/pr_scope.py fails open, so anything else runs them).
    _docs_if = ["steps.scope.outputs.docs_only != 'true'"]
    if (_re29.search(r"^ {8}continue-on-error:", rs, _re29.M)
            or _re29.findall(r"^ {8}if: (.*)$", rs, _re29.M) != _docs_if
            or _re29.findall(r"^ {8}if: (.*)$", steps[rt], _re29.M) != _docs_if):
        bad.append("the root step can be skipped or fail without failing the job")
    return bad


def _ci1_wiring():
    bad = _ci1_root_step_bad(_steps29(_job29(_wf29("ci.yml"), "checks")))
    rt = _read29("tools", "run-tests.sh")
    if ('"$PY" tests/unit_test.py | tee "${UNIT_LOG}"' not in rt
            or "set -euo pipefail" not in rt.splitlines()[:12]):
        bad.append("run-tests.sh does not tee the unit run to UNIT_LOG under pipefail")
    check("ci: every checks leg runs the unit suite again as root, against the runner's own run",
          not bad, repr(bad))


# ...and its verdict: the step's own python, cut out of the workflow, on made-up runs.
_U29 = ("PASS  a\nPASS  b\nSKIP  root gate   [skipped: needs root and a daemon account]\n"
        "SKIP  zsh thing   [skipped: no zsh on this machine]\n\n2 / 2 checks passed\n\n"
        "2 CHECK(S) DID NOT RUN:\n  SKIP  root gate   [skipped: needs root and a daemon account]\n")
_R_OK29 = ("PASS  a\nFAIL  b   [a detail\nthat spans lines]\nPASS  r1\nPASS  r2\n"
           "SKIP  zsh thing   [skipped: no zsh on this machine]\n\n3 / 4 checks passed\n")


def _verdict29(code, tmp, user, root):
    u, r = os.path.join(tmp, "u.txt"), os.path.join(tmp, "r.txt")
    with open(u, "w") as fh:
        fh.write(user)
    with open(r, "w") as fh:
        fh.write(root)
    p = _run29([_sys29.executable, "-", u, r], input=code)
    return p.returncode, p.stdout + p.stderr


def _ci1_verdict(tmp):
    ci = _wf29("ci.yml")
    src = _wf_run_block(ci, _CI_ROOT29) if _CI_ROOT29 in ci else "<<'EOF'\n\nEOF"
    code = src[src.find("<<'EOF'\n") + 8:src.rfind("\nEOF")]
    v = {"ok": _verdict29(code, tmp, _U29, _R_OK29),
         "fail": _verdict29(code, tmp, _U29, _R_OK29.replace("PASS  r2\n", "FAIL  r2   [boom]\n")),
         "shut": _verdict29(code, tmp, _U29, _R_OK29 + "SKIP  root gate   [skipped: needs root and x]\n"),
         "tally": _verdict29(code, tmp, _U29, _R_OK29.replace("3 / 4 checks passed", "Traceback")),
         "none": _verdict29(code, tmp, _U29, _U29),
         "nogate": _verdict29(code, tmp, _U29.replace("needs root and", "needs"), _R_OK29)}
    check("ci root step: passes when every check that ran only as root passed, a check failing as "
          "root that also ran as the runner aside (control)",
          all([code, v["ok"][0] == 0, "ran only as root: 2" in v["ok"][1]]), repr(v["ok"]))
    check("ci root step: ...fails on a root-only check that failed, naming it",
          all([v["fail"][0], "::error::failed as root: r2" in v["fail"][1]]), repr(v["fail"]))
    check("ci root step: ...and when a check skipped for want of root still skipped as root",
          all([v["shut"][0], "still skipped as root: root gate" in v["shut"][1]]), repr(v["shut"]))
    check("ci root step: ...and when a run left no tally, or nothing ran only as root, or nothing "
          "was skipped for want of root (it judged nothing)",
          all([v["tally"][0], "left no tally" in v["tally"][1],
               v["none"][0], "judged nothing" in v["none"][1],
               v["nogate"][0], "judged nothing" in v["nogate"][1]]),
          repr((v["tally"], v["none"], v["nogate"])))


# ── actionlint finds shellcheck, or fails, and proves it uses it (SC5) ────────────────────────────
# actionlint skips the run: scripts in silence when it cannot find shellcheck, and exits 0. The
# step's script after the download, run with stand-ins for actionlint and shellcheck.
_FAKE_AL29 = """#!/bin/bash
sc=""; files=()
for a in "$@"; do case "$a" in -shellcheck=*) sc="${a#-shellcheck=}" ;; -*) ;; *) files+=("$a") ;; esac; done
[ "${FAKE_BLIND:-}" = 1 ] && exit 0
if [ "${#files[@]}" -gt 0 ]; then
  [ -x "$sc" ] && grep -q 'echo \\$1' "${files[@]}" \\
    && { echo "control.yml:6:9: shellcheck reported issue in this script: SC2086:info"; exit 1; }
  exit 0
fi
echo "LINTED WITH ${sc}"
"""


def _al_setup29(tmp):
    abin, scbin = os.path.join(tmp, "abin"), os.path.join(tmp, "scbin")
    os.makedirs(abin)
    os.makedirs(scbin)
    _write_exe29(os.path.join(tmp, "fake-actionlint"), _FAKE_AL29)
    _write_exe29(os.path.join(scbin, "shellcheck"), "#!/bin/bash\necho 'ShellCheck - stand-in'\n")
    for tool in ("mktemp", "mkdir", "grep", "cat", "rm"):
        if _shutil29.which(tool):
            os.symlink(_shutil29.which(tool), os.path.join(abin, tool))
    return abin, scbin


def _al_run29(tail, tmp, path, blind=False):
    env = {"PATH": path, "HOME": tmp, "TMPDIR": tmp}
    if blind:
        env["FAKE_BLIND"] = "1"
    r = _run29(["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
                tail.replace(_AL_PATH29, os.path.join(tmp, "fake-actionlint"))], env=env)
    return r.returncode, r.stdout + r.stderr


def _sc5_shellcheck(tmp):
    step = _wf_run_block(_wf29("actionlint.yml"), "actionlint")
    cut = _AL_PATH29 + " -version\n"
    tail = step[step.find(cut) + len(cut):]
    abin, scbin = _al_setup29(tmp)
    a = {"ok": _al_run29(tail, tmp, abin + os.pathsep + scbin),
         "nosc": _al_run29(tail, tmp, abin),
         "blind": _al_run29(tail, tmp, abin + os.pathsep + scbin, blind=True)}
    check("actionlint: with shellcheck there, the control is caught and the lint runs with it named "
          "(control)",
          a["ok"][0] == 0 and "LINTED WITH %s" % os.path.join(scbin, "shellcheck") in a["ok"][1],
          repr(a["ok"]))
    check("actionlint: ...without shellcheck the step fails, not lints YAML alone",
          a["nosc"][0] != 0 and "shellcheck is not on this runner" in a["nosc"][1]
          and "LINTED" not in a["nosc"][1], repr(a["nosc"]))
    check("actionlint: ...and an actionlint that does not run shellcheck fails the control",
          a["blind"][0] != 0 and "did not report the control" in a["blind"][1]
          and "LINTED" not in a["blind"][1], repr(a["blind"]))


# ── actionlint checks vars.* strictly, against the variables the workflows read (SC9) ─────────────
def _sc9_vars():
    conf = _read29(".github", "actionlint.yaml")
    m = _re29.search(r"^config-variables:\n((?:  - \S+\n)+)", conf, _re29.M)
    listed = sorted(_re29.findall(r"  - (\S+)", m.group(1))) if m else []
    used = sorted({v for p in _glob29.glob(os.path.join(_WF29, "*.yml"))
                   for v in _re29.findall(r"\bvars\.([A-Za-z_][A-Za-z0-9_]*)",
                                          open(p, encoding="utf-8").read())})
    check("actionlint: config-variables lists exactly the vars.* the workflows read, so a typo fails",
          "DEPLOY_ENABLED" in used and listed == used, repr((listed, used)))
    check("actionlint: the runner-label override's removal note names the actionlint pinned now",
          "rhysd/actionlint (VERSION in .github/workflows/actionlint.yml)" in conf
          and "reviewdog" not in conf, conf[:900])


# ── the deploy job's Tailscale client is pinned by version and digest, uncached (SC6) ─────────────
# Without sha256sum the action trusts a checksum fetched from the server the tarball comes from;
# with the cache on, a hit installs binaries with no check at all. Each pair here was cross-checked
# by hand: version = the action's default at that SHA (its action.yml); digest = pkgs.tailscale.com's
# tarball, verified through Tailscale's distsign chain. A new action SHA fails here until that is
# redone and the row added.
_TS_PINS29 = {"d1b6cd204f8dceda5b3eaad7f1f767be390056cd":
              ("1.94.2", "c6f99a5d774c7783b56902188d69e9756fc3dddfb08ac6be4cb2585f3fecdc32")}


def _sc6_tailscale():
    dep = _wf29("deploy.yml")
    ts = dep[dep.find("- name: Join the tailnet"):]
    ts = ts[:ts.find("\n      - name: ", 1)]
    sha = _re29.search(r"uses: tailscale/github-action@([0-9a-f]{40})\b", ts)
    ver = _re29.search(r"^ +version: '([^']+)'$", ts, _re29.M)
    dig = _re29.search(r"^ +sha256sum: '([0-9a-f]{64})'$", ts, _re29.M)
    cache = _re29.search(r"^ +use-cache: '(\w+)'$", ts, _re29.M)
    check("deploy: the Tailscale client is pinned to a version and its sha256 for the action's SHA, "
          "and never taken from the cache",
          sha is not None and sha.group(1) in _TS_PINS29 and ver is not None and dig is not None
          and (ver.group(1), dig.group(1)) == _TS_PINS29[sha.group(1)]
          and cache is not None and cache.group(1) == "false", ts)


# ── every action is pinned to a full commit SHA (SC8) ─────────────────────────────────────────────
# The convention, never enforced: CodeQL's unpinned-tag query trusts actions/* and github/*, and the
# repository does not require SHA pins. A local action (./) and a docker:// image are not commits;
# every other `uses:` must end in @<40 hex>. Comment lines are not read.
def _all_uses29():
    files = (sorted(_glob29.glob(os.path.join(_WF29, "*.y*ml")))
             + sorted(_glob29.glob(os.path.join(_ROOT29, ".github", "actions", "**", "action.y*ml"),
                                   recursive=True)))
    uses = []
    for p in files:
        for ln in _code29(open(p, encoding="utf-8").read()).splitlines():
            uses += [(os.path.relpath(p, _ROOT29), m.group(2)) for m in
                     _re29.finditer(r"(?:^|[\s{,])uses:\s*(['\"]?)([^\s'\",}#]+)\1", ln)]
    return uses


def _pinned29(ref):
    """A local action and a docker:// image are not commits; anything else ends in @<40 hex>."""
    if ref.startswith(("./", "docker://")):
        return True
    return _re29.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref) is not None


_TAGGED29 = ("clusterfuzzlite-build-fuzzers:v1", "clusterfuzzlite-run-fuzzers:v1", "scorecard-action")


def _sc8_pins():
    uses = _all_uses29()
    unpinned = ["%s %s" % u for u in uses if not _pinned29(u[1])]
    check("workflows: every action is pinned to a full-length commit SHA",
          all([len(uses) >= 40, any(u.startswith("actions/checkout@") for _, u in uses), not unpinned]),
          repr((len(uses), unpinned)))
    # The ClusterFuzzLite actions run images they name by tag (the Dockerfile's header says so, of
    # "that SHA"): one SHA across every workflow, so the one note covers them all.
    shas = {_re29.sub(r".*@", "", u) for _, u in uses if u.startswith("google/clusterfuzzlite/")}
    df = _read29(".clusterfuzzlite", "Dockerfile")
    check("cflite: every ClusterFuzzLite action is at one SHA, and the Dockerfile says its images "
          "are pulled by tag",
          all([len(shas) == 1] + [w in df for w in _TAGGED29]), repr(shas))


_TMP29 = _tf29.mkdtemp(prefix="lgsm-unit-p29-")
try:
    _cf1_seconds()
    _cf1_imports(_cf1_preload(), _TMP29)
    _CFL29 = _cflite_files()
    _cf2_no_secret(_CFL29)
    _cf2_producers(_CFL29)
    _cf2_guard_placement(_CFL29)
    _cf2_guard_driven(_CFL29, _TMP29)
    _ci1_wiring()
    _ci1_verdict(_TMP29)
    _sc5_shellcheck(_TMP29)
    _sc9_vars()
    _sc6_tailscale()
    _sc8_pins()
finally:
    _shutil29.rmtree(_TMP29, ignore_errors=True)
