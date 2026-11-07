"""Part 153 of the unit suite: a push to main reuses the merged pull request's pass on the same tree.

After a pull request merged, main's push ran every CI job again on a commit whose files were the
very files the pull request had just passed on. The jobs still have to report on main (installed
panels offer a commit only when it carries passing checks with these names, system_ops._CI_REQUIRED,
and deploy.yml waits for the same), so each job runs .github/scripts/reuse_pr_result.py after its
scope step and skips its steps when the pull request provably passed this very job on this tree.

Held here:
* the script, run as the jobs run it: REUSE only when every condition holds (one merged pull request
  into main, merged as the pushed commit; main protected against force pushes; the same tree, with
  the head containing the pushed commit's parent, proved by real git on a fixture repository; a
  check run of the same name, from the Actions app, from a pull_request run of the same workflow,
  every one passed and its work steps ran). FULL when any one fails, on any API error, on a partial
  page, and on input that is not a push to main.
* the wiring: in each job that reuses, the step follows the scope step, names the job's own name,
  workflow file and work steps, and every later step is skipped on REUSE except the ones that must
  run (the coverage jobs take the pull request run's report and upload it as their own).
* what keeps running on main in full: CodeQL, the code-scanning uploaders and Gitleaks.

HOW IT RUNS. The script runs in a subprocess, in a fixture repository built here with git, with a
stand-in `gh` first on PATH that answers from a table; nothing touches the network.
"""
import importlib.util as _ilu153
import json as _json153
import os
import re as _re153
import shutil as _shutil153
import subprocess as _sp153  # nosec B404 - git and this repository's own script, fixed argv
import sys
import tempfile as _tf153

from unit.part01 import check
from unit.part05 import _root
from unit.part29 import _code29, _job29, _name29, _steps29, _wf29
from panel.ops import system_ops as _so153

_RPR153 = os.path.join(_root, ".github", "scripts", "reuse_pr_result.py")
_ENV153 = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
               GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
               GIT_TERMINAL_PROMPT="0")
_REUSE153 = "steps.reuse.outputs.reuse != 'true'"
_RUN153 = "steps.scope.outputs.docs_only != 'true'"


def _git153(cwd, *args):
    # nosec B603 B607 - git, a fixed argv, on this part's fixture repositories
    r = _sp153.run(["git", "-C", cwd, *args], capture_output=True, text=True,  # nosec B603 B607
                   env=_ENV153, timeout=60, check=False)
    return r.stdout.strip()


def _commit153(repo, files, *parents, msg="c"):
    """A commit of `files` (name -> text; None removes) on top of the index; returns its id."""
    for name, body in files.items():
        p = os.path.join(repo, name)
        if body is None:
            os.remove(p)
        else:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(body)
    _git153(repo, "add", "-A")
    tree = _git153(repo, "write-tree")
    return _git153(repo, "commit-tree", tree, *[a for p in parents for a in ("-p", p)], "-m", msg)


# ── the fixture: main B -> P -> S (S squashes the pull request's head H onto P) ─────────────────
_SB153 = _tf153.mkdtemp(prefix="p153-")
try:
    _up = os.path.join(_SB153, "up")
    os.makedirs(_up)
    _git153(_up, "init", "-q", "-b", "main")
    _git153(_up, "config", "uploadpack.allowAnySHA1InWant", "true")   # GitHub serves a commit by id
    _B = _commit153(_up, {"a.txt": "1\n"})
    _P = _commit153(_up, {"b.txt": "main\n"}, _B)                    # main moved on after the branch
    _git153(_up, "read-tree", "--reset", "-u", _B)
    _Hb = _commit153(_up, {"c.txt": "pr\n"}, _B)
    _git153(_up, "read-tree", "--reset", "-u", _P)
    _H = _commit153(_up, {"c.txt": "pr\n"}, _Hb, _P)                  # main merged into the branch
    _S = _git153(_up, "commit-tree", _H + "^{tree}", "-p", _P, "-m", "squash")
    # Same tree as S, but a head that never took in P: b.txt typed in by hand.
    _git153(_up, "read-tree", "--reset", "-u", _Hb)
    _H2 = _commit153(_up, {"b.txt": "main\n"}, _Hb)
    # Contains P, a different tree (a commit pushed to the branch after the merge's tree was taken).
    _git153(_up, "read-tree", "--reset", "-u", _H)
    _H3 = _commit153(_up, {"d.txt": "late\n"}, _H)
    for _ref, _c in (("main", _S), ("pr", _H), ("pr2", _H2), ("pr3", _H3)):
        _git153(_up, "update-ref", "refs/heads/" + _ref, _c)
    _TREE = _git153(_up, "rev-parse", _S + "^{tree}")
    _git153(_up, "symbolic-ref", "HEAD", "refs/heads/pr")   # a checkout of another commit
    # The job's checkout: main at S, depth 1, as actions/checkout leaves it; the heads are not in it.
    # A second one, for the check that a FULL answer from GitHub leaves the checkout untouched.
    _work, _work2 = os.path.join(_SB153, "work"), os.path.join(_SB153, "work2")
    for _w in (_work, _work2):
        _sp153.run(["git", "clone", "-q", "--depth", "1", "--no-local", "--branch", "main",  # nosec B603 B607
                    "file://" + _up, _w], env=_ENV153, capture_output=True, timeout=60, check=False)
    _fixture_ok = (_git153(_work, "rev-parse", "HEAD") == _S == _git153(_work2, "rev-parse", "HEAD")
                   and len({_S, _H, _H2, _H3, _P}) == 5
                   and _git153(_up, "rev-parse", _H2 + "^{tree}") == _TREE
                   and _git153(_work, "cat-file", "-t", _H) == "")
    check("reuse script: (fixture) a shallow checkout of the squash commit, whose tree is the pull "
          "request head's, and the heads not yet fetched", _fixture_ok)

    _bin = os.path.join(_SB153, "bin")
    os.makedirs(_bin)
    with os.fdopen(os.open(os.path.join(_bin, "gh"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700),
                   "w") as _fh:
        # Answers `gh api -- <path>` from the table in $RPR_FIX: the first [regex, answer] whose
        # regex matches the path; an answer of null fails as gh does; no row is a failure too.
        _fh.write("#!%s\nimport json, os, re, sys\n"
                  "path = sys.argv[-1]\n"
                  "open(os.environ['RPR_LOG'], 'a').write(path + '\\n')\n"
                  "for rx, ans in json.load(open(os.environ['RPR_FIX'])):\n"
                  "    if re.fullmatch(rx, path):\n"
                  "        if ans is None:\n"
                  "            sys.stderr.write('HTTP 502\\n'); sys.exit(1)\n"
                  "        sys.stdout.write(ans if isinstance(ans, str) else json.dumps(ans)); sys.exit(0)\n"
                  "sys.stderr.write('HTTP 404: ' + path + '\\n'); sys.exit(1)\n" % sys.executable)

    def _routes(head=_H, **over):
        """The stand-in's table for a pull request #7 with head `head`, one key per endpoint."""
        q = _re153.escape
        check_row = {"id": 3000, "name": "coverage", "head_sha": head, "status": "completed",
                     "conclusion": "success", "completed_at": "2026-11-07T12:00:00Z",
                     "app": {"id": 15368}, "check_suite": {"id": 900}}
        r = {
            "pulls": [q("repos/o/r/commits/%s/pulls?per_page=100" % _S), [{"number": 7}]],
            "pull": [q("repos/o/r/pulls/7"), {
                "number": 7, "merged": True, "state": "closed", "merge_commit_sha": _S,
                "base": {"ref": "main", "repo": {"full_name": "o/r"}}, "head": {"sha": head}}],
            "rules": [q("repos/o/r/rules/branches/main?per_page=100"),
                      [{"type": "deletion"}, {"type": "non_fast_forward"}]],
            "runs": [q("repos/o/r/actions/runs?head_sha=%s&event=pull_request&per_page=100" % head), {
                "total_count": 2, "workflow_runs": [
                    {"id": 500, "check_suite_id": 900, "path": ".github/workflows/ci.yml",
                     "event": "pull_request", "head_sha": head},
                    {"id": 501, "check_suite_id": 901, "path": ".github/workflows/codeql.yml",
                     "event": "pull_request", "head_sha": head}]}],
            "checks": [q("repos/o/r/commits/%s/check-runs?check_name=coverage&filter=all&app_id=15368"
                         "&per_page=100" % head), {"total_count": 1, "check_runs": [check_row]}],
            "job": [q("repos/o/r/actions/jobs/3000"), {
                "id": 3000, "run_id": 500, "head_sha": head, "name": "coverage",
                "check_run_url": "https://api.github.com/repos/o/r/check-runs/3000",
                "steps": [{"name": "Set up job", "conclusion": "success"},
                          {"name": "Measure", "conclusion": "success"}]}],
        }
        for k, v in over.items():
            r[k][1] = v
        return list(r.values())

    def _rpr(routes, sha=_S, event="push", ref="refs/heads/main", cwd=_work, steps=("Measure",)):
        """Run the script; return (exit status, output lines, stdout, the paths gh was asked)."""
        _d = _tf153.mkdtemp(dir=_SB153)
        out, log, fix = (os.path.join(_d, n) for n in ("out", "log", "fix"))
        with open(fix, "w", encoding="utf-8") as fh:
            _json153.dump(routes, fh)
        env = dict(_ENV153, PATH=_bin + os.pathsep + os.environ.get("PATH", ""),
                   GITHUB_OUTPUT=out, RPR_LOG=log, RPR_FIX=fix)
        argv = [sys.executable, _RPR153, "--event", event, "--ref", ref, "--repo", "o/r", "--sha", sha,
                "--workflow", ".github/workflows/ci.yml", "--check-name", "coverage"]
        for s in steps:
            argv += ["--work-step", s]
        p = _sp153.run(argv, cwd=cwd, capture_output=True, text=True, timeout=120, env=env,  # nosec B603 - fixed argv
                       check=False)

        def _read(f):
            return open(f, encoding="utf-8").read() if os.path.exists(f) else ""
        return p.returncode, _read(out).splitlines(), p.stdout + p.stderr, _read(log)

    def _full(r, why=""):
        """Whether a run answered FULL (exit 0, reuse=false, nothing else), saying `why`."""
        return r[0] == 0 and r[1] == ["reuse=false"] and "everything runs" in r[2] and why in r[2]

    _ok = _rpr(_routes())
    check("reuse script: REUSE when every condition holds, said as a notice naming the pull request "
          "and the tree, with the pull request run's id for the coverage jobs (positive control)",
          _ok[0] == 0 and _ok[1] == ["reuse=true", "pr=7", "run_id=500"]
          and "::notice::REUSE: verified on PR #7 (same tree %s)" % _TREE in _ok[2]
          and _git153(_work, "rev-parse", "HEAD") == _S, repr(_ok[1:3]))

    # ── the git proof ──────────────────────────────────────────────────────────────────────────
    _g = {"tree": _rpr(_routes(head=_H3)), "ancestry": _rpr(_routes(head=_H2)),
          "fetch": _rpr(_routes(head="e" * 40)), "checkout": _rpr(_routes(), cwd=_up)}
    check("reuse script: FULL when the pull request head's tree is not the pushed tree",
          _full(_g["tree"], "is not the pull request head's"), repr(_g["tree"][2]))
    check("reuse script: FULL when the head has the same tree but does not contain main's previous "
          "commit (the pull request's run may have tested another tree)",
          _full(_g["ancestry"], "does not contain"), repr(_g["ancestry"][2]))
    check("reuse script: FULL when the head cannot be fetched",
          _full(_g["fetch"], "git fetch failed"), repr(_g["fetch"][2]))
    check("reuse script: FULL when the checkout is not the pushed commit",
          _full(_g["checkout"], "not the pushed commit"), repr(_g["checkout"][2]))

    # ── the pull request ──────────────────────────────────────────────────────────────────────
    def _pr_with(**kw):
        pr = dict(_routes()[1][1])
        pr.update(kw)
        return _rpr(_routes(pull=pr))

    _pr_cases = {
        "not merged": (_pr_with(merged=False), "is not merged"),
        "merged flag a string": (_pr_with(merged="true"), "is not merged"),
        "still open": (_pr_with(state="open"), "is not closed"),
        "into another branch": (_pr_with(base={"ref": "dev", "repo": {"full_name": "o/r"}}),
                                "was not merged into main"),
        "into another repository": (_pr_with(base={"ref": "main", "repo": {"full_name": "x/r"}}),
                                    "into this repository"),
        "merged as another commit": (_pr_with(merge_commit_sha=_P), "merged as another commit"),
        "no head": (_pr_with(head={}), "no head commit id"),
    }
    check("reuse script: FULL when the pull request is not merged, not closed, not into this "
          "repository's main, merged as another commit, or has no head",
          all(_full(r, why) for r, why in _pr_cases.values()),
          repr({k: v[0][2] for k, v in _pr_cases.items() if not _full(*v)}))
    _two = _rpr(_routes(pulls=[{"number": 7}, {"number": 8}]))
    _none = _rpr(_routes(pulls=[]))
    check("reuse script: FULL when two pull requests, or none, are associated with the pushed commit",
          _full(_two, "exactly one") and _full(_none, "exactly one")
          and "pulls/7" not in _two[3], repr((_two[2], _none[2])))
    _nff = _rpr(_routes(rules=[{"type": "deletion"}]))
    check("reuse script: FULL when main has no non_fast_forward rule (it could have been rewritten)",
          _full(_nff, "non_fast_forward"), repr(_nff[2]))

    # ── the pull request's check ──────────────────────────────────────────────────────────────
    _row = _routes()[4][1]["check_runs"][0]

    def _checks_with(*rows, total=None):
        return {"total_count": len(rows) if total is None else total, "check_runs": list(rows)}

    _ck_cases = {
        "missing": (_rpr(_routes(checks=_checks_with())), "has no 'coverage' check"),
        "failed": (_rpr(_routes(checks=_checks_with(dict(_row, conclusion="failure")))),
                   "did not pass"),
        "still running": (_rpr(_routes(checks=_checks_with(
            dict(_row, status="in_progress", conclusion=None)))), "did not pass"),
        "a re-run after a failure": (_rpr(_routes(checks=_checks_with(
            _row, dict(_row, id=2999, conclusion="failure")))), "did not pass"),
        "another app": (_rpr(_routes(checks=_checks_with(dict(_row, app={"id": 999})))),
                        "has no 'coverage' check"),
        "another name": (_rpr(_routes(checks=_checks_with(dict(_row, name="coverage (x)")))),
                         "has no 'coverage' check"),
        "another workflow": (_rpr(_routes(checks=_checks_with(dict(_row, check_suite={"id": 901})))),
                             "has no 'coverage' check"),
        "a partial page": (_rpr(_routes(checks=_checks_with(_row, total=150))), "one whole page"),
    }
    check("reuse script: FULL when the same-named check is missing, failed, still running, or failed "
          "once before a re-run passed, or is only from another app, name or workflow, or the page "
          "is not the whole list",
          all(_full(r, why) for r, why in _ck_cases.values()),
          repr({k: v[0][2] for k, v in _ck_cases.items() if not _full(*v)}))
    _run_rows = _routes()[3][1]["workflow_runs"]
    _push_run = _rpr(_routes(runs={"total_count": 2, "workflow_runs": [
        dict(_run_rows[0], event="push"), _run_rows[1]]}))
    check("reuse script: FULL when the check's run is not a pull_request run (a push run of the same "
          "workflow on that commit is not the pull request's result)",
          _full(_push_run, "has no 'coverage' check"), repr(_push_run[2]))
    _job = _routes()[5][1]
    _job_cases = {
        "work step skipped (a documentation-only pass)": (_rpr(_routes(job=dict(_job, steps=[
            {"name": "Measure", "conclusion": "skipped"}]))), "did not run Measure"),
        "work step absent": (_rpr(_routes(job=dict(_job, steps=[]))), "did not run Measure"),
        "job of another run": (_rpr(_routes(job=dict(_job, run_id=501))), "is not a job of run"),
        "job of another check": (_rpr(_routes(job=dict(
            _job, check_run_url="https://api.github.com/repos/o/r/check-runs/30001"))),
            "is not a job of run"),
    }
    check("reuse script: FULL when the pull request's job skipped a work step (as a documentation-only "
          "pull request's does), or the job read is not that check's",
          all(_full(r, why) for r, why in _job_cases.values()),
          repr({k: v[0][2] for k, v in _job_cases.items() if not _full(*v)}))
    _two_steps = _rpr(_routes(), steps=("Measure", "Set up job"))
    _one_missing = _rpr(_routes(), steps=("Measure", "Run all checks"))
    check("reuse script: every work step named must have passed, not only the first",
          _two_steps[1][:1] == ["reuse=true"] and _full(_one_missing, "did not run Run all checks"),
          repr((_two_steps[2], _one_missing[2])))

    # ── errors and input ──────────────────────────────────────────────────────────────────────
    _err_cases = {k: _rpr(_routes(**{k: None})) for k in ("pulls", "pull", "rules", "runs", "checks", "job")}
    _err_cases["garbled"] = _rpr(_routes(pull="{not json"))
    _err_cases["a list for an object"] = _rpr(_routes(runs=[]))
    check("reuse script: FULL on any API error or an answer not in GitHub's shape, at every endpoint",
          all(_full(r) for r in _err_cases.values()),
          repr({k: v[1:3] for k, v in _err_cases.items() if not _full(v)}))
    _quiet = {"pull_request": _rpr(_routes(), event="pull_request"),
              "workflow_dispatch": _rpr(_routes(), event="workflow_dispatch"),
              "another branch": _rpr(_routes(), ref="refs/heads/dev"),
              "a tag named main": _rpr(_routes(), ref="refs/tags/main"),
              "Main": _rpr(_routes(), ref="refs/heads/Main"),
              "short sha": _rpr(_routes(), sha="abc"),
              "no work step": _rpr(_routes(), steps=())}
    check("reuse script: anything but a push to exactly refs/heads/main, or bad input, runs everything "
          "without asking GitHub",
          all(_full(v) and v[3] == "" for v in _quiet.values()),
          repr({k: v[1:] for k, v in _quiet.items() if not (_full(v) and v[3] == "")}))
    _ordered = _ok[3].split("\n")
    # The pull request's check is missing, so the answer is FULL; the head must not have been fetched.
    _api_full = _rpr(_routes(checks={"total_count": 0, "check_runs": []}), cwd=_work2)
    check("reuse script: it asks for the pull request before anything else, and fetches with git only "
          "after every API condition holds (a FULL answer leaves the checkout as it was)",
          _ordered[:3] == ["repos/o/r/commits/%s/pulls?per_page=100" % _S, "repos/o/r/pulls/7",
                           "repos/o/r/rules/branches/main?per_page=100"]
          and _full(_api_full) and _git153(_work2, "cat-file", "-t", _H) == ""
          and _git153(_work, "rev-list", "--count", "HEAD") == "1", repr((_ordered, _api_full[2])))
finally:
    _shutil153.rmtree(_SB153, ignore_errors=True)

# ── the wiring ────────────────────────────────────────────────────────────────────────────────
# (workflow, job id, the job's `name:` as written, the work steps it names)
_REUSERS153 = {
    ("ci.yml", "checks"): ("checks (${{ matrix.os }} · py${{ matrix.python }})",
                           ("Run all checks (compile, lint, unit, smoke, shellcheck)",
                            "Run the root-only unit checks, as root")),
    ("ci.yml", "coverage"): ("coverage", ("Measure",)),
    ("ci.yml", "js-coverage"): ("js coverage", ("Measure",)),
    ("ci.yml", "gamedig-lockfile"): ("gamedig lockfile (node ${{ matrix.node }})",
                                     ("npm ci from the lockfile, then run gamedig once",)),
    ("lighthouse.yml", "lighthouse"): ("lighthouse", ("Run Lighthouse CI",)),
}
# Steps after the reuse step that run on REUSE too, with the `if:` each must have.
_ON_REUSE153 = {
    ("ci.yml", "checks", "Documentation-only pull request, so the unit suite alone (it reads the docs)"):
        "steps.scope.outputs.docs_only == 'true' && matrix.docs",
    ("ci.yml", "coverage", "Take the report the pull request's run made on the same tree"):
        _RUN153 + " && steps.reuse.outputs.reuse == 'true'",
    ("ci.yml", "coverage", "Record that a documentation-only pull request measured nothing"):
        "steps.scope.outputs.docs_only == 'true'",
    ("ci.yml", "coverage", "Upload the report"): "",
    ("ci.yml", "js-coverage", "Take the report the pull request's run made on the same tree"):
        _RUN153 + " && steps.reuse.outputs.reuse == 'true'",
    ("ci.yml", "js-coverage", "Upload the report"): _RUN153,
}
# The `if:` of a step the reuse step skips: its docs-only gate, AND the reuse clause.
_SKIPPED_IFS153 = {_RUN153 + " && " + _REUSE153,
                   "(%s || matrix.docs) && %s" % (_RUN153, _REUSE153),
                   "always() && %s && %s" % (_RUN153, _REUSE153)}
# In the coverage jobs the steps are skipped only when the pull request's report was also taken: a
# download that failed (continue-on-error) leaves them to measure, rather than upload nothing.
_TAKEN_JOBS153 = {("ci.yml", "coverage"), ("ci.yml", "js-coverage")}
_TAKEN_IF153 = "%s && (%s || steps.take.outcome != 'success')" % (_RUN153, _REUSE153)


def _if153(step):
    m = _re153.search(r"^(?:- | {8})if: (.*)$", step, _re153.M)
    return m.group(1).strip() if m else ""


def _sname153(step):
    m = _re153.search(r"uses: ([^@\s]+)", step)
    return _name29(step) or (m.group(1) if m else "")


def _reuse_step_bad153(wf, step, name, work):
    """What is wrong with one job's reuse step ([] when nothing)."""
    one = " ".join(step.split())
    want = ('python3 .github/scripts/reuse_pr_result.py --event "$GITHUB_EVENT_NAME" --ref "$GITHUB_REF" '
            '--repo "$GITHUB_REPOSITORY" --sha "$GITHUB_SHA" --workflow .github/workflows/%s '
            '--check-name "$CHECK_NAME"%s' % (wf, "".join(' --work-step "%s"' % w for w in work)))
    return [why for bad, why in (
        (not _re153.search(r"^ {8}id: reuse$", step, _re153.M), "no id: reuse"),
        (_if153(step) != "github.event_name == 'push' && " + _RUN153, "if: %r" % _if153(step)),
        ("CHECK_NAME: %s\n" % name not in step, "CHECK_NAME is not the job's name"),
        ("GH_TOKEN: ${{ github.token }}" not in step, "no GH_TOKEN"),
        (want not in one, "not the script with this workflow, name and work steps"),
    ) if bad]


def _head_bad153(text, name):
    """What is wrong with a reusing job's own keys: its name, and what it may read."""
    bad = [] if "    name: %s\n" % name in text else ["the job's name is not %r" % name]
    return bad + ["no %s" % p for p in ("pull-requests: read", "actions: read", "checks: read")
                  if not _re153.search(r"^      %s\b" % p, text, _re153.M)]


def _later_bad153(wf, job, steps, names):
    """What is wrong with the steps after the reuse step: each skipped on REUSE, or exempt."""
    bad = []
    skipped = {_TAKEN_IF153} if (wf, job) in _TAKEN_JOBS153 else _SKIPPED_IFS153
    for step, sname in zip(steps, names):
        cond, want = _if153(step), _ON_REUSE153.get((wf, job, sname))
        if want is not None and cond != want:
            bad.append("%s: if %r, want %r" % (sname, cond, want))
        elif want is None and cond not in skipped:
            bad.append("%s: not skipped on REUSE (if: %r)" % (sname, cond))
    return bad


def _wiring153(wf, job, name, work):
    """What is wrong with one reusing job, as a list of reasons."""
    text = _code29(_job29(_wf29(wf), job))
    if not text:
        return ["no such job"]
    bad = _head_bad153(text, name)
    steps = _steps29(text)
    names = [_sname153(s) for s in steps]
    at = next((i for i, s in enumerate(steps) if _re153.search(r"^ {8}id: reuse$", s, _re153.M)), None)
    if at is None or not _re153.search(r"^ {8}id: scope$", steps[at - 1], _re153.M):
        return bad + ["no reuse step right after the scope step: %r" % names]
    bad += _reuse_step_bad153(wf, steps[at], name, work)
    bad += ["names a work step the job does not have: %r" % w for w in work if w not in names[at + 1:]]
    return bad + _later_bad153(wf, job, steps[at + 1:], names[at + 1:])


_wbad153 = {"%s:%s" % k: _wiring153(k[0], k[1], *v) for k, v in _REUSERS153.items()}
check("reuse wiring: each reusing job runs the script right after its scope step, with its own name, "
      "workflow and work steps, may read the runs and checks, and skips every later step on REUSE but "
      "the ones that must run",
      not any(_wbad153.values()), repr({k: v for k, v in _wbad153.items() if v}))
_ctl153 = _wiring153("ci.yml", "coverage", "coverage", ("Measure", "Not a step"))
check("reuse wiring: (control) a work step the job does not have is caught",
      any("does not have" in b for b in _ctl153), repr(_ctl153))

_ci_jobs153 = _re153.findall(r"^  ([a-z][a-z-]*):\n", _code29(_wf29("ci.yml")).split("\njobs:\n", 1)[1],
                             _re153.M)
check("reuse wiring: every ci.yml job reuses, and each is a check the panel's update gate requires "
      "(system_ops._CI_REQUIRED), so main still carries each name",
      sorted(_ci_jobs153) == sorted(j for w, j in _REUSERS153 if w == "ci.yml")
      and all(any(_so153._ci_name_matches(r, n) for r in _so153._CI_REQUIRED)
              for (w, _j), (n, _s) in _REUSERS153.items() if w == "ci.yml"),
      repr(_ci_jobs153))
_dl153 = {}
for _j153 in ("coverage", "js-coverage"):
    _st153 = {_sname153(s): s for s in _steps29(_code29(_job29(_wf29("ci.yml"), _j153)))}
    _take153 = _st153.get("Take the report the pull request's run made on the same tree", "")
    _up153 = _re153.search(r"^ {10}name: (\S+)$", _st153.get("Upload the report", ""), _re153.M)
    _dl153[_j153] = (_up153 is not None
                     and "          name: %s\n" % _up153.group(1) in _take153
                     and "run-id: ${{ steps.reuse.outputs.run_id }}" in _take153
                     and "github-token: ${{ github.token }}" in _take153
                     and "path:" not in _take153
                     and "        id: take\n" in _take153 and "        continue-on-error: true\n" in _take153
                     and _re153.search(r"uses: actions/download-artifact@[0-9a-f]{40} # v", _take153))
check("reuse wiring: on REUSE the coverage jobs take the artifact their own upload step publishes, from "
      "the pull request's run, into the workspace the upload reads, and a download that fails leaves the "
      "job to measure (continue-on-error, and every measuring step runs unless the download succeeded)",
      all(_dl153.values()), repr(_dl153))
_cc153 = _wf29("codacy-coverage.yml")
_pins153 = set(_re153.findall(r"uses: actions/download-artifact@([0-9a-f]{40})", _wf29("ci.yml") + _cc153))
check("reuse wiring: ...with the same pinned download-artifact codacy-coverage.yml uses",
      len(_pins153) == 1, repr(_pins153))

_spec153 = _ilu153.spec_from_file_location("reuse_pr_result_p153", _RPR153)
RP = _ilu153.module_from_spec(_spec153)
_spec153.loader.exec_module(RP)
# As pr_scope.py's slug (part50): the commit ids and the job name that reach gh's and git's argv are
# rebuilt from a constant table, not passed on as the text that matched a pattern.
_sha_in153 = "".join(["0123456789", "abcdef0123", "456789abcd", "ef01234567"])
_name_in153 = "".join(["checks (ubuntu-24.04 ", "· py3.12)"])
check("reuse script: the commit ids and job name it hands gh and git are REBUILT, and anything else "
      "is refused",
      RP._rebuilt(_sha_in153, RP._SHA_RE, RP._HEX) == _sha_in153
      and RP._rebuilt(_sha_in153, RP._SHA_RE, RP._HEX) is not _sha_in153
      and RP._rebuilt(_name_in153, RP._NAME_RE, RP._NAME_TABLE) == _name_in153
      and RP._rebuilt(_name_in153, RP._NAME_RE, RP._NAME_TABLE) is not _name_in153
      and all(RP._rebuilt(b, RP._SHA_RE, RP._HEX) is None for b in ("-" + "a" * 39, "A" * 40, None, ""))
      and all(RP._rebuilt(b, RP._NAME_RE, RP._NAME_TABLE) is None for b in ("x\ny", "a;b", "é", "")))
_rs153 = open(_RPR153, encoding="utf-8").read()
_req153 = open(os.path.join(_root, ".github", "required-checks.txt"), encoding="utf-8").read()
check("reuse script: the Actions app id it requires is the one required-checks.txt names for "
      "github-actions",
      "ACTIONS_APP_ID = 15368\n" in _rs153 and "Actions 15368" in _req153)
check("reuse wiring: CodeQL, Bandit/Semgrep, zizmor and Gitleaks keep a real run on every push to main "
      "(code scanning needs main's own analyses; the alerts check waits for them), and never reuse",
      not any("reuse_pr_result" in _wf29(f) for f in ("codeql.yml", "security-code.yml", "zizmor.yml",
                                                      "security.yml", "codeql-alerts.yml"))
      and all(_re153.search(r"^  push:\n    branches: \[ main \]\n", _code29(_wf29(f)), _re153.M)
              for f in ("codeql.yml", "security-code.yml", "zizmor.yml", "security.yml")))
