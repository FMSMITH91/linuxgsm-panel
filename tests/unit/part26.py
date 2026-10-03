"""Part 26 of the unit suite: the code-scanning alert gates judge THIS commit's analyses.

Both alert gates read a ref's open alerts, and a ref's alert set is the newest analysis in each of
five categories uploaded by two workflows nothing orders: CodeQL's three languages (codeql.yml) and
Bandit and Semgrep (security-code.yml). The PR gate (codeql.yml's pr-alerts) polled for ANY
analysis of refs/pull/<n>/merge, which after a PR's first push is always the previous push's: on
#385 it read the alerts 13 s before that commit's Semgrep analysis landed, and passed. The main gate
(codeql-alerts.yml) asked for "an analysis of this commit" with a `sha=` parameter the analyses list
does not have, so that guard could never fire, and it skipped scheduled runs, so the weekly scan's
new alerts were never judged on main.

Now both run .github/scripts/code_scanning_analyses.py first, which holds the one category list and
waits until each category's newest analysis is the judged commit's own. Here: the list is pinned to
the two workflows that upload; the decision is driven case by case; and each gate's own step is
taken out of its workflow and run with `gh` stubbed, so the callers are tested, not just the helper.

Workflows are read as text: PyYAML is not installed where CI runs this suite.
"""
import importlib.util as _ilu26
import json as _json26
import os
import re
import shutil as _shutil26
import subprocess as _sp26  # nosec B404 - runs bash and this interpreter on the suite's own files
import sys
import tempfile as _tf26

from unit.part01 import check
from unit.part05 import _root
from unit.part14 import _wf14, _wf14_code, _wf14_run

_CSA26_PATH = os.path.join(_root, ".github", "scripts", "code_scanning_analyses.py")
_spec26 = _ilu26.spec_from_file_location("code_scanning_analyses_p26", _CSA26_PATH)
CSA = _ilu26.module_from_spec(_spec26)
_spec26.loader.exec_module(CSA)

_cq26 = _wf14("codeql.yml")
_cqa26 = _wf14("codeql-alerts.yml")
_sec26 = _wf14("security-code.yml")


def _job26(text, job):
    """The text of one job (`  <job>:` up to the next two-space key), comment lines dropped."""
    m = re.search(r"^  %s:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)" % re.escape(job), text, re.M | re.S)
    body = m.group(1) if m else ""
    return "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))


def _upload_categories26(text):
    """Every `category:` given to github/codeql-action/upload-sarif in a workflow's text."""
    out = []
    for m in re.finditer(r"^(\s*)- (?:name: .*\n\s+)?uses: github/codeql-action/upload-sarif@.*$",
                         text, re.M):
        step = text[m.end():]
        nxt = re.search(r"^%s- |^  \S" % re.escape(m.group(1)), step, re.M)
        step = step[:nxt.start()] if nxt else step
        cat = re.search(r"^\s+category:\s*['\"]?([^'\"\s#]+)", step, re.M)
        out.append(cat.group(1) if cat else None)
    return out


# ── 1. one category list, held to the workflows that upload ──────────────────────────────────
_an26 = _job26(_cq26, "analyze")
_langs26 = re.findall(r"^\s+- language: (\S+)\s*$", _an26, re.M)
_from_wf26 = {("/language:" + lang, "codeql.yml") for lang in _langs26}
_sec_cats26 = _upload_categories26(_wf14_code("security-code.yml"))
_from_wf26 |= {(c, "security-code.yml") for c in _sec_cats26}
check("code-scanning gates: the category list is exactly what codeql.yml's language matrix and "
      "security-code.yml's upload-sarif steps upload, each named with its workflow",
      set(CSA.CATEGORIES.items()) == _from_wf26 and len(CSA.CATEGORIES) == len(_from_wf26),
      repr((sorted(CSA.CATEGORIES.items()), sorted(_from_wf26))))
check("code-scanning gates: ...read from the workflows themselves (positive control: three "
      "languages, CodeQL's category formula, and both SARIF uploads found)",
      len(_langs26) == 3 and 'category: "/language:${{ matrix.language }}"' in _an26
      and sorted(_sec_cats26) == ["bandit", "semgrep"], repr((_langs26, _sec_cats26)))
check("code-scanning gates: ...and the reader finds a category it was not told about (a third "
      "upload in a sample workflow)",
      _upload_categories26(
          "jobs:\n  a:\n    steps:\n      - name: Up\n        uses: github/codeql-action/upload-sarif@x"
          "\n        with:\n          sarif_file: a.sarif\n          category: zap\n"
          "      - uses: github/codeql-action/upload-sarif@x\n        with:\n"
          "          category: 'osv'\n") == ["zap", "osv"])


# ── 2. the decision, case by case ────────────────────────────────────────────────────────────
_S26, _P26, _N26 = "5" * 40, "4" * 40, "6" * 40   # this commit, its predecessor, a later one
_ALL26 = set(CSA.CATEGORIES)
_CQ26 = {c for c, w in CSA.CATEGORIES.items() if w == "codeql.yml"}


def _rows26(*spec):
    """Analyses rows, newest first, from (category, commit, created_at) triples."""
    return [{"category": c, "commit_sha": s, "created_at": t} for c, s, t in spec]


def _set26(sha, t, cats=None):
    return [(c, sha, t) for c in (cats if cats is not None else CSA.CATEGORIES)]


_whole26 = _rows26(*(_set26(_S26, "2026-10-03T10:00:00Z") + _set26(_P26, "2026-10-03T09:00:00Z")))
# PR #385's shape: four of this commit's analyses landed, Semgrep's newest is still the last push's.
_late26 = _rows26(*(_set26(_S26, "2026-10-03T10:00:00Z", [c for c in CSA.CATEGORIES if c != "semgrep"])
                    + _set26(_P26, "2026-10-03T09:00:00Z")))
_moved26 = _rows26(*([("/language:python", _N26, "2026-10-03T11:00:00Z")]
                     + _set26(_S26, "2026-10-03T10:00:00Z")))
# A scheduled CodeQL run over a docs-only head: CodeQL's categories are its own, Bandit's and
# Semgrep's are the predecessor's (security-code.yml did not run for a docs-only push either).
_sched_spec26 = (_set26(_S26, "2026-10-05T05:30:00Z", sorted(_CQ26))
                 + _set26(_P26, "2026-10-03T09:00:00Z"))
_sched26 = _rows26(*_sched_spec26)
_sched_later26 = _rows26(*([("bandit", _N26, "2026-10-05T05:40:00Z")] + _sched_spec26))
_cases26 = {
    "all five are this commit's": (CSA.assess(_whole26, _S26, _ALL26), ([], [])),
    "Semgrep still the last push's": (CSA.assess(_late26, _S26, _ALL26), (["semgrep"], [])),
    "nothing analysed yet": (CSA.assess([], _S26, _ALL26), (list(CSA.CATEGORIES), [])),
    "only an older commit's analyses": (CSA.assess(_rows26(*_set26(_P26, "t")), _S26, _ALL26),
                                        (list(CSA.CATEGORIES), [])),
    "a later commit's Python is newer": (CSA.assess(_moved26, _S26, _ALL26),
                                         ([], ["/language:python"])),
    "scheduled CodeQL, docs-only head": (CSA.assess(_sched26, _S26, _CQ26), ([], [])),
    "...but the same rows on a push": (CSA.assess(_sched26, _S26, _ALL26), (["bandit", "semgrep"], [])),
    "scheduled, a later commit's Bandit": (CSA.assess(_sched_later26, _S26, _CQ26), ([], ["bandit"])),
    "scheduled, own rows not landed yet": (
        CSA.assess(_rows26(*_set26(_P26, "2026-10-03T09:00:00Z")), _S26, _CQ26),
        (list(CSA.CATEGORIES), [])),
}
check("code-scanning gates: a category is MISSING until this commit's analysis is in it, and "
      "MOVED ON when a later commit's is newer",
      all(got == want for got, want in _cases26.values()),
      repr({k: v for k, v in _cases26.items() if v[0] != v[1]}))
_own26 = {
    "pull_request": CSA.own_categories("pull_request", ""),
    "push": CSA.own_categories("push", ".github/workflows/codeql.yml"),
    "schedule codeql": CSA.own_categories("schedule", ".github/workflows/codeql.yml"),
    "schedule security-code": CSA.own_categories("schedule", ".github/workflows/security-code.yml"),
    "schedule unknown": CSA.own_categories("schedule", ".github/workflows/other.yml"),
    "manual": CSA.own_categories("", ""),
}
check("code-scanning gates: every category must be the commit's own, except on a scheduled run, "
      "which re-analyses with its one workflow",
      _own26 == {"pull_request": _ALL26, "push": _ALL26, "schedule codeql": _CQ26,
                 "schedule security-code": {"bandit", "semgrep"}, "schedule unknown": _ALL26,
                 "manual": _ALL26}, repr(_own26))


# ── 3. each gate's own steps, run with `gh` stubbed ──────────────────────────────────────────
def _timeout26(job_text):
    m = re.search(r"^    timeout-minutes: (\d+)\s*$", job_text, re.M)
    return int(m.group(1)) if m else 0


def _step26(text, name):
    """The step's `run:` body, or "" when the workflow has no such step (its checks then fail)."""
    try:
        return _wf14_run(text, name)
    except (StopIteration, ValueError):
        return ""


def _poll26(run):
    """(tries, interval) the step passes the script, and the run with the interval cut to 0."""
    t = re.search(r"--tries (\d+)", run)
    i = re.search(r"--interval (\d+)", run)
    fast = run.replace(i.group(0), "--interval 0") if i and run.count(i.group(0)) == 1 else ""
    return (int(t.group(1)) if t else 0, int(i.group(1)) if i else 0, fast)


_pr26 = _job26(_cq26, "pr-alerts")
_STEP26 = r"^      - (?:name: (.+)|uses: (\S+).*)$"
_pr_steps26 = re.findall(_STEP26, _pr26, re.M)
_pr_wait26 = _step26(_cq26, "Wait for this merge commit's analysis in every category")
_pr_judge26 = _step26(_cq26, "Judge refs/pull/<n>/merge")
_pr_poll26 = _poll26(_pr_wait26)
_judge_name26 = "Fail if that ref has open code-scanning alerts"
_m_judge26 = _step26(_cqa26, _judge_name26)
_m_poll26 = _poll26(_m_judge26)
_m_job26 = _job26(_cqa26, "open-alerts")
_m_steps26 = [s[0] or s[1].split("@")[0] for s in re.findall(_STEP26, _m_job26, re.M)]
_sparse26 = "sparse-checkout: .github/scripts/code_scanning_analyses.py"
check("code-scanning gates: pr-alerts checks out the script, then waits for this merge commit "
      "(github.sha) in every category, and only then judges the alerts",
      [s[0] or s[1].split("@")[0] for s in _pr_steps26]
      == ["actions/checkout", "Wait for this merge commit's analysis in every category",
          "Judge refs/pull/<n>/merge"]
      and _sparse26 in _pr26 and "code_scanning_analyses.py" in _pr_wait26
      and "--event pull_request" in _pr_wait26 and "SHA: ${{ github.sha }}" in _pr26
      and "code_scanning_analyses.py" not in _pr_judge26, repr(_pr_steps26))
check("code-scanning gates: ...the main gate checks it out and runs it before reading any alert, "
      "with the triggering run's event and workflow",
      _sparse26 in _m_job26 and "actions/checkout" in _m_steps26 and _judge_name26 in _m_steps26
      and _m_steps26.index("actions/checkout") == _m_steps26.index(_judge_name26) - 1
      and 0 <= _m_judge26.find("code_scanning_analyses.py") < _m_judge26.find("code-scanning/alerts")
      and '--event "${WR_EVENT}" --workflow "${WR_PATH}"' in _m_judge26
      and "WR_EVENT: ${{ github.event.workflow_run.event }}" in _m_job26
      and "WR_PATH: ${{ github.event.workflow_run.path }}" in _m_job26, repr(_m_steps26))
check("code-scanning gates: pr-alerts waits about ten minutes for the other workflow, and its job "
      "timeout leaves room after the wait (it was 10 minutes, the wait's own length)",
      _pr_poll26[0] * _pr_poll26[1] >= 600
      and _pr_poll26[0] * _pr_poll26[1] + 120 <= _timeout26(_pr26) * 60 and _pr_poll26[2],
      repr((_pr_poll26[:2], _timeout26(_pr26))))
check("code-scanning gates: ...and the main gate's wait fits inside its job's timeout too",
      0 < _m_poll26[0] * _m_poll26[1] and _m_poll26[0] * _m_poll26[1] + 120 <= _timeout26(_m_job26) * 60
      and _m_poll26[2], repr((_m_poll26[:2], _timeout26(_m_job26))))

_sb26 = _tf26.mkdtemp(prefix="csa26-")
try:
    _bin26 = os.path.join(_sb26, "bin")
    os.makedirs(_bin26)
    with open(os.path.join(_bin26, "gh"), "w") as _fh:
        _fh.write('#!/bin/bash\necho "$*" >> "$GH_LOG"\n'
                  'case "$*" in\n'
                  '  *code-scanning/analyses*) [ -n "${GH_FAIL:-}" ] && { echo boom >&2; exit 1; }\n'
                  '                            cat "$ANALYSES" ;;\n'
                  '  *code-scanning/alerts*) echo "${ALERTS:-[]}" ;;\n'
                  '  *actions/workflows/*) echo 0 ;;\n'
                  '  *check-runs*) : ;;\n'
                  'esac\n')
    # A python3 on PATH that is this interpreter, so the step runs the script with the suite's own.
    with open(os.path.join(_bin26, "python3"), "w") as _fh:
        _fh.write('#!/bin/sh\nexec "%s" "$@"\n' % sys.executable)
    for _x in ("gh", "python3"):
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: owner-only stubs the suite runs itself
        os.chmod(os.path.join(_bin26, _x), 0o700)

    def _run26(run, rows, **env):
        """Run a step body in the checkout with `gh` stubbed; (rc, outputs, gh log, stdout, summary).

        A step that was not found runs as nothing, which exits 0: it is reported as rc 99 instead.
        """
        if not run.strip():
            return 99, {}, "", "no such step", ""
        paths = {k: os.path.join(_sb26, k) for k in ("out", "log", "summary", "analyses")}
        for p in paths.values():
            open(p, "w").close()
        with open(paths["analyses"], "w") as fh:
            _json26.dump(rows, fh)
        p = _sp26.run(["bash", "-c", run], capture_output=True, text=True, cwd=_root,  # nosec B603 B607 - the workflow's own step
                      env=dict(os.environ, PATH=_bin26 + os.pathsep + os.environ["PATH"],
                               GH_LOG=paths["log"], GITHUB_OUTPUT=paths["out"],
                               GITHUB_STEP_SUMMARY=paths["summary"], ANALYSES=paths["analyses"],
                               GITHUB_REPOSITORY="o/r", **env), timeout=120)
        outs = dict(ln.split("=", 1) for ln in open(paths["out"]).read().splitlines() if "=" in ln)
        return p.returncode, outs, open(paths["log"]).read(), p.stdout + p.stderr, \
            open(paths["summary"]).read()

    # ── pr-alerts ──
    _penv26 = dict(REF="refs/pull/7/merge", SHA=_S26)
    _pw = {k: _run26(_pr_poll26[2], rows, **_penv26) for k, rows in
           (("clean", _whole26), ("late", _late26), ("moved", _moved26), ("none", []))}
    _pw_fail = _run26(_pr_poll26[2], _whole26, GH_FAIL="1", **_penv26)
    _q26 = [ln for ln in _pw["clean"][2].splitlines() if "code-scanning/analyses" in ln]
    check("code-scanning gates (PR): it reads ONE page of the ref's newest 100 analyses, unpaginated, "
          "with no `sha=` (the list has no commit filter)",
          _q26 == ["api repos/o/r/code-scanning/analyses?ref=refs/pull/7/merge&per_page=100"
                   "&sort=created&direction=desc"], repr(_q26))
    check("code-scanning gates (PR): this merge commit in every category passes the wait",
          _pw["clean"][0] == 0, _pw["clean"][3][-800:])
    check("code-scanning gates (PR): Semgrep's newest still the last push's (PR #385) FAILS, naming "
          "semgrep, after polling the whole wait",
          _pw["late"][0] != 0 and re.search(r"::error::no analysis of %s .*: semgrep\." % _S26,
                                            _pw["late"][3]) is not None
          and _pw["late"][2].count("code-scanning/analyses") == _pr_poll26[0],
          _pw["late"][3][-800:])
    check("code-scanning gates (PR): ...a ref with nothing analysed fails, and so does one a later "
          "push already replaced",
          _pw["none"][0] != 0 and _pw["moved"][0] != 0 and "moved on" in _pw["moved"][3]
          and _pw["moved"][2].count("code-scanning/analyses") == 1,
          repr((_pw["none"][0], _pw["moved"][0], _pw["moved"][3][-400:])))
    check("code-scanning gates (PR): ...and an unreadable analyses list fails rather than reading as "
          "clean", _pw_fail[0] != 0 and "could not read the code-scanning analyses" in _pw_fail[3],
          _pw_fail[3][-400:])
    _pj = {k: _run26(_pr_judge26, [], REF="refs/pull/7/merge", ALERTS=a) for k, a in
           (("clean", "[]"), ("dirty", '[{"rule":"x","sev":"high","path":"a.py","line":1}]'))}
    check("code-scanning gates (PR): after the wait, an open alert still fails the job and none "
          "passes it", _pj["clean"][0] == 0 and _pj["dirty"][0] == 1,
          repr((_pj["clean"][:2], _pj["dirty"][:2])))

    # ── the main gate ──
    def _main26(rows, event="push", path=".github/workflows/codeql.yml", alerts="[]"):
        return _run26(_m_poll26[2], rows, REF="refs/heads/main", LABEL="`main`", SHA=_S26,
                      WR_EVENT=event, WR_PATH=path, ALERTS=alerts)

    _mj = {
        "clean": _main26(_whole26),
        "dirty": _main26(_whole26, alerts='[{"rule":"x","sev":"high","path":"a.py","line":1}]'),
        "late": _main26(_late26),
        "moved": _main26(_moved26),
        "sched docs-only": _main26(_sched26, event="schedule"),
        "push docs-only": _main26(_sched26),
        "manual": _main26(_whole26, event="", path=""),
    }
    check("code-scanning gates (main): clean is 'success', open alerts fail",
          _mj["clean"][:2] == (0, {"verdict": "success"}) and _mj["dirty"][0] == 1
          and _mj["manual"][:2] == (0, {"verdict": "success"}),
          repr((_mj["clean"][:2], _mj["dirty"][:2], _mj["manual"][:2])))
    check("code-scanning gates (main): a category with no analysis OF THIS COMMIT fails, names it, "
          "and no alert is read (the old `sha=` guard could never fire)",
          _mj["late"][0] == 1 and "verdict" not in _mj["late"][1]
          and "code-scanning/alerts" not in _mj["late"][2] and "sha=" not in _mj["late"][2]
          and ": semgrep." in _mj["late"][3] and "proves nothing" in _mj["late"][4],
          repr((_mj["late"][:3], _mj["late"][3][-400:])))
    check("code-scanning gates (main): a later commit's analysis being the newest in ANY category "
          "is 'skipped', not judged on that commit's alerts",
          _mj["moved"][:2] == (0, {"verdict": "skipped"})
          and "code-scanning/alerts" not in _mj["moved"][2], repr(_mj["moved"][:3]))
    check("code-scanning gates (main): a scheduled CodeQL run over a docs-only head is judged on its "
          "own analyses (success), where the same rows on a push fail",
          _mj["sched docs-only"][:2] == (0, {"verdict": "success"}) and _mj["push docs-only"][0] == 1,
          repr((_mj["sched docs-only"][:2], _mj["sched docs-only"][3][-400:],
                _mj["push docs-only"][:2])))
    check("code-scanning gates (main): the job summary shows what each category held",
          all(c in _mj["clean"][4] for c in CSA.CATEGORIES) and "None. :white_check_mark:"
          in _mj["clean"][4], _mj["clean"][4][-600:])

    # ── scheduled runs reach the gate, and wait for the other workflow's scheduled run ──
    _wait26 = _step26(_cqa26, "Wait for the other uploader")
    _ws = _run26(_wait26, [], GITHUB_EVENT_NAME="workflow_run", WR_SHA=_S26, WR_NAME="CodeQL",
                 WR_EVENT="schedule")
    check("code-scanning gates (main): a scheduled run looks for the other workflow's SCHEDULED run "
          "of the same commit",
          _ws[:2] == (0, {"judge": "true"}) and _ws[2].count("event=schedule") == 2
          and "event=push" not in _ws[2], repr(_ws[:3]))
finally:
    _shutil26.rmtree(_sb26, ignore_errors=True)

_if26 = re.search(r"^    if: >-\n((?:      .*\n)+)", _cqa26, re.M)
_if26 = " ".join(_if26.group(1).split()) if _if26 else ""
check("code-scanning gates (main): the gate's `if:` admits a scheduled run of main as well as a "
      "push, still only on success and only for main",
      "github.event.workflow_run.event == 'schedule'" in _if26
      and "github.event.workflow_run.event == 'push'" in _if26
      and "github.event.workflow_run.conclusion == 'success'" in _if26
      and "github.event.workflow_run.head_branch == 'main'" in _if26
      and re.search(r"^  schedule:\n    - cron: ", _cq26, re.M) is not None
      and re.search(r"^  schedule:\n    - cron: ", _sec26, re.M) is not None, _if26)

# ── 4. required-checks.txt says what pr-alerts gates, and no more ────────────────────────────
with open(os.path.join(_root, ".github", "required-checks.txt"), encoding="utf-8") as _fh:
    _rq26 = " ".join(ln.lstrip("# ").strip() for ln in _fh if ln.startswith("#"))
_rq_gate26 = _rq26[_rq26.index("GitHub's own code-scanning checks"):]
_rq_gate26 = _rq_gate26[:_rq_gate26.index("Codacy's coverage")]
check("required checks: the comment no longer claims the PR alerts gate covers ClusterFuzzLite, "
      "and names the job that does gate a fuzz crash",
      "ClusterFuzzLite/CIFuzz is not waited for" in _rq_gate26 and '"fuzz the diff"' in _rq_gate26
      and "CodeQL, Bandit, Semgrep OSS" in _rq_gate26
      and not re.search(r"ClusterFuzzLite/CIFuzz:", _rq_gate26), _rq_gate26)
