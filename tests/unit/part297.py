"""Part 297 of the unit suite: the main-only CI jobs that block egress, and the nightly fuzz workflow.

* Harden-Runner in block mode (OWASP Top 10 CI/CD Security Risks, CICD-SEC-5 and CICD-SEC-7) for the
  main-only jobs codacy-alerts, codacy-coverage, sonar-main-issues, codeql-alerts and cflite_cleanup:
  each allow-list is exactly the hosts the job was seen calling in its own Harden-Runner logs, pinned
  here as literals, so a host dropped or added is a decision someone makes, not an accident.
* A host missing from a list turns a main check red, and that holds every panel's update. So each
  of these jobs can be run by hand on the branch that changes it, before it merges, without doing on
  that branch what it does on main: no environment (and so no environment secret), no upload, no
  deletion, no verdict posted on a commit. Each manual arm runs here through the job's own step.
* cflite_nightly.yml: the corpus is pruned and its coverage measured after the batch run that
  fed it, by `needs:`, not by two schedules set a clock-guess apart.

Nothing here touches the network or the checkout's data/.
"""
import os
import re as _re297
import shutil as _shutil297
import subprocess as _sp297  # nosec B404 - runs bash on the workflows' own steps with stand-in programs
import tempfile as _tf297

from unit.part01 import check
from unit.part05 import _root
from unit.part06 import _wf_run_block, _wf_step_env
from unit.part223 import _egress223
from unit.part29 import _job29, _runbody29, _steps29, _wf29, _write_exe29
from unit.part30 import _if30, _row30

# ── 1. the allow-lists, exactly ─────────────────────────────────────────────────────────────────
# Read from each job's Harden-Runner "endpoint called" lines over its last eight runs of every event
# it runs on (2026-11-26), less the GitHub Actions service names the agent allows by itself
# (*.github.com, *.githubapp.com, results-receiver and the productionresultssa* blob stores).
# api.github.com and github.com are on every list (part223 holds that); the setup-python job also
# keeps the hosts an interpreter download goes to, for a runner image with none cached.
_ALLOW297 = {
    ("codacy-alerts.yml", "open-errors"): {
        "api.github.com:443", "app.codacy.com:443", "github.com:443", "objects.githubusercontent.com:443",
        "release-assets.githubusercontent.com:443"},
    ("codacy-coverage.yml", "upload"): {
        "api.codacy.com:443", "api.github.com:443", "github.com:443", "objects.githubusercontent.com:443",
        "release-assets.githubusercontent.com:443"},
    ("sonar-main-issues.yml", "sonar-main-issues"): {"api.github.com:443", "github.com:443", "sonarcloud.io:443"},
    ("codeql-alerts.yml", "open-alerts"): {"api.github.com:443", "github.com:443"},
    ("cflite_cleanup.yml", "cleanup"): {"api.github.com:443", "github.com:443"},
}
_lists297 = {fj: _egress223(_job29(_wf29(fj[0]), fj[1])) for fj in _ALLOW297}
check("main-only egress: each listed main-only job blocks, allowed exactly the hosts its own runs called",
      all(_lists297[fj][0] == "block" and set(_lists297[fj][1]) == want
          and len(_lists297[fj][1]) == len(want) for fj, want in _ALLOW297.items()),
      repr({"%s/%s" % fj: v for fj, v in _lists297.items()}))

# ── 2. codacy-alerts: the environment only on main ──────────────────────────────────────────────
# The `codacy` environment admits main alone, so a manual run on another branch that named it was
# refused before it started, and the allow-list could not be tried before it reached main. Only a
# run on main names it now; elsewhere the job runs with none, so no environment secret is in reach.
_ca297 = _job29(_wf29("codacy-alerts.yml"), "open-errors")
_ca_env297 = _re297.search(r"^    environment:\n      name: (.*)\n      deployment: false\n", _ca297, _re297.M)
check("codacy-alerts: names the codacy environment on main only (no deployment record), and stays "
      "runnable by hand on any branch",
      _ca_env297 is not None
      and _ca_env297.group(1) == "${{ github.ref == 'refs/heads/main' && 'codacy' || '' }}"
      and "\n  workflow_dispatch:\n" in _wf29("codacy-alerts.yml") and "\n    if:" not in _ca297,
      repr(_ca_env297 and _ca_env297.group(0)))

# sonar-main-issues needed nothing more: it has a manual trigger and no `if:`, environment or post
# step, and a manual run on a branch judges main's last analysis as the schedule does.
_sm297 = _wf29("sonar-main-issues.yml")
check("sonar-main-issues: runnable by hand on any branch, and on such a run it judges main and posts nothing",
      "\n  workflow_dispatch:\n" in _sm297 and "\n    if:" not in _job29(_sm297, "sonar-main-issues")
      and "environment:" not in _sm297 and "check-runs" not in _sm297
      and "--branch main ${SHA:+--sha \"$SHA\"}" in _sm297, _sm297[-400:])

# ── 3. codacy-coverage: a manual run does everything but the upload ─────────────────────────────
# A workflow_run job runs main's copy of its file, so its allow-list could be seen working only
# after it merged. A manual run runs the branch's copy: no environment (so no token), the given CI
# run's reports downloaded, checked and rewritten, the reporter fetched and verified, and
# api.codacy.com reached; the reporter is never run. Driven through the step itself.
_cc_wf297 = _wf29("codacy-coverage.yml")
_cc_job297 = _job29(_cc_wf297, "upload")
_cc_run297 = _wf_run_block(_cc_wf297, "Send coverage to Codacy")
_cc_env297 = _wf_step_env(_cc_wf297, "Send coverage to Codacy")
check("codacy-coverage: runnable by hand with a CI run's id; the codacy environment only for a "
      "workflow_run, and the step told when it is a manual run",
      _re297.search(r"\n  workflow_dispatch:\n    inputs:\n      ci_run_id:\n(?:        .*\n)*"
                    r"        required: true\n        type: number\n", _cc_wf297) is not None
      and "\n      name: ${{ github.event_name == 'workflow_run' && 'codacy' || '' }}\n" in _cc_job297
      and "      github.event_name == 'workflow_dispatch' ||\n" in _cc_job297
      and _cc_job297.count("run-id: ${{ github.event.workflow_run.id || inputs.ci_run_id }}") == 2
      and _cc_env297.get("DRY_RUN") == "${{ github.event_name == 'workflow_dispatch' }}",
      repr(_cc_env297))
_SB297 = _tf297.mkdtemp(prefix="p297-")
_cc_good297 = ('<?xml version="1.0" ?>\n<coverage version="7.6" line-rate="0.5">\n<packages><package name=".">'
               '<classes><class name="app.py" filename="panel/app.py"><lines><line number="1" hits="1"/>'
               '</lines></class></classes></package></packages>\n</coverage>\n')


def _cc_dry297(dry, tok="", blocked=False):
    """Run the send step; return (exit status, curl calls, reporter calls, output)."""
    d = _tf297.mkdtemp(dir=_SB297)
    art, rt, bin_ = (os.path.join(d, n) for n in ("art", "rt", "bin"))
    for p in (art, rt, bin_):
        os.makedirs(p)
    with open(os.path.join(art, "coverage.xml"), "w", encoding="utf-8") as fh:
        fh.write(_cc_good297)
    log = os.path.join(d, "log")
    # curl logs each call and writes a stand-in reporter where -o asks; a blocked host fails as
    # Harden-Runner's block makes it fail (no address: curl exit 6). The reporter logs its calls.
    _write_exe29(os.path.join(bin_, "curl"),
                 '#!/bin/sh\necho "CURL $*" >> "$P297_LOG"\n'
                 'case "$*" in *api.codacy.com*) [ -n "$P297_BLOCK" ] && exit 6; exit 0 ;; esac\n'
                 'while [ $# -gt 0 ]; do case "$1" in -o) o="$2"; shift 2;; *) shift;; esac; done\n'
                 'printf \'#!/bin/sh\\necho "REPORTER $*" >> "$P297_LOG"\\n\' > "$o"\n')
    _write_exe29(os.path.join(bin_, "sha256sum"), "#!/bin/sh\ncat >/dev/null\n")
    env = dict(os.environ, PATH=bin_ + os.pathsep + os.environ["PATH"], P297_LOG=log,
               P297_BLOCK="1" if blocked else "", CODACY_PROJECT_TOKEN=tok, HEAD_SHA="e" * 40,
               HEAD_BRANCH="", WR_EVENT="", REPORT_DIR=art, JS_REPORT_DIR=os.path.join(d, "none"),
               RUNNER_TEMP=rt, VERSION="0", SHA256="0" * 64, TMPDIR=d)
    env.pop("DRY_RUN", None)
    if dry is not None:
        env["DRY_RUN"] = dry
    p = _sp297.run(["bash", "-c", _cc_run297], capture_output=True, text=True, timeout=60,  # nosec B603 B607 - the workflow's own step
                   env=env)
    calls = open(log, encoding="utf-8").read().splitlines() if os.path.exists(log) else []
    return (p.returncode, [c for c in calls if c.startswith("CURL")], [c for c in calls if c.startswith("REPORTER")],
            p.stdout + p.stderr)


_cc_dry_ok297 = _cc_dry297("true")
check("codacy-coverage: a manual run checks the report, fetches the reporter, reaches api.codacy.com "
      "and uploads nothing",
      _cc_dry_ok297[0] == 0 and not _cc_dry_ok297[2] and len(_cc_dry_ok297[1]) == 2
      and "codacy-coverage-reporter-linux" in _cc_dry_ok297[1][0]
      and _cc_dry_ok297[1][1].endswith("https://api.codacy.com/")
      and "nothing was uploaded" in _cc_dry_ok297[3], repr(_cc_dry_ok297))
_cc_dry_blk297 = _cc_dry297("true", blocked=True)
check("codacy-coverage: ...and fails when api.codacy.com cannot be reached, as the upload would",
      _cc_dry_blk297[0] != 0 and not _cc_dry_blk297[2], repr(_cc_dry_blk297))
_cc_wr297 = {"false": _cc_dry297("false", "x0"), "unset": _cc_dry297(None, "x0")}
check("codacy-coverage: ...while a workflow_run with the token still uploads (control)",
      all(v[0] == 0 and len(v[2]) == 2 and v[2][0].startswith("REPORTER report --partial -l Python")
          and not any("api.codacy.com/" in c for c in v[1]) for v in _cc_wr297.values()),
      repr(_cc_wr297))

# ── 4. codeql-alerts: a manual run on another branch judges main and posts nothing ──────────────
# Started on a branch, it judged that branch (with no analysis of it, so red) and POSTED the verdict
# on the branch's commit. Now it judges main's head read-only: a verdict posted on main's head from a
# branch's copy of this file would be read by the update gate as main's own. Driven through the ref
# step with a stand-in gh; the judge step takes the commit the ref step chose.
_cqa_wf297 = _wf29("codeql-alerts.yml")
_cqa_run297 = _wf_run_block(_cqa_wf297, "Resolve which ref to judge")
_MAIN297 = "f" * 40


def _cqa_ref297(event, run_ref, gh_ok=True, head_branch="", wr_sha=""):
    """Run the ref step; return (exit status, its outputs, gh calls, output)."""
    d = _tf297.mkdtemp(dir=_SB297)
    out, log = os.path.join(d, "out"), os.path.join(d, "log")
    open(out, "w").close()
    _write_exe29(os.path.join(d, "gh"), '#!/bin/sh\necho "$*" >> "%s"\n%s\n'
                 % (log, ("echo " + _MAIN297) if gh_ok else "exit 1"))
    env = dict(os.environ, PATH=d + os.pathsep + os.environ["PATH"], GITHUB_EVENT_NAME=event,
               GITHUB_OUTPUT=out, GITHUB_REPOSITORY="o/r", HEAD_BRANCH=head_branch,
               WR_BRANCH=head_branch or run_ref.rsplit("/", 1)[-1], WR_SHA=wr_sha, RUN_REF=run_ref,
               RUN_SHA="b" * 40)
    p = _sp297.run(["bash", "-c", _cqa_run297], capture_output=True, text=True, timeout=60,  # nosec B603 B607 - the workflow's own step
                   env=env)
    outs = dict(ln.split("=", 1) for ln in open(out, encoding="utf-8").read().splitlines() if "=" in ln)
    calls = open(log, encoding="utf-8").read() if os.path.exists(log) else ""
    return p.returncode, outs, calls, p.stdout + p.stderr


_cqa_off297 = _cqa_ref297("workflow_dispatch", "refs/heads/qual/x")
check("codeql-alerts: a manual run on another branch judges main's head and posts no verdict",
      _cqa_off297[0] == 0 and _cqa_off297[1].get("ref") == "refs/heads/main"
      and _cqa_off297[1].get("sha") == _MAIN297 and _cqa_off297[1].get("post") == "false"
      and _cqa_off297[1].get("skip") == "false" and "repos/o/r/commits/main" in _cqa_off297[2],
      repr(_cqa_off297))
_cqa_bad297 = _cqa_ref297("workflow_dispatch", "refs/heads/qual/x", gh_ok=False)
check("codeql-alerts: ...and fails, judging nothing, when main's head cannot be read",
      _cqa_bad297[0] != 0 and "sha" not in _cqa_bad297[1], repr(_cqa_bad297))
_cqa_on297 = {"manual on main": _cqa_ref297("workflow_dispatch", "refs/heads/main"),
              "push to main": _cqa_ref297("workflow_run", "refs/heads/main", head_branch="main", wr_sha="a" * 40)}
check("codeql-alerts: ...while a run on main judges its own commit and posts (controls)",
      _cqa_on297["manual on main"][1] == {"ref": "refs/heads/main", "label": "`main`", "sha": "b" * 40,
                                          "post": "true", "skip": "false"}
      and _cqa_on297["push to main"][1].get("sha") == "a" * 40
      and _cqa_on297["push to main"][1].get("post") == "true"
      and not any(v[0] or v[2] for v in _cqa_on297.values()), repr(_cqa_on297))
_cqa_post297 = _wf_step_env(_cqa_wf297, "Fail if that ref has open code-scanning alerts")
_cqa_pif297 = _re297.search(r"- name: Post the verdict on the judged commit\n        if: >-\n((?:          .*\n)+)",
                            _cqa_wf297)
check("codeql-alerts: the judge step reads the commit the ref step chose, and the verdict is posted "
      "only when the ref step says so",
      _cqa_post297.get("SHA") == "${{ steps.ref.outputs.sha }}" and _cqa_pif297 is not None
      and "steps.ref.outputs.post == 'true'" in " ".join(_cqa_pif297.group(1).split()),
      repr((_cqa_post297.get("SHA"), _cqa_pif297 and _cqa_pif297.group(1))))

# ── 5. cflite_cleanup: a manual run on another branch deletes nothing ───────────────────────────
# It ran on main only, so a manual run on a branch was skipped and its allow-list could not be tried
# before it merged. Such a run now lists and judges every artifact as main's does and deletes
# nothing; deleting stays main's. Driven through the step with a stand-in gh that logs each delete.
_cl_job297 = _job29(_wf29("cflite_cleanup.yml"), "cleanup")
_cl_step297 = next((st for st in _steps29(_cl_job297) if "gh api --paginate" in st), "")
check("cflite_cleanup: runs on main, or by hand on any branch, in this repository only; a run off main "
      "is told it is one",
      _if30(_cl_job297) == "github.repository == 'FMSMITH91/linuxgsm-panel' && (github.ref == 'refs/heads/main' "
                           "|| github.event_name == 'workflow_dispatch')"
      and "          DRY_RUN: ${{ github.ref != 'refs/heads/main' }}\n" in _cl_step297, _if30(_cl_job297))


def _cl_run297(dry):
    """Run the cleanup step over a mixed listing; return (exit status, deleted ids, output)."""
    d = _tf297.mkdtemp(dir=_SB297)
    log = os.path.join(d, "log")
    open(log, "w").close()
    _write_exe29(os.path.join(d, "gh"), '#!/bin/bash\ncase "$*" in\n  *--paginate*) printf "%s\\n" "$ROWS" ;;\n'
                 '  *"-X DELETE"*) last="${!#}"; echo "${last##*/}" >> "$GH_LOG" ;;\n  *) exit 1 ;;\nesac\n')
    rows = [_row30("cifuzz-build-address-a", 1, 1), _row30("cifuzz-build-address-b", 2, 3),
            _row30("cifuzz-build-address-c", 3, 20), _row30("cifuzz-build-address-d", 4, 30),
            _row30("cifuzz-build-address-e", 5, 40), _row30("cifuzz-corpus-fuzz_x", 6, 60),
            _row30("cifuzz-build-address-f", 8, 1, branch="pr")]
    env = dict(os.environ, PATH=d + os.pathsep + os.environ["PATH"], GH_LOG=log, REPO="o/r", ROWS="\n".join(rows),
               DRY_RUN=dry)
    p = _sp297.run(["bash", "-c", _runbody29(_cl_step297)], capture_output=True, text=True, timeout=60,  # nosec B603 B607 - the workflow's own step
                   env=env)
    return p.returncode, sorted(int(x) for x in open(log, encoding="utf-8").read().split()), p.stdout


_cl_dry297 = _cl_run297("true")
check("cflite_cleanup: a run off main deletes nothing, and names each artifact main's run would delete",
      _cl_dry297[:2] == (0, []) and _cl_dry297[2].count("would delete ") == 3
      and all("artifact %d," % i in _cl_dry297[2] for i in (4, 5, 8)), repr(_cl_dry297))
_cl_main297 = _cl_run297("false")
check("cflite_cleanup: ...while a run on main deletes them (control)",
      _cl_main297[:2] == (0, [4, 5, 8]) and "would delete" not in _cl_main297[2], repr(_cl_main297))

# ── 6. cflite_nightly: prune and coverage start when the batch run has finished ─────────────────
# They were cflite_cron.yml on its own schedule, 86 minutes after cflite_batch.yml's, and GitHub
# starts scheduled runs hours late at times: a prune could read and rewrite the corpus while a batch
# run was still storing it. One workflow, one schedule, and `needs: batch`; a failed batch (a crash
# found) still leaves a corpus to prune and measure, a cancelled run starts neither. The job names
# are the check names the update gate has seen on main's head, so they stay.
_ng297 = _wf29("cflite_nightly.yml")
_ng_jobs297 = {j: _job29(_ng297, j) for j in ("batch", "prune", "coverage")}
_ng_after297 = "    needs: batch\n    if: ${{ !cancelled() && github.repository == 'FMSMITH91/linuxgsm-panel' && " \
               "github.ref == 'refs/heads/main' }}\n"
check("cflite_nightly: one schedule; batch first, then prune and coverage once it has finished (not on a "
      "cancelled run); the job names kept, and the two old workflows gone",
      _ng297.count("    - cron: ") == 1 and "\n  workflow_dispatch:\n" in _ng297
      and "needs:" not in _ng_jobs297["batch"]
      and all(_ng_after297 in _ng_jobs297[j] for j in ("prune", "coverage"))
      and [_re297.search(r"^    name: (.*)$", _ng_jobs297[j], _re297.M).group(1) for j in _ng_jobs297]
      == ["batch fuzz (${{ matrix.sanitizer }})", "prune the corpus", "fuzzing coverage report"]
      and not any(os.path.exists(os.path.join(_root, ".github", "workflows", f))
                  for f in ("cflite_batch.yml", "cflite_cron.yml")),
      repr({j: _re297.findall(r"^    (?:needs|if): .*$", t, _re297.M) for j, t in _ng_jobs297.items()}))

_shutil297.rmtree(_SB297, ignore_errors=True)
