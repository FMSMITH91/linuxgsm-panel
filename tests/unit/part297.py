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
import subprocess as _sp297  # nosec B404 - runs bash on the workflows' own steps with stand-in programs
import tempfile as _tf297

from unit.part01 import check
from unit.part06 import _wf_run_block, _wf_step_env
from unit.part223 import _egress223
from unit.part29 import _job29, _wf29, _write_exe29

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
