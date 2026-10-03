"""Part 30 of the unit suite: the CI review's fixes to the fuzz workflows and the CodeQL triggers.

The adversarial review of the vendor-documentation audit found these on the integrated branch:
* E3: ClusterFuzzLite logs a failed upload and goes on, so a build, batch, prune or coverage job
  could pass having stored nothing. Each producer now ends by listing its own run's artifacts.
* E4: cflite_build.yml's concurrency group cancelled a build on main when the next merge landed,
  and "cancelled" on main's head reads as a failure to the panel's update gate and deploy.yml.
* E5: codeql.yml's and security-code.yml's concurrency groups were workflow+ref, so the Monday
  scheduled run cancelled an in-progress push run on main. The event is part of the group now.
* SEC1: the fuzz-artifact guard runs again directly before the fuzzing step reads the corpus.
* SEC2: cflite_cleanup.yml deletes foreign cifuzz-* artifacts on a schedule; it must never fail,
  because its check lands on main's head.

HOW IT RUNS. It reads the workflow files as YAML (and as text where a comment or a step body is the
point); nothing runs.
"""
import os

import yaml as _yaml30

from unit.part01 import check
from unit.part05 import _root

_WF30 = os.path.join(_root, ".github", "workflows")


def _wf30(name):
    with open(os.path.join(_WF30, name), encoding="utf-8") as fh:
        return _yaml30.safe_load(fh)


def _steps30(job):
    return [(s.get("name") or s.get("uses") or "", s) for s in job.get("steps", [])]


_STORE30 = "This run stored the fuzz artifacts it made"
_GUARD30 = "Every stored fuzz artifact was made on main here"

# ── E3: every producer ends by checking its own run stored what it made ─────────────────────────
_producers30 = [("cflite_build.yml", "build"), ("cflite_batch.yml", "batch"),
                ("cflite_cron.yml", "prune"), ("cflite_cron.yml", "coverage")]
_store_bodies30, _store_bad30 = [], []
for _f30, _j30 in _producers30:
    _st30 = _steps30(_wf30(_f30)["jobs"][_j30])
    _names30 = [n for n, _s in _st30]
    if not _names30 or _names30[-1] != _STORE30:
        _store_bad30.append("%s/%s: last step is %r" % (_f30, _j30, _names30[-1:] or None))
        continue
    _body30 = _st30[-1][1].get("run", "")
    _store_bodies30.append(_body30)
    if "actions/runs/${GITHUB_RUN_ID}/artifacts" not in _body30 or "exit 1" not in _body30:
        _store_bad30.append("%s/%s: the step does not list this run's artifacts and fail" % (_f30, _j30))
    if (_wf30(_f30)["jobs"][_j30].get("permissions") or {}).get("actions") != "read":
        _store_bad30.append("%s/%s: no actions: read to list them" % (_f30, _j30))
check("cflite: every producer (build, batch, prune, coverage) ends by checking its own run stored "
      "the artifacts it made, with one body for all (ClusterFuzzLite logs a failed upload and goes on)",
      not _store_bad30 and len(_store_bodies30) == 4 and len(set(_store_bodies30)) == 1,
      repr(_store_bad30 or [len(set(_store_bodies30))]))

# ── E4: the build on main is never cancelled by the next merge ──────────────────────────────────
_bjob30 = _wf30("cflite_build.yml")["jobs"]["build"]
check("cflite: the continuous build on main has no concurrency group (a cancelled build on main's "
      "head is a failure to the update gate and deploy)",
      "concurrency" not in _bjob30 and "concurrency" not in _wf30("cflite_build.yml"),
      repr(_bjob30.get("concurrency")))

# ── E5: a scheduled CodeQL or security-code run never cancels the push run of the same ref ───────
_conc30 = {f: (_wf30(f).get("concurrency") or {}).get("group", "")
           for f in ("codeql.yml", "security-code.yml")}
check("CodeQL and security-code: the concurrency group includes the event, so the Monday schedule "
      "does not cancel an in-progress push run on main",
      all("${{ github.event_name }}" in g and "${{ github.ref }}" in g for g in _conc30.values()),
      repr(_conc30))

# ── SEC1: the guard runs before the build, directly before fuzzing, and after it ────────────────
_pr30 = _steps30(_wf30("cflite_pr.yml")["jobs"]["code-change"])
_pr_names30 = [n for n, _s in _pr30]
_fuzz_i30 = next((i for i, n in enumerate(_pr_names30) if n.startswith("Fuzz the changed code")), -1)
_guards30 = [i for i, n in enumerate(_pr_names30) if n.startswith(_GUARD30)]
_gbodies30 = {_pr30[i][1].get("run", "") for i in _guards30}
check("cflite PR: the foreign-artifact guard runs three times (before the build, directly before "
      "fuzzing, after it), with one body",
      len(_guards30) == 3 and _fuzz_i30 > 0 and _guards30[1] == _fuzz_i30 - 1
      and _guards30[0] < _fuzz_i30 < _guards30[2] and len(_gbodies30) == 1,
      repr((_guards30, _fuzz_i30, len(_gbodies30))))

# ── SEC2: the cleanup is scheduled on main only, may only touch artifacts, and never fails ──────
_cl30 = _wf30("cflite_cleanup.yml")
_cl_on30 = _cl30.get(True) or _cl30.get("on") or {}
_cl_job30 = _cl30["jobs"]["cleanup"]
_cl_run30 = "\n".join(s.get("run", "") for s in _cl_job30["steps"])
check("cflite cleanup: schedule and manual runs only, on this repository's main, with actions: write "
      "and nothing else, and it never fails (its check lands on main's head)",
      set(_cl_on30) == {"schedule", "workflow_dispatch"}
      and _cl_job30.get("permissions") == {"actions": "write"}
      and "refs/heads/main" in _cl_job30.get("if", "")
      and "exit 1" not in _cl_run30 and "set -euo" not in _cl_run30 and "::error::" not in _cl_run30
      and "::warning::" in _cl_run30, repr((sorted(_cl_on30), _cl_job30.get("permissions"))))
