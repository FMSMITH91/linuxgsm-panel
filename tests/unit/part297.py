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
import re as _re297

from unit.part01 import check
from unit.part223 import _egress223
from unit.part29 import _job29, _wf29

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
