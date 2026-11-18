"""Part 254 of the unit suite: the update gate and timer-started check runs.

* A daily scheduled job (the long fuzz pass) checks out main's newest commit, so its run lands on the
  release that was just published, and GitHub can start it hours late. Held as 'pending', it kept that
  release from being offered for its whole run, while GitHub's own green tick (which doesn't count it)
  already showed the commit as done. A RUNNING scheduled run no longer holds a commit; a FAILED one
  still does, and when the scheduled runs can't be read nothing is dropped.

HOW IT RUNS. In-process; urlopen is a stand-in answering the two GitHub API URLs. Nothing leaves.
"""
import io as _io254
import json as _json254
import urllib.error as _ue254

from unit.part01 import _r21d_urlopen_of, check
from unit.part12 import _p9_patch, _p9_restore_all
from panel.ops import system_ops as _so254


class _Resp254(_io254.BytesIO):
    headers = {}
    code = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _run254(name, status, conclusion, suite):
    return {"name": name, "status": status, "conclusion": conclusion, "check_suite": {"id": suite}}


_PUSH_OK254 = _run254("checks (ubuntu-24.04 · py3.12)", "completed", "success", 1)


def _state254(runs, scheduled, sched_error=False):
    """(_remote_ci_state_read's answer, the URLs asked) for these check runs and scheduled suites."""
    asked = []

    def _open(req, timeout=8):
        url = req.full_url
        asked.append(url.split("?")[0].rsplit("/", 1)[-1])
        if "/check-runs" in url:
            return _Resp254(_json254.dumps({"check_runs": runs}).encode())
        if sched_error:
            raise _ue254.HTTPError(url, 403, "rate limited", {}, None)
        return _Resp254(_json254.dumps({"workflow_runs": [
            {"event": "schedule", "check_suite_id": s} for s in scheduled]}).encode())
    _p9_patch(_r21d_urlopen_of(_so254), "urlopen", _open)
    _p9_patch(_so254, "_repo_slug", lambda: "o/r")
    _p9_patch(_so254, "_ci_suite_expected", lambda *a: False)
    try:
        return _so254._remote_ci_state_read("a" * 40, {}), asked
    finally:
        _p9_restore_all()


def _scheduled254():
    fuzz = "batch fuzz (address)"
    got = {
        "scheduled run still running": _state254(
            [_PUSH_OK254, _run254(fuzz, "in_progress", None, 7)], [7])[0],
        "scheduled run failed": _state254(
            [_PUSH_OK254, _run254(fuzz, "completed", "failure", 7)], [7])[0],
        "a push run still running": _state254(
            [_PUSH_OK254, _run254("CodeQL", "in_progress", None, 8)], [7])[0],
        "scheduled runs unreadable": _state254(
            [_PUSH_OK254, _run254(fuzz, "in_progress", None, 7)], [7], sched_error=True)[0],
        "nothing running: asks once": _state254([_PUSH_OK254], [7])[1],
    }
    check("update gate: a check run a timer started that is still RUNNING doesn't hold a release (it held "
          ".18.7 ~20 min while GitHub showed it green); a failed one still blocks, a running push run still "
          "holds, an unreadable answer drops nothing, and nothing running costs no extra request",
          got == {"scheduled run still running": "passing", "scheduled run failed": "failing",
                  "a push run still running": "pending", "scheduled runs unreadable": "pending",
                  "nothing running: asks once": ["check-runs"]}, repr(got))


try:
    _scheduled254()
finally:
    _p9_restore_all()
