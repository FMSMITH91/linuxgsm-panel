"""Part 113 of the unit suite: the pre-merge adversarial review of review 1017b (pass 19, fixer J).

* The OS Updates card's "another upgrade is running" refusal no longer says the panel did not start
  it: the panel's own host bootstrap (`apt-get full-upgrade`, the apt-full-upgrade verb) reads as
  exactly that upgrade, measured with the real pgrep over a stand-in named as the bootstrap.
* A helper older than the `os-update-own-running` verb answers it "unknown verb" (rc 2): Install
  updates then says to re-run install.sh, not "try again", on the panel host and a local host row.
* The panel-host reboot with no host row (no game servers on the panel's own host) is held by the
  panel's own work, as the row path is: a database repair starting, a full backup running.

HOW IT RUNS. As part111 does: on part12's Flask app and stand-ins, part12's transport tripwire re-armed
for this part's duration, every stub undone in its finally. Real pgrep runs over sleeping stand-in
processes whose argv is the verb's own. Nothing reaches a host, sudo, tmux or the checkout's data/.
"""
import json
import os
import subprocess as _sp113  # nosec B404 - real pgrep over this part's own sleeping stand-ins
import sys as _sys113
import time as _time113
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9_arm, _p9_client, _p9_core, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_so)
from unit.part110 import _Unread110
from panel.core import panel_state as _ps113
from panel.routes import panel_backup as _pb113
from panel.ops.ssh_manager import hosts as _hosts113
from panel.security import privileged as _priv113

_TRIP113_START = len(_P9_TRIPPED)
_ROOT113 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _catalogs113():
    """{lang: every key in translations/<lang>/*.json} for es and fr."""
    keys = {}
    for lg in ("es", "fr"):
        keys[lg] = set()
        root = os.path.join(_ROOT113, "translations", lg)
        for name in sorted(os.listdir(root)):
            if name.endswith(".json"):
                with open(os.path.join(root, name), encoding="utf-8") as fh:
                    keys[lg] |= set(json.load(fh))
    return keys


def _pgrep_rc113(verb):
    """`verb`'s real pgrep, run here: its exit code (0 matched, 1 not)."""
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    return _sp113.run(_priv113.tool_argv(verb, []), capture_output=True, text=True,  # nosec B603
                      timeout=20, check=False).returncode


# ── R2: the bootstrap's own apt-get full-upgrade is "another package upgrade" ───────────────────
def _bootstrap_busy113():
    """The panel host's bootstrap upgrade, running: refused, with a sentence that is true of it."""
    words = _priv113.tool_argv("apt-full-upgrade", [])
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    stand_in = _sp113.Popen(  # nosec B603 - a sleeping stand-in; its words are only argv
        [_sys113.executable, "-c", "import time; time.sleep(60)"] + words,
        stdout=_sp113.DEVNULL, stderr=_sp113.DEVNULL)
    try:
        up, own = _pgrep_rc113("apt-upgrade-running"), _pgrep_rc113("os-update-own-running")
    finally:
        stand_in.kill()
        stand_in.wait()
    answer = _p9_so.r31b_update_running_answer(up, lambda: own)
    msg = _p9_so.R31B_UPDATE_BUSY
    check("os update start (real pgrep): the panel's own bootstrap `apt-get full-upgrade` is another "
          "upgrade running — refused, nothing watched",
          (up, own, answer) == (0, 1, (False, msg)), repr((words, up, own, answer)))
    keys = _catalogs113()
    check("os update start: ...and the refusal does not say the panel did not start it (the bootstrap "
          "is the panel's own), in English, Spanish and French",
          "did not start" not in msg and "panel" not in msg.lower()
          and all(msg in k for k in keys.values()), repr((msg, {lg: msg in k for lg, k in keys.items()})))


# ── R3: a helper older than os-update-own-running ───────────────────────────────────────────────
def _old_helper_answers113(own_answer, calls):
    """A verb runner as a host answers: upgrade probe matched, own probe `own_answer`, start recorded."""
    def _rv(verb, args=(), **k):
        calls.append(verb)
        if verb == "apt-upgrade-running":
            return "", "", 0
        if verb == "os-update-own-running":
            return own_answer
        return _priv113.OS_UPDATE_STARTED, "", 0
    return _rv


def _old_helper113():
    """unknown_verb from the own-job probe: re-run install.sh, never "try again"; nothing is started."""
    unknown = ("", "panel-helper: unknown verb 'os-update-own-running'", 2)
    want = (False, _p9_so.R31J_UPDATE_OLD_HELPER)
    got = {}
    for where in ("panel host", "local host row", "remote (control)"):
        calls = []
        rv = _old_helper_answers113(unknown, calls)
        if where == "panel host":
            _p9_patch(_p9_so, "_run_verb", rv)
            _p9_patch(_p9_so, "_can_escalate", lambda: True)
            ans = _p9_so.os_run_update()
        else:
            _p9_patch(_p9_core, "run_privileged", lambda server, verb, *a, _rv=rv, **k: _rv(verb, *a, **k))
            ans = _hosts113.remote_os_update_start(NS(id=None, is_local=where == "local host row",
                                                      host="p113.example.invalid"))
        got[where] = (ans, "os-update-run" in calls)
    check("os update start: a helper older than os-update-own-running (unknown verb, rc 2) says to "
          "re-run install.sh, on the panel host and a local host row, and starts nothing",
          got["panel host"] == (want, False) and got["local host row"] == (want, False), repr(got))
    check("os update start: ...a remote's rc 2 (no helper there) is still 'couldn't check' (control)",
          got["remote (control)"] == ((False, _p9_so.R31B_UPDATE_UNCHECKED), False), repr(got))
    keys = _catalogs113()
    check("os update start: ...the install.sh refusal is in the Spanish and French catalogs",
          all(_p9_so.R31J_UPDATE_OLD_HELPER in k for k in keys.values()), repr(sorted(keys)))


# ── R4: the no-row reboot asks the panel's own blockers ─────────────────────────────────────────
def _no_row_reboot113(client):
    """No local host row: a repair starting or a full backup running holds the reboot (409), as the row path does."""
    sent = []
    _p9_patch(_p9_so, "server_reboot", lambda delay=5: (sent.append(delay), (True, "Server will reboot"))[1])
    _p9_patch(_pb113, "RemoteServer", _Unread110(False))
    got = {}
    for case in ("repair starting", "full backup", "nothing running"):
        _p9_patch(_p9_so, "_r30a_repair_launched",
                  {"dir": _p9_so.PANEL_DIR, "ts": _time113.time()} if case == "repair starting" else {})
        held = case == "full backup" and _ps113._full_backup_lock.acquire(blocking=False)
        try:
            n0 = len(sent)
            r = client.post("/api/server-management/reboot", json={"delay": 5})
            body = _p9_json(r)
            got[case] = (r.status_code, body.get("error"),
                         [b.get("kind") for b in body.get("blockers") or ()], len(sent) - n0)
        finally:
            if held:
                _ps113._full_backup_lock.release()
    check("reboot route (no host row): a database repair starting or a full backup running holds the "
          "reboot with 409 blocked and sends none (the repair was killed mid-rebuild)",
          got["repair starting"] == (409, "blocked", ["db_repair"], 0)
          and got["full backup"] == (409, "blocked", ["full_backup"], 0), repr(got))
    check("reboot route (no host row): ...and with nothing of the panel's running it reboots as before "
          "(control)", got["nothing running"][0] == 200 and got["nothing running"][3] == 1, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
try:
    _p9_arm(who="part113")
    _bootstrap_busy113()
    _old_helper113()
    _no_row_reboot113(_p9_client(P9_ADMIN))
finally:
    _p9_restore_all()

check("part113: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP113_START, repr(_P9_TRIPPED[_TRIP113_START:][:6]))
