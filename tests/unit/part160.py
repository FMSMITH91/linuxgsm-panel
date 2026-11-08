"""Part 160 of the unit suite: scheduled wipes and the host reboot's quiet window (review 1108 B).

Held here:
* A wipe whose start afterwards fails is a wipe that happened, with the exit code LinuxGSM v26.5.0
  really gives it: 1 (the failed start logs FAIL, its own core_exit.sh only unsets exitbypass, and
  command_start.sh's last core_exit.sh exits 1 from inside the wipe). Driven through the sweep, so
  the card's last run and the audit row are what is checked.
* LinuxGSM answering "Wipe not required" (it never stopped the server) ends the monitor's quiet window
  the wipe opened, as its players-online refusal does; the control (a wipe done) leaves it for the
  restart that follows.

HOW IT RUNS. Routes, workers and the reboot job's steps on part12's app with its transport tripwire
armed and every host call stubbed (part155's sweep; a stand-in clock for the window). Nothing reaches
a host or data/.
"""
from unit.part01 import check
from unit.part12 import _P9_TRIPPED, _p9_arm, _p9_audit, _p9_audit_count, _p9_restore_all
from unit.part155 import _sweep155
from panel.services import wipe_schedule as _ws160

_TRIP160_START = len(_P9_TRIPPED)

# ── 1. a wipe whose start after it fails (exit 1) ───────────────────────────────────────────────
# What LinuxGSM v26.5.0 prints for a running Rust server's full wipe whose start then fails
# (command_wipe.sh: stop, delete, "Success! Full wipe", alert, start; command_start.sh: "Unable to start").
_STARTFAIL160 = ("[ WARN ] Wiping rustserver: Server wipe will reset the map data\n"
                 "[  OK  ] Stopping rustserver: Rust Server\n"
                 "[  OK  ] Wiping rustserver: removing .map file(s)\n"
                 "Success! Full wipe\n"
                 "[ FAIL ] Starting rustserver: Unable to start Rust Server\n")
try:
    _p9_arm(who="part160")
    _sf_n160 = _p9_audit_count("wipe_server")
    _sf160 = _sweep155((True, "Backed up", False), wipe_out=(_STARTFAIL160, "", 1))
    _sf_aud160 = _p9_audit("wipe_server")
finally:
    _p9_restore_all()
_sf_last160 = (_sf160.get("entry") or {}).get("last") or {}
check("1108 r38b wipe: a wipe whose start afterwards fails, with the exit 1 LinuxGSM v26.5.0 gives it, "
      "is recorded as a wipe done (said with that failure), not as 'Scheduled wipe did not run'",
      _sf160["cmds"] == ["full-wipe"] and _sf_last160.get("ok") is True
      and "reported a failure after it: [ FAIL ] Starting rustserver" in (_sf_last160.get("detail") or "")
      and _p9_audit_count("wipe_server") == _sf_n160 + 1 and _sf_aud160.success is True
      and "alerts" not in _sf160, repr((_sf160, _sf_aud160)))
_lone160 = _ws160.judge("removing .map file(s)... OK\nSuccess! Map wipe\n", 124, "wipe")
_before160 = _ws160.judge("removing .map file(s)... FAIL\nSuccess! Map wipe\n", 1, "wipe")
_notreq160 = _ws160.judge("[  OK  ] Wiping rustserver: Wipe not required\n", 1, "wipe")
check("1108 r38b wipe judge: a non-zero exit after the success line with no FAIL after it is still a "
      "wipe, said with the exit code; a FAIL before the line, or 'Wipe not required' with a non-zero "
      "exit, is still a failure",
      _lone160[0] == "wiped" and str(_lone160[1]) == "Map wipe done, but LinuxGSM exited 124 after it"
      and _before160[0] == "failed" and _notreq160[0] == "failed", repr((_lone160, _before160, _notreq160)))

# ── 2. "Wipe not required" ends the quiet window ────────────────────────────────────────────────
try:
    _p9_arm(who="part160")
    _nothing160 = _sweep155((True, "Backed up", False),
                            wipe_out=("[  OK  ] Wiping rustserver: Wipe not required\n", "", 0))
    _p9_arm(who="part160")
    _done160 = _sweep155((True, "Backed up", False))
finally:
    _p9_restore_all()
check("1108 r38b wipe sweep: LinuxGSM answering 'Wipe not required' (the server was never stopped) ends "
      "the monitor's quiet window the wipe opened; a wipe done leaves it for its restart (control)",
      _nothing160["cmds"] == ["full-wipe"] and _nothing160.get("window_during") is True
      and _nothing160["window_after"] is False
      and ((_nothing160.get("entry") or {}).get("last") or {}).get("ok") is True
      and _done160.get("window_during") is True and _done160["window_after"] is True,
      repr((_nothing160, _done160)))

check("part160: no check reached a host (the transport tripwire stayed quiet)",
      len(_P9_TRIPPED) == _TRIP160_START, repr(_P9_TRIPPED[_TRIP160_START:]))
