"""Part 160 of the unit suite: scheduled wipes and the host reboot's quiet window (review 1108 B).

Held here:
* A wipe whose start afterwards fails is a wipe that happened, with the exit code LinuxGSM v26.5.0
  really gives it: 1 (the failed start logs FAIL, its own core_exit.sh only unsets exitbypass, and
  command_start.sh's last core_exit.sh exits 1 from inside the wipe). Driven through the sweep, so
  the card's last run and the audit row are what is checked.
* LinuxGSM answering "Wipe not required" (it never stopped the server) ends the monitor's quiet window
  the wipe opened, as its players-online refusal does; the control (a wipe done) leaves it for the
  restart that follows.
* A host reboot's census refuses a LinuxGSM `debug` running on a server (foreground, outside tmux:
  the server reads as stopped and is in no plan). The quiet window before the reboot waits on it, so
  unrefused the reboot stopped every server, waited ARM_WAIT and rolled back, every time.
* That quiet window opens only on a read pass that stays inside one minute of the host's clock: each
  read is judged on its own second, so a pass slowed by an account that did not answer (20 s, left
  out) read one account at :46 and the next at :06, and a cron line at :00 on the first was cut.

HOW IT RUNS. Routes, workers and the reboot job's steps on part12's app with its transport tripwire
armed and every host call stubbed (part155's sweep; a stand-in clock for the window). Nothing reaches
a host or data/.
"""
from types import SimpleNamespace as _NS160

from unit.part01 import check
from unit.part12 import P9_GS, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_audit_count, _p9_patch, _p9_restore_all
from unit.part155 import _sweep155
from panel.db.models import GameServer as _GS160, db as _db160
from panel.services import host_reboot as _hr160, reboot_words as _rw160, wipe_schedule as _ws160

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

# ── 3. the reboot census and a LinuxGSM `debug` ─────────────────────────────────────────────────
_probe160 = _hr160._probe_sh("u160", "vhserver")
_parsed160 = _hr160.parse_probe("SESSION=0\nLOCK=none\nASIDE=none\nCRON=\nINFLIGHT=1\nMAINT=0\nDEBUG=1\n"
                                "WARN=0\nBOOT=b\nMID=m\nNOW=1\nSEC=20\nPROBE_OK\n")
try:
    _p9_patch(_hr160._mon, "_host_reachable", lambda remote: True)
    _p9_patch(_hr160, "_row_blockers", lambda rows: [])
    _p9_patch(_hr160, "_host_blockers", lambda remote: [])
    _p9_patch(_hr160, "_count_players", lambda running, primaries: ([], []))
    _p9_patch(_hr160._mon, "_batched_slots", lambda rows: {})
    with _p9.app_context():
        _gs160 = _db160.session.get(_GS160, P9_GS)
        _quiet160 = {g.id: {"session": 0, "inflight": 0, "maint": 0, "debug": 0, "warn": 0}
                     for g in _GS160.query.filter_by(remote_id=_gs160.remote_id).all()}
        _dbg160 = dict(_quiet160)
        _dbg160[P9_GS] = _parsed160
        _cd160 = _hr160.host_player_state(_gs160.remote, probes=_dbg160)
        _cq160 = _hr160.host_player_state(_gs160.remote, probes=dict(_quiet160))
        _nm160 = _gs160.name
except Exception as _exc160:  # noqa: BLE001 - reported by the check below, by name
    _cd160 = _cq160 = {"state": repr(_exc160)[:120], "blockers": []}
    _nm160 = None
finally:
    _p9_restore_all()
check("1108 r38b reboot census: a LinuxGSM `debug` running on a server (it reads as stopped: no tmux) "
      "refuses the reboot before anything is stopped, named as a LinuxGSM action on it; the probe reads "
      "it with its own pgrep; a host with none is not blocked (control)",
      """echo "DEBUG=$(pgrep -u "$(id -un)" -fc '/[v]hserver (debug|d)( |$)')";""" in _probe160
      and _parsed160.get("debug") == 1 and _hr160.parse_probe("")["debug"] is None
      and _cd160["state"] == "blocked"
      and [(b["kind"], b["name"], b["detail"]) for b in _cd160["blockers"]] == [("action", _nm160, "debug")]
      and "a LinuxGSM action on %s" % _nm160 in str(_rw160.blocked_sentence(_cd160["blockers"]))
      and _cq160["state"] != "blocked", repr((_probe160[-400:], _parsed160, _cd160, _cq160)))


# ── 4. the quiet window's read pass stays inside one minute ─────────────────────────────────────
def _pass160(slow):
    """_Job._await_window over a plan account and two other accounts, `slow` the one that does not answer.

    The host's clock is at second 46 when the window starts; a read that does not answer costs 20 s.
    Returns (answer, [(account, host minute, sec)] of every read that answered).
    """
    clock, reads = [0.0], []

    def probe(remote, user, selfnames):
        if user == slow:
            clock[0] += 20.0
            return {"sec": None, "boot": None, "inflight": None}
        at = 46 + clock[0]
        reads.append((user, int(at // 60), int(at % 60)))
        clock[0] += 0.5
        return {"sec": int(at % 60), "boot": "b", "inflight": 0}

    def nap(sec):
        clock[0] += sec
    rows = [_NS160(short_name="acctb", lgsm_name="vhserver"), _NS160(short_name="acctc", lgsm_name="csserver")]
    try:
        _p9_patch(_hr160, "window_probe", probe)
        _p9_patch(_hr160, "_settled_rows", lambda r: rows)
        _p9_patch(_hr160, "time", _NS160(monotonic=lambda: clock[0], sleep=nap, time=lambda: clock[0]))
        with _p9.app_context():
            j = object.__new__(_hr160._Job)
            j.remote, j.remote_id = None, -1
            j.entries = [{"id": P9_GS, "user": "accta", "selfname": "gmodserver", "owner": "panel"}]
            try:
                return j._await_window(), reads
            except Exception as exc:  # noqa: BLE001 - reported by the check below, by name
                return repr(exc)[:120], reads
    finally:
        _p9_restore_all()


_slow160 = _pass160("acctb")
_fast160 = _pass160(None)
check("1108 r38b reboot: the quiet window does not open on a read pass that crossed a minute (an account "
      "that did not answer between a read at :46 and one at :06); it opens on the next pass, whose reads "
      "share a minute; a pass with every account answering opens at once (control)",
      _slow160[0] is None and len(_slow160[1]) == 4 and _slow160[1][1][1] != _slow160[1][0][1]
      and _slow160[1][2][1] == _slow160[1][3][1]
      and _fast160[0] is None and len(_fast160[1]) == 3, repr((_slow160, _fast160)))

check("part160: no check reached a host (the transport tripwire stayed quiet)",
      len(_P9_TRIPPED) == _TRIP160_START, repr(_P9_TRIPPED[_TRIP160_START:]))
