"""Part 162 of the unit suite: scheduled wipes, what may run beside one, and LinuxGSM's alert settings (review 1109 A).

Held here:
* Saving the schedule while its wipe is pending keeps that wipe (the save that unticks "wait until
  empty" to force it runs it on the next sweep); a save that reschedules it, or turns it off, drops
  it with an audit row saying so.
* A wipe whose connection drops after LinuxGSM's wipe was sent (paramiko's ConnectionError marked
  command_started) is ended, alerted and never run again; one never sent stays pending for the next try.
* A wipe whose server ignored the graceful `quit` and was stopped by LinuxGSM's tmux kill is a wipe
  that happened; "Unable to stop", or a removal FAIL, is still a failure.
* The host reboot's census and quiet window see LinuxGSM's wipe and the other file-changing
  commands by every name core_getopt.sh v26.5.0 gives them; the monitor sees an operator's cron wipe.
* LinuxGSM's own backup-postponed alert counts only through a channel whose settings are the
  operator's: blank, or the placeholder _default.cfg v26.5.0 ships, is not.
* Nothing the panel runs on a server goes beside its scheduled wipe: the backups (the hourly and
  queued sweeps, "Back up now"), a queued stop/restart, the server page's and bots' actions, a mods
  install and Run now refuse or wait while it runs, and the wipe waits while a queued stop/restart or
  a server-page action runs.

HOW IT RUNS. Routes, sweeps and workers on part12's app with its transport tripwire armed and every
host call stubbed. Nothing reaches a host or data/.
"""
import re as _re162
import time as _time162

from unit.part01 import check
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client,
                         _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_row,
                         _p9_set)
from panel.core import panel_state as _ps162
from panel.ops.ssh_manager import files as _files162
from panel.routes import _shared as _sh162, server_detail as _sd162
from panel.routes import wipe_schedule as _wr162
from panel.services import host_reboot as _hr162, lgsm_players as _lgp162, monitoring as _mon162
from panel.services import reboot_words as _rw162, wipe_schedule as _ws162

_TRIP162_START = len(_P9_TRIPPED)
_DONE162 = "[  OK  ] Stopping rustserver: Rust Server\n[ START ] Wiping rustserver: Full wipe\nSuccess! Full wipe\n"


class _Dropped162(Exception):
    """paramiko's mid-command drop as ssh_manager raises it (ConnectionError with command_started)."""


# The schedules here run against the real clock, so a fixed "0 19 * * 4" made a fresh wipe due when a
# run (plus the drop check's retry gap) crossed Thursday 19:00 UTC: a CI run at 18:56 saw two wipes.
# These daily times sit 11-12 hours from now, so no scheduled time falls inside a run.
_H162 = (_time162.gmtime().tm_hour + 12) % 24
_CRON162, _CRON2_162 = "0 %d * * *" % _H162, "30 %d * * *" % _H162


def _new_rust162(name):
    return _p9_new_server(P9_HOST, "rustserver", "rust", 28015, name=name)


def _pending162(sid, **extra):
    """Store a full wipe of `sid` that has been pending an hour, its backup taken, waiting for players."""
    with _p9.app_context():
        from panel.db.models import GameServer, db
        gs = db.session.get(GameServer, sid)
        entry = dict(_ws162.identity(gs), kind="full", preset="custom", at="", cron=_CRON162, tz="UTC",
                     wait_empty=True, anchor=_time162.time() - 7200, pending_since=_time162.time() - 3600,
                     backed_up=int(_time162.time() - 3500), tried=0, wait="LinuxGSM did not wipe: 2 player(s) online")
    entry.update(extra)
    _ws162.put(sid, entry)


def _wipe_stubs162(got, wipe=None):
    """Stub every host call a sweep makes; `wipe(action)` answers LinuxGSM's wipe (default: done)."""
    def _run(remote, user, action, **k):
        got["cmds"].append(action)
        got.setdefault("jobs_at_wipe", []).append(_ps162.r36j_route_jobs(got["sid"]))
        return wipe(action) if wipe else (_DONE162, "", 0)

    def _bk(*a, **k):
        got["backups"].append(a[2])
        return (True, "Backed up", False)
    _p9_patch(_sh162, "_marked_backup", _bk)
    _p9_patch(_sh162, "_alert_backup", lambda *a, **k: got["alerts"].append(a[2]))
    _p9_patch(_sh162, "_reboot_holds", lambda gs: False)
    _p9_patch(_lgp162, "timeout_for", lambda *a, **k: 900)
    _p9_patch_sm("run_as_game_user", _run)


def _sweep162(sid, got, now=None):
    try:
        _wr162.sweep(_p9, now=now)
    except Exception as exc:  # noqa: BLE001 - recorded, and named by the check that reads it
        got["raised"] = repr(exc)
    got["entry"] = _ws162.get(sid)


# ── 1. a save while the wipe is pending ─────────────────────────────────────────────────────────
def _save162(body, extra=None):
    """A pending wipe, then the route's save with `body`, then one sweep. Returns what happened."""
    sid = _new_rust162("p162-save")
    got = {"sid": sid, "cmds": [], "backups": [], "alerts": []}
    try:
        _pending162(sid, **(extra or {}))
        resp = _p9_client(P9_ADMIN).post("/api/server/%d/wipe-schedule" % sid, json=body)
        got["status"] = resp.status_code
        got["saved"] = dict(_ws162.get(sid) or {})
        got["dropped"] = _p9_audit("wipe_server")
        _p9_arm(who="part162")
        _wipe_stubs162(got)
        _sweep162(sid, got)
        return got
    finally:
        _p9_restore_all()
        _ws162.put(sid, None)
        _mon162._end_offline_window(sid)
        _p9_delete_server(sid)


_BODY162 = {"enabled": True, "kind": "full", "preset": "custom", "cron": _CRON162, "tz": "UTC"}
_force162 = _save162(dict(_BODY162, wait_empty=False))
_moved162 = _save162(dict(_BODY162, cron=_CRON2_162))
_off162 = _save162({"enabled": False})
_fl162 = ((_force162.get("entry") or {}).get("last") or {})
check("1109 r39a wipe save: unticking 'wait until empty' on a wipe pending for players keeps that wipe "
      "(its pending time and backup carried, tried at once) and the next sweep runs it, without another backup",
      _force162["status"] == 200 and _force162["saved"].get("pending_since")
      and _force162["saved"].get("backed_up") and _force162["saved"].get("tried") == 0
      and _force162["saved"].get("wait_empty") is False
      and _force162["cmds"] == ["full-wipe"] and _force162["backups"] == [] and _fl162.get("ok") is True,
      repr(_force162))
check("1109 r39a wipe save: a save that reschedules a pending wipe, or turns the schedule off, drops it "
      "with an audit row naming the drop and the wait; the rescheduled one runs at its new time (nothing now)",
      _moved162["status"] == 200 and not _moved162["saved"].get("pending_since") and _moved162["cmds"] == []
      and "not wiped: its schedule was turned off or changed while the wipe waited (LinuxGSM did not wipe: 2"
      in _moved162["dropped"].detail and _moved162["dropped"].success is False
      and _off162["status"] == 200 and _off162["cmds"] == []
      and "not wiped: its schedule was turned off or changed" in _off162["dropped"].detail,
      repr((_moved162, _off162)))


# ── 2. the connection drops while LinuxGSM's wipe runs ──────────────────────────────────────────
def _drop162(started):
    """A pending wipe whose run raises; then a second sweep past the retry gap. Returns what happened."""
    sid = _new_rust162("p162-drop")
    got = {"sid": sid, "cmds": [], "backups": [], "alerts": []}

    def _raise(action):
        exc = ConnectionError("Command failed: Socket is closed")
        exc.command_started = started
        raise exc
    try:
        _pending162(sid)
        _p9_arm(who="part162")
        _wipe_stubs162(got, wipe=_raise)
        _sweep162(sid, got)
        got["first"] = dict(got["entry"] or {})
        got["window"] = _mon162._offline_expected(sid)
        _sweep162(sid, got, now=_time162.time() + _wr162._RETRY_SECONDS + 5)
        got["audit"] = _p9_audit("wipe_server")
        return got
    finally:
        _p9_restore_all()
        _ws162.put(sid, None)
        _mon162._end_offline_window(sid)
        _p9_delete_server(sid)


_dropped162 = _drop162(True)
_unsent162 = _drop162(False)
_dl162 = _dropped162["first"].get("last") or {}
check("1109 r39a wipe: a connection that drops after LinuxGSM's wipe was sent ends the pending wipe, "
      "alerted as possibly done, and the sweep after the retry gap does NOT run the wipe again",
      _dropped162["cmds"] == ["full-wipe"] and not _dropped162["first"].get("pending_since")
      and _dl162.get("ok") is False and "connection dropped while LinuxGSM's wipe ran" in (_dl162.get("detail") or "")
      and _dropped162["alerts"] == ["Scheduled wipe did not run"] and _dropped162["audit"].success is False,
      repr(_dropped162))
check("1109 r39a wipe: one whose exec was never sent stays pending with its backup (tried again after the "
      "gap, never alerted) and the monitor's quiet window it opened ends",
      _unsent162["cmds"] == ["full-wipe", "full-wipe"] and _unsent162["first"].get("pending_since")
      and _unsent162["first"].get("backed_up") and _unsent162["alerts"] == []
      and _unsent162["window"] is False, repr(_unsent162))

# ── 3. the graceful stop that LinuxGSM's tmux kill finished ─────────────────────────────────────
# LinuxGSM v26.5.0 for a running Rust server that ignores `quit` for its 120 s (stopmode 4):
# fn_stop_graceful_cmd's FAIL, fn_stop_tmux's OK, then command_wipe.sh's fn_wipe_files and success line.
_GRACE162 = ("[ WARN ] Wiping rustserver: Server wipe will reset the map data and remove blueprint data\n"
             "[ ERROR ] Stopping rustserver: Graceful: sending \"quit\":  ... FAIL\n"
             "[  OK  ] Stopping rustserver: Rust Server\n"
             "[ START ] Wiping rustserver: Full wipe\n"
             "removing .map file(s)... ... OK\nremoving .db file(s)... ... OK\n"
             "Success! Full wipe\n[  OK  ] Starting rustserver: Rust Server\n")
_g162 = _ws162.judge(_GRACE162, 0, "full-wipe")
_unstopped162 = _ws162.judge(_GRACE162.replace("[  OK  ] Stopping rustserver: Rust Server",
                                               "[ FAIL ] Stopping rustserver: Unable to stop Rust Server"),
                             0, "full-wipe")
_rmfail162 = _ws162.judge(_GRACE162.replace("removing .db file(s)... ... OK", "removing .db file(s)... ... FAIL"),
                          0, "full-wipe")
check("1109 r39a wipe judge: a graceful-stop FAIL that LinuxGSM's tmux kill recovered, followed by the wipe's "
      "own start and success lines, is a wipe done; 'Unable to stop' or a removal FAIL is still a failure",
      _g162 == ("wiped", _g162[1]) and str(_g162[1]) == "Full wipe done"
      and _unstopped162[0] == "failed" and _rmfail162[0] == "failed", repr((_g162, _unstopped162, _rmfail162)))

# ── 4. LinuxGSM's wipe and file-changing commands in the reboot census ─────────────────────────
_maint162 = _hr162._cmd_pattern("rustserver", _hr162._MAINT_CMDS)
_infl162 = _hr162._cmd_pattern("rustserver", _hr162._INFLIGHT_CMDS)
_lines162 = {"/bin/bash ./rustserver full-wipe": True, "/bin/bash /home/u/rustserver fw": True,
             "/bin/bash ./rustserver wipeall": True, "/bin/bash ./rustserver wa": True,
             "/bin/bash ./rustserver map-wipe": True, "/bin/bash ./rustserver mw": True,
             "/bin/bash ./rustserver wipe": True, "/bin/bash ./rustserver w": True, "/bin/bash ./rustserver wi": True,
             "/bin/bash ./rustserver mods-install": True, "/bin/bash ./rustserver mi": True,
             "/bin/bash ./rustserver mods-remove": True, "/bin/bash ./rustserver mr": True,
             "/bin/bash ./rustserver fastdl": True, "/bin/bash ./rustserver fd": True,
             "/bin/bash ./rustserver map-compressor": True, "/bin/bash ./rustserver mc": True,
             "/bin/bash ./rustserver clear-modules": True, "/bin/bash ./rustserver cm": True,
             "/bin/bash ./rustserver install-default-resources": True, "/bin/bash ./rustserver ir": True,
             "/bin/bash ./rustserver details": False, "/bin/bash ./rustserver monitor": False,
             "/bin/bash ./rustserver wipes": False, "/bin/bash ./myrustserver full-wipe": False}
_seen162 = {ln: bool(_re162.search(_maint162, ln)) for ln in _lines162}
_mon_pat162 = "/rustserver (%s)( |$)" % "|".join(_mon162._LGSM_MAINTENANCE_CMDS)
_mon_seen162 = [bool(_re162.search(_mon_pat162, "/bin/bash /home/u/rustserver " + c))
                for c in ("full-wipe", "wi", "mi")]
_PROBE162 = "SESSION=0\nLOCK=none\nASIDE=none\nCRON=\nINFLIGHT=1\nMAINT=1\nDEBUG=0\nWARN=0\nBOOT=b\nMID=m\nNOW=1\n"
_blk162 = _lgp162.census_blockers([type("GS162", (), {"id": 1, "name": "p162-cron"})()],
                                  {1: _hr162.parse_probe(_PROBE162 + "SEC=20\nPROBE_OK\n")},
                                  lambda kind, name, detail=None: (kind, name))
check("1109 r39a reboot census: LinuxGSM's wipe (every core_getopt.sh v26.5.0 name) and the other "
      "file-changing commands are maintenance, which the census refuses on a stopped server and the quiet "
      "window waits on; details, monitor and another script are not",
      _seen162 == _lines162 and all(_re162.search(_infl162, ln) for ln, v in _lines162.items() if v)
      and _blk162 == [("maintenance", "p162-cron")],
      repr((_maint162, {k: v for k, v in _seen162.items() if v != _lines162[k]}, _blk162)))
check("1109 r39a monitor: an operator's cron wipe (and its alias) is LinuxGSM maintenance, not a crash; a mods "
      "install, which leaves the server up, is not",
      _mon_seen162 == [True, True, False], repr(_mon_seen162))

# ── 5. LinuxGSM's own alert: blank or stock settings deliver nothing ───────────────────────────
_al_vals162 = {}
_al_note162 = _lgp162.note(_lgp162.BACKUP_QUEUED, "lgsm_postponed", alerted=True)
_al_gs162 = type("GS162b", (), {"remote": None, "short_name": "u162", "lgsm_name": "rustserver"})()
_STOCK162 = {"email": "email@example.com", "telegramtoken": "access" + "token", "ntfytopic": "LinuxGSM",
             "ntfyserver": "https://ntfy.sh", "discordwebhook": "webhook", "pushovertoken": "access" + "token",
             "pushoveruserkey": "userkey"}
_al162 = {}
try:
    _p9_arm(who="part162")
    _p9_patch(_files162, "lgsm_get_values",
              lambda server, user, selfname, keys: {k: _al_vals162.get(k, _STOCK162.get(k, "")) for k in keys})
    for _name162, _cfg162 in (("email_stock", {"emailalert": "on"}),
                              ("email", {"emailalert": "on", "email": "ops@example.invalid"}),
                              ("telegram_stock", {"telegramalert": "on", "telegramchatid": "12345"}),
                              ("telegram_nochat", {"telegramalert": "on", "telegramtoken": "t162-x"}),
                              ("telegram", {"telegramalert": "on", "telegramtoken": "t162-x", "telegramchatid": "1"}),
                              ("ntfy_stock", {"ntfyalert": "on"}),
                              ("ntfy_own_server", {"ntfyalert": "on", "ntfyserver": "https://ntfy.example.invalid"}),
                              ("discord_stock", {"discordalert": "on"}),
                              ("discord", {"discordalert": "on",
                                           "discordwebhook": "https://hooks.example.invalid/p162"}),
                              ("pushover_half", {"pushoveralert": "on", "pushovertoken": "p162-x"})):
        _al_vals162.clear()
        _al_vals162.update(_cfg162)
        _al162[_name162] = _sh162._lg264_lgsm_alerted(_al_gs162, _al_note162)
finally:
    _p9_restore_all()
check("1109 r39a alerts: LinuxGSM's backup-postponed alert counts only through a channel whose settings are "
      "the operator's; the placeholders its _default.cfg ships (email@example.com, accesstoken, webhook, userkey, "
      "the LinuxGSM topic on ntfy.sh) or a blank chat id deliver nothing, so the panel's own alert goes out",
      _al162 == {"email_stock": False, "email": True, "telegram_stock": False, "telegram_nochat": False,
                 "telegram": True, "ntfy_stock": False, "ntfy_own_server": True, "discord_stock": False,
                 "discord": True, "pushover_half": False}, repr(_al162))


# ── 6. nothing runs beside a scheduled wipe ─────────────────────────────────────────────────────
def _bk_runner162(calls):
    def _run(*a, **k):
        calls.append(a[0] if a else None)
        return (True, "Backed up", False)
    return _run


_mb_calls162 = []
with _ps162.r36j_route_job(9162, "wipe"):
    _mb_wipe162 = _sh162._marked_backup(9162, "srv", runner=_bk_runner162(_mb_calls162))
    _mb_mark162 = _sh162._game_backup_status.get(9162)
    _mb_own162 = _sh162._marked_backup(9162, "own", runner=_bk_runner162(_mb_calls162), wipe_ok=True)
    with _ps162.r36j_route_job(9162, "queued"):
        _mb_ownq162 = _sh162._marked_backup(9162, "ownq", runner=_bk_runner162(_mb_calls162), wipe_ok=True)
_mb_free162 = _sh162._marked_backup(9162, "free", runner=_bk_runner162(_mb_calls162))
_sh162._game_backup_status.pop(9162, None)
check("1109 r39a backups: every backup path's run (_marked_backup) is a skip while the server's scheduled wipe "
      "or a queued stop/restart of it runs, leaving no 'running' mark; the wipe's own backup runs unless a "
      "queued stop/restart does; with neither it runs",
      _mb_wipe162[0] is False and _mb_wipe162[2] is True and _mb_mark162 is None
      and "scheduled wipe" in str(_mb_wipe162[1]) and _mb_own162 == (True, "Backed up", False)
      and _mb_ownq162[2] is True and _mb_free162 == (True, "Backed up", False)
      and _mb_calls162 == ["own", "free"], repr((_mb_wipe162, _mb_own162, _mb_ownq162, _mb_free162, _mb_calls162)))

# The callers: the queued sweep leaves a server queued, and "Back up now" refuses, while its wipe runs.
_q_sid162 = _new_rust162("p162-queue")
_q_calls162 = []
try:
    _p9_set(_q_sid162, backup_pending=True)
    _p9_arm(who="part162")
    _p9_patch(_sh162, "run_game_backup", _bk_runner162(_q_calls162))
    _p9_patch(_sh162, "_reboot_holds", lambda gs: False)
    _p9_patch(_sh162, "_backups_blocked_by_config", lambda app, what: False)
    _p9_patch(_sh162, "_report_long_queue", lambda *a, **k: None)
    with _ps162.r36j_route_job(_q_sid162, "wipe"):
        _sh162._run_pending_backups(_p9)
        _now_resp162 = _p9_client(P9_ADMIN).post("/api/panel/backup/game/%d" % _q_sid162, json={})
    _q_pending162 = _p9_row(_q_sid162).backup_pending
    _sh162._run_pending_backups(_p9)
    _q_after162 = _p9_row(_q_sid162).backup_pending
finally:
    _p9_restore_all()
    _sh162._game_backup_status.pop(_q_sid162, None)
    _p9_delete_server(_q_sid162)
check("1109 r39a backups: the queued sweep leaves a server queued and runs no LinuxGSM backup while its "
      "scheduled wipe runs, and backs it up once it ends; 'Back up now' is refused (409) meanwhile",
      _q_pending162 is True and _q_after162 is False and len(_q_calls162) == 1
      and _now_resp162.status_code == 409 and "scheduled wipe" in (_now_resp162.get_json() or {}).get("message", ""),
      repr((_q_pending162, _q_after162, _q_calls162, _now_resp162.status_code, _now_resp162.get_json())))


# The wipe waits on a queued stop/restart or a server-page action that is running.
def _wipe_beside162(kind):
    sid = _new_rust162("p162-beside")
    got = {"sid": sid, "cmds": [], "backups": [], "alerts": []}
    try:
        _pending162(sid, backed_up=0)
        _p9_arm(who="part162")
        _wipe_stubs162(got)
        with _ps162.r36j_route_job(sid, kind):
            _sweep162(sid, got)
        got["free"] = dict(got["entry"] or {})
        _sweep162(sid, got, now=_time162.time() + _wr162._RETRY_SECONDS + 5)
        return got
    finally:
        _p9_restore_all()
        _ws162.put(sid, None)
        _mon162._end_offline_window(sid)
        _p9_delete_server(sid)


_wq162 = _wipe_beside162("queued")
_wa162 = _wipe_beside162("action")
check("1109 r39a wipe: a due wipe waits (no backup, no wipe) while a queued stop/restart or a server-page "
      "action of its server runs, says so on the card, and runs once it has ended",
      [(g["free"].get("wait"), len(g["cmds"]), len(g["backups"])) for g in (_wq162, _wa162)]
      == [("another action on this server is running", 1, 1)] * 2
      and all((g.get("jobs_at_wipe") or [[]])[0] == ["wipe"] for g in (_wq162, _wa162)), repr((_wq162, _wa162)))

# A queued restart: registered while it runs, and not run when a wipe began during its status read.
_qr_sid162 = _new_rust162("p162-qr")
_qr162 = {"runs": [], "jobs": []}


def _qr_run162(remote, user, action, **k):
    _qr162["runs"].append(action)
    _qr162["jobs"].append(_ps162.r36j_route_jobs(_qr_sid162))
    return ("", "", 0)


def _qr_status162(started_wipe):
    def _status(remote, gs, **k):
        if started_wipe is not None:
            started_wipe.append(_ps162.r36j_route_job(_qr_sid162, "wipe"))
            started_wipe[-1].__enter__()
        return "online"
    return _status


_wipe_cm162 = []
try:
    _p9_set(_qr_sid162, restart_pending=True)
    _p9_arm(who="part162")
    _p9_patch(_sh162, "sm_player_count", lambda *a, **k: 0)
    _p9_patch_sm("run_as_game_user", _qr_run162)
    _p9_patch_sm("set_game_priority", lambda *a, **k: None)
    _p9_patch(_sh162, "get_server_status", _qr_status162(_wipe_cm162))
    with _p9.app_context():
        from panel.db.models import GameServer as _G162, db as _db162
        _sh162._settle_queued_action(_p9, _db162.session.get(_G162, _qr_sid162))
    for _cm162 in _wipe_cm162:
        _cm162.__exit__(None, None, None)
    _qr_held162 = (list(_qr162["runs"]), _p9_row(_qr_sid162).restart_pending)
    _p9_patch(_sh162, "get_server_status", _qr_status162(None))
    with _p9.app_context():
        _sh162._settle_queued_action(_p9, _db162.session.get(_G162, _qr_sid162))
finally:
    _p9_restore_all()
    _sh162._queued_action_failures.pop(_qr_sid162, None)
    _mon162._end_offline_window(_qr_sid162)
    _p9_delete_server(_qr_sid162)
_QB162 = [{"kind": "queued", "name": "p162", "detail": None}]
check("1109 r39a queued restart: one whose server's scheduled wipe began during its status read is not run "
      "(it stays queued); run later, it is registered as a queued stop/restart while LinuxGSM runs it, which the "
      "wipe and the backups read and the reboot census names",
      _qr_held162 == ([], True) and _qr162["runs"] == ["restart"] and _qr162["jobs"] == [["queued"]]
      and _ps162.r36j_route_jobs(_qr_sid162) == []
      and "a queued stop or restart of p162" in str(_rw162.blocked_sentence(_QB162)),
      repr((_qr_held162, _qr162)))

# The server page, the bulk bar and the bots (_run_action), a mods install and Run now refuse during a wipe.
_ra_sid162 = _new_rust162("p162-actions")
_ra162 = {"runs": []}
try:
    _p9_arm(who="part162")
    _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: (_ra162["runs"].append(action), ("", "", 0))[1])
    _p9_patch(_sd162, "_noop_power_refusal", lambda *a, **k: None)
    _p9_patch(_sd162, "_bg_power_action", lambda *a, **k: _ra162["runs"].append("bg-" + a[3]))
    _p9_patch(_sd162, "_bg_action", lambda *a, **k: _ra162["runs"].append("bg-" + a[3]))
    _p9_patch(_sd162, "_run_sync_action", lambda app, gs, remote, action, *a: (
        _ra162["runs"].append("sync-" + action), (True, "ok"))[1])
    with _p9.app_context():
        from panel.db.models import GameServer as _G162b, db as _db162b
        _ra_gs162 = _db162b.session.get(_G162b, _ra_sid162)
        with _ps162.r36j_route_job(_ra_sid162, "wipe"):
            _ra_out162 = {a: _sd162._run_action(_p9, _ra_gs162, _ra_gs162.remote, a, None)
                          for a in ("restart", "backup", "monitor", "details")}
    with _ps162.r36j_route_job(_ra_sid162, "wipe"):
        _A162 = _p9_client(P9_ADMIN)
        _cron162 = _A162.post("/api/server/%d/cron/run" % _ra_sid162, json={"raw": "0 5 * * * restart"})
        _mods162 = _A162.post("/api/server/%d/mods" % _ra_sid162, json={"action": "install", "mod": "oxide"})
    with _p9.app_context():
        _ra_free162 = _sd162._run_action(_p9, _db162b.session.get(_G162b, _ra_sid162),
                                         _db162b.session.get(_G162b, _ra_sid162).remote, "restart", None)
finally:
    _p9_restore_all()
    _mon162._end_offline_window(_ra_sid162)
    _p9_delete_server(_ra_sid162)
check("1109 r39a server actions: while a server's scheduled wipe runs, Restart, Backup and monitor from its "
      "page, the bulk bar or a bot are refused (saying so) and only read-only details runs; a mods install "
      "and Run now are refused (409); with no wipe, Restart is issued (control)",
      [o[0] for o in (_ra_out162["restart"], _ra_out162["backup"], _ra_out162["monitor"])] == [False] * 3
      and "A scheduled wipe of 'p162-actions' is running" in str(_ra_out162["restart"][1])
      and _ra_out162["details"][0] is True and _cron162.status_code == 409 and _mods162.status_code == 409
      and _ra_free162[0] is True and _ra162["runs"] == ["sync-details", "bg-restart"],
      repr((_ra_out162, _cron162.status_code, _mods162.status_code, _ra_free162, _ra162)))

check("part162: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP162_START, repr(_P9_TRIPPED[_TRIP162_START:]))
