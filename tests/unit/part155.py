"""Part 155 of the unit suite: scheduled wipes, FastDL and the other game operations (review 1107 B).

Held here:
* FastDL is not run when the account's LinuxGSM release could not be read: on v26.5.0 the old
  all-Y answers delete ${webdir}/fastdl, so the run is refused and said in the console.
* A scheduled wipe turned off or changed while its pre-wipe backup runs is not run (nor written
  over the new schedule); the wipe is a job the reboot census and the queued-restart loop see; the
  backup's outcome takes the card's own shape; its waits and results are said in the viewer's
  language; LinuxGSM refusing it ends the monitor's quiet window.
* A FAIL after LinuxGSM's wipe success line (the start that follows) is a wipe that happened.
* parse_cron reads a day field starting with `*` (`*/2`) as cron does (AND with the other day
  field), and takes month and weekday names only in their own fields.
* A queued stop/restart LinuxGSM refused ends the quiet window; host-read numbers are length-capped
  before int(); an icon whose format changed upstream replaces the old cached file; an upload over
  LinuxGSM's _default.cfg is refused as an edit of it is; LinuxGSM's own "alerted" mark counts only
  for a channel alert.sh really sends through; a queued stop/restart cancelled while the loop works
  on the servers ahead of it is not run.

HOW IT RUNS. Routes and workers on part12's app with its transport tripwire armed and every host
call stubbed; the icon cache in a scratch directory. Nothing reaches a host or data/.
"""
import datetime as _dt155
import os as _os155
import pathlib as _pl155
import shutil as _shutil155
import tempfile as _tf155
import time as _time155

from flask import session as _session155

from unit.part01 import check
from unit.part12 import (P9_GS, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_delete_server,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_set)
from panel.core import panel_state as _ps155
from panel.ops.ssh_manager import _core as _smc155, files as _files155, game as _game155, hosts as _hosts155
from panel.routes import _shared as _sh155, server_detail as _sd155, wipe_schedule as _wr155
from panel.services import game_icons as _gi155, host_reboot as _hr155, lgsm_players as _lgp155
from panel.services import monitoring as _mon155, wipe_schedule as _ws155

_TRIP155_START = len(_P9_TRIPPED)

# ── 1. FastDL with an unread LinuxGSM release ───────────────────────────────────────────────────
_fd155 = {"runs": [], "said": [], "began": []}
try:
    _p9_arm(who="part155")
    _p9_patch(_hosts155, "lgsm_versions", lambda server, account, selfname: (None, None))
    _fd_unread155 = _game155.fastdl_answers(None, "u155", "csserver", "cs")
    _p9_patch(_hosts155, "lgsm_versions", lambda server, account, selfname: ("v26.4.0", None))
    _fd_modsunread155 = _game155.fastdl_answers(None, "u155", "csserver", "cs")
    _p9_patch_sm("fastdl_answers", lambda server, user, selfname, game_type: None)
    _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: (
        _fd155["runs"].append(action), ("", "", 0))[1])
    _p9_patch(_sd155, "_begin_action_tail", lambda app, sid, action, *a, **k: _fd155["began"].append(action))
    _p9_patch(_sd155, "_end_action_tail", lambda *a, **k: None)
    _p9_patch(_sd155, "_console_push", lambda app, sid, text, ts=None: _fd155["said"].append((sid, str(text))))
    with _p9.app_context():
        _fd_out155 = _sd155._run_teed(_p9, None, P9_GS, "u155", "fastdl", "csserver")
finally:
    _p9_restore_all()
check("fastdl_answers: a release that could not be read, or modules unread under a pre-v26.5.0 script, "
      "gives no answers (None), never the eight Y's that delete the FastDL folder on v26.5.0",
      _fd_unread155 is None and _fd_modsunread155 is None, repr((_fd_unread155, _fd_modsunread155)))
check("FastDL run with an unread release: LinuxGSM is never run, the run fails with the reason, and the "
      "console says it was not run",
      _fd155["runs"] == [] and _fd155["began"] == [] and _fd_out155[2] != 0
      and "FastDL was not run" in _fd_out155[1]
      # r37g (adversarial L2): an account on a release older than v23.3.0 has no core_modules.sh, so the
      # refusal comes every time and "Try again" alone never helps; update-lgsm does.
      and "update-lgsm" in _fd_out155[1]
      and len(_fd155["said"]) == 1 and _fd155["said"][0][0] == P9_GS
      and _fd155["said"][0][1].startswith("[panel] fastdl: FastDL was not run"),
      repr((_fd155, _fd_out155)))


# ── 2. a scheduled wipe and its pre-wipe backup ─────────────────────────────────────────────────
def _utc155(*a):
    return _dt155.datetime(*a, tzinfo=_dt155.timezone.utc).timestamp()


_OK155 = "[ WARN ] Wiping rustserver: Server wipe will reset the map data\nSuccess! Full wipe\n"
_REFUSED155 = "[ INFO ] Stopping rustserver: 1 players are on the server: stop prevented\n"


def _sweep155(backup, wipe_out=(_OK155, "", 0), kind="full", during=None, extra=None):
    """One sweep over a fresh Rust server whose wipe is due.

    `backup` is the pre-wipe backup's (ok, reason, skipped); `during(sid)` runs inside it (the
    operator's save, say). Returns a dict: the backups and LinuxGSM commands run, the route jobs
    registered at each, the reboot census at the wipe, the entry left and the card's backup status.
    """
    sid = _p9_new_server(P9_HOST, "rustserver", "rust", 28015, name="p155-rust")
    got = {"backups": [], "cmds": [], "jobs_at_backup": [], "jobs_at_wipe": [], "census": []}
    try:
        with _p9.app_context():
            from panel.db.models import GameServer, db
            gs = db.session.get(GameServer, sid)
            entry = dict(_ws155.identity(gs), kind=kind, preset="custom", at="", cron="0 19 * * 4",
                         tz="UTC", wait_empty=True, anchor=_utc155(2026, 11, 1),
                         pending_since=0, backed_up=0, tried=0, wait="")
        entry.update(extra or {})
        _ws155.put(sid, entry)

        def _bk(*a, **k):
            got["backups"].append(a[2])
            got["jobs_at_backup"].append(_ps155.r36j_route_jobs(sid))
            if during:
                during(sid)
            return backup

        def _run(remote, user, action, **k):
            got["cmds"].append(action)
            got["jobs_at_wipe"].append(_ps155.r36j_route_jobs(sid))
            with _p9.app_context():
                from panel.db.models import GameServer as _G, db as _db
                got["census"].append([b["kind"] for b in _hr155._row_blockers([_db.session.get(_G, sid)])])
            got["window_during"] = _mon155._offline_expected(sid)
            return wipe_out
        _p9_patch(_sh155, "_marked_backup", _bk)
        _p9_patch(_sh155, "_alert_backup", lambda *a, **k: got.setdefault("alerts", []).append(a[2]))
        _p9_patch(_sh155, "_reboot_holds", lambda gs: False)
        _p9_patch(_lgp155, "timeout_for", lambda *a, **k: 900)
        _p9_patch_sm("run_as_game_user", _run)
        _wr155.sweep(_p9, now=_utc155(2026, 11, 5, 19, 1))
        got["entry"] = _ws155.get(sid)
        got["status"] = _ps155._game_backup_status.get(sid)
        got["window_after"] = _mon155._offline_expected(sid)
        got["jobs_after"] = _ps155.r36j_route_jobs(sid)
        return got
    finally:
        _p9_restore_all()
        _ws155.put(sid, None)
        _ps155._game_backup_status.pop(sid, None)
        _mon155._end_offline_window(sid)
        _p9_delete_server(sid)


def _resave155(sid):
    """The operator saving the schedule again, as a map wipe, while the backup runs."""
    _ws155.put(sid, dict(_ws155.get(sid), kind="map", pending_since=0, backed_up=0, tried=0, wait="",
                         anchor=_time155.time()))


try:
    _p9_arm(who="part155")
    _off155 = _sweep155((True, "Backed up", False), during=lambda sid: _ws155.put(sid, None))
    _aud_off155 = _p9_audit("wipe_server")
    _p9_arm(who="part155")
    _changed155 = _sweep155((True, "Backed up", False), during=_resave155)
    _p9_arm(who="part155")
    _plain155 = _sweep155((True, "Backed up", False))
    _p9_arm(who="part155")
    _skip155 = _sweep155((False, "2 player(s) online", True), kind="map")
    _p9_arm(who="part155")
    _refused155 = _sweep155((True, "", False), wipe_out=(_REFUSED155, "", 0))
finally:
    _p9_restore_all()
check("wipe sweep: a schedule turned OFF while its pre-wipe backup ran is not wiped, and says so",
      _off155["backups"] == ["rustserver"] and _off155["cmds"] == [] and _off155["entry"] is None
      and _aud_off155.success is False and "turned off or changed" in _aud_off155.detail,
      repr((_off155, _aud_off155)))
check("wipe sweep: a schedule CHANGED (full -> map) during the backup runs neither kind, and the new "
      "schedule is left as saved (not pending, not marked backed up, no wait)",
      _changed155["cmds"] == [] and _changed155["entry"]["kind"] == "map"
      and not _changed155["entry"].get("pending_since") and not _changed155["entry"].get("backed_up")
      and not _changed155["entry"].get("wait"), repr(_changed155))
check("wipe sweep: ...and one left alone still backs up, then wipes (control)",
      _plain155["cmds"] == ["full-wipe"] and not _plain155["entry"].get("pending_since"),
      repr(_plain155))
check("wipe sweep: the try is a route job from the backup to the wipe's end, so a clean reboot's census "
      "names the wipe; the job is gone after",
      _plain155["jobs_at_backup"] == [["wipe"]] and _plain155["jobs_at_wipe"] == [["wipe"]]
      and "wipe" in _plain155["census"][0] and _plain155["jobs_after"] == [], repr(_plain155))
check("wipe sweep: a skipped pre-wipe backup (players online) shows on the backup card as busy, not as "
      "a red failure",
      (_skip155["status"] or {}).get("busy") is True and (_skip155["status"] or {}).get("ok") is None
      and _skip155["cmds"] == [], repr(_skip155))
check("wipe sweep: LinuxGSM refusing the wipe (players on) ends the monitor's quiet window it opened",
      _refused155.get("window_during") is True and _refused155["window_after"] is False
      and _refused155["entry"].get("pending_since"), repr(_refused155))

# A pending restart waits while a wipe runs on the server; the control runs it.
_qsid155 = _p9_new_server(P9_HOST, "rustq", "rust", 28016, name="p155-q")
_settled155 = []
try:
    _p9_set(_qsid155, restart_pending=True)
    _p9_patch(_sh155, "_settle_queued_action", lambda app, gs: _settled155.append(gs.id))
    _p9_patch(_sh155, "_reboot_holds", lambda gs: False)
    with _ps155.r36j_route_job(_qsid155, "wipe"):
        _sh155._run_due_restarts(_p9)
    _held155 = list(_settled155)
    _sh155._run_due_restarts(_p9)
finally:
    _p9_restore_all()
    _p9_delete_server(_qsid155)
check("due restarts: a queued restart is not run on a server a scheduled wipe is running on; it runs "
      "once the wipe is over",
      _qsid155 not in _held155 and _qsid155 in _settled155, repr((_held155, _settled155)))

# A queued action cancelled while the loop works on the servers ahead of it is not run.
_qa155 = _p9_new_server(P9_HOST, "rustqa", "rust", 28019, name="p155-qa")
_qb155 = _p9_new_server(P9_HOST, "rustqb", "rust", 28020, name="p155-qb")
_qsettled155 = []


def _settle_cancel155(app, gs):
    """The first server's settle; meanwhile the operator cancels the other one's queued stop."""
    if gs.id not in (_qa155, _qb155):
        return                  # another part's server: not this check's
    _qsettled155.append(gs.id)
    if len(_qsettled155) == 1:
        _p9_set(_qb155 if gs.id == _qa155 else _qa155, stop_pending=False, restart_pending=False)


try:
    _p9_set(_qa155, stop_pending=True)
    _p9_set(_qb155, stop_pending=True)
    _p9_patch(_sh155, "_settle_queued_action", _settle_cancel155)
    _p9_patch(_sh155, "_reboot_holds", lambda gs: False)
    _sh155._run_due_restarts(_p9)
finally:
    _p9_restore_all()
    _p9_delete_server(_qa155)
    _p9_delete_server(_qb155)
check("due restarts: a 'stop when empty' cancelled while the loop works on another server is not run "
      "(its flags are read again before it is acted on)",
      len(_qsettled155) == 1 and _qsettled155[0] in (_qa155, _qb155), repr(_qsettled155))

# The card in the viewer's language: the reason it waits and how the last run went.
_vsid155 = _p9_new_server(P9_HOST, "rustv", "rust", 28017, name="p155-v")
try:
    with _p9.app_context():
        from panel.db.models import GameServer as _GS155, db as _db155
        _vgs155 = _db155.session.get(_GS155, _vsid155)
        _ws155.put(_vsid155, dict(_ws155.identity(_vgs155), kind="map", preset="custom", at="",
                                  cron="0 19 * * 4", tz="UTC", wait_empty=True, anchor=_time155.time(),
                                  pending_since=_time155.time(), backed_up=0, tried=0, wait=""))
        _wr155._r37b_wait(_vsid155, _ws155.judge(_REFUSED155, 0, "wipe")[1])
        _wr155._cmpd_finish(_p9, _vgs155, False, _ws155.judge("", 0, "wipe")[1])
        _wr155._r37b_wait(_vsid155, _ws155.judge(_REFUSED155, 0, "wipe")[1])
        _ws155.patch(_vsid155, pending_since=_time155.time())
        _views155 = {}
        for _lang155 in ("en", "es", "fr"):
            with _p9.test_request_context("/"):
                _session155["lang"] = _lang155
                _views155[_lang155] = _wr155._cmpd_view(_db155.session.get(_GS155, _vsid155))
finally:
    _ws155.put(_vsid155, None)
    _p9_delete_server(_vsid155)
check("wipe card: what a wipe waits for, and how its last run went, are said in the viewer's language "
      "(English stays English)",
      _views155["en"]["wait"] == "LinuxGSM did not wipe: 1 player(s) online"
      and _views155["en"]["last"]["detail"] == "wipe exited 0: no output"
      and _views155["es"]["wait"].startswith("LinuxGSM no hizo el borrado")
      and _views155["fr"]["wait"].startswith("LinuxGSM n'a pas fait le wipe")
      and _views155["es"]["last"]["detail"].startswith("el borrado terminó")
      and _views155["fr"]["last"]["detail"].startswith("le wipe s'est terminé")
      and "i18n" not in _views155["es"]["last"], repr(_views155))

# ── 3. parse_cron as cron reads it ──────────────────────────────────────────────────────────────
_step155 = _ws155.parse_cron("0 18 */2 * 4")
_fires155 = []
_t155 = _utc155(2026, 11, 1)
for _ in range(4):
    _t155 = _ws155.next_after(_step155, _t155, "UTC")
    _fires155.append(_dt155.datetime.fromtimestamp(_t155, _dt155.timezone.utc).date())
check("parse_cron: a day-of-month field STARTING with '*' (*/2) is a star, as cron's DOM_STAR is: "
      "'0 18 */2 * 4' fires on odd days that are Thursdays, not on every odd day plus every Thursday",
      _step155["dom_star"] is True and all(d.day % 2 == 1 and d.weekday() == 3 for d in _fires155)
      and _ws155.parse_cron("0 0 * * */2")["dow_star"] is True
      and _ws155.parse_cron("0 0 1 * 1")["dom_star"] is False, repr(_fires155))
check("parse_cron: month and weekday names only in their own fields (cron refuses them elsewhere)",
      _ws155.parse_cron("0 mon * * *") is None and _ws155.parse_cron("0 0 * mon *") is None
      and _ws155.parse_cron("0 0 * * jan") is None and _ws155.parse_cron("jan 0 * * *") is None
      and _ws155.parse_cron("0 0 * jan-mar mon-fri") is not None)

_late155 = _ws155.judge("[  OK  ] Stopping rustserver\nremoving .map file(s)... OK\nSuccess! Full wipe\n"
                        "[ FAIL ] Starting rustserver: Unable to start\n", 0, "full-wipe")
_early155 = _ws155.judge("removing .map file(s)... FAIL\nSuccess! Map wipe\n", 0, "wipe")
check("wipe judge: a FAIL after LinuxGSM's success line (the start it runs after the wipe) is a wipe "
      "that happened, said with that failure; a FAIL before it is still a failed wipe",
      _late155[0] == "wiped" and "reported a failure after it: [ FAIL ] Starting rustserver" in _late155[1]
      and _early155[0] == "failed", repr((_late155, _early155)))

# ── 4. a queued stop LinuxGSM refused ───────────────────────────────────────────────────────────
_wsid155 = _p9_new_server(P9_HOST, "rustw", "rust", 28018, name="p155-w")
try:
    _p9_arm(who="part155")
    _p9_set(_wsid155, stop_pending=True)
    _p9_patch(_lgp155, "timeout_for", lambda *a, **k: 90)
    _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: (_REFUSED155, "", 0))
    with _p9.app_context():
        from panel.db.models import GameServer as _GS155b, db as _db155b
        _sh155._run_queued_action(_p9, _db155b.session.get(_GS155b, _wsid155))
    _qwin155 = _mon155._offline_expected(_wsid155)
    _qaud155 = _p9_audit("lgsm_refused")
finally:
    _p9_restore_all()
    _mon155._end_offline_window(_wsid155)
    _p9_delete_server(_wsid155)
check("queued stop: LinuxGSM refusing it (players on) ends the quiet window the queued stop opened, as "
      "the Stop button's refusal does", _qwin155 is False and _qaud155.success is False,
      repr((_qwin155, _qaud155)))

# ── 5. numbers the game account writes, capped before int() ────────────────────────────────────
_LONG155 = "9" * 5000
try:
    _p9_arm(who="part155")
    _p9_patch(_smc155, "shell_as_game_user", lambda *a, **k: (
        "%s\t0\t1\t%s\n" % (_LONG155, _game155._LG264_BK_END), "", 0))
    try:
        _req155 = _game155._lg264_bk_request(None, "u155", "rustserver")
    except ValueError as _e155:
        _req155 = _e155
finally:
    _p9_restore_all()
check("backup request lock: a line too long for int() (the game account writes it) is read as an odd "
      "value, 0, never a ValueError out of every backup",
      _req155 == {"requested": 0, "alerted": False, "monitor": True}, repr(_req155))
try:
    _disc155 = _smc155._discovered_instance("FOUND|u155|rustserver|%s|1|0|0|0" % _LONG155)
except ValueError:
    _disc155 = None
check("discovery: a port line too long for int() (the game account's own config) is 0, never a "
      "ValueError out of the host's discovery (no port)", isinstance(_disc155, dict) and _disc155["port"] is None,
      repr(_disc155))

# ── 6. an icon whose format changed upstream ────────────────────────────────────────────────────
_ICONS155 = _pl155.Path(_tf155.mkdtemp(prefix="lgsm-unit-p155-"))
_saved_gi155 = (_gi155._CACHE_DIR, _gi155._cmpd_http_get, dict(_gi155._failed), _gi155._cmpd_load_index)
_PNG155 = b"\x89PNG\r\n\x1a\n" + b"\0" * 64
_WEBP155 = b"RIFF\x10\0\0\0WEBPVP8 " + b"\0" * 64
_gets155 = []
try:
    _gi155._CACHE_DIR = _ICONS155
    _gi155._failed.clear()
    _gi155._cmpd_load_index = lambda: {"vhserver": "https://linuxgsm.com/wp-content/uploads/vh.webp"}
    _gi155._cmpd_http_get = lambda url, cap: (_gets155.append(url), (_WEBP155, "image/webp", None))[1]
    _old155 = _ICONS155 / "vhserver.png"
    _old155.write_bytes(_PNG155)
    _stale155 = _time155.time() - 40 * 86400
    _os155.utime(_old155, (_stale155, _stale155))
    _first155 = _gi155.icon("vhserver", {"vhserver"})
    _second155 = _gi155.icon("vhserver", {"vhserver"})
    _left155 = sorted(p.name for p in _ICONS155.iterdir())
finally:
    _gi155._CACHE_DIR, _gi155._cmpd_http_get = _saved_gi155[0], _saved_gi155[1]
    _gi155._cmpd_load_index = _saved_gi155[3]
    _gi155._failed.clear()
    _gi155._failed.update(_saved_gi155[2])
    _shutil155.rmtree(_ICONS155, ignore_errors=True)
check("game icons: a month-old png whose upstream is now webp is replaced (the png removed), so the next "
      "request is served from the cache, not fetched again",
      _first155 == (_WEBP155, "image/webp") and _second155 == (_WEBP155, "image/webp")
      and len(_gets155) == 1 and _left155 == ["vhserver.webp"], repr((_gets155, _left155)))

# ── 7. an upload over LinuxGSM's _default.cfg ───────────────────────────────────────────────────
_up_calls155 = []
try:
    _p9_arm(who="part155")
    _p9_patch(_smc155, "shell_as_game_user", lambda *a, **k: (_up_calls155.append(a[2]), ("", "", 0))[1])
    _p9_patch(_files155, "_write_file_as_user", lambda *a, **k: (_up_calls155.append("write"), (True, "ok"))[1])
    _up155 = _files155.upload_file(None, "u155", "lgsm/config-lgsm/rustserver", "_default.cfg", b"port=1\n")
    _up_other155 = _files155.upload_file(None, "u155", "lgsm/config-lgsm/rustserver", "rustserver.cfg",
                                         b"port=1\n")
finally:
    _p9_restore_all()
check("upload: over LinuxGSM's _default.cfg it is refused with write_file's sentence (LinuxGSM puts its "
      "own copy back), and nothing is written; the instance's own .cfg still uploads (control)",
      _up155 == (False, _files155.CMPC_DEFAULT_CFG_REFUSED) and _up_other155[0] is True
      and _up_calls155.count("write") == 1, repr((_up155, _up_other155, _up_calls155)))

# ── 8. LinuxGSM's own backup-postponed alert: sent only through a channel alert.sh would use ───────
_al_vals155 = {}
_al_note155 = _lgp155.note(_lgp155.BACKUP_QUEUED, "lgsm_postponed", alerted=True)
_al_gs155 = type("GS155", (), {"remote": None, "short_name": "u155", "lgsm_name": "rustserver"})()
_al155 = {}
try:
    _p9_arm(who="part155")
    _p9_patch(_files155, "lgsm_get_values",
              lambda server, user, selfname, keys: {k: _al_vals155.get(k, "") for k in keys})
    for _name155, _cfg155 in (("email_unset", {"emailalert": "on"}),
                              ("email", {"emailalert": "on", "email": "ops@example.invalid"}),
                              ("telegram_unset", {"telegramalert": "on"}),
                              ("discord", {"discordalert": "on"})):
        _al_vals155.clear()
        _al_vals155.update(_cfg155)
        _al155[_name155] = _sh155._lg264_lgsm_alerted(_al_gs155, _al_note155)
finally:
    _p9_restore_all()
check("LinuxGSM's backup-postponed alert counts as sent only through a channel alert.sh sends on: email "
      "with no address, or Telegram with no token, sent nothing, so the panel's own alert still goes out",
      _al155 == {"email_unset": False, "email": True, "telegram_unset": False, "discord": True},
      repr(_al155))

check("part155: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP155_START, repr(_P9_TRIPPED[_TRIP155_START:]))
