"""Scheduled Rust wipes: the schedule card's two routes, and the sweep that runs a due wipe.

The schedule lives in config.json (panel/services/wipe_schedule.py). The sweep runs every minute on
its own supervised thread. A due wipe, in order:

1. waits while the host's clean reboot holds the server, or a backup of it is running;
2. takes a LinuxGSM backup through the panel's backup path (_marked_backup -> run_game_backup), so
   the same player check, lock sweep, disk headroom and pruning apply. With "wait until empty" on
   (the default) a backup with players online is skipped and the wipe waits; off, the backup is
   forced, as the Backup button's force is. A backup that FAILED stops the wipe: nothing is wiped
   without an archive to go back to;
3. runs LinuxGSM's `wipe` or `full-wipe` and judges its output (wipe_schedule.judge): LinuxGSM's
   own players-online refusal keeps it waiting, with the backup already taken;
4. audits every outcome as `wipe_server`, and alerts on a failure.

A wait that has gone on for MAX_WAIT_SECONDS gives up (audited and alerted). Same permission as the
server's other schedules on the Files & Config page: MANAGE_SERVERS (Scheduled Tasks).
"""
import functools
import time

from flask import jsonify, request
from flask_login import current_user, login_required

from panel.core import clock, i18n, runtime_stats
from panel.core.http import _json_body, _json_str, _log_and_generic, _r12c_json_flag
from panel.core.panel_state import _full_backup_lock, _game_backup_status
from panel.db.models import GameServer, db, still_held
from panel.ops import backup as bk
from panel.ops import ssh_manager as _sm
from panel.security.auth import (MANAGE_SERVERS, get_game, log_action, permission_required,
                                 server_access_required)
from panel.services import lgsm_players as _lgp
from panel.services import wipe_schedule as wipe
from panel.services.monitoring import _mark_expected_offline
from panel.routes import _shared

_RETRY_SECONDS = 300          # a waiting wipe is looked at again this often, not every sweep
_SWEEP_EVERY = 60


def _cmpd_view(gs):
    """What the schedule card shows for `gs`: the stored schedule, when it next runs, how it last went."""
    entry = wipe.get(gs.id)
    if entry is not None and not wipe.same_server(entry, gs):
        entry = None
    out = {"success": True, "supported": gs.game_type in wipe.WIPE_GAMES, "enabled": entry is not None}
    if entry is None:
        return out
    state, nxt = wipe.due(entry)
    out.update({k: entry.get(k) for k in ("kind", "preset", "at", "cron", "tz", "wait_empty", "last")})
    out.update(next=None if state else nxt, pending=bool(entry.get("pending_since")) or bool(state),
               wait=entry.get("wait") or "", describe=wipe.describe(entry))
    return out


def _cmpd_refuse(message, code=400):
    """The POST's refusal, in the viewer's language."""
    return jsonify({"success": False, "message": i18n.tr(message)}), code


def _cmpd_entry_from(body, gs):
    """(entry, None) for a valid request body, or (None, why)."""
    kind = _json_str(body, "kind")
    if kind not in wipe.WIPE_COMMANDS:
        return None, "kind must be map or full."
    preset = _json_str(body, "preset")
    spec, line = wipe.spec_for(preset, _json_str(body, "at"), _json_str(body, "cron"))
    if spec is None:
        return None, line
    wait_empty = _r12c_json_flag(body, "wait_empty", True)
    if wait_empty is None:
        return None, "wait_empty must be true or false."
    entry = dict(wipe.identity(gs), kind=kind, preset=preset, at=_json_str(body, "at")[:5],
                 cron=line, tz=clock.valid_timezone(body.get("tz")) or "UTC", wait_empty=wait_empty,
                 anchor=time.time(), pending_since=0, backed_up=0, tried=0, wait="")
    old = wipe.get(gs.id)
    if old is not None and wipe.same_server(old, gs) and isinstance(old.get("last"), dict):
        entry["last"] = old["last"]
    return entry, None


def _cmpd_save(gs, body):
    """The POST's work once access is checked: store or clear the schedule, audited either way."""
    enabled = _r12c_json_flag(body, "enabled", None)
    if enabled is None:
        return _cmpd_refuse("enabled must be true or false.")
    if enabled and gs.game_type not in wipe.WIPE_GAMES:
        return _cmpd_refuse("LinuxGSM has no wipe command for this game.")
    entry, why = _cmpd_entry_from(body, gs) if enabled else (None, None)
    if why:
        return _cmpd_refuse(why)
    wipe.put(gs.id, entry)
    log_action(current_user, "wipe_schedule_server", target=gs.name,
               detail=wipe.describe(entry) if entry else "scheduled wipe turned off", server=gs)
    return jsonify(_cmpd_view(gs))


def _register_routes(app):
    @app.route("/api/server/<int:server_id>/wipe-schedule", methods=["GET", "POST"])
    @login_required
    @permission_required(MANAGE_SERVERS)
    @server_access_required
    def api_server_wipe_schedule(server_id):
        """Read or set this server's scheduled map / full wipe (Rust only)."""
        gs = get_game(server_id)
        if request.method == "GET":
            return jsonify(_cmpd_view(gs))
        try:
            return _cmpd_save(gs, _json_body())
        except Exception:
            db.session.rollback()
            return jsonify({"success": False, "message": _log_and_generic("wipe schedule failed")}), 500


# ── the sweep ───────────────────────────────────────────────────────────────────────────────────
def _cmpd_record(app, gs, ok, detail):
    """Audit one scheduled wipe outcome (and alert when it is a failure). Never raises."""
    try:
        log_action(None, "wipe_server", target=gs.name, detail=detail[:500], success=ok, server=gs)
    except Exception:
        db.session.rollback()
        app.logger.warning("could not audit the scheduled wipe of %s", gs.name, exc_info=True)
    if not ok:
        _shared._alert_backup(app, gs, "Scheduled wipe did not run",
                              "%s: %s" % (gs.name, detail))


def _cmpd_finish(app, gs, ok, detail):
    """End a pending wipe: clear its wait, remember how it went, audit it."""
    wipe.patch(gs.id, pending_since=0, backed_up=0, tried=0, wait="",
               last={"at": int(time.time()), "ok": bool(ok), "detail": detail[:300]})
    _cmpd_record(app, gs, ok, detail)


def _cmpd_backup(gs, entry):
    """The backup before a wipe: run_game_backup's (ok, reason, skipped), through the panel's path."""
    if not _full_backup_lock.acquire(blocking=False):
        return False, "another backup is running", True
    try:
        keep, _read = bk.game_prune_keep(gs.id)
        ok, why, skipped = _shared._marked_backup(
            gs.id, gs.remote, gs.short_name, gs.lgsm_name, keep, game_type=gs.game_type, port=gs.port,
            force=not entry.get("wait_empty", True), query_type=gs.query_type,
            held=functools.partial(still_held, gs))
        _game_backup_status[gs.id] = {"running": False, "ok": ok, "ts": time.time(),
                                      "msg": str(why or ("Backed up" if ok else "failed"))}
        return ok, str(why or ""), skipped
    finally:
        _full_backup_lock.release()


def _cmpd_run_wipe(app, gs, entry):
    """Run LinuxGSM's wipe command and settle the pending wipe by what its output says."""
    cmd = wipe.WIPE_COMMANDS.get(entry.get("kind"), "wipe")
    _mark_expected_offline(gs.id, "restart")
    out, err, rc = _sm.run_as_game_user(
        gs.remote, gs.short_name, cmd, selfname=gs.lgsm_name,
        timeout=_lgp.timeout_for(gs.remote, gs.short_name, gs.lgsm_name, "stop", 900))
    verdict, why = wipe.judge((out or "") + "\n" + (err or ""), rc, cmd)
    if verdict == "refused":
        wipe.patch(gs.id, wait=why)
        return
    _cmpd_finish(app, gs, verdict in ("wiped", "nothing"), "%s: %s" % (cmd, why))


def _cmpd_attempt(app, gs, entry, now):
    """One try at a pending wipe: wait, back up, then wipe — never wipe after a failed backup."""
    if now - float(entry.get("pending_since") or now) > wipe.MAX_WAIT_SECONDS:
        return _cmpd_finish(app, gs, False, "not wiped: still waiting after %d hours (%s)"
                            % (wipe.MAX_WAIT_SECONDS // 3600, entry.get("wait") or "no reason recorded"))
    if now - float(entry.get("tried") or 0) < _RETRY_SECONDS:
        return None
    wipe.patch(gs.id, tried=now)
    if _shared._reboot_holds(gs) or _shared._backup_in_progress(gs.id):
        return wipe.patch(gs.id, wait="a host reboot or a backup of this server is running")
    if _cmpd_backup_first(app, gs, entry):
        _cmpd_run_wipe(app, gs, entry)
    return None


def _cmpd_backup_first(app, gs, entry):
    """Take the backup a wipe needs, once. True when the wipe may run; else it waits, or has ended."""
    if entry.get("backed_up"):
        return True
    ok, why, skipped = _cmpd_backup(gs, entry)
    if skipped:
        wipe.patch(gs.id, wait=why)
        return False
    if not ok:
        _cmpd_finish(app, gs, False, "not wiped: the backup before it failed: %s" % why)
        return False
    wipe.patch(gs.id, backed_up=int(time.time()))
    return True


def _cmpd_one(app, sid, entry, now):
    """Settle server `sid`'s stored schedule once: drop a stale one, start a due one, run a pending one."""
    gs = db.session.get(GameServer, sid)
    if gs is None or not wipe.same_server(entry, gs) or gs.game_type not in wipe.WIPE_GAMES:
        wipe.put(sid, None)      # its server is gone (or the id is another server's now)
        return
    if not gs.installed or not gs.remote_id:
        return
    if not entry.get("pending_since"):
        state, fire = wipe.due(entry, now)
        if state is None:
            return
        if state == "missed":
            wipe.patch(sid, anchor=now)
            _cmpd_record(app, gs, False, "skipped: it was due %d minutes ago and the panel was not "
                                         "running then" % ((now - fire) // 60))
            return
        wipe.patch(sid, anchor=fire, pending_since=now, backed_up=0, tried=0, wait="")
        entry = wipe.get(sid) or {}
    _cmpd_attempt(app, gs, entry, now)


def sweep(app, now=None):
    """Every stored wipe schedule, settled once (each on its own: one that raises is logged)."""
    if _shared._backups_blocked_by_config(app, "scheduled wipes"):
        return
    with app.app_context():
        for sid, entry in wipe.all_entries().items():
            try:
                _cmpd_one(app, sid, entry, time.time() if now is None else now)
            except Exception:
                db.session.rollback()
                app.logger.warning("scheduled wipe of server %s failed", sid, exc_info=True)


def _cmpd_ticker(app):
    runtime_stats.loop_started("wipe-schedule", 150)
    time.sleep(150)
    while True:
        t0 = time.time()
        try:
            sweep(app)
            runtime_stats.beat("wipe-schedule", _SWEEP_EVERY, time.time() - t0)
        except Exception:
            runtime_stats.bump("loopfail", "wipe-schedule")
            app.logger.warning("wipe-schedule pass failed", exc_info=True)
        time.sleep(_SWEEP_EVERY)


def register(app):
    """The schedule route, the template's `wipe_supported`, and the sweep's supervised thread.

    The thread gets the same supervisor every ticker does (app._make_supervisor: named, respawned,
    and not started at all under the recovery CLI's no-workers switch).
    """
    from app import _make_supervisor   # lazily: app imports this module while it is still loading
    _register_routes(app)
    app.jinja_env.globals["wipe_supported"] = lambda game_type: game_type in wipe.WIPE_GAMES
    _make_supervisor(app)("wipe-schedule", lambda: _cmpd_ticker(app))
