"""Panel backup and restore, including the per-game backup schedules.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (Response, abort, jsonify, request, send_file)
from flask_login import (current_user, login_required)
from panel.core.panel_state import (_full_backup_lock, _game_backup_status)
from sqlalchemy.orm import (joinedload)
from panel.db.models import (_NO_BIRTH, AuditLog, GameServer, LOCAL_HOST_LABEL, RemoteServer,
    claim_row, db, row_birth, still_held, taken_by_another)
from panel.ops import (backup as bk, system_ops as so)
from panel.ops.ssh_manager import (backup_disk_info, delete_game_backup, list_game_backups,
    run_game_backup, stream_game_backup)
from panel.security.auth import (get_game, log_action, superadmin_required)
from panel.services import (notifications)
from panel.services.monitoring import (_PLAYER_POLL_WORKERS, _cached_player_count)
import calendar
import concurrent.futures
import os
import threading
import time
from panel.core.http import (_json_body, _json_str, _log_and_generic)
from panel.core.validation import (_attachment_header)
from panel.routes._shared import (_button_backup_running, _marked_backup, _record_full_clock,
    _record_game_clock)


class _FullBackupTally:
    """What a full backup run did, server by server, and the one-line summary it records."""

    def __init__(self):
        """Start a run with nothing backed up, failed, skipped, queued or in flight."""
        self.ok_n = self.fail_n = self.skip_n = 0
        self.failures = []      # every failure, for the recorded summary
        self.alertable = []     # the subset whose servers aren't muted by a tag, for the alert
        self.queued = []
        self.in_flight = []     # already being archived by the maintenance menu's Backup button
        self.keep_unread = False   # config.json unreadable: pruned to the maximum, not the setting

    def failed(self, gs, text):
        """Count a failure; it is alertable unless the server's tags mute its alerts.

        `gs` None is a server that is no longer there to have tags: alertable.
        """
        self.fail_n += 1
        self.failures.append(text)
        if gs is None or not notifications.alerts_muted(gs):
            self.alertable.append(self.failures[-1])

    def summary(self):
        """Return the one-line outcome recorded as the full backup's "Last run"."""
        summary = "%d server(s) backed up%s%s" % (
            self.ok_n,
            (", %d failed" % self.fail_n) if self.fail_n else "",
            (", %d skipped (players online)" % self.skip_n) if self.skip_n else "")
        if self.failures:
            summary += " — " + "; ".join(self.failures)
        if self.queued:
            summary += " — will back up once empty: " + ", ".join(self.queued)
        if self.in_flight:
            summary += " — already being backed up from the server page: " + ", ".join(self.in_flight)
        if self.keep_unread:
            summary += (" — config.json could not be read, so old backups were kept up to "
                        "the maximum (%d) rather than pruned to each server's setting"
                        % bk.MAX_FULL_KEEP)
        return summary


def _full_backup_server(app, gs, modes, tally):
    """Back up one server as part of a full run, recording the outcome in `tally`.

    Nothing is recorded for a server deleted while it was archived: its status entry and its
    backup_pending flag would be the next server's with that id (models.still_held).
    """
    force, defer = modes
    # Read before the archive: recording the outcome can commit, which expires the row.
    ident, was_pending = (gs.id, gs.name), bool(gs.backup_pending)
    # game_prune_keep, not get_game_schedule: with config.json unreadable the
    # latter answers the default keep, and the prune deleted past the server's
    # own retention.
    _keep, _keep_read = bk.game_prune_keep(gs.id)
    tally.keep_unread = tally.keep_unread or not _keep_read
    # Marked RUNNING while it runs, like the two tickers: _run_due_restarts
    # (its own thread) reads that flag to keep its hands off a server a
    # backup has just stopped to archive, and this run set nothing.
    ok, reason, was_skipped = _marked_backup(
        gs.id, gs.remote, gs.short_name, gs.lgsm_name, _keep,
        game_type=gs.game_type, port=gs.port, force=force,
        query_type=gs.query_type, runner=run_game_backup)
    if still_held(gs):
        _record_full_backup_outcome(gs, (ok, reason, was_skipped), defer, tally)
        _schedule_after_full(app, ident, (ok, was_skipped), (defer, was_pending))


def _schedule_after_full(app, ident, result, queue):
    """A full run's schedule bookkeeping for one server: its clock, and when it was queued.

    The CLOCK: "Back up game servers now" moved only full_backup_last, never the server's own
    schedule clock, so every server it had just archived still looked due to the hourly ticker,
    which archived it again at its old due time — another stop and restart, another multi-GB
    archive, and the prune to `keep` evicting an older restore point early. The per-server "Back
    up now" and the queued sweep both move it for exactly this reason; this third path did not.
    Only an archive that worked moves it, as there: a skipped or failed server stays due.

    The QUEUE time: a server this run queues ('wait until empty') that was not already waiting
    starts a new wait, which _shared._report_long_queue measures.

    A write that fails is logged, never raised: it would reach _full_backup_next's except and
    tally a backup that worked as failed too, with a "Backup failed" alert about it.
    """
    sid, gname = ident
    ok, was_skipped = result
    defer, was_pending = queue
    try:
        if ok and not was_skipped:
            _record_game_clock(app, sid, gname)
        elif was_skipped and defer and not was_pending:
            bk.record_queued(sid)
    except Exception:
        app.logger.warning("could not save the backup schedule of %s after the full backup",
                           gname, exc_info=True)


def _record_full_backup_outcome(gs, result, defer, tally):
    """One server's outcome in a full run: its status entry, its queue flag, the tally."""
    ok, reason, was_skipped = result
    # ...and the outcome replaces the mark, which would otherwise hold the
    # restart sweep off this server for good.
    _game_backup_status[gs.id] = {
        "running": False, "ok": (None if was_skipped else ok),
        "busy": was_skipped,
        "msg": (reason or ("Backed up" if ok else "failed")), "ts": time.time()}
    if was_skipped:
        tally.skip_n += 1
        if defer:
            gs.backup_pending = True   # ticker backs it up once it empties
            db.session.commit()
            tally.queued.append(gs.name)
        return
    if gs.backup_pending:          # this run satisfied any prior queue
        gs.backup_pending = False
        db.session.commit()
    if ok:
        tally.ok_n += 1
    else:
        tally.failed(gs, "%s: %s" % (gs.name, reason or "failed"))


def _full_backup_next(app, gs, modes, tally):
    """The full run's loop body for one server of the list it read at the start.

    The list is read once and each archive takes minutes. A server deleted since is skipped
    without reading its object, which would reload from the row that took its id
    (models.RowReplaced).
    """
    if not still_held(gs):
        return
    gname = gs.name
    if _button_backup_running(gs.id):
        # That run holds no lock this one can see: run_game_backup would take its
        # backup.lock for an orphan once it is 5 minutes old and start a second
        # archive of the same files. It is being backed up; say so, move on.
        tally.in_flight.append(gname)
        return
    try:
        _full_backup_server(app, gs, modes, tally)
    except Exception as e:
        tally.failed(gs if still_held(gs) else None,
                     "%s: backup error (%s)" % (gname, type(e).__name__))
        app.logger.warning("full backup of %s failed", gname, exc_info=True)


def _run_full_backup(app, force=False, defer=False):
    """Run LinuxGSM's backup for every installed game server (space-heavy), pruning each.

    Each is pruned to the configured keep-count. Records a one-line outcome. Background; only
    one at a time.

    force=True   → back up even servers with players (disconnects them).
    defer=True   → back up empty servers now; QUEUE busy ones (backup_pending) so the hourly
                   ticker backs them up automatically once they empty.
    Neither      → back up empty servers, skip busy ones (no queue).

    _trigger_full_backup hands the lock over ALREADY HELD; the finally below releases it. It
    used to acquire here and return silently when it lost, which is the losing half of the
    race described there.
    """
    try:
        # The keep is resolved PER SERVER inside the loop below, not once out here. A server
        # can carry its own retention override — the schedule route writes it,
        # get_game_schedule resolves "its override where set, else the global default", the
        # API and the disk projection in the UI both show it — and pruning is an unconditional
        # `rm` of everything past `keep`. Reading the global value once meant a full backup
        # deleted archives the operator had explicitly said to retain, on every server that
        # had raised its own number. Only the scheduled ticker was getting this right.
        tally = _FullBackupTally()
        # Keep the whole run inside ONE app context: run_command touches the remote's ORM
        # attributes, which would raise DetachedInstanceError once the session is gone.
        with app.app_context():
            servers = [gs for gs in GameServer.query.filter_by(installed=True).all() if gs.remote_id]
            for gs in servers:
                _full_backup_next(app, gs, (force, defer), tally)
        summary = tally.summary()
        # The recorded summary keeps EVERY failure (it is the operator's record); the alert
        # carries only the servers whose tags haven't muted them, and is skipped entirely when
        # every failure came from a muted server.
        if tally.alertable:
            notifications.notify("backup_failed", "Backup failed",
                                 "%d server backup(s) failed: %s"
                                 % (len(tally.alertable), "; ".join(tally.alertable)))
        _record_full_clock(app, summary[:500])
    except Exception:
        app.logger.warning("full backup run failed", exc_info=True)
        notifications.notify("backup_failed", "Backup run failed",
                             "The panel backup run errored before completing.")
    finally:
        _full_backup_lock.release()


def _fetch_backup_listings(app, servers):
    """Each server's LinuxGSM backup list and each host's disk, fetched in PARALLEL.

    Returns (gb_by_sid, disk_by_remote). A listing is None when the host could not be read.

    One SSH per server (LinuxGSM backup list) + one per host (disk) — fetched in PARALLEL so
    the page doesn't load in N sequential round trips; the aggregation touches no SSH.

    The worker takes the remote and short_name it needs as ARGUMENTS rather than re-reading
    them from the database. It used to open its own app_context and re-fetch the
    GameServer by id — one query, plus a second when it touched g.remote — which is the
    whole N+1. Both objects are fully loaded by the caller (joinedload), so the worker only
    reads attributes already in memory: no session is touched from the thread, which is the
    reason the re-fetch was there in the first place.
    """
    def _bk_list(item):
        sid, remote, short = item
        try:
            return sid, list_game_backups(remote, short)
        except Exception:
            return sid, None        # could not read — NOT "this server has none"

    def _bk_disk(item):
        rid, short = item
        with app.app_context():
            r = db.session.get(RemoteServer, rid)
            try:
                return rid, (backup_disk_info(r, short) if r else {"free": 0, "total": 0})
            except Exception:
                return rid, {"free": 0, "total": 0}

    disk_by_remote = {}   # remote_id -> {free,total}; computed once per host
    gb_by_sid, remote_short = {}, {}
    for g in servers:
        remote_short.setdefault(g.remote_id, g.short_name)
    if servers:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(_PLAYER_POLL_WORKERS, len(servers))) as ex:
            for sid, gb in ex.map(_bk_list, [(g.id, g.remote, g.short_name) for g in servers]):
                gb_by_sid[sid] = gb
    if remote_short:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(_PLAYER_POLL_WORKERS, len(remote_short))) as ex:
            for rid, di in ex.map(_bk_disk, list(remote_short.items())):
                disk_by_remote[rid] = di
    return gb_by_sid, disk_by_remote


def _game_backup_row(gs, gb, hdisk):
    """One server's row on the all-servers Backups page, and the bytes its finished backups hold.

    `gb` is its listing (None when the host could not be read) and `hdisk` its host's disk.
    Returns (row, done_bytes); the row's est_backup is its largest finished backup.
    """
    gb_unreadable = gb is None
    gb = gb or []
    # A backup being written right now is partial — don't count it toward totals or the
    # next-size estimate (it would read as a too-small worst case).
    done = [b for b in gb if not b.get("in_progress")]
    done_bytes = sum(b.get("size", 0) for b in done)
    _est_one = max((b.get("size", 0) for b in done), default=0)  # largest = worst case
    rem = gs.remote
    host_label = "This host" if getattr(rem, "is_local", False) else (rem.name or rem.host or "remote")
    return {"id": gs.id, "name": gs.name, "backups": gb,
            "backups_unreadable": gb_unreadable,
            "status": _game_backup_status.get(gs.id),
            "schedule": bk.get_game_schedule(gs.id),
            "host": host_label,
            "est_backup": _est_one,  # largest existing backup = worst-case next size
            "disk": {"free": hdisk["free"], "total": hdisk["total"]}}, done_bytes


def _last_scheduled_backup():
    """The newest automatic (scheduled) game-server backup: {"at", "ok", "ok_at"}, or None.

    From the audit row _record_backup_outcome writes for every scheduled backup, success or not,
    and NOT from the servers' clocks: a clock also moves when it is first started (no backup at
    all), on a per-server or queued backup, and on a failure — so the newest clock says when a
    clock last moved, not when the schedule last backed anything up. The overdue report is not
    one of these rows: it has its own action (_shared._report_overdue_skip).

    `ok_at` is the newest one that WORKED (None if none did), read only when the newest failed:
    the rows are every server's, and one host failing hourly made the newest row a failure that
    hid the other servers' backups the night before. One or two indexed queries (action),
    whatever the number of servers.
    """
    q = (db.session.query(AuditLog.timestamp, AuditLog.success)
         .filter(AuditLog.action == "scheduled_backup").order_by(AuditLog.id.desc()))
    row = q.first()
    if row is None or row[0] is None:
        return None
    good = row if row[1] else q.filter(AuditLog.success.is_(True)).first()
    return {"at": calendar.timegm(row[0].timetuple()), "ok": bool(row[1]),
            "ok_at": calendar.timegm(good[0].timetuple()) if good and good[0] else None}


def _back_up_one_now(app, server_id, gname, opts, born):
    """The on-demand backup worker's body: run it, move the clock, return the status to show.

    `born` is the row the request saw (models.row_birth). The archive takes minutes; the clock is
    moved only if the server is still that one when it ends — it is config.json keyed by the id,
    and the server that took a deleted one's id inherited it.
    """
    keep, force = opts
    # This module's own lookup when the request had no identity to hand over (claim_row's
    # fallback, through the names the tests stub here).
    g = (db.session.get(GameServer, server_id) if born is _NO_BIRTH
         else claim_row(GameServer, server_id, born))
    if not g or not g.remote:
        return {"running": False, "ok": False, "msg": "server is no longer available",
                "ts": time.time()}
    ok, reason, was_skipped = run_game_backup(
        g.remote, g.short_name, g.lgsm_name, keep,
        game_type=g.game_type, port=g.port, force=force,
        query_type=g.query_type)
    if ok and not was_skipped and still_held(g):
        # Move this server's schedule clock, exactly as the scheduled path does.
        # record_game_backup is what game_backup_due measures against, and it was
        # called from ONE place — so a backup taken by hand left the scheduler
        # believing none had happened, and the hourly ticker archived the same
        # server again within the hour. Not recorded when SKIPPED: the ticker
        # deliberately leaves the clock alone there so the server stays due and is
        # retried once it empties.
        _record_game_clock(app, server_id, gname)
    return {"running": False, "ok": (None if was_skipped else ok), "busy": was_skipped,
            "msg": (reason or ("Backed up" if ok else "failed")), "ts": time.time()}


def _publish_backup_status(app, server_id, born, status):
    """Show an on-demand backup's outcome on its server's card — unless the id is another's now."""
    if status is None:
        return
    with app.app_context():
        if taken_by_another(GameServer, server_id, born):
            return
    _game_backup_status[server_id] = status


def register(app):
    """Register the game-server and panel backup routes, and the panel host's OS maintenance."""
    _register_full_backup(app)
    _register_game_backup(app)
    _register_game_backup_files(app)
    _register_game_backup_settings(app)
    _register_backup_overview(app)
    _register_panel_backups(app)
    _register_panel_diagnostics(app)
    _register_panel_host_os(app)


def _register_full_backup(app):
    """Full backup of every installed server: the players precheck and the start."""
    def _trigger_full_backup(force=False, defer=False):
        # Acquire HERE, atomically, and hand the held lock to the worker — the shape
        # api_panel_backup_game below and both runners in _shared.py already use. A `locked()`
        # test followed by a thread start is two steps: any of the three other holders (the manual
        # per-server backup, the hourly ticker, the 'wait until empty' sweep) could take the lock
        # in between, and _run_full_backup's own acquire then lost and returned in total silence.
        # The route had already answered "Full backup started", written an audit row saying it ran
        # — the very row whose success flag was corrected so /logs could not hide a refusal — and
        # left "Last run" pointing at the previous run. Nothing anywhere recorded the refusal.
        if not _full_backup_lock.acquire(blocking=False):
            return False
        try:
            threading.Thread(target=lambda: _run_full_backup(app, force=force, defer=defer),
                             daemon=True).start()
        except Exception:
            # The hand-off never happened, so nothing will release it — a leaked lock wedges every
            # backup path until a panel restart.
            _full_backup_lock.release()
            raise
        return True




    @app.route("/api/panel/backup/full/precheck")
    @login_required
    @superadmin_required
    def api_panel_backup_full_precheck():
        """Report which installed servers have players connected right now.

        The UI uses it to ask whether to disconnect them, wait until they're empty, or cancel
        before a full backup.
        """
        # Use the last poll's cached counts (instant) rather than an SSH gamedig call per server: this
        # is only a UI courtesy prompt, and the backup itself re-checks each server live and skips any
        # that are busy — so a slightly stale hint here can't disconnect anyone by mistake.
        busy = []
        total = 0
        for gs in GameServer.query.filter_by(installed=True).all():
            if not gs.remote_id:
                continue
            total += 1
            pc = _cached_player_count(gs.id)
            if pc and pc > 0:
                busy.append({"name": gs.name, "players": pc})
        return jsonify({"total": total, "busy": busy})

    @app.route("/api/panel/backup/full", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_backup_full():
        """Kick off a full (game-file) backup of all installed servers in the background.

        mode: 'now' → back up even busy servers (disconnects players); 'wait' → back up empty
        servers now and queue busy ones to back up once they empty; '' → skip busy servers.
        """
        mode = _json_str(_json_body(), "mode")
        force = (mode == "now")
        defer = (mode == "wait")
        started = _trigger_full_backup(force=force, defer=defer)
        # success=started, not True. The refusal below ("A full backup is already running") is a
        # request that did nothing, and hardcoding True recorded it as one that ran — so /logs
        # filtered to failures hid it, and the history showed two full backups where one happened.
        # `started` is right there. The reboot route on the remote page already carries this exact
        # correction: "log_action's default (True) records a refused reboot as one that happened".
        log_action(current_user, "panel_full_backup", target=LOCAL_HOST_LABEL,
                   detail="mode=%s%s" % (mode or "default", "" if started else " (refused: already running)"),
                   success=bool(started))
        if not started:
            return jsonify({"success": True, "running": True, "message": "A full backup is already running."})
        if defer:
            msg = ("Backing up empty servers now; any with players will back up automatically once "
                   "they're empty.")
        elif force:
            msg = "Backing up all servers now — those with players are briefly stopped (players disconnected)."
        else:
            msg = "Full backup started — this can take a while for large servers."
        return jsonify({"success": True, "running": True, "message": msg})


def _register_game_backup(app):
    """Back up one game server on demand, in the background."""
    @app.route("/api/panel/backup/game/<int:server_id>", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_backup_game(server_id):
        """Run LinuxGSM's backup for a single server on demand (background).

        Serialised with the full backup via the same lock so game backups never overlap and thrash
        the disk.
        """
        gs = get_game(server_id)
        if not gs.installed or not gs.remote_id:
            return jsonify({"success": False, "message": "Server is not installed."}), 400
        # `force` = the admin already saw the "players online" prompt and chose to back up anyway
        # (which will disconnect them). Default off, so a normal click never kicks players.
        force = bool(_json_body().get("force"))
        if _button_backup_running(server_id):
            # The maintenance menu's Backup is archiving it now, outside the lock below; a second
            # run would take that backup's lock for an orphan and archive the same files again.
            return jsonify({"success": False, "message": "This server is already being backed up "
                            "from its page — wait for that to finish."}), 200
        if not _full_backup_lock.acquire(blocking=False):
            return jsonify({"success": False, "message": "A backup is already running — try again in a moment."}), 200
        # From here the lock is HELD; the worker's finally releases it. But if we fail to even hand
        # off to the worker (config read throws, thread can't start), release it ourselves — a leaked
        # lock would wedge ALL backups until a panel restart.
        try:
            # This server's own retention, not the global default — see the comment in
            # _run_full_backup. "Back up now" pruning to the global number deleted archives the
            # per-server override said to keep. game_prune_keep, because with config.json unreadable
            # that lookup answers the DEFAULT, which is the same deletion by another route.
            keep, keep_read = bk.game_prune_keep(server_id)
            gname = gs.name   # plain string for logging; the ORM objects are re-fetched in the worker
            _game_backup_status[server_id] = {"running": True, "ok": None, "msg": "", "ts": time.time()}
            _start_backup_worker(server_id, gname, (keep, force), row_birth(gs))
        except Exception:
            _full_backup_lock.release()
            _game_backup_status[server_id] = {"running": False, "ok": False,
                                              "msg": "couldn't start the backup", "ts": time.time()}
            return jsonify({"success": False, "message": _log_and_generic("could not start backup")}), 500
        log_action(current_user, "game_backup", target=gname, success=True, server=gs)
        return jsonify({"success": True, "running": True,
                        "message": "Backing up " + gname + " — it'll appear below when done."
                                   + ("" if keep_read else
                                      " config.json could not be read, so no older backup within "
                                      "the maximum retention (%d) will be pruned." % bk.MAX_FULL_KEEP)})

    def _start_backup_worker(server_id, gname, opts, born=_NO_BIRTH):
        def _worker():
            # Re-fetch inside a fresh app context: the request's DB session is gone by the time this
            # thread runs, so ORM objects captured outside would raise DetachedInstanceError the
            # moment run_command touches the remote's connection attributes.
            status = None
            try:
                with app.app_context():
                    status = _back_up_one_now(app, server_id, gname, opts, born)
            except Exception as e:
                app.logger.warning("on-demand backup of %s failed", gname, exc_info=True)
                status = {"running": False, "ok": False,
                          "msg": "backup error (%s) — check the host is reachable "
                                 "and has free disk space" % type(e).__name__,
                          "ts": time.time()}
            finally:
                try:
                    _publish_backup_status(app, server_id, born, status)
                finally:
                    _full_backup_lock.release()

        threading.Thread(target=_worker, daemon=True).start()



def _register_game_backup_files(app):
    """One game server's backup archives: delete and download."""
    def _find_game_backup(gs, name):
        """(match, unreadable) for the archive called `name` on this server's host.

        Validating against the real listing — rather than building a path out of user input — is
        what keeps this path-injection safe, and that part is unchanged. What is new is the THIRD
        state: list_game_backups returns None when the host could not be READ, and app.py's
        version iterates it (`for b in list_game_backups(...)`), so both buttons in the Backups
        card raised TypeError on an unreachable host and answered a 500 whose body blamed the
        panel. Coercing it back to [] would restore the older, calmer lie — "Backup not found."
        about a directory nobody reached. Same three states the /info route below keeps.
        """
        try:
            listing = list_game_backups(gs.remote, gs.short_name) if gs.remote_id else []
        except Exception:
            listing = None
        if listing is None:
            return None, True
        return next((b for b in listing if b.get("name") == name), None), False

    # What to say when the listing could not be read — the wording the per-server card already
    # uses (static/js/server_files.js), so the two do not contradict each other.
    _BK_UNREADABLE = ("Couldn't read this server's backups — the host didn't answer. "
                      "This is not the same as there being none.")

    @app.route("/api/panel/backup/game/<int:server_id>/delete", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_backup_game_delete(server_id):
        """Delete one game-server backup archive."""
        gs = get_game(server_id)
        name = _json_body().get("name") or ""
        match, unreadable = _find_game_backup(gs, name)
        if unreadable:
            # str(): `name` is whatever the JSON body carried, and this is the one path that
            # records it before the listing has vouched for it.
            log_action(current_user, "game_backup_delete", target=gs.name,
                       detail="refused: could not read the host's backup listing (%s)"
                              % str(name)[:120], success=False, server=gs)
            return jsonify({"success": False, "message": _BK_UNREADABLE}), 200
        if not match:
            return jsonify({"success": False, "message": "Backup not found."}), 404
        try:
            ok = delete_game_backup(gs.remote, gs.short_name, match["name"])
            log_action(current_user, "game_backup_delete", target=gs.name,
                       detail=match["name"], success=ok, server=gs)
            return jsonify({"success": ok, "message": ("Deleted." if ok else "Delete failed.")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("game backup delete failed")}), 200

    @app.route("/backup/game/<int:server_id>/download")
    @login_required
    @superadmin_required
    def panel_backup_game_download(server_id):
        """Stream a game-server backup archive to the browser.

        The files live in the game user's home, so they're read via sudo/SSH rather than served
        from disk.
        """
        gs = get_game(server_id)
        match, unreadable = _find_game_backup(gs, request.args.get("name") or "")
        if unreadable:
            # 502, not 404: "no such backup" is a claim about the host's backup directory, and we
            # never read it. It used to be a TypeError — Werkzeug's HTML 500 page where a file
            # should have been, and a traceback in the panel log for a host that simply did not
            # answer.
            return Response(_BK_UNREADABLE + "\n", status=502, mimetype="text/plain")
        if not match:
            abort(404)
        log_action(current_user, "game_backup_download", target=gs.name, detail=match["name"],
                   server=gs)
        resp = Response(stream_game_backup(gs.remote, gs.short_name, match["name"]),
                        mimetype="application/octet-stream")
        resp.headers["Content-Length"] = str(match["size"])
        # _attachment_header, not a hand-built one: this name is read off the HOST's filesystem
        # (list_game_backups basenames whatever is in ~/lgsm/backup), so it is not the panel's
        # string to trust. A quoted f-string put it straight into a header that WSGI encodes as
        # latin-1, and both ways that can go are a 500 on a download that should have worked:
        # Werkzeug raises ValueError on a CR/LF in the value, and any character outside latin-1 —
        # an em-dash, a CJK name, an emoji in a map-pack archive — raises UnicodeEncodeError when
        # the response is serialised. The helper scrubs the ASCII copy and carries the real name
        # in RFC 5987's filename*, which is what the file browser's own download already does.
        resp.headers["Content-Disposition"] = _attachment_header(match["name"])
        return resp


def _register_game_backup_settings(app):
    """One game server's backup schedule and its backup picture."""
    @app.route("/api/panel/backup/game/<int:server_id>/schedule", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_backup_game_schedule(server_id):
        """Set one server's backup schedule.

        `interval` and `keep` are each a number to override, or "default" (or "") to inherit the
        global schedule. A field LEFT OUT of the body is left as it is, so a client changing one of
        the two cannot clear the other by accident.
        """
        gs = get_game(server_id)
        data = _json_body()

        def _field(v):
            # "" as well as "default". The per-server override is a number box now, and leaving it
            # EMPTY is how you say "use the global default" — a <select> could carry a labelled
            # "Default" option, a number input cannot. An empty string ALREADY landed here, via
            # int("") raising below; this states the contract instead of leaving the UI's only way
            # to clear an override resting on an exception nobody wrote down.
            if v is None or v == "default" or (isinstance(v, str) and not v.strip()):
                return None
            try:
                return int(v)   # OverflowError guards against JSON infinity (e.g. 1e400)
            except (TypeError, ValueError, OverflowError):
                return None
        # Absent means "not this one", which is a different request from "clear it". Both pages
        # posted both fields on a change to either, and a select that had no option for the stored
        # value turned an interval change into a silent reset of retention.
        sched = bk.set_game_schedule(
            server_id,
            _field(data["interval"]) if "interval" in data else bk.UNCHANGED,
            _field(data["keep"]) if "keep" in data else bk.UNCHANGED)
        log_action(current_user, "game_backup_schedule", target=gs.name,
                   detail="interval=%s keep=%s" % (sched["interval_days"], sched["keep"]),
                   server=gs)
        return jsonify({"success": True, "schedule": sched})

    @app.route("/api/panel/backup/game/<int:server_id>/info")
    @login_required
    @superadmin_required
    def api_panel_backup_game_info(server_id):
        """One server's backup picture for its Files & Config tab.

        That is its schedule (plus the global default it may inherit), its existing LinuxGSM
        backups, host disk headroom, and the live status of any in-flight backup. Single-server on
        purpose — opening the tab must not scan every host the way the all-servers
        /api/panel/backups does.
        """
        gs = get_game(server_id)
        try:
            backups = list_game_backups(gs.remote, gs.short_name) if gs.remote_id else []
        except Exception:
            backups = None
        # None means the host could not be READ. It used to arrive as [] — same as a server with
        # no backups yet — and the card said "No backups yet." about a directory it never reached.
        # Reported separately from the (now empty) list so the totals below stay arithmetic.
        backups_unreadable = backups is None
        backups = backups or []
        try:
            disk = backup_disk_info(gs.remote, gs.short_name) if gs.remote_id else {"free": 0, "total": 0}
        except Exception:
            disk = {"free": 0, "total": 0}
        done = [b for b in backups if not b.get("in_progress")]
        est = max((b.get("size", 0) for b in done), default=0)   # largest existing = worst-case next
        default = bk.get_full_settings()
        return jsonify({
            "installed": bool(gs.installed and gs.remote_id),
            "schedule": bk.get_game_schedule(gs.id),
            "default": {"interval_days": default["interval_days"], "keep": default["keep"]},
            "backups": backups,
            "backups_unreadable": backups_unreadable,
            "disk": {"free": disk.get("free", 0), "total": disk.get("total", 0)},
            "est_backup": est,
            "status": _game_backup_status.get(gs.id),
        })


def _register_backup_overview(app):
    """Register the all-servers Backups page's data."""
    @app.route("/api/panel/backups")
    @login_required
    @superadmin_required
    def api_panel_backups():
        """List panel backups + retention settings, and every game server's backups.

        That is: the panel's own backups and retention settings, plus full (game-file) backup
        settings/status and each installed game server's LinuxGSM backups.
        """
        try:
            games = []
            backup_bytes = 0   # total size of all existing game backups
            est_cycle = 0      # estimated size of ONE full backup run (all servers), from newest each
            # joinedload the remote: the listing worker needs it, and letting each worker lazy-load
            # its own cost one SELECT per server on top of the one it already did to re-fetch the
            # server. At 300 servers that was 644 queries for this endpoint; it is now host-bounded.
            servers = [g for g in GameServer.query.options(joinedload(GameServer.remote))
                       .filter_by(installed=True).all() if g.remote_id]
            # One SSH per server + one per host, in parallel — see _fetch_backup_listings.
            gb_by_sid, disk_by_remote = _fetch_backup_listings(app, servers)
            for gs in servers:
                hdisk = disk_by_remote.get(gs.remote_id, {"free": 0, "total": 0})
                row, done_bytes = _game_backup_row(gs, gb_by_sid.get(gs.id), hdisk)
                backup_bytes += done_bytes
                est_cycle += row["est_backup"]
                games.append(row)
            # Top-line disk uses the first host (kept for the summary); per-server disk is authoritative.
            first = next(iter(disk_by_remote.values()), {"free": 0, "total": 0})
            return jsonify({"backups": bk.list_backups(), "settings": bk.get_settings(),
                            # The retention numbers are TYPED in the UI now, not picked from a list,
                            # so the browser needs the same bounds the server clamps to — one
                            # source, rather than the same two numbers written out in three places.
                            "limits": bk.keep_limits(),
                            "full": bk.get_full_settings(), "full_running": _full_backup_lock.locked(),
                            "scheduled": _last_scheduled_backup(),
                            "games": games, "multi_host": len(disk_by_remote) > 1,
                            "disk": {"free": first["free"], "total": first["total"],
                                     "backup_bytes": backup_bytes, "est_cycle": est_cycle}})
        except Exception:
            return jsonify({"error": _log_and_generic("list backups failed")}), 200


def _register_panel_backups(app):
    """Register the panel's own backups: create, delete, restore, download and settings."""
    @app.route("/api/panel/backup", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_backup_create():
        """Create a backup now (database + config + encryption keys)."""
        try:
            ok, res = bk.create_backup("manual")
            log_action(current_user, "panel_backup_create", target=LOCAL_HOST_LABEL, detail=res if ok else "", success=ok)
            return jsonify({"success": ok, "message": ("Backup created." if ok else res),
                            "name": res if ok else ""})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("backup failed")}), 200

    @app.route("/api/panel/backup/delete", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_backup_delete():
        # _json_str, because a non-string reached backup._safe_path and raised TypeError out of
        # os.path — "expected str, bytes or os.PathLike object, not int", as a 500.
        name = _json_str(_json_body(), "name")
        ok, msg = bk.delete_backup(name)
        log_action(current_user, "panel_backup_delete", target=name, success=ok)
        return jsonify({"success": ok, "message": msg})

    @app.route("/api/panel/backup/restore", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_backup_restore():
        """Restore a panel backup (destructive).

        It takes a pre-restore safety backup, then swaps the data into place and restarts the
        panel.
        """
        _b = _json_body()
        name = _json_str(_b, "name")
        # Optional: only an encrypted archive needs it, and only when it was written under a
        # different passphrase than the one configured now (or this is a fresh install).
        # skip_safety_backup: the operator's answer to a pre-restore copy that could not be
        # written. Never a default — see backup._restore_validated.
        ok, msg = bk.restore_backup(name, passphrase=_b.get("passphrase") or None,
                                    skip_safety_backup=bool(_b.get("skip_safety_backup")))
        log_action(current_user, "panel_backup_restore", target=name, success=ok)
        return jsonify({"success": ok, "message": msg})

    @app.route("/api/panel/backup/download/<path:name>")
    @login_required
    @superadmin_required
    def api_panel_backup_download(name):
        p = bk._safe_path(name)
        if not p:
            abort(404)
        safe_name = os.path.basename(name)   # already validated by _safe_path; keep CodeQL happy
        log_action(current_user, "panel_backup_download", target=safe_name)
        return send_file(str(p), as_attachment=True, download_name=safe_name)

    @app.route("/api/panel/backup/settings", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_backup_settings():
        data = _json_body()
        s = bk.set_settings(enabled=data.get("enabled"), keep_days=data.get("keep_days"))
        full = bk.set_full_settings(interval_days=data.get("full_interval_days"),
                                    keep=data.get("full_keep"))
        # Absent key = leave it alone, so an unrelated settings save cannot silently turn
        # encryption off. "" is the explicit "stop encrypting". Never logged or echoed back.
        if "passphrase" in data:
            _pp = data.get("passphrase") or ""
            # bk.MIN_PASSPHRASE_LEN, not a literal 12: set_passphrase() enforces the same rule and
            # raises below it, so two independent numbers here would mean a drift turns a friendly
            # 400 into a 500.
            if _pp and len(_pp) < bk.MIN_PASSPHRASE_LEN:
                return jsonify({"success": False,
                                "message": "Use at least %d characters — this is the only thing "
                                           "protecting a backup that leaves the machine."
                                           % bk.MIN_PASSPHRASE_LEN}), 400
            bk.set_passphrase(_pp)
            s = bk.get_settings()
            log_action(current_user, "panel_backup_encryption", target=LOCAL_HOST_LABEL,
                       detail=("enabled" if _pp else "disabled"))
        log_action(current_user, "panel_backup_settings", target=LOCAL_HOST_LABEL, detail=str(s))
        return jsonify({"success": True, "settings": s, "full": full})


def _register_panel_diagnostics(app):
    """Register the diagnostic bundle, and the panel host's automatic security updates."""
    @app.route("/api/panel/debug-report")
    @login_required
    @superadmin_required
    def api_panel_debug_report():
        """A diagnostic bundle the operator can attach to a GitHub issue.

        {report, summary, issue_body, issues_url, filename}: whitelisted fields, classes and
        counts, and a log tail with known names pseudonymised and secrets redacted (see
        panel/ops/debug_report). Best-effort, so the page asks the operator to review it before
        sharing. One report is built at a time: a second request waits for the first's result.
        """
        from panel.ops.debug_report import ReportBusy
        try:
            return jsonify(so.generate_debug_report())
        except ReportBusy:
            return jsonify({"error": "A debug report is still being built. Try again in a "
                                     "minute."}), 429
        except Exception:
            return jsonify({"error": _log_and_generic("debug report failed")}), 500

    @app.route("/api/panel/auto-updates")
    @login_required
    @superadmin_required
    def api_panel_auto_updates():
        """Whether automatic OS security updates are installed + enabled."""
        try:
            return jsonify(so.unattended_upgrades_status())
        except Exception:
            return jsonify({"error": _log_and_generic("auto-updates status failed")}), 500

    @app.route("/api/panel/enable-auto-updates", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_enable_auto_updates():
        """Install + enable unattended-upgrades so the OS patches itself."""
        try:
            ok, msg = so.enable_unattended_upgrades()
            log_action(current_user, "enable_auto_updates", target=LOCAL_HOST_LABEL, detail=msg, success=ok)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False,
                            "message": _log_and_generic("enable auto-updates failed")}), 500


def _register_panel_host_os(app):
    """Register the panel host's OS updates and reboot."""
    @app.route("/api/server-management/os-update-check")
    @login_required
    @superadmin_required
    def api_os_update_check():
        """Check for available OS updates."""
        result = so.os_update_available()
        return jsonify(result)

    @app.route("/api/server-management/os-update-run", methods=["POST"])
    @login_required
    @superadmin_required
    def api_os_update_run():
        """Run apt upgrade."""
        success, msg = so.os_run_update()
        if success:
            log_action(current_user, "os_update_run", target=LOCAL_HOST_LABEL, detail=msg)
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "message": msg}), 500

    @app.route("/api/server-management/os-update-log")
    @login_required
    @superadmin_required
    def api_os_update_log():
        """Get recent apt history."""
        return jsonify(so.os_update_log())

    @app.route("/api/server-management/reboot", methods=["POST"])
    @login_required
    @superadmin_required
    def api_server_reboot():
        """Reboot the server."""
        data = _json_body()
        delay = data.get("delay", 5)
        # OverflowError is the one server_reboot's clamp does not catch: `{"delay": Infinity}`.
        if isinstance(delay, float) and not delay.is_integer():
            return jsonify({"success": False,
                            "message": "The reboot delay must be a number of seconds (0-300)."}), 400
        # Through the same expected-offline path Reboot now on a remote host takes
        # (monitoring._reboot_expecting_offline). This one called server_reboot bare, so every
        # game server on the panel host was still "up" in the monitor's memory when the reboot
        # verb ran — and the shutdown stops the games before it stops the panel, so a monitor pass
        # in that window pushed "went offline unexpectedly" for each of them, about a reboot the
        # panel had itself just made. No local host row (a panel with no servers on its own host)
        # means nothing to mark, so it reboots as before.
        from panel.services.monitoring import _reboot_expecting_offline
        try:
            _local = RemoteServer.query.filter_by(is_local=True).first()
        except Exception:
            # Marking is a courtesy to the alert channel; a reboot the operator asked for is not
            # refused because the row could not be read.
            import logging
            logging.getLogger("panel").debug("reboot: no local host row to mark expected-offline",
                                             exc_info=True)
            _local = None
        if _local is not None:
            success, msg = _reboot_expecting_offline(_local, lambda _r: so.server_reboot(delay))
        else:
            success, msg = so.server_reboot(delay)
        if success:
            log_action(current_user, "server_reboot", target=LOCAL_HOST_LABEL, detail=f"delay={delay}s")
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "message": msg}), 500
