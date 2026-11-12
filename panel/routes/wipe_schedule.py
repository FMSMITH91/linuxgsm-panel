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
from panel.core.panel_state import _full_backup_lock, _game_backup_status, r36j_route_job, r36j_route_jobs
from panel.db.models import GameServer, db, still_held
from panel.ops import backup as bk
from panel.ops import ssh_manager as _sm
from panel.security.auth import (MANAGE_SERVERS, get_game, log_action, permission_required,
                                 server_access_required)
from panel.services import lgsm_players as _lgp
from panel.services import wipe_schedule as wipe
from panel.services.monitoring import _end_offline_window, _mark_expected_offline
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
    out.update({k: entry.get(k) for k in ("kind", "preset", "at", "cron", "tz", "wait_empty")})
    last = entry.get("last")
    if isinstance(last, dict):
        last = {k: v for k, v in last.items() if k != "i18n"}
        last["detail"] = _r37b_shown(last.get("detail"), entry["last"].get("i18n"))
    out.update(next=None if state else nxt, pending=bool(entry.get("pending_since")) or bool(state),
               wait=_r37b_shown(entry.get("wait"), entry.get("wait_i18n")), describe=wipe.describe(entry),
               last=last)
    return out


def _r37b_shown(english, record):
    """A stored reason in the viewer's language.

    Its sentence record (i18n.sentence_record) when it restores to a sentence, else the English kept
    beside it (an entry stored before the record was).
    """
    built = i18n.sentence_restored(record) if record is not None else None
    if isinstance(built, (i18n.Sentence, i18n.Sentences)):
        return i18n.tr(built)
    return str(english or "")


def _r37b_said(sentence):
    """A reason as stored: (English, its sentence record).

    The English for the audit row and logs, the record so the card can say it in whoever's language
    looks (_r37b_shown).
    """
    return str(sentence)[:300], i18n.sentence_record(sentence)


def _r37b_wait_reason(entry):
    """What a pending wipe waits for, as stored: its sentence when the record restores to one."""
    record = entry.get("wait_i18n")
    built = i18n.sentence_restored(record) if record is not None else None
    if isinstance(built, (i18n.Sentence, i18n.Sentences)):
        return built
    return entry.get("wait") or i18n.Sentence("no reason recorded")


def _r37b_wait(sid, sentence):
    """Store why a due wipe is waiting."""
    english, record = _r37b_said(sentence)
    wipe.patch(sid, wait=english, wait_i18n=record)


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
    if _r39a_same_pending(old, entry, gs):
        # The wipe due now is still this schedule's: it goes on under the new settings rather than
        # being dropped. The save an operator makes to untick "wait until empty" and force a wipe
        # that is waiting for players reset it (anchor now, nothing pending), so the next sweep
        # measured from the new anchor, the forced wipe never ran, and the card just showed next
        # month. Its backup is kept (same server, same kind); `tried` is not, so the next sweep
        # tries at once.
        entry.update(anchor=old.get("anchor"), pending_since=old["pending_since"],
                     backed_up=old.get("backed_up") or 0)
    return entry, None


def _r39a_same_pending(old, entry, gs):
    """Whether stored entry `old` is a wipe pending now that new `entry` schedules in the same way.

    The same server and the same kind, cron line, preset and zone; only "wait until empty" may
    differ. A changed schedule is a new one: what was pending is dropped (_r39a_dropped_pending).
    """
    return (old is not None and entry is not None and wipe.same_server(old, gs)
            and bool(old.get("pending_since"))
            and all(old.get(k) == entry.get(k) for k in ("kind", "cron", "preset", "tz")))


def _r39a_dropped_pending(gs, old, entry):
    """Audit a pending wipe a save drops (turned off, or rescheduled): it never runs. Never raises."""
    if old is None or not old.get("pending_since") or not wipe.same_server(old, gs):
        return
    if entry is not None and entry.get("pending_since") == old.get("pending_since"):
        return                  # carried over (_r39a_same_pending)
    if "wipe" in r36j_route_jobs(gs.id):
        # The sweep is trying it right now: a save during its backup is audited there
        # (_r37b_still_due), and one during LinuxGSM's wipe did not stop the wipe.
        return
    try:
        log_action(current_user, "wipe_server", target=gs.name, success=False, server=gs,
                   detail="not wiped: its schedule was turned off or changed while the wipe waited (%s)"
                          % str(old.get("wait") or "no reason recorded")[:200])
    except Exception:
        db.session.rollback()


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
    old = wipe.get(gs.id)
    wipe.put(gs.id, entry)
    log_action(current_user, "wipe_schedule_server", target=gs.name,
               detail=wipe.describe(entry) if entry else "scheduled wipe turned off", server=gs)
    _r39a_dropped_pending(gs, old, entry)
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
    english, record = _r37b_said(detail)
    wipe.patch(gs.id, pending_since=0, backed_up=0, tried=0, wait="", wait_i18n=None,
               last={"at": int(time.time()), "ok": bool(ok), "detail": english, "i18n": record})
    _cmpd_record(app, gs, ok, str(detail))


def _cmpd_backup(gs, entry):
    """The backup before a wipe: run_game_backup's (ok, reason, skipped), through the panel's path."""
    if not _full_backup_lock.acquire(blocking=False):
        return False, i18n.Sentence("another backup is running"), True
    try:
        keep, _read = bk.game_prune_keep(gs.id)
        ok, why, skipped = _shared._marked_backup(
            gs.id, gs.remote, gs.short_name, gs.lgsm_name, keep, game_type=gs.game_type, port=gs.port,
            force=not entry.get("wait_empty", True), query_type=gs.query_type,
            held=functools.partial(still_held, gs), wipe_ok=True)
        # The card's own shape (a skip is "busy", not a red failure), and only while the row is still
        # this server's: a server deleted during the backup has its id taken by the next one created.
        if still_held(gs):
            _game_backup_status[gs.id] = _shared._lg264_bk_status(ok, why, skipped)
        return ok, (why or ""), skipped
    finally:
        _full_backup_lock.release()


def _cmpd_run_wipe(app, gs, entry):
    """Run LinuxGSM's wipe command and settle the pending wipe by what its output says."""
    cmd = wipe.WIPE_COMMANDS.get(entry.get("kind"), "wipe")
    # Read before the try: a raise from its own config read is not the wipe's connection dropping.
    timeout = _lgp.timeout_for(gs.remote, gs.short_name, gs.lgsm_name, "stop", 900)
    _mark_expected_offline(gs.id, "restart")
    try:
        out, err, rc = _sm.run_as_game_user(gs.remote, gs.short_name, cmd, selfname=gs.lgsm_name,
                                            timeout=timeout)
    except Exception as exc:
        if not getattr(exc, "command_started", False):
            # Never sent (the connection did not open): nothing ran, so the server stays up and
            # the wipe stays pending, its backup kept, for the next try. The window above ends.
            _end_offline_window(gs.id)
            raise
        # Sent, and the connection dropped under it (paramiko; ssh_manager marks it): LinuxGSM's
        # wipe runs on in its own scope and wipes and restarts the server. Left pending and backed
        # up, the next try 5 minutes later ran the wipe AGAIN on the fresh map with no new backup,
        # and every 5 minutes for 12 hours on a link that drops every long command. Ended instead,
        # alerted, never retried: the operator checks what it did.
        _cmpd_finish(app, gs, False, i18n.Sentence(
            "{command}: the connection dropped while LinuxGSM's wipe ran; it may have wiped: check the "
            "server", command=cmd))
        return
    verdict, why = wipe.judge((out or "") + "\n" + (err or ""), rc, cmd)
    if verdict == "refused":
        # LinuxGSM kept it running (players on): the quiet window opened above ends, as a refused
        # Stop button's does, or a crash in it would be taken for this wipe and never paged.
        _end_offline_window(gs.id)
        _r37b_wait(gs.id, why)
        return
    if verdict == "nothing":
        # "Wipe not required": LinuxGSM took neither branch that stops the server (command_wipe.sh's
        # outer else, v26.5.0), so nothing restarts either — the window ends for the same reason.
        _end_offline_window(gs.id)
    _cmpd_finish(app, gs, verdict in ("wiped", "nothing"),
                 i18n.Sentence("{command}: {result}", command=cmd, result=why))


def _cmpd_attempt(app, gs, entry, now):
    """One try at a pending wipe: wait, back up, then wipe — never wipe after a failed backup."""
    if now - float(entry.get("pending_since") or now) > wipe.MAX_WAIT_SECONDS:
        return _cmpd_finish(app, gs, False, i18n.Sentence(
            "not wiped: still waiting after {hours} hours ({reason})", hours=wipe.MAX_WAIT_SECONDS // 3600,
            reason=_r37b_wait_reason(entry)))
    if now - float(entry.get("tried") or 0) < _RETRY_SECONDS:
        return None
    wipe.patch(gs.id, tried=now)
    # Registered for the whole try, backup and wipe, and BEFORE the reboot question is asked (the SSH
    # port move's order): a clean host reboot's census then names the wipe and refuses (a reboot
    # under it leaves the files half deleted), and a queued "restart when empty" waits for it.
    with r36j_route_job(gs.id, "wipe"):
        if _shared._reboot_holds(gs) or _shared._backup_in_progress(gs.id):
            return _r37b_wait(gs.id, i18n.Sentence("a host reboot or a backup of this server is running"))
        if _r39a_other_work(gs.id):
            _r37b_wait(gs.id, i18n.Sentence("another action on this server is running"))
            return None
        if _cmpd_backup_first(app, gs, entry) and _r37b_still_due(app, gs, entry):
            _cmpd_run_wipe(app, gs, entry)
    return None


def _r39a_other_work(sid):
    """Whether the panel is running anything else on server `sid` that a wipe must not run beside.

    A queued "stop/restart when empty" being run, a Start/Stop/Restart or long action from the
    server page, a chat bot or the bulk bar (registered "action" for its run, and the long ones
    in the console's action chain), a mods install or removal, a Run now while it launches, a content
    install: the panel's own registrations the reboot census reads (host_reboot), less this wipe's own.
    A Run now is registered only while it starts its job, which then runs detached on the host, and a
    job from the account's own crontab never registers here: unlike the reboot census, this does not
    read the host's processes, so a wipe can still start beside those. Each of those
    registers before it asks whether a wipe runs (_shared._r39a_wipe_running), and this is asked
    after the wipe registers, so two that start together never both go ahead. Before, only a backup
    and a host reboot were waited for: a queued restart already running had LinuxGSM's wipe, or the
    backup before it, run beside its stop and start, and a queued stop came back up.
    """
    from panel.services import host_reboot as _hr
    return bool([k for k in _hr._r36j_route_jobs(sid) if k != "wipe"] or _hr._q_live_actions(sid))


def _r37b_still_due(app, gs, entry):
    """Whether the stored schedule is still the pending wipe `entry` is, read again now.

    The backup before a wipe takes minutes, and the operator can turn the schedule off or save a new
    one meanwhile (the route takes no lock the sweep holds). `entry` is what this try started from,
    so the wipe ran from it regardless: a schedule turned off still wiped, and one changed from a
    map to a full wipe ran the old kind. A save writes a fresh entry (pending_since 0), so the same
    server, the same pending_since and the same kind say it is still this wipe. Otherwise nothing is
    wiped, nothing is written over the new entry, and the audit row says why (no alert: the
    operator did it).
    """
    cur = wipe.get(gs.id)
    if (cur is not None and wipe.same_server(cur, gs) and cur.get("pending_since")
            and cur.get("pending_since") == entry.get("pending_since") and cur.get("kind") == entry.get("kind")):
        return True
    try:
        log_action(None, "wipe_server", target=gs.name, success=False, server=gs,
                   detail="not wiped: its schedule was turned off or changed while the backup before it ran")
    except Exception:
        db.session.rollback()
        app.logger.warning("could not audit the dropped wipe of %s", gs.name, exc_info=True)
    return False


def _cmpd_backup_first(app, gs, entry):
    """Take the backup a wipe needs, once. True when the wipe may run; else it waits, or has ended."""
    if entry.get("backed_up"):
        return True
    ok, why, skipped = _cmpd_backup(gs, entry)
    if not _r37b_still_due(app, gs, entry):
        return False            # turned off or changed meanwhile: nothing written over the new entry
    if skipped:
        _r37b_wait(gs.id, why)
        return False
    if not ok:
        _cmpd_finish(app, gs, False, i18n.Sentence("not wiped: the backup before it failed: {reason}",
                                                   reason=why))
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
            # Not "the panel was not running": a server not installed yet, or with no host, is
            # passed over above and comes here once it is.
            _cmpd_record(app, gs, False, "skipped: it was due %d minutes ago and the panel could not "
                                         "run it then" % ((now - fire) // 60))
            return
        wipe.patch(sid, anchor=fire, pending_since=now, backed_up=0, tried=0, wait="", wait_i18n=None)
        entry = wipe.get(sid)
        if entry is None:
            return              # turned off just now
    _cmpd_attempt(app, gs, entry, now)


def sweep(app, now=None):
    """Every stored wipe schedule, settled once (each on its own: one that raises is logged)."""
    if _shared._backups_blocked_by_config(app, "scheduled wipes"):
        return
    with app.app_context():
        for sid in wipe.all_entries():
            # Read again for each server: one server's backup takes minutes, and a schedule turned
            # off or changed meanwhile must not be run from the copy read when the sweep began.
            entry = wipe.get(sid)
            if entry is None:
                continue
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
