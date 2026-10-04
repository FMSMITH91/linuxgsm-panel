"""Helpers that more than one route module needs.

Each of these was a closure inside register_routes(), reachable by every handler in the file
because they all shared one scope. Splitting that scope is what made the sharing explicit: these
are the only eight that cross a section boundary, and each closed over `app` and nothing else, so
each takes it as its first parameter now.

flake8 is what caught them. The URL-map snapshot did not, and could not: these are referenced
inside handler BODIES, which do not run at registration — so the app still built, all 208 rules
still matched, and the routes would have failed only when someone used them. A green build over a
broken route is the exact failure this repo keeps finding; here the F821 gate was the net.
"""
from flask import (jsonify)
from flask_login import (current_user)
from panel.core.clock import (utcnow)
from panel.core.config import (ConfigUnreadable, is_unreadable, load_config)
from panel.core.http import (_json_str)
from panel.core.validation import (NOT_AN_IP, unzoned_ip_or_network)
from panel.core.panel_state import (_action_output, _console_backlog, _full_backup_lock,
    _game_backup_status, register_remote_state, register_server_state)
from panel.db.models import (_NO_BIRTH, GameServer, RemoteServer, claim_row, db, row_birth,
    still_held)
from panel.ops import (backup as bk)
from panel.ops.ssh_manager import (get_server_status, mod_restart_decision, player_count as
    sm_player_count, remote_bootstrap_vps, remote_public_ip, run_game_backup)
# Reached through the MODULE, not bound by name: these are the seams the test suite
# monkeypatches. `from x import f` copies the function object, so a stub on the source
# module would never be seen — attribute access resolves at call time and is stable
# however the handler moves.
from panel.ops import ssh_manager as _sm
from panel.security import banlist as _banlist
from panel.security.auth import (RESTART_SERVER, START_SERVER, STOP_SERVER, UPDATE_SERVER,
    VIEW_CONSOLE, get_user_permissions, log_action)
from panel.services import (notifications)
import threading
import time
from app import (_apply_whitelist_everywhere, _autoblock_hosts, _log, _mark_expected_offline,
    _prune_jobs, _run_autoblock_now, _security_whitelist, _security_whitelist_add,
    _security_whitelist_remove)
import re
from panel.core import (clock, runtime_stats, terminal)


def _begin_bootstrap(app, remote_id, opts, actor_id):
    """Seed the job registry and start the background bootstrap.

    Returns (started, message). Refuses if one is already running for this remote.
    """
    _prune_jobs(_bootstrap_jobs, _bootstrap_lock)
    with _bootstrap_lock:
        existing = _bootstrap_jobs.get(remote_id)
        if existing and existing.get("status") in ("running", "rebooting"):
            return False, "A bootstrap is already running for this server."
        job = _bootstrap_jobs[remote_id] = {
            "status": "running", "step": 0, "total": 0,
            "step_name": "Starting…", "log": [], "message": "",
            "started": time.time(), "updated": time.time(),
        }
    _start_bootstrap_job(app, remote_id, job, opts, actor_id)
    return True, "Bootstrap started."


def _bg_cache_commands(app, server_ids, autostart_ids=(), births=None):
    """Fetch + cache each server's LinuxGSM command list in the background.

    That way the "Supported Commands" panel is populated without the user hitting refresh. Install
    does this at step 5; import used to skip it, leaving the cache blank. Best-effort and
    per-server (one server's SSH failure never blocks the rest). Reading the list is read-only on
    the host — it runs the instance script with no args, which just prints its command menu.

    For the servers in `autostart_ids` it then turns Autostart on — LinuxGSM's `monitor` cron, the
    same step an install takes — when the list says the game has `monitor`. That needs the list, so
    it lives here rather than in the request. monitor restarts a server that should be running (it
    has a start lockfile) and leaves a deliberately stopped one down, so this never starts a server
    the operator stopped. The flag is set only once the cron line is written.

    `births` is {id: models.row_birth} of the rows the caller chose. The ids are looked up one
    after another, each after the last one's SSH, so a server deleted meanwhile answered with the
    server that took its id: it was handed the deleted one's command list, and Autostart was
    switched on for it — a cron line on a server nobody asked that of.
    """
    _app = app
    autostart_ids = set(autostart_ids)
    births = dict(births or {})

    def _run():
        with _app.app_context():
            for sid in server_ids:
                try:
                    gs = claim_row(GameServer, sid, births.get(sid, _NO_BIRTH))
                    if not gs:
                        continue
                    cmds = _sm.list_server_commands(gs.remote, gs.short_name, gs.lgsm_name)
                    if cmds:
                        gs.set_commands(cmds)
                        db.session.commit()
                    if sid in autostart_ids and "monitor" in {c.get("cmd") for c in cmds or []}:
                        ok, _msg = _sm.set_autostart(gs.remote, gs.short_name, True, gs.lgsm_name)
                        if ok:
                            gs.autostart = True
                            db.session.commit()
                        else:
                            _log.info("autostart for imported server %s not set: %s", sid, _msg)
                except Exception:
                    db.session.rollback()
                    _log.debug("command cache failed for server %s", sid, exc_info=True)

    threading.Thread(target=_run, daemon=True).start()


def _whitelist_mutate(app, body):
    """Shared add/remove for the global security whitelist.

    On add: persist, push the new ignoreip to the panel jail, and immediately lift any existing
    fail2ban ban / UFW auto-block for the address so a just-whitelisted admin isn't left locked out
    until the next tick. The slow firewall work (jail reload, unban) is backgrounded so the button
    responds instantly — the config is already saved and reflected in the response.
    """
    raw = _json_str(body, "ip")
    remove = bool(body.get("remove"))
    if remove:
        # The raw text only picks the entry to drop, so one stored with a zone id before the add
        # refused them can still go. What is audited and answered is the address or network it
        # names, read as the gate reads a stored entry, or a fixed text — never the request's own.
        _security_whitelist_remove(raw)
        shown = unzoned_ip_or_network(raw) or NOT_AN_IP
        threading.Thread(target=_apply_whitelist_everywhere, args=(app,), daemon=True).start()
        _banlist.refresh_soon(0)
        log_action(current_user, "whitelist_remove", target=shown)
        return jsonify({"success": True, "removed": shown, "whitelist": _security_whitelist()})
    canon = _security_whitelist_add(raw)
    if not canon:
        return jsonify({"success": False, "message": "Enter a valid IP address or CIDR (e.g. 1.2.3.4 or 10.0.0.0/8)."})
    # A single address (not a CIDR range) also gets any existing ban lifted immediately.
    _unban = canon if "/" not in canon else None
    threading.Thread(target=_apply_whitelist_everywhere, args=(app, _unban), daemon=True).start()
    _banlist.refresh_soon(0)
    for rid in _autoblock_hosts():      # release any auto-block for the now-whitelisted address
        _run_autoblock_now(app, rid)
    log_action(current_user, "whitelist_add", target=canon)
    return jsonify({"success": True, "added": canon, "whitelist": _security_whitelist()})


def _maybe_resolve_public_ip(app, remote_id):
    """Resolve + cache a remote's public IP in the BACKGROUND (one SSH), rate-limited per remote.

    Request/render paths use remote.host as the immediate connect-address fallback and pick up the
    real public IP on a later load — instead of blocking on an SSH that hangs for the full connect
    timeout when the remote is unreachable. Best-effort; never raises.
    """
    now = time.time()
    if now - _pubip_resolve_attempts.get(remote_id, 0) < 300:
        return
    _pubip_resolve_attempts[remote_id] = now
    _app = app

    def _run():
        with _app.app_context():
            try:
                remote = db.session.get(RemoteServer, remote_id)
                if remote is None or remote.public_ip:
                    return
                ip = remote_public_ip(remote)
                if ip:
                    remote.public_ip = ip
                    db.session.commit()
            except Exception:
                db.session.rollback()
                _log.debug("background public-IP resolve failed for remote %s", remote_id, exc_info=True)

    threading.Thread(target=_run, daemon=True).start()


def _lifecycle_actions(can, supports_update):
    """Return the lifecycle buttons `can` allows, as (cmd, label) in on-screen order."""
    # Order matters — this is the on-screen button order (lifecycle order reads most naturally).
    actions = []
    if can(START_SERVER):
        actions.append(("start", "Start"))
    if can(STOP_SERVER):
        actions.append(("stop", "Stop"))
    if can(RESTART_SERVER):
        actions.append(("restart", "Restart"))
    if can(UPDATE_SERVER) and supports_update:
        actions.append(("update", "Update"))
    return actions


def _server_action_buttons(app, gs):
    """Return the control bar's buttons: (actions, maintenance, all_commands, supports_update).

    Filtered by what the game supports and what the CURRENT user may run.

    Shared by the server detail page and Files & Config, which renders the same bar — the two used
    to differ only because Files & Config had no bar at all, and it told you to "restart the server
    to apply" without offering a way to do it.
    """
    user_perms = get_user_permissions(current_user)
    is_sa = current_user.is_superadmin

    def _can(perm):
        return is_sa or perm in user_perms

    all_commands = gs.get_commands()
    if not all_commands:
        _maybe_cache_commands(app, gs)
    # Some games aren't SteamCMD-based (the Call of Duty family) and have NO `update` command.
    # GameServer.supports_update is the ONE place that decides this; it used to be decided a
    # second time here as `(not cmd_set) or ("update" in cmd_set)`, which disagreed with the model
    # on the case that matters. An empty command list means it has not been fetched yet, and both
    # fail open there — except the model also knows the Call of Duty family has no `update` at
    # all, so it keeps the button hidden for those while this copy showed it.
    #
    # The consequence was the whole round trip: clicking Update on a freshly imported cod server
    # queued a LONG action, answered "watch the live console for progress", ran a command LinuxGSM
    # does not have, and discarded the error. Meanwhile /api/servers/bulk-action — which asks the
    # model — correctly skipped the same server as "no update support". Two answers to one
    # question, and the button bar had the wrong one.
    supports_update = gs.supports_update

    actions = _lifecycle_actions(_can, supports_update)

    maint_perm = {
        # monitor can restart the server: auth.ACTION_PERMISSION_MAP, which the route enforces.
        "monitor": RESTART_SERVER, "details": VIEW_CONSOLE, "check-update": VIEW_CONSOLE,
        "postdetails": VIEW_CONSOLE, "test-alert": VIEW_CONSOLE,
        "validate": UPDATE_SERVER, "backup": UPDATE_SERVER, "force-update": UPDATE_SERVER,
        "update-lgsm": UPDATE_SERVER, "mods-update": UPDATE_SERVER, "fastdl": UPDATE_SERVER,
    }
    core = {"start", "stop", "restart", "update"}
    maintenance = [
        {"cmd": c["cmd"], "desc": c["desc"]}
        for c in all_commands
        if c["cmd"] in maint_perm and c["cmd"] not in core and _can(maint_perm[c["cmd"]])
    ]
    return actions, maintenance, all_commands, supports_update


def _record_backup_outcome(app, sid, gname, ok, reason, action, title, born=_NO_BIRTH):
    """Audit an unattended backup's outcome, and alert when it failed.

    run_game_backup does not RAISE for a backup that fails: it returns (False, reason, False), and
    a host that is down reaches it as rc=-1/255 from run_command rather than as an exception on
    the tailscale and local transports. Both runners below alerted only from their `except`
    branch, so the failure shape that actually happens in production took no branch at all: a
    scheduled backup that failed sent no alert, wrote no audit row, and — because the ticker
    records the clock for a genuine failure so it does not retry hourly — was not retried either.
    The whole record was an in-memory dict the operator had to go and open a page to see, and they
    learned of it when they needed a restore.

    So: one audit row per unattended backup (success=ok, so /logs' failures filter shows it), and
    the alert on every failure rather than only on an exception. Server-scoped, so a muting tag
    still applies — the Tags UI promises muting keeps a server out of the alert channel.

    `born` (models.row_birth) is the server the backup was for. A backup runs for minutes; by id
    alone, a server deleted meanwhile was answered by the one that took its id, which then had
    the row filed under it and its tags deciding the alert.

    `title` None audits the failure without alerting: a repeat the operator was already told about
    (see _record_raised_backup).

    The audit row and the alert are written apart (_audit_backup_outcome, _alert_backup): they
    shared one try, so an audit write that failed (SQLite "database is locked") skipped the alert
    too, and the callers that mark an alert as sent before sending it (_report_once, the raise
    streak) then never sent it at all.
    """
    _bk_gs = _audit_backup_outcome(app, (sid, gname, born), ok, reason, action)
    if ok or title is None:
        return
    _alert_backup(app, _bk_gs, title,
                  "The backup of %s failed: %s" % (gname, reason or "no reason given"))


def _audit_backup_outcome(app, ident, ok, reason, action):
    """The audit row for one unattended backup of ident=(sid, gname, born). Returns its server row.

    That is claim_row's answer: None for a server deleted (or its id taken) meanwhile, and None
    when even that read failed. Never raises: this is the reporting, and the sweeps run the
    remaining servers after it. A write that failed is rolled back, because the session refuses
    every later query until it is (PendingRollbackError), and the sweep's next server would have
    failed on its first read of the database.
    """
    sid, gname, born = ident
    _bk_gs = None
    try:
        _bk_gs = claim_row(GameServer, sid, born)
        log_action(None, action, target=gname, detail=(reason or "")[:500], success=bool(ok),
                   server=_bk_gs)
    except Exception:
        app.logger.warning("could not record %s of %s", action, gname, exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            app.logger.debug("rolling back after a failed audit write failed", exc_info=True)
    return _bk_gs


def _alert_backup(app, gs, title, body):
    """One backup_failed alert, unless the server's tags mute it. Never raises.

    `gs` None (a server gone, or one that could not be read) is not muted: alerts_muted fails open
    for the same reason. notify() is documented never to raise; a channel that does anyway is
    logged here, so it is never what breaks the sweep.
    """
    try:
        if gs is not None and notifications.alerts_muted(gs):
            return
        notifications.notify("backup_failed", title, body)
    except Exception:
        app.logger.warning("could not send the '%s' alert", title, exc_info=True)


# Servers whose last unattended backup attempt RAISED (a direct-SSH host that is down, a key it
# now refuses), and when. Both sweeps retry such a server every hour, which is right for a
# transient drop, and each retry alerted again: notify() has no rate limit, so one host down for a
# weekend was ~50 "backup failed" alerts per server, two an hour for one both due and queued. One
# map for BOTH sweeps, so one outage is one alert. An entry is dropped only once run_game_backup
# has RETURNED for the server (_marked_backup), not on a pass that never reached the host — a
# schedule that is off or not due says nothing about whether the host answers. In memory on
# purpose: a restart re-alerts at most once. Registered, so a deleted server's id is forgotten.
_backup_raise_streak = register_server_state({})
# The overdue and long-queue reports below are persisted in config.json (they must survive the
# daily self-update restart). These hold the same mark for when config.json refused the write,
# so a write that keeps failing cannot turn one report into one per hour.
_overdue_reported = register_server_state({})
_queue_wait_reported = register_server_state({})


def _record_raised_backup(app, ident, exc, action, title):
    """A backup of ident=(sid, gname, born) that RAISED `exc`: audited always, alerted once.

    The first raise of a streak alerts; the hourly retries after it are audit rows only. The
    streak is marked only while the server is still the row it was (claim_row): a server deleted
    meanwhile, its id now another's, must not have its first alert muted by this one's outage.
    """
    sid, gname, born = ident
    first = sid not in _backup_raise_streak
    if first and claim_row(GameServer, sid, born) is not None:
        _backup_raise_streak[sid] = time.time()
    _record_backup_outcome(app, sid, gname, False, "backup error (%s)" % type(exc).__name__,
                           action, title if first else None, born)


def _report_once(app, ident, marker, report):
    """Send one escalation `report`=(reason, action, title, body) unless `marker` was reported.

    marker=(value, read_saved, save, fallback): read_saved(sid) is the persisted mark, save(sid,
    value) persists it, `fallback` is the in-memory map used when that write is refused. Persisted
    FIRST, so a report is never sent twice for one value: an in-memory-only mark sent the same
    alert again after every restart, and the panel restarts daily on a self-update. Marking first
    loses nothing, because nothing after it can stop the alert: the audit row is written apart
    from it (_audit_backup_outcome) and _alert_backup never raises.

    `action` is the report's OWN audit action, never the backup's: the Backups page reads the
    newest "scheduled_backup" row as the newest automatic backup, and a report filed under it read
    there as "Last automatic backup failed" about a backup that had not been attempted.
    """
    sid, gname, _born = ident
    value, read_saved, save, fallback = marker
    if value in (read_saved(sid), fallback.get(sid)):
        return False
    fallback[sid] = value
    try:
        save(sid, value)
    except Exception:
        app.logger.warning("could not save that '%s' was reported for %s", report[2], gname,
                           exc_info=True)
    reason, action, title, body = report
    _alert_backup(app, _audit_backup_outcome(app, ident, False, reason, action), title, body)
    return True


def _report_overdue_skip(app, ident, sched, reason):
    """A due server that players kept from its backup for a whole extra interval: report it once.

    The scheduled sweep skips a server with players on and leaves its clock alone, so it is
    retried every hour until it is empty at the top of an hour. A server that never is (a 24/7
    community server) was never backed up, and nothing said so: no audit row, no alert, only a
    status that a page had to be opened to see. Past twice its own interval since the clock last
    moved — one full interval overdue — that is audited and alerted, once per clock value: the
    moment a backup runs (or fails, which records the clock), it re-arms by itself. It never
    forces the backup; no player is disconnected by this.

    The text says what is KNOWN: how old the clock is, and that players were on at THIS attempt.
    Not that they were on at every attempt, which it once said: the clock is as old for a schedule
    that was off (the sweep does not touch it then), for a host whose backups raised for days (a
    raise does not move it), and for days the panel was down — none of them players' doing.
    """
    last, every = sched["last"], sched["interval_days"] * 86400
    if not last or every <= 0 or time.time() - last < 2 * every:
        return False
    text = ("its backup clock last moved %d days ago (every %d d); skipped at this attempt: %s"
            % ((time.time() - last) // 86400, sched["interval_days"], reason or "players online"))
    return _report_once(app, ident, (last, bk.overdue_alerted, bk.mark_overdue_alerted,
                                     _overdue_reported),
                        (text, "scheduled_backup_overdue", "Scheduled backup overdue",
                         "%s is overdue for its scheduled backup: %s" % (ident[1], text)))


def _report_long_queue(app, gs, sched, reason):
    """A 'wait until empty' backup still waiting after DEFAULT_FULL_INTERVAL days: report it once.

    Only for a server whose own schedule is OFF. With a schedule on, the clock is not moved while
    players keep the queued backup waiting either, so _report_overdue_skip already reports the
    same wait; reporting it here too would be two alerts for one cause. The bound is the default
    backup interval, the one a server with no override is held to.
    """
    if sched["interval_days"] > 0:
        return False
    since = bk.queued_since(gs.id)
    if not since:
        # Queued before the queue time was recorded (an upgrade): start its clock now.
        _start_queue_time(app, gs.id, gs.name)
        return False
    if time.time() - since < bk.DEFAULT_FULL_INTERVAL * 86400:
        return False
    # What is known: when it was queued, that it still is, and why THIS attempt skipped it (an
    # attempt that raised, or hours the panel was down, also kept it waiting).
    text = ("queued %d days ago and still waiting; skipped at this attempt: %s"
            % ((time.time() - since) // 86400, reason or "players online"))
    return _report_once(app, (gs.id, gs.name, row_birth(gs)),
                        (since, bk.queued_alerted, bk.mark_queued_alerted, _queue_wait_reported),
                        (text, "queued_backup_waiting", "Queued backup still waiting",
                         "The queued backup of %s is still waiting: %s" % (gs.name, text)))


def _start_queue_time(app, sid, gname):
    """bk.record_queued(sid) for a queued server with no queue time, a refused write logged.

    Called only when none is recorded, under the backup lock the full run (the other writer) also
    holds, so there is nothing to keep: the time is simply now.
    """
    try:
        bk.record_queued(sid)
    except Exception:
        app.logger.warning("could not save when %s was queued for backup", gname, exc_info=True)


def _backup_ticker_pass(app, steps):
    """One backup-ticker pass: each (label, fn, args) of `steps` run on its own. Returns failures.

    They shared ONE try, so a daily panel backup that raised (data/backups not a directory, a
    hand-edited passphrase) skipped both game-server sweeps for that pass — every pass, for as
    long as the cause lasted — and the except logged it at DEBUG, which production drops. Each
    step's failure is logged at WARNING, by name, and the rest of the pass still runs.

    A pass with a failed step is a failed pass, counted under the loop's own name (the debug
    report reads loopfail by loop name, R22) and NOT a heartbeat, so the report can still say
    "every pass since start has failed". A step-specific key would hide it from the report.
    """
    t0 = time.time()
    failed = 0
    for label, fn, args in steps:
        try:
            fn(*args)
        except Exception:
            failed += 1
            app.logger.warning("backup tick (%s) failed", label, exc_info=True)
    if failed:
        runtime_stats.bump("loopfail", "backup-ticker")
    else:
        runtime_stats.beat("backup-ticker", 3600, time.time() - t0)
    return failed


def _backups_blocked_by_config(app, sweep):
    """True, logged, when config.json is there but unreadable — so `sweep` must not run.

    Both sweeps act on config: each server's schedule, and its `keep`, which decides what the
    prune after an archive DELETES. Read from an unreadable file those are the defaults, so a
    queued backup pruned to the default keep past a server's own retention, and every clock the
    sweeps then tried to record was refused (update_config raises ConfigUnreadable) and reported
    as a failed backup. Leaving them alone costs nothing that is not recovered: queued servers
    stay queued and due ones stay due until the file reads. The health check reports the file.
    """
    if not is_unreadable(load_config()):
        return False
    app.logger.warning("config.json could not be read; %s skipped until it can", sweep)
    return True


def _record_game_clock(app, sid, gname, started=False):
    """Move a server's backup schedule clock. False, logged, when config.json refused the write.

    record_game_backup writes config.json, and update_config refuses while the file is there but
    unparseable. That can happen between the archive being written and this call, and it is not
    the backup failing: letting it reach the sweep's `except` audited and alerted a backup that
    worked as "backup error (ConfigUnreadable)", and skipped recording what really happened.

    `started`: the clock is only being started, no backup was taken (bk.start_game_clock), so the
    report can say no backup has run yet rather than "last 0 s ago".
    """
    try:
        (bk.start_game_clock if started else bk.record_game_backup)(sid)
        return True
    except ConfigUnreadable:
        app.logger.warning("config.json could not be read; the backup clock of %s was not saved",
                           gname)
        return False


def _record_full_clock(app, summary):
    """record_full_backup, with a refused write logged rather than raised — see _record_game_clock.

    It runs after every server in a full backup has been archived; raising there reached the
    run's `except` and alerted "The panel backup run errored before completing." about a run that
    had completed.
    """
    try:
        bk.record_full_backup(summary)
        return True
    except ConfigUnreadable:
        app.logger.warning("config.json could not be read; the full backup's time and summary "
                           "were not saved")
        return False


def _button_backup_running(sid):
    """True while the maintenance menu's Backup button is archiving server `sid`.

    That runs LinuxGSM `backup` as a long action — registered in _action_output, outside
    _full_backup_lock and without the _game_backup_status flag — so neither the lock nor the flag
    can see it.

    The whole registration chain, not just its head: a later long action (an update started while
    the backup runs) displaces the backup's entry into `prev` — see _begin_action_tail — and the
    backup is still archiving underneath it.
    """
    e = _action_output.get(sid)
    while e is not None:
        if e.get("action") == "backup" and not e.get("ended"):
            return True
        e = e.get("prev")
    return False


def _marked_backup(sid, *args, runner=None, **kwargs):
    """run_game_backup, with the server marked RUNNING in _game_backup_status while it runs.

    Only the manual per-server route set that flag, so the two tickers backed servers up
    invisibly: _run_due_restarts — a separate 90 s thread whose own guard reads exactly this
    flag — stopped or restarted a server a scheduled backup had just stopped to archive, and the
    'backing up' state never reached the page. The caller overwrites the entry with the outcome,
    as it always did; a raise clears it here, so a failed run cannot leave the flag set.

    `runner` is the caller's own reference to run_game_backup (panel_backup imports it by name, and
    that name is the seam its tests stub); None means this module's.
    """
    _game_backup_status[sid] = {"running": True, "ok": None, "msg": "", "ts": time.time()}
    try:
        result = (runner or run_game_backup)(*args, **kwargs)
    except Exception as e:
        _game_backup_status[sid] = {"running": False, "ok": False,
                                    "msg": "backup error (%s)" % type(e).__name__, "ts": time.time()}
        raise
    # It RETURNED, so the host answered: a streak of raises (_backup_raise_streak) is over, and
    # the next raise is news worth an alert again.
    _backup_raise_streak.pop(sid, None)
    return result


def _back_up_if_due(app, target):
    """Back up one scheduled target if its OWN schedule is due. The caller holds the backup lock.

    The targets are read once and backed up one after another, minutes each, so each is checked
    to still be its server (models.row_birth) before it is touched and before anything is
    recorded for it: the clock and the status are keyed by the id, which a deleted server's
    successor takes.
    """
    sid, remote, short, lgsm, gname, gtype, port, qtype, born = target
    if claim_row(GameServer, sid, born) is None:
        return   # deleted since the list was read
    sched = bk.get_game_schedule(sid)
    if sched["interval_days"] <= 0:
        return   # backups off for this server
    if not sched["last"]:
        # Never backed up on a schedule yet (fresh install / pre-existing server):
        # start its clock now instead of backing up immediately, so the first
        # scheduled backup is one interval out — not the moment it's installed.
        _record_game_clock(app, sid, gname, started=True)
        return
    if not bk.game_backup_due(sid):
        return
    if _button_backup_running(sid):
        # A Backup-button run is archiving it now and holds LinuxGSM's backup.lock
        # (run_game_backup's sweep clears an old lock only while no tar runs as the
        # game user). A second run would fail on "Lockfile found" and be recorded
        # as a failed backup — or, once LinuxGSM's own 60-minute stale-lock rule
        # removes the lock, start a second archive of the same files. It stays
        # due; the next tick decides again.
        return
    keep = sched["keep"]
    ok, reason, was_skipped = _marked_backup(sid, remote, short, lgsm, keep,
                                             game_type=gtype, port=port,
                                             query_type=qtype)
    if claim_row(GameServer, sid, born) is None:
        return   # deleted while it was being archived: nothing below is its any more
    if was_skipped:
        # Players online — leave the clock untouched so it stays "due" and we
        # retry on the next hourly tick, backing up once the server empties.
        # busy=True so the UI shows why it's waiting (+ a "back up anyway").
        _game_backup_status[sid] = {"running": False, "ok": None, "busy": True,
                                    "msg": reason, "ts": time.time()}
        _report_overdue_skip(app, (sid, gname, born), sched, reason)
        return
    _record_game_clock(app, sid, gname)
    _game_backup_status[sid] = {"running": False, "ok": ok,
                                "msg": (reason or ("Backed up" if ok else "failed")),
                                "ts": time.time()}
    # Outside the except on purpose — a failed backup RETURNS here, it does not
    # raise, and the clock was just recorded so this server will not be retried
    # for a whole interval. See _record_backup_outcome.
    _record_backup_outcome(app, sid, gname, ok, reason,
                           "scheduled_backup", "Scheduled backup failed", born)


def _run_due_game_backups(app):
    """Scheduled per-server backups: back up each installed server whose OWN schedule is due.

    That is its override, or the global default. Serialised via the same lock as manual backups.
    """
    if _backups_blocked_by_config(app, "scheduled backups"):
        return
    if not _full_backup_lock.acquire(blocking=False):
        return
    try:
        with app.app_context():
            # query_type rides along: without the server's gamedig override, player_count has no
            # type for the games that need one (Project Zomboid, ARK, ...), answers None, and
            # run_game_backup reads None as EMPTY and runs LinuxGSM `backup`, which stops the
            # server with its players on it. Every backup and player-count caller passes it.
            # Not a server its host's clean reboot holds: the backup would stop and start it in
            # the middle of the plan (host_reboot), and the next tick takes it once that is done.
            targets = [(gs.id, gs.remote, gs.short_name, gs.lgsm_name, gs.name, gs.game_type, gs.port,
                        gs.query_type, row_birth(gs))
                       for gs in GameServer.query.filter_by(installed=True).all()
                       if gs.remote_id and not _reboot_holds(gs)]
            for target in targets:
                sid, gname, born = target[0], target[4], target[8]
                try:
                    _back_up_if_due(app, target)
                except Exception as e:
                    app.logger.warning("scheduled backup of %s failed", gname, exc_info=True)
                    _record_raised_backup(app, (sid, gname, born), e,
                                          "scheduled_backup", "Scheduled backup failed")
    finally:
        _full_backup_lock.release()


def _reboot_holds(gs):
    """Whether a clean reboot of gs's host holds it: the plan is running, or still restoring it."""
    from panel.services import host_reboot as _hr
    return _hr.reboot_busy(gs.remote_id) or bool(gs.reboot_restore)


def _back_up_queued(app, gs):
    """Back up one queued server if it is empty now; still busy, it stays queued.

    Backed up (or genuinely failed) clears its backup_pending. The caller holds the backup lock.
    Nothing is recorded once the server was deleted while it was archived (models.still_held):
    the flag, the clock, the status and the audit row would be the next server's with that id.
    """
    sched = bk.get_game_schedule(gs.id)
    ok, reason, was_skipped = _marked_backup(
        gs.id, gs.remote, gs.short_name, gs.lgsm_name, sched["keep"],
        game_type=gs.game_type, port=gs.port, query_type=gs.query_type)
    if not still_held(gs):
        return
    if was_skipped:
        # Still players on: stays queued. Clear the running mark set above.
        _game_backup_status[gs.id] = {"running": False, "ok": None, "busy": True,
                                      "msg": reason, "ts": time.time()}
        # ...and a wait that has gone on for a whole backup interval is reported, once. It was
        # as silent as the scheduled skip: a queue on a server never empty waited for ever.
        _report_long_queue(app, gs, sched, reason)
    if not was_skipped:
        # Backed up (or genuinely failed) — either way the wait is over.
        gs.backup_pending = False
        db.session.commit()
        if ok:
            # ...and the clock moves. record_game_backup was called from the
            # scheduled ticker alone, so a server archived by THIS sweep still
            # looked overdue and the next tick backed it up all over again.
            #
            # Only when it WORKED, which is narrower than the ticker above (that
            # one records a genuine failure too, so it does not retry hourly). A
            # failure here leaves the clock alone and the ticker picks the server
            # up on its own schedule — one retry, not a loop, because this sweep
            # has already cleared backup_pending.
            _record_game_clock(app, gs.id, gs.name)
        _game_backup_status[gs.id] = {"running": False, "ok": ok,
                                      "msg": (reason or ("Backed up" if ok else "failed")),
                                      "ts": time.time()}
        # This sweep reported NOTHING at all — not even on the exception path.
        # A queued backup that fails has also just left the queue, so nothing
        # picks it up again until its own schedule comes round.
        _record_backup_outcome(app, gs.id, gs.name, ok, reason,
                               "queued_backup", "Queued backup failed")
    # still players on → leave queued, retry next tick


def _run_pending_backups(app):
    """Back up the servers queued via 'wait until empty' (backup_pending) that are empty now.

    Each one backed up has its flag cleared; the still-busy ones stay queued for the next tick.
    Serialised via the same lock as the other backup paths.
    """
    if _backups_blocked_by_config(app, "queued backups"):
        return
    if not _full_backup_lock.acquire(blocking=False):
        return
    try:
        with app.app_context():
            # Per server, like the scheduled ticker above — not the global default. Pruning is an
            # unconditional rm of everything past `keep`, so using the global number here deleted
            # archives a server's own retention override said to retain.
            pending = GameServer.query.filter_by(installed=True, backup_pending=True).all()
            for gs in pending:
                # Deleted since the list was read (each backup takes minutes): skipped, and its
                # object is not read, since it would reload from whatever row took the id.
                if not still_held(gs):
                    continue
                sid, gname, born = gs.id, gs.name, row_birth(gs)
                if not gs.remote_id or _button_backup_running(sid) or _reboot_holds(gs):
                    continue   # (a Backup-button run in flight, or a reboot: stays queued)
                try:
                    _back_up_queued(app, gs)
                except Exception as e:
                    app.logger.warning("queued backup of %s failed", gname, exc_info=True)
                    _record_raised_backup(app, (sid, gname, born), e,
                                          "queued_backup", "Queued backup failed")
    finally:
        _full_backup_lock.release()


# Consecutive failed attempts at a queued stop/restart, per server id (registered, so a deleted
# server's count is not inherited by the next server SQLite gives its id). In memory on purpose: a
# panel restart starting the count again costs at most a few more attempts.
_queued_action_failures = register_server_state({})
# How many failed attempts before a queued stop/restart is given up on. Retrying at all is what the
# queue needs (a timed-out stop has not happened); retrying for ever is not, because an action that
# never gets an answer would otherwise be sent on every tick.
_QUEUED_ACTION_ATTEMPTS = 3


def _no_exit_status(rc):
    """Whether `rc` is the transport's rather than LinuxGSM's.

    That is < 0 (or None) when no exit status came back — a timeout, a dropped channel — and 255,
    the ssh client's own failure on the tailscale transport (LinuxGSM's core_exit uses 0-4).
    """
    return rc is None or rc < 0 or rc == 255


def _queued_action_retries(act, rc):
    """Whether a queued stop/restart that did not exit 0 stays queued for the next tick.

    Only a retry the next tick can see through is safe. With _no_exit_status, LinuxGSM's answer
    never arrived, so the action may not have happened, and both actions retry. Any other exit is
    LinuxGSM's own, and LinuxGSM exits non-zero on runs that did the job: exitcode is a global
    the last log line sets, so a failed status alert after a good restart ends it at 1.
      stop    — retries: the next tick asks the server first, and a stopped one reads 'idle'
                and is cleared, so a stop that worked is never repeated.
      restart — does NOT: a restart that worked leaves the server online and empty, which is
                exactly what triggers it, so every tick restarted it again up to the limit.
    """
    if rc == 0:
        return False
    if _no_exit_status(rc):
        return True
    return act == "stop"


def _last_output_line(text):
    """Return the last non-blank line of `text`, escapes stripped, capped at 200 characters."""
    why = [ln.strip() for ln in terminal.strip_escapes(text).splitlines() if ln.strip()]
    return why[-1][:200] if why else "no output"


def _queued_action_detail(act, result, fails, retry, give_up):
    """Audit detail for a queued stop/restart; `result` is run_as_game_user's (out, err, rc)."""
    _out, err, rc = result
    if rc == 0:
        return "queued '%s when empty' ran" % act
    last = _last_output_line(err or _out or "")
    if not retry:
        return ("queued '%s when empty' exited %s: %s — no longer queued (LinuxGSM also "
                "exits non-zero after a run that worked, and a retry would run it a second "
                "time)" % (act, rc, last))
    if _no_exit_status(rc):
        return ("queued '%s when empty' got no answer (exit %s, attempt %d of %d)%s: %s"
                % (act, rc, fails, _QUEUED_ACTION_ATTEMPTS,
                   " — no longer queued" if give_up else " — still queued, will retry", last))
    return ("queued '%s when empty' exited %s (attempt %d of %d)%s: %s"
            % (act, rc, fails, _QUEUED_ACTION_ATTEMPTS,
               " — no longer queued" if give_up
               else " — still queued until the server is seen stopped", last))


def _run_queued_action(app, gs):
    """Run the queued 'stop/restart when empty' for an online, empty server.

    Called from _run_due_restarts once it has decided to act.

    The result was thrown away and both flags were cleared whatever happened. run_as_game_user
    does not raise: a timeout or an unreachable host on the tailscale and local transports comes
    back as ("", "…timed out", -1), so a stop that never happened cleared stop_pending, nothing
    retried, and players rejoined a server the panel no longer showed as queued. No audit row was
    written for the unattended stop/restart either way.

    Now the flags clear when the action exited 0, when _queued_action_retries says a retry is not
    safe, or after _QUEUED_ACTION_ATTEMPTS failures in a row, and every attempt is audited.
    """
    act = "stop" if gs.stop_pending else "restart"
    # The panel's own stop/restart, marked as the Stop and Restart buttons mark theirs
    # (server_detail._run_action): unmarked, the monitor read a queued stop as a crash and paged
    # "went offline unexpectedly" two sweeps after it.
    _mark_expected_offline(gs.id)
    _out, err, rc = _sm.run_as_game_user(gs.remote, gs.short_name, act,
                                         timeout=90, selfname=gs.lgsm_name)
    ok = (rc == 0)
    retry = _queued_action_retries(act, rc)
    if act == "restart" and not retry:
        try:
            _sm.set_game_priority(gs.remote, gs.short_name)
        except Exception:
            app.logger.debug("priority boost failed", exc_info=True)
    fails = 0 if ok else _queued_action_failures.get(gs.id, 0) + 1
    give_up = retry and fails >= _QUEUED_ACTION_ATTEMPTS
    detail = _queued_action_detail(act, (_out, err, rc), fails, retry, give_up)
    try:
        log_action(None, "%s_server" % act, target=gs.name, detail=detail[:500], success=ok,
                   server=gs)
    except Exception:
        db.session.rollback()
        app.logger.warning("could not audit the queued %s of %s", act, gs.name, exc_info=True)
    if not retry or give_up:
        _queued_action_failures.pop(gs.id, None)
        gs.restart_pending = gs.stop_pending = False
    else:
        _queued_action_failures[gs.id] = fails
    db.session.commit()
    return ok


def _forget_unqueued_failures(pending):
    """Drop the failure count of every server no longer in `pending`.

    A failure count belongs to a queued action. One the operator cancelled has none, so a
    later re-queue must start from zero rather than inherit the old attempts.
    """
    _queued_ids = {gs.id for gs in pending}
    for _sid in [s for s in list(_queued_action_failures) if s not in _queued_ids]:
        _queued_action_failures.pop(_sid, None)


def _backup_in_progress(sid):
    """Whether server `sid` is being backed up: by a runner's flag, or by the Backup button."""
    _bst = _game_backup_status.get(sid)
    return bool((_bst and _bst.get("running")) or _button_backup_running(sid))


def _settle_queued_action(app, gs):
    """Clear a queued stop/restart whose server is stopped; run it once the server is online and empty."""
    # distinguish_unresponsive, because this loop is deciding whether there is
    # anything to ACT on, not whether players can connect. Folded into "offline", a
    # server whose session is alive but not serving read as "already stopped", so the
    # operator's queued stop/restart was cleared and never performed — silently, and
    # for a crashed server permanently. That is the very state the port check exists
    # to detect, and it is exactly when a queued "stop" most needs to happen.
    status = get_server_status(gs.remote, gs, distinguish_unresponsive=True)
    pc = sm_player_count(gs.remote, gs.short_name, gs.game_type, gs.port,
                         gs.query_type) if status == "online" else None
    # 'restart' here means "online + empty -> act now"; 'idle' = already stopped.
    decision = mod_restart_decision(status, pc)
    if decision == "idle":
        _queued_action_failures.pop(gs.id, None)
        gs.restart_pending = gs.stop_pending = False
        db.session.commit()
    elif decision == "restart":
        _run_queued_action(app, gs)
    # 'pending' (players on / unknown): leave the flags, retry next tick


def _run_due_restarts(app):
    """Run the restarts and stops queued for when a server empties.

    Those are mod-restarts and the user's 'restart/stop when empty'. Once empty, run the queued
    action (rechecked hourly). A stopped server clears its flags; an online-but-unqueryable one
    stays queued for a manual force.
    """
    with app.app_context():
        pending = [gs for gs in GameServer.query.filter_by(installed=True).all()
                   if gs.remote_id and (gs.restart_pending or gs.stop_pending)]
        # A cancelled action's failure count must not carry over — see _forget_unqueued_failures.
        _forget_unqueued_failures(pending)
        for gs in pending:
            # Each server's action takes up to a minute and a half, so a later one can have been
            # deleted, and its id taken, by the time it comes up: skipped, and its object is not
            # read, since it would reload from the other row (models.RowReplaced).
            if not still_held(gs):
                continue
            gname = gs.name
            # Don't restart/stop a server that's being backed up right now — the backup already
            # stops+starts it, and racing it could fail the backup. Leave it queued for next tick.
            # Both ways a backup can be running: the runners' flag, and the Backup button's long
            # action, which sets no flag at all. Nor one its host's reboot holds: the reboot's
            # stop honours a queued stop, and its restore clears a queued restart.
            if _backup_in_progress(gs.id) or _reboot_holds(gs):
                continue
            try:
                _settle_queued_action(app, gs)
            except Exception:
                # A refused write leaves the session needing a rollback before the next server.
                db.session.rollback()
                app.logger.debug("pending restart/stop of %s failed", gname, exc_info=True)


def _start_bootstrap_job(app, remote_id, job, opts, actor_id):
    """Run remote_bootstrap_vps in a background (green) thread.

    It streams progress into `job`, the entry _begin_bootstrap registered for the status endpoint.

    THAT entry, not whichever one holds remote_id when a step reports. remote_id is a rowid, and
    SQLite hands a deleted host's id to the next host added — while this worker, on a machine
    whose owner can hold any step for as long as they like, is still running. Looked up by id, a
    delegated admin's deleted host wrote its own output into the next host's job (a superadmin's,
    on a host outside the delegate's reach), flipped it to "done/Complete" while that host's real
    bootstrap was still running — which then let a second one start beside it — stamped that
    host's last_seen, and wrote a success audit row naming it.

    The row goes the same way. The bootstrap is handed a DETACHED copy of it: a session commit
    expires every object it holds, and the first SSH contact with a host commits (the host-key pin,
    _core._persist_host_key), after which the next attribute read reloads the row BY ID — from the
    new host's row, if its id was taken meanwhile. The remaining root steps were then aimed at the
    new host with its credentials, and the pin had been written onto the new row too. Detached, the
    bootstrap keeps the host it was started for, and what it learned is written back only if the
    row that holds the id now is still the one that was loaded (created_at is its identity: a
    superadmin editing the host mid-bootstrap is legitimate, so the address must not be).
    """
    run = _BootstrapRun(app, remote_id, job)
    threading.Thread(target=run.run, args=(opts,), daemon=True).start()


class _BootstrapRun:
    """One bootstrap worker: the job it registered, and the detached row it was started for."""

    def __init__(self, app, remote_id, job):
        self.app, self.remote_id, self.job = app, remote_id, job
        self.remote = self.created = self.pinned = None

    def _mine(self):
        """Whether our job is still the registered job for remote_id. Call holding the lock."""
        return _bootstrap_jobs.get(self.remote_id) is self.job

    def _pin_back(self):
        """Write back a pin first contact learned, at the next step rather than at the end.

        The monitor and every request reach the host through the ROW, and until the pin is on it
        they trust whatever key they are shown; the bootstrap itself runs for many minutes.
        """
        learned = self.remote.host_key if self.remote is not None else None
        if learned and learned != self.pinned:
            self.pinned = learned             # once, whatever the write does: never every step
            _settle_bootstrapped_row(self.remote_id, self.created, None, learned, None)

    def progress(self, step, total, name, status):
        """remote_bootstrap_vps's progress callback: the step it is on, into OUR job only."""
        try:
            self._pin_back()                  # outside the lock: it is a database write
        except Exception:
            _log.debug("bootstrap: writing the learned host key back failed", exc_info=True)
        with _bootstrap_lock:
            if not self._mine():
                return
            job = self.job
            job["step"] = step
            job["total"] = total
            job["step_name"] = name
            job["updated"] = time.time()
            if status in ("running", "rebooting", "done"):
                # keep top-level status "running" until finally done/failed
                job["status"] = "rebooting" if status == "rebooting" else job["status"]
            job["log"].append(f"[{step}/{total}] {name}" if total else name)

    def _end(self, status, step_name, message, log_line=None):
        """Mark OUR job finished — and nothing, if it is no longer the one registered."""
        with _bootstrap_lock:
            if not self._mine():
                return
            self.job["status"] = status
            if step_name is not None:
                self.job["step_name"] = step_name
            self.job["message"] = message
            if log_line is not None:
                self.job["log"].append(log_line)
            self.job["updated"] = time.time()

    def _bootstrap(self, opts):
        """Load the row, run the bootstrap on a detached copy, settle it: (success, message)."""
        remote = db.session.get(RemoteServer, self.remote_id)
        if not remote:
            raise RuntimeError("Remote no longer exists")
        self.remote, self.created, self.pinned = remote, remote.created_at, remote.host_key
        name = remote.name
        # The panel's own record of what runs here, beside the process probe the reboot step asks:
        # a host whose managed server was last seen online is never rebooted by a bootstrap.
        online = db.session.query(GameServer.id).filter_by(
            remote_id=self.remote_id, status="online").first() is not None
        db.session.expunge(remote)
        if online:
            opts = dict(opts, do_reboot=False)   # it then only reports a pending reboot
        success = False
        try:
            success, msg, _ = remote_bootstrap_vps(remote, progress=self.progress, **opts)
        finally:
            # However the run ended: a pin first contact learned was kept even when a later step
            # raised, back when first contact committed it itself.
            same = _settle_bootstrapped_row(self.remote_id, self.created, self.pinned,
                                            remote.host_key, success)
        # The row is filed under the host only while that id is still this host: _audit_ref
        # resolves an id, and one a new host took would show this run to that host's viewers.
        log_action(None, "remote_vps_bootstrap", target=name, detail=msg, success=success,
                   remote=remote if same else None)
        return success, msg

    def run(self, opts):
        """The thread's body."""
        try:
            with self.app.app_context():
                success, msg = self._bootstrap(opts)
            self._end("done" if success else "failed", "Complete" if success else "Failed", msg)
        except Exception as e:
            self._end("failed", None, str(e), f"ERROR: {e}")


def _settle_bootstrapped_row(remote_id, created, pinned, learned, success):
    """Write a bootstrap's result onto its host's row, if that row is still the one it loaded.

    `created` is the loaded row's created_at, which is what tells "the same host" from "a host
    that took its id". `success` True marks the host online and seen now (None: the run has not
    finished). `learned` is the host key the bootstrap's own connections pinned in memory, on the
    detached copy, and `pinned` what it was loaded with; it is written only when it is new and the
    row has no pin yet — first contact, the only time the in-session write it replaces would have
    happened. A pin the row already holds, or one that cannot be decrypted, is never replaced.
    Returns whether the row was still that host's.
    """
    from panel.db.models import UnreadableSecret
    row = db.session.get(RemoteServer, remote_id)
    if row is None or row.created_at != created:
        return False
    if success:
        row.is_online = True
        row.last_seen = utcnow()
    if (learned and learned != pinned and not row.host_key
            and not isinstance(row.host_key, UnreadableSecret)):
        row.host_key = learned
    db.session.commit()
    return True


def _maybe_cache_commands(app, gs):
    """Kick off a background command-list fetch for a server whose cache is empty.

    At most once every few minutes, so reloading the page can't stack SSH calls. Lets servers
    imported before auto-caching existed self-heal the first time they're viewed.
    """
    now = time.time()
    server_id = gs.id
    if now - _cmd_fetch_attempts.get(server_id, 0) < 300:
        return
    _cmd_fetch_attempts[server_id] = now
    _bg_cache_commands(app, [server_id], births={server_id: row_birth(gs)})


# ── Module state the route modules own ─────────────────────────────────────────────────────────
# These were defined in app.py and, after the split, read ONLY from here and the route modules.
# CodeQL reported all six as unused globals: it cannot follow a name across the app <-> routes
# import edge, and it was right that app.py no longer uses them. Their home is where their
# readers are.
# In-memory registry of running/finished VPS bootstrap jobs, keyed by remote_id.
# Populated by the async bootstrap runner and read by the status endpoint. Both
# live in the same (single) panel process, so a plain dict + lock is sufficient.
#
# REGISTERED (with its lock), like every other map keyed by a database row id — see
# panel_state.register_remote_state. It was not, and remote_id is a rowid SQLite hands straight to
# the next INSERT: delete a host mid-bootstrap and the job outlives the row, so the next host to
# take that id is refused by _begin_bootstrap with "A bootstrap is already running for this
# server" until _prune_jobs ages the entry out two hours later.
_bootstrap_lock = threading.Lock()
_bootstrap_jobs = register_remote_state({}, _bootstrap_lock)
# ── State that used to live inside register_routes() ──────────────────────────────────────────
# These were assigned in the body of register_routes, which made them closure cells: reachable
# only from the functions defined alongside them. Nothing outside could see them — including the
# tests, which had to dig state out of `_maybe_alert_os_updates.__code__.co_freevars` and
# `__closure__` to assert on it. Module level is where module state belongs; every one of these is
# process-wide anyway, none is per-app, and no nested function rebinds any of them (they are read,
# or mutated in place), so hoisting needs no `global` anywhere.
#
# `socketio` deliberately stays inside register_routes: it is constructed FROM the app and is the
# one genuinely per-app object in that set.
# Registered like every other map keyed by a row id, so a server or host that takes a deleted
# one's id does not inherit its rate limit.
_cmd_fetch_attempts = register_server_state({})     # server_id -> last background command-fetch time
_pubip_resolve_attempts = register_remote_state({})  # remote_id -> last background public-IP resolve time

# Hoisted for the second wave of sections: the file browser and the API routes both call
# these, and "Manage Game Servers" defines neither. Same rule as the first ten — each closed
# over `app` and nothing else, so each takes it explicitly.


def _serverfiles_verdict(remote, short_name):
    """Installed by serverfiles' size: True over 50 MB, False when absent, None when unread.

    The sentinel is what makes this a THREE-state answer instead of two. run_command does not
    raise on a transport failure — it returns ("", "…timed out", -1) — and `2>/dev/null` means
    a missing serverfiles dir ALSO prints nothing. Without the marker both read as "" and the
    old `int("0") > 50` answered False, i.e. "clearly NOT installed", for a read that never
    happened. That verdict is acted on: the reconcile ticker in app.py sets
    installed=False / status="failed" on it (its own next line says "None (host unreachable):
    leave it" — exactly the case False was stealing), and the install retry in
    manage_servers.py wipes lgsm/tmp and re-runs a 30-minute auto-install, three times over.

    With the marker: no marker means the command did not complete -> None ("couldn't tell").
    Marker present and no number means serverfiles really is absent -> False.
    """
    out2, _, _ = _sm.shell_as_game_user(
        remote, short_name,
        f"du -sm /home/{short_name}/serverfiles 2>/dev/null | cut -f1; echo __DU_DONE__",
        timeout=20)
    if "__DU_DONE__" not in (out2 or ""):
        return None
    _mb = (out2 or "").replace("__DU_DONE__", "").strip()
    try:
        return int(_mb or "0") > 50
    except ValueError:
        return None


def _looks_installed(app, remote, short_name, lgsm_name):
    """Best-effort check of whether a game server is actually installed on the remote.

    Used to reconcile an install whose live progress was lost (e.g. the panel restarted
    mid-install). Returns True (installed), False (clearly not), or None (couldn't tell).
    """
    # Both names, before either read: the second read names only the account, so a bad SCRIPT name
    # would otherwise still send it. And a refusal is "couldn't tell", never "not installed" —
    # False is acted on (the reconcile ticker marks the row failed; the install retry wipes
    # lgsm/tmp and re-downloads).
    if not _sm.game_idents_ok(short_name, lgsm_name):
        return None
    try:
        out, err, _ = _sm.shell_as_game_user(
            remote, short_name, f"cd /home/{short_name} && ./{lgsm_name} details 2>&1",
            timeout=30, selfname=lgsm_name)
        low = terminal.strip_escapes((out or "") + "\n" + (err or "")).lower()
        if re.search(r"not installed|please run .*install|serverfiles.*(missing|not found)|no such file", low):
            return False
        if "status:" in low or "server ip:" in low:
            return True
        # Fallback: real content in serverfiles means the download completed.
        return _serverfiles_verdict(remote, short_name)
    except Exception:
        app.logger.debug("install reconcile check failed", exc_info=True)
        return None


def _notify_servers_changed(app):
    """Best-effort broadcast to every connected browser that the game-server set changed.

    One was added or removed, so open dashboards / Game Servers pages
    reconcile live instead of waiting for a manual refresh. A dropped broadcast must
    never affect the actual install/uninstall, so this is fully swallowed.
    """
    try:
        sio = getattr(app, "socketio", None)
        if sio is not None:
            sio.emit("servers_changed", {})
    except Exception:
        _log.debug("UI-nicety broadcast only — never let it affect the install/uninstall", exc_info=True)


# ── Live output for a long LinuxGSM action ─────────────────────────────────────────────────────
# update/validate/backup/force-update/mods-update/fastdl all run in a background thread and are
# accepted with "watch the live console for progress". That was not true of any of them: the
# command ran over its own SSH channel and its output went into a Python variable, so the only
# place it ever appeared was the audit log, minutes later, truncated to 300 characters. The
# console the message pointed at is a tail of the GAME's console log, which an update does not
# write to at all — so an operator watching it saw nothing happen for the whole download and had
# no way to tell a working update from a stalled one.
#
# The fix is to give the output a file on the host and tail it the same way the console itself is
# tailed. These helpers are here rather than in either caller because both sides need them: the
# action registers and drains its own file (server_detail), and the console poller drains it on
# every tick while it is registered (server_files).

# Chunk ceiling per drain, matching the console poller's. SteamCMD's progress spool is chatty; this
# bounds one tick's emit rather than the whole action.
_ACTION_TAIL_CHUNK = 65536


def _action_log_path(short_name, action):
    """Where a long action's output is written on the host, for tailing.

    A dotfile in the game user's OWN home: that directory is guaranteed to exist (every LinuxGSM
    command cds into it) so the redirect cannot fail and take the action down with it, only the
    game user and root can write there — unlike a predictable path in /tmp — and the leading dot
    keeps it out of the file browser's listing. `action` comes from RUNNABLE_ACTIONS and
    short_name is validated as a shell identifier on the model, so neither can escape the path.
    """
    return f"/home/{short_name}/.panel-{action}.log"


# How many pushed lines to keep per server for replay after a reload. A `validate` on a large
# game is a few hundred lines of SteamCMD spool; this holds one comfortably without becoming a
# place anyone would mistake for the log.
_CONSOLE_BACKLOG_MAX = 600
# ...and how much of it, in characters, since a line count is no bound on its own: a drain pushes
# up to _ACTION_TAIL_CHUNK bytes, and 64KB with no newline in it is ONE line, so 600 of them held
# ~39MB per server and /api/console sent all of it on every poll. A line is cut at
# _CONSOLE_LINE_MAX (SteamCMD and LinuxGSM lines are a fraction of that), and the oldest lines go
# once the whole backlog passes _CONSOLE_BACKLOG_BYTES — 600 ordinary lines are ~90KB, so the
# budget only ever bites on output nobody could read anyway. Only the REPLAY is bounded: the live
# socket push still carries what the command printed.
_CONSOLE_LINE_MAX = 2048
_CONSOLE_BACKLOG_BYTES = 256 * 1024
# A colour escape the cut may land inside: the browser would print its tail as text.
_PARTIAL_SGR_RE = re.compile(r"\x1b(?:\[[0-9;]*)?\Z")


def _backlog_line(ln):
    """`ln` as the backlog keeps it: whole, or cut at _CONSOLE_LINE_MAX and marked with '…'."""
    if len(ln) <= _CONSOLE_LINE_MAX:
        return ln
    cut = _PARTIAL_SGR_RE.sub("", ln[:_CONSOLE_LINE_MAX])
    # render_colour leaves SGR open across a line; close it so the marker is not painted too.
    return cut + ("\x1b[0m" if "\x1b[" in cut else "") + "…"


def _backlog_append(server_id, text, ts):
    """Keep `text`'s non-blank lines in the server's backlog, inside both of its ceilings."""
    buf = _console_backlog.setdefault(server_id, [])
    buf.extend({"t": ts, "line": _backlog_line(ln)} for ln in str(text).split("\n") if ln.strip())
    if len(buf) > _CONSOLE_BACKLOG_MAX:
        del buf[:len(buf) - _CONSOLE_BACKLOG_MAX]
    size = sum(len(e["line"]) for e in buf)
    drop = 0
    while size > _CONSOLE_BACKLOG_BYTES and drop < len(buf) - 1:     # the newest line always stays
        size -= len(buf[drop]["line"])
        drop += 1
    del buf[:drop]


def _console_push(app, server_id, text, ts=None):
    """Push text into a server's live console for whoever has it open, and remember it.

    Goes to the same `console_output` event and `console_{id}` room the console poller uses, so
    the browser needs no new handling and the lines land in its scrollback with everything else.
    Fully swallowed: a socket problem must never be what fails an update.

    It is also kept in _console_backlog, because the socket reaches only the pages that are open
    RIGHT NOW. /api/console rebuilds a console from the game's console log, which a panel action
    never writes to — so before this, reloading the page after an update threw away everything the
    update had said.

    `ts` is when the panel SAW this text — epoch seconds, UTC — and rides ALONGSIDE the payload
    rather than being prefixed onto it. That is not a style choice: the browser stitches its
    scrollback by matching line STRINGS between successive overlapping windows of the log, so a
    timestamp inside the text would make every line unique, defeat the overlap match, and render
    the whole window twice on every poll.
    """
    if not text:
        return
    ts = float(ts if ts is not None else time.time())
    try:
        _backlog_append(server_id, text, ts)
    except Exception:
        _log.debug("console backlog append failed for server %s", server_id, exc_info=True)
    try:
        sio = getattr(app, "socketio", None)
        if sio is not None:
            # `panel: True` because these lines are NOT in the game's console log. The browser
            # de-duplicates the log by matching its own copy against each /api/console window, so
            # a line that exists only on the page can never match — the first poll after an
            # update found no overlap and appended the whole window again beneath "[panel] update
            # finished". It renders these, and leaves them out of that copy.
            sio.emit("console_output",
                     {"server_id": server_id, "data": text, "ts": ts, "panel": True},
                     room=f"console_{server_id}")
    except Exception:
        _log.debug("console push for server %s failed (non-fatal)", server_id, exc_info=True)


def _drain_action_output(app, remote, server_id):
    """Send any NEW bytes of server_id's in-flight action output to its console viewers.

    Returns True if an action is registered for this server (i.e. keep draining), False if there
    is nothing to tail. Offsets work exactly as the console poller's do, and for the same reason:
    `stat` reports the size in the SAME round trip, because run_command strips the output it
    returns and a length measured on stripped text would drift the offset on every tick.
    """
    st = _action_output.get(server_id)
    if not st:
        return False
    path, user, pos = st["path"], st["user"], st["pos"]
    # One round trip: the size on its own first line, then the new bytes. Splitting this into a
    # stat call and a tail call would double the SSH traffic of every tick for no gain.
    sh = (f"s=$(stat -c%s {path} 2>/dev/null || echo 0); printf '%s\\n' \"$s\"; "
          f"if [ \"$s\" -gt {int(pos)} ]; then "
          f"tail -c +{int(pos) + 1} {path} 2>/dev/null | head -c {_ACTION_TAIL_CHUNK}; fi")
    try:
        # Through the MODULE, not the name this file also imports directly: `from ssh_manager
        # import run_command` copies the function object at import time, so a stub placed on the
        # definition site would be assigned cleanly and intercept nothing here. See the note at
        # the top of panel/ops/ssh_manager/__init__.py — that is the failure this repo hits most.
        out, _, _ = _sm.shell_as_game_user(remote, user, sh, timeout=15)
    except Exception:
        _log.debug("action-output tail for server %s failed; retrying next tick", server_id,
                   exc_info=True)
        return True
    head, _, body = (out or "").partition("\n")
    try:
        size = int(head.strip())
    except ValueError:
        return True          # no size line — the file isn't there yet; try again next tick
    if size < pos:
        # Truncated under us — a second run of the same action re-opens the file with `>`. Start
        # over from byte 0 and read it on the NEXT tick rather than falling through: `body` here is
        # whatever the command returned for a range that no longer exists, and the offset write at
        # the end of this function would then advance pos over bytes nothing has emitted, silently
        # eating the first chunk of the new run's output. Two seconds late beats losing it.
        st["pos"] = 0
        return True
    if body.strip():
        # render_colour, not strip_escapes: LinuxGSM colours its output and that is most of what
        # makes a long update readable at a glance. The escapes that are NOT colour still go.
        _console_push(app, server_id, terminal.render_colour(body))
    st["pos"] = min(size, pos + _ACTION_TAIL_CHUNK)
    return True


# Which registration THIS worker made, per (server_id, action). A thread-local (a greenlet-local
# under eventlet's monkey-patching), because the worker that begins a tail is the one that ends
# it, and the caller does not hand anything back — see _end_action_tail.
_action_tail_local = threading.local()


def _begin_action_tail(app, server_id, action, path, user):
    """Register an action's output file for tailing and announce it in the console."""
    # `prev` is the registration this one displaces, so that when this run ends first the one it
    # displaced — still running — is tailed again rather than left streaming nothing.
    entry = {"action": action, "path": path, "user": user, "pos": 0,
             "prev": _action_output.get(server_id)}
    _action_output[server_id] = entry
    toks = getattr(_action_tail_local, "tokens", None)
    if toks is None:
        toks = _action_tail_local.tokens = {}
    toks[(server_id, action)] = entry
    _console_push(app, server_id, f"[panel] {action} started — its output follows.")


def _reinstate_displaced(server_id, cur):
    """Tail again the newest run `cur` displaced that is still going, or stop tailing the server."""
    nxt = cur.get("prev")
    # A forgotten run belonged to a server that is gone (panel_state.forget_rows): its id may be
    # another server's now, so it is never tailed again.
    while nxt is not None and (nxt.get("ended") or nxt.get("forgotten")):
        nxt = nxt.get("prev")
    if nxt is not None:
        _action_output[server_id] = nxt
    else:
        _action_output.pop(server_id, None)


def _announce_action_end(app, server_id, action, rc):
    """Say in the console how a long action ended: success, no exit status, or its failure code."""
    if rc == 0:
        _console_push(app, server_id, f"[panel] {action} finished successfully.")
    elif rc is None or rc < 0:
        # We never got an exit code: the SSH call raised (rc None), or the transport gave up — a
        # local or Tailscale timeout, or paramiko's silent-channel give-up, all answer rc -1. An
        # exit STATUS is 0-255, so a negative rc is never the action's own. This used to test only
        # None, so a 30-minute update the transport stopped waiting for was announced as
        # "failed (exit -1)" while it may well still have been running on the host.
        _console_push(app, server_id, f"[panel] {action} stopped reporting — see the audit log.")
    else:
        _console_push(app, server_id, f"[panel] {action} failed (exit {rc}) — see above.")


def _end_action_tail(app, server_id, remote, action, rc):
    """Drain whatever is left, say how it went, and stop tailing.

    The final drain is the point of doing this here rather than just deleting the entry: the
    poller ticks every two seconds, so the last — and most interesting — lines of a command that
    has just exited are the ones that would otherwise never be sent.
    """
    # Only OUR entry. _action_output is keyed by server_id alone and _begin_action_tail overwrites
    # whatever is there, so two long actions on one server (nothing serialises them — every
    # maintenance button posts the same route and returns within a second) left this popping the
    # OTHER action's registration. The shorter one finishing then drained the longer one's file,
    # deregistered it, and every later poller tick returned immediately: the ten-minute SteamCMD
    # download the panel had just told the operator to watch the console for streamed nothing, and
    # its own final drain found no entry, so the last lines were lost too.
    #
    # The name alone only told DIFFERENT actions apart. Two runs of the SAME action (two operators,
    # a bot and a click, a double submit) matched each other's name, so the first to finish popped
    # the registration of the one still running. When this worker made a registration, "ours"
    # means that very entry; the name check remains only for a caller that ends a tail it did not
    # begin on this thread. And when ours had displaced a run that is STILL going, that run is
    # registered again, so the later of two overlapping runs finishing first does not leave the
    # earlier one streaming nothing for the rest of its life.
    mine = (getattr(_action_tail_local, "tokens", None) or {}).pop((server_id, action), None)
    if mine is not None:
        mine["ended"] = True
        if mine.get("forgotten"):
            # The server this run was registered for was deleted while it ran, and forget_rows
            # dropped the registration. The id may already be ANOTHER server's, so there is nothing
            # of ours to drain and no console of ours to announce the end in: "[panel] update
            # finished" pushed now lands in the new server's backlog and its viewers' live console.
            return
    cur = _action_output.get(server_id)
    own = cur is not None and (cur is mine if mine is not None else cur.get("action") == action)
    if own:
        cur["ended"] = True
        try:
            _drain_action_output(app, remote, server_id)
        except Exception:
            _log.debug("final action-output drain for server %s failed", server_id, exc_info=True)
        finally:
            _reinstate_displaced(server_id, cur)
    _announce_action_end(app, server_id, action, rc)


_tz_resolve_attempts = register_remote_state({})   # remote_id -> last attempt (rate limit)


def _maybe_resolve_host_timezone(app, remote_id):
    """Read + cache a host's IANA timezone in the BACKGROUND, rate-limited per remote.

    Same shape and the same reason as _maybe_resolve_public_ip above: the detail page's rule is
    that nothing on the render path touches the remote, because an unreachable host then hangs the
    render for the whole SSH connect timeout. The page shows what is stored and picks the real
    value up on a later load. Best-effort; never raises.
    """
    now = time.time()
    if now - _tz_resolve_attempts.get(remote_id, 0) < 300:
        return
    _tz_resolve_attempts[remote_id] = now
    _app = app

    def _run():
        with _app.app_context():
            try:
                remote = db.session.get(RemoteServer, remote_id)
                if remote is None or remote.timezone:
                    return
                tz = _sm.host_timezone(remote)
                if tz:
                    remote.timezone = tz
                    db.session.commit()
            except Exception:
                db.session.rollback()
                _log.debug("background host-timezone read failed for remote %s", remote_id,
                           exc_info=True)

    threading.Thread(target=_run, daemon=True).start()


def _host_timezone_cached(remote, app=None):
    """The host's IANA timezone from the row, WITHOUT touching the remote.

    Cron fires on the host's clock, so every schedule the panel shows or writes needs this — and
    it is needed on ordinary page loads, which is exactly where an SSH round trip does not belong.
    So this only ever reads the stored value; pass `app` to have a miss kick off the background
    read that fills it in for next time.

    Returns "" when it has not been read yet or could not be. The UI says so rather than assuming
    UTC: a timezone shown confidently and wrong is the bug this whole change exists to remove.
    """
    if remote is None:
        return ""
    tz = (getattr(remote, "timezone", "") or "").strip()
    if not tz and app is not None and getattr(remote, "id", None) is not None:
        _maybe_resolve_host_timezone(app, remote.id)
    return tz


def _console_rows(lines, host_tz):
    """[{t, line}] for console text: LinuxGSM's own per-line timestamp parsed off the front.

    `t` is a UTC epoch and is set ONLY where the line actually carried a stamp — the panel tails a
    file, so for an unstamped line it knows when it READ the line and not when the game wrote it,
    and there is no honest time to put there. The stamp is stripped from the text because the page
    shows it in the gutter; leaving it inline would print the same time twice.

    A host whose timezone is unknown yields t=None even for stamped lines: the stamp is in the
    host's local time and converting it against a guess would date every line hours wrong.
    """
    rows = []
    for ln in lines:
        stamp, rest = terminal.split_log_timestamp(ln)
        rows.append({"t": clock.host_stamp_to_epoch(stamp, host_tz) if stamp else None,
                     "line": rest})
    return rows


# ── JSON integers ───────────────────────────────────────────────────────────────────────────────

def _json_int(value):
    """An id or number a JSON body sent, as an int — or None for anything that is not one.

    `int(x)` under `except (TypeError, ValueError)` was the idiom in a dozen handlers, and it is not
    total: Python's json module accepts `Infinity` (and `1e400`, which is the same float), and
    int(float("inf")) raises OverflowError, which none of them caught — so `{"ids": [Infinity]}` was
    a 500 from the bulk action, the tag set, the discover import and the console socket. It also
    TRUNCATED: 3.7 became server 3, a value nobody sent. A float is accepted only when it is a whole
    finite number (JS sends 3 as 3, but a hand-built body may say 3.0); a bool is refused, although
    it is an int to Python, because `true` is not an id. A string is parsed as int() always parsed
    it here, and int() of a string never overflows.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None    # False for inf and nan
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


# ── Re-authentication throttle ──────────────────────────────────────────────────────────────────
# The routes that ask a signed-in user for their CURRENT password (or a live second factor) again —
# the password change, 2FA on and off, minting an API token, deleting a host — are a password
# oracle for whoever holds the session: a borrowed tab, a stolen cookie. /login has had a throttle
# since the start, and the bearer token has one; these had none, and most of them did not even
# write an audit row on a wrong guess, so a cookie thief could try passwords against the account
# at bcrypt speed, silently, until one worked — and a correct one is exactly what the password
# change and the 2FA switch-off need to take the account over for good.
#
# Keyed on the ACCOUNT, not the address: the session is the attacker's foothold, and it is the
# same session whichever address it is replayed from. The same budget and window as the login
# throttle, and the same reserve-then-release shape, for the reason _login_throttled gives: bcrypt
# runs in tpool and yields the hub, so counting a failure only after it would let a parallel burst
# all read "under the limit". A check that passes gives its slot back.
_REAUTH_FAILS = {}            # user id -> [time of each failed (or still in-flight) check]
_REAUTH_LOCK = threading.Lock()
REAUTH_BLOCKED_MSG = ("Too many wrong passwords or codes for this account. Wait a few minutes and "
                      "try again.")


def _reauth_key(user):
    """The throttle's key for `user`: its id, or — for an object with none yet — the object."""
    uid = getattr(user, "id", None)
    return uid if uid is not None else ("unsaved", id(user))


def reauth_reserve(user, now=None):
    """Reserve one re-authentication attempt for `user`; its stamp, or None when throttled."""
    from app import LOGIN_MAX_FAILS, LOGIN_WINDOW
    now = time.time() if now is None else now
    user_id = _reauth_key(user)
    with _REAUTH_LOCK:
        for uid in [k for k, v in _REAUTH_FAILS.items() if not v or now - v[-1] >= LOGIN_WINDOW]:
            del _REAUTH_FAILS[uid]      # bounded to the accounts that failed recently
        fails = [t for t in _REAUTH_FAILS.get(user_id, []) if now - t < LOGIN_WINDOW]
        if len(fails) >= LOGIN_MAX_FAILS:
            _REAUTH_FAILS[user_id] = fails
            return None
        fails.append(now)
        _REAUTH_FAILS[user_id] = fails
        return now


def reauth_release(user, stamp):
    """Give back the slot reauth_reserve handed out, for a check that PASSED."""
    user_id = _reauth_key(user)
    with _REAUTH_LOCK:
        fails = _REAUTH_FAILS.get(user_id)
        if fails and stamp in fails:
            fails.remove(stamp)
            if not fails:
                _REAUTH_FAILS.pop(user_id, None)


def reauth_password(user, password):
    """Check `user`'s CURRENT password under the throttle: "ok", "wrong" or "throttled".

    A throttled attempt is refused before bcrypt runs. A `password` that is not a string (a JSON
    body can send 5) is a wrong password rather than a 500 — check_password's prehash raises on it.
    """
    from panel.security.auth import check_password
    stamp = reauth_reserve(user)
    if stamp is None:
        return "throttled"
    if not (isinstance(password, str) and check_password(password, user.password_hash)):
        return "wrong"              # the slot stays spent: that is the count
    reauth_release(user, stamp)
    return "ok"


def spend_totp_step(u, step):
    """Record `step` as `u`'s last spent authenticator step, unless one at least as new is. -> bool.

    ONE conditional UPDATE, not a read, a compare and a write. The check was `step <= the
    last_totp_step this request loaded`, then an assignment committed with the rest of the change:
    two requests carrying the same observed code both loaded the old value, both passed, and one
    code was spent twice — the exact replay last_totp_step exists to stop, won by sending the two
    requests together. The database now decides: the row is written only while its stored step is
    older, and a request whose UPDATE matched nothing lost the race (or replayed) and is refused.
    The write joins the caller's transaction and commits with it; SQLite holds the second writer
    until the first commits, so it then sees the new step.

    The ONE copy. Two review passes each added their own — auth_routes for login and the API-token
    mint, tags for the password change and the 2FA switch-off — and they had already drifted: only
    this one told the loaded object about the write, so after the other the request went on
    holding the stale step it had loaded. Every route that accepts a live authenticator code
    (login, the mint, the password change, 2FA off, and 2FA enrolment) spends it here.
    """
    from sqlalchemy import or_, update
    from sqlalchemy.orm.attributes import set_committed_value
    from panel.db.models import User
    res = db.session.execute(
        update(User).where(User.id == u.id,
                           or_(User.last_totp_step.is_(None), User.last_totp_step < step))
        .values(last_totp_step=step).execution_options(synchronize_session=False))
    if res.rowcount != 1:
        return False
    # The loaded object agrees with the row without being marked dirty, so the caller's commit
    # does not write the step a second time (unconditionally) behind the guarded UPDATE.
    set_committed_value(u, "last_totp_step", step)
    return True


# ── Accounts the panel must never adopt ─────────────────────────────────────────────────────────
# Groups whose members are root, or one command from it, on a stock Linux host. sudo/wheel/admin
# are the sudoers groups of Debian/Ubuntu, RHEL/Arch and older Ubuntu; root is gid 0; docker, lxd
# and disk each hand out root outright (a privileged container, a raw block device).
_ROOT_EQUIVALENT_GROUPS = frozenset({"sudo", "wheel", "admin", "root", "docker", "lxd", "disk"})
_ACCOUNT_PROBE_END = "LGSM_ACCT_PROBE_DONE"
# privileged_accounts' reason for a name it will not put into any command (see _refused_by_name).
INVALID_ACCOUNT_NAME = "its name is not a plain account name, so the panel puts it into no command"


def _account_probe_cmd(users):
    """One shell command that reports, per account, its uid and groups — and any sudoers rule.

    Each name reaches the text ONLY as a shell-quoted word: the report lines are printf ARGUMENTS,
    never part of the format. They were `echo "ACCT <name> …"`, the raw name inside double quotes,
    where $(…) and backticks still expand and a `"` in the name ends the string — so a stored
    short_name of `gm$(id>/tmp/x)` ran its payload as root on a sudo-enabled remote (GHSA-hh39,
    reopened by #374). privileged_accounts refuses such a name before this is built; this is the
    second wall, for a caller that does not.
    """
    import shlex as _shlex
    parts = []
    for u in users:
        parts.append(
            "if uid=$(id -u %(q)s 2>/dev/null); then "
            "printf 'ACCT %%s %%s %%s\\n' %(q)s \"$uid\" \"$(id -Gn %(q)s 2>/dev/null)\"; "
            # `sudo -l -U` needs root, so it is asked only when the probe IS root (a remote whose
            # login escalates); otherwise the groups above are the evidence there is.
            "if [ \"$(id -u)\" = 0 ] && LC_ALL=C sudo -n -l -U %(q)s 2>/dev/null "
            "| grep -q \"may run the following\"; then printf 'SUDOERS %%s\\n' %(q)s; fi; "
            "else printf 'NOACCT %%s\\n' %(q)s; fi" % {"q": _shlex.quote(u)})
    parts.append("echo %s" % _ACCOUNT_PROBE_END)
    return "; ".join(parts)


def _fold_acct_line(verdict, words):
    """Fold an `ACCT <user> <uid> <groups...>` line: uid 0 or a root group refuses, else "ok"."""
    groups = set(words[3:]) & _ROOT_EQUIVALENT_GROUPS
    if words[2] == "0":
        verdict[words[1]] = "it is uid 0 (root)"
    elif groups:
        verdict[words[1]] = ("it is in the %s group, which can become root"
                             % ", ".join(sorted(groups)))
    else:
        verdict.setdefault(words[1], "ok")


def _fold_probe_line(verdict, words, users):
    """Fold one line of the probe's output, split into words, into `verdict`."""
    if len(words) < 2 or words[1] not in users:
        return
    kind, user = words[0], words[1]
    if kind == "ACCT" and len(words) >= 3:
        _fold_acct_line(verdict, words)
    elif len(words) != 2:
        return
    elif kind == "NOACCT":
        verdict.setdefault(user, "absent")
    elif kind == "SUDOERS" and verdict.get(user) in (None, "ok"):   # uid 0 / a group says more
        verdict[user] = "it has sudo rules of its own"


def _parse_account_probe(out, users):
    """{user: "absent" | "ok" | <why it is refused>} from the probe's output; None if it didn't finish."""
    lines = (out or "").splitlines()
    if not any(ln.strip() == _ACCOUNT_PROBE_END for ln in lines):
        return None
    verdict = {}
    for ln in lines:
        _fold_probe_line(verdict, ln.split(), users)
    if any(u not in verdict for u in users):
        return None                 # a line went missing: an unknown, not a clean bill
    return verdict


def _refused_by_name(remote, users, local):
    """{user: why} for the accounts refused without asking the host.

    Root, any name that is not a plain account word, the host's login, and the panel's own.

    A name game_idents_ok refuses is refused HERE, before any probe is built. The probe is shell
    text run as root on a sudo-enabled remote, and its callers hand it names nothing has checked:
    a stored short_name (the model validates on assignment, never on a load — a database from
    before the validator, a hand edit, a restore) and the /home listing discover found. Asking the
    host about such a name ran it; the host's answer could not even be matched back to it, so
    privileged_accounts answered None, the uninstall said "couldn't check, try again", and every
    retry ran the payload again. Refused by name, the row reaches _remove_row_only, which touches
    no host: the operator's way out the load-time warning promises.
    """
    # The login the panel signs in as, by NAME, whatever its groups say: it is the account whose
    # authorized_keys the panel's own access rests on, and on a host whose sudoers grants it by
    # name (cloud-init's 90-cloud-init-users) the group test in the probe would not see it without
    # root. Not linuxgsm_user: nothing reads that field any more (see _run_via_paramiko), and on an
    # old single-account setup it names the very account that holds the servers — it gets the same
    # group and sudoers test as any other account instead.
    login = getattr(remote, "username", "") or ""
    refused = {}
    for u in users:
        if u == "root":
            refused[u] = "it is root"
        elif not _sm.game_idents_ok(u):
            refused[u] = INVALID_ACCOUNT_NAME
        elif u == login:
            refused[u] = "it is the account the panel signs in to this host as"
        elif local:
            from panel.security.privileged import _is_panel_account
            if _is_panel_account(u):
                refused[u] = "it is the panel's own account"
    return refused


def _probe_accounts(remote, users, local):
    """The host's own verdict on `users` (see _parse_account_probe); None when it could not be asked."""
    try:
        out, _err, _rc = _sm.run_command(
            remote, _account_probe_cmd(users), timeout=20,
            sudo=(False if local else bool(getattr(remote, "sudo_enabled", False))))
    except Exception:
        _log.debug("account privilege probe failed", exc_info=True)
        return None
    return _parse_account_probe(out, users)


def privileged_accounts(remote, users):
    """Which of `users` on `remote` the panel must refuse to adopt or delete.

    -> {user: why} for each account that is the host's own login, the panel's own account, uid 0,
    in a root-equivalent group, or (when the probe runs as root) holding sudo rules; or None when
    the host could not be asked. An account that does not exist is not in the answer.

    WHY. Import turned any account a discover scan found into a GameServer row, and the only name
    it refused was "root" (game_idents_ok). Every file, cron and console action on that row then
    runs AS the account — so a delegated MANAGE_SERVERS admin who imported the host's own SSH
    login (`ubuntu`, in the sudo group, with a ~/linuxgsm.sh in its home) could write its
    ~/.bashrc, authorized_keys or crontab and be root on the host at its next login or cron tick;
    and uninstalling that row ran `userdel -r -f` on the host's login account. The helper refuses a
    root-capable account on the PANEL host, but a remote host has no helper: enrol_game_user
    returns None there without looking, and _destroyable_user refuses only uid 0 and the panel's
    own account. So the route asks the host itself. Superadmins are refused too: nothing the panel
    does through a game account is something the host's own login needs, and a superadmin who
    really means it has the host's shell.

    A name that is not a plain account word (game_idents_ok) — "" and None included — is refused
    as INVALID_ACCOUNT_NAME without asking the host: see _refused_by_name.
    """
    users = list(dict.fromkeys(users))
    if not users:
        return {}
    local = _sm.is_local_server(remote)
    refused = _refused_by_name(remote, users, local)
    rest = [u for u in users if u not in refused]
    if not rest:
        return refused
    verdict = _probe_accounts(remote, rest, local)
    if verdict is None:
        return None
    refused.update({u: v for u, v in verdict.items() if v not in ("ok", "absent")})
    return refused


# ── Writing as a game account that can become root ──────────────────────────────────────────────
# privileged_accounts closed the door on IMPORTING (and userdel-ing) a root-capable account, but a
# row imported before that check existed is still in the database, and every file-manager and cron
# write on it runs AS that account: saving ~/.bashrc, ~/.ssh/authorized_keys or a crontab line
# through the file browser is root on the host at the account's next login or cron tick, for any
# delegated admin who can manage that server's files. The import check could not reach those rows,
# so the WRITE routes ask too.
#
# Cached per (host, login, account) for a short while, because each answer is an SSH round trip
# and an editor saves often. Only a definite answer is cached: a host that could not be asked is
# asked again next time, and the write is refused meanwhile (fail closed — "couldn't check" must
# never read as "it's a plain account"). A minute is short enough that an account put into sudo on
# the host is refused within it, and the refusal needs the host's own root to have happened.
_ACCOUNT_VERDICT_TTL = 60.0
_ACCOUNT_VERDICTS = {}        # (remote id, host, login, account) -> (expires at, why or "")
_ACCOUNT_VERDICTS_LOCK = threading.Lock()


def game_account_write_refusal(remote, user, now=None):
    """Why a write as `user` on `remote` is refused, or None when it is a plain game account.

    -> a message for the operator; None only when the host confirmed `user` is not root-capable
    (see privileged_accounts). A host that cannot be asked is refused, not waved through.
    """
    now = time.monotonic() if now is None else now
    key = (getattr(remote, "id", None), getattr(remote, "host", None),
           getattr(remote, "username", None), user)
    why = _cached_account_verdict(key, now)
    if why is not None:
        return _privileged_write_msg(user, why) if why else None
    verdict = privileged_accounts(remote, [user])
    if verdict is None:
        return ("Couldn't check whether the '%s' account can become root on this host, and the "
                "panel only writes files or scheduled tasks as an account it has confirmed is not "
                "an administrator or root account. Nothing was changed; try again when the host "
                "answers." % user)
    why = verdict.get(user) or ""
    _store_account_verdict(key, now, why)
    return _privileged_write_msg(user, why) if why else None


def _cached_account_verdict(key, now):
    """The cached why ("" for a plain account) for `key` while it is fresh; None when there is none."""
    with _ACCOUNT_VERDICTS_LOCK:
        hit = _ACCOUNT_VERDICTS.get(key)
        return hit[1] if hit is not None and hit[0] > now else None


def _store_account_verdict(key, now, why):
    """Cache a definite answer for `key`, dropping the ones that have expired."""
    with _ACCOUNT_VERDICTS_LOCK:
        for k in [k for k, v in _ACCOUNT_VERDICTS.items() if v[0] <= now]:
            del _ACCOUNT_VERDICTS[k]            # bounded to the accounts asked about recently
        _ACCOUNT_VERDICTS[key] = (now + _ACCOUNT_VERDICT_TTL, why)


def _privileged_write_msg(user, why):
    if why == INVALID_ACCOUNT_NAME:
        # Not "can become root": nothing was asked of the host. And the name is not repeated —
        # it is exactly the text the panel refuses to handle.
        return ("Refused: this server's account name is not a plain account name, so the panel "
                "puts it into no command on the host and writes none of its files or scheduled "
                "tasks. Remove the server from the panel (that leaves the host untouched) and "
                "import or install it again under a valid name.")
    return ("Refused: the '%s' account on this host can become root (%s), so the panel does not "
            "write its files or scheduled tasks — that would be root on the host. This server was "
            "imported before the panel refused such accounts; remove it from the panel and run the "
            "game under a plain account." % (user, why))
