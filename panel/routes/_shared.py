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
from panel.core.http import (_json_str)
from panel.core.panel_state import (_action_output, _console_backlog, _full_backup_lock,
    _game_backup_status, register_remote_state)
from panel.db.models import (GameServer, RemoteServer, db)
from panel.ops import (backup as bk)
from panel.ops.ssh_manager import (get_server_status, mod_restart_decision, player_count as
    sm_player_count, remote_bootstrap_vps, remote_public_ip, run_game_backup)
# Reached through the MODULE, not bound by name: these are the seams the test suite
# monkeypatches. `from x import f` copies the function object, so a stub on the source
# module would never be seen — attribute access resolves at call time and is stable
# however the handler moves.
from panel.ops import ssh_manager as _sm
from panel.security.auth import (RESTART_SERVER, START_SERVER, STOP_SERVER, UPDATE_SERVER,
    VIEW_CONSOLE, get_user_permissions, log_action)
from panel.services import (notifications)
import threading
import time
from app import (_apply_whitelist_everywhere, _autoblock_hosts, _log, _prune_jobs,
    _run_autoblock_now, _security_whitelist, _security_whitelist_add,
    _security_whitelist_remove)
import re
from panel.core import (clock, terminal)

def _begin_bootstrap(app, remote_id, opts, actor_id):
    """Seed the job registry and start the background bootstrap. Returns
    (started, message). Refuses if one is already running for this remote."""
    _prune_jobs(_bootstrap_jobs, _bootstrap_lock)
    with _bootstrap_lock:
        existing = _bootstrap_jobs.get(remote_id)
        if existing and existing.get("status") in ("running", "rebooting"):
            return False, "A bootstrap is already running for this server."
        _bootstrap_jobs[remote_id] = {
            "status": "running", "step": 0, "total": 0,
            "step_name": "Starting…", "log": [], "message": "",
            "started": time.time(), "updated": time.time(),
        }
    _start_bootstrap_job(app, remote_id, opts, actor_id)
    return True, "Bootstrap started."

def _bg_cache_commands(app, server_ids):
    """Fetch + cache each server's LinuxGSM command list in the background so the
    "Supported Commands" panel is populated without the user hitting refresh. Install
    does this at step 5; import used to skip it, leaving the cache blank. Best-effort and
    per-server (one server's SSH failure never blocks the rest) and read-only on the host
    — it runs the instance script with no args, which just prints its command menu."""
    _app = app

    def _run():
        with _app.app_context():
            for sid in server_ids:
                try:
                    gs = db.session.get(GameServer, sid)
                    if not gs:
                        continue
                    cmds = _sm.list_server_commands(gs.remote, gs.short_name, gs.lgsm_name)
                    if cmds:
                        gs.set_commands(cmds)
                        db.session.commit()
                except Exception:
                    db.session.rollback()
                    _log.debug("command cache failed for server %s", sid, exc_info=True)

    threading.Thread(target=_run, daemon=True).start()

def _whitelist_mutate(app, body):
    """Shared add/remove for the global security whitelist. On add: persist, push the new
    ignoreip to the panel jail, and immediately lift any existing fail2ban ban / UFW auto-block
    for the address so a just-whitelisted admin isn't left locked out until the next tick. The
    slow firewall work (jail reload, unban) is backgrounded so the button responds instantly —
    the config is already saved and reflected in the response."""
    raw = _json_str(body, "ip")
    remove = bool(body.get("remove"))
    if remove:
        canon = _security_whitelist_remove(raw)
        threading.Thread(target=_apply_whitelist_everywhere, args=(app,), daemon=True).start()
        log_action(current_user, "whitelist_remove", target=canon)
        return jsonify({"success": True, "removed": canon, "whitelist": _security_whitelist()})
    canon = _security_whitelist_add(raw)
    if not canon:
        return jsonify({"success": False, "message": "Enter a valid IP address or CIDR (e.g. 1.2.3.4 or 10.0.0.0/8)."})
    # A single address (not a CIDR range) also gets any existing ban lifted immediately.
    _unban = canon if "/" not in canon else None
    threading.Thread(target=_apply_whitelist_everywhere, args=(app, _unban), daemon=True).start()
    for rid in _autoblock_hosts():      # release any auto-block for the now-whitelisted address
        _run_autoblock_now(app, rid)
    log_action(current_user, "whitelist_add", target=canon)
    return jsonify({"success": True, "added": canon, "whitelist": _security_whitelist()})

def _maybe_resolve_public_ip(app, remote_id):
    """Resolve + cache a remote's public IP in the BACKGROUND (one SSH), rate-limited per
    remote. Request/render paths use remote.host as the immediate connect-address fallback and
    pick up the real public IP on a later load — instead of blocking on an SSH that hangs for
    the full connect timeout when the remote is unreachable. Best-effort; never raises."""
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

def _server_action_buttons(app, gs):
    """(actions, maintenance) for the control bar, filtered by what the game supports and what the
    CURRENT user may run.

    Shared by the server detail page and Files & Config, which renders the same bar — the two used
    to differ only because Files & Config had no bar at all, and it told you to "restart the server
    to apply" without offering a way to do it."""
    user_perms = get_user_permissions(current_user)
    is_sa = current_user.is_superadmin

    def _can(perm):
        return is_sa or perm in user_perms

    all_commands = gs.get_commands()
    if not all_commands:
        _maybe_cache_commands(app, gs.id)
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

    # Order matters — this is the on-screen button order (lifecycle order reads most naturally).
    actions = []
    if _can(START_SERVER):
        actions.append(("start", "Start"))
    if _can(STOP_SERVER):
        actions.append(("stop", "Stop"))
    if _can(RESTART_SERVER):
        actions.append(("restart", "Restart"))
    if _can(UPDATE_SERVER) and supports_update:
        actions.append(("update", "Update"))

    maint_perm = {
        "monitor": VIEW_CONSOLE, "details": VIEW_CONSOLE, "check-update": VIEW_CONSOLE,
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

def _record_backup_outcome(app, sid, gname, ok, reason, action, title):
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
    still applies — the Tags UI promises muting keeps a server out of the alert channel."""
    try:
        log_action(None, action, target=gname, detail=(reason or "")[:500], success=bool(ok))
        if ok:
            return
        _bk_gs = db.session.get(GameServer, sid)
        if _bk_gs is not None and notifications.alerts_muted(_bk_gs):
            return
        notifications.notify("backup_failed", title,
                             "The backup of %s failed: %s" % (gname, reason or "no reason given"))
    except Exception:
        # Never the thing that breaks the sweep: this is the reporting, and the callers below run
        # the remaining servers after it.
        app.logger.warning("could not record %s of %s", action, gname, exc_info=True)


def _run_due_game_backups(app):
    """Scheduled per-server backups: back up each installed server whose OWN schedule is due
    (its override, or the global default). Serialised via the same lock as manual backups."""
    if not _full_backup_lock.acquire(blocking=False):
        return
    try:
        with app.app_context():
            targets = [(gs.id, gs.remote, gs.short_name, gs.lgsm_name, gs.name, gs.game_type, gs.port)
                       for gs in GameServer.query.filter_by(installed=True).all() if gs.remote_id]
            for sid, remote, short, lgsm, gname, gtype, port in targets:
                try:
                    sched = bk.get_game_schedule(sid)
                    if sched["interval_days"] <= 0:
                        continue   # backups off for this server
                    if not sched["last"]:
                        # Never backed up on a schedule yet (fresh install / pre-existing server):
                        # start its clock now instead of backing up immediately, so the first
                        # scheduled backup is one interval out — not the moment it's installed.
                        bk.record_game_backup(sid)
                        continue
                    if not bk.game_backup_due(sid):
                        continue
                    keep = sched["keep"]
                    ok, reason, was_skipped = run_game_backup(remote, short, lgsm, keep,
                                                              game_type=gtype, port=port)
                    if was_skipped:
                        # Players online — leave the clock untouched so it stays "due" and we
                        # retry on the next hourly tick, backing up once the server empties.
                        # busy=True so the UI shows why it's waiting (+ a "back up anyway").
                        _game_backup_status[sid] = {"running": False, "ok": None, "busy": True,
                                                    "msg": reason, "ts": time.time()}
                        continue
                    bk.record_game_backup(sid)
                    _game_backup_status[sid] = {"running": False, "ok": ok,
                                                "msg": (reason or ("Backed up" if ok else "failed")),
                                                "ts": time.time()}
                    # Outside the except on purpose — a failed backup RETURNS here, it does not
                    # raise, and the clock was just recorded so this server will not be retried
                    # for a whole interval. See _record_backup_outcome.
                    _record_backup_outcome(app, sid, gname, ok, reason,
                                           "scheduled_backup", "Scheduled backup failed")
                except Exception as e:
                    app.logger.warning("scheduled backup of %s failed", gname, exc_info=True)
                    _record_backup_outcome(app, sid, gname, False,
                                           "backup error (%s)" % type(e).__name__,
                                           "scheduled_backup", "Scheduled backup failed")
    finally:
        _full_backup_lock.release()

def _run_pending_backups(app):
    """Servers queued via 'wait until empty' (backup_pending): back up each one that's now empty
    and clear its flag; leave the still-busy ones queued for the next tick. Serialised via the
    same lock as the other backup paths."""
    if not _full_backup_lock.acquire(blocking=False):
        return
    try:
        with app.app_context():
            # Per server, like the scheduled ticker above — not the global default. Pruning is an
            # unconditional rm of everything past `keep`, so using the global number here deleted
            # archives a server's own retention override said to retain.
            pending = GameServer.query.filter_by(installed=True, backup_pending=True).all()
            for gs in pending:
                if not gs.remote_id:
                    continue
                try:
                    ok, reason, was_skipped = run_game_backup(
                        gs.remote, gs.short_name, gs.lgsm_name,
                        bk.get_game_schedule(gs.id)["keep"],
                        game_type=gs.game_type, port=gs.port)
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
                            bk.record_game_backup(gs.id)
                        _game_backup_status[gs.id] = {"running": False, "ok": ok,
                                                      "msg": (reason or ("Backed up" if ok else "failed")),
                                                      "ts": time.time()}
                        # This sweep reported NOTHING at all — not even on the exception path.
                        # A queued backup that fails has also just left the queue, so nothing
                        # picks it up again until its own schedule comes round.
                        _record_backup_outcome(app, gs.id, gs.name, ok, reason,
                                               "queued_backup", "Queued backup failed")
                    # still players on → leave queued, retry next tick
                except Exception as e:
                    app.logger.warning("queued backup of %s failed", gs.name, exc_info=True)
                    _record_backup_outcome(app, gs.id, gs.name, False,
                                           "backup error (%s)" % type(e).__name__,
                                           "queued_backup", "Queued backup failed")
    finally:
        _full_backup_lock.release()

def _run_due_restarts(app):
    """Servers queued to restart OR stop once they empty — mod-restarts and the user's
    'restart/stop when empty'. Once empty, run the queued action (rechecked hourly). A stopped
    server clears its flags; an online-but-unqueryable one stays queued for a manual force."""
    with app.app_context():
        pending = [gs for gs in GameServer.query.filter_by(installed=True).all()
                   if gs.remote_id and (gs.restart_pending or gs.stop_pending)]
        for gs in pending:
            # Don't restart/stop a server that's being backed up right now — the backup already
            # stops+starts it, and racing it could fail the backup. Leave it queued for next tick.
            _bst = _game_backup_status.get(gs.id)
            if _bst and _bst.get("running"):
                continue
            try:
                # distinguish_unresponsive, because this loop is deciding whether there is
                # anything to ACT on, not whether players can connect. Folded into "offline", a
                # server whose session is alive but not serving read as "already stopped", so the
                # operator's queued stop/restart was cleared and never performed — silently, and
                # for a crashed server permanently. That is the very state the port check exists
                # to detect, and it is exactly when a queued "stop" most needs to happen.
                status = get_server_status(gs.remote, gs, distinguish_unresponsive=True)
                pc = sm_player_count(gs.remote, gs.short_name, gs.game_type, gs.port) \
                    if status == "online" else None
                # 'restart' here means "online + empty -> act now"; 'idle' = already stopped.
                decision = mod_restart_decision(status, pc)
                if decision == "idle":
                    gs.restart_pending = gs.stop_pending = False
                    db.session.commit()
                elif decision == "restart":
                    act = "stop" if gs.stop_pending else "restart"
                    _sm.run_as_game_user(gs.remote, gs.short_name, act,
                                     timeout=90, selfname=gs.lgsm_name)
                    if act == "restart":
                        try:
                            _sm.set_game_priority(gs.remote, gs.short_name)
                        except Exception:
                            app.logger.debug("priority boost failed", exc_info=True)
                    gs.restart_pending = gs.stop_pending = False
                    db.session.commit()
                # 'pending' (players on / unknown): leave the flags, retry next tick
            except Exception:
                app.logger.debug("pending restart/stop of %s failed", gs.name, exc_info=True)


def _start_bootstrap_job(app, remote_id, opts, actor_id):
    """Run remote_bootstrap_vps in a background (green) thread, streaming
    progress into the _bootstrap_jobs registry for the status endpoint."""
    _app = app

    def _progress(step, total, name, status):
        with _bootstrap_lock:
            job = _bootstrap_jobs.get(remote_id)
            if job is None:
                return
            job["step"] = step
            job["total"] = total
            job["step_name"] = name
            job["updated"] = time.time()
            if status in ("running", "rebooting", "done"):
                # keep top-level status "running" until finally done/failed
                job["status"] = "rebooting" if status == "rebooting" else job["status"]
            job["log"].append(f"[{step}/{total}] {name}" if total else name)

    def _run():
        try:
            with _app.app_context():
                remote = db.session.get(RemoteServer, remote_id)
                if not remote:
                    raise RuntimeError("Remote no longer exists")
                success, msg, log = remote_bootstrap_vps(remote, progress=_progress, **opts)
                if success:
                    remote.is_online = True
                    remote.last_seen = utcnow()
                    db.session.commit()
                log_action(None, "remote_vps_bootstrap", target=remote.name, detail=msg, success=success)
                with _bootstrap_lock:
                    job = _bootstrap_jobs.get(remote_id)
                    if job is not None:
                        job["status"] = "done" if success else "failed"
                        job["step_name"] = "Complete" if success else "Failed"
                        job["message"] = msg
                        job["updated"] = time.time()
        except Exception as e:
            with _bootstrap_lock:
                job = _bootstrap_jobs.get(remote_id)
                if job is not None:
                    job["status"] = "failed"
                    job["message"] = str(e)
                    job["log"].append(f"ERROR: {e}")
                    job["updated"] = time.time()

    threading.Thread(target=_run, daemon=True).start()

def _maybe_cache_commands(app, server_id):
    """Kick off a background command-list fetch for a server whose cache is empty, at most
    once every few minutes so reloading the page can't stack SSH calls. Lets servers
    imported before auto-caching existed self-heal the first time they're viewed."""
    now = time.time()
    if now - _cmd_fetch_attempts.get(server_id, 0) < 300:
        return
    _cmd_fetch_attempts[server_id] = now
    _bg_cache_commands(app, [server_id])

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
_cmd_fetch_attempts = {}       # server_id -> last background command-fetch time (rate-limits lazy refetch)
_pubip_resolve_attempts = {}   # remote_id -> last background public-IP resolve time

# Hoisted for the second wave of sections: the file browser and the API routes both call
# these, and "Manage Game Servers" defines neither. Same rule as the first ten — each closed
# over `app` and nothing else, so each takes it explicitly.

def _looks_installed(app, remote, short_name, lgsm_name):
    """Best-effort check of whether a game server is actually installed on the remote — used
    to reconcile an install whose live progress was lost (e.g. the panel restarted mid-install).
    Returns True (installed), False (clearly not), or None (couldn't tell)."""
    try:
        out, err, _ = _sm.run_command(
            remote,
            f"sudo -u {short_name} bash -c 'cd /home/{short_name} && ./{lgsm_name} details 2>&1'",
            timeout=30, sudo=False)
        low = terminal.strip_escapes((out or "") + "\n" + (err or "")).lower()
        if re.search(r"not installed|please run .*install|serverfiles.*(missing|not found)|no such file", low):
            return False
        if "status:" in low or "server ip:" in low:
            return True
        # Fallback: real content in serverfiles means the download completed.
        #
        # The sentinel is what makes this a THREE-state answer instead of two. run_command does not
        # raise on a transport failure — it returns ("", "…timed out", -1) — and `2>/dev/null` means
        # a missing serverfiles dir ALSO prints nothing. Without the marker both read as "" and the
        # old `int("0") > 50` answered False, i.e. "clearly NOT installed", for a read that never
        # happened. That verdict is acted on: the reconcile ticker in app.py sets
        # installed=False / status="failed" on it (its own next line says "None (host unreachable):
        # leave it" — exactly the case False was stealing), and the install retry in
        # manage_servers.py wipes lgsm/tmp and re-runs a 30-minute auto-install, three times over.
        #
        # With the marker: no marker means the command did not complete -> None ("couldn't tell").
        # Marker present and no number means serverfiles really is absent -> False.
        out2, _, _ = _sm.run_command(
            remote,
            f"sudo -u {short_name} bash -c 'du -sm /home/{short_name}/serverfiles 2>/dev/null "
            f"| cut -f1; echo __DU_DONE__'",
            timeout=20, sudo=False)
        if "__DU_DONE__" not in (out2 or ""):
            return None
        _mb = (out2 or "").replace("__DU_DONE__", "").strip()
        try:
            return int(_mb or "0") > 50
        except ValueError:
            return None
    except Exception:
        app.logger.debug("install reconcile check failed", exc_info=True)
        return None

def _notify_servers_changed(app):
    """Best-effort broadcast to every connected browser that the game-server set
    changed (one was added or removed), so open dashboards / Game Servers pages
    reconcile live instead of waiting for a manual refresh. A dropped broadcast must
    never affect the actual install/uninstall, so this is fully swallowed."""
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
    short_name is validated as a shell identifier on the model, so neither can escape the path."""
    return f"/home/{short_name}/.panel-{action}.log"


# How many pushed lines to keep per server for replay after a reload. A `validate` on a large
# game is a few hundred lines of SteamCMD spool; this holds one comfortably without becoming a
# place anyone would mistake for the log.
_CONSOLE_BACKLOG_MAX = 600


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
    the whole window twice on every poll."""
    if not text:
        return
    ts = float(ts if ts is not None else time.time())
    try:
        buf = _console_backlog.setdefault(server_id, [])
        buf.extend({"t": ts, "line": ln} for ln in str(text).split("\n") if ln.strip())
        if len(buf) > _CONSOLE_BACKLOG_MAX:
            del buf[:len(buf) - _CONSOLE_BACKLOG_MAX]
    except Exception:
        _log.debug("console backlog append failed for server %s", server_id, exc_info=True)
    try:
        sio = getattr(app, "socketio", None)
        if sio is not None:
            sio.emit("console_output", {"server_id": server_id, "data": text, "ts": ts},
                     room=f"console_{server_id}")
    except Exception:
        _log.debug("console push for server %s failed (non-fatal)", server_id, exc_info=True)


def _drain_action_output(app, remote, server_id):
    """Send any NEW bytes of server_id's in-flight action output to its console viewers.

    Returns True if an action is registered for this server (i.e. keep draining), False if there
    is nothing to tail. Offsets work exactly as the console poller's do, and for the same reason:
    `stat` reports the size in the SAME round trip, because run_command strips the output it
    returns and a length measured on stripped text would drift the offset on every tick."""
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
        out, _, _ = _sm.run_command(remote, f"sudo -u {user} bash -c {_sm._quote(sh)}",
                                    timeout=15, sudo=False)
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


def _begin_action_tail(app, server_id, action, path, user):
    """Register an action's output file for tailing and announce it in the console."""
    _action_output[server_id] = {"action": action, "path": path, "user": user, "pos": 0}
    _console_push(app, server_id, f"[panel] {action} started — its output follows.")


def _end_action_tail(app, server_id, remote, action, rc):
    """Drain whatever is left, say how it went, and stop tailing.

    The final drain is the point of doing this here rather than just deleting the entry: the
    poller ticks every two seconds, so the last — and most interesting — lines of a command that
    has just exited are the ones that would otherwise never be sent."""
    # Only OUR entry. _action_output is keyed by server_id alone and _begin_action_tail overwrites
    # whatever is there, so two long actions on one server (nothing serialises them — every
    # maintenance button posts the same route and returns within a second) left this popping the
    # OTHER action's registration. The shorter one finishing then drained the longer one's file,
    # deregistered it, and every later poller tick returned immediately: the ten-minute SteamCMD
    # download the panel had just told the operator to watch the console for streamed nothing, and
    # its own final drain found no entry, so the last lines were lost too.
    own = (_action_output.get(server_id) or {}).get("action") == action
    if own:
        try:
            _drain_action_output(app, remote, server_id)
        except Exception:
            _log.debug("final action-output drain for server %s failed", server_id, exc_info=True)
        finally:
            _action_output.pop(server_id, None)
    if rc == 0:
        _console_push(app, server_id, f"[panel] {action} finished successfully.")
    elif rc is None:
        # The SSH call raised, or timed out — we never got an exit code. Deliberately not
        # reported as a failure of the action itself: on a 30-minute timeout the update may well
        # still be running on the host.
        _console_push(app, server_id, f"[panel] {action} stopped reporting — see the audit log.")
    else:
        _console_push(app, server_id, f"[panel] {action} failed (exit {rc}) — see above.")


_tz_resolve_attempts = register_remote_state({})   # remote_id -> last attempt (rate limit)


def _maybe_resolve_host_timezone(app, remote_id):
    """Read + cache a host's IANA timezone in the BACKGROUND, rate-limited per remote.

    Same shape and the same reason as _maybe_resolve_public_ip above: the detail page's rule is
    that nothing on the render path touches the remote, because an unreachable host then hangs the
    render for the whole SSH connect timeout. The page shows what is stored and picks the real
    value up on a later load. Best-effort; never raises."""
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
    UTC: a timezone shown confidently and wrong is the bug this whole change exists to remove."""
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
    host's local time and converting it against a guess would date every line hours wrong."""
    rows = []
    for ln in lines:
        stamp, rest = terminal.split_log_timestamp(ln)
        rows.append({"t": clock.host_stamp_to_epoch(stamp, host_tz) if stamp else None,
                     "line": rest})
    return rows
