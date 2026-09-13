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
from panel.core.panel_state import (_full_backup_lock, _game_backup_status)
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
from panel.core import (terminal)
from panel.ops.ssh_manager import (run_command)

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
    raw = (body.get("ip") or "").strip()
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
    cmd_set = {c["cmd"] for c in all_commands}
    # Some games aren't SteamCMD-based (the Call of Duty family) and have NO `update` command.
    # An empty list means it hasn't been fetched yet — fail open rather than hide the button.
    supports_update = (not cmd_set) or ("update" in cmd_set)

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
                except Exception:
                    app.logger.warning("scheduled backup of %s failed", gname, exc_info=True)
                    # Server-scoped, so a muting tag applies here too — the Tags UI promises
                    # muting keeps a server out of the alert channel, without qualification.
                    _bk_gs = db.session.get(GameServer, sid)
                    if not (_bk_gs is not None and notifications.alerts_muted(_bk_gs)):
                        notifications.notify("backup_failed", "Scheduled backup failed",
                                             "The scheduled backup of %s failed." % gname)
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
            keep = bk.get_full_settings()["keep"]
            pending = GameServer.query.filter_by(installed=True, backup_pending=True).all()
            for gs in pending:
                if not gs.remote_id:
                    continue
                try:
                    ok, reason, was_skipped = run_game_backup(
                        gs.remote, gs.short_name, gs.lgsm_name, keep,
                        game_type=gs.game_type, port=gs.port)
                    if not was_skipped:
                        # Backed up (or genuinely failed) — either way the wait is over.
                        gs.backup_pending = False
                        db.session.commit()
                        _game_backup_status[gs.id] = {"running": False, "ok": ok,
                                                      "msg": (reason or ("Backed up" if ok else "failed")),
                                                      "ts": time.time()}
                    # still players on → leave queued, retry next tick
                except Exception:
                    app.logger.warning("queued backup of %s failed", gs.name, exc_info=True)
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
                status = get_server_status(gs.remote, gs)
                pc = sm_player_count(gs.remote, gs.short_name, gs.game_type, gs.port) \
                    if status == "online" else None
                # 'restart' here means "online + empty -> act now"; 'idle' = already stopped.
                decision = mod_restart_decision(status, pc)
                if decision == "idle":
                    gs.restart_pending = gs.stop_pending = False
                    db.session.commit()
                elif decision == "restart":
                    act = "stop" if gs.stop_pending else "restart"
                    _sm.run_as_game_user(gs.remote, gs.short_name, act + " 2>&1",
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
_bootstrap_jobs = {}
_bootstrap_lock = threading.Lock()
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
        out, err, _ = run_command(
            remote,
            f"sudo -u {short_name} bash -c 'cd /home/{short_name} && ./{lgsm_name} details 2>&1'",
            timeout=30, sudo=False)
        low = terminal.strip_escapes((out or "") + "\n" + (err or "")).lower()
        if re.search(r"not installed|please run .*install|serverfiles.*(missing|not found)|no such file", low):
            return False
        if "status:" in low or "server ip:" in low:
            return True
        # Fallback: real content in serverfiles means the download completed.
        out2, _, _ = run_command(
            remote,
            f"sudo -u {short_name} bash -c 'du -sm /home/{short_name}/serverfiles 2>/dev/null | cut -f1'",
            timeout=20, sudo=False)
        try:
            return int((out2 or "0").strip() or "0") > 50
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
