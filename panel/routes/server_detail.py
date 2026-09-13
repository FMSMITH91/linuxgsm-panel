"""One server's detail page, its live console and its per-server actions.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (flash, jsonify, redirect, render_template, request, url_for)
from flask_login import (current_user, login_required)
from panel.core import (terminal)
from panel.core.panel_state import (_cron_restart_pending)
from panel.db.models import (CUSTOM_ARG_DEFAULT_PATTERN, CUSTOM_ARG_PLACEHOLDER, CustomCommand,
    GameServer, GlobalBan, RemoteServer, User, db)
from panel.ops.ssh_manager import (GAMEDIG_TYPE as GAMEDIG_TYPE_MAP, _invalidate_port_scan,
    _resolve_from_console, _sanitize_steamid, game_engine, is_player_queryable,
    list_server_commands, moderate, moderation_caps, player_count as sm_player_count,
    player_list, run_as_game_user, send_console_command, set_autostart, set_daily_restart,
    set_game_priority)
from panel.security.auth import (MANAGE_SERVERS, MODERATE_SERVER, READONLY_ACTIONS,
    RESTART_SERVER, SEND_COMMAND, _can_manage_files, _perm_for_action, allowed_custom_commands,
    can_access_server, can_moderate_action, can_run_custom_command, get_game,
    get_user_permissions, has_permission, log_action, server_access_required)
from panel.services.monitoring import (_PLAYER_POLL_WORKERS)
import concurrent.futures
import re
import threading
from app import (LONG_ACTIONS, RUNNABLE_ACTIONS, _apply_mod_restart, _json_body,
    _live_run_state, _log, _log_and_generic, _mark_expected_offline)
from panel.routes._shared import (_maybe_resolve_public_ip, _server_action_buttons)


def register(app):






    @app.route("/server/<int:server_id>")
    @login_required
    @server_access_required
    def server_detail(server_id):
        gs = get_game(server_id)
        if not gs.installed:   # still installing (or a failed install) — nothing to show a console for yet
            flash("That server is still installing — its console isn't available until it's done.", "info")
            return redirect(url_for("manage_servers"))
        remote = gs.remote

        # Render fast: no SSH on the render path. Live status, console output and
        # per-game metrics all stream in asynchronously (websocket + /stats + /console
        # polling), so the page appears instantly instead of waiting on the remote.
        console_lines = []

        # Available actions based on permissions
        user_perms = get_user_permissions(current_user)
        is_sa = current_user.is_superadmin

        def _can(perm):
            return is_sa or perm in user_perms

        # The control bar (start/stop/restart/update + maintenance), built once and shared with
        # Files & Config so the two pages cannot drift apart again.
        actions, maintenance, all_commands, supports_update = _server_action_buttons(app, gs)

        can_send_command = _can(SEND_COMMAND)
        can_autostart = _can(RESTART_SERVER)

        # Public address players connect to. For the LOCAL panel host, remote.host is
        # 127.0.0.1 (loopback SSH), so resolve/cache the real public IP instead. Do it in the
        # background: show remote.host now, fill in the public IP next load — never block the
        # render on an SSH that hangs for the whole connect timeout on an unreachable remote.
        if not remote.public_ip:
            _maybe_resolve_public_ip(app, remote.id)
        public_host = remote.public_ip or ("" if remote.is_local else remote.host)

        # Granular moderation flags (kick / ban / announce can be granted independently now).
        can_kick = can_moderate_action(current_user, "kick")
        can_ban = can_moderate_action(current_user, "ban")
        can_say = can_moderate_action(current_user, "say")
        can_moderate = can_kick or can_ban or can_say
        # Custom commands this user may run on THIS server (respects group assignment + scope).
        custom_commands = allowed_custom_commands(current_user, gs)
        return render_template("server_detail.html", server=gs, remote=remote,
                               console_lines=console_lines, actions=actions,
                               maintenance=maintenance, all_commands=all_commands,
                               can_send_command=can_send_command, can_moderate=can_moderate,
                               can_kick=can_kick, can_ban=can_ban, can_say=can_say,
                               custom_commands=custom_commands,
                               can_autostart=can_autostart, public_host=public_host,
                               # The console log lives under the game user's home, so the file
                               # browser's download route already serves it — no second endpoint.
                               # It needs MANAGE_SERVERS though, where the console itself only
                               # needs VIEW_CONSOLE, so the button is hidden for anyone who would
                               # just be bounced by it.
                               console_log_rel="log/console/%s-console.log" % gs.lgsm_name,
                               can_download_log=_can_manage_files(),
                               cron_restart_pending=_cron_restart_pending.get(gs.id, False))



    def _run_action(gs, remote, action, actor, origin=None):
        """Execute a whitelisted action (permission already checked).
        Returns (ok, message). Long actions run in the background.

        `origin` names a non-user caller for the audit log — currently the chat bots, which have
        no panel account to attribute to. Without it their actions were recorded as "system", so
        the log showed a server restarting with nothing to say a chat message caused it."""
        # Don't fire a power action that is already a no-op. LinuxGSM answers "Server already
        # started" and exits, but start/stop run in the background here and their output is
        # discarded, so the panel reported "'start' issued — status updates in a few seconds" as a
        # success for a server it had listed as online moments earlier. It had the answer and
        # wasn't using it.
        #
        # Two-step on purpose: the cached status column decides whether to LOOK (so the normal case
        # costs nothing), and the host decides whether to REFUSE. A stale "online" must never be
        # what stops someone starting a server that has actually died. 'restart' is never guarded —
        # it is correct from either state, and so is the way out if this ever refuses wrongly.
        # The message deliberately doesn't repeat the server's name: the two callers that show it
        # (both chat bots) already prefix every reply with it, and the background branch below
        # doesn't name it either.
        if action == "start" and gs.status == "online" and _live_run_state(gs, remote):
            return False, "already running. Use 'restart' if you want it bounced."
        if action == "stop" and gs.status == "offline" and _live_run_state(gs, remote) is False:
            return False, "already stopped."
        if action in ("stop", "restart"):
            _mark_expected_offline(gs.id)   # so the monitor doesn't alert on an intentional stop
        if action in LONG_ACTIONS:
            _bg_action(gs.id, remote.id, gs.short_name, action, gs.lgsm_name)
            log_action(actor, f"{action}_server", target=gs.name, actor=origin)
            return True, f"'{action}' started — watch the live console for progress."
        if action in ("start", "stop", "restart"):
            # These block for ~8-17s (srcds Steam/VAC init on start, a graceful `quit` wait on stop,
            # plus LinuxGSM confirming the outcome). Run them in the background so the click returns
            # immediately and the status poll reflects the result, instead of hanging the button.
            _bg_power_action(gs.id, remote.id, gs.short_name, action, gs.lgsm_name,
                             actor.id if actor else None, origin=origin)
            return True, f"'{action}' issued — status updates in a few seconds."
        timeout = 90 if action == "restart" else 60
        out, err, rc = run_as_game_user(remote, gs.short_name, f"{action} 2>&1", timeout=timeout, selfname=gs.lgsm_name)
        # Strip ALL ANSI/CSI escape sequences (colors end in 'm', but LinuxGSM also
        # emits erase-line "\x1b[K" etc.), plus collapse whitespace for a clean message.
        def _clean(s):
            s = terminal.strip_escapes(s or "")
            return re.sub(r"[ \t]{2,}", " ", s)
        log_action(actor, f"{action}_server", target=gs.name, success=(rc == 0),
                   detail=_clean(out)[-400:], actor=origin)
        clean = _clean((out or "") + "\n" + (err or "")).strip()
        # This changed what's listening on the host — drop the cached port scan so the dashboard
        # reflects the new state on its next poll instead of up to a TTL of stale "offline/online".
        if rc == 0 and action in ("restart", "start", "stop"):
            _invalidate_port_scan(remote.id)
        # A manual start/stop/restart makes any queued 'when empty' restart/stop moot — clear both.
        if rc == 0 and action in ("restart", "start", "stop") and (gs.restart_pending or gs.stop_pending):
            gs.restart_pending = False
            gs.stop_pending = False
            db.session.commit()
        # Give the freshly-(re)started game a small CPU-priority edge over background work.
        if rc == 0 and action in ("restart", "start"):
            try:
                set_game_priority(remote, gs.short_name)
            except Exception:
                app.logger.debug("game priority boost failed (non-fatal)", exc_info=True)
        if action in READONLY_ACTIONS:
            return True, f"{action}: {clean[:600] or 'no output'}"
        if rc == 0:
            return True, f"'{action}' succeeded for '{gs.name}'."
        # Surface WHY it failed — pull the most relevant LinuxGSM line.
        reason = ""
        for line in reversed(clean.splitlines()):
            low = line.lower()
            if any(k in low for k in ("fail", "unable", "error", "missing", "not found", "no such")):
                reason = line.strip()
                break
        if not reason and clean.splitlines():
            reason = clean.splitlines()[-1].strip()
        return False, f"'{action}' failed for '{gs.name}': {reason[:280] or 'unknown — check the console'}"

    @app.route("/server/<int:server_id>/action", methods=["POST"])
    @login_required
    @server_access_required
    def server_action(server_id):
        gs = get_game(server_id)
        action = request.form.get("action", "")
        if action not in RUNNABLE_ACTIONS:
            flash(f"Unknown or unsupported action: {action}", "danger")
            return redirect(url_for("server_detail", server_id=server_id))
        if not current_user.is_superadmin and not has_permission(current_user, _perm_for_action(action)):
            flash(f"You don't have permission to run '{action}'.", "danger")
            return redirect(url_for("server_detail", server_id=server_id))
        try:
            ok, msg = _run_action(gs, gs.remote, action, current_user)
            flash(msg, "info" if (action in LONG_ACTIONS or action in READONLY_ACTIONS) else ("success" if ok else "warning"))
        except Exception as e:
            log_action(current_user, f"{action}_server", target=gs.name, detail=str(e), success=False)
            # The exception text is in the audit log above, not in the flash: echoing str(e) to the
            # browser is how internals leak into the UI (py/stack-trace-exposure), and this
            # codebase's rule is never to do it.
            flash("That action failed. The audit log has the details.", "danger")
        return redirect(url_for("server_detail", server_id=server_id))

    @app.route("/api/server/<int:server_id>/action", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_action(server_id):
        """JSON action endpoint for inline controls (dashboard/lists) — no reload."""
        gs = get_game(server_id)
        data = _json_body()
        action = (data.get("action") or "").strip()
        if action not in RUNNABLE_ACTIONS:
            return jsonify({"success": False, "message": f"Unsupported action: {action}"}), 400
        if not current_user.is_superadmin and not has_permission(current_user, _perm_for_action(action)):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        try:
            ok, msg = _run_action(gs, gs.remote, action, current_user)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500

    def _bg_bulk_action(server_id, remote_id, action, actor_id):
        """Run one server's action in the background for the bulk endpoint, so a request
        that fans out to many servers returns immediately instead of blocking on each SSH
        round trip. Re-fetches the rows inside the worker's app context (the request's
        objects would be detached), then dispatches through the same _run_action path as
        the single-server controls."""
        _app = app

        def _run():
            try:
                with _app.app_context():
                    gs = db.session.get(GameServer, server_id)
                    remote = db.session.get(RemoteServer, remote_id)
                    actor = db.session.get(User, actor_id)
                    if gs and remote:
                        _run_action(gs, remote, action, actor)
            except Exception:
                app.logger.exception("bulk action %s failed for server %s", action, server_id)

        threading.Thread(target=_run, daemon=True).start()

    @app.route("/api/servers/bulk-action", methods=["POST"])
    @login_required
    def api_bulk_action():
        """Run one action (start/stop/restart/update/…) across several servers at once.

        Checks the caller's permission for the action once, then their access to EACH
        selected server, and dispatches each in the background so the request returns
        immediately — the dashboard's status poll reflects the outcome. Returns a
        per-server queued/skipped list. The fan-out is capped so one request can't spawn
        an unbounded number of SSH operations."""
        data = _json_body()
        action = (data.get("action") or "").strip()
        raw_ids = data.get("server_ids")
        if action not in RUNNABLE_ACTIONS:
            return jsonify({"success": False, "message": f"Unsupported action: {action}"}), 400
        if not isinstance(raw_ids, list) or not raw_ids:
            return jsonify({"success": False, "message": "No servers selected"}), 400
        if not current_user.is_superadmin and not has_permission(current_user, _perm_for_action(action)):
            return jsonify({"success": False, "message": "Permission denied"}), 403

        ids = []
        for sid in raw_ids[:100]:   # cap the batch — bounds the SSH fan-out per request
            try:
                ids.append(int(sid))
            except (TypeError, ValueError):
                continue

        queued, skipped = [], []
        for sid in ids:
            gs = db.session.get(GameServer, sid)
            if gs is None:
                skipped.append({"server_id": sid, "name": "#%d" % sid, "reason": "not found"})
                continue
            if not can_access_server(current_user, sid):
                skipped.append({"server_id": sid, "name": gs.name, "reason": "no access"})
                continue
            # Never run 'update' on a game that has no LinuxGSM update command (e.g. the Call of
            # Duty family) — in a mixed selection those are skipped, not failed.
            if action == "update" and not gs.supports_update:
                skipped.append({"server_id": sid, "name": gs.name, "reason": "no update support"})
                continue
            _bg_bulk_action(gs.id, gs.remote_id, action, current_user.id)
            queued.append({"server_id": sid, "name": gs.name})

        if queued:
            log_action(current_user, "bulk_%s" % action, target="%d server(s)" % len(queued),
                       detail="ids=%s" % ",".join(str(q["server_id"]) for q in queued))
        return jsonify({"success": bool(queued), "action": action,
                        "queued": queued, "skipped": skipped})

    @app.route("/api/server/<int:server_id>/players")
    @login_required
    @server_access_required
    def api_server_players(server_id):
        """Current player count for a server (or null if not queryable). Used to warn before a
        restart that would disconnect players."""
        gs = get_game(server_id)
        try:
            pc = sm_player_count(gs.remote, gs.short_name, gs.game_type, gs.port, gs.query_type)
        except Exception:
            pc = None
        return jsonify({"players": pc})

    @app.route("/api/server/<int:server_id>/playerlist")
    @login_required
    @server_access_required
    def api_server_playerlist(server_id):
        """Live list of connected players (names + score/time where the game reports them) plus
        which moderation actions this game supports, for the Players panel. The automatic poll asks
        gamedig only (never the game console); the panel sends `?console=1` only when you click the
        refresh button, so a single `status` is issued on your explicit request, not on a timer."""
        gs = get_game(server_id)
        allow_console = request.args.get("console") == "1"
        try:
            players = player_list(gs.remote, gs.short_name, gs.game_type, gs.port, gs.query_type,
                                  selfname=gs.lgsm_name, allow_console=allow_console)
        except Exception:
            players = None
        # None => couldn't read over the network (and console wasn't run). Tell the UI so it shows a
        # "set a GSLT / load once from console" hint instead of a misleading "no players connected".
        unknown = players is None
        return jsonify({"players": players or [], "unknown": unknown,
                        "console_capable": bool(game_engine(gs.game_type)),
                        "caps": moderation_caps(gs.game_type),
                        "queryable": is_player_queryable(gs.game_type, gs.query_type),
                        "engine": game_engine(gs.game_type),
                        "query_type": gs.query_type or "",
                        "default_query": GAMEDIG_TYPE_MAP.get(gs.game_type, "")})

    @app.route("/api/server/<int:server_id>/query-type", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_query_type(server_id):
        """Override (or clear) the gamedig query type for a server, so games the built-in map gets
        wrong or doesn't cover (e.g. cod) can still be queried. Validated to a gamedig-safe charset.

        Requires MODERATE_SERVER, SEND_COMMAND or MANAGE_SERVERS. Deliberately NOT the granular
        moderation permissions (kick_player / say_server): this writes server configuration, so it
        is not routed through can_moderate_action, which grants on any single moderation right."""
        gs = get_game(server_id)
        if not (current_user.is_superadmin or has_permission(current_user, MODERATE_SERVER)
                or has_permission(current_user, SEND_COMMAND)
                or has_permission(current_user, MANAGE_SERVERS)):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        raw = (_json_body().get("query_type") or "").strip().lower()
        if raw and not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", raw):
            return jsonify({"success": False, "message": "Invalid query type — use letters, "
                            "numbers, - or _ (see the gamedig games list)."}), 400
        gs.query_type = raw or None
        db.session.commit()
        log_action(current_user, "set_query_type", target=gs.name, detail=raw or "(default)")
        return jsonify({"success": True, "query_type": gs.query_type or "",
                        "queryable": is_player_queryable(gs.game_type, gs.query_type)})

    @app.route("/api/server/<int:server_id>/moderate", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_moderate(server_id):
        """Kick/ban a player or announce a message via the game console. Requires the moderate
        permission (or full console access / superadmin — those can already do it by hand). The
        player name is sanitized in ssh_manager.moderate() so a hostile name can't inject."""
        gs = get_game(server_id)
        data = _json_body()
        action = (data.get("action") or "").strip()
        if action not in ("kick", "ban", "say"):
            return jsonify({"success": False, "message": "Unknown action"}), 400
        # Per-action permission: a mod may hold only kick, only ban, etc. (SEND_COMMAND / the
        # umbrella MODERATE_SERVER / superadmin still grant all three).
        if not can_moderate_action(current_user, action):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        target = data.get("target", "")
        steamid = data.get("steamid", "")
        num = data.get("num", "")
        scope = (data.get("scope") or "this").strip()
        reason = (data.get("reason") or "").strip()[:200]
        # A Valve ban needs the SteamID up front — to also fan it out and record a global ban. The
        # on-screen list may be gamedig-sourced (no id), so resolve it from the console once here;
        # otherwise the cross-server fan-out below (guarded on `steamid`) would be silently skipped.
        if action == "ban" and game_engine(gs.game_type) == "valve" and not _sanitize_steamid(steamid):
            try:
                _rp = _resolve_from_console(gs.remote, gs.short_name, gs.game_type, target, gs.lgsm_name)
                if _rp and _rp.get("steamid"):
                    steamid = _rp["steamid"]
            except Exception:
                _log.debug("moderate: steamid pre-resolve failed", exc_info=True)
        try:
            ok, msg = moderate(gs.remote, gs.short_name, gs.game_type, action,
                               target=target, message=data.get("message", ""),
                               selfname=gs.lgsm_name, steamid=steamid, num=num)
            log_action(current_user, "moderate_%s" % action, target=gs.name,
                       detail=(target or steamid or data.get("message") or "")[:120], success=ok)
            # Cross-server ban: on a successful ban with scope "all", apply the SAME ban to every
            # OTHER server the user can moderate that acts on this player's identifier — SteamID on
            # all Valve servers, name on all Minecraft servers. Slot-based (idTech3) bans reference a
            # live connection slot, so they can't be ported and stay on this server only.
            if ok and action == "ban" and scope == "all":
                origin_eng = game_engine(gs.game_type)
                # Pick the target servers (access + engine checks are cheap/DB), then ban them all IN
                # PARALLEL so a many-server ban doesn't block on one SSH round trip per server.
                targets = []
                for other in GameServer.query.filter_by(installed=True).all():
                    if other.id == gs.id or game_engine(other.game_type) != origin_eng:
                        continue
                    if not can_access_server(current_user, other.id):
                        continue
                    if (origin_eng == "valve" and steamid) or (origin_eng == "minecraft" and target):
                        targets.append(other.id)   # idTech3 slot bans don't port; skipped

                def _ban_other(oid):
                    with app.app_context():
                        o = db.session.get(GameServer, oid)
                        if not o:
                            return False
                        try:
                            kw = {"steamid": steamid} if origin_eng == "valve" else {"target": target}
                            ok2, _m = moderate(o.remote, o.short_name, o.game_type, "ban",
                                               selfname=o.lgsm_name, **kw)
                            return bool(ok2)
                        except Exception:
                            return False

                applied = 0
                if targets:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=min(_PLAYER_POLL_WORKERS, len(targets))) as ex:
                        applied = sum(1 for r in ex.map(_ban_other, targets) if r)
                if applied:
                    log_action(current_user, "moderate_ban_all", target="%d server(s)" % applied,
                               detail=(steamid or target)[:120], success=True)
                    msg = (msg + " ").strip() + " Also banned on %d other server%s." % (
                        applied, "" if applied == 1 else "s")
                # Record a superadmin's cross-server SteamID ban on the MANAGED global list, so it
                # shows on /global-bans and re-applies to servers added later (the fan-out above only
                # hit servers that exist right now). Managing that list is superadmin-only, so gate it.
                if origin_eng == "valve" and current_user.is_superadmin:
                    _sid = _sanitize_steamid(steamid)
                    if _sid and not GlobalBan.query.filter_by(steamid=_sid).first():
                        db.session.add(GlobalBan(steamid=_sid, player_name=(target or "")[:80],
                                                 reason=reason, created_by=current_user.username))
                        db.session.commit()
                        log_action(current_user, "global_ban_add", target=_sid,
                                   detail=reason or "via all-servers ban")
                        msg = (msg + " Added to the global ban list.").strip()
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("moderation failed")}), 500

    @app.route("/api/server/<int:server_id>/custom-command/<int:cmd_id>", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_custom_command(server_id, cmd_id):
        """Run a superadmin-defined custom command on this server. The command TEMPLATE is trusted
        (authored by a superadmin); the only user input is the optional {} value, which is validated
        against the command's pattern before substitution so it can't inject extra console commands."""
        gs = get_game(server_id)
        cmd = db.session.get(CustomCommand, cmd_id)
        if not cmd or not can_run_custom_command(current_user, cmd, gs):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        final = cmd.command_template or ""
        if cmd.has_argument:
            value = (_json_body().get("value") or "").strip()
            try:
                if not re.fullmatch(cmd.effective_pattern(), value):
                    raise ValueError
            except (re.error, ValueError):
                # A bad stored pattern must not become a bypass — fall back to the safe default.
                if not re.fullmatch(CUSTOM_ARG_DEFAULT_PATTERN, value):
                    return jsonify({"success": False,
                                    "message": "Invalid value for %s." % (cmd.argument_label or "argument")}), 400
            final = final.replace(CUSTOM_ARG_PLACEHOLDER, value)
        try:
            out, err, rc = send_console_command(gs.remote, gs.short_name, final,
                                                timeout=10, selfname=gs.lgsm_name)
            log_action(current_user, "custom_command", target=gs.name,
                       detail=("%s: %s" % (cmd.name, final))[:200], success=(rc == 0))
            if rc != 0:
                return jsonify({"success": False,
                                "message": "Console (tmux) not accessible. Is the server running?"}), 502
            return jsonify({"success": True, "message": "Ran '%s'." % cmd.name})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("custom command failed")}), 500

    @app.route("/api/server/<int:server_id>/restart-when-empty", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_restart_when_empty(server_id):
        """Queue a restart for once the server is empty (players leave), instead of kicking them now.
        Reuses restart_pending — the hourly ticker restarts it as soon as it's empty."""
        gs = get_game(server_id)
        if not current_user.is_superadmin and not has_permission(current_user, _perm_for_action("restart")):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        gs.restart_pending = True
        gs.stop_pending = False   # restart supersedes a queued stop
        db.session.commit()
        log_action(current_user, "restart_when_empty", target=gs.name, success=True)
        return jsonify({"success": True,
                        "message": "Queued — %s will restart automatically once it's empty." % gs.name})

    @app.route("/api/server/<int:server_id>/stop-when-empty", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_stop_when_empty(server_id):
        """Queue a stop for once the server is empty, instead of kicking players now. The hourly
        ticker stops it as soon as it's empty."""
        gs = get_game(server_id)
        if not current_user.is_superadmin and not has_permission(current_user, _perm_for_action("stop")):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        gs.stop_pending = True
        gs.restart_pending = False   # stop supersedes a queued restart
        db.session.commit()
        log_action(current_user, "stop_when_empty", target=gs.name, success=True)
        return jsonify({"success": True,
                        "message": "Queued — %s will stop automatically once it's empty." % gs.name})

    @app.route("/api/server/<int:server_id>/autostart", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_autostart(server_id):
        """Toggle autostart. This manages the game user's LinuxGSM `monitor` cron (which keeps
        the server in its intended state across crashes/reboots) — it does not start or stop the
        server here and now."""
        gs = get_game(server_id)
        if not current_user.is_superadmin and not has_permission(current_user, RESTART_SERVER):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        data = _json_body()
        enabled = bool(data.get("enabled"))
        try:
            ok, detail = set_autostart(gs.remote, gs.short_name, enabled, gs.lgsm_name)
            if ok:
                gs.autostart = enabled
                db.session.commit()
                log_action(current_user, "set_autostart", target=gs.name, detail=str(enabled))
                return jsonify({"success": True, "enabled": enabled})
            return jsonify({"success": False, "message": detail or "Failed to update crontab"}), 500
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500

    @app.route("/api/server/<int:server_id>/daily-restart", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_daily_restart(server_id):
        """Toggle the daily restart-when-empty schedule for this server."""
        gs = get_game(server_id)
        if not current_user.is_superadmin and not has_permission(current_user, RESTART_SERVER):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        enabled = bool(_json_body().get("enabled"))
        try:
            ok, detail = set_daily_restart(gs.remote, gs.short_name, gs.lgsm_name,
                                           gs.game_type, gs.port, enabled)
            if ok:
                gs.daily_restart = enabled
                db.session.commit()
                log_action(current_user, "set_daily_restart", target=gs.name, detail=str(enabled))
                return jsonify({"success": True, "enabled": enabled})
            return jsonify({"success": False, "message": detail or "Failed to update schedule"}), 500
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500

    @app.route("/api/server/<int:server_id>/notify-empty", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_notify_empty(server_id):
        """Toggle the one-shot 'alert me once this server is empty' flag (a plain DB flag the player
        poller acts on). Fires a single server_empty notification when the count next hits 0, then
        clears itself — so an admin can wait for 0 players before making a change."""
        gs = get_game(server_id)
        if not current_user.is_superadmin and not has_permission(current_user, RESTART_SERVER):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        enabled = bool(_json_body().get("enabled"))
        gs.notify_when_empty = enabled
        db.session.commit()
        log_action(current_user, "set_notify_when_empty", target=gs.name, detail=str(enabled))
        return jsonify({"success": True, "enabled": enabled})

    def _bg_power_action(server_id, remote_id, short_name, action, selfname, actor_id, origin=None):
        """Run a start/stop/restart in the background so the click returns immediately (the command
        is slow — srcds Steam/VAC init on start, a graceful shutdown wait on stop, plus LinuxGSM's
        confirm step). The dashboard/list status poll reflects the outcome. Mirrors the synchronous
        path's post-action bookkeeping (audit log, port-scan invalidation, clearing 'when empty'
        flags, and the CPU-priority nudge)."""
        _app = app

        def _run():
            try:
                with _app.app_context():
                    remote = db.session.get(RemoteServer, remote_id)
                    gs = db.session.get(GameServer, server_id)
                    actor = db.session.get(User, actor_id) if actor_id else None
                    if not remote or not gs:
                        return
                    timeout = 90 if action == "restart" else 60
                    out, _, rc = run_as_game_user(remote, short_name, f"{action} 2>&1",
                                                  timeout=timeout, selfname=selfname)
                    clean = terminal.strip_escapes(out or "")
                    log_action(actor, f"{action}_server", target=gs.name, success=(rc == 0),
                               detail=clean[-400:], actor=origin)
                    if rc == 0:
                        _invalidate_port_scan(remote_id)
                        if gs.restart_pending or gs.stop_pending:
                            gs.restart_pending = False
                            gs.stop_pending = False
                            db.session.commit()
                        if action in ("restart", "start"):
                            try:
                                set_game_priority(remote, short_name)
                            except Exception:
                                app.logger.debug("game priority boost failed (non-fatal)", exc_info=True)
            except Exception:
                app.logger.exception("power action %s failed for server %s", action, server_id)

        threading.Thread(target=_run, daemon=True).start()

    def _bg_action(server_id, remote_id, short_name, action, selfname=None):
        """Run a long LinuxGSM command in the background (green thread)."""
        _app = app

        def _run():
            try:
                with _app.app_context():
                    remote = db.session.get(RemoteServer, remote_id)
                    if not remote:
                        return
                    act_cmd = f"{action} 2>&1"
                    if action == "fastdl":
                        # fastdl asks a few yes/no questions (overwrite / force-download / continue),
                        # all default Y, and loops forever on EOF — feed Y's so it runs unattended.
                        act_cmd = "fastdl <<< $'Y\\nY\\nY\\nY\\nY\\nY\\nY\\nY' 2>&1"
                    out, err, rc = run_as_game_user(remote, short_name, act_cmd, timeout=1800, selfname=selfname)
                    gs = db.session.get(GameServer, server_id)
                    log_action(None, f"{action}_complete", target=gs.name if gs else short_name,
                               success=(rc == 0), detail=(out or err or "")[-300:])
                    # An update/validate/fastdl can restart the server (port cycles) — drop the
                    # cached port scan so the dashboard shows the real state on its next poll.
                    _invalidate_port_scan(remote_id)
                    # Updated mods only load after a restart — apply it when empty, else flag pending.
                    if action == "mods-update" and rc == 0 and gs:
                        try:
                            _apply_mod_restart(gs, remote)
                        except Exception:
                            app.logger.warning("post mods-update restart of %s failed",
                                               gs.name, exc_info=True)
            except Exception:
                app.logger.exception("background action failed")

        threading.Thread(target=_run, daemon=True).start()

    @app.route("/server/<int:server_id>/refresh-commands", methods=["POST"])
    @login_required
    @server_access_required
    def refresh_server_commands(server_id):
        gs = get_game(server_id)
        try:
            cmds = list_server_commands(gs.remote, gs.short_name, gs.lgsm_name)
            gs.set_commands(cmds)
            db.session.commit()
            flash(f"Loaded {len(cmds)} commands for '{gs.name}'.", "success")
        except Exception:
            _log.debug("command list refresh failed for %s", gs.name, exc_info=True)
            flash(f"Could not read the command list for '{gs.name}'.", "danger")
        return redirect(url_for("server_detail", server_id=server_id))

    @app.route("/server/<int:server_id>/command", methods=["POST"])
    @login_required
    @server_access_required
    def server_command(server_id):
        gs = get_game(server_id)
        remote = gs.remote
        cmd_text = request.form.get("command", "").strip()

        if not cmd_text:
            flash("No command entered.", "warning")
            return redirect(url_for("server_detail", server_id=server_id))

        # Permission check
        if not current_user.is_superadmin and not has_permission(current_user, SEND_COMMAND):
            flash("You don't have permission to send commands.", "danger")
            return redirect(url_for("server_detail", server_id=server_id))

        try:
            # LinuxGSM runs each instance in a tmux session owned by its own user.
            out, err, rc = send_console_command(remote, gs.short_name, cmd_text, timeout=10, selfname=gs.lgsm_name)
            if rc != 0:
                flash("Cannot send command: server console (tmux) not accessible. Is the server running?", "warning")
                return redirect(url_for("server_detail", server_id=server_id))
            log_action(current_user, "send_command", target=gs.name, detail=cmd_text, success=True)
            flash(f"Command sent: {cmd_text}", "success")

        except Exception as e:
            log_action(current_user, "send_command", target=gs.name, detail=f"{cmd_text} - {e}", success=False)
            flash("Failed to send that command. The audit log has the details.", "danger")

        return redirect(url_for("server_detail", server_id=server_id))

    # Published on `app` because the module-level Telegram and Discord command bots drive a
    # start/stop/restart through this exact function, rather than a copy of its logic. It used to
    # be assigned at the end of register_routes(); now the module that owns it does the publishing,
    # so the export cannot outlive the definition moving.
    app._run_action = _run_action
