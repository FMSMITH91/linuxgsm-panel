"""The per-server config editor, file browser and the live console socket.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (Response, flash, jsonify, redirect, render_template, request, url_for)
from flask_login import (current_user, login_required)
from flask_socketio import (emit, join_room, leave_room)
from panel.core import (terminal)
from panel.db.models import (GameServer, RemoteServer, db)
from panel.ops.ssh_manager import (GMOD_CONTENT_GAMES, GMOD_CONTENT_SIZES, UPLOAD_EXISTS,
    add_cron_job, browse_dir, delete_path, detect_content_user, ensure_content_user,
    gmod_current_mounts, gmod_mount_setup, install_gmod_content, lgsm_game_config,
    lgsm_get_values, lgsm_read_config, lgsm_write_config, mods_action, mods_available,
    mods_installed, path_disk_free, read_file, run_cron_job_now, send_console_command,
    stat_path, stat_upload_targets, stream_path, uninstall_gmod_content, update_cron_job,
    upgrade_managed_cron_tracking, upload_file, write_file)
# Reached through the MODULE, not bound by name: these are the seams the test suite
# monkeypatches. `from x import f` copies the function object, so a stub on the source
# module would never be seen — attribute access resolves at call time and is stable
# however the handler moves.
from panel.ops import ssh_manager as _sm
from panel.security.auth import (SEND_COMMAND, UPDATE_SERVER, VIEW_CONSOLE, _can_manage_files,
    can_access_server, get_game, has_permission, log_action, server_access_required,
    superadmin_required)
from panel.services import (lgsm_data)
import re
import threading
import time
from app import (ALERT_PROVIDERS, _ALERT_KEYS, _ALERT_KEY_SET, _CONSOLE_LINES,
    _CONSOLE_LINES_MAX, _GAME_LIST_CACHE, _LGSM_NAME_MAP, _MAX_UPLOAD_BYTES, _apply_mod_restart,
    _attachment_header, _clean_console_text, _console_viewers, _gmod_content_apply_state,
    _json_body, _log, _log_and_generic, _sync_toggles_from_cron, _viewers_lock, load_game_list)
from flask_socketio import (SocketIO, emit, join_room, leave_room)
from app import (_socketio_cors)
from panel.routes._shared import (_server_action_buttons)


def register(app, supervise):
    """Register the file/config routes and the console socket. RETURNS the SocketIO instance.

    console_poller stays here too: it pushes through this socket, so it belongs beside the
    handlers that read from it. The supervisor is passed in for it, the way os_updates takes one.

    socketio is CONSTRUCTED here rather than handed in: the four @socketio.on handlers are the
    only ones in the codebase and they live in this section, so this is where it belongs. It is
    returned because register_routes still needs it — the console-poller ticker pushes through
    it, and app.socketio is what the entry point calls .run() on.
    """
    @app.route("/server/<int:server_id>/files")
    @login_required
    @server_access_required
    def server_files(server_id):
        """Config editor + live file browser for a game server."""
        gs = get_game(server_id)
        if not gs.installed:   # files don't exist yet while it's still installing (or after a failure)
            flash("That server is still installing — its files aren't available until it's done.", "info")
            return redirect(url_for("manage_servers"))
        if not _can_manage_files():
            flash("You don't have permission to manage server files.", "danger")
            return redirect(url_for("server_detail", server_id=server_id))
        # Same control bar as the detail page — this page tells you to restart to apply a
        # change, so it has to offer the button.
        actions, maintenance, _all_cmds, _sup = _server_action_buttons(app, gs)
        return render_template("server_files.html", server=gs, remote=gs.remote,
                               actions=actions, maintenance=maintenance)

    @app.route("/api/server/<int:server_id>/config", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_config(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if request.method == "GET":
            try:
                return jsonify(lgsm_read_config(gs.remote, gs.short_name, gs.lgsm_name))
            except Exception:
                return jsonify({"error": _log_and_generic("request failed")}), 500
        data = _json_body()
        try:
            if data.get("raw") is not None:
                rel = f"lgsm/config-lgsm/{gs.lgsm_name}/{gs.lgsm_name}.cfg"
                ok, msg = write_file(gs.remote, gs.short_name, rel, data["raw"])
            else:
                ok, msg = lgsm_write_config(gs.remote, gs.short_name, gs.lgsm_name, data.get("settings") or {})
            log_action(current_user, "edit_config", target=gs.name, success=ok)
            return jsonify({"success": ok, "message": msg or ("Saved" if ok else "Failed")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500

    @app.route("/api/server/<int:server_id>/game-config")
    @login_required
    @server_access_required
    def api_server_game_config(server_id):
        """The game's own server config file (detected via LinuxGSM details)."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        try:
            return jsonify(lgsm_game_config(gs.remote, gs.short_name, gs.lgsm_name))
        except Exception:
            return jsonify({"error": _log_and_generic("game config read failed")}), 200

    @app.route("/api/server/<int:server_id>/alerts", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_alerts(server_id):
        """Read/write the server's LinuxGSM alert settings (Discord/Telegram/email/…). Writes
        straight into the LinuxGSM config so the game server itself sends the notifications."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if request.method == "GET":
            try:
                vals = lgsm_get_values(gs.remote, gs.short_name, gs.lgsm_name, _ALERT_KEYS)
            except Exception:
                vals = {}   # host unreachable — still return the static provider list so it renders
                app.logger.debug("alerts read failed", exc_info=True)
            return jsonify({"providers": ALERT_PROVIDERS, "values": vals})
        # POST: only the known alert keys; toggles coerced to on/off.
        data = _json_body().get("values") or {}
        updates = {}
        for k, v in data.items():
            if k not in _ALERT_KEY_SET:
                continue
            if k.endswith("alert"):
                v = "on" if str(v).lower() in ("on", "true", "1", "yes") else "off"
            updates[k] = v
        try:
            ok, msg = lgsm_write_config(gs.remote, gs.short_name, gs.lgsm_name, updates)
            log_action(current_user, "server_alerts_save", target=gs.name, success=ok)
            return jsonify({"success": ok, "message": msg or ("Saved" if ok else "Failed")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("alerts save failed")}), 200

    @app.route("/api/server/<int:server_id>/mods", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_mods(server_id):
        """List / install / remove LinuxGSM mods (SourceMod, MetaMod, Oxide, …). Listing
        drives LinuxGSM's mods menus; install/remove feed the chosen mod id. Install/remove
        modify the install, so they need UPDATE_SERVER."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if request.method == "GET":
            available, installed, supported = [], [], True
            try:
                available, av_ok = mods_available(gs.remote, gs.short_name, gs.lgsm_name)
                installed, in_ok = mods_installed(gs.remote, gs.short_name, gs.lgsm_name)
                supported = av_ok and in_ok   # this game has a LinuxGSM mods installer
            except Exception:
                app.logger.debug("mods list failed", exc_info=True)  # unreachable host — return empties
            return jsonify({"available": available, "installed": installed, "supported": supported})
        # POST: install or remove a mod by its LinuxGSM id (e.g. "sourcemod").
        if not (current_user.is_superadmin or has_permission(current_user, UPDATE_SERVER)):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        data = _json_body()
        which = "install" if data.get("action") == "install" else ("remove" if data.get("action") == "remove" else "")
        mod_id = str(data.get("mod") or "").strip()   # str() so a numeric/other type can't crash .strip()
        if not which or not re.match(r"^[A-Za-z0-9._-]+$", mod_id):
            return jsonify({"success": False, "message": "Pick a valid mod to " + (which or "act on") + "."}), 400
        try:
            out, err, rc = mods_action(gs.remote, gs.short_name, gs.lgsm_name, which, mod_id)
            clean = terminal.strip_escapes(((out or "") + "\n" + (err or ""))).strip()
            log_action(current_user, f"mods_{which}", target=gs.name, success=(rc == 0), detail=clean[-400:])
            ok = rc == 0
            tail = ""
            for line in reversed(clean.splitlines()):
                if line.strip():
                    tail = line.strip()
                    break
            msg = (f"Mod {which} finished." if ok
                   else f"Mod {which} reported an error: {tail[:200] or 'check the console'}")
            restart_pending = False
            if ok:
                # A mod change only loads on restart — we never restart automatically; just tell the
                # admin a restart is needed so the UI can offer "Restart now".
                state, rmsg = _apply_mod_restart(gs, gs.remote)
                restart_pending = (state == "needed")   # drives the "Restart now" button in the UI
                if rmsg:
                    msg = msg + " " + rmsg
            return jsonify({"success": ok, "message": msg, "restart_pending": restart_pending})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("mods action failed")}), 200

    @app.route("/api/server/<int:server_id>/browse")
    @login_required
    @server_access_required
    def api_server_browse(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        try:
            result = browse_dir(gs.remote, gs.short_name, request.args.get("path", ""), gs.lgsm_name)
            if result is None:
                return jsonify({"error": "Invalid path"}), 400
            return jsonify(result)
        except Exception:
            return jsonify({"error": _log_and_generic("request failed")}), 500

    @app.route("/api/server/<int:server_id>/file", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_file(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if request.method == "GET":
            content, err = read_file(gs.remote, gs.short_name, request.args.get("path", ""))
            if err:
                return jsonify({"error": err}), 400
            return jsonify({"content": content, "path": request.args.get("path", "")})
        data = _json_body()
        rel = data.get("path", "")
        try:
            ok, msg = write_file(gs.remote, gs.short_name, rel, data.get("content", ""))
            log_action(current_user, "edit_file", target=gs.name, detail=rel, success=ok)
            return jsonify({"success": ok, "message": msg or ("Saved" if ok else "Failed")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500

    @app.route("/api/server/<int:server_id>/delete-path", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_delete_path(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        rel = _json_body().get("path", "")
        try:
            ok, msg = delete_path(gs.remote, gs.short_name, rel, gs.lgsm_name)
            log_action(current_user, "delete_file", target=gs.name, detail=rel, success=ok)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("delete_path failed")}), 500


    @app.route("/server/<int:server_id>/download")
    @login_required
    @server_access_required
    def server_file_download(server_id):
        """Download one file from the game server, or a .tar.gz of one directory.

        Not an /api route and not JSON: this is a plain GET the browser navigates to, so the file
        lands in the download manager with a name and a progress bar instead of being buffered
        through fetch() as a blob. A 4 GB map pack would not survive that.

        The editor's read (api_server_file) is text-only, capped at 1 MB and refuses a binary —
        which is right for an editor and useless for a download, so this streams instead. Same
        permission as the rest of the file browser: if you may edit and delete these files, you
        may take a copy of one.
        """
        gs = get_game(server_id)
        if not _can_manage_files():
            flash("You don't have permission to manage server files.", "danger")
            return redirect(url_for("server_detail", server_id=server_id))
        rel = request.args.get("path", "")
        # Every failure below ends in a flash and a redirect rather than an abort(), because this
        # is a LINK the browser follows: an error page would replace the file browser with a bare
        # 404, whereas a redirect back to the page says what went wrong and leaves the admin where
        # they were. A download that succeeds never navigates at all.
        def _refuse(message, category="warning"):
            flash(message, category)
            return redirect(url_for("server_files", server_id=server_id))

        try:
            info = stat_path(gs.remote, gs.short_name, rel)
        except Exception:
            _log.debug("download: could not stat the path", exc_info=True)
            return _refuse("Couldn't reach %s to read that file." % gs.name, "danger")
        if not info:
            return _refuse("That file or folder isn't there any more.")
        if info["rel"] in (".", ""):
            # The home directory itself — by an empty ?path=, or by any spelling that resolves
            # back to it ("." , "/", "cfg/.."). stream_path refuses it too; this is the half that
            # can still explain why, instead of sending a 0-byte archive named after the user.
            return _refuse("Pick a file or a folder to download, not the whole home directory.")
        is_dir = info["type"] == "d"
        name = info["name"] + (".tar.gz" if is_dir else "")
        log_action(current_user, "download_file", target=gs.name,
                   detail=rel + (" (as .tar.gz)" if is_dir else ""))
        resp = Response(stream_path(gs.remote, gs.short_name, rel, as_tar=is_dir,
                                    limit=None if is_dir else info["size"]),
                        mimetype="application/gzip" if is_dir else "application/octet-stream")
        if not is_dir:
            # A directory archive is generated as it streams, so its length is not knowable in
            # advance — the browser shows an indeterminate download for those. A file's is, and
            # the same number caps the stream: a console log the game is still writing to would
            # otherwise hand back more bytes than this header promises.
            resp.headers["Content-Length"] = str(info["size"])
        resp.headers["Content-Disposition"] = _attachment_header(name)
        return resp

    @app.route("/api/lgsm-data/refresh", methods=["POST"])
    @login_required
    @superadmin_required
    def api_lgsm_data_refresh():
        """Re-fetch LinuxGSM's serverlist/deps now.

        The install form offers this when it has no games to show, which means the fetch failed and
        nothing was cached — almost always a host with no outbound access to GitHub. Superadmin
        because it makes an outbound request and replaces install-wide data.
        """
        try:
            ok = lgsm_data.refresh()
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("lgsm data refresh failed")}), 200
        # Drop the module-level memos too, or the page would re-render the old (empty) answer.
        _GAME_LIST_CACHE["games"] = None
        _LGSM_NAME_MAP["data"] = None
        games = len(load_game_list())
        log_action(current_user, "lgsm_data_refresh", success=ok, detail="%d games" % games)
        return jsonify({"success": bool(ok and games), "games": games,
                        "message": ("Loaded %d games." % games) if games
                                   else "Could not reach LinuxGSM — check this host's outbound access."})

    @app.route("/api/server/<int:server_id>/cron", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_server_cron(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if request.method == "GET":
            try:
                # One-time, in-place upgrade so pre-existing managed jobs start reporting
                # success/error (idempotent + state-preserving; never blocks the listing).
                try:
                    upgrade_managed_cron_tracking(gs.remote, gs.short_name, gs.lgsm_name)
                except Exception:
                    app.logger.debug("cron tracking upgrade skipped", exc_info=True)
                jobs = _sm.list_cron_jobs(gs.remote, gs.short_name, gs.lgsm_name)
                _sync_toggles_from_cron(gs, jobs)
                return jsonify({"jobs": jobs})
            except Exception:
                return jsonify({"error": _log_and_generic("list_cron_jobs failed")}), 500
        data = _json_body()
        try:
            ok, msg = add_cron_job(gs.remote, gs.short_name, data.get("schedule"),
                                   data.get("command"), gs.lgsm_name)
            if ok:
                _sync_toggles_from_cron(gs, _sm.list_cron_jobs(gs.remote, gs.short_name, gs.lgsm_name))
            log_action(current_user, "cron_add", target=gs.name, success=ok,
                       detail=(data.get("schedule") or "")[:120])
            return jsonify({"success": ok, "message": msg or ("Added" if ok else "Failed")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("add_cron_job failed")}), 500

    @app.route("/api/server/<int:server_id>/cron/update", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_cron_update(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        data = _json_body()
        try:
            ok, msg = update_cron_job(gs.remote, gs.short_name, data.get("raw") or "",
                                      data.get("schedule"), data.get("command"), gs.lgsm_name)
            log_action(current_user, "cron_update", target=gs.name, success=ok,
                       detail=(data.get("schedule") or "")[:120])
            return jsonify({"success": ok, "message": msg or ("Updated" if ok else "Failed")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("update_cron_job failed")}), 500

    @app.route("/api/server/<int:server_id>/cron/delete", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_cron_delete(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        data = _json_body()
        try:
            ok, msg = _sm.delete_cron_job(gs.remote, gs.short_name, data.get("raw") or "", gs.lgsm_name)
            if ok:
                # The card's own help text promises that deleting `monitor` turns Autostart off.
                _sync_toggles_from_cron(gs, _sm.list_cron_jobs(gs.remote, gs.short_name, gs.lgsm_name))
            log_action(current_user, "cron_delete", target=gs.name, success=ok)
            return jsonify({"success": ok, "message": msg or ("Deleted" if ok else "Failed")})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("delete_cron_job failed")}), 500

    @app.route("/api/server/<int:server_id>/cron/run", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_cron_run(server_id):
        """Run a scheduled task on demand (records its exit code + output so Last-run updates)."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        raw = _json_body().get("raw") or ""
        try:
            ok, msg = run_cron_job_now(gs.remote, gs.short_name, raw, gs.lgsm_name)
            log_action(current_user, "cron_run_now", target=gs.name, success=ok)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("cron run failed")}), 200


    def _bg_gmod_content_apply(server_id, remote_id, gmod_user, games):
        """Apply a GMod content selection in the background (a download can take many minutes): ensure
        a content user, fetch any missing games, then rewrite the server's mount.cfg to exactly the
        selection. An empty selection unmounts everything. Result is stashed for the status poll."""
        _app = app
        _gmod_content_apply_state[server_id] = {"status": "running", "msg": "", "ts": time.time()}

        def _run():
            with _app.app_context():
                try:
                    remote = db.session.get(RemoteServer, remote_id)
                    if not remote:
                        return
                    if games:
                        cu = ensure_content_user(remote)
                        if not cu:
                            _gmod_content_apply_state[server_id] = {
                                "status": "error", "msg": "No content storage could be prepared on the host.",
                                "ts": time.time()}
                            return
                        install_gmod_content(remote, cu["user"], games)
                        ok, msg = gmod_mount_setup(remote, gmod_user, cu["user"], games)
                    else:
                        ok, msg = gmod_mount_setup(remote, gmod_user, "", [])
                    _gmod_content_apply_state[server_id] = {
                        "status": "done" if ok else "error", "msg": msg, "ts": time.time()}
                except Exception:
                    _log.warning("gmod content apply failed for %s", gmod_user, exc_info=True)
                    _gmod_content_apply_state[server_id] = {
                        "status": "error", "msg": "Content setup failed — check the server logs.",
                        "ts": time.time()}

        threading.Thread(target=_run, daemon=True).start()

    def _bg_gmod_content_uninstall(server_id, remote_id, gmod_user, games):
        """Uninstall content from the host (host-wide) in the background, then drop the removed games
        from THIS server's mounts. Result is stashed for the status poll."""
        _app = app
        _gmod_content_apply_state[server_id] = {"status": "running", "msg": "", "ts": time.time()}

        def _run():
            with _app.app_context():
                try:
                    remote = db.session.get(RemoteServer, remote_id)
                    if not remote:
                        return
                    cu = detect_content_user(remote, tuple(GMOD_CONTENT_GAMES))
                    removed = []
                    if cu:
                        _, removed, _m = uninstall_gmod_content(remote, cu["user"], games)
                    # Drop the removed games from THIS server's mount.cfg (other servers just skip the
                    # now-missing mount). Best-effort.
                    remaining = [g for g in gmod_current_mounts(remote, gmod_user) if g not in games]
                    gmod_mount_setup(remote, gmod_user, (cu or {}).get("user", ""), remaining)
                    _gmod_content_apply_state[server_id] = {
                        "status": "done", "msg": "Removed from host: " + (", ".join(removed) or "(none)"),
                        "ts": time.time()}
                except Exception:
                    _log.warning("gmod content uninstall failed for %s", gmod_user, exc_info=True)
                    _gmod_content_apply_state[server_id] = {
                        "status": "error", "msg": "Uninstall failed — check the server logs.",
                        "ts": time.time()}

        threading.Thread(target=_run, daemon=True).start()

    @app.route("/api/server/<int:server_id>/gmod-content", methods=["GET", "POST"])
    @login_required
    @server_access_required
    def api_gmod_content(server_id):
        # Gate BOTH methods, like every other file-editor route: mount status exposes what content
        # exists on the host. The POST branch used to carry its own inline copy of this check, which
        # is what left the GET ungated.
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        gs = get_game(server_id)
        if gs.game_type != "gmod":
            return jsonify({"error": "Content mounting is available for Garry's Mod only."}), 400
        remote = gs.remote
        if request.method == "GET":
            try:
                mounted = gmod_current_mounts(remote, gs.short_name)
                cu = detect_content_user(remote, tuple(GMOD_CONTENT_GAMES))
                present = set((cu or {}).get("present", {}))
                games = [{"key": k, "label": GMOD_CONTENT_GAMES[k][0], "size": GMOD_CONTENT_SIZES.get(k, ""),
                          "present": (k in present), "mounted": (k in mounted),
                          "downloadable": GMOD_CONTENT_GAMES[k][1] is not None} for k in GMOD_CONTENT_GAMES]
                st = _gmod_content_apply_state.get(server_id)
                # Free disk on the filesystem where content is stored — so nobody starts a 13GB
                # install without room. Uses the content user's serverfiles if one exists, else /home.
                content_path = ("/home/%s/serverfiles" % cu["user"]) if cu else "/home"
                disk_free, disk_total = path_disk_free(remote, content_path)
                return jsonify({"games": games, "mounted": mounted,
                                "disk_free": disk_free, "disk_total": disk_total,
                                "job": st if (st and st.get("status") == "running") else None})
            except Exception:
                return jsonify({"error": _log_and_generic("gmod content status failed"), "games": []}), 200
        # POST: apply a selection (mutating). The MANAGE_SERVERS gate is at the top of the route.
        body = _json_body()
        action = body.get("action") or "mount"
        sel = [g for g in (body.get("games") or []) if g in GMOD_CONTENT_GAMES]
        if action == "uninstall":
            _bg_gmod_content_uninstall(gs.id, remote.id, gs.short_name, sel)
            log_action(current_user, "gmod_content_uninstall", target=gs.name, detail=",".join(sel))
            return jsonify({"success": True, "games": sel,
                            "message": "Removing content from the host — this frees disk for every GMod "
                                       "server here. Restart affected servers afterwards."})
        _bg_gmod_content_apply(gs.id, remote.id, gs.short_name, sel)
        log_action(current_user, "gmod_content", target=gs.name, detail=(",".join(sel) or "(none)"))
        return jsonify({"success": True, "games": sel,
                        "message": "Applying mount changes — a download can take a while for large games. "
                                   "Restart the server afterwards to load the changes."})

    @app.route("/api/server/<int:server_id>/upload", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_upload(server_id):
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        reldir = request.form.get("path", "")
        f = request.files.get("file")
        if not f or not f.filename:
            return jsonify({"success": False, "message": "No file provided"}), 400
        data = f.read(_MAX_UPLOAD_BYTES + 1)   # bounded read: never pull more than the limit into memory
        if len(data) > _MAX_UPLOAD_BYTES:
            return jsonify({"success": False, "message": "File too large (max 50 MB)"}), 400
        # Overwriting is opt-in per request: the browser asks the user first (showing both files'
        # size and date), and only then sends overwrite=1. Anything else — an older client, a
        # direct API call, or a file that appeared between the check and this write — gets a 409
        # conflict rather than silently replacing someone's config.
        overwrite = request.form.get("overwrite") == "1"
        try:
            ok, msg = upload_file(gs.remote, gs.short_name, reldir, f.filename, data,
                                  overwrite=overwrite)
            if not ok and msg == UPLOAD_EXISTS:
                return jsonify({"success": False, "conflict": True, "name": f.filename,
                                "message": "A file with that name already exists."}), 409
            log_action(current_user, "upload_file", target=gs.name,
                       detail="%s/%s%s" % (reldir, f.filename, " (overwrote)" if overwrite else ""),
                       success=ok)
            return jsonify({"success": ok, "message": msg or ("Uploaded" if ok else "Failed"), "name": f.filename})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500

    @app.route("/api/server/<int:server_id>/upload-check", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_upload_check(server_id):
        """Which of these names already exist in the target directory, with size + mtime.

        Lets the browser show old-vs-new and ask before overwriting, without uploading the bytes
        twice. Advisory only — the upload route re-checks, so a file that appears in between is
        still refused rather than clobbered."""
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        body = _json_body()
        names = body.get("names")
        if not isinstance(names, list) or len(names) > 500:
            return jsonify({"error": "Invalid request"}), 400
        try:
            hits = stat_upload_targets(gs.remote, gs.short_name, body.get("path", ""), names)
            if hits is None:
                return jsonify({"error": "Invalid path"}), 400
            return jsonify({"existing": hits, "checked": True})
        except Exception:
            # An unreachable host is the ordinary case here, not a bug, and it must not answer
            # "nothing exists" — that reads as "no conflicts" and is exactly the false clear this
            # endpoint exists to prevent. checked=false lets the UI say it could not look; the
            # upload route's own refusal stays the backstop either way.
            _log.debug("upload-check: could not list the target directory", exc_info=True)
            return jsonify({"existing": [], "checked": False})

    @app.route("/api/console/<int:server_id>")
    @login_required
    @server_access_required
    def api_console(server_id):
        gs = get_game(server_id)
        if not current_user.is_superadmin and not has_permission(current_user, VIEW_CONSOLE):
            return jsonify({"error": "Permission denied", "lines": []}), 403
        remote = gs.remote
        # How much of the log to return. This was a hard `tail -100`, which is where "the console
        # clears out a lot of the old console" came from: 100 lines is a minute or two of chat and
        # connects on a busy server, and the poll returns a SLIDING WINDOW, so anything older had
        # already fallen off before the browser ever saw it. The browser keeps its own scrollback
        # now (it appends what is new instead of re-rendering), so this window only has to be big
        # enough that a gap between two polls is still covered — and the FIRST load has some
        # history to show. Clamped because it is a caller-supplied number that sizes a read.
        try:
            want = int(request.args.get("lines") or _CONSOLE_LINES)
        except (TypeError, ValueError):
            want = _CONSOLE_LINES
        want = max(50, min(want, _CONSOLE_LINES_MAX))
        try:
            log_path = gs.console_log
            out, err, rc = _sm.run_command(remote, f"tail -{want} {log_path} 2>/dev/null", timeout=15)
            lines = _clean_console_text(out).split("\n") if rc == 0 else []
        except Exception:
            lines = []
        return jsonify({"lines": lines})

    @app.route("/api/command/<int:server_id>", methods=["POST"])
    @login_required
    @server_access_required
    def api_send_command(server_id):
        gs = get_game(server_id)
        remote = gs.remote
        data = _json_body()
        cmd_text = data.get("command", "").strip()

        if not cmd_text:
            return jsonify({"error": "No command provided"}), 400

        if not current_user.is_superadmin and not has_permission(current_user, SEND_COMMAND):
            return jsonify({"error": "Permission denied"}), 403

        try:
            out, err, rc = send_console_command(remote, gs.short_name, cmd_text, timeout=10, selfname=gs.lgsm_name)
            log_action(current_user, "send_command", target=gs.name, detail=cmd_text, success=(rc == 0))
            if rc != 0:
                return jsonify({"error": "Console (tmux) not accessible. Is the server running?"}), 502
            return jsonify({"success": True, "command": cmd_text})
        except Exception:
            return jsonify({"error": _log_and_generic("request failed")}), 500


    socketio = SocketIO(app, cors_allowed_origins=_socketio_cors(), async_mode="eventlet")

    # Track which sockets are viewing which server console, so the poller only
    # polls consoles that someone is actually watching (idle = ~0% CPU).

    @socketio.on("connect")
    def on_socket_connect():
        # Defence in depth: only authenticated sessions get a socket at all. Anonymous or
        # cross-site handshakes (which, thanks to SameSite=Lax, won't carry the session
        # cookie) are refused here — so no client can hold a connection or receive any
        # broadcast (e.g. servers_changed) without being logged in. Returning False rejects
        # the connection. Per-event checks (join_console) still apply on top of this.
        if not current_user.is_authenticated:
            return False
        return True   # authenticated → accept the socket

    @socketio.on("join_console")
    def on_join_console(data):
        server_id = data.get("server_id")
        if not server_id:
            return
        # Enforce the SAME access control as the HTTP console routes: the socket must
        # belong to a logged-in user who has access to this specific server AND holds
        # VIEW_CONSOLE. Without this, any socket could stream any server's console.
        if (not current_user.is_authenticated
                or not can_access_server(current_user, server_id)
                or not (current_user.is_superadmin or has_permission(current_user, VIEW_CONSOLE))):
            emit("console_output", {"server_id": server_id,
                                    "data": "[access denied — you don't have permission to view this console]"})
            return
        join_room(f"console_{server_id}")
        with _viewers_lock:
            _console_viewers.setdefault(server_id, set()).add(request.sid)

    @socketio.on("leave_console")
    def on_leave_console(data):
        server_id = data.get("server_id")
        if server_id:
            leave_room(f"console_{server_id}")
            with _viewers_lock:
                if server_id in _console_viewers:
                    _console_viewers[server_id].discard(request.sid)
                    if not _console_viewers[server_id]:
                        del _console_viewers[server_id]

    @socketio.on("disconnect")
    def on_console_disconnect():
        # A browser that closed without leave_console must still stop the poller.
        with _viewers_lock:
            for sid_set in list(_console_viewers.values()):
                sid_set.discard(request.sid)
            for k in [k for k, v in _console_viewers.items() if not v]:
                del _console_viewers[k]

    # Console polling thread — streams new console output to WebSocket viewers.
    def console_poller():
        last_positions = {}
        while True:
            try:
                with _viewers_lock:
                    active_ids = list(_console_viewers.keys())
                if active_ids:
                    with app.app_context():
                        for server_id in active_ids:
                            gs = db.session.get(GameServer, server_id)
                            if not gs or not gs.remote:
                                continue
                            remote = gs.remote
                            try:
                                log_path = gs.console_log
                                size_out, _, _ = _sm.run_command(
                                    remote, f"stat -c%s {log_path} 2>/dev/null || echo 0", timeout=5
                                )
                                try:
                                    current_size = int(size_out.strip())
                                except ValueError:
                                    continue
                                last_pos = last_positions.get(server_id, 0)
                                if current_size < last_pos:  # log rotated/truncated
                                    last_pos = 0
                                if current_size > last_pos:
                                    if last_pos == 0:
                                        last_positions[server_id] = current_size
                                        continue
                                    diff = min(current_size - last_pos, 65536)  # cap 64KB/poll
                                    # tail -c +N | head -c diff: two reads, not one-per-byte.
                                    out, _, _ = _sm.run_command(
                                        remote,
                                        f"tail -c +{last_pos + 1} {log_path} 2>/dev/null | head -c {diff}",
                                        timeout=5,
                                    )
                                    if out:
                                        out = _clean_console_text(out)
                                    if out:
                                        socketio.emit("console_output",
                                                      {"server_id": server_id, "data": out},
                                                      room=f"console_{server_id}")
                                    last_positions[server_id] = current_size
                            except Exception:
                                continue   # skip this server; keep polling the rest
            except Exception:
                app.logger.debug("console poller iteration failed", exc_info=True)
            time.sleep(2)


    supervise("console-poller", console_poller)





    return socketio
