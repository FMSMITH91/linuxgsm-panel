"""Adding, editing and removing the hosts the panel manages.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (flash, jsonify, redirect, render_template, request, url_for)
from flask_login import (current_user, login_required)
from panel.core.clock import (utcnow)
from panel.core.config import (decrypt_secret, encrypt_secret, update_config)
from panel.db.models import (GameServer, RemoteServer, db)
from panel.ops import (tailscale_integration as ts)
from panel.ops.ssh_manager import (close_connection, ssh_test_connection)
from panel.security.auth import (MANAGE_REMOTES, accessible_remote_ids, check_password,
    get_remote, log_action, permission_required)
from panel.core.http import (_form_err, _form_ok, _json_body, _wants_json)
from panel.core.validation import (HOST_RE, LINUX_USER_RE, MAX_PORT, MIN_PORT, SAFE_LABEL_RE,
    _port_or)
from panel.core.panel_state import (_install_jobs, _install_lock)
from panel.routes._shared import (_begin_bootstrap, _bootstrap_jobs, _bootstrap_lock)
import logging

_log = logging.getLogger("panel.routes.remotes")


def _forget_deleted_remote_state(remote_id, game_server_ids):
    """Drop the in-memory job entries for a host and the game servers that went with it.

    The panel_state registry already covers these — but it is swept by the monitor, so it clears
    them on the NEXT pass rather than now. Demonstrated end to end: delete a host whose server had
    a failed install, add a new server that takes the freed row id, and /install-status answers
    with the DELETED server's failure ("SteamCMD could not log in") until the sweep catches up.

    An after_delete listener is not an option here and that is worth writing down: delete_remote
    removes this host's game servers with a BULK query, which bypasses the ORM entirely, so no
    per-row event ever fires for them. That is the same reason _forget_deleted_rows is driven off
    the live id sets instead of the delete routes. So the route clears what it knows it just
    deleted, and the sweep stays the backstop for everything that does not come through here.
    """
    with _install_lock:
        for gid in game_server_ids:
            _install_jobs.pop(gid, None)
    with _bootstrap_lock:
        _bootstrap_jobs.pop(remote_id, None)


def _forget_deleted_remote_config(remote_id, game_server_ids):
    """Drop everything a deleted host left in config.json — its auto-block opt-in, and a backup
    schedule for each game server that went with it.

    These are the PERSISTED half of the same problem panel_state solves for in-memory maps: a
    deleted row's id is handed straight to the next INSERT, and unlike a cache these survive a
    restart. uninstall_server already calls remove_game_schedule for exactly this reason ("can't
    be inherited if SQLite later reuses the row id") — but deleting a HOST bulk-deletes its game
    servers without that route ever running, so their schedules were left behind.

    `autoblock_hosts` is the one that matters most. It is a list of remote ids, and the hourly
    sweep looks each one up: once the id is live again it resolves to the NEW host and starts
    adding `ufw deny` rules to a machine whose operator never turned auto-blocking on.

    Best-effort and never fatal: the rows are already gone, and a config write that fails must not
    turn a completed delete into an error.
    """
    try:
        def _mut(cfg):
            hosts = [h for h in (cfg.get("autoblock_hosts") or []) if h != remote_id]
            if hosts != (cfg.get("autoblock_hosts") or []):
                cfg["autoblock_hosts"] = hosts
            sched = cfg.get("game_schedules")
            if isinstance(sched, dict):
                for gid in game_server_ids:
                    sched.pop(str(gid), None)
        update_config(_mut)
    except Exception:
        _log.debug("could not clear config state for deleted remote %s", remote_id, exc_info=True)


def register(app):
    @app.route("/remotes")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def manage_remotes():
        # Only actual remote VPSes — the panel's own host is managed under
        # System → Panel Server, not here. Non-superadmins only see remotes their
        # groups grant (consistent with the per-host access enforced in get_remote).
        remotes = RemoteServer.query.filter_by(is_local=False).order_by(RemoteServer.name).all()
        if not current_user.is_superadmin:
            allowed = accessible_remote_ids(current_user)
            remotes = [r for r in remotes if r.id in allowed]
        return render_template("manage_remotes.html", remotes=remotes,
                               tailscale_installed=ts.get_tailscale_info().installed)

    @app.route("/remotes/add", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def add_remote():
        name = request.form.get("name", "").strip()
        host = request.form.get("host", "").strip()
        ssh_user = request.form.get("ssh_user", "root").strip()
        ssh_port = _port_or(request.form.get("ssh_port"), None)
        auth_method = request.form.get("auth_method", "key")
        credential = request.form.get("credential", "").strip()
        sudo_enabled = request.form.get("sudo_enabled") == "on"
        lgsm_user = request.form.get("lgsm_user", "").strip()
        is_local = request.form.get("is_local") == "1"

        if not name or not SAFE_LABEL_RE.match(name):
            return _form_err("Name is required and cannot contain < > \" ' ` or backslashes.", "manage_remotes")
        if ssh_port is None:
            return _form_err("SSH port must be a number between %d and %d." % (MIN_PORT, MAX_PORT),
                             "manage_remotes")

        # SECURITY: these reach `sudo -u <user>` / SSH command construction — validate
        # to a safe Linux-username charset so they can't inject shell commands.
        if lgsm_user and not LINUX_USER_RE.match(lgsm_user):
            return _form_err("LinuxGSM user must be a valid Linux username (lowercase letters, numbers, - or _).",
                             "manage_remotes")
        if ssh_user and not LINUX_USER_RE.match(ssh_user):
            return _form_err("SSH user must be a valid Linux username.", "manage_remotes")
        if not is_local and (not host or not HOST_RE.match(host)):
            return _form_err("Host must be a valid hostname or IP address.", "manage_remotes")

        if is_local:
            remote = RemoteServer(
                name=name, host="127.0.0.1", port=22,
                username="local", auth_method="local",
                auth_credential="", sudo_enabled=True,
                linuxgsm_user=lgsm_user,
                is_local=True, is_online=True,
                last_seen=utcnow(),
            )
            db.session.add(remote)
            db.session.commit()
            log_action(current_user, "add_local_remote", target=name)
            return _form_ok(f"Local server '{name}' added! You can now install game servers on this machine.",
                            "manage_remotes")

        # (host presence + charset already validated above for non-local remotes)
        success, msg = ssh_test_connection(host, ssh_port, ssh_user, auth_method, credential)
        if not success:
            return _form_err(f"Connection test failed: {msg}", "manage_remotes")

        remote = RemoteServer(
            name=name, host=host, port=ssh_port,
            username=ssh_user, auth_method=auth_method,
            auth_credential=encrypt_secret(credential),
            sudo_enabled=sudo_enabled, linuxgsm_user=lgsm_user,
            is_online=True, last_seen=utcnow(),
        )
        db.session.add(remote)
        db.session.commit()
        log_action(current_user, "add_remote", target=name, detail=f"{ssh_user}@{host}")

        # Setup type. "fresh" runs the full Prepare & Secure bootstrap (updates, UFW, SSH hardening,
        # fail2ban, deps, then reboot) for a brand-new VPS. "existing" leaves the host untouched and
        # jumps straight to scanning it for LinuxGSM servers already installed. (The old auto_bootstrap
        # checkbox is honoured as a fallback so older/cached forms still work.)
        setup_type = request.form.get("setup_type", "").strip().lower()
        if setup_type not in ("fresh", "existing"):
            setup_type = "fresh" if request.form.get("auto_bootstrap", "on") == "on" else "existing"
        if setup_type == "existing":
            flash(f"Remote '{name}' added — scanning it for existing LinuxGSM servers…", "success")
            return redirect(url_for("remote_manage", remote_id=remote.id) + "?scan=1")

        opts = {
            "set_timezone": request.form.get("timezone", "UTC") or "UTC",
            "enable_ufw": True, "install_lgsm_deps": True,
            "username": lgsm_user, "install_fail2ban": True, "do_reboot": True,
        }
        started, _ = _begin_bootstrap(app, remote.id, opts, current_user.id)
        _m = (f"Remote '{name}' added. Preparing & securing it now — watch the progress on its card."
              if started else f"Remote '{name}' added.")
        return _form_ok(_m, "manage_remotes")

    @app.route("/remotes/<int:remote_id>/edit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def edit_remote(remote_id):
        remote = get_remote(remote_id)
        new_user = request.form.get("ssh_user", remote.username)
        # SECURITY: validate the username field (it reaches `sudo -u <user>` / SSH commands).
        if new_user and not LINUX_USER_RE.match(new_user):
            return _form_err("SSH user must be a valid Linux username.", "manage_remotes")
        new_name = request.form.get("name", remote.name)
        if new_name and not SAFE_LABEL_RE.match(new_name):
            return _form_err("Name cannot contain < > \" ' ` or backslashes.", "manage_remotes")
        remote.name = new_name
        new_host = request.form.get("host", remote.host)
        if not remote.is_local and new_host and not HOST_RE.match(new_host):
            return _form_err("Host must be a valid hostname or IP address.", "manage_remotes")
        new_port = _port_or(request.form.get("ssh_port"), None)
        if new_port is None:
            return _form_err("SSH port must be a number between %d and %d." % (MIN_PORT, MAX_PORT),
                             "manage_remotes")
        # Repointing to a different host/port means the pinned key no longer applies —
        # clear it so the new target is re-pinned (TOFU) instead of failing as a mismatch.
        if (new_host, new_port) != (remote.host, remote.port):
            remote.host_key = ""
        remote.host = new_host
        remote.port = new_port
        remote.username = new_user
        remote.auth_method = request.form.get("auth_method", remote.auth_method)
        # Credential: the edit form leaves it blank to keep the current one; a new
        # value is (re)encrypted before storage.
        new_cred = request.form.get("credential", "").strip()
        if new_cred:
            remote.auth_credential = encrypt_secret(new_cred)
        remote.sudo_enabled = request.form.get("sudo_enabled") == "on"
        db.session.commit()
        log_action(current_user, "edit_remote", target=remote.name)
        return _form_ok(f"Remote '{remote.name}' updated.", "manage_remotes")

    @app.route("/remotes/<int:remote_id>/delete", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def delete_remote(remote_id):
        remote = get_remote(remote_id)
        name = remote.name
        # The id off the ROW, not off the URL — the same number either way, but only one of them
        # is request text. api_server_version already does this and says why: `<int:remote_id>`
        # makes a CR/LF impossible, so nothing can really be injected, but CodeQL's
        # py/log-injection does not model Werkzeug's converters and the cleanup helper below logs
        # this value. Breaking the flow beats dismissing the alert — a gate that cries wolf is how
        # a real alert gets waved through.
        row_id = remote.id
        # Re-authenticate: deleting a remote (and ALL its game servers) is destructive, so require
        # the operator to re-enter their own account password — a guard against an accidental or
        # hijacked click. Verified constant-time via bcrypt (check_password).
        if not check_password(_json_body().get("password", ""), current_user.password_hash):
            if _wants_json():
                return jsonify({"success": False, "message": "Incorrect password."}), 403
            flash("Incorrect password.", "danger")
            return redirect(url_for("manage_remotes"))
        # Delete associated game servers. This is a BULK delete, which bypasses the ORM entirely —
        # so every association row keyed on those game_server ids has to go by hand. This app never
        # sets PRAGMA foreign_keys, so nothing removes them for us, and SQLite reuses rowids: an
        # orphan here is later inherited by a completely unrelated server.
        _doomed_ids = [gid for (gid,) in db.session.query(GameServer.id)
                       .filter_by(remote_id=remote_id).all()]
        GameServer.query.filter_by(remote_id=remote_id).delete()
        if _doomed_ids:
            from panel.db.models import game_server_tags
            db.session.execute(game_server_tags.delete()
                               .where(game_server_tags.c.game_server_id.in_(_doomed_ids)))
            # Same shape of orphan, pre-existing: per-server group grants are keyed the same way.
            _ggs = db.Table("group_game_servers", db.metadata, autoload_with=db.engine)
            db.session.execute(_ggs.delete().where(_ggs.c.game_server_id.in_(_doomed_ids)))
            # ...and their metric history, for the same reason and here rather than in models.py.
            # _prune_host_game_samples listens on RemoteServer's after_delete and finds the rows to
            # delete with `server_id IN (SELECT id FROM game_server WHERE remote_id = ...)` — but
            # the bulk delete above has already removed those game_server rows, so by the time it
            # fires the subquery matches nothing and it deletes nothing. The listener was written
            # BECAUSE the bulk delete bypasses the per-server one; it just could not see past it.
            # Reproduced in a throwaway SQLite DB: the samples survive, both rowids are recycled,
            # and the next server created serves the deleted one's CPU/RAM/player history on
            # /api/server/<id>/history for the whole 14-day prune window.
            from panel.db.models import MetricSample
            db.session.execute(MetricSample.__table__.delete()
                               .where(MetricSample.server_id.in_(_doomed_ids)))
        # Delete group associations
        group_servers_table = db.Table(
            "group_servers", db.metadata, autoload_with=db.engine
        )
        db.session.execute(
            group_servers_table.delete().where(
                group_servers_table.c.server_id == remote_id
            )
        )
        db.session.delete(remote)
        db.session.commit()
        close_connection(remote)
        _forget_deleted_remote_config(row_id, _doomed_ids)
        _forget_deleted_remote_state(row_id, _doomed_ids)
        log_action(current_user, "delete_remote", target=name)
        _m = f"Remote '{name}' deleted."
        if _wants_json():
            return jsonify({"success": True, "message": _m})
        flash(_m, "success")
        return redirect(url_for("manage_remotes"))

    @app.route("/remotes/<int:remote_id>/test", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def test_remote(remote_id):
        remote = get_remote(remote_id)
        success, msg = ssh_test_connection(
            remote.host, remote.port, remote.username,
            remote.auth_method, decrypt_secret(remote.auth_credential)
        )
        remote.is_online = bool(success)
        remote.last_seen = utcnow()
        db.session.commit()
        if success:
            return _form_ok(f"Connection to {remote.name} successful!", "manage_remotes")
        return _form_err(f"Connection failed: {msg}", "manage_remotes")
