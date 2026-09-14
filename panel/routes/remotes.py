"""Adding, editing and removing the hosts the panel manages.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (flash, jsonify, redirect, render_template, request, url_for)
from flask_login import (current_user, login_required)
from panel.core.clock import (utcnow)
from panel.core.config import (decrypt_secret, encrypt_secret)
from panel.db.models import (GameServer, RemoteServer, db)
from panel.ops import (tailscale_integration as ts)
from panel.ops.ssh_manager import (close_connection, ssh_test_connection)
from panel.security.auth import (MANAGE_REMOTES, accessible_remote_ids, check_password,
    get_remote, log_action, permission_required)
from panel.core.http import (_form_err, _form_ok, _json_body, _wants_json)
from panel.core.validation import (HOST_RE, LINUX_USER_RE, MAX_PORT, MIN_PORT, SAFE_LABEL_RE,
    _port_or)
from panel.routes._shared import (_begin_bootstrap)


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
        new_lgsm = request.form.get("lgsm_user", remote.linuxgsm_user)
        # SECURITY: validate the username fields (reach `sudo -u <user>` / SSH commands).
        if new_user and not LINUX_USER_RE.match(new_user):
            return _form_err("SSH user must be a valid Linux username.", "manage_remotes")
        if new_lgsm and not LINUX_USER_RE.match(new_lgsm):
            return _form_err("LinuxGSM user must be a valid Linux username.", "manage_remotes")
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
        remote.linuxgsm_user = new_lgsm
        db.session.commit()
        log_action(current_user, "edit_remote", target=remote.name)
        return _form_ok(f"Remote '{remote.name}' updated.", "manage_remotes")

    @app.route("/remotes/<int:remote_id>/delete", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def delete_remote(remote_id):
        remote = get_remote(remote_id)
        name = remote.name
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
