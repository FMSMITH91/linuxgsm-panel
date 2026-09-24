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
from panel.security.auth import (MANAGE_REMOTES, accessible_remote_ids, can_access_remote,
    check_password, get_remote, log_action, permission_required)
from panel.core.http import (_form_err, _form_ok, _json_body, _wants_json)
from panel.core.validation import (EDITABLE_AUTH_METHODS, HOST_RE, LINUX_USER_RE, MAX_PORT,
    MIN_PORT, SAFE_LABEL_RE, _port_or)
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


def _forget_deleted_from_ui_prefs(remote_id, game_server_ids):
    """Drop a deleted host/server from every user's saved layout.

    ui_prefs stores host_order (a list of remote ids) and server_order ({remote_id: [server id]}),
    and nothing cleared them — so after SQLite recycles the rowid a brand-new host or server
    silently inherited the deleted one's saved position in every user's dashboard, for every user
    who had ever reordered. _apply_user_order degrades gracefully, so the effect is ordering only;
    it is the same class as the other three things cleared beside it here and it belongs with them.
    """
    from panel.db.models import User
    gone = set(game_server_ids or ())
    try:
        for u in User.query.all():
            prefs = u.get_ui_prefs() or {}
            hosts = [h for h in (prefs.get("host_order") or []) if h != remote_id]
            servers = {k: [s for s in v if s not in gone]
                       for k, v in (prefs.get("server_order") or {}).items()
                       if str(k) != str(remote_id)}
            if hosts != (prefs.get("host_order") or []):
                u.set_ui_pref("host_order", hosts)
            if servers != (prefs.get("server_order") or {}):
                u.set_ui_pref("server_order", servers)
        db.session.commit()
    except Exception:
        db.session.rollback()
        _log.debug("could not clear ui_prefs for deleted remote %s", remote_id, exc_info=True)


# The ways of signing in to a host that prove the REQUESTER controls it. Only a password does:
# ssh_test_connection and _core.get_connection offer it with allow_agent=False and
# look_for_keys=False, so a login that succeeds used the requester's credential and nothing else.
# "key" is not key material — the credential field is a PATH ON THE PANEL HOST, a blank one falls
# back to the panel user's ~/.ssh/id_rsa (hosts.ssh_test_connection, _core.get_connection), and
# paramiko's defaults then try the agent and every ~/.ssh/id_* as well, so even a bogus path signs
# in with whatever the panel holds. "tailscale" is the panel node's own tailnet identity. A login
# that succeeds with either proves the PANEL can reach the host, not that the person asking may.
_REQUESTER_HELD_AUTH = frozenset({"password"})


def _delegated_add_refusal(is_local, auth_method):
    """Why the signed-in user may not add this host, or None when they may.

    add_remote grants a new host to the creator's MANAGE_REMOTES groups (see below), and it
    decides that the host is theirs to have by logging in to it. That was sound only for a
    credential the creator supplied. With the panel's own key or tailnet identity, a delegated
    admin could name ANY address the superadmin manages that way — leaving the form's
    pre-filled ~/.ssh/id_rsa in place — pass the test on the panel's credentials, and be granted
    root-level MANAGE_REMOTES (firewall, reboot, OS updates, a bootstrap that rewrites sshd and
    reboots) on a host nobody gave them.

    The panel's own host is superadmin-only on every other path that creates or manages it
    (host_local.server_management); from here a delegated admin got a row outside all of their
    groups and a message promising they could install on it."""
    if current_user.is_superadmin:
        return None
    if is_local:
        return ("Only a superadmin can register the panel's own machine as a host.")
    if auth_method not in _REQUESTER_HELD_AUTH:
        return ("Only a superadmin can add a host that signs in with the panel's own SSH key or "
                "Tailscale identity — a successful login with those proves the panel can reach "
                "the host, not that you can. Use password authentication with the host's own "
                "credentials, or ask a superadmin to add it.")
    return None


def _delegated_retarget_refusal(remote, new_host, new_port, new_user, new_auth, new_cred):
    """Why the signed-in user may not repoint `remote` this way, or None when they may.

    get_remote() scopes a delegated admin to the ROW, but the row's credential can be the
    panel's own (see _REQUESTER_HELD_AUTH). So editing the address of a host they were granted
    moved that grant, and the panel's key or tailnet identity with it, onto any machine they
    typed in — the next command for "their" host ran as root on one they were never given.
    Changing the SSH user on the panel's key is the same move on the same machine: from a
    limited account to whichever one the key also opens.

    So for anyone but a superadmin, a change to where or as whom the panel signs in has to come
    with a credential they supply in the same request: password authentication, and a new
    password. A new key PATH is the same move without touching the address — it picks which of
    the panel's own keys signs in — so it needs the same. Everything else on the form — the name,
    sudo, rotating the password in place — is unaffected. The panel's own row never leaves the
    local transport whatever its host says (is_local_server), so it is not a retarget."""
    if current_user.is_superadmin or remote.is_local:
        return None
    moved = (new_host, new_port, new_user, new_auth) != (remote.host, remote.port,
                                                         remote.username, remote.auth_method)
    new_key_path = bool(new_cred) and new_auth not in _REQUESTER_HELD_AUTH
    if not moved and not new_key_path:
        return None
    if new_auth in _REQUESTER_HELD_AUTH and new_cred:
        return None
    return ("Only a superadmin can change a host's address, SSH port, SSH user, sign-in method "
            "or key without a new password. Choose password authentication and enter the host's "
            "password to repoint it yourself, or ask a superadmin.")


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
        # The same allowlist edit_remote uses, and for the same reason: `auth_method` picks the
        # TRANSPORT, and "local" means "this record is the panel host" to is_local_server(). The
        # is_local branch below sets that itself, from a deliberate checkbox; reaching it through
        # the credential dropdown instead would store a host that is remote by every other field
        # and local by the only one that decides where commands run. Only checked off the
        # non-local path — the branch below hardcodes auth_method="local" on purpose.
        if not is_local and auth_method not in EDITABLE_AUTH_METHODS:
            return _form_err("Unknown authentication method.", "manage_remotes")
        _refused = _delegated_add_refusal(is_local, auth_method)
        if _refused:
            return _form_err(_refused, "manage_remotes", code=403)

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

        # ── the creator has to be able to reach what they just created ──────────────────────
        # Per-host access is purely group-derived — can_access_remote / accessible_remote_ids walk
        # group.servers — and nothing attached the new row to any group. So for a non-superadmin
        # the host was invisible and untouchable from the moment it committed: no card on
        # /remotes, and get_remote() -> 403 from its manage page, its edit and its delete. Mean-
        # while the panel held the host's SSH credential, the monitor sweep polled it, and on the
        # "fresh" path a root bootstrap that apt full-upgrades, rewrites sshd_config and reboots
        # the machine was already running, with no way for the person who started it to watch or
        # stop it. Both exits below also stated something false about that: a card that will never
        # appear, and a redirect to a page that answers 403.
        #
        # Granted to the creator's groups that carry MANAGE_REMOTES, not to every group they are
        # in: those are the groups whose members are already allowed to add and manage hosts, so
        # this widens nothing that was not already theirs to widen — the same "a new grant must
        # not exceed its creator's reach" rule add_group applies through grantable_object_ids.
        # The route's own decorator guarantees a non-superadmin has at least one such group.
        if not current_user.is_superadmin:
            for _g in (current_user.groups or []):
                if _g.has_permission(MANAGE_REMOTES) and remote not in (_g.servers or []):
                    _g.servers.append(remote)
            db.session.commit()
        # Belt and braces: if nothing granted it after all, say so rather than sending them to a
        # page that 403s and promising a card they cannot see.
        reachable = can_access_remote(current_user, remote.id)

        # Setup type. "fresh" runs the full Prepare & Secure bootstrap (updates, UFW, SSH hardening,
        # fail2ban, deps, then reboot) for a brand-new VPS. "existing" leaves the host untouched and
        # jumps straight to scanning it for LinuxGSM servers already installed. (The old auto_bootstrap
        # checkbox is honoured as a fallback so older/cached forms still work.)
        setup_type = request.form.get("setup_type", "").strip().lower()
        if setup_type not in ("fresh", "existing"):
            setup_type = "fresh" if request.form.get("auto_bootstrap", "on") == "on" else "existing"
        if setup_type == "existing":
            if not reachable:
                return _form_ok(f"Remote '{name}' added, but your groups don't grant access to it "
                                "— an administrator has to grant it before you can manage or scan "
                                "it.", "manage_remotes")
            flash(f"Remote '{name}' added — scanning it for existing LinuxGSM servers…", "success")
            return redirect(url_for("remote_manage", remote_id=remote.id) + "?scan=1")

        opts = {
            "set_timezone": request.form.get("timezone", "UTC") or "UTC",
            "enable_ufw": True, "install_lgsm_deps": True,
            "username": lgsm_user, "install_fail2ban": True, "do_reboot": True,
        }
        started, _ = _begin_bootstrap(app, remote.id, opts, current_user.id)
        # "watch the progress on its card" is a statement about a card. Only say it to someone who
        # will be shown one — /remotes filters to accessible_remote_ids, and the bootstrap-status
        # endpoint behind the card answers 403 to anyone else.
        if started and reachable:
            _m = f"Remote '{name}' added. Preparing & securing it now — watch the progress on its card."
        elif started:
            _m = (f"Remote '{name}' added and is being prepared & secured now, but your groups "
                  "don't grant access to it — an administrator has to grant it before you can "
                  "see or manage the host.")
        else:
            _m = f"Remote '{name}' added."
        return _form_ok(_m, "manage_remotes")

    @app.route("/remotes/<int:remote_id>/edit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def edit_remote(remote_id):
        remote = get_remote(remote_id)
        # A BLANK field is not an edit. `.get(key, default)` only falls back when the key is
        # ABSENT, and the edit form posts all three of these every time — without `required`,
        # unlike the add form above it (templates/manage_remotes.html:25/29 have it, :193/:197 do
        # not). So clearing the box and saving used to store "" over the real name, host or SSH
        # user, and the guards below are all `if new_x and …`, which an empty string skips. A
        # remote with host "" is unreachable and its game servers unmanageable.
        new_user = (request.form.get("ssh_user") or "").strip() or remote.username
        # SECURITY: validate the username field (it reaches `sudo -u <user>` / SSH commands).
        if not LINUX_USER_RE.match(new_user):
            return _form_err("SSH user must be a valid Linux username.", "manage_remotes")
        new_name = (request.form.get("name") or "").strip() or remote.name
        if not SAFE_LABEL_RE.match(new_name):
            return _form_err("Name cannot contain < > \" ' ` or backslashes.", "manage_remotes")
        remote.name = new_name
        new_host = (request.form.get("host") or "").strip() or remote.host
        if not remote.is_local and not HOST_RE.match(new_host):
            return _form_err("Host must be a valid hostname or IP address.", "manage_remotes")
        new_port = _port_or(request.form.get("ssh_port"), None)
        if new_port is None:
            return _form_err("SSH port must be a number between %d and %d." % (MIN_PORT, MAX_PORT),
                             "manage_remotes")
        # Before anything on the row changes: a delegated admin may not move where, or as whom,
        # the panel signs in on its own credentials. See _delegated_retarget_refusal.
        _refused = _delegated_retarget_refusal(
            remote, new_host, new_port, new_user,
            (request.form.get("auth_method") or "").strip() or remote.auth_method,
            request.form.get("credential", "").strip())
        if _refused:
            return _form_err(_refused, "manage_remotes", code=403)
        # Repointing to a different host/port means the pinned key no longer applies —
        # clear it so the new target is re-pinned (TOFU) instead of failing as a mismatch.
        if (new_host, new_port) != (remote.host, remote.port):
            remote.host_key = ""
        remote.host = new_host
        remote.port = new_port
        remote.username = new_user
        # SECURITY: the one field on this form that was taken raw, while the four above it were
        # each validated. `auth_method` is not a label — it SELECTS THE TRANSPORT, and
        # `_core.is_local_server()` returns True for `auth_method == "local"` (panel/ops/
        # ssh_manager/_core.py:423-424, `or getattr(server, "auth_method", None) == "local"`).
        # So posting auth_method=local for an ordinary remote moved every command the panel runs
        # "on that host" — console input, file writes, privileged verbs, firewall changes — onto
        # the PANEL HOST instead, the machine holding the database, the credential key and the
        # panel's own sudoers grant. The form never offers it: the select at
        # templates/manage_remotes.html:210-212 lists exactly key/password/tailscale, so any other
        # value arrived from a forged request. An unknown value was no better — it falls through
        # `enforce_pin = auth_method not in ("tailscale", "local")` (_core.py:569) into the key
        # path with a method nothing recognises.
        new_auth = (request.form.get("auth_method") or "").strip() or remote.auth_method
        if remote.is_local:
            # The panel's own row is created by host_local.py with auth_method="local" and is not
            # repointable from this form; keep whatever it has.
            new_auth = remote.auth_method
        elif new_auth not in EDITABLE_AUTH_METHODS:
            return _form_err("Unknown authentication method.", "manage_remotes")
        remote.auth_method = new_auth
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
        _forget_deleted_from_ui_prefs(row_id, _doomed_ids)
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
            remote.auth_method, decrypt_secret(remote.auth_credential),
            host_key=remote.host_key or "",
        )
        remote.is_online = bool(success)
        remote.last_seen = utcnow()
        db.session.commit()
        if success:
            return _form_ok(f"Connection to {remote.name} successful!", "manage_remotes")
        return _form_err(f"Connection failed: {msg}", "manage_remotes")
