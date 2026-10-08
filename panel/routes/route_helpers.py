"""Small shared route helpers and the setup gate.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (current_app, flash, jsonify, redirect, render_template, request, url_for)
from flask_login import (current_user)
from panel.core.clock import (utcnow)
from panel.core.config import (encrypt_secret, load_config, remove_setup_token, save_config)
from panel.db.models import (Group, RemoteServer, SetupState, User, db)
from panel.ops import (system_ops as so, tailscale_integration as ts)
from panel.ops.ssh_manager import (ssh_test_connection)
from panel.security.auth import (hash_password, log_action)
import json
import os
import threading
from panel.core.validation import (MAX_PORT, MIN_PORT, MIN_UNPRIVILEGED_PORT,
    _port_or, bind_host_error, can_bind_address, password_problem, username_problem)
from panel.routes.remotes import (_add_remote_field_error, _add_remote_target_error)
from panel.ops.serve_upkeep import (_leftover_note, _remove_serve_leftovers)
from app import (_bind_is_loopback, _current_lang, _log, _serve_scheme_now, _setup_open,
    _setup_owner_ok, _setup_ts_ok, _superadmin_exists, claim_setup, is_setup_complete,
    issue_setup_owner_token)

# The wizard's steps in the order it walks them. A POST naming a step AHEAD of the stored one is
# refused (see _setup_post); an earlier one is a harmless Back-button resubmit.
_STEP_ORDER = ("welcome", "admin_user", "tailscale", "remote_server")

# Held from "is there a superadmin yet?" to the commit that creates one, so two admin_user POSTs
# cannot both pass the check. Green under eventlet's monkey_patch (app.py patches before any panel
# import), so a greenlet waiting on it parks rather than blocking the hub; the panel is one
# process. The password is hashed BEFORE it is taken — bcrypt is the slow part, and it yields.
_ADMIN_CREATE_LOCK = threading.Lock()


def wizard_credential(auth_method, raw):
    """The credential the setup wizard tests and stores.

    A key path is expanded. The form offers "~/.ssh/id_rsa" (the panel account's own key), and
    paramiko opens key_filename exactly as given, with no expanduser, so the literal tilde named a
    file that never exists: every key-auth attempt with the default failed, reported as "check the
    host, port, credentials", and the wizard refused to add the host.
    """
    cred = (raw or "").strip()
    if auth_method == "key" and cred.startswith("~"):
        cred = os.path.expanduser(cred)
    return cred


def register(app):
    _register_setup_wizard(app)
    _register_setup_tailscale(app)


def _register_setup_wizard(app):
    """The setup gate every request passes, and the wizard itself."""
    @app.before_request
    def check_setup():
        """Redirect to setup if not complete (except for setup pages and static).

        Until setup is finished there are no users, so every other page — including the login page
        and the dashboard root — funnels into the setup wizard.
        """
        # The wizard's own AJAX lives under /api/setup/* — it must NOT be redirected to
        # /setup or the JS gets an HTML redirect instead of JSON ("Could not check
        # Tailscale status"). Those endpoints self-guard with _setup_open() (403 once
        # setup is done), so exempting them here is safe.
        if request.path.startswith("/static/") or request.path == "/setup" \
                or request.path.startswith("/setup/") or request.path.startswith("/api/setup/") \
                or request.path in ("/robots.txt", "/healthz"):
            # /healthz is a liveness probe: it says whether the process and DB answer, which is as
            # true before setup as after, and a monitor should not read "302 to /setup" as health.
            return None          # exempt path: let the request through untouched
        if not is_setup_complete():
            # /login stays reachable once the wizard has an admin: the rest of the wizard is
            # bound to the browser that created it (_setup_owner_ok), and signing in as that
            # superadmin is how the operator gets back in from any other browser. Before an admin
            # exists there is no one to sign in as, so it funnels into the wizard as before.
            if request.path == "/login" \
                    and User.query.filter_by(is_superadmin=True).first() is not None:
                return None
            return redirect("/setup")
        # Setup IS complete and the path is not exempt: fall through to the request. Spelled out
        # rather than dropping off the end, because a before_request handler returning None means
        # "carry on" while returning a response means "stop here" — the difference is the whole
        # contract, and an implicit None leaves a reader checking whether it was intended.
        return None

    @app.route("/setup", methods=["GET", "POST"])
    def setup_wizard():
        # SECURITY: the setup wizard has NO authentication (it must be reachable on a
        # fresh install to create the first admin). Once setup is finished it is
        # PERMANENTLY LOCKED for both GET and POST. Previously only GET was blocked, so
        # an unauthenticated POST /setup with step=admin_user could create a brand-new
        # superadmin (or step=welcome could rewrite bind_host/port). Lock everything.
        # The LOCK checks the completed SetupState row alone — the same test is_setup_complete()
        # makes, so the wizard's show-condition and its lock can no longer disagree. config.json's
        # setup_complete is still written but neither of them reads it.
        #
        # is_setup_complete() used to be (DB row AND config flag), and the lock had to differ from
        # it: load_config() falls back to DEFAULT_CONFIG on any JSONDecodeError/OSError, and
        # DEFAULT_CONFIG has setup_complete=False. So a config.json that is deleted, or merely
        # hand-edited into invalid JSON, reopened this UNAUTHENTICATED wizard on a fully configured
        # install — where step=welcome rewrites bind_host/port (turning a loopback-only panel into
        # 0.0.0.0 on the next restart) and step=remote_server makes the panel SSH to an
        # attacker-supplied host. The admin_user step's own guard stopped account creation, but
        # nothing stopped the rest.
        #
        # Gating on "a superadmin exists" instead would break the wizard: it creates one at step 2
        # and then continues through tailscale/remote_server. state.complete is the one signal that
        # is false for the whole wizard and true only once it has finished.
        if SetupState.query.filter_by(complete=True).first() is not None:
            return redirect(url_for("login"))
        refused = _setup_gate()
        if refused is not None:
            return refused

        state = _setup_state()
        data = json.loads(state.data or "{}")
        cfg = load_config()

        if request.method == "POST":
            return _setup_post(state, data, cfg)

        # GET request - render the current step
        step_templates = {
            "welcome": "setup_welcome.html",
            "admin_user": "setup_admin.html",
            "tailscale": "setup_tailscale.html",
            "remote_server": "setup_remote.html",
            "complete": "setup_complete.html",
        }
        tmpl = step_templates.get(state.step, "setup_welcome.html")
        ts_info = ts.get_tailscale_info()
        # setup_mode surfaces the language picker in base.html (there's no sidebar/login
        # switcher during setup); the choice is kept in the session across steps.
        return render_template(tmpl, step=state.step, data=data, config=cfg, ts=ts_info,
                               setup_mode=True)

    @app.route("/setup/restart", methods=["POST"])
    def setup_restart():
        """The complete page's "Restart now": apply a bind the wizard stored for the next start.

        Only after the wizard has finished, only for the browser that ran it (or a signed-in
        superadmin), and only while the running bind is public and the stored one is loopback —
        otherwise there is nothing to apply and it restarts nothing. Never automatic: an operator
        on the public address, off the tailnet, would be cut off.
        """
        if _setup_open() or not _setup_owner_ok():
            return redirect(url_for("login"))
        cfg = load_config()
        if not _rebind_pending(cfg):
            flash("The panel already listens where its settings say — nothing to restart.", "info")
            return redirect(url_for("login"))
        # BEFORE the restart, as remote_security's binding change does: restart_panel arms a
        # detached two-second timer that stops the unit, and a row queued behind a SQLite lock for
        # longer than that (the busy timeout is 15 s) died with the process. It was written after.
        # The outcome is only known once restart_panel answers, so a failure is a row of its own.
        _setup_log("panel_restart", target=_SETUP_TARGET,
                   detail="requested, to listen on %s as the setup wizard stored"
                          % cfg.get("bind_host"))
        ok, msg = so.restart_panel()
        if not ok:
            _setup_log("panel_restart", target=_SETUP_TARGET, success=False,
                       detail="the restart could not be scheduled: %s" % msg)
        return _complete_page(cfg, restarting=True, restart_ok=ok)


# Who and what the setup wizard's audit rows name: no account need be signed in while it runs.
_SETUP_ACTOR = "setup wizard"
_SETUP_TARGET = "Panel Server"


def _setup_log(action, target, **kw):
    """Write one of the setup wizard's audit rows, as the signed-in account driving it if any.

    Once the first admin exists a signed-in superadmin may drive the wizard too (_setup_owner_ok),
    and every row said "setup wizard" with no account: a host added with root SSH, or a restart, was
    on record as nobody's. The browser that ran the wizard from the start is signed in as no one,
    so its rows still read "setup wizard".
    """
    user = current_user if getattr(current_user, "is_authenticated", False) else None
    log_action(user, action, target=target, actor=None if user else _SETUP_ACTOR, **kw)


def _register_setup_tailscale(app):
    """The wizard's Tailscale step: status, install, sign-in and Serve."""
    @app.route("/api/setup/tailscale/status")
    def api_setup_ts_status():
        if not _setup_ts_ok():
            return jsonify({"error": "forbidden"}), 403
        info = ts.get_tailscale_info(force_refresh=True)
        # "Serving" means the PANEL is published, at its own mount, on the scheme this process
        # serves. It was the first Serve service of any app, so a node where another app held "/"
        # read as done: the step hid its button and named the other app's address as the panel's.
        serve_url = _wizard_serve_url(info, load_config())
        return jsonify({
            "installed": info.installed, "running": info.running,
            "dns_name": info.dns_name, "ips": info.tailscale_ips,
            "serve_url": serve_url,
            "https_url": serve_url,
        })

    @app.route("/api/setup/tailscale/install", methods=["POST"])
    def api_setup_ts_install():
        if not _setup_ts_ok():
            return jsonify({"error": "forbidden"}), 403
        ok, log = ts.install_tailscale_local()
        # Audited like every other mutating endpoint. The rbac gate counted these three as audited
        # only because a helper they reach is named `_run`, the same name as two workers that do
        # log; nothing here ever wrote a row, for installing a package as root and joining a tailnet.
        _setup_log("setup_tailscale_install", target=_SETUP_TARGET, success=ok)
        return jsonify({"success": ok, "log": log})

    @app.route("/api/setup/tailscale/up", methods=["POST"])
    def api_setup_ts_up():
        if not _setup_ts_ok():
            return jsonify({"error": "forbidden"}), 403
        ok, res = ts.tailscale_up_local(enable_ssh=True)
        _setup_log("setup_tailscale_up", target=_SETUP_TARGET, success=ok)
        if not ok:
            return jsonify({"success": False, "message": res})
        if res == "ALREADY_CONNECTED":
            return jsonify({"success": True, "connected": True})
        return jsonify({"success": True, "connected": False, "auth_url": res})

    @app.route("/api/setup/tailscale/serve", methods=["POST"])
    def api_setup_ts_serve():
        if not _setup_ts_ok():
            return jsonify({"error": "forbidden"}), 403
        cfg = load_config()
        port = cfg.get("port", 5000)
        # Not the stored mount as it stands: on a node where another app holds "/", publishing
        # there REPLACES that app's route (the CLI overwrites a mount without asking). The same
        # rule as the finish and the Tailscale page's Enable form.
        mount, why = _wizard_serve_mount(cfg, port)
        if mount is None:
            _setup_log("setup_tailscale_serve", target=_SETUP_TARGET,
                       detail="port %s: %s" % (port, why), success=False)
            return jsonify({"success": False, "message": why})
        ok, msg = ts.setup_tailscale_serve(port=port, mount=mount, funnel=False,
                                           backend_scheme=_serve_scheme_now(cfg, current_app.config))
        _setup_log("setup_tailscale_serve", target=_SETUP_TARGET,
                   detail="port %s, mount %s" % (port, mount), success=ok)
        if not ok:
            return jsonify({"success": False, "message": msg})
        left = _remove_serve_leftovers(port, mount, "setup wizard", _wizard_audit)
        info = ts.get_tailscale_info(force_refresh=True)
        cfg["tailscale_setup_done"] = True
        cfg["tailscale_mount"] = mount
        cfg["bind_host"] = "127.0.0.1"   # Serve proxies to localhost; go tailnet-only
        if info.dns_name and not cfg.get("site_domain"):
            cfg["site_domain"] = info.dns_name
        save_config(cfg)
        return jsonify({"success": True, "message": msg + _leftover_note(left),
                        "url": _wizard_serve_url(info, cfg)})


def _setup_gate():
    """Who may drive the wizard now: None to go on, else the response that refuses the caller.

    Before the admin exists, only a browser that has shown the setup token — the printed link's
    ?token=, or the token page's field. The link's token is redirected out of the URL at once, so
    it does not stay in history, the address bar or a Referer. Once the admin exists, only its
    creator or a signed-in superadmin (_setup_owner_ok).
    """
    if not _superadmin_exists():
        offered = (request.args.get("token") if request.method == "GET"
                   else request.form.get("setup_token"))
        if offered is not None:
            if claim_setup(offered):
                return redirect("/setup")
            _log.warning("setup wizard: a wrong setup token was offered")
            return _setup_token_page(bad=True)
        if not _setup_owner_ok():
            # NOT the sign-in redirect below: before an admin exists check_setup sends /login
            # straight back to /setup, so that would loop forever.
            return _setup_token_page(bad=False)
        return None
    if not _setup_owner_ok():
        flash("Sign in as the administrator to finish setup.", "info")
        return redirect(url_for("login", next="/setup"))
    return None


def _setup_token_page(bad):
    """The page that asks for the setup token.

    200 when it is simply not given yet; 403 when a wrong one was, or a step was posted without it.
    """
    status = 403 if (bad or request.method == "POST") else 200
    return render_template("setup_token.html", setup_mode=True, bad=bad), status


def _step_index(step):
    return _STEP_ORDER.index(step) if step in _STEP_ORDER else 0


def _advance(state, step):
    """Move the wizard forward to `step`, never back.

    Re-posting an earlier step (Back, then submit) must not return an install that already has its
    admin to the admin page, whose POST then refuses — the owner would be stuck there.
    """
    if _step_index(step) > _step_index(state.step):
        state.step = step


def _setup_state():
    """The wizard's SetupState row, created at the welcome step when there is none yet."""
    state = SetupState.query.first()
    if not state:
        state = SetupState(step="welcome", data="{}")
        db.session.add(state)
        db.session.commit()
    return state


def _setup_post(state, data, cfg):
    """One wizard step's form, dispatched on the `step` it names — never one AHEAD of the stored step.

    It dispatched on the posted step alone, so nothing made a caller walk the wizard in order:
    step=remote_server action=add made the panel test an SSH connection to a host of the caller's
    choosing before any admin existed. The token gate is what keeps strangers out; this keeps the
    steps in order for everyone, so each step's own checks always ran first.
    """
    step = request.form.get("step", "welcome")
    if step not in _STEP_ORDER or _step_index(step) > _step_index(state.step):
        return redirect("/setup")

    if step == "welcome":
        return _setup_welcome(state, data, cfg)

    elif step == "admin_user":
        return _setup_admin_user(state, data)

    elif step == "tailscale":
        # The interactive install/connect/serve runs via /api/setup/tailscale/*;
        # this POST (Continue or Skip) just advances the wizard.
        _advance(state, "remote_server")
        state.data = json.dumps(data)
        db.session.commit()
        return redirect("/setup")

    elif step == "remote_server":
        return _setup_remote_server(state, data, cfg)

    return redirect("/setup")


def _setup_welcome(state, data, cfg):
    """Step 1: the site title, domain, port and bind address."""
    # Step 1: Site settings
    # The port is VALIDATED here, not merely parsed. This value is written straight to
    # config.json and read back by the entry point as the address to bind — so an
    # out-of-range one (a typo of 0, or 99999) produced a panel that would not start on
    # its next boot, recoverable only with linuxgsm-panel-recover or by hand-editing
    # the file. The comment that used to sit here said api_panel_change_port validated
    # it; that is a different route, and the wizard never calls it. Same bounds as that
    # route, so the panel's port means one thing wherever it is set.
    _wiz_port = _port_or(request.form.get("port"), None, lo=MIN_UNPRIVILEGED_PORT)
    if _wiz_port is None:
        flash("Pick a port between %d and %d." % (MIN_UNPRIVILEGED_PORT, MAX_PORT),
              "danger")
        return redirect("/setup")
    cfg["site_title"] = request.form.get("site_title", "LinuxGSM Panel")
    cfg["site_domain"] = request.form.get("site_domain", "")
    cfg["port"] = _wiz_port
    # The bind address is VALIDATED here for the same reason the port above it is,
    # and the comment that used to sit here made the same mistake the port's once
    # did: it said "api_panel_change_port validates whatever they choose". That is a
    # different route and the wizard never calls it, so this wrote whatever was
    # posted — and an address the host cannot bind produces a panel that does not come
    # back up, recoverable only with linuxgsm-panel-recover or by hand-editing
    # config.json. can_bind_address asks the kernel whether that address is really
    # on this host: a well-formed IP that is not (10.0.0.51 on 10.0.0.50) passed the
    # parse and failed with EADDRNOTAVAIL on the next start.
    #
    # nosec B104 - not a hardcoded bind: 0.0.0.0 is the DEFAULT offered when the
    # operator leaves the field blank, and it is what a panel reached over a tailnet
    # or a LAN has to listen on. The value is the operator's to set.
    _wiz_bind = (request.form.get("bind_host") or "0.0.0.0").strip()  # nosec B104
    _bind_err = bind_host_error(_wiz_bind, can_bind_address)
    if _bind_err:
        flash(_bind_err, "danger")
        return redirect("/setup")
    cfg["bind_host"] = _wiz_bind
    save_config(cfg)
    data["site_configured"] = True
    _advance(state, "admin_user")
    state.data = json.dumps(data)
    db.session.commit()
    _setup_log("setup_site_settings", target=_SETUP_TARGET,
               detail="bind %s, port %s" % (_wiz_bind, _wiz_port))
    return redirect("/setup")


def _setup_admin_user(state, data):
    """Step 2: create the first administrator."""
    # Defence in depth: the setup wizard only ever creates the FIRST admin.
    # If a superadmin already exists, refuse (belt-and-suspenders behind the
    # is_setup_complete lock above).
    if User.query.filter_by(is_superadmin=True).first():
        return redirect(url_for("login"))
    # Step 2: Create admin user
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    email = request.form.get("email", "").strip()

    # username_problem, not a length test: the first admin is created here and nowhere else, and
    # every other create/rename path refuses a tab or interior space (an account the login box
    # cannot reproduce), a control or bidi character, and a name longer than the column.
    if username_problem(username):
        flash(username_problem(username), "danger")
    elif password_problem(password):
        flash(password_problem(password), "danger")
    elif password != confirm:
        flash("Passwords do not match.", "danger")
    else:
        return _create_first_admin(state, data, username, password, email)
    return redirect("/setup")


def _create_first_admin(state, data, username, password, email):
    """Create the first superadmin, unless another request got there first.

    The superadmin-exists check above ran BEFORE hash_password, and under eventlet the hash parks
    this greenlet in tpool, so two concurrent POSTs both passed it and both made a superadmin
    (reproduced: ['attacker', 'operator'], one of them hidden). So: hash first, outside the lock,
    then re-check, insert and commit while holding it, with nothing in between that could hand the
    hub to a second request that has not seen this row.
    """
    password_hash = hash_password(password)
    with _ADMIN_CREATE_LOCK:
        if _superadmin_exists():
            return redirect(url_for("login"))
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect("/setup")
        admin = User(
            username=username,
            password_hash=password_hash,
            email=encrypt_secret(email) if email else None,
            display_name=username,
            is_superadmin=True,
            is_active=True,
            # Carry the language chosen during setup into the admin account, so
            # they land in it after logging in (falls back to en).
            language=_current_lang(),
        )
        db.session.add(admin)
        # Add to Everyone group
        everyone = Group.query.filter_by(name="Everyone").first()
        if everyone:
            admin.groups.append(everyone)
        data["admin_created"] = True
        issue_setup_owner_token(data)   # the rest of the wizard is this browser's
        _advance(state, "tailscale")
        state.data = json.dumps(data)
        db.session.commit()
    # Single-use: from here the wizard answers to this admin (the owner token, or signing in).
    remove_setup_token()
    _setup_log("add_user", target=username, detail="the first administrator, a superadmin")
    return redirect("/setup")


def _setup_remote_server(state, data, cfg):
    """Step 4: optionally add a first remote host, then (on skip or done) finish setup."""
    action = request.form.get("action", "skip")
    if action == "add":
        _setup_add_remote(state, data)

    if action == "skip" or request.form.get("done") == "1":
        return _finish_setup(state, data, cfg)

    state.data = json.dumps(data)
    db.session.commit()
    return redirect("/setup")


def _setup_add_remote(state, data):
    """Test and add the remote host the wizard's form names; the outcome is flashed."""
    name = request.form.get("name", "").strip()
    host = request.form.get("host", "").strip()
    ssh_user = request.form.get("ssh_user", "root").strip()
    ssh_port = _port_or(request.form.get("ssh_port"), None)
    auth_method = request.form.get("auth_method", "key")
    credential = wizard_credential(auth_method, request.form.get("credential", ""))
    sudo_enabled = request.form.get("sudo_enabled") == "on"
    lgsm_user = request.form.get("lgsm_user", "").strip()

    # The Hosts page's own add-form checks, before anything connects. The wizard stored
    # auth_method straight from the form, and "local" is what makes is_local_server() read a row as
    # the PANEL HOST — so a "remote" named anything, at any address, became a host the terminal and
    # every panel-host refusal treated as this machine. The field checks keep a name, user or host
    # out of the row (and out of the SSH test) that the Hosts page would refuse.
    refusal = (_add_remote_field_error(name, ssh_port, lgsm_user, ssh_user)
               or _add_remote_target_error(False, host, auth_method))
    if not name or not host:
        flash("Name and host are required.", "danger")
    elif ssh_port is None:
        flash("SSH port must be between %d and %d." % (MIN_PORT, MAX_PORT), "danger")
    elif refusal:
        flash(refusal, "danger")
    else:
        # Pinned with the row, from this login. The wizard makes no connection of its own after
        # this, so otherwise the first contact to pin from would be a background worker's.
        _seen_key = []
        success, msg = ssh_test_connection(host, ssh_port, ssh_user, auth_method, credential,
                                           captured=_seen_key)
        if not success:
            flash(f"Connection test failed: {msg}", "danger")
        else:
            remote = RemoteServer(
                name=name, host=host, port=ssh_port,
                username=ssh_user, auth_method=auth_method,
                auth_credential=encrypt_secret(credential),
                sudo_enabled=sudo_enabled,
                linuxgsm_user=lgsm_user,
                is_online=True,
                last_seen=utcnow(),
                host_key=_seen_key[0] if _seen_key else "",
            )
            db.session.add(remote)
            db.session.commit()
            _setup_log("add_remote", target=name, detail="%s@%s" % (ssh_user, host),
                       remote=remote)
            flash(f"Remote '{name}' added successfully!", "success")
            data["remote_added"] = True
            state.data = json.dumps(data)


def _finish_setup(state, data, cfg):
    """Close the wizard, once it has produced an admin, and set up Tailscale Serve if it can."""
    # Setup is not over until it has produced an ADMIN.
    #
    # This handler dispatches on the `step` field FROM THE FORM, so nothing makes
    # a caller walk the wizard in order — and the wizard is unauthenticated until
    # it completes, which is the whole point of a first-run flow. So on a freshly
    # installed panel anyone who could reach the port could POST
    # step=remote_server&action=skip and close setup with zero accounts.
    # Reproduced: SetupState.complete True, config setup_complete True,
    # superadmins 0, and every page then redirecting to a login nobody can pass.
    # Getting back in needs `manage.py create-admin` from a shell.
    #
    # The same request also ran the Tailscale auto-setup below, so an
    # unauthenticated POST reconfigured the host's serve settings.
    #
    # Counting ANY superadmin row rather than only active ones, deliberately: a
    # deactivated sole admin is a job for manage.py, and reopening the wizard for
    # an install that already has an owner would hand the next caller an account.
    # The panel refuses to leave zero superadmins through the UI, so zero here
    # means setup genuinely never finished.
    if User.query.filter_by(is_superadmin=True).first() is None:
        flash("Create the administrator account before finishing setup.", "danger")
        state.step = "admin_user"
        state.data = json.dumps(data)
        db.session.commit()
        return redirect("/setup")
    state.step = "complete"
    state.complete = True
    state.data = json.dumps(data)
    cfg["setup_complete"] = True
    save_config(cfg)  # Save FIRST, before Tailscale attempt
    # Auto-configure Tailscale Serve if available
    if cfg.get("tailscale_auto_setup", True):
        try:
            _auto_tailscale_serve(cfg)
        except Exception:
            _log.debug("setup_wizard: ignored non-fatal error", exc_info=True)
    db.session.commit()
    remove_setup_token()     # already gone with the admin step; this covers a token made since
    _setup_log("setup_finished", target=_SETUP_TARGET)
    # Rendered here rather than redirected to: the finished wizard is locked, so a GET of /setup
    # goes to /login, and this page — the one that says where the panel is reachable — was never
    # shown to anyone.
    return _complete_page(cfg)


def _rebind_pending(cfg):
    """Is the panel still listening on a PUBLIC bind while its settings say loopback?

    The Serve step stores bind_host 127.0.0.1, but the bind is read only when the process starts,
    so until the next restart the panel keeps answering on its public address — and from then on
    ONLY on the tailnet. False when the running bind is unknown (not started by app.py's main).
    """
    running = current_app.config.get("_BOOT_BIND")
    stored = (cfg.get("bind_host") or "").strip()
    return bool(running and stored) and _bind_is_loopback(stored) and not _bind_is_loopback(running)


def _complete_facts(cfg):
    """What the complete page may truthfully say about where the panel can be reached."""
    running = current_app.config.get("_BOOT_BIND")
    # "Only your devices can reach it" is true only while nothing but loopback is listening (Serve
    # is then the one way in) and Funnel is not publishing it to the internet.
    private = (bool(running) and _bind_is_loopback(running)
               and not cfg.get("tailscale_use_funnel") and not cfg.get("trust_proxy"))
    return {"rebind_pending": _rebind_pending(cfg), "running_bind": running or "",
            "panel_port": cfg.get("port", 5000), "tailnet_private": private}


def _complete_page(cfg, restarting=False, restart_ok=None):
    """The wizard's last page: done, where the panel answers, and (after Restart now) what next."""
    return render_template("setup_complete.html", setup_mode=True, restarting=restarting,
                           restart_ok=restart_ok, **_complete_facts(cfg))


def _wizard_audit(detail, ok):
    """One wizard audit row about a leftover Serve route (the shape _remove_serve_leftovers takes)."""
    _setup_log("tailscale_serve_leftover_removed", target=_SETUP_TARGET, detail=detail, success=ok)


def _wizard_serve_url(info, cfg):
    """The panel's own Serve address (ts.route_url), or None when no route at its mount works now."""
    route = ts.panel_route(info.serve_config, cfg.get("port", 5000), cfg.get("tailscale_mount"),
                           _serve_scheme_now(cfg, current_app.config))
    return ts.route_url(route) if route is not None else None


def _wizard_serve_mount(cfg, port):
    """(mount, None) for the wizard to publish the panel at, or (None, why) to publish nothing.

    ts.free_panel_mount on a FRESH read: the stored mount unless another app holds it on :443,
    then /lgsm. A Serve config that cannot be read is not an empty one: it cannot say whether "/"
    is another app's, and the CLI replaces a mount without asking. Until the panel's account is the
    Tailscale operator, an unreadable config is what `serve status` answers, so the operator is set
    (as setup_tailscale_serve would) and the config read once more before giving up.
    """
    info = ts.get_tailscale_info(force_refresh=True)
    if info.serve_unreadable:
        ts.ensure_operator()
        info = ts.get_tailscale_info(force_refresh=True)
    if info.serve_unreadable:
        return None, ("Couldn't read this host's Tailscale Serve configuration, so the panel can't "
                      "tell whether another app is published where it would go. Nothing was "
                      "changed; set Serve up on the Tailscale page once it can be read.")
    mount = ts.free_panel_mount(info.serve_config, port, cfg.get("tailscale_mount") or "/")
    if mount is None:
        return None, ("Other apps hold both / and /lgsm on this host's Tailscale Serve, so the "
                      "panel was not published. Choose a mount on the Tailscale page.")
    return mount, None


def _auto_tailscale_serve(cfg):
    """Point Tailscale Serve at the panel when this host is on a tailnet; the caller treats a failure as non-fatal.

    Nothing when the wizard's own Serve step has already published it: that route is on the scheme
    this process serves, and the boot re-point moves it to the next one after the restart. Running
    anyway is how a setup ended with the panel at "/" AND /lgsm: the "/" the step had just written
    was read as another app's ("root taken" never asked whose), so the finish published a second
    route at /lgsm, on the scheme the NEXT start would serve, in front of this one — a 502 until
    the restart, and the "/" route a 502 from the restart on.
    """
    if cfg.get("tailscale_setup_done"):
        return
    ts_info = ts.get_tailscale_info()
    if ts_info.running and ts_info.dns_name:
        port = cfg.get("port", 5000)
        mount, why = _wizard_serve_mount(cfg, port)
        if mount is None:
            _record_auto_serve(cfg, cfg.get("tailscale_mount") or "/", False, why)
            return
        ok, msg = ts.setup_tailscale_serve(
            port=port,
            mount=mount,
            funnel=cfg.get("tailscale_use_funnel", False),
            backend_scheme=_serve_scheme_now(cfg, current_app.config),
        )
        _record_auto_serve(cfg, mount, ok, msg)
        if ok:
            _remove_serve_leftovers(port, mount, "at the end of setup", _wizard_audit)


def _record_auto_serve(cfg, mount, ok, msg):
    """Audit the end-of-setup Serve, and store it as set up only when it took.

    The result was dropped, and tailscale_setup_done is what tells the firewall page the panel is
    reachable over the tailnet, so a Serve that failed left the public web port's rule unprotected.
    """
    _setup_log("setup_tailscale_serve", target=_SETUP_TARGET, success=ok,
               detail="at the end of setup: port %s, mount %s: %s"
                      % (cfg.get("port", 5000), mount, msg))
    if ok:
        cfg["tailscale_mount"] = mount
        cfg["tailscale_setup_done"] = True
        save_config(cfg)
