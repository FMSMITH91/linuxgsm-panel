"""Small shared route helpers and the setup gate.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (flash, jsonify, redirect, render_template, request, url_for)
from panel.core.clock import (utcnow)
from panel.core.config import (encrypt_secret, load_config, save_config)
from panel.db.models import (Group, RemoteServer, SetupState, User, db)
from panel.ops import (tailscale_integration as ts)
from panel.ops.ssh_manager import (ssh_test_connection)
from panel.security.auth import (hash_password)
import json
from panel.core.validation import (MAX_PORT, MIN_PORT, MIN_UNPRIVILEGED_PORT, _port_or,
    password_problem)
from app import (_current_lang, _log, _setup_open, _ts_backend_scheme, is_setup_complete)


def register(app):
    @app.before_request
    def check_setup():
        """Redirect to setup if not complete (except for setup pages and static).
        Until setup is finished there are no users, so every other page — including
        the login page and the dashboard root — funnels into the setup wizard."""
        # The wizard's own AJAX lives under /api/setup/* — it must NOT be redirected to
        # /setup or the JS gets an HTML redirect instead of JSON ("Could not check
        # Tailscale status"). Those endpoints self-guard with _setup_open() (403 once
        # setup is done), so exempting them here is safe.
        if request.path.startswith("/static/") or request.path == "/setup" \
                or request.path.startswith("/setup/") or request.path.startswith("/api/setup/") \
                or request.path == "/robots.txt":
            return None          # exempt path: let the request through untouched
        if not is_setup_complete():
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
        # The LOCK deliberately checks the DB row alone, not is_setup_complete().
        #
        # is_setup_complete() is (DB row AND config flag), which is right for deciding whether to
        # SHOW the wizard — a restored or blank DB must be able to run setup again. It is wrong for
        # the lock: load_config() falls back to DEFAULT_CONFIG on any JSONDecodeError/OSError, and
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

        state = SetupState.query.first()
        if not state:
            state = SetupState(step="welcome", data="{}")
            db.session.add(state)
            db.session.commit()

        data = json.loads(state.data or "{}")
        cfg = load_config()

        if request.method == "POST":
            step = request.form.get("step", "welcome")

            if step == "welcome":
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
                # nosec B104 - not a hardcoded bind: this is the DEFAULT offered in the setup
                # wizard when the operator leaves the field blank, and 0.0.0.0 is what a panel
                # reached over a tailnet or a LAN has to listen on. The value is the operator's
                # to set, and api_panel_change_port validates whatever they choose.
                cfg["bind_host"] = request.form.get("bind_host", "0.0.0.0")  # nosec B104
                save_config(cfg)
                data["site_configured"] = True
                state.step = "admin_user"
                state.data = json.dumps(data)
                db.session.commit()
                return redirect("/setup")

            elif step == "admin_user":
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

                if not username or len(username) < 3:
                    flash("Username must be at least 3 characters.", "danger")
                elif password_problem(password):
                    flash(password_problem(password), "danger")
                elif password != confirm:
                    flash("Passwords do not match.", "danger")
                else:
                    existing = User.query.filter_by(username=username).first()
                    if existing:
                        flash("Username already exists.", "danger")
                    else:
                        admin = User(
                            username=username,
                            password_hash=hash_password(password),
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
                        db.session.commit()
                        data["admin_created"] = True
                        state.step = "tailscale"
                        state.data = json.dumps(data)
                        db.session.commit()
                        return redirect("/setup")

            elif step == "tailscale":
                # The interactive install/connect/serve runs via /api/setup/tailscale/*;
                # this POST (Continue or Skip) just advances the wizard.
                state.step = "remote_server"
                state.data = json.dumps(data)
                db.session.commit()
                return redirect("/setup")

            elif step == "remote_server":
                action = request.form.get("action", "skip")
                if action == "add":
                    name = request.form.get("name", "").strip()
                    host = request.form.get("host", "").strip()
                    ssh_user = request.form.get("ssh_user", "root").strip()
                    ssh_port = _port_or(request.form.get("ssh_port"), None)
                    auth_method = request.form.get("auth_method", "key")
                    credential = request.form.get("credential", "").strip()
                    sudo_enabled = request.form.get("sudo_enabled") == "on"
                    lgsm_user = request.form.get("lgsm_user", "").strip()

                    if not name or not host:
                        flash("Name and host are required.", "danger")
                    elif ssh_port is None:
                        flash("SSH port must be between %d and %d." % (MIN_PORT, MAX_PORT), "danger")
                    else:
                        success, msg = ssh_test_connection(host, ssh_port, ssh_user, auth_method, credential)
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
                            )
                            db.session.add(remote)
                            db.session.commit()
                            flash(f"Remote '{name}' added successfully!", "success")
                            data["remote_added"] = True
                            state.data = json.dumps(data)

                if action == "skip" or request.form.get("done") == "1":
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
                            ts_info = ts.get_tailscale_info()
                            if ts_info.running and ts_info.dns_name:
                                mount = "/lgsm"
                                serve_info = ts_info.serve_config
                                root_taken = False
                                if serve_info and serve_info.get("services"):
                                    for svc in serve_info["services"]:
                                        for route in svc.get("routes", []):
                                            if route.get("mount") == "/":
                                                root_taken = True
                                                break
                                if not root_taken:
                                    mount = cfg.get("tailscale_mount", "/")
                                ts.setup_tailscale_serve(
                                    port=cfg.get("port", 5000),
                                    mount=mount,
                                    funnel=cfg.get("tailscale_use_funnel", False),
                                    backend_scheme=_ts_backend_scheme(cfg),
                                )
                                cfg["tailscale_mount"] = mount
                                cfg["tailscale_setup_done"] = True
                                save_config(cfg)
                        except Exception:
                            _log.debug("setup_wizard: ignored non-fatal error", exc_info=True)
                    db.session.commit()
                    flash("Setup complete! You can now log in.", "success")
                    return redirect("/setup")

                state.data = json.dumps(data)
                db.session.commit()

            return redirect("/setup")

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


    @app.route("/api/setup/tailscale/status")
    def api_setup_ts_status():
        if not _setup_open():
            return jsonify({"error": "forbidden"}), 403
        info = ts.get_tailscale_info(force_refresh=True)
        serve_url = next((s.get("url") for s in (info.serve_config or {}).get("services", [])), None)
        return jsonify({
            "installed": info.installed, "running": info.running,
            "dns_name": info.dns_name, "ips": info.tailscale_ips,
            "serve_url": serve_url,
            "https_url": (f"https://{info.dns_name}" if info.dns_name else None),
        })

    @app.route("/api/setup/tailscale/install", methods=["POST"])
    def api_setup_ts_install():
        if not _setup_open():
            return jsonify({"error": "forbidden"}), 403
        ok, log = ts.install_tailscale_local()
        return jsonify({"success": ok, "log": log})

    @app.route("/api/setup/tailscale/up", methods=["POST"])
    def api_setup_ts_up():
        if not _setup_open():
            return jsonify({"error": "forbidden"}), 403
        ok, res = ts.tailscale_up_local(enable_ssh=True)
        if not ok:
            return jsonify({"success": False, "message": res})
        if res == "ALREADY_CONNECTED":
            return jsonify({"success": True, "connected": True})
        return jsonify({"success": True, "connected": False, "auth_url": res})

    @app.route("/api/setup/tailscale/serve", methods=["POST"])
    def api_setup_ts_serve():
        if not _setup_open():
            return jsonify({"error": "forbidden"}), 403
        cfg = load_config()
        port = cfg.get("port", 5000)
        mount = cfg.get("tailscale_mount", "/") or "/"
        ok, msg = ts.setup_tailscale_serve(port=port, mount=mount, funnel=False,
                                           backend_scheme=_ts_backend_scheme(cfg))
        if not ok:
            return jsonify({"success": False, "message": msg})
        info = ts.get_tailscale_info(force_refresh=True)
        cfg["tailscale_setup_done"] = True
        cfg["tailscale_mount"] = mount
        cfg["bind_host"] = "127.0.0.1"   # Serve proxies to localhost; go tailnet-only
        if info.dns_name and not cfg.get("site_domain"):
            cfg["site_domain"] = info.dns_name
        save_config(cfg)
        return jsonify({"success": True, "message": msg,
                        "url": (f"https://{info.dns_name}" if info.dns_name else None)})
