"""Tailscale status, Serve and Funnel for the panel itself.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (jsonify, render_template, request)
from flask_login import (current_user, login_required)
from panel.core.config import (load_config, save_config)
from panel.security import privileged as _priv
from panel.ops import (tailscale_integration as ts)
from panel.security.auth import (MANAGE_REMOTES, log_action, permission_required,
    superadmin_required)
from panel.core.http import (_json_body)
from panel.db.models import LOCAL_HOST_LABEL
from app import (_ts_backend_scheme)


def register(app):
    @app.route("/tailscale")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def tailscale_page():
        """Tailscale status and management page."""
        info = ts.get_tailscale_info(force_refresh=request.args.get("refresh") == "1")
        cfg = load_config()
        suggestion = ts.suggest_best_bind(cfg.get("port", 5000))
        return render_template("tailscale.html", info=info, config=cfg, suggestion=suggestion)

    @app.route("/api/tailscale")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_tailscale():
        """JSON endpoint with live Tailscale info."""
        info = ts.get_tailscale_info(force_refresh=True)
        cfg = load_config()
        suggestion = ts.suggest_best_bind(cfg.get("port", 5000))
        return jsonify({
            "installed": info.installed,
            "running": info.running,
            "backend_state": info.backend_state,
            "version": info.version,
            "hostname": info.hostname,
            "dns_name": info.dns_name,
            "tailscale_ips": info.tailscale_ips,
            "magic_dns_enabled": info.magic_dns_enabled,
            "funnel_enabled": info.funnel_enabled,
            "peer_count": len(info.peers),
            "serve": info.serve_config,
            "suggestion": suggestion,
        })

    # superadmin, not MANAGE_REMOTES, on all three below. These act on the PANEL HOST, not on a
    # granted remote — get_remote never runs, so a host admin scoped to one VPS was changing the
    # machine the panel itself runs on. Their equivalents under System -> Panel Server are already
    # superadmin: /api/server-management/ts-ssh-enable is the same state change as `up` (which
    # hardcodes enable_ssh=True), and /api/panel/change-port is the same class of change as
    # `serve`, which with funnel=true publishes the panel to the public internet and rewrites
    # config.json. Whoever opens the login URL `up` returns also chooses the tailnet this host
    # joins, with SSH enabled.
    @app.route("/api/tailscale/install", methods=["POST"])
    @login_required
    @superadmin_required
    def api_tailscale_install():
        """Install Tailscale on the PANEL HOST itself — the same in-panel flow the setup
        wizard and the remote-server bootstrap use, instead of sending the user off to
        tailscale.com to do it by hand."""
        ok, log = ts.install_tailscale_local()
        log_action(current_user, "tailscale_install_local", target=LOCAL_HOST_LABEL, success=ok)
        return jsonify({"success": ok, "log": log})

    @app.route("/api/tailscale/up", methods=["POST"])
    @login_required
    @superadmin_required
    def api_tailscale_up():
        """Run `tailscale up` on the panel host and return the browser login URL to
        approve this machine (or connected=True if it's already on the tailnet)."""
        ok, res = ts.tailscale_up_local(enable_ssh=True)
        # Logged BEFORE the branching, on every outcome. log_action used to sit inside the
        # ALREADY_CONNECTED arm — the one where nothing changed — so the failure path and the path
        # that actually starts the join (returning the login URL that decides which tailnet this
        # host joins, with SSH on) both returned with the audit log silent. Its two siblings,
        # api_tailscale_install and api_remote_tailscale_up, both log unconditionally.
        log_action(current_user, "tailscale_up_local", target=LOCAL_HOST_LABEL, success=ok,
                   detail=("already connected" if res == "ALREADY_CONNECTED"
                           else "login URL issued" if ok else "failed"))
        if not ok:
            return jsonify({"success": False, "message": res})
        if res == "ALREADY_CONNECTED":
            return jsonify({"success": True, "connected": True})
        return jsonify({"success": True, "connected": False, "auth_url": res})

    @app.route("/api/tailscale/serve", methods=["POST"])
    @login_required
    @superadmin_required
    def api_tailscale_serve():
        """Enable/disable Tailscale Serve for the panel."""
        data = _json_body()
        action = data.get("action", "enable")
        mount = data.get("mount", "/")
        funnel = data.get("funnel", False)
        port = load_config().get("port", 5000)
        # Checked HERE as well as in setup_tailscale_serve, for the reason api_tags_create gives
        # about tag names: this is where the value came from a request, so this is where a bad one
        # can be answered as a 400 with a message the form can show. The branches below report
        # every failure as a 500 — right for "the host refused the command", wrong for "you typed
        # a mount point that isn't one", and the two are not distinguishable from a message.
        try:
            mount = _priv._ts_mount(mount or "/")
        except _priv.VerbError:
            return jsonify({"success": False,
                            "message": "That isn't a usable mount point. Use \"/\" or a short "
                                       "path like \"/lgsm\"."}), 400

        if action == "enable":
            success, msg = ts.setup_tailscale_serve(port=port, mount=mount, funnel=funnel,
                                                    backend_scheme=_ts_backend_scheme(load_config()))
            if success:
                cfg = load_config()
                cfg["tailscale_setup_done"] = True
                cfg["tailscale_use_funnel"] = funnel
                cfg["tailscale_mount"] = mount
                save_config(cfg)
                log_action(current_user, "tailscale_serve_enable", target=LOCAL_HOST_LABEL, detail=msg)
                return jsonify({"success": True, "message": msg})
            return jsonify({"success": False, "message": msg}), 500

        elif action == "disable":
            success, msg = ts.disable_tailscale_serve(mount=mount)
            if success:
                # Mirror the enable branch. Nothing else in the repo ever cleared these, so a
                # disable left tailscale_setup_done True — which six readers treat as ground truth:
                # one permits a 127.0.0.1-only bind (lockout risk) and the boot path RE-APPLIES
                # Serve, quietly undoing the disable on the next restart.
                cfg = load_config()
                cfg["tailscale_setup_done"] = False
                cfg["tailscale_use_funnel"] = False
                cfg["tailscale_mount"] = ""
                save_config(cfg)
                log_action(current_user, "tailscale_serve_disable", target=LOCAL_HOST_LABEL, detail=msg)
                return jsonify({"success": True, "message": msg})
            return jsonify({"success": False, "message": msg}), 500

        return jsonify({"success": False, "message": f"Unknown action: {action}"}), 400

    @app.route("/api/tailscale/check-peer", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_tailscale_check_peer():
        """Check if a host is reachable on the tailnet."""
        data = _json_body()
        host = (data.get("host") or "").strip()
        if not host:
            return jsonify({"success": False, "message": "Host required"}), 400
        # It becomes ping's last argv element, where a leading dash reads as an option.
        if not ts.valid_peer_host(host):
            return jsonify({"success": False,
                            "message": "Enter a hostname or IP address."}), 400
        result = ts.check_peer_reachability(host)
        is_ts = ts.is_tailscale_ip(host)
        return jsonify({
            "success": True,
            "host": host,
            "reachable": result["reachable"],
            "latency_ms": result["latency_ms"],
            "is_tailscale_ip": is_ts,
        })
