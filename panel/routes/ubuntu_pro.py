"""Ubuntu Pro attach/detach and status, for any host including the panel's own.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (jsonify, request)
from flask_login import (current_user, login_required)
from panel.ops.ssh_manager import (pro_attach, pro_detach, pro_service, remote_live_metrics)
from panel.security.auth import (MANAGE_REMOTES, get_remote, log_action, permission_required)
from app import (_json_body, _log_and_generic, _pro_status_cached, _unreachable)


def register(app):
    @app.route("/api/remote/<int:remote_id>/pro-status")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_pro_status(remote_id):
        force = request.args.get("force") in ("1", "true", "yes")
        try:
            return jsonify(_pro_status_cached(get_remote(remote_id), force=force))
        except ConnectionError:
            return _unreachable("remote pro-status")

    @app.route("/api/remote/<int:remote_id>/pro-attach", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_pro_attach(remote_id):
        remote = get_remote(remote_id)
        token = _json_body().get("token", "")
        ok, msg = pro_attach(remote, token)
        # NOTE: the token is deliberately never logged.
        if ok:
            _pro_status_cached(remote, force=True)   # state changed → refresh the stored status
        log_action(current_user, "pro_attach", target=remote.name, success=ok)
        return jsonify({"success": ok, "message": msg})

    @app.route("/api/remote/<int:remote_id>/pro-service", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_pro_service(remote_id):
        remote = get_remote(remote_id)
        data = _json_body()
        service = (data.get("service") or "").strip()
        action = (data.get("action") or "").strip()
        ok, msg = pro_service(remote, service, action)
        if ok:
            _pro_status_cached(remote, force=True)   # a service toggled → refresh the stored status
        log_action(current_user, f"pro_{action or 'service'}", target=remote.name,
                   detail=service, success=ok)
        return jsonify({"success": ok, "message": msg})

    @app.route("/api/remote/<int:remote_id>/pro-detach", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_pro_detach(remote_id):
        remote = get_remote(remote_id)
        ok, msg = pro_detach(remote)
        if ok:
            _pro_status_cached(remote, force=True)   # detached → refresh the stored status
        log_action(current_user, "pro_detach", target=remote.name, success=ok)
        return jsonify({"success": ok, "message": msg})

    @app.route("/api/remote/<int:remote_id>/live")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_live(remote_id):
        """Realtime per-core + overall CPU and RAM/swap for a remote's live bars."""
        remote = get_remote(remote_id)
        try:
            return jsonify(remote_live_metrics(remote))
        except ConnectionError:
            return _unreachable("remote live metrics")
        except Exception:
            return jsonify({"error": _log_and_generic("request failed")}), 500
