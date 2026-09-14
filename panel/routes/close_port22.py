"""Closing inbound SSH once a host is reachable over the tailnet.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (jsonify)
from flask_login import (current_user, login_required)
from panel.ops.ssh_manager import (remote_ufw_close_port_22)
from panel.security.auth import (MANAGE_REMOTES, get_remote, log_action, permission_required)
from panel.core.http import (_log_and_generic)


def register(app):
    @app.route("/api/remote/<int:remote_id>/close-port-22", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_close_port_22(remote_id):
        remote = get_remote(remote_id)
        try:
            success, msg = remote_ufw_close_port_22(remote)
            log_action(current_user, "remote_close_port_22", target=remote.name, detail=msg, success=success)
            return jsonify({"success": success, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500
