"""Closing inbound SSH once a host is reachable over the tailnet.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (jsonify)
from flask_login import (current_user, login_required)
from panel.ops.ssh_manager import (_tailnet_ssh_state, remote_ufw_close_port_22)
from panel.security.auth import (MANAGE_REMOTES, get_remote, log_action, permission_required)
from panel.core.http import (_log_and_generic, _unreachable)

# Word-for-word the refusal remote_set_public_ssh(..., "off") gives, because it is the same
# change asked for from a different button and a user who sees one and then the other should not
# have to work out whether they mean the same thing.
_NO_WAY_BACK = ("Refused — there's no Tailscale way back into this host, so closing port 22 would "
                "lock you out. Enable Tailscale SSH, or make sure Tailscale is running and the "
                "tailscale0 interface is allowed in UFW, first.")


def register(app):
    @app.route("/api/remote/<int:remote_id>/close-port-22", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_close_port_22(remote_id):
        remote = get_remote(remote_id)
        try:
            # This route removed the public SSH rule with NOTHING checked — the op itself checks
            # nothing either ("safe if Tailscale SSH is active" is a docstring, not a guard) — so a
            # POST naming a key-auth host reachable only over its public IP answered "Port 22 rule
            # removed from UFW", wrote a success audit row, and left neither the panel nor the
            # operator a way back in. Both siblings that make this exact change already refuse
            # without a tailnet path: remote_set_public_ssh(..., "off") gates on
            # _tailnet_ssh_state, and the Tailscale migrate path proves a real tailnet login
            # before it closes anything. Same gate here, before the delete.
            running, ssh_enabled, iface_allowed = _tailnet_ssh_state(remote)
            if not (running and (ssh_enabled or iface_allowed)):
                log_action(current_user, "remote_close_port_22", target=remote.name,
                           detail=_NO_WAY_BACK, success=False)
                return jsonify({"success": False, "message": _NO_WAY_BACK})
            success, msg = remote_ufw_close_port_22(remote)
            log_action(current_user, "remote_close_port_22", target=remote.name, detail=msg, success=success)
            return jsonify({"success": success, "message": msg})
        # Ahead of the catch-all: a host that is switched off is not a fault in the panel. The
        # catch-all below stays 500 on purpose — anything that is not a ConnectionError is ours.
        except ConnectionError:
            return _unreachable("close port 22")
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500
