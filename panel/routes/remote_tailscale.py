"""Bringing a remote host onto the tailnet.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (jsonify)
from flask_login import (current_user, login_required)
from panel.db.models import (db)
from panel.ops.ssh_manager import (close_connection, remote_bootstrap_tailscale,
    remote_check_tailscale, remote_install_tailscale, remote_migrate_to_tailscale,
    remote_tailscale_finalize, remote_tailscale_up_url)
from panel.security.auth import (MANAGE_REMOTES, get_remote, log_action, permission_required)
from panel.security import privileged as _priv
from panel.core.http import (_json_body, _json_str, _log_and_generic, _unreachable)
from app import (_refuse_on_panel_host)


def register(app):
    @app.route("/api/remote/<int:remote_id>/tailscale-check")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_tailscale_check(remote_id):
        """Check if Tailscale is installed/running on the remote VPS."""
        remote = get_remote(remote_id)
        try:
            status = remote_check_tailscale(remote)
            return jsonify({"success": True, **status})
        except ConnectionError:
            return _unreachable("remote tailscale-check")
        except Exception:
            return jsonify({"success": False, "error": _log_and_generic("request failed")}), 500

    @app.route("/api/remote/<int:remote_id>/tailscale-up", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_tailscale_up(remote_id):
        """Start `tailscale up` and return a browser login URL (no auth key needed)."""
        remote = get_remote(remote_id)
        # The same guard tailscale-install and tailscale-bootstrap carry, and for the reason
        # _refuse_on_panel_host states: these three "can change the tailnet identity of the very
        # machine the operator is reaching it through". This route IS the Tailscale join — the UI
        # offers it and tailscale-bootstrap as the two buttons in one dialog ("Get login link" vs
        # "Connect with key") — and it was the one of the pair that never got the server-side half.
        # manage_remotes.html hides the button for the local host, and a UI-only restriction on a
        # privileged action is not a restriction: the route still accepted the local host's id,
        # ran `tailscale up --ssh` on the panel's own machine and handed back the login URL, so
        # whoever called it chose which tailnet the panel host joined, with Tailscale SSH on.
        refused = _refuse_on_panel_host(remote, "Tailscale join")
        if refused:
            return refused
        data = _json_body()
        try:
            ok, result = remote_tailscale_up_url(
                remote,
                enable_ssh=data.get("enable_ssh", True),
                advertise_routes=_json_str(data, "advertise_routes"),
            )
            log_action(current_user, "remote_tailscale_up", target=remote.name, success=ok)
            if not ok:
                return jsonify({"success": False, "message": result}), 500
            if result == "ALREADY_CONNECTED":
                return jsonify({"success": True, "connected": True})
            return jsonify({"success": True, "connected": False, "url": result})
        except ConnectionError:
            return _unreachable("tailscale on a remote host")
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500

    @app.route("/api/remote/<int:remote_id>/tailscale-finalize", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_tailscale_finalize(remote_id):
        """After a node joins the tailnet, allow tailscale0 in UFW and report status."""
        remote = get_remote(remote_id)
        try:
            status, log = remote_tailscale_finalize(remote)
            # Opens tailscale0 in the remote's UFW — a firewall change, and the only one of this
            # file's five Tailscale actions that was not audited.
            #
            # `log` is non-empty only when the host's UFW read came back ACTIVE and the allow was
            # issued; remote_tailscale_finalize skips the allow otherwise and returns "". The audit
            # row used to key off status["running"], which is tailscaled's BackendState and says
            # nothing about the firewall — so a `ufw-status` that answered rc 127 (ufw absent) or
            # ("", "…timed out", -1) (the tailscale transport, which never raises) recorded a
            # successful firewall change that was never attempted. An audit row for an action that
            # did not happen is worse than no row — same reasoning as remote_vps.py:338-346.
            ufw_allowed = bool(log)
            log_action(current_user, "remote_tailscale_finalize", target=remote.name,
                       success=ufw_allowed,
                       detail=("tailscale0 allowed in UFW" if ufw_allowed
                               else "UFW rule NOT applied (inactive, absent, unreadable, or refused)"))
            return jsonify({
                "success": True, "running": status.get("running", False),
                # So the caller can say the UFW sentence only when it is true, rather than
                # printing it on every finalize.
                "ufw_allowed": ufw_allowed,
                "tailscale_ip": status.get("tailscale_ip", ""),
                "dns_name": status.get("dns_name", ""), "log": log,
            })
        except ConnectionError:
            return _unreachable("tailscale on a remote host")
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500


    @app.route("/api/remote/<int:remote_id>/tailscale-install", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_tailscale_install(remote_id):
        """Install Tailscale on the remote VPS."""
        remote = get_remote(remote_id)
        refused = _refuse_on_panel_host(remote, "Tailscale install")
        if refused:
            return refused
        try:
            success, msg, log = remote_install_tailscale(remote)
            log_action(current_user, "remote_tailscale_install", target=remote.name, detail=msg, success=success)
            return jsonify({"success": success, "message": msg, "log": log})
        except ConnectionError:
            return _unreachable("tailscale on a remote host")
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed"), "log": ""}), 500

    @app.route("/api/remote/<int:remote_id>/tailscale-bootstrap", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_tailscale_bootstrap(remote_id):
        """Authenticate and configure Tailscale on the remote VPS.
        Requires a Tailscale pre-auth key.
        """
        remote = get_remote(remote_id)
        refused = _refuse_on_panel_host(remote, "Tailscale join")
        if refused:
            return refused
        data = _json_body()
        auth_key = _json_str(data, "auth_key")
        enable_ssh = data.get("enable_ssh", True)
        advertise_routes = _json_str(data, "advertise_routes")

        if not auth_key:
            return jsonify({"success": False, "message": "Auth key is required. Get one at https://login.tailscale.com/admin/keys"}), 400

        try:
            success, msg, log = remote_bootstrap_tailscale(
                remote, auth_key=auth_key,
                enable_ssh=enable_ssh,
                advertise_routes=advertise_routes,
            )
            log_action(current_user, "remote_tailscale_bootstrap", target=remote.name, detail=msg, success=success)
            return jsonify({"success": success, "message": msg, "log": log})
        except ConnectionError:
            return _unreachable("tailscale on a remote host")
        # A VerbError is the privilege boundary REFUSING the value — "not an auth key" — which is
        # a bad request, not a panel fault. api_tailscale_serve already answers 400 for its own
        # mount-point refusal and says why: the branches below report every failure as a 500,
        # right for "the host refused the command", wrong for "you pasted something that isn't a
        # key", and the two are not distinguishable from the message.
        except _priv.VerbError:
            # A FIXED message. Interpolating the VerbError put exception text in the response —
            # ours today ("not an auth key"), but the boundary raises it from several places and
            # "what the validator said" is not a contract this endpoint should re-export to the
            # browser. The 400 already tells the form which field to blame.
            return jsonify({"success": False,
                            "message": "That isn't a usable Tailscale auth key."}), 400
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed"), "log": ""}), 500

    @app.route("/api/remote/<int:remote_id>/tailscale-migrate", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_tailscale_migrate(remote_id):
        """After bootstrapping, migrate the RemoteServer record to use Tailscale SSH."""
        remote = get_remote(remote_id)
        try:
            new_host, status = remote_migrate_to_tailscale(remote)
            if not new_host:
                # `status` is the REASON when the migration refused, and it was being thrown away
                # for one hardcoded sentence. The reasons are actionable and different from each
                # other — tailscaled down, SSH server not enabled, ACL refusing this node/user —
                # and the operator can only act on the one they actually hit.
                return jsonify({"success": False, "message": (
                    status if isinstance(status, str) and status
                    else "Tailscale is not running on the remote")}), 400

            old_host = remote.host
            remote.host = new_host
            remote.auth_method = "tailscale"
            remote.auth_credential = ""
            remote.port = 22
            db.session.commit()
            close_connection(remote)

            log_action(current_user, "remote_tailscale_migrate",
                       target=remote.name,
                       detail=f"{old_host} -> {new_host} (Tailscale SSH)")
            return jsonify({
                "success": True,
                "message": f"Migrated to Tailscale SSH: {new_host}",
                "old_host": old_host,
                "new_host": new_host,
                "tailscale_ip": status.get("tailscale_ip", ""),
                "dns_name": status.get("dns_name", ""),
            })
        except ConnectionError:
            return _unreachable("tailscale on a remote host")
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500
