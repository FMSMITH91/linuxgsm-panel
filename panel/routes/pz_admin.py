"""Project Zomboid's admin password: the one-click fix for LinuxGSM's CHANGE_ME.

LinuxGSM v26.3.0 (#4991) ships pzserver with `adminpassword="CHANGE_ME"` and starts the game with
`-adminpassword ${adminpassword}`, so a server still on it has an admin account anyone who has read
LinuxGSM's config can use; the config read flags it (files.lgsm_read_config). Kept beside the config
editor's routes (server_files) rather than in them: that module is at its size limit.
"""
from flask import (jsonify)
from flask_login import (current_user, login_required)
from panel.core import i18n
from panel.core.http import (_log_and_generic)
from panel.ops import ssh_manager as _sm
from panel.routes._shared import (_r20b_audit_on_raise)
from panel.security.auth import (_can_manage_files, get_game, log_action, server_access_required)


def register(app):
    @app.route("/api/server/<int:server_id>/pz-admin-password", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_pz_admin_password(server_id):
        """Give a Project Zomboid server a random adminpassword in place of LinuxGSM's CHANGE_ME.

        The same permission and refusals as a settings save, which can write the same key. The
        password goes into the instance cfg and nowhere else: not the reply, not the audit row.
        """
        from panel.routes import server_files as _sf
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if gs.game_type != "pz":
            return jsonify({"success": False,
                            "message": i18n.tr("This server is not a Project Zomboid server.")}), 400
        refused = _sf._write_refused(gs, "edit_config")
        if refused is not None:
            return refused
        try:
            with _r20b_audit_on_raise("edit_config", target=gs.name, server=gs):
                ok, msg = _sm.lgc_pz_set_admin_password(gs.remote, gs.short_name, gs.lgsm_name)
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500
        log_action(current_user, "edit_config", target=gs.name,
                   detail=_sf._failed_detail("adminpassword set to a random value", ok,
                                             _sm.write_failure_reason(msg)),
                   success=ok, server=gs)
        if not ok:
            return jsonify({"success": False, "message": i18n.tr(msg or "Failed")})
        return jsonify({"success": True, "message": i18n.tr(
            "Set a random admin password: it is adminpassword below. Restart the server to apply it. "
            "Project Zomboid uses it when it creates the admin account, on the server's first start; "
            "if this server has started before, change the admin's password in game as well.")})
