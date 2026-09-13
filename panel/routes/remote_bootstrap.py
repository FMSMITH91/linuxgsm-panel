"""Full remote-host bootstrap, with live progress.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (jsonify)
from flask_login import (current_user, login_required)
from panel.security.auth import (MANAGE_REMOTES, get_remote, permission_required)
import time
from app import (_bootstrap_jobs, _bootstrap_lock, _json_body, _refuse_on_panel_host)
from panel.routes._shared import (_begin_bootstrap)


def register(app):
    @app.route("/api/remote/<int:remote_id>/bootstrap", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_bootstrap(remote_id):
        """Kick off a fresh-VPS bootstrap in the background: updates, essential
        packages, UFW, SSH hardening, swap, fail2ban, LinuxGSM user, then reboot.
        Returns immediately; poll /bootstrap-status for live progress."""
        refused = _refuse_on_panel_host(get_remote(remote_id), "VPS bootstrap")
        if refused:
            return refused
        data = _json_body()
        opts = {
            "set_timezone": data.get("timezone", "UTC"),
            "enable_ufw": data.get("enable_ufw", True),
            "install_lgsm_deps": data.get("install_lgsm_deps", True),
            "username": data.get("lgsm_user", ""),
            "install_fail2ban": data.get("install_fail2ban", True),
            "do_reboot": data.get("reboot", True),
        }
        started, msg = _begin_bootstrap(app, remote_id, opts, current_user.id)
        if not started:
            return jsonify({"success": False, "message": msg}), 409
        return jsonify({"success": True, "started": True})

    @app.route("/api/remote/<int:remote_id>/bootstrap-status")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_bootstrap_status(remote_id):
        """Live status of an in-progress (or just-finished) bootstrap job."""
        get_remote(remote_id)   # enforce access, like the route that starts the job
        with _bootstrap_lock:
            job = _bootstrap_jobs.get(remote_id)
            if not job:
                return jsonify({"status": "none"})
            # Auto-expire a finished job after a while so the completed/failed card
            # doesn't linger (or re-trigger) forever across page visits.
            if job["status"] in ("done", "failed") and (time.time() - job.get("updated", job["started"])) > 900:
                _bootstrap_jobs.pop(remote_id, None)
                return jsonify({"status": "none"})
            pct = int(job["step"] / job["total"] * 100) if job.get("total") else 0
            return jsonify({
                "status": job["status"],
                "step": job["step"],
                "total": job["total"],
                "percent": pct,
                "step_name": job["step_name"],
                "message": job.get("message", ""),
                "log": job["log"][-200:],
                "elapsed": int(time.time() - job["started"]),
            })

    @app.route("/api/remote/<int:remote_id>/bootstrap-dismiss", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_bootstrap_dismiss(remote_id):
        """Clear a finished (done/failed) bootstrap job so its card goes away."""
        get_remote(remote_id)   # enforce access, like the route that starts the job
        with _bootstrap_lock:
            job = _bootstrap_jobs.get(remote_id)
            if job and job["status"] in ("done", "failed"):
                _bootstrap_jobs.pop(remote_id, None)
        return jsonify({"success": True})


