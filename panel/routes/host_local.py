"""The panel host's own service, firewall and OS management.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
import time
from flask import (jsonify, render_template, request)
from flask_login import (current_user, login_required)
from panel.core.clock import (utcnow)
from panel.core.config import (DB_PATH, load_config)
from panel.db.models import (LOCAL_HOST_LABEL, RemoteServer, db)
from panel.ops import (system_ops as so)
from panel.ops.ssh_manager import (host_specs, tailnet_exempt_ips)
from panel.security.auth import (log_action, superadmin_required)
from panel.services.monitoring import (_autoblock_threshold, _whitelisted)
from types import (SimpleNamespace)
from panel.core.http import (_json_body, _json_str, _log_and_generic)
from app import (_autoblock_hosts, _local_remote_id, _maybe_set_threshold, _os_update_note,
    _run_autoblock_now, _security_whitelist, _set_autoblock_host)
from panel.routes._shared import (_whitelist_mutate)

# A token unique to THIS panel process — it changes only when the panel actually restarts.
# The self-update UI polls for this to flip, rather than the git SHA: install.sh moves HEAD
# the instant it resets, before the new process is serving, so a SHA change doesn't mean the
# update is live — a boot-id change does.
_BOOT_ID = "%.6f" % time.time()


def register(app):
    @app.route("/server-management")
    @login_required
    @superadmin_required
    def server_management():
        """Panel host management. The panel host is just the local remote, so it uses
        the SAME template (and endpoints) as a remote server — only the panel-specific
        extras (self-update, its own Tailscale SSH controls) differ, keyed on is_local."""
        local = RemoteServer.query.filter_by(is_local=True).first()
        if local is None:
            # Fresh install that never added the panel host as a manageable server —
            # create it so the panel can manage itself with the unified UI.
            local = RemoteServer(
                name="Panel Server", host="127.0.0.1", port=22, username="local",
                auth_method="local", auth_credential="", sudo_enabled=True,
                linuxgsm_user="", is_local=True, is_online=True,
                last_seen=utcnow(),
            )
            db.session.add(local)
            db.session.commit()
        status = so.get_server_status()
        # get_server_status already read the panel host's pending packages off the cached apt lists
        # (no network) — hand that to the shared snapshot so the banner reflects it immediately
        # rather than waiting for the next daily sweep.
        _os_update_note(local, status.get("updates") or {})
        return render_template("remote_manage.html", remote=local, status=status,
                               config=load_config())

    @app.route("/api/server-management")
    @login_required
    @superadmin_required
    def api_server_management():
        """JSON status for server management dashboard."""
        return jsonify(so.get_server_status())

    @app.route("/api/server-management/specs")
    @login_required
    @superadmin_required
    def api_server_management_specs():
        """Static hardware/OS specs for the panel host."""
        local = RemoteServer.query.filter_by(is_local=True).first()
        if local is None:
            # Panel host wasn't added as a manageable remote — gather specs anyway
            # via a lightweight local-only stand-in.
            local = SimpleNamespace(is_local=True, auth_method="local",
                                    sudo_enabled=False, linuxgsm_user="")
        return jsonify(host_specs(local))

    @app.route("/api/server-management/live")
    @login_required
    @superadmin_required
    def api_server_management_live():
        """Realtime per-core + overall CPU and RAM/swap for the live bar graphs."""
        return jsonify(so.live_metrics())

    @app.route("/api/server-management/ufw-allow-tailscale", methods=["POST"])
    @login_required
    @superadmin_required
    def api_ufw_allow_tailscale():
        """Allow traffic on the Tailscale interface via UFW."""
        success, msg = so.ufw_allow_tailscale()
        if success:
            so.invalidate_server_status()   # firewall changed → next page load re-probes
            log_action(current_user, "ufw_allow_tailscale", target=LOCAL_HOST_LABEL, detail=msg)
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "message": msg}), 500

    @app.route("/api/server-management/ts-ssh-enable", methods=["POST"])
    @login_required
    @superadmin_required
    def api_ts_ssh_enable():
        """Enable Tailscale SSH."""
        success, msg = so.tailscale_ssh_enable()
        if success:
            so.invalidate_server_status()   # tailscale-ssh state changed → next load re-probes
            log_action(current_user, "tailscale_ssh_enable", target=LOCAL_HOST_LABEL, detail=msg)
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "message": msg}), 500

    @app.route("/api/server-management/ts-ssh-disable", methods=["POST"])
    @login_required
    @superadmin_required
    def api_ts_ssh_disable():
        """Disable Tailscale SSH."""
        success, msg = so.tailscale_ssh_disable()
        if success:
            so.invalidate_server_status()   # tailscale-ssh state changed → next load re-probes
            log_action(current_user, "tailscale_ssh_disable", target=LOCAL_HOST_LABEL, detail=msg)
            return jsonify({"success": True, "message": msg})
        return jsonify({"success": False, "message": msg}), 500

    @app.route("/api/panel/update-status")
    @login_required
    @superadmin_required
    def api_panel_update_status():
        """Is the LinuxGSM Panel itself behind its GitHub repo? (git-based check)"""
        force = request.args.get("force") in ("1", "true", "yes")
        try:
            data = dict(so.panel_update_status(force=force))
            data["boot_id"] = _BOOT_ID   # flips only when the panel process restarts
            return jsonify(data)
        except Exception:
            return jsonify({"git": False, "update_available": False, "boot_id": _BOOT_ID,
                            "current_version": so.panel_version(),
                            "message": _log_and_generic("panel update-status failed")})

    @app.route("/api/panel/update", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_update():
        """Pull the latest panel code and restart (one-click self-update)."""
        success, msg = so.panel_self_update()
        log_action(current_user, "panel_self_update", target=LOCAL_HOST_LABEL, detail=msg, success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/panel/update-log")
    @login_required
    @superadmin_required
    def api_panel_update_log():
        """Live progress of an in-flight self-update (the [1/5]…[5/5] steps + result)."""
        try:
            return jsonify(so.panel_update_log())
        except Exception:
            return jsonify({"exists": False, "lines": [],
                            "error": _log_and_generic("panel update-log failed")})

    @app.route("/api/panel/branches")
    @login_required
    @superadmin_required
    def api_panel_branches():
        """Remote branches the panel can switch to, plus the one it currently tracks."""
        try:
            branches, current = so.list_panel_branches()
            return jsonify({"branches": branches, "current": current})
        except Exception:
            return jsonify({"branches": [], "current": "main",
                            "error": _log_and_generic("listing branches failed")})

    @app.route("/api/panel/switch-branch", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_switch_branch():
        """Switch the panel to another branch and pull it (same rollback-safe path as an update)."""
        branch = _json_str(_json_body(), "branch")
        success, msg = so.panel_switch_branch(branch)
        log_action(current_user, "panel_switch_branch", target=branch, detail=msg, success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/panel/diagnostics")
    @login_required
    @superadmin_required
    def api_panel_diagnostics():
        """Fast local self-check of the panel's own health (integrity, DB, keys,
        disk, cert, service). No SSH/network."""
        try:
            return jsonify(so.panel_diagnostics())
        except Exception:
            return jsonify({"checks": [], "summary": "fail", "ok": 0, "warn": 0, "fail": 1,
                            "error": _log_and_generic("panel diagnostics failed")})

    @app.route("/api/panel/integrity")
    @login_required
    @superadmin_required
    def api_panel_integrity():
        """Which of the panel's own git-tracked files have been modified/deleted."""
        try:
            return jsonify(so.panel_integrity())
        except Exception:
            return jsonify({"git": False, "clean": True, "modified": [], "count": 0,
                            "current_sha": "",
                            "error": _log_and_generic("panel integrity check failed")})

    @app.route("/api/panel/repair", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_repair():
        """Restore tampered panel files from git. Body: {"paths": [...]} to restore
        specific reported files, or {} / omitted to restore all of them."""
        data = _json_body()
        paths = data.get("paths")
        if paths is not None and not isinstance(paths, list):
            paths = None
        try:
            # `paths`, not `paths or None`: an empty list is a request to restore NOTHING, and
            # collapsing it to None turned that into "restore every modified file". The UI sends
            # {} for restore-all, which is still None here.
            ok, msg, restored = so.panel_repair(paths)
            if ok and restored:
                log_action(current_user, "panel_repair", target="panel",
                           detail=", ".join(restored)[:500], success=True)
            return jsonify({"success": ok, "message": msg, "restored": restored})
        except Exception:
            return jsonify({"success": False,
                            "message": _log_and_generic("panel repair failed")}), 500

    @app.route("/api/panel/db-stats")
    @login_required
    @superadmin_required
    def api_panel_db_stats():
        """DB + WAL size and audit-log row count (so growth is visible)."""
        try:
            from panel.db.models import database_stats
            return jsonify(database_stats())
        except Exception:
            return jsonify({"error": _log_and_generic("db-stats failed")}), 500

    @app.route("/api/panel/optimize-db", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_optimize_db():
        """VACUUM + ANALYZE + WAL checkpoint — reclaim space, refresh stats."""
        try:
            from panel.db.models import optimize_database
            ok, msg, info = optimize_database()
            if ok:
                try:
                    log_action(current_user, "panel_db_optimize", target=LOCAL_HOST_LABEL,
                               detail="freed %d bytes" % info.get("freed", 0), success=True)
                except Exception:
                    app.logger.warning("optimize: audit-log write failed", exc_info=True)
            return jsonify({"success": ok, "message": msg, **(info or {})})
        except Exception:
            return jsonify({"success": False,
                            "message": _log_and_generic("db optimize failed")}), 500

    @app.route("/api/panel/db-health")
    @login_required
    @superadmin_required
    def api_panel_db_health():
        """On-demand database integrity check — read-only PRAGMA integrity_check, which is
        deeper than the fast quick_check the panel runs at startup. Reports healthy/flagged;
        an actual repair is never done to the live file, it runs safely offline during an
        update (or a restart), so this endpoint has no destructive side effects."""
        try:
            import db_maintenance
            ok, detail = db_maintenance.integrity_check(str(DB_PATH))
            return jsonify({"healthy": bool(ok), "detail": detail})
        except Exception:
            return jsonify({"healthy": None, "detail": _log_and_generic("db health check failed")}), 200

    @app.route("/api/panel/repair-db", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_repair_db():
        """Repair a flagged database on-demand: a detached job stops the panel, rebuilds/restores the
        DB offline (original copied aside first), and restarts. For when the health check fails."""
        try:
            ok, msg = so.panel_repair_database()
            log_action(current_user, "panel_repair_db", target="database", detail=msg, success=ok)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("db repair failed")}), 500



    @app.route("/api/panel/security/bans")
    @login_required
    @superadmin_required
    def api_panel_security_bans():
        """Every fail2ban jail on the panel host with its current bans (panel-login + sshd + …)."""
        try:
            return jsonify(so.fail2ban_overview())
        except Exception:
            return jsonify({"installed": False, "jails": [], "error": _log_and_generic("ban list failed")}), 200

    @app.route("/api/panel/security/top-ips")
    @login_required
    @superadmin_required
    def api_panel_security_top_ips():
        """Top offending IPs on the panel host (last 7 days), aggregated from the fail2ban log."""
        try:
            # `or []`: the reader answers None when the read failed, which the card renders as
            # "no offenders" either way — but the DIFFERENCE now matters to _autoblock_reconcile.
            return jsonify({"ips": so.fail2ban_top_ips(100, days=7) or [],
                            "autoblock": _local_remote_id() in _autoblock_hosts(),
                            "threshold": _autoblock_threshold(),
                            "whitelist": _security_whitelist()})
        except Exception:
            return jsonify({"ips": [], "error": _log_and_generic("top-ips failed")}), 200

    @app.route("/api/panel/security/block", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_security_block():
        """UFW-block (all ports, permanent) an IP on the panel host."""
        ip = _json_str(_json_body(), "ip")
        unblock = bool(_json_body().get("unblock"))
        if not unblock:
            lr = RemoteServer.query.filter_by(is_local=True).first()
            if lr and tailnet_exempt_ips(lr, {ip}):
                return jsonify({"success": False, "message":
                                "%s is a Tailscale address — blocking it would cut off tailnet access." % ip})
            if _whitelisted(ip):
                return jsonify({"success": False, "message":
                                "%s is on the security whitelist — remove it there first to block it." % ip})
        try:
            ok, msg = (so.ufw_undeny_ip(ip) if unblock else so.ufw_deny_ip(ip))
            log_action(current_user, "ufw_unblock" if unblock else "ufw_block", target=ip, success=ok)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("block failed")}), 500

    @app.route("/api/panel/security/autoblock", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_security_autoblock():
        """Turn the rolling auto-block (attempts >= threshold over 7 days) on/off for the panel host,
        and optionally update the shared threshold."""
        enabled = bool(_json_body().get("enabled"))
        rid = _local_remote_id()
        if rid is None:
            return jsonify({"success": False, "message": "No local host record."}), 200
        _maybe_set_threshold(_json_body())
        _set_autoblock_host(rid, enabled)
        log_action(current_user, "autoblock_toggle", target="panel host", detail="on" if enabled else "off")
        if enabled:
            _run_autoblock_now(app, rid)
        return jsonify({"success": True, "enabled": enabled, "threshold": _autoblock_threshold()})

    @app.route("/api/panel/security/whitelist", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_security_whitelist():
        """Add or remove a global security-whitelist entry (IP or CIDR). Whitelisted addresses are
        never fail2ban-banned (jail ignoreip) or UFW auto-blocked, and adding one lifts any ban/block
        it already has."""
        return _whitelist_mutate(app, _json_body())

    @app.route("/api/panel/security/unban", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_security_unban():
        """Lift a fail2ban ban (jail + IP validated server-side)."""
        d = _json_body()
        jail, banned_ip = _json_str(d, "jail"), _json_str(d, "ip")
        try:
            ok, msg = so.fail2ban_unban(jail, banned_ip)
            log_action(current_user, "fail2ban_unban", target=banned_ip,
                       detail="%s — %s" % (jail, msg), success=ok)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("unban failed")}), 500

    @app.route("/api/panel/security/events")
    @login_required
    @superadmin_required
    def api_panel_security_events():
        """Recent security-relevant audit entries (failed/blocked logins, fail2ban bans)."""
        try:
            from panel.db.models import AuditLog
            acts = ["login_failed", "login_blocked", "fail2ban_ban", "fail2ban_unban"]
            rows = (AuditLog.query.filter(AuditLog.action.in_(acts))
                    .order_by(AuditLog.id.desc()).limit(50).all())
            return jsonify({"events": [
                {"time": (r.timestamp.isoformat() if r.timestamp else ""), "action": r.action,
                 "user": r.username, "target": r.target, "detail": r.detail, "ip": r.ip_address}
                for r in rows]})
        except Exception:
            return jsonify({"events": [], "error": _log_and_generic("security events failed")}), 200

    @app.route("/api/panel/security/log")
    @login_required
    @superadmin_required
    def api_panel_security_log():
        """Tail of a whitelisted security log: panel (data/auth.log), fail2ban, or ssh."""
        which = request.args.get("which", "panel")
        if which not in ("panel", "fail2ban", "ssh"):
            return jsonify({"text": "", "error": "unknown log"}), 400
        jail = (request.args.get("jail") or "").strip() or None   # only meaningful for which=fail2ban
        try:
            return jsonify({"text": so.security_log_tail(which, 300, jail=jail)})
        except Exception:
            return jsonify({"text": "", "error": _log_and_generic("log read failed")}), 200
