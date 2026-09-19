"""Remote host management: ports, OS updates, reboots and diagnostics.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (jsonify, render_template, url_for)
from flask_login import (current_user, login_required)
from panel.core.config import (load_config)
from panel.core.panel_state import (_os_update_seen, _reboot_when_empty, _rwe_lock)
from panel.db.models import (GameServer, db)
from panel.ops import (system_ops as so)
from panel.ops.ssh_manager import (change_ssh_port, close_connection, detect_game_ports,
    host_specs, is_player_queryable as sm_is_player_queryable, player_count as sm_player_count,
    remote_os_run_updates, remote_os_update_start, remote_os_update_status,
    remote_public_ssh_status, remote_reboot, remote_reboot_required, remote_set_public_ssh,
    remote_ufw_allow_game_port, remote_ufw_allow_game_ports, remote_ufw_close_port,
    remote_ufw_allow_from, remote_ufw_delete_rule, remote_ufw_limit_port,
    remote_ufw_open_port, remote_ufw_status, remote_uptime)
# Reached through the MODULE, not bound by name: these are the seams the test suite
# monkeypatches. `from x import f` copies the function object, so a stub on the source
# module would never be seen — attribute access resolves at call time and is stable
# however the handler moves.
from panel.ops import ssh_manager as _sm
from panel.security.auth import (INSTALL_SERVER, MANAGE_REMOTES, accessible_remote_ids,
    can_access_remote, get_game,
    get_remote, has_permission, log_action, permission_required, server_access_required)
import time
from panel.core.http import (_json_body, _json_str, _log_and_generic, _unreachable)
from app import (_local_remote_id, _log, _os_update_note)


def register(app):
    @app.route("/remote/<int:remote_id>/firewall")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def remote_firewall(remote_id):
        """Remote VPS firewall management page."""
        remote = get_remote(remote_id)
        try:
            status = remote_ufw_status(remote)
        except ConnectionError:
            # A host that is down, rebooting or behind a dropped tunnel raises here, and this
            # view rendered a 500 for it — while the API twin below, calling the same function,
            # has always caught ConnectionError and answered "unreachable". A page whose whole
            # job is managing a remote must survive that remote being off.
            #
            # This is the same shape remote_ufw_status() returns when the command runs but fails,
            # so the template has one unreachable state to render rather than two.
            # remote.id, not the raw remote_id path segment: get_remote() has already looked the
            # host up and enforced access, so this is the integer primary key off the row rather
            # than request input reaching a log sink (py/log-injection). Same shape as the other
            # id-logging sites in panel/routes/_shared.py.
            _log.info("remote firewall page: remote %s unreachable", remote.id, exc_info=True)
            status = {"installed": False, "enabled": False, "rules": [], "groups": [],
                      "unreachable": True}
        games = GameServer.query.filter_by(remote_id=remote_id).all()
        return render_template("remote_firewall.html", remote=remote, status=status, games=games)

    @app.route("/api/remote/<int:remote_id>/firewall")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall(remote_id):
        remote = get_remote(remote_id)
        try:
            return jsonify(remote_ufw_status(remote))
        except ConnectionError:
            return _unreachable("remote firewall status")

    @app.route("/api/remote/<int:remote_id>/retrust-hostkey", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_retrust_hostkey(remote_id):
        # Clear the pinned SSH host key so the next connection re-pins it (TOFU). Use
        # after legitimately reinstalling a server, when its host key has changed and
        # connections are being rejected as a mismatch.
        remote = get_remote(remote_id)
        old_fp = remote.host_key_fingerprint
        remote.host_key = ""
        db.session.commit()
        try:
            close_connection(remote)   # drop any cached client → reconnect fresh
        except Exception:
            _log.debug("no cached connection to drop, or it's already gone", exc_info=True)
        log_action(current_user, "retrust_hostkey", target=remote.name,
                   detail="cleared pinned host key (%s)" % (old_fp or "none"))
        return jsonify({"success": True,
                        "message": "Host key cleared — it will be re-pinned on the next connection."})

    @app.route("/api/remote/<int:remote_id>/firewall/open", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_open(remote_id):
        remote = get_remote(remote_id)
        data = _json_body()
        port = data.get("port", "")
        proto = data.get("protocol", "tcp")
        if not port:
            return jsonify({"success": False, "message": "Port required"}), 400
        success, msg = remote_ufw_open_port(remote, port, proto, data.get("comment", ""))
        log_action(current_user, "remote_port_open", target=f"{remote.name}:{port}/{proto}", success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/firewall/allow-from", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_allow_from(remote_id):
        """Open a port only from one address or network (`allow: false` removes the rule).

        The gap this fills: every other allow here opens a port to the internet, so a port that
        only you or only your LAN should reach had no way to say so."""
        remote = get_remote(remote_id)
        data = _json_body()
        source = _json_str(data, "source")
        port = data.get("port", "")
        proto = data.get("protocol", "tcp")
        on = data.get("allow", True) is not False
        if not source or not port:
            return jsonify({"success": False, "message": "Source and port required"}), 400
        success, msg = remote_ufw_allow_from(remote, source, port, proto,
                                             data.get("comment", ""), allow=on)
        log_action(current_user, "remote_port_allow_from" if on else "remote_port_allow_from_remove",
                   target=f"{remote.name}:{port}/{proto}", detail="from %s" % source, success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/firewall/limit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_limit(remote_id):
        """Rate-limit a port, or lift the limit (`limit: false`).

        UFW has done this since forever and the panel has used it on every bootstrap to harden
        SSH — it just had no way to ask for it on a port you choose."""
        remote = get_remote(remote_id)
        data = _json_body()
        port = data.get("port", "")
        proto = data.get("protocol", "tcp")
        on = data.get("limit", True) is not False
        if not port:
            return jsonify({"success": False, "message": "Port required"}), 400
        success, msg = remote_ufw_limit_port(remote, port, proto, limit=on)
        log_action(current_user, "remote_port_limit" if on else "remote_port_unlimit",
                   target=f"{remote.name}:{port}/{proto}", success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/firewall/close", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_close(remote_id):
        remote = get_remote(remote_id)
        data = _json_body()
        port = data.get("port", "")
        proto = data.get("protocol", "tcp")
        if not port:
            return jsonify({"success": False, "message": "Port required"}), 400
        success, msg = remote_ufw_close_port(remote, port, proto)
        log_action(current_user, "remote_port_close", target=f"{remote.name}:{port}/{proto}", success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/firewall/delete-rule", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_delete_rule(remote_id):
        """Delete a UFW rule by its number (the reliable way to remove any rule)."""
        remote = get_remote(remote_id)
        num = _json_body().get("num")
        success, msg = remote_ufw_delete_rule(remote, num)
        log_action(current_user, "remote_ufw_delete_rule", target=f"{remote.name}:#{num}", success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/ssh-status")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_ssh_status(remote_id):
        remote = get_remote(remote_id)
        try:
            # On the panel host, also report whether the panel's own public web port is
            # still open, so the UI can disable "Close public panel port" once it's closed.
            panel_port = load_config().get("port", 5000) if remote.is_local else None
            st = remote_public_ssh_status(remote, panel_port=panel_port)
            st["auth_method"] = remote.auth_method
            return jsonify(st)
        except Exception:
            return jsonify({"error": _log_and_generic("ssh-status failed")}), 200

    @app.route("/api/remote/<int:remote_id>/ssh-mode", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_ssh_mode(remote_id):
        """Set public SSH via UFW: allow / limit / off (tailnet-only)."""
        remote = get_remote(remote_id)
        mode = _json_body().get("mode", "")
        success, msg = remote_set_public_ssh(remote, mode)
        log_action(current_user, "remote_ssh_mode", target=f"{remote.name}:{mode}", success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/ssh-port", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_ssh_port(remote_id):
        """Move this host's sshd to a new port (lockout-safe: the old port stays open as a fallback,
        and UFW + fail2ban are updated with it). Works for a remote and the panel host itself."""
        if not (current_user.is_superadmin or can_access_remote(current_user, remote_id)):
            return jsonify({"success": False, "message": "You don't have access to that host."}), 403
        remote = get_remote(remote_id)
        body = _json_body()
        try:
            new_port = int(body.get("port"))
        except (TypeError, ValueError):
            return jsonify({"success": False, "message": "Enter a valid port number."}), 400
        if not (1 <= new_port <= 65535):
            return jsonify({"success": False, "message": "Port must be between 1 and 65535."}), 400
        bind = _json_str(body, "bind")
        old = remote.port
        try:
            ok, msg = change_ssh_port(remote, new_port, bind)
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("SSH port change failed")}), 500
        if ok:
            # Point the panel at the new port for future connections (cosmetic for the local host,
            # which doesn't SSH). Same host, so the pinned host key still applies — leave it. The old
            # port stays open, so any connection the panel is using right now survives.
            remote.port = new_port
            db.session.commit()
        log_action(current_user, "change_ssh_port", target=remote.name,
                   detail=f"{old} -> {new_port}", success=ok)
        return jsonify({"success": ok, "message": msg})

    @app.route("/api/remote/<int:remote_id>/close-panel-port", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_close_panel_port(remote_id):
        """Close the panel's public web port on the panel host so the UI is reachable only
        over the tailnet. Refuses unless Tailscale Serve is configured — otherwise this
        would remove your only way into the panel."""
        remote = get_remote(remote_id)
        if not remote.is_local:
            return jsonify({"success": False, "message": "Only applies to the panel host."}), 400
        cfg = load_config()
        if not cfg.get("tailscale_setup_done"):
            return jsonify({"success": False, "message": "Set up Tailscale Serve first — "
                            "otherwise closing the public port would lock you out of the panel."}), 400
        try:
            port = int(cfg.get("port", 5000))
        except (TypeError, ValueError):
            port = 5000

        def _panel_port_rule_nums():
            nums = []
            for g in remote_ufw_status(remote).get("groups", []):
                if not g.get("is_iface") and str(g.get("port_num", "")) == str(port):
                    nums.extend(g.get("nums", []))
            return sorted(set(nums), reverse=True)   # highest first so numbering stays valid

        nums = _panel_port_rule_nums()
        if not nums:
            return jsonify({"success": True, "message": f"Public port {port} is already closed."})
        # Delete by rule NUMBER (reliable across any rule format), force=True since this is
        # the intentional guided close and Serve is already confirmed as the way in.
        for n in nums:
            remote_ufw_delete_rule(remote, n, force=True)
        ok = not _panel_port_rule_nums()
        log_action(current_user, "close_panel_port", target=str(port), success=ok)
        return jsonify({"success": ok, "message": (
            f"Public port {port} closed — the panel is now reachable only over your tailnet."
            if ok else f"Couldn't remove every rule for port {port}; check the firewall page.")})

    @app.route("/api/remote/<int:remote_id>/game-port/<int:port>/open", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES, INSTALL_SERVER)
    def api_remote_game_port_open(remote_id, port):
        remote = get_remote(remote_id)
        gs = GameServer.query.filter_by(remote_id=remote_id, port=port).first()
        count, msg = remote_ufw_allow_game_port(remote, port, gs.short_name if gs else "Game")
        success = count >= 1
        log_action(current_user, "game_port_open", target=f"{remote.name}:{port}", success=success)
        return jsonify({"success": success, "message": msg, "rules_added": count})

    @app.route("/api/server/<int:server_id>/sync-ports", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_sync_ports(server_id):
        """Detect ALL of a game server's ports from LinuxGSM and open every one in the
        firewall (game/query/rcon/etc.). Also re-syncs the stored port. Fixes servers
        that were installed before multi-port support, or whose ports changed."""
        gs = get_game(server_id)
        if not (current_user.is_superadmin or has_permission(current_user, MANAGE_REMOTES)
                or has_permission(current_user, INSTALL_SERVER)):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        try:
            info = detect_game_ports(gs.remote, gs.short_name, gs.lgsm_name)
            gp = info.get("game_port")
            if gp and gp != gs.port:
                gs.port = gp
                db.session.commit()
            to_open = info.get("open_ports") or ([gs.port] if gs.port else [])
            # The count and message are deliberately unused — the reply below states what was
            # REQUESTED, and a partially-applied rule set is reported by the firewall page
            # rather than here. Not bound at all: a leading underscore is a convention CodeQL
            # does not read, and an unused name is an unused name.
            remote_ufw_allow_game_ports(gs.remote, to_open, gs.short_name)
            log_action(current_user, "sync_ports", target=gs.name, detail=str(to_open), success=True)
            return jsonify({"success": True, "message": f"Ports {', '.join(map(str, to_open)) or '—'} opened.",
                            "ports": info.get("ports", []), "open_ports": to_open, "game_port": gp})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500

    @app.route("/api/remote/<int:remote_id>/live-stats")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_live_stats(remote_id):
        """Real-time CPU, RAM, disk, uptime from the remote VPS. Also persisted to the
        remote so the card can render the last-known values instantly on the next load
        instead of showing a spinner."""
        remote = get_remote(remote_id)
        try:
            stats = remote_uptime(remote)
            try:
                remote.update_cached_stats(stats)
                db.session.commit()
            except Exception:
                db.session.rollback()
            return jsonify({"success": True, **stats})
        except Exception:
            # Unreachable host is expected — 200 with an error field, not a console 500.
            return jsonify({"success": False, "error": _log_and_generic("remote live-stats failed")}), 200

    @app.route("/api/remote/<int:remote_id>/uptime")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_uptime(remote_id):
        remote = get_remote(remote_id)
        try:
            return jsonify(remote_uptime(remote))
        except ConnectionError:
            return _unreachable("remote uptime")

    @app.route("/api/remote/<int:remote_id>/check-updates")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_check_updates(remote_id):
        """Force a fresh check on one host. The panel host runs it locally rather than over SSH to
        itself, which is what the daily sweep does too."""
        remote = get_remote(remote_id)
        try:
            result = (so.os_update_available(refresh=True) if remote.is_local
                      else _sm.remote_os_check_updates(remote))
        except ConnectionError:
            # Same reasoning as the "ok" flag below — a host we could not ask is not a host that is
            # up to date. The difference is that this one could not be asked at all.
            return _unreachable("remote check-updates")
        # "ok" travels to the UI: a check that failed (apt locked by unattended-upgrades, host mid
        # reboot) returns an empty list, and without this the card would report "System is up to
        # date" for a host nobody managed to ask.
        _os_update_note(remote, result)
        return jsonify({"ok": bool(result.get("ok")), "count": result["count"],
                        "packages": result["packages"]})

    @app.route("/api/os-updates/summary")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_os_updates_summary():
        """What every host had waiting as of its last check — served from memory, never probing.

        This is what the login banner and the OS Updates card render. Page loads must not trigger
        `apt update` (a network fetch per host, 60s timeout each), so they read the daily sweep's
        answer instead; the Check button is there for anyone who wants it re-asked now."""
        # .copy() rather than iterating the live dict: the daily sweep writes to it from its own
        # thread, and a resize mid-iteration would 500 the page this banner sits on.
        snapshot = _os_update_seen.copy()
        if not snapshot:
            return jsonify({"hosts": []})     # nothing known yet — don't spend a query finding out
        hosts = []
        local_id = _local_remote_id()
        # The accessible set, resolved ONCE. can_access_remote per host is the same answer and
        # costs a query set each time it is asked — fine when the grants were lazily cached on the
        # user, and three queries per host now that they are eagerly loaded. Same check, same
        # result, asked once instead of once per host in the snapshot.
        _allowed = None if current_user.is_superadmin else accessible_remote_ids(current_user)
        for rid, seen in sorted(snapshot.items()):
            if not seen.get("count"):
                continue
            # MANAGE_REMOTES is scoped per host (see get_remote): a user who can manage one remote
            # must not learn the name or patch state of another's from this summary.
            if _allowed is not None and rid not in _allowed:
                continue
            hosts.append({"id": rid, "name": seen["name"], "count": seen["count"],
                          "security": seen["security"], "at": seen["at"],
                          # The panel host has a dedicated page, but it is superadmin-only — anyone
                          # else reaching it through the banner would land on a 403, so send them
                          # to the same host's ordinary manage page (it is just a remote row).
                          "url": url_for("server_management")
                                 if rid == local_id and current_user.is_superadmin
                                 else url_for("remote_manage", remote_id=rid)})
        return jsonify({"hosts": hosts})

    @app.route("/api/remote/<int:remote_id>/updates-cached")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_updates_cached(remote_id):
        """One host's last-known package list, for filling the OS Updates card on page load without
        making the page wait on apt. {known:false} when nothing has checked this host yet."""
        remote = get_remote(remote_id)
        seen = _os_update_seen.get(remote.id)
        if not seen:
            return jsonify({"known": False})
        return jsonify({"known": True, "count": seen["count"], "security": seen["security"],
                        "at": seen["at"], "packages": seen["packages"]})

    @app.route("/api/remote/<int:remote_id>/run-updates", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_run_updates(remote_id):
        remote = get_remote(remote_id)
        success, msg = remote_os_run_updates(remote)
        log_action(current_user, "remote_os_update", target=remote.name, success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/os-update/start", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_os_update_start(remote_id):
        """Start a detached, watchable OS update; the popup polls .../os-update/status for live output."""
        remote = get_remote(remote_id)
        try:
            ok, msg = remote_os_update_start(remote)
            if ok:
                log_action(current_user, "remote_os_update", target=remote.name, detail="started")
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("couldn't start update")}), 500

    @app.route("/api/remote/<int:remote_id>/os-update/status")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_os_update_status(remote_id):
        """Live output + running/done state of the OS update, for the watch popup."""
        remote = get_remote(remote_id)
        try:
            return jsonify(remote_os_update_status(remote))
        except Exception:
            return jsonify({"running": False, "done": True, "rc": None,
                            "log": "", "error": _log_and_generic("status read failed")}), 200

    @app.route("/api/remote/<int:remote_id>/players")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_players(remote_id):
        """Players connected across ALL installed game servers on this host, so a reboot can warn
        before disconnecting everyone. Returns {total, busy:[{name, players}]}."""
        remote = get_remote(remote_id)
        busy = []
        total = 0
        for gs in GameServer.query.filter_by(remote_id=remote.id, installed=True).all():
            try:
                pc = sm_player_count(gs.remote, gs.short_name, gs.game_type, gs.port)
            except Exception:
                pc = None
            if pc and pc > 0:
                busy.append({"name": gs.name, "players": pc})
                total += pc
        return jsonify({"total": total, "busy": busy})

    @app.route("/api/remote/<int:remote_id>/reboot-required")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_reboot_required(remote_id):
        """Does this host need a reboot to finish applying updates, and is an auto-reboot-when-empty
        already scheduled for it? {required, packages[], pending_empty}."""
        remote = get_remote(remote_id)
        try:
            info = dict(remote_reboot_required(remote))
        except Exception:
            info = {"required": False, "packages": []}
        with _rwe_lock:
            info["pending_empty"] = remote_id in _reboot_when_empty
        return jsonify(info)

    @app.route("/api/remote/<int:remote_id>/reboot", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_reboot(remote_id):
        """Reboot a host now, or (when_empty=true) schedule it to reboot once every game server on it
        is empty. An explicit 'now' supersedes any pending when-empty request."""
        remote = get_remote(remote_id)
        when_empty = bool((_json_body() or {}).get("when_empty"))
        if when_empty:
            with _rwe_lock:
                _reboot_when_empty[remote_id] = {"by": current_user.username, "since": time.time()}
            log_action(current_user, "reboot_when_empty_arm", target=remote.name)
            # Warn if any game here can't be player-queried (no gamedig type AND no console engine):
            # the panel can't confirm it's empty while it's running, so the reboot waits until it is
            # stopped. Cheap, offline check — no network calls.
            try:
                unq = [gs.name for gs in GameServer.query.filter_by(remote_id=remote.id, installed=True).all()
                       if not sm_is_player_queryable(gs.game_type, getattr(gs, "query_type", None))]
            except Exception:
                unq = []
            note = ""
            if unq:
                note = (" Note: the panel can't read the player count for %s, so it'll reboot only "
                        "once that server is stopped (or the rest of the host is empty and it is too)."
                        % ", ".join(unq[:4]))
            return jsonify({"success": True, "pending": True,
                            "message": ("Scheduled — %s will reboot once every game server on it is "
                                        "empty." % remote.name) + note})
        with _rwe_lock:
            _reboot_when_empty.pop(remote_id, None)
        success, msg = remote_reboot(remote)
        # success=, or log_action's default (True) records a refused reboot as one that happened —
        # and /logs filtered to failures hides it. The OS-update sibling on this page passes it.
        log_action(current_user, "remote_reboot", target=remote.name, success=success)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/reboot-cancel", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_reboot_cancel(remote_id):
        """Cancel a pending 'reboot when empty' for this host."""
        remote = get_remote(remote_id)
        with _rwe_lock:
            had = _reboot_when_empty.pop(remote_id, None)
        if had:
            log_action(current_user, "reboot_when_empty_cancel", target=remote.name)
        return jsonify({"success": True, "pending": False,
                        "message": "Auto-reboot canceled." if had else "Nothing was scheduled."})

    @app.route("/remote/<int:remote_id>/manage")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def remote_manage(remote_id):
        """Rich management page for a remote server — live per-core resources plus
        OS updates, reboot and firewall — the same experience as the Panel Server."""
        remote = get_remote(remote_id)
        games = GameServer.query.filter_by(remote_id=remote_id).all()
        # config=, because remote_manage.html reads config.port / config.bind_host /
        # config.tailscale_setup_done for the panel-host card. Without it Jinja fell back to
        # FLASK'S app.config — truthy, but with no lowercase keys — so every read was empty and
        # every `if config else <default>` fallback was dead code that could not fire. The page
        # said "Public panel access (port )" with the number missing, claimed Serve was not set
        # up when it was, and pre-filled the binding form with 0.0.0.0 and a blank port next to an
        # "Apply & restart" button. server_management passes it; this route did not.
        return render_template("remote_manage.html", remote=remote, games=games,
                               config=load_config())

    @app.route("/api/remote/<int:remote_id>/specs")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_specs(remote_id):
        """Static hardware/OS specs for a remote host (loaded once, not polled)."""
        remote = get_remote(remote_id)
        return jsonify(host_specs(remote))
