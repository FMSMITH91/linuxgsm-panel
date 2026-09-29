"""fail2ban bans, recent security events and raw SSH logs, per remote host.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (jsonify, request)
from flask_login import (current_user, login_required)
from panel.core.config import (load_config, save_config)
from panel.db.models import (GameServer, LOCAL_HOST_LABEL, RemoteServer)
from panel.ops import (system_ops as so)
from panel.ops.ssh_manager import (remote_fail2ban_overview, remote_fail2ban_top_ips,
    remote_fail2ban_unban, remote_security_log, remote_ufw_close_port, remote_ufw_deny_ip,
    remote_ufw_open_port, remote_ufw_undeny_ip, tailnet_exempt_ips)
from panel.security.auth import (MANAGE_REMOTES, get_remote, log_action, permission_required,
    superadmin_required)
from panel.services.monitoring import (_autoblock_threshold, _whitelisted)
from panel.core.http import (_json_body, _json_str, _log_and_generic, _unreachable)
from panel.core.validation import (MAX_PORT, MIN_UNPRIVILEGED_PORT, NOT_AN_IP, _port_or,
                                   canonical_ip, ip_address_or_none)
from app import (AUTH_LOG_PATH, _autoblock_hosts, _maybe_set_threshold, _run_autoblock_now,
    _security_whitelist, _set_autoblock_host)
from panel.routes._shared import (_whitelist_mutate)
import ipaddress as _ipaddress

# Where a panel bound to a SPECIFIC address is still reached through the tailnet rather than the
# public port: loopback (Tailscale Serve proxies to it) and the host's own Tailscale addresses,
# from system_ops._TAILNET_RANGES rather than a copy of Tailscale's ranges here.
_TAILNET_NETS = tuple(_ipaddress.ip_network(n) for n in so._TAILNET_RANGES)


def _panel_bind_is_public(bind):
    """Whether a panel bound to `bind` needs its port OPEN in the firewall to be reached.

    Only the wildcard counted, so every specific address, the host's public or LAN IP included,
    had its port's allow rule deleted and was reported "kept tailnet-only": the panel restarted
    onto an address UFW's default-deny then shut, on the route that promises to refuse anything
    leaving the panel unreachable. Loopback and Tailscale addresses are the ones that really are
    reached without a public rule; anything else is reached on its port and needs it open.
    """
    b = (bind or "").strip()
    if b == "localhost":
        return False
    a = ip_address_or_none(b)
    if a is None:
        return True          # validated before this is asked; unknown keeps the port open
    if a.is_unspecified:
        return True
    return not (a.is_loopback or any(a in n for n in _TAILNET_NETS if n.version == a.version))


def register(app):
    _register_ban_lists(app)
    _register_blocking(app)
    _register_whitelist_and_log(app)
    _register_panel_binding(app)


def _register_ban_lists(app):
    """A host's fail2ban bans and its top offending addresses."""
    @app.route("/api/remote/<int:remote_id>/security/bans")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_bans(remote_id):
        remote = get_remote(remote_id)
        try:
            return jsonify(remote_fail2ban_overview(remote))
        except Exception:
            return jsonify({"installed": False, "jails": [], "error": _log_and_generic("ban list failed")}), 200

    @app.route("/api/remote/<int:remote_id>/security/top-ips")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_top_ips(remote_id):
        """Top offending IPs on a remote host (last 7 days), aggregated from its fail2ban log."""
        remote = get_remote(remote_id)
        # The auto-block SETTINGS come from config.json, not from the host, so a host read that
        # fails must not take them down with it. They were inside this try: an exception building
        # the IP list answered {"ips": [], "error": ...} with no `autoblock` key at all, and the
        # card repainted its toggle from the missing value — `tog.checked = !!(d && d.autoblock)`
        # — showing OFF. saveThreshold then reads that toggle back, under a comment saying
        # "preserve the on/off state", so one failed read followed by one Save silently disabled
        # auto-blocking on a host that had it on.
        _settings = {"autoblock": remote_id in _autoblock_hosts(),
                     "threshold": _autoblock_threshold()}
        # The whitelist is INSTALL-WIDE, and every other read or write of it is superadmin-only
        # (the panel-host top-ips, both whitelist routes). Sent here at MANAGE_REMOTES, a host
        # operator scoped to one VPS learned every address exempt from bans and auto-blocks on
        # every host, the admins' own home IPs included.
        if current_user.is_superadmin:
            _settings["whitelist"] = _security_whitelist()
        try:
            _ips = remote_fail2ban_top_ips(remote, 100, days=7)
        except Exception:
            return jsonify(dict(_settings, ips=[], error=_log_and_generic("top-ips failed"))), 200
        if _ips is None:
            return jsonify(dict(_settings, ips=[], unreadable=True)), 200
        return jsonify(dict(_settings, ips=_ips))


def _register_blocking(app):
    """Blocking an address on a host, and its auto-block switch."""
    @app.route("/api/remote/<int:remote_id>/security/block", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_block(remote_id):
        """UFW-block (all ports, permanent) an IP on a remote host."""
        remote = get_remote(remote_id)
        ip = _json_str(_json_body(), "ip")
        unblock = bool(_json_body().get("unblock"))
        if not unblock and tailnet_exempt_ips(remote, {ip}):
            return jsonify({"success": False, "message":
                            "%s is a Tailscale address — blocking it would cut off tailnet access." % ip})
        if not unblock and _whitelisted(ip):
            return jsonify({"success": False, "message":
                            "%s is on the security whitelist — remove it there first to block it." % ip})
        try:
            ok, msg = (remote_ufw_undeny_ip(remote, ip) if unblock else remote_ufw_deny_ip(remote, ip))
            # The address, never the request's text: the row records what was acted on.
            log_action(current_user, "ufw_unblock" if unblock else "ufw_block",
                       target=canonical_ip(ip) or NOT_AN_IP, detail=remote.name, success=ok,
                       remote=remote)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("block failed")}), 500

    @app.route("/api/remote/<int:remote_id>/security/autoblock", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_autoblock(remote_id):
        """Turn the rolling auto-block (attempts >= threshold over 7 days) on/off for a remote host.

        Turning it on or off is PER HOST, which is what MANAGE_REMOTES is for. The THRESHOLD is
        install-wide — the panel-host sibling that writes it is @superadmin_required — so a host
        admin scoped to one VPS could move it for every host, to 3 (mass-blocking) or to a huge
        value (disabling it everywhere). Confirmed by driving both routes as such a user.
        """
        remote = get_remote(remote_id)
        enabled = bool(_json_body().get("enabled"))
        if current_user.is_superadmin:
            _maybe_set_threshold(_json_body())
        _set_autoblock_host(remote_id, enabled)
        log_action(current_user, "autoblock_toggle", target=remote.name, detail="on" if enabled else "off",
                   remote=remote)
        if enabled:
            _run_autoblock_now(app, remote_id)
        return jsonify({"success": True, "enabled": enabled, "threshold": _autoblock_threshold()})


def _register_whitelist_and_log(app):
    """The security whitelist, unbanning, and a host's raw security log."""
    @app.route("/api/remote/<int:remote_id>/security/whitelist", methods=["POST"])
    @login_required
    @superadmin_required
    def api_remote_security_whitelist(remote_id):
        """Add/remove a global security-whitelist entry from a remote host's page.

        The whitelist is INSTALL-WIDE — this route does not even use its remote_id beyond the
        access check — and the panel-host sibling that writes the same list is
        @superadmin_required. At MANAGE_REMOTES a host admin scoped to one VPS could make any
        address permanently exempt from fail2ban bans and UFW auto-blocks everywhere, and lift any
        ban it already had, including on the panel host they have no rights to.
        """
        get_remote(remote_id)
        return _whitelist_mutate(app, _json_body())

    @app.route("/api/remote/<int:remote_id>/security/unban", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_unban(remote_id):
        remote = get_remote(remote_id)
        d = _json_body()
        jail, banned_ip = _json_str(d, "jail"), _json_str(d, "ip")
        try:
            ok, msg = remote_fail2ban_unban(remote, jail, banned_ip)
            log_action(current_user, "fail2ban_unban", target=canonical_ip(banned_ip) or NOT_AN_IP,
                       detail="%s on %s — %s" % (jail, remote.name, msg), success=ok,
                       remote=remote)
            return jsonify({"success": ok, "message": msg})
        except ConnectionError:
            return _unreachable("fail2ban unban")
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("unban failed")}), 500

    @app.route("/api/remote/<int:remote_id>/security/log")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_log(remote_id):
        remote = get_remote(remote_id)
        which = request.args.get("which", "ssh")
        if which not in ("fail2ban", "ssh"):
            return jsonify({"text": "", "error": "unknown log"}), 400
        jail = (request.args.get("jail") or "").strip() or None   # only meaningful for which=fail2ban
        try:
            text = remote_security_log(remote, which, 300, jail=jail)
        except Exception:
            return jsonify({"text": "", "error": _log_and_generic("log read failed")}), 200
        if text is None:
            # No read answered (Tailscale SSH and the panel host return "" rather than raising):
            # an unknown, which the viewer must not print as "(log is empty)".
            return jsonify({"text": "", "error": "The host did not answer the log read."}), 200
        return jsonify({"text": text})


def _register_panel_binding(app):
    """Moving the panel's own bind address and port."""
    @app.route("/api/panel/change-port", methods=["POST"])
    @login_required
    @superadmin_required
    def api_panel_change_port():
        """Change where the panel's web server listens: its bind address and/or port.

        Saves the new binding, brings the firewall in line (a publicly-bound panel needs its port
        open; a loopback/tailnet-bound one doesn't, and a changed port's old rule is removed), then
        restarts the panel so it rebinds (on restart it re-points Tailscale Serve at the current
        port). Refuses anything that would leave the panel unreachable: a port outside 1024-65535 /
        already in use / used by a local game server, a bind address that isn't a valid IP or isn't
        on this host, or a loopback-only bind without Tailscale Serve to proxy to it.
        """
        data = _json_body()
        cfg = load_config()
        cur_port = int(cfg.get("port", 5000))
        # nosec B104 - not a bind: the stored value, defaulted for a config written
        # before bind_host existed. The operator chooses it; this only reads it back.
        cur_bind = (cfg.get("bind_host") or "0.0.0.0").strip()  # nosec B104
        new_port = _port_or(data.get("port"), None, lo=MIN_UNPRIVILEGED_PORT)
        new_bind = str(data.get("bind_host") or cur_bind).strip()

        local = RemoteServer.query.filter_by(is_local=True).first()
        refusal = (_port_refusal(local, cur_port, new_port)
                   or _bind_refusal(bool(cfg.get("tailscale_setup_done")), new_bind))
        if refusal:
            return jsonify({"success": False, "message": refusal}), 400
        if new_port == cur_port and new_bind == cur_bind:
            return jsonify({"success": False, "message": "That's already the panel's binding."}), 400

        # ── Save the new binding ──
        cfg["port"] = new_port
        cfg["bind_host"] = new_bind
        save_config(cfg)

        fw_note, fw_ok = _follow_binding_in_firewall(app, local, new_bind, new_port, cur_port)
        f2b_ok, f2b_msg = _follow_binding_in_fail2ban(app, new_port, cur_port)

        # The row says what HAPPENED. It used to be success=True whatever the firewall and the
        # jail did — both outcomes were computed and dropped — so "the panel moved to 5055" was on
        # record as a success for a move whose port the firewall still blocked. The binding itself
        # is saved above either way; the detail says which half did not follow it.
        #
        # BEFORE the restart, and it stays there: restart_panel arms a detached two-second timer
        # that restarts the unit (KillMode=control-group), and an audit write queued behind a
        # SQLite lock for longer than that would die with the process. The restart's own outcome
        # is therefore a row of its own, below.
        log_action(current_user, "panel_change_binding", target=LOCAL_HOST_LABEL,
                   detail=f"{cur_bind}:{cur_port} -> {new_bind}:{new_port}; "
                          f"firewall: {fw_note.strip() or 'n/a'}; fail2ban: {f2b_msg}",
                   success=fw_ok and f2b_ok)
        ok, restart_msg = so.restart_panel()
        if not ok:
            log_action(current_user, "panel_restart", target=LOCAL_HOST_LABEL,
                       detail=f"after the binding change: {restart_msg}", success=False)
            return jsonify({"success": False,
                            "message": "Saved the new binding, but couldn't restart the panel "
                                       "automatically — restart it (or reboot the host) to apply."
                                       + fw_note}), 200
        return jsonify({"success": True, "new_port": new_port, "old_port": cur_port,
                        "new_bind": new_bind, "port_changed": new_port != cur_port,
                        "served_over_tailscale": bool(cfg.get("tailscale_setup_done")),
                        "message": f"Panel binding to {new_bind}:{new_port}. Restarting…{fw_note}"})


def _port_refusal(local, cur_port, new_port):
    """Why the panel must not listen on `new_port`, or None when it may."""
    # ── Validate the port ──
    # The bound now lives in _port_or (shared with the setup wizard, which writes the SAME
    # config key and used to write it unchecked). Kept as an explicit branch so the refusal
    # still carries its own message.
    if new_port is None:
        return "Pick a port between %d and %d." % (MIN_UNPRIVILEGED_PORT, MAX_PORT)
    if new_port != cur_port:
        clash = GameServer.query.filter_by(remote_id=local.id, port=new_port).first() if local else None
        if clash:
            return (f"Port {new_port} is used by game server "
                    f"'{clash.name}'. Pick another.")
        if so.port_in_use(new_port):
            return f"Port {new_port} is already in use on this host."
    return None


def _bind_refusal(served, new_bind):
    """Why the panel must not bind to `new_bind`, or None when it may.

    `served` is whether Tailscale Serve is set up to proxy to the panel on localhost.
    """
    # nosec B104 - the set of wildcard addresses to RECOGNISE, so the code below
    # can tell "listening everywhere" from loopback. Detecting a value is not
    # binding to it.
    wildcard = {"0.0.0.0", "::"}  # nosec B104
    loopback = {"127.0.0.1", "::1", "localhost"}
    # ── Validate the bind address ──
    if new_bind not in wildcard:
        # A zone id is not an address to bind (see panel/core/validation.py).
        if ip_address_or_none(new_bind) is None:
            return ("Bind address must be an IP — e.g. 0.0.0.0 (all "
                    "interfaces), 127.0.0.1 (localhost), or this host's "
                    "Tailscale IP.")
        if new_bind not in loopback:
            # A specific IP: with Tailscale Serve (which proxies to localhost) this would
            # break Serve and lock you out; without Serve it must at least be a real local IP.
            if served:
                return ("Tailscale Serve reaches the panel on localhost, so "
                        "bind to 0.0.0.0 (all) or 127.0.0.1 (localhost). A "
                        "specific IP would break Serve and lock you out.")
            if not so.host_has_ip(new_bind):
                return (f"{new_bind} isn't an address on this host — the "
                        "panel couldn't bind to it.")
    if new_bind in loopback and not served:
        return ("Binding to localhost only would lock you out unless "
                "Tailscale Serve is set up to reach the panel. Set up "
                "Serve first.")
    return None


def _follow_binding_in_fail2ban(app, new_port, cur_port):
    """Point the panel-login jail at the new port: (ok, what happened, for the audit row).

    Keeps brute-force protection following the move. Idempotent; a no-op when the jail is not set
    up. Not asked at all when the port did not change, which is not a failure.
    """
    if new_port == cur_port:
        return True, "n/a (port unchanged)"
    try:
        # _security_whitelist() is NOT optional here: ensure_panel_fail2ban REWRITES the jail
        # whenever the port changes, and an omitted ignore_ips writes an ignoreip of localhost
        # only — silently dropping every whitelisted IP/CIDR until the next boot re-applies it
        # (or indefinitely, if the restart after this fails).
        ok, msg = so.ensure_panel_fail2ban(AUTH_LOG_PATH, new_port, _security_whitelist())
        # "Does NOT install fail2ban — no-ops when it isn't present", and says so with ok=False.
        # A host with no fail2ban has no jail to follow the move, which is not a failed move.
        if not ok and not so.panel_fail2ban_status().get("installed"):
            return True, "n/a (fail2ban is not installed)"
    except Exception:
        app.logger.warning("change-port: fail2ban port update failed", exc_info=True)
        return False, "the jail update failed"
    return bool(ok), (msg or ("updated" if ok else "not updated"))


def _follow_binding_in_firewall(app, local, new_bind, new_port, cur_port):
    """Open or close the panel's port for the new binding's exposure.

    -> (the reply's note, whether the firewall now matches the binding). With no local host row
    there is no firewall to follow, which is not a failure.
    """
    # ── Bring the firewall in line with the resulting exposure ──
    # Reached on its port (the wildcard, or the host's own public/LAN address) → the port must
    # be open. Loopback/tailnet-bound → the public port rule isn't needed, so close it. A
    # changed port also gets its old rule gone.
    now_public = _panel_bind_is_public(new_bind)
    fw_note, fw_ok = "", True
    if local:
        # Each of these returns (ok, msg) and all three were called for effect, with fw_note
        # assigned on the next line regardless — so the panel could restart onto a port the
        # firewall does not allow having just said "Firewall: opened 5055.", on the one route
        # whose docstring is "Refuses anything that would leave the panel unreachable".
        try:
            if now_public:
                _fw_ok, _fw_msg = remote_ufw_open_port(local, new_port, "tcp", "LinuxGSM Panel")
                fw_note = (f" Firewall: opened {new_port}." if _fw_ok
                           else f" FIREWALL NOT UPDATED — port {new_port} may be blocked ({_fw_msg}).")
            else:
                _fw_ok, _fw_msg = remote_ufw_close_port(local, new_port, "tcp")
                fw_note = (f" Firewall: {new_port} kept tailnet-only." if _fw_ok
                           else f" Firewall rule for {new_port} could not be removed ({_fw_msg}).")
            fw_ok = bool(_fw_ok)
            if new_port != cur_port:
                _old_ok, _old_msg = remote_ufw_close_port(local, cur_port, "tcp")
                fw_note += (f" Removed the old rule for {cur_port}." if _old_ok
                            else f" The old rule for {cur_port} is still there ({_old_msg}).")
                fw_ok = fw_ok and bool(_old_ok)
        except Exception:
            app.logger.warning("change-port: firewall update failed", exc_info=True)
            fw_note += " The firewall could not be updated."
            fw_ok = False
    return fw_note, fw_ok
