"""fail2ban bans, recent security events and raw SSH logs, per remote host.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (current_app, jsonify, request)
from flask_login import (current_user, login_required)
from panel.core.config import (_r13a_cfg_text, _r15a_cfg_int, bound_port, load_config, set_config_keys)
from panel.db.models import (GameServer, LOCAL_HOST_LABEL, RemoteServer)
from panel.ops import (system_ops as so)
from panel.ops.ssh_manager import (remote_fail2ban_overview, remote_fail2ban_top_ips,
    remote_fail2ban_unban, remote_security_log, remote_ufw_close_port, remote_ufw_deny_ip,
    remote_ufw_open_port, remote_ufw_put_back_tcp, remote_ufw_undeny_ip, tailnet_exempt_ips)
from panel.security.auth import (MANAGE_REMOTES, client_ip, get_host_remote, get_remote, log_action,
    permission_required, superadmin_required)
from panel.services.monitoring import (_autoblock_threshold, _whitelist_networks, _whitelisted)
from panel.core import i18n
from panel.core.http import (_json_body, _json_str, _log_and_generic, _r13b_json_flag,
                             _r22b_unreachable_or_generic, _unreachable)
from panel.core.validation import (MAX_PORT, MIN_UNPRIVILEGED_PORT, NOT_AN_IP, _port_or,
                                   canonical_ip, ip_address_or_none)
from app import (AUTH_LOG_PATH, _autoblock_hosts, _maybe_set_threshold, _run_autoblock_now,
    _security_whitelist, _set_autoblock_host)
from panel.routes._shared import (_r20b_audit_on_raise, _r23a_not_while_panel_host_reboots, _whitelist_mutate)
from panel.ops import ssh_manager as _sm
from panel.ops.ssh_manager import _core as _sm_core
from panel.security import banlist as _banlist
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
        # get_host_remote: on the panel's own host its bans are superadmin-only, as the
        # /api/panel/security/* twins are; a delegable whole-host grant does not reach them.
        remote = get_host_remote(remote_id)
        try:
            return jsonify(remote_fail2ban_overview(remote))
        except Exception:
            return jsonify({"installed": False, "jails": [], "error": _log_and_generic("ban list failed")}), 200

    @app.route("/api/remote/<int:remote_id>/security/top-ips")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_top_ips(remote_id):
        """Top offending IPs on a remote host (last 7 days), aggregated from its fail2ban log."""
        # get_host_remote: on the panel's own host its bans are superadmin-only, as the
        # /api/panel/security/* twins are; a delegable whole-host grant does not reach them.
        remote = get_host_remote(remote_id)
        # The auto-block SETTINGS come from config.json, not from the host, so a host read that
        # fails must not take them down with it. They were inside this try: an exception building
        # the IP list answered {"ips": [], "error": ...} with no `autoblock` key at all, and the
        # card repainted its toggle from the missing value — `tog.checked = !!(d && d.autoblock)`
        # — showing OFF. saveThreshold then reads that toggle back, under a comment saying
        # "preserve the on/off state", so one failed read followed by one Save silently disabled
        # auto-blocking on a host that had it on.
        # Guarded on their own, as on the panel host's twin: a read of them that raised escaped as
        # an HTML 500, which the card can only call "Could not load".
        try:
            _settings = {"autoblock": remote_id in _autoblock_hosts(),
                         "threshold": _autoblock_threshold()}
            # The whitelist is INSTALL-WIDE, and every other read or write of it is superadmin-only
            # (the panel-host top-ips, both whitelist routes). Sent here at MANAGE_REMOTES, a host
            # operator scoped to one VPS learned every address exempt from bans and auto-blocks on
            # every host, the admins' own home IPs included.
            if current_user.is_superadmin:
                _settings["whitelist"] = _security_whitelist()
        except Exception:
            return jsonify({"ips": [], "error": _log_and_generic("top-ips settings failed")}), 200
        try:
            _ips = remote_fail2ban_top_ips(remote, 100, days=7)
        except Exception:
            return jsonify(dict(_settings, ips=[], error=_log_and_generic("top-ips failed"))), 200
        if _ips is None:
            return jsonify(dict(_settings, ips=[], unreadable=True)), 200
        return jsonify(dict(_settings, ips=_ips))


def _follow_in_panel_gate(remote, ok):
    """Re-read the ban list now when a block or unban on the PANEL host just succeeded.

    The panel's own gate (banlist) refuses banned addresses on traffic UFW never sees — a
    Tailscale Funnel or a reverse proxy. Its siblings in host_local (api_panel_security_block and
    _unban) ask for a refresh at once; these routes reach the same host through its row id (the
    Security tab of the panel host's own page) and did not, so a block made here left the address
    served, and an unban left it refused, until the next 90 s tick. A remote host's bans are not in
    the panel's gate at all, so nothing is asked there.
    """
    if ok and _sm.is_local_server(remote):
        _banlist.refresh_soon(0)


def _fwa_block_refusal(remote, target):
    """Why blocking `target` (fwa_block_target's text: an address or a network) is refused, or None.

    A block is a deny on every port inserted at the TOP, so whatever it covers is cut off. Every
    target, one address or many, is held to the same checks on its canonical form: it may not cover
    the address of the viewer making it, reach into the tailnet's addresses or an entry of the
    security whitelist (one address: the route's own checks, _fwb_single_refusal), nor cover an
    address the panel connects to this host from: the session's source, which must be read (unread
    refuses), and every global address of the panel's own host, any of which it may dial from next
    time (a second uplink, a new IPv6 temporary address).
    """
    net = _ipaddress.ip_network(target, strict=False)
    mine = ip_address_or_none(client_ip())
    mine = mine.ipv4_mapped if mine is not None and getattr(mine, "ipv4_mapped", None) else mine
    if mine is not None and mine.version == net.version and mine in net:
        return i18n.Sentence("{ip} covers your own address ({mine}) — blocking it would lock you out.",
                             ip=target, mine=str(mine))
    if net.num_addresses > 1:
        why = _fwa_range_refusal(net, target)
        if why:
            return why
    return _fwa_source_refusal(remote, net, target)


def _fwa_range_refusal(net, target):
    """_fwa_block_refusal's tailnet and whitelist half for a RANGE: any overlap refuses.

    One address is held to the route's own checks instead (_fwb_single_refusal), which exempt a
    CGNAT-range address only while the host's tailnet is up, as the auto-block does.
    """
    if any(net.version == n.version and net.overlaps(n) for n in _TAILNET_NETS):
        return i18n.Sentence("{ip} reaches into Tailscale's addresses — blocking it would cut off tailnet "
                             "access.", ip=target)
    if any(net.version == w.version and net.overlaps(w) for w in _whitelist_networks()):
        return i18n.Sentence("{ip} covers an address on the security whitelist — remove it there first, "
                             "or block a narrower range.", ip=target)
    return None


def _fwa_source_refusal(remote, net, target):
    """_fwa_block_refusal's half for the addresses the panel's connection to the host may come from.

    The session's source and the panel host's own addresses, named; then the panel's own connection
    read as ufw reads it with the deny on top (ufweval, fwc_block_ip_refusal), which holds what those
    cannot see.
    """
    return _fwb_named_source_refusal(remote, net, target) or _sm.fwc_block_ip_refusal(remote, target)


def _fwb_named_source_refusal(remote, net, target):
    """_fwa_source_refusal's named checks: the session's source, then the panel host's own addresses."""
    src = _sm.fwa_panel_source(remote)
    if src is None:
        return i18n.Sentence("Couldn't read the address the panel connects to this host from, so {ip} was "
                             "not blocked.", ip=target)
    s_addr = ip_address_or_none(src) if src else None
    if s_addr is not None and s_addr.version == net.version and s_addr in net:
        return i18n.Sentence("{ip} covers the address the panel connects to this host from ({src}) — "
                             "blocking it would cut the panel off from the host.", ip=target, src=src)
    if not src:
        return None                  # the panel's own host, or one reached over Tailscale
    return _fwb_own_addr_refusal(net, target)


def _fwb_own_addr_refusal(net, target):
    """_fwa_source_refusal's half for the panel host's own global addresses (any it may dial from)."""
    own = _fwb_panel_host_addrs()
    if own is None:
        return i18n.Sentence("Couldn't read this panel host's own addresses, so {ip} was not blocked.", ip=target)
    hit = sorted(str(a) for a in own if a.version == net.version and a in net)
    if hit:
        return i18n.Sentence("{ip} covers {addr}, an address of the panel's own host it may connect to this host "
                             "from — blocking it could cut the panel off from the host.", ip=target, addr=hit[0])
    return None


def _fwb_panel_host_addrs():
    """The panel host's own global interface addresses (ip_address objects), or None when unread.

    ufweval.local_addrs's reading (`ip -o addr` in the C locale), global scope only: loopback and
    link-local never carry the panel's connection to another host.
    """
    rows = _sm.ufweval.local_addrs()
    if rows is None:
        return None
    return {addr for _iface, addr, scope in rows if scope == "global"}


def _fwb_single_refusal(remote, target):
    """The route's own refusal for ONE address (a JSON answer's message), on its canonical form, or None.

    The tailnet: an address tailscale_exempt_ips holds (the host's tailnet up), or one in Tailscale's
    own IPv6 range, which nothing else uses; and the whitelist.
    """
    addr = ip_address_or_none(target)
    if addr is None:
        return None
    if tailnet_exempt_ips(remote, {target}) or (addr.version == 6 and any(
            addr in n for n in _TAILNET_NETS if n.version == 6)):
        return i18n.tr("{ip} is a Tailscale address — blocking it would cut off tailnet access.", ip=target)
    if _whitelisted(target):
        return i18n.tr("{ip} is on the security whitelist — remove it there first to block it.", ip=target)
    return None


def _fwa_block_or_unblock(remote, ip, shown, unblock):
    """The block route's write -> (ok, msg): the unblock, or the block once nothing refuses it.

    The refusal is decided, and the deny written, under one hold of the host's ufw_lock (re-entrant:
    remote_ufw_deny_ip takes it again for its own read and write).
    """
    if unblock:
        return remote_ufw_undeny_ip(remote, ip)
    if shown == NOT_AN_IP:
        return False, "Invalid IP address."
    with _sm_core.ufw_lock(remote):
        why = _fwa_block_refusal(remote, shown)
        return (False, why) if why else remote_ufw_deny_ip(remote, shown)


def _register_blocking(app):
    """Blocking an address on a host, and its auto-block switch."""
    @app.route("/api/remote/<int:remote_id>/security/block", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_block(remote_id):
        """UFW-block (all ports, permanent) an IP, or a range of them (CIDR), on a remote host."""
        remote = get_host_remote(remote_id)
        ip = _json_str(_json_body(), "ip")
        # JSON booleans or a 400, here and in the auto-block switch: bool("false") is True, so
        # `{"unblock": "false"}` unblocked the address it asked to block.
        unblock = _r13b_json_flag(_json_body(), "unblock", False)
        # The address (or network), never the request's text: the row records what was acted on, and
        # the guards below and the deny all read this one canonical form (fwa_block_target).
        act = "ufw_unblock" if unblock else "ufw_block"
        shown = _sm.fwa_block_target(ip, unmap=not unblock) or NOT_AN_IP
        refused = None if unblock or shown == NOT_AN_IP else _fwb_single_refusal(remote, shown)
        if refused:
            return jsonify({"success": False, "message": refused})
        try:
            with _r20b_audit_on_raise(act, detail=remote.name, target=shown, remote=remote):
                ok, msg = _fwa_block_or_unblock(remote, ip, shown, unblock)
            # The action spelled out: the audit-ids gate reads it from this call.
            log_action(current_user, "ufw_unblock" if unblock else "ufw_block", target=shown,
                       detail=remote.name, success=ok, remote=remote)
            _follow_in_panel_gate(remote, ok)
            return jsonify({"success": ok, "message": i18n.tr(msg)})
        except Exception:
            # A host that is down or refused the panel is not a fault in it: _unreachable's answer
            # (200, `unreachable`, a `code`); anything else is the generic 500.
            return _r22b_unreachable_or_generic("block failed")

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
        remote = get_host_remote(remote_id)
        enabled = _r13b_json_flag(_json_body(), "enabled", False)
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
        remote = get_host_remote(remote_id)
        d = _json_body()
        jail, banned_ip = _json_str(d, "jail"), _json_str(d, "ip")
        try:
            with _r20b_audit_on_raise("fail2ban_unban", detail="%s on %s" % (jail, remote.name),
                                      target=canonical_ip(banned_ip) or NOT_AN_IP, remote=remote):
                ok, msg = remote_fail2ban_unban(remote, jail, banned_ip)
            _follow_in_panel_gate(remote, ok)
            log_action(current_user, "fail2ban_unban", target=canonical_ip(banned_ip) or NOT_AN_IP,
                       detail="%s on %s — %s" % (jail, remote.name, msg), success=ok,
                       remote=remote)
            return jsonify({"success": ok, "message": i18n.tr(msg)})
        except ConnectionError:
            return _unreachable("fail2ban unban")
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("unban failed")}), 500

    @app.route("/api/remote/<int:remote_id>/security/log")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_security_log(remote_id):
        remote = get_host_remote(remote_id)
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
    @_r23a_not_while_panel_host_reboots
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
        # _r15a_cfg_int: a hand-edited `port` that is not a number ("5000x", Infinity) made this
        # form answer a bare 500, the same hand-edit class as bind_host below.
        stored_port = _r15a_cfg_int(cfg.get("port", 5000), 5000)
        # The port the panel serves on NOW (config.bound_port), not config.json's: after a move whose
        # restart could not be scheduled the two differ, and the old port's rule, the jail and the
        # helper's record were put back on the port still served (_r30b_keep_old_port). Read from
        # config.json, a second move closed the rule of a port nothing served and left the live
        # one's open, pointed the jail and the record at the unserved port when its own restart
        # failed too, and a move back to the served port was refused as "in use" (by the panel).
        cur_port = _r32a_served_port(stored_port)
        # nosec B104 - not a bind: the stored value, defaulted for a config written
        # before bind_host existed. The operator chooses it; this only reads it back. A non-string
        # (a hand edit) reads as unset, as the boot reads it (_r13a_cfg_text): .strip() on it made
        # this form answer a bare 500.
        cur_bind = (_r13a_cfg_text(cfg, "bind_host") or "0.0.0.0").strip()  # nosec B104
        new_port = _port_or(data.get("port"), None, lo=MIN_UNPRIVILEGED_PORT)
        new_bind = _r11c_canonical_bind(str(data.get("bind_host") or cur_bind).strip())

        local = RemoteServer.query.filter_by(is_local=True).first()
        refusal = _r25j_binding_refusal(local, cfg, cur_port, new_port, new_bind, stored_port)
        if refusal:
            return jsonify({"success": False, "message": refusal}), 400
        # With a move still waiting for its restart, asking for the served port (to undo it) or for
        # the saved one again (to retry it) is a change, not the binding the panel already has. The
        # same for the bind: after a bind change whose restart could not be scheduled the process
        # still listens on the old one, and re-asking for the saved bind was refused as "already",
        # leaving no way to apply it short of a host reboot (review 1022a).
        if new_port == cur_port == stored_port and new_bind == cur_bind == _r34j_bind_now(cfg, cur_bind):
            return jsonify({"success": False, "message": "That's already the panel's binding."}), 400

        # ── Save the new binding ──
        # Only these two keys, onto the file as it is now: the checks above ran `ss` and `ip`,
        # which yield, and a whole-dict save_config(cfg) reverted any write made meanwhile.
        set_config_keys(cfg, port=new_port, bind_host=new_bind)

        fw_notes, fw_ok, old_removed = _follow_binding_in_firewall(app, local, new_bind, new_port, cur_port)
        fw_ok = _r32a_close_unapplied_port(app, local, stored_port, cur_port, new_port, fw_notes) and fw_ok
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
                   detail=f"{_r18a_bracketed(cur_bind)}:{cur_port} -> {_r18a_bracketed(new_bind)}:{new_port}; "
                          f"firewall: {' '.join(fw_notes) or 'n/a'}; fail2ban: {f2b_msg}",
                   success=fw_ok and f2b_ok)
        ok, restart_msg = so.restart_panel()
        if not ok:
            # The panel still listens where it did, and the steps above took that port's rule and
            # jail away: put them back, or the page that says "restart it" is the last one served.
            back_notes, back_audit = _r30b_keep_old_port(app, local, cur_port, new_port, old_removed)
            log_action(current_user, "panel_restart", target=LOCAL_HOST_LABEL,
                       detail=f"after the binding change: {restart_msg}; {back_audit}", success=False)
            return jsonify({"success": False, "message": _r15e_with_notes(i18n.Sentence(
                "Saved the new binding, but couldn't restart the panel automatically — restart it "
                "(or reboot the host) to apply."), fw_notes + back_notes)}), 200
        return jsonify({"success": True, "new_port": new_port, "old_port": cur_port,
                        "new_bind": new_bind, "port_changed": new_port != cur_port,
                        "served_over_tailscale": bool(cfg.get("tailscale_setup_done")),
                        "message": _r15e_with_notes(i18n.Sentence(
                            "Panel binding to {address}:{port}. Restarting…",
                            address=_r18a_bracketed(new_bind), port=new_port), fw_notes)})


def _r32a_served_port(stored_port):
    """The port this process is bound to (config.bound_port), else config.json's `stored_port`."""
    return bound_port() or stored_port


def _r34a_served_bind(stored_bind):
    """The bind this process listens on (app.config BOOT_BIND, canonical), else `stored_bind`."""
    bound = str(current_app.config.get("BOOT_BIND") or "").strip()
    return _r11c_canonical_bind(bound) if bound else stored_bind


def _r34j_bind_now(cfg, cur_bind):
    """The bind an unchanged change-port form is compared with: the served one only when bind_host is STORED.

    Unset, the form shows the 0.0.0.0 default while the boot may have resolved loopback (Serve), and
    compared with the served bind an unchanged Apply restarted the panel onto every interface. Unset
    keeps the rule from before: the default again is already the binding.
    """
    return _r34a_served_bind(cur_bind) if _r13a_cfg_text(cfg, "bind_host") else cur_bind


def _r18a_bracketed(host):
    """`host` as it reads before a `:port`: an IPv6 address in brackets (`:::5000` names nothing)."""
    return "[%s]" % host if ":" in (host or "") and not host.startswith("[") else host


def _r15e_with_notes(head, notes):
    """The reply's sentence, then each firewall note — every one translated whole, then joined.

    The notes were one English string appended to the sentence, so the reply never matched a key.
    """
    return " ".join(i18n.tr(s) for s in [head] + list(notes))


def _port_refusal(local, cur_port, new_port):
    """Why the panel must not listen on `new_port`, or None when it may."""
    # ── Validate the port ──
    # The bound now lives in _port_or (shared with the setup wizard, which writes the SAME
    # config key and used to write it unchecked). Kept as an explicit branch so the refusal
    # still carries its own message.
    if new_port is None:
        return i18n.tr("Pick a port between {lo} and {hi}.", lo=MIN_UNPRIVILEGED_PORT, hi=MAX_PORT)
    if new_port != cur_port:
        clash = GameServer.query.filter_by(remote_id=local.id, port=new_port).first() if local else None
        if clash:
            return i18n.tr("Port {port} is used by game server '{name}'. Pick another.",
                           port=new_port, name=clash.name)
        if so.port_in_use(new_port):
            return i18n.tr("Port {port} is already in use on this host.", port=new_port)
    return None


def _r25j_binding_refusal(local, cfg, cur_port, new_port, new_bind, stored_port=None):
    """Why the panel must not move to `new_bind`:`new_port`, or None when it may.

    `cur_port` is the port the panel serves on now, `stored_port` config.json's (None: the same).
    The record last: it is the one refusal that writes (root's panel.conf), so only a move every
    other check allowed is recorded.
    """
    return (_port_refusal(local, cur_port, new_port)
            or _bind_refusal(bool(cfg.get("tailscale_setup_done")), new_bind)
            or _r25j_port_not_recorded(cur_port, new_port, stored_port))


def _r25j_port_not_recorded(cur_port, new_port, stored_port=None):
    """Why the move to `new_port` must stop here, or None: the helper would not record it.

    Before anything is saved. The helper publishes only the port it has recorded as the panel's,
    so an unrecorded move would come back up behind a Serve route the helper refuses to re-point.
    It also refuses a port another account is listening on, which _port_refusal's `ss` read can
    miss (that read answers "free" when it cannot run). A move back to the served port while
    another one is saved is recorded too: the record may still name the saved one.
    """
    if new_port == cur_port and stored_port in (None, cur_port):
        return None
    ok, why = so.record_panel_port(new_port)
    if ok:
        return None
    return i18n.tr("Port {port} could not be recorded as the panel's port, so nothing was "
                   "changed ({why}).", port=new_port, why=why)


def _r11c_canonical_bind(bind):
    """`bind` in canonical form: "0:0:0:0:0:0:0:1" and "0::1" are ::1.

    Stored and judged that way because the loopback guard in _bind_refusal once compared the TEXT,
    so those spellings bound the panel to loopback with no Serve in front of it. Text that is not
    an IP is returned as typed (and refused there).
    """
    return canonical_ip(bind) or bind


def _bind_refusal(served, new_bind):
    """Why the panel must not bind to `new_bind`, or None when it may.

    `served` is whether Tailscale Serve is set up to proxy to the panel on localhost.
    """
    # nosec B104 - the set of wildcard addresses to RECOGNISE, so the code below
    # can tell "listening everywhere" from loopback. Detecting a value is not
    # binding to it.
    wildcard = {"0.0.0.0", "::"}  # nosec B104
    loopback = {"127.0.0.1", "::1", "localhost"}
    addr = ip_address_or_none(new_bind)
    # Judged on the parsed address, not the text: any spelling of ::1 or of a 127/8 address is
    # loopback, and a loopback bind without Serve locks the panel out (as _panel_bind_is_public
    # and app._bind_is_loopback already read it).
    is_loopback = addr is not None and addr.is_loopback
    # ── Validate the bind address ──
    if new_bind not in wildcard:
        # A zone id is not an address to bind (see panel/core/validation.py).
        if addr is None:
            return ("Bind address must be an IP — e.g. 0.0.0.0 (all "
                    "interfaces), 127.0.0.1 (localhost), or this host's "
                    "Tailscale IP.")
        # With Tailscale Serve the one bind besides the wildcard is Serve's own upstream,
        # 127.0.0.1 (privileged.ts_serve_argv hardcodes it). Any other address breaks Serve and
        # locks you out — ::1 too: it is loopback, but an IPv6 socket on ::1 refuses Serve's
        # IPv4 connection, and the move closes the public port as well. It passed while this
        # tested "not in loopback", and the page then showed the stored ::1 as 127.0.0.1.
        # (new_bind is canonical here, so no other spelling of 127.0.0.1 reaches this.)
        if served and new_bind != "127.0.0.1":
            return ("Tailscale Serve reaches the panel on localhost, so "
                    "bind to 0.0.0.0 (all) or 127.0.0.1 (localhost). A "
                    "specific IP would break Serve and lock you out.")
        if new_bind not in loopback:
            # A specific IP without Serve: it must at least be a real local IP.
            if not so.host_has_ip(new_bind):
                return i18n.tr("{address} isn't an address on this host — the panel couldn't bind "
                               "to it.", address=new_bind)
    if is_loopback and not served:
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

    -> (the reply's notes, whether the firewall now matches the binding, the address families whose
    public rule for the old port the close really removed). With no local host row there is no
    firewall to follow, which is not a failure.
    Each note is a whole i18n.Sentence: English in the audit row, translated in the reply.
    """
    # ── Bring the firewall in line with the resulting exposure ──
    # Reached on its port (the wildcard, or the host's own public/LAN address) → the port must
    # be open. Loopback/tailnet-bound → the public port rule isn't needed, so close it. A
    # changed port also gets its old rule gone.
    now_public = _panel_bind_is_public(new_bind)
    fw_notes, fw_ok, old_removed = [], True, ()
    if local:
        # Each of these returns (ok, msg) and all three were called for effect, with fw_note
        # assigned on the next line regardless — so the panel could restart onto a port the
        # firewall does not allow having just said "Firewall: opened 5055.", on the one route
        # whose docstring is "Refuses anything that would leave the panel unreachable".
        try:
            if now_public:
                _fw_ok, _fw_msg = remote_ufw_open_port(local, new_port, "tcp", "LinuxGSM Panel")
                fw_notes.append(i18n.Sentence("Firewall: opened {port}.", port=new_port) if _fw_ok
                                else i18n.Sentence("FIREWALL NOT UPDATED — port {port} may be blocked "
                                                   "({why}).", port=new_port, why=_fw_msg))
            else:
                # force: the panel's own move (the config already names new_port, so the guard
                # would read this as the panel's web-port rule and refuse to close it).
                _fw_ok, _fw_msg = remote_ufw_close_port(local, new_port, "tcp", force=True)
                fw_notes.append(i18n.Sentence("Firewall: {port} kept tailnet-only.", port=new_port)
                                if _fw_ok else
                                i18n.Sentence("Firewall rule for {port} could not be removed ({why}).",
                                              port=new_port, why=_fw_msg))
            fw_ok = bool(_fw_ok)
            if new_port != cur_port:
                _gone = []
                _old_ok, _old_msg = remote_ufw_close_port(local, cur_port, "tcp", force=True, deleted=_gone)
                fw_notes.append(i18n.Sentence("Removed the old rule for {port}.", port=cur_port)
                                if _old_ok else
                                i18n.Sentence("The old rule for {port} is still there ({why}).",
                                              port=cur_port, why=_old_msg))
                fw_ok = fw_ok and bool(_old_ok)
                # What the delete removed, by ufw's words, not its answer: that answer is "no public
                # rule lets the port in now", True too for a port the operator had already closed
                # or opened only from one address, and the rollback re-opened those to everyone.
                old_removed = tuple(_gone)
        except Exception:
            app.logger.warning("change-port: firewall update failed", exc_info=True)
            fw_notes.append(i18n.Sentence("The firewall could not be updated."))
            fw_ok = False
    return fw_notes, fw_ok, old_removed


def _r32a_close_unapplied_port(app, local, stored_port, cur_port, new_port, fw_notes):
    """Close the rule a move that never applied opened, when this move leaves its port behind.

    -> whether that went as it should (True when there was nothing to do). A move whose restart
    could not be scheduled keeps the rule it opened for the saved port (_r30b_keep_old_port: the
    restart still needs it). Once a later move replaces that saved port, nothing will ever listen
    there, and its rule was left open for good. The served port is not this one: the move's own
    close handles it (and puts it back if this restart fails as well).
    """
    if not local or stored_port in (cur_port, new_port):
        return True
    try:
        ok, why = remote_ufw_close_port(local, stored_port, "tcp", force=True)
    except Exception:
        app.logger.warning("change-port: the unapplied port's rule could not be removed", exc_info=True)
        ok, why = False, "error"
    fw_notes.append(i18n.Sentence("Removed the rule for {port}, the port of the earlier change that never "
                                  "applied.", port=stored_port) if ok else
                    i18n.Sentence("The rule for {port}, the port of the earlier change that never applied, "
                                  "is still there ({why}).", port=stored_port, why=why))
    return bool(ok)


def _r30b_keep_old_port(app, local, cur_port, new_port, old_removed):
    """After a restart that could not be scheduled: keep the panel reachable where it still listens.

    -> (the reply's notes, the audit row's words). The binding change removed `cur_port`'s rule (in
    the address families `old_removed` names) and pointed the login jail at `new_port` before
    restarting; with no restart, a publicly bound panel kept listening on `cur_port` behind a
    firewall that now dropped it, and nothing in the panel could be reached to restart it (review
    1017a). The new port's rule stays: the saved binding
    still needs it once the panel restarts, and the boot points the jail at that port again.
    """
    if new_port == cur_port:
        return [], "binding port unchanged"
    notes, audit = [], []
    # Exactly what the close removed and nothing more: a port the operator had closed, rate limited
    # or opened only from one address was not removed, so nothing is added for it, and an IPv4-only
    # rule comes back without an IPv6 twin. (This used to be gated on a publicly reached binding,
    # because "removed" was the close's answer and ufw answers 0 to deleting a rule that is not
    # there; what ufw said it deleted needs no such stand-in.)
    if old_removed and local:
        try:
            _ok, _why = remote_ufw_put_back_tcp(local, cur_port, old_removed, "LinuxGSM Panel")
        except Exception:
            app.logger.warning("change-port: the old port's rule could not be put back", exc_info=True)
            _ok, _why = False, "error"
        notes.append(i18n.Sentence("Put the rule for {port} back, so the panel stays reachable there until it "
                                   "restarts.", port=cur_port) if _ok else
                     i18n.Sentence("The rule for {port} could not be put back ({why}), and the panel still "
                                   "listens there.", port=cur_port, why=_why))
        audit.append("old rule for %s %s" % (cur_port, "put back" if _ok else "NOT put back"))
    f2b_ok, f2b_msg = _follow_binding_in_fail2ban(app, cur_port, new_port)
    if not f2b_ok:
        notes.append(i18n.Sentence("fail2ban could not be pointed back at port {port}.", port=cur_port))
    audit.append("fail2ban back on %s: %s" % (cur_port, f2b_msg))
    # The helper's record too: it publishes only the port panel.conf names, and the move recorded
    # new_port, so Enable on the Tailscale page (which publishes the port this process serves on)
    # was refused until the restart. The boot records the port it binds (reconcile_panel_port).
    rec_ok, rec_why = so.record_panel_port(cur_port)
    if not rec_ok:
        notes.append(i18n.Sentence("Port {port} could not be recorded back as the panel's port for Tailscale "
                                   "Serve ({why}).", port=cur_port, why=rec_why))
    audit.append("helper port record back on %s: %s" % (cur_port, "ok" if rec_ok else rec_why))
    return notes, "; ".join(audit)
