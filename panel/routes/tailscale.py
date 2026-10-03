"""Tailscale status, Serve and Funnel for the panel itself.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (current_app, jsonify, render_template, request)
from flask_login import (current_user, login_required)
from panel.core.config import (load_config, save_config)
from panel.security import privileged as _priv
from panel.ops import (tailscale_integration as ts)
from panel.security.auth import (MANAGE_REMOTES, log_action, permission_required,
    superadmin_required)
from panel.core.http import (_json_body, _json_str)
from panel.db.models import LOCAL_HOST_LABEL
from app import (_bind_is_loopback, _effective_https, _leftover_note, _remove_serve_leftovers,
    _resolved_bind, _serve_scheme_now)


def _sees_panel_host_tailnet(user):
    """Whether `user` is shown the PANEL HOST's tailnet identity and inventory.

    That means its name, tailnet IPs and MagicDNS name, its Serve mappings and their backends, and
    every peer on the tailnet.

    Superadmins only. This page is gated on MANAGE_REMOTES, which is granted per host — a delegated
    admin for one rented VPS holds it — and none of this is about a host they were granted. It is
    the panel host's, whose management (System -> Panel Server) is superadmin-only, and the peer
    list is the operator's whole tailnet: other servers they were not granted, and personal devices
    ("alice-iphone", "nas") with their addresses, OS and when each was last online.
    """
    return bool(getattr(user, "is_superadmin", False))


def _panel_scheme(cfg):
    """How the panel is serving its own port right now — self-signed https by default."""
    return "https" if _effective_https(cfg) else "http"


def _serve_default_mount(info, cfg, port):
    """The mount the Enable form offers.

    Enabling Serve at a mount another app already holds REPLACES that app's mapping, and the form
    offered "/" without looking — the setup wizard already moves the panel to /lgsm when "/" is
    taken, and this is the same rule (ts.free_panel_mount, which both use). When both are another
    app's, the stored mount is offered and the operator chooses.
    """
    mount = cfg.get("tailscale_mount") or "/"
    return ts.free_panel_mount(info.serve_config, port, mount) or mount


def _disable_would_strand_panel(cfg):
    """Why removing Serve now would leave nothing able to reach the panel, or "" when it would not.

    A panel bound to loopback is reached ONLY through Serve. Removing the mapping ends the session
    the admin is using, and nothing else can reach the process; a restart does not help either,
    because the stored bind is still 127.0.0.1 and the boot path re-applies Serve only while
    tailscale_setup_done is set, which the disable clears. Getting back in took host SSH and
    linuxgsm-panel-recover. /api/panel/change-port refuses to create this same state ("Binding to
    localhost only would lock you out unless Tailscale Serve is set up"); this is that rule seen
    from the other side. The bind is the RESOLVED one: an unset bind_host that boot resolved to
    127.0.0.1 is just as stranded until someone restarts the panel from the host.
    """
    if not _bind_is_loopback(_resolved_bind(cfg)):
        return ""
    return ("The panel is bound to localhost only, so Tailscale Serve is the only way to reach it. "
            "Disabling Serve would lock you out. Change the panel's bind address to 0.0.0.0 "
            "(all interfaces) under System → Panel Server first, then disable Serve.")


def _serve_audit(detail, ok):
    """One audit row about a leftover Serve route, as the signed-in superadmin."""
    log_action(current_user, "tailscale_serve_leftover_removed", target=LOCAL_HOST_LABEL,
               detail=detail, success=ok)


def _serve_enable(port, mount, funnel):
    """Publish the panel at `mount`, then take down its own routes at any other mount on :443.

    Moving the mount here left the old route behind, on the scheme it was written with: a second
    address for the panel that nothing re-points, and a 502 from the next flip of the panel's
    scheme. The scheme written is the one this process serves now (_serve_scheme_now): the stored
    answer is the NEXT start's, and differs while a bind change waits for a restart.
    """
    cfg = load_config()
    success, msg = ts.setup_tailscale_serve(port=port, mount=mount, funnel=funnel,
                                            backend_scheme=_serve_scheme_now(cfg, current_app.config))
    if not success:
        return jsonify({"success": False, "message": msg}), 500
    cfg = load_config()
    cfg["tailscale_setup_done"] = True
    cfg["tailscale_use_funnel"] = funnel
    cfg["tailscale_mount"] = mount
    save_config(cfg)
    log_action(current_user, "tailscale_serve_enable", target=LOCAL_HOST_LABEL, detail=msg)
    left = _remove_serve_leftovers(port, mount, "Enable on the Tailscale page", _serve_audit)
    return jsonify({"success": True, "message": msg + _leftover_note(left)})


def _serve_disable(port, mount):
    """Stop publishing the panel: every route to it comes down (ts.disable_tailscale_serve)."""
    refusal = _disable_would_strand_panel(load_config())
    if refusal:
        return jsonify({"success": False, "message": refusal}), 400
    success, msg = ts.disable_tailscale_serve(mount=mount, port=port)
    if not success:
        return jsonify({"success": False, "message": msg}), 500
    # Mirror the enable branch. Nothing else in the repo ever cleared these, so a disable left
    # tailscale_setup_done True — which six readers treat as ground truth: one permits a
    # 127.0.0.1-only bind (lockout risk) and the boot path RE-APPLIES Serve, quietly undoing the
    # disable on the next restart.
    cfg = load_config()
    cfg["tailscale_setup_done"] = False
    cfg["tailscale_use_funnel"] = False
    cfg["tailscale_mount"] = ""
    save_config(cfg)
    log_action(current_user, "tailscale_serve_disable", target=LOCAL_HOST_LABEL, detail=msg)
    return jsonify({"success": True, "message": msg})


def _serve_remove_route(port, data):
    """Remove ONE route to the panel that the panel does not manage; the config is untouched.

    The page lists them (ts.is_managed_route), each with its own Remove, so a leftover can come down
    without Disable — which clears tailscale_mount, and with it the prefix of every link on the
    page in use. The route is named by its listener URL and mount, and read again here from the
    host: only a route that still proxies the panel's port is removed, never the one the panel is
    published at, and Serve is read once more right before the command (ts.remove_panel_route).
    """
    route, refusal = _leftover_route(port, _json_str(data, "url"), _json_str(data, "mount"))
    if refusal is not None:
        return refusal
    mount, url = route["mount"], route["url"]
    state, err = ts.remove_panel_route(route, port)
    if state == "gone":
        return jsonify({"success": True, "message": "That route was already gone."})
    if state == "removed":
        _serve_audit("removed the Tailscale Serve route to the panel at %s (%s)"
                     % (mount, ts.listener_flag(url)), True)
        return jsonify({"success": True, "message": "Removed the route at %s." % mount})
    _serve_audit("could not remove the Tailscale Serve route to the panel at %s: %s"
                 % (mount, err or state), False)
    return jsonify({"success": False, "message": (
        "Couldn't read this host's Tailscale Serve configuration, so nothing was removed."
        if state == "unread" else "Failed to remove: %s" % err)}), 500


def _leftover_route(port, url, raw_mount):
    """(the route to remove, None), or (None, the response that refuses it) — read from the host."""
    try:
        mount = ts.off_mount(raw_mount)
    except _priv.VerbError:
        return None, (jsonify({"success": False, "message": "That isn't a usable mount point."}), 400)
    info = ts.get_tailscale_info(force_refresh=True)
    if info.serve_unreadable:
        return None, (jsonify({"success": False, "message": "Couldn't read this host's Tailscale "
                               "Serve configuration, so nothing was removed."}), 500)
    ours = ts.panel_serve_routes(info.serve_config, port)
    route = next((r for r in ours if r["url"] == url and r["mount"] == mount), None)
    if route is None:
        return None, (jsonify({"success": False, "message": "No route to the panel is at %s on "
                               "that listener any more." % mount}), 404)
    cfg = load_config()
    if ts.is_managed_route(route, cfg):
        return None, (jsonify({"success": False, "message": "That is the route the panel is "
                               "published at. Use Disable to stop publishing it."}), 400)
    # The LAST route to a panel bound to localhost is the only way in: the same lock-out Disable
    # refuses (_disable_would_strand_panel), reached through the other button.
    stranded = _disable_would_strand_panel(cfg) if len(ours) == 1 else ""
    if stranded:
        return None, (jsonify({"success": False, "message": stranded}), 400)
    return route, None


def register(app):
    _register_tailscale_setup(app)
    _register_tailscale_serve(app)


def _register_tailscale_setup(app):
    """The panel host's Tailscale page, status, install and sign-in."""
    @app.route("/tailscale")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def tailscale_page():
        """Tailscale status and management page."""
        info = ts.get_tailscale_info(force_refresh=request.args.get("refresh") == "1")
        cfg = load_config()
        port = cfg.get("port", 5000)
        suggestion = ts.suggest_best_bind(port, scheme=_panel_scheme(cfg),
                                          mount=cfg.get("tailscale_mount"))
        # The Serve mappings that proxy THIS panel, read from the host. The Disable button removes
        # one of these, never "the first route listed" — Tailscale lists "/" first, and when the
        # panel sits at a sub-path "/" belongs to another app.
        panel_routes = ts.panel_serve_routes(info.serve_config, port)
        # ...and the ones among them the panel does not manage (ts.is_managed_route): each gets
        # its own Remove. Disable was the only control, and it cleared tailscale_mount, so a page
        # in use at /lgsm rebuilt every link for "/" the moment it next loaded.
        panel_leftovers = [r for r in panel_routes if not ts.is_managed_route(r, cfg)]
        return render_template("tailscale.html", info=info, config=cfg, suggestion=suggestion,
                               panel_routes=panel_routes, panel_leftovers=panel_leftovers,
                               serve_default_mount=_serve_default_mount(info, cfg, port),
                               ts_detail=_sees_panel_host_tailnet(current_user))

    @app.route("/api/tailscale")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_tailscale():
        """JSON endpoint with live Tailscale info."""
        info = ts.get_tailscale_info(force_refresh=True)
        out = {
            "installed": info.installed,
            "running": info.running,
            "backend_state": info.backend_state,
            "version": info.version,
            "magic_dns_enabled": info.magic_dns_enabled,
            "funnel_enabled": info.funnel_enabled,
        }
        if _sees_panel_host_tailnet(current_user):
            out.update({
                "hostname": info.hostname,
                "dns_name": info.dns_name,
                "tailscale_ips": info.tailscale_ips,
                "peer_count": len(info.peers),
                "serve": info.serve_config,
                "suggestion": ts.suggest_best_bind(load_config().get("port", 5000),
                                                   scheme=_panel_scheme(load_config()),
                                                   mount=load_config().get("tailscale_mount")),
            })
        return jsonify(out)

    # superadmin, not MANAGE_REMOTES, on all three below. These act on the PANEL HOST, not on a
    # granted remote — get_remote never runs, so a host admin scoped to one VPS was changing the
    # machine the panel itself runs on. Their equivalents under System -> Panel Server are already
    # superadmin: /api/server-management/ts-ssh-enable is the same state change as `up` (which
    # hardcodes enable_ssh=True), and /api/panel/change-port is the same class of change as
    # `serve`, which with funnel=true publishes the panel to the public internet and rewrites
    # config.json. Whoever opens the login URL `up` returns also chooses the tailnet this host
    # joins, with SSH enabled.
    @app.route("/api/tailscale/install", methods=["POST"])
    @login_required
    @superadmin_required
    def api_tailscale_install():
        """Install Tailscale on the PANEL HOST itself.

        This is the same in-panel flow the setup wizard and the remote-server bootstrap use, instead
        of sending the user off to tailscale.com to do it by hand.
        """
        ok, log = ts.install_tailscale_local()
        log_action(current_user, "tailscale_install_local", target=LOCAL_HOST_LABEL, success=ok)
        return jsonify({"success": ok, "log": log})

    @app.route("/api/tailscale/up", methods=["POST"])
    @login_required
    @superadmin_required
    def api_tailscale_up():
        """Run `tailscale up` on the panel host and return the browser login URL.

        Opening that URL approves this machine; the reply says connected=True instead if it's
        already on the tailnet.
        """
        ok, res = ts.tailscale_up_local(enable_ssh=True)
        # Logged BEFORE the branching, on every outcome. log_action used to sit inside the
        # ALREADY_CONNECTED arm — the one where nothing changed — so the failure path and the path
        # that actually starts the join (returning the login URL that decides which tailnet this
        # host joins, with SSH on) both returned with the audit log silent. Its two siblings,
        # api_tailscale_install and api_remote_tailscale_up, both log unconditionally.
        log_action(current_user, "tailscale_up_local", target=LOCAL_HOST_LABEL, success=ok,
                   detail=("already connected" if res == "ALREADY_CONNECTED"
                           else "login URL issued" if ok else "failed"))
        if not ok:
            return jsonify({"success": False, "message": res})
        if res == "ALREADY_CONNECTED":
            return jsonify({"success": True, "connected": True})
        return jsonify({"success": True, "connected": False, "auth_url": res})


def _register_tailscale_serve(app):
    """Tailscale Serve for the panel, and the peer check."""
    @app.route("/api/tailscale/serve", methods=["POST"])
    @login_required
    @superadmin_required
    def api_tailscale_serve():
        """Enable/disable Tailscale Serve for the panel."""
        data = _json_body()
        action = data.get("action", "enable")
        port = load_config().get("port", 5000)
        if action == "remove-route":
            return _serve_remove_route(port, data)
        if action not in ("enable", "disable"):
            return jsonify({"success": False, "message": f"Unknown action: {action}"}), 400
        # Checked HERE as well as in setup_tailscale_serve, for the reason api_tags_create gives
        # about tag names: this is where the value came from a request, so this is where a bad one
        # can be answered as a 400 with a message the form can show. The branches below report
        # every failure as a 500 — right for "the host refused the command", wrong for "you typed
        # a mount point that isn't one", and the two are not distinguishable from a message.
        try:
            mount = _priv._ts_mount(data.get("mount", "/") or "/")
        except _priv.VerbError:
            return jsonify({"success": False,
                            "message": "That isn't a usable mount point. Use \"/\" or a short "
                                       "path like \"/lgsm\"."}), 400
        if action == "enable":
            return _serve_enable(port, mount, data.get("funnel", False))
        return _serve_disable(port, mount)

    @app.route("/api/tailscale/check-peer", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_tailscale_check_peer():
        """Check if a host is reachable on the tailnet.

        Superadmins only, for the reason _sees_panel_host_tailnet gives. The ping runs FROM the
        panel host, and MANAGE_REMOTES is granted per host: a delegated admin for one rented VPS
        was hidden the panel host's tailnet peer list on the page above, and could then map it
        anyway, and the LAN behind it, one address at a time through this box.
        """
        if not _sees_panel_host_tailnet(current_user):
            return jsonify({"success": False,
                            "message": "Only a super admin can probe from the panel host."}), 403
        data = _json_body()
        host = _json_str(data, "host")
        if not host:
            return jsonify({"success": False, "message": "Host required"}), 400
        # It becomes ping's last argv element, where a leading dash reads as an option.
        if not ts.valid_peer_host(host):
            return jsonify({"success": False,
                            "message": "Enter a hostname or IP address."}), 400
        result = ts.check_peer_reachability(host)
        is_ts = ts.is_tailscale_ip(host)
        return jsonify({
            "success": True,
            "host": host,
            "reachable": result["reachable"],
            "latency_ms": result["latency_ms"],
            "is_tailscale_ip": is_ts,
        })
