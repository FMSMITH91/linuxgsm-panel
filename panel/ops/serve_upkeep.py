"""Keeping the panel published over Tailscale Serve at ONE mount, and naming the address that works.

Moved out of app.py, which had grown past Codacy's file-length limit (1700 lines of code) with them.
app.py's _boot_serve, the setup wizard (panel/routes/route_helpers.py) and the Tailscale page
(panel/routes/tailscale.py) call these. Nothing here imports app: app.py imports this module, and the
routes import a second copy of app, so the one app-side answer these need (_serve_scheme_now, the
scheme this process really serves) is passed in by the caller.
"""
import logging

from panel.db.models import LOCAL_HOST_LABEL
from panel.ops import tailscale_integration as ts
from panel.ops.debug_report import process as _dr_process
from panel.security.auth import log_action

_log = logging.getLogger("panel.app")


def _panel_tailscale_url(conf, stored, scheme_now):
    """The panel's own Tailscale Serve address, for the setup-complete page, or None.

    `conf` is the app's config, `stored` config.json, `scheme_now` app._serve_scheme_now. It was
    https://<MagicDNS name>, the root, whenever the node had a name: with no Serve route at all, and
    right after the wizard's finish had published the panel at /lgsm because another app held "/".
    Now the panel's route at tailscale_mount, on the scheme this process serves.
    """
    try:
        route = ts.panel_route(ts.get_tailscale_info().serve_config,
                               conf.get("BOOT_PORT") or stored.get("port", 5000),
                               stored.get("tailscale_mount"), scheme_now(stored, conf))
    except Exception:
        _log.debug("inject_globals: ignored non-fatal error", exc_info=True)
        return None
    return ts.route_url(route) if route is not None else None


def _boot_audit(flask_app, detail, ok, action="tailscale_serve_leftover_removed"):
    """One audit row from boot, outside any request (as _f2b_record_events writes its rows)."""
    try:
        with flask_app.test_request_context():
            log_action(None, action, target=LOCAL_HOST_LABEL, detail=detail, success=ok)
    except Exception:
        _log.debug("boot audit row not written", exc_info=True)


def _boot_shared_funnel(app, cfg, port, audit=None):
    """Put on record a panel the boot left on Funnel, against its own setting, for another app.

    `audit` is app.py's _boot_audit (this module's when None), passed so app's own name is the one
    called.

    Funnel is per listener, and the re-point keeps the shared :443 listener's Funnel as it is
    (setup_tailscale_serve's keep_shared_funnel) rather than take the other app off the internet.
    With it on and tailscale_use_funnel off, the panel is reachable from the internet; read back
    from the host, and said in the audit log, not only in a log line.
    """
    try:
        serve_config = ts.get_tailscale_info().serve_config
        use_funnel = bool(cfg.get("tailscale_use_funnel", False))
        others = ts.shared_funnel_apps(serve_config, port, use_funnel)
        kept_off = _r13a_kept_off(serve_config, port, use_funnel)
    except Exception:
        _log.debug("shared-Funnel read at boot failed", exc_info=True)
        return
    if others:
        (audit or _boot_audit)(
            app, "at boot: Funnel is on for the whole :443 listener because %s uses it, so the "
                 "panel is reachable from the internet too, although its own Funnel setting is off"
                 % ts._r12a_apps_at(others), True, action="tailscale_serve_funnel_shared")
    elif kept_off:
        # The other direction, which nothing reported: the panel's setting says Funnel, the
        # re-point kept the shared listener's Funnel OFF, so the panel is tailnet-only.
        (audit or _boot_audit)(
            app, "at boot: Funnel is off for the whole :443 listener because %s shares it without "
                 "Funnel, so the panel is tailnet-only, although its own Funnel setting is on"
                 % ts._r12a_apps_at(kept_off), True, action="tailscale_serve_funnel_shared")


def _r13a_kept_off(serve_config, port, use_funnel):
    """The other apps' mounts when the boot kept the shared :443 listener's Funnel off against the
    panel's own setting (on); [] otherwise. The mirror of ts.shared_funnel_apps."""
    shared, others = ts._r12a_listener_funnel(serve_config, port)
    if shared or not use_funnel or not others:
        return []
    return others if ts._r13a_panel_on_listener(serve_config, port) else []


def _remove_serve_leftovers(panel_port, mount, where, audit):
    """Remove the panel's own :443 Serve routes at mounts other than `mount`; return the outcome.

    The outcome is what app.config["BOOT_SERVE_LEFTOVERS"] holds: "none", "unread" (Serve could not
    be read, so nothing was removed), "removed:<mount>,<mount>" or "failed:<fixed reason class>".
    `audit(detail, ok)` writes one row per route removed, and one for a removal that failed — the
    only privileged way to run `off` is the operator setting (the helper's Serve verb publishes,
    it never removes), so a host where that did not take fails here, and that has to be on record.
    """
    try:
        state, removed, err = ts.remove_stale_panel_routes(panel_port, mount)
    except Exception as e:
        _log.debug("leftover Serve route cleanup failed", exc_info=True)
        return "failed:" + type(e).__name__
    for m in removed:
        audit("%s: removed the panel's old Tailscale Serve route at %s on :443 (the panel is "
              "published at %s)" % (where, m, mount), True)
    if state == "failed":
        audit("%s: could not remove a Tailscale Serve route to the panel at a mount other than %s: "
              "%s" % (where, mount, err), False)
        return "failed:" + _dr_process.serve_reason(err)
    if state == "removed":
        return "removed:" + ",".join(removed)
    return state


def _leftover_note(outcome):
    """What the answer to a Serve write adds about the panel's routes at other mounts.

    `outcome` is _remove_serve_leftovers' answer. Nothing for "none".
    """
    if outcome.startswith("removed:"):
        return (" — and the panel's old route at %s was removed."
                % outcome[len("removed:"):].replace(",", ", "))
    if outcome.startswith("failed:"):
        return (" — but a route to the panel at another mount could not be removed (%s). Remove it "
                "with: sudo tailscale serve --https=443 --set-path=<that mount> off"
                % outcome[len("failed:"):])
    if outcome == "unread":
        return (" — but this host's Serve configuration could not be read afterwards, so a route "
                "to the panel at another mount may still be there.")
    return ""


def _tailscale_banner(stored, panel_port, conf, info, scheme_now):
    """The startup banner's Tailscale lines: only addresses that reach THIS panel.

    It printed https://<MagicDNS name> whether or not Serve published the panel there. That is the
    root, "/", and a panel at /lgsm is not there: on a host whose "/" held another app the banner
    named the other app, and on one with a leftover "/" route it named a 502. The Serve line is now
    the panel's own route at tailscale_mount, and only while it is on the scheme this process
    serves (`scheme_now` is app._serve_scheme_now); the Funnel line follows that route's own
    listener, not "any app is funnelled". The tailnet-IP fallback said http:// for a panel serving
    TLS, and showed for a panel bound to loopback, where nothing on the tailnet can reach the port.
    """
    lines = []
    route = ts.panel_route(info.serve_config, panel_port, stored.get("tailscale_mount"),
                           scheme_now(stored, conf))
    bind = str(conf.get("BOOT_BIND") or "")
    if route is not None:
        lines.append("\n  🌐 Tailscale: %s" % ts.route_url(route))
        if route["funnel"]:
            lines.append("  🌍 Funnel (public): %s" % ts.route_url(route))
    elif info.tailscale_ips and (bind in ("0.0.0.0", "::", "") or bind in info.tailscale_ips):  # nosec B104 - compared, never bound
        scheme = "https" if conf.get("BOOT_TLS") else "http"
        addr = info.tailscale_ips[0]
        lines.append("\n  🌐 Tailscale IP: %s://%s:%s" % (
            scheme, "[%s]" % addr if ":" in addr else addr, panel_port))
    return lines
