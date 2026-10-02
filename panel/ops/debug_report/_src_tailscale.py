"""The ONE Tailscale read per report, shared by R36, R49 and R72's name list. Owner: builder B3.

info() -> dict or None
    From panel.ops.tailscale_integration.get_tailscale_info() WITHOUT force_refresh (its 15 s
    cache), plus the fields R36/R49 need from the same status/prefs JSON. No second CLI call, no
    ping. Never raises: None when tailscale is absent or unreadable.

The dict (every key always present):
    installed, running            bool
    backend_state                 str, Tailscale's own word ("Running", "NeedsLogin", ...)
    version                       str, the first line of `tailscale version`
    hostname, dns_name            str: IDENTIFYING. For R72's name list and R49's matching; never print
    ips                           list of str: IDENTIFYING, as above
    magic_dns                     bool
    serve_unreadable              bool: `tailscale serve status` did not answer (not "no routes")
    serve_services                list of {"url", "funnel", "routes": [{"mount", "target"}]}: the URL
                                  is IDENTIFYING; mounts and loopback targets are the panel's own
    funnel_enabled                bool, what Serve says
    peers                         list of tailscale_integration's peer dicts: IDENTIFYING fields
                                  (hostname, dns_name, ips); online, os, last_seen, relay are not
    key_expiry                    str (RFC 3339) or None when not recorded
    health                        list of str or None when not recorded: FREE TEXT, print a count
    operator_user                 str or None when not recorded: compare, never print
    run_ssh                       bool or None when not recorded
    magic_dns_suffix, tailnet_name  str or None when not recorded: IDENTIFYING
    user_logins                   list of str (LoginName and DisplayName): IDENTIFYING
    extras_recorded               bool: whether the status/prefs JSON was kept by this panel's
                                  tailscale_integration (the fields above that say "or None")

The "or None" fields come from the status and prefs JSON that tailscale_integration already reads.
It keeps them on the TailscaleInfo as `status_json` and `prefs_json` when it does; until then they
read as None ("not recorded"), never as False or empty.

read() -> ("ok", dict) | ("absent", None) | ("error", "<ExceptionClass>"): info() with its two
    Nones told apart.

cached() -> the same dict built from whatever is already cached, or None; never runs the CLI.
"""
from panel.ops import tailscale_integration as ts


def _dict(value):
    return value if isinstance(value, dict) else {}


def _logins(users):
    """Every LoginName and DisplayName of status JSON's "User" map."""
    out = []
    for u in _dict(users).values():
        out += [str(u[k]) for k in ("LoginName", "DisplayName") if _dict(u).get(k)]
    return out


def _status_extras(status):
    """Fields from `tailscale status --json` that TailscaleInfo does not carry on its own."""
    status = _dict(status)
    health = status.get("Health")
    return {"key_expiry": _dict(status.get("Self")).get("KeyExpiry") or None,
            "health": list(health) if isinstance(health, list) else None,
            "magic_dns_suffix": status.get("MagicDNSSuffix") or None,
            "tailnet_name": _dict(status.get("CurrentTailnet")).get("Name") or None,
            "user_logins": _logins(status.get("User"))}


def _prefs_extras(prefs):
    """Fields from `tailscale debug prefs` beyond RouteAll."""
    prefs = prefs if isinstance(prefs, dict) else {}
    run_ssh = prefs.get("RunSSH")
    return {"operator_user": prefs.get("OperatorUser") if "OperatorUser" in prefs else None,
            "run_ssh": run_ssh if isinstance(run_ssh, bool) else None}


def as_dict(ti):
    """The report's view of one TailscaleInfo (see the module docstring)."""
    status = getattr(ti, "status_json", None)
    prefs = getattr(ti, "prefs_json", None)
    out = {"installed": bool(ti.installed), "running": bool(ti.running),
           "backend_state": str(ti.backend_state or ""), "version": str(ti.version or ""),
           "hostname": str(ti.hostname or ""), "dns_name": str(ti.dns_name or ""),
           "ips": list(ti.tailscale_ips or []), "magic_dns": bool(ti.magic_dns_enabled),
           "serve_unreadable": bool(getattr(ti, "serve_unreadable", False)),
           "serve_services": list((ti.serve_config or {}).get("services") or []),
           "funnel_enabled": bool(ti.funnel_enabled), "peers": list(ti.peers or []),
           "extras_recorded": isinstance(status, dict)}
    out.update(_status_extras(status))
    if not isinstance(status, dict):
        out["key_expiry"] = out["health"] = None
    out.update(_prefs_extras(prefs))
    return out


def read():
    """("ok", dict) | ("absent", None) | ("error", exception class name). Never raises.

    info()'s answer with the two kinds of None told apart, for a section that must not print
    "not installed" for a status it could not read.
    """
    try:
        ti = ts.get_tailscale_info()
    except Exception as exc:  # noqa: BLE001 - reported as its class
        return "error", type(exc).__name__
    if ti is None or not ti.installed:
        return "absent", None
    try:
        return "ok", as_dict(ti)
    except Exception as exc:  # noqa: BLE001
        return "error", type(exc).__name__


def info():
    """The cached Tailscale reading as a dict, or None when tailscale is absent or unreadable."""
    state, val = read()
    return val if state == "ok" else None


def cached():
    """What info() would answer from the cache alone, without ever running the CLI; else None."""
    try:
        ti = (getattr(ts, "_cache", None) or {}).get("info")
        if ti is None or not ti.installed:
            return None
        return as_dict(ti)
    except Exception:  # noqa: BLE001
        return None
