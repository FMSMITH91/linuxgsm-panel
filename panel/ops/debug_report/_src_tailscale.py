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
    key_expiry                    str (RFC 3339), or one of KEY_DISABLED / KEY_NO_NETMAP /
                                  KEY_NO_FIELD (why there is none), or None when not recorded
    health                        list of str or None when not recorded: FREE TEXT, Tailscale's own
                                  messages; printed only through the privacy pass (network.py)
    control_host                  str or None: the control server's host when it is NOT Tailscale's
                                  own (a self-hosted one): IDENTIFYING, for R72's name list only
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

shared_read(ctx) / shared_info(ctx) -> read() / info() through the report's memo (key MEMO_KEY), so
every section and the privacy pass share ONE reading per report. Sections call these, never read()
or info() directly.
"""
import re

from panel.ops import tailscale_integration as ts

# Why a status carries no Self.KeyExpiry. Tailscale leaves the field out when the node's expiry
# is disabled (tailcfg's zero KeyExpiry: a tagged node, or expiry turned off in the admin console),
# but it also builds Self with no netmap at all (NeedsLogin, logged out, before the first netmap),
# and before v1.36 it never sent the field.
KEY_DISABLED = "disabled"
KEY_NO_NETMAP = "no-netmap"
KEY_NO_FIELD = "no-field"
# Tailscale's own control servers: a host that names no one, so it is not mapped.
_DEFAULT_CONTROL = frozenset(("controlplane.tailscale.com", "login.tailscale.com"))


def _dict(value):
    return value if isinstance(value, dict) else {}


def _logins(users):
    """Every LoginName and DisplayName of status JSON's "User" map."""
    out = []
    for u in _dict(users).values():
        out += [str(u[k]) for k in ("LoginName", "DisplayName") if _dict(u).get(k)]
    return out


def _reports_key_expiry(version):
    """Whether this Tailscale version sends Self.KeyExpiry at all (v1.36 and later)."""
    m = re.match(r"(\d+)\.(\d+)", str(version or ""))
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (1, 36)


def _key_expiry(status, version):
    """Self.KeyExpiry, or why it is absent (KEY_*); None when there is no Self to read."""
    me = status.get("Self")
    if not isinstance(me, dict):
        return None
    if me.get("KeyExpiry"):
        return me["KeyExpiry"]
    if me.get("InNetworkMap") is not True:
        return KEY_NO_NETMAP
    return KEY_DISABLED if _reports_key_expiry(version) else KEY_NO_FIELD


def _status_extras(status, version=""):
    """Fields from `tailscale status --json` that TailscaleInfo does not carry on its own."""
    status = _dict(status)
    health = status.get("Health")
    return {"key_expiry": _key_expiry(status, version),
            "health": list(health) if isinstance(health, list) else None,
            "magic_dns_suffix": status.get("MagicDNSSuffix") or None,
            "tailnet_name": _dict(status.get("CurrentTailnet")).get("Name") or None,
            "user_logins": _logins(status.get("User"))}


def _control_host(url):
    """The host of prefs' ControlURL when it is not Tailscale's own control server, else None."""
    from urllib.parse import urlsplit
    try:
        host = (urlsplit(str(url or "")).hostname or "").lower()
    except ValueError:
        return None
    return host if host and host not in _DEFAULT_CONTROL else None


def _prefs_extras(prefs):
    """Fields from `tailscale debug prefs` beyond RouteAll."""
    prefs = prefs if isinstance(prefs, dict) else {}
    run_ssh = prefs.get("RunSSH")
    return {"operator_user": prefs.get("OperatorUser") if "OperatorUser" in prefs else None,
            "run_ssh": run_ssh if isinstance(run_ssh, bool) else None,
            "control_host": _control_host(prefs.get("ControlURL"))}


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
    out.update(_status_extras(status, out["version"]))
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


# The one memo key for the report's Tailscale reading (network's R36, hosts' R49, privacy's R72).
MEMO_KEY = "tailscale_read"


def shared_read(ctx, wait=None):
    """read(), once per report: every caller gets the same ("ok"|"absent"|"error", value).

    `wait`: how long to wait for a read another section is making (default: the deadline).
    """
    return ctx.memo(MEMO_KEY, read, wait=wait)    # the module's read, looked up at this call


def shared_info(ctx):
    """info() from the report's one reading: the dict, or None when absent or unreadable."""
    state, val = shared_read(ctx)
    return val if state == "ok" else None
