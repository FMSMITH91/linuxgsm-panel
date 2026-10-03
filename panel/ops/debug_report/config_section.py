"""Debug-report section: config (R65, R66, R67), with R37's proxy trust and R39's session cookie.

Owner: builder B1. A request-mode section: the running values come from the Flask app's config.

- Only DEBUG_CONFIG_KEYS (below) are shown, and never as typed where the value names something:
  bind_host as loopback / all interfaces / auto / [ip:class] / hostname; site_domain as set
  (a .ts.net name) / set / unset; site_title as custom / default; tailscale_mount as / or a short
  plain path, else custom; list-valued keys as counts.
- A key read once at startup shows the file AND the running value, with RESTART PENDING when they
  differ (port, bind, trust_proxy, the session values, the cookie's Secure flag).
- An unreadable config.json prints no values at all: load_config hands back the defaults then, and
  printing them would present the defaults as the operator's settings.
"""
import ipaddress
import re
from datetime import timedelta

from panel.ops.debug_report._base import Result

# Config keys that are settings/behaviour, never secrets. Everything else in
# config.json (secret_key, cred_key, credentials, host keys, TOTP, …) is excluded
# by construction — this is a whitelist, not a "strip the secrets" blacklist.
# Several of these are not printed as they are: this module prints
# bind_host, site_domain, site_title and tailscale_mount as classes, and the list-valued keys
# (trusted_proxies, trusted_proxy_users, security_whitelist, autoblock_hosts,
# socketio_cors_origins) as counts, because their values name hosts, addresses and accounts.
DEBUG_CONFIG_KEYS = (
    "port", "bind_host", "use_https", "trust_proxy", "cookie_secure",
    "tailscale_setup_done", "tailscale_auto_setup", "tailscale_mount", "tailscale_use_funnel",
    "setup_complete", "remember_days", "session_lifetime_hours",
    "session_protection", "audit_log_retention_days", "audit_ip_retention_days",
    "ssh_timeout", "site_title", "site_domain",
    "trusted_proxies", "trusted_proxy_users", "security_whitelist", "autoblock_hosts",
    "socketio_cors_origins",
)
_PLAIN_MOUNT_RE = re.compile(r"/[A-Za-z0-9_-]{0,32}\Z")
# Whitelisted keys the file-vs-running lines print; every other key of DEBUG_CONFIG_KEYS
# prints in _other_lines, through its classifier when it has one, else as a scalar or its type.
_RUNNING_KEYS = frozenset(("port", "bind_host", "trust_proxy", "trusted_proxies", "trusted_proxy_users",
                           "socketio_cors_origins", "cookie_secure", "session_lifetime_hours",
                           "remember_days", "session_protection", "use_https"))
# What an unset key means, for the keys DEFAULT_CONFIG does not carry.
_UNSET_EFFECTIVE = {"audit_log_retention_days": "0: audit rows are kept forever"}
_DEFAULT_PROXY_USERS = ("www-data", "nginx", "http", "caddy", "cloudflared")
_IGNORED_WARN_WINDOW = 3600


def _scalar(value):
    """A bool or number as it is; anything else as its type, never the free text."""
    if isinstance(value, bool) or value is None:
        return str(value).lower()
    if isinstance(value, (int, float)):
        return str(value)
    return "(a %s value)" % type(value).__name__


def addr_class(value):
    """The class a bind or peer address prints as: loopback / all interfaces / auto / [ip:...]."""
    from panel.ops.debug_report import privacy
    text = str(value or "").strip()
    if not text:
        return "auto"
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0].strip("[]"))
    except ValueError:
        return "a hostname"
    if ip.is_unspecified:
        return "all interfaces"
    cls = privacy._ip_class(ip)
    return "loopback" if cls is None else "[ip:%s]" % cls


def _domain_class(value):
    text = str(value or "").strip().lower().rstrip(".")
    if not text:
        return "unset"
    return "set (a .ts.net name)" if text.endswith(".ts.net") else "set"


def _mount_class(value):
    text = str(value or "")
    if text in ("", "/"):
        return "/ (default)"
    return text if _PLAIN_MOUNT_RE.match(text) else "custom"


def _count(value):
    if value is None:
        return "unset (default)"
    items = [value] if isinstance(value, (str, int)) else value
    try:
        return "%d entr%s" % (len(items), "y" if len(items) == 1 else "ies")
    except TypeError:
        return "(a %s value)" % type(value).__name__


def _running(ctx, key):
    """app.config[key] of the running process, or the _NO_APP marker."""
    if ctx.app is None:
        return _NO_APP
    return ctx.app.config.get(key, _NO_APP)


_NO_APP = object()


def _both(label, file_txt, run_txt, why="no app context"):
    """'- **label**: file X · running Y' with RESTART PENDING when both are known and differ.

    `run_txt` None is a running value that is not known; `why` says why, and nothing is compared.
    """
    if run_txt is None:
        return "- **%s**: file %s · running value unknown (%s)" % (label, file_txt, why)
    pending = " (RESTART PENDING)" if file_txt != run_txt else ""
    return "- **%s**: file %s · running %s%s" % (label, file_txt, run_txt, pending)


def _hours(value):
    if isinstance(value, timedelta):
        value = value.total_seconds()
    return "%d h" % (int(value) // 3600) if isinstance(value, (int, float)) else None


def _days(value):
    if isinstance(value, timedelta):
        return "%d d" % value.days
    return None


def _clamp(value, default, lo, hi):
    """app._session_lifetimes' coercion (int(float(v)), held to lo..hi), without importing app."""
    try:
        n = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return default
    return max(lo, min(n, hi))


def _session_values(ctx, cfg, res):
    hours = _clamp(cfg.get("session_lifetime_hours", 8), 8, 1, 168)
    days = _clamp(cfg.get("remember_days", 3), 3, 1, 90)
    run_h = _running(ctx, "PERMANENT_SESSION_LIFETIME")
    run_d = _running(ctx, "REMEMBER_COOKIE_DURATION")
    res.add(_both("session_lifetime_hours", "%s (%d h)" % (
        _scalar(cfg.get("session_lifetime_hours")), hours),
        None if run_h is _NO_APP else "%s (%s)" % (
            _scalar(cfg.get("session_lifetime_hours")), _hours(run_h))))
    res.add(_both("remember_days", "%s (%d d)" % (_scalar(cfg.get("remember_days")), days),
                  None if run_d is _NO_APP else "%s (%s)" % (
                      _scalar(cfg.get("remember_days")), _days(run_d))))
    prot = _running(ctx, "SESSION_PROTECTION")
    res.add(_both("session_protection", _scalar_or_word(cfg.get("session_protection")),
                  None if prot is _NO_APP else _scalar_or_word(prot)))


def _scalar_or_word(value):
    """'strong' / 'basic' as they are; anything else through _scalar."""
    if isinstance(value, str) and value in ("strong", "basic"):
        return value
    return _scalar(value)


def _cookie_lines(ctx, cfg, res):
    """R39: the session cookie's effective flags, and why Secure is what it is."""
    secure = _running(ctx, "SESSION_COOKIE_SECURE")
    if "cookie_secure" in cfg:
        reason = "cookie_secure override %s" % _scalar(cfg.get("cookie_secure"))
    else:
        reason = "cookie_secure unset → auto from use_https %s, tailscale_setup_done %s, " \
                 "trust_proxy %s" % (_scalar(cfg.get("use_https")),
                                     _scalar(cfg.get("tailscale_setup_done")),
                                     _scalar(cfg.get("trust_proxy")))
    if secure is _NO_APP:
        res.add("- **Session cookie**: unknown (no app context) · %s" % reason)
        return
    samesite = _running(ctx, "SESSION_COOKIE_SAMESITE")
    res.add("- **Session cookie**: Secure %s (%s) · HttpOnly %s · SameSite %s" % (
        "yes" if secure else "no", reason,
        "yes" if _running(ctx, "SESSION_COOKIE_HTTPONLY") is True else "no",
        samesite if samesite in ("Lax", "Strict", "None") else "unset"))
    boot_tls = _running(ctx, "BOOT_TLS")
    bind = _boot_bind(ctx)
    if secure and boot_tls is False and addr_class(bind) != "loopback" \
            and not _running(ctx, "_TRUST_PROXY"):
        res.add("- [!] Secure cookies while the process serves plain HTTP directly: browsers drop "
                "them and sign-in loops back to /login")


def _boot_bind(ctx):
    for key in ("BOOT_BIND", "_BOOT_BIND"):
        val = _running(ctx, key)
        if val is not _NO_APP:
            return val
    return None


def _no_record(ctx):
    """Why a boot-record value is unknown: no app at all, or an app that did not boot one."""
    return "no app context" if ctx.app is None else "no boot record"


def _bind_line(ctx, cfg):
    """The bind_host line: the file against the boot record.

    An unset bind_host is resolved at boot (loopback behind Tailscale Serve, else every
    interface), so its running value is shown and never compared.
    """
    bind = _boot_bind(ctx)
    stored = addr_class(cfg.get("bind_host"))
    if bind is None:
        return _both("bind_host", stored, None, _no_record(ctx))
    if stored == "auto":
        return "- **bind_host**: file auto · running %s (picked at boot)" % addr_class(bind)
    return _both("bind_host", stored, addr_class(bind))


def _bind_lines(ctx, cfg, res):
    port = _running(ctx, "BOOT_PORT")
    res.add(_both("port", _scalar(cfg.get("port")),
                  None if port is _NO_APP else _scalar(port), _no_record(ctx)))
    res.add(_bind_line(ctx, cfg))
    res.add("- **use_https**: file %s · the process serves TLS itself: %s"
            % (_scalar(cfg.get("use_https")), _tls_text(ctx)))


def _tls_text(ctx):
    """What the boot record says about TLS: yes / no (and why it failed) / unknown."""
    tls = _running(ctx, "BOOT_TLS")
    if tls is _NO_APP:
        return "unknown (no app context)" if ctx.app is None else "unknown (no boot record)"
    if tls is None:
        return "unknown (no boot record)"
    err = _running(ctx, "BOOT_TLS_ERROR")
    if tls:
        return "yes"
    if isinstance(err, str) and err.isidentifier():
        return "no (configured, but it failed to start: %s)" % err
    return "no"


def _proxy_users_existing(value):
    """(entries naming an account that exists here, entries), from /etc/passwd.

    Never pwd.getpwnam: on names mostly absent locally it falls through to LDAP/SSSD, a native call
    that blocks the eventlet hub, and this section runs in the request greenlet.
    """
    from panel.ops.debug_report import privacy
    entries = list(_DEFAULT_PROXY_USERS if value is None else
                   ([value] if isinstance(value, (str, int)) else value))
    local = {parts[0] for parts in privacy._etc_rows(privacy.ETC_PASSWD) if parts}
    found = sum(1 for entry in entries if isinstance(entry, int) or str(entry).strip().isdecimal()
                or str(entry).strip() in local)
    return found, len(entries)


def _ignored_peers():
    """{category: count} of peers whose forwarding headers were ignored in the last hour."""
    import time
    from panel.security import auth
    now, out = time.monotonic(), {}
    for (addr, uid), when in list(auth._ignored_proxy_warned.items()):
        if now - when > _IGNORED_WARN_WINDOW:
            continue
        cls = addr_class(addr)
        key = "loopback non-proxy account" if uid is not None else cls
        out[key] = out.get(key, 0) + 1
    return out


def _trusted_lines(ctx, cfg, res):
    nets = _running(ctx, "_TRUSTED_PROXIES")
    listed = cfg.get("trusted_proxies")
    invalid = ""
    if isinstance(listed, (list, tuple)) and isinstance(nets, tuple):
        invalid = " · invalid entries %d" % max(0, len(listed) - len(nets))
    users = cfg.get("trusted_proxy_users")
    found, total = _proxy_users_existing(users)
    res.add("- **trusted_proxies**: %s%s · **trusted_proxy_users**: %s, %d of %d accounts exist"
            % ("default (loopback)" if listed is None else _count(listed), invalid,
               "default" if users is None else _count(users), found, total))


def _peer_and_origin_lines(cfg, res):
    peers = _ignored_peers()
    res.add("- **Forwarding headers ignored, last hour**: %s" % (
        "%d peer(s) (%s)" % (sum(peers.values()), ", ".join(
            "%d %s" % (n, k) for k, n in sorted(peers.items()))) if peers else "none"))
    origins = cfg.get("socketio_cors_origins")
    listed = [origins] if isinstance(origins, str) else list(origins or [])
    exact = [o for o in listed if str(o).strip() != "*"]
    res.add("- **Console socket origins**: %d exact ('*' listed and ignored: %s) · site_domain %s"
            % (len(exact), "yes" if len(exact) != len(listed) else "no",
               _domain_class(cfg.get("site_domain"))))


def _proxy_lines(ctx, cfg, res):
    """R37: proxy trust as the process runs it, compared with the file; counts and classes only."""
    run = _running(ctx, "_TRUST_PROXY")
    res.add(_both("trust_proxy", _scalar(bool(cfg.get("trust_proxy"))),
                  None if run is _NO_APP else _scalar(bool(run))))
    _trusted_lines(ctx, cfg, res)
    _peer_and_origin_lines(cfg, res)
    if run is not _NO_APP and run and addr_class(_boot_bind(ctx)) != "loopback":
        res.add("- [!] trust_proxy is on but the panel listens beyond loopback, so it can be "
                "reached without going through the proxy")
        res.find("warn", "Network", "trust_proxy is on but the panel listens beyond loopback")


def _ssh_timeout(cfg):
    from panel.ops.ssh_manager import _core
    return "%s (effective, clamped: %d s)" % (_scalar(cfg.get("ssh_timeout")),
                                             _core._ssh_connect_timeout())


def _site_title(cfg):
    return "default" if cfg.get("site_title") in (None, "", "LinuxGSM Panel") else "custom"


def _mount(cfg):
    return _mount_class(cfg.get("tailscale_mount"))


def _domain(cfg):
    return _domain_class(cfg.get("site_domain"))


def _counted(key):
    def _c(cfg):
        return "%s (counts only)" % _count(cfg.get(key))
    return _c


_CLASSIFY = {"ssh_timeout": _ssh_timeout, "site_title": _site_title, "tailscale_mount": _mount,
             "site_domain": _domain, "security_whitelist": _counted("security_whitelist"),
             "autoblock_hosts": _counted("autoblock_hosts")}


def _other_lines(cfg, res):
    """Every other whitelisted key: classified, counted, or a scalar; never free text."""
    from panel.ops import system_ops as so
    for key in DEBUG_CONFIG_KEYS:
        if key in _RUNNING_KEYS:
            continue
        if key in _CLASSIFY:
            value = _CLASSIFY[key](cfg)
        else:
            value = _scalar(cfg[key]) if key in cfg else "(unset → %s)" % _UNSET_EFFECTIVE.get(
                key, "default")
        res.add("- **%s**: %s" % (key, value))


def section_config(ctx):
    """Whitelisted, classified settings: file vs running, never defaults when unreadable."""
    from panel.core import config as cfgmod
    res = Result()
    try:
        cfg = cfgmod.load_config()
    except Exception as exc:  # noqa: BLE001 - printed as unread, never as defaults
        return res.add("- config.json could not be read (%s); values unknown"
                       % type(exc).__name__).find("unread", "Config", "config.json could not be read")
    if cfgmod.is_unreadable(cfg):
        return res.add("- config.json could not be read; values unknown").find(
            "unread", "Config", "config.json could not be read")
    for fn in (_bind_lines, _proxy_lines, _cookie_lines, _session_values):
        fn(ctx, cfg, res)
    _other_lines(cfg, res)
    return res
