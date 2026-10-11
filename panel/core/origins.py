"""Reading the origins and hosts the console/terminal socket's per-request check compares.

WHY THIS IS ITS OWN MODULE — the same reason as panel/core/http.py. app.py is at the 1700 lines
of code Codacy allows a file, and these three are pure string parsing: no models, no panel state,
no app factory. Their code moved verbatim. app.py imports them back, so app._host_port and the
rest still resolve, and _socket_origin_allowed (which stays in app.py, beside the config it reads)
is unchanged.
"""


def _origin_candidates(environ, cfg):
    """The hosts a page allowed to open the socket may be served from, as Host-header strings.

    The Host this request arrived with, the X-Forwarded-Host a reverse proxy passes on, and
    site_domain. Each may carry an explicit port or none.
    """
    out = [environ.get("HTTP_HOST") or ""]
    fwd = environ.get("HTTP_X_FORWARDED_HOST")
    if fwd:
        out.append(fwd.split(",")[0].strip())
    # Not a string (a hand edit): no domain. `(5 or "").strip()` raised inside engineio's CORS
    # callback, on every handshake: no console and no terminal.
    domain = cfg.get("site_domain")
    out.append(domain.strip() if isinstance(domain, str) else "")
    return [h for h in out if h]


def _host_port(value):
    """(host, port) of a Host-header-like value, port None when none is given; None for no host.

    A value written with a scheme (a site_domain typed as a URL) is read the same way.
    """
    from urllib.parse import urlsplit
    value = str(value or "").strip()
    try:
        u = urlsplit(value if "://" in value else "//" + value)
        host, port = (u.hostname or "").lower(), u.port
    except ValueError:
        return None
    return (host, port) if host else None


def _origin_key(origin):
    """(scheme, host, port) of an origin, the default port filled in.

    None for anything that is not an http(s) origin with a host.
    """
    from urllib.parse import urlsplit
    try:
        u = urlsplit(str(origin or ""))
        host, port = (u.hostname or "").lower(), u.port
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not host:
        return None
    return (u.scheme, host, port or (443 if u.scheme == "https" else 80))
