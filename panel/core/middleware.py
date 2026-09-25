"""WSGI middleware for serving the panel under a sub-path.

Moved out of app.py, where it sat between the game-list loader and the app factory with no
relation to either. It closes over nothing from app.py — it reads the mount point from
config.load_config() on each call — so it moved verbatim.
"""
from panel.core.config import load_config


class PrefixMiddleware:
    """WSGI middleware that handles sub-path mounts (Tailscale Serve, reverse proxy).
    Fixes both incoming PATH_INFO and outgoing Location redirect headers."""
    def __init__(self, app, prefix=""):
        self.app = app
        self.prefix = prefix.rstrip("/")

    @staticmethod
    def _clean_prefix(raw):
        """A mount prefix, or "" — the header says WHO, this says WHAT.

        _may_trust_header decides whether X-Forwarded-Prefix is believable; nothing constrained
        what it was allowed to say, so a trusted-source request could set SCRIPT_NAME to
        "//evil.example" or "https://evil.example" and have every url_for() on the page it got
        back, and the Location of every redirect, point off-site. That is the exact harm the
        docstring below says the source rule prevents — which would have read to the next
        maintainer as a solved problem.

        A mount is a path: one leading slash, then path characters. Anything else is refused
        outright rather than sanitised, because there is no "nearly a mount point"."""
        raw = (raw or "").strip()
        if not raw or not raw.startswith("/") or raw.startswith("//"):
            return ""
        if any(c in raw for c in ("\\", "\r", "\n", "\t", " ", ":", "?", "#", "@")) or ".." in raw:
            return ""
        return raw.rstrip("/")

    @staticmethod
    def _may_trust_header(environ, cfg):
        """Whether X-Forwarded-Prefix is believable on this request.

        Same rule auth.client_ip() applies to X-Forwarded-For, and for the same reason: on a direct
        bind (the panel supports 0.0.0.0) the header is fully client-controlled. Trusting it there
        let any caller set SCRIPT_NAME for its own response, which is what every url_for() and every
        outgoing Location header is built from.

        This answers WHO may set it and nothing else. What they may SAY — including the
        protocol-relative "//host" that resolves off-site — is _clean_prefix's job, above; this
        docstring used to claim both, which is a solved problem the next reader would not go
        looking for.

        Trusted only when the operator has declared a reverse proxy in front with trust_proxy. It
        was believed from loopback, on the premise that Tailscale Serve sends it there; it does not
        (nothing in tailscaled sets it), and tailscaled forwards a Funnel client's own copy, so on
        loopback it was the CLIENT's word. A proxy on this host that mounts the panel under a path
        needs trust_proxy, as the documented nginx/Caddy setups already set.
        """
        # Only a reverse proxy the operator declared (trust_proxy) authors this header. Tailscale
        # Serve and Funnel never set it — and they pass a CLIENT's own copy through unchanged, so a
        # root-owned loopback peer (tailscaled) proves nothing about who wrote it; any local account
        # on loopback proves less.
        return bool(cfg.get("trust_proxy"))

    def __call__(self, environ, start_response):
        cfg = load_config()
        # Priority: X-Forwarded-Prefix from a trusted proxy, then the configured mount
        prefix = (self._clean_prefix(environ.get("HTTP_X_FORWARDED_PREFIX", ""))
                  if self._may_trust_header(environ, cfg) else "")
        if not prefix:
            mount = cfg.get("tailscale_mount", "")
            if mount and mount != "/":
                prefix = mount
            else:
                prefix = self.prefix

        prefix = prefix.rstrip("/")

        # Assigned even when it is "": this middleware alone decides the mount. With trust_proxy on,
        # werkzeug's ProxyFix(x_prefix=1) runs first and copies X-Forwarded-Prefix into SCRIPT_NAME
        # unvalidated; when _clean_prefix refused that same header and the mount was "/", nothing
        # here overwrote it, so "//evil.example" survived as SCRIPT_NAME and every url_for() and
        # window.MOUNT on the page pointed off-site.
        environ["SCRIPT_NAME"] = prefix
        if prefix:
            path_info = environ.get("PATH_INFO", "")
            # "under the prefix" means the prefix itself or a path below it — the same rule the
            # outgoing Location rewrite below spells out, applied to the INCOMING path, where it
            # was a bare substring test. With mount "/panel" that served every page a second time
            # at a URL outside the mount: /panelserver/1 became SCRIPT_NAME=/panel PATH_INFO=
            # server/1 and answered 200, and /paneling became PATH_INFO=ing.
            if path_info == prefix:
                environ["PATH_INFO"] = "/"
            elif path_info.startswith(prefix + "/"):
                environ["PATH_INFO"] = path_info[len(prefix):]

        def _start_response(status, headers, *args):
            # Rewrite outgoing Location headers so redirects include the prefix
            if prefix:
                for i, (k, v) in enumerate(headers):
                    # "already under the prefix" means the prefix itself or a path below it — NOT
                    # merely sharing its first characters. With prefix "/panel" a redirect to
                    # "/panelserver" starts with it and is a different location entirely, so it
                    # was left unprefixed and pointed outside the mount.
                    if k.lower() == "location" and v.startswith("/") \
                            and not (v == prefix or v.startswith(prefix + "/")):
                        headers[i] = (k, prefix + v)
            return start_response(status, headers, *args)

        return self.app(environ, _start_response)


class ProxiedBanGate:
    """Refuses a request whose forwarded client address is banned (panel/security/banlist.py).

    For traffic the host firewall cannot see: Tailscale Funnel delivers every public client from
    127.0.0.1, so fail2ban's and the auto-block's firewall bans never touch it. The outermost layer,
    because Socket.IO's handshake and the static files never reach Flask's request hooks.

    The header is not authenticated here, and needs no authentication: this can only REFUSE. Through
    tailscaled the last hop is always tailscaled's own value, and any other sender can only name a
    banned address to have its own request refused. With nothing banned it costs one truth test."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        from panel.security import banlist
        if banlist.active():
            xff = environ.get("HTTP_X_FORWARDED_FOR")
            if xff and banlist.is_banned(banlist.forwarded_client(xff)):
                body = b"Forbidden\n"
                start_response("403 Forbidden", [
                    ("Content-Type", "text/plain; charset=utf-8"),
                    ("Content-Length", str(len(body))),
                    ("Cache-Control", "no-store"),
                    ("Connection", "close")])
                return [body]
        return self.app(environ, start_response)
