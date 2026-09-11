"""WSGI middleware for serving the panel under a sub-path.

Moved out of app.py, where it sat between the game-list loader and the app factory with no
relation to either. It closes over nothing from app.py — it reads the mount point from
config.load_config() on each call — so it moved verbatim.
"""
from config import load_config


class PrefixMiddleware:
    """WSGI middleware that handles sub-path mounts (Tailscale Serve, reverse proxy).
    Fixes both incoming PATH_INFO and outgoing Location redirect headers."""
    def __init__(self, app, prefix=""):
        self.app = app
        self.prefix = prefix.rstrip("/")

    @staticmethod
    def _may_trust_header(environ, cfg):
        """Whether X-Forwarded-Prefix is believable on this request.

        Same rule auth.client_ip() applies to X-Forwarded-For, and for the same reason: on a direct
        bind (the panel supports 0.0.0.0) the header is fully client-controlled. Trusting it there
        let any caller set SCRIPT_NAME for its own response, which is what every url_for() and every
        outgoing Location header is built from — so a request could rewrite each link on the page it
        got back, including to a protocol-relative "//host" that resolves off-site.

        Trusted when the request actually arrived from the local proxy (Tailscale Serve runs on
        loopback, which is the case this header exists for), or when the operator has declared a
        reverse proxy in front with trust_proxy.
        """
        if cfg.get("trust_proxy"):
            return True
        return (environ.get("REMOTE_ADDR") or "") in ("127.0.0.1", "::1")

    def __call__(self, environ, start_response):
        cfg = load_config()
        # Priority: X-Forwarded-Prefix header (Tailscale Serve), then config
        prefix = environ.get("HTTP_X_FORWARDED_PREFIX", "") if self._may_trust_header(environ, cfg) else ""
        if not prefix:
            mount = cfg.get("tailscale_mount", "")
            if mount and mount != "/":
                prefix = mount
            else:
                prefix = self.prefix

        prefix = prefix.rstrip("/")

        if prefix:
            environ["SCRIPT_NAME"] = prefix
            path_info = environ.get("PATH_INFO", "")
            if path_info.startswith(prefix):
                environ["PATH_INFO"] = path_info[len(prefix):]

        def _start_response(status, headers, *args):
            # Rewrite outgoing Location headers so redirects include the prefix
            if prefix:
                for i, (k, v) in enumerate(headers):
                    if k.lower() == "location" and v.startswith("/") and not v.startswith(prefix):
                        headers[i] = (k, prefix + v)
            return start_response(status, headers, *args)

        return self.app(environ, _start_response)
