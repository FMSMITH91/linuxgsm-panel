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

    def __call__(self, environ, start_response):
        cfg = load_config()
        # Priority: X-Forwarded-Prefix header (Tailscale Serve), then config
        prefix = environ.get("HTTP_X_FORWARDED_PREFIX", "")
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
