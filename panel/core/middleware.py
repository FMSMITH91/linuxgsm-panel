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
        prefix = (self._clean_prefix(environ.get("HTTP_X_FORWARDED_PREFIX", ""))
                  if self._may_trust_header(environ, cfg) else "")
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
