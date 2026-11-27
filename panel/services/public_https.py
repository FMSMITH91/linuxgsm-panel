"""HTTPS to the fixed outside hosts the panel reads data files from: no redirect, no proxy, public addresses only.

Used by services/geoip.py (DB-IP's country database) and services/addons_bluemap.py (Mojang's version
list and a version's details). Each caller checks its own URL against its own host allowlist first
(scheme https, its hosts, port 443, no userinfo); this module adds what an allowlist alone cannot.

OWASP Server Side Request Forgery Prevention Cheat Sheet, "Case 1: Application can send request only to
identified and trusted applications", "Available protections" -> "Application layer":
- no redirect is followed, to any host (NoRedirect): the 3xx is the answer, an HTTPError;
- DNS rebinding: a host-name allowlist alone does not stop it, so the name is resolved once and nothing
  is connected when ANY answer is not a public unicast address, and the connection goes only to those
  checked answers, the name kept for TLS's SNI and certificate check. That is the panel's reviewed
  checked connect, the one web push uses (webpush._connect_checked: webpush.address_refused, then
  notifications._connect_infos); it resolves port 443, which every caller's allowlist requires;
- no proxy (an empty ProxyHandler stands in for the one urllib builds from the environment), so the
  address checked is the address connected to;
- TLS: web push's verified context (webpush._tls_context: certificate and host name checked, TLS 1.2 at
  least, OWASP Transport Layer Security Cheat Sheet), held on the handler itself.
"""
import http.client
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Follow no redirect: the 3xx itself is then the answer, an HTTPError ("could not be downloaded")."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Refuse (None) every redirect, to any host."""
        return None


def _connect(address, timeout=None, source_address=None):
    """The socket for `address` (host, 443): web push's checked connect. OSError when it is refused."""
    from panel.services import webpush as _wp   # it imports much of the panel: read at call time
    return _wp._connect_checked(address, timeout, source_address)


class _Connection(http.client.HTTPSConnection):
    """HTTPS whose socket _connect opens; the certificate and SNI still name the host."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _connect


class _Handler(urllib.request.HTTPSHandler):
    """urllib's https handler, connecting through _Connection with a TLS context of its own."""

    def __init__(self, tls):
        super().__init__()
        self._tls = tls        # kept here, not read back from urllib's own attribute (which may change)

    def https_open(self, req):
        """Open `req` over _Connection."""
        return self.do_open(_Connection, req, context=self._tls)


def handlers():
    """Return the handlers for one request's opener, as urllib.request.build_opener takes them.

    No redirect, the checked connect with web push's verified TLS context (certificate and host name
    checked, TLS 1.2 at least), no proxy. The caller builds the opener itself, so its request stays a
    reviewed call site (tests/unit/part37.py, codeql-config.yml).
    """
    from panel.services import webpush as _wp   # it imports much of the panel: read at call time
    return NoRedirect(), _Handler(_wp._tls_context()), urllib.request.ProxyHandler({})
