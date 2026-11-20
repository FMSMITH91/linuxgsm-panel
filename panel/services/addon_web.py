"""An add-on's web page shown through the panel: its capability links, and what the proxy changes on the way.

WHY A LINK, AND WHY A SANDBOX. An add-on's page (IW4MAdmin's webfront, BlueMap's map) listens on the game
host's 127.0.0.1 only. The panel shows it under /addon-web/<token>/ on its own address, so a phone needs no
SSH tunnel and no port is opened anywhere. That page is someone else's HTML and script, served from the
panel's own origin, so every answer carries `Content-Security-Policy: sandbox allow-scripts allow-forms`
WITHOUT allow-same-origin (OWASP HTML5 Security Cheat Sheet, "Sandboxed frames"; the CSP `sandbox`
directive applies the same to a page opened on its own). The browser gives such a page an opaque origin:
its script cannot read the panel's cookies, storage or pages, and what it asks of the panel's address
goes as a cross-site request, which carries no SameSite=Lax/Strict cookie (the panel's are). So the
page's own requests cannot prove who is asking with the panel's session; the link itself does.

THE LINK (a capability URL). 32 random bytes from `secrets` (OWASP Session Management Cheat Sheet,
"Session ID Entropy": at least 64 bits), kept here only as their SHA-256, bound to the user's sign-in
(the id flask-login keeps: user, auth epoch, session), one server, one add-on and the port read for it
when it was opened. On EVERY request the proxy asks again whether that sign-in is still live (signed
out, password changed, session revoked or expired: refused) and whether the user still holds the
permission and the server (Authorization Cheat Sheet, "Validate the Permissions on Every Request").
It ends after the panel's own idle timeout without use, and at the panel's absolute session limit
from its opening ("Session Expiration"). It is never logged (the panel's server keeps no access log,
and nothing here writes a path), and every answer says `Referrer-Policy: no-referrer`.

WHAT IS PASSED ON. Request headers from an allowlist only: never the panel's cookies, Authorization,
Origin, Referer, the proxy's forwarding headers or Tailscale's user headers. Response headers from an
allowlist only: never Set-Cookie (kept in a jar on the server, per link, and sent back to the add-on
alone, so the add-on's own sign-in works and can never touch the panel's cookies), nor
Clear-Site-Data, which would wipe the panel's own site data, nor the add-on's own CSP or framing
headers (the sandbox replaces them).

WHAT IS CHANGED. The page lives under a path, and IW4MAdmin's pages name theirs from the root (`<base
href="/">`, `/css/...`): root-relative addresses in HTML and CSS are put under the link's path. A page
in an opaque origin cannot use localStorage, sessionStorage or document.cookie (each throws), which
stops BlueMap's map from loading: a short script, first in the page's <head>, gives them in-memory
stand-ins for that page. BlueMap's settings.json is also told not to keep settings (`useCookies`).
"""
import gzip
import hashlib
import json
import re
import secrets
import shlex
import threading
import time
import zlib

from panel.services import addons as _ad

PATH_ROOT = "/addon-web/"
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
TOKEN_BYTES = 32                     # 256 bits; token_urlsafe(32) is 43 characters
MAX_LINKS_PER_USER = 20
MAX_LINKS = 500
# The add-on side: how long a dial and a quiet read may take, the body sizes, the head's size.
CONNECT_SECONDS = 15
# IW4MAdmin's Blazor circuit is a WebSocket; a long poll or a slow first render must not be cut.
READ_SECONDS = 120
MAX_REQUEST_BODY = 1024 * 1024
MAX_RESPONSE_BODY = 64 * 1024 * 1024
MAX_REWRITE = 4 * 1024 * 1024
MAX_HEAD = 64 * 1024
# How long a request may wait for its turn at an add-on that takes few connections at a time.
QUEUE_SECONDS = 30
# A WebSocket's link is asked again this often, so a sign-out or a removed permission ends it too.
RECHECK_SECONDS = 30
# The cookie jar per link (the add-on's own sign-in).
JAR_COOKIES = 32
JAR_BYTES = 16 * 1024

# Per add-on: how many connections the page takes at once (IW4MAdmin's Kestrel takes one at a time:
# WebfrontCore/Program.cs at the pinned image, MaxConcurrentConnections from MaxConcurrentRequests,
# default 1; an upgraded WebSocket is not counted), whether it needs a WebSocket (IW4MAdmin's pages
# are Blazor Server, whose live updates and buttons run over SignalR), its own rewrite, and whether its
# script must evaluate strings (`eval`: BlueMap's web app does, through vue-i18n's message compiler,
# `new Function(...)`, and without 'unsafe-eval' the map never loads; see _csp).
WEB = {
    _ad.IW4MADMIN: {"connections": 1, "websocket": True, "settings_json": False, "eval": False},
    _ad.BLUEMAP: {"connections": 6, "websocket": False, "settings_json": True, "eval": True},
}
# Each id mapped to itself: a route turns the URL's text into this constant before anything uses it.
WEB_IDS = {k: k for k in WEB}

# OWASP HTTP Headers Cheat Sheet / CSP Cheat Sheet: the page runs in a sandbox with an opaque origin
# (no allow-same-origin), loads only from this address, may not be framed and sends no referrer.
_CSP = ("sandbox allow-scripts allow-forms; default-src 'self'; script-src 'self' 'unsafe-inline'%s; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; "
        "connect-src 'self'; worker-src 'self' blob:; media-src 'self' data: blob:; object-src 'none'; "
        "frame-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")


def _csp(addon_id=None):
    """The policy for `addon_id`'s page (None: the proxy's own answers, a refusal or a redirect).

    'unsafe-eval' only where the add-on's page needs it (WEB "eval"). OWASP's CSP Cheat Sheet advises
    against it: it lets the page's script turn a string into code. What contains it here is the sandbox
    WITHOUT allow-same-origin, kept for every add-on: the page has an opaque origin, so code it evaluates
    runs as that origin and reaches nothing of the panel's (no cookie, storage, page or same-origin
    request), exactly as the add-on's own script already does. It changes what the add-on's page can do
    to itself, not what it can do to the panel; 'unsafe-inline' is already there for the same pages.
    """
    return _CSP % (" 'unsafe-eval'" if WEB.get(addon_id, {}).get("eval") else "")


_PERMISSIONS = ("camera=(), microphone=(), geolocation=(), usb=(), payment=(), serial=(), "
                "accelerometer=(), gyroscope=(), magnetometer=()")
# Answers a browser may keep (revalidated on each use): the map's tiles, scripts and styles.
_CACHEABLE = re.compile(r"(?:image|font)/|text/css|(?:application|text)/javascript|application/octet-stream")

REQUEST_HEADERS = frozenset((
    "accept", "accept-language", "content-type", "if-none-match", "if-modified-since", "if-match",
    "if-unmodified-since", "range", "if-range", "cache-control", "pragma", "user-agent", "x-requested-with",
    "x-signalr-user-agent", "requestverificationtoken", "last-event-id"))
WEBSOCKET_HEADERS = frozenset(("sec-websocket-key", "sec-websocket-version", "sec-websocket-protocol",
                               "sec-websocket-extensions"))
RESPONSE_HEADERS = frozenset((
    "content-type", "content-encoding", "content-language", "etag", "last-modified", "expires",
    "accept-ranges", "content-range", "vary", "content-disposition", "retry-after", "allow"))
SWITCH_HEADERS = frozenset(("sec-websocket-accept", "sec-websocket-protocol", "sec-websocket-extensions"))

# Stand-ins for the storage an opaque origin is refused (see the module docstring), in memory, for this
# page only. Nothing in it reaches the panel; the sandbox is unchanged.
SHIM = ("<script>(function(){function m(){var d=Object.create(null);return{getItem:function(k){k=String(k);"
        "return k in d?d[k]:null},setItem:function(k,v){d[String(k)]=String(v)},removeItem:function(k){"
        "delete d[String(k)]},clear:function(){d=Object.create(null)},key:function(i){var a=Object.keys(d);"
        "return i<a.length?a[i]:null},get length(){return Object.keys(d).length}}}"
        "['localStorage','sessionStorage'].forEach(function(n){try{void window[n].length}catch(e){try{"
        "Object.defineProperty(window,n,{value:m(),configurable:true})}catch(f){}}});"
        "try{void document.cookie}catch(e){try{Object.defineProperty(document,'cookie',{get:function(){"
        "return''},set:function(){},configurable:true})}catch(f){}}})();</script>")

_LINKS = {}            # sha256(token) -> Link
_LOCK = threading.Lock()
_GATES = {}            # (remote id, port) -> BoundedSemaphore
_GATES_LOCK = threading.Lock()


class Link:
    """One opened page: who, which server and add-on, its port, its path, its add-on cookies."""

    __slots__ = ("user_key", "user_id", "server_id", "remote_id", "addon_id", "port", "lang", "born", "used",
                 "jar", "refusal_logged")

    def __init__(self, user_key, user_id, target, lang, now):
        """Bind the link to its sign-in (`user_key`) and `target` (server id, host id, add-on, port); opened `now`."""
        self.user_key, self.user_id = user_key, user_id
        self.server_id, self.remote_id, self.addon_id, self.port = target
        self.lang, self.born, self.used, self.jar, self.refusal_logged = lang, now, now, {}, False


def _digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _expired(link, now, idle, absolute):
    return now - link.used > idle or now - link.born > absolute


def mint(user_key, user_id, target, lang, idle, absolute, now=None):
    """A new link's token for `target` (server id, host id, add-on, port), stored only as its hash.

    Expired links are swept, and a user's and all links are capped.
    """
    now = time.time() if now is None else now
    token = secrets.token_urlsafe(TOKEN_BYTES)
    with _LOCK:
        for k in [k for k, v in _LINKS.items() if _expired(v, now, idle, absolute)]:
            del _LINKS[k]
        mine = sorted((v.born, k) for k, v in _LINKS.items() if v.user_id == user_id)
        for _born, k in mine[:max(0, len(mine) - MAX_LINKS_PER_USER + 1)]:
            del _LINKS[k]
        if len(_LINKS) >= MAX_LINKS:
            del _LINKS[min(_LINKS, key=lambda k: _LINKS[k].born)]
        _LINKS[_digest(token)] = Link(user_key, user_id, target, lang, now)
    return token


def lookup(token, idle, absolute, now=None):
    """The live Link for `token`, its use noted; None for an unknown, malformed or expired one (dropped)."""
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        return None
    now = time.time() if now is None else now
    key = _digest(token)
    with _LOCK:
        link = _LINKS.get(key)
        if link is None:
            return None
        if _expired(link, now, idle, absolute):
            del _LINKS[key]
            return None
        link.used = now
        return link


def revoke(token):
    """Forget the link for `token` (a refused request: its sign-in or permission has gone)."""
    if not isinstance(token, str):
        return
    with _LOCK:
        _LINKS.pop(_digest(token), None)


def revoke_user(user_id):
    """Forget every link of `user_id`."""
    with _LOCK:
        for k in [k for k, v in _LINKS.items() if v.user_id == user_id]:
            del _LINKS[k]


def gate(remote_id, port, addon_id):
    """The semaphore that holds requests to one add-on's page to the connections it takes at once."""
    with _GATES_LOCK:
        g = _GATES.get((remote_id, port))
        if g is None:
            g = _GATES[(remote_id, port)] = threading.BoundedSemaphore(WEB[addon_id]["connections"])
        return g


# ── the request ──────────────────────────────────────────────────────────────────────────────────
def upstream_headers(environ, port, jar, websocket=False):
    """The request's headers for the add-on: the allowlist, its own Host, the link's cookie jar.

    `environ` is the WSGI request. Accept-Encoding is gzip at most (a page the proxy rewrites must be
    one it can read), and a plain request asks for the connection to be closed after its answer.
    """
    allow = REQUEST_HEADERS | (WEBSOCKET_HEADERS if websocket else frozenset())
    out = [("Host", "%s:%d" % ("127.0.0.1", port))] + list(_allowlisted(environ, allow))
    if environ.get("CONTENT_TYPE") and _header_ok(environ["CONTENT_TYPE"]):
        out.append(("content-type", environ["CONTENT_TYPE"]))
    if "gzip" in environ.get("HTTP_ACCEPT_ENCODING", ""):
        out.append(("Accept-Encoding", "gzip"))
    cookie = "; ".join("%s=%s" % kv for kv in jar.items())
    if cookie:
        out.append(("Cookie", cookie))
    out.extend([("Upgrade", "websocket"), ("Connection", "Upgrade")] if websocket else [("Connection", "close")])
    return out


def _allowlisted(environ, allow):
    """(name, value) of the request's HTTP_ headers whose name is in `allow` and whose value is one line."""
    for key, value in environ.items():
        name = key[5:].replace("_", "-").lower() if key.startswith("HTTP_") else ""
        if name in allow and _header_ok(value):
            yield name, value


def _header_ok(value):
    return isinstance(value, str) and len(value) <= 8192 and not any(c in value for c in "\r\n\0")


_PATH_SAFE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/!$&'()*+,;=:@%")


def upstream_target(raw_path, query):
    """The request line's target for the add-on, or None when it is not a plain path and query.

    `raw_path` is the part after the link's token, as the browser sent it (still percent-encoded):
    only URL characters pass, so nothing can end the request line or add a header.
    """
    if not raw_path.startswith("/") or not set(raw_path) <= _PATH_SAFE or len(raw_path) > 4096:
        return None
    if query and (not set(query) <= _PATH_SAFE | {"?"} or len(query) > 8192):
        return None
    return raw_path + ("?" + query if query else "")


# ── the answer ───────────────────────────────────────────────────────────────────────────────────
def page_headers(ctype, websocket=False, addon_id=None):
    """The headers every proxied answer carries (see the module docstring); the policy is `addon_id`'s."""
    out = [("Content-Security-Policy", _csp(addon_id)), ("Referrer-Policy", "no-referrer"),
           ("X-Content-Type-Options", "nosniff"), ("Permissions-Policy", _PERMISSIONS),
           ("X-Robots-Tag", "noindex, nofollow"), ("X-Frame-Options", "DENY")]
    if websocket:
        return out
    # The page's origin is opaque, so to the browser everything it loads from here is cross-origin, and
    # its module scripts, fetches and textures are CORS requests sent with `Origin: null`. So CORS allows
    # exactly that origin, not `*` (OWASP HTML5 Security Cheat Sheet, "Cross Origin Resource Sharing":
    # only the origins that need it): an ordinary page on another site can't read an answer. No
    # Cross-Origin-Resource-Policy: `same-site` and `same-origin` refuse the opaque page's own <script>,
    # stylesheet and <img> loads (measured in headless Brave), and leaving it out is narrower than
    # `cross-origin` (a cross-origin page that requires CORP can't embed these files). A panel page can't
    # load them either way: the proxy refuses a panel page's request (routes/addon_web.py), and the
    # panel's policy takes no script or stylesheet without its nonce.
    out += [("Access-Control-Allow-Origin", "null"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
            ("Cache-Control", "private, no-cache" if _CACHEABLE.match(ctype or "") else "no-store")]
    return out


def kept_response_headers(headers, prefix, port):
    """The add-on's response headers the browser may see: the allowlist, and Location under the link."""
    out = []
    for name, value in headers:
        low = name.lower()
        if low == "location":
            out.append(("Location", location(value, prefix, port)))
        elif low in RESPONSE_HEADERS and _header_ok(value):
            out.append((name, value))
    return out


def location(value, prefix, port):
    """A redirect's address under the link: the add-on's own (root-relative or 127.0.0.1) moved under it.

    A relative one is kept; any other host is not followed (the link's root instead).
    """
    for own in ("http://127.0.0.1:%d" % port, "http://localhost:%d" % port):  # NOSONAR(S5332) - the add-on's own address
        if value.lower().startswith(own):
            value = value[len(own):] or "/"
            break
    if value.startswith("//") or re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", value):
        return prefix + "/"
    if value.startswith("/"):
        return prefix + value
    return value


def keep_cookies(jar, headers):
    """Put the add-on's Set-Cookie headers in the link's jar (bounded); a cookie it expires is dropped."""
    for name, value in headers:
        got = _cookie(value) if name.lower() == "set-cookie" else None
        if got is None:
            continue
        key, val, gone = got
        if gone:
            jar.pop(key, None)
        elif key in jar or len(jar) < JAR_COOKIES:
            jar[key] = val
        while sum(len(k) + len(v) for k, v in jar.items()) > JAR_BYTES:
            jar.pop(next(iter(jar)))


def _cookie(value):
    """(name, value, expired) of one Set-Cookie header, or None when it is malformed or too long."""
    first, _sep, attrs = value.partition(";")
    key, eq, val = first.strip().partition("=")
    if not eq or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", key) or len(val) > 4096:
        return None
    gone = bool(re.search(r"(?i)(?:^|;)\s*max-age\s*=\s*(?:0|-\d+)\s*(?:;|$)", ";" + attrs)) or _expires_past(attrs)
    return key, val.strip(), gone


def _expires_past(attrs):
    m = re.search(r"(?i)expires\s*=\s*([^;]+)", attrs)
    if not m:
        return False
    from email.utils import parsedate_to_datetime
    try:
        return parsedate_to_datetime(m.group(1).strip()).timestamp() < time.time()
    except (TypeError, ValueError, OverflowError):
        return False


def rewrites(ctype, raw_path, addon_id):
    """What kind of rewrite an answer gets: "html", "css", "settings" (BlueMap's settings.json) or ""."""
    low = (ctype or "").lower()
    if low.startswith("text/html"):
        return "html"
    if low.startswith("text/css"):
        return "css"
    if WEB[addon_id]["settings_json"] and raw_path.split("?", 1)[0].endswith("/settings.json"):
        return "settings"
    return ""


_ATTR_ROOT = re.compile(rb"""(\b(?:href|src|action|formaction|poster|data)\s*=\s*["'])/(?!/)""", re.I)
_CSS_ROOT = re.compile(rb"""(url\(\s*["']?)/(?!/)""", re.I)
_HEAD = re.compile(rb"<head\b[^>]*>", re.I)


def rewrite(kind, body, prefix):
    """`body` with the link's changes for `kind` (see rewrites); unchanged for any other."""
    p = prefix.encode("utf-8")
    if kind == "html":
        body = _CSS_ROOT.sub(rb"\1" + p + b"/", _ATTR_ROOT.sub(rb"\1" + p + b"/", body))
        m = _HEAD.search(body)
        at = m.end() if m else 0
        return body[:at] + SHIM.encode("ascii") + body[at:]
    if kind == "css":
        return _CSS_ROOT.sub(rb"\1" + p + b"/", body)
    if kind == "settings":
        try:
            doc = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return body
        if isinstance(doc, dict):
            doc["useCookies"] = False
            return json.dumps(doc).encode("utf-8")
    return body


def decoded(body, encoding):
    """`body` without its Content-Encoding (gzip or deflate, capped at MAX_REWRITE), or None when it can't be."""
    enc = (encoding or "").strip().lower()
    if enc in ("", "identity"):
        return body
    try:
        if enc in ("gzip", "x-gzip"):
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif enc == "deflate":
            d = zlib.decompressobj()
        else:
            return None
        out = d.decompress(body, MAX_REWRITE + 1)
    except (zlib.error, gzip.BadGzipFile):
        return None
    return out if len(out) <= MAX_REWRITE else None


# ── opening a page: one read of the add-on on its host ─────────────────────────────────────────────
def open_sh(addon_id):
    """The read, as the server's account, before a link is made.

    It prints the add-on's record, its state, and the loopback ports the ACCOUNT'S OWN processes listen
    on (`ss -p` names a process only to its owner, so a port listed here is one this account's container
    publishes, not some other service on the host).
    """
    meta = shlex.quote("%s/%s/%s" % (_ad.HOME_DIR, addon_id, _ad.META_FILE))
    return (_ad._ENV + 'echo "meta=$(head -c 4000 %s 2>/dev/null | base64 -w0)"; '
            'echo "state=$(systemctl --user is-active %s.service 2>/dev/null | head -n 1)"; '
            'echo "own=$(ss -Htlnp 2>/dev/null | grep -F "users:((" | awk \'{print $4}\' | tr "\\n" " ")"; true'
            % (meta, _ad.unit_name(addon_id)))


def page_port(out, server_id):
    """(the add-on page's port, why not: "" | "stopped" | "port") from open_sh's lines.

    The port is the add-on's recorded one only when it is in the server's own window of add-on ports
    (addons.PORT_BASE + server id, the install's choice) and this account listens on 127.0.0.1 there.
    """
    kv = _ad.kv_lines(out)
    if kv.get("state") != "active":
        return None, "stopped"
    try:
        meta = json.loads(_ad._unb64(kv.get("meta", "")) or "{}")
    except ValueError:
        meta = {}
    port = meta.get("port") if isinstance(meta, dict) else None
    first = _ad.PORT_BASE + int(server_id)
    if isinstance(port, bool) or not isinstance(port, int) or not first <= port < first + _ad._PORT_TRIES \
            or port > 65535 or "127.0.0.1:%d" % port not in kv.get("own", "").split():
        return None, "port"
    return port, ""
