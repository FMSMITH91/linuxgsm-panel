"""Part 279 of the unit suite: an add-on's web page through the panel (routes/addon_web.py, services/addon_web*.py).

1. The pieces: a link's token (random, kept only as its hash, idle and absolute ends, a cap per user), the
   headers passed each way (allowlists: no panel cookie, Authorization, Origin or forwarding header goes
   to the add-on; no Set-Cookie or Clear-Site-Data comes back), the sandbox headers on every answer, the
   add-on's cookies kept per link, the rewrites (root paths under the link, the storage stand-ins, BlueMap's
   useCookies), the port check at Open (the server's window, the account's own listener), the request
   target's characters, HTTP framing (Content-Length, chunked, to the end, the caps), the WebSocket splice
   and its recheck, and the stream for each transport.
2. The routes on part12's app: Open needs View add-on pages (or Manage add-ons) and the server, reads the
   host once, audits, and sends the tab to the link; the proxy asks the link again on every request (a
   removed permission, a bumped epoch or a deleted session refuses it, audited once), connects only to the
   port read at Open, passes no panel cookie, keeps the add-on's own, and leaves other paths to the app.
   The Add-ons list for a viewer with View add-on pages alone.
3. The card (node over server_addons.js): Open on a running add-on with a page posts a form to a new tab
   with the CSRF token; a viewer's rows have only Open.
4. The text: every new sentence in Spanish and French.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; the host read and the tunnel are
stand-ins (a scripted stream). The splice and the local transport use socketpairs and a loopback listener
this part opens and closes. Nothing reaches a host, /etc or data/.
"""
import json as _json279
import os
import shutil as _shutil279
import socket as _socket279
import subprocess as _sp279  # nosec B404 - node over the panel's own script
import tempfile as _tf279
import threading as _th279

from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_HOST, _p9, _p9_arm, _p9_audit, _p9_audit_count, _p9_client, _p9_delete_server,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_seeded_default_group)
from panel.core import i18n as _i18n279
from panel.db import models as _m279
from panel.ops.ssh_manager import tunnel as _tun279
from panel.routes import addon_web as _rw279, addons as _ra279
from panel.security import auth as _auth279
from panel.services import addon_web as _aw279, addon_web_http as _ht279, addons as _ad279

_ROOT279 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_IDLE279, _ABS279 = 1800.0, 8 * 3600.0


# ── 1. the pieces ─────────────────────────────────────────────────────────────────────────────────
def _links279():
    _aw279._LINKS.clear()
    t = _aw279.mint("5:0", 5, (9, 2, _ad279.BLUEMAP, 21010), "es", _IDLE279, _ABS279, now=1000.0)
    stored = list(_aw279._LINKS.items())
    live = _aw279.lookup(t, _IDLE279, _ABS279, now=1500.0)
    idle_gone = _aw279.lookup(t, _IDLE279, _ABS279, now=1500.0 + _IDLE279 + 1)
    t2 = _aw279.mint("5:0", 5, (9, 2, _ad279.BLUEMAP, 21010), "es", _IDLE279, _ABS279, now=1000.0)
    for i in range(int(_ABS279 // 1000) + 2):          # used often, never idle: the absolute end still comes
        last = _aw279.lookup(t2, _IDLE279, _ABS279, now=1000.0 + 1000 * (i + 1))
    many = [_aw279.mint("6:0", 6, (9, 2, _ad279.BLUEMAP, 21010), "en", _IDLE279, _ABS279, now=2000.0 + i)
            for i in range(_aw279.MAX_LINKS_PER_USER + 3)]
    kept6 = sum(1 for v in _aw279._LINKS.values() if v.user_id == 6)
    first_gone = _aw279.lookup(many[0], _IDLE279, _ABS279, now=2100.0)
    _aw279._LINKS.clear()
    return t, stored, live, idle_gone, last, kept6, first_gone


_lk279 = _links279()
check("link: a token is 43 URL-safe characters (32 random bytes) and is kept only as its SHA-256, never itself",
      _aw279.TOKEN_RE.fullmatch(_lk279[0]) is not None and len(_lk279[1]) == 1 and _lk279[1][0][0] != _lk279[0]
      and _lk279[0] not in repr([getattr(_lk279[1][0][1], n) for n in _aw279.Link.__slots__]), repr(_lk279[1][:1]))
check("link: a lookup inside the idle window finds it, bound to its user, server, add-on and port",
      _lk279[2] is not None and (_lk279[2].user_key, _lk279[2].server_id, _lk279[2].addon_id, _lk279[2].port)
      == ("5:0", 9, _ad279.BLUEMAP, 21010), repr(_lk279[2]))
check("link: ...and past the idle timeout it is gone", _lk279[3] is None, repr(_lk279[3]))
check("link: a link used every few minutes still ends at the absolute limit from its opening", _lk279[4] is None,
      repr(_lk279[4]))
eq("link: one user keeps at most MAX_LINKS_PER_USER links; the oldest go first",
   (_lk279[5], _lk279[6]), (_aw279.MAX_LINKS_PER_USER, None))
check("link: a malformed or unknown token finds nothing",
      _aw279.lookup("../../etc", _IDLE279, _ABS279) is None and _aw279.lookup("A" * 43, _IDLE279, _ABS279) is None, "")


def _headers279():
    env = {"HTTP_COOKIE": "session=panel; remember_token=x", "HTTP_AUTHORIZATION": "Bearer panel-api",
           "HTTP_ORIGIN": "null", "HTTP_REFERER": "https://panel.example/x", "HTTP_X_FORWARDED_FOR": "203.0.113.9",
           "HTTP_TAILSCALE_USER_LOGIN": "someone@example.com", "HTTP_X_CSRFTOKEN": "tok", "HTTP_HOST": "panel.example",
           "HTTP_ACCEPT": "text/html", "HTTP_ACCEPT_ENCODING": "gzip, deflate, br, zstd", "HTTP_IF_NONE_MATCH": '"e1"',
           "HTTP_X_SIGNALR_USER_AGENT": "sr", "CONTENT_TYPE": "application/json", "HTTP_USER_AGENT": "ua\r\nX-Evil: 1"}
    return (dict((k.lower(), v) for k, v in _aw279.upstream_headers(env, 21010, {".AspNetCore.Cookies": "iw"})),
            dict((k.lower(), v) for k, v in _aw279.upstream_headers(
                dict(env, HTTP_UPGRADE="websocket", HTTP_SEC_WEBSOCKET_KEY="k=="), 21010, {}, websocket=True)))


_hd279 = _headers279()
check("to the add-on: the panel's cookies, Authorization, Origin, Referer, X-Forwarded-For, Tailscale's user "
      "header, the CSRF token and the browser's Host are not passed on",
      not {"authorization", "origin", "referer", "x-forwarded-for", "tailscale-user-login", "x-csrftoken"}
      & set(_hd279[0]) and "panel" not in _hd279[0].get("cookie", ""), repr(sorted(_hd279[0])))
eq("to the add-on: its own Host, the link's cookie jar, gzip at most, the connection closed after the answer, "
   "and the allowlisted headers kept",
   (_hd279[0]["host"], _hd279[0]["cookie"], _hd279[0]["accept-encoding"], _hd279[0]["connection"],
    _hd279[0]["accept"], _hd279[0]["if-none-match"], _hd279[0]["x-signalr-user-agent"], _hd279[0]["content-type"]),
   ("127.0.0.1:21010", ".AspNetCore.Cookies=iw", "gzip", "close", "text/html", '"e1"', "sr", "application/json"))
check("to the add-on: a header value with a line break is dropped, not passed on", "user-agent" not in _hd279[0], "")
eq("to the add-on: a WebSocket upgrade carries its key and asks to upgrade",
   (_hd279[1].get("sec-websocket-key"), _hd279[1].get("upgrade"), _hd279[1].get("connection")),
   ("k==", "websocket", "Upgrade"))


def _answer_headers279():
    kept = dict((k.lower(), v) for k, v in _aw279.kept_response_headers(
        [("Content-Type", "text/html"), ("Set-Cookie", "session=evil; Path=/"), ("Clear-Site-Data", '"*"'),
         ("Content-Security-Policy", "default-src *"), ("X-Frame-Options", "ALLOWALL"), ("Server", "Kestrel"),
         ("Location", "/Account/Login"), ("ETag", '"e1"'), ("Strict-Transport-Security", "max-age=1")],
        "/m/addon-web/T", 21010))
    page = dict(_aw279.page_headers("text/html"))
    return kept, page


_ah279 = _answer_headers279()
check("from the add-on: Set-Cookie, Clear-Site-Data (it would wipe the panel's own site data), its CSP, framing, "
      "HSTS and Server headers are not passed to the browser",
      not {"set-cookie", "clear-site-data", "content-security-policy", "x-frame-options", "server",
           "strict-transport-security"} & set(_ah279[0]), repr(sorted(_ah279[0])))
eq("from the add-on: a root-relative redirect goes under the link; the content type and ETag are kept",
   (_ah279[0].get("location"), _ah279[0].get("content-type"), _ah279[0].get("etag")),
   ("/m/addon-web/T/Account/Login", "text/html", '"e1"'))
check("every answer: CSP sandbox with scripts and forms but NOT allow-same-origin (an opaque origin), framed by "
      "nobody, no referrer",
      _ah279[1]["Content-Security-Policy"].startswith("sandbox allow-scripts allow-forms;")
      and "allow-same-origin" not in _ah279[1]["Content-Security-Policy"]
      and "frame-ancestors 'none'" in _ah279[1]["Content-Security-Policy"]
      and _ah279[1]["Referrer-Policy"] == "no-referrer", repr(_ah279[1]))
eq("every answer: an HTML page is not stored; a stylesheet may be kept and revalidated",
   (_ah279[1]["Cache-Control"], dict(_aw279.page_headers("text/css"))["Cache-Control"]),
   ("no-store", "private, no-cache"))
eq("redirects: the add-on's own absolute address goes under the link, another host goes to the link's root, a "
   "relative one stays",
   (_aw279.location("http://127.0.0.1:21010/x?y=1", "/addon-web/T", 21010),
    _aw279.location("https://elsewhere.example/p", "/addon-web/T", 21010),
    _aw279.location("//elsewhere.example/p", "/addon-web/T", 21010), _aw279.location("next", "/addon-web/T", 21010)),
   ("/addon-web/T/x?y=1", "/addon-web/T/", "/addon-web/T/", "next"))


def _jar279():
    jar = {}
    _aw279.keep_cookies(jar, [("Set-Cookie", ".AspNetCore.Cookies=abc; path=/; httponly; samesite=lax"),
                              ("Set-Cookie", "bad name=x"), ("Set-Cookie", "gone=1")])
    first = dict(jar)
    _aw279.keep_cookies(jar, [("set-cookie", "gone=; Max-Age=0"),
                              ("Set-Cookie", "old=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT")])
    for i in range(_aw279.JAR_COOKIES + 5):
        _aw279.keep_cookies(jar, [("Set-Cookie", "c%d=v" % i)])
    return first, jar


_jr279 = _jar279()
eq("cookie jar: the add-on's cookies are kept by name (attributes dropped); a malformed one is not",
   _jr279[0], {".AspNetCore.Cookies": "abc", "gone": "1"})
check("cookie jar: Max-Age=0 or an Expires in the past removes a cookie, and the jar holds at most JAR_COOKIES",
      "gone" not in _jr279[1] and "old" not in _jr279[1] and len(_jr279[1]) <= _aw279.JAR_COOKIES, repr(len(_jr279[1])))


def _rewrites279():
    html = (b'<!doctype html><html><HEAD><base href="/"/><link rel="stylesheet" href="/css/app.min.css">'
            b'<script src="/js/app.min.js"></script><a href="//cdn.example/x">x</a><a href="about">a</a>'
            b'<style>.a{background:url(/img/a.png)}</style></head><body></body></html>')
    out = _aw279.rewrite("html", html, "/addon-web/T")
    css = _aw279.rewrite("css", b".x{background:url('/img/b.png')} .y{background:url(//cdn.example/c.png)}",
                         "/addon-web/T")
    settings = _json279.loads(_aw279.rewrite("settings", b'{"useCookies": true, "version": "5.29"}', "/addon-web/T"))
    return out, css, settings


_rr279 = _rewrites279()
check("rewrite: a page's <base href=\"/\">, root-relative href/src and CSS url(/...) go under the link",
      b'<base href="/addon-web/T/"' in _rr279[0] and b'href="/addon-web/T/css/app.min.css"' in _rr279[0]
      and b'src="/addon-web/T/js/app.min.js"' in _rr279[0] and b"url(/addon-web/T/img/a.png)" in _rr279[0],
      _rr279[0][:400].decode())
check("rewrite: ...a protocol-relative address and a relative one are left alone",
      b'href="//cdn.example/x"' in _rr279[0] and b'href="about"' in _rr279[0], "")
check("rewrite: the storage stand-ins are the first thing in <head>, so they run before the page's own scripts",
      _rr279[0].find(_aw279.SHIM.encode()) == _rr279[0].lower().find(b"<head>") + len(b"<head>"), "")
eq("rewrite: a stylesheet's url(/...) goes under the link, url(//...) does not",
   _rr279[1], b".x{background:url('/addon-web/T/img/b.png')} .y{background:url(//cdn.example/c.png)}")
eq("rewrite: BlueMap's settings.json is told not to keep settings (localStorage), the rest kept",
   _rr279[2], {"useCookies": False, "version": "5.29"})
eq("rewrite: which answers are rewritten (HTML, CSS, BlueMap's settings.json only)",
   (_aw279.rewrites("text/html; charset=utf-8", "/", _ad279.IW4MADMIN),
    _aw279.rewrites("application/json", "/settings.json", _ad279.BLUEMAP),
    _aw279.rewrites("application/json", "/settings.json", _ad279.IW4MADMIN),
    _aw279.rewrites("application/octet-stream", "/maps/world/tiles/0/x1/z1.prbm", _ad279.BLUEMAP)),
   ("html", "settings", "", ""))
eq("rewrite: a gzip body is read for the rewrite; an encoding it can't read is None (passed on as it is)",
   (_aw279.decoded(__import__("gzip").compress(b"<head>"), "gzip"), _aw279.decoded(b"x", "br")), (b"<head>", None))


def _port279():
    sid = 7
    first = _ad279.PORT_BASE + sid
    meta = _ad279._b64(_json279.dumps({"port": first + 2}))
    good = "meta=%s\nstate=active\nown=0.0.0.0:28960 127.0.0.1:%d \n" % (meta, first + 2)
    return (_aw279.page_port(good, sid),
            _aw279.page_port(good.replace("state=active", "state=inactive"), sid),
            _aw279.page_port(good.replace("127.0.0.1:%d" % (first + 2), "127.0.0.1:1"), sid),
            _aw279.page_port("meta=%s\nstate=active\nown=127.0.0.1:22 \n" % _ad279._b64('{"port": 22}'), sid),
            _aw279.page_port("meta=%s\nstate=active\nown=127.0.0.1:%d \n"
                             % (_ad279._b64('{"port": %d}' % (first + 99)), first + 99), sid))


_pp279 = _port279()
eq("Open's read: a running add-on whose recorded port is in the server's window and listened on by the account "
   "itself gives that port; stopped, not the account's own listener, or outside the window gives none",
   _pp279, ((_ad279.PORT_BASE + 9, ""), (None, "stopped"), (None, "port"), (None, "port"), (None, "port")))
check("Open's read: it runs as the account, reads the record and asks ss for the account's OWN listeners (-p)",
      "addon.json" in _aw279.open_sh(_ad279.BLUEMAP) and "ss -Htlnp" in _aw279.open_sh(_ad279.BLUEMAP)
      and 'users:((' in _aw279.open_sh(_ad279.BLUEMAP), _aw279.open_sh(_ad279.BLUEMAP))
eq("request target: a plain path and query pass; a space, a line break or a quote ends nothing",
   (_aw279.upstream_target("/maps/world/tiles/0/x-1/z2.prbm", "v=1&x=%20"), _aw279.upstream_target("/a b", ""),
    _aw279.upstream_target("/a\r\nHost: x", ""), _aw279.upstream_target("/a", 'x="y"'),
    _aw279.upstream_target("noslash", "")),
   ("/maps/world/tiles/0/x-1/z2.prbm?v=1&x=%20", None, None, None, None))
eq("request target: the proxy percent-encodes again what WSGI hands over decoded",
   _rw279._quoted("/a b/\xc3\xbc%x"), "/a%20b/%C3%BC%25x")


class _Stream279:
    """A scripted tunnel stream: what the add-on answers, and what it was sent."""

    def __init__(self, answer, piece=7):
        self.out, self.sent, self.closed, self.piece, self.timeout = answer, b"", False, piece, None

    def settimeout(self, seconds):
        self.timeout = seconds

    def sendall(self, data):
        self.sent += bytes(data)

    def recv(self, n):
        got, self.out = self.out[:min(n, self.piece)], self.out[min(n, self.piece):]
        return got

    def close(self):
        self.closed = True


def _framing279():
    def run(answer, method="GET", cap=None):
        s = _Stream279(answer)
        try:
            head = _ht279.exchange(s, method, "/x", [("Host", "127.0.0.1:1")])
            return head.status, b"".join(_ht279.body(s, head, method, cap=cap))
        except _ht279.UpstreamError as e:
            return "error", str(e)
    return (run(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA"),
            run(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=1\r\nabc\r\n2\r\nde\r\n0\r\nT: 1\r\n\r\n"),
            run(b"HTTP/1.1 200 OK\r\n\r\nto the end"),
            run(b"HTTP/1.1 200 OK\r\n\r\n0123456789", cap=4),
            run(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort"),
            run(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n"),
            run(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", method="HEAD"),
            run(b""), run(b"SSH-2.0-OpenSSH\r\n\r\n"), run(b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 9000))


_fr279 = _framing279()
eq("HTTP: Content-Length, chunked (extensions and trailer) and to-the-end bodies are read exactly",
   _fr279[:3], ((200, b"hello"), (200, b"abcde"), (200, b"to the end")))
check("HTTP: a body past the cap, or shorter than its Content-Length, is an error, not a short page",
      _fr279[3][0] == "error" and _fr279[4][0] == "error", repr(_fr279[3:5]))
eq("HTTP: a 304 and a HEAD answer have no body", (_fr279[5], _fr279[6]), ((304, b""), (200, b"")))
check("HTTP: no answer, not HTTP, and a head past MAX_HEAD are errors",
      all(r[0] == "error" for r in _fr279[7:10]), repr(_fr279[7:10]))


def _req279():
    s = _Stream279(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    _ht279.exchange(s, "POST", "/Account/Login", [("Host", "127.0.0.1:1")], b"a=1")
    return s.sent


eq("HTTP: a request is its line, its headers, its Content-Length and its body",
   _req279(), b"POST /Account/Login HTTP/1.1\r\nHost: 127.0.0.1:1\r\nContent-Length: 3\r\n\r\na=1")


def _splice279():
    c_app, c_peer = _socket279.socketpair()
    u_app, u_peer = _socket279.socketpair()
    c_app.settimeout(0.2)
    up = _tun279._SocketStream(u_app, 0.2)
    allowed, finished = [True], _th279.Event()

    def run():
        try:
            _ht279.splice(c_app, up, b"first", still_allowed=lambda: allowed[0], recheck=0.1)
        finally:
            finished.set()
    _th279.Thread(target=run, daemon=True).start()
    c_peer.settimeout(3)
    u_peer.settimeout(3)
    got_first = c_peer.recv(5)
    c_peer.sendall(b"to-addon")
    to_addon = u_peer.recv(100)
    u_peer.sendall(b"to-browser")
    to_browser = c_peer.recv(100)
    allowed[0] = False
    ended = finished.wait(5)
    for s in (c_peer, u_peer, c_app, u_app):     # and a splice that did not end is ended here, not left running
        s.close()
    finished.wait(5)
    return got_first, to_addon, to_browser, ended


_spl279 = _splice279()
eq("WebSocket splice: the add-on's first bytes, then each side's bytes reach the other unchanged",
   _spl279[:3], (b"first", b"to-addon", b"to-browser"))
check("WebSocket splice: when the link is no longer allowed (asked every recheck) both ends are closed",
      _spl279[3], "the splice was still running")


def _local279():
    srv = _socket279.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    got = []

    def serve():
        conn, _a = srv.accept()
        got.append(conn.recv(100))
        conn.sendall(b"pong")
        conn.close()
    t = _th279.Thread(target=serve, daemon=True)
    t.start()
    _p9_patch(_tun279._core, "is_local_server", lambda server: True)
    try:
        s = _tun279.open_loopback(object(), port, timeout=3)
        s.sendall(b"ping")
        answer = s.recv(10)
        s.close()
    finally:
        _p9_restore_all()
        t.join(3)
        srv.close()
    refused = []
    for bad in (0, 70000, "21010", True):
        try:
            _tun279.open_loopback(object(), bad)
        except _tun279.TunnelError:
            refused.append(bad)
    return got, answer, refused


_lo279 = _local279()
eq("tunnel: on the panel's own host the stream is a socket to 127.0.0.1:<port>",
   (_lo279[0], _lo279[1]), ([b"ping"], b"pong"))
eq("tunnel: a port that is not a plain int in 1..65535 is refused before anything is dialled",
   _lo279[2], [0, 70000, "21010", True])


class _Chan279:
    def settimeout(self, s):
        self.t = s


class _Transport279:
    def __init__(self):
        self.asked = []

    def is_active(self):
        return True

    def open_channel(self, kind, dest, src, timeout=None):
        self.asked.append((kind, dest, src))
        return _Chan279()


def _remote279():
    tr = _Transport279()
    _p9_patch(_tun279._core, "is_local_server", lambda server: False)
    _p9_patch(_tun279._core, "get_connection", lambda server: type("C", (), {"get_transport": lambda self: tr})())
    _p9_patch(_tun279._core, "_ssh_mux_opts", lambda: ["-o", "ControlMaster=auto"])
    _p9_patch(_tun279._core, "_resolve_ts_host", lambda server: "host.tailnet.example")
    try:
        _tun279.open_loopback(type("S", (), {"auth_method": "key"})(), 21010)
        argv = _tun279._ssh_cli_argv(type("S", (), {"auth_method": "tailscale", "username": "ops", "port": 22,
                                                     "host": "host"})(), 21010)
        try:
            _tun279._ssh_cli_argv(type("S", (), {"username": "-oProxyCommand=x", "port": 22, "host": "h"})(), 21010)
            bad = "accepted"
        except _tun279.TunnelError:
            bad = "refused"
    finally:
        _p9_restore_all()
    return tr.asked, argv, bad


_re279 = _remote279()
eq("tunnel: a direct-SSH host gets a direct-tcpip channel to 127.0.0.1:<port> on the pooled connection",
   _re279[0], [("direct-tcpip", ("127.0.0.1", 21010), ("127.0.0.1", 0))])
check("tunnel: a Tailscale host gets ssh's stdio forwarding to 127.0.0.1:<port> over the multiplexed master, the "
      "destination after --", "-W" in _re279[1] and _re279[1][_re279[1].index("-W") + 1] == "127.0.0.1:21010"
      and _re279[1][-2:] == ["--", "ops@host.tailnet.example"] and "ControlMaster=auto" in _re279[1], repr(_re279[1]))
eq("tunnel: a stored login that reads as an ssh option is refused", _re279[2], "refused")


# ── 2. the routes ─────────────────────────────────────────────────────────────────────────────────
def _member279(perms):
    from werkzeug.security import generate_password_hash
    with _p9.app_context():
        grp = _m279.Group(name="p279_%d" % len(perms), description="", is_default=False)
        grp.set_permissions(perms)
        grp.servers.append(_m279.db.session.get(_m279.RemoteServer, P9_HOST))
        u = _m279.User(username="p279_%s" % "_".join(perms), password_hash=generate_password_hash(os.urandom(12).hex()),
                       display_name="p279", is_superadmin=False, is_active=True)
        u.groups.append(grp)
        _m279.db.session.add_all([grp, u])
        _m279.db.session.commit()
        return u.id, grp.id


def _session_client279(uid):
    """A test client signed in as `uid` the way a browser is: its login id names a per-device session row.

    An add-on page link is bound to that row (routes/addon_web.py refuses a login with none), so the
    client that presses Open needs one. The row records no client (ip and User-Agent empty), so the
    loader's "strong" check falls back to the Flask session's own binding, as for a row made outside a
    request. _drop_member279 deletes it with the user.
    """
    from panel.core.clock import utcnow
    with _p9.app_context():
        u = _m279.db.session.get(_m279.User, uid)
        row = _m279.UserSession(user_id=uid, sid=os.urandom(16).hex(), created_at=utcnow(), last_seen=utcnow())
        _m279.db.session.add(row)
        _m279.db.session.commit()
        login_id = "%d:%d:%s" % (uid, u.auth_epoch or 0, row.sid)
    c = _p9.test_client()
    with c.session_transaction() as s:
        s["_user_id"] = login_id
        s["_fresh"] = True
        s.permanent = True
    return c


def _drop_member279(uid, gid):
    with _p9.app_context():
        _m279.UserSession.query.filter_by(user_id=uid).delete()
        _m279.User.query.filter_by(id=uid).delete()
        _m279.Group.query.filter_by(id=gid).delete()
        _m279.db.session.commit()


_HTML279 = b'<html><head><base href="/"></head></html>\n'
_PAGE279 = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nSet-Cookie: .AspNetCore.Cookies=iw1; path=/\r\n"
            b"Set-Cookie: session=evil\r\nClear-Site-Data: \"*\"\r\nContent-Length: %d\r\n\r\n" % len(_HTML279)) + _HTML279


def _routes_setup279(answers, opened, reads):
    def shell(server, user, sh, timeout=30, **_k):
        reads.append(sh)
        return answers.pop(0) if answers else ("", "", 1)

    def tunnel(server, port, timeout=30):
        s = _Stream279(_PAGE279)
        opened.append((getattr(server, "id", None), port, s))
        return s
    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch_sm("open_loopback", tunnel)
    _p9_patch(_rw279, "game_account_write_refusal", lambda remote, user, reading=False: None)


def _open_answer279(sid, port, state="active"):
    meta = _ad279._b64(_json279.dumps({"port": port}))
    return ("meta=%s\nstate=%s\nown=127.0.0.1:%d \n" % (meta, state, port), "", 0)


def _web279(ctx, client):
    """Press Open for BlueMap on the part's server as `client`: the answer."""
    return client.post("/api/server/%d/addons/%s/web" % (ctx["sid"], _ad279.BLUEMAP))


def _r_open279(ctx, res):
    """Open: refused without the permission; refused while stopped; a running add-on's link."""
    r = _web279(ctx, _p9_client(ctx["plain"][0]))
    res["no_perm"] = (r.status_code, len(ctx["reads"]))
    ctx["answers"].append(_open_answer279(ctx["sid"], ctx["port"], "inactive"))
    r = _web279(ctx, ctx["c"])
    res["stopped"] = (r.status_code, _p9_audit("addon_web_refused").detail)
    ctx["answers"].append(_open_answer279(ctx["sid"], ctx["port"]))
    before = _p9_audit_count("addon_web_opened")
    r = _web279(ctx, ctx["c"])
    loc = r.headers.get("Location", "")
    opened_row = _p9_audit("addon_web_opened")
    res["open"] = (r.status_code, loc.startswith("/addon-web/") and loc.endswith("/"),
                   _p9_audit_count("addon_web_opened") - before, opened_row)
    ctx["token"], ctx["loc"] = loc[len("/addon-web/"):-1], loc
    res["token_in_audit"] = ctx["token"] in (opened_row.detail + opened_row.target)


def _r_proxy279(ctx, res):
    """The proxy: one page, the jar, the slash, unknown links, refused methods, other paths."""
    fresh, loc, opened = ctx["fresh"], ctx["loc"], ctx["opened"]
    r = fresh.get(loc + "maps/world/settings.json?x=1", headers={"Cookie": "session=panel", "Origin": "null",
                                                                "Accept-Encoding": "gzip"})
    last = opened[-1] if opened else (None, None, _Stream279(b""))
    res["proxy"] = (r.status_code, r.headers.get("Content-Security-Policy", ""), r.headers.get("Set-Cookie"),
                    r.headers.get("Clear-Site-Data"), r.get_data(), last[2].sent, last[:2], last[2].closed)
    fresh.get(loc)
    res["jar"] = opened[-1][2].sent if opened else b""
    r = fresh.get("/addon-web/" + ctx["token"])
    res["slash"] = (r.status_code, r.headers.get("Location"))
    dialled = len(opened)       # before the request: an unknown link dials nothing (review 1123)
    res["unknown"] = (fresh.get("/addon-web/" + "B" * 43 + "/").status_code, len(opened) - dialled)
    res["put"] = fresh.open(loc, method="PUT").status_code
    res["ws_bluemap"] = fresh.get(loc, headers={"Upgrade": "websocket", "Connection": "Upgrade"}).status_code
    res["other"] = fresh.get("/login").status_code


def _set_perms279(gid, perms):
    with _p9.app_context():
        _m279.db.session.get(_m279.Group, gid).set_permissions(perms)
        _m279.db.session.commit()


def _set_epoch279(uid, epoch):
    with _p9.app_context():
        _m279.db.session.get(_m279.User, uid).auth_epoch = epoch
        _m279.db.session.commit()


def _r_revoke279(ctx, res):
    """A removed permission, then a bumped auth epoch, end a link."""
    fresh, loc, opened = ctx["fresh"], ctx["loc"], ctx["opened"]
    _set_perms279(ctx["viewer"][1], [_auth279.VIEW_SERVERS])
    n0, k0 = _p9_audit_count("addon_web_refused"), len(opened)
    r1, r2 = fresh.get(loc), fresh.get(loc)
    res["revoked"] = (r1.status_code, r2.status_code, _p9_audit_count("addon_web_refused") - n0,
                      len(opened) - k0, _p9_audit("addon_web_refused").detail)
    _set_perms279(ctx["viewer"][1], [_auth279.VIEW_SERVERS, _auth279.VIEW_ADDON_PAGES])
    ctx["answers"].append(_open_answer279(ctx["sid"], ctx["port"]))
    loc2 = _web279(ctx, ctx["c"]).headers.get("Location", "")
    ok_before = fresh.get(loc2).status_code
    _set_epoch279(ctx["viewer"][0], 1)
    res["epoch"] = (ok_before, fresh.get(loc2).status_code)
    _set_epoch279(ctx["viewer"][0], 0)


def _r_list279(ctx, res):
    """The Add-ons list for View add-on pages alone, and for View servers alone."""
    status_out = ("os=26.04\npodman=podman version 5.7.0\nmeta.bluemap=%s\nstate.bluemap=active\n"
                  % _ad279._b64(_json279.dumps({"port": ctx["port"], "eula_accepted_by": "admin"})), "", 0)
    ctx["answers"].extend([status_out, status_out])
    _p9_patch(_ra279, "game_account_write_refusal", lambda remote, user, reading=False: None)
    res["list"] = _p9_client(ctx["viewer"][0]).get("/api/server/%d/addons" % ctx["sid"]).get_json(silent=True) or {}
    res["list_plain"] = _p9_client(ctx["plain"][0]).get("/api/server/%d/addons" % ctx["sid"]).status_code


def _routes279():
    res = {}
    ctx = {"opened": [], "reads": [], "answers": []}
    _p9_arm(who="part279")
    _routes_setup279(ctx["answers"], ctx["opened"], ctx["reads"])
    ctx["sid"] = _p9_new_server(P9_HOST, "mcp279", "mc", 25565, name="p279-mc")
    ctx["viewer"] = _member279([_auth279.VIEW_SERVERS, _auth279.VIEW_ADDON_PAGES])
    ctx["plain"] = _member279([_auth279.VIEW_SERVERS])
    ctx["port"] = _ad279.PORT_BASE + ctx["sid"]
    try:
        ctx["c"], ctx["fresh"] = _session_client279(ctx["viewer"][0]), _p9.test_client()   # the link's page: no cookie
        for step in (_r_open279, _r_proxy279, _r_revoke279, _r_list279):
            try:
                step(ctx, res)
            except Exception as e:       # a step that raised fails its checks by name (below), not the suite
                res.setdefault("raised", []).append("%s: %r" % (step.__name__, e))
    finally:
        _p9_restore_all()
        _aw279._LINKS.clear()
        _drop_member279(*ctx["viewer"])
        _drop_member279(*ctx["plain"])
        _p9_delete_server(ctx["sid"])
    return res, ctx["port"]


_rt279, _port_rt279 = _routes279()
eq("routes: no step of the routes' checks raised", _rt279.get("raised", []), [])
eq("Open: without View add-on pages (or Manage add-ons) it is refused, and the host is not asked",
   _rt279.get("no_perm"), (403, 0))
check("Open: an add-on that isn't running is refused with that reason, audited",
      _rt279.get("stopped", (0,))[0] == 409 and "not running" in _rt279.get("stopped", (0, ""))[1], repr(_rt279.get("stopped")))
check("Open: a running add-on sends the new tab (303) to its link, audited once with the add-on's name",
      _rt279.get("open", (0,))[:3] == (303, True, 1) and "BlueMap" in getattr(_rt279["open"][3], "detail", ""),
      repr(_rt279.get("open")))
check("Open: the link itself is never written to the audit log", _rt279.get("token_in_audit") is False,
      repr(_rt279.get("token_in_audit")))
_px279 = _rt279.get("proxy", (0, "", None, None, b"", b"", None, None))
check("proxy: the link's page is served with the sandbox CSP, and the add-on's Set-Cookie and Clear-Site-Data "
      "never reach the browser",
      _px279[0] == 200 and _px279[1].startswith("sandbox allow-scripts") and _px279[2] is None and _px279[3] is None,
      repr(_px279[:4]))
check("proxy: the page's HTML is rewritten under the link, with the storage stand-ins first in <head>",
      b'<base href="/addon-web/' in _px279[4] and _aw279.SHIM.encode() in _px279[4], _px279[4][:200].decode("latin-1"))
check("proxy: the request reached the add-on as /maps/world/settings.json?x=1 on 127.0.0.1:<the port read at Open>, "
      "with no panel cookie and no Origin",
      _px279[5].startswith(b"GET /maps/world/settings.json?x=1 HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % _port_rt279)
      and b"session=panel" not in _px279[5] and b"rigin" not in _px279[5] and _px279[6][1] == _port_rt279,
      _px279[5][:300].decode("latin-1"))
check("proxy: the stream is closed once the answer has been passed on", _px279[7] is True, repr(_px279[7]))
check("proxy: the add-on's own cookie (from its Set-Cookie) goes back to it on the next request, the panel's "
      "never", b"Cookie: .AspNetCore.Cookies=iw1; session=evil" in _rt279.get("jar", b"")
      and b"session=panel" not in _rt279.get("jar", b""), _rt279.get("jar", b"")[:300].decode("latin-1"))
check("proxy: a link without its trailing slash is redirected to it (BlueMap's relative paths need it)",
      _rt279.get("slash", (0, ""))[0] == 308 and str(_rt279["slash"][1]).endswith("/"), repr(_rt279.get("slash")))
eq("proxy: an unknown link is a 404 and nothing is dialled", _rt279.get("unknown", (0, -1)), (404, 0))
eq("proxy: a method other than GET, HEAD, POST (or a preflight) is refused; a WebSocket to BlueMap too",
   (_rt279.get("put"), _rt279.get("ws_bluemap")), (405, 400))
eq("proxy: every other path still goes to the panel itself", _rt279.get("other"), 200)
_rv279 = _rt279.get("revoked", (0, 0, 0, 0, ""))
eq("proxy: once the permission is removed the next request is refused (403), the link is dropped (then 404), "
   "nothing is dialled, and the refusal is audited once", _rv279[:4], (403, 404, 1, 0))
check("proxy: ...the audit row says why", "no permission" in _rv279[4], _rv279[4])
eq("proxy: a bumped auth epoch (password change, sign out everywhere) ends a link that worked a moment before",
   _rt279.get("epoch"), (200, 403))
_ls279 = _rt279.get("list", {})
eq("list: a viewer with View add-on pages alone gets only the installed add-ons with a page, and no management",
   (_ls279.get("manage"), [(a.get("id"), a.get("web"), a.get("state")) for a in _ls279.get("addons", [])],
    "databases" in _ls279), (False, [(_ad279.BLUEMAP, True, "active")], False))
eq("list: View servers alone is still refused", _rt279.get("list_plain"), 403)


def _gate279():
    """An answer the server closes before reading any of it still frees the add-on's one connection slot."""
    gate = _th279.BoundedSemaphore(1)
    gate.acquire()
    s = _Stream279(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 3\r\n\r\nabc")
    head = _ht279.exchange(s, "GET", "/i.png", [])
    link = _aw279.Link("1:0", 1, (1, 1, _ad279.IW4MADMIN, 21001), "en", 0.0)
    started = []
    body = _rw279._answer(lambda status, headers: started.append(status), s, head, "GET", "/i.png", link,
                          "/addon-web/T", gate)
    body.close()                                # never iterated: a client that went away at once
    freed = gate.acquire(timeout=0)
    body.close()                                # a second close releases nothing more
    return started, s.closed, freed


eq("proxy: an answer closed before any of it was read still closes its stream and frees the add-on's connection "
   "slot (IW4MAdmin has one: a leak would refuse every later request)", _gate279(), (["200 OK"], True, True))


def _not_modified279():
    """A 304 for a page is passed on as a 304 with no body: nothing is rewritten into it."""
    s = _Stream279(b'HTTP/1.1 304 Not Modified\r\nContent-Type: text/html\r\nETag: "e1"\r\n\r\n')
    head = _ht279.exchange(s, "GET", "/", [])
    link = _aw279.Link("1:0", 1, (1, 1, _ad279.BLUEMAP, 21001), "en", 0.0)
    started, gate = [], _th279.BoundedSemaphore(1)
    gate.acquire()
    body = _rw279._answer(lambda status, headers: started.append(status), s, head, "GET", "/", link, "/addon-web/T", gate)
    data = b"".join(body)
    return started, data


eq("proxy: a 304 for a page stays a 304 with no body (the storage stand-ins are not written into it)",
   _not_modified279(), (["304 Not Modified"], b""))


def _session279():
    """live_session_user: a link bound to a sign-in with a session row lives only as long as that row."""
    from panel.core.clock import utcnow
    with _p9.app_context():
        u = _m279.db.session.get(_m279.User, P9_ADMIN)
        row = _m279.UserSession(user_id=u.id, sid="p279sid" + "0" * 20, created_at=utcnow(), last_seen=utcnow())
        _m279.db.session.add(row)
        _m279.db.session.commit()
        key = "%d:%d:%s" % (u.id, u.auth_epoch or 0, row.sid)
        live = _auth279.live_session_user(key) is not None
        _m279.UserSession.query.filter_by(sid=row.sid).delete()
        _m279.db.session.commit()
        gone = _auth279.live_session_user(key) is None
        stale = _auth279.live_session_user("%d:%d" % (u.id, (u.auth_epoch or 0) + 5)) is None
        return live, gone, stale, _auth279.live_session_user("") is None


eq("sign-in: a link's sign-in with a session row is live; once logout deletes the row it is not; a stale epoch "
   "or no id is not", _session279(), (True, True, True, True))


def _tab279():
    with _p9.test_request_context():
        from flask_login import login_user
        uid, gid = _member279([_auth279.VIEW_SERVERS, _auth279.VIEW_ADDON_PAGES])
        try:
            u = _m279.db.session.get(_m279.User, uid)
            login_user(u)
            cod2 = type("G", (), {"game_type": "cod2"})()       # B3 only: no add-on with a page
            mc = type("G", (), {"game_type": "mc"})()
            return _ra279.tab_access(mc), _ra279.tab_access(cod2)
        finally:
            _drop_member279(uid, gid)


_tb279 = _tab279()
eq("tab: View add-on pages alone gets the Add-ons tab where an add-on with a page is offered, without managing; "
   "not where none is", ((_tb279[0]["view"], _tb279[0]["manage"]), _tb279[1]["view"]), ((True, False), False))
# Each claim read (review 1123): the label and the seeded group were never looked at.
_seed279 = _p9_seeded_default_group()
check("permission: View add-on pages is grantable, labelled, opens Files & Config, and in no group the panel made",
      _auth279.VIEW_ADDON_PAGES in _auth279.ALL_PERMISSIONS and _auth279.VIEW_ADDON_PAGES in _auth279.FILES_PAGE_PERMS
      and bool(str(_auth279.ALL_PERMISSIONS.get(_auth279.VIEW_ADDON_PAGES) or "").strip())
      and len(_seed279) == 1 and "view_servers" in (_seed279[0][1] or ())
      and _auth279.VIEW_ADDON_PAGES not in _seed279[0][1], repr((_auth279.ALL_PERMISSIONS.get(_auth279.VIEW_ADDON_PAGES),
                                                                  _seed279)))


# ── 3. the card ───────────────────────────────────────────────────────────────────────────────────
_HARNESS279 = r"""'use strict';
const fs = require('fs'), vm = require('vm');
const cfg = JSON.parse(fs.readFileSync(0, 'utf8'));
const forms = [];
function El(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.className = '';
  this._text = ''; this.style = {}; this.disabled = false; this.id = ''; this.checked = false; this.value = ''; }
El.prototype.appendChild = function (c) { this.children.push(c); c.parent = this; return c; };
El.prototype.remove = function () { this.removed = true; };
El.prototype.submit = function () { forms.push({method: this.method, action: this.action, target: this.target,
  rel: this.rel, fields: this.children.map(function (c) { return [c.type, c.name, c.value]; }),
  inBody: this.parent === body}); };
Object.defineProperty(El.prototype, 'textContent', {
  get() { return this._text + this.children.map(function (c) { return c.textContent || ''; }).join(''); },
  set(v) { this._text = String(v); this.children = []; }});
El.prototype.setAttribute = function (k, v) { this.attrs[k] = String(v); };
El.prototype.getAttribute = function (k) { return k in this.attrs ? this.attrs[k] : null; };
function walk(e, out) { out.push(e); (e.children || []).forEach(function (c) { if (c instanceof El) walk(c, out); }); return out; }
const fixed = {}, body = new El('body');
['ad-card', 'ad-list', 'ad-loading', 'ad-runtime', 'ad-msg'].forEach(function (id) { fixed[id] = new El('div'); fixed[id].id = id; });
const document = {body: body, createElement: function (t) { return new El(t); },
  createTextNode: function (t) { return {textContent: String(t)}; },
  getElementById: function (id) { return fixed[id] || null; }, querySelector: function () { return null; },
  querySelectorAll: function () { return []; }, addEventListener: function () {}};
const ctx = {document: document, MOUNT: '/m', serverId: 7, CSRF: 'csrf-279', JSON: JSON, Promise: Promise, Number: Number,
  Array: Array, setInterval: function () { return 0; }, clearInterval: function () {}, Date: Date, encodeURIComponent: encodeURIComponent,
  fetch: function () { return Promise.resolve({ok: true, json: function () { return Promise.resolve(cfg.data); }}); }};
ctx.window = ctx; ctx.addEventListener = function () {};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(cfg.src, 'utf8'), ctx);
ctx.window.adLoad(true).then(function () {
  const els = walk(fixed['ad-list'], []);
  const opens = els.filter(function (e) { return e.getAttribute('data-action') === 'adOpen'; })
    .map(function (e) { return JSON.parse(e.getAttribute('data-args')); });
  const others = els.filter(function (e) { const a = e.getAttribute('data-action'); return a && a !== 'adOpen'; }).length;
  if (opens.length) ctx.window.adOpen(opens[0][0]);
  process.stdout.write(JSON.stringify({opens: opens, others: others, forms: forms, text: fixed['ad-list'].textContent}));
}).catch(function (e) { process.stdout.write(JSON.stringify({error: String(e && e.stack || e)})); });
"""


def _card279(data):
    node = _shutil279.which("node")
    if not node:
        return {"error": "node is not installed"}
    tmp = _tf279.mkdtemp(prefix="p279-")
    try:
        path = os.path.join(tmp, "harness.js")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_HARNESS279)
        cfg = {"src": os.path.join(_ROOT279, "panel", "static", "js", "server_addons.js"), "data": data}
        r = _sp279.run([node, path], input=_json279.dumps(cfg),  # nosec B603 - node on this part's harness
                       capture_output=True, text=True, timeout=120, check=False)
        try:
            return _json279.loads(r.stdout)
        except ValueError:
            return {"error": (r.stdout + r.stderr)[-800:]}
    finally:
        _shutil279.rmtree(tmp, ignore_errors=True)


_row279 = {"id": "bluemap", "name": "BlueMap", "version": "v5", "installed": True, "state": "active", "port": 21007,
           "web": True, "eula_url": "https://www.minecraft.net/eula", "render_threads": 1}
_cm279 = _card279({"success": True, "manage": True, "addons": [_row279], "databases": []})
_cs279 = _card279({"success": True, "manage": True, "addons": [dict(_row279, state="inactive")], "databases": []})
_cv279 = _card279({"success": True, "manage": False, "addons": [{"id": "bluemap", "name": "BlueMap", "version": "v5",
                                                                  "installed": True, "state": "active", "web": True}]})
eq("card: a running add-on with a page has Open; Open posts a form to /api/server/<id>/addons/<id>/web in a new tab, "
   "with the CSRF token and no referrer",
   (_cm279.get("opens"), [(f["method"], f["action"], f["target"], f["rel"], f["fields"], f["inBody"])
                          for f in _cm279.get("forms", [])]),
   ([["bluemap"]], [("post", "/m/api/server/7/addons/bluemap/web", "_blank", "noopener noreferrer",
                     [["hidden", "csrf_token", "csrf-279"]], True)]))
check("card: the web page line no longer sends people to an SSH tunnel",
      "ssh -L" not in _cm279.get("text", "x") and "Open shows it through the panel" in _cm279.get("text", ""),
      _cm279.get("text", "")[:300])
eq("card: a stopped add-on has no Open", _cs279.get("opens"), [])
eq("card: a viewer's row has Open and nothing that manages the add-on", (_cv279.get("opens"), _cv279.get("others")),
   ([["bluemap"]], 0))


# ── 4. the text ───────────────────────────────────────────────────────────────────────────────────
def _text279():
    sentences = [_rw279._NO_PAGE, _rw279._STOPPED, _rw279._NOT_LISTENING, _rw279._UNREAD, _rw279._ENDED,
                 _rw279._REVOKED, _rw279._NO_ANSWER, _rw279._BUSY, _rw279._REFUSED,
                 _auth279.ALL_PERMISSIONS[_auth279.VIEW_ADDON_PAGES],
                 "Its web page listens on 127.0.0.1:{port} on this host only; Open shows it through the panel.",
                 "No add-on with a web page is installed on this server.", "Its page opens once the add-on is running."]
    with open(os.path.join(_ROOT279, "panel", "templates", "_server_addons.html"), encoding="utf-8") as fh:
        tpl = fh.read()
    bullet = next((ln.strip()[4:-5] for ln in tpl.splitlines() if "Open shows it through the panel" in ln), "")
    sentences.append(bullet)
    js = open(os.path.join(_ROOT279, "panel", "static", "js", "server_addons.js"), encoding="utf-8").read()
    missing = [(lang, s[:50]) for lang in ("es", "fr") for s in sentences
               if _i18n279.translate(lang, s) == s]
    return missing, bool(bullet), all(s in js for s in sentences[10:13])


_tx279 = _text279()
eq("text: every new sentence (Open's refusals, the proxy's pages, the permission, the card and its help) is in "
   "Spanish and French", _tx279[0], [])
check("text: ...the card's sentences checked are the ones server_addons.js and the template really say",
      _tx279[1] and _tx279[2], repr(_tx279[1:]))
