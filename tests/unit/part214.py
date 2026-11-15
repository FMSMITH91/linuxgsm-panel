"""Part 214 of the unit suite: web hardening from the OWASP cheat sheets.

* TLS (Transport Layer Security Cheat Sheet, "Use TLS for All Pages"): when the panel's own HTTPS is
  configured and fails to start, a network-facing bind is moved to 127.0.0.1 instead of serving plain
  HTTP there, the console says what happened and how to fix it, and the run line listens on the bind
  that was recorded; a loopback bind keeps plain HTTP, as the design behind Tailscale Serve or a proxy.
* Uploads (File Upload Cheat Sheet, "Filename Safety"): the upload route refuses a name with a
  control character, a direction override or whitespace at either end, as rename and create do.
* ntfy (SSRF Prevention Cheat Sheet): the operator-chosen server is refused when ANY address its name
  resolves to is loopback, 0.0.0.0/8, link-local (metadata), multicast, reserved or a metadata address,
  IPv4-mapped, NAT64 and 6to4 forms unwrapped first; LAN, tailnet and public addresses are connected to,
  through the one lookup that was checked; the Test button says why, in the viewer's language.
* Headers (HTTP Headers, Clickjacking Defense, XS Leaks, HSTS sheets): the response hook's rules on a
  page, a JSON answer and an asset; the pages that show a secret answer no-store through their routes.
  The full app's own responses are checked in the smoke suite (tests/smoke/part03.py).
* Socket.IO (WebSocket Security Cheat Sheet): the app's one SocketIO takes no message over 64 KB (the
  smoke suite reads it in a real handshake); the terminal page cuts a paste into pieces under that,
  never splitting a surrogate pair (run in node).
* Links and scripts: every target="_blank" anchor in the templates and the panel's JS carries
  rel="noopener noreferrer", and no panel script uses eval, new Function or a string timer.
Every route runs on part12's app with its transport tripwire armed; nothing reaches a host or data/.
"""
import contextlib as _ctx214
import io as _io214
import json as _json214
import os as _os214
import re as _re214
import shutil as _shutil214
import subprocess as _sp214  # nosec B404 - runs node on the panel's own JS, nothing else
import socket as _socket214
import types as _types214

import app as _app214
from flask import Flask as _Flask214, jsonify as _jsonify214

from unit import REPO_ROOT as _ROOT214
from unit.part01 import check, eq, skip
from unit.part12 import (P9_ADMIN, P9_GS, _P9_TRIPPED, _p9, _p9_client, _p9_json, _p9_patch, _p9_restore_all)
from panel.ops.ssh_manager import files as _files214
from panel.routes import server_files as _sf214
from panel.security import headers as _hdr214
from panel.services import certs as _certs214
from panel.services import notifications as _nt214

_trips214 = len(_P9_TRIPPED)


# ── 1. TLS that failed to start never serves plain HTTP off this host ───────────────────────────
def _tls_boot214(host, fail=True):
    """Run _boot_ssl_args with the cert step failing (or not); return (args, config, console text)."""
    fake = type("A", (), {"config": {"BOOT_BIND": host, "_BOOT_BIND": host}})()

    def _cert(*_a):
        if fail:
            raise PermissionError("cannot write /srv/p214/ssl/cert.pem")
    _p9_patch(_app214, "_effective_https", lambda cfg: True)
    _p9_patch(_app214, "_ensure_self_signed_cert", _cert)
    out = _io214.StringIO()
    try:
        with _ctx214.redirect_stdout(out):
            args = _app214._boot_ssl_args(fake, {}, host, 5214)
    finally:
        _p9_restore_all()
    return args, fake.config, out.getvalue()


_args214, _conf214, _said214 = _tls_boot214("0.0.0.0")   # nosec B104 - a bind string, not a socket
check("tls: HTTPS that fails on a public bind listens on 127.0.0.1 instead, recorded for the run line",
      _args214 == {} and _conf214["BOOT_BIND"] == "127.0.0.1" and _conf214["_BOOT_BIND"] == "127.0.0.1"
      and _conf214["BOOT_TLS"] is False and _conf214["BOOT_TLS_ERROR"] == "PermissionError", repr(_conf214))
check("tls: ...and the console says why, how to reach it now and how to fix it",
      all(s in _said214 for s in ("could not start", "127.0.0.1:5214 only", "ssh -L 5214:127.0.0.1:5214",
                                  "Tailscale Serve", "restart the panel", "trust_proxy"))
      and "serving plain HTTP instead" not in _said214, _said214)
_v6args214, _v6conf214, _ = _tls_boot214("::")
eq("tls: an IPv6 any-address bind is moved to loopback too", _v6conf214["BOOT_BIND"], "127.0.0.1")
for _lo214 in ("127.0.0.1", "::1"):
    _largs214, _lconf214, _lsaid214 = _tls_boot214(_lo214)
    check("tls: a loopback bind (%s) keeps plain HTTP there, and says it is loopback only" % _lo214,
          _largs214 == {} and _lconf214["BOOT_BIND"] == _lo214 and "loopback" in _lsaid214,
          repr((_lconf214, _lsaid214)))
_okargs214, _okconf214, _ = _tls_boot214("0.0.0.0", fail=False)   # nosec B104 - a bind string
check("tls: HTTPS that starts keeps the configured bind",
      bool(_okargs214) and _okconf214["BOOT_BIND"] == "0.0.0.0" and _okconf214["BOOT_TLS"] is True,
      repr(_okconf214))
with open(_app214.__file__, encoding="utf-8") as _fh214:
    _main214 = _fh214.read().split('if __name__ == "__main__":', 1)[1]
check("tls: the run line listens on the recorded bind, not on the configured host",
      'app.socketio.run(app, app.config["BOOT_BIND"], port,' in _main214
      and "socketio.run(app, host=host" not in _main214, "")
eq("tls: the fallback bind is loopback", _certs214.TLS_FAILED_BIND, "127.0.0.1")


# ── 2. an uploaded file's name is held to the rules a rename's is ───────────────────────────────
def _upload214(name):
    """POST one file named `name` through the upload route; return (json, names written)."""
    wrote = []
    _p9_patch(_sf214, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_files214, "_write_file_as_user",
              lambda server, user, ap, data, selfname=None: wrote.append(ap) or (True, ""))
    try:
        r = _p9_client(P9_ADMIN).post("/api/server/%d/upload" % P9_GS, content_type="multipart/form-data",
                                      data={"path": "cfg", "overwrite": "1",
                                            "file": (_io214.BytesIO(b"x"), name)})
        return _p9_json(r), wrote
    finally:
        _p9_restore_all()


_good214, _gw214 = _upload214("server.cfg")
check("upload: an ordinary name is written into the folder",
      _good214.get("success") is True and _gw214 == ["/home/csgoserver/cfg/server.cfg"], repr((_good214, _gw214)))
for _bad214, _why214 in (("evil\u202egfc.exe", "direction"), ("bell\x07.cfg", "control characters"),
                         ("server.cfg ", None), (" server.cfg", None)):
    _res214, _bw214 = _upload214(_bad214)
    check("upload: %r is refused with name_problem's reason and nothing is written" % _bad214,
          _res214.get("success") is False and _bw214 == []
          and _res214.get("message") == _files214.name_problem(_bad214)
          and (_why214 is None or _why214 in _res214.get("message", "")), repr((_res214, _bw214)))


# ── 3. the ntfy server is never reached on an address alerts are never sent to ──────────────────
class _Sock214:
    """A socket whose connect() records the address and is refused, so no request goes further."""

    def __init__(self, log):
        self.log = log

    def settimeout(self, _t):
        return None

    def connect(self, sockaddr):
        self.log.append(sockaddr[0])
        raise ConnectionRefusedError("p214 stand-in")

    def close(self):
        return None


def _ntfy214(addrs, via_route=False):
    """Send to https://ntfy.p214.example/alerts, whose name resolves to `addrs`.

    Returns (answer, getaddrinfo calls, addresses connected to): the answer is send_ntfy's (ok, detail),
    or the Test route's JSON when `via_route`.
    """
    lookups, connected = [], []

    def _gai(host, port, *_a, **_k):
        lookups.append((host, port))
        return [(_socket214.AF_INET6 if ":" in a else _socket214.AF_INET, _socket214.SOCK_STREAM, 6, "",
                 (a, port) if ":" not in a else (a, port, 0, 0)) for a in addrs]
    _p9_patch(_nt214, "socket", _types214.SimpleNamespace(
        SOCK_STREAM=_socket214.SOCK_STREAM, getaddrinfo=_gai,
        socket=lambda *_a: _Sock214(connected)))
    try:
        if via_route:
            r = _p9_client(P9_ADMIN).post("/api/notifications/test", json={
                "channel": "ntfy", "server": "https://ntfy.p214.example", "topic": "alerts"})
            return _p9_json(r), lookups, connected
        return _nt214.send_ntfy("https://ntfy.p214.example", "alerts", "", "p214"), lookups, connected
    finally:
        _p9_restore_all()


for _addrs214 in (["127.0.0.1"], ["::1"], ["169.254.169.254"], ["::ffff:169.254.169.254"],
                  ["64:ff9b::a9fe:a9fe"], ["fd00:ec2::254"], ["100.100.100.200"], ["0.0.0.0"], ["0.1.2.3"],
                  ["224.0.0.251"], ["ff02::1"], ["fe80::1%2"], ["2002:7f00:1::1"], ["240.0.0.1"],
                  ["255.255.255.255"], ["198.51.100.20", "127.0.0.1"]):
    _ans214, _look214, _conn214 = _ntfy214(_addrs214)
    check("ntfy: a server resolving to %s is refused before any connect, and says why" % _addrs214,
          _ans214 == (False, _nt214.NTFY_ADDRESS_REFUSED) and _conn214 == [] and len(_look214) == 1,
          repr((_ans214, _look214, _conn214)))
for _addrs214 in (["198.51.100.20"], ["10.1.2.3"], ["192.168.1.9"], ["100.64.5.6"], ["fd12:3456::5"],
                  ["2001:db8::20"], ["64:ff9b::c633:6414"]):
    _ans214, _look214, _conn214 = _ntfy214(_addrs214)
    check("ntfy: a server on %s (public, LAN, tailnet or NAT64 of a public one) is connected to, on the "
          "one address that was looked up and checked" % _addrs214,
          _conn214 == _addrs214 and len(_look214) == 1 and _ans214[0] is False
          and _ans214[1] != _nt214.NTFY_ADDRESS_REFUSED, repr((_ans214, _look214, _conn214)))
_seen214 = []
_p9_patch(_nt214._FallbackHTTPS, "do_open", lambda self, conn, req, **k: _seen214.append(
    (req.full_url.split("/")[2], conn.__name__)) or (_ for _ in ()).throw(OSError("p214 stand-in")))
try:
    _nt214._post("https://api.telegram.org/bot1:x/sendMessage", b"x", {}, provider="telegram")
    _nt214._post("https://ntfy.p214.example/alerts", b"x", {}, allow_configured_host=True, provider="ntfy")
finally:
    _p9_restore_all()
eq("ntfy: only the ntfy request opens the address-checking connection; Telegram keeps its own",
   _seen214, [("api.telegram.org", "_FallbackHTTPSConnection"), ("ntfy.p214.example", "_NtfyHTTPSConnection")])
_route214, _, _rconn214 = _ntfy214(["169.254.169.254"], via_route=True)
check("ntfy: the Test button names the refusal, and nothing was connected to",
      _route214.get("success") is False and "never sent to" in (_route214.get("message") or "")
      and _rconn214 == [], repr(_route214))


# ── 4. headers ──────────────────────────────────────────────────────────────────────────────────
_happ214 = _Flask214("unit_part214_headers")
_happ214.add_url_rule("/page", "page", lambda: "<p>p</p>")
_happ214.add_url_rule("/api/x", "api", lambda: _jsonify214(ok=True))
_happ214.add_url_rule("/api/own", "own", lambda: (_jsonify214(ok=True), 200, {"Cache-Control": "public, max-age=300"}))
_happ214.add_url_rule("/css", "css", lambda: ("a{}", 200, {"Content-Type": "text/css"}))
_happ214.add_url_rule("/secret", "secret", lambda: _hdr214.no_store("<p>token</p>"))


@_happ214.after_request
def _hook214(resp):
    """The two steps app.py runs, in Flask's order: the cache step first, then the security headers."""
    if "Cache-Control" not in resp.headers:
        resp.headers["Cache-Control"] = _hdr214.PRIVATE_REVALIDATE
    _hdr214.set_page_headers(resp, lambda: "default-src 'self'")
    return resp


_hc214 = _happ214.test_client()
_page214, _api214, _own214, _css214, _sec214 = (_hc214.get(u) for u in ("/page", "/api/x", "/api/own", "/css", "/secret"))
check("headers: a page is never framed (X-Frame-Options DENY), keeps no opener, prefetches no DNS, "
      "and loads only on its own origin",
      _page214.headers.get("X-Frame-Options") == "DENY"
      and _page214.headers.get("Cross-Origin-Opener-Policy") == "same-origin"
      and _page214.headers.get("X-DNS-Prefetch-Control") == "off"
      and _page214.headers.get("Cross-Origin-Resource-Policy") == "same-origin", repr(dict(_page214.headers)))
check("headers: ...and keeps no-cache, private, so the back/forward cache still works",
      _page214.headers.get("Cache-Control") == "no-cache, private", repr(_page214.headers.get("Cache-Control")))
check("headers: a JSON answer is no-store, with the inert CSP and CORP",
      _api214.headers.get("Cache-Control") == "no-store"
      and _api214.headers.get("Content-Security-Policy") == _hdr214.INERT_CSP
      and _api214.headers.get("Cross-Origin-Resource-Policy") == "same-origin"
      and "X-Frame-Options" not in _api214.headers, repr(dict(_api214.headers)))
eq("headers: ...a JSON answer that chose its own caching keeps it", _own214.headers.get("Cache-Control"),
   "public, max-age=300")
check("headers: a stylesheet keeps its caching and gets CORP",
      _css214.headers.get("Cache-Control") == "no-cache, private"
      and _css214.headers.get("Cross-Origin-Resource-Policy") == "same-origin", repr(dict(_css214.headers)))
eq("headers: no_store() makes a page that shows a secret no-store", _sec214.headers.get("Cache-Control"), "no-store")
eq("headers: HSTS is two years with includeSubDomains, and no preload", _hdr214.HSTS,
   "max-age=63072000; includeSubDomains")
check("headers: Permissions-Policy denies the sensors, serial and Bluetooth too",
      all(f + "=()" in _hdr214.PERMISSIONS_POLICY for f in ("camera", "microphone", "geolocation", "usb",
                                                           "accelerometer", "gyroscope", "magnetometer",
                                                           "serial", "bluetooth")), _hdr214.PERMISSIONS_POLICY)
with open(_os214.path.join(str(_ROOT214), "panel", "install", "app.py"), encoding="utf-8") as _fh214:
    _appsrc214 = _fh214.read()
_csp214 = _appsrc214[_appsrc214.index("    def _csp():"):_appsrc214.index("    @app.after_request")]
check("headers: the page CSP sends frame-ancestors 'none', base-uri 'none' and form-action 'self'",
      "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'" in _csp214
      and "frame-ancestors 'self'" not in _csp214, _csp214[-200:])
check("headers: HSTS in app.py is the module's value",
      'setdefault("Strict-Transport-Security", _sec_headers.HSTS)' in _appsrc214
      and "max-age=31536000" not in _appsrc214, "")
_tfa214 = _p9_client(P9_ADMIN).get("/account/2fa/enable")
check("headers: the 2FA enrolment page (its secret and QR code) is no-store, through its route",
      _tfa214.status_code == 200 and _tfa214.headers.get("Cache-Control") == "no-store",
      "%d %r" % (_tfa214.status_code, _tfa214.headers.get("Cache-Control")))
with open(_os214.path.join(str(_ROOT214), "panel", "routes", "auth_routes.py"), encoding="utf-8") as _fh214:
    _authsrc214 = _fh214.read()
check("headers: the new API token and the backup codes are rendered through no_store()",
      'no_store(render_template("account.html", languages=i18n.LANGUAGES, new_token=token))' in _authsrc214
      and 'no_store(render_template("backup_codes.html", codes=codes, first_time=True))' in _authsrc214
      and _authsrc214.count("new_token=") == 1 and _authsrc214.count('"backup_codes.html"') == 1, "")


# ── 5. Socket.IO: an explicit message limit, and a terminal paste that fits under it ────────────
_eio214 = _p9.socketio.server.eio
eq("socket.io: the app's SocketIO takes no message over 64 KB, pings every 25 s and drops a peer silent "
   "for 20 s more", (_eio214.max_http_buffer_size, _eio214.ping_interval, _eio214.ping_timeout),
   (64 * 1024, 25, 20))
_CHUNK_JS214 = r"""
%s
const paste = 'a'.repeat(8191) + '\u{1F600}' + '\u0001'.repeat(9000) + 'z';
const parts = _termChunks(paste);
const bytes = parts.map(p => Buffer.byteLength(JSON.stringify(['term_input', {data: p}])));
const lone = parts.some(p => /[\uD800-\uDBFF]$/.test(p) || /^[\uDC00-\uDFFF]/.test(p));
console.log(JSON.stringify({joined: parts.join('') === paste, n: parts.length, max: Math.max(...bytes),
                            lone: lone, empty: _termChunks('').length, small: _termChunks('ls\r')}));
"""


def _chunks214():
    if not _shutil214.which("node"):
        skip("terminal: a paste is sent in pieces under the server's message limit", "no node on this machine")
        return
    with open(_os214.path.join(str(_ROOT214), "panel", "static", "js", "host_terminal.js"), encoding="utf-8") as fh:
        src = fh.read()
    a, b = src.find("var TERM_CHUNK = 8192;"), src.find("function _r17cTermText(s) {")
    if min(a, b) < 0:
        check("terminal: a paste is sent in pieces under the server's message limit", False, "source not found")
        return
    r = _sp214.run(["node", "-"], input=_CHUNK_JS214 % src[a:b], capture_output=True, text=True,  # nosec B603 B607
                   timeout=60, check=False)
    try:
        got = _json214.loads(r.stdout.strip())
    except ValueError:
        got = {"error": (r.stdout + r.stderr)[-300:]}
    check("terminal: a paste is sent in pieces that rebuild it exactly, each under the server's 64 KB "
          "limit even when every character is JSON-escaped, never splitting an emoji",
          got.get("joined") is True and got.get("n") == 3 and got.get("max", 1 << 20) < 64 * 1024
          and got.get("lone") is False and got.get("empty") == 0 and got.get("small") == ["ls\r"], repr(got))
    with open(_os214.path.join(str(_ROOT214), "panel", "static", "js", "host_terminal.js"), encoding="utf-8") as fh:
        src = fh.read()
    check("terminal: keystrokes go out through _termChunks, one emit per piece",
          "_termChunks(data).forEach(function (part) { sock.emit('term_input', { data: part }); });" in src
          and src.count("emit('term_input'") == 1, "")


_chunks214()


eq("part214: nothing reached a real transport", _P9_TRIPPED[_trips214:], [])
