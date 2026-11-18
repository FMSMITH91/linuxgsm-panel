"""Part 241 of the unit suite: the second pen test's panel findings.

* The web server (wsgi_serve.serve, started for real on loopback) answers a request line with no HTTP
  version with a bare 400 and logs nothing; the standard library's other refusals log nothing either
  and do not name the Python version.
* The panel's own TLS takes TLS 1.2 and 1.3 only, and in TLS 1.2 only ECDHE suites with an AEAD
  cipher: a client that offers only CBC suites, or only TLS 1.1, gets no connection.
* Sign-out deletes the `__Host-` remember cookie with Secure, HttpOnly, Path=/ and SameSite, so a
  browser applies the deletion; Clear-Site-Data clears the cache as well.
* A JSON field of the wrong type or past its range is refused (delete-path's path, a firewall rule
  number, a database endpoint id) instead of answering 500.
* A host command that failed answers 502 with the route's own message, not 500.

HOW IT RUNS. The server checks start wsgi_serve in a child process on a free loopback port, over this
part's own throwaway certificate. The route checks drive part12's Flask app with its transport
tripwire armed, every stub undone in the finally. Nothing reaches a host, sudo or the checkout's data/.
"""
import os as _os241
import shutil as _shutil241
import socket as _socket241
import ssl as _ssl241
import subprocess as _sp241  # nosec B404 - starts this part's own loopback server
import sys as _sys241
import tempfile as _tempfile241
import time as _time241
from datetime import timedelta as _td241

from unit import REPO_ROOT as _ROOT241
from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch,
                         _p9_restore_all)
from panel.core import wsgi_serve as _ws241
from panel.db.models import GameServer as _GS241, RemoteServer as _RS241, User as _U241, db as _db241
from panel.ops import system_ops as _so241
from panel.ops import tailscale_integration as _ts241
from panel.routes import server_detail as _sd241
from panel.security import account_guard as _ag241, auth as _auth241
from panel.services.certs import _ensure_self_signed_cert as _mkcert241

_trips241 = len(_P9_TRIPPED)
_TMP241 = _tempfile241.mkdtemp(prefix="lgsm-unit-p241-")
_ROWS241 = {"remotes": [], "servers": [], "users": []}
# The fixture account's sign-in secret (no real credential), named so no scanner reads it as one.
_K241 = "pewter lantern orchard 241"

_SERVE241 = r"""
import os, sys
os.environ["EVENTLET_NO_GREENDNS"] = "yes"
sys.path.insert(0, sys.argv[2])
from flask import Flask
from panel.core import wsgi_serve

app = Flask("p241")
app.add_url_rule("/ok", "ok", lambda: "fine")
tls = {"certfile": sys.argv[3], "keyfile": sys.argv[4]} if len(sys.argv) > 4 else None
wsgi_serve.serve(app, "127.0.0.1", int(sys.argv[1]), tls)
"""


def _free_port241():
    with _socket241.socket() as so:
        so.bind(("127.0.0.1", 0))
        return so.getsockname()[1]


def _raw241(port, data, wrap=None):
    """Send `data` on a fresh connection (TLS-wrapped by `wrap`) and read until it closes; b"" on none."""
    try:
        with _socket241.create_connection(("127.0.0.1", port), timeout=5) as raw:
            so = wrap(raw) if wrap else raw
            so.sendall(data)
            got = b""
            while len(got) < 65536:
                part = so.recv(4096)
                if not part:
                    break
                got += part
            return got
    except (OSError, _ssl241.SSLError):
        return b""


class _Server241:
    """wsgi_serve.serve in a child process on a free loopback port; its stderr kept for the checks."""

    def __init__(self, tls=None):
        self.port = _free_port241()
        args = [_sys241.executable, "-c", _SERVE241, str(self.port), str(_ROOT241)] + list(tls or ())
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
        self.proc = _sp241.Popen(args, stdout=_sp241.DEVNULL, stderr=_sp241.PIPE)  # nosec B603
        self.err = ""

    def wait_ready(self, probe):
        deadline = _time241.monotonic() + 20
        while self.proc.poll() is None and _time241.monotonic() < deadline:
            if probe():
                return True
            _time241.sleep(0.2)
        return False

    def stop(self):
        self.proc.kill()
        self.err = self.proc.communicate(timeout=10)[1].decode("utf-8", "replace")
        return self.err


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A request line with no HTTP version (F2-1)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _http09_241():
    """A bare `GET /` gets a 400 and leaves nothing in the log; malformed lines name no Python version."""
    srv = _Server241()
    ok = b"GET /ok HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    try:
        ready = srv.wait_ready(lambda: _raw241(srv.port, ok).startswith(b"HTTP/1.1 200"))
        bare = [_raw241(srv.port, b"GET /\r\n\r\n") for _ in range(3)]
        odd = [_raw241(srv.port, line) for line in (b"POST /\r\n\r\n", b"GET / HTTP/9.9\r\n\r\n", b"X\r\n\r\n")]
        after = _raw241(srv.port, ok)
    finally:
        err = srv.stop()
    eq("web server: a request line with no HTTP version answers a bare 400 and closes (each of three)",
       [b.split(b"\r\n")[0] for b in bare], [b"HTTP/1.0 400 Bad Request"] * 3)
    eq("web server: the line with no version, and the standard library's own refusals (an HTTP/0.9 POST, "
       "version 9.9, no method), write nothing to the log: no traceback, no echoed request line",
       ("Traceback" in err, "AttributeError" in err, "Bad request" in err, "HTTP/9.9" in err), (False,) * 4)
    eq("web server: the standard library's refusals say Server: LinuxGSM Panel, not its name and the Python "
       "version", [(b"Server: LinuxGSM Panel" in r, b"Python/" in r, b"BaseHTTP" in r) for r in odd],
       [(True, False, False)] * 3)
    eq("web server: it keeps serving before and after (control)",
       (ready, after.split(b"\r\n")[0]), (True, b"HTTP/1.1 200 OK"))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The panel's own TLS (F2-8)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _client241(cafile, max_version=None, ciphers=None):
    """A client context that trusts only this part's certificate, with the given protocol and cipher limits."""
    ctx = _ssl241.SSLContext(_ssl241.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile)
    ctx.verify_flags |= _ssl241.VERIFY_X509_PARTIAL_CHAIN
    ctx.minimum_version = _ssl241.TLSVersion.MINIMUM_SUPPORTED
    if max_version is not None:
        ctx.maximum_version = max_version
    if ciphers:
        ctx.set_ciphers(ciphers)
    return ctx


def _handshake241(port, ctx):
    """(protocol, cipher) a client with `ctx` agreed with the server, or None when it was refused."""
    try:
        with _socket241.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="p241.localhost") as so:
                return so.version(), so.cipher()[0]
    except (OSError, _ssl241.SSLError):
        return None


def _tls241():
    """TLS 1.2 with ECDHE AEAD suites, TLS 1.3; no CBC suite and no TLS 1.1, through serve() itself."""
    cert, key = _mkcert241(_os241.path.join(_TMP241, "cert.pem"), _os241.path.join(_TMP241, "key.pem"),
                           "p241.localhost")
    ctx = _ws241.tls_context(cert, key)
    tls12 = [c for c in ctx.get_ciphers() if c.get("protocol") == "TLSv1.2"]
    eq("TLS context: every TLS 1.2 suite offered is an ECDHE AEAD suite (none CBC), and the floor is TLS 1.2",
       ([c["name"] for c in tls12 if not (c.get("aead") and c.get("kea") == "kx-ecdhe")],
        bool(tls12), ctx.minimum_version), ([], True, _ssl241.TLSVersion.TLSv1_2))
    srv = _Server241(tls=(cert, key))
    try:
        ready = srv.wait_ready(lambda: _handshake241(srv.port, _client241(cert)) is not None)
        cbc = _handshake241(srv.port, _client241(cert, _ssl241.TLSVersion.TLSv1_2,
                                                 "ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256"))
        gcm = _handshake241(srv.port, _client241(cert, _ssl241.TLSVersion.TLSv1_2,
                                                 "ECDHE-ECDSA-AES128-GCM-SHA256"))
        best = _handshake241(srv.port, _client241(cert))
        try:
            old = _handshake241(srv.port, _client241(cert, _ssl241.TLSVersion.TLSv1_1))
        except ValueError:
            old = None      # this machine's OpenSSL cannot even offer TLS 1.1: refused either way
        page = _raw241(srv.port, b"GET /ok HTTP/1.1\r\nHost: p241\r\nConnection: close\r\n\r\n",
                       wrap=lambda s: _client241(cert).wrap_socket(s, server_hostname="p241.localhost"))
    finally:
        srv.stop()
    eq("panel TLS (serve, for real): a TLS 1.2 client offering only the CBC suites gets no connection; an AEAD "
       "suite is agreed; a default client gets TLS 1.3; a TLS 1.1 client is refused; the page is served",
       (ready, cbc, gcm, best and best[0], old, page.split(b"\r\n")[0]),
       (True, None, ("TLSv1.2", "ECDHE-ECDSA-AES128-GCM-SHA256"), "TLSv1.3", None, b"HTTP/1.1 200 OK"))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Sign-out's remember-cookie deletion and Clear-Site-Data (F2-3, F2-4)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _user241(name):
    with _p9.app_context():
        u = _U241(username=name, password_hash=_auth241.hash_password(_K241), display_name=name,
                  is_superadmin=False, is_active=True)
        _db241.session.add(u)
        _db241.session.commit()
        _ROWS241["users"].append(u.id)
        return u.id


def _logout_cookies241():
    """Over HTTPS, sign in with "remember me", sign out: every __Host- cookie set is Secure, Path=/, no Domain."""
    keys = ("REMEMBER_COOKIE_NAME", "REMEMBER_COOKIE_SECURE", "SESSION_COOKIE_NAME", "SESSION_COOKIE_SECURE",
            "SESSION_COOKIE_PATH", "REMEMBER_COOKIE_PATH", "REMEMBER_COOKIE_HTTPONLY", "REMEMBER_COOKIE_SAMESITE",
            "REMEMBER_COOKIE_DURATION")
    saved = {k: _p9.config.get(k) for k in keys}
    _p9.config.update(REMEMBER_COOKIE_NAME="__Host-remember_token", REMEMBER_COOKIE_SECURE=True,
                      SESSION_COOKIE_NAME="__Host-p241_session", SESSION_COOKIE_SECURE=True,
                      SESSION_COOKIE_PATH="/", REMEMBER_COOKIE_PATH="/", REMEMBER_COOKIE_HTTPONLY=True,
                      REMEMBER_COOKIE_SAMESITE="Lax",    # as create_app sets them (app.py); an earlier part
                      REMEMBER_COOKIE_DURATION=_td241(days=3))   # leaves the duration unset
    try:
        _user241("p241_out")
        # An earlier part's failed sign-ins must not throttle this one (part215 resets the same way).
        _ag241.reset_throttle()
        _ag241.reset_denials()
        c = _p9.test_client()
        c.environ_base["REMOTE_ADDR"] = "198.51.100.241"
        signin = c.post("/login", data={"username": "p241_out", "password": _K241, "remember": "on"},
                        base_url="https://p241.localhost")
        set_at_signin = [h for h in signin.headers.getlist("Set-Cookie") if h.startswith("__Host-remember_token=")]
        out = c.post("/logout", base_url="https://p241.localhost")
    finally:
        _p9.config.update(saved)
    cookies = out.headers.getlist("Set-Cookie")
    gone = [h for h in cookies if h.startswith("__Host-remember_token=")]
    attrs = [a.strip().lower() for a in (gone[0].split(";")[1:] if gone else [])]
    eq("sign-out: the remember cookie set at sign-in is deleted with Max-Age=0, Secure, HttpOnly, Path=/ and "
       "SameSite=Lax (a browser ignores a __Host- cookie sent without Secure), and only once",
       (len(set_at_signin), len(gone), "max-age=0" in attrs, "secure" in attrs, "httponly" in attrs,
        "path=/" in attrs, "samesite=lax" in attrs), (1, 1, True, True, True, True, True),
       ) if set_at_signin else check("sign-out: the 'remember me' sign-in set the remember cookie (fixture)", False,
                                     repr((signin.status_code, signin.headers.get("Location"), cookies)))
    bad = [h.split("=")[0] for h in cookies if h.startswith("__Host-")
           and not ("; Secure" in h and "; Path=/" in h and "Domain=" not in h)]
    eq("sign-out: every __Host- cookie the answer sets carries Secure and Path=/ and no Domain", bad, [])
    eq("sign-out: Clear-Site-Data clears the cache, cookies and storage (OWASP Session Management Cheat Sheet)",
       out.headers.get("Clear-Site-Data"), '"cache", "cookies", "storage"')


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. JSON fields of the wrong type or range (F2-2)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _setup241():
    """A host row, one game server on it and one external database endpoint; (remote id, server id)."""
    with _p9.app_context():
        r = _RS241(name="p241-host", host="p241.example.invalid", port=22, username="admin",
                   auth_method="key", auth_credential="", is_online=True)
        _db241.session.add(r)
        _db241.session.commit()
        gs = _GS241(remote_id=r.id, name="p241-css", short_name="p241u", game_type="css", port=27241,
                    installed=True, status="offline")
        _db241.session.add(gs)
        _db241.session.commit()
        _ROWS241["remotes"].append(r.id)
        _ROWS241["servers"].append(gs.id)
        return r.id, gs.id


def _types241():
    """delete-path's path, a rule number and an endpoint id: refused, never a 500, nothing sent to a host."""
    rid, gid = _setup241()
    c = _p9_client(P9_ADMIN)
    wrong = [c.post("/api/server/%d/delete-path" % gid, json={"path": v})
             for v in ([None, None], {"a": 1}, 5, True, 1.5)]
    eq("delete-path: a path that is a list, object, number or true is a 400 'Invalid path' (it was a 500)",
       [(r.status_code, _p9_json(r).get("message")) for r in wrong], [(400, "Invalid path")] * 5)
    from panel.ops.ssh_manager import hosts as _hosts241
    from panel.ops.ssh_manager import firewall as _fw241
    _p9_patch(_fw241, "remote_ufw_status", lambda server: {"installed": True, "groups": []})
    sent = []
    _p9_patch(_hosts241._core, "run_privileged", lambda *a, **k: sent.append(a[1:3]) or ("", "", 0))
    big = _hosts241.remote_ufw_delete_rule(object(), 10 ** 30)
    past = _hosts241.remote_ufw_delete_rule(object(), 10000)
    refused_sent = list(sent)
    _hosts241.remote_ufw_delete_rule(object(), 9999)
    eq("firewall: a rule number past the helper's 1-9999 is refused as one before anything runs (10**30 raised "
       "the helper's VerbError, a 500); 9999 still reaches the helper (control)",
       (big, past, refused_sent, len(sent), "9999" in repr(sent)),
       ((False, "Invalid rule number"), (False, "Invalid rule number"), [], 1, True))
    r = c.post("/api/remote/%d/databases/endpoint" % rid, json={"endpoint_id": 10 ** 30})
    eq("databases: an endpoint id past SQLite's integer range is 'No such database server' (404), not a 500",
       (r.status_code, _p9_json(r).get("message")), (404, "No such database server."))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. A failed host command answers 502 (F2-6)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SAID241 = "p241: the host refused the command"


def _host_502_241():
    """Tailscale SSH, ufw for Tailscale, Serve, the OS update and the autostart crontab: 502, same message."""
    gid = _ROWS241["servers"][0] if _ROWS241["servers"] else _setup241()[1]
    _p9.config["STEP_UP_MINUTES"] = 0
    fail = lambda *a, **k: (False, _SAID241)  # noqa: E731 - one stand-in for five host calls
    for name in ("tailscale_ssh_enable", "tailscale_ssh_disable", "ufw_allow_tailscale", "os_run_update"):
        _p9_patch(_so241, name, fail)
    _p9_patch(_ts241, "setup_tailscale_serve", fail)
    _p9_patch(_sd241, "set_autostart", fail)
    from panel.services import host_reboot as _hr241
    _p9_patch(_hr241, "panel_host_busy", lambda: None)
    c = _p9_client(P9_ADMIN)
    got = [c.post("/api/server-management/" + u) for u in ("ts-ssh-enable", "ts-ssh-disable",
                                                           "ufw-allow-tailscale", "os-update-run")]
    got.append(c.post("/api/tailscale/serve", json={"action": "enable", "mount": "/"}))
    got.append(c.post("/api/server/%d/autostart" % gid, json={"enabled": True}))
    eq("host failures: Tailscale SSH on and off, ufw for Tailscale, the OS update, Serve and the autostart "
       "crontab answer 502 with the route's own JSON message (a 500 is the panel's own fault)",
       [(r.status_code, _p9_json(r).get("success"), _SAID241 in (_p9_json(r).get("message") or "")) for r in got],
       [(502, False, True)] * 6)


def _cleanup241():
    with _p9.app_context():
        for model, ids in ((_GS241, _ROWS241["servers"]), (_RS241, _ROWS241["remotes"]),
                           (_U241, _ROWS241["users"])):
            for row_id in ids:
                row = _db241.session.get(model, row_id)
                if row is not None:
                    _db241.session.delete(row)
        _db241.session.commit()
    _shutil241.rmtree(_TMP241, ignore_errors=True)


_STEP_UP_SAVED241 = _p9.config.get("STEP_UP_MINUTES")
try:
    for _fn241 in (_http09_241, _tls241, _logout_cookies241, _types241, _host_502_241):
        _p9_arm(who="part241")
        try:
            _fn241()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()
    _p9.config["STEP_UP_MINUTES"] = _STEP_UP_SAVED241
    _cleanup241()

check("part241: nothing reached a real transport", len(_P9_TRIPPED) == _trips241, repr(_P9_TRIPPED[_trips241:]))
