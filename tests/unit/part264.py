"""Part 264 of the unit suite: review pass 32's security fixes.

1. The web server (wsgi_serve.serve, started for real on loopback in a child process) holds a request to
   whole-request deadlines, not per-read timeouts: a client trickling its request line and headers one
   byte at a time is closed at the header deadline, a TLS handshake trickled the same way at the idle
   time, and a body sent below the minimum rate is answered and the connection closed (OWASP Denial of
   Service Cheat Sheet, "Rate limiting": request-read timeouts with a minimum ingress rate, an absolute
   timeout, a load limit). A route that takes its time between reads of a fast body loses nothing; a
   Socket.IO WebSocket outlives every deadline. One source holds a bounded number of connections
   (loopback, where a proxy's viewers arrive, is not counted). A response the client stops reading
   leaves no traceback in the log (OWASP Logging Cheat Sheet, "Attacks on Logs"), while a timeout of
   the panel's own still does.
"""
import os
import socket as _socket264
import ssl as _ssl264
import subprocess as _sp264  # nosec B404 - the web server in a child process, a fixed argv
import sys as _sys264
import tempfile as _tf264
import time as _time264

from unit import REPO_ROOT as _ROOT264
from unit.part01 import check, eq, skip
from panel.core import wsgi_serve as _ws264

_TMP264 = _tf264.mkdtemp(prefix="p264-")

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The web server: whole-request deadlines, the body's minimum rate, the per-source cap, quiet stalls
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SERVE264 = r"""
import os, sys
os.environ["EVENTLET_NO_GREENDNS"] = "yes"
sys.path.insert(0, sys.argv[2])
mode = sys.argv[3]
import eventlet
if mode == "ws":
    eventlet.monkey_patch()
from flask import Flask, Response, request
from panel.core import wsgi_serve
from panel.ops import socket_hooks

app = Flask("p264")
app.add_url_rule("/ok", "ok", lambda: "fine")
app.add_url_rule("/big", "big", lambda: "x" * (8 << 20))


def up():
    return "got %d" % len(request.get_data())


def slow_app():
    # Reads the body in small pieces and spends 0.8 s on each, as an upload copied on over SSH does:
    # the client is not the one being slow. Counted on the clock instead, 200 bytes earn 0.4 s, so the
    # 1 s grace would be spent by the third piece.
    got = 0
    while True:
        part = request.stream.read(200)
        if not part:
            break
        got += len(part)
        eventlet.sleep(0.8)
    return "got %d" % got


def own_timeout():
    def gen():
        yield b"x" * 10
        raise TimeoutError("an SSH read of the panel's own timed out")
    return Response(gen())


app.add_url_rule("/up", "up", up, methods=["POST"])
app.add_url_rule("/slowapp", "slowapp", slow_app, methods=["POST"])
app.add_url_rule("/own", "own", own_timeout)
port = int(sys.argv[1])
kw = dict(idle_seconds=1, io_timeout=3)
limits = dict(header=2.5, body_grace=1, body_rate=500)
tls = None
if mode == "ws":
    socket_hooks.LIMITS.update(ping_interval=1, ping_timeout=1)
    from flask_socketio import SocketIO
    SocketIO(app, async_mode="eventlet", **socket_hooks.LIMITS)
    kw.update(io_timeout=None)
elif mode == "cap":
    # Loopback is not counted (a proxy's viewers all arrive on it), so for this server every
    # connection is counted under the address it came from.
    wsgi_serve._source_key = lambda addr: str(addr[0])  # noqa: E731
    kw.update(idle_seconds=8)
    limits.update(header=8, per_source=3)
elif mode == "tls":
    tls = {"certfile": sys.argv[4], "keyfile": sys.argv[5]}
wsgi_serve.serve(app, "127.0.0.1", port, tls, limits=limits, **kw)
"""
_OK264 = b"GET /ok HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"


def _free_port264():
    with _socket264.socket() as so:
        so.bind(("127.0.0.1", 0))
        return so.getsockname()[1]


def _get_ok264(port, wrap=None):
    """The status line of GET /ok on a fresh connection, b"" when there is no answer."""
    try:
        with _socket264.create_connection(("127.0.0.1", port), timeout=5) as raw:
            so = wrap(raw) if wrap else raw
            so.sendall(_OK264)
            return so.recv(4096).split(b"\r\n")[0]
    except (OSError, _ssl264.SSLError):
        return b""


class _Server264:
    """wsgi_serve.serve in a child process on a free loopback port (`mode` picks the set-up)."""

    def __init__(self, mode, extra=(), wrap=None):
        self.port = _free_port264()
        argv = [_sys264.executable, "-c", _SERVE264, str(self.port), str(_ROOT264), mode, *extra]
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
        self.proc = _sp264.Popen(argv, stdout=_sp264.DEVNULL, stderr=_sp264.PIPE)  # nosec B603
        deadline = _time264.monotonic() + 30
        self.ready = False
        while self.proc.poll() is None and _time264.monotonic() < deadline and not self.ready:
            self.ready = _get_ok264(self.port, wrap) == b"HTTP/1.1 200 OK"
            if not self.ready:
                _time264.sleep(0.2)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
        return self.proc.communicate(timeout=10)[1].decode("utf-8", "replace")


def _trickle264(port, data, gap, limit, head=b""):
    """Send `head`, then `data` one byte every `gap` s: (seconds until the server ended it or None, what it sent).

    None when the connection was still open after `limit` s (each byte arriving well inside every
    per-read timeout, so only a whole-request deadline ends it).
    """
    got = b""
    try:
        so = _socket264.create_connection(("127.0.0.1", port), timeout=5)
    except OSError:
        return "no connection", b""
    try:
        so.settimeout(0.05)
        t0 = _time264.monotonic()
        if head:
            so.sendall(head)
        for i in range(10 ** 6):
            if _time264.monotonic() - t0 > limit:
                return None, got
            try:
                if i < len(data):
                    so.send(data[i:i + 1])
                part = so.recv(4096)
                if not part:
                    return round(_time264.monotonic() - t0, 1), got
                got += part
            except _socket264.timeout:
                # Nothing from the server yet: wait out the gap before the next byte.
                _time264.sleep(gap)
            except OSError:
                return round(_time264.monotonic() - t0, 1), got
        return None, got
    finally:
        so.close()


# Headers a byte every 0.4 s: each read makes progress well inside the 3 s read timeout, so only the
# 2.5 s header deadline ends it.
_HEADERS264 = b"GET /ok HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: " + b"a" * 200 + b"\r\n\r\n"
_srv_d264 = _Server264("deadlines")
try:
    if _srv_d264.ready:
        _hdr264 = _trickle264(_srv_d264.port, _HEADERS264, 0.4, 12)
        # A body at ~2.5 bytes a second (100,000 promised): 1 s of grace and one more second per 500
        # bytes is spent at about 1 s, and the request is answered, then the connection closed.
        _body264 = _trickle264(_srv_d264.port, b"z" * 400, 0.4, 12,
                               head=b"POST /up HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100000\r\n\r\n")
        # A whole 1,000-byte body sent at once to a route that reads 200 bytes at a time and spends
        # 0.8 s on each (4 s in all, past the 1 s grace): every byte arrives.
        with _socket264.create_connection(("127.0.0.1", _srv_d264.port), timeout=30) as _so264:
            _so264.sendall(b"POST /slowapp HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
                           b"Content-Length: 1000\r\n\r\n" + b"y" * 1000)
            _slow_app264 = b""
            while True:
                _part264 = _so264.recv(4096)
                if not _part264:
                    break
                _slow_app264 += _part264
        # A client that asks for 8 MB and never reads: the write times out after the 3 s read timeout.
        _stall264 = _socket264.socket()
        _stall264.setsockopt(_socket264.SOL_SOCKET, _socket264.SO_RCVBUF, 4096)
        _stall264.connect(("127.0.0.1", _srv_d264.port))
        _stall264.sendall(b"GET /big HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        _time264.sleep(5)
        _stall264.close()
        _own264 = _trickle264(_srv_d264.port, b"", 0.1, 5, head=b"GET /own HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        _after_d264 = _get_ok264(_srv_d264.port)
    else:
        _hdr264 = _body264 = _own264 = ("not ready", b"")
        _slow_app264 = _after_d264 = b"not ready"
finally:
    _err_d264 = _srv_d264.stop()
check("web server r32: a request whose line and headers arrive one byte every 0.4 s (each read well inside the "
      "3 s read timeout) is closed at the 2.5 s header deadline (it stayed for as long as the client liked)",
      isinstance(_hdr264[0], float) and 2.0 <= _hdr264[0] < 5 and _hdr264[1] == b"",
      "closed after %r s, answer %r" % (_hdr264[0], _hdr264[1][:60]))
check("web server r32: a body sent below the minimum rate is answered (400) and the connection closed, about when "
      "its budget runs out (1 s of grace here), not kept for as long as each byte keeps a read alive",
      isinstance(_body264[0], float) and _body264[0] < 5 and _body264[1].startswith(b"HTTP/1.1 400")
      and b"Connection: close" in _body264[1], "after %r s: %r" % (_body264[0], _body264[1][:120]))
check("web server r32: a body sent at once and read by a route that spends 4 s on it, in pieces too small to earn "
      "that time at the minimum rate, arrives whole (only time spent waiting for the client counts)",
      _slow_app264.startswith(b"HTTP/1.1 200") and _slow_app264.endswith(b"got 1000"), _slow_app264[-120:])
check("web server r32: a client that stops reading an 8 MB answer leaves no traceback and no error in the log "
      "(it logged one ERROR traceback per connection per read timeout)",
      _err_d264.count("A response failed") == 1 and "TimeoutError: timed out" not in _err_d264, _err_d264[-800:])
check("web server r32: ...while a timeout of the panel's own inside a streamed answer is still logged in full",
      "A response failed" in _err_d264 and "an SSH read of the panel's own timed out" in _err_d264,
      "own=%r log=%s" % (_own264[0], _err_d264[-400:]))
eq("web server r32: ...and the server answers the next request", _after_d264, b"HTTP/1.1 200 OK")


# The panel's own TLS: a handshake trickled a byte every 0.3 s (a record header promising 16,000 bytes,
# then its body) is closed at the 1 s idle time, which covers everything before the request's first byte.
from panel.services.certs import _ensure_self_signed_cert as _mkcert264  # noqa: E402

_CERT264 = os.path.join(_TMP264, "cert.pem")
_KEY264 = os.path.join(_TMP264, "key.pem")
_mkcert_err264 = ""
try:
    _mkcert264(_CERT264, _KEY264, "p264.localhost")
except (OSError, ValueError) as _e264:   # the TLS check below then names it instead of crashing the part
    _mkcert_err264 = repr(_e264)


def _tls_wrap264(raw):
    """A client that trusts only this part's certificate, at the library's default (TLS 1.2 or newer)."""
    ctx = _ssl264.SSLContext(_ssl264.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = _ssl264.TLSVersion.TLSv1_2
    ctx.load_verify_locations(_CERT264)
    ctx.verify_flags |= _ssl264.VERIFY_X509_PARTIAL_CHAIN
    return ctx.wrap_socket(raw, server_hostname="p264.localhost")


_srv_s264 = _Server264("tls", (_CERT264, _KEY264), wrap=_tls_wrap264) if not _mkcert_err264 else None
try:
    if _srv_s264 is not None and _srv_s264.ready:
        _hs264 = _trickle264(_srv_s264.port, b"\x01" * 200, 0.3, 10, head=b"\x16\x03\x01\x3e\x80")
        _after_s264 = _get_ok264(_srv_s264.port, _tls_wrap264)
    else:
        _hs264, _after_s264 = ("not ready %s" % _mkcert_err264, b""), b""
finally:
    _err_s264 = _srv_s264.stop() if _srv_s264 is not None else ""
check("web server r32: a TLS handshake trickled a byte every 0.3 s is closed at the 1 s idle time (each read made "
      "progress, so the per-read timeouts never fired)", isinstance(_hs264[0], float) and _hs264[0] < 3,
      "closed after %r s" % (_hs264[0],))
eq("web server r32: ...the TLS server then serves the next request, with no traceback logged",
   (_after_s264, "Traceback" in _err_s264), (b"HTTP/1.1 200 OK", False))


# One source holds at most per_source connections (3 here): the fourth is closed as soon as it is
# accepted, one warning names it, and once the three are gone the source is served again.
_srv_c264 = _Server264("cap")
_held264 = []
try:
    if _srv_c264.ready:
        _time264.sleep(0.3)      # the readiness probe's own connection is gone
        for _ in range(3):
            _held264.append(_socket264.create_connection(("127.0.0.1", _srv_c264.port), timeout=5))
        _time264.sleep(0.3)
        _fourth264 = _trickle264(_srv_c264.port, b"", 0.1, 4)
        _held_open264 = []
        for _so264 in _held264:
            _so264.settimeout(0.2)
            try:
                _held_open264.append(_so264.recv(10) != b"")
            except _socket264.timeout:
                _held_open264.append(True)
            except OSError:
                _held_open264.append(False)
        for _so264 in _held264:
            _so264.close()
        _time264.sleep(0.5)
        _after_c264 = _get_ok264(_srv_c264.port)
    else:
        _fourth264, _held_open264, _after_c264 = ("not ready", b""), [], b""
finally:
    for _so264 in _held264:
        _so264.close()
    _err_c264 = _srv_c264.stop()
check("web server r32: a source holding its 3 connections has a fourth closed at once (it waited for room in "
      "the pool of 1,024 with everyone else)", isinstance(_fourth264[0], float) and _fourth264[0] < 1,
      "fourth closed after %r s" % (_fourth264[0],))
eq("web server r32: ...the three it holds stay open, and once they close the source is served again",
   (_held_open264, _after_c264), ([True, True, True], b"HTTP/1.1 200 OK"))
check("web server r32: ...and the log says so once, naming the source, with no traceback",
      _err_c264.count("already holds 3 connections") == 1 and "Traceback" not in _err_c264, _err_c264[-500:])
eq("web server r32: the per-source key: loopback (v4, v6, mapped) is not counted, a mapped address is its IPv4, "
   "an IPv6 source counts as its /64",
   [_ws264._source_key(a) for a in (("127.0.0.1", 1), ("127.8.9.1", 1), ("::1", 1, 0, 0),
                                     ("::ffff:127.0.0.1", 1, 0, 0), ("203.0.113.9", 1),
                                     ("::ffff:203.0.113.9", 1, 0, 0), ("2001:db8:1:2:3:4:5:6", 1, 0, 0),
                                     ("fe80::1%eth0", 1, 0, 2))],
   [None, None, None, None, "203.0.113.9", "203.0.113.9", "2001:db8:1:2::/64", "fe80::/64"])


# The console and terminal: a Socket.IO WebSocket answering the heartbeat stays open for 9 s, past the
# 2.5 s header deadline and the 1 s body grace (the deadline ends when the request reaches the app).
from unit.part260 import _ws_session260  # noqa: E402

_srv_w264 = _Server264("ws")
try:
    _ws264s = _ws_session260(_srv_w264.port, 9) if _srv_w264.ready else (0, False, "not ready")
finally:
    _err_w264 = _srv_w264.stop()
check("web server r32: a Socket.IO WebSocket answering the heartbeat stays open for 9 s, past every request "
      "deadline (the console and terminal are not cut)", _ws264s[1] and _ws264s[0] >= 5,
      "pings=%s open=%s why=%s err=%s" % (_ws264s[0], _ws264s[1], _ws264s[2], _err_w264[-400:]))

_chained264 = _ws264.ClientStalled("stalled while a real failure was handled")
_chained264.__context__ = RuntimeError("the real failure")
eq("web server r32: a client stall (on a read or a write) is a hang-up for the log; a TimeoutError of the panel's "
   "own, or a stall chained to another failure, is not",
   [_ws264._client_hung_up(e) for e in (_ws264.ClientStalled("x"), TimeoutError("own"), None, _chained264)],
   [True, False, False, False])



def _discard_logged264(exc):
    """How many warnings eventlet's "could not read the body" line leaves while `exc` is being handled."""
    import logging as _logging264
    records = []

    class _Keep264(_logging264.Handler):
        def emit(self, record):
            records.append(record)
    handler = _Keep264()
    lg = _logging264.getLogger("panel.wsgi")
    lg.addHandler(handler)
    try:
        try:
            raise exc
        except OSError:
            _ws264._TracebacksOnly().error("I/O error while discarding request body. client=%s", "203.0.113.9")
    finally:
        lg.removeHandler(handler)
    return len(records)


eq("web server r32: eventlet's 'could not read the request body' line, which names the client's request, is not "
   "logged when the client stalled or hung up, and still is for any other read error",
   [_discard_logged264(e) for e in (_ws264.ClientStalled("slow body"), ConnectionResetError(104, "reset"),
                                    OSError(5, "I/O error"))], [0, 0, 1])

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. ufw: a deny with logging is a deny (Block, Unblock, the tailscale0 test), and the page shows the logging
# ════════════════════════════════════════════════════════════════════════════════════════════════
import json as _json264  # noqa: E402
from types import SimpleNamespace as _NS264  # noqa: E402

from unit.part47 import _cut47, _node47  # noqa: E402
from unit.part260 import _ufw_row260  # noqa: E402
from panel.ops import system_ops as _so264  # noqa: E402
from panel.ops.ssh_manager import _core as _smc264, firewall as _fw264, hosts as _hosts264  # noqa: E402


def _status264(rows):
    """`ufw status` (the ufw-status verb's plain form) holding `rows`, as ufw 0.36 prints it."""
    return "Status: active\n\nTo                         Action      From\n--                         ------      ----\n" + \
        "\n".join(rows) + "\n"


# An operator's logged deny ABOVE the allows (it blocks), and one appended BELOW them (it blocks nothing on
# those ports: ufw takes the first match). In plain `ufw status` an inbound rule prints no direction.
_LOGGED264 = _status264([_ufw_row260("Anywhere", "DENY", "198.51.100.7", "log-all", "mine"),
                         _ufw_row260("22/tcp", "LIMIT", "Anywhere"),
                         _ufw_row260("27015", "ALLOW", "Anywhere"),
                         _ufw_row260("Anywhere", "DENY", "203.0.113.9", "log")])
_shadow264 = {}
eq("ufw r32: the blocked-IPs read counts a logged deny above the allows as the operator's block, and puts one "
   "below them in `shadowed` with its logging (it skipped both: no block, nothing to move)",
   (_so264._ufw_deny_sources(_LOGGED264, _shadow264), _shadow264),
   ({"198.51.100.7": ""}, {"203.0.113.9": {"comment": "", "action": "DENY", "log": "log"}}))


class _UfwHost264:
    """A firewall answering the ufw verbs from `status`; records every write (deny, delete) it is asked for."""

    def __init__(self, status, delete_out="Could not delete non-existent rule\n"):
        self.status, self.delete_out, self.writes = status, delete_out, []

    def answer(self, verb, args):
        if verb == "ufw-status":
            return self.status, "", 0
        self.writes.append((verb, list(args)))
        if verb == "ufw-delete-deny-ip":
            return self.delete_out, "", 0
        return "Skipping inserting existing rule\n", "", 0


def _local_block264(fn, ip, status):
    """system_ops.<fn>(ip) against _UfwHost264(status): (its answer as text, writes)."""
    host = _UfwHost264(status)
    saved = _so264._run_verb
    _so264._run_verb = lambda verb, args=(), timeout=30, **_k: host.answer(verb, args)  # noqa: E731
    try:
        ok, msg = fn(ip)
    finally:
        _so264._run_verb = saved
    return ok, str(msg), host.writes


_blk_shadowed264 = _local_block264(_so264.ufw_deny_ip, "203.0.113.9", _LOGGED264)
check("ufw r32: Block on an address whose only deny is a logged one below the allows answers that it cannot move "
      "it, and writes nothing (it inserted a deny ufw skipped as a duplicate and answered 'Blocked'; moving it "
      "would be a delete ufw does not match and the same skipped insert)",
      _blk_shadowed264[0] is False and "blocks nothing" in _blk_shadowed264[1] and _blk_shadowed264[2] == [],
      repr(_blk_shadowed264))
_blk_top264 = _local_block264(_so264.ufw_deny_ip, "198.51.100.7", _LOGGED264)
eq("ufw r32: ...while one whose logged deny sits above the allows is already blocked, left as it is",
   _blk_top264, (True, "198.51.100.7 is already blocked by an existing firewall rule (left as it is).", []))


def _remote_block264(ip, status):
    """hosts.remote_ufw_deny_ip on a stand-in remote whose firewall answers from `status`."""
    host = _UfwHost264(status)
    saved = _smc264.run_privileged
    _smc264.run_privileged = lambda server, verb, args=(), timeout=30, **_k: host.answer(verb, args)  # noqa: E731
    try:
        ok, msg = _hosts264.remote_ufw_deny_ip(_NS264(id=992640, name="p264", is_local=False), ip)
    finally:
        _smc264.run_privileged = saved
    return ok, str(msg), host.writes


_rblk264 = _remote_block264("203.0.113.9", _LOGGED264)
check("ufw r32: ...and the same on a remote host (one implementation, both callers)",
      _rblk264[0] is False and "blocks nothing" in _rblk264[1] and _rblk264[2] == [], repr(_rblk264))
_unblk264 = _local_block264(_so264.ufw_undeny_ip, "198.51.100.7", _LOGGED264)
check("ufw r32: Unblock on an address held by a logged deny (which `delete deny from` does not match) answers that "
      "it is still blocked (the read-back did not list the logged deny, so it answered 'Unblocked')",
      _unblk264[0] is False and "still blocked" in _unblk264[1], repr(_unblk264))

# `ufw status verbose` rows, as ufw_status() reads them: a logged UDP-only allow on tailscale0 carries no SSH.
_TS_ROWS264 = [_so264._r14a_ufw_row(_ufw_row260("Anywhere on tailscale0", "ALLOW IN", "100.64.0.0/10/udp", "log"))]
eq("ufw r32: a logged UDP-only allow on tailscale0 is read with its logging apart and does not count as letting "
   "everything in (its From read '<net>/udp (log)', which is not UDP to the test)",
   ([(_r["from"], _r["log"]) for _r in _TS_ROWS264], _so264.ufw_allows_iface_in(_TS_ROWS264, "tailscale0")),
   ([("100.64.0.0/10/udp", "log")], False))

# The Firewall page: a logged rule and an unlogged one for the same port are two rows, the logged one marked.
_G264 = _fw264._group_ufw_rules([{"num": "1", "detail": _ufw_row260("22/tcp", "ALLOW IN", "Anywhere", "log")},
                                 {"num": "2", "detail": _ufw_row260("22/tcp", "ALLOW IN", "Anywhere")},
                                 {"num": "3", "detail": _ufw_row260("22/tcp (v6)", "ALLOW IN", "Anywhere (v6)", "log")}])
eq("ufw r32: the Firewall page's groups carry a rule's logging, and a logged and an unlogged rule are two rows (the "
   "logged rule showed exactly like the unlogged one, merged into it)",
   [(g["nums"], g.get("log"), g["scope"]) for g in _G264], [([1, 3], "log", "Any address"), ([2], "", "Any address")])
_fwjs264 = open(os.path.join(_ROOT264, "panel", "static", "js", "remote_firewall.js"), encoding="utf-8").read()
_paint264 = _node47(
    "const esc = s => String(s).replace(/[&<>\"']/g, c => '&#' + c.charCodeAt(0) + ';');\n"
    "const t = s => s; const protoBadge = p => p; const _fwReason = () => ''; const _da = () => '';\n"
    "const _fwDelTitle = () => ''; const document = {getElementById: () => null};\n"
    "%s\nconst list = {innerHTML: ''}; _fwRenderRules(list, %s);\n"
    "const rows = list.innerHTML.split('<tr>').slice(2);\n"
    "console.log(JSON.stringify(rows.map(r => (r.match(/data-no-i18n>(log[a-z-]*)<\\/span>/) || [null, ''])[1])));\n"
    % (_cut47(_fwjs264, "function _fwRenderRules("), _json264.dumps(_G264)))
if _paint264 is None:
    skip("ufw r32: the Firewall page marks a logged rule with ufw's word for it", "no node")
else:
    eq("ufw r32: the Firewall page marks a logged rule with ufw's word for it (log), and an unlogged one with "
       "nothing", _paint264, ["log", ""])


# Every reader of ufw's rows, fed the same logged rules (log, log-all, IPv6, UDP-only, LIMIT, a deny): each
# takes the attribute off the same way (system_ops.ufw_split_attribs, the one parse), so no From it hands
# on still ends in "(log)". Verbose form (the direction printed), as ufw_status, the tailscale0 test and
# the Firewall page read it; the deny first, so the blocked-IPs read counts it.
from panel.ops.ssh_manager import ufweval as _ufe264  # noqa: E402

_ONE_SET264 = [_ufw_row260("Anywhere", "DENY IN", "203.0.113.9", "log"),
               _ufw_row260("22/tcp", "LIMIT IN", "Anywhere", "log-all"),
               _ufw_row260("27015/udp", "ALLOW IN", "Anywhere", "log"),
               _ufw_row260("Anywhere on tailscale0", "ALLOW IN", "100.64.0.0/10/udp", "log"),
               _ufw_row260("22/tcp (v6)", "LIMIT IN", "Anywhere (v6)", "log-all")]
_parsed264 = [_fw264._parse_ufw_rule(_r) for _r in _ONE_SET264]
_rows264 = [_so264._r14a_ufw_row(_r) for _r in _ONE_SET264]
_FROMS264 = ["203.0.113.9", "Anywhere", "Anywhere", "100.64.0.0/10/udp", "Anywhere"]
_LOGS264 = ["log", "log-all", "log", "log", "log-all"]
eq("ufw r32: every reader of ufw's rows takes a logged rule's attribute off the same way: the Firewall page and "
   "lock-out guards' parse (firewall._parse_ufw_rule), ufw_status and the tailscale0 test's rows "
   "(system_ops._r14a_ufw_row, which keeps ufw's (v6) family mark, as it always did), with the logging kept apart; "
   "the IPv6 row still IPv6",
   ([(_p["from"], _p["log"]) for _p in _parsed264], [(_r["from"], _r["log"]) for _r in _rows264], _parsed264[4]["v6"]),
   (list(zip(_FROMS264, _LOGS264)), list(zip(_FROMS264[:4] + ["Anywhere (v6)"], _LOGS264)), True))
eq("ufw r32: ...the public-rules read sees the logged LIMIT and the logged UDP allow as public, IPv4 and IPv6 apart "
   "(hosts._ufw_public_rules); the blocked-IPs read counts the logged deny (system_ops._ufw_deny_sources); the "
   "one evaluator reads the logged UDP-only source as UDP from the tailnet (ufweval.row_spec); and the logged "
   "UDP-only tailscale0 allow does not let TCP in (system_ops.ufw_allows_iface_in)",
   ([(_p["to"], _p["action"]) for _p in _hosts264._ufw_public_rules("\n".join(_ONE_SET264))],
    [(_p["to"], _p["action"]) for _p in _hosts264._ufw_public_rules("\n".join(_ONE_SET264), v6=True)],
    _so264._ufw_deny_sources(_status264(_ONE_SET264)),
    (_ufe264.row_spec(_parsed264[3])["proto"], str(_ufe264.row_spec(_parsed264[3])["src"]),
     _ufe264.row_spec({"to": "Anywhere", "from": "100.64.0.0/10/udp (log)", "action": "ALLOW"})["proto"]),
    _so264.ufw_allows_iface_in(_rows264, "tailscale0")),
   ([("22/tcp", "LIMIT"), ("27015/udp", "ALLOW")], [("22/tcp", "LIMIT")], {"203.0.113.9": ""},
    ("udp", "100.64.0.0/10", "udp"), False))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Every folder the account's user manager reads at start is a sign-in path: tmpfiles, the session bus
# ════════════════════════════════════════════════════════════════════════════════════════════════
import shlex as _shlex264  # noqa: E402
import tarfile as _tarfile264  # noqa: E402

from unit.part190 import _U190, _UNDO190, _Sb190, _crafted190, _missing190  # noqa: E402
from panel.ops.ssh_manager import files as _files264  # noqa: E402
from panel.services import game_restore as _grs264, sftp_files as _sftpf264  # noqa: E402

_START264 = (".config/user-tmpfiles.d/x.conf", ".local/share/user-tmpfiles.d/x.conf",
             ".local/share/dbus-1/services/x.service", ".config/user-tmpfiles.d", ".local/share/dbus-1", ".forward")
eq("sign-in paths r32: user tmpfiles (applied by the user manager at every start), the session bus's services and "
   "~/.forward are sign-in paths by name", [n for n in _START264 if not _files264._is_login_path(n)], [])
eq("sign-in paths r32: ...while names beside them are not (controls)",
   [_files264._is_login_path(n) for n in (".config/user-tmpfiles.dx", ".local/share/dbus-10/x", ".forwardx",
                                          "serverfiles/.config/user-tmpfiles.d/x.conf")], [False] * 4)
_t264 = _NS264(user="p264u", selfname="p264srv")
eq("sign-in paths r32: the file browser refuses to create a tmpfiles line or the folder, and SFTP refuses the same "
   "writes and new names, with the sign-in sentence",
   [_files264.create_refusal("p264u", ".config/user-tmpfiles.d", "x.conf", "file"),
    _files264.create_refusal("p264u", ".local/share", "user-tmpfiles.d", "folder"),
    _files264.create_refusal("p264u", "", ".forward", "file"),
    _sftpf264._write_problem(_t264, ".config/user-tmpfiles.d/x.conf", False),
    _sftpf264._write_problem(_t264, ".local/share/dbus-1/services/x.service", True),
    _sftpf264._new_name_problem(_t264, ".local/share/user-tmpfiles.d")],
   [_files264.LOGIN_FILE_REFUSED] * 6)


def _host_guard264(resolved):
    """The host-side guard on a write whose path resolved to `resolved`: its exit status (13 refused)."""
    script = 'h=/home/p264u; p=%s; %s exit 0' % (_shlex264.quote(resolved), _files264._login_guard("/home/p264u", "p"))
    return _sp264.run(["bash", "-c", script], capture_output=True, text=True, timeout=30).returncode  # nosec B603 B607


eq("sign-in paths r32: on the host, a write that RESOLVES into a user tmpfiles folder, the session bus's folder or "
   "onto ~/.forward is refused, and a game file beside them is not",
   [_host_guard264("/home/p264u/" + n) for n in (
       ".config/user-tmpfiles.d/x.conf", ".local/share/user-tmpfiles.d/y.conf", ".local/share/dbus-1/services/z",
       ".forward", ".local/share/Steam/x")], [13, 13, 13, 13, 0])


def _start_restore264():
    """Restore an archive holding planted tmpfiles lines over a home with its own; -> what is left."""
    sb = _Sb190()
    try:
        os.makedirs(os.path.join(sb.home, ".config/user-tmpfiles.d"))
        sb.put(".config/user-tmpfiles.d/own.conf", "own line\n")
        planted = (".config/user-tmpfiles.d/evil.conf", ".local/share/user-tmpfiles.d/evil.conf",
                   ".local/share/dbus-1/services/evil.service", ".forward")
        dirs = sorted({"/".join(n.split("/")[:i]) for n in planted + (".config/app/settings.ini",)
                       for i in range(1, n.count("/") + 1)})
        name = _crafted190(sb, [("././%s/" % d, _tarfile264.DIRTYPE, "") for d in dirs]
                           + [("././" + n, _tarfile264.REGTYPE, "") for n in planted + (".config/app/settings.ini",)])
        ready = sb.vet(name)[1][1]
        with open(os.path.join(sb.bdir, _UNDO190), "wb") as f:
            f.write(b"undo")
        out, rc = sb.run(_grs264.restore_script(_U190, _U190, name, ready["t0"], ready["need"], _UNDO190,
                                                busy_polls=1, members=ready["members"]))
        return (_grs264.restore_outcome(out, rc)[0], sb.read(".config/user-tmpfiles.d/own.conf"),
                [n for n in planted if os.path.lexists(os.path.join(sb.home, n))], sb.read(".config/app/settings.ini"))
    except Exception as e:  # noqa: BLE001 - recorded as the check's failure, not a crash of the part
        return ("raised %r" % e, None, None, None)
    finally:
        sb.gone()


if _missing190:
    skip("sign-in paths r32: a restore keeps the account's own tmpfiles lines", "missing tools: %s" % _missing190)
else:
    eq("sign-in paths r32: a restore of an archive holding tmpfiles lines (both folders), a session-bus service and a "
       ".forward keeps the account's own tmpfiles line, brings in none of them, and restores the game's own "
       "~/.config file", _start_restore264(), ("done", "own line\n", [], ""))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. World reset: a start parameter naming many settings is read in linear time
# ════════════════════════════════════════════════════════════════════════════════════════════════
from panel.services import world_reset as _wwr264  # noqa: E402


def _start_seconds264(n):
    """The fastest of three start_words runs over a startparameters naming `n` distinct settings."""
    texts = ['startparameters="%s"\n' % " ".join("${a%d}" % i for i in range(n)), "", "", "", ""]
    best = None
    for _ in range(3):
        t0 = _time264.perf_counter()
        _wwr264.start_words(texts, "p264u", "p264srv")
        took = _time264.perf_counter() - t0
        best = took if best is None else min(best, took)
    return best


# Quadruple the names: linear time grows about four-fold, quadratic sixteen-fold (1,500 -> 6,000 names took
# 0.6 s -> 8 s before, one config scan per name and the long line judged once per name; 0.03 s -> 0.2 s now).
_ws_small264, _ws_big264 = _start_seconds264(1500), _start_seconds264(6000)
check("world reset r32: start_words over a startparameters naming 4x as many settings takes under 8x as long "
      "(linear: one index of the config per read, each line judged once)",
      _ws_big264 < 8 * _ws_small264 + 0.05, "1500: %.3f s, 6000: %.3f s" % (_ws_small264, _ws_big264))
eq("world reset r32: ...and still reads what LinuxGSM reads: names expanded from base values and from settings "
   "set once, a setting set twice in a file refused, a setting set through another line's arithmetic refused",
   [_wwr264.start_words(['startparameters="-port ${port} -name ${selfname} ${a1}"\nport="2456"\n',
                         'a1="x"\n', "", "", ""], "p264u", "p264srv")[0],
    _wwr264.start_words(['startparameters="${port}"\nport="1"\nport="2"\n', "", "", "", ""], "p264u", "s")[0],
    _wwr264.start_words(['startparameters="${port}"\nother="$((port=5))"\nport="1"\n', "", "", "", ""],
                        "p264u", "s")[0]],
   [["-port", "2456", "-name", "p264srv", "x"], None, None])
