"""Part 274 of the unit suite: review pass 34's security fixes.

1. The web server (wsgi_serve.serve, started for real on loopback in a child process) refuses a request
   carrying Transfer-Encoding before the app: 411 for `chunked` alone, 400 for any other coding, the
   connection closed. A chunk-size line with no newline no longer grows the process by what the client
   sends (it was buffered whole by eventlet's discard), a malformed or cut-off chunked body logs nothing,
   and `gzip, chunked` is not read as an empty body followed by a second request. Ordinary requests with
   a Content-Length (a sign-in form, an upload piece, a Socket.IO polling post) are answered as before.
   OWASP Denial of Service Cheat Sheet, "Input validation"; WSTG-INJT-16, "Remediation".
2. The body reader's own bounds, should a chunked body ever reach it: a readline with no size stops at
   _LINE_MAX and a line that fills it ends the connection, a body with no Content-Length is read to
   _UNSIZED_BODY_MAX at most; eventlet's discard over the reader stops there, and logs nothing.
3. The helper's db-import opens the dump without waiting: a FIFO the game account put at the dump's
   name is refused at once (rc 4, as the remote form does), and a regular dump is still imported.

HOW IT RUNS. The web server in a child process on a free loopback port; the body reader over in-memory
files; the helper's real main() with stand-in tools in a temp dir. Nothing reaches a host.
"""
import contextlib as _ctx274
import gzip as _gz274
import io as _io274
import json as _js274
import logging as _lg274
import os
import pwd as _pwd274
import shutil as _sh274
import socket as _socket274
import subprocess as _sp274  # nosec B404 - the web server and a FIFO opener in child processes, fixed argv
import sys as _sys274
import tempfile as _tf274
import time as _time274
import types as _ty274

import eventlet.wsgi as _ewsgi274

from unit import REPO_ROOT as _ROOT274
from unit.part01 import check, eq
from unit.part05 import _helper as _h274
from panel.core import wsgi_serve as _ws274
from panel.security import privileged as _priv274

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The web server: Transfer-Encoding refused before the app
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SERVE274 = r"""
import os, sys
os.environ["EVENTLET_NO_GREENDNS"] = "yes"
sys.path.insert(0, sys.argv[2])
import eventlet
eventlet.monkey_patch()
from flask import Flask, request
from flask_socketio import SocketIO
from panel.core import wsgi_serve

if sys.argv[3] == "inner":
    # The body reader's own bounds, with the refusal before the app taken away.
    wsgi_serve._transfer_coding_answer = lambda headers: None
app = Flask("p274")
app.add_url_rule("/ok", "ok", lambda: "fine")
app.add_url_rule("/form", "form", lambda: "form %s" % request.form.get("username", ""), methods=["POST"])
app.add_url_rule("/piece", "piece", lambda: "piece %d" % len(request.files["piece"].read()), methods=["POST"])
SocketIO(app, async_mode="eventlet")
wsgi_serve.serve(app, "127.0.0.1", int(sys.argv[1]), None, limits=dict(header=5, body_grace=5, body_rate=500),
                 idle_seconds=5, io_timeout=5)
"""
_MIB274 = 1 << 20
# Sent as one chunk-size line with no newline: the unfixed server grew by about twice this.
_LINE_SENT274 = 32 * _MIB274
_CHUNKED_HEAD274 = b"GET /ok HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"


def _serve274(mode):
    """(the child process, its port) once GET /ok answers, or (process, None); `mode` "inner" lifts the refusal."""
    with _socket274.socket() as so:
        so.bind(("127.0.0.1", 0))
        port = so.getsockname()[1]
    argv = [_sys274.executable, "-c", _SERVE274, str(port), str(_ROOT274), mode]
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    proc = _sp274.Popen(argv, stdout=_sp274.DEVNULL, stderr=_sp274.PIPE)  # nosec B603
    deadline = _time274.monotonic() + 30
    while proc.poll() is None and _time274.monotonic() < deadline:
        if _ask274(port, b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").startswith(b"HTTP/1.1 200"):
            return proc, port
        _time274.sleep(0.2)
    return proc, None


def _ask274(port, raw, half_close=False):
    """Send `raw` on a fresh connection and read until the server closes it: everything it answered."""
    try:
        so = _socket274.create_connection(("127.0.0.1", port), timeout=10)
    except OSError:
        return b""
    with so:
        try:
            so.sendall(raw)
            if half_close:
                so.shutdown(_socket274.SHUT_WR)
        except OSError:
            pass  # the server closed the connection before all of it was sent: read what it answered
        return _read_all_of274(so)


def _read_all_of274(so):
    """What arrives on `so` until it is closed, reset or silent for its timeout."""
    got = b""
    try:
        while True:
            part = so.recv(65536)
            if not part:
                return got
            got += part
    except OSError:
        return got


def _hwm274(pid):
    """The child's peak resident memory in KiB (VmHWM), 0 when it cannot be read."""
    try:
        with open("/proc/%d/status" % pid, encoding="ascii") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
    except OSError:
        pass  # no /proc entry: the child has gone, reported by the check as 0
    return 0


def _long_line274(port):
    """Send a chunked request whose chunk-size line is _LINE_SENT274 bytes with no newline; what came back."""
    got = b""
    try:
        with _socket274.create_connection(("127.0.0.1", port), timeout=10) as so:
            so.sendall(_CHUNKED_HEAD274)
            block = b"1" * _MIB274
            try:
                for _ in range(_LINE_SENT274 // _MIB274):
                    so.sendall(block)
                so.shutdown(_socket274.SHUT_WR)
            except OSError:
                pass  # the server closed the connection while the line was still being sent
            got = _read_all_of274(so)
    except OSError:
        pass  # no connection: nothing came back
    return got


def _socketio_poll274(port):
    """A Socket.IO polling handshake and one post with a Content-Length: the post's answer body."""
    hello = _ask274(port, b"GET /socket.io/?EIO=4&transport=polling HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    body = hello.partition(b"\r\n\r\n")[2]
    try:
        sid = _js274.loads(body[1:].decode())["sid"]
    except (ValueError, KeyError):
        return b"no handshake: " + hello[:200]
    post = ("POST /socket.io/?EIO=4&transport=polling&sid=%s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
            "Content-Type: text/plain;charset=UTF-8\r\nContent-Length: 2\r\n\r\n40" % sid).encode()
    return _ask274(port, post).partition(b"\r\n\r\n")[2]


def _controls274(port):
    """The ordinary requests with a Content-Length: {name: what came back}."""
    form = b"username=alice&password=x"
    two = (b"POST /form HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: %d\r\n\r\n%s" % (len(form), form)
           + b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    piece = b"P" * (70 * 1024)
    mp = (b"--b274\r\nContent-Disposition: form-data; name=\"piece\"; filename=\"blob\"\r\n"
          b"Content-Type: application/octet-stream\r\n\r\n" + piece + b"\r\n--b274--\r\n")
    upload = (b"POST /piece HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: multipart/form-data; "
              b"boundary=b274\r\nContent-Length: %d\r\n\r\n" % len(mp)) + mp
    return {"form": _ask274(port, two), "piece": _ask274(port, upload), "socketio": _socketio_poll274(port)}


def _refusals274(port):
    """The Transfer-Encoding requests: {name: what came back}."""
    return {
        "chunked": _ask274(port, _CHUNKED_HEAD274),
        "bad size": _ask274(port, _CHUNKED_HEAD274 + b"zz\r\n", half_close=True),
        "cut off": _ask274(port, _CHUNKED_HEAD274 + b"5\r\nab", half_close=True),
        "gzip": _ask274(port, b"POST /ok HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
                              b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        "two headers": _ask274(port, b"GET /ok HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
                                     b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        "with length": _ask274(port, b"POST /ok HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
                                     b"Content-Length: 5\r\n\r\n0\r\n\r\n"),
    }


def _web274():
    """Run every request against one server: (memory before, after, the long line's answer, refusals, controls)."""
    proc, port = _serve274("refuse")
    try:
        if not port:
            return 0, 0, b"not ready", {}, {}
        before = _hwm274(proc.pid)
        line = _long_line274(port)
        _time274.sleep(0.5)
        after = _hwm274(proc.pid)
        return before, after, line, _refusals274(port), _controls274(port)
    finally:
        if proc.poll() is None:
            proc.kill()
        _err274[0] = proc.communicate(timeout=10)[1].decode("utf-8", "replace")


_err274 = ["", ""]
_before274, _after274, _line274, _ref274, _ctl274 = _web274()
_status274 = {k: v.split(b"\r\n")[0] for k, v in _ref274.items()}
check("web server r34: a chunked request whose chunk-size line is 32 MiB with no newline does not grow the server "
      "(it was buffered whole by eventlet's discard: about 64 MiB more per connection, no account needed)",
      _before274 > 0 and _after274 - _before274 < 8 * 1024,
      "VmHWM %d KiB -> %d KiB, answer %r" % (_before274, _after274, _line274[:60]))
check("web server r34: ...it is answered 411 Length Required (or cut) and never reaches the app's 200",
      not _line274.startswith(b"HTTP/1.1 200"), _line274[:80])
eq("web server r34: Transfer-Encoding is refused before the app: 411 for chunked alone, 400 for another coding, "
   "two headers, or a Content-Length beside it", _status274,
   {"chunked": b"HTTP/1.0 411 Length Required", "bad size": b"HTTP/1.0 411 Length Required",
    "cut off": b"HTTP/1.0 411 Length Required", "gzip": b"HTTP/1.0 400 Bad Request",
    "two headers": b"HTTP/1.0 400 Bad Request", "with length": b"HTTP/1.0 400 Bad Request"})
check("web server r34: ...each refusal closes the connection and answers once: `gzip, chunked` is not read as an "
      "empty body followed by the next request (two answers, the desync behind request smuggling)",
      all(v.count(b"HTTP/1.") == 1 and b"Connection: close" in v for v in _ref274.values()) and len(_ref274) == 6,
      repr({k: v.count(b"HTTP/1.") for k, v in _ref274.items()}))
check("web server r34: a malformed chunk size and a body cut off mid-chunk log nothing (each logged a warning "
      "naming the client and its request line, one per connection)",
      "web server:" not in _err274[0] and "discarding" not in _err274[0] and "Traceback" not in _err274[0],
      _err274[0][-600:])
check("web server r34: ...while a sign-in form with a Content-Length is read, and the same connection answers the "
      "next request", _ctl274.get("form", b"").count(b"HTTP/1.1 200") == 2 and b"form alice" in _ctl274["form"],
      repr(_ctl274.get("form", b"")[-200:]))
check("web server r34: ...a 70 KiB upload piece (multipart, a Content-Length) arrives whole",
      _ctl274.get("piece", b"").startswith(b"HTTP/1.1 200") and _ctl274["piece"].endswith(b"piece 71680"),
      repr(_ctl274.get("piece", b"")[-200:]))
eq("web server r34: ...and a Socket.IO polling post (the console's fallback transport) is accepted",
   _ctl274.get("socketio"), b"OK")



def _chunks274(total):
    """A valid chunked body of `total` bytes in 4 KiB chunks, its end included."""
    piece = b"1000\r\n" + b"c" * 4096 + b"\r\n"
    return piece * (total // 4096) + b"0\r\n\r\n"


def _inner274():
    """With the refusal lifted: (memory before, after the long line, {body size: answers on its connection})."""
    proc, port = _serve274("inner")
    try:
        if not port:
            return 0, 0, {}
        before = _hwm274(proc.pid)
        _long_line274(port)
        _time274.sleep(0.5)
        after = _hwm274(proc.pid)
        follow = b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        answers = {size: _ask274(port, _CHUNKED_HEAD274 + _chunks274(size) + follow).count(b"HTTP/1.1 200")
                   for size in (4096, _MIB274)}
        return before, after, answers
    finally:
        if proc.poll() is None:
            proc.kill()
        _err274[1] = proc.communicate(timeout=10)[1].decode("utf-8", "replace")


_in_before274, _in_after274, _in_answers274 = _inner274()
check("web server r34 (refusal lifted): eventlet's own discard of a 32 MiB chunk-size line with no newline stops "
      "at the reader's line cap, and the server does not grow by what was sent",
      _in_before274 > 0 and _in_after274 - _in_before274 < 8 * 1024,
      "VmHWM %d KiB -> %d KiB" % (_in_before274, _in_after274))
eq("web server r34 (refusal lifted): a 1 MiB chunked body is read only to the unsized cap and its connection "
   "closed (no answer to the request behind it), while a 4 KiB one is read whole and the next request answered",
   _in_answers274, {4096: 2, _MIB274: 1})
check("web server r34 (refusal lifted): ...and neither bound logs anything",
      "web server:" not in _err274[1] and "Traceback" not in _err274[1], _err274[1][-600:])

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The body reader's own bounds
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _paced274(data, limit=None):
    """A _PacedBody over `data` (no waiting: the budget's timeout is a no-op), and its handler."""
    handler = _ty274.SimpleNamespace(close_connection=0)
    body = _ws274._PacedBody(_io274.BufferedReader(_io274.BytesIO(data)), handler,
                             lambda *_a: _ctx274.nullcontext(), 60, 500, limit)
    return body, handler


def _outcome274(fn):
    """What `fn()` gave: ("ok", its value) or ("refused", None) on BodyRefused."""
    try:
        return "ok", fn()
    except _ws274.BodyRefused:
        return "refused", None


_long_body274, _long_h274 = _paced274(b"1" * _MIB274)
eq("body reader: a readline with no size over a line with no newline is refused at _LINE_MAX bytes, and the "
   "connection is to be closed (it read the whole line into memory, however long)",
   (_outcome274(_long_body274.readline), _long_h274.close_connection), (("refused", None), 1))
_ok_body274, _ok_h274 = _paced274(b"5\r\nhello\r\n" + b"x" * (_ws274._LINE_MAX - 1) + b"\n" + b"y" * 20)
eq("body reader: ...while short lines, a line of _LINE_MAX bytes ending in a newline, and a sized readline read "
   "as before",
   ([_ok_body274.readline(), _ok_body274.readline(3), _ok_body274.readline(None), len(_ok_body274.readline()),
     _ok_body274.readline(-1)], _ok_h274.close_connection),
   ([b"5\r\n", b"hel", b"lo\r\n", _ws274._LINE_MAX, b"y" * 20], 0))


def _read_all274(body, step=16384):
    got = 0
    while True:
        part = body.read(step)
        if not part:
            return got
        got += len(part)


_unsized274, _unsized_h274 = _paced274(b"z" * (200 << 10), limit=_ws274._UNSIZED_BODY_MAX)
_sized274 = _paced274(b"z" * (200 << 10))[0]
eq("body reader: a body with no Content-Length is read to _UNSIZED_BODY_MAX at most, then refused and the "
   "connection closed; a sized body reads to its end",
   (_outcome274(lambda: _read_all274(_unsized274)), _unsized_h274.close_connection, _read_all274(_sized274)),
   (("refused", None), 1, 200 << 10))
_sized_line274 = _paced274(b"1" * _MIB274, limit=_ws274._UNSIZED_BODY_MAX)[0]
eq("body reader: ...and on such a body a readline given a size of 16 MiB (eventlet's readline of a chunk whose "
   "size line promised that much) reads no more than the cap leaves, then is refused",
   (_outcome274(lambda: _sized_line274.readline(16 * _MIB274)), _sized_line274._got <= _ws274._UNSIZED_BODY_MAX + 1),
   (("refused", None), True))


class _Lines274(_lg274.Handler):
    """Every record logged to panel.wsgi."""

    def __init__(self):
        """Nothing logged yet."""
        super().__init__()
        self.lines = []

    def emit(self, record):
        """Keep the record's text."""
        self.lines.append(record.getMessage())


def _discard274():
    """Eventlet's discard of a chunked body over the reader, as handle_one_response runs it: (what it raised, log)."""
    body, _h = _paced274(b"1" * (8 * _MIB274))
    request_input = _ewsgi274.Input(body, None, None, chunked_input=True)
    lines = _Lines274()
    logger = _lg274.getLogger("panel.wsgi")
    logger.addHandler(lines)
    raised = None
    try:
        try:
            request_input.discard()
        except OSError as e:          # handle_one_response's own except, then its log.error
            raised = type(e).__name__
            _ws274._TracebacksOnly().error("I/O error while discarding request body. client=x request=y error=%s", e)
    finally:
        logger.removeHandler(lines)
    return raised, lines.lines, body._got


_disc274 = _discard274()
check("body reader: eventlet's discard of a chunked body whose size line never ends stops at _LINE_MAX with "
      "BodyRefused, and the error line eventlet writes for it is not logged",
      _disc274[0] == "BodyRefused" and _disc274[1] == [] and _disc274[2] <= _ws274._LINE_MAX, repr(_disc274))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The helper's db-import: a FIFO at the dump's name
# ════════════════════════════════════════════════════════════════════════════════════════════════
_T274 = _tf274.mkdtemp(prefix="lgsm-unit-p274-")
_ACCT274 = "gm274"
_HOME274 = os.path.join(_T274, "home", _ACCT274)
_DUMPS274 = os.path.join(_HOME274, _h274.DB_DUMP_DIR)
_FED274 = os.path.join(_T274, "fed")
_CLIENT274 = os.path.join(_T274, "mariadb")
_DBPW274 = "Sentinelpw7Xq-ab.cd_ef274"          # a database password of the generator's shape
os.makedirs(_DUMPS274)
with open(_CLIENT274, "w", encoding="utf-8") as _fh274:
    _fh274.write('#!/bin/bash\nfor a in "$@"; do [ "$a" = --help ] && exit 0; done\ncat > %s\n' % _FED274)
# nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- a stand-in in this part's temp dir
os.chmod(_CLIENT274, 0o700)  # nosec B103 - owner-only stand-in program in a temp dir
_me274 = _pwd274.getpwuid(os.getuid())


def _getpwnam274(name):
    if name != _ACCT274:
        raise KeyError(name)
    return _pwd274.struct_passwd((name, "x", _me274.pw_uid or 4242, _me274.pw_gid, "", _HOME274, "/bin/sh"))


def _import274():
    """(rc, seconds) of the helper's real main() for db-import of gs12_lp, with stand-in tools."""
    args = ["mariadb", "3306", _ACCT274, "gs12_lp"]
    saved = {k: getattr(_h274, k) for k in ("TOOLS", "pwd", "_drop_to")}
    io_saved = (_sys274.stdin, _sys274.stdout, _sys274.stderr)
    _h274.TOOLS = dict(_h274.TOOLS, mariadb=(_CLIENT274,))
    _h274.pwd = _ty274.SimpleNamespace(getpwnam=_getpwnam274, getpwuid=_pwd274.getpwuid)
    _h274._drop_to = lambda pw, own_groups=False: True
    _sys274.stdin = _io274.StringIO(_priv274.helper_stdin("db-import", args, {"pw": _DBPW274}))
    _sys274.stdout, _sys274.stderr = _io274.StringIO(), _io274.StringIO()
    t0 = _time274.monotonic()
    try:
        return _h274.main(["panel-helper", "db-import"] + args), round(_time274.monotonic() - t0, 1)
    finally:
        _sys274.stdin, _sys274.stdout, _sys274.stderr = io_saved
        for _k, _v in saved.items():
            setattr(_h274, _k, _v)


def _fifo_import274():
    """db-import with a FIFO at the dump's name: (rc, seconds, whether the client was run).

    A writer opens the FIFO after 4 s (read-write, so it never waits itself): a plain open that
    waited for one returns then, so the broken helper ends too, only late, and the suite never hangs.
    """
    fifo = os.path.join(_DUMPS274, "gs12_lp.sql.gz")
    os.mkfifo(fifo, 0o600)
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    opener = _sp274.Popen(["bash", "-c", 'sleep 4; exec 3<>"$1"', "_", fifo])  # nosec B603 B607
    try:
        rc, took = _import274()
    finally:
        opener.wait(timeout=20)
        os.unlink(fifo)
    return rc, took, os.path.exists(_FED274)


try:
    _fifo274 = _fifo_import274()
    check("db-import (helper): a FIFO the game account put at the dump's name is refused at once with rc 4, as the "
          "remote form refuses it (the open waited for a writer for ever, and the root helper with it)",
          _fifo274[0] == 4 and _fifo274[1] < 3 and not _fifo274[2], repr(_fifo274))
    with _gz274.open(os.path.join(_DUMPS274, "gs12_lp.sql.gz"), "wb") as _fh274:
        _fh274.write(b"CREATE TABLE t274 (i int);\n")
    _reg274 = _import274()
    check("db-import (helper): ...while a regular dump is still fed to the client whole",
          _reg274[0] == 0 and open(_FED274, "rb").read() == b"CREATE TABLE t274 (i int);\n", repr(_reg274))
finally:
    _sh274.rmtree(_T274, ignore_errors=True)
