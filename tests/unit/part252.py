"""Part 252 of the unit suite: a client that hangs up is not logged; a database upload holds its guard.

* The web server (wsgi_serve.serve, started for real on loopback) logs no traceback when a client
  reads one byte of a static file and resets the connection, however often; a response that fails
  for a real reason is still logged in full. The filter itself: a chain that holds any exception
  other than a hang-up is logged.
* A database upload stays listed until its restore has ended: a second upload to the same database,
  a cancel or another finish of it, sent while the restore runs, is refused ("already running"), and
  the next upload starts once it is over. An upload with a request running is never swept as idle.

HOW IT RUNS. The server check starts wsgi_serve in a child process on a free loopback port and
resets its connections with SO_LINGER 0. The upload checks drive part12's Flask app with its
transport tripwire armed and the host's commands stubbed; every stub is undone in the finally.
Nothing reaches a host, sudo or the checkout's data/.
"""
import logging as _logging252
import os as _os252
import shutil as _shutil252
import socket as _socket252
import struct as _struct252
import subprocess as _sp252  # nosec B404 - starts this part's own loopback server
import sys as _sys252
import tempfile as _tempfile252
import time as _time252

from unit import REPO_ROOT as _ROOT252
from unit.part01 import check, eq
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_patch_sm, _p9_restore_all
from unit.part226 import _db_setup226, _db_teardown226
from panel.core import wsgi_serve as _ws252
from panel.ops.ssh_manager import databases as _dbs252
from panel.routes import databases_files as _dfr252

_trips252 = len(_P9_TRIPPED)
_TMP252 = _tempfile252.mkdtemp(prefix="lgsm-unit-p252-")

_SERVE252 = r"""
import os, sys
os.environ["EVENTLET_NO_GREENDNS"] = "yes"
sys.path.insert(0, sys.argv[2])
from flask import Flask
from panel.core import wsgi_serve

app = Flask("p252", static_folder=sys.argv[3], static_url_path="/static")
app.add_url_rule("/ok", "ok", lambda: "fine")


def _broken():
    yield b"x" * 70000
    raise RuntimeError("stream part252 broke")


app.add_url_rule("/broken", "broken", lambda: app.response_class(_broken()))
wsgi_serve.serve(app, "127.0.0.1", int(sys.argv[1]))
"""
_OK252 = b"GET /ok HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"


def _free_port252():
    with _socket252.socket() as so:
        so.bind(("127.0.0.1", 0))
        return so.getsockname()[1]


def _get252(port, path):
    """GET `path` on a fresh connection and read until it closes: the bytes read, b"" on none."""
    got = b""
    try:
        with _socket252.create_connection(("127.0.0.1", port), timeout=5) as so:
            so.sendall(b"GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" % path)
            while len(got) < 1 << 20:
                part = so.recv(65536)
                if not part:
                    break
                got += part
    except OSError:
        pass
    return got


def _reset252(port):
    """Ask for the large static file, read one byte, and reset the connection (RST, not FIN): the first byte."""
    with _socket252.create_connection(("127.0.0.1", port), timeout=5) as so:
        so.setsockopt(_socket252.SOL_SOCKET, _socket252.SO_RCVBUF, 4096)
        so.sendall(b"GET /static/big.bin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        first = so.recv(1)
        so.setsockopt(_socket252.SOL_SOCKET, _socket252.SO_LINGER, _struct252.pack("ii", 1, 0))
    return first


def _serve252():
    """Start the child server on a free port: (process, port, whether it answered /ok in time)."""
    static = _os252.path.join(_TMP252, "static")
    _os252.makedirs(static, exist_ok=True)
    with open(_os252.path.join(static, "big.bin"), "wb") as fh:
        fh.write(b"\0" * (3 * 1024 * 1024))
    port = _free_port252()
    args = [_sys252.executable, "-c", _SERVE252, str(port), str(_ROOT252), static]
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    proc = _sp252.Popen(args, stdout=_sp252.DEVNULL, stderr=_sp252.PIPE)  # nosec B603
    deadline = _time252.monotonic() + 20
    while proc.poll() is None and _time252.monotonic() < deadline:
        if _get252(port, b"/ok").startswith(b"HTTP/1.1 200"):
            return proc, port, True
        _time252.sleep(0.2)
    return proc, port, False


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A client that resets a static download leaves nothing in the log
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _resets252():
    proc, port, ready = _serve252()
    try:
        firsts = [_reset252(port) for _ in range(5)] if ready else []
        _time252.sleep(0.5)        # the server's write to each reset socket fails at once; let it run
        broken = _get252(port, b"/broken")
        after = _get252(port, b"/ok")
    finally:
        proc.kill()
        err = proc.communicate(timeout=10)[1].decode("utf-8", "replace")
    eq("web server: five downloads of a static file, each read for one byte and then reset, log no traceback "
       "(no 'A response failed', no ConnectionResetError or BrokenPipeError)",
       (ready, firsts, err.count("A response failed"), "ConnectionResetError" in err, "BrokenPipeError" in err),
       (True, [b"H"] * 5, 1, False, False))
    eq("web server: a response that fails for a real reason is still logged in full, once, and the server keeps "
       "serving (control)",
       ("RuntimeError: stream part252 broke" in err, broken.startswith(b"HTTP/1.1 200"), after.split(b"\r\n")[0]),
       (True, True, b"HTTP/1.1 200 OK"))


def _chain252(exc):
    """What _TracebacksOnly.info logs for a traceback formatted while `exc` is handled: the error count."""
    seen = []
    handler = _logging252.Handler()
    handler.emit = seen.append
    logger = _logging252.getLogger("panel.wsgi")
    logger.addHandler(handler)
    try:
        try:
            raise exc
        except (OSError, RuntimeError):
            _ws252._TracebacksOnly().info("Traceback (most recent call last):\n  ...\n")
    finally:
        logger.removeHandler(handler)
    return len([r for r in seen if r.levelno == _logging252.ERROR])


def _filter252():
    def _reset_during(first):
        try:
            raise first
        except (OSError, RuntimeError):
            try:
                raise ConnectionResetError(104, "Connection reset by peer")
            except ConnectionResetError as exc:
                return exc
    reset_on_reset = _reset_during(BrokenPipeError(32, "Broken pipe"))
    reset_on_fault = _reset_during(RuntimeError("a real fault first"))
    got = [_chain252(e) for e in (ConnectionResetError(104, "reset"), BrokenPipeError(32, "pipe"),
                                  OSError(32, "a plain EPIPE"), reset_on_reset, reset_on_fault,
                                  OSError(5, "an I/O error"), RuntimeError("a real fault"))]
    eq("web server log: a reset, a broken pipe, a plain EPIPE and a reset while a broken pipe was handled are "
       "dropped; a reset while a real fault was handled, an I/O error and a real fault are logged",
       got, [0, 0, 0, 0, 1, 1, 1])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A database upload holds its guard until its restore has ended
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cmd252(server, cmd, timeout=30, sudo=True, **kw):
    if ".piece" in cmd:
        return "__DBUP_SIZE__ 10", "", 0
    return ("__DBUP_STORED__" if "awk -v me=" in cmd else "__DBUP_READY__"), "", 0


def _overlap252(c, api, name):
    """Requests sent while an upload's restore runs: {what: (status, success)}, and the uploads listed after."""
    during, restores = {}, []
    uid = _p9_json(c.post(api + "/upload", json={"size": 10})).get("id", "")

    def _restore(*a, **k):
        restores.append(a[3])
        if len(restores) == 1:
            for what, path, body in (("start", "/upload", {"size": 10}), ("cancel", "/upload/%s/cancel" % uid, {}),
                                     ("finish", "/upload/%s/finish" % uid, {"confirm": name})):
                r = c.post(api + path, json=body)
                during[what] = (r.status_code, _p9_json(r).get("success"))
        return True, ""
    _p9_patch(_dbs252, "restore", _restore)
    c.post(api + "/upload/%s?offset=0" % uid, data=b"0123456789")
    done = c.post(api + "/upload/%s/finish" % uid, json={"confirm": name})
    listed = len(_dfr252._UPLOADS)
    nxt = c.post(api + "/upload", json={"size": 10})
    return during, (done.status_code, len(restores), listed, nxt.status_code)


def _idle_busy252(c, api):
    """A start over an upload of this database idle past UPLOAD_IDLE but with a request running."""
    _dfr252._UPLOADS.clear()
    entry = {"uid": "b" * 32, "db": int(api.rsplit("/", 1)[1]), "user": P9_ADMIN, "size": 10,
             "ts": _time252.time() - _dfr252.UPLOAD_IDLE - 60, "busy": 1}
    _dfr252._UPLOADS[entry["uid"]] = entry
    r = c.post(api + "/upload", json={"size": 10})
    return r.status_code, entry["uid"] in _dfr252._UPLOADS


def _uploads252():
    sid = None
    try:
        sid, api, name = _db_setup226()
        _p9_patch_sm("run_command", _cmd252)
        _p9_patch(_dfr252, "game_account_write_refusal", lambda remote, user, **k: None)
        c = _p9_client(P9_ADMIN)
        during, after = _overlap252(c, api, name)
        idle = _idle_busy252(c, api)
    finally:
        if sid is not None:
            _db_teardown226(sid)
    running = (409, False)
    eq("database upload: while an upload's restore runs, a second upload to the same database is refused "
       "(already running), and so are a cancel and another finish of it — before, the upload was dropped "
       "first, so the second start ran alongside the restore", during,
       {"start": running, "cancel": running, "finish": running})
    eq("database upload: the restore runs once and answers; afterwards nothing is listed and the next upload "
       "starts", after, (200, 1, 0, 200))
    eq("database upload: an upload with a request running is never swept as idle, however old its last "
       "answer: a new start is refused and it stays listed", idle, (409, True))


try:
    _filter252()
    _resets252()
    _p9_arm(who="part252")
    try:
        _uploads252()
    finally:
        _p9_restore_all()
        _dfr252._UPLOADS.clear()
finally:
    _shutil252.rmtree(_TMP252, ignore_errors=True)

check("part252: nothing reached a real transport", len(_P9_TRIPPED) == _trips252, repr(_P9_TRIPPED[_trips252:]))
