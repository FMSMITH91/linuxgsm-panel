"""Part 252 of the unit suite: a client that hangs up is not logged; a database upload holds its guard.

* The web server (wsgi_serve.serve, started for real on loopback) logs no traceback when a client
  reads one byte of a static file and resets the connection, however often; a response that fails
  for a real reason is still logged in full. The filter itself: a chain that holds any exception
  other than a hang-up is logged.
* A database upload stays listed until its restore has ended: a second upload to the same database,
  a cancel or another finish of it, sent while the restore runs, is refused ("already running"), and
  the next upload starts once it is over. An upload with a request running is never swept as idle.
* A failed upload restore says what the server's files hold now: the earlier dump put back, or no
  dump at all when there was none before (settle_script reports which).
* Let's Encrypt: the helper says "no such certificate" for a name panel.conf lists that has no
  certificate and "not opened" for a name it does not list (and never looks for that one); the route
  shows the matching sentence and writes a tls_cert_refused audit row, with the name only when it is
  a valid certificate name.

HOW IT RUNS. The server check starts wsgi_serve in a child process on a free loopback port and
resets its connections with SO_LINGER 0. The upload checks drive part12's Flask app with its
transport tripwire armed and the host's commands stubbed; every stub is undone in the finally.
Nothing reaches a host, sudo or the checkout's data/.
"""
import io as _io252
import logging as _logging252
import os as _os252
import pathlib as _pl252
import shutil as _shutil252
import socket as _socket252
import struct as _struct252
import subprocess as _sp252  # nosec B404 - starts this part's own loopback server
import sys as _sys252
import tempfile as _tempfile252
import time as _time252
from importlib import machinery as _mach252, util as _ilu252

from unit import REPO_ROOT as _ROOT252
from unit.part01 import check, eq
from unit.part05 import _helper_path
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_flashes, _p9_json, _p9_patch,
                         _p9_patch_sm, _p9_restore_all)
from unit.part226 import _db_setup226, _db_teardown226
from panel.core import wsgi_serve as _ws252
from panel.db.models import AuditLog as _AL252
from panel.ops import system_ops as _so252
from panel.ops.ssh_manager import databases as _dbs252
from panel.routes import databases_files as _dfr252, tls_cert as _tlsr252
from panel.services import certs as _certs252, host_reboot as _hr252, tls_own as _own252

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


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A failed upload restore says what the server's files hold now
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _settle_bash252(had_earlier):
    """Settle a failed restore with bash on a temp home: (outcome(), what <name>.sql.gz holds, a .prev left)."""
    home = _os252.path.join(_TMP252, "home", "gm252")
    dumps = _os252.path.join(home, "panel-db-dumps")
    _shutil252.rmtree(home, ignore_errors=True)
    _os252.makedirs(dumps)
    dest = _os252.path.join(dumps, "gs1_lp.sql.gz")
    for path, data in [(dest, b"the upload")] + ([(dest + ".prev", b"the earlier dump")] if had_earlier else []):
        with open(path, "wb") as fh:
            fh.write(data)
    script = _dfr252.settle_script("gm252", "gs1_lp", False, "e" * 32).replace("/home/gm252", home)
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    p = _sp252.run(["bash", "-c", script], capture_output=True, text=True, timeout=60, check=False)  # nosec B603 B607
    held = None
    if _os252.path.exists(dest):
        with open(dest, "rb") as fh:
            held = fh.read()
    return _dfr252.outcome(p.stdout + p.stderr), held, _os252.path.exists(dest + ".prev")


def _settle_said252(c, api, name, settle_out):
    """A failed restore whose settle answers `settle_out`: the answer's message."""
    def _cmd(server, cmd, timeout=30, sudo=True, **kw):
        if "k=none" in cmd:
            return settle_out, "", 0
        return _cmd252(server, cmd, timeout, sudo, **kw)
    _p9_patch_sm("run_command", _cmd)
    _p9_patch(_dbs252, "restore", lambda *a, **k: (False, "The import failed (part252)."))
    uid = _p9_json(c.post(api + "/upload", json={"size": 10})).get("id", "")
    c.post(api + "/upload/%s?offset=0" % uid, data=b"0123456789")
    return _p9_json(c.post(api + "/upload/%s/finish" % uid, json={"confirm": name})).get("message", "")


def _settle_copy252():
    eq("upload settle: after a failed restore, an earlier dump kept aside is put back and reported as 'prev'; "
       "with none before, the upload is removed and 'none' is reported",
       [_settle_bash252(True), _settle_bash252(False)],
       [(("ok", "prev"), b"the earlier dump", False), (("ok", "none"), None, False)])
    sid = None
    try:
        sid, api, name = _db_setup226()
        _p9_patch(_dfr252, "game_account_write_refusal", lambda remote, user, **k: None)
        c = _p9_client(P9_ADMIN)
        said = [_settle_said252(c, api, name, out) for out in ("__DBUP_READY__ prev", "__DBUP_READY__ none", "")]
    finally:
        if sid is not None:
            _db_teardown226(sid)
    eq("upload restore failed: the answer says the earlier dump is back only when there was one; with none it "
       "says the files hold no dump of this database; an unanswered settle says to check the folder",
       [(m.startswith("The import failed (part252)."), m.endswith(s)) for m, s in
        zip(said, (_dfr252.S_PREV_BACK, _dfr252.S_NO_PREV, _dfr252.S_PREV_UNKNOWN))],
       [(True, True)] * 3)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Let's Encrypt: no such certificate, not opened, and the audit row
# ════════════════════════════════════════════════════════════════════════════════════════════════
_spec252 = _ilu252.spec_from_loader("ph_le252", _mach252.SourceFileLoader("ph_le252", _helper_path))
_ph252 = _ilu252.module_from_spec(_spec252)
_spec252.loader.exec_module(_ph252)
_LISTED252, _UNLISTED252 = "listed.example.com", "absent.example.org"


def _helper252(verb, args, timeout=30, merge_stderr=True):
    """system_ops._run_verb as the helper answers it, in this process: (stdout, stderr, rc)."""
    saved = (_sys252.stdout, _sys252.stderr, _sys252.stdin)
    _sys252.stdout, _sys252.stderr, _sys252.stdin = _io252.StringIO(), _io252.StringIO(), _io252.StringIO("")
    try:
        rc = _ph252.main(["panel-helper", verb] + list(args))
        return _sys252.stdout.getvalue(), _sys252.stderr.getvalue(), rc
    finally:
        _sys252.stdout, _sys252.stderr, _sys252.stdin = saved


def _audit252(since):
    with _p9.app_context():
        return [(r.detail, r.success) for r in _AL252.query.filter(
            _AL252.action == "tls_cert_refused", _AL252.id > since).order_by(_AL252.id).all()]


def _last_audit252():
    with _p9.app_context():
        row = _AL252.query.order_by(_AL252.id.desc()).first()
        return row.id if row else 0


def _le252():
    le_root = _os252.path.join(_TMP252, "letsencrypt")
    _os252.makedirs(_os252.path.join(le_root, "live"), exist_ok=True)
    _os252.makedirs(_os252.path.join(_TMP252, "data", "ssl"), mode=0o700, exist_ok=True)
    cfg = {}
    _p9_patch(_ph252, "TLS_LE_ROOT", le_root)
    _p9_patch(_ph252, "panel_conf", lambda: {"data_dir": _os252.path.join(_TMP252, "data"),
                                             "tls_le_names": _LISTED252})
    _p9_patch(_certs252, "DATA_DIR", _pl252.Path(_TMP252) / "data")
    for mod in (_own252, _tlsr252):
        _p9_patch(mod, "load_config", lambda: dict(cfg))
        _p9_patch(mod, "update_config", lambda mutate: mutate(cfg))
    _p9_patch(_hr252, "panel_host_busy", lambda: None)
    _p9_patch(_so252, "restart_panel", lambda delay_seconds=2: (False, "part252 never restarts"))
    helper = [_helper252("tls-le-copy", [n])[1:] for n in (_LISTED252, _UNLISTED252)]
    _p9_patch(_so252, "_run_verb", _helper252)
    since, c, flashed = _last_audit252(), _p9_client(P9_ADMIN), []
    for name in (_LISTED252, _UNLISTED252, "bad name\ninjected"):
        c.post("/settings/tls/letsencrypt", data={"le_name": name})
        flashed.append(_p9_flashes(c))
    rows = _audit252(since)
    eq("le copy: the helper says 'no such certificate' for a listed name with no certificate, and 'not opened' for "
       "an unlisted one", helper,
       [("tls-le-copy: no such certificate\n", 1), ("tls-le-copy: certificate not opened to the panel at install\n", 1)])
    eq("le copy: through the route, the listed name with no certificate gets the 'no such certificate' sentence and "
       "the unlisted one the 'not opened' sentence",
       [f[:1] for f in flashed[:2]],
       [[_own252.LE_NOT_FOUND.replace("{name}", _LISTED252)], [_own252.LE_NOT_OPENED.replace("{name}", _UNLISTED252)]])
    eq("le copy: each refusal writes a failed tls_cert_refused audit row naming the certificate; a value that is not "
       "a certificate name is not written into the row",
       [(d.split(":")[0], ok) for d, ok in rows] + [any("injected" in d for d, _ok in rows)],
       [("letsencrypt " + _LISTED252, False), ("letsencrypt " + _UNLISTED252, False),
        ("letsencrypt (not a certificate name)", False), False])


try:
    _filter252()
    _resets252()
    _p9_arm(who="part252")
    try:
        _uploads252()
        _settle_copy252()
        _le252()
    finally:
        _p9_restore_all()
        _dfr252._UPLOADS.clear()
finally:
    _shutil252.rmtree(_TMP252, ignore_errors=True)

check("part252: nothing reached a real transport", len(_P9_TRIPPED) == _trips252, repr(_P9_TRIPPED[_trips252:]))
