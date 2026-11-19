"""Part 269 of the unit suite: review pass 33, the app side.

1. A game that listens beside its own port (Valheim on -crossplay, port + 1) reads online on its own
   page (/api/server/<id>/stats), on the dashboard's per-host sample and after a start, by the one
   rule the host scan uses.
2. SFTP: an open file whose permission re-check is answered "busy" (or not at all) goes on for a
   few seconds on the last "yes", then fails with that reason, never "no longer have permission";
   a definite "no" still ends it at once; one host's permission checks hold at most a quarter of
   the panel's file-request slots.
3. Add-ons: a Remove stays a job until the account's user manager has been released, and a remove
   and the server's other add-on jobs exclude each other; an Update or an Apply running is named
   as such when it refuses a second action.
4. The web server: a request body that stalls past the socket's own timeout closes the connection
   quietly (eventlet's discard logged a warning naming the client's request), and a client that
   stopped reading an answer is not waited for twice more at the end of the request.
5. An uninstall in progress refuses a server action, a mods change, a Run now and an add-on job;
   the uninstall in turn refuses beside one of those still registered.
6. A plugin Enable/Disable onto a name already taken says so (it showed "__RENAME_EXISTS__"), a
   failed plugin install is answered in the viewer's language, and a refused host edit saves
   nothing (a 403's audit row committed the new name).
7. A commit signed with no release name and no tooling-only mark (its release was not published)
   shows its date, never an older release's name; a reboot blocked by an add-on remove says so.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; every host call is a stub.
The web server runs in a child process on a free loopback port.
"""
import io as _io269
import os
import re as _re269
import shutil as _shutil269
import socket as _socket269
import subprocess as _sp269  # nosec B404 - the web server in a child process, a fixed argv
import sys as _sys269
import tempfile as _tf269
import types as _types269

import time as _time269

from paramiko import SFTP_FAILURE as _SFTP_FAILURE269, SFTP_OK as _SFTP_OK269
from paramiko import SFTP_PERMISSION_DENIED as _SFTP_DENIED269

from unit import REPO_ROOT as _ROOT269
from unit.part01 import check, eq
from unit.part06 import _inst_shfn as _shfn269
from panel.core import wsgi_serve as _ws269
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_delete_server,
                         _p9_host_row, _p9_json, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all,
                         _p9_row)
from panel.core.panel_state import r36j_route_job as _rj269
from panel.db.models import GameServer as _GS269, Group as _Group269, RemoteServer as _RS269, User as _User269
from panel.db.models import db as _db269
from panel.security import auth as _auth269
from panel.ops.ssh_manager import _core as _core269, portscan as _ps269
from panel.routes import manage_servers as _ms269
from panel.core import i18n as _i18n269
from panel.routes import addons as _ra269, addons_change as _ch269, modrinth_plugins as _mdr269
from panel.routes import server_files as _srvf269
from panel.ops.ssh_manager import files as _files269
from panel.services import monitoring as _mon269
from panel.services import sftp_broker as _br269, sftp_files as _sf269, sftp_server as _ss269

_trips269 = len(_P9_TRIPPED)
_NS269 = _types269.SimpleNamespace


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Ports a game listens on beside its own
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SAMPLE269 = ("cpu  100 0 100 800 0 0 0 0\ncpu  110 0 110 880 0 0 0 0\nMEM 8000000000 2000000000\n"
              "LOAD 0.1 0.2 0.3\nDISK 100000 50000\nCORES 2\nUPTIME 999\n")


def _sample_host269(listening, sent):
    """A run_command stand-in answering the live sample: PORT counts the listening ports `ss` names."""
    def _run(server, cmd, timeout=None, sudo=None, **_kw):
        sent.append(cmd)
        asked = {int(p) for p in _re269.findall(r"sport = :(\d+)", cmd)}
        port = "PORT %d\n" % len(asked & listening) if "sport = :" in cmd else ""
        return _SAMPLE269 + port, "", 0
    return _run


def _stats_status269(sid, listening):
    """(the /stats answer's status, the row's persisted status, the commands sent) for one poll."""
    sent = []
    _p9_patch_sm("run_command", _sample_host269(listening, sent))
    _core269._live_metrics_cache.clear()
    got = _p9_json(_p9_client(P9_ADMIN).get("/api/server/%d/stats" % sid))
    return got.get("status"), _p9_row(sid).status, sent


def _valheim_stats269():
    from panel.routes import api as _api
    _p9_patch(_api, "_maybe_resolve_public_ip", lambda *a, **k: None)   # the route's background lookup
    vh = _p9_new_server(P9_HOST, "vh269", "vh", 24560, status="online")
    gm = _p9_new_server(P9_HOST, "gm269", "gmod", 24570, status="online")
    try:
        eq("listen beside: /stats reads a Valheim listening on its port + 1 only (crossplay) online, and keeps "
           "the row online", _stats_status269(vh, {24561})[:2], ("online", "online"))
        eq("listen beside: ...one listening on its own port only (crossplay off) online too",
           _stats_status269(vh, {24560})[:2], ("online", "online"))
        eq("listen beside: ...one listening on neither offline",
           _stats_status269(vh, {24562})[:2], ("offline", "offline"))
        eq("listen beside: another game listening on its port + 1 is not counted (the offsets are Valheim's)",
           _stats_status269(gm, {24571})[:2], ("offline", "offline"))
        sent = _stats_status269(vh, set())[2]
        check("listen beside: the sample stays one round trip, with one `ss` asking for both ports",
              len(sent) == 1 and sent[0].count("ss -H") == 1 and "( sport = :24560 or sport = :24561 )" in sent[0],
              repr(sent)[:300])
    finally:
        _p9_delete_server(vh)
        _p9_delete_server(gm)
        _core269._live_metrics_cache.clear()


def _valheim_dashboard269():
    sample = {"host": {"cpu_percent": 1.0, "ram_total": 8, "ram_used": 1}, "users": {}, "ports": {24581}}
    _p9_patch(_mon269, "host_live_metrics", lambda remote: sample)
    host = _NS269(id=269001)
    rows = [_NS269(installed=True, remote=host, remote_id=269001, id=i, short_name=u, port=24580,
                   game_type=gt, query_type=None, status="online")
            for i, (u, gt) in enumerate((("vh2690", "vh"), ("gm2690", "gmod")))]
    out = {sid: m["port_open"] for work in _mon269._host_metrics_work(rows)
           for sid, m, _r, _mp in _mon269._query_host_metrics(work)}
    eq("listen beside: the dashboard's per-host sample reads the Valheim on port + 1 open, the other game not",
       out, {0: True, 1: False})


def _valheim_started269():
    sid = _p9_new_server(P9_HOST, "vh2691", "vh", 24590, status="offline")
    _p9_patch(_ms269, "_remote_listening_ports", lambda remote: {24591})
    _p9_patch(_ms269, "time", _NS269(time=_ms269.time.time, sleep=lambda s: None, monotonic=_ms269.time.monotonic))
    try:
        with _p9.app_context():
            gs = _db269.session.get(_GS269, sid)
            polled = _ms269._poll_for_game_port(gs.remote, gs)
            rescanned = _ms269._rescan_started(gs.remote, gs, (False, 0, ""))[0]
        eq("listen beside: after a start, the install's port poll and the re-read both see the Valheim on port + 1 "
           "up (no \"it hasn't opened port X yet\")", (polled, rescanned, _p9_row(sid).status),
           ((True, True), True, "online"))
    finally:
        _p9_delete_server(sid)


def _listen_ports269():
    eq("listen beside: the shared rule names Valheim's port + 1 after its own, nothing beyond 65535, and leaves a "
       "port that is not a number to the plain test",
       (_ps269.listen_ports("vh", 2456), _ps269.listen_ports("VH", 65535), _ps269.listen_ports("gmod", 27015),
        _ps269.listen_ports("vh", "2456")), ((2456, 2457), (65535,), (27015,), ("2456",)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. SFTP: busy is not "no"
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _busy_handle269(answer):
    """A WriteHandle whose next permission re-check is answered by `answer` (an exception is raised)."""
    vfs = _NS269(service=_NS269(files=_NS269(cap=1 << 30)), open_count=0, split=lambda p: tuple(p.rsplit("/", 1)))
    info = {"rel": "cfg/b269.cfg", "limit": 1 << 30, "readable": False, "mode": {}}
    wh = _sf269.WriteHandle(vfs, "/P269/cfg/b269.cfg", _NS269(key=(269,)), None, None, info, stage=bytearray())

    def _ask(folder, write):
        if isinstance(answer, Exception):
            raise answer
        return answer
    vfs.ask_folder = _ask
    wh._checked = 0.0
    return wh


def _sftp_busy269():
    busy = _sf269.Unanswered(_SFTP_FAILURE269, _br269.HOST_BUSY)
    wh = _busy_handle269(busy)
    within = wh.write(0, b"x" * 64)
    wh._granted, wh._checked = _time269.monotonic() - _sf269.AUTHZ_GRACE - 1, 0.0
    past = wh.write(64, b"x" * 64)
    eq("sftp busy: an upload whose re-check is answered busy goes on within the grace after the last yes, then "
       "fails with the busy reason (it used to abort at once as \"no longer have permission\")",
       (within, past, wh.failed), (_SFTP_OK269, (_SFTP_FAILURE269, _br269.HOST_BUSY), _br269.HOST_BUSY))
    wh = _busy_handle269(_sf269.Refused(_SFTP_DENIED269, "no"))
    eq("sftp busy: ...a definite no still ends it at once, as no longer permitted",
       (wh.write(0, b"x"), wh.failed), ((_SFTP_DENIED269, _sf269.DENIED_NOW), _sf269.DENIED_NOW))
    vfs = object.__new__(_ss269.VirtualSftp)
    vfs.conn = _NS269(signed_in=lambda: {"uid": 1, "epoch": 0, "fp": ""}, ip="192.0.2.69")
    vfs.service = _NS269(panel=_NS269(ask=lambda req, timeout=60: {}))
    try:
        vfs.ask_folder("p269", True)
        said = None
    except _sf269.Refused as r:
        said = (type(r).__name__, r.answer())
    eq("sftp busy: a permission check the panel never answered is no verdict (a failure saying so), not a refusal",
       said, ("Unanswered", (_SFTP_FAILURE269, _sf269.NO_ANSWER)))


def _sftp_host_slots269():
    asked = []
    servers = {"a": _NS269(remote_id=269101, id=1), "b": _NS269(remote_id=269102, id=2)}
    _p9_patch(_br269, "_session_user", lambda req: (_NS269(is_superadmin=True), None))
    _p9_patch(_br269, "editable", lambda user: servers)
    _p9_patch(_br269, "describe", lambda gs: {"sid": gs.id})
    _p9_patch(_br269, "account_refusal", lambda gs, write: asked.append(gs.id))
    _br269._HOST_ASKS[269101] = _br269.HOST_SLOTS
    try:
        full = _br269._h_authz(_p9, {"folder": "a", "write": True}, None)
        other = _br269._h_authz(_p9, {"folder": "b", "write": True}, None)
    finally:
        _br269._HOST_ASKS.pop(269101, None)
    again = _br269._h_authz(_p9, {"folder": "a", "write": True}, None)
    eq("sftp busy: with a host's permission checks all running (a host that stopped answering), the next one for "
       "it is answered busy at once and never asks the host; another host's is answered, and a check ending "
       "frees its count", (full, other, again, asked, dict(_br269._HOST_ASKS)),
       ({"ok": False, "busy": True, "reason": _br269.HOST_BUSY}, {"ok": True, "sid": 2}, {"ok": True, "sid": 1},
        [2, 1], {}))
    check("sftp busy: one host may hold at most a quarter of the file-request slots",
          0 < _br269.HOST_SLOTS <= _br269.HANDLER_SLOTS // 4, repr(_br269.HOST_SLOTS))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Add-on jobs
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _addon_stubs269():
    _p9_patch(_ra269, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_ra269, "_install_worker", lambda *a, **k: None)     # a claim that slips through starts nothing
    _p9_patch(_ch269, "_worker", lambda *a, **k: None)


def _post_msgs269(c, sid, paths):
    out = []
    for path in paths:
        r = c.post("/api/server/%d/addons/%s" % (sid, path), json={})
        out.append((r.status_code, (r.get_json(silent=True) or {}).get("message")))
    return out


def _addon_remove_release269(sid):
    seen = []

    def priv(remote, verb, args, timeout=None, **_k):
        seen.append((verb, _ra269.job_running(sid)))
        return "", "", 0
    _addon_stubs269()
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: ("removed=1\nothers=0\nADDON_REMOVED\n", "", 0))
    _p9_patch_sm("run_privileged", priv)
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/remove" % sid)
    eq("add-on jobs: the last add-on's Remove is still a job while the account's user manager is released (an "
       "install begun then lost its user manager), and is cleared after",
       (r.status_code, seen, _ra269.job_running(sid)), (200, [("addon-account-release", True)], False))


def _addon_exclusive269(sid):
    _addon_stubs269()
    shells = []
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: shells.append(a) or ("", "", 1))
    c = _p9_client(P9_ADMIN)
    try:
        with _ra269._JOBS_LOCK:
            _ra269._JOBS[(sid, "iw4madmin")] = {"running": True, "why": "", "tail": "", "kind": "install"}
        while_install = _post_msgs269(c, sid, ["b3/remove"])
        ran = len(shells)
        with _ra269._JOBS_LOCK:
            _ra269._JOBS[(sid, "iw4madmin")] = {"running": True, "why": "", "tail": "", "kind": "start"}
        while_start = _post_msgs269(c, sid, ["b3/remove"])[0][0]
        with _ra269._JOBS_LOCK:
            _ra269._JOBS.pop((sid, "iw4madmin"), None)
            _ra269._JOBS[(sid, "b3")] = {"running": True, "why": "", "tail": "", "kind": "remove"}
        while_remove = _post_msgs269(c, sid, ["iw4madmin/install", "iw4madmin/update", "iw4madmin/start"])
    finally:
        with _ra269._JOBS_LOCK:
            for key in ((sid, "b3"), (sid, "iw4madmin")):
                _ra269._JOBS.pop(key, None)
    eq("add-on jobs: a Remove is refused while another add-on's install runs on the server (its remove would find "
       "no other add-on and purge the account's containers under it), before anything runs on the host",
       (while_install, ran), ([(409, _ra269.ADDON_BUSY)], 0))
    check("add-on jobs: ...but not for another add-on's start being watched (it is installed, so nothing is purged)",
          while_start != 409, repr(while_start))
    eq("add-on jobs: while one add-on is being removed, an install, update or start of another on the server is "
       "refused", while_remove, [(409, _ra269.ADDON_BUSY)] * 3)


def _addon_busy_words269(sid):
    _addon_stubs269()
    c = _p9_client(P9_ADMIN)
    got = []
    try:
        for kind in ("update", "settings"):
            with _ra269._JOBS_LOCK:
                _ra269._JOBS[(sid, "b3")] = {"running": True, "why": "", "tail": "", "kind": kind}
            got.append(_post_msgs269(c, sid, ["b3/start", "b3/update"]))
    finally:
        with _ra269._JOBS_LOCK:
            _ra269._JOBS.pop((sid, "b3"), None)
    eq("add-on jobs: while an Update or an Apply runs, a second action is refused naming it (it said the add-on "
       "was being installed)", got, [[(409, _ra269._BUSY_UPDATE)] * 2, [(409, _ra269._BUSY_SETTINGS)] * 2])
    eq("add-on jobs: ...both sentences are translated (es, fr)",
       [bool(_i18n269.catalog(lang).get(t)) for lang in ("es", "fr") for t in (_ra269._BUSY_UPDATE, _ra269._BUSY_SETTINGS)],
       [True] * 4)


def _addons269():
    sid = _p9_new_server(P9_HOST, "cod4p269", "cod4", 28969, name="p269-cod4")
    try:
        _addon_remove_release269(sid)
        _addon_exclusive269(sid)
        _addon_busy_words269(sid)
    finally:
        _p9_delete_server(sid)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The web server's stalls
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SERVE269 = r"""
import os, sys
os.environ["EVENTLET_NO_GREENDNS"] = "yes"
sys.path.insert(0, sys.argv[2])
from flask import Flask, request
from panel.core import wsgi_serve

app = Flask("p269")
app.add_url_rule("/ok", "ok", lambda: "fine")


def up():
    # Small reads, as a form or upload parser makes: each one that the client's bytes satisfy grows
    # the body's budget (1 s + 1 s per 500 bytes) past the 2 s socket timeout.
    got = 0
    while True:
        part = request.stream.read(1000)
        if not part:
            return "got %d" % got
        got += len(part)


app.add_url_rule("/up", "up", up, methods=["POST"])
wsgi_serve.serve(app, "127.0.0.1", int(sys.argv[1]), None, limits=dict(header=5, body_grace=1, body_rate=500),
                 idle_seconds=5, io_timeout=2)
"""


def _serve269():
    """(the child process, its port) once GET /ok answers, or (process, None)."""
    with _socket269.socket() as so:
        so.bind(("127.0.0.1", 0))
        port = so.getsockname()[1]
    argv = [_sys269.executable, "-c", _SERVE269, str(port), str(_ROOT269)]
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    proc = _sp269.Popen(argv, stdout=_sp269.DEVNULL, stderr=_sp269.PIPE)  # nosec B603
    deadline = _time269.monotonic() + 30
    while proc.poll() is None and _time269.monotonic() < deadline:
        try:
            with _socket269.create_connection(("127.0.0.1", port), timeout=5) as so:
                so.sendall(b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                if so.recv(64).startswith(b"HTTP/1.1 200"):
                    return proc, port
        except OSError:
            _time269.sleep(0.2)
    return proc, None


def _stalled_body269(port):
    """POST 20,000 of 100,000 bytes at once, then nothing: (status line, seconds until the server closed)."""
    so = _socket269.create_connection(("127.0.0.1", port), timeout=15)
    try:
        t0 = _time269.monotonic()
        so.sendall(b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n" + b"a" * 20000)
        got = b""
        while True:
            part = so.recv(4096)
            if not part:
                return got.split(b"\r\n")[0], round(_time269.monotonic() - t0, 1)
            got += part
    except OSError as exc:
        return repr(exc).encode(), None
    finally:
        so.close()


def _body_stall269():
    proc, port = _serve269()
    try:
        answer = _stalled_body269(port) if port else (b"not ready", None)
    finally:
        if proc.poll() is None:
            proc.kill()
        err = proc.communicate(timeout=10)[1].decode("utf-8", "replace")
    check("web stalls: a body that stalls after a fair start (its budget past the 2 s socket timeout) is answered "
          "and the connection closed by the socket's own timeout", answer[0].startswith(b"HTTP/1.1 4")
          and answer[1] is not None and answer[1] < 10, repr(answer))
    check("web stalls: ...and nothing is logged for it (eventlet's discard re-read the timed-out socket and logged a "
          "warning naming the client's request, once per stalled connection)",
          "discarding" not in err and "web server:" not in err and "Traceback" not in err, err[-600:])


class _StuckRaw269(_io269.RawIOBase):
    """A socket the client stopped reading: every write waits out the timeout (counted) and raises."""

    def __init__(self):
        """Nothing written yet."""
        super().__init__()
        self.waits = 0

    def writable(self):
        """It is a writer."""
        return True

    def write(self, b):
        """Wait out the socket's timeout: TimeoutError."""
        self.waits += 1
        raise TimeoutError("timed out")


def _write_stall269():
    raw = _StuckRaw269()
    wfile = _ws269._ClientWrites(_io269.BufferedWriter(raw, 16))
    said = []
    for step in (lambda: wfile.write(b"x" * 64), wfile.flush):
        try:
            step()
        except _ws269.ClientStalled:
            said.append("stalled")
    if not wfile.closed:             # what the request handler's finish does, then its close
        try:
            wfile.flush()
        except OSError:
            said.append("finish")
    try:
        wfile.close()
    except OSError:
        said.append("close raised")
    eq("web stalls: a client that stopped reading an answer is waited for once: later writes, the request's final "
       "flush and the writer's close do not wait the socket's timeout again (it was three timeouts)",
       (raw.waits, said, wfile.closed), (1, ["stalled", "stalled", "finish"], True))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Beside an uninstall
# ════════════════════════════════════════════════════════════════════════════════════════════════
_XHR269 = {"X-Requested-With": "XMLHttpRequest"}


def _msg269(r):
    return r.status_code, (r.get_json(silent=True) or {}).get("message", "")


def _during_uninstall269(sid, gm):
    _addon_stubs269()
    host = []
    for name in ("run_as_game_user", "shell_as_game_user", "mods_action", "run_cron_job_now"):
        _p9_patch_sm(name, lambda *a, _n=name, **k: host.append(_n) or ("", "", 0))
    c = _p9_client(P9_ADMIN)
    with _rj269(sid, "uninstall"), _rj269(gm, "uninstall"):
        got = [_msg269(c.post("/api/server/%d/action" % sid, json={"action": "start"})),
               _msg269(c.post("/api/server/%d/addons/iw4madmin/install" % sid, json={})),
               _msg269(c.post("/api/server/%d/mods" % gm, json={"action": "install", "mod": "sourcemod"})),
               _msg269(c.post("/api/server/%d/cron/run" % gm, json={"raw": "0 4 * * * update"}))]
    said = "'p269-gmod' is being uninstalled. Nothing was changed."
    eq("beside an uninstall: a Start, an add-on install, a mods install and a Run now are each refused naming "
       "the uninstall, and none reaches the host (each ran in an account seconds from userdel)",
       (got, host), ([(200, "'p269-cod4u' is being uninstalled — 'start' was not run."), (409, _ra269._BUSY_UNINSTALL),
                      (409, said), (409, said)], []))
    eq("beside an uninstall: ...its sentences are translated (es, fr)",
       [bool(_i18n269.catalog(lang).get(t)) for lang in ("es", "fr")
        for t in ("'{name}' is being uninstalled — '{action}' was not run.", _ra269._BUSY_UNINSTALL,
                  "'{name}' is being uninstalled. Nothing was changed.")], [True] * 6)


def _uninstall_beside269(sid):
    ran = []
    _p9_patch(_ms269, "_r25b_uninstall_claimed",
              lambda app, gs, remote, server_id, name: ran.append(server_id) or _ms269._index_reply("x", True, "success"))
    c = _p9_client(P9_ADMIN)
    got = []
    for kind in ("mods", "cron", "action", "queued"):
        with _rj269(sid, kind):
            got.append(_msg269(c.post("/servers/%d/delete" % sid, headers=_XHR269))[0])
    eq("beside an uninstall: the uninstall is refused (409) while a mods change, a Run now, an action or a queued "
       "restart is registered on the server, and removes nothing", (got, ran), ([409] * 4, []))


def _uninstall269():
    sid = _p9_new_server(P9_HOST, "cod4u269", "cod4", 28979, name="p269-cod4u")
    gm = _p9_new_server(P9_HOST, "gmu269", "gmod", 27069, name="p269-gmod")
    try:
        _during_uninstall269(sid, gm)
        _uninstall_beside269(sid)
    finally:
        _p9_delete_server(sid)
        _p9_delete_server(gm)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. Plugins and the host edit
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _user_lang269(uid, lang):
    """Set user `uid`'s saved language to `lang`; -> the one it had."""
    with _p9.app_context():
        user = _db269.session.get(_User269, uid)
        before, user.language = user.language, lang
        _db269.session.commit()
        return before


def _plugins269():
    sid = _p9_new_server(P9_HOST, "pmc269", "pmc", 25569, name="p269-pmc")
    _p9_patch(_srvf269, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch_sm("rename_path", lambda *a, **k: (False, _files269.RENAME_EXISTS))
    _p9_patch(_mdr269._mr, "resolve", lambda pid, ver: ({"plan": {"filename": "Foo-2.jar"}, "title": "Foo",
                                                       "version_number": "2", "version_id": "V2"}, None))
    _p9_patch(_mdr269._mr, "download", lambda plan: (b"PK", None))
    _p9_patch(_mdr269, "mc_version", lambda gs: "1.21.4")
    _p9_patch_sm("upload_file", lambda *a, **k: (False, "Invalid filename"))
    c = _p9_client(P9_ADMIN)
    try:
        r = c.post("/api/server/%d/plugins/change" % sid, json={"action": "enable", "name": "Foo.jar.disabled"})
        before = _user_lang269(P9_ADMIN, "es")
        try:
            inst = _p9_json(c.post("/api/server/%d/plugins/install" % sid, json={"project_id": "AABBCC12"}))
        finally:
            _user_lang269(P9_ADMIN, before)
    finally:
        _p9_delete_server(sid)
    eq("plugins: an Enable onto a name already in the folder is a 409 conflict saying so, not the internal "
       "\"__RENAME_EXISTS__\"", (r.status_code, _p9_json(r).get("message"), _p9_json(r).get("conflict")),
       (409, _i18n269.tr(_mdr269._MDR_NAME_TAKEN, name="Foo.jar"), True))
    want = _i18n269.catalog("es").get("Invalid filename")
    check("plugins: ...a plugin install whose write failed is answered in the viewer's language (es)",
          bool(want) and inst.get("message") == want, repr((inst, want)))
    eq("plugins: ...the new sentence is translated (es, fr)",
       [bool(_i18n269.catalog(lang).get(_mdr269._MDR_NAME_TAKEN)) for lang in ("es", "fr")], [True, True])


_WORDS269 = "Tr4ck-269-hors3-batt3ry"


def _host_edit269():
    with _p9.app_context():
        host = _RS269(name="p269-host", host="192.0.2.169", port=22, username="root", auth_method="password",
                      auth_credential="")
        group = _Group269(name="p269_deleg", description="", is_default=False)
        group.set_permissions([_auth269.MANAGE_REMOTES])
        group.servers.append(host)
        user = _User269(username="p269_deleg", password_hash=_auth269.hash_password(_WORDS269),
                        is_superadmin=False, is_active=True)
        user.groups.append(group)
        _db269.session.add_all([host, group, user])
        _db269.session.commit()
        rid, uid, gid = host.id, user.id, group.id
    try:
        r = _p9_client(uid).post("/remotes/%d/edit" % rid, headers=_XHR269,
                                 data={"name": "p269-renamed", "host": "192.0.2.170", "ssh_port": "22",
                                       "ssh_user": "root"})
        row = _p9_host_row(rid)
        eq("host edit: a delegated admin's edit refused for moving the address (403) leaves the name as it was "
           "(the refusal's audit row committed the name set before it)", (r.status_code, row.name, row.host),
           (403, "p269-host", "192.0.2.169"))
    finally:
        with _p9.app_context():
            for model, key in ((_User269, uid), (_Group269, gid), (_RS269, rid)):
                obj = _db269.session.get(model, key)
                if obj is not None:
                    _db269.session.delete(obj)
            _db269.session.commit()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. Release names, and the reboot's words for an add-on job
# ════════════════════════════════════════════════════════════════════════════════════════════════
_DAY269 = 1795046400          # 2026-11-19 00:00 UTC
_GIT_ENV269 = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def _git269(repo, *args, stdin=None, **env):
    r = _sp269.run(["git", "-C", repo, *args], input=stdin, capture_output=True, text=True, check=False,  # nosec B603 B607
                   env=dict(os.environ, **_GIT_ENV269, **env))
    return r.stdout.strip()


def _commit269(repo, msg, at):
    _git269(repo, "commit", "-q", "--allow-empty", "-m", msg, GIT_COMMITTER_DATE="@%d +0000" % at,
            GIT_AUTHOR_DATE="@%d +0000" % at)
    return _git269(repo, "rev-parse", "HEAD")


def _signatures269(repo, ref, entries):
    """Save main/<sha>.<kind> (kind "name" holding the name, or "inherit") on the signatures ref, as sign-release does."""
    idx = os.path.join(repo, ".git", "sig-index")
    for sha, kind, text in entries:
        blob = _git269(repo, "hash-object", "-w", "--stdin", stdin=text + "\n")
        _git269(repo, "update-index", "--add", "--cacheinfo", "100644,%s,main/%s.%s" % (blob, sha, kind),
                GIT_INDEX_FILE=idx)
    tree = _git269(repo, "write-tree", GIT_INDEX_FILE=idx)
    _git269(repo, "update-ref", ref, _git269(repo, "commit-tree", tree, "-m", "signatures"))


def _installer_label269(repo):
    prog = "set -euo pipefail\n" + "".join(_shfn269(n) for n in (
        "_gitc", "_epoch_version", "_r42i_tree_owner", "_owner_read", "_version_file", "_release_name",
        "panel_version")) + "panel_version\n"
    r = _sp269.run(["bash", "-c", prog], capture_output=True, text=True, check=False, timeout=60,  # nosec B603 B607
                   env=dict(os.environ, PANEL_DIR=repo, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                            GIT_CEILING_DIRECTORIES=os.path.dirname(repo)))
    return r.stdout.strip().split(" · ")[0]


def _release_names269():
    from panel.ops import system_ops as _so
    tmp = _tf269.mkdtemp(prefix="p269-")
    repo = os.path.join(tmp, "rel")
    try:
        _sp269.run(["git", "init", "-q", "-b", "main", repo], capture_output=True, check=False)  # nosec B603 B607
        third = _commit269(repo, "release 2026.11.19.3", _DAY269 + 3600)
        runtime = _commit269(repo, "panel code, its release not published", _DAY269 + 7200)
        tooling = _commit269(repo, "tooling after it", _DAY269 + 9000)
        _signatures269(repo, _so._RELEASE_SIG_REF, [(third, "name", "2026.11.19.3"), (tooling, "inherit", "tooling only")])
        saved_dir = _so.PANEL_DIR
        _so.PANEL_DIR = repo
        try:
            labels = [_so.version_for_commit(c) for c in (tooling, runtime, third)]
            installer = _installer_label269(repo)
            _git269(repo, "reset", "-q", "--hard", runtime)
            _signatures269(repo, _so._RELEASE_SIG_REF, [(runtime, "inherit", "tooling only")])
            marked = (_so.version_for_commit(runtime), _installer_label269(repo))
        finally:
            _so.PANEL_DIR = saved_dir
    finally:
        _shutil269.rmtree(tmp, ignore_errors=True)
    eq("release name: a commit signed with neither a name nor the tooling-only mark (it changes panel code; its "
       "release was not published) shows its date, and so does a tooling commit after it; the named one keeps "
       "its name (an older release's name was shown for newer code)", labels,
       ["2026.11.19", "2026.11.19", "2026.11.19.3"])
    eq("release name: ...install.sh's label follows the same rule", installer, "2026.11.19")
    eq("release name: ...and a commit marked tooling-only still takes the name before it, in both (control)",
       marked, ("2026.11.19.3", "2026.11.19.3"))


def _reboot_words269():
    from panel.services import reboot_words as _rw
    said = _rw._BLOCKER_WORDS["addon"].template
    check("reboot words: an add-on job blocking a reboot is named for every kind it can be (a remove read as an "
          "install or update)", "removal" in said and "settings" in said, said)
    eq("reboot words: ...translated (es, fr)",
       [bool(_i18n269.catalog(lang).get(said)) for lang in ("es", "fr")], [True, True])


def _main269():
    _p9_arm(_p9_patch, who="part269")
    try:
        _valheim_stats269()
        _valheim_dashboard269()
        _valheim_started269()
        _listen_ports269()
        _sftp_busy269()
        _sftp_host_slots269()
        _addons269()
        _uninstall269()
        _plugins269()
        _host_edit269()
    finally:
        _p9_restore_all()
    _body_stall269()
    _write_stall269()
    _release_names269()
    _reboot_words269()
    check("part269: no check reached a real transport", len(_P9_TRIPPED) == _trips269,
          repr(_P9_TRIPPED[_trips269:][:4]))


_main269()
