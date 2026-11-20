"""Part 263 of the unit suite: SFTP service robustness, add-on and database guards, host and installer fixes.

1. SFTP: the service's link to the panel survives an answer that came too late, and answers come
   back by request id (several in flight); the panel answers each request in its own thread, so a
   slow one holds no other; an upload cut off by a disconnect has its hidden staged copy removed
   before the host connection closes; removing a key ends the sessions signed in with it; "last
   used" is stamped when a session starts, not when a key is merely offered; FSETSTAT on an open
   file keeps the path form's protected-name rule and audit row; a name paused by wrong passwords
   still signs in with its key.
2. Add-ons: Remove is refused while an install, update or settings change runs (and the card hides
   it); a change runs the install's log and ids checks before it writes the unit; the reboot census
   counts a running add-on job.
3. Databases: a cancel is refused while a finish still checks the dump; a password reset or delete
   is refused while an installed add-on uses the database; the remote db-import gives a tailnet
   server every option the other connections get.
4. Step-up: a game restore, a game backup upload's start, a panel backup's delete and the backup
   settings ask for the password again past the window.
5. Hosts: Tailscale's IPv6 range is exempt from blocks everywhere; the add-on account's subordinate
   ids are picked under a lock (helper and remote form) and an overlapping range is taken back.
6. GMod content cron per script; a JSON config with a duplicate key gets the raw editor only; an
   install's last-pass remedy gets its pass; the update abort trap says when its unpack failed.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; every host call is a stub.
The SFTP pieces run over socket pairs in this process (the service's Panel with its _die stubbed).
"""
import base64 as _b64_263
import fcntl as _fcntl263
import json as _json263
import os
import shlex as _shlex263
import socket as _socket263
import subprocess as _sp263  # nosec B404 - bash over this part's own throwaway files
import sys as _sys263
import tempfile as _tf263
import threading as _th263
import time as _time263
import types as _types263

from paramiko import SFTP_OK as _SFTP_OK263, SFTP_PERMISSION_DENIED as _SFTP_DENIED263, SFTPAttributes as _Attr263

from unit.part01 import _iw_fetch, _iw_run, check, eq
from unit.part05 import _helper as _h263
from unit.part12 import (P9_ADMIN, P9_HOST, P9_LOCAL, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_delete_server,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part47 import _cut47
from unit.part221 import _node221, _stale221
from unit.part256 import _SUM_OUT256, _step4_256
from panel.core import i18n as _i18n263
from panel.core.config import encrypt_secret as _enc263
from panel.db.models import GameDatabase as _GD263, SftpKey as _Key263, User as _User263, db as _db263
from panel.ops.ssh_manager import _core as _core263, gmod as _gmod263, hosts as _hosts263
from panel.routes import addons as _ra263, addons_change as _ch263, databases_files as _dbf263
from panel.routes import databases_net as _net263, host_local as _hl263, manage_servers as _ms263
from panel.routes import remote_security as _rs263
from panel.security import account_guard as _ag263, privileged as _pv263
from panel.services import addons as _ad263, game_config_form as _gcf263, host_reboot as _hr263
from panel.services import reboot_words as _rw263, sftp_backend as _bk263, sftp_broker as _br263
from panel.services import sftp_common as _sc263, sftp_files as _sf263, sftp_server as _ss263
from eventlet.timeout import Timeout as _GreenTimeout263   # noqa: E402 - with the other imports above
# A stored hash no password can match (a test user that signs in only by key).
_NO_LOGIN263 = "!"

_trips263 = len(_P9_TRIPPED)
_TMP263 = _tf263.mkdtemp(prefix="p263-")
_NS263 = _types263.SimpleNamespace


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. SFTP
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _line263(sock_file):
    """One JSON line from a socket file, or {"read failed": why}."""
    try:
        return _json263.loads(sock_file.readline())
    except (OSError, ValueError) as exc:
        return {"read failed": type(exc).__name__}


def _answer263(sock, rid, **fields):
    sock.sendall(_json263.dumps(dict(fields, id=rid)).encode("utf-8") + b"\n")


def _join263(thread, seconds):
    """Wait for `thread` at most `seconds` (eventlet's green join raises its Timeout instead of returning)."""
    try:
        thread.join(seconds)
    except _GreenTimeout263:
        pass   # still running after `seconds`: the caller checks is_alive()


def _end_link263(panel, ours, theirs, rf):
    """Close the panel's end and wait for the reader to see it, while _die is still the stub.

    The real _die ends the process (os._exit): a reader that saw the end of the socket after the stub
    was put back would end the whole suite here with status 0, every later check unrun.
    """
    rf.close()                  # a socket's fd stays open while a file made from it is
    theirs.close()
    reader = getattr(panel, "reader", None)
    if reader is not None:
        _join263(reader, 5)
    ours.close()
    check("sftp service (harness): the Panel's reader ended with the socket", not (reader and reader.is_alive()))


def _panel_late263():
    """A request that timed out, then another: (the first's answer, the second's)."""
    ours, theirs = _socket263.socketpair()
    theirs.settimeout(5)
    rf, got = theirs.makefile("rb"), {}
    panel = _ss263.Panel(ours)
    try:
        first = _th263.Thread(target=lambda: got.__setitem__("slow", panel.ask({"op": "slow"}, timeout=0.3)))
        first.start()
        req1 = _line263(rf)
        _join263(first, 5)
        second = _th263.Thread(target=lambda: got.__setitem__("next", panel.ask({"op": "next"}, timeout=5)))
        second.start()
        req2 = _line263(rf)
        _answer263(theirs, req1.get("id"), late=True)      # the first's answer, after its request gave up
        _answer263(theirs, req2.get("id"), ok=True, n=2)
        _join263(second, 6)
        return got.get("slow"), (got.get("next") or {}).get("n")
    finally:
        _end_link263(panel, ours, theirs, rf)


def _panel_parallel263():
    """Two requests in flight, answered in the other order: (both sent before any answer, A's, B's)."""
    ours, theirs = _socket263.socketpair()
    theirs.settimeout(3)
    rf, got = theirs.makefile("rb"), {}
    panel = _ss263.Panel(ours)
    try:
        ta = _th263.Thread(target=lambda: got.__setitem__("a", panel.ask({"op": "a"}, timeout=5)))
        tb = _th263.Thread(target=lambda: got.__setitem__("b", panel.ask({"op": "b"}, timeout=5)))
        ta.start()
        tb.start()
        reqs = {r.get("op"): r.get("id") for r in (_line263(rf), _line263(rf))}
        _answer263(theirs, reqs.get("b"), w="b")
        _join263(tb, 5)
        _answer263(theirs, reqs.get("a"), w="a")
        _join263(ta, 5)
        return sorted(map(str, reqs)) == ["a", "b"], (got.get("a") or {}).get("w"), (got.get("b") or {}).get("w")
    finally:
        _end_link263(panel, ours, theirs, rf)


_NONBLOCK_PROG263 = r"""
import fcntl, json, os, socket, sys, threading, time
sys.path.insert(0, os.getcwd())
from panel.services import sftp_server as ss
ss._die = lambda why: None
ours, theirs = socket.socketpair()
fcntl.fcntl(ours.fileno(), fcntl.F_SETFL, fcntl.fcntl(ours.fileno(), fcntl.F_GETFL) | os.O_NONBLOCK)
child = socket.socket(fileno=os.dup(ours.fileno()))     # as the service gets it: an inherited descriptor
ours.close()
panel = ss.Panel(child)

def answer():
    rf = theirs.makefile("rb")
    req = json.loads(rf.readline())
    time.sleep(0.3)                                     # a quiet moment before the answer
    theirs.sendall(json.dumps({"id": req["id"], "ok": True, "n": 7}).encode() + b"\n")
threading.Thread(target=answer, daemon=True).start()
print(json.dumps(panel.ask({"op": "x"}, timeout=5)))
"""


def _panel_nonblocking263():
    """The service's Panel over an inherited O_NONBLOCK descriptor, in a plain interpreter -> its answer."""
    from unit import REPO_ROOT as _root263
    r = _sp263.run([_sys263.executable, "-I", "-c", _NONBLOCK_PROG263], capture_output=True, text=True,  # nosec B603
                   timeout=60, check=False, cwd=_root263, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"})
    try:
        return _json263.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"failed": (r.stdout + r.stderr)[-300:]}


def _panel_link263():
    _p9_patch(_ss263, "_die", lambda why: None)
    try:
        eq("sftp service: a panel answer that came after its request gave up leaves the link working: the next "
           "request is answered (a timed-out reader used to refuse every later request, the service still 'running')",
           _panel_late263(), ({}, 2))
        eq("sftp service: several requests are in flight at once, each answer reaching its own request by id",
           _panel_parallel263(), (True, "a", "b"))
        eq("sftp service: an inherited non-blocking descriptor (the panel makes the pair under eventlet) still waits "
           "for the panel's answer: a quiet moment is not the panel going away", _panel_nonblocking263(),
           {"ok": True, "n": 7, "id": 1})
    finally:
        _p9_restore_all()


def _broker_parallel263():
    """The panel side: a slow request sent first, a fast one second -> (first answer's id and word, second's id)."""
    ours, theirs = _socket263.socketpair()
    theirs.settimeout(3)
    release = _th263.Event()

    def slow(_app, _req, _spawn):
        release.wait(6)
        return {"ok": True, "w": "slow"}
    _p9_patch(_br263, "_HANDLERS", dict(_br263._HANDLERS, slow263=slow,
                                        fast263=lambda _a, _r, _s: {"ok": True, "w": "fast"}))
    runner = _th263.Thread(target=_br263.serve, args=(_p9, ours, {}), daemon=True)
    runner.start()
    rf = theirs.makefile("rb")
    try:
        _answer263(theirs, 1, op="slow263")
        _answer263(theirs, 2, op="fast263")
        first = _line263(rf)
        release.set()
        second = _line263(rf)
        return first.get("id"), first.get("w"), second.get("id")
    finally:
        release.set()
        rf.close()
        theirs.close()
        _join263(runner, 5)
        ours.close()
        _p9_restore_all()


class _Backend263:
    """A host connection: records each call; once closed, every call fails as a dead one does."""

    dead = None

    def __init__(self):
        """A live connection, nothing called yet."""
        self.calls, self.closed = [], False

    def _live(self, *call):
        if self.closed:
            raise _bk263.BackendError(4, "the connection to the host is closed")
        self.calls.append(call)

    def send_write(self, handle, offset, data):
        """Queue a write."""
        self._live("write", offset, len(data))
        return object()

    def wait(self, _slot):
        """Settle a write."""
        self._live("wait")

    def close_handle(self, handle):
        """Close a handle."""
        self._live("close_handle", handle)

    def remove(self, path):
        """Remove a file."""
        self._live("remove", path)

    def replace(self, src, dst):
        """Rename over."""
        self._live("replace", src, dst)

    def setstat(self, path, attrs):
        """Set attributes by path."""
        self._live("setstat", path)

    def fsetstat(self, handle, attrs):
        """Set attributes on a handle."""
        self._live("fsetstat", handle, dict(attrs))

    def close(self):
        """Close the connection."""
        self.calls.append(("backend-close",))
        self.closed = True


class _Vfs263:
    """The session's file system as WriteHandle sees it: the audit rows, the open count, the cap."""

    def __init__(self, backend):
        """A session over `backend`."""
        self.backend, self.open_count, self.audits = backend, 0, []
        self.service = _NS263(files=_NS263(cap=1 << 30))

    def session_ended(self):
        """Close the session's host connections (VirtualSftp.session_ended)."""
        self.backend.close()

    def audit(self, target, action, detail, success=True):
        """One audit row."""
        self.audits.append((action, detail, bool(success)))


_TARGET263 = _NS263(sid=263, user="p263", selfname="p260server", key=(263,))


def _write_handle263(rel, staged=True):
    backend = _Backend263()
    vfs = _Vfs263(backend)
    info = {"rel": rel, "real": "/home/p263/" + rel, "existed": True, "old": {"mode": 0o100644, "size": 5},
            "limit": 1 << 30, "readable": False, "mode": {}}
    if staged:
        info["staged_to"] = "/home/p263/.%s.panel-sftp-0a0b0c" % rel
    wh = _sf263.WriteHandle(vfs, "/P263/" + rel, _TARGET263, backend, "H263", info)
    wh._checked = _time263.monotonic() + 3600        # the panel's answer is fresh for this check
    return wh, vfs, backend


def _cut_off263():
    """An upload left open when the session ends: (backend calls, audit rows)."""
    wh, vfs, backend = _write_handle263("maps/big.bsp")
    wh.write(0, b"x" * 64)
    srv = object.__new__(_ss263.PanelSftpServer)
    srv.server = vfs
    srv.file_table, srv.folder_table = {b"1": wh}, {}
    srv._SubsystemHandler__channel = _NS263(close=lambda: None)
    srv.finish_subsystem()
    return backend.calls, vfs.audits


def _sftp_close263():
    calls, audits = _cut_off263()
    names = [c[0] for c in calls]
    check("sftp service: an upload cut off by a disconnect has its hidden staged copy removed, before the session "
          "closes its host connections (paramiko closed them first, and the copy stayed in the game folder)",
          ("remove", "/home/p263/.maps/big.bsp.panel-sftp-0a0b0c") in calls and "backend-close" in names
          and names.index("remove") < names.index("backend-close"), repr(calls))
    check("sftp service: ...never renamed over the file (a partial upload must not replace it), and audited as "
          "refused because the connection ended", "replace" not in names
          and audits == [("upload_file", "refused: maps/big.bsp (64 bytes): %s" % _sf263.CUT_OFF, False)],
          repr(audits))


def _chattr263(rel, staged):
    wh, vfs, backend = _write_handle263(rel, staged=staged)
    a = _Attr263()
    a.st_mode = 0o100600
    a._flags = a.FLAG_PERMISSIONS
    return wh.chattr(a), [c for c in backend.calls if c[0] == "fsetstat"], vfs.audits


def _sftp_fsetstat263():
    reply, sets, audits = _chattr263("p260server", staged=False)
    check("sftp FSETSTAT: permissions on an open protected file (the LinuxGSM script) are refused and audited, "
          "as the path form refuses them (an open handle went round the rule)",
          reply == (_SFTP_DENIED263, _sf263.MODE_PROTECTED) and sets == []
          and audits == [("edit_file", "refused: p260server: %s" % _sf263.MODE_PROTECTED, False)],
          repr((reply, sets, audits)))
    reply, sets, audits = _chattr263("server.cfg", staged=False)
    eq("sftp FSETSTAT: ...an ordinary file's permissions change, with the audit row the path form writes",
       (reply, [s[2] for s in sets], audits),
       (_SFTP_OK263, [{"mode": 0o600}], [("edit_file", "server.cfg (permissions 0600)", True)]))
    reply, sets, audits = _chattr263("server.cfg", staged=True)
    eq("sftp FSETSTAT: ...and on a whole-file upload over an existing file, whose close gives the old mode back, "
       "no permission change is claimed", (reply, sets, audits), (_SFTP_OK263, [], []))


def _key_user263():
    """A user with one registered key: (uid, fingerprint, base64 of the key)."""
    k = _sc263.host_key_from_text(_sc263.new_host_key_text())
    pk = _sc263.parse_public_key("%s %s p263" % (k.get_name(), k.get_base64()))[0]
    with _p9.app_context():
        u = _User263(username="p260_sftp", password_hash=_NO_LOGIN263, is_active=True)
        _db263.session.add(u)
        _db263.session.flush()
        _db263.session.add(_Key263(user_id=u.id, label="k", key_type=pk.key_type, key_blob=pk.blob_b64,
                                   fingerprint=pk.fingerprint))
        _db263.session.commit()
        return u.id, pk.fingerprint, k.get_name(), _b64_263.b64encode(k.asbytes()).decode("ascii")


def _last_used263(uid):
    with _p9.app_context():
        row = _Key263.query.filter_by(user_id=uid).first()
        return None if row is None else row.last_used


def _sftp_keys263():
    uid, fp, ktype, blob = _key_user263()
    _ag263.reset_throttle()
    for _ in range(_ag263.ACCOUNT_SOFT_FAILS):
        _ag263.account_reserve("p260_sftp", _time263.time())
    got = _br263.handle(_p9, {"op": "auth_key", "ip": "192.0.2.60", "username": "p260_sftp", "type": ktype,
                              "blob": blob}, {})
    _ag263.reset_throttle()
    eq("sftp keys: a name paused after repeated wrong passwords still signs in with its key (the pause is for "
       "guesses; wrong passwords sent by anyone kept a key holder out)", (got.get("ok"), got.get("fp")), (True, fp))
    eq("sftp keys: ...and the key's 'last used' is not stamped yet: paramiko asks this before checking the "
       "signature, so a bare public key reached it", _last_used263(uid), None)
    with _p9.app_context():
        epoch = _db263.session.get(_User263, uid).auth_epoch or 0
    _br263.handle(_p9, {"op": "auth_done", "ip": "192.0.2.60", "uid": uid, "method": "publickey",
                        "detail": "k", "fp": fp}, {})
    check("sftp keys: ...it is stamped when the session really starts", _last_used263(uid) is not None)
    session = {"op": "servers", "uid": uid, "epoch": epoch, "fp": fp}
    before = _br263.handle(_p9, dict(session), {})
    with _p9.app_context():
        _Key263.query.filter_by(user_id=uid).delete()
        _db263.session.commit()
    after = _br263.handle(_p9, dict(session), {})
    eq("sftp keys: removing a key ends the sessions signed in with it at their next request",
       (before.get("ok"), after.get("ok"), "key it signed in with was removed" in (after.get("reason") or "")),
       (True, False, True))
    pw = _br263.handle(_p9, {"op": "servers", "uid": uid, "epoch": epoch, "fp": ""}, {})
    eq("sftp keys: ...a password session (no key) is not affected by keys", pw.get("ok"), True)
    with _p9.app_context():
        _db263.session.delete(_db263.session.get(_User263, uid))
        _db263.session.commit()


def _sftp263():
    _panel_link263()
    eq("sftp broker: each request is answered in its own thread: a slow permission check sent first does not "
       "hold the next request's answer", _broker_parallel263(), (2, "fast", 1))
    _sftp_close263()
    _sftp_fsetstat263()
    _sftp_keys263()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Add-ons
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _status_out263(database):
    meta = _b64_263.b64encode(_json263.dumps({"database": database, "port": 0}).encode()).decode()
    return "os=ubuntu 24.04\npodman=5.0\nmeta.b3=%s\nstate.b3=active\n" % meta


def _addon_remove263(sid):
    shells = []
    _p9_arm(who="part263")
    _p9_patch(_ra263, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: shells.append(a[2]) or ("removed=1\nothers=1\n", "", 0))
    try:
        with _ra263._JOBS_LOCK:
            _ra263._JOBS[(sid, "b3")] = {"running": True, "why": "", "tail": "", "kind": "update"}
        r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/remove" % sid)
        busy = (r.status_code, r.get_json(silent=True) or {}, list(shells))
        with _ra263._JOBS_LOCK:
            _ra263._JOBS.pop((sid, "b3"), None)
        r2 = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/remove" % sid)
    finally:
        with _ra263._JOBS_LOCK:
            _ra263._JOBS.pop((sid, "b3"), None)
        _p9_restore_all()
    eq("add-ons: Remove is refused while an update (or install, or settings change) of the add-on runs, and "
       "nothing runs on the host (the job wrote its unit again after the remove)",
       (busy[0], busy[1].get("message"), busy[2]), (409, _ra263._BUSY_REMOVE, []))
    eq("add-ons: ...with no job running it removes as before (control)", (r2.status_code, len(shells)), (200, 1))


def _addon_card263():
    src = open(os.path.join(os.path.dirname(_ra263.__file__), "..", "static", "js", "server_addons.js"),
               encoding="utf-8").read()
    prog = ("var made = [];\n"
            "function node(t, c, x){ return {appendChild: function(){}}; }\n"
            "function button(label, icon, act){ made.push(act); return {}; }\n"
            "function T(s){ return s; } function TF(s){ return s; } function geoStatus(){} function settingsFold(){}\n"
            "var BM = {status: function(){}, updateWords: function(){ return ''; }};\n"
            "var WEB = {open: function(){}};\n"
            + _cut47(src, "function installedRow(") + "\n"
            "function acts(a){ made = []; installedRow(a, node()); return made; }\n"
            "console.log(JSON.stringify({install: acts({id: 'b3', state: 'active', installing: true, job: 'install'}),"
            " update: acts({id: 'b3', update: 'image', installing: true, job: 'update'}),"
            " start: acts({id: 'b3', state: 'inactive', installing: true, job: 'start'}),"
            " idle: acts({id: 'b3', state: 'active'})}));\n")
    got = _node221("add-ons card: no buttons while a job runs", prog)
    if got is not None:
        eq("add-ons card: while an install, update or settings change runs the row offers no button; a start being "
           "watched can be stopped (a Remove then is refused); an idle row offers Stop, Log and Remove",
           got, {"install": [], "update": [], "start": ["adAct", "adLog", "adRemove"],
                 "idle": ["adAct", "adLog", "adRemove"]})


def _addon_change263(sid):
    shells = []
    probe = {"meta": {"database": "", "port": 0}, "ports": [], "udp": [], "ids": (1000, 1000), "logdir": "log",
             "log_found": False, "log_name": "games_mp.log", "splice": False, "rcon_lines": ""}
    _p9_arm(who="part263")
    _p9_patch(_ch263, "_read", lambda gs, addon_id: (dict(probe), "", ""))
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: shells.append(a[2]) or ("", "", 0))
    try:
        with _p9.app_context():
            from panel.db.models import GameServer as _GS263
            gs = _db263.session.get(_GS263, sid)
            no_log = _ch263._change_steps(gs, "b3", "p263", "update")
            probe.update(log_found=True, ids=None)
            no_ids = _ch263._change_steps(gs, "b3", "p263", "update")
    finally:
        _p9_restore_all()
    eq("add-ons: an update or Apply runs the install's checks first: no game log, or no account ids, is refused "
       "with the install's sentence and no unit is written (Volume=:/gamelog, a unit with no User=)",
       (no_log[0] == _ra263._AGAIN[_ra263._NO_LOG], no_ids[0], shells), (True, _ra263._NO_IDS, []))


def _addon_census263(sid):
    try:
        with _ra263._JOBS_LOCK:
            _ra263._JOBS[(sid, "b3")] = {"running": True, "kind": "install"}
        during = _hr263._r36j_route_jobs(sid)
        with _ra263._JOBS_LOCK:
            _ra263._JOBS[(sid, "b3")] = {"running": True, "kind": "start"}
        watching = _hr263._r36j_route_jobs(sid)
    finally:
        with _ra263._JOBS_LOCK:
            _ra263._JOBS.pop((sid, "b3"), None)
    said = _i18n263.tr(_rw263.blocked_sentence([_rw263.blocker("addon", "p263-cod4")]))
    eq("reboot census: a running add-on install, update or settings change holds a reboot (it cut a build off "
       "part way); a 30-second start watch does not",
       ("addon" in during, "addon" in watching, "an add-on install, update, settings change or removal on p263-cod4" in said),
       (True, False, True))


def _addons263(sid):
    _addon_remove263(sid)
    _addon_card263()
    _addon_change263(sid)
    _addon_census263(sid)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Databases
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _db_row263(sid, name):
    with _p9.app_context():
        r = _GD263(remote_id=P9_HOST, game_server_id=sid, name=name, secret=_enc263("p263-db-" + "value"))
        _db263.session.add(r)
        _db263.session.commit()
        return r.id


def _db_cancel263(sid, rid):
    uid, ran = "a" * 32, []
    _p9_arm(who="part263")
    _p9_patch(_dbf263, "_upcmd", lambda gs, script, timeout, stdin=None: ran.append(script) or ("ok", ""))
    try:
        with _dbf263._UPLOADS_LOCK:
            _dbf263._UPLOADS[uid] = {"uid": uid, "db": rid, "user": P9_ADMIN, "size": 10, "ts": _time263.time(),
                                     "busy": 1, "finishing": 1}
        r = _p9_client(P9_ADMIN).post("/api/server/%d/databases/%d/upload/%s/cancel" % (sid, rid, uid), json={})
        held = (r.status_code, uid in _dbf263._UPLOADS, list(ran))
        ran[:] = []
        with _dbf263._UPLOADS_LOCK:
            _dbf263._UPLOADS[uid] = {"uid": uid, "db": rid, "user": P9_ADMIN, "size": 10, "ts": _time263.time(),
                                     "busy": 0, "finishing": 0}
        r2 = _p9_client(P9_ADMIN).post("/api/server/%d/databases/%d/upload/%s/cancel" % (sid, rid, uid), json={})
    finally:
        with _dbf263._UPLOADS_LOCK:
            _dbf263._UPLOADS.pop(uid, None)
        _p9_restore_all()
    eq("databases: a cancel while a finish still checks the dump is refused and the upload stays listed (a second "
       "upload to the database was accepted and moved the first over the kept earlier dump)", held, (409, True, []))
    eq("databases: ...an idle upload is cancelled as before (control)", (r2.status_code, len(ran)), (200, 1))


def _db_stubs263(name):
    """Stub the host for the Databases tab's reset and delete; -> the list the database-server calls land in."""
    calls = []

    def note(what):
        return lambda *a, **k: calls.append(what) or (True, "")
    _p9_arm(who="part263")
    _p9_patch(_ra263, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: (_status_out263(name), "", 0))
    _p9_patch(_net263, "admin_target", lambda *a, **k: (object(), _NS263(flavor="mariadb", native_ok=True)))
    from panel.routes import databases as _dbr263
    _p9_patch(_dbr263._dbs, "set_password", note("set_password"))
    _p9_patch(_dbr263, "drop_row", note("drop"))
    return calls


def _db_addon263(sid, rid, name):
    calls = _db_stubs263(name)
    try:
        c = _p9_client(P9_ADMIN)
        reset = c.post("/api/server/%d/databases/%d/reset-password" % (sid, rid), json={})
        delete = c.post("/api/server/%d/databases/%d/delete" % (sid, rid), json={"confirm": name})
        held = list(calls)
        _p9_patch_sm("shell_as_game_user", lambda *a, **k: (_status_out263("gs1_other"), "", 0))
        reset2 = c.post("/api/server/%d/databases/%d/reset-password" % (sid, rid), json={})
    finally:
        _p9_restore_all()
    said = [(x.get_json(silent=True) or {}).get("message", "") for x in (reset, delete)]
    named = [s.startswith(_ad263.CATALOG[_ad263.B3]["name"] + " uses this database") for s in said]
    check("databases: a password reset and a delete are refused while an installed add-on (B3) uses the database, "
          "naming it; nothing is changed on the database server",
          (reset.status_code, delete.status_code) == (409, 409)
          and named == [True, True]
          and "reset the password" in said[0] and "delete the database" in said[1] and not held,
          repr((reset.status_code, delete.status_code, said, held)))
    eq("databases: ...a database no add-on uses is reset as before (control)", (reset2.status_code, calls),
       (200, ["set_password"]))


def _db_import263():
    tail = _pv263.remote_command("db-import", ["mysql", "3306@100.64.1.2", "gs1_x", "gs1_x"])
    local = _pv263.remote_command("db-import", ["mysql", "3306", "gs1_x", "gs1_x"])
    want = list(_pv263.DB_NET_CONNECT + _pv263.DB_NET_TLS_OFF + _pv263.DB_NET_KEY)
    helper = _h263.db_conn_net("tcp3306@100.64.1.2")[3:]
    eq("databases remote: db-import to a tailnet server gives the client the connect timeout and the server's RSA "
       "key option as well as TLS off (ERROR 2061 on MySQL 8 otherwise), as the helper's own db-import does; "
       "none for 127.0.0.1",
       ([o in _shlex263.split(tail) for o in want], sorted(helper) == sorted(want),
        [o for o in want if o in _shlex263.split(local)]), ([True] * len(want), True, []))


def _databases263(sid):
    name = "gs%d_b3" % sid
    rid = _db_row263(sid, name)
    try:
        _db_cancel263(sid, rid)
        _db_addon263(sid, rid, name)
    finally:
        with _p9.app_context():
            row = _db263.session.get(_GD263, rid)
            if row is not None:
                _db263.session.delete(row)
                _db263.session.commit()
    _db_import263()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Step-up on backup changes
# ════════════════════════════════════════════════════════════════════════════════════════════════
_STEP_UP_POSTS263 = ("/api/panel/backup/game/{s}/restore", "/api/panel/backup/game/{s}/upload",
                     "/api/panel/backup/delete", "/api/panel/backup/settings")


def _step_up263(sid):
    was = _p9.config.get("STEP_UP_MINUTES")
    _p9.config["STEP_UP_MINUTES"] = 10
    _p9_arm(who="part263")
    try:
        c = _stale221()
        wrong = [(u, r.status_code) for u in _STEP_UP_POSTS263 for r in [c.post(u.format(s=sid), json={})]
                 if not (r.status_code == 403 and r.headers.get("X-Reauth-Required") == "1")]
        fresh = _p9_client(P9_ADMIN).post("/api/panel/backup/delete", json={"name": "p263-none.tar.gz"})
    finally:
        _p9_restore_all()
        if was is None:
            _p9.config.pop("STEP_UP_MINUTES", None)
        else:
            _p9.config["STEP_UP_MINUTES"] = was
    eq("step-up: a game restore, a game backup upload's start, a panel backup's delete and the backup settings "
       "ask for the password again past the window (their database twins did, these did not)", wrong, [])
    eq("step-up: ...a fresh sign-in is not asked (control)", fresh.headers.get("X-Reauth-Required"), None)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Hosts: the tailnet exemption, the subordinate ids
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _tailnet263():
    asked = []

    def run_command(server, cmd, **_k):
        asked.append(cmd)
        return '{"BackendState": "Stopped"}', "", 0
    _p9_arm(who="part263")
    _p9_patch_sm("run_command", run_command)
    try:
        v6 = _hosts263.tailnet_exempt_ips(_NS263(name="p263"), {"fd7a:115c:a1e0::5", "2001:db8::5"})
        v6_asked = list(asked)
        mixed = _hosts263.tailnet_exempt_ips(_NS263(name="p263"), {"fd7a:115c:a1e0::5", "100.100.1.1"})
        with _p9.app_context(), _p9.test_request_context("/"):
            local = _hl263._r13c_block_refusal("fd7a:115c:a1e0::5")
            remote = _rs263._fwb_single_refusal(_NS263(name="p263", id=P9_LOCAL), "fd7a:115c:a1e0::5")
            local_said = (local.get_json() or {}).get("message", "") if local is not None else ""
    finally:
        _p9_restore_all()
    eq("tailnet exemption: Tailscale's IPv6 range is exempt without asking the host (nothing else uses it); "
       "another IPv6 address is not", (v6, v6_asked), ({"fd7a:115c:a1e0::5"}, []))
    eq("tailnet exemption: ...the IPv4 range still only while Tailscale runs (stopped here)", mixed,
       {"fd7a:115c:a1e0::5"})
    check("tailnet exemption: the panel host's Block and the remote Block both refuse a Tailscale IPv6 address "
          "(the panel host's card and the auto-block allowed it)",
          "Tailscale address" in local_said and "Tailscale address" in (remote or ""), repr((local_said, remote)))


def _hold263(folder, seconds):
    """Another process holding `folder`'s lock for `seconds`, returned once it holds it.

    A process, not a thread: under the suite's eventlet a thread is a greenlet, and a blocking flock
    in one stops every greenlet, the one that would release it too.
    """
    holder = _sp263.Popen(["flock", folder, "sleep", str(seconds)])  # nosec B603 B607 - util-linux flock
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        deadline = _time263.monotonic() + 5
        while _time263.monotonic() < deadline:
            try:
                _fcntl263.flock(fd, _fcntl263.LOCK_EX | _fcntl263.LOCK_NB)
            except BlockingIOError:
                break                   # the holder has it
            _fcntl263.flock(fd, _fcntl263.LOCK_UN)
            _time263.sleep(0.02)
    finally:
        os.close(fd)
    return holder


def _helper_subids263(subuid, subgid, on_add=None, hold=False):
    """do_addon_account_prepare over stand-in files -> (rc, argv lists run, seconds it took)."""
    folder = _tf263.mkdtemp(prefix="sub-", dir=_TMP263)
    files = []
    for name, text in (("subuid", subuid), ("subgid", subgid)):
        files.append(os.path.join(folder, name))
        with open(files[-1], "w", encoding="utf-8") as fh:
            fh.write(text)
    ran = []

    def run(argv, **_k):
        ran.append(argv)
        if on_add and argv[0] == "usermod" and argv[1].startswith("--add-"):
            on_add(files)
        return _NS263(returncode=0, stderr=b"")
    saved = {k: getattr(_h263, k) for k in ("SUBID_FILES", "_groups_of", "pwd", "subprocess", "resolve")}
    holder = _hold263(folder, 0.8) if hold else None
    try:
        _h263.SUBID_FILES = tuple(files)
        _h263._groups_of = lambda u: {_h263.GAME_GROUP}
        _h263.pwd = _NS263(getpwnam=lambda n: _NS263(pw_name=n, pw_uid=4263))
        _h263.subprocess = _NS263(run=run)
        _h263.resolve = lambda prog: prog
        t0 = _time263.monotonic()
        rc = _h263.do_addon_account_prepare(["p260acct"], None)
        took = _time263.monotonic() - t0
    finally:
        for k, v in saved.items():
            setattr(_h263, k, v)
        if holder is not None:
            holder.wait(10)
    return rc, ran, took


def _clash263(files):
    with open(files[1], "a", encoding="utf-8") as fh:
        fh.write("zed:231072:10\n")


def _remote_subids263(hold):
    """The remote form under bash with stand-in tools -> (rc, stdout, stderr, finished while the lock was held)."""
    folder = _tf263.mkdtemp(prefix="rsub-", dir=_TMP263)
    bindir = os.path.join(folder, "bin")
    os.makedirs(bindir)
    with open(os.path.join(folder, "subuid"), "w", encoding="utf-8") as fh:
        fh.write("alice:100000:65536\nnobody:165536:65536\n")
    with open(os.path.join(folder, "subgid"), "w", encoding="utf-8") as fh:
        fh.write("alice:100000:65536\n")
    clash = "" if hold else 'case "$1" in --add-*) echo "zed:231072:10" >> %s;; esac\n' % _shlex263.quote(
        os.path.join(folder, "subgid"))
    for tool, body in (("usermod", 'echo "usermod $*"\n' + clash), ("loginctl", 'echo "loginctl $*"\n')):
        path = os.path.join(bindir, tool)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\n" + body)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(path, 0o700)  # nosec B103 - a stand-in tool in the part's own temp dir
    cmd = _pv263.remote_command("addon-account-prepare", ["nobody"])
    cmd = cmd.replace("exec 9</etc ", "exec 9<%s " % _shlex263.quote(folder)).replace(
        "/etc/subuid", os.path.join(folder, "subuid")).replace("/etc/subgid", os.path.join(folder, "subgid"))
    lock = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if hold:
            _fcntl263.flock(lock, _fcntl263.LOCK_EX)
        p = _sp263.Popen(["bash", "-c", cmd], stdout=_sp263.PIPE, stderr=_sp263.PIPE, text=True,  # nosec B603 B607
                         env={"PATH": bindir + ":/usr/bin:/bin"})
        early = None
        if hold:
            _time263.sleep(0.4)
            early = p.poll() is not None
            _fcntl263.flock(lock, _fcntl263.LOCK_UN)
        out, err = p.communicate(timeout=30)
    finally:
        os.close(lock)
    return p.returncode, out, err, early


def _subids263():
    rc, ran, took = _helper_subids263("alice:100000:65536\n", "alice:100000:65536\n", hold=True)
    eq("add-on account (helper): the subordinate ids are picked and added under a lock: it waits while another "
       "run holds it (two installs at once could both pick the same range), then the range is added",
       (took >= 0.4, rc, ran[:1]),
       (True, 0, [["usermod", "--add-subuids", "165536-231071", "--add-subgids", "165536-231071", "p260acct"]]))
    rc, ran, _h = _helper_subids263("alice:100000:65536\nnobody:165536:65536\n", "alice:100000:65536\n",
                                    on_add=_clash263)
    eq("add-on account (helper): a new range another account's overlaps (an add made outside the panel meanwhile) "
       "is taken back and refused", (rc, ran),
       (1, [["usermod", "--add-subuids", "231072-296607", "--add-subgids", "231072-296607", "p260acct"],
            ["usermod", "--del-subuids", "231072-296607", "--del-subgids", "231072-296607", "p260acct"]]))
    rc, out, _err, early = _remote_subids263(hold=True)
    eq("add-on account (remote form): it waits for the lock, then adds the range",
       (early, rc, out.splitlines()[:2]), (False, 0, ["usermod --add-subgids 231072-296607 nobody", "subids=added"]))
    rc, out, err, _e = _remote_subids263(hold=False)
    eq("add-on account (remote form): ...and takes back a range that overlaps another account's",
       (rc, out.splitlines(), "overlaps another account" in err),
       (1, ["usermod --add-subgids 231072-296607 nobody", "usermod --del-subgids 231072-296607 nobody"], True))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. GMod content cron, duplicate JSON keys, the install's last pass, the update abort trap
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _gmod_cron263(crontab):
    """ensure_content_update_cron with `crontab` and two installed games -> (result, the cron body written or None)."""
    written = {}
    _p9_patch(_core263, "run_privileged", lambda server, verb, args=(), **k: (crontab, "", 0)
              if verb == "crontab-list" else ("", "", 0))
    _p9_patch(_core263, "write_content_cron", lambda s, u, body, **k: written.__setitem__("body", body) or ("", "", 0))
    _p9_patch(_gmod263, "_installed_content_lgsm_names", lambda s, u: ["cssserver", "tf2server"])
    try:
        return _gmod263.ensure_content_update_cron(object(), "gmodcontent"), written.get("body")
    finally:
        _p9_restore_all()


def _gmod260_checks():
    ok, body = _gmod_cron263("30 2 * * 0 /home/gmodcontent/cssserver update > /dev/null 2>&1\n")
    check("gmod content cron: a game the account already updates in its own crontab is left to that job; the other "
          "installed game still gets its weekly update (one `update` line used to stop the whole cron)",
          ok is True and body is not None and "tf2server update" in body and "cssserver" not in body, repr(body))
    ok, body = _gmod_cron263("0 4 * * * apt update\n10 3 * * 0 /home/gmodcontent/tf2server update-lgsm\n")
    check("gmod content cron: ...an `apt update` line or another script's update-lgsm is not a content update",
          ok is True and body is not None and "cssserver update" in body and "tf2server update >" in body, repr(body))


def _gcf_dup263():
    dup = _gcf263.build("serverfiles/server-settings.json", '{"max_players": 8, "name": "x", "max_players": 10}\n')
    one = _gcf263.build("serverfiles/server-settings.json", '{"max_players": 8, "name": "x"}\n')
    eq("game config form: a JSON file holding one key twice gets the raw editor only (two fields of one name, the "
       "first edited and ignored by a last-wins reader, 'Saved' all the same); one key once has its form",
       (dup is None, one is not None), (True, True))


def _install_pass263():
    _p9_arm(who="part263")
    ok, fails, downloads, _w = _step4_256("p263-last", [("", 1, False), ("", 1, False), (_SUM_OUT256, 1, False),
                                                        ("Install Complete!\n", 0, True)])
    eq("install step 4: a checksum failure first seen on the third download still gets the one more download it "
       "was promised, and that download installs (the loop ended there and the install failed)",
       (ok, fails, downloads), (True, [], 4))
    _p9_restore_all()
    _install_prime263()


def _install_prime263():
    """Run step 4 where "Invalid platform" is first seen on the third download (the Windows-depot prime's pass)."""
    written, validated = [], []
    _p9_arm(who="part263")
    _p9_patch(_ms263, "lgsm_write_config", lambda r, u, n, kv: written.append(dict(kv)) or (True, ""))
    _p9_patch_sm("run_as_game_user", lambda r, u, cmd, **k: validated.append(cmd) or ("", "", 0))
    try:
        # Two quiet failures, then SteamCMD's refusal; the prime's own download, then the pass it was promised.
        ok, fails, downloads, _w = _step4_256("p263-prime", [
            ("", 1, False), ("", 1, False), ("Error! App '222860' state is 0x202 after update job.\n"
                                             "Invalid platform\n", 1, False),
            ("windows depot pulled\n", 0, False), ("Install Complete!\n", 0, True)])
    finally:
        _p9_restore_all()
    eq("install step 4: \"Invalid platform\" first seen on the third download is primed with the Windows depot "
       "(set, then unset, then validate) and still gets the download it was promised, which installs (the loop "
       "ended after the prime and the install failed)",
       (ok, fails, downloads, written, validated),
       (True, [], 5, [{"steamcmdforcewindows": "yes"}, {"steamcmdforcewindows": "no"}], ["validate"]))


def _abort_trap263():
    folder = _tf263.mkdtemp(prefix="abort-", dir=_TMP263)
    pd, bk = os.path.join(folder, "linuxgsm-panel"), os.path.join(folder, "snapshot")
    os.makedirs(pd)
    os.makedirs(bk)
    with open(os.path.join(pd, "old.txt"), "w", encoding="utf-8") as fh:
        fh.write("previous version " * 200)
    _sp263.run(["tar", "-C", pd, "-czf", os.path.join(bk, "code.tgz"), "."], check=True)  # nosec B603 B607
    with open(os.path.join(bk, "code.tgz"), "r+b") as fh:
        fh.truncate(os.path.getsize(os.path.join(bk, "code.tgz")) // 2)
    rc, out = _iw_run(_iw_fetch + "\nfalse   # an abort after the tree was replaced", pd, bk)
    check("install.sh: when the abort trap cannot unpack the snapshot it says the panel folder is INCOMPLETE and "
          "where to restore from, and never that the panel was restarted on the old version",
          rc != 0 and "INCOMPLETE" in out and os.path.join(bk, "code.tgz") in out and "restarted on" not in out
          and "SVC start linuxgsm-panel.service" not in out and "INSTALL_DEPS" not in out, out[-600:])


def _main263():
    sid = _p9_new_server(P9_HOST, "cod4p263", "cod4", 28960, name="p263-cod4")
    try:
        _sftp263()
        _addons263(sid)
        _databases263(sid)
        _step_up263(sid)
    finally:
        _p9_delete_server(sid)
        _p9_restore_all()
    _tailnet263()
    _subids263()
    _gmod260_checks()
    _gcf_dup263()
    _install_pass263()
    _abort_trap263()
    check("part263: no check reached a real transport", len(_P9_TRIPPED) == _trips263,
          repr(_P9_TRIPPED[_trips263:][:4]))


try:
    _main263()
finally:
    import shutil as _shutil263
    _shutil263.rmtree(_TMP263, ignore_errors=True)
