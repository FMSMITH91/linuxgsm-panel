"""Part 286 of the unit suite: Socket.IO flooding and four request races.

1. The event budget (socket_hooks.install_event_budget; OWASP WebSocket Security Cheat Sheet,
   "Denial-of-Service Protection"): every Socket.IO packet spends from its account's budget (shared by
   that account's sockets) before it is decoded; past it a packet is dropped, and a connection that
   keeps on is closed through THE disconnect handler. Terminal typing has its own, larger budget.
   Ordinary use stays inside it.
2. A packet python-socketio cannot take (a client-sent CONNECT_ERROR, a broken body) closes its
   connection with one short warning and no traceback, at most one a minute (OWASP Logging Cheat
   Sheet, "Attacks on Logs"); an error raised by a handler is still raised and logged. A connection
   closed that way leaves engine.io's table before it is closed, so a POST that follows is a 400.
3. Every socket event handler takes its argument as optional: an event sent with none is not a
   traceback.
4. One operation at a time per database: a restore, a dump, an uploaded dump's restore and a delete
   each hold the database, and a second request meanwhile is refused (409) and audited.
5. The invite's second code: the try is counted before the code is checked, so a burst cannot have
   more codes checked than tries are left; a right code gives its try back.
6. SFTP key add: the cap and the duplicate check are asked again with the insert, after the password
   (which yields), so parallel adds cannot pass the cap and a duplicate is a clean, audited refusal.

The sockets run through flask-socketio's test client on part12's app (its real handlers, its real
SocketIO and so the budget it installed), the routes through part12's app with its tripwire armed;
the clock the budget reads is a stand-in, so nothing here depends on how fast the machine is.
"""
import ast as _ast286
import logging as _lg286
import os as _os286

import time as _time286

import eventlet as _ev286

from unit import REPO_ROOT as _ROOT286
from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, P9_VIEWER, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json,
                         _p9_new_server, _p9_patch, _p9_restore_all)
from panel.core.config import encrypt_secret as _enc286
from panel.db.models import (AuditLog as _AL286, GameDatabase as _GD286, Invite as _Inv286, SftpKey as _Key286,
                             User as _U286, db as _db286)
from panel.ops import socket_hooks as _sh286
from panel.routes import databases as _dbr286, databases_files as _dbf286, sftp_settings as _sfs286
from panel.routes import server_files as _sf286
from panel.security import account_guard as _ag286, auth as _auth286

_SIO286 = _p9.socketio
_SRV286 = _SIO286.server


class _Clock286:
    """The budget's clock, moved by hand."""

    def __init__(self):
        self.t = 5.0e6

    def __call__(self):
        return self.t


class _Logs286(_lg286.Handler):
    """Every record socket_hooks logs."""

    def __init__(self):
        super().__init__(_lg286.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    def lines(self, word):
        return [r for r in self.records if word in r.getMessage()]


_CLK286 = _Clock286()
_LOGS286 = _Logs286()
_saved_clock286 = _sh286._clock
_saved_logstate286 = dict(_sh286._log_state)
_sh286._clock = _CLK286
_sh286._log_state.clear()
_sh286._log.addHandler(_LOGS286)


def _sio286(uid):
    return _SIO286.test_client(_p9, flask_test_client=_p9_client(uid))


def _settle286():
    """Let the background close run (it is spawned, never run inside the receive path)."""
    for _ in range(5):
        _ev286.sleep(0)


def _watching286(uid):
    with _sf286._viewers_lock:
        return uid in (_sf286._console_viewers.get(P9_GS) or {}).values()


def _raises286(fn):
    """The exception fn() raised, as text, or ''."""
    try:
        fn()
    except Exception as exc:
        return "%s: %s" % (type(exc).__name__, exc)
    return ""


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The event budget
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _s286_installed():
    handler = _SRV286.eio.handlers.get("message")
    check("socket budget: engine.io hands every message to the budget, and the server object (where the test "
          "client calls it) holds the same function",
          handler is _SRV286._handle_eio_message and "install_event_budget" in getattr(handler, "__qualname__", ""),
          repr((handler, _SRV286._handle_eio_message)))
    eq("socket budget: the packet's kind is read off its text (an ack id allowed; another event, a CONNECT or "
       "bytes are general)",
       [_sh286._event_kind(x) for x in ('2["term_input",{"data":"a"}]', '27["term_resize",{}]', '2["join_console",{}]',
                                        '0', '2["term_inputx"]', b'2["term_input"]', '2/x,["term_input"]')],
       ["terminal", "terminal", "general", "general", "general", "general", "general"])


def _s286_general_and_shared():
    _CLK286.t += 1000.0
    a = _sio286(P9_VIEWER)
    check("socket budget: the connect handler records the socket's account in its connection",
          (_SRV286.environ.get(a.eio_sid) or {}).get(_sh286.UID_KEY) == P9_VIEWER,
          repr((_SRV286.environ.get(a.eio_sid) or {}).get(_sh286.UID_KEY)))
    cap = _sh286.EVENT_BUDGET["general"][0]
    for _ in range(cap):
        a.emit("leave_console", {"server_id": P9_GS})
    a.emit("join_console", {"server_id": P9_GS})
    past = _watching286(P9_VIEWER)
    b = _sio286(P9_VIEWER)
    b.emit("join_console", {"server_id": P9_GS})
    other_socket = _watching286(P9_VIEWER)
    _CLK286.t += 0.5            # one event's worth at 2 a second
    b.emit("join_console", {"server_id": P9_GS})
    refilled = _watching286(P9_VIEWER)
    eq("socket budget: past %d events the account's next join is dropped, on that socket and on another socket of "
       "the same account, and half a second later one more is let through" % cap,
       (past, other_socket, refilled, a.is_connected(), b.is_connected()), (False, False, True, True, True))
    a.disconnect()
    b.disconnect()


def _s286_terminal_budget():
    _CLK286.t += 1000.0
    seen = []
    handlers = _SRV286.handlers["/"]
    real = handlers["term_resize"]
    handlers["term_resize"] = lambda sid, *a: seen.append(a)
    try:
        c = _sio286(P9_ADMIN)
        for _ in range(_sh286.EVENT_BUDGET["general"][0] + 5):
            c.emit("leave_console", {"server_id": P9_GS})
        cap = _sh286.EVENT_BUDGET["terminal"][0]
        for _ in range(cap + 1):
            c.emit("term_resize", {"cols": 80, "rows": 24})
        eq("socket budget: terminal events spend their own budget (%d at once), not the one the console events "
           "used up, and the one after it is dropped" % cap, len(seen), cap)
        c.disconnect()
    finally:
        handlers["term_resize"] = real


def _s286_disconnect():
    _CLK286.t += 1000.0
    del _LOGS286.records[:]
    c = _sio286(P9_ADMIN)
    c.emit("join_console", {"server_id": P9_GS})
    joined = _watching286(P9_ADMIN)
    for _ in range(_sh286.EVENT_BUDGET["general"][0] - 1):
        c.emit("leave_console", {"server_id": -1})
    for _ in range(_sh286.DROP_LIMIT[0] - 1):
        c.emit("leave_console", {"server_id": -1})
    _settle286()
    before = c.is_connected()
    c.emit("leave_console", {"server_id": -1})
    _settle286()
    eq("socket budget: a connection is closed at its %dth dropped packet, not before, through THE disconnect "
       "handler (its console viewer is gone)" % _sh286.DROP_LIMIT[0],
       (joined, before, c.is_connected(), _watching286(P9_ADMIN)), (True, True, False, False))
    drop, closed = _LOGS286.lines("dropping packets"), _LOGS286.lines("kept sending")
    check("socket budget: the drops are one warning line and the close another, with the account and no traceback",
          len(drop) == 1 and len(closed) == 1 and all(r.exc_info is None for r in _LOGS286.records)
          and "account %d" % P9_ADMIN in closed[0].getMessage(), repr([r.getMessage() for r in _LOGS286.records]))


def _s286_normal_use():
    """A page in ordinary use: a phone waking (40 consoles rejoined), then a paste and some typing."""
    _CLK286.t += 1000.0
    c = _sio286(P9_ADMIN)
    for _ in range(40):
        c.emit("leave_console", {"server_id": P9_GS})
        c.emit("join_console", {"server_id": P9_GS})
    woke = _watching286(P9_ADMIN)
    for i in range(150):
        c.emit("term_input", {"data": "x"})
        if i % 3 == 0:
            _CLK286.t += 0.05
    for _ in range(600):        # 20 keystrokes a second for 30 s
        _CLK286.t += 0.05
        c.emit("term_input", {"data": "k"})
    c.emit("leave_console", {"server_id": P9_GS})
    eq("socket budget: ordinary use stays inside it (a wake that rejoins 40 consoles, a 150-piece paste, 30 s of "
       "typing): nothing dropped, still connected", (woke, _watching286(P9_ADMIN), c.is_connected()),
       (True, False, True))
    c.disconnect()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Packets the library cannot take, and handler errors
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _s286_protocol_errors():
    _CLK286.t += 1000.0
    del _LOGS286.records[:]
    _sh286._log_state.clear()
    c = _sio286(P9_VIEWER)
    raised = _raises286(lambda: _SRV286._handle_eio_message(c.eio_sid, '4"p286-client-bytes"'))
    _settle286()
    lines = _LOGS286.lines("malformed")
    check("socket protocol: a client-sent CONNECT_ERROR is not an exception out of the message handler; the "
          "connection is closed with one warning naming the error's type, no traceback, none of the client's bytes",
          raised == "" and not c.is_connected() and len(lines) == 1 and lines[0].exc_info is None
          and "(ValueError)" in lines[0].getMessage() and "p286" not in lines[0].getMessage(),
          repr((raised, c.is_connected(), [(r.getMessage(), r.exc_info) for r in _LOGS286.records])))
    more = []
    for pkt in ("2", "2[", "4", "9", "2[]") * 6:
        d = _sio286(P9_VIEWER)
        more.append(_raises286(lambda: _SRV286._handle_eio_message(d.eio_sid, pkt)))
        _settle286()
        more.append(d.is_connected())
    eq("socket protocol: 30 more of them (no data, a broken body, unknown types) raise nothing, each closes its "
       "connection, and within the minute they add no line", (set(more), len(_LOGS286.lines("malformed"))),
       ({"", False}, 1))
    _CLK286.t += 61.0
    e = _sio286(P9_VIEWER)
    _SRV286._handle_eio_message(e.eio_sid, "4")
    _settle286()
    last = _LOGS286.lines("malformed")[-1].getMessage()
    check("socket protocol: the next minute's line says how many were held back",
          "(and 30 more since the last such line)" in last, last)


def _s286_handler_errors_still_raise():
    _CLK286.t += 1000.0
    handlers = _SRV286.handlers["/"]

    def boom(_sid, *_a):
        raise ValueError("p286 handler fault")
    handlers["p286_boom"] = boom
    try:
        c = _sio286(P9_VIEWER)
        raised = _raises286(lambda: c.emit("p286_boom", {}))
        eq("socket protocol: an error raised by an event handler is still raised (and so logged), not taken for a "
           "client's bad packet", (raised, c.is_connected()), ("ValueError: p286 handler fault", True))
        c.disconnect()
    finally:
        handlers.pop("p286_boom", None)


class _FakeSock286:
    def __init__(self, eio):
        self.eio, self.seen = eio, []

    def close(self, wait=True, abort=False, reason=None):
        self.seen.append(("listed" if "e286" in self.eio.sockets else "unlisted", wait, abort))


def _s286_close_unlists_first():
    class _Eio:
        reason = type("R", (), {"SERVER_DISCONNECT": "server disconnect"})
        sockets = {}
    sock = _FakeSock286(_Eio)
    _Eio.sockets["e286"] = sock
    srv = type("S", (), {"eio": _Eio, "manager": type("M", (), {"sid_from_eio_sid": staticmethod(lambda e, n: None)}),
                         "disconnect": staticmethod(lambda *a, **k: None)})
    _sh286._close_now(srv, "e286")
    eq("socket protocol: a closed connection leaves engine.io's table before it is closed, without waiting for a "
       "polling client to collect it (a POST meanwhile was a KeyError: a 500 with a traceback)",
       (sock.seen, "e286" in _Eio.sockets), ([("unlisted", False, False)], False))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Every event's argument is optional
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _socket_event286(dec):
    """The event name a decorator registers with `@socketio.on("<event>")`, or None."""
    if not (isinstance(dec, _ast286.Call) and isinstance(dec.func, _ast286.Attribute) and dec.func.attr == "on"):
        return None
    if not (isinstance(dec.func.value, _ast286.Name) and dec.func.value.id == "socketio"):
        return None
    return dec.args[0].value if dec.args and isinstance(dec.args[0], _ast286.Constant) else None


def _socket_handlers286():
    """(name, event, positional parameters without a default) for every @socketio.on handler under panel/."""
    found = []
    for dp, _dn, fn in _os286.walk(_os286.path.join(_ROOT286, "panel")):
        for f in (x for x in fn if x.endswith(".py")):
            with open(_os286.path.join(dp, f), encoding="utf-8") as fh:
                tree = _ast286.parse(fh.read())
            funcs = (n for n in _ast286.walk(tree) if isinstance(n, _ast286.FunctionDef))
            for node in funcs:
                pos = node.args.posonlyargs + node.args.args
                found.extend((node.name, ev, len(pos) - len(node.args.defaults))
                             for ev in map(_socket_event286, node.decorator_list) if ev is not None)
    return found


def _s286_optional_argument():
    found = _socket_handlers286()
    events = {e for _n, e, _r in found}
    bare = [(n, e) for n, e, req in found if req and e not in ("connect", "disconnect")]
    check("socket handlers: every event handler takes its argument as optional (join/leave_console, term_*)",
          {"join_console", "leave_console", "term_open", "term_input", "term_resize", "term_close"} <= events
          and bare == [], repr((sorted(events), bare)))
    _CLK286.t += 1000.0
    c = _sio286(P9_VIEWER)
    said = {ev: _raises286(lambda: c.emit(ev)) for ev in ("join_console", "leave_console", "term_open",
                                                         "term_input", "term_resize")}
    eq("socket handlers: each event sent with no argument raises nothing and keeps the socket",
       (said, c.is_connected()), ({k: "" for k in said}, True))
    c.disconnect()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. One operation at a time per database
# ════════════════════════════════════════════════════════════════════════════════════════════════
_DBA286 = {}


def _db_row286(sid):
    with _p9.app_context():
        r = _GD286(remote_id=P9_HOST, game_server_id=sid, name="gs%d_p286" % sid, secret=_enc286("Zp286" + "q" * 27),
                   auth_plugin="mysql_native_password", max_conn=10, created_by="p286")
        _db286.session.add(r)
        _db286.session.commit()
        return r.id, r.name


def _db_nested286(api, name, client, uid_box):
    """While the outer operation is at its host call: a restore, a dump, a delete and an upload's finish."""
    out = {"restore": client.post(api + "/restore", json={"confirm": name}),
           "dump": client.post(api + "/dump"),
           "delete": client.post(api + "/delete", json={"confirm": name}),
           "finish": client.post(api + "/upload/%s/finish" % (uid_box[0] or "none"), json={"confirm": name})}
    return {k: (v.status_code, _p9_json(v).get("message", "")) for k, v in out.items()}


def _s286_database_claim():
    _p9_arm(who="part286")
    sid = _p9_new_server(P9_HOST, "p286db", "pmc", 25586, name="p286 db")
    rid, name = _db_row286(sid)
    api = "/api/server/%d/databases/%d" % (sid, rid)
    adm = _p9_client(P9_ADMIN)
    hd = object()
    _p9_patch(_dbr286, "_restore_target", lambda gs, r: hd)
    _p9_patch(_dbr286, "game_account_write_refusal", lambda remote, user, **k: None)
    _p9_patch(_dbf286, "own_target", lambda gs, r: hd)
    _p9_patch(_dbr286._net, "admin_target", lambda *a: (None, None))
    _p9_patch(_dbr286, "_forget_data", lambda db_id: None)
    seen, box = {}, [None]

    def restore(remote, hostdb, account, n, pw):
        if "restore" not in seen:
            seen["restore"] = _db_nested286(api, name, adm, box)
        return True, ""

    def dump(remote, hostdb, dest, account, names):
        if "dump" not in seen:
            seen["dump"] = adm.post(api + "/restore", json={"confirm": name})
        return True, ""
    _p9_patch(_dbr286._dbs, "restore", restore)
    _p9_patch(_dbf286._dbs, "dump", dump)
    first = adm.post(api + "/restore", json={"confirm": name})
    busy = "being restored right now"
    inner = seen.get("restore") or {}
    eq("database claim: while a restore runs, a second restore, a dump, a delete and an uploaded dump's finish of "
       "the same database are each refused (409, saying it is being restored); the first completes",
       ({k: (s, busy in m) for k, (s, m) in inner.items()}, first.status_code),
       ({"restore": (409, True), "dump": (409, True), "delete": (409, True), "finish": (409, True)}, 200))
    with _p9.app_context():
        refused = [(a.action, a.success) for a in _AL286.query.filter(_AL286.detail.like("%" + name + " (refused:%"))]
    eq("database claim: each refusal is audited as a failure under its own action",
       sorted(refused), sorted([("db_restore", False), ("db_dump_download", False), ("db_delete", False),
                                ("db_upload", False)]))
    d = adm.post(api + "/dump")
    nested = seen.get("dump")
    eq("database claim: a dump holds it too (a restore meanwhile is refused saying it is being dumped), and the "
       "claim is released after each: the dump itself was taken after the restore ended",
       (d.status_code, getattr(nested, "status_code", 0), "being dumped" in _p9_json(nested).get("message", "")
        if nested is not None else False), (200, 409, True))

    def broken(remote, hostdb, account, n, pw):
        raise RuntimeError("p286 host fault")
    _p9_patch(_dbr286._dbs, "restore", broken)
    failed = adm.post(api + "/restore", json={"confirm": name})
    _p9_patch(_dbr286._dbs, "restore", lambda *a: (True, ""))
    again = adm.post(api + "/restore", json={"confirm": name})
    eq("database claim: a restore that raised releases it (the next restore runs)",
       (failed.status_code, again.status_code), (500, 200))
    _DBA286["upload"] = (sid, rid, name, api, adm)


def _s286_upload_finish_holds():
    _sid, rid, name, api, adm = _DBA286["upload"]
    uid = "86" * 16
    with _dbf286._UPLOADS_LOCK:
        _dbf286._UPLOADS[uid] = {"uid": uid, "db": rid, "user": P9_ADMIN, "size": 10, "ts": _time286.time()}
    nested = []

    def upcmd(gs, script, timeout, stdin=None):
        if not nested:
            nested.append(adm.post(api + "/restore", json={"confirm": name}))
        return "unread", None
    _p9_patch(_dbf286, "_upcmd", upcmd)
    fin = adm.post(api + "/upload/%s/finish" % uid, json={"confirm": name})
    _dbf286._drop_upload(uid)
    eq("database claim: an uploaded dump's finish holds it from its first host step (it puts the upload in place "
       "as the dump a restore reads): a restore meanwhile is refused",
       (fin.status_code, [(r.status_code, "being restored" in _p9_json(r).get("message", "")) for r in nested]),
       (200, [(409, True)]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The invite's second code
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _inv_failures286(iid):
    with _p9.app_context():
        return _db286.session.get(_Inv286, iid).code_failures


def _set_failures286(iid, n):
    with _p9.app_context():
        _db286.session.get(_Inv286, iid).code_failures = n
        _db286.session.commit()


def _s286_invite():
    from unit.part222 import _admin222, _mint222, _redeem222
    real = _Inv286.code_matches
    from panel.routes import admin_notifications as _an286
    _p9_patch(_an286.notifications, "notify", lambda *a, **k: None)
    a = _admin222()
    token, code, (iid, _h) = _mint222(a, require_code="on", note="p286")
    wrong = "0000 0000" if code != "0000 0000" else "1111 1111"
    calls = []

    def counting(inv, typed):
        calls.append(_inv_failures286(inv.id))
        return real(inv, typed)
    _p9_patch(_Inv286, "code_matches", counting)
    _redeem222(_p9.test_client(), token, invite_code=wrong)
    eq("invite code: the try is counted before the code is checked (the check sees it already)", calls, [1])
    del calls[:]
    _set_failures286(iid, 2)
    right = _redeem222(_p9.test_client(), token, invite_code=code)
    eq("invite code: a right code gives its try back (2 wrong before, still 2) and opens the account form",
       (right[0], 'name="username"' in right[1], _inv_failures286(iid)), (200, True, 2))
    _set_failures286(iid, _Inv286.CODE_MAX_TRIES - 1)
    nested = []

    def burst(inv, typed):
        calls.append(1)
        if not nested:
            nested.append(_redeem222(_p9.test_client(), token, invite_code=code))
        return real(inv, typed)
    del calls[:]
    _p9_patch(_Inv286, "code_matches", burst)
    outer = _redeem222(_p9.test_client(), token, invite_code=wrong)
    _p9_patch(_Inv286, "code_matches", real)
    with _p9.app_context():
        state = _db286.session.get(_Inv286, iid).state
    eq("invite code: with one try left, a second code arriving while the first is checked is not checked at all "
       "(429, try again), so no more codes are checked than tries were left; the wrong one then revokes it",
       (len(calls), nested[0][0] if nested else 0, "being checked" in (nested[0][1] if nested else ""), outer[0],
        state), (1, 429, True, 404, "burned"))
    late = _redeem222(_p9.test_client(), token, invite_code=code)
    eq("invite code: once revoked, a code is refused without being checked", (late[0], len(calls)), (404, 1))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. SFTP key add
# ════════════════════════════════════════════════════════════════════════════════════════════════
_PW286 = "p286-Pass" + "word-long-enough-2"     # a fixture account's password, never a real one


def _ed25519_286():
    """(None, a new Ed25519 public key line)."""
    from panel.services import sftp_common as sc
    k = sc.host_key_from_text(sc.new_host_key_text())
    return None, "%s %s p286" % (k.get_name(), k.get_base64())


def _sftp_user286(tag):
    with _p9.app_context():
        u = _U286(username="p286_" + tag, password_hash=_auth286.hash_password(_PW286), is_active=True)
        _db286.session.add(u)
        _db286.session.commit()
        return u.id


def _key_row286(uid, line):
    from panel.services import sftp_common as sc
    p = sc.parse_public_key(line)[0]
    return _Key286(user_id=uid, label="p286", key_type=p.key_type, key_blob=p.blob_b64, fingerprint=p.fingerprint)


def _keys286(uid):
    with _p9.app_context():
        return _Key286.query.filter_by(user_id=uid).count()


def _add_audits286(uid):
    with _p9.app_context():
        return [(r.success, r.detail) for r in _AL286.query.filter_by(action="sftp_key_add", user_id=uid)
                .order_by(_AL286.id)]


def _meanwhile286(uid, line):
    """The proof, with another request's insert of `line` landing while it runs (as the password hashes)."""
    real = _sfs286._key_add_proof_refusal

    def proof(u):
        with _p9.app_context():
            _db286.session.add(_key_row286(uid, line))
            _db286.session.commit()
        return real(u)
    return proof


def _s286_sftp():
    real = _sfs286._key_add_proof_refusal
    _ag286.reset_throttle()
    uid = _sftp_user286("dup")
    c = _p9_client(uid)
    line = _ed25519_286()[1]
    _p9_patch(_sfs286, "_key_add_proof_refusal", _meanwhile286(uid, line))
    r = c.post("/account/sftp-keys/add", data={"public_key": line, "password": _PW286})
    _p9_patch(_sfs286, "_key_add_proof_refusal", real)
    eq("sftp key add: a copy of the key stored while the password was checked is a clean refusal (no 500), "
       "audited, and the key is held once",
       (r.status_code, _keys286(uid), _add_audits286(uid)),
       (302, 1, [(False, "refused: That key is already on your account.")]))
    uid2 = _sftp_user286("cap")
    with _p9.app_context():
        for _ in range(19):
            _db286.session.add(_key_row286(uid2, _ed25519_286()[1]))
        _db286.session.commit()
    _p9_patch(_sfs286, "_key_add_proof_refusal", _meanwhile286(uid2, _ed25519_286()[1]))
    r2 = _p9_client(uid2).post("/account/sftp-keys/add", data={"public_key": _ed25519_286()[1], "password": _PW286})
    _p9_patch(_sfs286, "_key_add_proof_refusal", real)
    eq("sftp key add: a key that reached the cap while the password was checked stops this one (20, not 21)",
       (r2.status_code, _keys286(uid2), [d for _s, d in _add_audits286(uid2)][-1:]),
       (302, _sfs286.sc.MAX_KEYS_PER_USER, ["refused: An account can hold 20 SFTP keys. Remove one first."]))
    proofs = []
    _p9_patch(_sfs286, "_key_add_proof_refusal", lambda u: proofs.append(u) or "unreached")
    c.post("/account/sftp-keys/add", data={"public_key": line, "password": _PW286})
    _p9_patch(_sfs286, "_key_add_proof_refusal", real)
    eq("sftp key add: a duplicate known before the proof is refused without asking for it (a backup code is not "
       "spent)", len(proofs), 0)
    _p9_patch(_sfs286, "_key_refusal", lambda u, p: None)
    from panel.services import sftp_common as sc
    with _p9.test_request_context(), _p9.app_context():
        u = _db286.session.get(_U286, uid)
        said = _raises286(lambda: _box286.append(_sfs286._store_key(u, sc.parse_public_key(line)[0])))
        try:
            alive = _db286.session.query(_Key286).filter_by(user_id=uid).count()
        except Exception as exc:        # a session left in a failed transaction
            alive = type(exc).__name__
    _p9_patch(_sfs286, "_key_refusal", _P9_KEYREF286)
    eq("sftp key add: a duplicate the database's own unique rule catches is the same refusal, and the session is "
       "usable after it", (said, _box286[-1:], alive), ("", ["That key is already on your account."], 1))
    ok = _p9_client(uid).post("/account/sftp-keys/add", data={"public_key": _ed25519_286()[1], "password": _PW286})
    eq("sftp key add: a new key is still added (302, two keys, audited)",
       (ok.status_code, _keys286(uid), _add_audits286(uid)[-1][0]), (302, 2, True))


_box286 = []
_P9_KEYREF286 = _sfs286._key_refusal
_trips286 = len(_P9_TRIPPED)

try:
    for _step286 in (_s286_installed, _s286_general_and_shared, _s286_terminal_budget, _s286_disconnect,
                     _s286_normal_use, _s286_protocol_errors, _s286_handler_errors_still_raise,
                     _s286_close_unlists_first, _s286_optional_argument, _s286_database_claim,
                     _s286_upload_finish_holds, _s286_invite, _s286_sftp):
        _why286 = _raises286(_step286)
        if _why286:
            check("part286: %s ran to the end" % _step286.__name__, False, _why286)
    eq("part286: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips286:], [])
finally:
    _p9_restore_all()
    _sh286._clock = _saved_clock286
    _sh286._log_state.clear()
    _sh286._log_state.update(_saved_logstate286)
    _sh286._log.removeHandler(_LOGS286)
    getattr(_SRV286._handle_eio_message, "budgets", {}).clear()     # absent when the budget was never installed
