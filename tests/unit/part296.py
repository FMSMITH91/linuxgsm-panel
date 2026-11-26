"""Part 296 of the unit suite: pen-test leftovers and the update gate.

1. Every Socket.IO event handler takes at most one argument (socket_hooks.one_argument): an event
   sent with two is dropped without an answer and without a traceback, one log line a minute names
   the event and never the client's text, and the socket stays up. Each event family is driven: the
   console (join_console, leave_console) and the terminal (term_open, term_input, term_resize,
   term_close). Every handler the app registers is covered, so a new one without it fails here.
2. A database password reset holds the database like a restore, a dump and a delete do
   (databases.one_at_a_time): while one runs, a second reset, a restore, a dump and a delete are
   refused (409) and audited, and a reset while a restore runs is refused the same way.

The sockets run through flask-socketio's test client on part12's app (its real handlers and its real
SocketIO, with the event budget it installed); the clock the budget and the log limit read is a
stand-in, so nothing here depends on how fast the machine is.
"""
import logging as _lg296
from types import SimpleNamespace as _ns296

from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, P9_VIEWER, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json,
                         _p9_new_server, _p9_patch, _p9_restore_all)
from panel.core.config import encrypt_secret as _enc296
from panel.db.models import AuditLog as _AL296, GameDatabase as _GD296, db as _db296
from panel.ops import socket_hooks as _sh296
from panel.routes import databases as _dbr296, databases_files as _dbf296
from panel.routes import host_terminal as _ht296, server_files as _sf296

_SIO296 = _p9.socketio
_SRV296 = _SIO296.server


class _Clock296:
    """The budget's and the log limit's clock, moved by hand."""

    def __init__(self):
        self.t = 7.0e6

    def __call__(self):
        return self.t


class _Logs296(_lg296.Handler):
    """Every record socket_hooks logs."""

    def __init__(self):
        super().__init__(_lg296.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    def lines(self, word):
        return [r.getMessage() for r in self.records if word in r.getMessage()]


_CLK296 = _Clock296()
_LOGS296 = _Logs296()
_saved_clock296 = _sh296._clock
_saved_logstate296 = dict(_sh296._log_state)


def _sio296(uid):
    return _SIO296.test_client(_p9, flask_test_client=_p9_client(uid))


def _raises296(fn):
    """The exception fn() raised, as text, or ''."""
    try:
        fn()
    except Exception as exc:
        return "%s: %s" % (type(exc).__name__, exc)
    return ""


def _watching296(uid):
    with _sf296._viewers_lock:
        return uid in (_sf296._console_viewers.get(P9_GS) or {}).values()


class _Sess296:
    """A terminal session that records what reached it."""

    def __init__(self):
        self.calls = []

    def write(self, data):
        self.calls.append(("write", data))

    def resize(self, cols, rows):
        self.calls.append(("resize", cols, rows))


_EVENTS296 = ("join_console", "leave_console", "term_open", "term_input", "term_resize", "term_close")
_MARK296 = "p296MARK"


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. One argument per socket event
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _s296_every_handler():
    events = sorted(e for e in _SRV296.handlers.get("/", {}) if e not in ("connect", "disconnect"))
    check("socket argument shape: the app registers the console and terminal event families",
          set(_EVENTS296) <= set(events), repr(events))
    _CLK296.t += 1000.0
    c = _sio296(P9_ADMIN)
    said = {ev: _raises296(lambda ev=ev: c.emit(ev, {"server_id": P9_GS, "x": _MARK296}, {"y": _MARK296}))
            for ev in events}
    eq("socket argument shape: every registered event sent with two arguments raises nothing, answers nothing "
       "and keeps the socket", (said, c.get_received(), c.is_connected()), ({e: "" for e in events}, [], True))
    c.disconnect()


def _s296_console_family():
    _CLK296.t += 1000.0
    c = _sio296(P9_VIEWER)
    c.emit("join_console", {"server_id": P9_GS}, {"server_id": P9_GS})
    refused = _watching296(P9_VIEWER)
    c.emit("join_console", {"server_id": P9_GS})
    joined = _watching296(P9_VIEWER)
    c.emit("leave_console", {"server_id": P9_GS}, {"server_id": P9_GS})
    still = _watching296(P9_VIEWER)
    c.emit("leave_console", {"server_id": P9_GS})
    left = _watching296(P9_VIEWER)
    eq("socket argument shape (console): a join or a leave sent with two arguments is not acted on; with one "
       "it is (control)", (refused, joined, still, left, c.is_connected()), (False, True, True, False, True))
    c.disconnect()


def _s296_terminal_family():
    _CLK296.t += 1000.0
    sess, closed = _Sess296(), []
    _p9_patch(_ht296._ts, "get", lambda sid: sess)
    _p9_patch(_ht296, "_close_and_audit", lambda app, sid, reason, user=None: closed.append(reason))
    c = _sio296(P9_ADMIN)
    c.emit("term_open", {"remote_id": 1}, {"remote_id": 1})
    open_two = c.get_received()
    c.emit("term_open", {"remote_id": 999999})
    open_one = [p["name"] for p in c.get_received()]
    c.emit("term_input", {"data": "two"}, {"data": "two"})
    c.emit("term_resize", {"cols": 90, "rows": 30}, {})
    c.emit("term_close", {}, {})
    two = (list(sess.calls), list(closed))
    c.emit("term_input", {"data": "one"})
    c.emit("term_resize", {"cols": 90, "rows": 30})
    c.emit("term_close", {})
    one = (sess.calls[len(two[0]):], closed[len(two[1]):])
    eq("socket argument shape (terminal): term_open, term_input, term_resize and term_close sent with two "
       "arguments reach no shell and answer nothing; with one each is acted on (control)",
       (open_two, open_one, two, one, c.is_connected()),
       ([], ["term_error"], ([], []), ([("write", "one"), ("resize", 90, 30)], ["closed"]), True))
    c.disconnect()
    _p9_restore_all()
    _p9_arm(who="part296")


def _s296_log():
    _CLK296.t += 1000.0
    _sh296._log_state.clear()
    before = len(_LOGS296.records)
    c = _sio296(P9_VIEWER)
    for ev in ("join_console", "leave_console", "term_input"):
        c.emit(ev, {"x": _MARK296}, {"y": _MARK296})
    _CLK296.t += 61.0
    c.emit("term_resize", {"x": _MARK296}, _MARK296)
    got = [r.getMessage() for r in _LOGS296.records[before:]]
    dropped = [m for m in got if "dropped an event" in m]
    eq("socket argument shape: the refusal logs one line a minute, naming the handler and the count of the ones "
       "held back, and no record holds the client's text or a traceback",
       (len(dropped), "on_join_console" in dropped[0] if dropped else False,
        "on_term_resize" in dropped[-1] and "2 more" in dropped[-1] if dropped else False,
        any(_MARK296 in m for m in got), any(r.exc_info for r in _LOGS296.records[before:])),
       (2, True, True, False, False))
    c.disconnect()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A database password reset holds the database
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _db_row296(sid):
    with _p9.app_context():
        r = _GD296(remote_id=P9_HOST, game_server_id=sid, name="gs%d_p296" % sid, secret=_enc296("Zp296" + "q" * 27),
                   auth_plugin="mysql_native_password", max_conn=10, created_by="p296")
        _db296.session.add(r)
        _db296.session.commit()
        return r.id, r.name


def _said296(resp):
    return resp.status_code, _p9_json(resp).get("message", "")


def _s296_password_claim():
    sid = _p9_new_server(P9_HOST, "p296db", "pmc", 25596, name="p296 db")
    rid, name = _db_row296(sid)
    api = "/api/server/%d/databases/%d" % (sid, rid)
    adm = _p9_client(P9_ADMIN)
    hd = _ns296(flavor="mariadb", native_ok=True)     # the host's database server, as its record reads
    _p9_patch(_dbr296, "_restore_target", lambda gs, r: hd)
    _p9_patch(_dbr296, "game_account_write_refusal", lambda remote, user, **k: None)
    _p9_patch(_dbf296, "own_target", lambda gs, r: hd)
    _p9_patch(_dbr296._net, "admin_target", lambda *a: (object(), hd))
    _p9_patch(_dbr296, "drop_row", lambda *a: (True, ""))
    _p9_patch(_dbr296, "_forget_data", lambda db_id: None)
    _p9_patch(_dbr296._dbs, "restore", lambda *a: (True, ""))
    _p9_patch(_dbf296._dbs, "dump", lambda *a: (True, ""))
    seen = {}

    def set_password(remote, hostdb, n, secret):
        if not seen:
            seen["entered"] = True      # once: a nested reset that got through must not nest again
            seen["reset"] = {k: _said296(v) for k, v in (
                ("reset", adm.post(api + "/reset-password")),
                ("restore", adm.post(api + "/restore", json={"confirm": name})),
                ("dump", adm.post(api + "/dump")),
                ("delete", adm.post(api + "/delete", json={"confirm": name})))}
        return True, ""
    _p9_patch(_dbr296._dbs, "set_password", set_password)
    first = adm.post(api + "/reset-password")
    busy = "password is being changed right now"
    inner = seen.get("reset") or {}
    eq("database claim (password reset): while a reset runs, a second reset, a restore, a dump and a delete of the "
       "same database are each refused (409, saying its password is being changed); the first completes",
       ({k: (s, busy in m) for k, (s, m) in inner.items()}, first.status_code),
       ({"reset": (409, True), "restore": (409, True), "dump": (409, True), "delete": (409, True)}, 200))
    with _p9.app_context():
        refused = sorted((a.action, a.success) for a in
                         _AL296.query.filter(_AL296.detail.like("%" + name + " (refused:%")))
    eq("database claim (password reset): each refusal is audited as a failure under its own action",
       refused, sorted([("db_password", False), ("db_restore", False), ("db_dump_download", False),
                        ("db_delete", False)]))
    nested = []

    def restore(*a):
        if not nested:
            nested.append(_said296(adm.post(api + "/reset-password")))
        return True, ""
    _p9_patch(_dbr296._dbs, "restore", restore)
    _p9_patch(_dbr296._dbs, "set_password", lambda *a: (True, ""))
    rest = adm.post(api + "/restore", json={"confirm": name})
    with _p9.app_context():
        before = _db296.session.get(_GD296, rid).secret
    alone = adm.post(api + "/reset-password")
    with _p9.app_context():
        after = _db296.session.get(_GD296, rid).secret
    eq("database claim (password reset): a reset while a restore runs is refused (409, saying it is being "
       "restored), and a reset alone runs and stores a new password (control)",
       (rest.status_code, nested[:1] and (nested[0][0], "being restored" in nested[0][1]), alone.status_code,
        before != after), (200, (409, True), 200, True))

    def broken(*a):
        raise RuntimeError("p296 host fault")
    _p9_patch(_dbr296._dbs, "set_password", broken)
    failed = adm.post(api + "/reset-password")
    _p9_patch(_dbr296._dbs, "set_password", lambda *a: (True, ""))
    again = adm.post(api + "/reset-password")
    eq("database claim (password reset): a reset that raised releases it (the next reset runs)",
       (failed.status_code, again.status_code), (500, 200))
    _p9_restore_all()
    _p9_arm(who="part296")


_trips296 = len(_P9_TRIPPED)
_sh296._clock = _CLK296
_sh296._log_state.clear()
_sh296._log.addHandler(_LOGS296)
try:
    _p9_arm(who="part296")
    for _step296 in (_s296_every_handler, _s296_console_family, _s296_terminal_family, _s296_log,
                     _s296_password_claim):
        _why296 = _raises296(_step296)
        if _why296:
            check("part296: %s ran to the end" % _step296.__name__, False, _why296)
    eq("part296: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips296:], [])
finally:
    _p9_restore_all()
    _sh296._clock = _saved_clock296
    _sh296._log_state.clear()
    _sh296._log_state.update(_saved_logstate296)
    _sh296._log.removeHandler(_LOGS296)
    getattr(_SRV296._handle_eio_message, "budgets", {}).clear()     # absent when the budget was never installed
