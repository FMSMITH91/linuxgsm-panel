"""Part 246 of the unit suite: Settings' "Require 2FA" on the Socket.IO paths.

Settings can require two-factor authentication of superadmins and of anyone allowed the terminal,
users or groups. The rule is a before_request (account_guard.twofa_gate), and a before_request never
runs for a Socket.IO event, so every socket path asks account_guard.held_at_sign_in_gate itself:

* the connect handler refuses the handshake;
* join_console refuses a socket that connected before the rule applied, and the console's viewer
  sweep drops one already watching;
* term_open refuses a shell, and the terminal's revocation sweep closes one already open.

Each is shown against a control: the same account with the switch off gets through.
Every route runs on part12's app with its transport tripwire armed; nothing reaches a host or data/.
"""
from unit.part01 import check
from unit.part12 import P9_GS, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_patch, _p9_restore_all
from panel.db.models import Group as _G246, RemoteServer as _RS246, User as _U246, UserSession as _US246, db as _db246
from panel.routes import host_terminal as _ht246, server_files as _sf246
from panel.security import account_guard as _ag246, auth as _auth246

_trips246 = len(_P9_TRIPPED)
_IDS246 = []
_K246 = "willow lantern orchard drift"      # the fixtures' sign-in secret (no real credential)


def _user246(name, superadmin=False, perms=(), host=None):
    """A fresh account with _K246 as its password and no 2FA (its group granted `host`); its id."""
    with _p9.app_context():
        u = _U246(username=name, password_hash=_auth246.hash_password(_K246), display_name=name,
                  is_superadmin=superadmin, is_active=True)
        if perms:
            grp = _G246(name="g246-" + name, description="", is_default=False)
            grp.set_permissions(list(perms))
            if host is not None:
                grp.servers.append(_db246.session.get(_RS246, host))
            _db246.session.add(grp)
            u.groups.append(grp)
        _db246.session.add(u)
        _db246.session.commit()
        _IDS246.append(u.id)
        return u.id


def _signed_in246(name):
    """A test client signed in as `name` through the login form (password step only)."""
    _ag246.reset_throttle()
    c = _p9.test_client()
    c.environ_base["REMOTE_ADDR"] = "198.51.100.46"
    c.post("/login", data={"username": name, "password": _K246})
    return c


def _with_2fa_required(on):
    """Set Settings' "Require 2FA" switch on the test app; the value it had."""
    was = _p9.config.get("REQUIRE_2FA")
    _p9.config["REQUIRE_2FA"] = on
    return was


def _s246_connect():
    c = _signed_in246("p246_sa")
    was = _with_2fa_required(False)
    try:
        sio_off = _p9.socketio.test_client(_p9, flask_test_client=c)
        off = sio_off.is_connected()
        sio_off.disconnect()
        _with_2fa_required(True)
        sio_on = _p9.socketio.test_client(_p9, flask_test_client=c)
        on = sio_on.is_connected()
        if on:
            sio_on.disconnect()
    finally:
        _with_2fa_required(was)
    check("2fa socket: the handshake of an account held at 2FA setup is refused (accepted with the switch off)",
          off and not on, repr((off, on)))


def _s246_join_console():
    c = _signed_in246("p246_sa")
    was = _with_2fa_required(False)
    sio = _p9.socketio.test_client(_p9, flask_test_client=c)
    try:
        _with_2fa_required(True)
        sio.emit("join_console", {"server_id": P9_GS})
        got = sio.get_received()
        with _sf246._viewers_lock:
            joined = any(uid in _IDS246 for uid in (_sf246._console_viewers.get(P9_GS) or {}).values())
    finally:
        _with_2fa_required(was)
        sio.disconnect()
    said = [e["args"][0].get("data", "") for e in got if e["name"] == "console_output"]
    check("2fa socket: a socket that connected before the rule applied cannot join a console",
          not joined and any("access denied" in s for s in said), repr((joined, got)))


def _s246_console_sweep():
    c = _signed_in246("p246_sa")
    was = _with_2fa_required(False)
    sio = _p9.socketio.test_client(_p9, flask_test_client=c)
    try:
        sio.emit("join_console", {"server_id": P9_GS})
        with _p9.app_context():
            kept = _sf246._evict_unauthorized_viewers(_p9, _p9.socketio, P9_GS)
            _with_2fa_required(True)
            dropped = _sf246._evict_unauthorized_viewers(_p9, _p9.socketio, P9_GS)
    finally:
        _with_2fa_required(was)
        sio.disconnect()
    check("2fa socket: the console sweep drops a viewer once the rule applies to it (kept with the switch off)",
          kept == 0 and dropped == 1, repr((kept, dropped)))


def _s246_term_open():
    _p9_patch(_ht246._ts, "open_session", lambda sid, remote, is_local, **k: None)
    _p9_patch(_ht246._ts, "close_for_sid", lambda sid, reason: None)
    c = _signed_in246("p246_term")
    was = _with_2fa_required(False)
    sio = _p9.socketio.test_client(_p9, flask_test_client=c)
    try:
        sio.emit("term_open", {"remote_id": P9_HOST, "cols": 80, "rows": 24})
        off = sio.get_received()
        _with_2fa_required(True)
        sio.emit("term_open", {"remote_id": P9_HOST, "cols": 80, "rows": 24})
        on = sio.get_received()
    finally:
        _with_2fa_required(was)
        sio.disconnect()
    said = [e["args"][0].get("message", "") for e in on if e["name"] == "term_error"]
    check("2fa socket: term_open refuses a terminal holder held at 2FA setup (opens with the switch off)",
          [e["name"] for e in off] == ["term_ready"]
          and said == ["You don't have permission to open a terminal."]
          and not [e for e in on if e["name"] == "term_ready"], repr((off, on)))


def _s246_term_sweep():
    _p9_patch(_ht246._ts, "open_session", lambda sid, remote, is_local, **k: None)
    _p9_patch(_ht246._ts, "close_for_sid", lambda sid, reason: None)
    c = _signed_in246("p246_term")
    was = _with_2fa_required(False)
    sio = _p9.socketio.test_client(_p9, flask_test_client=c)
    try:
        sio.emit("term_open", {"remote_id": P9_HOST, "cols": 80, "rows": 24})
        ready = [e for e in sio.get_received() if e["name"] == "term_ready"]
        with _p9.app_context():
            kept = _ht246.sweep_revoked_terminals(_p9, _p9.socketio)
            _with_2fa_required(True)
            closed = _ht246.sweep_revoked_terminals(_p9, _p9.socketio)
    finally:
        _with_2fa_required(was)
        sio.disconnect()
    check("2fa socket: the terminal sweep closes an open shell once the rule applies (kept with the switch off)",
          bool(ready) and kept == 0 and closed == 1, repr((ready, kept, closed)))


try:
    _p9_arm(who="part246")
    _user246("p246_sa", superadmin=True)
    _user246("p246_term", perms=(_auth246.USE_TERMINAL,), host=P9_HOST)
    for _fn246 in (_s246_connect, _s246_join_console, _s246_console_sweep, _s246_term_open, _s246_term_sweep):
        _p9_arm(who="part246")
        try:
            _fn246()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()
    _ag246.reset_throttle()
    with _p9.app_context():
        for _uid246 in _IDS246:
            _US246.query.filter_by(user_id=_uid246).delete()
            _u246 = _db246.session.get(_U246, _uid246)
            if _u246 is not None:
                for _g246 in list(_u246.groups):
                    _db246.session.delete(_g246)
                _db246.session.delete(_u246)
        _db246.session.commit()

check("part246: nothing reached a real transport", len(_P9_TRIPPED) == _trips246, repr(_P9_TRIPPED[_trips246:]))
