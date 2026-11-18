"""Part 246 of the unit suite: "Require 2FA" on the Socket.IO paths, and device cookies at sign-in.

Settings can require two-factor authentication of superadmins and of anyone allowed the terminal,
users or groups. The rule is a before_request (account_guard.twofa_gate), and a before_request never
runs for a Socket.IO event, so every socket path asks account_guard.held_at_sign_in_gate itself:

* the connect handler refuses the handshake;
* join_console refuses a socket that connected before the rule applied, and the console's viewer
  sweep drops one already watching;
* term_open refuses a shell, and the terminal's revocation sweep closes one already open.

Each is shown against a control: the same account with the switch off gets through.

Device cookies (OWASP "Slow Down Online Guessing Attacks with Device Cookies"): a name paused by wrong
guesses still signs in from a browser that signed in to it before, and refuses every other client; the
cookie is bound to the account, rotated on each sign-in, signed for this purpose only, and sent
`__Host-`, Secure, HttpOnly and SameSite=Strict over HTTPS; a known browser's own failures pause that
browser and not the name; and the low-and-slow day rule holds an unknown client but not a known one.
Every route runs on part12's app with its transport tripwire armed; nothing reaches a host or data/.
"""
import hashlib as _hl246
import time as _time246

from itsdangerous import URLSafeTimedSerializer as _UTS246

from unit.part01 import check
from unit.part12 import P9_GS, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_patch, _p9_restore_all
from panel.db.models import (AuditLog as _AL246, Group as _G246, RemoteServer as _RS246, User as _U246,
                             UserSession as _US246, db as _db246)
from panel.routes import host_terminal as _ht246, server_files as _sf246
from panel.security import account_guard as _ag246, auth as _auth246, device_cookie as _dc246
from panel.services import notifications as _nt246

_trips246 = len(_P9_TRIPPED)
_IDS246 = []
_K246 = "willow lantern orchard drift"      # the fixtures' sign-in secret (no real credential)
_K246_WRONG = "not what was set at all"
_NOTES246 = []


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


# ── device cookies ────────────────────────────────────────────────────────────────────────────────
def _reset246():
    from app import _LOGIN_FAILS, _LOGIN_FAILS_LOCK
    _ag246.reset_throttle()
    with _LOGIN_FAILS_LOCK:
        _LOGIN_FAILS.clear()


def _device_name246():
    with _p9.test_request_context("/"):
        return _dc246.cookie_name()


def _login246(name, secret, ip, device=None):
    """POST the login form from a fresh browser at `ip`, holding `device` as its device cookie."""
    c = _p9.test_client()
    c.environ_base["REMOTE_ADDR"] = ip
    if device:
        c.set_cookie(_device_name246(), device)
    return c, c.post("/login", data={"username": name, "password": secret})


def _signed_in_as246(c):
    with c.session_transaction() as s:
        return bool(s.get("_user_id"))


def _device_of246(c):
    ck = c.get_cookie(_device_name246())
    return ck.value if ck is not None else None


def _pause_name246(name, base):
    """Pause `name` with ACCOUNT_SOFT_FAILS wrong guesses from as many fresh browsers; their statuses."""
    return [_login246(name, _K246_WRONG, "198.51.100.%d" % (base + i))[1].status_code
            for i in range(_ag246.ACCOUNT_SOFT_FAILS)]


def _locks246(since_id):
    with _p9.app_context():
        return [r.detail for r in _AL246.query.filter(_AL246.action == "login_locked", _AL246.id > since_id,
                                                      _AL246.username == "p246_owner").all()]


def _last_audit246():
    with _p9.app_context():
        r = _AL246.query.order_by(_AL246.id.desc()).first()
        return r.id if r else 0


def _s246_device_signs_in():
    _reset246()
    first, _r = _login246("p246_owner", _K246, "203.0.113.10")
    dev = _device_of246(first)
    tries = _pause_name246("p246_owner", 60)
    plain, r_plain = _login246("p246_owner", _K246, "203.0.113.11")
    known, r_known = _login246("p246_owner", _K246, "203.0.113.12", device=dev)
    check("device cookie: a paused name still signs in from a browser it signed in from before; an unknown "
          "browser is refused",
          bool(dev) and tries == [200] * _ag246.ACCOUNT_SOFT_FAILS
          and "Too many failed attempts" in r_plain.get_data(as_text=True) and not _signed_in_as246(plain)
          and r_known.status_code == 302 and _signed_in_as246(known),
          repr((bool(dev), tries, r_plain.status_code, r_known.status_code)))
    again = _device_of246(known)
    check("device cookie: each sign-in gives the browser a new cookie (rotated)",
          bool(again) and again != dev, repr((dev, again)))


def _s246_device_bound():
    _reset246()
    other, _r = _login246("p246_other", _K246, "203.0.113.20")
    theirs = _device_of246(other) or ""
    mine_c, _r = _login246("p246_owner", _K246, "203.0.113.21")
    mine = _device_of246(mine_c) or ""
    with _p9.app_context():
        owner_id = _db246.session.query(_U246.id).filter_by(username="p246_owner").scalar()
    with _p9.test_request_context("/"):
        wrong_use = _UTS246(_p9.secret_key, salt="another-purpose",
                            signer_kwargs={"digest_method": _hl246.sha256}).dumps({"u": owner_id, "n": "n" * 32})
    _pause_name246("p246_owner", 80)
    said = {}
    altered = mine[:-3] + ("AAA" if mine[-3:] != "AAA" else "BBB")
    for label, value in (("another account's", theirs), ("altered", altered), ("other purpose", wrong_use)):
        c, r = _login246("p246_owner", _K246, "203.0.113.22", device=value)
        said[label] = (r.status_code, _signed_in_as246(c))
    days = _dc246.DEVICE_COOKIE_DAYS
    _dc246.DEVICE_COOKIE_DAYS = -1
    try:
        c, r = _login246("p246_owner", _K246, "203.0.113.23", device=mine)
    finally:
        _dc246.DEVICE_COOKIE_DAYS = days
    said["expired"] = (r.status_code, _signed_in_as246(c))
    c, r = _login246("p246_owner", _K246, "203.0.113.24", device=mine)
    said["its own (control)"] = (r.status_code, _signed_in_as246(c))
    check("device cookie: another account's cookie, an altered one, one signed for another purpose and an "
          "expired one count as no cookie: the paused name refuses them; its own signs in",
          said == {"another account's": (200, False), "altered": (200, False), "other purpose": (200, False),
                   "expired": (200, False), "its own (control)": (302, True)}, repr(said))


def _device_set_cookie246(secure):
    """The device cookie's Set-Cookie line from one sign-in with the cookies Secure or not."""
    _reset246()
    was = _p9.config.get("SESSION_COOKIE_SECURE")
    _p9.config["SESSION_COOKIE_SECURE"] = secure
    try:
        _c, r = _login246("p246_owner", _K246, "203.0.113.30")
    finally:
        _p9.config["SESSION_COOKIE_SECURE"] = was
    return [h for h in r.headers.getlist("Set-Cookie") if "lgpanel_device=" in h]


def _s246_device_attributes():
    https = _device_set_cookie246(True)
    plain = _device_set_cookie246(False)
    line = https[0] if len(https) == 1 else ""
    parts = [p.strip() for p in line.split(";")]
    wanted = {"Secure", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=%d" % (_dc246.DEVICE_COOKIE_DAYS * 86400)}
    domains = [p for p in parts if p.lower().startswith("domain=")]
    check("device cookie: over HTTPS it is __Host-, Secure, HttpOnly, SameSite=Strict, Path=/, no Domain, "
          "kept DEVICE_COOKIE_DAYS",
          all([line.startswith("__Host-lgpanel_device="), wanted <= set(parts), not domains]), repr(https))
    one = plain[0] if len(plain) == 1 else ""
    check("device cookie: ...over plain HTTP it keeps a plain name and no Secure, so the browser keeps it",
          all([one.startswith("lgpanel_device="), "Secure" not in one, "SameSite=Strict" in one]), repr(plain))


def _s246_device_own_failures():
    _reset246()
    first_id = _last_audit246()
    _NOTES246.clear()
    first, _r = _login246("p246_owner", _K246, "203.0.113.40")
    dev = _device_of246(first)
    for i in range(_ag246.ACCOUNT_SOFT_FAILS):
        _login246("p246_owner", _K246_WRONG, "198.51.100.%d" % (100 + i), device=dev)
    locks = _locks246(first_id)
    other, _r = _login246("p246_owner", _K246, "203.0.113.41")
    other_in = _signed_in_as246(other)
    _pause_name246("p246_owner", 120)
    held, r_held = _login246("p246_owner", _K246, "203.0.113.42", device=dev)
    check("device cookie: a known browser's wrong guesses pause that browser only (one audit row and one alert "
          "saying so); the name stays open to another browser",
          len(locks) == 1 and "one signed-in browser" in locks[0]
          and [k for k, b in _NOTES246 if k == "account_locked" and "browser it has signed in from" in b]
          == ["account_locked"] and other_in, repr((locks, _NOTES246, other_in)))
    check("device cookie: ...and a paused browser is then held like an unknown one (refused while the name is "
          "paused too)",
          "Too many failed attempts" in r_held.get_data(as_text=True) and not _signed_in_as246(held),
          repr(r_held.status_code))


def _s246_day_rule():
    _reset246()
    t = _time246.time() - 23 * 3600
    for i in range(_ag246.ACCOUNT_DAY_FAILS):
        _ag246.account_reserve("p246_slow", t + i * 25 * 60)
    now = t + (_ag246.ACCOUNT_DAY_FAILS - 1) * 25 * 60 + 60
    unknown, _left = _ag246.account_reserve("p246_slow", now)
    known, _left2 = _ag246.account_reserve("p246_slow", now, device="k" * 32)
    _reset246()
    check("device cookie: after a day's slow trickle of wrong guesses the name holds an unknown client but not a "
          "known browser",
          unknown is None and known is not None and _ag246.is_device_slot(known), repr((unknown, known)))


try:
    _p9_arm(who="part246")
    _user246("p246_sa", superadmin=True)
    _user246("p246_term", perms=(_auth246.USE_TERMINAL,), host=P9_HOST)
    _user246("p246_owner")
    _user246("p246_other")
    for _fn246 in (_s246_connect, _s246_join_console, _s246_console_sweep, _s246_term_open, _s246_term_sweep,
                   _s246_device_signs_in, _s246_device_bound, _s246_device_attributes, _s246_device_own_failures,
                   _s246_day_rule):
        _p9_arm(who="part246")
        _p9_patch(_nt246, "notify", lambda key, title, body="", **_kw: _NOTES246.append((key, body)))
        try:
            _fn246()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()
    _reset246()
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
