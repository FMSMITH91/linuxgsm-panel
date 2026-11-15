"""Part 215 of the unit suite: sign-in hardening to the OWASP cheat sheets.

* Sessions (Session Management, "Session Expiration"): the idle timeout in minutes (30 for a new
  install; an older install's hours converted), the absolute limit as its own setting (8 h, or the
  old rule when unset), the Settings page's OWASP hints and "Longer than OWASP recommends" notes, a save
  refused only when the idle timeout would outlast the absolute limit; and a background poll neither
  moves the login's last-seen time nor re-sends the cookie, so polling past the idle timeout ends it.
* Passwords (Authentication, "Implement Proper Password Strength Controls"): 15 characters, 8 with 2FA,
  no composition rules, the bundled common-password screen, the username refused; through the routes.
* Per-account throttle (Authentication "Login Throttling" / "Account Lockout"): failures from many
  addresses pause one name with an increasing, capped pause; one audit row and one alert per lockout;
  an unknown name is treated the same; the address day limit.
* Required 2FA (Multifactor Authentication): the Settings switch, the gate and who it covers.
* Step-up (Session Management "Reauthentication After Risk Events"): the high-risk routes refuse a stale
  proof, the confirm page restores it, API tokens are exempt, the terminal socket asks too.
* Notices, logging and sessions: account-change notices at sign-in and on the Account page, the
  admin-level alerts, 403 / CSRF / binding-mismatch audit rows (rate-limited), session rotation on 2FA
  changes, Clear-Site-Data at logout, API-token expiry, and the Fetch Metadata guard.
Every route runs on part12's app with its transport tripwire armed; nothing reaches a host or data/.
"""
import time as _time215
from datetime import timedelta as _td215
from types import SimpleNamespace as _NS215

import pyotp as _pyotp215

from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_HOST, P9_VIEWER, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_flashes,
                         _p9_json, _p9_patch, _p9_restore_all)
from panel.core import session_policy as _sp215
from panel.core.clock import utcnow as _now215
from panel.core.common_passwords import is_common as _common215
from panel.core.validation import password_problem as _pp215
from panel.db.models import AuditLog as _AL215, Group as _G215, User as _U215, UserSession as _US215, db as _db215
from panel.routes import auth_routes as _ar215, host_terminal as _ht215
from panel.routes import _shared as _sh215
from panel.security import account_guard as _ag215, auth as _auth215, session_cookie as _sc215
from panel.services import notifications as _nt215

_trips215 = len(_P9_TRIPPED)
_IDS215 = []
_K215 = "lantern harbour quietly"        # the fixtures' password (no real credential)
_K215_NEW = "copper meadow whistle"
_K215_SHORT = "Tr4vel!ng"                 # 9 characters: enough with 2FA only
_K215_WRONG = "not the password at all"
_XHR215 = {"X-Requested-With": "XMLHttpRequest"}
_BG215 = {"X-Requested-With": "XMLHttpRequest", "X-Panel-Background": "1"}
_NOTES215 = []


def _user215(name, superadmin=False, perms=(), totp=None):
    """A fresh account with _K215 as its password; its id."""
    with _p9.app_context():
        u = _U215(username=name, password_hash=_auth215.hash_password(_K215), display_name=name,
                  is_superadmin=superadmin, is_active=True)
        if totp:
            from panel.core.config import encrypt_secret
            u.totp_secret, u.totp_enabled = encrypt_secret(totp), True
        if perms:
            grp = _G215(name="g215-" + name, description="", is_default=False)
            grp.set_permissions(list(perms))
            _db215.session.add(grp)
            u.groups.append(grp)
        _db215.session.add(u)
        _db215.session.commit()
        _IDS215.append(u.id)
        return u.id


def _login215(name, secret=_K215, ip="198.51.100.215", code=None):
    """POST the login form (and the 2FA step); (client, response)."""
    c = _p9.test_client()
    c.environ_base["REMOTE_ADDR"] = ip
    r = c.post("/login", data={"username": name, "password": secret})
    if code is not None:
        r = c.post("/login", data={"totp_code": code})
    return c, r


def _audits215(action, since_id=0):
    with _p9.app_context():
        return [(_r.username, _r.detail, _r.success) for _r in
                _AL215.query.filter(_AL215.action == action, _AL215.id > since_id).order_by(_AL215.id).all()]


def _last_id215():
    with _p9.app_context():
        r = _AL215.query.order_by(_AL215.id.desc()).first()
        return r.id if r else 0


def _reset215():
    _ag215.reset_throttle()
    _ag215.reset_denials()
    with _p9_app_fails215()[1]:
        _p9_app_fails215()[0].clear()
    _sh215._REAUTH_FAILS.clear()


def _p9_app_fails215():
    from app import _LOGIN_FAILS, _LOGIN_FAILS_LOCK
    return _LOGIN_FAILS, _LOGIN_FAILS_LOCK


# ── 1. session lifetimes ─────────────────────────────────────────────────────────────────────────
def _s215_policy():
    eq("sessions: a new install's idle timeout is 30 minutes and its absolute limit 8 hours",
       (_sp215.idle_minutes({}), _sp215.absolute_hours({})), (30, 8))
    eq("sessions: an older install's idle hours are converted to minutes, and its absolute limit keeps the old "
       "rule (the longer of 8 h and the idle time)",
       [(_sp215.idle_minutes(c), _sp215.absolute_hours(c)) for c in
        ({"session_lifetime_hours": 8}, {"session_lifetime_hours": 72})], [(480, 8), (4320, 72)])
    eq("sessions: a set idle timeout wins over the old key, held to 5..10080 minutes",
       [_sp215.idle_minutes({"session_idle_minutes": v, "session_lifetime_hours": 8}) for v in (45, 1, 10 ** 9)],
       [45, 5, 10080])
    ok, _why = _sp215.parse_form({"session_idle_minutes": "20", "session_absolute_hours": "4", "remember_days": "3"})
    bad, why = _sp215.parse_form({"session_idle_minutes": "600", "session_absolute_hours": "8"})
    check("sessions: an idle timeout longer than the absolute limit is refused, and says so plainly",
          ok == {"session_idle_minutes": 20, "session_absolute_hours": 4, "remember_days": 3}
          and bad is None and "cannot be longer than the absolute session limit" in why, repr((ok, bad, why)))


def _settings_page215():
    page = _p9_client(P9_ADMIN).get("/settings").get_data(as_text=True)
    return page


def _note_shown215(page, note_id):
    """Whether the note with `note_id` is shown (it carries d-none while hidden)."""
    import re
    m = re.search(r'<div class="([^"]*)" id="%s">' % note_id, page)
    return None if m is None else "d-none" not in m.group(1)


def _all215(name, conds, detail=""):
    """check() over a list of conditions, so a check of several facts stays one branch."""
    check(name, all(conds), detail)


def _s215_settings():
    saved, live = {}, {k: _p9.config.get(k) for k in ("PERMANENT_SESSION_LIFETIME", "SESSION_ABSOLUTE_SECONDS",
                                                       "REMEMBER_COOKIE_DURATION", "SESSION_PROTECTION",
                                                       "REQUIRE_2FA")}
    try:
        import panel.routes.admin_notifications as _an215
        _p9_patch(_an215, "update_config", lambda mutate: mutate(saved))
        _p9_patch(_an215, "load_config", lambda: dict(saved))
        saved.update({"session_idle_minutes": 20, "session_absolute_hours": 6})
        inside = _settings_page215()
        saved.update({"session_idle_minutes": 90, "session_absolute_hours": 12})
        outside = _settings_page215()
        r = _p9_client(P9_ADMIN).post("/settings/save", data={
            "session_idle_minutes": "45", "session_absolute_hours": "9", "remember_days": "5", "require_2fa": "on"})
        applied = (_p9.config.get("PERMANENT_SESSION_LIFETIME"), _p9.config.get("SESSION_ABSOLUTE_SECONDS"),
                   _p9.config.get("REQUIRE_2FA"))
        stored = dict(saved)
        # The save just put its own values in force: undo the two that would gate this admin's next
        # request (the 2FA switch, and "strong" session protection on a test client's session).
        _p9.config.update(REQUIRE_2FA=False, SESSION_PROTECTION=live["SESSION_PROTECTION"])
        rc = _p9_client(P9_ADMIN)
        refused = rc.post("/settings/save", data={"session_idle_minutes": "900", "session_absolute_hours": "8"})
        refused_said = _p9_flashes(rc)
        after = dict(saved)
    finally:
        _p9.config.update(live)
        _p9_restore_all()
    _all215("settings: the idle and absolute fields show the values in force with OWASP's ranges beside them",
          ['name="session_idle_minutes"' in inside,
              'value="20"' in inside,
              'value="6"' in inside,
              "OWASP: 15–30 min (2–5 for high-value panels)." in inside,
              "OWASP: 4–8 hours." in inside,
              "OWASP gives no number; keep it short." in inside], "")
    eq("settings: the 'Longer than OWASP recommends' notes follow the values (hidden inside the ranges, shown past)",
       (_note_shown215(inside, "s-idle-note"), _note_shown215(inside, "s-absolute-note"),
        _note_shown215(outside, "s-idle-note"), _note_shown215(outside, "s-absolute-note")),
       (False, False, True, True))
    _all215("settings: a save outside OWASP's ranges is not refused; the three values and the 2FA switch are "
          "stored, the old hours key dropped, and put in force at once",
          [r.status_code == 302,
              stored.get("session_idle_minutes") == 45,
              stored.get("session_absolute_hours") == 9,
              stored.get("remember_days") == 5,
              stored.get("require_2fa") is True,
              "session_lifetime_hours" not in stored,
              applied == (45 * 60, 9 * 3600, True)], repr((r.status_code, stored, applied)))
    _all215("settings: an idle timeout past the absolute limit is refused, says why, and nothing is written",
          [refused.status_code == 302,
              after == stored,
              any("cannot be longer than the absolute session limit" in m for m in refused_said)],
          repr((refused.status_code, after, refused_said)))


def _row_seen215(uid):
    with _p9.app_context():
        row = _US215.query.filter_by(user_id=uid).first()
        return None if row is None else row.last_seen


def _set_seen215(uid, ago):
    with _p9.app_context():
        row = _US215.query.filter_by(user_id=uid).first()
        row.last_seen = _now215() - _td215(seconds=ago)
        _db215.session.commit()


def _s215_polls():
    uid = _user215("p215_poll")
    live = _p9.config.get("PERMANENT_SESSION_LIFETIME")
    idle = 20 * 60
    _p9.config["PERMANENT_SESSION_LIFETIME"] = idle
    try:
        c, _r = _login215("p215_poll")
        _set_seen215(uid, idle - 60)
        before = _row_seen215(uid)
        bg = c.get("/api/auth/ping", headers=_BG215)
        kept = _row_seen215(uid)
        fg = c.get("/api/auth/ping", headers=_XHR215)
        moved = _row_seen215(uid)
        # A tab polling every few seconds with nobody at it: only polls, past the idle window.
        for _ in range(3):
            c.get("/api/auth/ping", headers=_BG215)
        _set_seen215(uid, idle + 300 + 5)
        ended = c.get("/api/auth/ping", headers=_BG215)
        row_left = _row_seen215(uid)
        later = [None]
        _p9_patch(_sc215, "time", _NS215(time=lambda: later[0] or _time215.time()))
        c2, _r = _login215("p215_poll")
        later[0] = _time215.time() + 400
        bg_cookie = c2.get("/api/auth/ping", headers=_BG215)
        fg_cookie = c2.get("/api/auth/ping", headers=_XHR215)
    finally:
        _p9.config["PERMANENT_SESSION_LIFETIME"] = live
        _p9_restore_all()
    check("idle: a background poll answers but leaves the login's last-seen time where it was",
          bg.status_code == 200 and kept == before, repr((bg.status_code, before, kept)))
    check("idle: ...while a request the person made moves it (control)",
          fg.status_code == 200 and moved is not None and before is not None and moved > before, repr((before, moved)))
    check("idle: a tab that only polls past the idle timeout is signed out (401) and its row is gone",
          ended.status_code == 401 and row_left is None, repr((ended.status_code, row_left)))
    eq("idle: a background poll never re-sends an old cookie; a use re-sends it (the timeout slides on use only)",
       ("Set-Cookie" in bg_cookie.headers, "session=" in fg_cookie.headers.get("Set-Cookie", "")), (False, True))


# ── 2. passwords ─────────────────────────────────────────────────────────────────────────────────
def _s215_password_rules():
    eq("passwords: 15 characters without 2FA, 8 with it; no composition rules; spaces and any script count",
       [_pp215("x" * 3 + "quiet lamp"), _pp215(_K215), _pp215(_K215_SHORT, has_mfa=True), _pp215("ñandú violeta río"),
        _pp215("short", has_mfa=True)],
       ["Password must be at least 15 characters, or 8 with two-factor authentication on.", None, None, None,
        "Password must be at least 8 characters."])
    common = ["P@ssw0rd2026!!!!", "Password123456789", "qwertyuiopasdfgh", "dragondragondragon",
              "sunshinefootball", "123456789012345", "aaaaaaaaaaaaaaaa", "1q2w3e4r5t6y7u8i", "Welcome2026!!!!!"]
    eq("passwords: the bundled screen refuses breach-list shapes (leetspeak, digits and symbols around a root, "
       "keyboard walks, repeats, two roots run together)", [p for p in common if not _common215(p)], [])
    eq("passwords: ...and passes long phrases of ordinary words and random strings (control)",
       [p for p in (_K215, _K215_NEW, "correct horse battery staple", "vX9#qL2!mT7@wR4z") if _common215(p)], [])
    eq("passwords: a password holding the username is refused",
       _pp215("p215_alice-gardens-blue", avoid=("p215_alice",)), "Password must not contain your username.")


def _s215_password_screen_cost():
    # A long run of symbols before letters made the screen's old edge regex backtrack: 2 s at 20 000
    # characters, quadratic, and a password may be a megabyte. Linear now: well under a second.
    hostile = "!#" * 25000 + "abc"          # 50 000 characters: the old regex took about 13 s here
    t0 = _time215.monotonic()
    verdict = _common215(hostile)
    took = _time215.monotonic() - t0
    check("passwords: the common-password screen takes well under a second on 50 000 symbols "
          "then letters (it backtracked quadratically)", took < 1.0 and verdict is False, "%.3fs %r" % (took, verdict))


def _change215(uid, new, code=None):
    data = {"current_password": _K215, "new_password": new, "confirm_password": new}
    if code:
        data["totp_code"] = code
    c = _p9_client(uid)
    r = c.post("/account/password", data=data)
    return r, _p9_flashes(c)


def _s215_password_routes():
    _reset215()
    plain = _user215("p215_plain")
    short, said = _change215(plain, "fourteen chars")
    _common, said_common = _change215(plain, "Password12345678")
    secret = _pyotp215.random_base32()
    mfa = _user215("p215_mfa", totp=secret)
    ok, said_ok = _change215(mfa, _K215_SHORT, code=_pyotp215.TOTP(secret).now())
    with _p9.app_context():
        changed = _auth215.check_password(_K215_SHORT, _db215.session.get(_U215, mfa).password_hash)
    check("passwords: the change route refuses 14 characters for an account without 2FA, saying the rule",
          short.status_code == 302 and any("at least 15 characters" in m for m in said), repr(said))
    check("passwords: ...and a common password, saying why", any("too common" in m for m in said_common), repr(said_common))
    check("passwords: an account with 2FA may choose 9 characters (the route passes its 2FA state)",
          ok.status_code == 302 and changed and any("has been changed" in m for m in said_ok), repr(said_ok))


# ── 3. per-account throttle ──────────────────────────────────────────────────────────────────────
def _fake_clock215(start):
    now = [start]
    _p9_patch(_ar215, "time", _NS215(time=lambda: now[0], sleep=_time215.sleep, monotonic=_time215.monotonic))
    return now


def _throttle_setup215():
    """A fresh p215_target, alerts collected in _NOTES215, and a fake clock: (first audit id, clock)."""
    _reset215()
    _user215("p215_target")
    _NOTES215.clear()
    _p9_patch(_nt215, "notify", lambda key, title, body="", **_kw: _NOTES215.append((key, body)))
    return _last_id215(), _fake_clock215(_time215.time())


def _s215_account_throttle():
    first, now = _throttle_setup215()
    try:
        tries = [_login215("p215_target", _K215_WRONG, ip="198.51.100.%d" % (10 + i))[1].status_code
                 for i in range(_ag215.ACCOUNT_SOFT_FAILS)]
        _c, paused = _login215("p215_target", _K215, ip="203.0.113.77")
        paused_text = paused.get_data(as_text=True)
        locks = _audits215("login_locked", first)
        notes = list(_NOTES215)
        # Any later failure for the name inside this pause (a wrong 2FA code reaches _login_fail too)
        # must not report the same lockout again.
        reported_again = _ag215.account_new_lockout("p215_target", now[0])
        _c, ghost = _login215("p215_nobody", _K215_WRONG, ip="203.0.113.78")
        now[0] += _ag215.LOCK_BASE + 1
        c_ok, back = _login215("p215_target", _K215, ip="203.0.113.79")
        with c_ok.session_transaction() as s:
            signed_in = bool(s.get("_user_id"))
        # One more failure inside the window: the next pause is twice as long.
        _login215("p215_target", _K215_WRONG, ip="198.51.100.40")
        now[0] += _ag215.LOCK_BASE + 1
        _c, still = _login215("p215_target", _K215, ip="203.0.113.80")
        now[0] += _ag215.LOCK_BASE + 1
        c_two, _r = _login215("p215_target", _K215, ip="203.0.113.81")
        with c_two.session_transaction() as s:
            second_in = bool(s.get("_user_id"))
    finally:
        _p9_restore_all()
        _reset215()
    _all215("throttle: ten wrong passwords from ten addresses pause the name: the right password is then refused "
          "with the address throttle's sentence, before any check",
          [tries == [200] * _ag215.ACCOUNT_SOFT_FAILS,
              "Too many failed attempts" in paused_text,
              paused.status_code == 200], repr((tries, paused_text[:0])))
    _all215("throttle: the lockout writes ONE audit row and ONE alert, naming the account",
          [len(locks) == 1,
              locks[0][0] == "p215_target",
              locks[0][2] is False,
              [k for k, _b in notes if k == "account_locked"] == ["account_locked"],
              "p215_target" in notes[0][1],
              reported_again == 0], repr((locks, notes, reported_again)))
    _all215("throttle: a name that does not exist is answered the same as one that does (no enumeration)",
          [ghost.status_code == 200,
              "Invalid username or password" in ghost.get_data(as_text=True)], "")
    _all215("throttle: after the pause the right password signs in (the lock is never permanent)",
          [signed_in,
              back.status_code == 302], repr(back.status_code))
    _all215("throttle: the next failure doubles the pause: refused after one base pause, signed in after two",
          ["Too many failed attempts" in still.get_data(as_text=True),
              second_in], repr(second_in))


def _s215_pause_table():
    t = 10 ** 6
    pauses = [_ag215._pause_end([t - 1] * (n - 1) + [t], t) - t for n in (9, 10, 11, 12, 14, 30)]
    eq("throttle: under ten recent failures no pause; then 1, 2, 4 and 16 minutes, capped at 15",
       pauses, [0 - t, 60, 120, 240, 900, 900])


def _s215_successes_not_counted():
    _reset215()
    _user215("p215_regular")
    ins = []
    for i in range(_ag215.ACCOUNT_SOFT_FAILS + 2):
        c, _r = _login215("p215_regular", ip="198.51.100.%d" % (120 + i))
        with c.session_transaction() as s:
            ins.append(bool(s.get("_user_id")))
    _reset215()
    eq("throttle: signing in correctly again and again never pauses the name (a success gives its slot back)",
       ins, [True] * (_ag215.ACCOUNT_SOFT_FAILS + 2))


def _s215_ip_day():
    _reset215()
    bucket = _auth215.throttle_key("203.0.113.90")
    t0 = _time215.time()
    for i in range(_ag215.IP_DAY_FAILS):
        _ag215.ip_day_note(bucket, t0 - 3600 + i)
    _c, r = _login215("p215_target", _K215, ip="203.0.113.90")
    other_c, other = _login215("p215_target", _K215, ip="203.0.113.91")
    with other_c.session_transaction() as s:
        other_in = bool(s.get("_user_id"))
    _reset215()
    check("throttle: an address with a day's worth of failures is refused even under the 5-minute limit",
          "Too many failed attempts" in r.get_data(as_text=True), "")
    check("throttle: ...and another address signs the same account in (control)", other_in, repr(other.status_code))


# ── 4. required 2FA ──────────────────────────────────────────────────────────────────────────────
def _s215_required_2fa():
    _reset215()
    admin = _user215("p215_sa", superadmin=True)
    term = _user215("p215_term", perms=(_auth215.USE_TERMINAL,))
    _NOTES215.clear()
    _p9_patch(_nt215, "notify", lambda key, title, body="", **_kw: _NOTES215.append((key, body)))
    was = _p9.config.get("REQUIRE_2FA")
    first = _last_id215()
    try:
        _p9.config["REQUIRE_2FA"] = True
        ca = _p9_client(admin)
        page = ca.get("/")
        api = ca.get("/api/auth/ping", headers=_XHR215)
        servers = ca.get("/api/account/sessions", headers=_XHR215)
        setup = ca.get("/account/2fa/enable")
        term_page = _p9_client(term).get("/")
        viewer = _p9_client(P9_VIEWER).get("/api/account/sessions", headers=_XHR215)
        _p9.config["REQUIRE_2FA"] = False
        off = _p9_client(admin).get("/api/account/sessions", headers=_XHR215)
    finally:
        _p9.config["REQUIRE_2FA"] = was
        _p9_restore_all()
    _all215("2fa required: a superadmin without 2FA is sent to set it up from any page",
          [page.status_code == 302,
              page.headers.get("Location", "").endswith("/account/2fa/enable")],
          repr((page.status_code, page.headers.get("Location"))))
    _all215("2fa required: ...an in-page call is refused with a code it can act on; the session probe still answers",
          [servers.status_code == 403,
              _p9_json(servers).get("error") == "2fa_setup_required",
              api.status_code == 200], repr((servers.status_code, _p9_json(servers), api.status_code)))
    _all215("2fa required: the setup page itself stays reachable (the last superadmin cannot be shut out)",
          [setup.status_code == 200,
              'name="totp_code"' in setup.get_data(as_text=True)], repr(setup.status_code))
    setup_html = setup.get_data(as_text=True)
    _all215("2fa required: ...offers Sign out instead of a Cancel that leads back to itself, and starts no "
            "host polls the gate can only refuse",
            ['action="/logout"' in setup_html, "Sign out instead" in setup_html,
             "window.OS_NAG = false" in setup_html, "window.LOCAL_HOST_ID = null" in setup_html,
             "window.LOCAL_HOST_CTL = false" in setup_html], repr(setup.status_code))
    _all215("2fa required: a terminal holder is covered; a viewer is not; with the switch off nobody is",
          [term_page.status_code == 302,
              viewer.status_code != 403,
              off.status_code != 403],
          repr((term_page.status_code, viewer.status_code, off.status_code)))
    rows = [r for r in _audits215("2fa_setup_required", first) if r[0] == "p215_sa"]
    _all215("2fa required: enforcement is audited and alerted once per session, naming only the account",
          [len(rows) == 1,
              [b for k, b in _NOTES215 if k == "twofa_enforced" and "p215_sa" in b] != [],
              len([1 for k, b in _NOTES215 if k == "twofa_enforced" and "p215_sa" in b]) == 1], repr((rows, _NOTES215)))


# ── 5. step-up ───────────────────────────────────────────────────────────────────────────────────
def _age_proof215(client, seconds):
    with client.session_transaction() as s:
        s["_auth_at"] = _time215.time() - seconds


def _s215_step_up():
    _reset215()
    _user215("p215_step", superadmin=True)
    first = _last_id215()
    c, _r = _login215("p215_step")
    fresh = c.post("/groups/add", data={"name": "p215-fresh"}, headers=_XHR215)
    _age_proof215(c, 11 * 60)
    stale = c.post("/groups/add", data={"name": "p215-stale"}, headers=_XHR215)
    nav = c.post("/groups/add", data={"name": "p215-stale"}, headers={"Referer": "http://localhost/groups"})
    term = c.get("/terminal/%d" % P9_HOST)
    wrong = c.post("/account/reauth", data={"password": _K215_WRONG, "next": "/groups"})
    right = c.post("/account/reauth", data={"password": _K215, "next": "/groups"})
    again = c.post("/groups/add", data={"name": "p215-again"}, headers=_XHR215)
    with _p9.app_context():
        made = sorted(g.name for g in _G215.query.filter(_G215.name.like("p215-%")).all())
    _all215("step-up: a fresh sign-in may change groups at once",
          [fresh.status_code == 200,
              _p9_json(fresh).get("error") != "reauth_required"], repr(_p9_json(fresh)))
    _all215("step-up: after the window an in-page change is refused with reauth_required and nothing is made",
          [stale.status_code == 403,
              _p9_json(stale).get("error") == "reauth_required",
              "p215-stale" not in made], repr((stale.status_code, made)))
    _all215("step-up: a form post or the terminal page is sent to the confirm page, coming back where it was",
          [nav.status_code == 302,
              "/account/reauth?next=%2Fgroups" in nav.headers.get("Location", ""),
              term.status_code == 302,
              ("next=%2Fterminal%2F" + str(P9_HOST)) in term.headers.get("Location", "")],
          repr((nav.headers.get("Location"), term.headers.get("Location"))))
    _all215("step-up: a wrong password does not confirm and is audited; the right one does and goes back",
          [wrong.status_code == 200,
              right.status_code == 302,
              right.headers.get("Location", "").endswith("/groups"),
              [r[2] for r in _audits215("reauth", first)] == [False, True]], repr(_audits215("reauth", first)))
    _all215("step-up: ...after which the change goes through", [again.status_code == 200,
              "p215-again" in made],
          repr((again.status_code, made)))


def _s215_step_up_rules():
    from flask import session as _flask_session
    results = {}
    with _p9.test_request_context("/", headers={"Authorization": "Bearer x"}):
        results["bearer"] = _ag215.step_up_needed()
    for label, data in (("fresh-legacy", {"_fresh": True}), ("remembered", {"_fresh": False}),
                        ("recent", {"_auth_at": _time215.time() - 60}), ("old", {"_auth_at": _time215.time() - 3600})):
        with _p9.test_request_context("/"):
            _flask_session.update(data)
            results[label] = _ag215.step_up_needed()
    eq("step-up: an API token is exempt; a remember-me restore and an old proof need it; a recent proof or a "
       "pre-upgrade password session do not",
       results, {"bearer": False, "fresh-legacy": False, "remembered": True, "recent": False, "old": True})


def _s215_terminal_socket():
    _reset215()
    _p9_arm(who="part215")
    _p9_patch(_ht215._ts, "open_session", lambda sid, remote, is_local, **k: None)
    c, _r = _login215("p215_step")
    _age_proof215(c, 11 * 60)
    sio = _p9.socketio.test_client(_p9, flask_test_client=c)
    try:
        sio.emit("term_open", {"remote_id": P9_HOST, "cols": 80, "rows": 24})
        got = sio.get_received()
    finally:
        sio.disconnect()
        _p9_restore_all()
    errs = [e["args"][0].get("message", "") for e in got if e["name"] == "term_error"]
    check("step-up: a terminal opened over the socket with a stale proof is refused and told to reload",
          any("Confirm your password to open a terminal" in m for m in errs)
          and not [e for e in got if e["name"] == "term_ready"], repr(got))


# ── 6. notices, logging and sessions ─────────────────────────────────────────────────────────────
def _s215_notices():
    _reset215()
    uid = _user215("p215_note")
    c, _r = _login215("p215_note")
    with _p9.app_context():
        u = _db215.session.get(_U215, uid)
        u.last_login = _now215() - _td215(hours=1)
        _db215.session.commit()
    _NOTES215.clear()
    _p9_patch(_nt215, "notify", lambda key, title, body="", **_kw: _NOTES215.append((key, body)))
    try:
        r = c.post("/account/api-token/generate", data={"password": _K215, "expires_days": "30"})
        with _p9.app_context():
            exp = _db215.session.get(_U215, uid).api_token_expires
        page = c.get("/account").get_data(as_text=True)
        c2, _r = _login215("p215_note", ip="198.51.100.216")
        said = _p9_flashes(c2)
    finally:
        _p9_restore_all()
    _all215("api token: a new token gets the chosen expiry (30 days)",
          [r.status_code == 200,
              exp is not None,
              _td215(days=29) < exp - _now215() <= _td215(days=30)],
          repr((r.status_code, exp)))
    _all215("notices: the Account page lists the change, when and from where, with the 'Wasn't you?' pointer",
          ["Recent security changes" in page,
              "New API token created" in page,
              "198.51.100.215" in page,
              "Wasn't you?" in page], "")
    _all215("notices: the next sign-in says what changed, when and from which address, then the pointer",
          [any(m.startswith("Since you last signed in: a new API token was created (") and "198.51.100.215" in m for m in said),
              any(m.startswith("Wasn't you?") for m in said)], repr(said))
    check("notices: a plain user's change sends no panel-wide alert (admin-level events only)",
          [k for k, _b in _NOTES215 if k == "credential_change"] == [], repr(_NOTES215))


def _s215_token_expiry():
    uid = _user215("p215_tok")
    with _p9.app_context():
        u = _db215.session.get(_U215, uid)
        tok = u.generate_api_token()
        u.api_token_expires = _now215() - _td215(minutes=1)
        _db215.session.commit()
    expired = _p9.test_client().get("/api/auth/ping", headers={"Authorization": "Bearer " + tok})
    with _p9.app_context():
        _db215.session.get(_U215, uid).api_token_expires = _now215() + _td215(days=1)
        _db215.session.commit()
    live = _p9.test_client().get("/api/auth/ping", headers={"Authorization": "Bearer " + tok})
    eq("api token: an expired token is refused; one inside its lifetime works (control)",
       (expired.status_code, live.status_code), (401, 200))


def _s215_denials():
    _reset215()
    first = _last_id215()
    v = _p9_client(P9_VIEWER)
    for _ in range(5):
        v.get("/users", headers=_XHR215)
    rows = _audits215("access_denied", first)
    _ag215.reset_denials()
    from flask_wtf.csrf import CSRFError
    hook = _p9.error_handler_spec[None][400].get(CSRFError)
    with _p9.test_request_context("/api/servers", method="POST"):
        resp = hook(CSRFError("The CSRF token is missing.")) if hook else None
    csrf_rows = _audits215("csrf_rejected", first)
    check("logging: a 403 is audited as access_denied, once for five repeats (rate-limited)",
          len(rows) == 1 and rows[0][0] == "p9_viewer" and rows[0][2] is False, repr(rows))
    check("logging: a CSRF failure is audited as csrf_rejected and still answered 400 in the viewer's words",
          resp is not None and resp[1] == 400 and len(csrf_rows) == 1, repr((resp, csrf_rows)))


def _s215_denial_log_line():
    import logging as _logging215
    seen = []
    handler = _logging215.Handler()
    handler.emit = lambda rec: seen.append(rec.getMessage())
    _ag215._log.addHandler(handler)
    _ag215.reset_denials()
    try:
        with _p9.test_request_context("/no-such-page%0D%0AFAKE-line", method="POST",
                                      headers={"X-Forwarded-For": "203.0.113.5 FAKE-line"},
                                      environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            _ag215.note_denial("access_denied", detail="unit")
    finally:
        _ag215._log.removeHandler(handler)
        _ag215.reset_denials()
    lines = [m for m in seen if m.startswith("refused (")]     # the address parser logs its own note
    check("logging: the panel-log line for a refusal holds nothing the client wrote (no path, no header text)",
          len(lines) == 1 and "FAKE" not in lines[0] and "\n" not in lines[0] and "(no route)" in lines[0], repr(seen))


def _s215_binding():
    _reset215()
    uid = _user215("p215_bind")
    first = _last_id215()
    was = _p9.config.get("SESSION_PROTECTION")
    _p9.config["SESSION_PROTECTION"] = "strong"
    _ag215.reset_denials()      # earlier parts' refusals count toward the per-minute audit cap
    try:
        c, _r = _login215("p215_bind", ip="198.51.100.30")
        c.environ_base["REMOTE_ADDR"] = "203.0.113.31"
        moved = c.get("/api/auth/ping", headers=_XHR215)
        c.get("/api/auth/ping", headers=_XHR215)
    finally:
        _p9.config["SESSION_PROTECTION"] = was
    rows = _audits215("session_binding_mismatch", first)
    check("logging: a session replayed from another address is refused and audited once (rate-limited)",
          moved.status_code == 401 and len(rows) == 1 and rows[0][0] == "p215_bind", repr((moved.status_code, rows)))
    # A login from before per-device sessions ("<id>:<epoch>", no row) bound to another client.
    legacy = _user215("p215_bind_old")
    first = _last_id215()
    _p9.config["SESSION_PROTECTION"] = "strong"
    _ag215.reset_denials()
    try:
        with _p9.app_context():
            # Fresh from the database: SQLite hands a deleted row's id to the next account, and a
            # cached copy of the old one would carry its epoch (the cookie would then be stale for a
            # reason this check is not about).
            _db215.session.expire_all()
            epoch = _db215.session.get(_U215, legacy).auth_epoch or 0
        c = _p9.test_client()
        with c.session_transaction() as s:
            # Permanent, as every panel login is: flask-login's own "strong" mode would otherwise
            # wipe a non-permanent session before load_user runs, and this check would pass on
            # that instead of on the panel's binding check.
            s.permanent = True
            s["_user_id"], s["_fresh"], s["_bind"] = "%d:%d" % (legacy, epoch), True, "0" * 32
        old = c.get("/api/auth/ping", headers=_XHR215)
    finally:
        _p9.config["SESSION_PROTECTION"] = was
    rows = _audits215("session_binding_mismatch", first)
    check("logging: ...and so is a login with no session row bound to another client",
          old.status_code == 401 and [r[0] for r in rows] == ["p215_bind_old"], repr((old.status_code, rows, epoch)))
    return uid


def _s215_rotation_and_logout():
    _reset215()
    uid = _user215("p215_rot")
    c1, _r = _login215("p215_rot", ip="198.51.100.41")
    c2, _r = _login215("p215_rot", ip="198.51.100.42")
    with c2.session_transaction() as s:
        before = s.get("_user_id")
    c2.get("/account/2fa/enable")
    with c2.session_transaction() as s:
        secret = _sh215.decrypt_secret(s.get("_2fa_setup_secret", "")) if hasattr(_sh215, "decrypt_secret") else None
    if secret is None:
        from panel.core.config import decrypt_secret
        with c2.session_transaction() as s:
            secret = decrypt_secret(s.get("_2fa_setup_secret", ""))
    on = c2.post("/account/2fa/enable", data={"password": _K215, "totp_code": _pyotp215.TOTP(secret).now()})
    with c2.session_transaction() as s:
        after = s.get("_user_id")
    other = c1.get("/api/auth/ping", headers=_XHR215)
    here = c2.get("/api/auth/ping", headers=_XHR215)
    out = c2.post("/logout")
    check("sessions: turning 2FA on gives this device a new session id and signs the others out",
          on.status_code == 200 and before != after and other.status_code == 401 and here.status_code == 200,
          repr((on.status_code, before, after, other.status_code, here.status_code)))
    check("sessions: logout sends Clear-Site-Data for cookies and storage (not cache), and says so on the login page",
          out.headers.get("Clear-Site-Data") == '"cookies", "storage"'
          and out.headers.get("Location", "").endswith("/login?signed_out=1")
          and "You have been logged out." in c2.get("/login?signed_out=1").get_data(as_text=True),
          repr(dict(out.headers)))
    return uid


def _s215_fetch_metadata():
    _reset215()
    first = _last_id215()
    a = _p9_client(P9_ADMIN)
    cross = a.post("/api/account/ui-order/reset", headers={"Sec-Fetch-Site": "cross-site", **_XHR215})
    same = a.post("/api/account/ui-order/reset", headers={"Sec-Fetch-Site": "same-origin", **_XHR215})
    none = a.post("/api/account/ui-order/reset", headers=_XHR215)
    get = a.get("/api/auth/ping", headers={"Sec-Fetch-Site": "cross-site", **_XHR215})
    rows = _audits215("csrf_rejected", first)
    eq("fetch metadata: a cross-site POST is refused; same-origin, a client without the header and a cross-site "
       "GET pass", (cross.status_code, same.status_code, none.status_code, get.status_code), (403, 200, 200, 200))
    check("fetch metadata: the refusal is audited once as csrf_rejected (no second access_denied row)",
          len(rows) == 1 and _audits215("access_denied", first) == [], repr(rows))


# ── 7. Tailscale Serve: change the path in one step; Disable warns from a Serve page ─────────────
def _serve_rig215(add_ok=True, shown=True, host_dns="panel-box.tail-p215.ts.net"):
    """Stub the Serve layer for the change-path and disable routes; the call log, in order."""
    from panel.ops import tailscale_integration as _tsi
    from panel.routes import tailscale as _rts
    log, cfg = [], {"tailscale_setup_done": True, "tailscale_mount": "/lgsm", "tailscale_use_funnel": False}
    _p9_patch(_rts, "load_config", lambda: dict(cfg))
    _p9_patch(_rts, "set_config_keys", lambda c, **kw: (cfg.update(kw), log.append(("config", kw))))
    _p9_patch(_rts, "_serve_scheme_now", lambda c, conf: "http")
    _p9_patch(_rts, "_disable_would_strand_panel", lambda c: "")
    _p9_patch(_tsi, "setup_tailscale_serve",
              lambda **kw: (log.append(("add", kw["mount"])) or (add_ok, "Tailscale Serve enabled" if add_ok else "boom")))
    _p9_patch(_tsi, "get_tailscale_info", lambda force_refresh=False: _tsi.TailscaleInfo(
        installed=True, running=True, backend_state="Running", dns_name=host_dns + ".", serve_config={}))
    _p9_patch(_tsi, "panel_route", lambda conf, port, mount, scheme: (
        {"url": "https://" + host_dns, "mount": mount} if shown else None))
    _p9_patch(_tsi, "route_url", lambda r: r["url"] + r["mount"])
    _p9_patch(_rts, "_remove_serve_leftovers", lambda port, mount, where, audit: (log.append(("remove-old", mount)),
                                                                                 "removed:/lgsm")[1])
    _p9_patch(_tsi, "disable_tailscale_serve", lambda **kw: (log.append(("disable", kw)), (True, "Serve off"))[1])
    return log, cfg


def _s215_serve_path():
    first = _last_id215()
    a = _p9_client(P9_ADMIN)
    results = {}
    for label, kw in (("ok", {}), ("add-fails", {"add_ok": False}), ("not-shown", {"shown": False})):
        try:
            log, cfg = _serve_rig215(**kw)
            r = a.post("/api/tailscale/serve", json={"action": "change-mount", "mount": "/panel", "page": ""})
            results[label] = (r.status_code, _p9_json(r), list(log), dict(cfg))
        finally:
            _p9_restore_all()
    st, body, log, cfg = results["ok"]
    _all215("serve path: the new mount is published, then confirmed, and only then the old one removed; the config "
          "follows and the answer names the new address",
          [st == 200,
              [e[0] for e in log] == ["add", "config", "remove-old"],
              log[0][1] == "/panel",
              cfg["tailscale_mount"] == "/panel",
              "https://panel-box.tail-p215.ts.net/panel" in body.get("message", "")],
          repr(results["ok"]))
    for label in ("add-fails", "not-shown"):
        st, body, log, cfg = results[label]
        _all215("serve path: when %s, the old mount is left untouched and the config unchanged" % label,
              [st == 500,
                  "remove-old" not in [e[0] for e in log],
                  cfg["tailscale_mount"] == "/lgsm"],
              repr(results[label]))
    rows = _audits215("tailscale_serve_change_path", first)
    check("serve path: each attempt is audited, failures as failures",
          [r[2] for r in rows] == [True, False, False], repr(rows))
    viewer = _p9_client(P9_VIEWER).post("/api/tailscale/serve", json={"action": "change-mount", "mount": "/x"})
    check("serve path: superadmin-only, like the rest of Serve", viewer.status_code in (302, 401, 403),
          repr(viewer.status_code))


def _s215_serve_disable_warning():
    out = {}
    # The test client is at "localhost": a node whose ts.net name is that is one this page came through.
    for label, dns, data in (("via-serve", "localhost", {}), ("via-serve-confirmed", "localhost", {"confirm": True}),
                             ("direct", "panel-box.tail-p215.ts.net", {})):
        try:
            log, _cfg = _serve_rig215(host_dns=dns)
            r = _p9_client(P9_ADMIN).post("/api/tailscale/serve", json=dict({"action": "disable", "mount": "/lgsm"}, **data))
            out[label] = (r.status_code, _p9_json(r), [e[0] for e in log])
        finally:
            _p9_restore_all()
    check("serve disable: from a page that came through Serve, an unconfirmed disable is refused with the plain warning",
          out["via-serve"][0] == 409 and out["via-serve"][1].get("needs_confirm") is True
          and "ends this connection" in out["via-serve"][1].get("message", "") and out["via-serve"][2] == [],
          repr(out["via-serve"]))
    eq("serve disable: ...confirmed, it runs; reached directly, it runs with no extra step (control)",
       (out["via-serve-confirmed"][2], out["direct"][2]), (["disable", "config"], ["disable", "config"]))
    try:
        _serve_rig215(host_dns="localhost")
        _pr215 = _p9_client(P9_ADMIN).get("/tailscale")
        page = _pr215.get_data(as_text=True)
    finally:
        _p9_restore_all()
    check("serve disable: the page marks its Disable as reached through Serve, and offers Change path",
          'data-via-serve="1"' in page and 'data-action="changeServePath"' in page,
          repr((_pr215.status_code, page[:200])))


try:
    _p9_arm(who="part215")
    for _fn215 in (_s215_policy, _s215_settings, _s215_polls, _s215_password_rules,
                   _s215_password_screen_cost, _s215_password_routes,
                   _s215_account_throttle, _s215_pause_table, _s215_successes_not_counted, _s215_ip_day,
                   _s215_required_2fa, _s215_step_up, _s215_step_up_rules,
                   _s215_terminal_socket, _s215_notices, _s215_token_expiry, _s215_denials, _s215_denial_log_line, _s215_binding,
                   _s215_rotation_and_logout, _s215_fetch_metadata, _s215_serve_path,
                   _s215_serve_disable_warning):
        _p9_arm(who="part215")
        try:
            _fn215()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()
    _reset215()
    with _p9.app_context():
        for _uid215 in _IDS215:
            _US215.query.filter_by(user_id=_uid215).delete()
            _u215 = _db215.session.get(_U215, _uid215)
            if _u215 is not None:
                for _g215 in list(_u215.groups):
                    _db215.session.delete(_g215)
                _db215.session.delete(_u215)
        for _g215 in _G215.query.filter(_G215.name.like("p215-%")).all():
            _db215.session.delete(_g215)
        _db215.session.commit()

check("part215: nothing reached a real transport", len(_P9_TRIPPED) == _trips215, repr(_P9_TRIPPED[_trips215:]))
