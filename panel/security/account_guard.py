"""Sign-in hardening: per-account throttling, required 2FA, step-up re-authentication, denial logging.

Each part names the OWASP cheat sheet section it follows (read 2026-11-15).

* Per-account throttle (Authentication Cheat Sheet, "Login Throttling" / "Account Lockout"; Credential
  Stuffing Prevention Cheat Sheet). /login already limits each address (8 failures in 5 minutes);
  failures are now also counted per USERNAME, so a spray from many addresses meets a limit too: after
  ACCOUNT_SOFT_FAILS failures in ACCOUNT_WINDOW the name is paused for LOCK_BASE seconds, doubling with
  each further failure up to LOCK_MAX ("exponential backoff", never a permanent lockout), and
  ACCOUNT_DAY_FAILS in a day pause it for LOCK_MAX after every failure (low-and-slow guessing). An
  address gets a day limit as well (IP_DAY_FAILS). Any name is counted, real or not, and the refusal
  is the address throttle's own sentence, so nothing tells an account that exists from one that does
  not. One audit row (`login_locked`, the vocabulary's authn_login_lock) and one alert per lockout.
  The pause holds only browsers the account has not signed in from: one with a valid device cookie
  (device_cookie, OWASP "Slow Down Online Guessing Attacks with Device Cookies") is counted on its
  own, so a slow trickle of wrong guesses at a name cannot keep its owner out.
* Required 2FA (Multifactor Authentication Cheat Sheet, "Quick Recommendations": require MFA for
  administrative users). With Settings' switch on, a superadmin or anyone allowed the terminal, users
  or groups who has no 2FA is sent to set it up right after the password and can do nothing else.
* Step-up (Session Management Cheat Sheet, "Reauthentication After Risk Events"; Transaction
  Authorization Cheat Sheet, 2.9 "Authorization credentials should only be valid during a limited
  time period"). Opening a terminal, uninstalling a server, restoring a panel backup, changing users
  or groups and saving Settings or Notifications (which can switch step-up itself off) ask for the
  password (and the code, with 2FA) again once the last sign-in or confirmation is older than
  step_up_minutes (Settings, default 10; panel/core/session_policy.py), then not again for that
  long. API tokens are exempt: minting one already takes the password and the code, it can be given
  an expiry, and it is revoked by a password change or "sign out everywhere". The chat bots never
  reach these routes.
* Denials are logged (Logging Cheat Sheet, "Which events to log": authorization, session management
  and CSRF failures; Logging Vocabulary: authz_fail, malicious_csrf): one audit row per kind, user or
  address and route every DENIAL_EVERY seconds, at most DENIAL_BURST a minute in all, so a client that
  loops on a refused request cannot flood the log ("Ensure logging cannot be used to deplete system
  resources").
"""
import logging
import re
import threading
import time
from collections import deque
from functools import wraps
from urllib.parse import quote, urlsplit

from flask import current_app, g, has_request_context, jsonify, redirect, request, session, url_for
from flask_login import current_user

from panel.core.session_policy import STEP_UP_DEFAULT_MINUTES

_log = logging.getLogger("panel.app")

# ── Per-account sign-in throttle ──────────────────────────────────────────────────────────────────
ACCOUNT_SOFT_FAILS = 10       # more than the address limit (8), so one address meets its own first
ACCOUNT_WINDOW = 15 * 60
ACCOUNT_DAY_FAILS = 50
DAY_WINDOW = 24 * 3600
LOCK_BASE = 60
LOCK_MAX = 15 * 60
IP_DAY_FAILS = 100
_MAX_KEYS = 20000             # names and addresses held at once; the oldest goes first past this
_FAILS = {}                   # "u:<name>" / "d:<device>" / "ip:<bucket>" -> deque of failure (or in-flight) times
_NOTED = {}                   # "u:<name>" / "d:<device>" -> the pause end already audited (one row per lockout)
_LOCK = threading.Lock()


def _dkey(device):
    """The throttle key for a browser holding a valid device cookie: its nonce."""
    return "d:" + device


def _ukey(username):
    """The throttle key for a submitted name: case-folded, so Admin and admin share one count."""
    from panel.core.validation import MAX_USERNAME_LEN
    return "u:" + (username or "").strip()[:MAX_USERNAME_LEN].casefold()


def _prune(now):
    """Drop counts older than a day, then the oldest keys past _MAX_KEYS. Call under _LOCK."""
    for k in [k for k, v in _FAILS.items() if not v or now - v[-1] >= DAY_WINDOW]:
        del _FAILS[k]
        _NOTED.pop(k, None)
    while len(_FAILS) > _MAX_KEYS:
        oldest = min(_FAILS, key=lambda k: _FAILS[k][-1])
        del _FAILS[oldest]
        _NOTED.pop(oldest, None)


def _pause_end(fails, now):
    """When the name with these failure times may try again (<= now: it may)."""
    if not fails:
        return 0
    recent = sum(1 for t in fails if now - t < ACCOUNT_WINDOW)
    day = sum(1 for t in fails if now - t < DAY_WINDOW)
    if recent >= ACCOUNT_SOFT_FAILS:
        pause = min(LOCK_MAX, LOCK_BASE * 2 ** (recent - ACCOUNT_SOFT_FAILS))
    elif day >= ACCOUNT_DAY_FAILS:
        pause = LOCK_MAX
    else:
        return 0
    return fails[-1] + pause


def account_reserve(username, now, device=None):
    """Count one password attempt for `username`; (slot, 0), or (None, seconds left) while paused.

    `device` is the nonce of a valid device cookie for that account (device_cookie.presented_nonce).
    Such a browser's attempt is counted against the browser instead of the name, and the name's pause
    does not hold it; a browser that is itself paused counts as an unknown one, held by the name.
    Reserved before the hash runs, as the address throttle does, so a parallel burst cannot all read
    "under the limit"; account_release gives the slot back for an attempt that did not fail.
    """
    key = _ukey(username)
    with _LOCK:
        _prune(now)
        if device and _pause_end(_FAILS.get(_dkey(device)), now) <= now:
            key = _dkey(device)
        fails = _FAILS.get(key)
        end = _pause_end(fails, now) if fails else 0
        if end > now:
            return None, int(end - now) + 1
        _FAILS.setdefault(key, deque(maxlen=ACCOUNT_DAY_FAILS * 2)).append(now)
        return (key, now), 0


def account_release(slot):
    """Give back a slot account_reserve handed out, for an attempt that did not fail."""
    key, stamp = slot
    with _LOCK:
        fails = _FAILS.get(key)
        if fails and stamp in fails:
            fails.remove(stamp)
            if not fails:
                _FAILS.pop(key, None)


def is_device_slot(slot):
    """Whether account_reserve counted this attempt against a known browser rather than the name."""
    return bool(slot) and slot[0].startswith("d:")


def account_new_lockout(username, now, slot=None):
    """After a failure: the pause it started, in seconds, when it started one not yet reported; else 0.

    `slot` is the attempt's account_reserve slot when there was one: a known browser's failure pauses
    that browser, not the name.
    """
    key = slot[0] if slot else _ukey(username)
    with _LOCK:
        end = _pause_end(_FAILS.get(key), now)
        if end <= now or _NOTED.get(key) == end:
            return 0
        _NOTED[key] = end
        return int(end - now)


def ip_day_blocked(bucket, now):
    """Whether the address bucket has failed IP_DAY_FAILS sign-ins in the last day."""
    with _LOCK:
        fails = _FAILS.get("ip:%s" % bucket)
        return bool(fails) and sum(1 for t in fails if now - t < DAY_WINDOW) >= IP_DAY_FAILS


def ip_day_note(bucket, now):
    """Count one failed sign-in against the address bucket's day limit."""
    with _LOCK:
        _prune(now)
        _FAILS.setdefault("ip:%s" % bucket, deque(maxlen=IP_DAY_FAILS)).append(now)


def reset_throttle():
    """Forget every count (tests, and the recovery CLI)."""
    with _LOCK:
        _FAILS.clear()
        _NOTED.clear()


# ── Required 2FA ──────────────────────────────────────────────────────────────────────────────────
# Reachable while 2FA setup is required: the setup page and the form it posts to, signing out, the
# page's own language switcher and the session probe.
TWOFA_GATE_OPEN = frozenset(("account_2fa_enable", "logout", "account_signout", "set_language", "api_i18n_catalog",
                             "api_auth_ping", "healthz", "static", "force_password_change",
                             "account_change_password"))


def twofa_required(user):
    """Whether `user` must set up 2FA before using the panel (Settings' switch, see the module note)."""
    if getattr(user, "totp_enabled", True):
        return False
    # A customer (a member of a customer group) must, while Settings' "Require 2FA for customers"
    # is on (the default; OWASP Multifactor Authentication Cheat Sheet: MFA for every user is the
    # recommended option). A customer group's members reach other people's hosting.
    if current_app.config.get("WEBSITES_CUSTOMER_2FA", True) and _in_customer_group(user):
        return True
    if not current_app.config.get("REQUIRE_2FA"):
        return False
    # A superadmin's permissions are all of them (get_user_permissions), so this covers superadmins.
    from panel.security.auth import MANAGE_GROUPS, MANAGE_USERS, USE_TERMINAL, get_user_permissions
    return bool(get_user_permissions(user) & {USE_TERMINAL, MANAGE_USERS, MANAGE_GROUPS})


def _in_customer_group(user):
    """Whether `user` belongs to a customer group (Group.is_customer)."""
    return any(getattr(g, "is_customer", False) for g in (getattr(user, "groups", None) or []))


def held_at_sign_in_gate(user):
    """Whether `user` is held at a sign-in gate: a handed-over password to change, or 2FA to set up.

    The two gates are before_request hooks (app.py's password-change gate and twofa_gate below), and
    a before_request never runs for a Socket.IO event: flask-socketio takes /socket.io/ ahead of the
    Flask app. So every socket path asks this instead (the connect handler, join_console, term_open
    and the terminal's other events, and the console and terminal sweeps), with the same predicates
    the hooks use. Without it an account held at 2FA setup opened a terminal or a console with its
    password alone.
    """
    return bool(getattr(user, "must_change_password", False) or twofa_required(user))


def twofa_gate():
    """before_request: send an account that must set up 2FA to the setup page; None to go on."""
    if not getattr(current_user, "is_authenticated", False) or not twofa_required(current_user):
        return None
    g._twofa_gate = True            # the setup page is drawn without the app's chrome
    _note_enforced(current_user)
    if (request.endpoint or "") in TWOFA_GATE_OPEN:
        return None
    from panel.core import i18n
    from panel.security.auth import _denial_wants_json
    if _denial_wants_json():
        resp = jsonify({"success": False, "error": "2fa_setup_required",
                        "message": i18n.tr("Set up two-factor authentication before using the panel.")})
        resp.status_code = 403
        resp.headers["X-2FA-Setup-Required"] = "1"
        return resp
    return redirect(url_for("account_2fa_enable"))


def _note_enforced(user):
    """Once per session: audit (2fa_setup_required) and alert that 2FA setup is being required.

    Not for an API token's request: it has no session to remember the note in, so every call would
    write one (the gate still refuses it).
    """
    if session.get("_2fa_enforced") or _bearer():
        return
    session["_2fa_enforced"] = True
    from panel.security.auth import log_action
    from panel.services import notifications
    log_action(user, "2fa_setup_required", target=user.username,
               detail="signed in without two-factor authentication; sent to set it up")
    notifications.notify("twofa_enforced", "Two-factor setup required",
                         "%s signed in without two-factor authentication and must set it up first."
                         % user.username)


# ── Step-up re-authentication (STEP_UP_DEFAULT_MINUTES: session_policy) ───────────────────────────
def mark_authenticated(now=None):
    """Record that this session's holder has just proved who they are (sign-in or confirmation)."""
    session["_auth_at"] = time.time() if now is None else now


def _bearer():
    """True only for a request an API token signed in: a Bearer header and NO browser session cookie.

    A header alone is not enough: flask-login signs a request in from its session (or remember)
    cookie first, so a cookie-borne session with an added "Authorization: Bearer x" header is still
    the browser session, and must not skip step-up or the required-2FA gate. The same condition the
    CSRF and Origin checks exempt on (account_security._cookie_less_bearer).
    """
    if not request.headers.get("Authorization", "").startswith("Bearer "):
        return False
    names = (current_app.config["SESSION_COOKIE_NAME"],
             current_app.config.get("REMEMBER_COOKIE_NAME", "remember_token"))
    return not any(request.cookies.get(n) for n in names)


def step_up_needed():
    """Whether this request must confirm the password again before a high-risk action.

    The time of the last proof is the session's _auth_at (set at sign-in and on confirming). A session
    signed in before it existed has none: its server-side row's sign-in time stands in, and a session
    with no row is one flask-login marks fresh (a password sign-in, not a "remember me" restore) or not.
    """
    window = current_app.config.get("STEP_UP_MINUTES", STEP_UP_DEFAULT_MINUTES)
    if not window or window <= 0 or _bearer():
        return False
    at = session.get("_auth_at")
    if at is None:
        at = _row_signed_in_at()
        if at is None:
            return not session.get("_fresh", False)
    return time.time() - float(at) > window * 60


def _row_signed_in_at():
    """The sign-in time (epoch seconds) of this session's server-side row, or None without one."""
    sid = getattr(current_user, "_sid", None)
    if not sid:
        return None
    from panel.db.models import UserSession
    row = UserSession.query.filter_by(sid=sid, user_id=current_user.id).first()
    if row is None or row.created_at is None:
        return None
    from calendar import timegm
    return float(timegm(row.created_at.timetuple()))


def step_up_refusal():
    """The answer to a high-risk request whose last proof is too old: a JSON 403 or the confirm page."""
    from panel.core import i18n
    from panel.security.auth import _denial_wants_json
    if _denial_wants_json():
        resp = jsonify({"success": False, "error": "reauth_required",
                        "message": i18n.tr("Confirm your password to continue.")})
        resp.status_code = 403
        resp.headers["X-Reauth-Required"] = "1"
        return resp
    back = request.full_path if request.method == "GET" else (urlsplit(request.referrer or "").path or "/")
    return redirect(url_for("account_reauth") + "?next=" + quote(safe_next(back), safe=""))


def step_up_required(f):
    """Decorator (after login_required and the permission check): a recent proof for a high-risk route."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if getattr(current_user, "is_authenticated", False) and step_up_needed():
            return step_up_refusal()
        return f(*args, **kwargs)
    wrapped._step_up = True
    return wrapped


def step_up_required_to_change(f):
    """Decorator: step_up_required for a route that also answers GET, asked only by its changing methods."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if (request.method not in ("GET", "HEAD") and getattr(current_user, "is_authenticated", False)
                and step_up_needed()):
            return step_up_refusal()
        return f(*args, **kwargs)
    wrapped._step_up = True
    return wrapped


def rotate_sessions(user):
    """Sign every session of `user` out and re-admit this device with a new identifier. -> bool.

    For a privilege-level change (2FA on or off): Session Management Cheat Sheet, "Renew the Session
    ID After Any Privilege Level Change". The epoch bump ends every cookie ever issued, the rows go,
    and this device gets a fresh row and cookie, "remember me" carried over. False when this device
    could not be registered again: it is then signed out too, and the caller says so.
    """
    from flask_login import login_user, logout_user
    from panel.db.models import UserSession, db
    from panel.routes.tags import _remember_this_device, _reregister_session
    remember = _remember_this_device(user)
    user.auth_epoch = (user.auth_epoch or 0) + 1
    UserSession.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    if not _reregister_session(user, remember):
        logout_user()
        return False
    login_user(user, remember=remember)
    mark_authenticated()
    return True


_SAFE_NEXT = re.compile(r"/(?P<path>(?:[A-Za-z0-9._~\-]+/)*[A-Za-z0-9._~\-]*)(?:\?(?P<q>[A-Za-z0-9._~\-=&%]*))?")


def safe_next(raw):
    """A same-site path rebuilt from what matched (no scheme, host, "//" or backslash), else "/"."""
    raw = raw[:-1] if (raw or "").endswith("?") else (raw or "")
    m = _SAFE_NEXT.fullmatch(raw)
    if not m:
        return "/"
    out = "/" + "/".join(s for s in m.group("path").split("/") if s)
    return out + ("?" + m.group("q") if m.group("q") else "")


# ── Denials in the audit log ──────────────────────────────────────────────────────────────────────
DENIAL_EVERY = 300
DENIAL_BURST = 30
_DENIED = {}                  # (kind, who, where) -> when last written
_DENIAL_TIMES = deque(maxlen=DENIAL_BURST)


def _denial_due(key, now):
    """Whether a denial row for `key` may be written now; records it when so. Call under _LOCK."""
    for k in [k for k, t in _DENIED.items() if now - t >= DENIAL_EVERY]:
        del _DENIED[k]
    if key in _DENIED:
        return False
    if len(_DENIAL_TIMES) == DENIAL_BURST and now - _DENIAL_TIMES[0] < 60:
        return False
    _DENIED[key] = now
    _DENIAL_TIMES.append(now)
    return True


def _log_denial(kind, ip):
    """The panel-log line for a refusal, with nothing the client wrote in it.

    The kind is a constant at every call; the route is the endpoint NAME (a 404 has none, so
    "(no route)", never the raw path); the address is a parsed IP literal or "unknown".
    """
    from panel.core.validation import canonical_ip
    route = (request.endpoint or "(no route)") if has_request_context() else "(no request)"
    _log.warning("refused (%s) %s from %s", kind, route[:120], canonical_ip(str(ip)) or "unknown")


def note_denial(kind, detail="", user=None):
    """Audit one refused request (`kind`: access_denied, csrf_rejected, session_binding_mismatch).

    Rate-limited (see the module note). Never raises: logging a refusal must not turn it into a 500.
    """
    try:
        from panel.security.auth import client_ip, log_action
        ip = (client_ip() or "unknown") if has_request_context() else "unknown"
        uid = getattr(user, "id", None)
        where = (request.endpoint or request.path or "")[:120] if has_request_context() else ""
        with _LOCK:
            due = _denial_due((kind, uid or ip, where), time.time())
        if not due:
            return False
        _log_denial(kind, ip)
        log_action(user, kind, target=where, detail=detail[:300], success=False,
                   actor=None if user is not None else "(not signed in)")
        return True
    except Exception:  # noqa: BLE001 - see the docstring
        from panel.db.models import db
        db.session.rollback()
        return False


def reset_denials():
    """Forget the denial rate limit (tests)."""
    with _LOCK:
        _DENIED.clear()
        _DENIAL_TIMES.clear()
