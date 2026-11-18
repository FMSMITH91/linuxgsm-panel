"""Device cookies: a browser that has signed in to an account is not held by that name's sign-in pause.

The per-name throttle (account_guard) pauses sign-ins for a name after repeated failures, from any
address. Alone it refused the right password too, so anyone who knew a name could keep that account,
the superadmin's included, from signing in by sending one wrong guess every few minutes. OWASP's
answer is "Slow Down Online Guessing Attacks with Device Cookies" (OWASP community page, read
2026-11-17), which this follows:

* After a successful sign-in (password and, with 2FA, the code) the browser is given a device cookie:
  the account's id and a random nonce, signed with HMAC-SHA256 under a key of its own (the app's
  secret with this module's salt, so no other signed value of the panel's is accepted as one). A new
  nonce on every sign-in, so the cookie rotates.
* A sign-in that carries a valid device cookie for the account it names is counted against that
  browser alone (account_guard.account_reserve's `device`): the name's pause does not hold it, and
  its own failures pause only that browser. A browser whose cookie is paused, or that has none, is an
  unknown client and is held by the name's pause as before. The address throttle, the address day
  limit and fail2ban apply to every client either way.
* The cookie is HttpOnly, SameSite=Strict, Path=/ with no Domain, and `__Host-` with Secure when the
  panel is reached over HTTPS (OWASP Session Management Cheat Sheet, "Cookies" and "Cookie Name
  Prefixes"), the same rule the session cookie follows (auth._host_prefix_cookies): over plain HTTP a
  browser refuses a Secure cookie, so there it keeps its plain name and is sent without Secure.

The cookie authenticates nothing: it only decides which failure count an attempt is held by, and the
password (and code) are checked the same way. Sign-out's Clear-Site-Data drops it with the site's
other cookies, so the next sign-in from that browser is an unknown client's until it succeeds.
"""
import hashlib
import secrets

from flask import current_app, request
from itsdangerous import BadSignature, URLSafeTimedSerializer

# How long a browser stays known without signing in again. The OWASP page sets no lifetime; each
# sign-in replaces the cookie, so a browser in regular use never reaches it.
DEVICE_COOKIE_DAYS = 180
_SALT = "lgpanel-device-cookie"
_NAME = "lgpanel_device"
_MAX_VALUE = 512              # a real value is about 120 characters


def cookie_name():
    """The device cookie's name: `__Host-` prefixed when the panel's cookies are Secure."""
    return "__Host-" + _NAME if current_app.config.get("SESSION_COOKIE_SECURE") else _NAME


def _serializer():
    """The signer for device cookies: the app's secret, this module's salt, HMAC-SHA256."""
    return URLSafeTimedSerializer(current_app.secret_key, salt=_SALT,
                                  signer_kwargs={"digest_method": hashlib.sha256})


def presented_nonce(user):
    """The nonce of a valid device cookie this request carries for `user`; None for any other.

    Valid: signed by this panel for device cookies, younger than DEVICE_COOKIE_DAYS, and naming this
    account. Anything else (no cookie, a forged or expired one, another account's) is no cookie.
    """
    if user is None or not getattr(user, "id", None):
        return None
    raw = request.cookies.get(cookie_name()) or ""
    if not raw or len(raw) > _MAX_VALUE:
        return None
    try:
        data = _serializer().loads(raw, max_age=DEVICE_COOKIE_DAYS * 86400)
    except BadSignature:          # SignatureExpired is a BadSignature too
        return None
    return _nonce_for(data, user.id)


def _nonce_for(data, user_id):
    """The nonce of a verified cookie payload when it names account `user_id`; else None."""
    if not isinstance(data, dict) or data.get("u") != user_id:
        return None
    nonce = data.get("n")
    return nonce if isinstance(nonce, str) and 16 <= len(nonce) <= 64 else None


def issue(response, user_id):
    """Give the browser a fresh device cookie for account `user_id` on `response`; the response."""
    secure = bool(current_app.config.get("SESSION_COOKIE_SECURE"))
    value = _serializer().dumps({"u": user_id, "n": secrets.token_urlsafe(24)})
    response.set_cookie(cookie_name(), value, max_age=DEVICE_COOKIE_DAYS * 86400, path="/",
                        secure=secure, httponly=True, samesite="Strict")
    return response
