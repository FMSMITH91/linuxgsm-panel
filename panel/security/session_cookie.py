"""The session cookie, re-issued every few minutes instead of on every response.

Flask's signed-cookie session re-signs and re-sends a permanent session on EVERY response
(SESSION_REFRESH_EACH_REQUEST), and the signature carries the time it was made, so the value changes
every second. Measured on an open dashboard: 420 bytes of Set-Cookie on each of its ~13 polls a
minute, about a quarter of every poll's download, plus a request cookie that never repeats, which
HTTP/2 header compression cannot shorten.

Two changes, and nothing else about the cookie (its name, flags, lifetime and contents) moves:

* An UNCHANGED session is re-sent once its cookie is _REISSUE_SECONDS old, not on every response. The
  idle timeout still slides: a cookie is accepted for PERMANENT_SESSION_LIFETIME after it was SIGNED,
  so an idle session now ends between that lifetime less _REISSUE_SECONDS and that lifetime after the
  last request, where it ended at exactly the lifetime. The server's own record of the login
  (UserSession.last_seen) already moves in the same 300 s steps (auth._touch_session). A session
  that CHANGED (a login, a language switch, a 2FA step, a logout) is sent at once, as before.
* A /static file is sent with no Set-Cookie and no `Vary: Cookie`: it is the same bytes for every
  viewer, and a cookie that changed on every response defeated the browser's cache of the panel's
  content-hashed assets (each page load re-asked for all ~20 of them). A static request that did
  change the session still sends it.
* A request the page marks as BACKGROUND (X-Panel-Background: 1, which panel.js adds to a fetch that
  no click, key press, tap or scroll started: a poll) never re-sends an unchanged cookie, and does not
  move the login's last-seen time (auth._touch_session). So the idle timeout counts from the person's
  last use of the panel, not from the dashboard's last poll: OWASP Session Management Cheat Sheet,
  "Idle Timeout", ends a session that has not been USED; a tab left open polling every few seconds
  used to keep it alive until the absolute limit.
"""
import time

from flask import has_request_context, request
from flask.sessions import SecureCookieSession, SecureCookieSessionInterface
from itsdangerous import BadSignature

# How old an unchanged session's cookie may get before a response re-sends it. The same step as
# auth._touch_session's write of the login's last-seen time. A fifth of the idle timeout when that is
# shorter (reissue_seconds), or a 5-minute timeout would end 4 minutes after a use.
_REISSUE_SECONDS = 300


def reissue_seconds(app):
    """Seconds after which an unchanged session's cookie is re-sent: _REISSUE_SECONDS, or less."""
    life = app.permanent_session_lifetime.total_seconds()
    return min(_REISSUE_SECONDS, max(1.0, life / 5.0))


def background_request():
    """Whether this request was started by a timer in the page rather than by the person (see above)."""
    return has_request_context() and request.headers.get("X-Panel-Background") == "1"


class _Session(SecureCookieSession):
    """A cookie session that knows when the cookie it was read from was signed (None: no cookie)."""

    issued_at = None


class ThrottledCookieSessions(SecureCookieSessionInterface):
    """Flask's signed-cookie sessions, re-sent only when changed or _REISSUE_SECONDS old."""

    session_class = _Session

    def open_session(self, app, request_):
        """Read the cookie as Flask does, keeping the time it was signed."""
        s = self.get_signing_serializer(app)
        if s is None:
            return None
        val = request_.cookies.get(self.get_cookie_name(app))
        if not val:
            return self.session_class()
        max_age = int(app.permanent_session_lifetime.total_seconds())
        try:
            data, signed = s.loads(val, max_age=max_age, return_timestamp=True)
        except BadSignature:
            return self.session_class()
        sess = self.session_class(data)
        sess.issued_at = signed.timestamp()
        return sess

    def should_set_cookie(self, app, session):
        """Changed: always. Unchanged and permanent: once its cookie is reissue_seconds old, on a use."""
        if session.modified:
            return True
        if not (session.permanent and app.config["SESSION_REFRESH_EACH_REQUEST"]):
            return False
        if background_request():
            return False            # a poll is not a use: the idle clock keeps running
        issued = getattr(session, "issued_at", None)
        return issued is None or time.time() - issued >= reissue_seconds(app)

    def save_session(self, app, session, response):
        """Flask's save, except that a static file leaves an unchanged session alone."""
        if not session.modified and has_request_context() and request.endpoint == "static":
            return
        super().save_session(app, session, response)


def _deletes(header, name):
    """Whether the Set-Cookie value `header` deletes the cookie called `name` (Max-Age=0)."""
    head, _, rest = header.partition(";")
    return head.split("=", 1)[0].strip() == name and "max-age=0" in rest.lower().replace(" ", "")


def remember_deletion_with_attributes(response):
    """Re-send flask-login's deletion of the remember cookie with the cookie's own attributes.

    flask-login 0.6.3 clears the "remember me" cookie (at sign-out, and when a stale one comes back)
    with delete_cookie(name, domain, path) alone: no Secure, HttpOnly or SameSite. Over HTTPS the
    cookie is `__Host-remember_token`, and a browser ignores a `__Host-` Set-Cookie without Secure
    (the cookie prefix rules), so the old remember cookie stayed in the jar after sign-out. The server
    no longer accepted it, but the sign-out's own deletion did nothing. OWASP Session Management Cheat
    Sheet, "Cookies" (`__Host-` needs Secure, Path=/ and no Domain) and "Session Expiration" (sign-out
    overwrites the cookie with an empty, already expired one). Registered as an after-request step
    that runs after flask-login's own (auth.init_auth), so the deletion it wrote is replaced here.
    """
    from flask import current_app
    cfg = current_app.config
    name = cfg.get("REMEMBER_COOKIE_NAME", "remember_token")
    sent = response.headers.getlist("Set-Cookie")
    if not any(_deletes(h, name) for h in sent):
        return response
    response.headers.remove("Set-Cookie")
    for h in sent:
        if not _deletes(h, name):
            response.headers.add("Set-Cookie", h)
    response.delete_cookie(name, path=cfg.get("REMEMBER_COOKIE_PATH") or "/",
                           domain=cfg.get("REMEMBER_COOKIE_DOMAIN"),
                           secure=bool(cfg.get("REMEMBER_COOKIE_SECURE")),
                           httponly=bool(cfg.get("REMEMBER_COOKIE_HTTPONLY", True)),
                           samesite=cfg.get("REMEMBER_COOKIE_SAMESITE"))
    return response
