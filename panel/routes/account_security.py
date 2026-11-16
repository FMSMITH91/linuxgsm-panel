"""Sign-in hardening wired into the app: the 2FA gate, step-up confirmation, denial logging, Fetch Metadata.

The rules themselves live in panel/security/account_guard.py; this registers them (app.py is at its
size limit). Registered from register_routes, so every hook here runs after create_app's own: the CSRF
check, the held-body read and the forced password change come first.
"""
from flask import flash, g, jsonify, redirect, render_template, request
from flask_login import current_user, login_required
from flask_wtf.csrf import CSRFError

from panel.core import i18n, session_policy
from panel.core.config import load_config
from panel.core.http import _r23c_error_json, _wants_json, http_error_page, http_error_sentence
from panel.db.models import db
from panel.security import account_guard, account_notices
from panel.security.auth import log_action, verify_totp_step

# A 403 that is not an access-control refusal: the account has a step to take first.
_NOT_DENIALS = ("X-Password-Change-Required", "X-2FA-Setup-Required", "X-Reauth-Required")
_UNSAFE = frozenset(("POST", "PUT", "PATCH", "DELETE"))


def register(app):
    cfg = load_config()
    app.config.setdefault("REQUIRE_2FA", bool(cfg.get("require_2fa")))
    app.config.setdefault("STEP_UP_MINUTES", session_policy.step_up_minutes(cfg))
    app.before_request(fetch_metadata_guard)
    app.before_request(account_guard.twofa_gate)
    app.after_request(_log_access_denied)
    app.register_error_handler(CSRFError, _csrf_refused)
    # The Account page's "Recent security changes" (read by the template, so both of the page's
    # renders show it without passing it).
    app.jinja_env.globals["account_changes"] = account_notices.recent_changes
    # How long a "remember me" sign-in lasts: the login page's hint and the Settings card's sentence.
    app.jinja_env.globals["remember_for"] = lambda: i18n.tr("for {lasts}", lasts=remember_lasts())
    app.jinja_env.globals["remember_rule"] = lambda: i18n.tr(
        "With “Remember me”, a sign-in lasts {lasts}, then asks for the password.", lasts=remember_lasts())
    _register_reauth(app)


def remember_lasts():
    """How long a "remember me" sign-in lasts from its sign-in, in the viewer's language ("3 days").

    Read from models.session_absolute_limits, the limit the server ends such a login at, so the hint
    is the rule in force (Settings' days, or the absolute limit when that is set longer).
    """
    from panel.db.models import session_absolute_limits
    hours = int(round(session_absolute_limits()[1] / 3600.0))
    if hours % 24:
        return i18n.tr("{n} hours", n=hours)
    days = hours // 24
    return i18n.tr("1 day") if days == 1 else i18n.tr("{n} days", n=days)


def fetch_metadata_guard():
    """before_request: refuse a state-changing request a browser says came from another site.

    OWASP CSRF Prevention Cheat Sheet, "Fetch Metadata headers": Sec-Fetch-Site "cross-site" on a
    non-safe method is refused; same-origin and none pass. Every other case -- no header (an older
    browser, an API client, the chat bots), "same-site" (another port of the panel's address, or a
    sibling node on the same tailnet) or a value this code does not know -- falls back to "Verifying
    origin with standard headers", which that section makes mandatory (see _foreign_origin). The
    panel's own forms and fetches are same-origin, and so is a page reached through Tailscale Serve
    or a proxy (the browser compares the page's origin with the request's, both the front's).
    """
    if request.method not in _UNSAFE:
        return None
    site = request.headers.get("Sec-Fetch-Site")
    if site == "cross-site":
        return _refuse_foreign("cross-site %s (Sec-Fetch-Site)" % request.method,
                               "That request came from another site and was refused.")
    if site in ("same-origin", "none") or _cookie_less_bearer():
        return None
    foreign = _foreign_origin()
    if foreign is None:
        return None
    return _refuse_foreign("foreign %s %r on %s" % (foreign[0], foreign[1][:120], request.method),
                           "That request did not come from this panel's own page and was refused.")


def _refuse_foreign(detail, sentence):
    """The 403 for a request from another site, audited once as csrf_rejected."""
    account_guard.note_denial("csrf_rejected", detail=detail, user=_signed_in_user())
    g._denial_logged = True         # the 403 hook must not write a second row for it
    resp = _r23c_error_json(i18n.tr(sentence))
    resp.status_code = 403
    return resp


def _cookie_less_bearer():
    """True for an API-token request that carries no cookie: CSRF cannot apply to it.

    The same condition app.py's CSRF hook exempts on: a Bearer header and neither the session cookie
    nor the remember cookie, so there is nothing for a page on another site to ride.
    """
    from flask import current_app
    if not request.headers.get("Authorization", "").startswith("Bearer "):
        return False
    names = (current_app.config["SESSION_COOKIE_NAME"],
             current_app.config.get("REMEMBER_COOKIE_NAME", "remember_token"))
    return not any(request.cookies.get(n) for n in names)


def _foreign_origin():
    """(header, origin) when the request's source origin is not the panel's own; None when it is or is unknown.

    OWASP CSRF Prevention Cheat Sheet, "Using Standard Headers to Verify Origin": the Origin header
    when present, else the origin of the Referer. "null" is never the panel's own (the cheat sheet:
    do not allowlist it); the panel's pages never send it, since Referrer-Policy same-origin keeps
    the real Origin on their own requests. With neither header there is no evidence either way and
    the synchronizer token, already checked, decides -- as that section allows.

    The target origin is the one the console socket accepts (app._socket_origin_allowed): the exact
    origins in socketio_cors_origins, else the Host the request arrived with, the X-Forwarded-Host a
    proxy passed on, or site_domain, port included. A page on another site cannot choose either
    header for a request it makes: a form cannot set headers, and a fetch that sets one needs a
    CORS preflight the panel never approves.
    """
    from app import _socket_origin_allowed
    origin, which = request.headers.get("Origin"), "Origin"
    if origin is None:
        origin, which = _referer_origin(request.headers.get("Referer")), "Referer"
        if origin is None:
            return None
    if origin and _socket_origin_allowed(origin, request.environ):
        return None
    return which, origin


def _referer_origin(referer):
    """The origin (scheme://host[:port]) of a Referer, "" for one that has none, None for no header."""
    from urllib.parse import urlsplit
    if not referer:
        return None
    try:
        u = urlsplit(referer)
        host, port = u.hostname, u.port
    except ValueError:
        return ""
    if u.scheme not in ("http", "https") or not host:
        return ""
    netloc = ("[" + host + "]" if ":" in host else host) + (":" + str(port) if port else "")
    return u.scheme + "://" + netloc


def _signed_in_user():
    """The signed-in user, or None (never raises: used while answering a refusal)."""
    try:
        return current_user._get_current_object() if current_user.is_authenticated else None
    except Exception:  # noqa: BLE001 - a refusal is answered whatever the identity lookup does
        db.session.rollback()
        return None


def _log_access_denied(resp):
    """after_request: audit an access-control refusal (a 403), rate-limited (account_guard)."""
    if (resp.status_code == 403 and not g.get("_denial_logged")
            and not any(h in resp.headers for h in _NOT_DENIALS)):
        account_guard.note_denial("access_denied", detail="HTTP 403 %s" % request.method,
                                  user=_signed_in_user())
    return resp


def _csrf_refused(e):
    """A failed CSRF check: audited (Logging Vocabulary's malicious_csrf), then answered as before."""
    account_guard.note_denial("csrf_rejected", detail=str(e.description or "")[:200], user=_signed_in_user())
    if request.path.startswith("/api/") or _wants_json():
        return _r23c_error_json(i18n.tr(http_error_sentence(e))), 400
    return http_error_page(e)


def _register_reauth(app):
    """The confirm-it-is-you page step-up sends a high-risk request to."""
    @app.route("/account/reauth", methods=["GET", "POST"])
    @login_required
    def account_reauth():
        """Confirm the password (and the 2FA code) again; then back to where the action was.

        Under the same per-account budget as every other place that re-asks for the password
        (_shared.reauth_reserve; Transaction Authorization Cheat Sheet, 2.4 "Application should
        prevent authorization credentials brute-forcing"). Every refusal is audited.
        """
        nxt = account_guard.safe_next(request.values.get("next", "/"))
        if request.method == "GET":
            return render_template("reauth.html", next_path=nxt)
        u = current_user._get_current_object()
        why = _reauth_refusal(u, request.form.get("password", ""), (request.form.get("totp_code") or "").strip())
        if why is not None:
            log_action(u, "reauth", target=u.username, detail=why, success=False)
            if _wants_json():
                return jsonify({"success": False, "message": i18n.tr(_REFUSED[why])}), 403
            flash(_REFUSED[why], "danger")
            return render_template("reauth.html", next_path=nxt)
        db.session.commit()
        account_guard.mark_authenticated()
        log_action(u, "reauth", target=u.username)
        if _wants_json():
            return jsonify({"success": True})
        # nosemgrep: python.flask.security.audit.open-redirect.flask-open-redirect -- safe_next rebuilt it
        return redirect(nxt)


_REFUSED = {
    "throttled": "Too many wrong passwords or codes for this account. Wait a few minutes and try again.",
    "wrong password": "Password incorrect.",
    "wrong code": "That authenticator code didn't match.",
    "replayed code": "That code has already been used — wait for your authenticator to show the next one.",
}


def _reauth_refusal(u, password, code):
    """None when `password` (and, with 2FA, `code`) are right and unspent; else the refusal's key."""
    from panel.routes._shared import reauth_password, reauth_release, reauth_reserve, spend_totp_step
    pw = reauth_password(u, password)
    if pw != "ok":
        return "throttled" if pw == "throttled" else "wrong password"
    if not u.totp_enabled:
        return None
    stamp = reauth_reserve(u)
    if stamp is None:
        return "throttled"
    step = verify_totp_step(u.totp_secret_plain, code) if u.totp_secret_plain else None
    if step is not None:
        if not spend_totp_step(u, step):
            db.session.rollback()
            return "replayed code"
    elif not u.use_backup_code(code):
        return "wrong code"
    reauth_release(u, stamp)
    return None


