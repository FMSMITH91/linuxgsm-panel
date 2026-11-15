"""Sign-in hardening wired into the app: the 2FA gate, step-up confirmation, denial logging, Fetch Metadata.

The rules themselves live in panel/security/account_guard.py; this registers them (app.py is at its
size limit). Registered from register_routes, so every hook here runs after create_app's own: the CSRF
check, the held-body read and the forced password change come first.
"""
from flask import flash, g, jsonify, redirect, render_template, request
from flask_login import current_user, login_required
from flask_wtf.csrf import CSRFError

from panel.core import i18n
from panel.core.config import load_config
from panel.core.http import _r23c_error_json, _wants_json, http_error_page, http_error_sentence
from panel.db.models import db
from panel.security import account_guard
from panel.security.auth import log_action, verify_totp_step

# A 403 that is not an access-control refusal: the account has a step to take first.
_NOT_DENIALS = ("X-Password-Change-Required", "X-2FA-Setup-Required", "X-Reauth-Required")
_UNSAFE = frozenset(("POST", "PUT", "PATCH", "DELETE"))


def register(app):
    cfg = load_config()
    app.config.setdefault("REQUIRE_2FA", bool(cfg.get("require_2fa")))
    app.config.setdefault("STEP_UP_MINUTES", _step_up_minutes(cfg))
    app.before_request(fetch_metadata_guard)
    app.before_request(account_guard.twofa_gate)
    app.after_request(_log_access_denied)
    app.register_error_handler(CSRFError, _csrf_refused)
    _register_reauth(app)


def _step_up_minutes(cfg):
    """config.json's step_up_minutes (0 switches step-up off), held to 0..1440; 10 when unset or bad."""
    try:
        n = int(float(cfg.get("step_up_minutes", account_guard.STEP_UP_DEFAULT_MINUTES)))
    except (TypeError, ValueError, OverflowError):
        return account_guard.STEP_UP_DEFAULT_MINUTES
    return max(0, min(n, 1440))


def fetch_metadata_guard():
    """before_request: refuse a state-changing request a browser says came from another site.

    OWASP CSRF Prevention Cheat Sheet, "Fetch Metadata headers": with Sec-Fetch-Site "cross-site",
    reject non-safe methods. same-origin, same-site and none pass, and so does a request without the
    header (an API client, the chat bots, an older browser), for which the CSRF token and the Origin
    check stay the defence, as that section requires. The panel's own forms and fetches are
    same-origin, and so is a page reached through Tailscale Serve or a proxy (the browser compares
    the page's origin with the request's, both the front's).
    """
    if request.method not in _UNSAFE or request.headers.get("Sec-Fetch-Site") != "cross-site":
        return None
    account_guard.note_denial("csrf_rejected", detail="cross-site %s (Sec-Fetch-Site)" % request.method,
                              user=_signed_in_user())
    g._denial_logged = True         # the 403 hook must not write a second row for it
    resp = _r23c_error_json(i18n.tr("That request came from another site and was refused."))
    resp.status_code = 403
    return resp


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


