"""Reset a WordPress site's administrator password, and its email, from the site's Overview.

Whoever runs the site (MANAGE_WEBSITE on it, or an administrator: site_for, 404 otherwise) may do it, after
the password check (step-up: OWASP Authentication Cheat Sheet, "Require Re-authentication for Sensitive
Features"). The panel lists the site's administrators (services.website_app_admin), one is chosen, and the new password is generated
with the CSPRNG at the install's length (24 characters) or typed, ADMIN_PW_MIN to 128 characters as at install
(OWASP Authentication Cheat Sheet, "Implement Proper Password Strength Controls": at least 15 characters without
MFA, at least 64 allowed). A generated password is in the no-store answer once and is never stored or logged; a
typed one is never sent back. The optional email is checked here and by WordPress. One audit row says who changed
which administrator of which site, and whether the email changed; never the password or the address (OWASP
Logging Cheat Sheet, "Data to exclude"). The administrator is signed out of WordPress everywhere and is not
signed in by the reset (OWASP Forgot Password Cheat Sheet, "User Resets Password").
"""
import secrets

from flask import jsonify
from flask_login import current_user, login_required

from panel.core import i18n
from panel.ops.ssh_manager import websites as _sw
from panel.routes import websites as _w
from panel.routes import websites_apps as _apps
from panel.security.account_guard import step_up_needed, step_up_refusal
from panel.services import website_app_admin as _adm
from panel.services import websites_access as _wa

S_NOT_WP = "The panel can reset the administrator password of a WordPress site only."
S_BUSY = "The website is being set up. Wait until it is running or stopped, then try again."
S_USER = "Choose one of the site's administrators."
S_EMAIL = "Enter an email address, or leave it empty to keep the current one."


def _no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    return resp


def _site(site_id):
    """(site, None) when its administrators can be reached now, else (site, the refusal to answer)."""
    site = _wa.site_for(current_user, site_id, _w.manage_perm(site_id))
    if site.kind != "wordpress":
        return site, _w.say(409, S_NOT_WP)
    if site.state not in ("running", "stopped") or _w.setting_up(site.id):
        return site, _w.say(409, S_BUSY)
    if step_up_needed():
        return site, step_up_refusal()
    return site, None


def _db_port(site):
    db = _w.site_db(site)
    return db[1] if db else 3306


def _fields(data):
    """(user, typed password or "", email or "", the refusal sentence or None) from the form."""
    user = data.get("user") if isinstance(data.get("user"), str) else ""
    typed = data.get("password") if isinstance(data.get("password"), str) else ""
    email = _w.field(data, "email")
    if not _adm.LOGIN_RE.match(user):
        return user, typed, email, S_USER
    why = _apps._typed_password_problem(typed)
    if why:
        return user, typed, email, why
    if email and (len(email) > 254 or not _apps._EMAIL_RE.fullmatch(email)):
        return user, typed, email, S_EMAIL
    return user, typed, email, None


def _reset(site, data):
    user, typed, email, why = _fields(data)
    if why:
        return _w.say(400, why)
    password = typed or secrets.token_urlsafe(18)
    ok, said = _w.host_call(_sw.wp_admin_reset, site.remote, site, user, password, email, _db_port(site))
    detail = "new password for WordPress administrator %s%s" % (user, " and a new email" if email else "")
    _w.audit(site, "website_app_admin_password", detail if ok else "%s failed: %s" % (detail, i18n.tr(said)), ok)
    if not ok:
        return _w.done(False, said)
    return _no_store(jsonify({"success": True, "message": i18n.tr(said), "user": user,
                              "password": "" if typed else password, "generated": not typed}))


def register(app):
    """The app administrator routes."""
    @app.route("/websites/<int:site_id>/app-admin/users", methods=["POST"])
    @login_required
    def website_app_admins(site_id):
        site, refused = _site(site_id)
        if refused is not None:
            return refused
        ok, got = _w.host_call(_sw.wp_admins, site.remote, site, _db_port(site))
        if not ok:
            return _w.done(False, got)
        return _no_store(jsonify({"success": True, "users": got}))

    @app.route("/websites/<int:site_id>/app-admin/reset", methods=["POST"])
    @login_required
    def website_app_admin_reset(site_id):
        site, refused = _site(site_id)
        return refused if refused is not None else _reset(site, _w.body())
