"""Transferring the panel's ownership from the Account page (see panel/security/owner.py).

Read against the OWASP Transaction Authorization Cheat Sheet (2026-11-15): the owner sees whom they
hand the panel to and confirms it with their password AND a live authenticator code in the same
request (1.1, 1.4); each code is spent once (1.5, 2.10: spend_totp_step), under the per-account
re-authentication budget every other password and code check shares (2.4: reauth_reserve); the
target is re-checked on the server when the request arrives and again inside the move itself (2.1,
2.5, 2.8: owner._move's conditional UPDATEs). Backup codes are not accepted here: a transfer is not a
recovery, and the host shell (`manage.py set-owner`) is the way back for an owner without their
authenticator. Logging Cheat Sheet, "Which events to log" (changes to privileges): every attempt is an
`owner_transferred` audit row, refused or not; a completed one is two rows, one filed under each
account, both naming the two accounts, which is also what puts the notice in front of each of them
(account_notices) at their next sign-in and on their Account page.
"""
from flask import flash, redirect, request, url_for
from flask_login import current_user, login_required

from panel.core import i18n
from panel.db.models import db
from panel.routes._shared import (REAUTH_BLOCKED_MSG, reauth_password, reauth_release, reauth_reserve,
                                  spend_totp_step)
from panel.security import owner as _owner
from panel.security.auth import _r17c_row_id, log_action, verify_totp_step
from panel.services import notifications

NOT_OWNER = "Only the panel owner can transfer ownership."
NEEDS_2FA = ("Turn on two-factor authentication first: a transfer of ownership is confirmed with your "
             "password and a code from your authenticator.")
NOT_ELIGIBLE = ("Ownership can only go to another active superadmin who has two-factor "
                "authentication turned on.")
WRONG_PW_MSG = "Password incorrect — ownership was not transferred."
WRONG_CODE = "That authenticator code didn't match — ownership was not transferred."
REPLAYED_CODE = "That code has already been used — wait for your authenticator to show the next one."
CHANGED_MEANWHILE = "Ownership changed while this was being confirmed, so nothing was transferred."
DONE = "Ownership transferred to {name}. You are still a superadmin."


def register(app):
    """Register the transfer route, and the Account page's list of who ownership can go to."""
    app.jinja_env.globals["owner_successors"] = _owner.successors

    @app.route("/account/owner/transfer", methods=["POST"])
    @login_required
    def account_owner_transfer():
        """Hand the panel's ownership to another active superadmin with 2FA on (owner only)."""
        u = current_user._get_current_object()
        if not _owner.is_owner(u):
            return _owner.refuse(u, _owner.owner(), "a transfer of ownership by an account that is not "
                                 "the owner", NOT_OWNER, "account")
        target = _chosen_successor(u)
        why = _refusal(u, target)
        if why is not None:
            _audit_refused(u, target, why)
            flash(why, "danger")
            return redirect(url_for("account"))
        if not _owner.transfer(u, target):
            _audit_refused(u, target, CHANGED_MEANWHILE)
            flash(CHANGED_MEANWHILE, "danger")
            return redirect(url_for("account"))
        _audit_done(u.username, target.username)
        flash(i18n.tr(DONE, name=target.username), "success")
        return redirect(url_for("account"))


def _chosen_successor(u):
    """The account the form names, when it is one ownership may go to now; else None."""
    raw = request.form.get("new_owner") or ""
    tid = _r17c_row_id(int(raw)) if raw.isascii() and raw.isdecimal() and len(raw) <= 19 else None
    if tid is None:
        return None
    return next((s for s in _owner.successors(u) if s.id == tid), None)


def _refusal(u, target):
    """Why the transfer may not go ahead (a sentence), or None once the password and code are spent."""
    if not u.totp_enabled:
        return NEEDS_2FA
    if target is None:
        return NOT_ELIGIBLE
    pw = reauth_password(u, request.form.get("password", ""))
    if pw != "ok":
        return REAUTH_BLOCKED_MSG if pw == "throttled" else WRONG_PW_MSG
    stamp = reauth_reserve(u)
    if stamp is None:
        return REAUTH_BLOCKED_MSG
    code = (request.form.get("totp_code") or "").strip()
    step = verify_totp_step(u.totp_secret_plain, code) if u.totp_secret_plain else None
    if step is None:
        return WRONG_CODE                   # the slot stays spent: that is the count
    if not spend_totp_step(u, step):
        db.session.rollback()
        return REPLAYED_CODE
    # Committed on its own, before the move: the code is spent whether or not the move then finds
    # the target still eligible.
    db.session.commit()
    reauth_release(u, stamp)
    return None


def _audit_refused(u, target, why):
    """One failed `owner_transferred` row: who asked, to whom, and why it was refused."""
    log_action(u, "owner_transferred", target=getattr(target, "username", "") or "(not an eligible account)",
               detail="refused: %s" % why, success=False)


def _audit_done(old, new):
    """The completed transfer: a row filed under each account, and the panel-wide alert."""
    detail = "ownership moved from '%s' to '%s'" % (old, new)
    log_action(current_user, "owner_transferred", target=old, detail=detail)
    log_action(current_user, "owner_transferred", target=new, detail=detail)
    notifications.notify("account_change", "Panel ownership transferred",
                         "'%s' transferred ownership of the panel to '%s'." % (old, new))
