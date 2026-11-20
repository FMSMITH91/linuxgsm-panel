"""Telling a user about changes to their own account's security, and admins about admin-level ones.

OWASP Multifactor Authentication Cheat Sheet, "Changing MFA Factors" ("Notify the user ... whenever an
MFA factor is changed"); Authentication Cheat Sheet, "Logging and Monitoring" (lockouts); Credential
Stuffing Prevention Cheat Sheet, "Notify users about unusual security events" (read 2026-11-15).

The panel sends no e-mail. The account holder is told IN THE PANEL: at their next sign-in, one line per
change made to the account since they last signed in (what, when and from which address), with a
pointer to "Sign out everywhere" and the password change; and on their Account page, the recent
changes as a list. Both read the audit log (one indexed query), so a change made in a borrowed
session, or by an admin, reaches the person it concerns. The panel-wide channels (Telegram, Discord,
ntfy, through notifications.notify and its per-event switches) carry only admin-level events: a
lockout, a change to an administrator's password, 2FA, API token or SFTP keys, and required-2FA
enforcement.
Their messages name the account and the event; a lockout also names the address, as the existing
admin_login and admin_bruteforce alerts do.
"""
from datetime import timedelta

from flask import flash

from panel.core import i18n
from panel.core.clock import utcnow

# Audit action -> (the Account page's label, the sign-in notice with {when} and {ip}).
_CHANGES = {
    "password_changed": ("Password changed",
                         "Since you last signed in: your password was changed ({when}, from {ip})."),
    "reset_user_password": ("Password reset by an administrator",
                            "Since you last signed in: an administrator reset your password ({when}, "
                            "from {ip})."),
    "2fa_enabled": ("Two-factor authentication turned on",
                    "Since you last signed in: two-factor authentication was turned on ({when}, from {ip})."),
    "2fa_disabled": ("Two-factor authentication turned off",
                     "Since you last signed in: two-factor authentication was turned off ({when}, from "
                     "{ip})."),
    "2fa_reset": ("Two-factor authentication removed by an administrator",
                  "Since you last signed in: an administrator removed your two-factor authentication "
                  "({when}, from {ip})."),
    "api_token_generate": ("New API token created",
                           "Since you last signed in: a new API token was created ({when}, from {ip})."),
    "api_token_revoke": ("API token revoked",
                         "Since you last signed in: your API token was revoked ({when}, from {ip})."),
    "owner_transferred": ("Panel ownership transferred",
                          "Since you last signed in: ownership of this panel was transferred ({when}, "
                          "from {ip})."),
    "sftp_key_add": ("SFTP key added",
                     "Since you last signed in: an SFTP key was added to your account ({when}, from {ip})."),
    "sftp_key_remove": ("SFTP key removed",
                        "Since you last signed in: an SFTP key was removed from your account ({when}, from {ip})."),
    "push_subscribe": ("Alerts turned on for a new device",
                       "Since you last signed in: alerts were turned on for a new device ({when}, from {ip})."),
    "telegram_link": ("A Telegram chat was linked for alerts",
                      "Since you last signed in: a Telegram chat was linked to get your alerts ({when}, "
                      "from {ip})."),
    "login_locked": ("Sign-ins paused after repeated failed attempts",
                     "Since you last signed in: sign-ins to your account were paused after repeated "
                     "failed attempts ({when}, last from {ip})."),
}
_IF_NOT_YOU = ("Wasn't you? Change your password and use \"Sign out everywhere\" on your Account page.")
_NOTICE_MAX = 5
RECENT_DAYS = 90


def _admin_level(user):
    """Whether `user` is a superadmin or may use the terminal, users or groups (the 2FA-required set)."""
    # A superadmin's permissions are all of them (get_user_permissions), so this covers superadmins.
    from panel.security.auth import MANAGE_GROUPS, MANAGE_USERS, USE_TERMINAL, get_user_permissions
    return bool(get_user_permissions(user) & {USE_TERMINAL, MANAGE_USERS, MANAGE_GROUPS})


def alert_credential_change(user, what, was_admin=False):
    """For an administrator's account: a `credential_change` alert on the panel-wide channels.

    `was_admin`: the account was administrator-level before the change (a demotion or deactivation
    the alert reports has taken that away by now).
    """
    try:
        if was_admin or _admin_level(user):
            from panel.services import notifications
            notifications.notify("credential_change", "Administrator account changed",
                                 "%s: %s" % (user.username, what))
    except Exception:  # noqa: BLE001 - an alert must never undo the change it reports
        from panel.db.models import db
        db.session.rollback()


def _rows(user, since, limit):
    """The audit rows of security changes to `user` after `since`, newest first."""
    from sqlalchemy import and_, or_
    from panel.db.models import AuditLog
    from panel.security.auth import audit_username
    name = user.username
    return (AuditLog.query.with_entities(AuditLog.action, AuditLog.timestamp, AuditLog.ip_address)
            .filter(AuditLog.timestamp > since, AuditLog.action.in_(tuple(_CHANGES)),
                    or_(and_(AuditLog.target == name, AuditLog.success.is_(True)),
                        and_(AuditLog.action == "login_locked", AuditLog.username == audit_username(name))))
            .order_by(AuditLog.timestamp.desc()).limit(limit).all())


def flash_changes_since(user, since):
    """At sign-in: flash what changed on `user`'s account since `since`, and the pointer. Never raises."""
    if since is None:
        return
    try:
        rows = _rows(user, since, _NOTICE_MAX)
    except Exception:  # noqa: BLE001 - a notice must never stop a sign-in
        from panel.db.models import db
        db.session.rollback()
        return
    for action, when, ip in rows:
        flash(i18n.tr(_CHANGES[action][1], when=when.strftime("%Y-%m-%d %H:%M UTC"),
                      ip=ip or i18n.tr("an unknown address")), "warning")
    if rows:
        flash(_IF_NOT_YOU, "warning")


def recent_changes(user):
    """For the Account page: [(label, when, address)] for the last RECENT_DAYS days, newest first."""
    try:
        rows = _rows(user, utcnow() - timedelta(days=RECENT_DAYS), 10)
    except Exception:  # noqa: BLE001 - the page renders without the list
        from panel.db.models import db
        db.session.rollback()
        return []
    return [(_CHANGES[a][0], w, ip or "") for a, w, ip in rows]
