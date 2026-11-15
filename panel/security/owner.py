"""The panel's owner: one account that no other administrator can deactivate, demote or remove.

Superadmin is a flag that any superadmin can grant and take away, so with two of them either could
deactivate, demote, delete or reset the other, and one compromised superadmin could take the panel
from the person who set it up. The owner (User.is_owner) is that person: the account the setup
wizard creates, or on an upgrade the active superadmin with the lowest id (models._ensure_one_owner).

What protects it, read against the OWASP Authorization Cheat Sheet (2026-11-15):
- "Validate the Permissions on Every Request" / "Verify that Authorization Checks are Performed in
  the Right Location": every route that changes an account asks owner_edit_refusal or
  owner_delete_refusal on the server, whatever the Users page offers.
- "Deny by Default": another account's request to change the owner is refused whole, not filtered
  field by field; the owner's own edit is refused when it touches what the owner must keep.
- "Exit Safely when Authorization Checks Fail" / "Implement Appropriate Logging": each refusal is a
  403 with a plain sentence and an `access_denied` audit row naming who tried what.
OWASP has no guidance on an owner role that other administrators cannot remove; the rule here is
this panel's own.

Ownership moves only by transfer(): the owner's password and a live authenticator code at that
moment, to an active superadmin with 2FA on (Transaction Authorization Cheat Sheet 1.1, 1.5, 2.1, 2.4,
2.5, 2.8), or by `manage.py set-owner` on the panel host, whose shell is the root of trust.
"""
from flask import g, jsonify
from sqlalchemy import update

from panel.core import i18n
from panel.core.http import _form_err
from panel.db.models import User, db

# The sentences a refusal answers with (each also in the es/fr catalogs, owner.json).
NOT_YOURS = "Only the panel owner can change the owner's account."
NO_DELETE = "The panel owner's account can't be deleted."
NO_DEACTIVATE = "The panel owner's account can't be deactivated."
NO_DEMOTE = "The panel owner's account stays a superadmin."
NO_RENAME = "The panel owner's username can't be changed."
NO_SELF_DEACTIVATE = "You can't deactivate your own account."
RESTORE_OWNER_ONLY = ("Only the panel owner can restore a panel backup: it replaces every account, "
                      "the owner's included.")
DOWNLOAD_OWNER_ONLY = ("Only the panel owner can download a panel backup: it holds the keys that sign "
                       "every sign-in and decrypt every stored SSH credential.")


def owner():
    """The owner's User row, or None on a panel that has none (no superadmin yet)."""
    return User.query.filter_by(is_owner=True).first()


def is_owner(user):
    """Whether `user` is the panel's owner (False for None or an anonymous user)."""
    return bool(getattr(user, "is_owner", False))


def owner_edit_refusal(actor, target, form):
    """Why `actor` may not make the /users edit in `form` to `target`, as owner rules go; else None.

    Another account's edit of the owner is refused whole. The owner's own edit keeps the display
    name, e-mail and groups and is refused when it would deactivate, demote or rename the account
    (the password and 2FA resets on your own row are refused by the route for everyone).
    Every account is refused deactivating itself.
    """
    if target.id == getattr(actor, "id", None) and form.get("is_active") != "on":
        return NO_DEACTIVATE if is_owner(target) else NO_SELF_DEACTIVATE
    if not is_owner(target):
        return None
    if target.id != getattr(actor, "id", None):
        return NOT_YOURS
    if form.get("is_superadmin") != "on":
        return NO_DEMOTE
    _name = (form.get("username") or "").strip()
    if _name and _name != target.username:
        return NO_RENAME
    return None


def owner_delete_refusal(target):
    """Why `target` may not be deleted, as owner rules go; else None."""
    return NO_DELETE if is_owner(target) else None


def refuse(actor, target, what, message, endpoint=None):
    """Audit a refused change to the owner's account (`access_denied`) and answer it with a 403.

    `what` says what was asked ("an edit of the panel owner's account", ...). The row names the account that asked and
    the account it was about; nothing from the request body goes in it. The after_request 403 hook
    is told this refusal is already written, so it adds no second, rate-limited row. `endpoint`:
    where a plain form post is sent back to; None for a JSON-only API route.
    """
    from panel.security.auth import log_action
    try:
        log_action(actor, "access_denied", target=getattr(target, "username", ""),
                   detail="refused: %s" % what, success=False)
    except Exception:  # noqa: BLE001 - the refusal must still be answered
        db.session.rollback()
    g._denial_logged = True
    if endpoint is None:
        return jsonify({"success": False, "message": i18n.tr(message)}), 403
    return _form_err(i18n.tr(message), endpoint, code=403)


def successors(current):
    """The accounts `current` may transfer ownership to: active superadmins with 2FA on, by name."""
    return (User.query.filter(User.id != current.id, User.is_superadmin.is_(True),
                              User.is_active.is_(True), User.totp_enabled.is_(True))
            .order_by(User.username).all())


def _move(from_id, to_id, need_2fa):
    """Clear the owner flag on `from_id` and set it on `to_id`, in the caller's transaction.

    Both UPDATEs are conditional, so the move happens only from the account that holds the flag NOW
    to one that is NOW an active superadmin (with 2FA, when `need_2fa`). Cleared before it is set:
    the unique index never sees two owners, and a statement that matches nothing leaves the flag
    where it was once the caller rolls back. Two transfers racing from the same owner: SQLite runs
    one writer at a time, and the second finds the flag already gone. True when both matched.
    """
    cond = [User.id == to_id, User.is_owner.is_(False), User.is_superadmin.is_(True),
            User.is_active.is_(True)]
    if need_2fa:
        cond.append(User.totp_enabled.is_(True))
    if from_id is not None:
        cleared = db.session.execute(update(User).where(User.id == from_id, User.is_owner.is_(True))
                                     .values(is_owner=False).execution_options(synchronize_session=False))
        if cleared.rowcount != 1:
            return False
    given = db.session.execute(update(User).where(*cond).values(is_owner=True)
                               .execution_options(synchronize_session=False))
    return given.rowcount == 1


def transfer(current, target):
    """Move ownership from `current` to `target` (an active superadmin with 2FA on). -> bool.

    Committed when it happened, rolled back when it did not; the caller has already checked the
    owner's password and authenticator code. One owner before and after, never none or two.
    """
    try:
        if not _move(current.id, target.id, need_2fa=True):
            db.session.rollback()
            return False
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    db.session.expire(current)
    db.session.expire(target)
    return True


def set_owner(target):
    """Make `target` (an active superadmin) the owner, from wherever it is now. -> (ok, previous name).

    manage.py's set-owner: the host shell is the authority, so 2FA is not required here. A target
    that already owns the panel is a success with nothing changed.
    """
    if is_owner(target):
        return True, target.username
    previous = owner()
    prev_name = previous.username if previous else ""
    try:
        if not _move(previous.id if previous else None, target.id, need_2fa=False):
            db.session.rollback()
            return False, prev_name
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    db.session.expire_all()
    return True, prev_name
