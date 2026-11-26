"""Whether the credential a console or terminal socket joined with is still one the panel accepts.

The console poller (server_files) and the host terminal (host_terminal) re-ask this on every tick,
outside any request: the login id's epoch, the account, its per-device session row and idle expiry,
and for a socket opened with an API token, that token, still current and unexpired.
"""
from flask import request
from flask_login import current_user

from panel.db.models import db


def _viewer_credential():
    """What join_console records for this socket: (current_user's login id, bearer digest).

    The login id is the string the session cookie carries ("<uid>:<epoch>[:<session sid>]"), so
    running it back through _login_id_still_accepted later asks what a page load asks. The
    digest is recorded only when this socket authenticated with a bearer token that is the
    current user's: revoking a token changes neither the epoch nor any session row, so the token
    itself has to be compared. Request context only.
    """
    import hashlib
    digest = None
    hdr = request.headers.get("Authorization", "")
    if hdr.startswith("Bearer "):
        d = hashlib.sha256(hdr[7:].strip().encode()).hexdigest()
        if getattr(current_user, "api_token", None) == d:
            digest = d
    return current_user.get_id(), digest


def _login_id_still_accepted(login_id):
    """The User a recorded login id still names, or None: load_user's verdict without its writes.

    For the console poller, which holds each viewer's login id ("<uid>:<epoch>[:<sid>]",
    User.get_id) outside any request and re-asks every tick whether the panel would still accept
    it. It asks load_user's questions (the epoch still matches, the account is active, the
    per-device UserSession row still exists and has not idled out) and nothing else, because
    load_user is a REQUEST hook and two of its side effects are wrong here. It writes last_seen
    every ~5 minutes, and idle expiry is measured from last_seen, so a poller calling it kept a
    login alive for as long as a console socket stayed open (a stolen remember cookie included).
    And it turns a database error into None ("deny this request"), which the poller read as
    "revoked" and evicted a legitimate viewer on a transient lock.

    So this writes and deletes nothing, and RAISES when it cannot look (after a rollback, so the
    next viewer's query is not refused by a session left mid-failure). The per-request client
    binding (_session_binding_ok) is not asked: there is no request. Keep it in step with
    auth.load_user: smoke_test drives both over the same login ids.
    """
    s = str(login_id)
    try:
        if ":" not in s:      # legacy cookie from before epochs: load_user accepts the plain id
            return _legacy_login_user(s)
        return _epoch_login_user(s)
    except Exception:
        db.session.rollback()
        raise


def _legacy_login_user(s):
    """The active User a pre-epoch login id (the bare user id) names, or None.

    Only while that account's auth_epoch is still 0, as auth._load_legacy_user: a bare id predates
    epochs, so once a password change or "sign out everywhere" has moved the epoch it is one of the
    cookies that bump revoked.
    """
    from panel.db.models import User
    user = db.session.get(User, int(s)) if s.isdecimal() else None
    ok = user is not None and user.is_active and (user.auth_epoch or 0) == 0
    return user if ok else None


def _epoch_login_user(s):
    """The User an "<uid>:<epoch>[:<sid>]" login id still names, or None."""
    from panel.db.models import User
    parts = s.split(":")
    uid, epoch = parts[0], parts[1]
    sid = parts[2] if len(parts) > 2 and parts[2] else None
    if not uid.isdecimal():
        return None
    user = db.session.get(User, int(uid))
    if user is None or str(user.auth_epoch or 0) != epoch or not user.is_active:
        return None
    if sid and not _session_row_live(sid, user):
        return None
    return user


def _session_row_live(sid, user):
    """Whether `user`'s per-device UserSession row `sid` still exists and has not idled out."""
    from panel.core.clock import utcnow
    from panel.db.models import UserSession
    sess = UserSession.query.filter_by(sid=sid, user_id=user.id).first()
    return not (sess is None or sess.is_expired(utcnow()))


def _credential_still_valid(uid, cred):
    """Is the credential a viewer joined with still one the panel would accept?

    cred is what _viewer_credential recorded, or None for a viewer registered without one (nothing
    to check). A revoked device, a bumped auth_epoch, an idle-expired session and a deactivated account all
    fail here as they fail a page load.

    It asks _login_id_still_accepted, NOT the app's user_loader: load_user refreshed last_seen
    from this poller (so an open console socket kept its login from ever idling out) and answered
    a database error with None (so a transient lock evicted a legitimate viewer as "revoked").
    _login_id_still_accepted writes nothing and RAISES when it cannot look, and
    _evict_unauthorized_viewers keeps a viewer it could not check.
    """
    if cred is None:
        return True
    login_id, digest = cred
    user = _login_id_still_accepted(login_id)
    if user is None or user.id != uid:
        return False
    if digest is None:
        return True
    # A bearer socket: the token must still be the account's AND unexpired. User.by_api_token asks
    # the expiry only when a request authenticates, and nothing clears the stored hash when it
    # passes, so a socket joined before the expiry kept the live console after it (OWASP Session
    # Management Cheat Sheet, "Session Expiration": enforce it server side). host_terminal shares this.
    if getattr(user, "api_token", None) != digest:
        return False
    from panel.core.clock import utcnow
    expires = getattr(user, "api_token_expires", None)
    return expires is None or expires > utcnow()
