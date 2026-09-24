"""The host terminal: one page, and the Socket.IO events behind it.

Registered AFTER the SocketIO instance exists and handed that instance, because there is exactly
one in this app (panel/routes/server_files.py) and a second would collide on /socket.io/.

Deliberately on the DEFAULT namespace. flask-socketio's connect gate is per-namespace, so a
terminal on its own namespace would not inherit `on_socket_connect`'s
`if not current_user.is_authenticated: return False` — it would get a fresh, ungated one. The
events below re-check authentication AND the permission on every message anyway, because socket
events are covered by neither CSRFProtect nor rbac_test's url_map sweeps: nothing else is
watching them.
"""
import threading
import time

from flask import has_request_context, render_template, request
from flask_login import current_user, login_required
from flask_socketio import emit

from panel.db.models import RemoteServer
from panel.ops import socket_hooks as _socket_hooks
from panel.ops import terminal_session as _ts
from panel.ops.ssh_manager import is_local_server
from panel.security.auth import (USE_TERMINAL, _deny, get_remote, has_permission, log_action,
    permission_required)

# sid -> (remote_id or None). Only used to label audit rows and to tear down on disconnect.
_sid_host = {}
_sid_lock = threading.Lock()

# sid -> (monotonic, allowed). Per-host access was checked when the shell OPENED and never again,
# so revoking someone's access to a host left their live shell typing into it until they closed
# the tab or the idle sweeper reaped it fifteen minutes later. Re-checking on every keystroke
# would put a group query behind every character, so it is re-checked at most this often.
_sid_access = {}
_ACCESS_RECHECK_SECONDS = 10.0

# sid -> (user id, the credential the socket opened its shell with). What the revocation sweep
# re-asks about: it has no request, so it asks of what term_open recorded.
_sid_owner = {}

_REVOKED_MESSAGE = ("Your access to the terminal was removed, so this session has been closed.")


def _may_use_terminal():
    """Every socket event asks this, because a socket event is not an HTTP request.

    must_change_password is enforced by an @app.before_request (app.py), and before_request never
    runs for a Socket.IO event — so an account holding a handed-over temporary password was
    redirected to the change-password page for every route in the panel and could still emit
    term_open and get a shell. The whole point of that gate is that the admin who typed the
    temporary password must not be able to keep using it, and a shell is the last place to make an
    exception. The route above is covered by before_request; these events are not, so they ask
    here.
    """
    if not current_user.is_authenticated:
        return False
    if getattr(current_user, "must_change_password", False):
        return False
    return bool(current_user.is_superadmin or has_permission(current_user, USE_TERMINAL))


def may_shell_on(user, remote):
    """May `user` have a shell on `remote`? The per-HOST half of the question.

    On the panel's OWN host the answer is superadmin only, whatever the grants say. A shell there
    runs as the panel's service account, and that account owns data/: panel.db (every user and
    every is_superadmin flag), secret_key (which signs every session cookie) and cred_key (which
    decrypts every remote's stored SSH credential). So it is not a shell on one host; it is the
    panel itself, and through it every host the panel reaches. It was grantable by accident:
    USE_TERMINAL and a whole-host grant covering the panel host are both ordinary, delegable
    grants, unioned across a user's groups, and neither says that together they add up to
    superadmin. Every other panel-host management surface is already @superadmin_required.

    On a remote the host grant stays the rule: the panel is root there by design, and a shell on
    it reaches that host and nothing else the panel holds.
    """
    if remote is None or user is None or not getattr(user, "is_authenticated", False):
        return False
    if user.is_superadmin:
        return True
    if is_local_server(remote):
        return False
    from panel.security.auth import can_access_remote
    return bool(can_access_remote(user, remote.id))


LOCAL_HOST_REFUSAL = ("A terminal on the panel's own host is for superadmins only: it runs as "
                      "the account that owns the panel's database and keys.")


def _terminal_still_permitted(uid, cred, remote_id):
    """Would term_open still give this user a shell on this host, on the login it opened with?

    The same questions the event handlers ask of current_user — active, not held at a forced
    password change, USE_TERMINAL (or superadmin), may_shell_on the host — plus whether the login
    itself is still accepted (_credential_still_valid: epoch, session row, idle expiry, a bearer
    token's hash). Asked of what term_open recorded, because the sweep has no request.

    RAISES when it cannot look. load_user answers a locked database with None, and closing a live
    shell — and whatever is running in it — on a transient lock is not the same as revoking it."""
    from panel.db.models import User, db
    from panel.routes.server_files import _credential_still_valid
    user = db.session.get(User, uid) if uid is not None else None
    if user is None or not user.is_active or getattr(user, "must_change_password", False):
        return False
    if not (user.is_superadmin or has_permission(user, USE_TERMINAL)):
        return False
    if not may_shell_on(user, db.session.get(RemoteServer, remote_id)):
        return False
    return bool(_credential_still_valid(uid, cred))


def revoked_terminal_sids(only_sid=None):
    """[(sid, user or None)] for every open shell whose owner may no longer have it.

    A positive "no" only: a socket whose owner could not be checked is left alone this time and
    asked again on the next sweep. Must run inside an app context. Never raises."""
    from panel.db.models import User, db
    with _sid_lock:
        owners = {s: (o, _sid_host.get(s)) for s, o in _sid_owner.items()
                  if only_sid is None or s == only_sid}
    out = []
    for sid, ((uid, cred), remote_id) in owners.items():
        try:
            if _terminal_still_permitted(uid, cred, remote_id):
                continue
            out.append((sid, db.session.get(User, uid) if uid is not None else None))
        except Exception:
            try:
                db.session.rollback()
            except Exception:  # nosec B110
                pass
    return out


def _close_and_audit(app, sid, reason, user=None):
    """Tear a socket's shell down and write the closing audit row.

    `user` is whom to record. None means the request's own user, when there is a request and it
    is authenticated; the revocation sweep has no request and names the owner itself."""
    # TEAR DOWN FIRST, and never on the strength of the audit bookkeeping. _sid_host[sid] is
    # written AFTER open_session returns, while the session itself is registered (and counting
    # against the per-user limit) BEFORE the transport is opened — and paramiko's connect can
    # take the full ssh_timeout. A disconnect in that window found no _sid_host entry and
    # returned right here, leaving the shell running and the slot held until the idle sweeper
    # reaped it fifteen minutes later; three of those and the fourth open is refused with "you
    # already have 3 terminals open" while none are. close_for_sid is a no-op when there is no
    # session, so calling it unconditionally costs nothing.
    _ts.close_for_sid(sid, reason)
    _sid_access.pop(sid, None)
    with _sid_lock:
        remote_id = _sid_host.pop(sid, None)
        _sid_owner.pop(sid, None)
    if remote_id is None:
        return          # nothing to audit: this socket never got as far as an open session
    try:
        if user is None and has_request_context() and current_user.is_authenticated:
            user = current_user
        remote = RemoteServer.query.get(remote_id)
        log_action(user, "terminal_close",
                   target=(remote.name if remote else str(remote_id)), detail=reason)
    except Exception:
        app.logger.debug("terminal close audit failed", exc_info=True)


def sweep_revoked_terminals(app, socketio, only_sid=None):
    """Close every open shell whose owner has lost it, and say why. Returns how many.

    A shell following a log is sent no input, so a check made only when a keystroke arrives never
    runs for it: an admin revoking a user's sessions, deactivating them or taking use_terminal
    away left the output of that shell — usually root, on a remote — streaming to the revoked
    browser until the idle sweeper reaped it fifteen minutes later. So this runs on a timer as
    well as from the event handlers. Module level so a test can drive it directly."""
    closed = 0
    for sid, user in revoked_terminal_sids(only_sid):
        try:
            socketio.emit("term_error", {"message": _REVOKED_MESSAGE}, room=sid)
        except Exception:
            app.logger.debug("terminal: could not tell %s it was revoked", sid, exc_info=True)
        _close_and_audit(app, sid, "terminal access was revoked", user=user)
        closed += 1
    return closed


def register(app, socketio, supervise):
    _ts.start_idle_sweeper(supervise)

    @app.route("/terminal/<int:remote_id>")
    @login_required
    @permission_required(USE_TERMINAL)
    def host_terminal(remote_id):
        """A shell on one host. get_remote() enforces per-host access (and 404s), which is also
        what rbac_test's <remote_id> sweep requires to see."""
        remote = get_remote(remote_id)
        if not may_shell_on(current_user, remote):
            return _deny(LOCAL_HOST_REFUSAL, 403)
        return render_template("terminal.html", remote=remote,
                               sudo_note=_ts.sudo_hint(remote, bool(remote.is_local)),
                               local_user=_ts.panel_account())

    # ── socket events ─────────────────────────────────────────────────────────────────────────
    def _send(sid, data):
        socketio.emit("term_output", {"data": data}, room=sid)

    def _exited(sid, reason):
        socketio.emit("term_exit", {"reason": reason or ""}, room=sid)

    @socketio.on("term_open")
    def on_term_open(data):
        sid = request.sid
        if not _may_use_terminal():
            emit("term_error", {"message": "You don't have permission to open a terminal."})
            return
        try:
            remote_id = int((data or {}).get("remote_id"))
        except (TypeError, ValueError):
            emit("term_error", {"message": "No host was named."})
            return
        # Per-host access, exactly as the page route checks it — a socket event is not covered by
        # the route's decorators and must ask again.
        from panel.security.auth import can_access_remote
        if not (current_user.is_superadmin or can_access_remote(current_user, remote_id)):
            emit("term_error", {"message": "You don't have access to that host."})
            return
        remote = RemoteServer.query.get(remote_id)
        if remote is None:
            emit("term_error", {"message": "That host no longer exists."})
            return
        # ...and the panel's own host is superadmin-only, which no host grant changes. The page
        # route refuses it as well, but this event is reachable without ever loading the page.
        if not may_shell_on(current_user, remote):
            emit("term_error", {"message": LOCAL_HOST_REFUSAL})
            return
        _ts.close_for_sid(sid, "")          # one shell per socket
        try:
            _ts.open_session(sid, remote, bool(remote.is_local),
                             user_key=current_user.id,
                             on_output=_send, on_exit=_exited,
                             cols=(data or {}).get("cols", 80),
                             rows=(data or {}).get("rows", 24))
        except _ts.TerminalError as e:
            emit("term_error", {"message": str(e)})
            return
        from panel.routes.server_files import _viewer_credential
        with _sid_lock:
            _sid_host[sid] = remote_id
            _sid_owner[sid] = (current_user.id, _viewer_credential())
        # The session opening is auditable; what gets typed into it is not recorded anywhere —
        # people type passwords into terminals.
        log_action(current_user, "terminal_open", target=remote.name)
        emit("term_ready", {"host": remote.display_name})

    def _still_allowed(sid):
        """Does this socket's user STILL have access to the host its shell is on?

        Cached for _ACCESS_RECHECK_SECONDS: the answer changes when an admin edits a group, not
        between keystrokes, and a group lookup per character would be absurd. Revocation therefore
        takes effect within ten seconds rather than at the next reconnect.
        """
        with _sid_lock:
            remote_id = _sid_host.get(sid)
        if remote_id is None:
            return True                       # no open session of ours on this socket
        now = time.monotonic()
        cached = _sid_access.get(sid)
        if cached is not None and (now - cached[0]) < _ACCESS_RECHECK_SECONDS:
            return cached[1]
        ok = may_shell_on(current_user, RemoteServer.query.get(remote_id))
        _sid_access[sid] = (now, ok)
        if not ok:
            emit("term_error", {"message": "Your access to this host was removed, so the "
                                           "terminal has been closed."})
            _close_and_audit(app, sid, "access to the host was revoked")
        return ok

    def _refused(sid):
        """An event from a socket whose user may no longer use the terminal at all.

        Refusing the event is not enough: the shell stays up and its output keeps streaming to
        this socket. Ask whether the access is really gone — a locked database also makes
        current_user anonymous — and close the shell if it is."""
        sweep_revoked_terminals(app, socketio, only_sid=sid)

    @socketio.on("term_input")
    def on_term_input(data):
        if not _may_use_terminal():
            _refused(request.sid)
            return
        if not _still_allowed(request.sid):
            return
        sess = _ts.get(request.sid)
        if sess is not None:
            sess.write((data or {}).get("data", ""))

    @socketio.on("term_resize")
    def on_term_resize(data):
        if not _may_use_terminal():
            _refused(request.sid)
            return
        if not _still_allowed(request.sid):
            return
        sess = _ts.get(request.sid)
        if sess is not None:
            sess.resize((data or {}).get("cols", 80), (data or {}).get("rows", 24))

    @socketio.on("term_close")
    def on_term_close(_data=None):
        _close_and_audit(app, request.sid, "closed")

    # A browser that closed without term_close must still take the shell with it — but NOT via a
    # second @socketio.on("disconnect"). flask-socketio keeps one handler per event per namespace
    # and the later registration wins outright, so this one would have deleted the console's viewer
    # cleanup: every closed browser stays in _console_viewers and the poller keeps SSH-polling the
    # host for a viewer that is gone. Measured, not guessed — see panel/ops/socket_hooks.py.
    _socket_hooks.add_disconnect_hook(
        lambda sid: _close_and_audit(app, sid, "the connection closed"))

    def _revocation_sweeper():
        """Output needs no input: see sweep_revoked_terminals."""
        while True:
            time.sleep(_ACCESS_RECHECK_SECONDS)
            try:
                with app.app_context():
                    sweep_revoked_terminals(app, socketio)
            except Exception:
                app.logger.debug("terminal revocation sweep failed", exc_info=True)

    supervise("terminal-revocation-sweeper", _revocation_sweeper)
