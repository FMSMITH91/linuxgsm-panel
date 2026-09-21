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

from flask import render_template, request
from flask_login import current_user, login_required
from flask_socketio import emit

from panel.db.models import RemoteServer
from panel.ops import socket_hooks as _socket_hooks
from panel.ops import terminal_session as _ts
from panel.security.auth import (USE_TERMINAL, get_remote, has_permission, log_action,
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


def register(app, socketio, supervise):
    _ts.start_idle_sweeper(supervise)

    @app.route("/terminal/<int:remote_id>")
    @login_required
    @permission_required(USE_TERMINAL)
    def host_terminal(remote_id):
        """A shell on one host. get_remote() enforces per-host access (and 404s), which is also
        what rbac_test's <remote_id> sweep requires to see."""
        remote = get_remote(remote_id)
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
        with _sid_lock:
            _sid_host[sid] = remote_id
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
        from panel.security.auth import can_access_remote
        ok = bool(current_user.is_superadmin or can_access_remote(current_user, remote_id))
        _sid_access[sid] = (now, ok)
        if not ok:
            emit("term_error", {"message": "Your access to this host was removed, so the "
                                           "terminal has been closed."})
            _close_and_audit(sid, "access to the host was revoked")
        return ok

    @socketio.on("term_input")
    def on_term_input(data):
        if not _may_use_terminal() or not _still_allowed(request.sid):
            return
        sess = _ts.get(request.sid)
        if sess is not None:
            sess.write((data or {}).get("data", ""))

    @socketio.on("term_resize")
    def on_term_resize(data):
        if not _may_use_terminal() or not _still_allowed(request.sid):
            return
        sess = _ts.get(request.sid)
        if sess is not None:
            sess.resize((data or {}).get("cols", 80), (data or {}).get("rows", 24))

    @socketio.on("term_close")
    def on_term_close(_data=None):
        _close_and_audit(request.sid, "closed")

    # A browser that closed without term_close must still take the shell with it — but NOT via a
    # second @socketio.on("disconnect"). flask-socketio keeps one handler per event per namespace
    # and the later registration wins outright, so this one would have deleted the console's viewer
    # cleanup: every closed browser stays in _console_viewers and the poller keeps SSH-polling the
    # host for a viewer that is gone. Measured, not guessed — see panel/ops/socket_hooks.py.
    _socket_hooks.add_disconnect_hook(
        lambda sid: _close_and_audit(sid, "the connection closed"))

    def _close_and_audit(sid, reason):
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
        if remote_id is None:
            return          # nothing to audit: this socket never got as far as an open session
        try:
            remote = RemoteServer.query.get(remote_id)
            log_action(current_user if current_user.is_authenticated else None,
                       "terminal_close", target=(remote.name if remote else str(remote_id)),
                       detail=reason)
        except Exception:
            app.logger.debug("terminal close audit failed", exc_info=True)
