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

from flask import render_template, request
from flask_login import current_user, login_required
from flask_socketio import emit

from panel.db.models import RemoteServer
from panel.ops import terminal_session as _ts
from panel.security.auth import (USE_TERMINAL, get_remote, has_permission, log_action,
    permission_required)

# sid -> (remote_id or None). Only used to label audit rows and to tear down on disconnect.
_sid_host = {}
_sid_lock = threading.Lock()


def _may_use_terminal():
    return bool(current_user.is_authenticated
                and (current_user.is_superadmin or has_permission(current_user, USE_TERMINAL)))


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
                               sudo_note=_ts.sudo_hint(remote, bool(remote.is_local)))

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

    @socketio.on("term_input")
    def on_term_input(data):
        if not _may_use_terminal():
            return
        sess = _ts.get(request.sid)
        if sess is not None:
            sess.write((data or {}).get("data", ""))

    @socketio.on("term_resize")
    def on_term_resize(data):
        if not _may_use_terminal():
            return
        sess = _ts.get(request.sid)
        if sess is not None:
            sess.resize((data or {}).get("cols", 80), (data or {}).get("rows", 24))

    @socketio.on("term_close")
    def on_term_close(_data=None):
        _close_and_audit(request.sid, "closed")

    @socketio.on("disconnect")
    def on_term_disconnect():
        # A browser that closed without term_close must still take the shell with it. The console
        # registers its own disconnect handler too; flask-socketio runs both.
        _close_and_audit(request.sid, "the connection closed")

    def _close_and_audit(sid, reason):
        with _sid_lock:
            remote_id = _sid_host.pop(sid, None)
        if remote_id is None:
            return          # this socket had no terminal — nothing to do
        _ts.close_for_sid(sid, reason)
        try:
            remote = RemoteServer.query.get(remote_id)
            log_action(current_user if current_user.is_authenticated else None,
                       "terminal_close", target=(remote.name if remote else str(remote_id)),
                       detail=reason)
        except Exception:
            app.logger.debug("terminal close audit failed", exc_info=True)
