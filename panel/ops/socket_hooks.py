"""The one place a socket disconnect is handled.

flask-socketio does NOT chain handlers. python-socketio's BaseServer.on ends in

    self.handlers[namespace][event] = handler

— a plain dict assignment, so a second ``@socketio.on("disconnect")`` on the same namespace
silently REPLACES the first and the first never runs again. Verified against the pinned
python-socketio 5.17.0 / flask-socketio 5.6.1.

That is not a theoretical risk here: the host terminal registered its own disconnect handler and
took out the console's viewer cleanup, which would have left every closed browser in
``_console_viewers`` forever and kept the poller SSH-ing ``stat -c%s`` at the host on its behalf.

So there is exactly ONE disconnect handler in this app (panel/routes/server_files.py) and anything
else that needs to clean up per-socket registers a hook here. tests/unit/part06.py fails the build
if a second one ever appears.
"""
import logging

_log = logging.getLogger(__name__)

_hooks = {}

# The app's one SocketIO is built with these (routes/server_files.py). OWASP WebSocket Security Cheat
# Sheet, "Denial-of-Service Protection": an explicit message size limit, 64 KB, and heartbeats that find
# a dead connection. The largest message a browser sends is a terminal paste, which host_terminal.js
# cuts into pieces of 8192 UTF-16 units (under 50 KB JSON-escaped); the rest are a server id or a
# terminal size. A bigger message closes that connection (engineio's own rule, for the websocket frame
# and a polling POST alike), and the handshake tells the client the limit (maxPayload). The heartbeat
# is engineio's: a ping every 25 s, and a peer silent 20 s more is gone, so a vanished phone's console
# viewer and terminal are dropped within 45 s while a slow link is not.
LIMITS = {"max_http_buffer_size": 64 * 1024, "ping_interval": 25, "ping_timeout": 20}


def add_disconnect_hook(fn):
    """Register fn(sid) to run when any socket disconnects.

    Keyed by definition site (module and qualified name), not by identity: register() builds a
    fresh closure every call, so a second app in the same process (which the test suite does
    routinely) would otherwise stack up hooks holding references to a torn-down app. The module is
    part of the key because the qualified name alone is not unique: every route module's entry
    point is called register, so two modules' `lambda sid: ...` were both
    "register.<locals>.<lambda>" and the second silently replaced the first.
    """
    key = (getattr(fn, "__module__", None) or "", getattr(fn, "__qualname__", None) or repr(fn))
    _hooks[key] = fn
    return fn


def run_disconnect_hooks(sid):
    """Run every registered disconnect hook for `sid`.

    One that raises must not skip the ones after it — a leaked terminal process is not a reason to
    leak a console viewer too.
    """
    for fn in list(_hooks.values()):
        try:
            fn(sid)
        except Exception:
            _log.warning("disconnect hook %s failed", getattr(fn, "__name__", fn), exc_info=True)
