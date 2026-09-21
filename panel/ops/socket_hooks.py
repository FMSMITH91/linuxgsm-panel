"""The one place a socket disconnect is handled.

flask-socketio does NOT chain handlers. python-socketio's BaseServer.on ends in

    self.handlers[namespace][event] = handler

— a plain dict assignment, so a second ``@socketio.on("disconnect")`` on the same namespace
silently REPLACES the first and the first never runs again. Verified against the pinned
python-socketio 5.16.3 / flask-socketio 5.6.1.

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


def add_disconnect_hook(fn):
    """Register fn(sid) to run when any socket disconnects.

    Keyed by qualified name, not by identity: register() builds a fresh closure every call, so a
    second app in the same process (which the test suite does routinely) would otherwise stack up
    hooks holding references to a torn-down app."""
    key = getattr(fn, "__qualname__", None) or repr(fn)
    _hooks[key] = fn
    return fn


def run_disconnect_hooks(sid):
    """Run every hook. One that raises must not skip the ones after it — a leaked terminal process
    is not a reason to leak a console viewer too."""
    for fn in list(_hooks.values()):
        try:
            fn(sid)
        except Exception:
            _log.warning("disconnect hook %s failed", getattr(fn, "__name__", fn), exc_info=True)
