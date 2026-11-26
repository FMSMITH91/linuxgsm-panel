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
import functools
import logging
import time

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


def one_argument(handler):
    """Make a Socket.IO event handler take at most one argument; an event sent with more is dropped.

    python-socketio calls a handler with every argument the client put into the event, so
    `2["join_console",{},{}]` called a one-parameter handler with two and raised TypeError, which
    flask-socketio logged with a full traceback, one per packet. A browser page of the panel sends
    one payload per event, so more than one is a client that is not the page: the event is refused
    without a word to it, and one line a minute says so, naming the event (the handler's own name,
    never the client's text). OWASP Error Handling Cheat Sheet: no stack traces for a client's
    mistake; Logging Cheat Sheet, "Attacks on Logs": logging must not be a way to fill the log.
    """
    @functools.wraps(handler)
    def held(*args):
        if len(args) > 1:
            from flask import request
            _log_limited("shape", "socket: dropped an event for %s from %s: it carried %d arguments",
                         handler.__name__, _who(request.environ), len(args))
            return None
        return handler(*args)
    return held


# ── the event budget ──────────────────────────────────────────────────────────────────────────────
# Every packet a browser sends runs on the one eventlet hub, and most events load the account from the
# database before they do anything. With no rate limit, one signed-in socket sending 1,000 join_console
# events a second (to a console it may not even open) held every page, console and terminal of every
# user for seconds at a time. OWASP WebSocket Security Cheat Sheet, "Denial-of-Service Protection": rate
# limit messages, per user where the user is known ("100 messages per minute is a common starting
# point"). So every Socket.IO packet is counted, here, before it is decoded: per account once the socket
# has signed in (that account's connections share one budget), per connection before then. A packet over
# budget is dropped for the price of a dict lookup, and a connection that keeps sending past it is
# closed.
#
# Two budgets, each a token bucket (capacity, refill per second). Everything but terminal typing is held
# to 2 a second, about the cheat sheet's starting point, with room for a phone that wakes and rejoins
# every console it had open at once. The terminal cannot live on 100 a minute: each keystroke is one
# term_input, a held key repeats 30 times a second or more, an application tracking the mouse reports
# every move, and a paste arrives as 8192-character pieces (host_terminal.js _termChunks), so 200 of
# them is a paste of 1.6 million characters.
EVENT_BUDGET = {"general": (120, 2.0), "terminal": (200, 60.0)}
TERMINAL_EVENTS = ("term_input", "term_resize")
# A connection that has this many packets dropped within this many seconds is closed. The browser pages
# never come near it, so reaching it is a client that is not a browser page.
DROP_LIMIT = (60, 10.0)
# The account a socket signed in as, put in its connection's environ by the connect handler.
UID_KEY = "panel.socket_uid"
_STATE_KEY = "panel.socket_budget"
# One line per kind per minute, with a count of the ones held back, so a flood cannot flood the log.
_LOG_EVERY = 60.0
_log_state = {}
_clock = time.monotonic


def note_user(environ, uid):
    """Record the account a socket signed in as (from the connect handler), so its budget is the account's."""
    environ[UID_KEY] = uid


def _event_kind(data):
    """Which budget a raw Socket.IO packet spends: "terminal" for a term_input/term_resize event, else "general".

    None (no budget) for a DISCONNECT, which only ever ends work. Read off the packet text without
    decoding it: an EVENT ("2"), an optional ack id, then `["<name>"`. A packet that only looks like
    one (another namespace, a broken body) reaches no terminal handler, so it costs no more than the
    budget it was given.
    """
    if isinstance(data, str) and data.startswith("1"):
        return None     # a DISCONNECT: it ends the cost, so it is never held back
    if not isinstance(data, str) or not data.startswith("2"):
        return "general"
    i = 1
    while i < len(data) and i < 24 and data[i].isdecimal():
        i += 1
    for name in TERMINAL_EVENTS:
        if data.startswith('["%s"' % name, i):
            return "terminal"
    return "general"


def _take(bucket, kind, now):
    """Spend one token from `bucket` ([tokens, stamp]); False when it is empty."""
    cap, rate = EVENT_BUDGET[kind]
    tokens = min(cap, bucket[0] + max(0.0, now - bucket[1]) * rate)
    bucket[1] = now
    if tokens < 1:
        bucket[0] = tokens
        return False
    bucket[0] = tokens - 1
    return True


def _conn_state(environ):
    """The connection's budget state, kept in its environ: it goes when the connection does."""
    st = environ.get(_STATE_KEY)
    if st is None:
        now = _clock()
        st = environ[_STATE_KEY] = {"general": [EVENT_BUDGET["general"][0], now],
                                    "terminal": [EVENT_BUDGET["terminal"][0], now],
                                    "drops": [now, 0], "closing": False}
    return st


def _within_budget(environ, users, kind):
    """Spend one packet of `kind` for this connection: from its account's budget, or its own before sign-in."""
    if kind is None:
        return True
    now = _clock()
    uid = environ.get(UID_KEY)
    if uid is None:
        return _take(_conn_state(environ)[kind], kind, now)
    if len(users) > 4096:
        # A full bucket is no different from a fresh one, so the idle ones can go.
        for key in [k for k, b in users.items() if now - b[1] > 120]:
            del users[key]
    bucket = users.get((uid, kind))
    if bucket is None:
        bucket = users[(uid, kind)] = [EVENT_BUDGET[kind][0], now]
    return _take(bucket, kind, now)


def _log_limited(kind, msg, *args):
    """Log a warning at most once a minute per kind, saying how many were held back since the last."""
    now = _clock()
    st = _log_state.setdefault(kind, [None, 0])
    if st[0] is not None and 0 <= now - st[0] < _LOG_EVERY:
        st[1] += 1
        return False
    held, st[0], st[1] = st[1], now, 0
    if held:
        msg, args = msg + " (and %d more since the last such line)", args + (held,)
    _log.warning(msg, *args)
    return True


def _who(environ):
    """The account and address a connection belongs to, for a log line: no text the client chose."""
    from panel.core.validation import canonical_ip
    addr = canonical_ip(environ.get("REMOTE_ADDR")) or "an unknown address"
    uid = environ.get(UID_KEY)
    return addr if not isinstance(uid, int) else "account %d at %s" % (uid, addr)


def _close_connection(server, environ, eio_sid):
    """Close a connection, once, from a background task: never from inside its own receive path."""
    st = _conn_state(environ)
    if st["closing"]:
        return
    st["closing"] = True
    server.start_background_task(_close_now, server, eio_sid)


def _close_now(server, eio_sid):
    """Disconnect `eio_sid` at both layers; a connection already gone is not an error."""
    try:
        # Socket.IO's own disconnect first: THE disconnect handler runs (console viewer, terminal), and
        # the page is told, so it does not reconnect on its own.
        sid = server.manager.sid_from_eio_sid(eio_sid, "/")
        if sid is not None:
            server.disconnect(sid, namespace="/")
        # Out of engine.io's table BEFORE it is closed, and closed without waiting. eio.disconnect()
        # waits for a polling client to collect the close, and a POST arriving meanwhile found the
        # session closed but still listed: engine.io's _get_socket raised KeyError out of
        # handle_request, a 500 with a traceback for every such POST. Unlisted first, it is answered
        # "Invalid session" (400, logged once) like any session that is gone.
        sock = server.eio.sockets.pop(eio_sid, None)
        if sock is not None:
            sock.close(wait=False, reason=server.eio.reason.SERVER_DISCONNECT)
    except Exception:
        _log.debug("could not close socket connection %s", eio_sid, exc_info=True)


def _over_budget(server, environ, eio_sid):
    """A packet past the budget: dropped, noted once, and the connection closed if it keeps on."""
    st = _conn_state(environ)
    now = _clock()
    drops = st["drops"]
    if not 0 <= now - drops[0] <= DROP_LIMIT[1]:
        drops[0], drops[1] = now, 0
    drops[1] += 1
    if drops[1] == 1:
        _log_limited("budget", "socket: dropping packets from %s past the event budget", _who(environ))
    if drops[1] >= DROP_LIMIT[0] and not st["closing"]:
        _log_limited("budget-close", "socket: closed a connection from %s that kept sending past the event budget",
                     _who(environ))
        _close_connection(server, environ, eio_sid)


def _raised_in_a_handler(exc):
    """Whether `exc` came out of an event handler (the panel's code) rather than the packet's decoding.

    python-socketio calls every handler through Server._trigger_event; anything raised before that
    frame is the library refusing what the client sent.
    """
    tb = exc.__traceback__
    while tb is not None:
        if tb.tb_frame.f_code.co_name == "_trigger_event":
            return True
        tb = tb.tb_next
    return False


def _protocol_error(server, environ, eio_sid, exc):
    """A packet python-socketio could not take: one short line, no traceback, and the connection closed.

    A client-sent CONNECT_ERROR, an unknown packet type or a broken body each raised out of the
    library's message handler, and engine.io logged every one with a full traceback, 16 to a polling
    POST and before any sign-in: about 175 bytes of log per byte sent. OWASP Logging Cheat Sheet,
    "Attacks on Logs" (availability) and "Verification": logging must not be a way to use up the
    host's resources. The exception's text can hold the client's bytes, so only its type is logged.
    """
    _log_limited("protocol", "socket: closed a connection from %s that sent a malformed Socket.IO packet (%s)",
                 _who(environ or {}), type(exc).__name__)
    if environ is not None:
        _close_connection(server, environ, eio_sid)


def install_event_budget(socketio):
    """Put the event budget and the protocol-error handling in front of every Socket.IO packet.

    Engine.IO hands each message to the one handler registered for "message", which python-socketio
    set to its own _handle_eio_message (verified against python-socketio 5.18.1 / python-engineio
    4.15.1). This takes that place, in engine.io (eio.on, its public API) and on the server object,
    where flask-socketio's test client calls it, and passes on what it lets through.
    """
    server = socketio.server
    inner = server._handle_eio_message
    users = {}

    def on_message(eio_sid, data):
        environ = server.environ.get(eio_sid)
        if environ is not None and not _within_budget(environ, users, _event_kind(data)):
            _over_budget(server, environ, eio_sid)
            return None
        try:
            return inner(eio_sid, data)
        except Exception as exc:
            if _raised_in_a_handler(exc):
                raise
            _protocol_error(server, environ, eio_sid, exc)
            return None

    on_message.budgets = users      # the per-account buckets, for the suite to read and clear
    server._handle_eio_message = on_message
    server.eio.on("message", on_message)
    return on_message
