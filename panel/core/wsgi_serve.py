"""Start the panel's web server: eventlet's WSGI server, with its traceback answer turned off.

Flask-SocketIO's run() keeps its `debug` argument for itself (Werkzeug's debugger, the reloader) and
does not pass it on to eventlet.wsgi.server, whose own `debug` is True by default. With it True, an
exception raised while a streamed body is being sent (a download whose SSH read fails, a database dump,
the console socket's HTTP polling) was answered `500 text/plain` with the whole Python traceback:
install paths, the venv layout, library versions and the exception's text. OWASP Error Handling Cheat
Sheet: an unexpected error gets a generic answer, and its details go to the server's log only.

So the server is started here, the way Flask-SocketIO starts it in eventlet mode (one address from
getaddrinfo, eventlet.listen, a server-side TLS socket when the panel serves TLS itself), with
`debug=False` reaching eventlet. The client gets an empty 500 when nothing was sent yet, and a cut
connection when part of the body already was (so a truncated download never reads as a complete one).
The traceback goes to the panel's log instead (_TracebacksOnly): eventlet writes it through the same
`info` as its access log, which stays off as it was.

A client that hangs up mid-response (it closes or resets the connection while the body is still being
sent) is not a fault of the panel's, and its traceback is not logged (_client_hung_up): eventlet reports
the BrokenPipeError / ConnectionResetError of that write through the same `info`, and anyone could
request a static file, read one byte and reset, adding ~1 KB of ERROR to the log each time with no
account and no rate limit. OWASP Logging Cheat Sheet, "Attacks on Logs" (availability: an attacker
floods the log) and "Verification" (logging cannot be used to deplete resources). A traceback whose
chain holds any other exception (a real failure the hang-up interrupted) is still logged in full.

A request line with no HTTP version (HTTP/0.9, `GET /` and nothing else) is refused with a bare 400
before eventlet builds its environ (_protocol): eventlet's get_environ reads `self.headers` as a
header Message, and for HTTP/0.9 the standard library leaves it a plain dict, so every such line
raised AttributeError in the hub and printed two chained tracebacks (~35 lines) to the log, outside
_TracebacksOnly. Anyone who could reach the port could add them at will. OWASP Logging Cheat Sheet:
protect the log from being flooded by an unauthenticated client; Error Handling Cheat Sheet: a
malformed request is the client's error, answered without detail. Nothing is logged for it.

The panel's own TLS (tls_context) offers what the OWASP Transport Layer Security Cheat Sheet
recommends ("Only Support Strong Protocols", "Only Support Strong Ciphers"): TLS 1.3, and TLS 1.2
only with forward-secret AEAD suites (ECDHE with AES-GCM or ChaCha20-Poly1305), no CBC. Python's
default server list also offered two TLS 1.2 ECDHE-ECDSA CBC suites.

Idle and slow connections are closed, one source cannot hold the server, and running out of
descriptors does not end the server (OWASP Denial of Service Cheat Sheet, "Rate limiting": request-read
timeouts with a minimum ingress data rate against slow HTTP attacks, an absolute connection timeout, a
load limit). eventlet's defaults were `socket_timeout=None` and `keepalive=True`: a connection that
sent nothing waited in readline for ever, holding a green thread and a descriptor, so about a thousand
idle TCP connections (no account needed) used the process's 1,024 descriptors, accept() raised EMFILE,
eventlet re-raised it out of server(), and the process ended; Restart=always brought it back for the
same connections to take down again. Timeouts per read alone were not enough either: a client sending
one byte every few seconds made progress on every read, so it kept its connection for days, and about
1,024 of them filled eventlet's pool, after which nobody was served (review 1120). Now:
  * IDLE_SECONDS: from the end of a request (or the accept) to the next request's first byte, the TLS
    handshake included, whatever arrives in between (_Protocol._first_byte, one eventlet.Timeout);
  * HEADER_SECONDS: from that first byte to the end of the request's headers, however they trickle
    (one eventlet.Timeout, cancelled when the request reaches the app: from then on the time is the
    app's, and a WebSocket's upgrade or a polling request is not cut);
  * a request body: BODY_GRACE_SECONDS of waiting for the client, plus one second for every
    BODY_MIN_RATE bytes it has sent (_PacedBody); only time spent waiting for the client counts;
  * io_seconds(): every read and write also gives up after this long with no progress. It is longer
    than Socket.IO's own heartbeat window (socket_hooks.LIMITS: a ping every ping_interval, answered
    within ping_timeout). Once a WebSocket is open, engineio sets that window as the socket's
    timeout itself (engineio socket.py _websocket_handler), and the browser answers every ping, so a
    live console or terminal is not cut by any of these;
  * PER_SOURCE_CONNECTIONS: one source (an IPv6 one by its /64) holds at most this many connections;
    a further one is closed as soon as it is accepted (_SourceCap). Loopback is not counted: behind
    Tailscale Serve or a proxy on the box every viewer arrives on it. Those viewers are not capped
    per client (docs/THREAT-MODEL.md, Residual risks: the cap acts before headers are read, and a
    proxy may reuse one connection for many clients); the deadlines below still apply to them;
  * a client that stops reading an answer, or stalls its body, is ClientStalled, which the log treats
    like a client that hung up (_client_hung_up): nothing is logged for it, as for a reset;
  * the listening socket's accept() (_Listener) waits and tries again on EMFILE, ENFILE, ENOBUFS and
    ENOMEM instead of ending the server, and on the errors Linux passes up from a connection that
    failed before it was accepted (accept(2), "Error handling"), which eventlet also took as the end;
  * the pool of connections stays eventlet's 1,024, and the unit sets LimitNOFILE (install.sh), so
    that pool can never take every descriptor the panel's own work needs.

eventlet is imported inside serve(), never at module level: importing panel must not import eventlet
(EVENTLET_NO_GREENDNS has to be set first).
"""
import errno
import ipaddress
import logging
import ssl
import sys
import time

_log = logging.getLogger("panel.wsgi")


def _text(msg, args):
    """Format eventlet's log call as it would (`msg % args`), or `msg` itself when that does not format."""
    try:
        return (str(msg) % args) if args else str(msg)
    except (TypeError, ValueError):
        return str(msg)


# The errors of a write to a client that has gone away: it closed (EPIPE), reset (ECONNRESET) or
# aborted (ECONNABORTED) the connection, or shut its side down (ESHUTDOWN). eventlet's own BROKEN_SOCK.
_HANGUP_ERRNOS = frozenset({errno.EPIPE, errno.ECONNRESET, errno.ECONNABORTED, errno.ESHUTDOWN})


class ClientStalled(TimeoutError):
    """The client stopped keeping up: it sent its request, or read the answer, too slowly.

    Raised in place of the socket's own timeout wherever the client is the one being waited for (the
    request's first byte, its line and headers, its body, a write it does not read), and only there, so
    a timeout of the panel's own (an SSH read inside a streamed download) is still a TimeoutError of
    another class and is still logged. A TimeoutError, so eventlet's process_request takes it as the
    expected end of a connection (`except socket.timeout`) and closes it without a word.
    """


def _client_hung_up(exc):
    """Whether `exc` and every exception in its chain is the client going away or stalling.

    A write to a client that closed or reset the connection (_HANGUP_ERRNOS), or a ClientStalled (a
    client that stopped reading). False for no exception, and for a chain that also holds any other
    one (a real failure, then the hang-up while it was handled). The walk is bounded, as a chain may
    be built by hand.
    """
    found = False
    for _ in range(8):
        if exc is None:
            return found
        if not isinstance(exc, ClientStalled) and (not isinstance(exc, OSError) or exc.errno not in _HANGUP_ERRNOS):
            return False
        found = True
        exc = exc.__cause__ or exc.__context__
    return False


class _TracebacksOnly:
    """The log given to eventlet.wsgi.server: a failed response's traceback, logged; nothing else.

    eventlet sends its access log, its start-up line and a response's traceback all to `info`. Only the
    traceback starts with "Traceback", and that one goes to the panel's log as an error, unless the
    exception being handled is the client hanging up (_client_hung_up): eventlet calls `info` inside its
    `except` block, so sys.exc_info() is the exception the traceback was formatted from.
    """

    def info(self, msg, *args, **_kwargs):
        """Log `msg` when it is a traceback of a real failure; drop the rest (access log, start-up, hang-ups)."""
        text = _text(msg, args)
        if text.startswith("Traceback") and not _client_hung_up(sys.exc_info()[1]):
            _log.error("A response failed while it was being sent:\n%s", text)

    def debug(self, *_args, **_kwargs):
        """Nothing: eventlet's debug lines (a client that went away) are not the panel's to keep."""

    def error(self, msg, *args, **_kwargs):
        """Log one of eventlet's own error lines (a request body it could not read) as a warning.

        Not when the body could not be read because the client hung up or stalled (_client_hung_up):
        that line names the client's own request, and anyone could add one per connection.
        """
        if _client_hung_up(sys.exc_info()[1]):
            return
        _log.warning("web server: %s", _text(msg, args))

    def write(self, msg, *args):
        """The file-like form eventlet may also use: treated as info."""
        self.info(msg, *args)


# TLS 1.2's suites: ECDHE key exchange (forward secrecy) with an AEAD cipher, for an ECDSA key (the
# panel's own certificate) or an RSA one (an operator's or Let's Encrypt's). TLS 1.3's suites are all
# AEAD and are not set by this list.
TLS12_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL"

# The answer to a request line the server will not read (no HTTP version): no body, nothing logged.
_BAD_REQUEST = b"HTTP/1.0 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"


def tls_context(certfile, keyfile, ssl_module=ssl):
    """A server context with the TLS cheat sheet's protocol floor and cipher list, the pair loaded.

    `ssl_module` is eventlet's green ssl when serving (its SSLContext makes green sockets) and the
    standard library's otherwise. PROTOCOL_TLS_SERVER already keeps compression off and the server's
    cipher order; the floor is set here rather than left to the system's OpenSSL configuration.
    """
    ctx = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl_module.TLSVersion.TLSv1_2
    ctx.set_ciphers(TLS12_CIPHERS)
    ctx.load_cert_chain(certfile, keyfile)
    return ctx


class _ClientWrites:
    """The response's writer (the protocol's wfile): a write the client does not read in time is ClientStalled.

    The socket's own timeout (io_seconds()) is a TimeoutError like any other, and eventlet logs a
    failed response's traceback, so a client that asked for a large answer and never read it put one
    ERROR traceback in the log per connection per minute: no account needed, and a phone that slept
    mid-download read as a panel fault. Raised outside the `except`, so the chain holds nothing else.

    Once stalled, nothing more is tried: the buffer still held what the client never read, and the
    end of the request flushed it twice more (the handler's finish, then the writer's close), each
    waiting io_seconds() again, so a stalled client held its connection for three timeouts.
    """

    def __init__(self, fileobj):
        self._f = fileobj
        self._stalled = False

    def __getattr__(self, name):
        return getattr(self._f, name)

    def _call(self, fn, *args):
        if not self._stalled:
            try:
                return fn(*args)
            except TimeoutError:
                self._stalled = True    # raised below, outside the except, so the chain holds nothing else
        raise ClientStalled("the client stopped reading the response")

    def close(self):
        """Close the writer; after a stall, drop what the client never read instead of waiting to send it."""
        if self._stalled:
            raw = getattr(self._f, "raw", None)
            if raw is not None:
                raw.close()     # a closed raw stream makes the buffered close a no-op (no flush)
        return self._f.close()

    def write(self, data):
        """The buffered writer's write, ClientStalled on a timeout."""
        return self._call(self._f.write, data)

    def writelines(self, lines):
        """The buffered writer's writelines, ClientStalled on a timeout."""
        return self._call(self._f.writelines, lines)

    def flush(self):
        """The buffered writer's flush, ClientStalled on a timeout."""
        return self._call(self._f.flush)


_STALLED = object()     # _PacedBody._paced's read that timed out


class _PacedBody:
    """The request body's reader (what wsgi.input reads from): the client must keep a minimum rate.

    The socket's timeout is per read, so a body sent one byte a minute held a green thread for as long
    as the client liked. Here the client gets `grace` seconds of waiting, plus one more for every
    `rate` bytes it has sent (Apache's RequestReadTimeout body=…,MinRate=…, the example the OWASP
    Denial of Service Cheat Sheet gives under "Rate limiting"). Only time spent waiting for the client
    counts: a route that reads a piece and then spends a minute on it (an upload copied on over SSH)
    loses nothing. Past the budget the read raises ClientStalled (werkzeug answers the request as a
    client disconnect) and the connection is closed, never kept alive to read the rest.
    """

    def __init__(self, rfile, handler, timeout, grace, rate):
        self._f = rfile
        self._handler = handler
        self._timeout = timeout
        self._grace = grace
        self._rate = rate
        self._waited = 0.0
        self._got = 0

    def __getattr__(self, name):
        return getattr(self._f, name)

    def budget(self):
        """Seconds the client may still keep the next read waiting."""
        return self._grace + self._got / self._rate - self._waited

    def _paced(self, fn, *args):
        """Call the read `fn` inside the budget; a stall of either kind is ClientStalled, and ends the connection.

        The socket's own timeout (io_seconds()) usually fires before a budget that has grown past it
        (a client that sent at a fair rate, then stopped). That plain TimeoutError left the connection
        open, so eventlet's discard of the unread body read the timed-out socket again and logged a
        warning naming the client's request, one per stalled connection. Any other failed read also
        closes the connection: the socket is never read again.
        """
        left = self.budget()
        started = time.monotonic()
        try:
            if left <= 0:
                raise ClientStalled("the client sent its request body too slowly")
            with self._timeout(left, ClientStalled("the client sent its request body too slowly")):
                data = fn(*args)
        except TimeoutError:          # ClientStalled (the budget) or the socket's own timeout
            data = _STALLED
        except OSError:
            self._handler.close_connection = 1
            raise
        finally:
            self._waited += time.monotonic() - started
        if data is _STALLED:
            self._handler.close_connection = 1
            raise ClientStalled("the client sent its request body too slowly")   # outside the except: no chain
        self._got += sum(map(len, data)) if isinstance(data, list) else len(data or b"")
        return data

    def read(self, *args):
        """The buffered reader's read, inside the body's time budget."""
        return self._paced(self._f.read, *args)

    def readline(self, *args):
        """The buffered reader's readline, inside the body's time budget."""
        return self._paced(self._f.readline, *args)

    def readlines(self, *args):
        """The buffered reader's readlines, inside the body's time budget."""
        return self._paced(self._f.readlines, *args)


class _DeadlinesMixin:
    """The whole-request deadlines (see the module docstring), mixed into _protocol's class with a timeout.

    `_timeout` is eventlet.Timeout (a class, so reading it from the instance does not bind it) and
    `_limits` the {idle, header, body_grace, body_rate} seconds; _protocol sets both on the class it
    builds, which is the only class this is mixed into.
    """

    _deadline = None

    def setup(self):
        """The base's setup, with a client write that stalls past its timeout read as a hang-up."""
        super().setup()
        self.wfile = _ClientWrites(self.wfile)

    def handle_one_request(self):
        """One request: the next request's first byte within idle seconds, then its headers within header seconds."""
        if not self._first_byte():
            self.close_connection = 1
            return
        # From the request's first byte to the end of its headers: one deadline for the lot.
        self._deadline = self._timeout(self._limits["header"],
                                       ClientStalled("the client sent its request too slowly"))
        try:
            super().handle_one_request()
        finally:
            self._end_deadline()

    def _first_byte(self):
        """Wait (idle seconds at most, a TLS handshake included) for the next request's first byte."""
        peek = getattr(self.rfile, "peek", None)
        if peek is None or self.rfile.closed:
            return True
        try:
            with self._timeout(self._limits["idle"], ClientStalled("no request")):
                return bool(peek(1))
        except OSError:
            # Gone, reset, a failed handshake, or silent for the idle time: nothing to answer.
            return False

    def _end_deadline(self):
        if self._deadline is not None:
            self._deadline.cancel()
            self._deadline = None

    def get_environ(self):
        """The base's environ, with the body read through _PacedBody and the header deadline ended."""
        # The request's headers are in: the app's time is not the client's. The body is read from
        # here on through _PacedBody (wsgi.input and eventlet.input are the same Input).
        self._end_deadline()
        raw = getattr(self, "rfile")   # set by the base handler's setup()
        setattr(self, "rfile", _PacedBody(raw, self, self._timeout, self._limits["body_grace"],
                                          self._limits["body_rate"]))
        try:
            return super().get_environ()
        finally:
            setattr(self, "rfile", raw)


def _protocol(base, timeout=None, limits=None):
    """Eventlet's HttpProtocol, refusing a request line that names no HTTP version (see the module).

    The other malformed request lines (no method, an unknown protocol, a version past HTTP/1.x) were
    already refused by the standard library's parse_request, but each wrote two lines to stderr, and
    so to the journal, with the line the client sent in them, and its answer named the Python version
    in `Server:`. Both are dropped: the answer says `Server: LinuxGSM Panel`, as the panel's own
    responses do, and nothing an unauthenticated client sends before a request reaches Flask is logged.

    With `timeout` (eventlet.Timeout) and `limits` ({idle, header, body_grace, body_rate}), each request
    also has whole-request deadlines rather than per-read ones (see the module docstring).
    """
    class _Protocol(base):
        def parse_request(self):
            if not super().parse_request():
                return False
            if self.request_version == "HTTP/0.9" or not hasattr(self.headers, "get_all"):
                self.wfile.write(_BAD_REQUEST)
                self.close_connection = True
                return False
            return True

        def log_message(self, *_args):
            """Nothing: the standard library's line for a request line it refused (see above)."""

        def version_string(self):
            """The panel's own Server value, not the standard library's name and Python version."""
            return "LinuxGSM Panel"
    if timeout is None:
        return _Protocol
    return type("_TimedProtocol", (_DeadlinesMixin, _Protocol), {"_timeout": timeout, "_limits": limits})


# A connection with no request in progress (before its first request line, or kept alive between
# two) is closed after this many seconds: from the end of the last request (or the accept) to the next
# request's first byte, a TLS handshake included.
IDLE_SECONDS = 30
# From a request's first byte to the end of its headers, whatever the pace: Apache's own ceiling for the
# header read (mod_reqtimeout's default header=20-40,MinRate=500). A browser sends both in one packet.
HEADER_SECONDS = 40
# A request body: this many seconds of waiting for the client, plus one more for every BODY_MIN_RATE
# bytes it has sent (mod_reqtimeout's MinRate=500, about 4 kbit/s, far below any real link). The grace
# is the read timeout the body had before (io_seconds() with the panel's own heartbeat), so a phone
# whose link stalls at the start of an upload is no worse off than it was.
BODY_GRACE_SECONDS = 60
BODY_MIN_RATE = 500
# Connections one source may hold open at once; a further one is closed as soon as it is accepted. A
# browser opens at most 6 HTTP/1.1 connections to a host plus a Socket.IO socket per open tab, so a
# household or office behind one address, several people with several tabs, stays well inside it.
# Loopback (Tailscale Serve, a reverse proxy on the box, where every viewer arrives as 127.0.0.1 or
# ::1) is not counted: capping it would cap everyone, and the residual risk (no per-client cap behind
# a proxy or Funnel) is in docs/THREAT-MODEL.md.
# An IPv6 source is counted by its /64, the block one subscriber is given.
PER_SOURCE_CONNECTIONS = 64
# Socket.IO's heartbeat window (ping_interval + ping_timeout) is multiplied by this for io_seconds(),
# so a WebSocket answering every ping always reads well inside it: 45 s -> 60 s with the panel's own.
_IO_OVER_HEARTBEAT = 4 / 3
# accept() errors that are a full process or system (descriptors, buffers, memory): wait, then retry.
_ACCEPT_STARVED = frozenset({errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM})
# accept() errors of one connection that failed before it was taken (accept(2): Linux passes pending
# network errors up from accept; treat them as EAGAIN), and the ones eventlet ends server() on.
_ACCEPT_ONE_FAILED = frozenset({errno.ECONNABORTED, errno.EPROTO, errno.ENOPROTOOPT, errno.EHOSTDOWN,
                                errno.ENONET, errno.EHOSTUNREACH, errno.EOPNOTSUPP, errno.ENETUNREACH,
                                errno.ENETDOWN, errno.EPERM, errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN,
                                errno.ETIMEDOUT})
_STARVED_WAIT_MAX = 1.0
_STARVED_LOG_EVERY = 60.0


def io_seconds(limits=None):
    """The read/write timeout for a connection: Socket.IO's heartbeat window times _IO_OVER_HEARTBEAT."""
    if limits is None:
        from panel.ops.socket_hooks import LIMITS
        limits = LIMITS
    return (limits["ping_interval"] + limits["ping_timeout"]) * _IO_OVER_HEARTBEAT


class _Listener:
    """The listening socket, with an accept() that never ends the server over one connection or a full table.

    Everything but accept() is the socket's own (eventlet reads getsockname, family, close).
    """

    def __init__(self, sock, sleep):
        self._sock = sock
        self._sleep = sleep
        self._logged = 0.0

    def __getattr__(self, name):
        return getattr(self._sock, name)

    def accept(self):
        """The next connection; out of descriptors or memory it waits (up to 1 s, doubling) and tries again."""
        wait = 0.05
        while True:
            try:
                return self._sock.accept()
            except OSError as e:
                if e.errno in _ACCEPT_ONE_FAILED:
                    continue
                if e.errno not in _ACCEPT_STARVED:
                    raise
                self._starved(e)
                self._sleep(wait)
                wait = min(wait * 2, _STARVED_WAIT_MAX)

    def _starved(self, e):
        """One warning a minute at most while accept() is starved: the log stays readable under a flood."""
        now = time.monotonic()
        if now - self._logged >= _STARVED_LOG_EVERY:
            self._logged = now
            _log.warning("web server: cannot accept a connection (%s); waiting for one to close",
                         errno.errorcode.get(e.errno, e.errno))


def _source_key(addr):
    """The source a connection from `addr` (accept()'s address) is counted under; None for loopback.

    An IPv4-mapped IPv6 address is its IPv4 address, and an IPv6 address counts as its /64.
    """
    host = str(addr[0] if isinstance(addr, tuple) and addr else addr).partition("%")[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return None
    if ip.version == 6:
        return str(ipaddress.ip_network((ip, 64), strict=False))
    return str(ip)


def _refused(*_args):
    """A refused connection's green thread: nothing to do, eventlet's link closes the socket."""


class _SourceCap:
    """eventlet's pool of connections, holding no more than `cap` from one source (_source_key) at a time.

    Given to eventlet.wsgi.server as its custom_pool: its accept loop calls spawn(process_request,
    [addr, socket, state]) for every connection and links the green thread to its clean-up, which closes
    the socket. A source already at the cap gets a free green thread that does nothing, so its socket is
    closed at once, without waiting for room in the pool (OWASP Denial of Service Cheat Sheet, "Rate
    limiting": a load limit, by the offending address). One warning a minute at most names it.
    """

    def __init__(self, pool, spawn_free, cap):
        self._pool = pool
        self._spawn_free = spawn_free
        self._cap = cap
        self._open = {}
        self._refusals = 0
        self._logged = 0.0

    def open_from(self, key):
        """How many connections from `key` are open (or waiting for room in the pool)."""
        return self._open.get(key, 0)

    def spawn(self, function, conn_state, *args, **kwargs):
        """Start `function(conn_state, ...)` in the pool, or refuse the connection when its source is full."""
        key = _source_key(conn_state[0])
        if key is not None and self._open.get(key, 0) >= self._cap:
            self._refuse(key)
            return self._spawn_free(_refused, conn_state)
        if key is not None:
            self._open[key] = self._open.get(key, 0) + 1
        try:
            return self._pool.spawn(self._run, key, function, conn_state, *args, **kwargs)
        except Exception:
            self._release(key)
            raise

    def _run(self, key, function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        finally:
            self._release(key)

    def _release(self, key):
        if key is None:
            return
        left = self._open.get(key, 0) - 1
        if left > 0:
            self._open[key] = left
        else:
            self._open.pop(key, None)

    def _refuse(self, key):
        self._refusals += 1
        now = time.monotonic()
        if now - self._logged >= _STARVED_LOG_EVERY:
            self._logged = now
            _log.warning("web server: %s already holds %d connections; closed %d more from it since the last "
                         "warning", key, self._cap, self._refusals)
            self._refusals = 0

    def waitall(self):
        """Wait for every greenthread in the pool: eventlet calls this when the server ends."""
        return self._pool.waitall()


def serve(app, host, port, ssl_args=None, idle_seconds=IDLE_SECONDS, io_timeout=None, limits=None):
    """Serve `app` on host:port until the process ends; `ssl_args` holds certfile/keyfile for TLS.

    `idle_seconds` and `io_timeout` (default io_seconds()) are the two connection timeouts above;
    `limits` may replace any of the request deadlines and the per-source cap: {"header":
    HEADER_SECONDS, "body_grace": BODY_GRACE_SECONDS, "body_rate": BODY_MIN_RATE, "per_source":
    PER_SOURCE_CONNECTIONS}.
    """
    import eventlet
    import eventlet.green.socket
    import eventlet.green.ssl
    import eventlet.wsgi
    addresses = eventlet.green.socket.getaddrinfo(host, port)
    if not addresses:
        raise RuntimeError("Could not resolve host to a valid address")
    sock = eventlet.listen(addresses[0][4], addresses[0][0])
    if ssl_args:
        ctx = tls_context(ssl_args["certfile"], ssl_args["keyfile"], eventlet.green.ssl)
        sock = ctx.wrap_socket(sock, server_side=True)
    limits = dict({"header": HEADER_SECONDS, "body_grace": BODY_GRACE_SECONDS, "body_rate": BODY_MIN_RATE,
                   "per_source": PER_SOURCE_CONNECTIONS}, **(limits or {}), idle=idle_seconds)
    pool = _SourceCap(eventlet.GreenPool(eventlet.wsgi.DEFAULT_MAX_SIMULTANEOUS_REQUESTS), eventlet.spawn,
                      limits["per_source"])
    eventlet.wsgi.server(_Listener(sock, eventlet.sleep), app, log=_TracebacksOnly(), log_output=True,
                         debug=False, protocol=_protocol(eventlet.wsgi.HttpProtocol, eventlet.Timeout, limits),
                         keepalive=idle_seconds, socket_timeout=io_seconds() if io_timeout is None else io_timeout,
                         custom_pool=pool)
