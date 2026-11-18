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

eventlet is imported inside serve(), never at module level: importing panel must not import eventlet
(EVENTLET_NO_GREENDNS has to be set first).
"""
import errno
import logging
import ssl
import sys

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


def _client_hung_up(exc):
    """Whether `exc` and every exception in its chain is a write to a client that went away.

    False for no exception, and for a chain that also holds any other one (a real failure, then the
    hang-up while it was handled). The walk is bounded, as a chain may be built by hand.
    """
    found = False
    for _ in range(8):
        if exc is None:
            return found
        if not isinstance(exc, OSError) or exc.errno not in _HANGUP_ERRNOS:
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
        """Log one of eventlet's own error lines (a request body it could not read) as a warning."""
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


def _protocol(base):
    """Eventlet's HttpProtocol, refusing a request line that names no HTTP version (see the module).

    The other malformed request lines (no method, an unknown protocol, a version past HTTP/1.x) were
    already refused by the standard library's parse_request, but each wrote two lines to stderr, and
    so to the journal, with the line the client sent in them, and its answer named the Python version
    in `Server:`. Both are dropped: the answer says `Server: LinuxGSM Panel`, as the panel's own
    responses do, and nothing an unauthenticated client sends before a request reaches Flask is logged.
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
    return _Protocol


def serve(app, host, port, ssl_args=None):
    """Serve `app` on host:port until the process ends; `ssl_args` holds certfile/keyfile for TLS."""
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
    eventlet.wsgi.server(sock, app, log=_TracebacksOnly(), log_output=True, debug=False,
                         protocol=_protocol(eventlet.wsgi.HttpProtocol))
