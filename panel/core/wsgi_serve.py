"""Start the panel's web server: eventlet's WSGI server, with its traceback answer turned off.

Flask-SocketIO's run() keeps its `debug` argument for itself (Werkzeug's debugger, the reloader) and
does not pass it on to eventlet.wsgi.server, whose own `debug` is True by default. With it True, an
exception raised while a streamed body is being sent (a download whose SSH read fails, a database dump,
the console socket's HTTP polling) was answered `500 text/plain` with the whole Python traceback:
install paths, the venv layout, library versions and the exception's text. OWASP Error Handling Cheat
Sheet: an unexpected error gets a generic answer, and its details go to the server's log only.

So the server is started here, the way Flask-SocketIO starts it in eventlet mode (one address from
getaddrinfo, eventlet.listen, eventlet.wrap_ssl with server_side for the self-signed TLS), with
`debug=False` reaching eventlet. The client gets an empty 500 when nothing was sent yet, and a cut
connection when part of the body already was (so a truncated download never reads as a complete one).
The traceback goes to the panel's log instead (_TracebacksOnly): eventlet writes it through the same
`info` as its access log, which stays off as it was.

eventlet is imported inside serve(), never at module level: importing panel must not import eventlet
(EVENTLET_NO_GREENDNS has to be set first).
"""
import logging

_log = logging.getLogger("panel.wsgi")


def _text(msg, args):
    """Format eventlet's log call as it would (`msg % args`), or `msg` itself when that does not format."""
    try:
        return (str(msg) % args) if args else str(msg)
    except (TypeError, ValueError):
        return str(msg)


class _TracebacksOnly:
    """The log given to eventlet.wsgi.server: a failed response's traceback, logged; nothing else.

    eventlet sends its access log, its start-up line and a response's traceback all to `info`. Only the
    traceback starts with "Traceback", and that one goes to the panel's log as an error.
    """

    def info(self, msg, *args, **_kwargs):
        """Log `msg` when it is a traceback; drop the access-log and start-up lines."""
        text = _text(msg, args)
        if text.startswith("Traceback"):
            _log.error("A response failed while it was being sent:\n%s", text)

    def debug(self, *_args, **_kwargs):
        """Nothing: eventlet's debug lines (a client that went away) are not the panel's to keep."""

    def error(self, msg, *args, **_kwargs):
        """Log one of eventlet's own error lines (a request body it could not read) as a warning."""
        _log.warning("web server: %s", _text(msg, args))

    def write(self, msg, *args):
        """The file-like form eventlet may also use: treated as info."""
        self.info(msg, *args)


def serve(app, host, port, ssl_args=None):
    """Serve `app` on host:port until the process ends; `ssl_args` holds certfile/keyfile for TLS."""
    import eventlet
    import eventlet.green.socket
    import eventlet.wsgi
    addresses = eventlet.green.socket.getaddrinfo(host, port)
    if not addresses:
        raise RuntimeError("Could not resolve host to a valid address")
    sock = eventlet.listen(addresses[0][4], addresses[0][0])
    if ssl_args:
        sock = eventlet.wrap_ssl(sock, server_side=True, **ssl_args)
    eventlet.wsgi.server(sock, app, log=_TracebacksOnly(), log_output=True, debug=False)
