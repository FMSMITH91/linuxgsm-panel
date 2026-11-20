"""A byte stream to 127.0.0.1:<port> on a host: how the panel shows an add-on's web page (routes/addon_web.py).

An add-on's page listens on the game host's loopback only, and no port is opened anywhere for it. The
panel reaches it over what it already has to that host:

    the panel's own host   a TCP socket to 127.0.0.1:<port>;
    a direct-SSH host      a "direct-tcpip" channel on the pooled paramiko connection (RFC 4254 7.2),
                           to 127.0.0.1:<port> as the HOST sees it;
    a Tailscale host       the system ssh client's stdio forwarding (`ssh -W 127.0.0.1:<port>`), over the
                           same multiplexed master connection its commands use.

The address is always 127.0.0.1 and the port an int the caller has checked against the add-on's own
record (OWASP Server-Side Request Forgery Prevention Cheat Sheet, "Application layer": the destination
is never taken from the request). Each stream has sendall(data), recv(n) (b"" at the end) and close();
recv gives up with TimeoutError after the stream's timeout with nothing to read.
"""
import os
import select
import socket

from panel.ops.ssh_manager import _core

LOOPBACK = "127.0.0.1"


class TunnelError(ConnectionError):
    """The host or the add-on's page could not be reached (the reason is for the log, never the browser)."""


def _port(port):
    """`port` as an int in 1..65535, or raise TunnelError: only a checked number is ever dialled."""
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        raise TunnelError("not a port number")
    return port


class _SocketStream:
    """A socket or a paramiko channel: both already have sendall, recv, settimeout and close."""

    def __init__(self, conn, timeout):
        self._conn = conn
        conn.settimeout(timeout)

    def sendall(self, data):
        """Send all of `data`."""
        self._conn.sendall(data)

    def settimeout(self, seconds):
        """Give each later recv `seconds` to get something."""
        self._conn.settimeout(seconds)

    def recv(self, n):
        """Up to `n` bytes; b"" once the other side has finished; TimeoutError past the timeout."""
        try:
            return self._conn.recv(n)
        except socket.timeout as e:
            raise TimeoutError("no answer from the add-on's page") from e

    def close(self):
        """Close the stream; one that is already closed is fine."""
        try:
            self._conn.close()
        except Exception:  # nosec B110 - closing a stream the other side already dropped is not a failure
            _core._log.debug("tunnel close: already closed", exc_info=True)


class _ProcessStream:
    """The ssh client's stdin and stdout as a stream (`ssh -W` for a Tailscale host)."""

    def __init__(self, proc, timeout):
        self._p = proc
        self._timeout = timeout

    def sendall(self, data):
        """Write all of `data` to the client's stdin."""
        fd, view = self._p.stdin.fileno(), memoryview(data)
        while view:
            n = os.write(fd, view)
            if not n:
                raise TunnelError("the ssh client closed its input")
            view = view[n:]

    def settimeout(self, seconds):
        """Give each later recv `seconds` to get something."""
        self._timeout = seconds

    def recv(self, n):
        """Up to `n` bytes of the client's stdout; b"" at its end; TimeoutError past the timeout."""
        fd = self._p.stdout.fileno()
        ready, _w, _x = select.select([fd], [], [], self._timeout)
        if not ready:
            raise TimeoutError("no answer from the add-on's page")
        return os.read(fd, n)

    def close(self):
        """End the client (its forwarding ends with it) and reap it."""
        for pipe in (self._p.stdin, self._p.stdout):
            try:
                pipe.close()
            except Exception:  # nosec B110 - a pipe the child already closed
                _core._log.debug("tunnel close: pipe already closed", exc_info=True)
        try:
            self._p.terminate()
            self._p.wait(timeout=5)
        except Exception:
            _core._log.debug("tunnel close: the ssh client did not end on its own", exc_info=True)
            _core._kill_quietly(self._p)


def _local(port, timeout):
    try:
        return _SocketStream(socket.create_connection((LOOPBACK, port), timeout=timeout), timeout)
    except OSError as e:
        raise TunnelError("the add-on's page did not answer on this host: %s" % e.strerror) from e


def _paramiko(server, port, timeout):
    transport = _core.get_connection(server).get_transport()
    if transport is None or not transport.is_active():
        raise TunnelError("the SSH connection to the host is closed")
    try:
        chan = transport.open_channel("direct-tcpip", (LOOPBACK, port), (LOOPBACK, 0), timeout=timeout)
    except Exception as e:
        # paramiko's ChannelException when sshd refuses (AllowTcpForwarding no, nothing listening).
        raise TunnelError("the host refused the forwarded connection: %s" % type(e).__name__) from e
    return _SocketStream(chan, timeout)


def _ssh_cli_argv(server, port):
    try:
        return (["ssh", "-T", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
                 "-o", "ConnectTimeout=%d" % _core._ssh_connect_timeout()] + _core._ssh_mux_opts()
                + ["-W", "%s:%d" % (LOOPBACK, port), "-p", _core._ssh_port_arg(server), _core.SSH_DEST_SEP,
                   _core.ssh_destination(server.username, _core._resolve_ts_host(server))])
    except (TypeError, ValueError) as e:
        raise TunnelError("the host's stored ssh login or address can't be used") from e


def _tailscale(server, port, timeout):
    argv = _ssh_cli_argv(server, port)
    try:
        proc = _core.subprocess.Popen(argv, stdin=_core.subprocess.PIPE,  # nosec B603  # nosemgrep - an argv list, no shell
                                      stdout=_core.subprocess.PIPE, stderr=_core.subprocess.DEVNULL)
    except OSError as e:
        raise TunnelError("couldn't start the ssh client") from e
    return _ProcessStream(proc, timeout)


def open_loopback(server, port, timeout=30):
    """A stream to 127.0.0.1:`port` on `server`'s host (see the module docstring); raises TunnelError."""
    port = _port(port)
    if _core.is_local_server(server):
        return _local(port, timeout)
    if getattr(server, "auth_method", "") == "tailscale":
        return _tailscale(server, port, timeout)
    try:
        return _paramiko(server, port, timeout)
    except TunnelError:
        raise
    except Exception as e:
        raise TunnelError("couldn't reach the host: %s" % type(e).__name__) from e
