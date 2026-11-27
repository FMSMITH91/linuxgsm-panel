"""A website's only way out: an HTTP CONNECT proxy to a fixed list of hosts, port 443 only.

Run as the site's own account by its user unit (websites.egress_unit), listening on 127.0.0.1:<port>;
pasta forwards the container's 127.0.0.1:3128 to it. WordPress reaches its update hosts through it
(WP_PROXY_HOST), an app's build reaches npm's registry (HTTPS_PROXY). Nothing else gets through:

- only CONNECT, only to a host named on the command line (exact match, lowercase) and only port 443;
- the name is resolved HERE and connected to only when every address is a global one (OWASP SSRF
  Prevention Cheat Sheet: validate the resolved addresses, connect only to those; refuse loopback,
  private, link-local, IPv4-mapped and NAT64 ranges), so a name that resolves into the host's own
  networks is refused;
- TLS stays end to end (the proxy never sees inside), with a connection cap and idle timeouts;
- each validated address is tried in turn, and only those (the cheat sheet: connect only to the validated
  addresses, and apply that to retries and fallback connections too), so one unreachable address (an IPv6 one on
  a host without IPv6, say) does not fail the request;
- bytes the client sent after its CONNECT head (a TLS hello sent without waiting) are passed on, not dropped;
- every refusal and failed connection is one line on stderr (the unit's journal: the host name and the reason,
  never anything from inside the tunnel), so a site that cannot reach its update hosts says why.

Usage: egress_proxy.py <port> <host> [<host> ...]   Standard library only; run with python3 -I.
"""
import ipaddress
import re
import socket
import sys
import threading

MAX_CONNECTIONS = 32
IDLE_SECONDS = 120
HEAD_MAX = 4096
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def address_ok(text):
    """Whether `text` is an address a site may connect to: global, not mapped, not NAT64, not multicast."""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    if addr.version == 6 and (addr.ipv4_mapped is not None or any(addr in n for n in _NAT64)):
        return False
    return addr.is_global and not addr.is_multicast


def target(request_line, allowed):
    """(host, 443) when `request_line` is a CONNECT to an allowed host on 443, else None."""
    parts = request_line.split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or not parts[2].startswith("HTTP/1."):
        return None
    host, sep, port = parts[1].rpartition(":")
    host = host.lower()
    if not sep or port != "443" or not _HOST_RE.match(host) or host not in allowed:
        return None
    return host, 443


def resolve(host, port, getaddrinfo=socket.getaddrinfo):
    """The addresses of `host` to connect to, or [] when any of them is not address_ok (all or nothing)."""
    try:
        infos = getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return []
    addrs = [i[4][0] for i in infos]
    return addrs if addrs and all(address_ok(a) for a in addrs) else []


def _pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass  # either side closed or timed out: the tunnel ends
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # already closed


def _read_head(conn):
    """(the request line, the bytes after the head) of a client's request; ("", b"") for none within HEAD_MAX."""
    got = b""
    while b"\r\n\r\n" not in got and len(got) < HEAD_MAX:
        chunk = conn.recv(1024)
        if not chunk:
            return "", b""
        got += chunk
    if b"\r\n\r\n" not in got:
        return "", b""
    head, rest = got.split(b"\r\n\r\n", 1)
    return head.split(b"\r\n", 1)[0].decode("ascii", "replace"), rest


def say(text):
    """One line on stderr (the unit's journal)."""
    try:
        sys.stderr.write("egress: %s\n" % text)
        sys.stderr.flush()
    except (OSError, ValueError):
        pass  # no journal to write to: the answer to the site is unchanged


def connect(addrs, port=443):
    """A connection to the first of `addrs` (all validated) that answers, or None when none does."""
    for addr in addrs:
        try:
            return socket.create_connection((addr, port), timeout=15)
        except OSError as e:
            say("could not connect to %s: %s" % (addr, e.strerror or type(e).__name__))
    return None


def _why(want, addrs):
    if not want:
        return "not an allowed host on 443"
    return "no global address" if not addrs else "no address answered"


def handle(conn, allowed, slots):
    """Serve one client connection; always closes it and frees its slot."""
    upstream = None
    try:
        conn.settimeout(IDLE_SECONDS)
        line, rest = _read_head(conn)
        want = target(line, allowed)
        addrs = resolve(*want) if want else []
        upstream = connect(addrs) if addrs else None
        if upstream is None:
            # The request line's first two words only: CONNECT and its host, never a header.
            say("refused %s: %s" % (" ".join(line.split(" ")[:2])[:300] or "an empty request", _why(want, addrs)))
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        upstream.settimeout(IDLE_SECONDS)
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        if rest:
            upstream.sendall(rest)
        t = threading.Thread(target=_pipe, args=(upstream, conn), daemon=True)
        t.start()
        _pipe(conn, upstream)
        t.join(IDLE_SECONDS)
    except OSError:
        pass  # a client or upstream error ends this connection only
    finally:
        for s in (conn, upstream):
            if s is not None:
                s.close()
        slots.release()


def main(argv):
    """Listen on 127.0.0.1:<port> and serve until killed."""
    if len(argv) < 3 or not argv[1].isdecimal():
        sys.stderr.write(__doc__)
        return 2
    allowed = frozenset(h.lower() for h in argv[2:] if _HOST_RE.match(h.lower()))
    srv = socket.create_server(("127.0.0.1", int(argv[1])))
    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
    while True:
        conn, _peer = srv.accept()
        if not slots.acquire(blocking=False):
            conn.close()
            continue
        try:
            threading.Thread(target=handle, args=(conn, allowed, slots), daemon=True).start()
        except RuntimeError:
            # No thread to be had (the unit's task limit): this connection is closed, the proxy keeps serving.
            conn.close()
            slots.release()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
