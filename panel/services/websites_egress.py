"""A website's only way out: an HTTP CONNECT proxy to a fixed list of hosts, port 443 only.

Run as the site's own account by its user unit (websites.egress_unit), listening on 127.0.0.1:<port>;
pasta forwards the container's 127.0.0.1:3128 to it. WordPress reaches its update hosts through it
(WP_PROXY_HOST), an app's build reaches npm's registry (HTTPS_PROXY). Nothing else gets through:

- only CONNECT, only to a host named on the command line (exact match, lowercase) and only port 443;
- the name is resolved HERE and connected to only when every address is a global one (OWASP SSRF
  Prevention Cheat Sheet: validate the resolved addresses, connect only to those; refuse loopback,
  private, link-local, IPv4-mapped and NAT64 ranges), so a name that resolves into the host's own
  networks is refused;
- TLS stays end to end (the proxy never sees inside), with a connection cap and idle timeouts.

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
    data = b""
    while b"\r\n\r\n" not in data and len(data) < HEAD_MAX:
        chunk = conn.recv(1024)
        if not chunk:
            return ""
        data += chunk
    return data.split(b"\r\n", 1)[0].decode("ascii", "replace") if b"\r\n\r\n" in data else ""


def handle(conn, allowed, slots):
    """Serve one client connection; always closes it and frees its slot."""
    upstream = None
    try:
        conn.settimeout(IDLE_SECONDS)
        want = target(_read_head(conn), allowed)
        addrs = resolve(*want) if want else []
        if not addrs:
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        upstream = socket.create_connection((addrs[0], 443), timeout=15)
        upstream.settimeout(IDLE_SECONDS)
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
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
        threading.Thread(target=handle, args=(conn, allowed, slots), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
