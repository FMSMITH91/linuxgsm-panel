"""The panel process's LISTEN sockets from /proc/net/tcp and tcp6, read once per report (R19, R38).

Owner: builder B3.

listening() -> list of {"addr": str, "port": int, "family": 4|6, "inode": int} owned by this process,
    or raises OSError (the caller prints 'could not be read').

addr_class(text) -> "loopback" | "wildcard" | "tailnet" | "private" | "public" | "not an address"
    The only form a non-loopback, non-wildcard address is ever printed in. Loopback and the
    wildcard are not identifying; every other address is a class.

shown(addr) -> the address itself when loopback or wildcard, else its class in brackets.
"""
import ipaddress
import os
import struct

from panel.ops import system_ops as _so

# Module constants so a test can point them at fixtures; nothing else changes them.
PROC_NET_TCP = {4: "/proc/net/tcp", 6: "/proc/net/tcp6"}
PROC_SELF_FD = "/proc/self/fd"
# A host with tens of thousands of sockets prints megabytes here. LISTEN rows are a handful; the
# read stops after this many rows per table rather than walking every connection on the host.
MAX_ROWS = 50000
# How many of this process's fds are looked at for socket inodes (RLIMIT_NOFILE is the real cap).
MAX_FDS = 65536
_LISTEN = "0A"
# Tailscale's fixed ranges, from their one definition (system_ops._TAILNET_RANGES).
_TAILNET = tuple(ipaddress.ip_network(n) for n in _so._TAILNET_RANGES)


def _socket_inodes():
    """The inodes of every socket this process holds, from /proc/self/fd's readlinks."""
    out = set()
    for i, name in enumerate(os.listdir(PROC_SELF_FD)):
        if i >= MAX_FDS:
            break
        try:
            target = os.readlink(os.path.join(PROC_SELF_FD, name))
        except OSError:
            continue        # the fd closed between the listing and the readlink
        if target.startswith("socket:[") and target.endswith("]"):
            try:
                out.add(int(target[8:-1]))
            except ValueError:
                continue
    return out


def _decode(hexaddr, family):
    """A /proc/net/tcp{,6} address column ('0100007F:1388') as (address text, port)."""
    # The kernel prints each 32-bit word of the address as an integer in HOST byte order (so
    # 127.0.0.1 is 0100007F on a little-endian machine); packing the words natively undoes it. The
    # inverse of auth._proc_net_address.
    host, _, port = hexaddr.partition(":")
    words = [int(host[i:i + 8], 16) for i in range(0, len(host), 8)]
    if len(words) != (4 if family == 6 else 1):
        raise ValueError("address width")
    addr = ipaddress.ip_address(struct.pack("=%dI" % len(words), *words))
    return str(addr), int(port, 16)


def _listen_rows(table, family, inodes):
    """The LISTEN rows of one table that belong to `inodes`, bounded to MAX_ROWS rows."""
    rows = []
    with open(table, encoding="ascii", errors="replace") as fh:
        next(fh, None)                       # the header row
        for n, line in enumerate(fh):
            if n >= MAX_ROWS:
                break
            cols = line.split()
            if len(cols) <= 9 or cols[3] != _LISTEN:
                continue
            try:
                inode = int(cols[9])
                if inode not in inodes:
                    continue
                addr, port = _decode(cols[1], family)
            except (ValueError, struct.error):
                continue
            rows.append({"addr": addr, "port": port, "family": family, "inode": inode})
    return rows


def listening():
    """The LISTEN sockets this process holds. Raises OSError when /proc/net/tcp cannot be read."""
    inodes = _socket_inodes()
    rows = _listen_rows(PROC_NET_TCP[4], 4, inodes)
    try:
        rows += _listen_rows(PROC_NET_TCP[6], 6, inodes)
    except FileNotFoundError:
        pass                # a kernel without IPv6: tcp6 does not exist, which is not an error
    return rows


def _parse(text):
    """An ip_address from text ('[::1]', 'fe80::1%eth0', '::ffff:1.2.3.4' as its IPv4), or None."""
    try:
        a = ipaddress.ip_address(str(text or "").strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped is not None else a


def addr_class(text):
    """The class of an address: never the address itself unless loopback or the wildcard."""
    a = _parse(text)
    if a is None:
        return "not an address"
    if a.is_unspecified:
        return "wildcard"
    if a.is_loopback:
        return "loopback"
    if any(a in n for n in _TAILNET):
        return "tailnet"
    if a.is_private or a.is_link_local:
        return "private"
    return "public"


def shown(addr):
    """The address when it is loopback or the wildcard, else '[<class>]'."""
    cls = addr_class(addr)
    if cls in ("loopback", "wildcard"):
        return str(addr).strip()
    return "[%s]" % cls
