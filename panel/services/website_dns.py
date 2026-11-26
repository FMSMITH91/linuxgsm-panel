"""Whether a website's domain points at its host: DNS answers compared, never connected to.

OWASP Server Side Request Forgery Prevention Cheat Sheet ("Case 2", "Domain name": resolve both A and
AAAA, check every answer; DNS rebinding): the panel makes NO request of any kind to a domain a
customer typed. It asks the operating system's resolver for the name's A and AAAA records (the
panel's own resolver path, core/green_dns, off the event hub) and only compares the addresses with
the host's public ones. An answer that is not a public address (private, loopback, link-local, the
tailnet's shared range, multicast, reserved; an IPv4-mapped IPv6 address is judged as the IPv4 it
carries) marks the domain "private" and it cannot go online: a name pointing a certificate request
or a visitor at the host's internal networks is refused, not merely mismatched.

States (WebsiteDomain.dns_state): matching (every answer is one of the host's public addresses),
mismatch (a public answer that is not the host's), private (an answer that is not public), failed
(no answer).
"""
import ipaddress
import socket

S_STATES = {
    "matching": "The domain points at this website's host.",
    "mismatch": "The domain points somewhere else. Create the A (and AAAA) record shown, then check again.",
    "private": "The domain points at a private or internal address, so it cannot be used for a public website.",
    "failed": "The domain has no A or AAAA record yet. Create the record shown, then check again.",
}


def _address(text):
    """`text` as an ip_address (an IPv4-mapped IPv6 address as its IPv4), or None."""
    try:
        ip = ipaddress.ip_address(str(text).split("%", 1)[0])
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def resolve(domain, lookup=None):
    """The addresses `domain` resolves to (A and AAAA), as canonical strings; [] when it resolves to none."""
    lookup = lookup or socket.getaddrinfo
    try:
        answers = lookup(domain, None, 0, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    out = []
    for entry in answers or []:
        ip = _address(entry[4][0]) if len(entry) > 4 and entry[4] else None
        if ip is not None and str(ip) not in out:
            out.append(str(ip))
    return out


def host_addresses(remote):
    """The host's public addresses the domain must point at: its cached public IP, and its address if public."""
    out = set()
    for text in (getattr(remote, "public_ip", "") or "", getattr(remote, "host", "") or ""):
        ip = _address(text.strip())
        if ip is not None and ip.is_global:
            out.add(str(ip))
    return out


def classify(addresses, host_addrs):
    """The dns_state for resolved `addresses` against the host's public `host_addrs`."""
    if not addresses:
        return "failed"
    ips = [_address(a) for a in addresses]
    if any(ip is None or not ip.is_global for ip in ips):
        return "private"
    return "matching" if host_addrs and all(str(ip) in host_addrs for ip in ips) else "mismatch"


def check(domain, remote, lookup=None):
    """(dns_state, the addresses the domain resolved to, the host's public addresses)."""
    addrs = resolve(domain, lookup)
    hosts = host_addresses(remote)
    return classify(addrs, hosts), addrs, sorted(hosts)


def records(remote):
    """The DNS records the operator creates for a domain of a site on `remote`: [(type, address)]."""
    return [("AAAA" if ":" in a else "A", a) for a in sorted(host_addresses(remote))]
