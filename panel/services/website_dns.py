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
cdn (every answer is inside Cloudflare's published ranges, the signed catalog's list the Restricted
preset uses: the name goes through Cloudflare's proxy, which passes visitors on to the host), mismatch
(a public answer that is neither), private (an answer that is not public), failed (no answer). A
domain is verified, and served by the web proxy, once a check finds it matching or cdn (VERIFIED).
"""
import ipaddress
import socket
import time

S_STATES = {
    "matching": "The domain points at this website's host.",
    "cdn": "This domain goes through Cloudflare, which passes its visitors on to this host.",
    "mismatch": "The domain points somewhere else. Create the A (and AAAA) record shown, then check again.",
    "private": "The domain points at a private or internal address, so it cannot be used for a public website.",
    "failed": "The domain has no A or AAAA record yet. Create the record shown, then check again.",
}


# The states that verify a domain: the web proxy serves it from then on.
VERIFIED = ("matching", "cdn")


def _address(text):
    """Parse `text` into an address object (an IPv4-mapped IPv6 address as its IPv4), or None."""
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


# The tailnet's ranges: a domain never points there, and Tailscale Serve, not the web proxy, holds its 443.
_TAILNET = (ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48"))
LOCAL_FRESH = 60                  # seconds the panel host's interface addresses are reused
_LOCAL = {"at": None, "addrs": set()}


def _iface_addresses(text):
    """The public addresses in `ip -o addr show`'s lines: global scope, not temporary or deprecated, not the tailnet's."""
    from panel.ops.ssh_manager import ufweval
    out = set()
    for line in (text or "").splitlines():
        row = ufweval._ip_addr_row(line)
        if row is None or row[0].startswith("tailscale") or row[2] != "global":
            continue
        words = line.split()
        ip = _address(str(row[1]))
        if (ip is None or not ip.is_global or "temporary" in words or "deprecated" in words
                or any(ip.version == n.version and ip in n for n in _TAILNET)):
            continue
        out.add(str(ip))
    return out


def _read_ip():
    """`ip -o addr show` on the panel's host in the C locale (system_ops._run, as ufweval reads it); "" when unread."""
    from panel.ops import system_ops as _so
    try:
        out, _err, rc = _so._run("export LC_ALL=C.UTF-8 LANG=C.UTF-8; unset LANGUAGE; ip -o addr show", timeout=8)
    except Exception:  # noqa: BLE001 - unread is an answer: the cached public address is still used
        return ""
    return out if rc == 0 else ""


def local_addresses(now=None):
    """The panel host's own public addresses, IPv4 and IPv6, read from its interfaces (reused LOCAL_FRESH seconds)."""
    now = time.monotonic() if now is None else now
    if _LOCAL["at"] is not None and now - _LOCAL["at"] < LOCAL_FRESH:
        return set(_LOCAL["addrs"])
    addrs = _iface_addresses(_read_ip())
    _LOCAL.update(at=now, addrs=addrs)
    return set(addrs)


def host_addresses(remote):
    """The host's public addresses a domain must point at.

    Its cached public IP and its address when public, and for the panel's own host (where websites run) the
    public IPv4 and IPv6 addresses on its interfaces, read again every LOCAL_FRESH seconds: a correct AAAA
    record matches, and a changed address is noticed without the Servers page.
    """
    out = set()
    for text in (getattr(remote, "public_ip", "") or "", getattr(remote, "host", "") or ""):
        ip = _address(text.strip())
        if ip is not None and ip.is_global:
            out.add(str(ip))
    if getattr(remote, "is_local", False) or getattr(remote, "auth_method", "") == "local":
        out |= local_addresses()
    return out


def classify(addresses, host_addrs, cdn_nets=()):
    """The dns_state for resolved `addresses` against the host's public `host_addrs` and a CDN's `cdn_nets`."""
    if not addresses:
        return "failed"
    ips = [_address(a) for a in addresses]
    if any(ip is None or not ip.is_global for ip in ips):
        return "private"
    if host_addrs and all(str(ip) in host_addrs for ip in ips):
        return "matching"
    if cdn_nets and all(any(ip.version == net.version and ip in net for net in cdn_nets) for ip in ips):
        return "cdn"
    return "mismatch"


def cdn_networks():
    """Cloudflare's published ranges from the signed catalog, as networks ([] when they cannot be read)."""
    from panel.services import websites_catalog
    try:
        return [ipaddress.ip_network(n) for n in websites_catalog.preset_ranges("cloudflare")]
    except Exception:  # noqa: BLE001 - no catalog section: a CDN answer stays a mismatch
        return []


def check(domain, remote, lookup=None):
    """(dns_state, the addresses the domain resolved to, the host's public addresses)."""
    addrs = resolve(domain, lookup)
    hosts = host_addresses(remote)
    return classify(addrs, hosts, cdn_networks()), addrs, sorted(hosts)


def records(remote):
    """The DNS records the operator creates for a domain of a site on `remote`: [(type, address)]."""
    return [("AAAA" if ":" in a else "A", a) for a in sorted(host_addresses(remote))]
