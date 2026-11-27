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
cdn (every answer is inside ONE CDN's published ranges, the signed catalog's allow-list presets:
the name goes through that CDN, which passes visitors on to the host; WebsiteDomain.dns_cdn names
the preset), mismatch (a public answer that is none of these, answers split between two CDNs
included), private (an answer that is not public), failed (no answer). A domain is verified, and
served by the web proxy, once a check finds it matching or cdn (VERIFIED).
"""
import ipaddress
import socket
import time

S_STATES = {
    "matching": "The domain points at this website's host.",
    "cdn": "This domain goes through {provider}.",
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
    return {ip for ip in map(_iface_address, (text or "").splitlines()) if ip}


def _iface_address(line):
    """One `ip -o addr` line's address when a domain may point at it, else ""."""
    from panel.ops.ssh_manager import ufweval
    row = ufweval._ip_addr_row(line)
    if row is None or row[0].startswith("tailscale") or row[2] != "global":
        return ""
    words = line.split()
    ip = _address(str(row[1]))
    if ip is None or not ip.is_global or "temporary" in words or "deprecated" in words or _inside(ip, _TAILNET):
        return ""
    return str(ip)


def _inside(ip, nets):
    """Whether address `ip` is inside one of `nets` (of its own family)."""
    return any(ip.version == n.version and ip in n for n in nets)


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


# A host's public address (RemoteServer.public_ip) was found once by the Servers page and kept for good. A DNS check
# from the Websites page looks it up again, at most once per PUBLIC_IP_FRESH seconds per host, with the panel's own
# lookup (ssh_manager remote_public_ip: the host's default-route address, and only behind NAT the one outside service
# Settings > Outside services allows; with that switch off nothing is asked and the stored address stays).
PUBLIC_IP_FRESH = 600
_PUBLIC_AT = {}                   # remote id -> monotonic time of its last lookup


def _lookup_public_ip(remote):
    from panel.ops.ssh_manager import remote_public_ip
    return remote_public_ip(remote)


def refresh_public_ip(remote, now=None):
    """Look the host's public IPv4 up again (PUBLIC_IP_FRESH); store a new one. -> whether it changed."""
    now = time.monotonic() if now is None else now
    last = _PUBLIC_AT.get(remote.id)
    if last is not None and now - last < PUBLIC_IP_FRESH:
        return False
    _PUBLIC_AT[remote.id] = now
    try:
        ip = _address((_lookup_public_ip(remote) or "").strip())
    except Exception:  # noqa: BLE001 - a lookup that fails keeps the stored address
        return False
    if ip is None or not ip.is_global or str(ip) == (remote.public_ip or ""):
        return False
    remote.public_ip = str(ip)
    return True


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
    """The dns_state for resolved `addresses` against the host's public `host_addrs` and the CDNs' `cdn_nets`.

    `cdn_nets` is {preset: networks} (cdn_sets), or one CDN's networks as a list.
    """
    if not addresses:
        return "failed"
    ips = [_address(a) for a in addresses]
    if not all(_public(ip) for ip in ips):
        return "private"
    if host_addrs and {str(ip) for ip in ips} <= set(host_addrs):
        return "matching"
    return "cdn" if _provider(ips, cdn_nets) else "mismatch"


def _provider(ips, cdn_nets):
    """The preset whose networks hold EVERY address of `ips` ("" when none does; "cdn" for a bare list)."""
    sets = cdn_nets if isinstance(cdn_nets, dict) else {"cdn": cdn_nets}
    return next((name for name, nets in sorted(sets.items()) if _all_inside(ips, nets)), "")


def provider(addresses, cdn_nets=None):
    """The CDN preset every one of `addresses` goes through (cdn_sets() when `cdn_nets` is None), or ""."""
    ips = [_address(a) for a in addresses or []]
    if not ips or not all(_public(ip) for ip in ips):
        return ""
    return _provider(ips, cdn_sets() if cdn_nets is None else cdn_nets)


def _all_inside(ips, nets):
    """Whether every address of `ips` is inside one of `nets` (False when there are no networks)."""
    return bool(nets) and all(_inside(ip, nets) for ip in ips)


def _public(ip):
    """Whether parsed answer `ip` is a public address (None, an unparsable answer, is not)."""
    return ip is not None and ip.is_global


def cdn_sets():
    """{preset: networks} for every CDN preset of the signed catalog ({} when it cannot be read)."""
    from panel.services import websites_catalog
    try:
        return {name: [ipaddress.ip_network(n) for n in nets] for name, nets in websites_catalog.cdn_ranges().items()}
    except Exception:  # noqa: BLE001 - no catalog section: a CDN answer stays a mismatch
        return {}


def cdn_networks(name="cloudflare"):
    """One CDN preset's published ranges from the signed catalog, as networks ([] when they cannot be read)."""
    return cdn_sets().get(name, [])


def state_sentence(state, preset=""):
    """What a check found, as the page's sentence: a cdn state names its CDN (websites_catalog.cdn_info)."""
    from panel.core import i18n
    if state != "cdn":
        return S_STATES[state]
    from panel.services import websites_catalog
    return i18n.Sentence(S_STATES["cdn"], provider=websites_catalog.cdn_info(preset or "cloudflare")["name"])


def check(domain, remote, lookup=None):
    """(dns_state, the addresses the domain resolved to, the host's public addresses)."""
    addrs = resolve(domain, lookup)
    hosts = host_addresses(remote)
    return classify(addrs, hosts, cdn_sets()), addrs, sorted(hosts)


def records(remote):
    """The DNS records the operator creates for a domain of a site on `remote`: [(type, address)]."""
    return [("AAAA" if ":" in a else "A", a) for a in sorted(host_addresses(remote))]
