"""The client addresses the panel refuses itself, for traffic its host firewall never sees.

fail2ban's panel-login jail and the UFW auto-block both ban an offender at the host firewall. That
works for a client that connects to the host. It does nothing for Tailscale Funnel: the public
client's connection ends at Tailscale's relay, the relay tunnels it to tailscaled, and tailscaled
connects to the panel from 127.0.0.1 — so the banned address never sends this host a packet the
firewall could drop. The panel logs the real client (tailscaled sets X-Forwarded-For to it and
strips any value the client sent), fail2ban bans it, the ban-watcher announces "IP banned on the
panel login", and the banned client carries on at 8 guesses per 5 minutes. A proxy on ANOTHER
machine (a Cloudflare Tunnel, say) has the same shape; one on this host does not, since the jail's
all-ports ban drops the client at the proxy's own port.

So the panel keeps the current ban set in memory and ProxiedBanGate (panel/core/middleware.py)
refuses a request whose forwarded client is in it. Reads do no I/O: the set is rebuilt whole by
set_f2b / set_ufw / set_whitelist and swapped in, and a failed read (None) keeps the last good one
— an unreadable firewall is not "nothing is banned".
"""
import ipaddress
import logging
import threading
import time

_log = logging.getLogger(__name__)

_lock = threading.Lock()
_f2b = frozenset()          # networks from fail2ban's panel jail
_ufw = frozenset()          # networks from the host's all-ports UFW denies
_taken = {"f2b": float("-inf"), "ufw": float("-inf")}   # when the reading in use was TAKEN
_allow = ()                 # the security whitelist, never refused here
# Tailscale's CGNAT IPv4 range and its IPv6 ULA prefix — system_ops._TAILNET_RANGES, which tests
# hold equal. A tailnet peer is never refused here: the panel never firewall-blocks one anywhere
# else, and the jail can ban one on the web port alone (a hand-made Serve), which this gate would
# otherwise have turned into a lock-out from every page served through tailscaled.
_TAILNET = tuple(ipaddress.ip_network(n) for n in ("100.64.0.0/10", "fd7a:115c:a1e0::/48"))
# What is_banned reads, rebuilt whole and swapped in: every banned network grouped by (IP version,
# prefix length), so a lookup costs one set test per length present rather than one per network.
_by_len = {}


def _networks(values):
    """ip_network for every value that is an address or a CIDR; anything else is skipped. An
    IPv4-mapped IPv6 address counts as the IPv4 address it carries."""
    out = set()
    for v in values or ():
        try:
            n = ipaddress.ip_network(str(v).strip(), strict=False)
        except ValueError:
            continue
        if n.version == 6 and n.num_addresses == 1 and n.network_address.ipv4_mapped:
            n = ipaddress.ip_network(n.network_address.ipv4_mapped)
        out.add(n)
    return frozenset(out)


def _rebuild():
    global _by_len
    groups = {}
    for n in _f2b | _ufw:
        groups.setdefault((n.version, n.prefixlen), set()).add(n)
        # An IPv6 client holds its whole /64 — the login throttle keys it that way
        # (auth.throttle_key) — so a ban on one address covers the rest of its /64 too.
        if n.version == 6 and n.prefixlen > 64:
            groups.setdefault((6, 64), set()).add(n.supernet(new_prefix=64))
    _by_len = {k: frozenset(v) for k, v in groups.items()}


def _fresher(kind, taken):
    """Record `taken` as the newest reading of `kind`; False if a newer one was already used."""
    if taken is None:
        return True
    if taken < _taken[kind]:
        return False
    _taken[kind] = taken
    return True


def set_f2b(ips, taken=None):
    """fail2ban's current ban list for the panel jail. None (the read failed) changes nothing, and
    so does a reading TAKEN (time.monotonic() before the read) before one already in use: the
    ban-watcher and a refresh can read concurrently, and the slower one must not win."""
    global _f2b
    if ips is None:
        return
    with _lock:
        if not _fresher("f2b", taken):
            return
        _f2b = _networks(ips)
        _rebuild()


def set_ufw(ips, taken=None):
    """The host's all-ports UFW denies ({ip: tag} or an iterable). As set_f2b."""
    global _ufw
    if ips is None:
        return
    with _lock:
        if not _fresher("ufw", taken):
            return
        _ufw = _networks(ips)
        _rebuild()


def set_whitelist(entries):
    """The security whitelist: addresses and networks this gate never refuses."""
    global _allow
    _allow = tuple(_networks(entries))


def active():
    """Whether anything is banned at all — the gate's free first test."""
    return bool(_by_len)


def forwarded_client(xff):
    """The client address a proxy put LAST in X-Forwarded-For, or None if it is not an address.

    The last hop is the one the nearest proxy wrote: tailscaled sets the header outright
    (discarding anything the client sent), and a reverse proxy appends to it."""
    hop = (xff or "").split(",")[-1].strip()
    if hop.startswith("["):
        hop = hop[1:].split("]", 1)[0]
    elif hop.count(":") == 1:
        hop = hop.split(":", 1)[0]
    try:
        a = ipaddress.ip_address(hop)
    except ValueError:
        return None
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a


def is_banned(addr):
    """True if `addr` (an ip_address) is banned, and neither whitelisted nor a tailnet peer."""
    groups = _by_len
    if addr is None or not groups:
        return False
    hit = False
    for (version, plen), nets in groups.items():
        if version == addr.version and ipaddress.ip_network((addr, plen), strict=False) in nets:
            hit = True
            break
    if not hit:
        return False
    return not any(addr in n for n in _TAILNET + _allow if n.version == addr.version)


# ── refreshing ──────────────────────────────────────────────────────────────────────────────────
# The ban-watcher feeds set_f2b / set_ufw every 90 seconds. Between ticks, a ban the panel caused (a
# failed login that reached the jail's limit, an admin's Block IP) is picked up by refresh_soon():
# one background read, and one more if another request arrived while it was pending — a request
# is never dropped, because the ban it is for may land just after the read that was already due.

_sched = threading.Lock()
# "scheduled": a refresh is pending or running; "again": the delay of a request that arrived while
# one was, or None.
_state = {"scheduled": False, "again": None}


def refresh():
    """Read fail2ban's jail, the UFW denies and the whitelist now. Best-effort: a failed read keeps
    what was there."""
    from panel.core.config import load_config
    from panel.ops import system_ops as so
    try:
        set_whitelist(load_config().get("security_whitelist") or [])
    except Exception:
        _log.debug("ban gate: config unreadable; whitelist kept", exc_info=True)
    for kind, read, apply in (("f2b", so.panel_fail2ban_banned_ips, set_f2b),
                              ("ufw", so.ufw_blocked_ips, set_ufw)):
        taken = time.monotonic()
        try:
            apply(read(), taken)
        except Exception:
            _log.debug("ban gate: %s read failed; last good set kept", kind, exc_info=True)


def refresh_soon(delay=3.0):
    """Schedule a refresh() `delay` seconds from now. If one is already pending, schedule ONE more
    after it rather than dropping this request."""
    with _sched:
        if _state["scheduled"]:
            _state["again"] = delay if _state["again"] is None else max(_state["again"], delay)
            return
        _state["scheduled"] = True

    def _run():
        wait = delay
        try:
            while True:
                time.sleep(wait)
                refresh()
                with _sched:
                    if _state["again"] is None:
                        _state["scheduled"] = False
                        return
                    wait, _state["again"] = _state["again"], None
        except BaseException:
            with _sched:
                _state["scheduled"], _state["again"] = False, None
            raise
    threading.Thread(target=_run, daemon=True).start()
