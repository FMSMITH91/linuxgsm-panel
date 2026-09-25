"""The client addresses the panel refuses itself, for traffic its host firewall never sees.

fail2ban's panel-login jail and the UFW auto-block both ban an offender at the host firewall. That
works for a client that connects to the host. It does nothing for Tailscale Funnel: the public
client's connection ends at Tailscale's relay, the relay tunnels it to tailscaled, and tailscaled
connects to the panel from 127.0.0.1 — so the banned address never sends this host a packet the
firewall could drop. The panel logs the real client (tailscaled sets X-Forwarded-For to it and
strips any value the client sent), fail2ban bans it, the ban-watcher announces "IP banned on the
panel login", and the banned client carries on at 8 guesses per 5 minutes. A reverse proxy
declared with trust_proxy has the same shape.

So the panel keeps the current ban set in memory and ProxiedBanGate (panel/core/middleware.py)
refuses a request whose forwarded client is in it. Reads do no I/O: the set is rebuilt whole by
set_f2b / set_ufw / set_whitelist and swapped in, and a failed read (None) keeps the last good one
— an unreadable firewall is not "nothing is banned".
"""
import ipaddress
import threading
import time

_lock = threading.Lock()
_f2b = frozenset()          # networks from fail2ban's panel jail
_ufw = frozenset()          # networks from the host's all-ports UFW denies
_allow = ()                 # the security whitelist, never refused here
# What is_banned reads, rebuilt whole and swapped in under _lock: single addresses in a set, for
# an O(1) test, and the (rare) wider networks in a tuple.
_addrs = frozenset()
_nets = ()


def _networks(values):
    """ip_network for every value that is an address or a CIDR; anything else is skipped."""
    out = set()
    for v in values or ():
        try:
            out.add(ipaddress.ip_network(str(v).strip(), strict=False))
        except ValueError:
            continue
    return frozenset(out)


def _rebuild():
    global _addrs, _nets
    both = _f2b | _ufw
    _addrs = frozenset(n.network_address for n in both if n.num_addresses == 1)
    _nets = tuple(n for n in both if n.num_addresses > 1)


def set_f2b(ips):
    """fail2ban's current ban list for the panel jail. None (the read failed) changes nothing."""
    global _f2b
    if ips is None:
        return
    with _lock:
        _f2b = _networks(ips)
        _rebuild()


def set_ufw(ips):
    """The host's all-ports UFW denies ({ip: tag} or an iterable). None changes nothing."""
    global _ufw
    if ips is None:
        return
    with _lock:
        _ufw = _networks(ips)
        _rebuild()


def set_whitelist(entries):
    """The security whitelist: addresses and networks this gate never refuses."""
    global _allow
    _allow = tuple(_networks(entries))


def active():
    """Whether anything is banned at all — the gate's free first test."""
    return bool(_addrs or _nets)


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
    """True if `addr` (an ip_address) is banned and not whitelisted."""
    if addr is None or not (_addrs or _nets):
        return False
    if not (addr in _addrs or any(addr in n for n in _nets if n.version == addr.version)):
        return False
    return not any(addr in n for n in _allow if n.version == addr.version)


# ── refreshing ──────────────────────────────────────────────────────────────────────────────────
# The ban-watcher feeds set_f2b every 90 seconds from the reading it already takes. Between ticks,
# a ban the panel caused (a login failure that reached the jail's limit, an admin's Block IP) is
# picked up by refresh_soon(): one debounced background read a few seconds later.

_pending = threading.Event()


def proxied_traffic_possible(cfg):
    """Whether clients can reach the panel through a proxy the host firewall cannot see past:
    Tailscale Funnel, or a reverse proxy the operator declared with trust_proxy."""
    return bool(cfg.get("tailscale_use_funnel") or cfg.get("trust_proxy"))


def refresh():
    """Read fail2ban's jail, the whitelist and — where proxied traffic can arrive — the UFW
    denies, now. Best-effort: a failed read keeps what was there."""
    from panel.core.config import load_config
    from panel.ops import system_ops as so
    try:
        cfg = load_config()
    except Exception:
        cfg = {}
    set_whitelist(cfg.get("security_whitelist") or [])
    try:
        set_f2b(so.panel_fail2ban_banned_ips())
    except Exception:
        pass
    if proxied_traffic_possible(cfg):
        try:
            set_ufw(so.ufw_blocked_ips())
        except Exception:
            pass


def refresh_soon(delay=3.0):
    """Schedule one refresh() `delay` seconds from now, unless one is already scheduled."""
    if _pending.is_set():
        return
    _pending.set()

    def _run():
        try:
            time.sleep(delay)
            refresh()
        finally:
            _pending.clear()
    threading.Thread(target=_run, daemon=True).start()
