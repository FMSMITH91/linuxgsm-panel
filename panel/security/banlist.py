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
import os
import logging
import threading
import time

from panel.core.validation import (ip_network_or_none, unzoned_ip_address_or_none,
                                   unzoned_ip_or_network)

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
# Written out rather than imported: this module loads none of the panel's own at import time
# beyond the stdlib-only panel.core.validation (system_ops only inside refresh()), and the ranges
# are Tailscale's, not a host or a setting.
_TAILNET = tuple(ipaddress.ip_network(n) for n in ("100.64.0.0/10", "fd7a:115c:a1e0::/48"))  # NOSONAR - Tailscale's fixed ranges
# What is_banned reads, rebuilt whole and swapped in: every banned network grouped by (IP version,
# prefix length), so a lookup costs one set test per length present rather than one per network.
_by_len = {}


def _networks(values):
    """ip_network for every value that is an address or a CIDR; anything else is skipped.

    An IPv4-mapped IPv6 address counts as the IPv4 address it carries. A value with a zone id is
    not an address or a CIDR, and is skipped with the rest.
    """
    out = set()
    for v in values or ():
        n = ip_network_or_none(v)
        if n is None:
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


# Called after every new ban set: an OPEN connection was accepted before its client was banned,
# and nothing re-asks — a Socket.IO socket (the live console, the host terminal) stays up until it
# closes, on Funnel and, under a UFW deny, directly too (ufw accepts ESTABLISHED traffic before
# its own rules). server_files registers the sweep that drops those sockets. Keyed by qualified
# name, as socket_hooks is, so a second app in one process replaces its hook instead of stacking.
_listeners = {}


def on_change(fn):
    """Register fn() to run after the ban set is replaced."""
    _listeners[getattr(fn, "__qualname__", None) or repr(fn)] = fn
    return fn


def _changed():
    """Run every listener, outside _lock. One that raises does not skip the rest."""
    for fn in list(_listeners.values()):
        try:
            fn()
        except Exception:
            _log.warning("ban gate: listener %s failed", getattr(fn, "__name__", fn), exc_info=True)


def set_f2b(ips, taken=None):
    """fail2ban's current ban list for the panel jail.

    None (the read failed) changes nothing, and so does a reading TAKEN (time.monotonic() before the
    read) before one already in use: the ban-watcher and a refresh can read concurrently, and the
    slower one must not win.
    """
    global _f2b
    if ips is None:
        return
    with _lock:
        if not _fresher("f2b", taken):
            return
        _f2b = _networks(ips)
        _rebuild()
    _changed()


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
    _changed()


# ── the ban-watcher's UFW read, skipped while ufw's rule files are unchanged ──────────────────────
# `ufw status` lists the rules it reads from these files, and ufw rewrites one of them (in place:
# same inode, new mtime) for every rule it adds or deletes. The panel's account can stat them
# without privilege (/etc/ufw is 0755), so the 90 s watcher reads UFW, a privileged call, only when
# one changed. ufw.conf is in the key because enabling or disabling ufw rewrites it.
#
# What keeps this from going stale:
#   * the files are stat'ed BEFORE the read, so a change made while it ran is seen next tick;
#   * the key advances only on a real reading: ufw_blocked_ips answers None for an inactive or
#     unreadable firewall, and rules added while ufw was off and then enabled would otherwise stay
#     invisible — so a None keeps the read happening every tick, as before;
#   * a stat that fails (other than a file that does not exist) reads, never skips;
#   * every UFW_FORCED_READ seconds it reads regardless.
# The panel's own blocks do not wait for any of this: they call refresh_soon(), which reads at once.
UFW_RULE_FILES = ("/etc/ufw/user.rules", "/etc/ufw/user6.rules", "/etc/ufw/ufw.conf")
UFW_FORCED_READ = 900
# last_skipped: whether the LAST check skipped its read. Only then may the debug report say "rule
# files unchanged" — a None reading or a failed stat also leaves read_at behind checked_at, and
# neither skipped anything.
_ufw_gate = {"key": None, "read_at": float("-inf"), "checked_at": float("-inf"), "skipped": 0,
             "last_skipped": False}


def ufw_rules_key():
    """(inode, size, mtime_ns) per rule file — ("missing",) for one that is absent — or None.

    None is "could not look", and the watcher reads on it.
    """
    key = []
    for path in UFW_RULE_FILES:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            key.append(("missing",))
            continue
        except OSError:
            return None
        key.append((st.st_ino, st.st_size, st.st_mtime_ns))
    return tuple(key)


def watch_ufw(read):
    """The ban-watcher's UFW step: read() into set_ufw unless the rule files are unchanged.

    `read` is system_ops.ufw_blocked_ips. Returns whether it read.
    """
    key = ufw_rules_key()                 # before the read: a change made during it is caught next tick
    now = time.monotonic()
    _ufw_gate["checked_at"] = now
    if (key is not None and key == _ufw_gate["key"]
            and now - _ufw_gate["read_at"] < UFW_FORCED_READ):
        _ufw_gate["skipped"] += 1
        _ufw_gate["last_skipped"] = True
        return False
    _ufw_gate["last_skipped"] = False
    taken = time.monotonic()
    reading = read()
    set_ufw(reading, taken)
    if reading is not None and key is not None:
        _ufw_gate["key"], _ufw_gate["read_at"] = key, now
    else:
        _ufw_gate["key"] = None           # nothing measured: read again next tick
    return True


def ufw_gate_state():
    """A copy of the UFW gate's state for the debug report.

    When it last checked, when it last read, and whether that last check skipped its read.
    """
    return dict(_ufw_gate)


def set_whitelist(entries):
    """The security whitelist: addresses and networks this gate never refuses.

    An entry stored with a zone id, from before the whitelist refused one, still exempts the
    address or network it names, as it did then and as the Settings page shows it: skipped, it
    stopped exempting anything with nothing on screen to say so (validation.unzoned_ip_or_network).
    """
    global _allow
    _allow = tuple(_networks(unzoned_ip_or_network(e) for e in entries or ()))


def active():
    """Whether anything is banned at all — the gate's free first test."""
    return bool(_by_len)


def forwarded_client(xff):
    """The client address a proxy put LAST in X-Forwarded-For, or None if it is not an address.

    The last hop is the one the nearest proxy wrote: tailscaled sets the header outright
    (discarding anything the client sent), and a reverse proxy appends to it.

    An IPv6 zone id is DROPPED, not refused, and the address it is attached to is judged. Every
    caller only refuses (ProxiedBanGate, and the socket sweep, which also hands the socket peer
    here), so reading the address can only refuse more; refusing the value instead would let
    '2001:db8::1%x' past a ban on 2001:db8::1. Kept, the zone made the address unequal to the
    banned one (ipaddress counts it), so the firewall-exact test missed it.
    """
    hop = (xff or "").split(",")[-1].strip()
    if hop.startswith("["):
        hop = hop[1:].split("]", 1)[0]
    elif hop.count(":") == 1:
        hop = hop.split(":", 1)[0]
    a = unzoned_ip_address_or_none(hop)
    if a is None:
        return None
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a


def is_banned(addr, widen=True):
    """True if `addr` (an ip_address) is banned, and neither whitelisted nor a tailnet peer.

    `widen=False` asks what the host FIREWALL asks — the banned address or network itself, not the
    /64 an IPv6 ban is widened to here. For a client that connects directly: the firewall still
    lets a neighbour in the same /64 in, so refusing it only the console would be a half lock-out.
    """
    groups = _by_len
    if addr is None or not groups:
        return False
    if not _in_banned_network(addr, groups, widen):
        return False
    return not _never_refused(addr)


def _in_banned_network(addr, groups, widen):
    """Whether `addr` lies in a banned network of `groups` (a _by_len snapshot); see is_banned."""
    for (version, plen), nets in groups.items():
        if version != addr.version:
            continue
        net = ipaddress.ip_network((addr, plen), strict=False)
        if net in nets and (widen or net in _f2b or net in _ufw):
            return True
    return False


def _never_refused(addr):
    """Whether `addr` is a tailnet peer or on the security whitelist, which this gate never refuses."""
    return any(addr in n for n in _TAILNET + _allow if n.version == addr.version)


# ── refreshing ──────────────────────────────────────────────────────────────────────────────────
# The ban-watcher feeds set_f2b every 90 seconds, and set_ufw through watch_ufw (when ufw's rule
# files changed, and every UFW_FORCED_READ seconds). Between ticks, a ban the panel caused (a
# failed login that reached the jail's limit, an admin's Block IP) is picked up by refresh_soon():
# one background read, and one more if another request arrived while it was pending — a request
# is never dropped, because the ban it is for may land just after the read that was already due.

_sched = threading.Lock()
# "scheduled": a refresh is pending or running; "again": the delay of a request that arrived while
# one was, or None.
_state = {"scheduled": False, "again": None}


def refresh():
    """Read fail2ban's jail, the UFW denies and the whitelist now.

    Best-effort: a failed read keeps what was there.
    """
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
    """Schedule a refresh() `delay` seconds from now.

    If one is already pending, schedule ONE more after it rather than dropping this request.
    """
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
