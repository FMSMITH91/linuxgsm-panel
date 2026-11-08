"""Part 154 of the unit suite: review 1107's firewall and lock-out findings (builder A).

* HIGH: the hourly auto-block never denies an address the panel's own connection to a remote comes
  from (the session's source, read from the host, or a global address of the panel's own host); when
  those cannot be read it blocks nothing new that cycle and still releases.

HOW IT RUNS. Monitoring's reconcile and the firewall module over part135's stand-in hosts, on
part12's patcher with its transport tripwire armed. Nothing reaches a host, sudo, ufw or data/.
"""
import ipaddress as _ip154

from unit.part01 import check
from unit.part12 import _P9_TRIPPED, _p9_arm, _p9_patch, _p9_restore_all
from unit import part135 as _p135
from panel.ops.ssh_manager import ufweval as _ue154
from panel.services import monitoring as _mon154

_TRIP154_START = len(_P9_TRIPPED)

# ════════════════════════════════════════════════════════════════════════════════════════════════
# HIGH: the auto-block spares the addresses the panel reaches a remote from
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SRC154 = "198.51.100.40"          # NOSONAR(S1313) - the session's source, as the remote reads it
_OWN154 = "203.0.113.5"            # NOSONAR(S1313) - a global address of the panel's own host
_OWN6_154 = "2001:db8::5"          # NOSONAR(S1313) - and its IPv6 one
_LL154 = "fe80::5"                 # the panel host's link-local address: never the panel's way out
_NEAR154 = "198.51.100.41"         # NOSONAR(S1313) - the source's neighbour: an ordinary offender
_OTHER154 = "192.0.2.77"           # NOSONAR(S1313) - an ordinary offender
_OLD154 = "192.0.2.78"             # NOSONAR(S1313) - an auto-block whose count has fallen under


def _addrs154():
    return _p135._addrs135(("eth0", _OWN154), ("eth0", _OWN6_154)) + [
        ("eth0", _ip154.ip_address(_LL154), "link")]


def _no_read154():
    raise AssertionError("the panel host's addresses were read with no source to spare")


def _reconcile154(src, addrs=_addrs154, server=_p135._REMOTE135):
    """One remote reconcile -> (result, denied, undenied); the session's source reads `src`."""
    denied, undenied = [], []
    counts = {_SRC154: 50, "::ffff:" + _SRC154: 3, _OWN154: 50, _OWN6_154: 50, "127.0.0.1": 50,  # NOSONAR(S1313)
              _LL154: 50, _NEAR154: 50, _OTHER154: 50, _OLD154: 1}
    blocked = [{_OLD154: _mon154._AUTOBLOCK_TAG}]
    try:
        _p9_arm(who="part154")
        _p9_patch(_mon154, "_autoblock_threshold", lambda: 20)
        _p9_patch(_mon154, "tailnet_exempt_ips", lambda r, ips: set())
        _p9_patch(_mon154, "_whitelist_networks", lambda: [])
        _p9_patch(_mon154, "remote_fail2ban_attempt_counts", lambda r, days=7: dict(counts))
        _p9_patch(_mon154, "remote_ufw_blocked_ips", lambda r: dict(blocked[0]))
        _p9_patch(_mon154, "remote_ufw_deny_ip", lambda r, ip, tag=None: (denied.append(ip), (True, "ok"))[1])
        _p9_patch(_mon154, "remote_ufw_undeny_ip", lambda r, ip: (undenied.append(ip), (True, "ok"))[1])
        _p9_patch(_mon154, "fwa_panel_source", lambda r: src)
        _p9_patch(_ue154, "local_addrs", addrs)
        out = _mon154._autoblock_reconcile(server)
    except Exception as e:     # a raise is the failure, recorded as one rather than ending the part
        out = "raised %r" % (e,)
    finally:
        _p9_restore_all()
    return out, sorted(denied), sorted(undenied)


_ORDINARY154 = sorted(["127.0.0.1", _LL154, _NEAR154, _OTHER154])   # NOSONAR(S1313)
_hi = _reconcile154(_SRC154)
check("1107 HIGH: the auto-block never denies the address the panel's SSH session to the remote comes from (in either "
      "spelling) nor a global address of the panel's own host (IPv4 and IPv6); its neighbour, a link-local or "
      "loopback address of the panel host and an ordinary offender are still blocked, and a stale auto-block "
      "released",
      _hi == ((4, 1), _ORDINARY154, [_OLD154]), repr(_hi))
_hi_src = _reconcile154(None)
_hi_own = _reconcile154(_SRC154, addrs=lambda: None)
check("1107 HIGH: with the session's source unread, or the panel host's own addresses unread, nothing new is blocked that "
      "cycle (as the manual Block refuses), and the stale auto-block is still released",
      _hi_src == ((0, 1), [], [_OLD154]) and _hi_own == ((0, 1), [], [_OLD154]), repr((_hi_src, _hi_own)))
_hi_ts = _reconcile154("", addrs=_no_read154, server=_p135._TSREMOTE135)
check("1107 HIGH: a host with no source of the panel's to spare (reached over Tailscale) blocks every offender over the "
      "threshold, and the panel host's addresses are not read for it",
      _hi_ts == ((7, 1), sorted([_SRC154, _OWN154, _OWN6_154] + _ORDINARY154), [_OLD154]), repr(_hi_ts))

check("1107 part154: nothing reached a real transport", len(_P9_TRIPPED) == _TRIP154_START,
      repr(_P9_TRIPPED[_TRIP154_START:]))
