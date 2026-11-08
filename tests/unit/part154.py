"""Part 154 of the unit suite: review 1107's firewall and lock-out findings (builder A).

* HIGH: the hourly auto-block never denies an address the panel's own connection to a remote comes
  from (the session's source, read from the host, or a global address of the panel's own host); when
  those cannot be read it blocks nothing new that cycle and still releases.

HOW IT RUNS. Monitoring's reconcile and the firewall module over part135's stand-in hosts, on
part12's patcher with its transport tripwire armed. Nothing reaches a host, sudo, ufw or data/.
"""
import ipaddress as _ip154
from types import SimpleNamespace as _NS154

from unit.part01 import check
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9_arm, _p9_client, _p9_patch, _p9_patch_sm, _p9_restore_all
from unit import part135 as _p135
from unit.part136 import _deny136
from panel.core import i18n as _i18n154
from panel.ops import system_ops as _so154
from panel.ops.ssh_manager import firewall as _fw154, hosts as _hosts154, ufweval as _ue154
from panel.routes import host_local as _hl154, remote_security as _rs154
from panel.security import banlist as _bl154
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

# ════════════════════════════════════════════════════════════════════════════════════════════════
# A09 MEDIUM: the panel host's Block card refuses what its row refuses
# ════════════════════════════════════════════════════════════════════════════════════════════════
_VIEW154 = "203.0.113.20"          # NOSONAR(S1313) - the superadmin pressing Block
_VIEW6_154 = "2001:db8::7"         # NOSONAR(S1313)


def _panel_block154(viewer, ip, unblock=False, evaluator=None):
    """POST the panel host's Block as a superadmin seen at `viewer` -> (ok, message, firewall calls, evaluated)."""
    calls, evaluated = [], []

    def fwc(server, target):
        evaluated.append((bool(getattr(server, "is_local", False)), target))
        return evaluator

    try:
        _p9_arm(who="part154")
        _p9_patch(_hl154, "tailnet_exempt_ips", lambda remote, ips: set())
        _p9_patch(_hl154, "_whitelisted", lambda ip: False)
        _p9_patch(_rs154, "client_ip", lambda: viewer)
        _p9_patch(_rs154, "_whitelist_networks", lambda: [])
        _p9_patch_sm("fwc_block_ip_refusal", fwc)
        _p9_patch(_so154, "ufw_deny_ip", lambda a: (calls.append(("deny", a)), (True, "blocked"))[1])
        _p9_patch(_so154, "ufw_undeny_ip", lambda a: (calls.append(("undeny", a)), (True, "unblocked"))[1])
        _p9_patch(_bl154, "refresh_soon", lambda *a, **k: None)
        body = _p9_client(P9_ADMIN).post("/api/panel/security/block",
                                         json={"ip": ip, "unblock": unblock}).get_json(silent=True) or {}
    finally:
        _p9_restore_all()
    return body.get("success"), str(body.get("message")), calls, evaluated


_OWN_CASES154 = {
    "the viewer's address": (_VIEW154, _VIEW154),
    "its IPv4-mapped spelling": (_VIEW154, "::ffff:" + _VIEW154),
    "a mapped viewer's IPv4 address": ("::ffff:" + _VIEW154, _VIEW154),
    "an IPv6 viewer's address": (_VIEW6_154, _VIEW6_154),
}
_own154 = {k: _panel_block154(v, ip) for k, (v, ip) in _OWN_CASES154.items()}
check("1107 A09 MEDIUM: the panel host's Block refuses the viewer's own address (as given, IPv4-mapped, a mapped "
      "viewer, IPv6), says it would lock them out, and sends nothing to the firewall",
      all(r[0] is False and "lock you out" in r[1] and r[2] == [] for r in _own154.values()), repr(_own154))
_ok154 = {
    "a neighbour": _panel_block154(_VIEW154, "203.0.113.21"),   # NOSONAR(S1313)
    "the other family's viewer": _panel_block154(_VIEW6_154, _VIEW154),
    "unblocking the viewer's own address": _panel_block154(_VIEW154, _VIEW154, unblock=True),
}
check("1107 A09 MEDIUM: ...while a neighbour of the viewer, the address of a viewer in the other family and an "
      "unblock of the viewer's own address go through (controls), the block evaluated against the panel host",
      _ok154["a neighbour"][:3] == (True, "blocked", [("deny", "203.0.113.21")])   # NOSONAR(S1313)
      and _ok154["a neighbour"][3] == [(True, "203.0.113.21")]   # NOSONAR(S1313)
      and _ok154["the other family's viewer"][:3] == (True, "blocked", [("deny", _VIEW154)])
      and _ok154["unblocking the viewer's own address"][:3] == (True, "unblocked", [("undeny", _VIEW154)]),
      repr(_ok154))
_cut154 = _panel_block154(_VIEW154, "198.51.100.9", evaluator=_i18n154.Sentence(   # NOSONAR(S1313)
    "Blocking that would lock you out of the panel: your connection to it comes in from {src} to {dst}, port "
    "{port}/tcp, on {iface}.", src="198.51.100.9", dst="192.0.2.1", port=5000, iface="eth0"))   # NOSONAR(S1313)
check("1107 A09 MEDIUM: a deny the panel's own connections would not survive (the row's evaluator) is refused on "
      "this card too, nothing sent",
      _cut154[0] is False and "lock you out of the panel" in _cut154[1] and _cut154[2] == [], repr(_cut154))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# A03 MEDIUM: the tailscale0 rule is the panel's sole way in when tailscaled is not ahead of ufw
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TSH154 = "100.100.5.5"            # NOSONAR(S1313) - the remote's tailnet address, which the row dials
_TSP154 = "100.100.9.9"            # NOSONAR(S1313) - the panel host's tailnet address
_TS0_154 = "Anywhere on tailscale0  ALLOW IN  Anywhere"
_HOME154 = "22/tcp  ALLOW IN  203.0.113.0/24"   # NOSONAR(S1313) - an admin's home range


def _tsrow154(port=22):
    return _NS154(is_local=False, auth_method="key", host=_TSH154, port=port, id=None, name="ts154")


def _tsconn154(port=22, iface="tailscale0"):
    """hosts._fwb_ssh_conn's reading of the panel's session over the tailnet."""
    return {"client": _ip154.ip_address(_TSP154), "server": _ip154.ip_address(_TSH154), "port": port,
            "iface": iface, "addrs": _p135._addrs135(("eth0", "192.0.2.10"), ("tailscale0", _TSH154))}  # NOSONAR(S1313)


def _ts_guard154(rows, ts_ssh=False, netfilter_on=False, port=22):
    """The delete guard over `rows` on the tailnet remote -> {(port label, scope): PROTECTED | warn | -}."""
    host = _p135._Host135(rules=rows, ts=(True, ts_ssh))

    def run():
        _p9_patch(_hosts154, "_fwb_ssh_conn", lambda s: _tsconn154(port))
        _p9_patch(_ue154, "ts_netfilter_on", lambda s: netfilter_on)
        return _fw154.remote_ufw_status(_tsrow154(port))

    st = _p135._on135(host, run)
    return {(g["port_label"], g["scope"]): "PROTECTED" if g["protected"] else ("warn" if g["warn"] else "-")
            for g in st.get("groups", [])}


def _ts0_154(guard):
    return next((v for (label, scope), v in guard.items() if "tailscale0" in "%s %s" % (label, scope)), None)


_m_cut = {
    "beside a home-range SSH rule": _ts_guard154([_TS0_154, _HOME154]),
    "beside an SSH rule on docker0": _ts_guard154([_TS0_154, "22/tcp on docker0  ALLOW IN  Anywhere"]),
    "beside an SSH rule on lo": _ts_guard154([_TS0_154, "22/tcp on lo  ALLOW IN  Anywhere"]),
    "beside a UDP 22 rule": _ts_guard154([_TS0_154, "22/udp  ALLOW IN  Anywhere"]),
    "beside an SSH rule from 127.0.0.1": _ts_guard154([_TS0_154, "22/tcp  ALLOW IN  127.0.0.1"]),  # NOSONAR(S1313)
    "beside an outbound SSH rule": _ts_guard154([_TS0_154, "22/tcp  ALLOW OUT  Anywhere (out)"]),
    "beside a routed SSH rule": _ts_guard154([_TS0_154, "22/tcp  ALLOW FWD  Anywhere"]),
    "Tailscale SSH on, the panel dialling 2222": _ts_guard154([_TS0_154, "2222/tcp  ALLOW IN  203.0.113.0/24"],  # NOSONAR(S1313)
                                                             ts_ssh=True, port=2222),
}
check("1107 A03 MEDIUM: on a remote the panel dials at its tailnet address, with tailscaled not ahead of ufw "
      "(nodivert/off), the host's only tailscale0 allow is PROTECTED beside an SSH rule that is no way in for the "
      "panel's session (another source, docker0, lo, UDP, 127.0.0.1, OUT, FWD), and with Tailscale SSH on while "
      "the panel dials another port",
      all(_ts0_154(g) == "PROTECTED" for g in _m_cut.values()), repr(_m_cut))
_m_ok = {
    "tailscaled's own chain ahead of ufw": _ts_guard154([_TS0_154, _HOME154], netfilter_on=True),
    "Tailscale SSH on, the panel dialling 22": _ts_guard154([_TS0_154, _HOME154], ts_ssh=True),
}
check("1107 A03 MEDIUM: ...and it is not protected where something else keeps the session in: tailscaled's "
      "default netfilter mode, Tailscale SSH answering the port 22 the panel dials",
      all(_ts0_154(g) not in ("PROTECTED", None) for g in _m_ok.values()), repr(_m_ok))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# A03 LOW: a host dialled by name keeps SSH open in both families
# ════════════════════════════════════════════════════════════════════════════════════════════════
_NAMED154 = _NS154(is_local=False, auth_method="key", host="h154.example.net", port=22, id=None, name="n154")
_V6_154 = "22/tcp (v6)  ALLOW IN  Anywhere (v6)"
_fam_cut = {
    "a v4-only SSH rule": _deny136([_p135._SSH22], server=_NAMED154),
    "v6: UDP only": _deny136([_p135._SSH22, "22/udp (v6)  ALLOW IN  Anywhere (v6)"], server=_NAMED154),
    "v6: OUT only": _deny136([_p135._SSH22, "22/tcp (v6)  ALLOW OUT  Anywhere (v6) (out)"], server=_NAMED154),
    "v6: a DENY above the ALLOW": _deny136([_p135._SSH22, "22/tcp (v6)  DENY IN  Anywhere (v6)", _V6_154],
                                           server=_NAMED154),
}
check("1107 A03 LOW: on a remote dialled by name, measured over IPv4, a default incoming deny is refused (nothing "
      "sent, SSH's port named) while the IPv6 list has no way in for SSH (%s)" % ", ".join(_fam_cut),
      all(r[0] is False and r[2] == [] and "No rule lets SSH in" in r[1] for r in _fam_cut.values()),
      repr({k: (r[0], r[1][:160]) for k, r in _fam_cut.items()}))
_fam_ok = {
    "both families": _deny136([_p135._SSH22, _V6_154], server=_NAMED154),
    "an address literal, v4 rule only": _deny136([_p135._SSH22]),
    "a name, IPV6=no": _deny136([_p135._SSH22], server=_NAMED154, ipv6="no"),
}
check("1107 A03 LOW: ...and set with a way in both families, for an address literal dialled in its own family, "
      "and where ufw does not handle IPv6 (the controls)",
      all(r[0] is True and r[2] == [("ufw-default", ["deny", "incoming"])] for r in _fam_ok.values()),
      repr({k: (r[0], r[1][:160]) for k, r in _fam_ok.items()}))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# A03 LOW: the panel host refuses an IP block while the viewer is unknown
# ════════════════════════════════════════════════════════════════════════════════════════════════
_RANGE154 = "198.51.100.0/24"      # NOSONAR(S1313) - a range holding the admin's address
_PROXIED154 = "198.51.100.7"       # NOSONAR(S1313)


def _ipblock154(viewer, via_proxy=False, seen=(), tunnel=False, target=_RANGE154):
    """fwc_block_ip_refusal on the panel host, the viewer read as (viewer, via_proxy) -> its answer as text."""
    host = _p135._Host135(rules=[_p135._SSH22, "5000/tcp  ALLOW IN  Anywhere", "443/tcp  ALLOW IN  Anywhere"])

    def run():
        _p9_patch(_fw154, "_fwb_panel_viewer",
                  lambda: (None if viewer is None else _ip154.ip_address(viewer), via_proxy))
        _p9_patch(_ue154, "inbound_from", lambda peer: [(_ip154.ip_address(a), p) for a, p in seen])
        _p9_patch(_ue154, "tunnel_running", lambda: tunnel)
        why = _fw154.fwc_block_ip_refusal(_p135._LOCAL135, target)
        return None if why is None else str(why)

    return _p135._on135(host, run)


_ub = _ipblock154(None)
check("1107 A03 LOW: on the panel host behind a proxy here the panel was not told to believe (viewer unknown), "
      "blocking an address range is refused, naming trust_proxy",
      _ub is not None and "trust_proxy" in _ub, repr(_ub))
_ub_ok = {
    "a viewer straight in, elsewhere": _ipblock154("203.0.113.20"),   # NOSONAR(S1313)
    "a Cloudflare Tunnel": _ipblock154(_PROXIED154, via_proxy=True, tunnel=True),
    "a proxy here, its port ambiguous": _ipblock154(_PROXIED154, via_proxy=True,
                                                    seen=[(_PROXIED154, 443), (_PROXIED154, 8443)]),
}
check("1107 A03 LOW: ...while a known viewer the range does not hold, a Cloudflare Tunnel and a proxy whose port "
      "alone is unknown still pass (the controls)",
      all(v is None for v in _ub_ok.values()), repr(_ub_ok))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# A03 LOW: "Disable public SSH" and the panel's tailnet session on a port Tailscale SSH does not answer
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _pub_off154(port=2222, ssh_on=True, iface=False, netfilter_on=False, auth="key", host=_TSH154):
    """remote_set_public_ssh(.., "off") -> (ok, message, privileged calls); "past the gates" reads sshd's ports."""
    sent = []
    row = _NS154(is_local=False, auth_method=auth, host=host, port=port, id=None, name="pub154")
    try:
        _p9_arm(who="part154")
        _p9_patch(_hosts154, "_tailnet_ssh_state", lambda s: (True, ssh_on, iface))
        _p9_patch(_ue154, "ts_netfilter_on", lambda s: netfilter_on)
        _p9_patch(_hosts154, "_r32b_public_ssh_ports", lambda s: ([], []))   # past the gates: the next read
        _p9_patch(_hosts154._core, "run_privileged", lambda *a, **k: (sent.append(a[1:3]), ("", "", 1))[1])
        ok, msg = _hosts154.remote_set_public_ssh(row, "off")
    finally:
        _p9_restore_all()
    return ok, str(msg), sent


_PAST154 = str(_hosts154._R32B_PORTS_UNREAD)
_po_cut = _pub_off154()
check("1107 A03 LOW: \"Disable public SSH\" is refused, nothing sent, when the panel dials the host's tailnet "
      "address on 2222 (Tailscale SSH answers 22 only) with no tailscale0 rule and tailscaled not ahead of ufw",
      _po_cut[0] is False and "port 2222" in _po_cut[1] and "Tailscale SSH" in _po_cut[1] and _po_cut[2] == [],
      repr(_po_cut))
_po_ok = {
    "a tailscale0 rule": _pub_off154(iface=True),
    "tailscaled's chain ahead of ufw": _pub_off154(netfilter_on=True),
    "the panel dialling 22": _pub_off154(port=22),
    "a Tailscale-SSH row": _pub_off154(auth="tailscale"),
}
check("1107 A03 LOW: ...and goes past that gate with a tailscale0 rule, under tailscaled's default netfilter mode, "
      "when the panel dials 22, and for a Tailscale-SSH row (the controls)",
      all(r[1] == _PAST154 for r in _po_ok.values()), repr(_po_ok))

check("1107 part154: nothing reached a real transport", len(_P9_TRIPPED) == _TRIP154_START,
      repr(_P9_TRIPPED[_TRIP154_START:]))
