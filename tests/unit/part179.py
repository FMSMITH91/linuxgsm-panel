r"""Part 179 of the unit suite: review 1112's SSH port move under a default allow, and stacked interfaces.

* OWNER RULE: under a default incoming ALLOW policy, a DENY for one public address of the host with no
  rule for everyone below it shapes public SSH (the policy lets SSH in on every address but that one).
  An SSH port move dropped it and the allow policy let the new port in on the one address where SSH was
  refused. The move is refused naming it, as with a rule for everyone below it (adversarial M1), until
  a DENY for that address covers the new port too. Driven through _r38h_public_fams, change_ssh_port on
  part159's stand-in and POST /api/remote/<id>/ssh-port on part12's app.
* Host traffic counts the bottom of each interface stack once: bond and team masters, bridges (br0,
  vmbr0), VLAN sub-interfaces (eno1.100), macvlan/ipvlan links, guest taps, ifb and tunnels (tun, ppp,
  ZeroTier, the kernel's tunnel devices) are skipped, as their bytes are on the NIC below too. Driven
  through netdev.counted, the host read's /proc/net/dev line (part177's runner) and the history sampler.

HOW IT RUNS. part159's port-move stand-in and part163's stored-file patch on part12's patcher with its
transport tripwire armed; the host read's command under bash on a file in a temporary directory, the
sampler with run_command replaced. Nothing reaches a host, sudo, ufw, a resolver or data/.
"""
from unit.part01 import check, eq
from unit.part12 import (NS, P9_ADMIN, P9_HOST, P9_HOST2, P9_LOCAL, _P9_TRIPPED, _p9, _p9_arm, _p9_audit,
                         _p9_client, _p9_host_row, _p9_json, _p9_patch, _p9_restore_all, _p9_set_host)
from unit.part159 import _Box159, _PUB_SESS159, _SSH6_PUB159, _move159
from unit.part163 import _DENY_OTHER163, _OTHER_PUB163, _PROXY_ADD163, _PUB22_163, _move163
from unit.part177 import _clear177, _host_rows177, _run_netif177
from panel.ops import netdev as _netdev179
from panel.ops.ssh_manager import _core as _core179, firewall as _fw179, hosts as _hosts179, ufweval as _ue179
from panel.services import monitoring as _mon179

_TRIP179_START = len(_P9_TRIPPED)
_HELD179 = "depends on the firewall rule `%s`" % _DENY_OTHER163
_DENY2022_179 = _OTHER_PUB163 + " 2022/tcp  DENY IN  Anywhere"
_DENY6_179 = "2001:db8::9 22/tcp  DENY IN  Anywhere (v6)"      # NOSONAR(S1313) - documentation address


# ════════════════════════════════════════════════════════════════════════════════════════════════
# OWNER RULE: a held one-address DENY under a default incoming allow, with or without a rule below it
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _status179(rules):
    """An active `ufw status numbered` listing `rules` in order."""
    return ("Status: active\n\nTo  Action  From\n--  ------  ----\n"
            + "".join("[%2d] %s\n" % (n + 1, r) for n, r in enumerate(rules)))


def _fams179(rules, allow_in):
    """_r38h_public_fams over [22] for a move to 2022, the default incoming policy allow or not, IPV6=no."""
    try:
        _p9_arm(who="part179")
        _p9_patch(_fw179, "remote_ufw_default_allows_in", lambda server: allow_in)
        _p9_patch(_hosts179, "_r40_ufw_v6_state", lambda server: False)
        listed, fams, held, met = _hosts179._r38h_public_fams(object(), _status179(rules), [22], 2022)
        return sorted(listed), sorted(fams), held and held["detail"], met
    finally:
        _p9_restore_all()


_fam179 = {"no rule below": _fams179([_DENY_OTHER163], True),
           "an allow for everyone below": _fams179([_DENY_OTHER163, _PUB22_163], True)}
check("1112 A03 (OWNER RULE): under a default incoming allow, _r38h_public_fams holds a DENY for one public "
      "address of the host both with and without a rule for everyone below it (SSH is public by the policy on "
      "every address but that one): the variant with nothing below it was dropped, held None",
      all(r[2] == _DENY_OTHER163 for r in _fam179.values()), repr(_fam179))
_famctl179 = {"a default deny, the DENY alone": _fams179([_DENY_OTHER163], False),
              "the same DENY for 2022 already": _fams179([_DENY_OTHER163, _DENY2022_179], True),
              "a LAN-address DENY": _fams179(["10.0.0.5 22/tcp  DENY IN  Anywhere"], True)}  # NOSONAR(S1313)
check("1112 A03: ...while a default deny reads the DENY alone as no public SSH, held nothing (unchanged), and "
      "under the allow policy a DENY already matched for the new port, or one for an address the internet does "
      "not reach, holds nothing (controls)",
      all(r[2] is None for r in _famctl179.values()) and _famctl179["a default deny, the DENY alone"][1] == []
      and _famctl179["the same DENY for 2022 already"][1] == [4], repr(_famctl179))
_walk179 = _hosts179._r41f_policy_deny(_status179([_PUB22_163, _DENY6_179]), [22], {4, 6}, 2022)
check("1112 A03: ...and an IPv6 DENY for one address with no IPv6 rule for everyone below it is found in that "
      "family's list while IPv4's SSH is public by its own rule",
      (_walk179 or {}).get("detail") == _DENY6_179, repr(_walk179))


def _move_allow179(rules, *a, **kw):
    """part163's move (22 -> 2022) with IPV6=no and `ufw status verbose`'s default incoming policy allow."""
    _p9_patch(_fw179, "remote_ufw_default_allows_in", lambda server: True)
    return _move163(rules, *a, ipv6="no", **kw)


_mv179 = {"a remote, no rule below": _move_allow179([_DENY_OTHER163]),
          "a remote, an allow for everyone below": _move_allow179([_DENY_OTHER163, _PUB22_163]),
          "the panel's host, no rule below": _move_allow179([_DENY_OTHER163], None, local=True)}
check("1112 A03 (OWNER RULE): change_ssh_port under a default incoming allow, with SSH denied on one public "
      "address of the host, is refused naming that DENY and sends no allow verb, both with no rule below it "
      "and with an allow for everyone below it (%s): with nothing below, the new port opened on that address"
      % ", ".join(_mv179),
      all(r[0] is False and r[2] == [] and _HELD179 in r[1] and "Nothing was changed" in r[1]
          for r in _mv179.values()),
      repr({k: (r[0], r[1][:240], r[2]) for k, r in _mv179.items()}))
_mvok179 = _move_allow179([_DENY_OTHER163, _DENY2022_179])
check("1112 A03: ...while with the same DENY for the new port already the move goes on, the public path's "
      "allow below it (control)",
      _mvok179[0] is True and _mvok179[2] == _PROXY_ADD163, repr(_mvok179))


def _route179(rules, session=_PUB_SESS159, box=None, allow_in=True):
    """POST /api/remote/<P9_HOST>/ssh-port {port: 2022} over part159's stand-in (or `box`), IPV6=no.

    `session`: the panel's session as the remote reads it (None: unread); `allow_in`: the default incoming
    policy. -> (status, json, the allow verbs sent, the newest change_ssh_port audit row). The host row's
    SSH port is put back afterwards, so a move that went through does not shift the next call's.
    """
    box = box or _Box159(rules)
    port0 = _p9_host_row(P9_HOST).port
    try:
        _p9_arm(who="part179")
        _p9_patch(_core179, "run_privileged", box.priv)
        _p9_patch(_core179, "run_command", lambda *a, **k: ("", "", 1))
        _p9_patch(_core179, "write_root_file", box.write)
        _p9_patch(_hosts179, "_sshd_socket_activated", lambda s: False)
        _p9_patch(_hosts179, "_restart_ssh_listener", box.restart)
        _p9_patch(_hosts179, "_point_f2b_sshd_at", lambda server, ports: ("updated", ""))
        _p9_patch(_hosts179, "_fwb_ssh_conn", lambda s: session)
        _p9_patch(_hosts179, "_tailscale_conn_state", lambda s: (True, False))
        _p9_patch(_ue179, "ts_netfilter_on", lambda s: False)
        _p9_patch(_ue179, "app_profiles", lambda s: None)
        _p9_patch(_hosts179, "_r40_ufw_v6_state", lambda server: False)
        _p9_patch(_fw179, "remote_ufw_default_allows_in", lambda server: allow_in)
        r = _p9_client(P9_ADMIN).post("/api/remote/%d/ssh-port" % P9_HOST, json={"port": 2022})
        return r.status_code, _p9_json(r), box.allows, _p9_audit("change_ssh_port")
    finally:
        _p9_restore_all()
        _p9_set_host(P9_HOST, port=port0)


_rt179 = {"no rule below": _route179([_DENY_OTHER163]),
          "an allow for everyone below": _route179([_DENY_OTHER163, _PUB22_163])}
check("1112 A03 (route, OWNER RULE): POST /api/remote/<id>/ssh-port under a default incoming allow, SSH denied on "
      "one public address of the host, answers the refusal naming that DENY, sends no allow verb, and audits the "
      "move as failed, with and without a rule for everyone below the DENY",
      all(r[0] == 200 and r[1].get("success") is False and _HELD179 in (r[1].get("message") or "") and r[2] == []
          and r[3].success is False and r[3].detail == "22 -> 2022" for r in _rt179.values()),
      repr({k: (r[0], r[1], r[2], getattr(r[3], "detail", None)) for k, r in _rt179.items()}))
_rtok179 = _route179([_DENY_OTHER163, _DENY2022_179])
check("1112 A03 (route): ...and with the same DENY for 2022 already the route moves SSH, the public path's allow "
      "sent (control)",
      _rtok179[0] == 200 and _rtok179[1].get("success") is True and _rtok179[2] == _PROXY_ADD163,
      repr((_rtok179[0], _rtok179[1], _rtok179[2])))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# OWNER RULE: an unread `ufw status`, or an inactive firewall's unread stored rules, refuses step 1
# ════════════════════════════════════════════════════════════════════════════════════════════════
_UNREAD_ST179 = "Couldn't read the firewall (ufw status), so whether opening port 2022/tcp would make SSH"
_UNREAD_ADDED179 = "its stored rules (ufw show added) could not be read"


def _step1_179(status_rc, added=("", "", 0)):
    """_open_ssh_port_rule(22 -> 2022) with `ufw status` answering rc `status_rc` -> (its answer, verbs sent)."""
    sent = []

    def run(server, verb, args=(), **k):
        sent.append(verb)
        if verb == "ufw-status":
            return ("Status: inactive\n", "", 0) if status_rc == 0 else ("", "ufw: timed out", status_rc)
        return added if verb == "ufw-show-added" else ("", "", 0)
    try:
        _p9_arm(who="part179")
        _p9_patch(_core179, "run_privileged", run)
        got = _hosts179._open_ssh_port_rule(NS(id=-179, name="p179", host="198.51.100.9"), 2022, ["22"])
    finally:
        _p9_restore_all()
    return got, [v for v in sent if v.startswith("ufw-allow")]


_st179 = {"a failed read": _step1_179(1), "a timed-out read": _step1_179(124)}
check("1112 T8b (OWNER RULE): step 1 of an SSH port move refuses when `ufw status` cannot be read, naming the "
      "unread read and sending no allow verb (%s): it added `allow 2022/tcp` from Anywhere blind, on a host "
      "whose SSH may be tailnet-only, and kept it after a failed move" % ", ".join(_st179),
      all(r[0][0] is False and _UNREAD_ST179 in str(r[0][1]) and "Nothing was changed" in str(r[0][1])
          and r[1] == [] for r in _st179.values()), repr(_st179))
_st_ctl179 = {"no ufw (127)": _step1_179(127),
              "inactive, stored rules unread": _step1_179(0, ("", "panel-helper: unknown verb", 2)),
              "inactive, a failed read": _step1_179(0, ("", "ufw: timed out", 1))}
check("1112 T8b: ...a host without ufw (the read answers 127) has nothing to open: no refusal and no verb; and "
      "an inactive firewall whose stored rules cannot be read (an older helper, a failed read) refuses, "
      "naming `ufw show added`, with no allow sent (it opened blind, applied the moment UFW came on)",
      _st_ctl179["no ufw (127)"] == ((False, None), [])
      and all(_st_ctl179[k][0][0] is False and _UNREAD_ADDED179 in str(_st_ctl179[k][0][1])
              and _st_ctl179[k][1] == [] for k in ("inactive, stored rules unread", "inactive, a failed read")),
      repr(_st_ctl179))


class _UnreadBox179(_Box159):
    """part159's stand-in whose `ufw status` read fails."""

    def _answer(self, verb):
        return ("", "ufw: timed out", 1) if verb == "ufw-status" else super()._answer(verb)


_rtst179 = _route179([], box=_UnreadBox179([]), allow_in=False)
check("1112 T8b (route, OWNER RULE): POST /api/remote/<id>/ssh-port on a host whose `ufw status` cannot be read "
      "answers the refusal, sends no allow verb, and audits the move as failed",
      _rtst179[0] == 200 and _rtst179[1].get("success") is False
      and _UNREAD_ST179 in (_rtst179[1].get("message") or "") and _rtst179[2] == []
      and _rtst179[3].success is False and _rtst179[3].detail == "22 -> 2022",
      repr((_rtst179[0], _rtst179[1], _rtst179[2], getattr(_rtst179[3], "detail", None))))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# A dialled remote, SSH public everywhere, a scoped DENY ahead of the new port, the session unread
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SCOPED179 = "Couldn't read the panel's own SSH connection to this host, and a firewall rule for one interface"
_scoped_rows179 = {"an interface DENY": "2022/tcp on eth0  DENY IN  Anywhere",
                   "a source DENY": "2022/tcp  DENY IN  198.51.100.0/24"}       # NOSONAR(S1313)
_sc179 = {k: _move159([row, _PUB22_163, _SSH6_PUB159], None) for k, row in _scoped_rows179.items()}
check("1112 T8b: an SSH port move on a remote the panel dials through sshd, SSH public in both families, with an "
      "interface- or source-scoped DENY ahead of the new port and the panel's session unread, is refused and "
      "sends no allow verb (%s): it took the public path, appended the allow below the DENY, and the route "
      "pointed the panel at a port that drops its own connection" % ", ".join(_sc179),
      all(r[0] is False and r[2] == [] and _SCOPED179 in r[1] and "Nothing was changed" in r[1]
          for r in _sc179.values()), repr({k: (r[0], r[1][:240], r[2]) for k, r in _sc179.items()}))
_sc_ctl179 = {"no scoped DENY, session unread": _move159([_PUB22_163, _SSH6_PUB159], None),
              "the panel's host, a scoped DENY": _move159([_scoped_rows179["an interface DENY"], _PUB22_163,
                                                           _SSH6_PUB159], None, local=True)}
check("1112 T8b: ...while with no scoped DENY the unread session still takes the public path, and the panel's own "
      "host (no session through sshd to read) still does with one (controls)",
      all(r[0] is True and r[2] == _PROXY_ADD163 for r in _sc_ctl179.values()),
      repr({k: (r[0], r[1][:200], r[2]) for k, r in _sc_ctl179.items()}))
_rtsc179 = _route179([_scoped_rows179["an interface DENY"], _PUB22_163, _SSH6_PUB159], session=None,
                     allow_in=False)
check("1112 T8b (route): POST /api/remote/<id>/ssh-port on that remote answers the refusal, sends no allow verb, "
      "and audits the move as failed",
      _rtsc179[0] == 200 and _rtsc179[1].get("success") is False
      and _SCOPED179 in (_rtsc179[1].get("message") or "") and _rtsc179[2] == []
      and _rtsc179[3].success is False and _rtsc179[3].detail == "22 -> 2022",
      repr((_rtsc179[0], _rtsc179[1], _rtsc179[2], getattr(_rtsc179[3], "detail", None))))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# Host traffic: stacked interfaces are not summed with the NIC they ride on
# ════════════════════════════════════════════════════════════════════════════════════════════════
_skip179 = ("bond0", "team0", "br0", "vmbr0", "eno1.100", "bond0.20", "vlan100", "macvlan0", "macvtap0",
            "ipvlan0", "tap100i0", "fwbr100i0", "fwpr100p0", "fwln100i0", "vnet3", "ifb0", "tun0", "ppp0",
            "ztabcd1234", "gre0", "gretap0", "erspan0", "ip6tnl0", "ip6gre0", "ip_vti0", "ip6_vti0", "sit0",
            "tunl0", "vxlan0", "podman0", "cni-podman0", "lxdbr0", "lxcbr0")
_keep179 = ("eno1", "eno2", "eth0", "ens3", "enp0s3", "enp1s0f1", "wlp2s0", "lowpan0", "venet0")
eq("1112 A03 host traffic: bond and team masters, bridges, VLAN sub-interfaces, macvlan/ipvlan links, guest taps, "
   "ifb and tunnels do not count (their bytes are on the NIC below too); NICs still count",
   ([n for n in _skip179 if _netdev179.counted(n)], [n for n in _keep179 if not _netdev179.counted(n)]), ([], []))


def _dev179(rows):
    """A /proc/net/dev holding `rows` [(name, rx bytes, tx bytes)], in the kernel's layout."""
    head = ("Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo "
            "colls carrier compressed\n")
    return head + "".join("%6s: %d 1 0 0 0 0 0 0 %d 1 0 0 0 0 0 0\n" % r for r in rows)


def _stack179(eno1, eno2, tx1, tx2):
    """A bonded host with a VLAN, a VM bridge and its taps, and a tunnel: the NICs carry everything."""
    rx, tx = eno1 + eno2, tx1 + tx2
    return [("lo", 5, 5), ("eno1", eno1, tx1), ("eno2", eno2, tx2), ("bond0", rx, tx), ("bond0.100", rx, tx),
            ("vmbr0", rx, tx), ("tap100i0", rx // 2, tx // 2), ("fwbr100i0", rx // 2, tx // 2),
            ("tun0", rx // 3, tx // 3), ("ppp0", 9, 9), ("ztabcd1234", 7, 7)]


_lines179 = _run_netif177(_dev179(_stack179(1000, 2000, 30, 40)))
_host179, _ = _core179._parse_host_sample("MEM 100 50\n" + "\n".join(_lines179 or []))
eq("1112 A03 host traffic: the host read of a bonded host with a VLAN, a VM bridge, guest taps and tunnels sums "
   "the member NICs' bytes once (the bond, its VLAN and the bridge carry the same bytes again)",
   (len(_lines179 or []), _host179.get("net_rx_bytes"), _host179.get("net_tx_bytes")), (11, 3000, 70))


class _Clock179:
    """netdev's `time`: time() answers the sampler pass's reading time."""

    at = 0.0

    def time(self):
        return self.at


_clk179 = _Clock179()
_out179 = {"text": ""}


def _pass179(at, eno1, eno2, tx1, tx2):
    """One sampler pass whose host read prints the stacked host's counters, read at `at`."""
    _clk179.at = at
    _out179["text"] = "MEM 100 50\n" + "\n".join(_run_netif177(_dev179(_stack179(eno1, eno2, tx1, tx2))) or [])
    for k in (P9_HOST, P9_HOST2, P9_LOCAL):
        _core179._host_metrics_cache.pop(k, None)
    _mon179._record_metric_samples(_p9)


_smp179 = {}
try:
    _p9_arm(who="part179")
    _trips179 = len(_P9_TRIPPED)
    _p9_patch(_core179, "run_command", lambda *a, **k: (_out179["text"], "", 0))
    _p9_patch(_netdev179, "time", _clk179)
    for _k179 in (P9_HOST, P9_HOST2, P9_LOCAL):
        _mon179._hch_net_last.pop(_k179, None)
    with _p9.app_context():
        _clear177()
    _pass179(7000.0, 1000, 2000, 30, 40)
    _pass179(7060.0, 1000 + 375000, 2000 + 375000, 30 + 3750, 40 + 3750)
    _smp179["rows"] = _host_rows177()
    _smp179["trips"] = _P9_TRIPPED[_trips179:]
finally:
    _p9_restore_all()
    for _k179 in (P9_HOST, P9_HOST2, P9_LOCAL):
        _mon179._hch_net_last.pop(_k179, None)
        _core179._host_metrics_cache.pop(_k179, None)
    with _p9.app_context():
        _clear177()
eq("1112 A03 host traffic (sampler): the history sampler, reading that bonded host twice 60 s apart, stores the "
   "NICs' rate once (100 and 1 kbit/s), not the bond's, VLAN's and bridge's copies added on top",
   _smp179.get("rows"), [(None, None), (100.0, 1.0)])

check("part179: nothing reached a host, sudo, ufw, a resolver or data/ (the transport tripwire)",
      _P9_TRIPPED[_TRIP179_START:] == [] and _smp179.get("trips") == [], repr(_P9_TRIPPED[_TRIP179_START:][:4]))
