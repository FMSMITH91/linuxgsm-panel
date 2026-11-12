"""Part 163 of the unit suite: review 1109's firewall and lock-out findings (builder B).

* LOW (Q1): an SSH port move on a remote the panel dials through sshd, with SSH public in one family only
  and the panel's session unread, is refused: only that family's rule went in, and a panel dialling the
  other family was cut off.
* LOW (Q1): a rule for one private, link-local or tailnet address above the public SSH rule no longer
  hides public SSH (the move was refused naming the public rule as one it could not copy).
* LOW, OWNER RULE (Q1): SSH public on ONE public address of the host (or denied on one, above the rule
  letting everyone else in) is copied by nothing the panel has: the move is refused naming the rule,
  until the operator has the same rule for the new port. It used to open the new port on every address.
* lead (Q1/Q4), OWNER RULE: a firewall that lists no `(v6)` row while ufw's files say IPV6=yes is not
  "IPv4 alone": ufw writes `allow proto tcp to any port N` for both families, so an IPv4-only public SSH
  rule made the new port public over IPv6 too. IPv4's rule from anywhere goes in alone.
* LOW (A03): on the panel host, a loopback viewer (a proxy here that sends no forwarding header looks the
  same) has every established connection to the panel's and a proxy's ports held by an IP block, not
  only sshd's: a block of the range holding the admin's address cut them off through nginx.
* LOW (A03): on the panel host with the viewer unknown, the delete guard keeps the rules that may let a
  proxy's port in (the reverse proxy's own `443/tcp` allow was an ordinary delete).
* LOW (A03): Close port 22 shares "Disable public SSH"'s whole gate, so a panel dialling the host's
  tailnet address on a port Tailscale SSH does not answer is not cut off by it.

HOW IT RUNS. part159's port-move stand-in, part135's stand-in hosts and part154's loopback runner, on
part12's patcher with its transport tripwire armed. Nothing reaches a host, sudo, ufw, a resolver or data/.
"""
from unit.part01 import check
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_host_row, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_set_host)
from unit import part135 as _p135
from unit.part154 import _lo154
from unit.part159 import _HARD4_159, _PUBH159, _SSH6_PUB159, _TS0_159, _TSH159, _V4_ADD159, _V6_ADD159, _move159
from panel.ops.ssh_manager import firewall as _fw163, hosts as _hosts163, ufweval as _ue163
from panel.routes import close_port22 as _cp163

_TRIP163_START = len(_P9_TRIPPED)
_PUB22_163 = "22/tcp  ALLOW IN  Anywhere"
_PUBH_ALLOW163 = _PUBH159 + " 22/tcp  ALLOW IN  Anywhere"
_OTHER_PUB163 = "203.0.113.9"      # NOSONAR(S1313) - another public address of the remote (a failover IP)
_PROXY_ADD163 = [("ufw-allow-proto-port", ["tcp", "2022", "SSH panel"])]

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LOW (Q1): one family public, the panel's session unread, on a remote it dials -> refused
# ════════════════════════════════════════════════════════════════════════════════════════════════
_unread163 = {
    "v6 public, v4 hardened": _move159([_HARD4_159, _SSH6_PUB159], None),
    "v4 public, v6 hardened": _move159([_PUB22_163, "22/tcp (v6)  ALLOW IN  2001:db8:77::/64"], None),
}
_unread_ctl163 = _move159([_HARD4_159, _SSH6_PUB159], None, local=True)
check("1109 Q1: an SSH port move on a remote the panel dials through sshd, SSH public in one family only and the "
      "panel's session unread, is refused naming that family, nothing sent (only that family's rule went in, and "
      "the panel's own family got nothing); on the panel's host, which the panel does not dial, that family's rule "
      "still goes in alone (control)",
      all(r[0] is False and r[2] == [] and "is public over IPv" in r[1] and "Nothing was changed" in r[1]
          for r in _unread163.values())
      and "IPv6 only" in _unread163["v6 public, v4 hardened"][1]
      and "IPv4 only" in _unread163["v4 public, v6 hardened"][1]
      and _unread_ctl163[0] is True and _unread_ctl163[2] == _V6_ADD159,
      repr(({k: (r[0], r[1][:200], r[2]) for k, r in _unread163.items()}, _unread_ctl163)))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LOW (Q1): a rule for one address that the internet does not reach does not end the reading
# ════════════════════════════════════════════════════════════════════════════════════════════════
_BOTH163 = [_PUB22_163, _SSH6_PUB159]
_inner163 = {
    "a LAN-address allow above it": ["10.0.0.5 22/tcp  ALLOW IN  Anywhere"],    # NOSONAR(S1313)
    "a LAN-address DENY above it": ["192.168.1.5 22/tcp  DENY IN  Anywhere"],   # NOSONAR(S1313)
    "a tailnet-address DENY above it": [_TSH159 + " 22/tcp  DENY IN  Anywhere"],
    "a public-address allow above it": [_PUBH_ALLOW163],
}
_in_got163 = {k: _move159(rows + _BOTH163) for k, rows in _inner163.items()}
_in_got163["the panel's host, a LAN-address allow above it"] = _move159(
    _inner163["a LAN-address allow above it"] + _BOTH163, None, local=True)
check("1109 Q1: public SSH listed below a rule for one private, link-local or tailnet address of the host (an allow "
      "or a DENY), or below an allow for one public address, still reads as public: the move takes the public "
      "path, as without that rule (%s); it was refused naming the public rule as one it could not copy, and on the "
      "panel's host said public SSH was off" % ", ".join(_in_got163),
      all(r[0] is True and r[2] == _PROXY_ADD163 and "Public SSH is off" not in r[1] for r in _in_got163.values()),
      repr({k: (r[0], r[1][:200], r[2]) for k, r in _in_got163.items()}))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LOW, OWNER RULE (Q1): SSH public on one public address only, or denied on one -> refused, named
# ════════════════════════════════════════════════════════════════════════════════════════════════
_DENY_OTHER163 = _OTHER_PUB163 + " 22/tcp  DENY IN  Anywhere"
_held163 = {
    "public on one address, a v6 row elsewhere": (_move159([_PUBH_ALLOW163, "80/tcp (v6)  ALLOW IN  Anywhere (v6)"]),
                                                  _PUBH_ALLOW163),
    "public on one address, no v6 row": (_move159([_PUBH_ALLOW163]), _PUBH_ALLOW163),
    "the panel's host, public on one address": (_move159([_PUBH_ALLOW163], None, local=True), _PUBH_ALLOW163),
    "denied on one address above the public rule": (_move159([_DENY_OTHER163] + _BOTH163), _DENY_OTHER163),
    "the panel's host, denied on one address": (_move159([_DENY_OTHER163] + _BOTH163, None, local=True),
                                                _DENY_OTHER163),
}
check("1109 Q1 (OWNER RULE): where SSH is public on ONE public address of the host only, or denied on one above "
      "the rule letting everyone else in, the move is refused naming that rule, with nothing sent (%s): it opened "
      "the new port to the internet on every address of the family (both families with no v6 row)"
      % ", ".join(_held163),
      all(r[0] is False and r[2] == [] and "depends on the firewall rule `%s`" % rule in r[1]
          and "Nothing was changed" in r[1] for r, rule in _held163.values()),
      repr({k: (r[0], r[1][:240], r[2]) for k, (r, _rule) in _held163.items()}))
_met163 = {
    "public on one address, the operator's 2022 rule for it": _move159(
        [_PUBH_ALLOW163, _PUBH159 + " 2022/tcp  ALLOW IN  Anywhere"]),
    "the panel's host, the same": _move159([_PUBH_ALLOW163, _PUBH159 + " 2022/tcp  ALLOW IN  Anywhere"], None,
                                           local=True),
    "denied on one address, the operator's 2022 DENY for it": _move159(
        [_DENY_OTHER163, _OTHER_PUB163 + " 2022/tcp  DENY IN  Anywhere"] + _BOTH163),
}
check("1109 Q1 (OWNER RULE): ...and once the operator has the same rule for the new port, the move goes on: nothing "
      "public added for an address-only allow (the operator's rule already does it, and the note says so on the "
      "panel's host), the public path below an address-only DENY the operator copied",
      _met163["public on one address, the operator's 2022 rule for it"][:3:2] == (True, [])
      and _met163["the panel's host, the same"][:3:2] == (True, [])
      and "a rule of yours already does the same for port 2022" in _met163["the panel's host, the same"][1]
      and _met163["denied on one address, the operator's 2022 DENY for it"][:3:2] == (True, _PROXY_ADD163),
      repr({k: (r[0], r[1][:240], r[2]) for k, r in _met163.items()}))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# lead (Q1/Q4), OWNER RULE: no (v6) row listed is not "IPv4 alone"
# ════════════════════════════════════════════════════════════════════════════════════════════════
_STORED_TEXT163 = _p135._Host135()._stored()          # ufw's files as the helper prints them: IPV6=yes


def _move163(rules, *a, ipv6="yes", **kw):
    """_move159 with ufw's stored files read as IPV6=`ipv6` (None: the files could not be read)."""
    text = _STORED_TEXT163.replace("IPV6=yes", "IPV6=%s" % ipv6) if ipv6 else ""
    _p9_patch(_fw163, "_fwa_read_stored", lambda server: _fw163._fwa_split_stored(text) if ipv6 else None)
    return _move159(rules, *a, **kw)        # its restore ends this patch too


_v4only163 = {
    "a remote, IPv4 public SSH and no v6 row": _move163([_PUB22_163]),
    "a remote, a LIMIT and no v6 row": _move163(["22/tcp  LIMIT IN  Anywhere"]),
    "the panel's host, IPv4 public SSH and no v6 row": _move163([_PUB22_163, _TS0_159], None, local=True),
}
_v4fail163 = _move163([_PUB22_163], up=False)
check("1109 lead (OWNER RULE): on a firewall listing no (v6) row while ufw's files say it handles IPv6 (IPV6=yes, "
      "so `allow proto tcp to any port N` is written for both families), IPv4 public SSH gets IPv4's rule from "
      "anywhere alone for the new port, never the both-family allow (%s); a failed move takes exactly that rule "
      "back out" % ", ".join(_v4only163),
      all(r[0] is True and r[2] == _V4_ADD159 and "over IPv4 only" in r[1] for r in _v4only163.values())
      and _v4fail163[0] is False and _v4fail163[2] == _V4_ADD159 + [
          ("ufw-delete-allow-from-port", ["0.0.0.0/0", "2022", "tcp"])],    # NOSONAR(S1313)
      repr(({k: (r[0], r[1][:200], r[2]) for k, r in _v4only163.items()}, _v4fail163)))
_v6off163 = {"IPV6=no": _move163([_PUB22_163], ipv6="no")}
check("1109 lead: ...while with IPV6=no (ufw drops IPv6 whatever its rules say) the IPv4 reading decides as "
      "before: the public path (control; the files unread is part178's: refused)",
      all(r[0] is True and r[2] == _PROXY_ADD163 for r in _v6off163.values()),
      repr({k: (r[0], r[1][:200], r[2]) for k, r in _v6off163.items()}))
_both_ctl163 = _move159(_BOTH163)
check("1109 lead: ...while public SSH in both families still takes the public path (control)",
      _both_ctl163[0] is True and _both_ctl163[2] == _PROXY_ADD163, repr(_both_ctl163))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LOW (A03): a loopback viewer's IP block holds the panel's and a proxy's established connections too
# ════════════════════════════════════════════════════════════════════════════════════════════════
_ADMIN163 = "198.51.100.7"         # NOSONAR(S1313) - the admin's real address, behind a headerless proxy
_RANGE163 = "198.51.100.0/24"      # NOSONAR(S1313) - holds it
_ELSE163 = "203.0.113.0/24"        # NOSONAR(S1313) - holds no connection


def _lo_block163(target, sessions):
    return _lo154(lambda: _fw163.fwc_block_ip_refusal(_p135._LOCAL135, target), sessions=sessions)


_lo_cut163 = {"443 (nginx)": _lo_block163(_RANGE163, [(_ADMIN163, 443)]),
              "80": _lo_block163(_RANGE163, [(_ADMIN163, 80)]),
              "the panel's own port": _lo_block163(_RANGE163, [(_ADMIN163, 5000)])}
_lo_ok163 = {"a game port": _lo_block163(_RANGE163, [(_ADMIN163, 27015)]),
             "443, another range": _lo_block163(_ELSE163, [(_ADMIN163, 443)]),
             "nothing open": _lo_block163(_RANGE163, [])}
check("1109 A03: on the panel host, a request over loopback naming no forwarded client (a minimal nginx "
      "proxy_pass sends none) may not block a range holding an established connection to 443, 80 or the panel's "
      "port: refused, naming it as a way in through a proxy here (it held sshd's sessions only, and the admin's "
      "nginx connection was cut)",
      all(v is not None and _ADMIN163 in v and "through a proxy here" in v for v in _lo_cut163.values()),
      repr(_lo_cut163))
check("1109 A03: ...while a connection to a game port, a range holding none, or nothing open still lets the block "
      "through (controls)", all(v is None for v in _lo_ok163.values()), repr(_lo_ok163))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LOW (A03): the viewer unknown on the panel host keeps the proxy port's allow
# ════════════════════════════════════════════════════════════════════════════════════════════════
_WEB_RULES163 = ["22/tcp  ALLOW IN  Anywhere", "443/tcp  ALLOW IN  Anywhere", "443/tcp  DENY IN  192.0.2.99",
                 "443/udp  ALLOW IN  Anywhere", "443/tcp  ALLOW OUT  Anywhere (out)", "27015/tcp  ALLOW IN  Anywhere",
                 "443/tcp on docker0  ALLOW IN  Anywhere"]


def _guard163(headers, peer="127.0.0.1"):   # NOSONAR(S1313)
    """{rule text: protect_reason_key} of the panel host's rules, read by a request from `peer` with `headers`."""
    host = _p135._Host135(rules=_WEB_RULES163, incoming="deny")

    def run():
        with _p9.test_request_context("/", environ_base={"REMOTE_ADDR": peer}, headers=headers):
            groups = _fw163.remote_ufw_status(_p135._LOCAL135).get("groups") or []
        return {"%s %s %s %s" % (g.get("port_label"), g.get("iface") or "", g.get("action"), g.get("direction")):
                g.get("protect_reason_key") if g.get("protected") else None for g in groups}
    return _p135._on135(host, run)


_g_unknown163 = _guard163({"X-Forwarded-For": "198.51.100.40"})     # NOSONAR(S1313) - an unbelieved proxy
_g_local163 = _guard163({})
_g_known163 = _guard163({}, peer=_p135._VIEWER135)


def _key163(got, label, action="ALLOW", direction="IN", iface=""):
    return next((v for k, v in got.items() if k.split()[0] == label and action in k and direction in k
                 and (iface in k)), "absent")


_web_unknown163 = _fw163.R14A_REASONS["web_unknown"]
check("1109 A03: on the panel host with the viewer unknown (an unbelieved proxy, or loopback naming no client), the "
      "delete guard protects the 443/tcp allow a reverse proxy may serve the panel on (it was an ordinary delete), "
      "and not the DENY, the UDP or OUT rules for 443, or a game port's allow",
      all(_key163(g, "443/tcp") == _web_unknown163 for g in (_g_unknown163, _g_local163))
      and all(_key163(g, "443/tcp", action="DENY") is None and _key163(g, "443/udp") is None
              and _key163(g, "443/tcp", direction="OUT") is None and _key163(g, "27015/tcp") is None
              for g in (_g_unknown163, _g_local163)),
      repr((_g_unknown163, _g_local163)))
check("1109 A03: ...while a viewer the panel can read (straight in from its own address) leaves 443/tcp deletable "
      "(control: it comes in on the panel's port)", _key163(_g_known163, "443/tcp") is None, repr(_g_known163))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LOW (A03): Close port 22 has "off"'s tailnet-dial gate
# ════════════════════════════════════════════════════════════════════════════════════════════════
_closed163 = []


def _close22_163(netfilter_on):
    """POST close-port-22 for a key-auth row dialled at the host's tailnet address on 2222 -> (message, closed)."""
    was = _p9_host_row(P9_HOST)
    _closed163[:] = []
    try:
        _p9_arm(who="part163")
        _p9_set_host(P9_HOST, host=_TSH159, port=2222, auth_method="key")
        _p9_patch(_hosts163, "_tailnet_ssh_state", lambda s: (True, True, False))   # Tailscale SSH on, no ts0 rule
        _p9_patch(_hosts163, "_r28b_resolve", lambda name: [])
        _p9_patch(_ue163, "ts_netfilter_on", lambda s: netfilter_on)
        _p9_patch(_cp163, "remote_ufw_close_port_22", lambda r: (_closed163.append(r.id), (True, "closed p163"))[1])
        msg = _p9_json(_p9_client(P9_ADMIN).post("/api/remote/%d/close-port-22" % P9_HOST)).get("message")
        return str(msg), list(_closed163)
    finally:
        _p9_restore_all()
        _p9_set_host(P9_HOST, host=was.host, port=was.port, auth_method=was.auth_method)


_c22_cut163, _c22_ok163 = _close22_163(False), _close22_163(True)
check("1109 A03: Close port 22 on a host the panel dials at its tailnet address on 2222, Tailscale SSH on, no "
      "tailscale0 rule and tailscaled not in its default netfilter mode, is refused as \"Disable public SSH\" is, "
      "nothing deleted (it checked only the public-dial half); with tailscaled's chain ahead of ufw it closes "
      "(control)",
      "Tailscale SSH does not answer" in _c22_cut163[0] and _c22_cut163[1] == []
      and _c22_ok163 == ("closed p163", [P9_HOST]), repr((_c22_cut163, _c22_ok163)))

check("1109 part163: nothing reached a real transport", len(_P9_TRIPPED) == _TRIP163_START,
      repr(_P9_TRIPPED[_TRIP163_START:]))
