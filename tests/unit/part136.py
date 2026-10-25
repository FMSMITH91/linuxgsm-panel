"""Part 136 of the unit suite: the adversarial review of fw-more PR A (#460), every finding held.

The firewall's lock-out guards read the rules family-blind and source-blind, and Block IP guarded the
request's text rather than what it blocked. Held here, each finding with both directions:

* H1: a whitelisted or tailnet address written `/32`, `/128`, IPv4-mapped (or a mapped /128) is refused
  as itself, and the deny gets the canonical form; one address covering the panel's own source too.
* H2/H3: a way in counts only in the address family it covers, in that family's own rule order; a
  default deny is refused for an IPv4 panel with only a v6 SSH rule (and the mirror), and with IPV6=no
  for an IPv6 panel; the delete guard keeps the host's last IPv4 SSH rule beside a v6-only one.
* H4: the panel's way in must admit the address its connection comes from (a LAN-only rule does not,
  from outside the LAN); the panel host's web port must admit the viewer; unknown sources refuse.
* M1: a reverse proxy's port (trust_proxy, Serve) is the panel's own for a port block, and a viewer
  through a local proxy needs the port it reached the proxy on, not the panel's.
* M2/L4: a both-protocol block undoes only the halves THIS call added, per family; a skip is "already
  blocked" only where a block is listed; an allow that made ufw skip it is "not blocked"; while off, the
  answer says the block is only stored.
* M3: a block cannot cover any global address of the panel host; the check runs under the ufw_lock.
* L1-L7 as the report names them (L5's first half REFUTED: ufw's own reader is anchored at column 0).

HOW IT RUNS. On part135's stand-in host and patcher (part12's tripwire armed), routes on part12's app.
Nothing reaches a host, sudo, ufw or data/.
"""
import ipaddress as _ip136
from types import SimpleNamespace as _NS136

from unit.part01 import check
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client, _p9_patch,
                         _p9_restore_all)
from unit import part135 as _p135
from panel.core import config as _cfg136, i18n as _i18n136
from panel.ops.ssh_manager import _core as _core136, firewall as _fw136, hosts as _hosts136
from panel.routes import remote_security as _rs136, remote_vps as _rv136
from panel.services import monitoring as _mon136

# part135's stand-in host and its runner (its _VIEWER135 is set through the module, so one import form).
_Host135, _LOCAL135, _REMOTE135, _SSH22 = _p135._Host135, _p135._LOCAL135, _p135._REMOTE135, _p135._SSH22
_on135, _stored_text135 = _p135._on135, _p135._stored_text135
_TRIP136_START = len(_P9_TRIPPED)
_REAL_TSPORT136 = _fw136._fwb_tailscaled_port
_OUT136 = "198.51.100.77"     # NOSONAR(S1313) - documentation addresses throughout, never dialled
_V6SRC136 = "2001:db8::50"


class _Host136(_Host135):
    """_Host135 with IPV6=<ipv6> in its stored defaults and stored IPv6 tuples of its own."""

    def __init__(self, *a, ipv6="yes", stored6="", **k):
        super().__init__(*a, **k)
        self.ipv6, self.stored6 = ipv6, stored6

    def _stored(self):
        word = {"allow": "ACCEPT", "deny": "DROP", "reject": "REJECT"}
        default = "IPV6=%s\n" % self.ipv6 + "".join(
            'DEFAULT_%s_POLICY="%s"\n' % (k, word[self.pol[d]])
            for k, d in (("INPUT", "incoming"), ("OUTPUT", "outgoing"), ("FORWARD", "routed")))
        return _stored_text135(default, "LOGLEVEL=%s\n" % self.logging, self.stored_rules, self.stored6)


def _src136(src, fn):
    """`fn` with the panel's SSH source read as `src` (None: unread)."""
    def run(*a, **k):
        _p9_patch(_hosts136, "_fwb_ssh_conn", lambda s: _p135._conn135(src, s))
        return fn(*a, **k)
    return run


def _also136(patches, fn):
    """`fn` run after `patches` [(owner, name, value)] (inside _on135's patch scope)."""
    def run(*a, **k):
        for owner, name, value in patches:
            _p9_patch(owner, name, value)
        return fn(*a, **k)
    return run


def _deny136(rows, src=_OUT136, server=_REMOTE135, ipv6="yes", viewer=None, extra=(), **kw):
    """Default incoming deny on a stand-in with `rows`; -> (ok, message, what was sent)."""
    host = _Host136(rules=rows, incoming="allow", ipv6=ipv6, ts=kw.pop("ts", (False, False)),
                    sshd=kw.pop("sshd", ("22",)))
    old = _p135._VIEWER135
    _p135._VIEWER135 = viewer or old
    try:
        res = _on135(host, _also136(list(extra), _src136(src, _fw136.remote_ufw_set_default)), server,
                     "incoming", "deny", **kw)
    finally:
        _p135._VIEWER135 = old
    return res[0], str(res[1]), host.changes()


_SET = [("ufw-default", ["deny", "incoming"])]

# ════════════════════════════════════════════════════════════════════════════════════════════════
# H2: the family the panel uses
# ════════════════════════════════════════════════════════════════════════════════════════════════
_V6ONLY = ["22/tcp (v6)  ALLOW IN  Anywhere (v6)"]
_BOTH = [_SSH22, "22/tcp (v6)  ALLOW IN  Anywhere (v6)"]
_h2 = {
    "v6 rule, v4 panel": _deny136(_V6ONLY),
    "v4 rule, v6 panel": _deny136([_SSH22], src=_V6SRC136),
    "both, v6 panel, IPV6=no": _deny136(_BOTH, src=_V6SRC136, ipv6="no"),
    # A deny prepended for IPv6 alone, above the both-family allow in the v6 list: the v6 panel is cut.
    "v6 deny above, v6 panel": _deny136([_SSH22, "22/tcp (v6)  DENY IN  Anywhere (v6)",
                                         "22/tcp (v6)  ALLOW IN  Anywhere (v6)"], src=_V6SRC136),
}
_h2ok = {
    "v6 rule, v6 panel": _deny136(_V6ONLY, src=_V6SRC136),
    "both, v4 panel": _deny136(_BOTH),
    "both, v6 panel": _deny136(_BOTH, src=_V6SRC136),
    "v6 deny above, v4 panel": _deny136([_SSH22, "22/tcp (v6)  DENY IN  Anywhere (v6)",
                                         "22/tcp (v6)  ALLOW IN  Anywhere (v6)"]),
    "both, v4 panel, IPV6=no": _deny136(_BOTH, ipv6="no"),
}
check("H2: a default incoming deny is refused where the only way in is of the OTHER family (a v6-only SSH rule "
      "for an IPv4 panel, and the mirror), where IPV6=no drops the IPv6 panel, and where a v6-only deny sits "
      "above the allow in the v6 list — nothing sent",
      all(r[0] is False and r[2] == [] and "lock the panel or SSH out" in r[1] for r in _h2.values())
      and "IPV6=no" in _h2["both, v6 panel, IPV6=no"][1],
      repr({k: (r[0], r[1][:160]) for k, r in _h2.items()}))
check("H2: ...and set where the family the panel uses has its way in (the positive controls)",
      all(r[0] is True and r[2] == _SET for r in _h2ok.values()), repr({k: (r[0], r[1][:160]) for k, r in _h2ok.items()}))
# ufw marks "(v6)" only on ::/0; a rule from an IPv6 network lists without it and is IPv6 all the same.
_V6NET = ["22/tcp  ALLOW IN  2001:db8::/32"]
_v6net_v6 = _deny136(_V6NET, src=_V6SRC136)
_v6net_v4 = _deny136(_V6NET + ["22/tcp  ALLOW IN  192.0.2.0/24"], src="192.0.2.9")   # NOSONAR(S1313)
_v6net_v4no = _deny136(_V6NET)
check("H2: a rule from an IPv6 network (listed with no \"(v6)\") is the IPv6 panel's way in (set) and not an "
      "IPv4 panel's (refused); beside an IPv4 LAN rule the IPv4 panel inside that LAN is set",
      _v6net_v6[0] is True and _v6net_v4no[0] is False and _v6net_v4[0] is True,
      repr((_v6net_v6[:2], _v6net_v4no[:2], _v6net_v4[:2])))
_ST_V6 = "### tuple ### allow tcp 22 ::/0 any ::/0 in\n"
_ST6_136 = "### tuple ### allow udp 53 ::/0 any ::/0 out\n"
# The stored IPv6 rules are read only where ufw would load them (IPV6=yes): an IPV6=no host's v6 rows
# would otherwise count for the outbound checks, which read the groups family-blind.
_g6 = {k: _on135(_Host136(enabled=False, stored6=_ST6_136), _fw136._fwa_rule_groups, _REMOTE135, {"ipv6": k})
       for k in (True, False)}
check("H2: turning UFW on reads user6.rules only with IPV6=yes (an IPv6 row is in the groups then, none without)",
      any("IPv6" in g["families"] for g in _g6[True]) and not any("IPv6" in g["families"] for g in _g6[False]),
      repr({k: [(g["port_label"], g["families"]) for g in v] for k, v in _g6.items()}))
# Turning UFW on reads the STORED rules: user6.rules counts only with IPV6=yes.
_on_v6 = {}
for _k136, _ipv6, _src in (("v6 stored, v4 panel", "yes", _OUT136), ("v6 stored, v6 panel", "yes", _V6SRC136),
                           ("v6 stored, v6 panel, IPV6=no", "no", _V6SRC136)):
    _h136 = _Host136(enabled=False, stored6=_ST_V6, ipv6=_ipv6)
    _on_v6[_k136] = (_on135(_h136, _src136(_src, _fw136.remote_ufw_set_enabled), _REMOTE135, True), _h136.changes())
check("H2: turning UFW on with only a stored v6 SSH rule: refused for an IPv4 panel, and for an IPv6 one when "
      "IPV6=no (ufw would not load user6.rules); allowed for an IPv6 panel with IPV6=yes",
      _on_v6["v6 stored, v4 panel"][0][0] is False and _on_v6["v6 stored, v4 panel"][1] == []
      and _on_v6["v6 stored, v6 panel, IPV6=no"][0][0] is False and _on_v6["v6 stored, v6 panel, IPV6=no"][1] == []
      and _on_v6["v6 stored, v6 panel"][0][0] is True
      and _on_v6["v6 stored, v6 panel"][1] == [("ufw-enable", [])],
      repr({k: (v[0][0], str(v[0][1])[:140], v[1]) for k, v in _on_v6.items()}))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# H3: the delete guard, per family
# ════════════════════════════════════════════════════════════════════════════════════════════════


def _guard136(rows, server=_REMOTE135):
    st = _on135(_Host135(rules=rows), _fw136.remote_ufw_status, server)
    return {(g["port_label"], g["comment"], g["family_label"]): (g["protected"], g["warn"]) for g in st["groups"]}


_h3 = _guard136([_SSH22, "22/tcp (v6)  ALLOW IN  Anywhere (v6)  # v6", "22/tcp (v6)  ALLOW IN  Anywhere (v6)"])
_h3_two = _guard136([_SSH22, "22/tcp  ALLOW IN  Anywhere  # second", "22/tcp (v6)  ALLOW IN  Anywhere (v6)",
                     "22/tcp (v6)  ALLOW IN  Anywhere (v6)  # second"])
_h3_name = _guard136([_SSH22, "22/tcp  ALLOW IN  Anywhere  # v4", "22/tcp (v6)  ALLOW IN  Anywhere (v6)"],
                     server=_NS136(is_local=False, auth_method="key", host="box.example.net", port=22, id=None,
                                   name="n136"))
check("H3: beside a v6-only SSH rule the host's one IPv4 SSH rule is PROTECTED for a panel dialling an IPv4 "
      "address (deleting it is refused, not warned); the v6-only rule itself only warns",
      _h3.get(("22/tcp", "", "IPv4 + IPv6")) == (True, False) and _h3.get(("22/tcp", "v6", "IPv6")) == (False, True),
      repr(_h3))
check("H3: ...with two rules in each family both only warn; for a host dialled by NAME (family unknown) the "
      "only rule that covers IPv6 is protected while the v4 one beside it warns",
      _h3_two.get(("22/tcp", "", "IPv4 + IPv6")) == (False, True)
      and _h3_two.get(("22/tcp", "second", "IPv4 + IPv6")) == (False, True)
      and _h3_name.get(("22/tcp", "", "IPv4 + IPv6")) == (True, False)
      and _h3_name.get(("22/tcp", "v4", "IPv4")) == (False, True), repr((_h3_two, _h3_name)))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# H4: the source the panel's connection comes from
# ════════════════════════════════════════════════════════════════════════════════════════════════
_LAN = ["22/tcp  ALLOW IN  192.0.2.0/24"]   # NOSONAR(S1313)
_h4_out = _deny136(_LAN)
_h4_in = _deny136(_LAN, src="192.0.2.9")   # NOSONAR(S1313)
_h4_unread = _deny136([_SSH22], src=None)
_h4_srcport = _deny136(["22/tcp  ALLOW IN  192.0.2.9 51515"], src="192.0.2.9")   # NOSONAR(S1313)
_h4_autoblk = _deny136(["Anywhere  DENY IN  198.51.100.77", _SSH22])   # NOSONAR(S1313)
check("H4: an SSH rule kept to a LAN is no way in for a panel connecting from outside it (refused, the source "
      "named), nor a From with a source port, nor anything when the source cannot be read; a deny of the "
      "panel's own source above the allow refuses too",
      _h4_out[0] is False and _h4_out[2] == [] and "from 198.51.100.77 to" in _h4_out[1]
      and _h4_srcport[0] is False and _h4_unread[0] is False and "Couldn't read the address" in _h4_unread[1]
      and _h4_autoblk[0] is False,
      repr((_h4_out[:2], _h4_srcport[:2], _h4_unread[:2], _h4_autoblk[:2])))
check("H4: ...and set where the panel's source is inside the LAN rule (positive control)",
      _h4_in[0] is True and _h4_in[2] == _SET, repr(_h4_in))
_PANEL_ONE = [_SSH22, "5000/tcp  ALLOW IN  192.0.2.10"]   # NOSONAR(S1313)
_h4p_out = _deny136(_PANEL_ONE, server=_LOCAL135)
_h4p_in = _deny136(_PANEL_ONE, server=_LOCAL135, viewer="192.0.2.10")   # NOSONAR(S1313)
_h4p_lo = _deny136([_SSH22, "5000/tcp  ALLOW IN  Anywhere"], server=_LOCAL135, viewer="127.0.0.1")   # NOSONAR(S1313)
check("H4 (panel host): a web-port rule from one address is no way in for a viewer elsewhere (refused), is for "
      "that address (set); a request from the panel's own machine (who is behind it unknown) refuses",
      _h4p_out[0] is False and "from 203.0.113.20 to" in _h4p_out[1] and _h4p_in[0] is True
      and _h4p_lo[0] is False and "Couldn't tell which address" in _h4p_lo[1],
      repr((_h4p_out[:2], _h4p_in[:2], _h4p_lo[:2])))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# M1: a reverse proxy's port
# ════════════════════════════════════════════════════════════════════════════════════════════════
_PROXY_CFG = (_cfg136, "load_config", lambda *x, **y: {"port": 5000, "trust_proxy": True})
# The viewer's connection to the proxy is open while this request is answered: to the host's 443.
_via = [(_fw136, "_fwb_panel_viewer", lambda: (_ip136.ip_address("203.0.113.20"), True)),   # NOSONAR(S1313)
        (_p135._ue135, "inbound_from", lambda peer: [(_ip136.ip_address(_p135._HOST_ADDR135), 443)])]
_m1_443 = _deny136([_SSH22, "443/tcp  ALLOW IN  Anywhere"], server=_LOCAL135, extra=_via)
_m1_5000 = _deny136([_SSH22, "5000/tcp  ALLOW IN  Anywhere"], server=_LOCAL135, extra=_via)
check("M1: a viewer who came through a reverse proxy on this machine keeps the panel with 443 open and 5000 shut "
      "(set), and loses it with only 5000 open (refused, naming 443)",
      _m1_443[0] is True and _m1_5000[0] is False and "port 443/tcp" in _m1_5000[1], repr((_m1_443, _m1_5000)))


def _blk136(spec, proto="tcp", server=_LOCAL135, extra=(), host=None):
    host = host or _Host135(rules=[_SSH22])
    res = _on135(host, _also136(list(extra), _fw136.remote_ufw_block_port), server, spec, proto, "both", "deny", "")
    return res[0], str(res[1]), host.changes()


_m1_b443 = _blk136("443", extra=[_PROXY_CFG])
_m1_b80 = _blk136("70:90", extra=[_PROXY_CFG])
_m1_bno = _blk136("443")
_m1_bserve = _blk136("443", extra=[(_cfg136, "load_config", lambda *x, **y: {"port": 5000,
                                                                           "tailscale_setup_done": True})])
check("M1: behind a reverse proxy (trust_proxy) blocking 443, or a range over 80, on the panel host is refused as the "
      "proxy's port; published over Tailscale Serve 443 is too; with neither it is blocked (positive control)",
      _m1_b443[0] is False and _m1_b443[2] == [] and "proxy on this host" in _m1_b443[1]
      and _m1_b80[0] is False and "Port 80" in _m1_b80[1] and _m1_bserve[0] is False
      and _m1_bno[0] is True, repr((_m1_b443[:2], _m1_b80[:2], _m1_bserve[:2], _m1_bno[:2])))
with _p9.test_request_context("/", base_url="https://panel.example:8443/"):
    _rp_8443 = _fw136._fwb_request_port()
with _p9.test_request_context("/", base_url="https://panel.example/"):
    _rp_443 = _fw136._fwb_request_port()
check("M1: the port a viewer reached is the Host's port, else the scheme's", (_rp_8443, _rp_443) == (8443, 443),
      repr((_rp_8443, _rp_443)))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# M2 / L4: what a block really did
# ════════════════════════════════════════════════════════════════════════════════════════════════


class _OutHost136(_Host135):
    """ufw-block-port answers per protocol from `outs` {proto: (out, rc)}; an undo of `undo_fail` fails."""

    def __init__(self, outs, undo_fail=(), **k):
        super().__init__(**k)
        self.outs, self.undo_fail = outs, set(undo_fail)

    def run(self, server, verb, args=(), **k):
        a = list(args)
        if verb == "ufw-block-port":
            self.sent.append((verb, a))
            out, rc = self.outs[a[2]]
            return (out, "", rc)
        if verb == "ufw-delete-block-port":
            self.sent.append((verb, a))
            return ("ERROR: x", "", 1) if (a[2], a[3]) in self.undo_fail else ("Rule deleted", "", 0)
        return super().run(server, verb, args, **k)


_SKIP4_ADD6 = "Skipping inserting existing rule\nRule inserted (v6)\n"
_m2 = _blk136("27015", "both", server=_REMOTE135, host=_OutHost136(
    {"tcp": (_SKIP4_ADD6, 0), "udp": ("ERROR: udp", 1)}, rules=[_SSH22, "27015/tcp  DENY IN  Anywhere"]))
check("M2: a both-family block whose v4 half was already there and v6 half went in, then the UDP rule failed, takes "
      "out ONLY the v6 half it added (never the v4 one that was there before), and says so",
      _m2[0] is False and _m2[2][-1] == ("ufw-delete-block-port", ["deny", "27015", "tcp", "v6"])
      and sum(1 for c in _m2[2] if c[0] == "ufw-delete-block-port") == 1
      and "ERROR: udp" in _m2[1] and "taken out again" in _m2[1] and "nothing is blocked" not in _m2[1], repr(_m2))
_m2_left = _blk136("27015", "both", server=_REMOTE135, host=_OutHost136(
    {"tcp": ("Rule inserted\nRule inserted (v6)\n", 0), "udp": ("ERROR: udp", 1)}, undo_fail=[("tcp", "v6")]))
check("M2: ...and an undo that fails is reported as a partial block, naming what is left",
      _m2_left[0] is False and "partly in place" in _m2_left[1] and "27015/tcp (IPv6)" in _m2_left[1]
      and "27015/tcp (IPv4)" not in _m2_left[1], repr(_m2_left))
_SKIP_BOTH = "Skipping inserting existing rule\nSkipping inserting existing rule (v6)\n"
_l4_already = _blk136("27015", "tcp", server=_REMOTE135, host=_OutHost136(
    {"tcp": (_SKIP_BOTH, 0)}, rules=[_SSH22, "27015/tcp  DENY IN  Anywhere", "27015/tcp (v6)  DENY IN  Anywhere (v6)"]))
_l4_allowed = _blk136("27015", "both", server=_REMOTE135, host=_OutHost136(
    {"tcp": (_SKIP_BOTH, 0), "udp": ("Rule inserted\nRule inserted (v6)\n", 0)},
    rules=[_SSH22, "27015/tcp  ALLOW IN  Anywhere", "27015/tcp (v6)  ALLOW IN  Anywhere (v6)"]))
_l4_off = _blk136("27015", "tcp", server=_REMOTE135, host=_OutHost136({"tcp": ("Rules updated\nRules updated (v6)\n", 0)}))
_l4_on = _blk136("27015", "tcp", server=_REMOTE135, host=_OutHost136({"tcp": ("Rule inserted\nRule inserted (v6)\n", 0)}))
check("L4: a block ufw skipped because one is listed reads 'already blocked' (no claim of a new block); one it "
      "skipped because an ALLOW has the same addresses is NOT blocked (failed, the UDP half undone); while UFW is off "
      "the answer says it is only stored",
      _l4_already[0] is True and "already blocked" in _l4_already[1] and "Blocked 27015" not in _l4_already[1]
      and _l4_allowed[0] is False and "Not blocked" in _l4_allowed[1]
      and ("ufw-delete-block-port", ["deny", "27015", "udp", "v4"]) in _l4_allowed[2]
      and ("ufw-delete-block-port", ["deny", "27015", "udp", "v6"]) in _l4_allowed[2]
      and _l4_off[0] is True and "UFW is off" in _l4_off[1]
      and _l4_on[0] is True and "UFW is off" not in _l4_on[1] and "Blocked 27015/tcp" in _l4_on[1],
      repr((_l4_already[:2], _l4_allowed, _l4_off[:2], _l4_on[:2])))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# H1 / M3: Block IP on the canonical target, and every address the panel may come from
# ════════════════════════════════════════════════════════════════════════════════════════════════
_ipb_calls, _ipb = [], {}
_OWN136 = {"v": {_ip136.ip_address("203.0.113.9")}}   # NOSONAR(S1313)


def _ipb_cmd(server, cmd, **k):
    if "SSH_CONNECTION" in cmd:
        return ("conn " + _OUT136 + " 51515 192.0.2.10 22\n1: lo    inet 127.0.0.1/8 scope host lo\n"   # NOSONAR(S1313)
                "2: eth0    inet 192.0.2.10/24 scope global eth0\n", "", 0)   # NOSONAR(S1313)
    return ("", "", 1)


try:
    _p9_arm(who="part136")
    _WL136 = [_ip136.ip_network("198.51.100.5/32")]   # NOSONAR(S1313)
    _p9_patch(_rs136, "_whitelist_networks", lambda: _WL136)
    _p9_patch(_mon136, "_whitelist_networks", lambda: _WL136)
    _p9_patch(_rs136, "tailnet_exempt_ips", lambda remote, ips: {i for i in ips if i == "100.100.1.1"})
    _p9_patch(_rs136, "remote_ufw_deny_ip", lambda r, ip: (_ipb_calls.append(ip), (True, "ok"))[1])
    _p9_patch(_rs136, "_follow_in_panel_gate", lambda remote, ok: None)
    _p9_patch(_rs136, "_fwb_panel_host_addrs", lambda: _OWN136["v"])
    _p9_patch(_core136, "run_command", _ipb_cmd)
    _p9_patch(_core136, "run_privileged", _Host135(rules=[_SSH22]).run)   # the rules ufweval reads
    _A136 = _p9_client(P9_ADMIN)
    _u136 = "/api/remote/%d/security/block" % P9_HOST
    for _k136, _v136 in (("wl32", "198.51.100.5/32"), ("wlmapped", "::ffff:198.51.100.5"),   # NOSONAR(S1313)
                         ("wlmapped128", "::ffff:198.51.100.5/128"), ("ts32", "100.100.1.1/32"),  # NOSONAR(S1313)
                         ("tsmapped", "::ffff:100.100.1.1"), ("ts6", "fd7a:115c:a1e0::5/128"),  # NOSONAR(S1313)
                         ("source", _OUT136), ("own", "203.0.113.0/28"), ("ok", "198.51.100.6/32"),  # NOSONAR(S1313)
                         ("okmapped", "::ffff:198.51.100.7")):  # NOSONAR(S1313)
        _ipb[_k136] = _A136.post(_u136, json={"ip": _v136}).get_json(silent=True) or {}
    _OWN136["v"] = None
    _ipb["ownunread"] = _A136.post(_u136, json={"ip": "192.0.2.128/25"}).get_json(silent=True) or {}  # NOSONAR(S1313)
    _a_ipb136 = _p9_audit("ufw_block")
finally:
    _p9_restore_all()
_ipbm = {k: (v.get("success"), str(v.get("message", ""))[:150]) for k, v in _ipb.items()}
check("H1: a whitelisted address written /32, IPv4-mapped or as a mapped /128, and a tailnet one as /32, mapped "
      "or a Tailscale IPv6 /128, are refused as themselves; never reaching the deny",
      all(_ipb[k].get("success") is False for k in ("wl32", "wlmapped", "wlmapped128", "ts32", "tsmapped", "ts6"))
      and all("whitelist" in _ipbm[k][1] for k in ("wl32", "wlmapped", "wlmapped128"))
      and all("Tailscale" in _ipbm[k][1] for k in ("ts32", "tsmapped", "ts6")), repr(_ipbm))
check("H1/M3: one address that IS the panel's SSH source is refused (it was checked for ranges only), a range "
      "over one of the panel host's own global addresses is refused, and so is any block when those cannot be read",
      _ipb["source"].get("success") is False and "the panel connects to this host from" in _ipbm["source"][1]
      and _ipb["own"].get("success") is False and "203.0.113.9" in _ipbm["own"][1]
      and _ipb["ownunread"].get("success") is False and "own addresses" in _ipbm["ownunread"][1], repr(_ipbm))
check("H1: clear addresses are blocked, and the deny is given the canonical form (198.51.100.6, and the mapped "
      "address as the IPv4 one a connection from it is)",
      _ipb["ok"].get("success") is True and _ipb["okmapped"].get("success") is True
      and _ipb_calls == ["198.51.100.6", "198.51.100.7"]   # NOSONAR(S1313)
      and _hosts136.fwa_block_target("::ffff:192.0.2.0/120") == "192.0.2.0/24"   # NOSONAR(S1313)
      and _hosts136.fwa_block_target("::ffff:192.0.2.1", unmap=False) == "::ffff:192.0.2.1"   # NOSONAR(S1313)
      and _a_ipb136.target == "192.0.2.128/25", repr((_ipb_calls, _a_ipb136)))   # NOSONAR(S1313)
_RS_SRC136 = open(_rs136.__file__, encoding="utf-8").read()
_bou136 = _RS_SRC136[_RS_SRC136.index("def _fwa_block_or_unblock("):_RS_SRC136.index("def _register_blocking(")]
check("M3: the Block IP refusal and the deny are made under one hold of the host's ufw_lock",
      "with _sm_core.ufw_lock(remote):" in _bou136
      and _bou136.index("ufw_lock") < _bou136.index("_fwa_block_refusal(remote, shown)"), _bou136[-400:])
_FW_SRC136 = open(_fw136.__file__, encoding="utf-8").read()
_bp136 = _FW_SRC136[_FW_SRC136.index("def remote_ufw_block_port("):_FW_SRC136.index("def _fwb_rule_lines(")]
check("M3: the port-block refusal is decided under the ufw_lock it is written under",
      _bp136.index("with _core.ufw_lock(server):") < _bp136.index("_fwa_port_block_refusal("), _bp136[-500:])

# ════════════════════════════════════════════════════════════════════════════════════════════════
# L1, L2, L3, L5, L6, L7
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TS2222 = _NS136(is_local=False, auth_method="key", host="100.100.5.5", port=2222, id=None, name="t2222")  # NOSONAR
_TS22 = _NS136(is_local=False, auth_method="key", host="100.100.5.6", port=22, id=None, name="t22")  # NOSONAR
_l1 = _deny136(["2222/tcp  ALLOW IN  192.0.2.0/24"], src="100.100.9.9", server=_TS2222, ts=(True, True),  # NOSONAR
               sshd=("2222",))
_l1_ok = _deny136([], src="100.100.9.9", server=_TS22, ts=(True, True))   # NOSONAR(S1313)
check("L1: Tailscale SSH is the panel's way in only where it dials port 22: on 2222 with a LAN-only rule the deny "
      "is refused; on 22 with Tailscale SSH on it is set",
      _l1[0] is False and _l1[2] == [] and _l1_ok[0] is True, repr((_l1, _l1_ok)))
_l2 = {}
for _k136, _stored in (("no rules", ""), ("a stored deny of 22", "### tuple ### deny tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n")):  # NOSONAR
    _h136 = _Host136(enabled=False, incoming="allow", stored_rules=_stored)
    _l2[_k136] = (_on135(_h136, _src136(_OUT136, _fw136.remote_ufw_set_enabled), _REMOTE135, True), _h136.changes())
check("L2: with the stored incoming policy allow, turning UFW on with no rules at all is no lock-out (sent); a "
      "stored deny of the SSH port still refuses it",
      _l2["no rules"][0][0] is True and _l2["no rules"][1] == [("ufw-enable", [])]
      and _l2["a stored deny of 22"][0][0] is False and _l2["a stored deny of 22"][1] == [],
      repr({k: (v[0][0], str(v[0][1])[:120], v[1]) for k, v in _l2.items()}))
_l3 = {}
for _k136, _rows in (("shadowed", ["27015/tcp  DENY IN  Anywhere", "27015  ALLOW IN  Anywhere"]),
                     ("range", ["27000:27100/udp  DENY IN  Anywhere", "27015  ALLOW IN  Anywhere"]),
                     ("v6 only", ["27015/tcp (v6)  DENY IN  Anywhere (v6)", "27015 (v6)  ALLOW IN  Anywhere (v6)"]),
                     ("open", ["27015  ALLOW IN  Anywhere", "27015/tcp  DENY IN  Anywhere"])):
    _l3[_k136] = _on135(_Host135(rules=_rows), _fw136.fwb_open_shadow_note, _REMOTE135, 27015, "both", "both")
check("L3: after Open a port, a block above the new allow is named (the TCP rule, a UDP range, a v6-only one); "
      "an allow ABOVE the block says nothing",
      "27015/tcp (IPv4)" in str(_l3["shadowed"]) and "27015/udp" not in str(_l3["shadowed"])
      and "27015/udp (IPv4)" in str(_l3["range"]) and "27015/tcp (IPv6)" in str(_l3["v6 only"])
      and _l3["open"] is None, repr(_l3))
_l37 = {}
try:
    _p9_arm(who="part136")
    _p9_patch(_rv136, "remote_ufw_open_port", lambda r, *a, **k: (True, _i18n136.Sentence("Port {port} opened on remote",
                                                                                          port="27015")))
    _p9_patch(_fw136, "fwb_open_shadow_note", lambda *a: _i18n136.Sentence("A block above it still drops {rules}: UFW "
                                                                           "takes the first rule that matches, so "
                                                                           "delete that block for the port to be "
                                                                           "open.", rules="27015/tcp (IPv6)"))
    _l37["resp"] = _p9_client(P9_ADMIN).post("/api/remote/%d/firewall/open" % P9_HOST,
                                             json={"port": 27015, "protocol": "tcp", "family": "v6"}).get_json()
    _l37["audit"] = _p9_audit("remote_port_open")
finally:
    _p9_restore_all()
check("L3/L7: the open route adds the shadow note to its answer, and its audit row records the family (v6)",
      "A block above it still drops 27015/tcp (IPv6)" in str(_l37["resp"].get("message"))
      and _l37["audit"].detail == "v6", repr(_l37))
_dup = _stored_text135(u4="==> /etc/ufw/user6.rules <==\n")
check("L5: a stored-files listing in which a file holds another's mark is unread (None), not mis-split; the plain "
      "listing still splits (ufw's own reader is anchored at column 0, so an indented setting is unread there too)",
      _fw136._fwa_split_stored(_dup) is None and _fw136._fwa_split_stored(_stored_text135()) is not None
      and _fw136._FWA_DEFAULT_LINE_RE.pattern.startswith("^"))
_tsp = {}


def _ts_cmd136(txt, rc):
    """A run_command stand-in answering the tailscaled defaults read with (txt, rc)."""
    return lambda s, cmd, **k: (txt, "", rc) if "tailscaled" in cmd else ("", "", 1)


for _k136, _txt, _rc in (("set", 'FLAGS=""\nPORT="41700"\n', 0), ("zero", "PORT=0\n", 0), ("missing", "", 1),
                         ("last wins", "PORT=41700\nPORT=41800 # moved\n", 0)):
    try:
        _p9_arm(who="part136")
        _p9_patch(_core136, "run_command", _ts_cmd136(_txt, _rc))
        _tsp[_k136] = _REAL_TSPORT136(_REMOTE135)
    finally:
        _p9_restore_all()
_l6 = _blk136("41690:41710", "udp", server=_REMOTE135,
              extra=[(_fw136, "_fwb_tailscaled_port", lambda s: 41700)])
_l6_dflt = _blk136("41641", "udp", server=_REMOTE135, extra=[(_fw136, "_fwb_tailscaled_port", lambda s: 41700)])
check("L6: tailscaled's port is read from /etc/default/tailscaled (the last PORT= wins); 0 or no file keeps 41641; "
      "a UDP block over the configured port is refused, over 41641 then it is not",
      _tsp == {"set": 41700, "zero": 41641, "missing": 41641, "last wins": 41800}
      and _l6[0] is False and "41700/udp" in _l6[1] and _l6_dflt[0] is True, repr((_tsp, _l6[:2], _l6_dflt[:2])))

check("part136: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP136_START, repr(_P9_TRIPPED[_TRIP136_START:][:3]))
