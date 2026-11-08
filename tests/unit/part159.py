"""Part 159 of the unit suite: review 1108's firewall and lock-out findings (builder A).

* MEDIUM (F1): a remote dialled by NAME is held to an IPv6 SSH way in only when the name resolves to
  IPv6 here: a provider's default global IPv6 on eth0 under an A-only name is never dialled.
* MEDIUM + LOW (P1 carried lead 1): an SSH port move never writes a public allow where public SSH is
  off (OWNER RULE: no port opened to the internet unasked). The new port gets the scope of the way the
  panel's own session comes in (nothing where that already lets it in, the same source-only rule, or a
  refusal naming the rule to add), and a rule that would refuse the panel's session on the new port (an
  interface- or source-scoped DENY the public reading never saw) refuses the move.
* MEDIUM (P1 carried lead 2): the panel host's hourly auto-block never denies the address of a live,
  signed-in superadmin session (an IPv6 one by its /64) or the host's own addresses; unreadable, it
  blocks nothing new that cycle.
* LOW (P1): on a remote the panel dials over the tailnet, a session read that fails keeps its tailscale0
  rule protected (it fell back to a warn and could be deleted).
* LOW (P1): on the panel host, a viewer a believed proxy here names as a loopback client (an SSH tunnel to
  nginx, a browser on the host through it) is the local viewer: its blocks are decided by sshd's sessions,
  not refused with trust_proxy advice that is already applied.
* lead (P1): with Tailscale Serve up, a viewer on the panel host's loopback (an SSH tunnel) still has its
  SSH session held by an IP block (every request was taken to come through Serve).
* lead (P1): the panel's change-port, its new port already opened, answers a config.json that cannot be
  written by putting the helper's port record back and saying what was left (it was a bare 500).
* lead (P1): "Disable public SSH" and Close port 22 count tailscaled's own chain (its default netfilter
  mode) as a Tailscale way back, as the policy and enable checks do (they refused "no way back").
* LOW (P5): a panel host booted with IPv6 off (no /proc/net/tcp6) still reads sshd's sessions, so a
  loopback viewer's IP block is decided rather than refused as unread.

HOW IT RUNS. The firewall module over part135's stand-in hosts, on part12's patcher with its
transport tripwire armed. Nothing reaches a host, sudo, ufw, a resolver or data/.
"""
import ipaddress as _ip159
import os
import struct as _st159
import tempfile as _tf159
from datetime import timedelta as _td159
from types import SimpleNamespace as _NS159

from unit.part01 import check
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_cfg, _p9_client, _p9_core, _p9_json, _p9_patch,
                         _p9_patch_sm, _p9_restore_all, _p9_so)
from unit.part108 import _ANY108
from unit.part116 import _boot116, _saved116
from unit.part125 import _Box125
from unit import part135 as _p135
from unit.part136 import _OUT136, _deny136
from unit.part154 import _TS0_154, _lo154, _proc154, _tsrow154
from panel.core.clock import utcnow as _now159
from panel.db.models import User as _User159, UserSession as _US159, db as _db159
from panel.ops import system_ops as _so159
from panel.ops.ssh_manager import firewall as _fw159, hosts as _hosts159, ufweval as _ue159
from panel.routes import close_port22 as _cp22_159, host_local as _hl159, remote_security as _rs159
from panel.security import auth as _auth159
from panel.services import monitoring as _mon159

_TRIP159_START = len(_P9_TRIPPED)

# ════════════════════════════════════════════════════════════════════════════════════════════════
# MEDIUM (F1): a named remote's families are the ones its name resolves to
# ════════════════════════════════════════════════════════════════════════════════════════════════
_NAMED159 = _NS159(is_local=False, auth_method="key", host="h159.example.net", port=22, id=None, name="n159")
_A159 = "192.0.2.10"               # NOSONAR(S1313) - the name's A record (part135's remote address)
_AAAA159 = "2001:db8::10"          # its AAAA record, where it has one
_ULA159 = "fd00:159::10"           # a LAN host's ULA, which `ip` reports as scope global
_ADMIN_SSH159 = "22/tcp  ALLOW IN  " + _OUT136      # the hardened single-source IPv4 SSH rule
_V6_SSH159 = "22/tcp (v6)  ALLOW IN  Anywhere (v6)"


def _named159(rows, resolves, v6=("eth0", _AAAA159)):
    """_deny136 on the named remote: its name resolves to `resolves`, its session read finds `v6` on it too."""
    real = _p135._conn135

    def conn(src, server, *a, **k):
        res = real(src, server, *a, **k)
        if res is not None:
            res["addrs"] = res["addrs"] + [(v6[0], _ip159.ip_address(v6[1]), "global")]
        return res
    return _deny136(rows, server=_NAMED159,
                    extra=[(_p135, "_conn135", conn), (_hosts159, "_r28b_resolve", lambda name: list(resolves))])


_SET159 = [("ufw-default", ["deny", "incoming"])]
_f1_ok = {
    "global IPv6 on eth0, A-only name": _named159([_ADMIN_SSH159], [_A159]),
    "a ULA on eth0, A-only name": _named159([_ADMIN_SSH159], [_A159], v6=("eth0", _ULA159)),
    "an IPv4-mapped spelling of the A record only": _named159([_ADMIN_SSH159], ["::ffff:" + _A159]),
    "AAAA and A, both families let in": _named159([_ADMIN_SSH159, _V6_SSH159], [_A159, _AAAA159]),
}
check("1108 F1: on a remote dialled by a name with only an A record, a global IPv6 (or ULA) address on its "
      "interface no longer holds it to an IPv6 SSH way in: a default incoming deny beside the single-source IPv4 "
      "SSH rule is set (%s)" % ", ".join(_f1_ok),
      all(r[0] is True and r[2] == _SET159 for r in _f1_ok.values()),
      repr({k: (r[0], r[1][:160]) for k, r in _f1_ok.items()}))
_f1_cut = {
    "AAAA and A": _named159([_ADMIN_SSH159], [_A159, _AAAA159]),
    "AAAA only": _named159([_ADMIN_SSH159], [_AAAA159]),
    "IPv4-mapped AAAA beside a real AAAA": _named159([_ADMIN_SSH159], ["::ffff:" + _A159, _AAAA159]),
    "the name does not resolve here": _named159([_ADMIN_SSH159], []),
}
check("1108 F1: ...and still refused, nothing sent, where the name resolves to IPv6 (beside IPv4, alone, or "
      "beside an IPv4-mapped spelling) or does not resolve here at all, while the IPv6 list has no way in (%s)"
      % ", ".join(_f1_cut),
      all(r[0] is False and r[2] == [] and "No rule lets SSH in" in r[1] for r in _f1_cut.values()),
      repr({k: (r[0], r[1][:160]) for k, r in _f1_cut.items()}))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LOW (P5): /proc/net/tcp6 missing (IPv6 disabled in the kernel) is not "sessions unread"
# ════════════════════════════════════════════════════════════════════════════════════════════════
_HERE159 = _p135._HOST_ADDR135
_TUNNEL159 = "198.51.100.9"        # NOSONAR(S1313) - the admin's SSH session's source
_TUNNEL6_159 = "2001:db8:5::9"     # an IPv6 session, in the tcp6 table where there is one
_RANGE159 = "198.51.100.0/24"      # NOSONAR(S1313) - holds _TUNNEL159
_ELSE_RANGE159 = "203.0.113.0/24"  # NOSONAR(S1313) - holds no session


def _proc6_159(rows):
    """A /proc/net/tcp6 body: rows [(local addr, local port, remote addr, remote port, state)]."""
    def end(a, port):
        return "".join("%08X" % w for w in _st159.unpack("=4I", _ip159.ip_address(a).packed)) + ":%04X" % port
    return "  sl  local_address rem_address   st\n" + "".join(
        "   %d: %s %s %s 00000000:00000000 00:00000000 00000000  1000 0 1 1\n" % (n, end(la, lp), end(ra, rp), st)
        for n, (la, lp, ra, rp, st) in enumerate(rows))


def _tables159(fn, v4=True, v6=None):
    """fn() with _PROC_TCP pointed at a tcp and a tcp6 table.

    The tcp table holds one SSH session (`v4` False: absent); the tcp6 one holds rows `v6` (None: absent,
    as on a kernel booted with ipv6.disable=1).
    """
    with _tf159.TemporaryDirectory() as d:
        t4, t6 = os.path.join(d, "tcp"), os.path.join(d, "tcp6")
        if v4:
            with open(t4, "w") as fh:
                fh.write(_proc154([(_HERE159, 22, _TUNNEL159, 50000, "01")]))
        if v6 is not None:
            with open(t6, "w") as fh:
                fh.write(_proc6_159(v6))
        try:
            _p9_patch(_ue159, "_PROC_TCP", {4: t4, 6: t6})
            return fn()
        finally:
            _p9_restore_all()


def _inbound159(**kw):
    return _tables159(lambda: _ue159.inbound_to(frozenset({22})), **kw)


_S4_159 = (_ip159.ip_address(_TUNNEL159), _ip159.ip_address(_HERE159), 22)
_S6_159 = (_ip159.ip_address(_TUNNEL6_159), _ip159.ip_address("2001:db8::1"), 22)
_in = {
    "no tcp6 table": _inbound159(),
    "both tables": _inbound159(v6=[("2001:db8::1", 22, _TUNNEL6_159, 50001, "01")]),
    "no table at all": _inbound159(v4=False),
}
check("1108 P5: ufweval.inbound_to reads the tcp table alone where the kernel has no tcp6 one (IPv6 disabled), "
      "reads both where both exist, and is None (unread) only when no table can be opened",
      _in == {"no tcp6 table": [_S4_159], "both tables": [_S4_159, _S6_159], "no table at all": None}, repr(_in))


def _lo159(target):
    """fwc_block_ip_refusal of `target` on the panel host, from a loopback viewer, with no tcp6 table -> text."""
    host = _p135._Host135(rules=[_p135._SSH22, "5000/tcp  ALLOW IN  Anywhere"], incoming="allow")

    def run():
        with _p9.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}):  # NOSONAR(S1313)
            why = _fw159.fwc_block_ip_refusal(_p135._LOCAL135, target)
        return None if why is None else str(why)

    # _tables159's restore, once run() has answered, also ends _on135's patches: both scopes end there.
    return _p135._on135(host, lambda: _tables159(run))


_lo_else, _lo_hit = _lo159(_ELSE_RANGE159), _lo159(_RANGE159)
check("1108 P5: on a panel host with no /proc/net/tcp6, a loopback viewer may block a range none of sshd's "
      "sessions comes from, and a block of the range holding one is refused naming that session (not refused "
      "as \"can't read sshd's sessions\")",
      _lo_else is None and _lo_hit is not None and _TUNNEL159 in _lo_hit, repr((_lo_else, _lo_hit)))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# MEDIUM + LOW (P1): an SSH port move where public SSH is off, and a DENY ahead of the new port
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TSH159 = "100.64.0.159"           # NOSONAR(S1313) - the remote's tailnet address (the panel dials it)
_TSP159 = "100.100.9.159"          # NOSONAR(S1313) - the panel host's tailnet address
_PUBH159 = "203.0.113.159"         # NOSONAR(S1313) - the remote's public address
_ADMIN159 = "198.51.100.77"        # NOSONAR(S1313) - the panel's public source
_ADMIN_NET159 = "198.51.100.0/24"  # NOSONAR(S1313)
_TS0_159 = "Anywhere on tailscale0  ALLOW IN  Anywhere"
_LIMIT22_159 = "22/tcp  LIMIT IN  Anywhere"
_ALLOWS159 = ("ufw-allow-proto-port", "ufw-allow-port", "ufw-allow-from-port", "ufw-allow-port-family")


def _from_row159(src, port):
    """The row `ufw status` lists for `allow from <src> to any port <port> proto tcp`.

    A family's every address is listed as ufw lists it (Anywhere, or the `(v6)` row), any other source as given.
    """
    return {"0.0.0.0/0": "%s/tcp  ALLOW IN  Anywhere" % port,   # NOSONAR(S1313) - ufw's IPv4 "any" network
            "::/0": "%s/tcp (v6)  ALLOW IN  Anywhere (v6)" % port}.get(src, "%s/tcp  ALLOW IN  %s" % (port, src))


class _Box159(_Box125):
    """part125's stand-in host that succeeds, with its own ufw rule rows; what each allow verb was sent."""

    def __init__(self, rules, **kw):
        super().__init__(**kw)
        self.rules, self.allows, self.from_rules = list(rules), [], []

    def priv(self, server, verb, args=(), **kw):
        if verb in _ALLOWS159 or verb.startswith("ufw-delete-allow"):
            self.allows.append((verb, list(args)))
        if verb == "ufw-allow-from-port":
            self.from_rules.append(_from_row159(args[0], args[1]))
        elif verb == "ufw-delete-allow-from-port":
            self.from_rules = [r for r in self.from_rules if r != _from_row159(args[0], args[1])]
        return super().priv(server, verb, args, **kw)

    def _answer(self, verb):
        if verb == "ufw-status":
            return ("Status: active\n\nTo  Action  From\n--  ------  ----\n"
                    + "".join("[%2d] %s\n" % (n + 1, r) for n, r in enumerate(
                        self.rules + self.from_rules + (["2022/tcp  ALLOW IN  Anywhere"] if self.added else [])))), "", 0
        return super()._answer(verb)


def _sess159(src, dst, iface):
    return {"client": _ip159.ip_address(src), "server": _ip159.ip_address(dst), "port": 22, "iface": iface,
            "addrs": _p135._addrs135(("eth0", _PUBH159), ("tailscale0", _TSH159))}


_TS_SESS159 = _sess159(_TSP159, _TSH159, "tailscale0")
_PUB_SESS159 = _sess159(_ADMIN159, _PUBH159, "eth0")


_PUB_DEFAULT159 = object()   # "the public session", told apart from None (unread)


def _move159(rules, session=_PUB_DEFAULT159, local=False, netfilter_on=False, up=True):
    """A 22 -> 2022 move on a stand-in with `rules` -> (ok, message, the allow verbs sent).

    `session`: the panel's session as the remote reads it (None: unread; by default the public one).
    `local`: the panel's own host.
    """
    if session is _PUB_DEFAULT159:
        session = _PUB_SESS159
    box = _Box159(rules, up=up)
    row = (_NS159(id=-159, name="Panel", host="127.0.0.1", port=22, auth_method="local", is_local=True)  # NOSONAR
           if local else _NS159(id=-159, name="p159", host=_TSH159, port=22, auth_method="key", is_local=False))
    try:
        _p9_arm(who="part159")
        _p9_patch(_p9_core, "run_privileged", box.priv)
        _p9_patch(_p9_core, "run_command", lambda *a, **k: ("", "", 1))
        _p9_patch(_p9_core, "write_root_file", box.write)
        _p9_patch(_hosts159, "_sshd_socket_activated", lambda s: False)
        _p9_patch(_hosts159, "_restart_ssh_listener", box.restart)
        _p9_patch(_hosts159, "_point_f2b_sshd_at", lambda server, ports: ("updated", ""))
        _p9_patch(_hosts159, "_fwb_ssh_conn", lambda s: session)
        _p9_patch(_hosts159, "_tailscale_conn_state", lambda s: (True, False))
        _p9_patch(_ue159, "ts_netfilter_on", lambda s: netfilter_on)
        _p9_patch(_ue159, "app_profiles", lambda s: None)
        ok, msg = _hosts159.change_ssh_port(row, 2022)
    except Exception as e:     # a raise is an answer here, recorded as the failure
        ok, msg = "raised", repr(e)
    finally:
        _p9_restore_all()
    return ok, str(msg), box.allows


_mv_off = {
    "a tailnet session, the tailscale0 rule for every port": _move159([_TS0_159], _TS_SESS159),
    "a tailnet session, tailscaled's own chain (no rule)": _move159([], _TS_SESS159, netfilter_on=True),
    "the panel's host, public SSH off": _move159([_TS0_159], None, local=True),
}
check("1108 P1 MEDIUM: an SSH port move on a host whose public SSH is off (only the tailnet lets SSH in: a "
      "tailscale0 rule, tailscaled's own chain, or the panel's own host) succeeds without adding ANY firewall "
      "rule, and says that no rule (no public rule) was added (%s)" % ", ".join(_mv_off),
      all(r[0] is True and r[2] == [] and "was added" in r[1] for r in _mv_off.values()),
      repr({k: (r[0], r[1][:200], r[2]) for k, r in _mv_off.items()}))
_mv_src = _move159(["22/tcp  ALLOW IN  " + _ADMIN_NET159, _TS0_159.replace("tailscale0", "tailscale1")])
check("1108 P1 MEDIUM: ...and where the panel's session comes in by a source-only rule (its home range), the new "
      "port gets that same source-only rule, nothing public, and the message names the source",
      _mv_src[0] is True and _mv_src[2] == [("ufw-allow-from-port", [_ADMIN_NET159, "2022", "tcp", "SSH panel"])]
      and _ADMIN_NET159 in _mv_src[1], repr(_mv_src))
_mv_ref = {
    "an SSH-only tailscale0 rule": _move159(["22/tcp on tailscale0  ALLOW IN  Anywhere"], _TS_SESS159),
    "an eth0 rule from the home range": _move159(["22/tcp on eth0  ALLOW IN  " + _ADMIN_NET159]),
    "the session unread": _move159([_TS0_159], None),
}
check("1108 P1 MEDIUM: ...and refused, no rule sent, where that rule cannot be copied by the panel (an interface "
      "rule naming the port) or the panel's session could not be read (%s)" % ", ".join(_mv_ref),
      all(r[0] is False and r[2] == [] and "Nothing was changed" in r[1] for r in _mv_ref.values())
      and "22/tcp on tailscale0" in _mv_ref["an SSH-only tailscale0 rule"][1], repr(_mv_ref))
_mv_pub = {
    "public LIMIT 22, a home-range session": _move159([_LIMIT22_159]),
    "public LIMIT 22 beside the tailscale0 rule": _move159([_TS0_159, _LIMIT22_159], _TS_SESS159),
    "the panel's host, public LIMIT 22": _move159([_TS0_159, _LIMIT22_159], None, local=True),
    "public LIMIT 22, the session unread": _move159([_LIMIT22_159], None),
}
check("1108 P1 MEDIUM: ...while where public SSH is on (a public rule lets the served port in) the new port is "
      "opened to the public as before (the controls: %s)" % ", ".join(_mv_pub),
      all(r[0] is True and r[2] == [("ufw-allow-proto-port", ["tcp", "2022", "SSH panel"])] for r in _mv_pub.values()),
      repr({k: (r[0], r[1][:200], r[2]) for k, r in _mv_pub.items()}))
_mv_deny = {
    "an eth0 DENY on a range": _move159(["2000:2099/tcp on eth0  DENY IN  Anywhere", _LIMIT22_159]),
    "a DENY from the panel's range": _move159(["2022/tcp  DENY IN  " + _ADMIN_NET159, _LIMIT22_159]),
    "a REJECT on tailscale0": _move159(["2022/tcp on tailscale0  REJECT IN  Anywhere", _TS0_159], _TS_SESS159),
}
check("1108 P1 LOW: a DENY or REJECT the panel's own session would meet on the new port, ahead of any allow, is seen "
      "(an interface rule, one from the panel's source range): the move is refused naming it, nothing sent (%s)"
      % ", ".join(_mv_deny),
      all(r[0] is False and r[2] == [] and "is blocked by the firewall rule" in r[1] for r in _mv_deny.values()),
      repr({k: (r[0], r[1][:200], r[2]) for k, r in _mv_deny.items()}))
_mv_nodeny = {
    "a DENY on docker0": _move159(["2022/tcp on docker0  DENY IN  Anywhere", _LIMIT22_159]),
    "a DENY on lo": _move159(["2022/tcp on lo  DENY IN  Anywhere", _LIMIT22_159]),
    "a DENY from another source": _move159(["2022/tcp  DENY IN  192.0.2.0/24", _LIMIT22_159]),   # NOSONAR(S1313)
    "a DENY from 127.0.0.1": _move159(["2022/tcp  DENY IN  127.0.0.1", _LIMIT22_159]),   # NOSONAR(S1313)
    "a UDP DENY": _move159(["2022/udp  DENY IN  Anywhere", _LIMIT22_159]),
    "an outbound DENY": _move159(["2022/tcp  DENY OUT  Anywhere (out)", _LIMIT22_159]),
    "a routed DENY": _move159(["2022/tcp  DENY FWD  Anywhere", _LIMIT22_159]),
    "a v6 DENY for a v4 session": _move159(["2022/tcp (v6) on eth0  DENY IN  Anywhere (v6)", _LIMIT22_159]),
    "a DENY below the allow that lets it in": _move159([_TS0_159, "2022/tcp on tailscale0  DENY IN  Anywhere"],
                                                         _TS_SESS159),
}
check("1108 P1 LOW: ...and a DENY the panel's session would not meet does not refuse it (docker0, lo, another "
      "source, a loopback source, UDP, OUT, FWD, the other family, below the allow that lets it in)",
      all(r[0] is True for r in _mv_nodeny.values()),
      repr({k: (r[0], r[1][:200], r[2]) for k, r in _mv_nodeny.items()}))
_mv_rev = _move159(["22/tcp  ALLOW IN  " + _ADMIN_NET159], up=False)
check("1108 P1 MEDIUM: a move that fails after the source-only rule went in takes exactly that rule back out",
      _mv_rev[0] is False and _mv_rev[2] == [("ufw-allow-from-port", [_ADMIN_NET159, "2022", "tcp", "SSH panel"]),
                                            ("ufw-delete-allow-from-port", [_ADMIN_NET159, "2022", "tcp"])],
      repr(_mv_rev))

# ── review 1108 H: the move's step 1 where the adversarial pass found it wrong ─────────────────────
_ADMIN6_159 = "2001:db8:77::77"
_PUBH6_159 = "2001:db8:159::159"
_SSH6_PUB159 = "22/tcp (v6)  ALLOW IN  Anywhere (v6)"
_HARD4_159 = "22/tcp  ALLOW IN  " + _ADMIN_NET159
_V6_SESS159 = _sess159(_ADMIN6_159, _PUBH6_159, "eth0")
_mv_r38h_unknown = {
    "an application profile the panel cannot resolve": _move159(["Custom159  ALLOW IN  " + _ADMIN_NET159]),
    "an interface rule, the session's interface not found": _move159(["22/tcp on eth0  ALLOW IN  Anywhere"],
                                                                     _sess159(_ADMIN159, _PUBH159, None)),
}
check("1108 r38h step 1: where public SSH is off and no rule the panel can read lets its session in (an "
      "unresolved application profile, an interface rule whose interface was not read), the default policy, not "
      "read as allow, is not assumed to let it in on the new port: refused, nothing sent (%s)"
      % ", ".join(_mv_r38h_unknown),
      all(r[0] is False and r[2] == [] and "No firewall rule the panel can read lets its SSH connection" in r[1]
          for r in _mv_r38h_unknown.values()),
      repr({k: (r[0], r[1][:200], r[2]) for k, r in _mv_r38h_unknown.items()}))
_mv_r38h_lhdeny = {
    "a public DENY above the tailscale0 rule": _move159(["2022/tcp  DENY IN  Anywhere", _TS0_159], None, local=True),
    "a public REJECT on a range, the hardened rule": _move159(["2000:2099/tcp  REJECT IN  Anywhere", _HARD4_159],
                                                              None, local=True),
}
_mv_r38h_lhok = {
    "a UDP DENY, a docker0 DENY and a v6 one on lo": _move159(
        ["2022/udp  DENY IN  Anywhere", "2022/tcp on docker0  DENY IN  Anywhere",
         "2022/tcp (v6) on lo  DENY IN  Anywhere (v6)", _TS0_159], None, local=True),
    "an outbound DENY, a DENY below the allow": _move159(
        ["2022/tcp  DENY OUT  Anywhere (out)", _HARD4_159], None, local=True),
}
check("1108 r38h step 1: on the panel's host with public SSH off, a public DENY or REJECT first on the new port "
      "still refuses the move, naming it (%s); one a connection to it would not meet does not (%s), and the note "
      "names the hardened rule on the old port that was not copied, or else asks for a check, never claiming the "
      "new port is reached" % (", ".join(_mv_r38h_lhdeny), ", ".join(_mv_r38h_lhok)),
      all(r[0] is False and r[2] == [] and "is blocked by the firewall rule" in r[1] for r in _mv_r38h_lhdeny.values())
      and all(r[0] is True and r[2] == [] and "reached only through" not in r[1] for r in _mv_r38h_lhok.values())
      and "were not copied: " + _HARD4_159 in _mv_r38h_lhok["an outbound DENY, a DENY below the allow"][1]
      and "Check that a rule of yours" in _mv_r38h_lhok["a UDP DENY, a docker0 DENY and a v6 one on lo"][1],
      repr({k: (r[0], r[1][:300], r[2]) for k, r in {**_mv_r38h_lhdeny, **_mv_r38h_lhok}.items()}))
_V6_ADD159 = [("ufw-allow-from-port", ["::/0", "2022", "tcp", "SSH panel"])]
_V4_ADD159 = [("ufw-allow-from-port", ["0.0.0.0/0", "2022", "tcp", "SSH panel"])]   # NOSONAR(S1313)
_mv_r38h_fam = {
    "v6 public, v4 hardened, a v6 session": _move159([_HARD4_159, _SSH6_PUB159], _V6_SESS159),
    "v6 public, v4 hardened, a v4 session": _move159([_HARD4_159, _SSH6_PUB159]),
    "the panel's host, v6 public only": _move159([_HARD4_159, _SSH6_PUB159], None, local=True),
    "the panel's host, v4 public, a v6 game rule only": _move159([_LIMIT22_159, "80/tcp (v6)  ALLOW IN  Anywhere (v6)"],
                                                                 None, local=True),
    "public SSH to the host's one address": _move159([_PUBH159 + " 22/tcp  ALLOW IN  Anywhere"]),
    "v6 public, a v6 session, the move fails": _move159([_HARD4_159, _SSH6_PUB159], _V6_SESS159, up=False),
    "v6 public, v4 hardened, the session unread": _move159([_HARD4_159, _SSH6_PUB159], None),
    "v6 public, a v4 DENY first on the new port": _move159(["2022/tcp  DENY IN  Anywhere", _HARD4_159, _SSH6_PUB159],
                                                           None, local=True),
}
_mv_r38h_fam.update({
    "public SSH to a private address only": _move159(["10.159.0.5 22/tcp  ALLOW IN  Anywhere"],   # NOSONAR(S1313)
                                                     None, local=True),
    "public SSH to a tailnet address only": _move159([_TSH159 + " 22/tcp  ALLOW IN  Anywhere"], None, local=True),
})
_f159 = {k: (r[0], r[2]) for k, r in _mv_r38h_fam.items()}
check("1108 r38h step 1: SSH public over one family only (IPv6, or IPv4 beside IPv6 rules) reads as public in that "
      "family: the new port gets a rule from anywhere in that family alone, never in the other (a v4 session there "
      "gets its own source-only rule copied, nothing public; with the session unread, the public family's rule "
      "alone); a public DENY first on the new port in either family refuses; public SSH to the host's one "
      "address reads as public; "
      "a failed move takes the family's rule back out; a rule for one private or tailnet address is not public SSH, "
      "and nothing is opened to the internet for it (the OWNER RULE)",
      _f159["v6 public, v4 hardened, a v6 session"] == (True, _V6_ADD159)
      and "over IPv6 only" in _mv_r38h_fam["v6 public, v4 hardened, a v6 session"][1]
      and _f159["v6 public, v4 hardened, a v4 session"] == (
          True, [("ufw-allow-from-port", [_ADMIN_NET159, "2022", "tcp", "SSH panel"])])
      and _f159["the panel's host, v6 public only"] == (True, _V6_ADD159)
      and "Public SSH is off" not in _mv_r38h_fam["the panel's host, v6 public only"][1]
      and _f159["the panel's host, v4 public, a v6 game rule only"] == (True, _V4_ADD159)
      and _f159["public SSH to the host's one address"] == (
          True, [("ufw-allow-proto-port", ["tcp", "2022", "SSH panel"])])
      and _f159["v6 public, a v6 session, the move fails"] == (
          False, _V6_ADD159 + [("ufw-delete-allow-from-port", ["::/0", "2022", "tcp"])])
      and _f159["v6 public, v4 hardened, the session unread"] == (True, _V6_ADD159)
      and _f159["v6 public, a v4 DENY first on the new port"] == (False, [])
      and "is blocked by the firewall rule" in _mv_r38h_fam["v6 public, a v4 DENY first on the new port"][1]
      and _f159["public SSH to a private address only"] == (True, [])
      and _f159["public SSH to a tailnet address only"] == (True, [])
      and "Public SSH is off" in _mv_r38h_fam["public SSH to a tailnet address only"][1],
      repr({k: (r[0], r[1][:240], r[2]) for k, r in _mv_r38h_fam.items()}))
_OTHER_NET159 = "192.0.2.0/24"    # NOSONAR(S1313) - the operator's own home range
_mv_r38h_two = _move159([_HARD4_159, "22/tcp  ALLOW IN  " + _OTHER_NET159])
_mv_r38h_one = _move159([_HARD4_159])
check("1108 r38h step 1 (lead): on a remote hardened to two sources, the move copies only the rule the panel's session "
      "comes in by, and the note names the operator's other rule on the old port that was not copied; with one source "
      "there is nothing else to name (control)",
      _mv_r38h_two[0] is True and _mv_r38h_two[2] == [("ufw-allow-from-port", [_ADMIN_NET159, "2022", "tcp", "SSH panel"])]
      and "were not copied: 22/tcp  ALLOW IN  " + _OTHER_NET159 in _mv_r38h_two[1]
      and _mv_r38h_one[0] is True and "were not copied" not in _mv_r38h_one[1],
      repr((_mv_r38h_two, _mv_r38h_one)))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# MEDIUM (P1): the panel host's auto-block spares its signed-in superadmins and its own addresses
# ════════════════════════════════════════════════════════════════════════════════════════════════
_HOME159 = "198.51.100.159"        # NOSONAR(S1313) - a superadmin's signed-in address (home NAT)
_HOME6_159 = "2001:db8:159:1::5"   # a superadmin's IPv6 sign-in (a privacy address)
_HOME6_NEXT159 = "2001:db8:159:1::99"   # the same /64, the next privacy address
_HOME6_OTHER159 = "2001:db8:159:2::99"  # another /64: an ordinary offender
_EXPIRED159 = "198.51.100.160"     # NOSONAR(S1313) - a superadmin login that has idled out
_OFF159 = "198.51.100.161"         # NOSONAR(S1313) - a disabled superadmin's login
_PLAIN159 = "198.51.100.162"       # NOSONAR(S1313) - an account that does not manage the panel host
_OWN159 = "203.0.113.59"           # NOSONAR(S1313) - the panel host's own global address
_STRANGER159 = "192.0.2.159"       # NOSONAR(S1313) - an ordinary offender
_STALE159 = "192.0.2.160"          # NOSONAR(S1313) - an auto-block whose count fell under
_LOCAL159 = _NS159(id=-1159, name="Panel", is_local=True, auth_method="local", host="127.0.0.1", port=22)  # NOSONAR


def _users159():
    """Three accounts and their logins in part12's database -> the user ids (removed at the end)."""
    ids = []
    with _p9.app_context():
        for name, sa, active, logins in (
                ("p159_sa", True, True, [(_HOME159, 0), (_HOME6_159, 0), (_EXPIRED159, 400)]),
                ("p159_off", True, False, [(_OFF159, 0)]),
                ("p159_plain", False, True, [(_PLAIN159, 0)])):
            u = _User159(username=name, password_hash=_auth159.hash_password("x" + "Q7!long-p159-pw"),
                         display_name=name, is_superadmin=sa, is_active=active)
            _db159.session.add(u)
            _db159.session.flush()
            for n, (ip, days_idle) in enumerate(logins):
                _db159.session.add(_US159(user_id=u.id, sid="p159-%s-%d" % (name, n), ip=ip, remember=False,
                                          last_seen=_now159() - _td159(days=days_idle)))
            ids.append(u.id)
        _db159.session.commit()
    return ids


def _drop_users159(ids):
    with _p9.app_context():
        _US159.query.filter(_US159.user_id.in_(ids)).delete(synchronize_session=False)
        _User159.query.filter(_User159.id.in_(ids)).delete(synchronize_session=False)
        _db159.session.commit()


def _local_reconcile159(addrs=True, sessions_raise=False):
    """One reconcile of the panel host -> (result, denied, undenied)."""
    denied, undenied = [], []
    counts = {ip: 50 for ip in (_HOME159, _HOME6_NEXT159, _HOME6_OTHER159, _EXPIRED159, _OFF159, _PLAIN159,
                                _OWN159, _STRANGER159)}
    counts[_STALE159] = 1
    try:
        _p9_arm(who="part159")
        _p9_patch(_mon159, "_autoblock_threshold", lambda: 20)
        _p9_patch(_mon159, "tailnet_exempt_ips", lambda r, ips: set())
        _p9_patch(_mon159, "_whitelist_networks", lambda: [])
        _p9_patch(_so159, "fail2ban_attempt_counts", lambda days=7: dict(counts))
        _p9_patch(_so159, "ufw_blocked_ips", lambda: {_STALE159: _mon159._AUTOBLOCK_TAG})
        _p9_patch(_so159, "ufw_deny_ip", lambda ip, tag=None: (denied.append(ip), (True, "ok"))[1])
        _p9_patch(_so159, "ufw_undeny_ip", lambda ip: (undenied.append(ip), (True, "ok"))[1])
        _p9_patch(_ue159, "local_addrs", (lambda: _p135._addrs135(("eth0", _OWN159))) if addrs else (lambda: None))
        if sessions_raise:
            def _unreadable(self, now=None):
                raise RuntimeError("p159: the session table could not be read")
            _p9_patch(_US159, "is_expired", _unreadable)
        with _p9.app_context():
            out = _mon159._autoblock_reconcile(_LOCAL159)
    except Exception as e:     # a raise is the failure, recorded as one rather than ending the part
        out = "raised %r" % (e,)
    finally:
        _p9_restore_all()
    return out, sorted(denied), sorted(undenied)


_uids159 = _users159()
try:
    _ab_ok = _local_reconcile159()
    _ab_unread = {"sessions unread": _local_reconcile159(sessions_raise=True),
                  "own addresses unread": _local_reconcile159(addrs=False)}
finally:
    _drop_users159(_uids159)
check("1108 P1 MEDIUM: the panel host's auto-block never denies the address of a live, signed-in superadmin "
      "session (IPv4, or IPv6 by its /64) nor the host's own address, while it still denies an idled-out login's, "
      "a disabled superadmin's, an account's that does not manage the panel host, another /64's and a stranger's",
      _ab_ok[1] == sorted([_EXPIRED159, _OFF159, _PLAIN159, _HOME6_OTHER159, _STRANGER159])
      and _ab_ok[2] == [_STALE159], repr(_ab_ok))
check("1108 P1 MEDIUM: ...and with the signed-in sessions or the host's own addresses unreadable it denies nothing "
      "new that cycle, while its own stale auto-block is still released",
      all(r[1] == [] and r[2] == [_STALE159] for r in _ab_unread.values()), repr(_ab_unread))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LOW (P1): an unread tailnet session keeps the tailscale0 rule protected
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _unread_guard159(rows, row, ts_ssh=False):
    """The delete guard's answer for the tailscale0 rule among `rows` on `row`, its session unread."""
    host = _p135._Host135(rules=rows, ts=(True, ts_ssh))

    def run():
        _p9_patch(_hosts159, "_fwb_ssh_conn", lambda s: None)
        st = _fw159.remote_ufw_status(row)
        g = next((g for g in st.get("groups", []) if "tailscale0" in "%s %s" % (g["port_label"], g["scope"])), None)
        return None if g is None else ("PROTECTED" if g["protected"] else ("warn" if g["warn"] else "-"))
    return _p135._on135(host, run)


_HOME2222_159 = "2222/tcp  ALLOW IN  " + _ADMIN_NET159
_ug_cut = _unread_guard159([_TS0_154, _HOME2222_159], _tsrow154(2222))
_ug_ok = {
    "dialled at a public address": _unread_guard159([_TS0_154, _HOME2222_159],
                                                     _NS159(is_local=False, auth_method="key", host=_PUBH159,
                                                            port=2222, id=None, name="pub159")),
    "Tailscale SSH answering the port 22 it dials (never read)": _unread_guard159([_TS0_154, _HOME2222_159],
                                                                                   _tsrow154(22), ts_ssh=True),
}
check("1108 P1 LOW: on a remote the panel dials at its tailnet address, with its SSH session unread, the host's "
      "tailscale0 rule is PROTECTED (it fell back to a warn beside a home-range SSH rule and could be deleted)",
      _ug_cut == "PROTECTED", repr(_ug_cut))
check("1108 P1 LOW: ...while a remote dialled at a public address, and one Tailscale SSH answers on port 22, keep "
      "the warn (the controls)", all(v == "warn" for v in _ug_ok.values()), repr(_ug_ok))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LOW (P1): a believed proxy naming a loopback client is the local viewer
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _proxied_block159(target, xff, believed, sessions=()):
    """The panel host's IP-block refusal of `target` from loopback, with X-Forwarded-For `xff`."""
    def fn():
        _p9_patch(_auth159, "_request_came_through_proxy", lambda peer: believed)
        return _fw159.fwc_block_ip_refusal(_p135._LOCAL135, target)
    return _lo154(fn, headers={"X-Forwarded-For": xff}, sessions=sessions)


_pl_ok = _proxied_block159(_ELSE_RANGE159, "127.0.0.1", True)   # NOSONAR(S1313)
_pl_v6 = _proxied_block159(_ELSE_RANGE159, "::1", True)
_pl_hit = _proxied_block159(_RANGE159, "127.0.0.1", True, sessions=[(_TUNNEL159, 22)])   # NOSONAR(S1313)
check("1108 P1 LOW: on the panel host, a believed proxy here naming a loopback client (IPv4 or IPv6: an SSH "
      "tunnel to nginx, a browser on the host through it) may block a range none of sshd's sessions comes from, "
      "and a block of one that holds a session is refused naming it",
      _pl_ok is None and _pl_v6 is None and _pl_hit is not None and _TUNNEL159 in _pl_hit and "trust_proxy" not in
      _pl_hit, repr((_pl_ok, _pl_v6, _pl_hit)))
_pl_cut = {
    "an unbelieved proxy naming loopback": _proxied_block159(_ELSE_RANGE159, "127.0.0.1", False),   # NOSONAR(S1313)
    "a believed proxy naming no address": _proxied_block159(_ELSE_RANGE159, "unknown", True),
}
check("1108 P1 LOW: ...while a proxy the panel does not believe (whatever it names), or a believed one naming no "
      "address, still refuses every block, naming trust_proxy",
      all(v is not None and "trust_proxy" in v for v in _pl_cut.values()), repr(_pl_cut))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# lead (P1): Tailscale Serve up, a loopback viewer's SSH session is still held by an IP block
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _serve_block159(target, headers=None, sessions=(), believed=False):
    """The panel host's IP-block refusal of `target` with the panel served over Tailscale, from loopback."""
    host = _p135._Host135(rules=[_p135._SSH22, _TS0_154], incoming="allow", ts=(True, False))

    def run():
        # tailscaled's default netfilter mode: its own chain lets tailscale0 (Serve's way in) in ahead of ufw.
        _p9_patch(_ue159, "ts_netfilter_on", lambda s: True)
        _p9_patch(_auth159, "_request_came_through_proxy", lambda peer: believed)
        _p9_patch(_ue159, "inbound_to", lambda ports: [
            (_ip159.ip_address(a), _ip159.ip_address(_p135._HOST_ADDR135), p) for a, p in sessions if p in ports])
        with _p9.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"},  # NOSONAR(S1313)
                                      headers=headers or {}):
            why = _fw159.fwc_block_ip_refusal(_p135._LOCAL135, target)
        return None if why is None else str(why)
    return _p135._on135(host, run, served=True)


_sv_hit = _serve_block159(_RANGE159, sessions=[(_TUNNEL159, 22)])
_sv_ok = {
    "a loopback viewer, no session in the range": _serve_block159(_ELSE_RANGE159, sessions=[(_TUNNEL159, 22)]),
    "a tailnet viewer through Serve": _serve_block159(_RANGE159, headers={"X-Forwarded-For": _TSP159},
                                                      sessions=[(_TUNNEL159, 22)], believed=True),
}
check("1108 P1 lead: with the panel served over Tailscale (tailscaled's chain letting tailscale0 in), a viewer on "
      "the panel host's loopback (an SSH tunnel) is refused a block of the range its SSH session comes from, named",
      _sv_hit is not None and _TUNNEL159 in _sv_hit, repr(_sv_hit))
check("1108 P1 lead: ...while a range no session comes from, and any block by a tailnet viewer that came through "
      "Serve, still pass (the controls)", all(v is None for v in _sv_ok.values()), repr(_sv_ok))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# lead (P1): the panel host's Block with no local row runs the evaluator on the stand-in row
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _norow159(target):
    host = _p135._Host135(rules=[_p135._SSH22, "5000/tcp  ALLOW IN  Anywhere"], incoming="allow")

    def run():
        try:
            why = _rs159._fwa_block_refusal(_hl159._R37A_LOCAL_ROW, target)
        except Exception as e:     # the lead: a missing attribute would be the route's generic 500
            return "raised %r" % (e,)
        return None if why is None else str(why)
    return _p135._on135(host, run)


_nr = {"the viewer's own address": _norow159(_p135._VIEWER135), "another address": _norow159(_STRANGER159)}
check("1108 P1 lead: the panel host's Block with no row of its own (host_local's stand-in row) runs the whole "
      "lock-out evaluator without raising: the viewer's own address is refused, another address passes",
      _nr["another address"] is None and _nr["the viewer's own address"] is not None
      and not _nr["the viewer's own address"].startswith("raised"), repr(_nr))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# lead (P1): the panel's change-port with config.json unwritable, after the open
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cp_unsaved159(save_raises):
    """change-port 5000 -> 5055 with the open working -> (status, reply, helper records, restarts, port saved)."""
    calls = {"record": [], "restart": []}

    def save(cfg, **keys):
        raise OSError(28, "No space left on device")
    try:
        _p9_arm(who="part159")
        _p9_patch(_rs159, "remote_ufw_open_port", lambda r, p, *a, **k: (True, "ok"))
        _p9_patch(_rs159, "remote_ufw_close_port", lambda r, p, *a, **k: (True, "closed"))
        _p9_patch_sm("remote_ufw_status", lambda r: {"installed": True, "enabled": True})
        _p9_patch(_p9_so, "ensure_panel_fail2ban", lambda log, port, wl=None: (True, "j"))
        _p9_patch(_p9_so, "panel_fail2ban_status", lambda: {"installed": True})
        _p9_patch(_p9_so, "port_in_use", lambda port: False)
        _p9_patch(_p9_so, "host_has_ip", lambda ip: True)
        _p9_patch(_p9_so, "record_panel_port", lambda port: (calls["record"].append(int(port)), (True, ""))[1])
        _p9_patch(_p9_so, "restart_panel", lambda *a, **k: (calls["restart"].append(1), (True, "p159"))[1])
        if save_raises:
            _p9_patch(_rs159, "set_config_keys", save)
        _saved116(port=5000, bind_host=_ANY108, tailscale_setup_done=True)
        with _boot116(BOOT_PORT=5000):
            resp = _p9_client(P9_ADMIN).post("/api/panel/change-port", json={"port": 5055, "bind_host": _ANY108})
            status, body = resp.status_code, _p9_json(resp)
        after = _p9_cfg.load_config().get("port")
    finally:
        _p9_restore_all()
        _saved116(port=5000, bind_host=_ANY108)
    return status, body, calls["record"], calls["restart"], after


_cpu = _cp_unsaved159(True)
_cpu_ok = _cp_unsaved159(False)
check("1108 P1 lead: a panel change-port whose config.json cannot be written (after the new port was opened) answers "
      "\"not changed\", puts the helper's port record back on the port still served, says the opened rule is left, "
      "and does not restart",
      _cpu[0] == 500 and _cpu[1].get("success") is False and "could not be saved" in str(_cpu[1].get("message"))
      and "5055" in str(_cpu[1].get("message")) and _cpu[2][-1:] == [5000] and _cpu[3] == [] and _cpu[4] == 5000,
      repr(_cpu))
check("1108 P1 lead: ...while a save that works moves the panel and restarts it (the control)",
      _cpu_ok[1].get("success") is True and _cpu_ok[3] == [1] and _cpu_ok[4] == 5055, repr(_cpu_ok))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# lead (P1): tailscaled's own chain is a Tailscale way back for "off" and Close port 22
# ════════════════════════════════════════════════════════════════════════════════════════════════
_NO_WAY159 = "no Tailscale way back"


def _way_back159(fn, netfilter_on=True, ifaces=("tailscale0",), off_tailnet=False):
    """fn() with Tailscale running, Tailscale SSH off and no tailscale0 rule; tailscaled's chain as given."""
    try:
        _p9_arm(who="part159")
        for mod in (_hosts159, _cp22_159):
            _p9_patch(mod, "_tailnet_ssh_state", lambda s: (True, False, False))
            _p9_patch(mod, "_r28b_panel_way_in_refusal", lambda s: None)
        _p9_patch(_ue159, "ts_netfilter_on", lambda s: netfilter_on)
        _p9_patch(_hosts159, "_tsiface_names", lambda s: list(ifaces))
        _p9_patch(_hosts159, "_r11a_sshd_off_tailnet", lambda s: off_tailnet)
        _p9_patch(_hosts159, "_r37a_tailnet_dial_refusal", lambda s, iface_allowed: None)
        _p9_patch(_hosts159, "_r32b_public_ssh_ports", lambda s: (None, []))   # stop at the next gate
        _p9_patch(_cp22_159, "remote_ufw_close_port_22", lambda r: (True, "closed p159"))
        return fn()
    finally:
        _p9_restore_all()


def _off159(**kw):
    return str(_way_back159(lambda: _hosts159.remote_set_public_ssh(_tsrow154(22), "off"), **kw)[1])


def _close22_159(**kw):
    return str(_way_back159(lambda: _p9_json(_p9_client(P9_ADMIN).post("/api/remote/%d/close-port-22" % P9_HOST))
                            .get("message"), **kw))


_wb_ok = {"off": _off159(), "close 22": _close22_159()}
check("1108 P1 lead: with Tailscale running, no tailscale0 rule and tailscaled in its default netfilter mode (its "
      "chain lets tailscale0 in ahead of ufw), \"Disable public SSH\" and Close port 22 get past the no-way-back gate",
      all(_NO_WAY159 not in v for v in _wb_ok.values()) and _wb_ok["close 22"] == "closed p159", repr(_wb_ok))
_wb_cut = {
    "off, nodivert/off mode": _off159(netfilter_on=False),
    "off, sshd bound off the tailnet": _off159(off_tailnet=True),
    "off, no Tailscale interface": _off159(ifaces=()),
    "close 22, nodivert/off mode": _close22_159(netfilter_on=False),
}
check("1108 P1 lead: ...and still refused with no way back where tailscaled's chain is not ahead of ufw, sshd "
      "listens only off the tailnet, or there is no Tailscale interface",
      all(_NO_WAY159 in v for v in _wb_cut.values()), repr(_wb_cut))

check("1108 part159: nothing reached a real transport", len(_P9_TRIPPED) == _TRIP159_START,
      repr(_P9_TRIPPED[_TRIP159_START:]))
