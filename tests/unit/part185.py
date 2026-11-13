"""Part 185 of the unit suite: no port opened to the internet by a rate limit or an inactive firewall's move.

Held here:
* Limit (remote_ufw_limit_port, and POST /api/remote/<id>/firewall/limit through the app): `ufw limit
  N/proto` ADDS a rule from Anywhere when no `N/proto` allow is there to rewrite. On a port closed, or
  open only to the tailnet, one source, one interface or one address of the host, "rate limit" opened
  it to the whole internet. It now runs only where every family it writes already lets everyone in;
  an unread or inactive firewall refuses, as lifting a limit does. Where the listing settles it, no
  host read is added.
* An SSH port move on an INACTIVE ufw (_open_ssh_port_rule, and POST /api/remote/<id>/ssh-port): where
  no stored rule lets SSH in from anywhere (tailnet-only, one source), no public allow is stored for
  the new port (it went live the moment UFW was enabled), and the success message says so.

HOW IT RUNS. On part12's app and stand-ins with its transport tripwire armed: run_privileged answers
from a small stand-in ufw (its numbered list, `status verbose`'s default policy, its stored IPv6
setting and `show added`). Nothing reaches a host, sudo or the checkout's data/.
"""
from types import SimpleNamespace as _NS185

from unit.part01 import check, ufw_stored_answer
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9_arm, _p9_audit, _p9_client, _p9_core, _p9_host_row,
                         _p9_json, _p9_patch, _p9_restore_all, _p9_set_host)
from unit.part159 import _Box159, _PUB_SESS159
from panel.ops.ssh_manager import firewall as _fw185, hosts as _hosts185, ufweval as _ue185

_TRIP185_START = len(_P9_TRIPPED)
_HDR185 = "Status: active\n\n     To                         Action      From\n     --                         ------      ----\n"
_TS185 = ["Anywhere on tailscale0  ALLOW IN  Anywhere", "Anywhere (v6) on tailscale0  ALLOW IN  Anywhere (v6)"]
_PUB185 = ["22/tcp  ALLOW IN  Anywhere", "22/tcp (v6)  ALLOW IN  Anywhere (v6)"]


class _Ufw185:
    """A stand-in ufw for remote_ufw_limit_port: its rows, default policy and stored IPv6 setting.

    `limit` rewrites an `N/proto` ALLOW in place (both families), else appends the LIMIT, as ufw does.
    """

    def __init__(self, rules, rc=0, active=True, default="deny", ipv6="no", stored_rc=0):
        self.rules, self.rc, self.active, self.default = list(rules), rc, active, default
        self.ipv6, self.stored_rc, self.sent = ipv6, stored_rc, []

    def priv(self, server, verb, args=(), **kw):
        self.sent.append(verb if verb != "ufw-status" or list(args) != ["verbose"] else "ufw-status verbose")
        if verb == "ufw-status" and list(args) == ["verbose"]:
            return "Status: active\nDefault: %s (incoming), allow (outgoing), deny (routed)\n" % self.default, "", 0
        if verb == "ufw-status":
            return self._listing()
        if verb == "ufw-stored-rules":
            return ufw_stored_answer(self.ipv6) if not self.stored_rc else ("", "permission denied", 1)
        if verb == "ufw-limit-port":
            self._limit(args[0])
        return "", "", 0

    def _listing(self):
        if self.rc:
            return "", "SSH command timed out", self.rc
        if not self.active:
            return "Status: inactive\n", "", 0
        return _HDR185 + "".join("[%2d] %s\n" % (n + 1, r) for n, r in enumerate(self.rules)), "", 0

    def _limit(self, spec):
        hit = False
        for n, r in enumerate(self.rules):
            words = r.split()
            if words[0] == spec and "ALLOW" in words:
                self.rules[n], hit = r.replace("ALLOW", "LIMIT"), True
        if not hit:
            self.rules.append("%s  LIMIT IN  Anywhere" % spec)


def _limit185(rules, port=22, **kw):
    """remote_ufw_limit_port(port/tcp) on a stand-in with `rules` -> (ok, message, verbs sent)."""
    ufw = _Ufw185(rules, **kw)
    _p9_patch(_p9_core, "run_privileged", ufw.priv)
    try:
        ok, msg = _hosts185.remote_ufw_limit_port(_NS185(id=-185, name="p185"), port, "tcp")
    finally:
        _p9_restore_all()
        _p9_arm(who="part185")
    return ok, str(msg), ufw.sent


def _r42f_limit_refused185():
    got = {
        "tailnet only": _limit185(_TS185),
        "one source": _limit185(["22/tcp  ALLOW IN  198.51.100.7"]),
        "one interface": _limit185(["22/tcp on eth0  ALLOW IN  Anywhere"]),
        "one address of the host": _limit185(["203.0.113.5 22/tcp  ALLOW IN  Anywhere"]),
        "closed": _limit185([], port=27015),
        "IPv4 only, IPv6 listed": _limit185(["22/tcp  ALLOW IN  Anywhere", "80/tcp (v6)  ALLOW IN  Anywhere (v6)"]),
        "IPv4 only, IPV6=yes": _limit185(["22/tcp  ALLOW IN  Anywhere"], ipv6="yes"),
        "IPv4 only, settings unread": _limit185(["22/tcp  ALLOW IN  Anywhere"], stored_rc=1),
        "denied, default allow": _limit185(["22/tcp  DENY IN  Anywhere"] + _PUB185, default="allow"),
    }
    check("1112 A03 (limit): Limit on a port closed, or open only to the tailnet, one source, one interface or "
          "one address of the host, or open to everyone over IPv4 alone where ufw would write the IPv6 half "
          "too (or its IPv6 setting is unread), or denied first, refuses and runs no `ufw limit` (it added a "
          "rule from Anywhere: the port opened to the internet, answered \"now rate limited\")",
          all(not ok and "already open to everyone" in msg and "ufw-limit-port" not in sent
              for ok, msg, sent in got.values()), repr(got))
    unread = {"unread": _limit185(_PUB185, rc=-1), "inactive": _limit185(_PUB185, active=False)}
    check("1112 A03 (limit): an unread firewall, or an inactive one whose stored rules cannot be read here, "
          "refuses with its own reason and runs no `ufw limit` (an unread listing went on to the limit)",
          not unread["unread"][0] and unread["unread"][1].startswith("Could not read the firewall")
          and not unread["inactive"][0] and unread["inactive"][1].startswith("UFW is not active")
          and all("ufw-limit-port" not in v[2] for v in unread.values()), repr(unread))


def _r42f_limit_controls185():
    got = {
        "public, both families": _limit185(_PUB185),
        "already limited": _limit185([r.replace("ALLOW", "LIMIT") for r in _PUB185]),
        "tailnet and public": _limit185(_TS185 + _PUB185),
        "IPv4 only, IPV6=no": _limit185(["22/tcp  ALLOW IN  Anywhere"], ipv6="no"),
        "closed, default allow": _limit185([], port=27015, default="allow"),
    }
    check("1112 A03 (limit): ...a port every family already lets everyone in (public in both, already limited, "
          "IPv4 with ufw's IPv6 off, or no rule under a default incoming allow) is still limited (controls)",
          all(ok and "ufw-limit-port" in sent for ok, _m, sent in got.values()), repr(got))
    check("1112 A03 (limit): ...and where the listing settles it, the limit adds no host read (status, limit, "
          "read-back only)",
          got["public, both families"][2] == ["ufw-status", "ufw-limit-port", "ufw-status"],
          repr(got["public, both families"]))


def _r42f_limit_route185():
    def post(rules):
        ufw = _Ufw185(rules)
        try:
            _p9_arm(who="part185")
            _p9_patch(_p9_core, "run_privileged", ufw.priv)
            r = _p9_client(P9_ADMIN).post("/api/remote/%d/firewall/limit" % P9_HOST, json={"port": 22})
            return r.status_code, _p9_json(r), ufw.sent, _p9_audit("remote_port_limit").success
        finally:
            _p9_restore_all()
    off, on = post(_TS185), post(_PUB185)
    check("1112 A03 (route, limit): POST /api/remote/<id>/firewall/limit on a host whose SSH is tailnet-only "
          "answers the refusal, sends no `ufw limit` and audits a failure; a public 22/tcp is limited and "
          "audited as done (control)",
          off[0] == 200 and off[1].get("success") is False
          and "already open to everyone" in off[1].get("message", "") and "ufw-limit-port" not in off[2]
          and off[3] is False and on[1].get("success") is True and "ufw-limit-port" in on[2] and on[3] is True,
          repr((off, on)))


# ── an inactive firewall's SSH port move ───────────────────────────────────────────────────────────
_ADDED185 = "Added user rules (see 'ufw status' for running firewall):\n"


def _inactive185(stored):
    """_open_ssh_port_rule(2022) on an inactive ufw storing `stored` -> ((added, refusal), the opens)."""
    opened = []

    def run(server, verb, args=(), **k):
        if verb == "ufw-status":
            return "Status: inactive\n", "", 0
        if verb == "ufw-show-added":
            return _ADDED185 + stored + ("ufw allow 2022/tcp comment 'SSH panel'\n" if opened else ""), "", 0
        return ufw_stored_answer() if verb == "ufw-stored-rules" else ("", "", 0)
    _p9_patch(_p9_core, "run_privileged", run)
    _p9_patch(_hosts185, "remote_ufw_open_port", lambda s, p, proto, comment="": opened.append(p) or (True, ""))
    _p9_patch(_hosts185, "remote_ufw_close_port", lambda *a, **k: (True, ""))
    try:
        return _hosts185._open_ssh_port_rule(_NS185(id=-18502, name="p185"), 2022, ["22"]), opened
    finally:
        _p9_restore_all()
        _p9_arm(who="part185")


def _r42f_inactive_move185():
    off = {name: _inactive185(body) for name, body in (
        ("tailnet only", "ufw allow in on tailscale0\n"),
        ("one source", "ufw allow from 198.51.100.7 to any port 22 proto tcp\n"),
        ("denied first", "ufw deny 22/tcp\nufw allow 22/tcp\nufw allow in on tailscale0\n"),
        ("udp", "ufw allow 22/udp\n"), ("outbound", "ufw allow out 22/tcp\n"))}
    check("1112 A03 (inactive move): on an inactive UFW whose stored rules let SSH in from anywhere on no port "
          "sshd serves (tailnet-only, one source, denied first, UDP, outbound), the move stores no public allow "
          "for the new port (it went live, SSH public, the moment UFW was enabled)",
          all(v == ((False, None), []) for v in off.values()), repr(off))
    on = {name: _inactive185(body) for name, body in (
        ("limit", "ufw limit 22/tcp\n"), ("bare", "ufw allow 22\n"), ("range", "ufw allow 20:30/tcp\n"),
        ("OpenSSH profile", "ufw allow OpenSSH\n"), ("commented", "ufw allow 22/tcp comment 'ssh'\n"))}
    check("1112 A03 (inactive move): ...where a stored rule does let SSH in from anywhere (a LIMIT, a bare 22, a "
          "range, the OpenSSH profile, a commented allow), the allow for the new port still goes in, counted as "
          "the panel's own (controls)",
          all(v == ((True, None), [2022]) for v in on.values()), repr(on))


class _Inactive185(_Box159):
    """part159's stand-in host that succeeds, its ufw inactive and storing `stored`."""

    def __init__(self, stored, **kw):
        super().__init__([], **kw)
        self.stored = stored

    def _answer(self, verb):
        if verb == "ufw-status":
            return "Status: inactive\n", "", 0
        if verb == "ufw-show-added":
            return _ADDED185 + self.stored + ("ufw allow 2022/tcp\n" if self.added else ""), "", 0
        return super()._answer(verb)


def _route_move185(stored):
    """POST /api/remote/<P9_HOST>/ssh-port {port: 2022} on an inactive stand-in -> (status, json, allow verbs)."""
    box = _Inactive185(stored)
    port0 = _p9_host_row(P9_HOST).port
    try:
        _p9_arm(who="part185")
        _p9_patch(_p9_core, "run_privileged", box.priv)
        _p9_patch(_p9_core, "run_command", lambda *a, **k: ("", "", 1))
        _p9_patch(_p9_core, "write_root_file", box.write)
        _p9_patch(_hosts185, "_sshd_socket_activated", lambda s: False)
        _p9_patch(_hosts185, "_restart_ssh_listener", box.restart)
        _p9_patch(_hosts185, "_point_f2b_sshd_at", lambda server, ports: ("updated", ""))
        _p9_patch(_hosts185, "_fwb_ssh_conn", lambda s: _PUB_SESS159)
        _p9_patch(_hosts185, "_tailscale_conn_state", lambda s: (True, False))
        _p9_patch(_ue185, "ts_netfilter_on", lambda s: False)
        _p9_patch(_ue185, "app_profiles", lambda s: None)
        _p9_patch(_fw185, "remote_ufw_default_allows_in", lambda server: False)
        r = _p9_client(P9_ADMIN).post("/api/remote/%d/ssh-port" % P9_HOST, json={"port": 2022})
        return r.status_code, _p9_json(r), [v for v, _a in box.allows if not v.startswith("ufw-delete")]
    finally:
        _p9_restore_all()
        _p9_set_host(P9_HOST, port=port0)


def _r42f_inactive_route185():
    off, on = _route_move185("ufw allow in on tailscale0\n"), _route_move185("ufw limit 22/tcp\n")
    check("1112 A03 (route, inactive move): POST /api/remote/<id>/ssh-port on an inactive UFW storing only a "
          "tailnet rule moves SSH, sends no allow verb, and says no public rule was added; a stored public "
          "LIMIT for 22 still has the new port's allow sent (control)",
          off[0] == 200 and off[1].get("success") is True and off[2] == []
          and "none of its stored rules lets SSH in from anywhere" in off[1].get("message", "")
          and on[1].get("success") is True and on[2] != [], repr((off, on)))


try:
    _p9_arm(who="part185")
    _r42f_limit_refused185()
    _r42f_limit_controls185()
    _r42f_limit_route185()
    _r42f_inactive_move185()
    _r42f_inactive_route185()
finally:
    _p9_restore_all()

check("part185: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP185_START, repr(_P9_TRIPPED[_TRIP185_START:][:6]))
