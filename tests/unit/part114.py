"""Part 114 of the unit suite: the twentieth review's ssh_manager fixes (builder B).

* The Public SSH card, its Allow / Limit / Disable and "Close public SSH" act on the ports sshd really
  serves (ssh.socket's, else `sshd -T`'s, plus the port the panel dials it on), not on a hard-coded 22.
  After the panel's own port move (change_ssh_port, which tells the operator to close the old port)
  the card read 22's rules — "disabled — tailnet only" with 2222 open to the internet — and its
  buttons changed 22 alone. Read against a ufw rule table in BOTH directions: the rules that let the
  public in on the served port, and the ones that must not count (an interface rule, a loopback
  source or destination, UDP, OUT, a route rule, a DENY above the ALLOW, the old port 22), for each
  family. Every lockout guard stays: an unread port list refuses, and so does a host the panel itself
  dials over a public address, whatever port it dials.
* An SSH port move whose transport raised mid-way (paramiko) left the new port's UFW allow and a
  changed drop-in behind; it now undoes them before the error goes on.
* A failed backup's partial archive, proven broken but not removable just then, is named as kept.
* The OS Updates popup: a previous run's completion sentinel is "finished" only when the panel's own
  job is known NOT to be running. An unanswered probe read as finished, so the popup said "Updates
  installed." about a run that had just started.

HOW IT RUNS. On part12's stand-ins with its transport tripwire armed for the part: run_privileged and
run_command answer from a small ufw rule table and a stand-in `sshd -T` / ssh.socket. Nothing reaches
a host, sudo or the checkout's data/.
"""
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import _P9_TRIPPED, _p9_arm, _p9_core, _p9_patch, _p9_restore_all
from panel.core import i18n as _i18n114
from panel.ops.ssh_manager import hosts as _hosts114

_TRIP114_START = len(_P9_TRIPPED)
# Stand-in addresses, never dialled (every transport is stubbed and the tripwire is armed).
_TS_ADDR114 = "100.64.0.114"   # NOSONAR(S1313) - a tailnet (CGNAT) address in a stand-in host row
_TS_ADDR114B = "100.64.0.115"  # NOSONAR(S1313) - a tailnet (CGNAT) address in a stand-in host row
_PUB_ADDR114 = "203.0.113.14"  # NOSONAR(S1313) - a documentation address in a stand-in host row
_LAN114 = "10.0.0.0/8"         # NOSONAR(S1313) - a private network in a stand-in ufw rule
_HDR114 = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n"


class _Ufw114:
    """A ufw rule table behind the panel's ufw verbs, with ufw's own spec matching.

    A rule is (to, action, v6, tail): `tail` is the From column and anything after it as ufw prints
    it ("Anywhere", "127.0.0.1", "Anywhere" with an interface in `to`). A spec verb (`ufw allow
    2222/tcp`, `ufw limit`, `ufw delete allow|limit`) touches only the public rule for that exact To
    in both families — never an interface rule, a source-restricted one, OUT or FWD; an allow or a
    limit over the other action rewrites it in place. `fail` names verbs that exit 1 doing nothing.
    """

    def __init__(self, *rules, fail=()):
        self.rules = [dict(zip(("to", "action", "v6", "tail"), r)) for r in rules]
        self.fail = set(fail)

    def status(self):
        rows = []
        for r in self.rules:
            to = r["to"] + (" (v6)" if r["v6"] else "")
            tail = r["tail"] + (" (v6)" if r["v6"] and r["tail"] == "Anywhere" else "")
            rows.append("%-26s %-11s %s" % (to, r["action"], tail))
        return _HDR114 + "\n".join(rows) + "\n"

    def _public(self, r, to):
        return r["to"] == to and r["tail"] == "Anywhere"

    def put(self, to, action):
        for v6 in (False, True):
            hit = [r for r in self.rules if self._public(r, to) and r["v6"] == v6
                   and r["action"] in ("ALLOW IN", "LIMIT IN")]
            if hit:
                hit[0]["action"] = action
            else:
                self.rules.append({"to": to, "action": action, "v6": v6, "tail": "Anywhere"})

    def drop(self, to, action):
        self.rules = [r for r in self.rules if not (self._public(r, to) and r["action"] == action)]

    def __call__(self, server, verb, args=(), **kw):
        if verb in self.fail:
            return "", "ERROR: Could not acquire lock", 1
        if verb == "ufw-status":
            return self.status(), "", 0
        if verb == "sshd-effective-config":
            return self.sshd_t, "", self.sshd_rc
        if verb in ("ufw-allow-port", "ufw-limit-port"):
            self.put(args[0], "ALLOW IN" if verb == "ufw-allow-port" else "LIMIT IN")
        elif verb in ("ufw-delete-allow-port", "ufw-delete-limit-port"):
            self.drop(args[0], "ALLOW IN" if verb == "ufw-delete-allow-port" else "LIMIT IN")
        elif verb == "ufw-delete-allow-app":
            self.drop(args[0], "ALLOW IN")
        self.ran.append((verb, list(args)))
        return "", "", 0

    def left(self):
        return sorted((r["to"], r["action"], r["v6"], r["tail"]) for r in self.rules)


def _both114(to, action, tail="Anywhere"):
    """One rule as ufw keeps it for both families."""
    return [(to, action, False, tail), (to, action, True, tail)]


def _wire114(ufw, sshd="port 2222\n", sshd_rc=0, socket=None):
    """Serve `ufw` as run_privileged; sshd -T answers `sshd`; ssh.socket answers `socket` (None: not read)."""
    ufw.sshd_t, ufw.sshd_rc, ufw.ran = sshd, sshd_rc, []
    _p9_patch(_p9_core, "run_privileged", ufw)
    _p9_patch(_p9_core, "run_command", lambda *a, **k: (socket, "", 0) if socket else ("", "", 1))
    _p9_patch(_hosts114, "_tailnet_ssh_state", lambda server: (True, True, True))
    return ufw


def _key114(port=2222, host=_TS_ADDR114):
    """A key-auth row the panel reaches over its tailnet address (so 'off' is not its own way in)."""
    return NS(id=-114, name="p114", host=host, port=port, auth_method="key", is_local=False)


def _ts114():
    """A row the panel reaches over Tailscale SSH: the stored 22 is tailscaled's, not sshd's."""
    return NS(id=-1141, name="p114ts", host=_TS_ADDR114B, port=22, auth_method="tailscale", is_local=False)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. What the card reads: the served port's rules, both directions, both families
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _status_table114():
    rows = {
        # ways in for the public on sshd's port
        "limit, both families": (_both114("2222/tcp", "LIMIT IN"), "limit"),
        "allow, v6 only": ([("2222/tcp", "ALLOW IN", True, "Anywhere")], "allow"),
        "v4 limit, v6 allow": ([("2222/tcp", "LIMIT IN", False, "Anywhere"),
                                ("2222/tcp", "ALLOW IN", True, "Anywhere")], "allow"),
        "bare port (any protocol)": (_both114("2222", "ALLOW IN"), "allow"),
        "a port list": (_both114("2222,80/tcp", "ALLOW IN"), "allow"),
        # not ways in on sshd's port
        "the old port 22 only": (_both114("22/tcp", "ALLOW IN") + _both114("OpenSSH", "ALLOW IN"), "off"),
        "tailscale0 interface": ([("Anywhere on tailscale0", "ALLOW IN", False, "Anywhere")], "off"),
        "docker0 interface": ([("2222/tcp on docker0", "ALLOW IN", False, "Anywhere")], "off"),
        "loopback interface": ([("Anywhere on lo", "ALLOW IN", False, "Anywhere")], "off"),
        "loopback source": ([("2222/tcp", "ALLOW IN", False, "127.0.0.1"),
                             ("2222/tcp", "ALLOW IN", True, "::1")], "off"),
        "loopback destination": ([("127.0.0.1 2222/tcp", "ALLOW IN", False, "Anywhere")], "off"),
        "udp": (_both114("2222/udp", "ALLOW IN"), "off"),
        "out": (_both114("2222/tcp", "ALLOW OUT"), "off"),
        "route (FWD)": (_both114("2222/tcp", "ALLOW FWD"), "off"),
        "deny above the allow": (_both114("2222/tcp", "DENY IN") + _both114("2222/tcp", "ALLOW IN"), "off"),
    }
    got, want = {}, {}
    for name, (rules, mode) in rows.items():
        _wire114(_Ufw114(*rules))
        st = _hosts114.remote_public_ssh_status(_key114())
        got[name], want[name] = (st.get("mode"), st.get("ssh_ports")), (mode, [2222])
    check("public SSH card: read on the port sshd serves (2222 after a move), not 22 — open in either "
          "family through a LIMIT, an ALLOW, a bare port or a list; and NOT open through the old 22 / "
          "OpenSSH rules, an interface rule (tailscale0, docker0, lo), a loopback source or destination, "
          "UDP, OUT, FWD, or an ALLOW below a DENY (it read 22's rules: \"disabled\" with 2222 open)",
          got == want, repr({k: (got[k], want[k]) for k in got if got[k] != want[k]}))


def _status_more114():
    # Two served ports (a move keeps the old one as a fallback): the most open one is the answer.
    two = {}
    for name, rules in (("22 off, 2222 limit", _both114("2222/tcp", "LIMIT IN")),
                        ("22 allow, 2222 limit", _both114("22/tcp", "ALLOW IN") + _both114("2222/tcp", "LIMIT IN")),
                        ("both off", [])):
        _wire114(_Ufw114(*rules), sshd="port 22\nport 2222\n")
        st = _hosts114.remote_public_ssh_status(_key114(port=22))
        two[name] = (st.get("mode"), st.get("ssh_ports"))
    check("public SSH card: with sshd on two ports it reports the more open one, and names both ports",
          two == {"22 off, 2222 limit": ("limit", [22, 2222]), "22 allow, 2222 limit": ("allow", [22, 2222]),
                  "both off": ("off", [22, 2222])}, repr(two))

    # ssh.socket's ports replace sshd -T's (it still says 22 after a socket-activated move).
    _wire114(_Ufw114(*_both114("22/tcp", "LIMIT IN")), sshd="port 22\n",
             socket="ActiveState=active\nListen=[::]:2222 (Stream)\n")
    st = _hosts114.remote_public_ssh_status(_ts114())
    check("public SSH card: on a socket-activated Tailscale-SSH host it reads ssh.socket's 2222 (not the "
          "row's 22, not sshd_config's 22): a leftover 22/tcp LIMIT is not public SSH",
          (st.get("mode"), st.get("ssh_ports"), st.get("sshd_ports")) == ("off", [2222], [2222]), repr(st))

    # Unread: no port to describe on a host the panel does not dial sshd on.
    _wire114(_Ufw114(*_both114("22/tcp", "LIMIT IN")), sshd="", sshd_rc=1)
    st = _hosts114.remote_public_ssh_status(_ts114())
    check("public SSH card: sshd's ports unread on a Tailscale-SSH host is mode unknown with ports_unread, "
          "never 22's rules",
          (st.get("mode"), st.get("ports_unread"), st.get("ssh_ports")) == ("unknown", True, []), repr(st))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. What the buttons change: the served port, both families, nothing else
# ════════════════════════════════════════════════════════════════════════════════════════════════
_KEEP114 = (_both114("22/tcp", "ALLOW IN")                      # an operator's rule on a port sshd left
            + [("Anywhere on tailscale0", "ALLOW IN", False, "Anywhere"),
               ("2222/tcp", "ALLOW IN", False, _LAN114)])  # a source-restricted allow


def _actions114():
    got = {}
    for mode, start, want_action in (("limit", _both114("2222/tcp", "ALLOW IN"), "LIMIT IN"),
                                     ("allow", _both114("2222/tcp", "LIMIT IN"), "ALLOW IN")):
        ufw = _wire114(_Ufw114(*(start + _KEEP114)))
        ok, msg = _hosts114.remote_set_public_ssh(_key114(), mode)
        want = sorted(list(_KEEP114) + [(t, want_action, v6, f) for t, _a, v6, f in start])
        got[mode] = (ok, ufw.left() == want, str(msg))
    ufw = _wire114(_Ufw114(*(_both114("2222/tcp", "LIMIT IN") + _both114("2222", "ALLOW IN") + _KEEP114)))
    ok, msg = _hosts114.remote_set_public_ssh(_key114(), "off")
    got["off"] = (ok, ufw.left() == sorted(_KEEP114), str(msg))
    check("public SSH Limit / Allow / Disable: change sshd's port 2222 in both families (LIMIT kept in "
          "place for Limit) and leave 22's rule, the tailscale0 allow and a source-restricted allow "
          "alone (they changed 22 only)",
          got == {"limit": (True, True, "Public SSH is now rate-limited (port 2222)"),
                  "allow": (True, True, "Public SSH is now open (allow) (port 2222)"),
                  "off": (True, True, "Public SSH is now disabled (tailnet-only) (port 2222)")}, repr(got))


def _actions_gate114():
    # The add is the gate, for every port: one that fails removes nothing.
    ufw = _wire114(_Ufw114(*(_both114("OpenSSH", "ALLOW IN") + _both114("2222/tcp", "ALLOW IN"))),
                   sshd="port 22\nport 2222\n")
    ufw.fail = {"ufw-limit-port"}
    ok, msg = _hosts114.remote_set_public_ssh(_key114(port=22), "limit")
    check("public SSH Limit: a refused limit on any served port removes nothing that lets SSH in",
          not ok and not [v for v, _a in ufw.ran if v.startswith("ufw-delete")]
          and ("OpenSSH", "ALLOW IN", False, "Anywhere") in ufw.left(), repr((msg, ufw.ran)))


def _actions_refusals114():
    # Refusals: sshd unread on a Tailscale-SSH host; the panel's own public connection, any port.
    ufw = _wire114(_Ufw114(*_both114("22/tcp", "LIMIT IN")), sshd="", sshd_rc=1)
    unread = {m: _hosts114.remote_set_public_ssh(_ts114(), m) for m in ("allow", "limit", "off")}
    check("public SSH: every mode is refused when sshd's ports cannot be read (no guessed 22), "
          "and no rule is touched",
          all(not ok and str(msg) == _hosts114._R32B_PORTS_UNREAD for ok, msg in unread.values())
          and ufw.ran == [] and ufw.left() == sorted(_both114("22/tcp", "LIMIT IN")), repr((unread, ufw.ran)))
    _actions_cut114()


def _actions_cut114():
    ufw = _wire114(_Ufw114(*_both114("2222/tcp", "LIMIT IN")))
    _p9_patch(_hosts114, "_r28b_resolve", lambda name: [_PUB_ADDR114])
    cut = {name: _hosts114.remote_set_public_ssh(_key114(port=p, host="vps.example.com"), "off")
           for name, p in (("port 2222", 2222), ("port 22", 22))}
    check("public SSH Disable: a host the panel itself dials at a public address is refused on ANY port "
          "(it was refused on 22 only, and Disable now closes the dialled port too), nothing removed",
          all(not ok and "connects to this host at vps.example.com on port" in str(msg) for ok, msg in cut.values())
          and "on port 2222 through" in str(cut["port 2222"][1])
          and ufw.left() == sorted(_both114("2222/tcp", "LIMIT IN")), repr(cut))
    ufw = _wire114(_Ufw114(*_both114("2222/tcp", "LIMIT IN")))
    ok, _msg = _hosts114.remote_set_public_ssh(_key114(), "off")
    check("public SSH Disable: ...a host it reaches over its tailnet address still goes ahead (control)",
          ok and ufw.left() == [], repr((ok, ufw.left())))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Close public SSH (after a Tailscale migration) and the migration's own last step
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _close114():
    ufw = _wire114(_Ufw114(*(_both114("2222/tcp", "LIMIT IN") + _KEEP114)))
    ok, msg = _hosts114.remote_ufw_close_port_22(_ts114())
    check("Close public SSH: removes sshd's port 2222 rules in both families and says which port; 22's "
          "rule and the tailscale0 allow stay (it removed 22 and answered \"Port 22 rule removed\")",
          ok and str(msg) == "Public SSH rules removed from UFW (port 2222)" and ufw.left() == sorted(_KEEP114),
          repr((ok, msg, ufw.left())))
    ufw = _wire114(_Ufw114(*_both114("2222/tcp", "LIMIT IN")), sshd="", sshd_rc=1)
    ok, msg = _hosts114.remote_ufw_close_port_22(_ts114())
    check("Close public SSH: refused, nothing removed, when sshd's ports cannot be read",
          not ok and str(msg) == _hosts114._R32B_PORTS_UNREAD and ufw.ran == [], repr((msg, ufw.ran)))
    ufw = _wire114(_Ufw114(*(_both114("2222/tcp", "LIMIT IN") + _both114("22/tcp", "LIMIT IN"))))
    _hosts114._r15c_delete_port_22(_key114())
    ufw2 = _wire114(_Ufw114(*_both114("22/tcp", "LIMIT IN")), sshd="", sshd_rc=1)
    _hosts114._r15c_delete_port_22(_ts114())
    check("Tailscale migration's close: removes the port sshd serves (2222), and 22 as before when "
          "sshd's ports cannot be read",
          ufw.left() == sorted(_both114("22/tcp", "LIMIT IN")) and ufw2.left() == [], repr((ufw.left(), ufw2.left())))
    # In the viewer's language: the new answer is a catalog sentence.
    with _hosts114_app().test_request_context("/"):
        __import__("flask").session["lang"] = "es"
        es = _i18n114.tr(_i18n114.Sentence("Public SSH rules removed from UFW (port {ports})", ports="2222"))
    check("Close public SSH (es): the answer is Spanish, naming the port",
          es == "Reglas de SSH público eliminadas de UFW (puerto 2222)", es)


def _hosts114_app():
    from unit.part12 import _p9
    return _p9


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. OS Updates: a previous run's sentinel is "finished" only on a definite "not running"
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _sentinel114():
    log = "Reading package lists...\n" + _hosts114._OS_UPDATE_DONE + "0\n"
    got = {}
    for name, own, upgrade in (("not running", ("", "", 1), None), ("running", ("", "", 0), None),
                               ("no answer", ("", "SSH command timed out", -1), None),
                               ("old helper, apt idle", ("", "unknown verb: os-update-own-running", 2), 1),
                               ("old helper, apt busy", ("", "unknown verb: os-update-own-running", 2), 0),
                               ("old helper, apt unread", ("", "unknown verb: os-update-own-running", 2), -1)):
        def _priv(server, verb, args=(), _own=own, _up=upgrade, **kw):
            if verb == "os-update-log":
                return log, "", 0
            if verb == "os-update-own-running":
                return _own
            if verb == "apt-upgrade-running":
                return "", "", _up
            return "", "", 0
        _p9_patch(_p9_core, "run_privileged", _priv)
        local = name.startswith("old helper")
        st = _hosts114.remote_os_update_status(NS(id=-1142, name="p114os", is_local=local,
                                                  auth_method="local" if local else "tailscale"))
        got[name] = (st.get("done"), st.get("running"), bool(st.get("unread")))
    check("OS update status: a previous run's sentinel is finished only when the panel's own job is known "
          "not to be running — an unanswered probe is unread, not \"Updates installed.\"; a helper "
          "older than the verb asks apt (running / finished / unread)",
          got == {"not running": (True, False, False), "running": (False, True, False),
                  "no answer": (False, None, True), "old helper, apt idle": (True, False, False),
                  "old helper, apt busy": (False, True, False), "old helper, apt unread": (False, None, True)},
          repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The card names those ports, and Disable's question does too
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _card_js114():
    import re
    from unit.part106 import _js106, _read106
    src = _read106("static", "js", "remote_manage_host.js")
    m = re.search(r"^var SSH_LABELS=.*$", src, re.M)
    name = "Public SSH card: the script that names its ports"
    out = _js106(name, (
        "var REMOTE_ID = 1; let asked = '';\n"
        "E87.prototype.hasAttribute = function(k){ return k in this.attrs; };\n"
        "E87.prototype.removeAttribute = function(k){ delete this.attrs[k]; };\n"
        "const spans = [new E87('span'), new E87('span')];\n"
        "document.querySelectorAll = q => q === '[data-ssh-public-ports]' ? spans : [];\n"
        "global.confirmDialog = o => { asked = o.bodyText; };\n"
        "function _r13c_closedPortTitle(){ return ''; }\n"
        + (m.group(0) if m else "/* MISSING var SSH_LABELS */") + "\n"
        "const reply = d => { global.fetch = u => d === undefined ? Promise.reject(new Error('x'))\n"
        "  : Promise.resolve({json: () => Promise.resolve(d)}); };\n"), src,
        ("function sshModeLabel(", "function loadSshStatus(", "function _r26bSshPortNow(", "var _r32bSshPorts",
         "function _r32bPublicPorts(", "function sshMode("), (
        "  const out = {};\n"
        "  reply({mode: 'limit', active: true, ssh_ports: [22, 2222], sshd_ports: [22, 2222]});\n"
        "  loadSshStatus(); await settle(); out.ports = spans.map(s => s.textContent);\n"
        "  sshMode('off'); out.asked = asked;\n"
        "  reply({mode: 'unknown', active: true, ssh_ports: [], ports_unread: true});"
        " loadSshStatus(); await settle();\n"
        "  out.unread = spans.map(s => s.textContent);\n"
        "  reply(undefined); loadSshStatus(); await settle(); out.failed = spans.map(s => s.textContent);\n"
        "  console.log(JSON.stringify(out));\n"))
    if out is not None:
        check("Public SSH card: names the ports ssh-status says it acts on (\"22, 2222\"), and Disable's "
              "question names them (it said port 22 whatever sshd served); unread or no answer is \"unknown\"",
              out.get("ports") == ["22, 2222"] * 2 and "(port 22, 2222)?" in (out.get("asked") or "")
              and out.get("unread") == ["unknown"] * 2 and out.get("failed") == ["unknown"] * 2, repr(out))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. An SSH port move whose transport RAISES mid-way undoes what it had changed
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _move_raise114():
    ufw0 = (_HDR114 + "22/tcp                     LIMIT IN    Anywhere\n")
    got = {}
    for case in ("write raises", "listing raises"):
        sent = []

        def _priv(server, verb, args=(), _c=case, **kw):
            sent.append((verb, list(args)))
            if verb == "ufw-status":     # the allow, once added, is there to read back
                # ...and gone once deleted (the undo's close reads it back, and retries one still there)
                added = [v for v, _a in sent if v in ("ufw-allow-proto-port", "ufw-delete-allow-proto-port")][-1:] == [
                    "ufw-allow-proto-port"]
                return ufw0 + ("2022/tcp                   ALLOW IN    Anywhere\n" if added else ""), "", 0
            if verb == "listening-sockets":
                if _c == "listing raises":
                    raise ConnectionError("socket closed")
                return "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", "", 0
            if verb == "sshd-effective-config":
                return "port 22\n", "", 0
            return "", "", 0

        def _write(*a, **k):
            raise ConnectionError("socket closed")
        _p9_patch(_p9_core, "run_privileged", _priv)
        _p9_patch(_p9_core, "run_command", lambda *a, **k: ("", "", 1))
        _p9_patch(_p9_core, "write_root_file", _write)
        _p9_patch(_hosts114, "_sshd_socket_activated", lambda s: False)
        _p9_patch(_hosts114, "_restart_ssh_listener", lambda *a, **k: sent.append(("restart", [])))
        try:
            _hosts114.change_ssh_port(_key114(port=22, host=_PUB_ADDR114), 2022)
            raised = False
        except ConnectionError:
            raised = True
        got[case] = (raised, [v for v in sent if v[0] in ("ufw-allow-proto-port", "ufw-delete-allow-proto-port",
                                                          "sshd-restore-dropin", "restart")])
    check("ssh port move: a transport that raises after the new port's allow was added (paramiko, mid-step) "
          "still raises, but first removes that allow and restores the drop-in snapshot (both were left "
          "behind); one that raises before anything changed undoes nothing (control)",
          got == {"write raises": (True, [("ufw-allow-proto-port", ["tcp", "2022", "SSH panel"]),
                                          ("sshd-restore-dropin", []),
                                          ("ufw-delete-allow-proto-port", ["tcp", "2022"]), ("restart", [])]),
                  "listing raises": (True, [])}, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. A partial backup archive proven broken but not removable is SAID to be kept
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _bkpart114():
    from panel.ops.ssh_manager import game as _game114
    name = "csgoserver-2026-10-17-120000.tar.zst"
    got = {}
    for removed in (True, False):
        _p9_patch(_game114, "_r13b_bkverify_code", lambda *a, **k: "CORRUPT")
        _p9_patch(_game114, "_bkpart_remove", lambda *a, _r=removed, **k: _r)
        _p9_patch(_game114, "_bkverify_name", lambda *a, **k: name)
        judged = _game114._r13b_bkpart_judge(NS(id=-1143), "p114u", name, 1)
        warned = _game114._r13b_bk_warned(NS(id=-1143), "p114u", "csgoserver", (1, {}),
                                          ("[ FAIL ] Backup", ""), 3, "")[1]
        got[removed] = (judged, "could not be removed" in warned, "Removed the partial" in warned)
    check("backup: a partial archive the read proves broken but that could not be removed (a tar running "
          "as the account, a lock) is named as kept, to delete by hand (the message said nothing, and it "
          "sat in the list like a backup); one removed is still said to be (control)",
          got[True] == (" Removed the partial archive it left (%s)." % name, False, True)
          and got[False][0].startswith(" The partial archive it left (%s) could not be removed" % name)
          and got[False][1:] == (True, False), repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
try:
    _p9_arm(who="part114")
    _status_table114()
    _status_more114()
    _actions114()
    _actions_gate114()
    _actions_refusals114()
    _close114()
    _sentinel114()
    _card_js114()
    _move_raise114()
    _bkpart114()
finally:
    _p9_restore_all()

check("part114: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP114_START, repr(_P9_TRIPPED[_TRIP114_START:][:6]))
