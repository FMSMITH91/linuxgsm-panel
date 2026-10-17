"""Part 108 of the unit suite: the eighteenth review's ssh_manager and route fixes (review 1017a, builder B).

* A remote root-file write creates its directory first, as the helper's does: a stock socket-activated
  Ubuntu 24.04 has no /etc/systemd/system/ssh.socket.d, so an SSH port move on such a remote wrote
  nothing, and change_ssh_port now reads the write's exit code before it validates or restarts (a bind
  change on the current port reported "SSH now listens on <ip>:22, and only there" with nothing
  written).
* GMod content held only in a panel server's account is named so for a server-only admin whichever
  account holds the most content games ("Not on this host yet" was false when another account held more).
* A panel port change whose restart could not be scheduled puts the old port's firewall rule and the
  login jail back: the panel still listens there.
* Close public panel port on an unreadable firewall is audited like its sibling refusals.

HOW IT RUNS. The remote write is the RENDERED command, run in bash with its /etc paths moved into a temp
root (no root, no sudo: an unmoved path could only fail). Everything else is stand-ins behind
ssh_manager's _core and the routes on part12's app. Nothing reaches a host, sudo or the checkout's data/.
"""
import os
import shutil as _shutil108
import stat as _stat108
import subprocess as _sp108  # nosec B404 - runs bash on this part's own rendered write command
import tempfile as _tf108
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import (P9_ADMIN, P9_LOCAL, _P9_TRIPPED, _p9, _p9_arm, _p9_cfg, _p9_client, _p9_core, _p9_json,
                         _p9_patch, _p9_restore_all, _p9_sf, _p9_so)
from panel.db.models import AuditLog, GameServer, RemoteServer, User, db
from panel.ops.ssh_manager import hosts as _hosts108
from panel.routes import remote_vps as _rv108
from panel.security import privileged as _priv108

_TRIP108_START = len(_P9_TRIPPED)
_ANY108 = "0.0.0.0"  # nosec B104 - a stored bind address the route is asked to accept, not a bind
_V6_108 = "2001:db8::7"  # NOSONAR(S1313) - an IPv6 documentation address, never dialled (stubbed)
_mine108 = {"hosts": [], "servers": []}


def _rooted108(cmd, root):
    """`cmd` with every absolute /etc path moved under `root`; None if one would stay on the real /etc."""
    moved = cmd.replace(" /etc/", " %s/etc/" % root)
    if moved.replace("%s/etc/" % root, "").count("/etc/"):
        return None
    return moved


def _bash108(cmd, root):
    """Run the rendered command in bash with its paths under `root`: (out, err, rc)."""
    moved = _rooted108(cmd, root)
    if moved is None:
        return "", "p108: a path was not moved under the temp root", 97
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp108.run(["bash", "-c", moved], capture_output=True, text=True, timeout=30,  # nosec B603 B607
                   env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}, check=False)
    return r.stdout, r.stderr, r.returncode


def _root108(layout):
    """A temp root laid out as `layout` says.

    "bare" has nothing, "systemd" has etc/systemd/system and etc/ssh but no drop-in dirs, "blocked" has
    etc/systemd/system/ssh.socket.d and etc/ssh/sshd_config.d as plain FILES (mkdir fails).
    """
    root = os.path.realpath(_tf108.mkdtemp(prefix="lgsm-unit-p108-"))
    if layout != "bare":
        os.makedirs(os.path.join(root, "etc", "systemd", "system"))
        os.makedirs(os.path.join(root, "etc", "ssh"))
    if layout == "blocked":
        for f in (("etc", "systemd", "system", "ssh.socket.d"), ("etc", "ssh", "sshd_config.d")):
            with open(os.path.join(root, *f), "w", encoding="utf-8") as fh:
                fh.write("not a directory\n")
    return root


def _write_targets108():
    """Every WRITE_TARGETS destination, rendered for a remote, into a root that has none of their dirs."""
    root = _root108("bare")
    got = {}
    try:
        for name, (path, mode) in sorted(_priv108.WRITE_TARGETS.items()):
            body = "# p108 %s\n" % name
            _o, err, rc = _bash108(_priv108.remote_write_command(name, body), root)
            dest = os.path.join(root, path.lstrip("/"))
            landed = os.path.isfile(dest) and open(dest, encoding="utf-8").read() == body
            got[name] = (rc, landed, landed and _stat108.S_IMODE(os.stat(dest).st_mode) == mode, err.strip()[:80])
    finally:
        _shutil108.rmtree(root, ignore_errors=True)
    bad = {k: v for k, v in got.items() if v[:3] != (0, True, True)}
    check("remote root write: every WRITE_TARGETS destination is written, with its mode, into a host that "
          "lacks its directory (a stock 24.04 has no /etc/systemd/system/ssh.socket.d, and the bare "
          "`base64 -d > path` failed there)",
          len(got) == len(_priv108.WRITE_TARGETS) and not bad, repr(bad or got))
    sock = _priv108.remote_write_command("sshd-socket-dropin", "[Socket]\n")
    check("remote root write: ...and the directory it creates is the table path's own dirname, quoted",
          sock.startswith("mkdir -p -m 755 /etc/systemd/system/ssh.socket.d && "), sock[:80])


def _ssh_stage108(root, socket_mode, calls):
    """Stand-ins for change_ssh_port on a key-auth remote whose root-file writes run under `root`."""
    dropin = os.path.join(root, (_priv108.SSHD_SOCKET_DROPIN if socket_mode
                                 else _priv108.SSHD_DROPIN).lstrip("/"))

    def _cmd(server, command, timeout=30, sudo=None, stdin_text=None):
        if "base64 -d >" in command:
            calls.append("write")
            return _bash108(command, root)
        if command == _hosts108._R26B_SOCKET_SHOW:
            return "ActiveState=active\nListen=0.0.0.0:22 (Stream)\nListen=[::]:22 (Stream)\n", "", 0
        calls.append("unexpected command")
        return "", "p108: unexpected command", 1

    def _priv(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, **k):
        calls.append(verb)
        if verb == "sshd-socket-active":
            return ("active\n", "", 0) if socket_mode else ("inactive\n", "", 3)
        if verb == "sshd-effective-config":
            return "port 22\n", "", 0
        if verb == "listening-sockets":
            # sshd serves 2222 only once the written drop-in names it (and the listener restarted).
            moved = os.path.isfile(dropin) and "2222" in open(dropin, encoding="utf-8").read() \
                and "restart" in calls
            return "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n" + (
                "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\n" if moved else ""), "", 0
        return "", "", 0
    _p9_patch(_p9_core, "run_command", _cmd)
    _p9_patch(_p9_core, "run_privileged", _priv)
    _p9_patch(_hosts108, "_open_ssh_port_rule", lambda server, port, way_in: (False, None))
    _p9_patch(_hosts108, "_r25b_close_added_ssh_rule", lambda *a, **k: None)
    _p9_patch(_hosts108, "_restart_ssh_listener", lambda *a, **k: calls.append("restart"))
    _p9_patch(_hosts108, "_sshd_holds_port", lambda *a, **k: (True, ""))
    _p9_patch(_hosts108, "_point_f2b_sshd_at", lambda *a, **k: ("updated", ""))
    _p9_patch(_hosts108, "_tcp_reachable", lambda *a, **k: True)
    return dropin


def _ssh_move108(layout, socket_mode, new_port, bind=""):
    """change_ssh_port on a stand-in remote: (ok, message, calls, the drop-in's text or None)."""
    root = _root108(layout)
    calls = []
    try:
        dropin = _ssh_stage108(root, socket_mode, calls)
        ok, msg = _hosts108.change_ssh_port(NS(id=-10801, name="p108", host="p108.example.invalid", port=22,
                                               is_local=False, auth_method="key"), new_port, bind)
        text = open(dropin, encoding="utf-8").read() if os.path.isfile(dropin) else None
        return ok, str(msg), calls, text
    finally:
        _shutil108.rmtree(root, ignore_errors=True)


def _ssh_port108():
    moved = _ssh_move108("systemd", True, 2222)
    check("ssh port: on a socket-activated remote with no ssh.socket.d (stock 24.04), a move 22 -> 2222 "
          "writes the drop-in through the rendered remote command and succeeds (the write failed and the "
          "move was reverted as \"sshd didn't come up\")",
          moved[0] is True and "ListenStream=0.0.0.0:2222" in (moved[3] or ""), repr(moved[:3]))
    bind = _ssh_move108("blocked", True, 22, _V6_108)
    check("ssh port: a bind change on the current port whose drop-in could not be written is refused "
          "saying so, before sshd -t or any restart (it reported \"SSH now listens on <ip>:22, and only "
          "there\" with nothing written), and the snapshot is restored",
          all((bind[0] is False, "could not be written" in bind[1], "sshd-validate" not in bind[2],
               "restart" not in bind[2], "sshd-socket-restore" in bind[2])), repr(bind[:3]))
    plain = _ssh_move108("blocked", False, 2222)
    check("ssh port: ...and an sshd_config remote whose drop-in could not be written says so too, not "
          "\"sshd didn't come up\" (nothing restarted)",
          all((plain[0] is False, "could not be written" in plain[1], "restart" not in plain[2],
               "sshd-restore-dropin" in plain[2])), repr(plain[:3]))
    ok_plain = _ssh_move108("systemd", False, 2222)
    check("ssh port: ...a written sshd_config drop-in still moves the port (control)",
          ok_plain[0] is True and "Port 2222" in (ok_plain[3] or ""), repr(ok_plain[:3]))


def _gmod_host108():
    """A host row with a panel CS:S server whose account is `p108css`: the host's id."""
    with _p9.app_context():
        host = RemoteServer(name="p108-host", host="p108-g.example.invalid", port=22, username="admin",
                            auth_method="key", auth_credential="", is_online=True)
        db.session.add(host)
        db.session.commit()
        _mine108["hosts"].append(host.id)
        gs = GameServer(remote_id=host.id, name="p108 CS:S", short_name="p108css", game_type="css",
                        port=27108, installed=True, status="offline")
        db.session.add(gs)
        db.session.commit()
        _mine108["servers"].append(gs.id)
        return host.id


def _said108(got, text):
    """The refusal's message for one case ("" when there was none) holds `text`."""
    return text in ((got or (None, ""))[1] or "")


def _gmod_held108():
    """A server-only admin's mount of content held only by a panel server's account, on any ordering."""
    rid = _gmod_host108()
    scan = {"lines": ""}
    _p9_patch(_p9_core, "run_privileged", lambda server, verb, args=(), **k: (
        (scan["lines"], "", 0) if verb == "content-scan" else ("", "p108: unexpected verb", 1)))
    _p9_patch(_p9_core, "run_command", lambda server, cmd, **k: ("p108grp\n", "", 0) if "id -gn" in cmd
              else ("", "p108: unexpected command", 1))
    _p9_patch(_p9_sf, "current_user", NS(is_superadmin=False))
    _p9_patch(_p9_sf, "can_access_remote", lambda user, remote_id: False)
    got = {}
    with _p9.test_request_context("/"), _p9.app_context():
        remote = db.session.get(RemoteServer, rid)
        for case, lines in (
                # The panel's content account holds MORE games than the server's account does.
                ("box holds more", "HIT|p108css|cstrike\nHIT|p108box|tf\nHIT|p108box|hl2mp\n"),
                ("server holds more", "HIT|p108css|cstrike\nHIT|p108css|tf\nHIT|p108box|hl2mp\n"),
                ("nobody holds it", "HIT|p108box|tf\nHIT|p108box|hl2mp\n"),
                # Another non-server account holds it too, so "only a server's account" would be false.
                ("also elsewhere", "HIT|p108css|cstrike\nHIT|p108box|tf\nHIT|p108box|hl2mp\n"
                                   "HIT|p108alt|cstrike\n")):
            scan["lines"] = lines
            r = _p9_sf._sf_gmod_host_refusal(NS(remote_id=rid, name="p108 GMod"), remote, "mount", ["cstrike"])
            got[case] = (r[1], (r[0].get_json() or {}).get("message", "")) if r else None
    _only = "Only a panel server's own account on this host holds Counter-Strike: Source"
    check("GMod content: content held only in a panel server's account is named so whichever account holds "
          "the most games (with the content account holding two others it said 'Not on this host yet')",
          all((got[c] or (0,))[0] == 403 and _said108(got[c], _only)
              for c in ("box holds more", "server holds more")), repr(got))
    check("GMod content: ...and a game no account holds is still 'Not on this host yet' (control)",
          _said108(got["nobody holds it"], "Not on this host yet"),
          repr(got["nobody holds it"]))
    check("GMod content: ...and a game another account holds as well is never said to be held ONLY in a "
          "panel server's account",
          got["also elsewhere"] is not None and not _said108(got["also elsewhere"], _only),
          repr(got["also elsewhere"]))


def _audit108(action):
    with _p9.app_context():
        return [NS(detail=a.detail or "", success=a.success)
                for a in AuditLog.query.filter_by(action=action).order_by(AuditLog.id).all()]


_ONE108 = "203.0.113.5"  # NOSONAR(S1313) - a documentation address in a stand-in ufw rule, never dialled
_UFW_HEAD108 = ("Status: active\n\nTo                         Action      From\n"
                "--                         ------      ----\n")


def _ufw108(rules):
    """A stand-in ufw over `rules` [(to, v6, action, source)], the list edited in place: (run_privileged, calls).

    Answers what ufw 0.36 answers (measured on Ubuntu 24.04): a by-spec `delete allow proto tcp to any port
    N` removes only `N/tcp ALLOW Anywhere`, says "Rule deleted[ (v6)]" or "Could not delete non-existent
    rule[ (v6)]" per family and exits 0 either way; `allow proto tcp to any port N` adds both families;
    `allow from 0.0.0.0/0` (or ::/0) adds that family's rule alone, listed "Anywhere".
    """
    calls = []

    def add(rule):
        if rule not in rules:
            rules.append(rule)

    def status():
        tail = {False: "", True: " (v6)"}
        return _UFW_HEAD108 + "".join(
            "%-27s%-12s%s\n" % (to + tail[v6], action, src + (tail[v6] if src == "Anywhere" else ""))
            for to, v6, action, src in rules)

    def deleted(args):
        said = []
        for v6, tail in ((False, ""), (True, " (v6)")):
            rule = (args[1] + "/tcp", v6, "ALLOW", "Anywhere")
            said.append(("Rule deleted" if rule in rules else "Could not delete non-existent rule") + tail)
            if rule in rules:
                rules.remove(rule)
        return "\n".join(said) + "\n"

    def allowed(args):
        for v6 in (False, True):
            add((args[1] + "/tcp", v6, "ALLOW", "Anywhere"))
        return "Rule added\nRule added (v6)\n"

    def allowed_from(args):
        v6 = ":" in args[0]
        add((args[1] + "/tcp", v6, "ALLOW", "Anywhere" if args[0] in ("0.0.0.0/0", "::/0") else args[0]))
        return "Rule added" + (" (v6)" if v6 else "") + "\n"

    verbs = {"ufw-status": lambda args: status(), "ufw-allow-proto-port": allowed,
             "ufw-delete-allow-proto-port": deleted, "ufw-allow-from-port": allowed_from}

    def run(server, verb, args=(), **k):
        args = [str(a) for a in args]
        calls.append((verb, args))
        if verb not in verbs:
            return "", "p108: unexpected verb " + verb, 1
        return verbs[verb](args), "", 0
    return run, calls


def _change_port108(client, cfg_bind, restart_ok, rules=None):
    """POST a panel port move 5000 -> 5077 from `cfg_bind`: (reply, ufw verbs run, fail2ban ports, 5000's rules).

    Against a stand-in ufw holding `rules` (default: 5000/tcp open to everyone in both families); the
    rules returned are 5000's after the move.
    """
    f2b = []
    rules = [("5000/tcp", v6, "ALLOW", "Anywhere") for v6 in (False, True)] if rules is None else list(rules)
    run, calls = _ufw108(rules)
    _p9_patch(_p9_core, "run_privileged", run)
    _p9_patch(_p9_so, "ensure_panel_fail2ban", lambda log, port, wl=None: f2b.append(int(port)) or (True, "jail"))
    _p9_patch(_p9_so, "panel_fail2ban_status", lambda: {"installed": True})
    _p9_patch(_p9_so, "restart_panel", lambda *a, **k: (True, "scheduled") if restart_ok
              else (False, "Could not restart the panel"))
    _p9_patch(_p9_so, "port_in_use", lambda port: False)
    _p9_patch(_p9_so, "record_panel_port", lambda port: (True, ""))
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), port=5000, bind_host=cfg_bind, tailscale_setup_done=True))
    r = client.post("/api/panel/change-port", json={"port": 5077, "bind_host": cfg_bind})
    return _p9_json(r), calls, f2b, sorted(x[1:] for x in rules if x[0] == "5000/tcp")


def _opened108(calls, port):
    """The ufw verbs that ADDED a rule for `port`."""
    return [c for c in calls if c[0].startswith("ufw-allow") and str(port) in c[1]]


# 5000's rules before a move whose restart fails, and so after it: the rollback puts back exactly what the
# move's close removed. (to, v6, action, source) as the stand-in ufw keeps them.
_KEEP108 = (
    ("open to everyone over both families", [("5000/tcp", v6, "ALLOW", "Anywhere") for v6 in (False, True)]),
    ("open to everyone over IPv4 only", [("5000/tcp", False, "ALLOW", "Anywhere")]),
    ("open to everyone over IPv6 only", [("5000/tcp", True, "ALLOW", "Anywhere")]),
    ("closed (the panel's own 'Close the panel's public port')", []),
    ("open only from one address", [("5000/tcp", False, "ALLOW", _ONE108)]),
    ("rate limited (LIMIT)", [("5000/tcp", v6, "LIMIT", "Anywhere") for v6 in (False, True)]),
)


def _panel_port108(client):
    n0 = len(_audit108("panel_restart"))
    failed, calls, f2b, after = _change_port108(client, _ANY108, False)
    rows = _audit108("panel_restart")[n0:]
    check("panel port: a move whose restart could not be scheduled puts the old port's rule back after "
          "removing it, and points the login jail back at it (the panel still listens there, and UFW "
          "dropped it: nothing in the panel could then be reached to restart it)",
          all((failed.get("success") is False, ("ufw-delete-allow-proto-port", ["tcp", "5000"]) in calls,
               after == [(False, "ALLOW", "Anywhere"), (True, "ALLOW", "Anywhere")],
               f2b[-1:] == [5000], "Put the rule for 5000 back" in str(failed.get("message")),
               [r.detail.count("old rule for 5000 put back") for r in rows] == [1])),
          repr((failed, calls, f2b, after, rows)))
    got = {}
    for case, before in _KEEP108:
        reply, calls, _f, after = _change_port108(client, _ANY108, False, before)
        got[case] = (after == sorted(x[1:] for x in before), _opened108(calls, 5000), after, reply.get("message"))
    check("panel port: ...and puts back exactly the rules the move removed, never one the host did not have: "
          "a port already closed, open from one address only, or rate limited gets no public ALLOW, and an "
          "IPv4-only (or IPv6-only) rule comes back without its other-family twin",
          all(g[0] for g in got.values()), repr(got))
    check("panel port: ...and a port whose rule the move did not remove gets no ufw allow at all, nor a "
          "reply saying it was put back",
          all(not got[c][1] and "Put the rule" not in str(got[c][3]) for c, _b in _KEEP108[3:]),
          repr({c: got[c] for c, _b in _KEEP108[3:]}))
    loop, calls_l, _f, after_l = _change_port108(client, "127.0.0.1", False, [])
    check("panel port: ...a loopback-bound panel (reached through Serve) with no rule for its old port gets "
          "none from that (ufw answers 0 to removing one that is not there) (control)",
          loop.get("success") is False and not _opened108(calls_l, 5000) and after_l == [],
          repr((loop, calls_l)))
    done, calls_d, f2b_d, after_d = _change_port108(client, _ANY108, True)
    check("panel port: ...and a move whose restart was scheduled leaves the old port closed and the jail "
          "on the new one (control)",
          all((done.get("success") is True, not _opened108(calls_d, 5000), after_d == [], f2b_d == [5077])),
          repr((done, calls_d, f2b_d)))


def _close_panel_port108(client):
    _p9_patch(_rv108, "remote_ufw_status", lambda remote: {"installed": True, "unreachable": True, "groups": []})
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), port=5000, tailscale_setup_done=True))
    n0 = len(_audit108("close_panel_port"))
    r = client.post("/api/remote/%d/close-panel-port" % P9_LOCAL)
    rows = _audit108("close_panel_port")[n0:]
    check("close panel port: refused because the firewall could not be read, the attempt is audited as a "
          "failed close_panel_port row like its sibling refusals (it left /logs with no trace)",
          _p9_json(r).get("success") is False and [(a.success, a.detail) for a in rows]
          == [(False, "firewall could not be read")], repr((_p9_json(r), [(a.success, a.detail) for a in rows])))


def _os_update_es108():
    """The OS-update start routes answer in the viewer's language (integration item, review 1017a).

    run-updates, os-update/start (the OS Updates card, the panel host's card too) and the panel
    host's os-update-run returned hosts.py's / system_ops' English as it was: an es or fr API
    caller read English. Driven through the real start functions; only the verb answers are stubbed.
    """
    with _p9.app_context():
        u = db.session.get(User, P9_ADMIN)
        lang0 = u.language
        u.language = "es"
        db.session.commit()
    try:
        # apt-upgrade-running: nothing running (rc 1); os-update-run: no STARTED marker → refused.
        _p9_patch(_p9_core, "run_privileged", lambda server, verb, args=(), **k: ("", "", 1))
        _p9_patch(_p9_so, "_can_escalate", lambda: True)
        _p9_patch(_p9_so, "_run_verb", lambda verb, args=(), **k: ("", "", 1))
        c = _p9_client(P9_ADMIN)
        want = "No se pudo iniciar la actualización."
        for name, url in (("run-updates", "/api/remote/%d/run-updates" % P9_LOCAL),
                          ("os-update/start", "/api/remote/%d/os-update/start" % P9_LOCAL),
                          ("os-update-run", "/api/server-management/os-update-run")):
            r = c.post(url)
            got = (_p9_json(r) or {}).get("message")
            check("OS update start: %s answers an es viewer in Spanish (it returned the start "
                  "function's English as it was)" % name, got == want,
                  "status=%s message=%r" % (r.status_code, got))
    finally:
        with _p9.app_context():
            u = db.session.get(User, P9_ADMIN)
            u.language = lang0
            db.session.commit()


def _cleanup108():
    with _p9.app_context():
        for i in _mine108["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
            GameServer.query.filter_by(id=i).delete()
        for i in _mine108["hosts"]:
            AuditLog.query.filter_by(remote_id=i).delete()
            RemoteServer.query.filter_by(id=i).delete()
        db.session.commit()


_CFG108 = _p9_cfg.load_config()
try:
    _p9_arm(who="part108")
    _write_targets108()
    _ssh_port108()
    _gmod_held108()
    _A108 = _p9_client(P9_ADMIN)
    _panel_port108(_A108)
    _close_panel_port108(_A108)
    _os_update_es108()
finally:
    _p9_restore_all()
    _p9_cfg.save_config(_CFG108)
    _cleanup108()

check("part108: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP108_START, repr(_P9_TRIPPED[_TRIP108_START:][:6]))
