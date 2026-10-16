"""Part 98 of the unit suite: the fifteenth review's ssh_manager and route fixes (review 1016c, builder B).

* On a socket-activated host the panel reaches over Tailscale SSH, the row's port stays 22 after a
  move, so it no longer names the port sshd serves: a second move dropped the first one's port
  from ssh.socket while saying "the previous port is still available". sshd's ports are read from
  systemd's ssh.socket, and the host page's SSH port card shows them.

HOW IT RUNS. Stand-ins behind run_privileged/run_command, and routes on part12's app with
recorders. Nothing reaches a host, sudo or the checkout's data/.
"""
import importlib.machinery as _mach98
import importlib.util as _ilu98
import os as _os98
from types import SimpleNamespace as NS

from sqlalchemy.exc import OperationalError as _OpErr98

from unit.part01 import _root as _root98, check
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core, _p9_json, _p9_ms, _p9_patch,
                         _p9_restore_all, _p9_sd, _p9_sf, _p9_sm)
from panel.core import i18n as _i18n98
from panel.core.panel_state import _install_jobs as _jobs98, _install_lock as _jlock98
from panel.db.models import AuditLog, CustomCommand, GameServer, RemoteServer, User, db
from panel.ops import system_ops as _so98
from panel.ops.ssh_manager import cron as _cron98, firewall as _fw98, hosts as _hosts98
from panel.security import auth as _auth98, privileged as _priv98

_TRIP98_START = len(_P9_TRIPPED)
_mine98 = {"hosts": [], "servers": [], "users": [], "cmds": []}


def _setup98():
    with _p9.app_context():
        ts = RemoteServer(name="p98-ts", host="p98-ts.example.invalid", port=22, username="admin",
                          auth_method="tailscale", auth_credential="", is_online=True)
        key = RemoteServer(name="p98-key", host="p98-key.example.invalid", port=22, username="admin",
                           auth_method="key", auth_credential="", is_online=True)
        admin = User(username="p98_admin", password_hash=_auth98.hash_password("Str0ng!passw0rd-p98"),
                     display_name="p98 admin", is_superadmin=True, is_active=True)
        db.session.add_all([ts, key, admin])
        db.session.commit()
        _mine98["hosts"] += [ts.id, key.id]
        _mine98["users"].append(admin.id)
        return ts.id, key.id, admin.id


def _new_server98(rid, short, **kw):
    with _p9.app_context():
        gs = GameServer(remote_id=rid, name=short, short_name=short, game_type="css", port=27098,
                        installed=kw.pop("installed", False), status=kw.pop("status", "failed"), **kw)
        db.session.add(gs)
        db.session.commit()
        _mine98["servers"].append(gs.id)
        return gs.id


def _cleanup98():
    with _p9.app_context():
        for i in _mine98["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
        for i in _mine98["hosts"]:
            AuditLog.query.filter_by(remote_id=i).delete()
        AuditLog.query.filter(AuditLog.username.like("p98%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((CustomCommand, "cmds"), (GameServer, "servers"), (User, "users"),
                           (RemoteServer, "hosts")):
            for i in _mine98[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
        db.session.commit()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. sshd's ports on a socket-activated host are read from ssh.socket, not from the row
# ════════════════════════════════════════════════════════════════════════════════════════════════
# What systemd prints for ssh.socket after the first move (22 -> 2222): both families on each port.
_SHOW98 = ("ActiveState=active\nListen=0.0.0.0:2222 (Stream)\nListen=[::]:2222 (Stream)\n"
           "Listen=0.0.0.0:22 (Stream)\nListen=[::]:22 (Stream)\n")


def _second_move98(show):
    """Move a Tailscale-SSH row (port 22) to 3333 on a socket-activated host: (drop-in, answer).

    Its ssh.socket answers `show`: a (stdout, stderr, rc), or an exception to raise.
    """
    written = []

    def _priv(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, **k):
        if verb == "sshd-socket-active":
            return ("active\n", "", 0)
        if verb == "sshd-effective-config":
            return ("port 22\n", "", 0)          # sshd_config's Port: ignored under the socket
        if verb == "listening-sockets":
            return ("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\n", "", 0)
        if verb == "ufw-status":
            return ("Status: inactive\n", "", 0)
        if verb == "sshd-validate":
            return ("", "p98 stops here", 1)
        return ("", "", 0)

    def _rc(server, cmd, timeout=30, sudo=None, stdin_text=None):
        if "systemctl show ssh.socket" not in cmd:
            return ("", "p98: unexpected command", 1)
        if isinstance(show, Exception):
            raise show
        return show
    _p9_patch(_p9_core, "run_privileged", _priv)
    _p9_patch(_p9_core, "run_command", _rc)
    _p9_patch(_p9_core, "write_root_file", lambda server, target, body, **k: written.append((target, body)))
    _p9_patch(_hosts98, "_restart_ssh_listener", lambda *a, **k: None)
    _p9_patch(_hosts98, "remote_ufw_open_port", lambda *a, **k: (True, "opened"))
    res = _hosts98.change_ssh_port(NS(id=-9801, name="p98", host="p98-ts.example.invalid", port=22,
                                      is_local=False, auth_method="tailscale"), 3333)
    bodies = [b for t, b in written if t == "sshd-socket-dropin"]
    return (bodies[0] if bodies else ""), res


def _listens98(body):
    return sorted({ln.rpartition(":")[2] for ln in body.splitlines() if ln.startswith("ListenStream=")
                   and ln != "ListenStream="})


def _socket_second_move98():
    got = {"read": _listens98(_second_move98((_SHOW98, "", 0))[0]),
           "unread": _listens98(_second_move98(("", "Failed to connect to bus", 1))[0]),
           "raised": _listens98(_second_move98(OSError("p98: transport down"))[0]),
           "inactive": _listens98(_second_move98(("ActiveState=inactive\nListen=[::]:2222 (Stream)\n",
                                                  "", 0))[0])}
    check("ssh port: a second move on a socket-activated host the panel reaches over Tailscale SSH "
          "(row port 22, sshd -T says 22) keeps the first move's port 2222 in the ssh.socket drop-in, "
          "read from systemd (it was dropped, under \"the previous port is still available\"); an "
          "unread, raising or inactive ssh.socket keeps the old answer (controls)",
          got == {"read": ["22", "2222", "3333"], "unread": ["22", "3333"], "raised": ["22", "3333"],
                  "inactive": ["22", "3333"]}, repr(got))


# The adversarial review's F3: with sshd moved off 22 under socket activation, `sshd -T` still prints
# `port 22`. Unioned in, that counted as served, so a leftover `22/tcp ALLOW` read as another way in
# and the rule for the port sshd really serves could be marked warn and deleted.
def _r26j_served98(show, sshd_t="port 22\n", stored=2222):
    """(_sshd_current_ports, _fwssh_served_ports, protected_host_ports) for one host."""
    _p9_patch(_p9_core, "run_privileged", lambda server, verb, args=(), **k: (
        (sshd_t, "", 0) if verb == "sshd-effective-config" else ("", "p98: unread", 1)))
    _p9_patch(_p9_core, "run_command", lambda server, cmd, **k: (
        show if "systemctl show ssh.socket" in cmd else ("", "p98: unexpected command", 1)))
    _p9_patch(_fw98, "_panel_web_port", lambda server: None)
    srv = NS(id=-9810, name="p98", host="p98-key.example.invalid", port=stored, is_local=False,
             auth_method="key")
    return (_hosts98._sshd_current_ports(srv), sorted(_fw98._fwssh_served_ports(srv)),
            sorted(_hosts98.protected_host_ports(srv)))


def _r26j_socket_replaces98():
    sock = ("ActiveState=active\nListen=0.0.0.0:2222 (Stream)\nListen=[::]:2222 (Stream)\n", "", 0)
    got = {"socket": _r26j_served98(sock),
           "socket, sshd_config elsewhere": _r26j_served98(sock, sshd_t="port 2022\n"),
           "inactive": _r26j_served98(("ActiveState=inactive\nListen=0.0.0.0:2222 (Stream)\n", "", 0),
                                      stored=22),
           "unread": _r26j_served98(("", "Failed to connect to bus", 1), stored=22)}
    check("ssh ports: on a socket-activated host ssh.socket's ports REPLACE `sshd -T`'s (it still says "
          "22 after sshd moved off it, so a leftover 22/tcp ALLOW counted as another way in and the "
          "served port's rule lost its protection, and sshd_config's ignored port was kept from game "
          "servers); an inactive or unread socket reads `sshd -T` (controls). The move's drop-in still "
          "keeps both (the socket second-move check)",
          got == {"socket": (["2222"], [2222], [22, 2222]),
                  "socket, sshd_config elsewhere": (["2222"], [2222], [22, 2222]),
                  "inactive": (["22"], [22], [22]),
                  "unread": (["22"], [22], [22])}, repr(got))


def _socket_parse98():
    def ports(out, rc=0):
        _p9_patch(_p9_core, "run_command", lambda *a, **k: (out, "", rc))
        return _hosts98._r26b_socket_ports(NS(id=-9802))
    got = {"both families": ports(_SHOW98),
           "bound": ports("ActiveState=active\nListen=[fd00::5]:2022 (Stream)\nListen=203.0.113.5:2022 (Stream)\n"),
           "datagram and junk": ports("ActiveState=active\nListen=0.0.0.0:53 (Datagram)\nListen=/run/x (Stream)\n"
                                      "Listen=0.0.0.0:99999999 (Stream)\nListen=0.0.0.0:2022 (Stream)\n"),
           "inactive": ports("ActiveState=inactive\nListen=0.0.0.0:22 (Stream)\n"),
           "failed": ports("ActiveState=active\nListen=0.0.0.0:22 (Stream)\n", rc=1)}
    check("ssh port: ssh.socket's ports are its TCP listeners while it is active (both families once, "
          "a bound address, no datagram, path or out-of-range entry); inactive or unread is None",
          got == {"both families": ["2222", "22"], "bound": ["2022"], "datagram and junk": ["2022"],
                  "inactive": None, "failed": None}, repr(got))


def _ssh_port_card98(client, ts_rid, key_rid):
    def _priv(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, **k):
        if verb == "ufw-status":
            return ("Status: active\n\nTo                         Action      From\n--                         "
                    "------      ----\n22/tcp                     LIMIT       Anywhere\n", "", 0)
        if verb == "sshd-effective-config":
            return ("port 22\n", "", 0)
        return ("", "", 0)
    _p9_patch(_p9_core, "run_privileged", _priv)
    _p9_patch(_p9_core, "run_command", lambda *a, **k: (_SHOW98, "", 0))
    d_ts = _p9_json(client.get("/api/remote/%d/ssh-status" % ts_rid))
    d_key = _p9_json(client.get("/api/remote/%d/ssh-status" % key_rid))
    _p9_patch(_p9_core, "run_command", lambda *a, **k: ("", "", 1))
    d_plain = _p9_json(client.get("/api/remote/%d/ssh-status" % ts_rid))
    page_ts = client.get("/remote/%d/manage" % ts_rid).get_data(as_text=True)
    page_key = client.get("/remote/%d/manage" % key_rid).get_data(as_text=True)
    check("ssh port card: on a host the panel reaches over Tailscale SSH, ssh-status reports the ports "
          "sshd serves (ssh.socket's, or sshd -T's when the socket is not in use) and the card shows "
          "those, not the row's 22; a key-auth host keeps its stored port (control)",
          d_ts.get("sshd_ports") == [2222, 22] and d_plain.get("sshd_ports") == [22]
          and "sshd_ports" not in d_key and d_ts.get("mode") == "limit"
          and 'id="ssh-port-now"' in page_ts and 'id="ssh-port-now"' not in page_key
          and "Currently: <code>22</code>" in page_key,
          repr((d_ts, d_key, d_plain)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A bind change on a Tailscale-SSH host is not checked by dialling the tailnet address
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _bind_move98(auth):
    """Move sshd to 203.0.113.5:2222 on a remote reached by `auth`: (ok, dialled, reverted)."""
    state = {"written": False, "dialled": [], "restored": False}

    def _priv(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, **k):
        if verb == "sshd-socket-active":
            return ("inactive\n", "", 3)
        if verb == "sshd-effective-config":
            return ("port 22\n", "", 0)
        if verb == "listening-sockets":
            new = "LISTEN 0 128 203.0.113.5:2222 0.0.0.0:*\n" if state["written"] else ""
            return ("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n" + new, "", 0)
        if verb == "sshd-restore-dropin":
            state["restored"] = True
        if verb in ("ufw-status", "listening-sockets-owner"):
            return ("", "p98: unread", 1)
        return ("", "", 0)
    _p9_patch(_p9_core, "run_privileged", _priv)
    _p9_patch(_p9_core, "run_command", lambda *a, **k: ("", "", 1))
    _p9_patch(_p9_core, "write_root_file", lambda *a, **k: state.update(written=True))
    _p9_patch(_hosts98, "_restart_ssh_listener", lambda *a, **k: None)
    _p9_patch(_hosts98, "remote_ufw_open_port", lambda *a, **k: (True, "opened"))
    _p9_patch(_hosts98, "_point_f2b_sshd_at", lambda server, ports: ("updated", ""))
    _p9_patch(_hosts98, "_tcp_reachable", lambda host, port, timeout=8: state["dialled"].append(host) and False)
    ok, _msg = _hosts98.change_ssh_port(NS(id=-9803, name="p98", host="100.64.0.10", port=22,
                                           is_local=False, auth_method=auth), 2222, "203.0.113.5")
    return ok, state["dialled"], state["restored"]


def _ts_bind98():
    got = {"tailscale": _bind_move98("tailscale"), "key": _bind_move98("key")}
    check("ssh bind: on a host the panel reaches over Tailscale SSH, binding sshd to the public "
          "address is confirmed by sshd listening there, not by dialling the tailnet address on the "
          "new port (every such bind was reverted as \"not the address the panel connects to\"); a "
          "key-auth host still must be reachable there (control)",
          got == {"tailscale": (True, [], False), "key": (False, ["100.64.0.10"], True)}, repr(got))


# The adversarial review's F2: under socket activation systemd binds an address the host does not
# have (in name), so on a Tailscale-SSH remote, which step 6 does not dial, nothing caught it.
_R26J_ADDRS98 = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
                 "2: eth0    inet 203.0.113.5/24 brd 203.0.113.255 scope global eth0\\       valid_lft forever\n"
                 "2: eth0    inet6 2001:db8::5/64 scope global \\       valid_lft forever\n")


def _r26j_socket_bind98(addr, ip_out, ip_rc=0):
    """Bind sshd to `addr`:2222 on a socket-activated Tailscale-SSH remote: (ok, wrote, asked ip)."""
    state = {"written": False, "ip": 0}

    def _priv(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True, **k):
        if verb == "sshd-socket-active":
            return ("active\n", "", 0)
        if verb == "sshd-effective-config":
            return ("port 22\n", "", 0)
        if verb == "listening-sockets":
            # systemd creates the socket for ANY address, so the listing shows it either way.
            new = ("LISTEN 0 4096 %s:2222 0.0.0.0:*\n" % ("[%s]" % addr if ":" in addr else addr)
                   if state["written"] else "")
            return ("LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n" + new, "", 0)
        if verb in ("ufw-status", "listening-sockets-owner"):
            return ("", "p98: unread", 1)
        return ("", "", 0)

    def _cmd(server, cmd, **k):
        if "ip -o addr show" in cmd:
            state["ip"] += 1
            return ip_out, "", ip_rc
        return ("", "", 1)
    _p9_patch(_p9_core, "run_privileged", _priv)
    _p9_patch(_p9_core, "run_command", _cmd)
    _p9_patch(_p9_core, "write_root_file", lambda *a, **k: state.update(written=True))
    _p9_patch(_hosts98, "_restart_ssh_listener", lambda *a, **k: None)
    _p9_patch(_hosts98, "remote_ufw_open_port", lambda *a, **k: (True, "opened"))
    _p9_patch(_hosts98, "_point_f2b_sshd_at", lambda server, ports: ("updated", ""))
    _p9_patch(_hosts98, "_tcp_reachable", lambda host, port, timeout=8: False)
    ok, msg = _hosts98.change_ssh_port(NS(id=-9809, name="p98", host="100.64.0.10", port=22,
                                          is_local=False, auth_method="tailscale"), 2222, addr)
    return ok, state["written"], state["ip"], str(msg)


def _r26j_ts_socket_bind98():
    got = {"has it": _r26j_socket_bind98("203.0.113.5", _R26J_ADDRS98),
           "has it, v6": _r26j_socket_bind98("2001:db8::5", _R26J_ADDRS98),
           "not its own": _r26j_socket_bind98("192.0.2.99", _R26J_ADDRS98),
           "unread": _r26j_socket_bind98("203.0.113.5", "", ip_rc=1),
           "nothing listed": _r26j_socket_bind98("203.0.113.5", "")}
    check("ssh bind on a socket-activated Tailscale-SSH remote: an address the host does not have is "
          "refused before anything is written (systemd bound it in name, the address check passed and "
          "the move reported success with SSH answering nowhere), and so is one whose host list could "
          "not be read; the host's own v4 and v6 addresses still bind (control)",
          [v[:3] for v in got.values()] == [(True, True, 1), (True, True, 1), (False, False, 1),
                                           (False, False, 1), (False, False, 1)]
          and got["not its own"][3].startswith("192.0.2.99 isn't an address on this host")
          and got["unread"][3].startswith("Could not list this host's addresses")
          and got["nothing listed"][3] == got["unread"][3], repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A delete that removed nothing, read back from an inactive or unreadable firewall
# ════════════════════════════════════════════════════════════════════════════════════════════════
_NOTHING98 = "Could not delete non-existent rule\nCould not delete non-existent rule (v6)"
_INACTIVE98 = ("Status: inactive\n", "", 0)
_UNREAD98 = ("", "ufw: permission denied", 1)
_LISTED98 = ("Status: active\n\nTo                         Action      From\n--                         "
             "------      ----\n22/tcp                     LIMIT       Anywhere\n", "", 0)


def _close_inactive98():
    def close(delete_out, status):
        _p9_patch(_p9_core, "run_privileged", lambda server, verb, args=(), timeout=30, **k: (
            status if verb == "ufw-status" else (delete_out, "", 0)))
        ok, msg = _hosts98.remote_ufw_close_port(NS(id=-9804, name="p98"), 27098, "tcp", force=True)
        return ok, str(msg)
    got = {"nothing, inactive": close(_NOTHING98, _INACTIVE98), "nothing, unread": close(_NOTHING98, _UNREAD98),
           "removed, inactive": close("Rule deleted\nRule deleted (v6)", _INACTIVE98),
           "nothing, listed closed": close(_NOTHING98, _LISTED98)}
    check("close port: a delete that removed nothing on a host whose UFW is inactive is refused saying "
          "UFW is not active (it said the firewall \"could not be read back\" about a host that answered); "
          "an unread one still says that, and a removed rule or a listing showing it closed is closed "
          "(controls)",
          not got["nothing, inactive"][0] and "UFW is not active" in got["nothing, inactive"][1]
          and "could not be read back" not in got["nothing, inactive"][1]
          and not got["nothing, unread"][0] and "could not be read back" in got["nothing, unread"][1]
          and got["removed, inactive"][0] and got["nothing, listed closed"][0], repr(got))


def _unblock98():
    ip = "198.51.100.98"

    def remote(delete_out, status):
        _p9_patch(_p9_core, "run_privileged", lambda server, verb, args=(), timeout=30, **k: (
            status if verb == "ufw-status" else (delete_out, "", 0)))
        ok, msg = _hosts98.remote_ufw_undeny_ip(NS(id=-9805, name="p98"), ip)
        return ok, str(msg)

    def local(delete_out, status):
        _p9_patch(_so98, "_run_verb",
                  lambda verb, args=(), timeout=30, **k: status if verb == "ufw-status" else (delete_out, "", 0))
        ok, msg = _so98.ufw_undeny_ip(ip)
        return ok, str(msg)
    got = {}
    for host, fn in (("remote", remote), ("panel host", local)):
        got[host] = {"nothing, unread": fn(_NOTHING98, _UNREAD98),
                     "nothing, inactive": fn(_NOTHING98, _INACTIVE98),
                     "removed, unread": fn("Rule deleted\nRule deleted (v6)", _UNREAD98),
                     "nothing, listed": fn(_NOTHING98, _LISTED98)}
    want = {"nothing, unread": False, "nothing, inactive": False, "removed, unread": True, "nothing, listed": True}
    check("unblock: on a remote and on the panel host, a delete that matched no deny rule with no "
          "listing to read back (unreadable, or UFW inactive) is not \"Unblocked\" (a REJECT or a "
          "port-scoped deny went on blocking the address); a removed rule, or a listing without the "
          "address, still is (controls)",
          all({k: v[0] for k, v in g.items()} == want for g in got.values())
          and all("nothing was removed" in g["nothing, unread"][1] for g in got.values()), repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. A retry keeps step 1's promise to leave a found account alone
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _unconfirmed_row98(rid, short):
    """A failed row recorded as step 1's UNCONFIRMED refusal records it (retryable)."""
    sid = _new_server98(rid, short)
    _p9_patch(_p9_sm, "read_as_game_user", lambda *a, **k: ("NOTEXISTS\n", "", 0))
    with _p9.app_context():
        gs = db.session.get(GameServer, sid)
        ok, why, retry = _p9_ms._existing_account_verdict(gs.remote, (rid, short), False)
        _p9_ms.record_install_failure(gs, "Preparing user account", why, retry)
        db.session.commit()
    return sid, ok, retry


def _retry_then_fail98(client, rid, short, created):
    """Retry the row, then fail that retry differently: (left after the retry, left after its failure)."""
    sid, ok, retry = _unconfirmed_row98(rid, short)
    _p9_patch(_p9_ms, "threading", NS(Thread=lambda target=None, daemon=None: NS(start=lambda: None)))
    d = _p9_json(client.post("/servers/%d/retry-install" % sid, headers={"X-Requested-With": "XMLHttpRequest"}))
    with _jlock98:
        _jobs98.pop(sid, None)
    with _p9.app_context():
        after_retry = (_p9_ms._r25b_left_account(db.session.get(GameServer, sid)),
                       db.session.get(GameServer, sid).install_error)
        if created:
            _p9_ms._accounts_created.add((rid, short))
        run = _p9_ms._InstallRun(_p9, sid, None)
        run.first_load()
        run.fail("Preparing user account", _i18n98.Sentence(
            "Couldn't check whether an account named '{name}' already exists — the host did not answer. "
            "Nothing was changed on it.", name=short))
        _p9_ms._accounts_created.discard((rid, short))
        gs = db.session.get(GameServer, sid)
        after_fail = (_p9_ms._r25b_left_account(gs), gs.status, "host did not answer" in gs.install_error)
    return sid, (ok, retry, d.get("success"), after_retry, after_fail)


def _said98(d):
    """(success, says the panel did not create it, points at LinuxGSM files) of a Remove answer."""
    msg = d.get("message") or ""
    return d.get("success"), "did not create it" in msg, "LinuxGSM files" in msg


def _retry_marker98(client, rid):
    host = []
    _p9_patch(_p9_ms, "privileged_accounts", lambda remote, users: host.append(("probe", list(users))) or {})
    _p9_patch(_p9_ms, "_stop_game_processes", lambda *a, **k: host.append(("stop",)))
    _p9_patch(_p9_ms, "_close_game_firewall", lambda remote, gs: host.append(("firewall",)) or ([], False))
    _p9_patch(_p9_ms, "_remove_account_crontab", lambda *a, **k: host.append(("crontab",)))
    _p9_patch(_p9_sm, "run_privileged", lambda server, verb, args=(), **k: host.append((verb,)) or ("", "", 0))
    sid, kept = _retry_then_fail98(client, rid, "p98unc", created=False)
    d = _p9_json(client.post("/servers/%d/delete" % sid, headers={"X-Requested-With": "XMLHttpRequest"}))
    check("install retry: a row whose step 1 refused an account it could not confirm it made, retried "
          "and failing differently (the host did not answer), still records that the account is left "
          "alone, and Remove touches nothing on the host and says the panel did not create it (the "
          "marker was lost and Remove ran `userdel -r -f` on the account)",
          (kept, _said98(d), host) == ((False, True, True, (True, ""), (True, "failed", True)),
                                       (True, True, False), []), repr((kept, d, host)))
    _sid2, dropped = _retry_then_fail98(client, rid, "p98own", created=True)
    sid3, _ok, _r = _unconfirmed_row98(rid, "p98fin")
    client.post("/servers/%d/retry-install" % sid3, headers={"X-Requested-With": "XMLHttpRequest"})
    with _jlock98:
        _jobs98.pop(sid3, None)
    with _p9.app_context():
        run = _p9_ms._InstallRun(_p9, sid3, None)
        run.first_load()
        run.finish("ok")
        gs = db.session.get(GameServer, sid3)
        finished = (gs.install_error_i18n, _p9_ms._r25b_left_account(gs))
    check("install retry: ...while a retry in which this process created the account drops it (it is "
          "the panel's to remove), and an install that finishes clears the record (controls)",
          dropped[4] == (False, "failed", True) and finished == (None, False), repr((dropped, finished)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The JSON routes: an audit row that cannot be written is not the action failing
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _locked98(*a, **k):
    raise _OpErr98("INSERT INTO audit_log", {}, Exception("database is locked"))


# A send and a custom command whose row raised: 200, sent, flagged; with rows written, no flag.
_AUDIT_WANT98 = ((200, True, True), (200, True, True), {"send": (True, None), "custom": (True, None)})


def _sent98(r):
    """(status, success, audit_unwritten, code, message) of a JSON route's answer."""
    d = _p9_json(r)
    return r.status_code, d.get("success"), d.get("audit_unwritten"), d.get("code"), d.get("message") or ""


def _json_audit98(client, rid):
    sid = _new_server98(rid, "p98aud", status="online", installed=True)
    with _p9.app_context():
        cmd = CustomCommand(name="p98say", command_template="say p98", scope_type="all", enabled=True)
        db.session.add(cmd)
        db.session.commit()
        _mine98["cmds"].append(cmd.id)
        cid = cmd.id
    _p9_patch(_p9_sf, "send_console_command", lambda *a, **k: ("", "", 0))
    _p9_patch(_p9_sd, "send_console_command", lambda *a, **k: ("", "", 0))
    ok = {"send": client.post("/api/command/%d" % sid, json={"command": "say p98"}),
          "custom": client.post("/api/server/%d/custom-command/%d" % (sid, cid), json={})}
    _p9_patch(_p9_sd, "log_action", _locked98)
    r_send = client.post("/api/command/%d" % sid, json={"command": "say p98"})
    r_custom = client.post("/api/server/%d/custom-command/%d" % (sid, cid), json={})
    _p9_patch(_p9_sd, "_run_action", _locked98)
    r_action = client.post("/api/server/%d/action" % sid, json={"action": "details"})
    got = {k: _sent98(r) for k, r in (("send", r_send), ("custom", r_custom), ("action", r_action))}
    good = {k: (_p9_json(r_ok).get("success"), _p9_json(r_ok).get("audit_unwritten")) for k, r_ok in ok.items()}
    check("audit: the console's send box and a custom command whose audit row cannot be written (the "
          "database locked) still answer that the command was sent, flagged audit_unwritten (they "
          "answered 500 for a command the game already had); written rows carry no flag (control)",
          (got["send"][:3], got["custom"][:3], good) == _AUDIT_WANT98
          and "Ran 'p98say'." in got["custom"][4], repr((got, good)))
    check("audit: the JSON action route (dashboard, detail page, palette) answers a database error "
          "with the form route's \"may or may not have run\" and a stable code, not a 500 \"request "
          "failed\" — and its failure row raising too changes nothing",
          got["action"] == (200, False, None, "action_unsure", _p9_sd._R25B_ACTION_UNSURE), repr(got["action"]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. Tailscale's and apt's world-readable reads run without sudo
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _sudo_reads98():
    asked, cur = [], ["?"]
    running = '{"BackendState": "Running", "Self": {"TailscaleIPs": ["100.64.0.10"], "DNSName": "n."}}'

    def _rc(server, cmd, timeout=30, sudo="(not passed)", stdin_text=None):
        asked.append((cur[0], cmd.split(" 2>")[0][-40:], sudo))
        if "which tailscale" in cmd:
            return "/usr/bin/tailscale\nINSTALLED\n", "", 0
        if "debug prefs" in cmd:
            return '{"RunSSH": true}', "", 0
        if "tailscale status" in cmd:
            return running, "", 0
        return "", "", 0
    _p9_patch(_p9_core, "run_command", _rc)
    _p9_patch(_p9_core, "run_privileged", lambda *a, **k: ("", "", 0))
    srv = NS(id=-9806, name="p98", host="p98.example.invalid", port=22, is_local=False,
             auth_method="key", sudo_enabled=True, username="admin")
    got = {}
    for name, fn in (("remote_check_tailscale", lambda: _hosts98.remote_check_tailscale(srv)["running"]),
                     ("_tailscale_conn_state", lambda: _hosts98._tailscale_conn_state(srv)),
                     ("tailnet_exempt_ips", lambda: _hosts98.tailnet_exempt_ips(srv, ["100.64.0.10"])),
                     ("remote_os_check_updates", lambda: _hosts98.remote_os_check_updates(srv)["ok"])):
        cur[0] = name
        got[name] = fn()
    bad = [a for a in asked if a[2] is not False]
    check("reads: Tailscale's status, prefs and `which`, and apt's upgradable list run with sudo=False, "
          "so a sudo that wants a password no longer reads as \"unreachable\" or (for the tailnet "
          "exemption) as Tailscale stopped, which let a tailnet address be blocked",
          not bad and got == {"remote_check_tailscale": True, "_tailscale_conn_state": (True, True),
                              "tailnet_exempt_ips": {"100.64.0.10"}, "remote_os_check_updates": True},
          repr((bad, got)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. The headroom prune leaves the archive a running backup is writing
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _prune_running98():
    gone = []
    _p9_patch(_cron98, "delete_game_backup", lambda server, user, name: gone.append(name) or True)
    backups = [{"name": "new.tar.zst", "size": 0, "created": 300, "in_progress": True},
               {"name": "b2.tar.zst", "size": 500, "created": 200},
               {"name": "failed.tar.zst", "size": 0, "created": 150},
               {"name": "b1.tar.zst", "size": 500, "created": 100}]
    n = _cron98._prune_for_headroom(NS(id=-9807), "p98u", backups, 2, 0, 10 ** 9)
    check("backup headroom: the prune deletes failed 0-byte archives and the oldest valid ones, never "
          "the 0-byte archive a backup started outside the panel is still writing (it was \"junk\", "
          "and that backup finished into an unlinked file)",
          gone == ["failed.tar.zst", "b1.tar.zst"] and n == 2, repr((gone, n)))


# The integrator's leftover (review 1016c, B's A03 lead): an inactive UFW lists no rules in `status`,
# so the SSH move's open ran `ufw allow` blind over a stored `port/tcp` LIMIT. The stored rules are
# now read with the read-only `ufw-show-added` verb.
_ADDED98 = "Added user rules (see 'ufw status' for running firewall):\n"


def _inactive_open98(added, added_rc=0, status="Status: inactive\n"):
    asked, opened = [], []

    def run(server, verb, args=(), **k):
        asked.append(verb)
        if verb == "ufw-status":
            return status, "", 0
        if verb == "ufw-show-added":
            return added, ("panel-helper: unknown verb 'ufw-show-added'" if added_rc else ""), added_rc
        return "", "", 0
    _p9_patch(_p9_core, "run_privileged", run)
    _p9_patch(_hosts98, "remote_ufw_open_port",
              lambda s, p, proto, comment="": opened.append((p, proto)) or (True, ""))
    got = _hosts98._open_ssh_port_rule(NS(id=-9808, name="p98"), 2222, ["22"])
    return got, opened, [v for v in asked if v.startswith("ufw-show")]


def _inactive_ufw98():
    kept = {name: _inactive_open98(_ADDED98 + line + "\n") for name, line in (
        ("limit", "ufw limit 2222/tcp"), ("allow, commented", "ufw allow 2222/tcp comment 'mine'"),
        ("allow ahead of a deny", "ufw allow 2222/tcp\nufw deny 2222"))}
    check("ssh port move on a host whose UFW is inactive: a STORED allow or LIMIT for exactly the new "
          "port/tcp (either family: `ufw show added` prints them alike) is the operator's, so nothing "
          "is opened over it (`ufw allow` rewrote a LIMIT into an ALLOW) and nothing is counted as added",
          all(v == ((False, None), [], ["ufw-show-added"]) for v in kept.values()), repr(kept))


def _r26j_inactive_refused98():
    _r26j_refused = {name: _inactive_open98(_ADDED98 + body) for name, body in (
        ("deny in log", "ufw deny in log 2222/tcp\n"), ("reject", "ufw reject 2222/tcp comment 'x'\n"),
        ("bare deny", "ufw limit 22/tcp\nufw deny 2222\n"), ("range", "ufw reject 2200:2300/tcp\n"),
        ("list", "ufw deny 22222,2222/tcp\n"),
        ("deny ahead of an allow", "ufw deny 2222/tcp\nufw allow 2222/tcp\n"))}
    _r26j_rule = {"deny in log": "ufw deny in log 2222/tcp", "reject": "ufw reject 2222/tcp comment 'x'",
                  "bare deny": "ufw deny 2222", "range": "ufw reject 2200:2300/tcp",
                  "list": "ufw deny 22222,2222/tcp", "deny ahead of an allow": "ufw deny 2222/tcp"}
    check("ssh port move on a host whose UFW is inactive: ...a stored DENY or REJECT that a TCP "
          "connection to the new port meets first (exact, bare, a range, a list) refuses the move "
          "with the active firewall's own refusal naming it, nothing opened or counted (it was kept "
          "silently, and the answer said to close the old port)",
          all(v[0][0] is False and v[1] == [] and v[2] == ["ufw-show-added"]
              and str(v[0][1]) == ("Port 2222/tcp is blocked by the firewall rule `%s`, so SSH moved there "
                                   "would be unreachable — remove or change that rule first. Nothing was "
                                   "changed." % _r26j_rule[name])
              for name, v in _r26j_refused.items()), repr(_r26j_refused))


def _r26j_inactive_opened98():
    opened = {name: _inactive_open98(_ADDED98 + body) for name, body in (
        ("none", "(None)\n"), ("other port", "ufw limit 22/tcp\nufw allow 22222/tcp\n"),
        ("both protocols", "ufw allow 2222\n"), ("outbound", "ufw allow out 2222/tcp\n"),
        ("one source", "ufw allow from 10.0.0.0/8 to any port 2222 proto tcp\n"),
        ("udp deny", "ufw deny 2222/udp\n"), ("outbound deny", "ufw deny out 2222/tcp\n"),
        ("deny one source", "ufw deny from 10.0.0.0/8 to any port 2222 proto tcp\n"),
        ("deny a range around it", "ufw reject 2223:2300/tcp\nufw deny 2000:2221/tcp\n"))}
    check("ssh port move on a host whose UFW is inactive: ...with no stored rule `ufw allow` would "
          "rewrite or a TCP connection would be refused by (none, other ports, a bare both-protocol "
          "allow, an outbound rule, a source-scoped one, a UDP deny, a range beside it) the allow goes "
          "in and is the panel's own (counted as added, so a revert deletes it)",
          all(v == ((True, None), [(2222, "tcp")], ["ufw-show-added"]) for v in opened.values()),
          repr(opened))
    unread = {"unknown verb": _inactive_open98("", added_rc=2), "empty": _inactive_open98("")}
    active = _inactive_open98(_ADDED98 + "ufw limit 2222/tcp\n", status="Status: active\n")
    check("ssh port move on a host whose UFW is inactive: ...stored rules that cannot be read (an "
          "older helper without the verb, an empty answer) open as before, NOT counted as added; an "
          "active firewall is read from `status` alone (control)",
          all(v[:2] == ((False, None), [(2222, "tcp")]) for v in unread.values())
          and active == ((True, None), [(2222, "tcp")], []), repr((unread, active)))


def _r26j_show_added_verb98():
    # The helper itself, loaded by file (a fresh module, so nothing leaks into another part's copy).
    _spec = _ilu98.spec_from_loader("ph98", _mach98.SourceFileLoader("ph98", _os98.path.join(
        _root98, "tools", "panel-helper")))
    _helper = _ilu98.module_from_spec(_spec)
    _spec.loader.exec_module(_helper)
    _entry = _helper.VERBS.get("ufw-show-added")
    check("ufw-show-added is a read: no arguments, `ufw show added` in both verb tables, not a "
          "mutating ufw verb (run_privileged takes no ufw_lock for it), and among the helper's reads",
          _priv98.tool_argv("ufw-show-added", [])[1:] == ["show", "added"]
          and not _p9_core._ufw_mutating("ufw-show-added") and _p9_core._ufw_mutating("ufw-enable")
          and _entry is not None and _entry[0] == [] and _entry[1]([])[1:] == ["show", "added"]
          and "ufw-show-added" in _helper.READ_VERBS,
          repr((_priv98.tool_argv("ufw-show-added", []), _entry and _entry[1]([]),
                "ufw-show-added" in getattr(_helper, "READ_VERBS", ()))))


try:
    _p9_arm(who="part98")
    _TS98, _KEY98, _ADMIN98 = _setup98()
    _A98 = _p9_client(_ADMIN98)
    _socket_second_move98()
    _socket_parse98()
    _r26j_socket_replaces98()
    _ssh_port_card98(_A98, _TS98, _KEY98)
    _ts_bind98()
    _r26j_ts_socket_bind98()
    _close_inactive98()
    _unblock98()
    _retry_marker98(_A98, _KEY98)
    _json_audit98(_A98, _KEY98)
    _sudo_reads98()
    _prune_running98()
    _inactive_ufw98()
    _r26j_inactive_refused98()
    _r26j_inactive_opened98()
    _r26j_show_added_verb98()
finally:
    _p9_restore_all()
    _cleanup98()

check("part98: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP98_START, repr(_P9_TRIPPED[_TRIP98_START:][:6]))
