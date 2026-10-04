"""Part 43 of the unit suite: an imported server's port is one READ on its host.

The import stored the port the browser sent, and 27015 when it sent none. Discovery read the first
`port=` of three LinuxGSM config files, and 46 of LinuxGSM's 140 games keep their port in the game's
own config instead (Minecraft in serverfiles/server.properties), so the card sent 0 for them and
the import stored 27015. On the test box that is Garry's Mod's port: the imported Minecraft server
read as up whenever Garry's Mod was, and its crash never paged.

Held here, each against fixture files in a throwaway "home":

* discovery's port reader, BOTH forms (the shell scan remote hosts run, under sh and bash, and the
  helper's on the panel host): LinuxGSM's load order with the secrets files, the last `port=` wins,
  and a port only when the start line in effect passes `${port}` — none for Minecraft (its port is
  in server.properties), San Andreas MP (its cfg port is never used) or a start line overridden
  without it;
* the import route, end to end: the scan's port is stored, never the client's (22, Infinity, none
  at all); a port the scan could not read is read from LinuxGSM's `details` (Minecraft: 25565 from
  its server.properties); a server whose port cannot be read is not imported, and the reason says
  why (details did not answer; the game has never started); SSH's port is refused;
* the monitor's up/down probe on what the import stored: the Minecraft server's crash pages while
  Garry's Mod keeps 27015 open;
* the startup re-read (game_ports.reconcile_stored_ports) heals a row stored on 27015, and keeps a
  port it cannot read or may not take; app.py starts it.

HOW IT RUNS. On part12's Flask app and database (imported; part12 has run by then), with the
transports tripped. The scan's shell text runs in a real sh/bash over the fixture home; `details`
is a stand-in that reads the fixture's server.properties with LinuxGSM's own sed expression
(info_game.sh fn_info_game_java_properties) and prints LinuxGSM's port table; everything else
(detect_game_ports' parser, protected_host_ports, the route) is real. Every stub is undone in the
finally, and the part ends by checking nothing reached a transport.
"""
import ast
import os
import shutil as _shutil43
import subprocess as _sp43  # nosec B404 - runs sh/bash/sed on this part's own fixture files
import tempfile as _tf43

from unit import REPO_ROOT as _ROOT43
from unit.part01 import check
from unit.part05 import _helper
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_app, _p9_client, _p9_core, _p9_json,
                         _p9_patch, _p9_restore_all, _p9_so, _p9_trip)
from panel.core.panel_state import forget_rows
from panel.db.models import AuditLog, GameServer, RemoteServer, db
from panel.routes import discover as _disc43
from panel.routes import manage_servers as _ms43
from panel.services import game_ports as _gp43
from panel.services import lgsm_data as _lgd43
from panel.services import monitoring as _mon43
from panel.services import notifications as _notif43

_TRIP43_START = len(_P9_TRIPPED)
_HOME43 = os.path.realpath(_tf43.mkdtemp(prefix="lgsm-unit-p43-home-"))
_mine43 = {"hosts": [], "servers": []}
_SILENT43 = set()          # accounts whose `details` never answers
_STARTED43 = set()         # accounts whose `details` says STARTED (the rest: STOPPED)
_LISTEN43 = {}             # host address -> the ports `ss` lists as listening there
_ASKED43 = []              # every account `details` was run for
_NOTIFIED43 = []
_MC_START43 = 'startparameters="nogui"\n'                       # LinuxGSM's mcserver _default.cfg
_COD_DEFAULT43 = ('port="28960"\nstartparameters="+set dedicated 2 +set net_ip ${ip} '
                  '+set net_port ${port} +map ${defaultmap} +exec ${servercfg}"\n')
_GMOD_DEFAULT43 = ('port="27015"\nstartparameters="-game garrysmod -strictportbind -ip ${ip} '
                   '-port ${port} +map ${defaultmap} -maxplayers ${maxplayers}"\n')
_SAMP_DEFAULT43 = 'port="7777"\nstartparameters=""\n'
# LinuxGSM's serverlist rows for the games here (the suite's own cached list has three others).
_ROWS43 = [{"shortname": sn, "gameservername": sn + "server", "gamename": name, "os": "ubuntu-24.04"}
           for sn, name in (("mc", "Minecraft"), ("cod", "Call of Duty"), ("gmod", "Garry's Mod"),
                            ("samp", "San Andreas Multiplayer"))]


# ── the fixture home ────────────────────────────────────────────────────────────────────────────
def _account43(user, inst, cfgs, props=None):
    """An account under the fixture home with one LinuxGSM instance; `props` is server.properties."""
    cfgdir = os.path.join(_HOME43, user, "lgsm", "config-lgsm", inst)
    os.makedirs(cfgdir)
    for name, text in cfgs.items():
        with open(os.path.join(cfgdir, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    if props is not None:
        os.makedirs(os.path.join(_HOME43, user, "serverfiles"))
        with open(os.path.join(_HOME43, user, "serverfiles", "server.properties"), "w",
                  encoding="utf-8") as fh:
            fh.write(props)
    launcher = os.path.join(_HOME43, user, inst)
    open(launcher, "w").close()
    os.chmod(launcher, 0o755)  # nosec B103 - a fixture launcher in a throwaway dir


def _mc_props43(port):
    return ("#Minecraft server properties\nenable-query=true\nquery.port=%d\nrcon.port=25575\n"
            "server-port=%d\nmotd=p43\n" % (port, port))


# The accounts, and the port discovery must report for each (None: not in the LinuxGSM config).
_SCAN_WANT43 = {
    "mc43": None,          # Minecraft: no port=, its port is server-port in server.properties
    "cod43": 28960,        # Call of Duty: port= in the cfg, and the start line passes ${port}
    "gm43": 27015,         # Garry's Mod, the neighbour on 27015
    "secret43": 27017,     # secrets-<instance>.cfg is sourced last and wins
    "last43": 27021,       # within a file the later line wins, as when bash sources it
    "samp43": None,        # San Andreas MP: port="7777" in the cfg, never passed to the game
    "start43": None,       # the instance cfg's start line drops ${port}: the cfg port is unused
    "fresh43": None,       # Minecraft never started: no server.properties yet
    "down43": None,        # Minecraft whose `details` will not answer
    "ssh43": 2222,         # a cfg port that is this host's SSH port
}


def _build_home43():
    _account43("mc43", "mcserver", {"_default.cfg": _MC_START43, "mcserver.cfg": "# instance\n"},
               props=_mc_props43(25565))
    _account43("cod43", "codserver", {"_default.cfg": _COD_DEFAULT43})
    _account43("gm43", "gmodserver", {"_default.cfg": _GMOD_DEFAULT43})
    _account43("secret43", "gmodserver", {
        "_default.cfg": _GMOD_DEFAULT43, "common.cfg": 'port="27018"\n',
        "gmodserver.cfg": 'port="27016"\n', "secrets-gmodserver.cfg": 'port="27017"\n'})
    # No newline at the end of the instance cfg: a file's last line must not run into the next.
    _account43("last43", "gmodserver", {"_default.cfg": _GMOD_DEFAULT43,
                                        "gmodserver.cfg": 'port="27020"\nport="27021"'})
    _account43("samp43", "sampserver", {"_default.cfg": _SAMP_DEFAULT43})
    _account43("start43", "gmodserver", {"_default.cfg": _GMOD_DEFAULT43,
                                         "gmodserver.cfg": 'startparameters="-game garrysmod"\n'})
    _account43("fresh43", "mcserver", {"_default.cfg": _MC_START43})
    _account43("down43", "mcserver", {"_default.cfg": _MC_START43}, props=_mc_props43(25566))
    _account43("ssh43", "codserver", {"_default.cfg": _COD_DEFAULT43,
                                      "codserver.cfg": 'port="2222"\n'})


# ── the host, as the fixture home answers it ────────────────────────────────────────────────────
def _scan_in43(shell):
    """run_command for discover_linuxgsm_servers: its script, run by `shell` over the fixture home."""
    def _run(server, command, timeout=30, sudo=None, stdin_text=None):
        if command.startswith("ss -H -lntu") and server.host in _LISTEN43:
            return "\n".join("0.0.0.0:%d" % p for p in sorted(_LISTEN43[server.host])), "", 0
        if "/home" not in command or "FOUND|" not in command:
            _P9_TRIPPED.append(("p43 run_command", command[:120]))
            return ("", "refused by part43", -1)
        p = _sp43.run([shell, "-c", command.replace("/home", _HOME43)],  # nosec B603 - this part's fixture
                      capture_output=True, text=True, timeout=60)
        return p.stdout.strip(), p.stderr.strip(), p.returncode
    return _run


def _lgsm_port43(user):
    """The port LinuxGSM's `details` reports for a fixture account.

    A Minecraft account's is read from its server.properties with info_game.sh's own sed
    (fn_info_game_java_properties "port" "server-port"); with no server.properties yet it is 0, as
    info_game.sh's `port="${port:-"0"}"` makes it. Any other account's is its LinuxGSM cfg port.
    """
    props = os.path.join(_HOME43, user, "serverfiles", "server.properties")
    if not os.path.exists(props):
        return _SCAN_WANT43.get(user) or 0
    out = _sp43.run(["sed", "-n", r'/^\<server-port\>/ { s/.*= *"\?\([^"]*\)"\?/\1/p;q }', props],  # nosec B603 B607
                    capture_output=True, text=True, timeout=10).stdout.replace("\r", "").strip()
    return int(out) if out.isdigit() else 0


def _details_text43(port, started=False):
    """`details` as LinuxGSM prints it for Minecraft: colour codes, Server IP, Status, port table."""
    return ("\x1b[34mServer name:\t\x1b[0mp43\n"
            "\x1b[34mServer IP:\t\x1b[0m0.0.0.0:%d\n"
            "\x1b[34mStatus:\t\x1b[0m%s\x1b[0m\n\n"
            "\x1b[34mDESCRIPTION  PORT   PROTOCOL  LISTEN\x1b[0m\n"
            "Game         %d  tcp       0\n"
            "Query        %d  udp       0\n"
            "RCON         25575  tcp       0\n\n"
            % (port, "\x1b[32mSTARTED" if started else "\x1b[31mSTOPPED", port, port))


def _run_as43(server, user, action, timeout=30, selfname=None, answers=None, tee_log=False):
    """run_as_game_user: `details` answered from the fixture; any other action is a trip."""
    if action != "details":
        _P9_TRIPPED.append(("p43 run_as_game_user", action))
        return ("", "refused by part43", 1)
    _ASKED43.append(user)
    if user in _SILENT43:
        return ("", "SSH command timed out", -1)       # tailscale/local: no raise, rc -1
    return (_details_text43(_lgsm_port43(user), user in _STARTED43), "", 0)


def _privileged43(server, verb, args=(), **_k):
    """run_privileged: only sshd's effective config is asked (protected_host_ports)."""
    if verb == "sshd-effective-config":
        return ("port 22\nport 2222\npermitrootlogin no\n", "", 0)
    _P9_TRIPPED.append(("p43 run_privileged", verb))
    return ("", "refused by part43", 1)


def _arm43():
    """part12's tripwire again, and the host's answers from the fixture home."""
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part43's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9_core, "run_command", _scan_in43("sh"))
    _p9_patch(_p9_core, "run_as_game_user", _run_as43)
    _p9_patch(_p9_core, "run_privileged", _privileged43)
    _p9_patch(_disc43, "privileged_accounts", lambda remote, users: {})
    _p9_patch(_disc43, "_bg_cache_commands", lambda *a, **k: None)
    _p9_patch(_notif43, "notify", lambda key, title, body="": _NOTIFIED43.append((key, body)))
    _p9_patch(_mon43, "_lgsm_maintenance_running", lambda remote, gs: False)
    _p9_patch(_lgd43, "serverlist", lambda *a, **k: _ROWS43)


def _host43(name, ip):
    with _p9.app_context():
        r = RemoteServer(name=name, host=ip, port=2222, username="admin", auth_method="key",
                         auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        _mine43["hosts"].append(r.id)
        return r.id


def _remote43(rid):
    return db.session.get(RemoteServer, rid)


# ── discovery's reader, both forms ──────────────────────────────────────────────────────────────
def _scan_ports43(found):
    return {f["user"]: f["port"] for f in found}


def _shell_scan43():
    """The shell form remote hosts run, under sh and bash, through discover_linuxgsm_servers."""
    for shell in ("sh", "bash"):
        _p9_patch(_p9_core, "run_command", _scan_in43(shell))
        with _p9.app_context():
            got = _scan_ports43(_p9_core.discover_linuxgsm_servers(_remote43(_H43)))
        for user, want in sorted(_SCAN_WANT43.items()):
            check("discover scan (%s): %s's port is %s" % (shell, user, want),
                  user in got and got[user] == want, "got %r of %r" % (got.get(user, "<absent>"), got))
    _p9_patch(_p9_core, "run_command", _scan_in43("sh"))


def _helper_scan43():
    """The helper's form, which the panel host runs: the same fixture, the same answers."""
    out = []

    class _Cap:
        def write(self, t):
            out.append(t)

        def flush(self):
            pass
    saved = (_helper.HOME_ROOT, _helper.sys.stdout)
    try:
        _helper.HOME_ROOT, _helper.sys.stdout = _HOME43, _Cap()
        _helper.do_lgsm_discover([], None)
    except Exception as exc:  # noqa: BLE001 - a raise is a named failure here, never a crash
        out.append("RAISED %r" % (exc,))
    finally:
        _helper.HOME_ROOT, _helper.sys.stdout = saved
    found = [e for e in (_p9_core._discovered_instance(ln) for ln in "".join(out).splitlines())
             if e is not None]
    got = _scan_ports43(found)
    for user, want in sorted(_SCAN_WANT43.items()):
        check("discover helper: %s's port is %s" % (user, want),
              user in got and got[user] == want, "got %r of %r" % (got.get(user, "<absent>"), got))


# ── the import route ────────────────────────────────────────────────────────────────────────────
def _post43(client, servers):
    return _p9_json(client.post("/api/remote/%d/import" % _H43, json={"servers": servers}))


def _rows43():
    with _p9.app_context():
        rows = GameServer.query.filter_by(remote_id=_H43).all()
        _mine43["servers"] += [g.id for g in rows if g.id not in _mine43["servers"]]
        return {g.short_name: g.port for g in rows}


def _reason43(reply, user):
    """The reason the reply gives for leaving `user` out; "" when it gives none."""
    return next((u.get("reason") or "" for u in reply.get("unread") or [] if u.get("user") == user),
                "")


def _import43(client):
    """One import of every kind of server, sent with what the old card and a client would send."""
    _SILENT43.add("down43")
    first = _post43(client, [
        {"user": "mc43", "game_type": "mc", "port": 0},           # what the card sent for it
        {"user": "cod43", "game_type": "cod", "port": 22},        # a client naming SSH's port
        {"user": "gm43", "game_type": "gmod"},                    # no port at all
        {"user": "last43", "game_type": "gmod", "port": float("inf")},
        {"user": "fresh43", "game_type": "mc", "port": 27015},
        {"user": "down43", "game_type": "mc", "port": 25565},
        {"user": "ssh43", "game_type": "cod", "port": 28960}])
    _SILENT43.discard("down43")
    _stored43(first, _rows43())
    _left_out43(first, _rows43())
    _again43(client)


def _stored43(first, rows):
    """What the first import stored for the servers it took."""
    check("import: a Minecraft server whose port is not in its LinuxGSM config is stored on the "
          "port LinuxGSM reads from its server.properties (25565), not 27015",
          rows.get("mc43") == 25565, "stored %r; reply %r" % (rows.get("mc43"), first))
    check("import: ...and LinuxGSM's details was asked only for the servers the scan had no port "
          "for", sorted(set(_ASKED43)) == ["down43", "fresh43", "mc43"], repr(_ASKED43))
    check("import: a port the CLIENT names is never stored — the scan's 28960, not the body's 22",
          rows.get("cod43") == 28960, "stored %r" % (rows.get("cod43"),))
    check("import: a body with no port stores the scan's port, not 27015's fallback (gmod 27015 "
          "is the scan's own reading here)", rows.get("gm43") == 27015, repr(rows))
    check("import: a body port of Infinity is ignored, not raised on: the scan's last line wins",
          rows.get("last43") == 27021, repr(rows))
    audit = _audit_detail43("import_servers")
    check("import: the audit row names each imported server with the port it was stored on",
          "mc43:25565" in audit and "cod43:28960" in audit, audit)


def _left_out43(first, rows):
    """The servers the first import left out, and what it said about them."""
    unread = repr(first.get("unread"))
    check("import: a Minecraft server that has never started (LinuxGSM reports port 0) gets NO "
          "row — not the body's 27015", "fresh43" not in rows, repr(rows))
    check("import: ...and the reply says to start it once first",
          "start it once" in _reason43(first, "fresh43"), unread)
    check("import: a server whose details does not answer gets NO row — not the body's 25565",
          "down43" not in rows, repr(rows))
    check("import: ...and the reply says details did not answer, and to try again",
          all(w in _reason43(first, "down43") for w in ("did not answer", "try the import again")),
          unread)
    check("import: a cfg port that is this host's SSH port (2222, from sshd's own config) is "
          "refused, with the reason", ("ssh43" not in rows, "SSH" in _reason43(first, "ssh43"))
          == (True, True), repr(rows) + unread)
    taken = (first.get("success"), set(first.get("skipped") or ()) >= {"fresh43", "down43", "ssh43"},
             sorted(first.get("added") or ()))
    check("import: the servers left out are named as skipped, and the import still succeeds for "
          "the rest", taken == (True, True, ["cod43", "gm43", "last43", "mc43"]), repr(first))


def _again43(client):
    """The servers left out, imported again."""
    again = _post43(client, [{"user": "down43", "game_type": "mc"}])
    check("import: ...and once details answers, the same server imports on its own port",
          _rows43().get("down43") == 25566 and again.get("added") == ["down43"], repr(again))
    alone = _post43(client, [{"user": "fresh43", "game_type": "mc"}])
    check("import: with nothing imported, the message names the server and why",
          alone.get("success") is False and "fresh43" in (alone.get("message") or "")
          and "start it once" in (alone.get("message") or ""), repr(alone))


def _audit_detail43(action):
    with _p9.app_context():
        a = AuditLog.query.filter_by(action=action).order_by(AuditLog.id.desc()).first()
        return (a.detail or "") if a is not None else ""


# ── the monitor's up/down probe on the stored port ──────────────────────────────────────────────
def _monitor43():
    """Garry's Mod keeps 27015 open; the imported Minecraft server crashes. That must page."""
    with _p9.app_context():
        gs = GameServer.query.filter_by(remote_id=_H43, short_name="mc43").first()
        if gs is None:
            check("monitor: the imported Minecraft server's crash pages while Garry's Mod's port "
                  "stays open", False, "no mc43 row was imported")
            return
        remote = _remote43(_H43)
        forget_rows(server_ids=(gs.id,))
        _mon43._monitor_state["servers"][gs.id] = True              # it was up
        n = len(_NOTIFIED43)
        for _ in range(_mon43._DOWN_CONFIRM_SWEEPS):
            _mon43._monitor_server(remote, gs, {}, {27015})          # only gmod's port listening
        status = gs.status
        paged = [b for k, b in _NOTIFIED43[n:] if k == "server_down" and "mc43" in b]
        forget_rows(server_ids=(gs.id,))
        _mon43._monitor_server(remote, gs, {}, {25565, 27015})
        up_status = gs.status
        forget_rows(server_ids=(gs.id,))
        db.session.rollback()
    check("monitor: the imported Minecraft server's crash pages while Garry's Mod keeps 27015 "
          "open", len(paged) == 1, "notified %r" % (_NOTIFIED43[n:],))
    check("monitor: ...and it is recorded offline, not online on Garry's Mod's socket",
          status == "offline", "status %r" % (status,))
    check("monitor: ...and it reads online when its own port 25565 listens (control)",
          up_status == "online", "status %r" % (up_status,))


# ── the startup re-read ─────────────────────────────────────────────────────────────────────────
def _heal_rows43(rid):
    """The heal host's rows, each on the port an old import might have stored. -> {account: id}."""
    want = {}
    with _p9.app_context():
        for short, gt, port in (("gm43", "gmod", 27015), ("mc43", "mc", 27015),
                                ("down43", "mc", 25570), ("sibl43", "mc", 25590),
                                ("sshp43", "mc", 25580), ("fresh43", "mc", 25600),
                                ("foreign43", "mc", 25610), ("quiet43", "mc", 25630)):
            gs = GameServer(remote_id=rid, name="heal-" + short, short_name=short, game_type=gt,
                            port=port, installed=True, status="offline")
            db.session.add(gs)
            db.session.commit()
            _mine43["servers"].append(gs.id)
            want[short] = gs.id
    # sibl43's server.properties names Garry's Mod's 27015, sshp43's SSH's 2222; foreign43's 25620
    # is held by a process outside the panel while foreign43 is stopped; quiet43's 25640 is free.
    for user, port in (("sibl43", 27015), ("sshp43", 2222), ("foreign43", 25620),
                       ("quiet43", 25640)):
        _account43(user, "mcserver", {"_default.cfg": _MC_START43}, props=_mc_props43(port))
    return want


def _heal43():
    """Rows stored before the import read ports: one on Garry's Mod's 27015 is healed."""
    rid = _host43("p43-heal", "192.0.2.143")
    want = _heal_rows43(rid)
    _LISTEN43["192.0.2.143"] = {22, 2222, 27015, 25565, 25620}    # mc43 runs on its 25565
    _SILENT43.add("down43")
    _STARTED43.add("mc43")
    try:
        _gp43.reconcile_stored_ports(_p9, _ms43.withheld_game_ports)
    except Exception as exc:  # noqa: BLE001 - a raise is a named failure here, never a crash
        check("startup port re-read: runs without raising", False, repr(exc))
    _SILENT43.discard("down43")
    _STARTED43.discard("mc43")
    with _p9.app_context():
        got = {s: db.session.get(GameServer, i).port for s, i in want.items()}
        audits = sorted(a.detail for a in AuditLog.query.filter_by(action="port_resync").all())
    check("startup port re-read: a Minecraft row stored on 27015 is moved to the 25565 LinuxGSM "
          "reads from its server.properties", got["mc43"] == 25565, repr(got))
    check("startup port re-read: ...and audited, old and new",
          any(d.startswith("27015 -> 25565") for d in audits), repr(audits))
    check("startup port re-read: Garry's Mod, already right, is left as it is (control)",
          got["gm43"] == 27015, repr(got))
    check("startup port re-read: a server whose details does not answer keeps its port",
          got["down43"] == 25570, repr(got))
    check("startup port re-read: a server that reports port 0 (never started) keeps its port",
          got["fresh43"] == 25600, repr(got))
    check("startup port re-read: a reported port in another server's block is not taken",
          got["sibl43"] == 25590, repr(got))
    check("startup port re-read: a reported port that is this host's SSH is not taken",
          got["sshp43"] == 25580, repr(got))
    check("startup port re-read: a reported port something else listens on while the server is "
          "stopped is not taken", got["foreign43"] == 25610, repr(got))
    check("startup port re-read: ...while a stopped server's free reported port is (control)",
          got["quiet43"] == 25640, repr(got))
    check("startup port re-read: only the moved rows are audited",
          [d.split(" (")[0] for d in audits] == ["25630 -> 25640", "27015 -> 25565"], repr(audits))


def _main_block43():
    """app.py's `if __name__ == "__main__":` block, or None."""
    src = open(os.path.join(_ROOT43, "app.py"), encoding="utf-8").read()
    return next((n for n in ast.parse(src).body if isinstance(n, ast.If)
                 and "__main__" in ast.dump(n.test)), None)


def _calls43(node, name):
    """Every call in `node` to a function or method called `name`."""
    return [c for c in ast.walk(node) if isinstance(c, ast.Call)
            and name in (getattr(c.func, "id", None), getattr(c.func, "attr", None))]


def _thread_target43(call):
    """The name a `threading.Thread(target=<name>, ...)` call is given as its target, or None."""
    return next((k.value.id for k in call.keywords
                 if k.arg == "target" and isinstance(k.value, ast.Name)), None)


def _wired43():
    """app.py starts the re-read once per panel start, in the background."""
    main = _main_block43() or ast.Module(body=[], type_ignores=[])
    runner = next((f.name for f in ast.walk(main) if isinstance(f, ast.FunctionDef)
                   and _calls43(f, "reconcile_stored_ports")), None)
    started = [c for c in _calls43(main, "start")
               if isinstance(getattr(c.func, "value", None), ast.Call)]
    targets = [_thread_target43(c.func.value) for c in started]
    check("startup port re-read: app.py's start runs it in a thread of its own",
          runner is not None and runner in targets, "function %r, threads started %r" % (runner, targets))


def _cleanup43():
    with _p9.app_context():
        for sid in _mine43["servers"]:
            gs = db.session.get(GameServer, sid)
            if gs is not None:
                db.session.delete(gs)
        db.session.commit()
        for rid in _mine43["hosts"]:
            GameServer.query.filter_by(remote_id=rid).delete()
            r = db.session.get(RemoteServer, rid)
            if r is not None:
                db.session.delete(r)
        db.session.commit()
    forget_rows(server_ids=tuple(_mine43["servers"]), remote_ids=tuple(_mine43["hosts"]))
    _shutil43.rmtree(_HOME43, ignore_errors=True)


_H43 = None
_CACHES43 = (dict(_p9_app._GAME_LIST_CACHE), dict(_p9_app._LGSM_NAME_MAP))
try:
    _build_home43()
    _arm43()
    _H43 = _host43("p43-host", "192.0.2.43")
    # What `ss` lists there, should the startup re-read below ever want to move a port on it.
    _LISTEN43["192.0.2.43"] = {22, 2222, 25565, 27015}
    _shell_scan43()
    _helper_scan43()
    _import43(_p9_client(P9_ADMIN))
    _monitor43()
    _heal43()
    _wired43()
finally:
    _p9_restore_all()
    _cleanup43()
    for _cache43, _saved43 in zip((_p9_app._GAME_LIST_CACHE, _p9_app._LGSM_NAME_MAP), _CACHES43):
        _cache43.clear()
        _cache43.update(_saved43)

check("part43: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP43_START, repr(_P9_TRIPPED[_TRIP43_START:][:6]))
