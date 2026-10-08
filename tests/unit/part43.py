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
  without it. And what it reads: only a regular file, not a symlink or a fifo, and at most 1 MiB;
* the import route, end to end: the scan's port is stored, never the client's (22, Infinity, none
  at all); a port the scan could not read is read from LinuxGSM's `details` (Minecraft: 25565 from
  its server.properties); a server whose port cannot be read is not imported, and the reason says
  what was seen (details did not answer, or raised; the game's own config is missing or does not
  set the port); SSH's port is refused; an account another import adds while the reads run is
  skipped, not doubled; on the panel's own host, the account is enrolled before `details` runs;
* a port an imported server shares with another server on its host (found on the test box:
  PaperMC's server.properties sets mcserver's 25565): imported on it, and the reply names the port
  and the servers and says what it means — two in one batch, one already in the panel (by its
  display name), three; a server on another host or one not imported is no share;
* the monitor's up/down probe on what the import stored: the Minecraft server's crash pages while
  Garry's Mod keeps 27015 open;
* the startup re-read (game_ports.reconcile_stored_ports) heals a row stored on another server's
  port, even onto a port it shares, keeps a port it cannot read or may not take, survives a row
  deleted and a host failing mid-pass, and moves the monitor's state, the restart cron line and its
  own firewall rule along with the port, and says in its audit row when the new port is shared;
  app.py starts it.

HOW IT RUNS. On part12's Flask app and database (imported; part12 has run by then), with the
transports tripped. The scan's shell text runs in a real sh/bash over the fixture home, and the
helper in a python of its own (a fifo would block this monkey-patched process whole); `details` is
a stand-in that reads the fixture's server.properties with LinuxGSM's own sed expression
(info_game.sh fn_info_game_java_properties) and prints LinuxGSM's port table; everything else
(detect_game_ports' parser, protected_host_ports, the route, the cron upgrade) is real. Every stub
is undone in the finally, and the part ends by checking nothing reached a transport.
"""
import ast
import os
import shutil as _shutil43
import signal as _signal43
import subprocess as _sp43  # nosec B404 - runs sh/bash/sed/python on this part's own fixture files
import sys as _sys43
import tempfile as _tf43
from types import SimpleNamespace as _NS43

from unit import REPO_ROOT as _ROOT43
from unit.part01 import check, skip
from unit.part12 import (P9_ADMIN, P9_LOCAL, _P9_TRIPPED, _p9, _p9_app, _p9_client, _p9_core,
                         _p9_json, _p9_patch, _p9_restore_all, _p9_sm, _p9_so, _p9_trip)
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
_SILENT43 = set()          # accounts whose `details` never answers (tailscale/local: rc -1)
_RAISE43 = set()           # accounts whose `details` raises (paramiko)
_STARTED43 = set()         # accounts whose `details` says STARTED (the rest: STOPPED)
_ENROLLED43 = set()        # accounts the helper has put in the game group (gameuser-group)
_LISTEN43 = {}             # host address -> the ports `ss` lists as listening there
_SS_RAISE43 = set()        # host addresses whose `ss` raises (paramiko)
_ASKED43 = []              # every account `details` was run for
_DETAILS_HOSTS43 = []      # server.host as each `details` call read it, in its pool thread
_ON_DETAILS43 = {}         # account -> a callable run as its `details` is (another import, ...)
_CRON43 = {}               # account -> its crontab listing
_CRON_WRITTEN43 = {}       # account -> the lines a crontab rewrite installed
_CLOSED43 = []             # (port, server name) for every firewall rule close asked for
_NOTIFIED43 = []
_FIFO_FDS43 = []           # the fixture fifo's own open end: a writer that has written to it
_MC_START43 = 'startparameters="nogui"\n'                       # LinuxGSM's mcserver _default.cfg
_COD_DEFAULT43 = ('port="28960"\nstartparameters="+set dedicated 2 +set net_ip ${ip} '
                  '+set net_port ${port} +map ${defaultmap} +exec ${servercfg}"\n')
_GMOD_DEFAULT43 = ('port="27015"\nstartparameters="-game garrysmod -strictportbind -ip ${ip} '
                   '-port ${port} +map ${defaultmap} -maxplayers ${maxplayers}"\n')
_SAMP_DEFAULT43 = 'port="7777"\nstartparameters=""\n'
# Vintage Story: no port in the LinuxGSM config, and no game config until its first start
# (install_config.sh: "Config is generated on first run").
_VINTS_DEFAULT43 = 'startparameters="--dataPath ${datadir}"\n'
# LinuxGSM's serverlist rows for the games here (the suite's own cached list has three others).
_ROWS43 = [{"shortname": sn, "gameservername": sn + "server", "gamename": name, "os": "ubuntu-24.04"}
           for sn, name in (("mc", "Minecraft"), ("cod", "Call of Duty"), ("gmod", "Garry's Mod"),
                            ("samp", "San Andreas Multiplayer"), ("vints", "Vintage Story"))]
# sshd's own config names 2200 as well as 22: a port the panel does NOT connect on (the fixture
# hosts' RemoteServer.port is 2222), so only protected_host_ports' read of sshd can refuse it.
_SSHD43 = "port 22\nport 2200\npermitrootlogin no\n"
_SCAN_TIMEOUT43 = 20      # a scan of the fixture home takes well under a second
# What a timed-out communicate() raises. This suite is monkey-patched, and eventlet's green Popen
# runs the ORIGINAL subprocess module's communicate, which raises that module's TimeoutExpired: one
# `except subprocess.TimeoutExpired` does not catch (measured; ssh_manager._core catches both too).
try:
    from eventlet import patcher as _patcher43
    _TIMEOUTS43 = (_sp43.TimeoutExpired, _patcher43.original("subprocess").TimeoutExpired)
except ImportError:
    _TIMEOUTS43 = (_sp43.TimeoutExpired,)


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
    # A fixture launcher in this part's own throwaway dir, which the stand-in account runs.
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(launcher, 0o755)  # nosec B103 - a fixture launcher in a throwaway dir
    return cfgdir


def _mc_props43(port):
    return ("#Minecraft server properties\nenable-query=true\nquery.port=%d\nrcon.port=25575\n"
            "server-port=%d\nmotd=p43\n" % (port, port))


def _mc43(user, port):
    """A Minecraft account whose server.properties sets `port`."""
    _account43(user, "mcserver", {"_default.cfg": _MC_START43}, props=_mc_props43(port))


# The accounts, and the port discovery must report for each (None: not in the LinuxGSM config).
_SCAN_WANT43 = {
    "mc43": None,          # Minecraft: no port=, its port is server-port in server.properties
    "cod43": 28960,        # Call of Duty: port= in the cfg, and the start line passes ${port}
    "gm43": 27015,         # Garry's Mod, the neighbour on 27015
    "nop43": 27030,        # Garry's Mod moved off its default in the instance cfg
    "secret43": 27017,     # secrets-<instance>.cfg is sourced last and wins
    "last43": 27021,       # within a file the later line wins, as when bash sources it
    "samp43": None,        # San Andreas MP: port="7777" in the cfg, never passed to the game
    "start43": None,       # the instance cfg's start line drops ${port}: the cfg port is unused
    "vint43": None,        # Vintage Story before its first start: no game config at all yet
    "noprop43": None,      # Minecraft whose server.properties does not set server-port
    "down43": None,        # Minecraft whose `details` will not answer
    "boom43": None,        # Minecraft whose `details` raises
    "race43": None,        # Minecraft another import adds while this one reads its port
    "loc43": None,         # Minecraft on the panel's own host
    "ssh43": 2200,         # a cfg port that is this host's SSH port (sshd's config names it)
    "big43": 27032,        # a 1 MiB+ secrets file: what lies past 1 MiB is never read
    "lnk43": 27033,        # the last cfg is a symlink to another file: never followed
    "fifo43": 27034,       # the last cfg is a fifo with a writer: never read, never stalls the scan
}


def _build_home43():
    _mc43("mc43", 25565)
    _account43("cod43", "codserver", {"_default.cfg": _COD_DEFAULT43})
    _account43("gm43", "gmodserver", {"_default.cfg": _GMOD_DEFAULT43})
    _account43("nop43", "gmodserver", {"_default.cfg": _GMOD_DEFAULT43,
                                       "gmodserver.cfg": 'port="27030"\n'})
    _account43("secret43", "gmodserver", {
        "_default.cfg": _GMOD_DEFAULT43, "common.cfg": 'port="27018"\n',
        "gmodserver.cfg": 'port="27016"\n', "secrets-gmodserver.cfg": 'port="27017"\n'})
    # No newline at the end of the instance cfg: a file's last line must not run into the next.
    _account43("last43", "gmodserver", {"_default.cfg": _GMOD_DEFAULT43,
                                        "gmodserver.cfg": 'port="27020"\nport="27021"'})
    _account43("samp43", "sampserver", {"_default.cfg": _SAMP_DEFAULT43})
    _account43("start43", "gmodserver", {"_default.cfg": _GMOD_DEFAULT43,
                                         "gmodserver.cfg": 'startparameters="-game garrysmod"\n'})
    _account43("vint43", "vintsserver", {"_default.cfg": _VINTS_DEFAULT43})
    _account43("noprop43", "mcserver", {"_default.cfg": _MC_START43},
               props="#Minecraft server properties\nmotd=p43\nmax-players=8\n")
    for user, port in (("down43", 25566), ("boom43", 25568), ("race43", 25569), ("loc43", 25567)):
        _mc43(user, port)
    _account43("ssh43", "codserver", {"_default.cfg": _COD_DEFAULT43,
                                      "codserver.cfg": 'port="2200"\n'})
    _odd_accounts43()


def _odd_accounts43():
    """The files a game account can put where the scan reads, which it must read safely.

    Each odd file sits AFTER the file that sets the right port, so reading it would change the
    answer: past the 1 MiB cap, a symlink's target, a fifo (which blocks whoever opens it).
    """
    d = _account43("big43", "gmodserver", {"_default.cfg": _GMOD_DEFAULT43,
                                           "common.cfg": 'port="27032"\n'})
    with open(os.path.join(d, "secrets-common.cfg"), "w", encoding="utf-8") as fh:
        fh.write(("# " + "x" * 1021 + "\n") * 1024)        # exactly 1 MiB of comment lines
        fh.write('port="27999"\n')                          # ...and a port past it
    d = _account43("lnk43", "gmodserver", {"_default.cfg": _GMOD_DEFAULT43,
                                           "gmodserver.cfg": 'port="27033"\n'})
    elsewhere = os.path.join(_HOME43, "lnk43", "elsewhere.cfg")
    with open(elsewhere, "w", encoding="utf-8") as fh:
        fh.write('port="27998"\n')
    os.symlink(elsewhere, os.path.join(d, "secrets-gmodserver.cfg"))
    d = _account43("fifo43", "gmodserver", {"_default.cfg": _GMOD_DEFAULT43,
                                            "gmodserver.cfg": 'port="27034"\n'})
    fifo = os.path.join(d, "secrets-gmodserver.cfg")
    os.mkfifo(fifo)
    # Held open for writing, with a port waiting in it, as a game account's process could: a
    # reader that opens it without blocking still reads that port, and one that reads to EOF
    # waits for as long as the writer lives. (O_RDWR: a fifo opened so never blocks.)
    fd = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    _FIFO_FDS43.append(fd)
    os.write(fd, b'port="27997"\n')


# ── the host, as the fixture home answers it ────────────────────────────────────────────────────
def _run_bounded43(argv):
    """(stdout, stderr, rc) of `argv`, killed with everything it started after _SCAN_TIMEOUT43.

    Its own session, and the whole group killed: a `cat` blocked opening a fifo outlives a killed
    shell, keeps the pipe open, and communicate() would then wait for it forever.
    """
    p = _sp43.Popen(argv, stdout=_sp43.PIPE, stderr=_sp43.PIPE, text=True,  # nosec B603 - fixture
                    start_new_session=True)
    try:
        out, err = p.communicate(timeout=_SCAN_TIMEOUT43)
    except _TIMEOUTS43:
        os.killpg(p.pid, _signal43.SIGKILL)
        out, err = p.communicate()
        return out or "", "timed out", -1
    return out, err, p.returncode


def _scan_in43(shell):
    """run_command for discover_linuxgsm_servers: its script, run by `shell` over the fixture home."""
    def _run(server, command, timeout=30, sudo=None, stdin_text=None):
        if command.startswith("ss -H -lntu") and server.host in _SS_RAISE43:
            raise ConnectionError("SSH connection failed (part43)")
        if command.startswith("ss -H -lntu") and server.host in _LISTEN43:
            return "\n".join("0.0.0.0:%d" % p for p in sorted(_LISTEN43[server.host])), "", 0
        if "/home" not in command or "FOUND|" not in command:
            _P9_TRIPPED.append(("p43 run_command", command[:120]))
            return ("", "refused by part43", -1)
        out, err, rc = _run_bounded43([shell, "-c", command.replace("/home", _HOME43)])
        return out.strip(), err.strip(), rc
    return _run


def _lgsm_port43(user):
    """The port LinuxGSM's `details` reports for a fixture account.

    A Minecraft account's is read from its server.properties with info_game.sh's own sed
    (fn_info_game_java_properties "port" "server-port"); with no server-port in it, or no file, it is
    0, as info_game.sh's `port="${port:-"0"}"` makes it. Any other account's is its LinuxGSM cfg port.
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
    """run_as_game_user: `details` answered from the fixture; any other action is a trip.

    It reads server.host first, as every real transport does — from a pool thread, for the
    import's and the re-read's parallel reads. On the panel's own host it refuses an account not
    enrolled yet, as the helper does on a narrow-grant install.
    """
    if action != "details":
        _P9_TRIPPED.append(("p43 run_as_game_user", action))
        return ("", "refused by part43", 1)
    _DETAILS_HOSTS43.append(server.host)
    _ASKED43.append(user)
    if user in _ON_DETAILS43:
        _ON_DETAILS43.pop(user)()
    if user in _RAISE43:
        raise ConnectionError("SSH connection failed (part43)")
    if user in _SILENT43:
        return ("", "SSH command timed out", -1)       # tailscale/local: no raise, rc -1
    if getattr(server, "is_local", False) and user not in _ENROLLED43:
        return ("", "panel-helper: %s is not a game account" % user, 1)
    return (_details_text43(_lgsm_port43(user), user in _STARTED43), "", 0)


def _privileged43(server, verb, args=(), **_k):
    """run_privileged: sshd's effective config, a crontab listing, the game-group enrolment."""
    if verb == "sshd-effective-config":
        return (_SSHD43, "", 0)
    if verb == "crontab-list" and args:
        return (_CRON43.get(args[0], ""), "", 0)
    if verb == "gameuser-group" and args:
        _ENROLLED43.add(args[0])
        return ("", "", 0)
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
    _p9_patch(_p9_core, "helper_present", lambda recheck=False: False)
    _p9_patch(_p9_core, "_rewrite_crontab",
              lambda s, u, grep, add, extra_pre="": (_CRON_WRITTEN43.setdefault(u, []).extend(add),
                                                     (True, "ok"))[1])
    _p9_patch(_p9_core, "_gamedig_host", lambda server: server.host)
    _p9_patch(_p9_sm, "remote_ufw_close_game_port",
              lambda r, port, name="", legacy=False, ports=(): (
                  _CLOSED43.append((port, name)), (1, "Port %s: 1 rule(s) removed" % port, []))[1])
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


# The helper's discover verb, run in a python of its own over the fixture home: in this
# monkey-patched process a fifo opened by the helper would block every green thread, the check's
# own timeout included, so the suite would hang instead of failing by name.
_HELPER_RUN43 = ("import importlib.machinery as m, importlib.util as u, sys\n"
                 "ld = m.SourceFileLoader('panel_helper_p43', sys.argv[1])\n"
                 "h = u.module_from_spec(u.spec_from_loader(ld.name, ld))\n"
                 "ld.exec_module(h)\n"
                 "h.HOME_ROOT = sys.argv[2]\n"
                 "h.do_lgsm_discover([], None)\n")


def _helper_scan43():
    """The helper's form, which the panel host runs: the same fixture, the same answers."""
    out, err, rc = _run_bounded43([_sys43.executable, "-c", _HELPER_RUN43,
                                   os.path.join(_ROOT43, "tools", "panel-helper"), _HOME43])
    check("discover helper: the scan finishes, a fifo among the configs included",
          rc == 0, "rc %r: %s" % (rc, err[-300:]))
    found = [e for e in (_p9_core._discovered_instance(ln) for ln in out.splitlines())
             if e is not None]
    got = _scan_ports43(found)
    for user, want in sorted(_SCAN_WANT43.items()):
        check("discover helper: %s's port is %s" % (user, want),
              user in got and got[user] == want, "got %r of %r" % (got.get(user, "<absent>"), got))


# ── the import route ────────────────────────────────────────────────────────────────────────────
def _post43(client, servers, rid=None):
    try:
        resp = client.post("/api/remote/%d/import" % (rid or _H43), json={"servers": servers})
    except Exception as exc:  # noqa: BLE001 - a raise is a named failure here, never a crash
        return {"raised": repr(exc)}
    return dict(_p9_json(resp), http_status=resp.status_code)


def _rows43(rid=None):
    with _p9.app_context():
        rows = GameServer.query.filter_by(remote_id=rid or _H43).all()
        _mine43["servers"] += [g.id for g in rows if g.id not in _mine43["servers"]]
        return {g.short_name: g.port for g in rows}


def _reason43(reply, user):
    """The reason the reply gives for leaving `user` out; "" when it gives none."""
    return next((u.get("reason") or "" for u in reply.get("unread") or [] if u.get("user") == user),
                "")


def _import43(client):
    """One import of every kind of server, sent with what the old card and a client would send."""
    _SILENT43.add("down43")
    _RAISE43.add("boom43")
    first = _post43(client, [
        {"user": "mc43", "game_type": "mc", "port": 0},           # what the card sent for it
        {"user": "cod43", "game_type": "cod", "port": 22},        # a client naming SSH's port
        {"user": "gm43", "game_type": "gmod"},                    # no port at all
        {"user": "nop43", "game_type": "gmod"},                   # no port, and not 27015
        {"user": "last43", "game_type": "gmod", "port": float("inf")},
        {"user": "vint43", "game_type": "vints", "port": 27015},
        {"user": "noprop43", "game_type": "mc", "port": 27015},
        {"user": "down43", "game_type": "mc", "port": 25565},
        {"user": "boom43", "game_type": "mc", "port": 25565},
        {"user": "ssh43", "game_type": "cod", "port": 28960}])
    _SILENT43.discard("down43")
    _RAISE43.discard("boom43")
    _stored43(first, _rows43())
    _left_out43(first, _rows43())
    _again43(client)
    _raced43(client)
    _local43(client)
    _expired_remote43()


def _stored43(first, rows):
    """What the first import stored for the servers it took."""
    check("import: a Minecraft server whose port is not in its LinuxGSM config is stored on the "
          "port LinuxGSM reads from its server.properties (25565), not 27015",
          rows.get("mc43") == 25565, "stored %r; reply %r" % (rows.get("mc43"), first))
    check("import: ...and LinuxGSM's details was asked only for the servers the scan had no port "
          "for", sorted(set(_ASKED43)) == ["boom43", "down43", "mc43", "noprop43", "vint43"],
          repr(_ASKED43))
    check("import: a port the CLIENT names is never stored — the scan's 28960, not the body's 22",
          rows.get("cod43") == 28960, "stored %r" % (rows.get("cod43"),))
    check("import: a body with no port stores the scan's port (27030), not 27015's fallback",
          rows.get("nop43") == 27030, repr(rows))
    check("import: a body port of Infinity is ignored, not raised on: the scan's last line wins",
          rows.get("last43") == 27021, repr(rows))
    audit = _audit_detail43("import_servers")
    check("import: the audit row names each imported server with the port it was stored on",
          "mc43:25565" in audit and "cod43:28960" in audit, audit)
    check("import: five servers on five ports: the reply names no shared port (control)",
          first.get("shared_ports") == [], repr(first.get("shared_ports")))


def _left_out43(first, rows):
    """The servers the first import left out, and what it said about them."""
    unread = repr(first.get("unread"))
    for user, what in (("vint43", "a Vintage Story server that has no game config yet"),
                       ("noprop43", "a Minecraft server whose server.properties sets no port")):
        check("import: %s (LinuxGSM reports port 0) gets NO row — not the body's 27015" % what,
              user not in rows, repr(rows))
        check("import: ...and the reply says what was seen: the game's own config is missing or "
              "does not set the port (%s)" % user,
              "is missing or does not set the port" in _reason43(first, user), unread)
    check("import: ...and says a first start helps only a game that writes its own config — not "
          "'it has never started', which is false for most",
          "A game that writes that file itself the first time it starts" in _reason43(first, "vint43")
          and "never started" not in _reason43(first, "vint43"), unread)
    check("import: a server whose details does not answer gets NO row — not the body's 25565",
          "down43" not in rows, repr(rows))
    check("import: ...and the reply says details did not answer, and to try again",
          all(w in _reason43(first, "down43") for w in ("did not answer", "try the import again")),
          unread)
    check("import: a server whose details RAISES (paramiko) gets no row and reads 'did not "
          "answer' — the import is not a 500",
          "boom43" not in rows and "did not answer" in _reason43(first, "boom43")
          and first.get("http_status") == 200, repr((first.get("http_status"), first.get("raised"),
                                                     unread)))
    check("import: a cfg port that is this host's SSH port (2200, named only by sshd's own config, "
          "not the port the panel connects on) is refused, with the reason",
          ("ssh43" not in rows, "SSH" in _reason43(first, "ssh43")) == (True, True),
          repr(rows) + unread)
    taken = (first.get("success"),
             set(first.get("skipped") or ()) >= {"vint43", "noprop43", "down43", "boom43", "ssh43"},
             sorted(first.get("added") or ()))
    check("import: the servers left out are named as skipped, and the import still succeeds for "
          "the rest", taken == (True, True, ["cod43", "gm43", "last43", "mc43", "nop43"]),
          repr(first))


def _again43(client):
    """The servers left out, imported again."""
    again = _post43(client, [{"user": "down43", "game_type": "mc"}])
    check("import: ...and once details answers, the same server imports on its own port",
          _rows43().get("down43") == 25566 and again.get("added") == ["down43"], repr(again))
    alone = _post43(client, [{"user": "noprop43", "game_type": "mc"}])
    check("import: with nothing imported, the message names the server and why",
          alone.get("success") is False and "noprop43" in (alone.get("message") or "")
          and "does not set the port" in (alone.get("message") or ""), repr(alone))


def _raced43(client):
    """Another import adds the account while this one reads its port: skipped, never doubled."""
    def _other_import():
        with _p9.app_context():
            db.session.add(GameServer(remote_id=_H43, name="race43-other", short_name="race43",
                                      game_type="mc", port=25569, installed=True, status="offline"))
            db.session.commit()
    _ON_DETAILS43["race43"] = _other_import
    reply = _post43(client, [{"user": "race43", "game_type": "mc"}])
    _ON_DETAILS43.pop("race43", None)
    with _p9.app_context():
        ids = [g.id for g in GameServer.query.filter_by(remote_id=_H43, short_name="race43").all()]
    _mine43["servers"] += ids
    check("import: an account another import added while this one read its port is reported as "
          "skipped, and gets no second row",
          (len(ids), "race43" in (reply.get("skipped") or ()), reply.get("added")) == (1, True, []),
          repr((ids, reply)))


def _local43(client):
    """On the panel's own host the helper runs `details` only as an enrolled account."""
    reply = _post43(client, [{"user": "loc43", "game_type": "mc"}], rid=P9_LOCAL)
    with _p9.app_context():
        rows = [(g.id, g.port) for g in GameServer.query.filter_by(remote_id=P9_LOCAL,
                                                                   short_name="loc43").all()]
    _mine43["servers"] += [i for i, _p in rows]
    check("import (panel host): the account is enrolled BEFORE its port is read, so details "
          "answers and the server is stored on its own port (25567)",
          [p for _i, p in rows] == [25567] and "loc43" in _ENROLLED43, repr((rows, reply)))


def _expired_remote43():
    """read_reported_ports given a host row a commit has expired: its pool threads still read it."""
    del _DETAILS_HOSTS43[:]
    with _p9.app_context():
        remote = _remote43(_H43)
        db.session.commit()      # expires every row the session holds, this one included
        got = _gp43.read_reported_ports(remote, [("k", "mc43", "mcserver")])
    check("port read: a host row expired by a commit is still read in the pool thread (its "
          "columns are loaded before the threads start), and the port comes back",
          (got.get("k", _gp43.NO_READING).port, _DETAILS_HOSTS43) == (25565, ["192.0.2.43"]),
          repr((got, _DETAILS_HOSTS43)))


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


# ── a port another server shares ────────────────────────────────────────────────────────────────
# Found by the VPS proof: pmcsrv's server.properties sets 25565, as mcserver's does. Both are
# stored there (it IS their port), and the reply has to say what that means. Each case on a host
# of its own making: (account, its server.properties port).
_SHARE_ACCOUNTS43 = (("sha43", 25580), ("shb43", 25580), ("shx43", 25583), ("shc43", 25580),
                     ("shd43", 25584), ("shy43", 25585), ("shz43", 25580))


def _shared_reply43(reply):
    """{port: servers} from a reply's shared_ports, and every note, in order."""
    got = reply.get("shared_ports")
    if not isinstance(got, list):
        return None, []
    return {s.get("port"): s.get("servers") for s in got}, [s.get("note") or "" for s in got]


def _shared43(client):
    """The import names each port an imported server shares with another server on its host."""
    for user, port in _SHARE_ACCOUNTS43:
        _mc43(user, port)
    _account43("gmc43", "gmodserver", {"_default.cfg": _GMOD_DEFAULT43})      # cfg port 27015
    rid, other = _host43("p43-share", "192.0.2.149"), _host43("p43-share-b", "192.0.2.150")
    with _p9.app_context():
        for host, short, name, gt, port in ((rid, "gex43", "p43 gmod main", "gmod", 27015),
                                            (other, "oth43", "oth43", "mc", 25584)):
            gs = GameServer(remote_id=host, name=name, short_name=short, game_type=gt, port=port,
                            installed=True, status="offline")
            db.session.add(gs)
            db.session.commit()
            _mine43["servers"].append(gs.id)
    _shared_batch43(client, rid)
    _shared_existing43(client, rid)
    _shared_apart43(client, rid)


def _shared_batch43(client, rid):
    """Two servers of one batch on one port, and then a third."""
    pair = _post43(client, [{"user": u, "game_type": "mc"} for u in ("sha43", "shb43", "shx43")],
                   rid=rid)
    ports, notes = _shared_reply43(pair)
    check("import shared port: two servers of one batch set to 25580 are both imported on it",
          {u: p for u, p in _rows43(rid).items() if u.startswith("sh")}
          == {"sha43": 25580, "shb43": 25580, "shx43": 25583}, repr(pair))
    check("import shared port: ...and the reply names that port and both servers, and not the "
          "third server's own port", ports == {25580: ["sha43", "shb43"]}, repr(pair))
    check("import shared port: ...and says no two can run at once unless one uses only TCP on it "
          "and the other only UDP (Terraria and ARK both default to 7777) or each has its own "
          "address, and that the panel cannot tell them apart by port while one runs", notes == [
              "sha43 and shb43 are set to the same port, 25580. No two of them can run at the same "
              "time unless one uses only TCP on it and the other only UDP, or each is bound to its "
              "own IP address. While one runs, the panel cannot tell them apart by port, so a "
              "stopped one may read online."], repr(notes))
    three = _post43(client, [{"user": "shc43", "game_type": "mc"}], rid=rid)
    ports, notes = _shared_reply43(three)
    check("import shared port: a third server on 25580 names all three, the two already in the "
          "panel included", (ports, [n.split(" are set to")[0] for n in notes])
          == ({25580: ["sha43", "shb43", "shc43"]}, ["sha43, shb43 and shc43"]), repr(three))


def _shared_existing43(client, rid):
    """A server whose LinuxGSM cfg port (the scan's) is one a server already in the panel has."""
    reply = _post43(client, [{"user": "gmc43", "game_type": "gmod"}], rid=rid)
    ports, notes = _shared_reply43(reply)
    check("import shared port: a server on the port of one already in the panel is imported, and "
          "the reply names that one by its display name",
          (_rows43(rid).get("gmc43"), ports) == (27015, {27015: ["p43 gmod main", "gmc43"]}),
          repr(reply))
    check("import shared port: ...with the same statement", notes[:1] == [
        _gp43.shared_port_note(["p43 gmod main", "gmc43"], 27015)], repr(notes))


def _shared_apart43(client, rid):
    """What is NOT a shared port: a server on another host, and a server that was not imported."""
    apart = _post43(client, [{"user": "shd43", "game_type": "mc"}], rid=rid)
    check("import shared port: a port only a server on ANOTHER host has is not shared — and the "
          "pairs already on this host are not named again", (_rows43(rid).get("shd43"),
                                                             apart.get("shared_ports"))
          == (25584, []), repr(apart))
    _SILENT43.add("shz43")
    try:
        left = _post43(client, [{"user": "shy43", "game_type": "mc"},
                                {"user": "shz43", "game_type": "mc"}], rid=rid)
    finally:
        _SILENT43.discard("shz43")
    check("import shared port: a server left out (its port could not be read) shares nothing: the "
          "one imported beside it is on a port of its own",
          (sorted(left.get("added") or ()), left.get("shared_ports"), "shz43" in _rows43(rid))
          == (["shy43"], [], False), repr(left))


# ── the startup re-read ─────────────────────────────────────────────────────────────────────────
# Each heal host: (name, address, what `ss` lists there or None when it raises, its rows). A row is
# (account, game type, the port stored on it, installed). The accounts' own ports (what LinuxGSM
# reports) are _HEAL_PROPS43; an account with none there reports port 0.
_HEAL_HOSTS43 = (
    ("p43-heal", "192.0.2.143", {22, 2222, 27015, 25565, 25620, 25670, 25680, 25720}, (
        ("gm43", "gmod", 27015, True),      # Garry's Mod, right where it is
        ("mc43", "mc", 27015, True),        # an old import on gmod's port; runs on its 25565
        ("pmc43", "mc", 27015, True),       # ...and a stopped one whose own port mc43 shares
        ("down43", "mc", 25570, True),      # details does not answer
        ("sibl43", "mc", 25590, True),      # reports 25650: blk43's block, nothing listening
        ("blk43", "mc", 25650, True),       # a stopped server reporting nothing
        ("sshp43", "mc", 25580, True),      # reports 2222, the port the panel connects on
        ("sshq43", "mc", 27015, True),      # on gmod's port, and reports sshd's 2200
        ("noprop43", "mc", 25600, True),    # reports port 0
        ("foreign43", "mc", 25610, True),   # reports 25620, which a process outside the panel has
        ("velo43", "mc", 25710, True),      # STARTED, reports 25720 — another process's socket
        ("squat43", "mc", 25670, True),     # stopped, and something else listens on 25670
        ("quiet43", "mc", 25630, True),     # reports a free 25640
        ("nib43", "mc", 25690, True),       # reports 25660: a failed install's block
        ("unins43", "mc", 25660, False),    # that failed install
        ("stop43", "mc", 27015, True))),    # stopped, on gmod's port; its own 25655 is free
    ("p43-heal-b", "192.0.2.144", {22, 2222}, (
        ("gmb43", "gmod", 27015, True),
        ("pmcb43", "mc", 25565, True),      # imported by the new code on its own 25565
        ("mcb43", "mc", 27015, True))),     # the old import of the bug report, on gmod's 27015
    ("p43-heal-del", "192.0.2.145", {22, 2222}, (
        ("qa43", "mc", 25701, True), ("del43", "mc", 25705, True), ("mv43", "mc", 25760, True),
        ("qb43", "mc", 25711, True))),
    ("p43-heal-raise", "192.0.2.146", None, (
        ("ra43", "mc", 25730, True),        # needs the listening ports, whose read raises
        ("rg43", "gmod", 27015, True),
        ("rb43", "mc", 27015, True))),      # on rg43's port: needs no listening read
    ("p43-heal-raise2", "192.0.2.147", {22, 2222}, (("rc43", "mc", 25750, True),)),
    ("p43-heal-after", "192.0.2.148", {22, 2222}, (("qc43", "mc", 25740, True),)),
    # Where the pass leaves the rows decides what its audit says they share.
    ("p43-heal-apart", "192.0.2.139", {22, 2222}, (
        ("gma43", "gmod", 27015, True),
        ("mca43", "mc", 27015, True),       # an old import on gmod's port; its own is 25565...
        ("pma43", "mc", 25565, True),       # ...where this one is stored, whose config now says 25570
        ("mcr43", "mc", 27015, True),       # moved onto pmr43's 25575, then by a request to 25590
        ("pmr43", "mc", 25575, True),       # right where it is
        ("refa43", "mc", 25595, True))),    # reports SSH's 2222: refused, after reading every row
)
_HEAL_PROPS43 = {"pmc43": 25565, "sibl43": 25650, "sshp43": 2222, "sshq43": 2200,
                 "foreign43": 25620, "velo43": 25720, "squat43": 25680, "quiet43": 25640,
                 "nib43": 25660, "stop43": 25655, "pmcb43": 25565, "mcb43": 25565, "qa43": 25700,
                 "del43": 25706, "mv43": 25761, "qb43": 25710, "ra43": 25731, "rb43": 25732, "rc43": 25751,
                 "qc43": 25741, "mca43": 25565, "pma43": 25570, "mcr43": 25575, "pmr43": 25575,
                 "refa43": 2222}


def _heal_rows43():
    """Every heal host and its rows. -> {account on the host: row id} and {address: host id}."""
    want, hosts = {}, {}
    for name, ip, listen, rows in _HEAL_HOSTS43:
        rid = hosts[ip] = _host43(name, ip)
        if listen is None:
            _SS_RAISE43.add(ip)
        else:
            _LISTEN43[ip] = listen
        with _p9.app_context():
            for short, gt, port, installed in rows:
                gs = GameServer(remote_id=rid, name="heal-" + short, short_name=short,
                                game_type=gt, port=port, installed=installed, status="offline")
                db.session.add(gs)
                db.session.commit()
                _mine43["servers"].append(gs.id)
                want[short] = gs.id
    for user, port in _HEAL_PROPS43.items():
        _mc43(user, port)
    return want, hosts


def _restart_listing43(user, port):
    """[flag line, check line] as set_daily_restart writes them for a Minecraft `user` on `port`."""
    before = list(_CRON_WRITTEN43.get(user, ()))
    _p9_core.set_daily_restart(_NS43(id=None, host="192.0.2.143"), user, "mcserver",
                               game_type="mc", port=port, enabled=True)
    lines = _CRON_WRITTEN43.get(user, [])[len(before):]
    _CRON_WRITTEN43[user] = before
    return "\n".join(lines)


def _heal_run43(want, hosts):
    """The re-read over every heal host, with a row deleted and one host's port read raising."""
    orig_read, orig_protected = _gp43.read_reported_ports, _p9_sm.protected_host_ports
    # Absent (a pass that audits each move as it makes it): no request moves mcr43, and the apart
    # host's ports check says so by name.
    orig_audit = getattr(_gp43, "_audit_moves", None)

    def _read_then_delete(remote, wanted):
        got = orig_read(remote, wanted)
        if any(key == want["del43"] for key, _u, _s in wanted):
            with _p9.app_context():         # other requests, with their own session, meanwhile:
                db.session.delete(db.session.get(GameServer, want["del43"]))     # delete one row
                db.session.get(GameServer, want["mv43"]).port = 25762            # move another
                db.session.commit()
        return got

    def _protected(remote):
        if remote.host == "192.0.2.147":
            raise RuntimeError("an unforeseen failure reading this host (part43)")
        return orig_protected(remote)

    def _moved_before_audit(remote_id, moves):
        if remote_id == hosts["192.0.2.139"]:
            with _p9.app_context():         # a request, after the pass moved mcr43 and before its audit
                db.session.get(GameServer, want["mcr43"]).port = 25590
                db.session.commit()
        return orig_audit(remote_id, moves)
    _p9_patch(_gp43, "read_reported_ports", _read_then_delete)
    _p9_patch(_p9_sm, "protected_host_ports", _protected)
    if orig_audit is not None:
        _p9_patch(_gp43, "_audit_moves", _moved_before_audit)
    try:
        _gp43.reconcile_stored_ports(_p9, _ms43.withheld_game_ports, _ms43.sibling_port_blocks)
    except Exception as exc:  # noqa: BLE001 - a raise is a named failure here, never a crash
        check("startup port re-read: runs without raising", False, repr(exc))
    finally:
        _p9_patch(_gp43, "read_reported_ports", orig_read)
        _p9_patch(_p9_sm, "protected_host_ports", orig_protected)
        if orig_audit is not None:
            _p9_patch(_gp43, "_audit_moves", orig_audit)
    forget_rows(server_ids=(want["del43"],))


def _heal43():
    """Rows stored before the import read ports, across six hosts: what moves, and what does not."""
    want, hosts = _heal_rows43()
    _CRON43["stop43"] = _restart_listing43("stop43", 27015)
    _SILENT43.add("down43")
    _STARTED43.update(("mc43", "velo43"))
    _mon43._monitor_state["servers"][want["stop43"]] = True     # read up on gmod's 27015 at boot
    del _CLOSED43[:]
    try:
        _heal_run43(want, hosts)
    finally:
        _SILENT43.discard("down43")
        _STARTED43.difference_update(("mc43", "velo43"))
    with _p9.app_context():
        got = {s: getattr(db.session.get(GameServer, i), "port", None) for s, i in want.items()}
        audits = sorted(a.detail for a in AuditLog.query.filter_by(action="port_resync").all())
    _heal_moved43(got, audits)
    _heal_kept43(got)
    _heal_survives43(got)
    _heal_follows43(want, hosts, audits)
    _heal_shared43(got)


def _heal_shared43(got):
    """A move onto a port another server is on says so in its audit row, as the import does."""
    with _p9.app_context():
        said = {a.target: a.detail or "" for a in AuditLog.query.filter_by(action="port_resync")}
    pair = _gp43.shared_port_note(["heal-mc43", "heal-pmc43"], 25565)
    check("startup port re-read: the stopped row moved onto 25565 beside the running one names "
          "the shared port in its audit row, as the import's reply does",
          pair in said.get("heal-pmc43", ""), repr(said.get("heal-pmc43")))
    check("startup port re-read: ...and so does the running one, moved there before the stopped "
          "one joined it in the same pass: the share is read where the pass leaves the rows",
          pair in said.get("heal-mc43", ""), repr(said.get("heal-mc43")))
    check("startup port re-read: ...and so does the old import moved onto the 25565 a newer "
          "import holds", _gp43.shared_port_note(["heal-pmcb43", "heal-mcb43"], 25565)
          in said.get("heal-mcb43", ""), repr(said.get("heal-mcb43")))
    _heal_apart43(got, said)


def _heal_apart43(got, said):
    """Check that a share the same pass ends, or a request ends before the audit, is not named."""
    check("startup port re-read: the apart host's rows end where their configs and the request "
          "put them", [got[u] for u in ("mca43", "pma43", "mcr43", "pmr43", "refa43")]
          == [25565, 25570, 25590, 25575, 25595], repr(got))
    check("startup port re-read: a row moved onto the port another row was stored on, which the "
          "same pass then moved to the port its config now says, claims no share — nor does that "
          "other row, nor one moved to a free port",
          [t in said and "set to the same port" not in said[t]
           for t in ("heal-mca43", "heal-pma43", "heal-quiet43")] == [True, True, True],
          repr({t: said.get(t) for t in ("heal-mca43", "heal-pma43", "heal-quiet43")}))
    check("startup port re-read: a row a request moved again between the pass's move and its audit "
          "claims no share of the port it left — though its audit row still says where the pass "
          "put it", said.get("heal-mcr43", "").startswith("27015 -> 25575 (")
          and "set to the same port" not in said.get("heal-mcr43", ""), repr(said.get("heal-mcr43")))


def _heal_moved43(got, audits):
    """The rows whose stored port is certainly not theirs, and the free reading: moved."""
    check("startup port re-read: a Minecraft row stored on Garry's Mod's 27015 is moved to the "
          "25565 LinuxGSM reads from its server.properties", got["mc43"] == 25565, repr(got))
    check("startup port re-read: ...and audited, old and new",
          any(d.startswith("27015 -> 25565") for d in audits), repr(audits))
    check("startup port re-read: a STOPPED row on Garry's Mod's 27015 is moved to its own 25565 "
          "although a running neighbour shares that default — the import's own rule",
          got["pmc43"] == 25565, repr(got))
    check("startup port re-read: an old import on 27015 is moved to its 25565 although a server "
          "the new import stored there holds it (the bug report's row, the other order)",
          got["mcb43"] == 25565, repr(got))
    check("startup port re-read: a stopped row whose stored port something else listens on is "
          "moved, even onto a port that is listened on too", got["squat43"] == 25680, repr(got))
    check("startup port re-read: Garry's Mod, already right, is left as it is (control)",
          got["gm43"] == 27015, repr(got))
    check("startup port re-read: ...while a stopped server's free reported port is taken (control)",
          got["quiet43"] == 25640, repr(got))
    check("startup port re-read: only the moved rows are audited",
          [d.split(" (")[0] for d in audits] == [
              "25565 -> 25570", "25630 -> 25640", "25670 -> 25680", "25701 -> 25700",
              "25711 -> 25710", "25740 -> 25741", "27015 -> 25565", "27015 -> 25565",
              "27015 -> 25565", "27015 -> 25565", "27015 -> 25575", "27015 -> 25655",
              "27015 -> 25732"], repr(audits))


def _heal_kept43(got):
    """The readings the re-read may not take."""
    check("startup port re-read: a server whose details does not answer keeps its port",
          got["down43"] == 25570, repr(got))
    check("startup port re-read: a server that reports port 0 keeps its port",
          got["noprop43"] == 25600, repr(got))
    check("startup port re-read: a reported port in another server's block is not taken — one "
          "nothing listens on, so only the block refuses it", got["sibl43"] == 25590, repr(got))
    check("startup port re-read: ...nor one in the block of a server whose install failed",
          got["nib43"] == 25690, repr(got))
    check("startup port re-read: a reported port that is this host's SSH is not taken",
          got["sshp43"] == 25580, repr(got))
    check("startup port re-read: ...nor SSH's port from sshd's config, even for a row whose "
          "stored port is another server's", got["sshq43"] == 27015, repr(got))
    check("startup port re-read: a reported port something else listens on while the server is "
          "stopped is not taken", got["foreign43"] == 25610, repr(got))
    check("startup port re-read: ...nor while LinuxGSM says STARTED: a game that failed to bind "
          "keeps its tmux session, so STARTED does not make the listener this server",
          got["velo43"] == 25710, repr(got))


def _heal_survives43(got):
    """A deleted row, a raising port read and a failing host stop nothing after them."""
    check("startup port re-read: a row deleted while the pass ran is skipped, and the rows after "
          "it on its host are still healed", (got["del43"], got["qa43"], got["qb43"])
          == (None, 25700, 25710), repr(got))
    check("startup port re-read: a row whose port something else changed while the pass ran is "
          "left on that port, not overwritten with the pass's older reading",
          got["mv43"] == 25762, repr(got))
    check("startup port re-read: a row whose listening-port read RAISES (paramiko) keeps its port, "
          "and the next row on that host is still healed", (got["ra43"], got["rb43"])
          == (25730, 25732), repr(got))
    check("startup port re-read: a host that fails outright keeps its rows, and the host after it "
          "is still read", (got["rc43"], got["qc43"]) == (25750, 25741), repr(got))


def _heal_follows43(want, hosts, audits):
    """What a move carries along: the monitor's state, the cron line, this server's own rule."""
    n = len(_NOTIFIED43)
    with _p9.app_context():
        gs = db.session.get(GameServer, want["stop43"])
        remote = _remote43(hosts["192.0.2.143"])
        for _ in range(_mon43._DOWN_CONFIRM_SWEEPS):
            _mon43._monitor_server(remote, gs, {}, {27015})       # its own 25655: nothing there
        paged = [b for k, b in _NOTIFIED43[n:] if k == "server_down" and "heal-stop43" in b]
        db.session.rollback()
    forget_rows(server_ids=(want["stop43"],))
    check("startup port re-read: a stopped server the monitor read up on its neighbour's port, and "
          "moved to its own, does not page 'went offline unexpectedly'", paged == [],
          repr(_NOTIFIED43[n:]))
    _heal_carried43(audits)


def _heal_carried43(audits):
    """The cron line and this server's own firewall rule, after a move."""
    lines = _CRON_WRITTEN43.get("stop43", [])
    check("startup port re-read: a moved server's restart-when-empty check asks its new port, not "
          "the neighbour's", any("192.0.2.143:25655 " in ln for ln in lines)
          and not any(":27015" in ln for ln in lines), repr(lines))
    check("startup port re-read: this server's own firewall rule on its old port is closed where "
          "nothing else can need it", (25630, "quiet43") in _CLOSED43, repr(_CLOSED43))
    check("startup port re-read: ...and never on a port another server's block covers, or that "
          "something listens on", not [c for c in _CLOSED43 if c[0] in (27015, 25670)],
          repr(_CLOSED43))
    check("startup port re-read: ...and the audit row says so, and that the new port is not opened",
          any(d.startswith("25630 -> 25640") and "closed this server's firewall rule on 25630" in d
              and "not opened on 25640: 'Open all ports'" in d for d in audits), repr(audits))


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
    for fd in _FIFO_FDS43:
        os.close(fd)
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
    _shared43(_p9_client(P9_ADMIN))
    _wired43()
finally:
    _p9_restore_all()
    _cleanup43()
    for _cache43, _saved43 in zip((_p9_app._GAME_LIST_CACHE, _p9_app._LGSM_NAME_MAP), _CACHES43):
        _cache43.clear()
        _cache43.update(_saved43)

check("part43: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP43_START, repr(_P9_TRIPPED[_TRIP43_START:][:6]))


# ══ Review 2026-10-08: core, routes and auth fixes, on part12's app ══════════════════════════════
# Each section drives the real route or function; part12's tripwire is armed again around them,
# and every row, stub and in-memory entry made here is undone in the finally.
import json as _json43
import re as _re43
import time as _time43

import pyotp as _pyotp43

from unit.part12 import (P9_GM, P9_GS, P9_HOST, _P9_PATCHED, _P9Thread, _p9_flashes, _p9_queue,
                         _p9_set, _p9_set_host, _p9_host_row, _p9_threading)
from panel.core import runtime_stats as _rs43
from panel.core.config import encrypt_secret as _enc43
from panel.core import panel_state as _state43
from panel.db import models as _models43
from panel.db.models import Group as _Group43, User as _User43
from panel.routes import _shared as _sh43
from panel.routes import remote_tailscale as _rts43
from panel.routes import route_helpers as _rh43
from panel.routes import server_detail as _sd43
from panel.routes import server_files as _sf43
from panel.ops import tailscale_integration as _ts43
from panel.security import auth as _pauth43

_TRIP_RV43 = len(_P9_TRIPPED)
_RV43 = {"users": [], "groups": [], "ips": []}


class _Rv43Stop(BaseException):
    """Ends a `while True` loop under test; BaseException so the loop's own except cannot eat it."""


def _rv43_arm():
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part43's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_ts43, "get_tailscale_info", lambda force_refresh=False: _NS43(dns_name=None))
    _p9_patch(_notif43, "notify", lambda key, title, body="": None)
    _p9_patch(_p9.socketio, "emit", lambda *a, **k: None)
    _p9_patch(_sd43, "threading", _p9_threading(_P9Thread))
    _p9_patch(_sh43, "privileged_accounts", lambda remote, users: {})


def _rv43_user(name, perms=(), hosts=(), superadmin=False, **kw):
    with _p9.app_context():
        u = _User43(username=name, password_hash=_pauth43.hash_password("Str0ng!passw0rd"),
                    display_name=name, is_superadmin=superadmin, is_active=True, **kw)
        if perms or hosts:
            grp = _Group43(name=name + "_grp", description="", is_default=False)
            grp.set_permissions(list(perms))
            for rid in hosts:
                grp.servers.append(db.session.get(RemoteServer, rid))
            db.session.add(grp)
            db.session.flush()
            _RV43["groups"].append(grp.id)
            u.groups.append(grp)
        db.session.add(u)
        db.session.commit()
        _RV43["users"].append(u.id)
        return u.id


# ── init_db: the default group is found by is_default, not by its name ────────────────────────────
def _rv43_default_group():
    with _p9.app_context():
        g = _Group43(name="rv43 Members", description="", is_default=True)
        g.set_permissions({"view_servers"})
        db.session.add(g)
        db.session.commit()
        gid = g.id
        try:
            _models43._ensure_default_group()
            second = _Group43.query.filter_by(name="Everyone").first()
            check("init_db: a renamed default group does not bring back a second 'Everyone' "
                  "(with view_console) at the next start",
                  second is None, "made %r" % (second and second.get_permissions()))
        except Exception as e:
            check("init_db: a renamed default group does not bring back a second 'Everyone' "
                  "(with view_console) at the next start", False, repr(e))
        finally:
            _Group43.query.filter_by(name="Everyone").delete()
            db.session.delete(db.session.get(_Group43, gid))
            db.session.commit()
        _models43._ensure_default_group()
        made = _Group43.query.filter_by(name="Everyone", is_default=True).first()
        check("init_db: ...while a database with no default group still gets one (positive control)",
              made is not None and "view_console" in made.get_permissions())
        _Group43.query.filter_by(name="Everyone").delete()
        db.session.commit()


# ── app.py run as __main__: one copy of the module ───────────────────────────────────────────────
def _rv43_one_module():
    main = _main_block43() or ast.Module(body=[], type_ignores=[])
    first = next((i for i, st in enumerate(main.body) if _calls43(st, "create_app")), None)
    before = "\n".join(ast.unparse(st) for st in main.body[:first or 0])
    check("app.py: run as __main__, it registers itself as 'app' before create_app imports a route "
          "module (no second copy of its globals)",
          first is not None and _re43.search(
              r"modules\.setdefault\('app', \w+\.modules\['__main__'\]\)", before) is not None,
          before[-300:])


# ── the auto-block loop: a malformed config value, and an exception in a pass ─────────────────
def _rv43_autoblock():
    got = []
    for raw in (5, True, "1,2", [[1], 2, True, "3", None]):
        _p9_patch(_p9_app, "load_config", lambda raw=raw: {"autoblock_hosts": raw})
        try:
            got.append(_p9_app._autoblock_hosts())
        except Exception as e:
            got.append(repr(e))
    check("autoblock: a hand-edited autoblock_hosts that is not a list of ids reads as those ids "
          "(none), not a TypeError", got == [set(), set(), set(), {2}], repr(got))
    sleeps = []

    def _sleep(_s):
        sleeps.append(_s)
        if len(sleeps) >= 2:
            raise _Rv43Stop()

    def _births(_ids):
        raise RuntimeError("a pass that fails")

    _p9_patch(_p9_app, "time", _NS43(sleep=_sleep, time=_time43.time, monotonic=_time43.monotonic))
    _p9_patch(_p9_app, "_autoblock_hosts", lambda: {1})
    _p9_patch(_p9_app, "_autoblock_births", _births)
    before = _rs43.snapshot("loopfail").get("autoblock", 0)
    try:
        _p9_app._autoblock_watch(_p9)
        outcome = "returned"
    except _Rv43Stop:
        outcome = "survived"
    except Exception as e:
        outcome = repr(e)
    finally:
        for name in ("time", "_autoblock_hosts", "_autoblock_births", "load_config"):
            _p9_patch(_p9_app, name, _P9_PATCHED[(_p9_app, name)])
    check("autoblock: a pass that raises does not end the (unsupervised) loop; it goes on to the "
          "next hour", outcome == "survived" and len(sleeps) == 2, "%s after %d sleep(s)"
          % (outcome, len(sleeps)))
    check("autoblock: ...and the failure is counted where the debug report reads it",
          _rs43.snapshot("loopfail").get("autoblock", 0) == before + 1,
          repr(_rs43.snapshot("loopfail")))


# ── Ubuntu Pro cache stamp: real epoch seconds on a non-UTC host ─────────────────────────────────
def _rv43_pro_stamp():
    saved = os.environ.get("TZ")
    os.environ["TZ"] = "RVT+5"           # POSIX form: UTC-5, no tz database needed
    _time43.tzset()
    try:
        offset = _time43.timezone
        r = RemoteServer(name="rv43-pro", host="192.0.2.99")
        r.update_pro_cache({"attached": False})
        ts = _json43.loads(r.pro_cache)["ts"]
        now = _time43.time()
    finally:
        if saved is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = saved
        _time43.tzset()
    check("Ubuntu Pro cache: stamped in epoch seconds on a host 5 h behind UTC, not 5 h ahead",
          offset == 18000 and abs(ts - now) < 60, "offset=%s ts-now=%.0f" % (offset, ts - now))


# ── actions on a server that is still installing ─────────────────────────────────────────────────
def _rv43_installing(admin):
    reasons = {}
    for label, fields in (("installing", dict(status="installing", installed=False)),
                          ("configuring", dict(status="configuring", installed=True)),
                          ("failed", dict(status="failed", installed=False))):
        _p9_set(P9_GM, **fields)
        r = admin.post("/api/servers/bulk-action", json={"action": "restart", "server_ids": [P9_GM]})
        d = _p9_json(r)
        reasons[label] = ([s.get("reason") for s in d.get("skipped", [])], len(d.get("queued", [])))
    _p9_set(P9_GM, status="offline", installed=True)
    with _state43._install_lock:
        _state43._install_jobs[P9_GM] = {"status": "running"}
    try:
        r = admin.post("/api/servers/bulk-action", json={"action": "update", "server_ids": [P9_GM]})
        d = _p9_json(r)
        reasons["job"] = ([s.get("reason") for s in d.get("skipped", [])], len(d.get("queued", [])))
        single = _p9_json(admin.post("/api/server/%d/action" % P9_GM, json={"action": "restart"}))
    finally:
        with _state43._install_lock:
            _state43._install_jobs.pop(P9_GM, None)
    leaked = len(_p9_queue)
    _p9_queue.clear()
    check("bulk action: a server still installing (or configuring) is skipped, not handed a second "
          "SteamCMD or a start",
          reasons.get("installing") == (["still installing"], 0)
          and reasons.get("configuring") == (["still installing"], 0)
          and reasons.get("job") == (["still installing"], 0), repr(reasons))
    check("bulk action: ...and a failed install is skipped as not installed",
          reasons.get("failed") == (["not installed"], 0), repr(reasons))
    check("server action: the single route refuses it too (it, the bulk worker and the chat bots "
          "share _run_action)",
          single.get("success") is False and "still installing" in (single.get("message") or "")
          and leaked == 0, "%r, %d worker(s) queued" % (single, leaked))


# ── file-browser READS as an account that can become root ────────────────────────────────────────
def _rv43_reads(admin):
    seen = []
    for name in ("browse_dir", "read_file", "stat_path", "stream_path", "stat_upload_targets"):
        _p9_patch(_sf43, name, lambda *a, _n=name, **k: (seen.append(_n), None)[1])
    _sh43._ACCOUNT_VERDICTS.clear()
    _p9_patch(_sh43, "privileged_accounts", lambda remote, users: {u: "in the sudo group" for u in users})
    try:
        b = admin.get("/api/server/%d/browse?path=.ssh" % P9_GS)
        f = admin.get("/api/server/%d/file?path=.bash_history" % P9_GS)
        u = admin.post("/api/server/%d/upload-check" % P9_GS, json={"path": "", "names": ["a"]})
        dl = admin.get("/server/%d/download?path=.ssh" % P9_GS)
        flashes = _p9_flashes(admin)
    finally:
        _p9_patch(_sh43, "privileged_accounts", lambda remote, users: {})
        _sh43._ACCOUNT_VERDICTS.clear()
    check("file browser: a listing as a root-capable account is refused (409), as its writes are",
          b.status_code == 409 and "can become root" in (_p9_json(b).get("error") or ""),
          "%d %r" % (b.status_code, _p9_json(b)))
    check("file browser: ...and so is reading a file as it",
          f.status_code == 409 and "can become root" in (_p9_json(f).get("error") or ""),
          "%d %r" % (f.status_code, _p9_json(f)))
    check("file browser: ...and the upload pre-check's listing",
          u.status_code == 409, "%d %r" % (u.status_code, _p9_json(u)))
    check("file browser: ...and a download is a redirect that says why, with nothing streamed",
          dl.status_code == 302 and any("can become root" in m for m in flashes) and not seen,
          "%d flashes=%r host reads=%r" % (dl.status_code, flashes, seen))
    _sh43._ACCOUNT_VERDICTS.clear()
    _p9_patch(_sf43, "browse_dir", lambda *a, **k: {"path": "", "entries": []})
    ok = admin.get("/api/server/%d/browse?path=" % P9_GS)
    check("file browser: ...while a plain game account is still listed (positive control)",
          ok.status_code == 200 and _p9_json(ok).get("entries") == [], "%d" % ok.status_code)


# ── the setup wizard's first admin: the same username rules as every other path ──────────────────
def _rv43_setup_username():
    made = []
    _p9_patch(_rh43, "User", _NS43(query=_NS43(filter_by=lambda **k: _NS43(first=lambda: None))))
    _p9_patch(_rh43, "_create_first_admin", lambda state, data, u, p, e: (made.append(u), "made")[1])
    try:
        for name in ("ad\tmin", "ad min", "ad\x1bmin", "a" * 81, "admin"):
            with _p9.test_request_context("/setup", method="POST", data={
                    "username": name, "password": "Str0ng!passw0rd-rv43",
                    "confirm_password": "Str0ng!passw0rd-rv43"}):
                _rh43._setup_admin_user(None, {})
    finally:
        for name in ("User", "_create_first_admin"):
            _p9_patch(_rh43, name, _P9_PATCHED[(_rh43, name)])
    check("setup wizard: the first admin's username is refused with a tab, a space, a control "
          "character or 81 characters, as on every other path",
          made == ["admin"], repr(made))


# ── Tailscale migrate: a delegated MANAGE_REMOTES admin may not repoint a host ──────────────────
def _rv43_migrate(admin, deleg):
    calls = []
    _p9_patch(_rts43, "remote_migrate_to_tailscale",
              lambda remote: (calls.append(remote.id), ("prod-db.tail0000.ts.net",
                                                        {"tailscale_ip": "100.64.0.9", "dns_name": ""}))[1])
    _p9_patch(_rts43, "close_connection", lambda remote: None)
    before = _p9_host_row(P9_HOST)
    r = deleg.post("/api/remote/%d/tailscale-migrate" % P9_HOST, json={})
    after = _p9_host_row(P9_HOST)
    check("tailscale migrate: a delegated MANAGE_REMOTES admin is refused (403) before the host is "
          "asked anything",
          r.status_code == 403 and not calls, "%d %r calls=%r" % (r.status_code, _p9_json(r), calls))
    check("tailscale migrate: ...and the row still points where it did, on its own credential",
          (after.host, after.auth_method) == (before.host, before.auth_method),
          "%s/%s -> %s/%s" % (before.host, before.auth_method, after.host, after.auth_method))
    r = admin.post("/api/remote/%d/tailscale-migrate" % P9_HOST, json={})
    moved = _p9_host_row(P9_HOST)
    _p9_set_host(P9_HOST, host=before.host, auth_method=before.auth_method,
                 auth_credential=before.auth_credential, port=before.port)
    check("tailscale migrate: ...while a superadmin still migrates it (positive control)",
          r.status_code == 200 and moved.host == "prod-db.tail0000.ts.net", "%d" % r.status_code)


# ── sign-in's second step: a per-account budget for codes ───────────────────────────────────────
def _rv43_totp_client(uid, ip):
    c = _p9.test_client()
    c.environ_base["REMOTE_ADDR"] = ip
    _RV43["ips"].append(ip)
    with c.session_transaction() as s:
        s["_2fa_pending"] = uid
        s["_2fa_at"] = _time43.time()
    return c


def _rv43_totp():
    secret = _pyotp43.random_base32()
    uid = _rv43_user("rv43_totp", totp_enabled=True, totp_secret=_enc43(secret))
    totp = _pyotp43.TOTP(secret)
    live = {totp.at(_time43.time() + d * totp.interval) for d in (-1, 0, 1, 2)}
    wrong = next(c for c in ("%06d" % n for n in range(123456, 999999, 7919)) if c not in live)
    for i in range(_p9_app.LOGIN_MAX_FAILS):
        _rv43_totp_client(uid, "198.51.100.%d" % (10 + i)).post("/login", data={"totp_code": wrong})
    late = _rv43_totp_client(uid, "198.51.100.99")
    r = late.post("/login", data={"totp_code": totp.now()})
    with late.session_transaction() as s:
        signed_in, pending = s.get("_user_id"), s.get("_2fa_pending")
    check("sign-in 2FA: wrong codes from many addresses use up the ACCOUNT's budget — a right code "
          "after them does not sign in",
          r.status_code != 302 and signed_in is None, "%d user=%r" % (r.status_code, signed_in))
    check("sign-in 2FA: ...and the pending login is dropped, so the password step comes first again",
          pending is None, repr(pending))
    with _sh43._REAUTH_LOCK:
        _sh43._REAUTH_FAILS.pop(uid, None)
    with _p9.app_context():
        _p9_u = db.session.get(_User43, uid)
        _p9_u.last_totp_step = 0
        db.session.commit()
    ok = _rv43_totp_client(uid, "198.51.100.98")
    r = ok.post("/login", data={"totp_code": totp.now()})
    with ok.session_transaction() as s:
        signed = s.get("_user_id")
    with _sh43._REAUTH_LOCK:
        left = list(_sh43._REAUTH_FAILS.get(uid, []))
    check("sign-in 2FA: ...while a right code inside the budget signs in, and gives its slot back "
          "(positive control)", r.status_code == 302 and signed is not None and not left,
          "%d user=%r slots=%r" % (r.status_code, signed, left))


# ── panel-host reads a delegable whole-host grant must not reach ─────────────────────────────────
def _rv43_panel_host_reads(admin, deleg):
    _p9_patch(_rts43, "remote_check_tailscale",
              lambda remote: {"running": True, "tailscale_ip": "100.64.0.1", "dns_name": "p.ts.net"})
    paths = ["/api/remote/%d/tailscale-check", "/api/remote/%d/security/bans",
             "/api/remote/%d/security/top-ips", "/remote/%d/firewall", "/api/remote/%d/firewall",
             "/api/remote/%d/ssh-status", "/api/remote/%d/check-updates", "/api/remote/%d/pro-status"]
    got = {p: deleg.get(p % P9_LOCAL).status_code for p in paths}
    check("panel host: its tailnet name, bans, firewall, SSH state, apt refresh and Pro status are "
          "superadmin-only on the /api/remote/<id> twins too (403 to a delegated grant)",
          all(c == 403 for c in got.values()), repr({p: c for p, c in got.items() if c != 403}))
    check("panel host: ...while the delegate still reads its own remote, and a superadmin the panel "
          "host (positive control)",
          deleg.get("/api/remote/%d/tailscale-check" % P9_HOST).status_code == 200
          and admin.get("/api/remote/%d/tailscale-check" % P9_LOCAL).status_code == 200)


# ── group ids from a form: what an id is ─────────────────────────────────────────────────────────
def _rv43_posted_ids(admin):
    with _p9.app_context():
        target = _Group43(name="rv43_posted", description="", is_default=False)
        db.session.add(target)
        db.session.commit()
        gid = target.id
    _RV43["groups"].append(gid)
    arabic = "".join(chr(0x0660 + int(ch)) for ch in str(gid))
    huge = "9" * 5000
    r1 = admin.post("/users/add", data={"username": "rv43_k1", "groups": [huge]})
    r2 = admin.post("/users/add", data={"username": "rv43_k2", "groups": [arabic, str(2 ** 64)]})
    edit_uid = _rv43_user("rv43_k3")
    r3 = admin.post("/users/%d/edit" % edit_uid, data={"display_name": "k3", "groups": [huge]})
    r4 = admin.post("/users/invite", data={"hours": "1", "groups": [huge]})
    with _p9.app_context():
        made = {n: (u.id, sorted(g.id for g in u.groups)) for n in ("rv43_k1", "rv43_k2")
                for u in [_User43.query.filter_by(username=n).first()] if u is not None}
        _RV43["users"].extend(v[0] for v in made.values())
        with _p9.test_request_context("/", method="POST", data={"groups": [str(2 ** 64), arabic]}):
            cmd = _NS43(groups=None)
            try:
                _p9_app._assign_command_groups(cmd)
                cmd_groups = cmd.groups
            except Exception as e:
                cmd_groups = repr(e)
        from panel.db.models import Invite as _Inv43
        _Inv43.query.delete()
        db.session.commit()
    codes = [r.status_code for r in (r1, r2, r3, r4)]
    check("users: a 5,000-digit or 2**64 group id on add, edit and invite is skipped, not a 500",
          500 not in codes and "rv43_k1" in made, "codes=%r made=%r" % (codes, made))
    check("users: ...and non-ASCII digits are not read as a group nobody ticked",
          made.get("rv43_k2", (0, None))[1] == [], repr(made))
    check("custom commands: the same parse for which groups may run a command (no OverflowError)",
          cmd_groups == [], repr(cmd_groups))


# ── the host page for a delegate on the panel host: no card whose route answers them 403 ─────────
# Rendered for real, then every script it loads (the vendor bundles aside) is RUN in node against
# the rendered markup: a vm context whose unknown globals are inert stubs, and a document whose
# getElementById answers only the ids the page really has. So a script that dereferences one of
# the hidden cards' elements at load throws here, by name.
_RV43_PAGE_JS = r"""
const vm = require('vm'), fs = require('fs');
const cfg = JSON.parse(fs.readFileSync(0, 'utf8'));
const errors = [];
const stub = new Proxy(function(){}, {
  get: (t, k) => k === Symbol.toPrimitive ? (() => '') : k === 'then' ? undefined
               : k === Symbol.iterator ? function*(){} : k === 'length' ? 0 : stub,
  apply: () => stub, construct: () => stub, set: () => true});
const ids = new Set(cfg.ids);
const handlers = [];
const document = {
  getElementById: id => ids.has(id) ? stub : null,
  querySelector: () => null, querySelectorAll: () => [], getElementsByClassName: () => [],
  addEventListener: (ev, fn) => { if (ev === 'DOMContentLoaded') handlers.push(fn); },
  createElement: () => stub, body: stub, documentElement: stub, head: stub, cookie: '',
  readyState: 'loading'};
const real = {console: {log(){}, warn(){}, error(){}, info(){}, debug(){}}, document, JSON, Math, Date,
  Promise, Object, Array, String, Number, Boolean, RegExp, Error, Map, Set, WeakMap, Symbol, parseInt,
  parseFloat, isNaN, encodeURIComponent, decodeURIComponent, setTimeout: () => 0, setInterval: () => 0,
  clearTimeout(){}, clearInterval(){}, requestAnimationFrame: () => 0,
  fetch: () => new Promise(() => {}), localStorage: {getItem: () => null, setItem(){}, removeItem(){}},
  sessionStorage: {getItem: () => null, setItem(){}, removeItem(){}}, MOUNT: ''};
const g = new Proxy(real, {has: () => true,
  get: (t, k) => k in t ? t[k] : (k === Symbol.unscopables ? undefined : stub),
  set: (t, k, v) => { t[k] = v; return true; }});
real.window = g; real.self = g; real.globalThis = g;
const ctx = vm.createContext(g);
for (const [name, code] of cfg.scripts) {
  try { vm.runInContext(code, ctx, {filename: name}); }
  catch (e) { errors.push(name + ': ' + (e && e.message)); }
}
for (const fn of handlers) { try { fn(); } catch (e) { errors.push('DOMContentLoaded: ' + (e && e.message)); } }
let value = null;
if (cfg.eval) { try { value = String(vm.runInContext(cfg.eval, ctx)); } catch (e) { value = 'threw: ' + e.message; } }
process.stdout.write(JSON.stringify({errors, value}));
"""


def _rv43_page_scripts(html):
    """[(name, code)] for every script the page runs, in order, vendor bundles skipped."""
    out = []
    for m in _re43.finditer(r"<script\b([^>]*)>(.*?)</script>", html, _re43.S):
        src = _re43.search(r'src="([^"]+)"', m.group(1))
        if not src:
            out.append(("inline#%d" % len(out), m.group(2)))
            continue
        rel = _re43.sub(r"^.*?/static/", "", src.group(1)).split("?")[0]
        if rel.startswith("vendor/"):
            continue
        with open(os.path.join(_ROOT43, "static", rel), encoding="utf-8") as fh:
            out.append((rel, fh.read()))
    return out


def _rv43_run_page(html, expr=None):
    """The page's scripts' load-time errors (a list), or (errors, value of `expr`); None: no node."""
    node = _shutil43.which("node")
    if not node:
        return None
    cfg = {"ids": sorted(set(_re43.findall(r'\bid="([^"]+)"', html))),
           "scripts": _rv43_page_scripts(html), "eval": expr}
    r = _sp43.run([node, "-e", _RV43_PAGE_JS], input=_json43.dumps(cfg), capture_output=True,
                  text=True, timeout=120, check=False)
    try:
        out = _json43.loads(r.stdout)
    except ValueError:
        out = {"errors": ["harness: " + (r.stdout + r.stderr)[-500:]], "value": None}
    return out.get("errors") if expr is None else (out.get("errors"), out.get("value"))


def _rv43_js_offers():
    """How many places manage_remotes.js builds the migrate offer through _tsMigrateOffer, and none
    that builds the button itself."""
    with open(os.path.join(_ROOT43, "static", "js", "manage_remotes.js"), encoding="utf-8") as fh:
        src = fh.read()
    body = src.split("function _tsMigrateOffer", 1)
    rest = body[0] + (body[1].split("\n}\n", 1)[1] if len(body) > 1 else "")
    return -1 if "_da('migrateToTailscale'" in rest else rest.count("_tsMigrateOffer(remoteId)")


def _rv43_host_page(admin, deleg):
    host_ids = ("sec-osupdates", "sec-firewall", "sec-power", "sec-ubuntupro", "conn-ssh-card")
    _p9_patch(_p9_so, "get_server_status", lambda *a, **k: None)   # remote_manage reads it for the panel host
    local = deleg.get("/remote/%d/manage" % P9_LOCAL)
    html = local.get_data(as_text=True)
    shown = [i for i in host_ids if 'id="%s"' % i in html]
    check("host page: a delegate on the PANEL host is not offered OS updates, firewall, power, "
          "Ubuntu Pro or Connection & SSH (each answers them 403)",
          local.status_code == 200 and not shown and "UPro.load(" not in html,
          "%d still shown: %r" % (local.status_code, shown))
    remote = deleg.get("/remote/%d/manage" % P9_HOST).get_data(as_text=True)
    check("host page: ...while on a REMOTE host the same delegate still has every one of them "
          "(positive control)", all('id="%s"' % i in remote for i in host_ids),
          repr([i for i in host_ids if 'id="%s"' % i not in remote]))
    _p9_set_host(P9_HOST, auth_method="password")
    try:
        mine = deleg.get("/remote/%d/manage" % P9_HOST).get_data(as_text=True)
        theirs = admin.get("/remote/%d/manage" % P9_HOST).get_data(as_text=True)
    finally:
        _p9_set_host(P9_HOST, auth_method="key")
    check("host page: 'Migrate to Tailscale SSH' is not offered to a delegate (the route refuses "
          "them), and says who can",
          'data-action="switchToTailscale"' not in mine and "A superadmin can switch" in mine
          and 'data-action="switchToTailscale"' in theirs)
    for label, page in (("the panel host, as a delegate", html), ("a remote host", remote)):
        errs = _rv43_run_page(page)
        if errs is None:
            skip("host page: its scripts run without touching a missing element (%s)" % label,
                 "no node on this host")
            continue
        check("host page: its scripts run without touching a missing element (%s)" % label,
              errs == [], repr(errs[:5]))
    # The hosts page: manage_remotes.js builds the offer after a join; the template says, by one
    # marker element, whether this viewer may migrate. The script is run with and without it.
    with open(os.path.join(_ROOT43, "templates", "manage_remotes.html"), encoding="utf-8") as fh:
        tpl = fh.read()
    with open(os.path.join(_ROOT43, "static", "js", "manage_remotes.js"), encoding="utf-8") as fh:
        js = "<script>%s</script>" % fh.read()
    prelude = ("<script>function _da(n, a) { return ' data-action=\"' + n + '\"'; }"
               "function escapeHtml(s) { return String(s); }</script>")
    offers = {}
    for who, marker in (("delegate", ""), ("superadmin", '<span id="ts-migrate-allowed" hidden></span>')):
        got = _rv43_run_page(marker + prelude + js, "_tsMigrateOffer(5)")
        offers[who] = None if got is None else (got[1] or "")
    marked = _re43.search(r"\{% if current_user\.is_superadmin %\}<span id=\"ts-migrate-allowed\"", tpl)
    if offers["delegate"] is None:
        skip("hosts page: the after-join 'Migrate' offer is a superadmin's only", "no node on this host")
    else:
        check("hosts page: the after-join 'Migrate' offer is a superadmin's only; a delegate is told "
              "who can (manage_remotes.js, all three places it is built)",
              marked is not None and "migrateToTailscale" not in offers["delegate"]
              and "A superadmin can" in offers["delegate"]
              and "migrateToTailscale" in offers["superadmin"] and _rv43_js_offers() == 3,
              "marker in template: %s, offers %r, built %d" % (bool(marked), offers, _rv43_js_offers()))


def _rv43_cleanup():
    with _p9.app_context():
        for uid in _RV43["users"]:
            u = db.session.get(_User43, uid)
            if u is not None:
                u.groups = []
                db.session.delete(u)
        db.session.commit()
        for gid in _RV43["groups"]:
            g = db.session.get(_Group43, gid)
            if g is not None:
                db.session.delete(g)
        db.session.commit()
    with _sh43._REAUTH_LOCK:
        for uid in _RV43["users"]:
            _sh43._REAUTH_FAILS.pop(uid, None)
    with _p9_app._LOGIN_FAILS_LOCK:
        for ip in _RV43["ips"]:
            _p9_app._LOGIN_FAILS.pop(_pauth43.throttle_key(ip), None)
    _p9_queue.clear()


try:
    _rv43_arm()
    _RV43_ADMIN = _p9_client(P9_ADMIN)
    _RV43_DELEG = _p9_client(_rv43_user("rv43_deleg", perms=[_pauth43.MANAGE_REMOTES],
                                        hosts=[P9_LOCAL, P9_HOST]))
    _rv43_default_group()
    _rv43_one_module()
    _rv43_autoblock()
    _rv43_pro_stamp()
    _rv43_installing(_RV43_ADMIN)
    _rv43_reads(_RV43_ADMIN)
    _rv43_setup_username()
    _rv43_migrate(_RV43_ADMIN, _RV43_DELEG)
    _rv43_totp()
    _rv43_panel_host_reads(_RV43_ADMIN, _RV43_DELEG)
    _rv43_posted_ids(_RV43_ADMIN)
    _rv43_host_page(_RV43_ADMIN, _RV43_DELEG)
finally:
    _p9_restore_all()
    _rv43_cleanup()

check("part43 review section: nothing it drove reached a real transport",
      len(_P9_TRIPPED) == _TRIP_RV43, repr(_P9_TRIPPED[_TRIP_RV43:][:6]))
