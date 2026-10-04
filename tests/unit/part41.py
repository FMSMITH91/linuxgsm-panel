"""Part 41 of the unit suite: clean host reboots (panel/services/host_reboot.py).

Every reboot the panel makes stops the host's running game servers gracefully first, reboots, and
brings back exactly the servers that were running. The invariant under test: every managed
server's LinuxGSM `-monitoring.lock` is in the same state after the reboot as before it, and each
server has exactly one starter (LinuxGSM's monitor for an Autostart server, the panel for one
without, nobody for a stopped one).

HOW IT RUNS. Nothing here reaches a host. Each test host is a DIRECTORY standing in for one: a
home per game account with LinuxGSM's `lgsm/lock` and `lgsm/data/<s>.uid`, a stand-in LinuxGSM
script that does what LinuxGSM's stop and start do to the lock files and the tmux session, and a
state directory the stand-in `tmux`, `pgrep`, `crontab`, `date` and `id` read. The panel's own
transports are replaced at their lowest layer (_core._run_via_paramiko, _run_via_ssh_cli,
_run_local, _exec_local_argv), so every command host_reboot builds goes through the REAL
shell_as_game_user / run_as_game_user / run_privileged code, and every shell script it builds is
RUN, by bash, against that directory (its /home, /proc and /etc paths pointed into it). A down
host fails the way each transport really fails: paramiko raises, the tailscale and local
transports return ("", "...timed out", -1).

The clock host_reboot reads is this part's own (sleeps advance it, nothing waits), and the second
of the minute every stand-in reports is that clock's. The job runs in line (host_reboot._spawn),
so nothing is left running. Notifications are recorded, never sent.

Two checks use REAL processes: the probe's LinuxGSM-command pattern is matched by the real pgrep
against a real `/bin/bash ./<s> start` process (and must not count the shell that asks), and the
bootstrap / install.sh "game servers running?" probe is run by the real pgrep against a process
named "tmux: server".
"""
import importlib.machinery as _mach41
import importlib.util as _ilu41
import json as _json41
import os
import shlex as _shlex41
import shutil as _shutil41
import subprocess as _sp41  # nosec B404 - runs this part's own stand-in scripts under bash
import sys
import tempfile as _tf41
import threading as _th41
import time as _time41
import uuid as _uuid41
from types import SimpleNamespace as NS

from flask import Flask as _Flask41
from sqlalchemy import text as _sa_text41

from unit.part01 import check, eq, skip
from unit.part20 import _patch, _patched
from panel.core import panel_state as _ps41
from panel.db.models import AuditLog, GameServer, RemoteServer, db
from panel.ops import ssh_manager as _sm41
from panel.ops import system_ops as _so41
from panel.ops.ssh_manager import _core as _core41
from panel.ops.ssh_manager import cron as _cron41
from panel.ops.ssh_manager import hosts as _hosts41
from panel.security import privileged as _priv41
from panel.services import host_reboot as HR
from panel.services import monitoring as _mon41
from panel.services import notifications as _notif41

_ROOT41 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_TMP41 = _tf41.mkdtemp(prefix="lgsm-unit-p41-")
_BIN41 = os.path.join(_TMP41, "bin")
os.makedirs(_BIN41)


def _run41(argv, **kw):
    """Run one of this part's own commands (a stand-in script, bash on one, pgrep); never raises."""
    return _sp41.run(argv, capture_output=True, text=True, check=False, **kw)  # nosec B603 - this part's own argv


def _popen41(argv, **kw):
    """Start one of this part's own stand-in processes."""
    return _sp41.Popen(argv, **kw)  # nosec B603 - this part's own argv


def _write_exec41(path, text):
    """Write a stand-in script this part runs, and make it executable."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, 0o755)  # nosec B103 - a stand-in script in this part's own temp dir must run


def _all41(*conds):
    """All of these hold (each named on its own, rather than one long `and` chain)."""
    return all(conds)


# ── the stand-in programs a host's shell finds first on PATH ────────────────────────────────────
_FAKES41 = {
    # tmux -L <socket> list-sessions | has-session -t <s> | send-keys -t <s> <text> Enter
    "tmux": r'''#!/bin/bash
sock=""; if [ "$1" = "-L" ]; then sock="$2"; shift 2; fi
cmd="$1"; shift; t=""; [ "$1" = "-t" ] && t="$2"
f="$FAKE_STATE/tmux/$sock"
case "$cmd" in
  list-sessions) [ -f "$f" ] || { echo "no server running on $sock" >&2; exit 1; }; cat "$f"; exit 0 ;;
  has-session) [ -f "$f" ] && grep -Fxq -- "$t" "$f"; exit $? ;;
  send-keys) [ -f "$f" ] || exit 1; printf 'say %s %s\n' "$t" "$3" >> "$FAKE_LOG"; exit 0 ;;
esac
exit 1
''',
    # pgrep -u <user> -fc <pattern>: the count this host's state says is running for <selfname>
    "pgrep": r'''#!/bin/bash
pat="${@: -1}"
s=$(printf '%s' "$pat" | sed -e 's#^/\[\(.\)\]\([^ ]*\) .*#\1\2#' -e 's#\[\.\]#.#g')
case "$pat" in *"(monitor|"*) f="$FAKE_STATE/inflight/$s" ;; *) f="$FAKE_STATE/maint/$s" ;; esac
n=$(cat "$f" 2>/dev/null || echo 0)
echo "$n"; [ "$n" -gt 0 ]
''',
    "crontab": r'''#!/bin/bash
cat "$FAKE_STATE/crontab/$FAKE_USER" 2>/dev/null || { echo "no crontab for $FAKE_USER" >&2; exit 1; }
''',
    "date": r'''#!/bin/bash
case "$1" in
  +%s) echo "$FAKE_NOW" ;;
  +%S) printf '%02d\n' "$FAKE_SEC" ;;
  *) exec /usr/bin/env -i PATH=/usr/bin:/bin date "$@" ;;
esac
''',
    "id": r'''#!/bin/bash
case "$1" in -un) echo "$FAKE_USER" ;; -u) echo 4242 ;; *) echo "uid=4242($FAKE_USER)" ;; esac
''',
}
for _n41, _src41 in _FAKES41.items():
    _write_exec41(os.path.join(_BIN41, _n41), _src41)

# What LinuxGSM's own `stop` and `start` do to the files this feature depends on (v26.2.0
# command_stop.sh / command_start.sh): a stop the operator typed removes -started.lock AND
# -monitoring.lock and ends the session; a start writes -monitoring.lock FIRST, refuses (exit 2)
# when the session is already up, else starts it, writes -started.lock and removes -starting.lock.
# Each call is logged with whether a -starting.lock was in place when it began.
_LGSM41 = r'''#!/bin/bash
s="$(basename "$0")"; L=lgsm/lock; ST="$FAKE_STATE"
u=$(cat "lgsm/data/$s.uid" 2>/dev/null); sock="$s${u:+-$u}"
sl=0; [ -f "$L/$s-starting.lock" ] && sl=1
echo "$1 $s starting_lock=$sl" >> "$FAKE_LOG"
echo "$1 $s $FAKE_NOW" >> "$FAKE_LOG.t"
case "$1" in
  stop)
    if [ -f "$ST/refuse_stop/$s" ]; then echo "1 players are on the server: stop prevented"; exit 0; fi
    rm -f "$ST/tmux/$sock" "$FAKE_R/tmuxdir-4242/$sock"
    rm -f "$L/$s-started.lock" "$L/$s-monitoring.lock"
    echo "Graceful: sending stop"; exit 0 ;;
  start)
    date +%s > "$L/$s-monitoring.lock"
    if [ -f "$ST/tmux/$sock" ] && grep -Fxq "$s" "$ST/tmux/$sock"; then echo "is already running"; exit 2; fi
    if [ -f "$ST/already/$s" ]; then echo "is already running"; exit 2; fi
    if [ -f "$ST/fail_start/$s" ]; then echo "FAIL: Unable to start $s"; exit 1; fi
    printf '%s\n' "$s" > "$ST/tmux/$sock"; : > "$FAKE_R/tmuxdir-4242/$sock"
    date +%s > "$L/$s-started.lock"; rm -f "$L/$s-starting.lock"
    echo "Started"; exit 0 ;;
esac
exit 3
'''


class _Clock41:
    """time.time / monotonic / sleep for host_reboot: a sleep advances it, nothing waits."""

    def __init__(self, start):
        self.t = float(start)

    def time(self):
        return self.t

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += max(0.0, float(s))


_CLOCK41 = _Clock41(1791000000.0)          # an exact minute: sec 0
_TRACE41 = []                              # (host, event) in the order things happened
_STAMPS41 = []                             # (host, event, second of the minute) for the same events
# What the "is apt running?" verb sends to a remote, as the verb table renders it: the stand-in
# hosts answer exactly this text, so a pattern change cannot leave them answering something else.
_APT_CMD41 = _priv41.remote_command("apt-any-running", [], merge_stderr=False)
# The transports' own bodies, kept before any stub: the apt check runs the real renderings.
_REAL_PARAMIKO41 = _core41._run_via_paramiko
_REAL_SSHCLI41 = _core41._run_via_ssh_cli
_HOSTS41 = {}                              # remote id -> _Host41
_NOTES41 = []                              # (event key, title, body)


class _Host41:
    """One stand-in host: its homes, its LinuxGSM state, and what was done to it."""

    def __init__(self, name):
        self.name = name
        self.root = _tf41.mkdtemp(prefix="host-%s-" % name, dir=_TMP41)
        self.state = os.path.join(self.root, "state")
        for d in ("tmux", "inflight", "maint", "crontab", "refuse_stop", "fail_start", "already"):
            os.makedirs(os.path.join(self.state, d))
        os.makedirs(os.path.join(self.root, "tmuxdir-4242"))
        self.log = os.path.join(self.root, "log")
        open(self.log, "w").close()
        self.boot = str(_uuid41.uuid4())
        self.mid = _uuid41.uuid4().hex
        self.booted_at, self.sysstate = _CLOCK41.time() - 5000.0, "running"
        self.down, self.sudo_ok, self.reboot_rc = False, True, 0
        self.dpkg_held = self.apt_running = False
        self.sudo_silent = None            # `sudo true` gets no answer: its rc (-1, 255), or "raise"
        self.root_refused = False          # root's sudo refused; `sudo -u <game account>` still works
        self.own = None                    # the account the panel itself runs as, on its own host
        self.no_sudo_self = False          # `sudo -u <own>` refused: no sudoers rule names it
        self.players = {}                  # user -> count, or None for unreadable
        self.servers = {}                  # selfname -> user
        self.scoped = []                   # commands that came in under systemd-run --user --scope
        self._write_ids()

    def _write_ids(self):
        for fn, val in (("boot_id", self.boot), ("machine-id", self.mid),
                        ("uptime", "%.2f 0.00" % self.uptime)):
            with open(os.path.join(self.state, fn), "w") as fh:
                fh.write(val + "\n")

    @property
    def uptime(self):
        return _CLOCK41.time() - self.booted_at

    def timed(self, kind):
        """[(selfname, clock)] of every `kind` (start/stop) LinuxGSM ran, in order."""
        try:
            with open(self.log + ".t") as fh:
                return [(ln.split()[1], float(ln.split()[2])) for ln in fh if ln.startswith(kind + " ")]
        except OSError:
            return []

    def home(self, user):
        return os.path.join(self.root, "home", user)

    def lock(self, selfname, kind="monitoring"):
        user = self.servers[selfname]
        suffix = "-monitoring.lock" if kind == "monitoring" else ".lock"
        return os.path.join(self.home(user), "lgsm", "lock", selfname + suffix)

    def add(self, user, selfname, running=True, lock="monitoring", autostart=True, uid="u1d00001"):
        """Install a LinuxGSM instance in `user`'s home."""
        self.servers[selfname] = user
        home = self.home(user)
        for d in ("lgsm/lock", "lgsm/data"):
            os.makedirs(os.path.join(home, d), exist_ok=True)
        if uid:
            with open(os.path.join(home, "lgsm", "data", selfname + ".uid"), "w") as fh:
                fh.write(uid + "\n")
        _write_exec41(os.path.join(home, selfname), _LGSM41)
        if lock == "monitoring":
            with open(self.lock(selfname), "w") as fh:
                fh.write("1790000000\n")
        elif lock == "legacy":
            with open(self.lock(selfname, "legacy"), "w") as fh:
                fh.write("1790000000\n")
        if autostart:
            line = "*/5 * * * * %s\n" % _cron41._record_managed_cmd(user, "/home/%s/%s monitor" % (user, selfname))
            with open(os.path.join(self.state, "crontab", user), "a") as fh:
                fh.write(line)
        if running:
            self.run(selfname, True)
        return self

    def sock(self, selfname):
        p = os.path.join(self.home(self.servers[selfname]), "lgsm", "data", selfname + ".uid")
        try:
            with open(p) as fh:
                return selfname + "-" + fh.read().strip()
        except OSError:
            return selfname

    def run(self, selfname, up):
        f = os.path.join(self.state, "tmux", self.sock(selfname))
        d = os.path.join(self.root, "tmuxdir-4242", self.sock(selfname))
        if up:
            with open(f, "w") as fh:
                fh.write(selfname + "\n")
            open(d, "w").close()
        else:
            for p in (f, d):
                if os.path.exists(p):
                    os.remove(p)

    def running(self, selfname):
        f = os.path.join(self.state, "tmux", self.sock(selfname))
        return os.path.exists(f)

    def setn(self, kind, selfname, n):
        with open(os.path.join(self.state, kind, selfname), "w") as fh:
            fh.write("%d\n" % n)

    def flag(self, kind, selfname, on=True):
        p = os.path.join(self.state, kind, selfname)
        if on:
            open(p, "w").close()
        elif os.path.exists(p):
            os.remove(p)

    def events(self):
        with open(self.log) as fh:
            return [ln.strip() for ln in fh if ln.strip()]

    def reboot_now(self):
        """What a reboot does: a new boot id, every session gone, the lock files untouched."""
        self.boot = str(_uuid41.uuid4())
        self.booted_at = _CLOCK41.time()
        for f in os.listdir(os.path.join(self.state, "tmux")):
            os.remove(os.path.join(self.state, "tmux", f))
        for f in os.listdir(os.path.join(self.root, "tmuxdir-4242")):
            os.remove(os.path.join(self.root, "tmuxdir-4242", f))
        self._write_ids()

    # ── the transport's other end ──
    def _env(self, user):
        now = int(_CLOCK41.time())
        return {"PATH": _BIN41 + ":/usr/bin:/bin", "FAKE_STATE": self.state, "FAKE_USER": user,
                "FAKE_NOW": str(now), "FAKE_SEC": str(now % 60), "FAKE_LOG": self.log,
                "FAKE_R": self.root, "HOME": self.home(user), "LC_ALL": "C"}

    def _paths(self, script):
        # nosec B108 below: the host's script names its own tmux dir; it is rewritten into this part's.
        return (script.replace("/home/", self.root + "/home/")
                .replace("/tmp/tmux-", self.root + "/tmuxdir-")  # nosec B108
                .replace("/proc/sys/kernel/random/boot_id", os.path.join(self.state, "boot_id"))
                .replace("/etc/machine-id", os.path.join(self.state, "machine-id"))
                .replace("/proc/uptime", os.path.join(self.state, "uptime")))

    def bash(self, user, script):
        """Run `script` as this host's `user` would: bash, this host's paths, the stand-ins."""
        _TRACE41.append((self.name, _kind41(script)))
        _STAMPS41.append((self.name, _kind41(script), int(_CLOCK41.time()) % 60))
        p = _run41(["bash", "-c", self._paths(script)], env=self._env(user), timeout=60)
        return p.stdout, p.stderr, p.returncode

    def lgsm(self, user, selfname, action):
        """A LinuxGSM action run the way the helper's lgsm-command runs it (./<s> from the home)."""
        return self.bash(user, "cd /home/%s && ./%s %s 2>&1" % (user, selfname, action))

    def execute(self, command, sudo):
        """One command over this host's transport."""
        cmd = command.strip()
        if cmd.startswith("systemd-run "):
            self.scoped.append(cmd)
            cmd = cmd[cmd.index(" -- ") + 4:].strip()
        if cmd.startswith("sudo -u "):
            return self._as_account(_shlex41.split(cmd))
        if "/etc/machine-id /proc/uptime" in cmd:
            _TRACE41.append((self.name, "identity"))
            return ("%s\n%s\n%.2f 0.00\n%d\n%s\n" % (self.boot, self.mid, self.uptime,
                                                    int(_CLOCK41.time()), self.sysstate), "", 0)
        if cmd == "echo ok":
            return "ok\n", "", 0
        if self.own and not sudo:
            return self.bash(self.own, cmd)          # the panel's own account, no sudo
        return self._escalated(cmd, sudo)

    def _as_account(self, toks):
        """`sudo -u <account> bash -c <script>`: refused as the host's sudoers would refuse it."""
        if not self.sudo_ok or (self.no_sudo_self and toks[2] == self.own):
            return "", "sudo: a password is required", 1
        if toks[3:5] == ["bash", "-c"]:
            return self.bash(toks[2], toks[5])
        return "", "unsupported", 1

    def _escalated(self, cmd, sudo):
        """A command as root (sudo) or as the login: answered, refused, or never answered."""
        if sudo and cmd == "true" and self.sudo_silent in (-1, 255):
            return "", "ssh: connect to host: Connection timed out", self.sudo_silent
        if sudo and (not self.sudo_ok or self.root_refused):
            return "", "sudo: a password is required", 1
        return self._root(cmd)

    def _root(self, cmd):
        if cmd == "true":
            return "", "", 0
        if "sleep 2 ; reboot" in cmd:
            _TRACE41.append((self.name, "reboot"))
            _STAMPS41.append((self.name, "reboot", int(_CLOCK41.time()) % 60))
            return ("scheduled\n" if self.reboot_rc == 0 else "",
                    "" if self.reboot_rc == 0 else "sudo: a password is required", self.reboot_rc)
        if "fuser /var/lib/dpkg/lock-frontend" in cmd:
            return "", "", 0 if self.dpkg_held else 1
        if cmd == _APT_CMD41:
            return "", "", 0 if self.apt_running else 1
        _TRACE41.append((self.name, "root:" + cmd[:40]))
        return "", "", 0


def _kind41(script):
    """What a shell script host_reboot sent IS, for the order of events."""
    for marker, kind in (("PROBE_OK", "probe"), ("DISARM=", "disarm"), ("ARMED=", "rearm"),
                         ("DROPPED=", "rearm"), ("GATE=", "gate"), ("WINDOW_OK", "window"),
                         ("send-keys", "say")):
        if marker in script:
            return kind
    for action in ("stop", "start"):
        if (" %s 2>&1" % action) in script:
            return action
    return "shell"


# ── the transports, replaced at their lowest layer ──────────────────────────────────────────────
_LOCAL41 = {"host": None}


def _paramiko41(server, command, timeout, sudo, stdin_text):
    h = _HOSTS41[server.id]
    if h.down or (h.sudo_silent == "raise" and sudo and command.strip() == "true"):
        raise ConnectionError("Could not reach %s: timed out" % h.name)
    return h.execute(command, sudo)


def _sshcli41(server, command, timeout=30, sudo=None, stdin_text=None):
    h = _HOSTS41[server.id]
    if h.down:
        return "", "SSH command timed out", -1
    return h.execute(command, sudo if sudo is not None else server.sudo_enabled)


def _runlocal41(cmd, timeout=30, sudo=False, stdin_text=None):
    h = _LOCAL41["host"]
    if h is None or h.down:
        return "", "Command timed out", -1
    return h.execute(cmd, sudo)


def _argv41(argv, timeout=30, stdin_text=None):
    """The panel host's argv path: the helper's verbs, and the user-scope probe."""
    h = _LOCAL41["host"]
    argv = list(argv)
    if argv[:3] == ["systemd-run", "--user", "--scope"]:
        return ("", "", 0) if getattr(h, "user_scope_ok", True) else ("", "Failed to connect to bus", 1)
    if h is None or h.down:
        return "", "Command timed out", -1
    if "lgsm-command" in argv:
        i = argv.index("lgsm-command")
        user, selfname, action = argv[i + 1:i + 4]
        _TRACE41.append((h.name, "helper:" + action))
        h.helper_argv = argv
        return h.lgsm(user, selfname, action)
    for verb in ("reboot-delayed", "dpkg-lock-held", "apt-any-running"):
        if verb in argv:
            return h._root({"reboot-delayed": "sleep 2 ; reboot", "dpkg-lock-held":
                            "fuser /var/lib/dpkg/lock-frontend", "apt-any-running": _APT_CMD41}[verb])
    _TRACE41.append((h.name, "argv:" + " ".join(argv[3:5])))
    return "", "", 0


# ── the app and its database ───────────────────────────────────────────────────────────────────
_app41 = _Flask41("unit_part41")
_app41.config.update(SECRET_KEY="unit-part41",  # nosec B106 - this part's throwaway app
                     SQLALCHEMY_TRACK_MODIFICATIONS=False, TESTING=True,
                     SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_TMP41, "p41.db"))
db.init_app(_app41)
_ctx41 = _app41.test_request_context()
_ctx41.push()
db.create_all()
# WAL, as init_db sets it: the job's thread writes while this part's own session holds a read.
db.session.execute(_sa_text41("PRAGMA journal_mode=WAL"))
db.session.commit()

# Every row-keyed panel-state map, emptied for this part and put back at its end: a fresh
# database hands out ids an earlier part's maps still hold.
_pstate_snap41 = [(m, dict(m)) for entries in _ps41.keyed_state_with_locks() for m, _lk in entries]
for _m41, _s41 in _pstate_snap41:
    _m41.clear()


def _fresh41():
    """An empty database, no reboot state, no hosts, nothing recorded."""
    db.session.rollback()
    db.session.expunge_all()          # a fresh table hands out the same ids: no stale object may stay
    db.drop_all()
    db.create_all()
    for m, _s in _pstate_snap41:
        m.clear()
    _HOSTS41.clear()
    _LOCAL41["host"] = None
    del _TRACE41[:]
    del _STAMPS41[:]
    del _NOTES41[:]
    _CLOCK41.t = 1791000000.0


def _remote41(name, auth="tailscale", local=False, sudo=True):
    r = RemoteServer(name=name, host="192.0.2.%d" % (len(_HOSTS41) + 10), username="root",
                     auth_method="local" if local else auth, is_local=local, sudo_enabled=sudo)
    db.session.add(r)
    db.session.commit()
    h = _Host41(name)
    _HOSTS41[r.id] = h
    if local:
        _LOCAL41["host"] = h
    return r, h


def _gs41(remote, user, game_type, port, status="online", **kw):
    g = GameServer(remote_id=remote.id, name=kw.pop("name", user), short_name=user,
                   game_type=game_type, port=port, installed=kw.pop("installed", True),
                   status=status, **kw)
    db.session.add(g)
    db.session.commit()
    return g


def _slots41(gs, allow_console=False, primary=None):
    h = _HOSTS41[gs.remote_id]
    n = h.players.get(gs.short_name, 0)
    return (n, 16, None)


def _notify41(key, title, body=""):
    _NOTES41.append((key, title, body))
    _TRACE41.append(("notify", key + ":" + title))


def _flush41(timeout=10.0):
    _TRACE41.append(("notify", "flush"))
    return True


def _audit41(action=None):
    q = AuditLog.query.order_by(AuditLog.id)
    if action:
        q = q.filter_by(action=action)
    return [(a.action, a.success, a.detail) for a in q.all()]


def _events41(host, kinds=None):
    return [e for h, e in _TRACE41 if h == host.name and (kinds is None or e in kinds)]


def _rr41(gs_id):
    db.session.expire_all()
    return HR.rr(db.session.get(GameServer, gs_id))


def _spawn41(target):
    """host_reboot's job thread, run to its end before the caller goes on.

    A thread of its own, as in production: it pushes its own app context and so has its own
    database session — run in line, it would share (and detach) the caller's rows.
    """
    t = _th41.Thread(target=target, name="host-reboot-job-p41", daemon=True)
    t.start()
    t.join(120)
    check("job thread: finished (not left running)", not t.is_alive())


def _std_patches41():
    """The stubs every check below runs under (inside a _patched() block)."""
    _patch(_core41, "_run_via_paramiko", _paramiko41)
    _patch(_core41, "_run_via_ssh_cli", _sshcli41)
    _patch(_core41, "_run_local", _runlocal41)
    _patch(_core41, "_exec_local_argv", _argv41)
    _patch(_core41, "helper_present", lambda recheck=False: False)
    _patch(HR, "time", _CLOCK41)
    _patch(HR, "_spawn", _spawn41)
    _patch(_mon41, "_server_slots", _slots41)
    _patch(_mon41, "_batched_slots", lambda servers: {})
    _patch(_notif41, "notify", _notify41)
    _patch(_notif41, "flush", _flush41)
    _patch(_so41, "_can_escalate", lambda: True)
    _patch(_so41, "_update_in_progress", lambda: False)
    _patch(_so41, "panel_starts_at_boot", lambda: True)
    _patch(_sm41.portscan, "_invalidate_port_scan", lambda rid: None)


def _std_host41(auth="tailscale", local=False):
    """Make a host with four servers, as on the test VPS.

    gmod runs with Autostart, mc runs without it, cod was stopped by the panel (no lock), and fctr
    runs with Autostart (its count is what a check says it is).
    """
    r, h = _remote41("vps" if not local else "panel", auth=auth, local=local)
    h.add("gmodserver", "gmodserver", running=True, lock="monitoring", autostart=True)
    h.add("mcserver", "mcserver", running=True, lock="monitoring", autostart=False)
    h.add("codserver", "codserver", running=False, lock="none", autostart=True)
    h.add("fctrserver", "fctrserver", running=True, lock="monitoring", autostart=True)
    rows = {"gmod": _gs41(r, "gmodserver", "gmod", 27015), "mc": _gs41(r, "mcserver", "mc", 25565),
            "cod": _gs41(r, "codserver", "cod", 28960, status="offline"),
            "fctr": _gs41(r, "fctrserver", "fctr", 34197)}
    return r, h, rows


def _lockfile41(h, selfname, kind="monitoring"):
    p = h.lock(selfname, kind)
    if not os.path.exists(p):
        return None
    st = os.stat(p)
    with open(p) as fh:
        return (fh.read(), st.st_ino, st.st_mtime_ns)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# A. Reading a server: the probe, run for real against a stand-in host
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _lines41(h, prefix):
    """The stand-in host's LinuxGSM/console log lines that start with `prefix`."""
    return [ln for ln in h.events() if ln.startswith(prefix)]


def _bodies41(title=None, key=None):
    """The bodies of the notifications sent, of one title and/or event key."""
    return [b for k, t, b in _NOTES41 if title in (None, t) and key in (None, k)]


def _noted41(fragment):
    """Whether any notification sent says `fragment`."""
    return any(fragment in b for _k, _t, b in _NOTES41)


def _actions41(action):
    """The audit actions written for `action`, in order."""
    return [a for a, _s, _d in _audit41(action)]


def _locks41(h, names):
    return {s: _lockfile41(h, s) for s in names}


def _probe_fixture41():
    _fresh41()
    r, h = _remote41("probe")
    h.add("codserver", "codserver", running=False, lock="monitoring", autostart=True, uid="aaaa1111")
    h.add("codserver", "codserver-2", running=True, lock="none", autostart=False, uid="bbbb2222")
    h.add("gmodserver", "gmodserver", running=True, lock="legacy", autostart=False, uid=None)
    h.add("gmodserver", "gmodserver-3", running=False, lock="none", autostart=False, uid=None)
    # Stray sessions on the stopped servers' own sockets whose names hold the server's: an
    # operator's `tmux -L <socket> new -s codserver-old`. LinuxGSM's check_status.sh matches the
    # session name exactly (grep -Ecx), so they are not the server.
    for sock, stray in ((h.sock("codserver"), "codserver-old"), (h.sock("gmodserver-3"), "gmodserver-3x")):
        with open(os.path.join(h.state, "tmux", sock), "w") as fh:
            fh.write(stray + "\n")
    with open(h.lock("codserver") + ".panel-reboot", "w") as fh:
        fh.write("x\n")
    h.setn("inflight", "codserver", 2)
    h.setn("maint", "codserver", 1)
    probes = [HR.probe_server(r, {"user": u, "selfname": s})
              for u, s in (("codserver", "codserver"), ("codserver", "codserver-2"),
                           ("gmodserver", "gmodserver"), ("gmodserver", "gmodserver-3"))]
    return r, h, probes


def _probe_checks41():
    r, h, (p1, p2, p3, p4) = _probe_fixture41()
    check("probe: an EXACT session name on the uid socket — codserver is stopped though a session "
          "codserver-old is on its socket, while codserver-2 (same account) runs",
          (p1["session"], p2["session"]) == (0, 1), repr((p1["session"], p2["session"])))
    check("probe: an EXACT session name on the legacy bare socket too — gmodserver-3x is not "
          "gmodserver-3", p4["session"] == 0, repr(p4))
    check("probe: the legacy socket (no uid file: the bare session name) is read too",
          p3["session"] == 1, repr(p3))
    check("probe: the lock and the aside file are told apart; legacy <s>.lock is its own word",
          (p1["lock"], p1["aside"], p2["lock"], p3["lock"]) == ("monitoring", "monitoring", "none", "legacy"),
          repr((p1["lock"], p1["aside"], p2["lock"], p3["lock"])))
    check("probe: LinuxGSM commands in flight, and the maintenance ones among them, are counted",
          (p1["inflight"], p1["maint"], p2["inflight"]) == (2, 1, 0), repr(p1))
    check("probe: the boot id, the machine id and the host's second of the minute come back",
          (p1["boot"], p1["mid"], p1["sec"]) == (h.boot, h.mid, int(_CLOCK41.time()) % 60), repr(p1))
    check("probe: the Autostart line is read the way the Autostart switch reads it",
          [HR.has_autostart_line(p1["cron"], "codserver", "codserver"),
           HR.has_autostart_line(p1["cron"], "codserver", "codserver-2"),
           HR.has_autostart_line(p3["cron"], "gmodserver", "gmodserver")] == [True, False, False],
          repr(p1["cron"]))
    unread = dict(HR._UNREAD)
    eq("probe: output without the probe's own PROBE_OK is unread, every field None — never 'stopped'",
       HR.parse_probe("SESSION=0\nLOCK=none\n"), unread)
    eq("probe: an empty answer (a tailscale or local timeout) is unread", HR.parse_probe(""), unread)
    eq("probe: an unsafe account name sends nothing and is unread",
       HR.probe_server(r, {"user": "x; id", "selfname": "codserver"}), unread)


def _transport_one41(auth, local):
    _fresh41()
    r, h, rows = _std_host41(auth=auth, local=local)
    h.down = True
    p = HR.probe_server(r, rows["gmod"])
    ident = _hosts41.host_boot_identity(r)
    census = HR.host_player_state(r)
    check("transport %s: a dead host's probe is unread (paramiko raises, the others return -1)"
          % auth, p == dict(HR._UNREAD), repr(p))
    check("transport %s: its boot identity is None, never a new boot" % auth, ident is None, repr(ident))
    check("transport %s: its census is 'unreachable', which never reboots" % auth,
          census["state"] == "unreachable", census["state"])
    code, body = HR.request_reboot(r, "now", None, "web")
    check("transport %s: Reboot now on it is refused, and nothing was stopped or rebooted" % auth,
          _all41(code == 409, body.get("error") == "unreachable",
                 not _events41(h, ("stop", "reboot", "disarm"))), repr((code, body)))


def _transport_checks41():
    """A host that does not answer, on each transport: unknown, never stopped or idle."""
    for auth, local in (("key", False), ("tailscale", False), ("local", True)):
        _transport_one41(auth, local)


def _pgrep_count41(me, selfname):
    pat = HR._cmd_pattern(selfname, HR._INFLIGHT_CMDS)
    return _run41(["bash", "-c", "pgrep -u %s -fc %s" % (_shlex41.quote(me), _shlex41.quote(pat))]).stdout.strip()


def _probe_pattern_checks41():
    """The LinuxGSM-command pattern, against the REAL pgrep and a real `/bin/bash ./<s> start`."""
    d = _tf41.mkdtemp(prefix="pat-", dir=_TMP41)
    # A name of this run's own: pgrep sees every process of this account, and a second suite
    # running at the same time (a mutation battery) runs this same check.
    name = "zq%sserver" % _uuid41.uuid4().hex[:8]
    _write_exec41(os.path.join(d, name), "#!/bin/bash\nsleep 30\n")
    me = _run41(["id", "-un"]).stdout.strip()
    before = _pgrep_count41(me, name)
    proc = _popen41(["./" + name, "start"], cwd=d)
    try:
        _time41.sleep(0.3)
        during = _pgrep_count41(me, name)
        other = _pgrep_count41(me, name[1:])
    finally:
        proc.kill()
        proc.wait()
    check("probe pattern: the shell asking is never counted — 0 with nothing running, though its "
          "own command line holds the pattern", before == "0", repr(before))
    check("probe pattern: a real `/bin/bash ./<s> start` is counted", during == "1", repr(during))
    check("probe pattern: ...and not as another script whose name is a suffix of it",
          other == "0", repr(other))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# B. Who brings each server back
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _classify_checks41():
    _fresh41()
    r, _h, rows = _std_host41()
    probes = HR._probe_rows(r, list(rows.values()))
    got = {k: HR.classify(g, probes[g.id]) for k, g in rows.items()}
    check("owner: running + Autostart line + lock -> LinuxGSM's monitor brings it back",
          (got["gmod"], got["fctr"]) == (("monitor", "autostart"), ("monitor", "autostart")), repr(got))
    check("owner: running without an Autostart line -> the panel brings it back",
          got["mc"] == ("panel", "no_autostart"), repr(got["mc"]))
    check("owner: ...or nobody, with the reboot_restore_no_autostart setting off",
          HR.classify(rows["mc"], probes[rows["mc"].id], no_autostart_restore=False)
          == ("none", "no_autostart_off"))
    check("owner: a stopped server is not in the plan at all (never stopped: that would delete its lock)",
          got["cod"] == (None, "stopped"), repr(got["cod"]))
    check("owner: a server whose state could not be read is not in the plan",
          HR.classify(rows["gmod"], dict(HR._UNREAD)) == (None, "unreadable"))
    rows["gmod"].stop_pending = True
    check("owner: a running server with a queued stop -> nobody: it stays stopped",
          HR.classify(rows["gmod"], probes[rows["gmod"].id]) == ("none", "stop_pending"))
    rows["gmod"].stop_pending = False
    p = dict(probes[rows["gmod"].id], lock="none")
    check("owner: Autostart without a lock is not the monitor's (it would never start it)",
          HR.classify(rows["gmod"], p)[0] == "panel")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# C. The gate every entry point goes through
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _gate_busy41():
    _fresh41()
    r, h, rows = _std_host41()
    h.players.update({"gmodserver": 3, "mcserver": 0, "fctrserver": 0})
    before = _locks41(h, h.servers)
    code, body = HR.request_reboot(r, None, None, "web")
    check("gate: a request with no mode while players are on answers 409 needs_choice",
          _all41(code == 409, body.get("error") == "players_online", body.get("needs_choice") is True,
                 body.get("choices") == ["when_empty", "now"],
                 (body.get("players") or {}).get("busy")
                 == [{"id": rows["gmod"].id, "name": "gmodserver", "players": 3}]),
          repr((code, body)))
    check("gate: ...and nothing was stopped, moved, written or rebooted",
          _all41(not _events41(h, ("stop", "disarm", "reboot")), not HR.plan_rows(r.id),
                 _locks41(h, h.servers) == before, not HR.job_of(r.id)), repr(_events41(h)))
    return r, h


def _gate_checks41():
    r, h = _gate_busy41()
    h.players.update({"gmodserver": 0, "fctrserver": None})
    code, body = HR.request_reboot(r, None, None, "web")
    check("gate: a count that cannot be read is NOT an empty server: 409 too, naming it",
          _all41(code == 409, body.get("error") == "players_online",
                 [u["name"] for u in (body.get("players") or {}).get("unknown", ())] == ["fctrserver"]),
          repr((code, body)))
    check("gate: ...and still nothing touched", not _events41(h, ("stop", "disarm", "reboot")))
    eq("gate: parse_mode — the older bodies and the new one",
       [HR.parse_mode(b) for b in ({}, {"mode": "now"}, {"mode": "force"}, {"force": True},
                                   {"when_empty": True}, {"when_empty": "true"}, {"when_empty": 1},
                                   {"when_empty": False}, {"when_empty": "false"}, {"when_empty": 0},
                                   {"mode": "wait"})],
       [(None, None), ("now", None), ("now", None), ("now", None), ("when_empty", None),
        ("when_empty", None), ("when_empty", None), (None, None), (None, None), (None, None),
        ("when_empty", None)])
    check("gate: an unknown mode or a when_empty that is not a boolean is an error, never a guess",
          all(HR.parse_mode(b)[1] for b in ({"mode": "later"}, {"when_empty": "maybe"},
                                             {"when_empty": 2})))


def _pass41():
    """One restore-worker pass, reading the rows afresh as the worker's own context would."""
    db.session.expire_all()
    out = HR.run_restore_pass(_app41)
    db.session.expire_all()
    return out


def _wpass41():
    """One 'reboot when empty' pass, reading the rows afresh as the loop's own context would."""
    db.session.expire_all()
    HR.wait_pass(_app41)
    db.session.expire_all()


def _restore_until41(rid, passes=30, step=15.0, between=None):
    """Run the restore worker's pass until the host has no plan rows left (or `passes` run out)."""
    for n in range(passes):
        if between is not None:
            between(n)
        _pass41()
        if not HR.plan_rows(rid):
            return n + 1
        _CLOCK41.sleep(step)
    return None


def _order41(events, first, then):
    """Every `first` event comes before every `then` event (and both happened)."""
    a = [i for i, e in enumerate(events) if e in first]
    b = [i for i, e in enumerate(events) if e in then]
    return _all41(bool(a), bool(b)) and max(a) < min(b)


def _trace41():
    """Every event of the run, a notification's prefixed with 'notify:'."""
    return [("notify:" + e if hh == "notify" else e) for hh, e in _TRACE41]


# ════════════════════════════════════════════════════════════════════════════════════════════════
# D. Reboot now, on a remote: the whole plan, in order, and the lock files after
# ════════════════════════════════════════════════════════════════════════════════════════════════
_AUTO41 = ("gmodserver", "fctrserver")


def _asides41(h):
    return [f for u in _AUTO41 for f in os.listdir(os.path.join(h.home(u), "lgsm", "lock"))
            if f.endswith(".panel-reboot")]


def _now_locks41(auth, h, before):
    check("now (%s): the Autostart servers' monitoring locks are THE SAME FILES after the reboot "
          "was sent (content, inode, mtime): moved aside for the stop, put back before the reboot" % auth,
          _locks41(h, _AUTO41) == {s: before[s] for s in _AUTO41}, repr(_locks41(h, h.servers)))
    check("now (%s): no aside file is left behind" % auth, not _asides41(h))
    check("now (%s): the stopped server's state is untouched (still no lock)" % auth,
          (_lockfile41(h, "codserver"), before["codserver"]) == (None, None))
    check("now (%s): the server without Autostart lost its lock to the stop: the panel starts it" % auth,
          _lockfile41(h, "mcserver") is None)


def _now_order41(auth):
    rebooting = "notify:host_reboot:Rebooting vps"
    order = [e for e in _trace41() if e in ("disarm", "stop", "rearm", "reboot", rebooting)]
    check("now (%s): disarm, then stop, then the 'Rebooting' notice, then the locks back, then the "
          "reboot — nothing between the last two" % auth,
          _all41(_order41(order, {"disarm"}, {"stop"}), _order41(order, {"stop"}, {rebooting}),
                 _order41(order, {rebooting}, {"rearm"}), order[-2:] == ["rearm", "reboot"]),
          repr(order))


def _now_rows41(auth, r, rows):
    recs = {k: _rr41(g.id) for k, g in rows.items()}
    planned = {k: (v["owner"], v["stop"], bool(v["sent"]), v["restore"]) for k, v in recs.items() if v}
    check("now (%s): the plan is in the database before the reboot: who brings each back, how it "
          "stopped, and that the reboot was sent" % auth,
          planned == {"gmod": ("monitor", "stopped", True, "pending"),
                      "fctr": ("monitor", "stopped", True, "pending"),
                      "mc": ("panel", "stopped", True, "pending")}, repr(recs))
    audit = _audit41("remote_reboot")
    check("now (%s): one audit row says what happened before the reboot was sent" % auth,
          _all41([(a, s) for a, s, _d in audit] == [("remote_reboot", True)],
                 "gmodserver: stopped, back by Autostart" in (audit[0][2] if audit else "")),
          repr(_audit41()))
    check("now (%s): the planned servers' 'went offline' alerts are held for the whole plan" % auth,
          [_ps41._expected_offline.get(rows[k].id) for k in ("gmod", "mc", "fctr")] == [float("inf")] * 3)
    check("now (%s): a remote's reboot does not wait on the panel's own notification queue" % auth,
          "notify:flush" not in _trace41())
    check("now (%s): the job is now just waiting for the host: phase rebooting" % auth,
          (HR.job_of(r.id) or {}).get("phase") == "rebooting")


def _now_flow_checks41(auth):
    _fresh41()
    r, h, rows = _std_host41(auth=auth)
    h.players.update({"gmodserver": 0, "mcserver": 0, "fctrserver": None})
    before = _locks41(h, _AUTO41 + ("codserver",))
    code, body = HR.request_reboot(r, "now", None, "web")
    check("now (%s): 202, and the reboot command was sent once" % auth,
          _all41(code == 202, body.get("success") is True, _trace41().count("reboot") == 1),
          repr((code, body, _trace41())))
    stops = _lines41(h, "stop ")
    check("now (%s): every RUNNING server got LinuxGSM's graceful stop; the stopped one none" % auth,
          sorted(s.split()[1] for s in stops) == ["fctrserver", "gmodserver", "mcserver"], repr(stops))
    _now_locks41(auth, h, before)
    _now_order41(auth)
    _now_rows41(auth, r, rows)
    _restore_flow_checks41(auth, r, h, rows)


def _monitor_cron41(h, started):
    """Stand in for LinuxGSM's */5 monitor, about 5 min after boot: it restarts what has its lock."""
    def _tick(n):
        if n != 12:
            return
        for s in ("gmodserver", "fctrserver", "mcserver"):
            if _lockfile41(h, s) is not None and not h.running(s):
                h.run(s, True)
                started[s] = True
    return _tick


def _restore_flow_checks41(auth, r, h, rows):
    """The host reboots; the monitor restarts its own; the panel starts the rest."""
    h.reboot_now()
    _CLOCK41.sleep(120)
    monitor_started = {}
    passes = _restore_until41(r.id, between=_monitor_cron41(h, monitor_started))
    starts = _lines41(h, "start ")
    check("restore (%s): the host is back and every plan row resolved" % auth, passes is not None,
          repr([_rr41(g.id) for g in rows.values()]))
    check("restore (%s): the panel started exactly the server without Autostart — never one "
          "LinuxGSM's monitor brings back" % auth,
          [s.split()[1] for s in starts] == ["mcserver"], repr(starts))
    check("restore (%s): ...and wrote LinuxGSM's -starting.lock before it, so a monitor run that "
          "overlaps backs off" % auth, starts == ["start mcserver starting_lock=1"], repr(starts))
    check("restore (%s): the Autostart servers came back by the monitor alone" % auth,
          sorted(monitor_started) == ["fctrserver", "gmodserver"], repr(monitor_started))
    back = _bodies41("Host reboot", "host_reboot")
    check("restore (%s): ONE summary: back, 3/3 running again, 2 by Autostart and 1 by the panel"
          % auth, _all41(len(back) == 1, "3/3 running again (2 by Autostart, 1 started by the panel)"
                         in "".join(back)), repr(_NOTES41))
    check("restore (%s): the rows are cleared and the outcome audited" % auth,
          _all41(not HR.plan_rows(r.id),
                 [(a, s) for a, s, _d in _audit41("remote_reboot_restore")] == [("remote_reboot_restore", True)]))
    check("restore (%s): the alerts get the monitor's 3 minutes of grace from now, not for ever" % auth,
          [_ps41._expected_offline.get(rows[k].id) for k in ("gmod", "mc", "fctr")] == [_CLOCK41.time()] * 3,
          repr({k: _ps41._expected_offline.get(g.id) for k, g in rows.items()}))
    check("restore (%s): the job is gone" % auth, HR.job_of(r.id) is None)


def _stop_calls41():
    """Record every run_as_game_user call (and pass it through): (action, selfname, timeout)."""
    calls = []
    real = _core41.run_as_game_user

    def _rec(server, user, action, timeout=30, selfname=None, **kw):
        calls.append((action, selfname, timeout))
        return real(server, user, action, timeout=timeout, selfname=selfname, **kw)
    _patch(_core41, "run_as_game_user", _rec)
    return calls


# ════════════════════════════════════════════════════════════════════════════════════════════════
# E. The stop: its budget, and a stop LinuxGSM refuses
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _stop_checks41():
    _fresh41()
    r, h = _remote41("budget")
    h.add("sdtdserver", "sdtdserver", running=True, autostart=True)
    h.add("gmodserver", "gmodserver", running=True, autostart=True)
    rows = {"sdtd": _gs41(r, "sdtdserver", "sdtd", 26900), "gmod": _gs41(r, "gmodserver", "gmod", 27015)}
    h.flag("refuse_stop", "gmodserver")
    before = _lockfile41(h, "gmodserver")
    calls = _stop_calls41()
    HR.request_reboot(r, "now", None, "web")
    budgets = {s: t for a, s, t in calls if a == "stop"}
    check("stop budget: 600 s for the telnet stopmodes (7 Days to Die), 180 s for the rest — never "
          "the panel's usual 60 s, which cut a graceful stop off mid-save",
          (budgets.get("sdtdserver"), budgets.get("gmodserver")) == (600, 180), repr(calls))
    rec = _rr41(rows["gmod"].id) or {}
    check("stop refused (stoponlyifnoplayers: exit 0, still running): recorded as still_running, by "
          "the session and not the exit code, and its owner is unchanged",
          (rec.get("stop"), rec.get("owner")) == ("still_running", "monitor"), repr(rec))
    check("stop refused: ...its lock is back where it was, so the monitor restores it after the "
          "shutdown ends it", _lockfile41(h, "gmodserver") == before)
    check("stop refused: ...and it is not stopped a second time by the re-scan",
          _lines41(h, "stop gmodserver") == ["stop gmodserver starting_lock=0"], repr(h.events()))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# F. Refusals before anything is touched
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _untouched41(h, before):
    return _all41(not _events41(h, ("stop", "disarm", "reboot", "rearm")),
                  _locks41(h, h.servers) == before)


def _refusal41(name, setup, error, local=False, also=None):
    """Reboot now on a host `setup` made busy: refused with `error`, and nothing touched."""
    _fresh41()
    r, h, _rows = _std_host41(local=local)
    setup(r, h)
    before = _locks41(h, h.servers)
    code, body = HR.request_reboot(r, "now", None, "web")
    check("refused before anything is touched: %s — no lock moved, no stop, no reboot" % name,
          _all41(code == 409, body.get("error") == error, _untouched41(h, before),
                 also is None or also(body)), repr((code, body)))


def _no_escalation41(_r, _h):
    _patch(_so41, "_can_escalate", lambda: False)


def _refusal_checks41():
    _refusal41("an install in flight",
               lambda r, h: _gs41(r, "rustserver", "rust", 28015, status="installing", installed=False),
               "blocked", also=lambda b: b.get("choices") == ["when_empty"])
    _refusal41("dpkg's lock held", lambda r, h: setattr(h, "dpkg_held", True), "blocked")
    _refusal41("LinuxGSM maintenance", lambda r, h: h.setn("maint", "gmodserver", 1), "blocked")
    _refusal41("a remote with sudo off", lambda r, h: setattr(h, "sudo_ok", False), "preflight",
               also=lambda b: "sudo" in b.get("message", ""))
    _refusal41("the panel host without escalation", _no_escalation41, "preflight", local=True)
    _patch(_so41, "_can_escalate", lambda: True)
    _late_refusal41()


def _late_refusal41():
    """A job that finds the host blocked by the time it runs (a delay, then a backup starts)."""
    _fresh41()
    r, h, _rows = _std_host41()
    before = _locks41(h, h.servers)
    real_census = HR.host_player_state

    def _late_block(remote, probes=None):
        c = real_census(remote, probes)
        if HR.job_of(remote.id):
            c["state"], c["blockers"] = "blocked", [HR._blocker("backup", "gmodserver")]
        return c
    _patch(HR, "host_player_state", _late_block)
    code, _body = HR.request_reboot(r, "now", None, "web", delay=30)
    check("refused at the job: work that started during the delay ends it with nothing touched, an "
          "audit row that says so, and a notice",
          _all41(code == 202, _untouched41(h, before),
                 [(a, s) for a, s, _d in _audit41("remote_reboot")] == [("remote_reboot", False)],
                 _noted41("was not rebooted")), repr((_audit41(), _NOTES41)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# G. The window: the locks go back only when no monitor run can read them
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _window_checks41():
    eq("window: second 5 and second 45 are outside it, 20 inside; a LinuxGSM command in flight "
       "keeps it shut; an unread second is shut",
       [HR._window_open([{"sec": s, "inflight": n}], HR.ARM_WINDOW)
        for s, n in ((5, 0), (45, 0), (20, 0), (20, 1), (None, 0), (20, None))],
       [False, False, True, False, False, False])
    _fresh41()
    r, h, _rows = _std_host41()
    h.setn("inflight", "gmodserver", 1)        # a scheduled update started and never ends
    real_census = HR.host_player_state

    def _quiet_census(remote, probes=None):
        h.setn("maint", "gmodserver", 0)
        return real_census(remote, probes)
    _patch(HR, "host_player_state", _quiet_census)
    t0 = _CLOCK41.time()
    HR.request_reboot(r, "now", None, "web")
    check("window: a LinuxGSM command in flight for 120 s — no reboot is sent",
          _all41("reboot" not in _events41(h), _CLOCK41.time() - t0 >= 120), repr(_events41(h)))
    check("window: ...the plan is rolled back: the locks are back, the panel-owned server is started "
          "again, and the operator is told why",
          _all41(None not in _locks41(h, _AUTO41).values(),
                 "start mcserver starting_lock=1" in h.events(),
                 _noted41("did not happen (a LinuxGSM command was running")),
          repr((h.events(), _NOTES41)))
    check("window: ...and the rows are gone", not HR.plan_rows(r.id))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# H. A reboot the host refuses, and a host that comes back on the same boot
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _refused_reboot_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.reboot_rc = 1
    before = _locks41(h, _AUTO41)
    HR.request_reboot(r, "now", None, "web")
    check("reboot refused (rc 1): rolled back at once — the Autostart servers' locks are the same "
          "files, so LinuxGSM's monitor restarts them", _locks41(h, _AUTO41) == before)
    check("reboot refused: ...the server without Autostart gets a SAFE START now",
          "start mcserver starting_lock=1" in h.events(), repr(h.events()))
    check("reboot refused: ...nothing it did not stop is started, and the monitor's are left to it",
          [ln.split()[1] for ln in _lines41(h, "start ")] == ["mcserver"], repr(h.events()))
    did_not = [b for b in _bodies41(key="host_reboot") if "did not happen" in b]
    check("reboot refused: ...ONE notification, with the host's refusal in it",
          _all41(len(did_not) == 1, "refused the reboot" in "".join(did_not)), repr(_NOTES41))
    check("reboot refused: ...audited as a rollback, and the job and the rows are gone",
          _all41(_actions41("remote_reboot_rollback") == ["remote_reboot_rollback"],
                 not HR.plan_rows(r.id), HR.job_of(r.id) is None))


def _send_answer41(answer):
    def _rp(_server, verb, _args=(), **_kw):
        if verb != "reboot-delayed":
            return "", "unexpected verb %s" % verb, 9
        if isinstance(answer, Exception):
            raise answer
        return answer
    return _rp


def _started41(exc):
    """`exc` marked as the paramiko transport marks a failure once its exec was under way."""
    exc.command_started = True
    return exc


def _send_reboot_checks41():
    """The reboot command's answer: a refusal is knowable, though a reboot's success is not."""
    _fresh41()
    r, _h, _rows = _std_host41()
    got = []
    for answer in (("", "sudo: a password is required\n", 1), ("", "SSH command timed out", -1),
                   ("", "", 0), _started41(ConnectionError("Command failed: dropped")),
                   ConnectionRefusedError(111, "Connection refused"),
                   _core41.HostKeyMismatch("the host key changed")):
        _patch(_core41, "run_privileged", _send_answer41(answer))
        got.append(HR.send_reboot(r))
    eq("send: a positive rc is the host refusing (sudo, an old helper) and says why; a connection "
       "that drops once the command is under way (-1, paramiko's marked ConnectionError) is what a reboot looks "
       "like, and 0 is sent; a connection that never opened sent nothing and says so",
       got, ["the host refused the reboot: sudo: a password is required", None, None, None,
             "the panel could not connect to send the reboot ([Errno 111] Connection refused)",
             "the panel could not connect to send the reboot (the host key changed)"])


def _plan_with_sent41(sent=True, mid=None, owner_map=None):
    """A host with plan rows written as a job would leave them, without running the job."""
    _fresh41()
    r, h, rows = _std_host41()
    now = _CLOCK41.time()
    for k, owner in (owner_map or {"gmod": "monitor", "mc": "panel"}).items():
        rec = {"v": 1, "plan": "p", "boot": h.boot, "mid": mid or h.mid, "owner": owner,
               "lock": "monitoring", "aside": None, "at": now, "sent": (now if sent else None),
               "by": "admin", "origin": "web", "mode": "now", "stop": "stopped", "restore": "pending",
               "attempts": 0, "boot_seen": None}
        rows[k].reboot_restore = _json41.dumps(rec)
    db.session.commit()
    h.run("gmodserver", False)
    h.run("mcserver", False)
    os.remove(h.lock("mcserver"))
    return r, h, rows


def _same_boot_unsent41():
    r, h, _rows = _plan_with_sent41(sent=False)
    _pass41()
    _restore_until41(r.id)
    check("same boot, never sent, no job (the panel restarted mid-plan): rolled back — the panel "
          "starts its own, the monitor's lock is left for the monitor",
          _all41(_lines41(h, "start ") == ["start mcserver starting_lock=1"], not HR.plan_rows(r.id),
                 _noted41("panel restarted before the reboot was sent")), repr((h.events(), _NOTES41)))


def _same_boot_checks41():
    _same_boot_unsent41()
    r, h, _rows = _plan_with_sent41()
    _pass41()
    check("same boot, sent a moment ago: wait — it may be shutting down right now",
          _all41(len(HR.plan_rows(r.id)) == 2, not _lines41(h, "start ")))
    h.sysstate = "stopping"
    _CLOCK41.sleep(300 + 5)                     # the design's 5 min, not the module's constant
    _pass41()
    check("same boot, sent 5 min ago, but the host says it is stopping: still waiting",
          _all41(len(HR.plan_rows(r.id)) == 2, not _lines41(h, "start ")))
    h.sysstate = "running"
    _restore_until41(r.id)
    check("same boot, 5 min after it was sent, running: the reboot did not happen — rolled back",
          _all41(_lines41(h, "start ") == ["start mcserver starting_lock=1"],
                 _noted41("still on the same boot")), repr(_NOTES41))
    r, h, _rows = _plan_with_sent41()
    h.down = True
    _CLOCK41.sleep(700)                         # past 5 min (did not happen) and 10 (late notice)
    _pass41()
    _pass41()
    check("a host that does not answer is never taken for a new boot: nothing started, the plan "
          "kept, and ONE 'not back yet' notice",
          _all41(len(HR.plan_rows(r.id)) == 2, not _lines41(h, "start "),
                 [t for _k, t, _b in _NOTES41] == ["Host not back yet"]), repr(_NOTES41))


def _stale_checks41():
    r, h, _rows = _plan_with_sent41(mid="f" * 32)
    h.reboot_now()
    _CLOCK41.sleep(200)
    _pass41()
    check("another machine at the address (machine id differs): the plan is dropped, nothing started",
          _all41(not HR.plan_rows(r.id), not _lines41(h, "start "), _noted41("different machine")),
          repr(_NOTES41))
    _stale_bounds41()


# The design's limits as literals: a check that sleeps HR.STALE_SENT + 10 moves with the constant
# it is meant to pin, and passed with the constant at 10**9.
_DAY41 = 86400


def _stale_bounds41():
    r, h, _rows = _plan_with_sent41()
    _CLOCK41.sleep(23 * 3600)
    _restore_until41(r.id)
    check("a same-boot plan sent 23 h ago is still a reboot that did not happen: rolled back (the "
          "panel's server started again), not dropped",
          _all41(_lines41(h, "start ") == ["start mcserver starting_lock=1"],
                 _noted41("still on the same boot")), repr((h.events(), _NOTES41)))
    r, h, _rows = _plan_with_sent41()
    _CLOCK41.sleep(_DAY41 + 10)
    _pass41()
    check("a same-boot plan sent more than a day ago (a restored database): dropped, nothing started",
          _all41(not HR.plan_rows(r.id), not _lines41(h, "start ")), repr((h.events(), _NOTES41)))
    r, h, _rows = _plan_with_sent41()
    h.down = True
    _CLOCK41.sleep(6 * _DAY41)
    _pass41()
    check("a plan for a host silent for 6 days is kept: it may still come back",
          _all41(len(HR.plan_rows(r.id)) == 2, not _noted41("has not answered for a week")))
    _CLOCK41.sleep(_DAY41 + 10)
    _pass41()
    check("a plan for a host silent for a week: dropped with a notice, nothing started",
          _all41(not HR.plan_rows(r.id), _noted41("has not answered for a week"),
                 not _lines41(h, "start ")))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# I. SAFE START
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _safe_start_gates41(r, h, g):
    _CLOCK41.t = 1791000000.0 + 45                           # second 45: outside the window
    out = HR.safe_start(r, g)
    check("safe start: outside seconds 5-40 it waits, and starts nothing",
          _all41(out[0] == "wait", not _lines41(h, "start ")), repr(out))
    _CLOCK41.t = 1791000000.0 + 20
    h.setn("inflight", "mcserver", 1)
    out = HR.safe_start(r, g)
    check("safe start: with a LinuxGSM command in flight for it, it waits", out[0] == "wait", repr(out))
    h.setn("inflight", "mcserver", 0)


def _safe_start_checks41():
    _fresh41()
    r, h = _remote41("ss")
    h.add("mcserver", "mcserver", running=False, lock="none", autostart=False)
    g = _gs41(r, "mcserver", "mc", 25565, status="offline")
    _safe_start_gates41(r, h, g)
    out = HR.safe_start(r, g)
    check("safe start: inside the window: -starting.lock first, then LinuxGSM's start",
          _all41(out == ("started", ""), h.events()[-1:] == ["start mcserver starting_lock=1"]),
          repr((out, h.events())))
    out = HR.safe_start(r, g)
    check("safe start: a server that is already running is not started twice",
          _all41(out == ("running", ""), len(_lines41(h, "start ")) == 1))
    h.run("mcserver", False)
    h.flag("already", "mcserver")                           # LinuxGSM says so, with no session the panel saw
    out = HR.safe_start(r, g)
    h.flag("already", "mcserver", on=False)
    check("safe start: LinuxGSM's 'already running' (exit 2) counts as started", out[0] == "started", repr(out))
    h.flag("fail_start", "mcserver")
    out = HR.safe_start(r, g)
    check("safe start: a start that fails says why, in LinuxGSM's words",
          _all41(out[0] == "failed", "Unable to start" in out[1]), repr(out))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# J. Wait for everyone to leave
# ════════════════════════════════════════════════════════════════════════════════════════════════
_WAITER41 = NS(id=None, username="admin")


def _wait_entry41(rid):
    with _ps41._rwe_lock:
        return dict(_ps41._reboot_when_empty.get(rid) or {}) or None


def _wait_arm_checks41():
    _fresh41()
    r, h, rows = _std_host41()
    h.players.update({"gmodserver": 2})
    t0 = _CLOCK41.time()
    code, body = HR.request_reboot(r, "when_empty", _WAITER41, "web")
    w = _wait_entry41(r.id) or {}
    check("wait: armed — 200 pending, it gives up 24 h from now, and nothing was touched",
          _all41(code == 200, body.get("pending") is True, w.get("expires") == t0 + 24 * 3600,
                 (w.get("by"), w.get("boot")) == ("admin", h.boot),
                 not _events41(h, ("stop", "disarm", "reboot"))), repr((code, body, w)))
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    check("wait: arming it again changes nothing and writes no second audit row",
          _all41((_wait_entry41(r.id) or {}).get("since") == w.get("since"),
                 _actions41("reboot_when_empty_arm") == ["reboot_when_empty_arm"]))
    _wpass41()
    w = _wait_entry41(r.id) or {}
    check("wait: someone on — it keeps waiting, and records who it is waiting on",
          _all41((w.get("waiting_on") or {}).get("busy") == [{"name": "gmodserver", "players": 2}],
                 "reboot" not in _events41(h)), repr(w))
    return r, h, rows


def _wait_checks41():
    r, h, rows = _wait_arm_checks41()
    # The pop is the COMMIT POINT: a cancel while the census runs means no reboot.
    h.players.update({"gmodserver": 0})
    real_census = HR.host_player_state

    def _cancel_mid(remote, probes=None):
        c = real_census(remote, probes)
        HR.cancel(remote, _WAITER41)
        return c
    _patch(HR, "host_player_state", _cancel_mid)
    _wpass41()
    _patch(HR, "host_player_state", real_census)
    check("wait: cancelled while the census ran — it is not rebooted, though the host was empty",
          _all41(_wait_entry41(r.id) is None, "reboot" not in _events41(h), not _events41(h, ("stop",))))
    _wait_fire_checks41(r, h, rows)


def _wait_fire_checks41(r, h, rows):
    """Armed again; now empty: it fires — the clean reboot, as the operator who armed it."""
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    _wpass41()
    check("wait: empty — it fires the clean reboot (stops, then reboots), and is no longer pending",
          _all41(_wait_entry41(r.id) is None, "reboot" in _events41(h),
                 sorted(ln.split()[1] for ln in _lines41(h, "stop ")) == ["fctrserver", "gmodserver", "mcserver"]),
          repr(h.events()))
    fire = AuditLog.query.filter_by(action="reboot_when_empty_fire").all()
    check("wait: the fire is audited under whoever armed it, and the auto_reboot notice goes out",
          _all41([(a.username, a.success) for a in fire] == [("admin", True)],
                 bool(_bodies41(key="auto_reboot"))), repr((_audit41(), _NOTES41)))
    check("wait: the reboot it fired ran in the 'when_empty' mode: no in-game countdown",
          _all41(not _lines41(h, "say "), (_rr41(rows["gmod"].id) or {}).get("mode") == "when_empty"))


def _wait_expiry41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": 1, "fctrserver": None})
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    _wpass41()
    _CLOCK41.sleep(24 * 3600 + 1)
    _wpass41()
    gave = "".join(_bodies41("Gave up waiting to reboot"))
    check("wait: after 24 h it gives up — dropped, audited, and the notice names what was still on",
          _all41(_wait_entry41(r.id) is None, len(_bodies41("Gave up waiting to reboot")) == 1,
                 "gmodserver (1 player)" in gave, "fctrserver (count unknown)" in gave,
                 _actions41("reboot_when_empty_expire") == ["reboot_when_empty_expire"]),
          repr(_NOTES41))


def _wait_reminder41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"fctrserver": None})
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    for _i in range(40):
        _wpass41()
        _CLOCK41.sleep(60)
    rem = _bodies41("Reboot still waiting")
    check("wait: a count unread for 30 min gets ONE reminder naming the server",
          _all41(len(rem) == 1, "fctrserver" in "".join(rem), _wait_entry41(r.id) is not None),
          repr(_NOTES41))


def _wait_outside41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": 1})
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    h.reboot_now()
    _wpass41()
    check("wait: the host rebooted outside the panel — the wait is dropped, with an audit row",
          _all41(_wait_entry41(r.id) is None,
                 _actions41("reboot_when_empty_drop") == ["reboot_when_empty_drop"]))


def _wait_unreachable41():
    _fresh41()
    r, h, _rows = _std_host41()
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    h.down = True
    _wpass41()
    check("wait: a host that does not answer stays queued and is not rebooted",
          _all41(_wait_entry41(r.id) is not None, "reboot" not in _events41(h)))
    with _ps41._rwe_lock:
        _ps41._reboot_when_empty[987654] = {"by": "x", "since": 1.0}
    _wpass41()
    check("wait: a host that no longer exists is dequeued", _wait_entry41(987654) is None)


def _wait_edges41():
    _wait_expiry41()
    _wait_reminder41()
    _wait_outside41()
    _wait_unreachable41()
    _fresh41()
    r, _h, _rows = _std_host41()
    _patch(HR, "wait_max_hours", lambda: 0)
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    check("wait: with the limit at 0 it never expires", (_wait_entry41(r.id) or {}).get("expires", 1) is None)


def _bounce_stubs41(seen):
    """Empty for the census; once the stops have begun, fctr reads 1 player right before ITS stop."""
    real_run = _core41.run_as_game_user

    def _run(server, user, action, timeout=30, selfname=None, **kw):
        seen["stopping"] = seen["stopping"] or action == "stop"
        return real_run(server, user, action, timeout=timeout, selfname=selfname, **kw)

    def _slots(gs, allow_console=False, primary=None):
        if gs.short_name == "fctrserver" and seen["stopping"]:
            seen["n"] += 1
            return (1, 16, None)
        return (0, 16, None)
    _patch(_core41, "run_as_game_user", _run)
    _patch(_mon41, "_server_slots", _slots)
    _patch(HR, "STOP_WORKERS", 1)               # one account at a time: a fixed order


def _bounce_checks41():
    """A player joins in the moment between the census and their server's stop."""
    _fresh41()
    r, h, _rows = _std_host41()
    seen = {"n": 0, "stopping": False}
    _bounce_stubs41(seen)
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    t_arm = _CLOCK41.time()
    _wpass41()
    w = _wait_entry41(r.id) or {}
    check("bounce: no reboot, and the server a player just joined was never stopped",
          _all41("reboot" not in _events41(h), seen["n"] >= 1, not _lines41(h, "stop fctrserver")),
          repr(h.events()))
    check("bounce: the servers already stopped are rolled back (locks back, the panel's started again)",
          _all41(None not in _locks41(h, _AUTO41).values(),
                 not _lines41(h, "stop mcserver") or "start mcserver starting_lock=1" in h.events(),
                 not HR.plan_rows(r.id)), repr(h.events()))
    check("bounce: back to waiting, not before 10 min from now, one bounce counted",
          _all41(w.get("bounces") == 1, w.get("not_before", 0) >= t_arm + 600), repr(w))
    check("bounce: no 'did not happen' notice for it — it is still waiting",
          not _noted41("did not happen"), repr(_NOTES41))
    _bounce_again41(r, seen)


def _bounce_again41(r, seen):
    _wpass41()
    check("bounce: inside the back-off it does not look again",
          (_wait_entry41(r.id) or {}).get("bounces") == 1)
    for _i in range(2):
        _CLOCK41.sleep(600 + 1)
        seen["stopping"] = False
        _wpass41()
    check("bounce: after the third, ONE notice that players keep joining; it keeps waiting",
          _all41((_wait_entry41(r.id) or {}).get("bounces") == 3,
                 len(_bodies41("Host reboot still waiting")) == 1), repr(_NOTES41))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# K. The in-game warning before a forced reboot
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _stamp_stops41(stamps):
    real_stop = _core41.run_as_game_user

    def _stop_at(server, user, action, timeout=30, selfname=None, **kw):
        stamps.setdefault(action, _CLOCK41.time())
        return real_stop(server, user, action, timeout=timeout, selfname=selfname, **kw)
    _patch(_core41, "run_as_game_user", _stop_at)


def _countdown_warned41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": 3, "fctrserver": 2})
    t0 = _CLOCK41.time()
    stamps = {}
    _stamp_stops41(stamps)
    HR.request_reboot(r, "now", None, "web")
    says = _lines41(h, "say ")
    check("countdown: players on a game that can show a message are warned at 60, 30 and 10 s",
          _all41([ln.split(" in ")[1].split(" seconds")[0] for ln in says] == ["60", "30", "10"],
                 all(ln.startswith("say gmodserver say Server restarting in") for ln in says)), repr(says))
    check("countdown: a game with no console message (Factorio) is not sent anything",
          not [ln for ln in says if "fctrserver" in ln])
    check("countdown: the first stop comes a full minute after the first warning",
          stamps.get("stop", 0) - t0 >= 60, repr((stamps, t0)))
    first_stop = min(i for i, ln in enumerate(h.events()) if ln.startswith("stop "))
    check("countdown: every warning comes before any stop", h.events().index(says[-1]) < first_stop)


def _countdown_cancelled41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": 3})
    real_say = _sm41.game.moderate

    def _say_then_cancel(server, user, game_type, action, **kw):
        out = real_say(server, user, game_type, action, **kw)
        HR.cancel(r, NS(id=None, username="ops"))
        return out
    _patch(_sm41.game, "moderate", _say_then_cancel)
    code, _body = HR.request_reboot(r, "now", None, "web")
    _patch(_sm41.game, "moderate", real_say)
    says = _lines41(h, "say ")
    check("countdown: cancelled during it — the players are told, nothing is stopped or moved, and "
          "the operator is told nothing had been stopped",
          _all41(code == 202, len(says) == 2, "cancelled" in "".join(says[-1:]),
                 not _events41(h, ("stop", "disarm", "reboot")), not HR.plan_rows(r.id),
                 _noted41("cancelled by ops; nothing had been stopped")), repr((says, _NOTES41)))


def _countdown_checks41():
    _countdown_warned41()
    _countdown_cancelled41()
    _fresh41()
    r, h, _rows = _std_host41()
    t0 = _CLOCK41.time()
    HR.request_reboot(r, "now", None, "web")
    check("countdown: nobody on — no warning and no minute's wait",
          _all41(not _lines41(h, "say "), _CLOCK41.time() - t0 < 60 + 120))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# L. The panel's own alerts while a plan holds a server or a host
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _down_sweeps41(r, gs, n=3):
    """`n` monitor sweeps that find `gs` down after it was up: the alerts they sent."""
    ms = _ps41._monitor_state
    ms["servers"][gs.id] = True
    ms["server_misses"].pop(gs.id, None)
    del _NOTES41[:]
    for _i in range(n):
        ms["servers"][gs.id] = _mon41._server_transition(r, gs, False, ms["servers"][gs.id], False)
    return [k for k, _t, _b in _NOTES41]


def _host_cycle41(r):
    """A host that goes down for three sweeps and comes back: the alerts that sent."""
    ms = _ps41._monitor_state
    del _NOTES41[:]
    ms["remotes"][r.id] = True
    ms["remote_misses"].pop(r.id, None)
    for up in (False, False, False, True):
        _mon41._record_host_reachability(r, up)
    return [k for k, _t, _b in _NOTES41]


def _server_alert_checks41(r, gs):
    _ps41._expected_offline[gs.id] = float("inf")
    held = _down_sweeps41(r, gs)
    _ps41._expected_offline.pop(gs.id, None)
    paged = _down_sweeps41(r, gs)
    check("alerts: a server a plan stopped never pages 'went offline unexpectedly' (control: one "
          "that is not held does)", (held, paged) == ([], ["server_down"]), repr((held, paged)))
    _ps41._expected_offline[gs.id] = _CLOCK41.time()
    _CLOCK41.sleep(170)
    grace = _down_sweeps41(r, gs)
    _CLOCK41.sleep(20)
    after = _down_sweeps41(r, gs)
    check("alerts: the 3 minutes of grace after a row clears are honoured, and end",
          (grace, after) == ([], ["server_down"]), repr((grace, after)))


def _empty_alert_checks41(gs):
    gs.notify_when_empty = True
    gs.reboot_restore = _json41.dumps({"v": 1})
    db.session.commit()
    del _NOTES41[:]
    _mon41._notify_if_emptied(gs, 0)
    kept = _all41(bool(db.session.get(GameServer, gs.id).notify_when_empty), not _NOTES41)
    gs.reboot_restore = None
    db.session.commit()
    _mon41._notify_if_emptied(gs, 0)
    check("alerts: 'notify when empty' is NOT consumed by a server the reboot emptied (control: an "
          "ordinary 0 fires it once)",
          _all41(kept, [k for k, _t, _b in _NOTES41] == ["server_empty"],
                 not db.session.get(GameServer, gs.id).notify_when_empty), repr(_NOTES41))


def _host_alert_checks41(r):
    now = _CLOCK41.time()
    _ps41._reboot_awaiting[r.id] = {"sent": now, "back": None}
    during = _host_cycle41(r)
    _ps41._reboot_awaiting[r.id] = {"sent": now - 400, "back": now - 100}
    just_back = _host_cycle41(r)
    _ps41._reboot_awaiting[r.id] = {"sent": now - 900, "back": now - 400}
    later = _host_cycle41(r)
    _ps41._reboot_awaiting.pop(r.id, None)
    with _ps41._hr_lock:
        _ps41._host_reboots[r.id] = {"phase": "rebooting", "sent": now - 60}
    bare = _host_cycle41(r)
    with _ps41._hr_lock:
        _ps41._host_reboots.pop(r.id, None)
    plain = _host_cycle41(r)
    pages = ["remote_unreachable", "remote_recovered"]
    check("alerts: a host the panel rebooted pages neither 'unreachable' nor 'back online' while it "
          "is down, nor for 5 min after it is seen back", (during, just_back) == ([], []),
          repr((during, just_back)))
    check("alerts: ...after that grace, and for a host nobody rebooted, both page as before",
          (later, plain) == (pages, pages), repr((later, plain)))
    check("alerts: an idle host's reboot (no plan rows) is muted by its job for 15 min",
          bare == [], repr(bare))


def _suppression_checks41():
    _fresh41()
    r, _h, rows = _std_host41()
    _patch(_mon41, "time", _CLOCK41)
    _patch(_mon41, "_lgsm_maintenance_running", lambda remote, g: False)
    _patch(_notif41, "alerts_muted", lambda g: False)
    _server_alert_checks41(r, rows["gmod"])
    _empty_alert_checks41(rows["gmod"])
    _host_alert_checks41(r)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# M. While a host is being rebooted, nothing else touches its servers
# ════════════════════════════════════════════════════════════════════════════════════════════════
from panel.routes import admin_notifications as _AN41  # noqa: E402
from panel.routes import host_local as _HL41  # noqa: E402
from panel.routes import manage_servers as _MSR41  # noqa: E402
from panel.routes import panel_backup as _PB41  # noqa: E402
from panel.routes import remote_bootstrap as _RB41  # noqa: E402
from panel.routes import remote_vps as _RV41  # noqa: E402
from panel.routes import server_detail as _SD41  # noqa: E402
from panel.routes import _shared as _SH41  # noqa: E402
import panel.security.auth as _auth41  # noqa: E402

_rapp41 = _Flask41("unit_part41_routes")
_rapp41.config.update(SECRET_KEY="unit-part41-routes",  # nosec B106 - this part's throwaway app
                      LOGIN_DISABLED=True, TESTING=True, SQLALCHEMY_TRACK_MODIFICATIONS=False,
                      SQLALCHEMY_DATABASE_URI=_app41.config["SQLALCHEMY_DATABASE_URI"])
db.init_app(_rapp41)
_RV41.register(_rapp41)
_PB41._register_panel_host_os(_rapp41)
_HL41._register_panel_update(_rapp41)
_RB41.register(_rapp41)
_SD41._register_schedules(_rapp41)
_MSR41._register_install(_rapp41)
_AN41._register_panel_settings(_rapp41)
_rapp41.logger.disabled = True
_ADMIN41 = NS(id=None, username="admin", is_superadmin=True, is_authenticated=True)
_ADMIN41._get_current_object = lambda: _ADMIN41
_XHR41 = {"X-Requested-With": "XMLHttpRequest"}


def _as_admin41():
    for mod in (_auth41, _RV41, _PB41, _HL41, _RB41, _SD41, _MSR41):
        _patch(mod, "current_user", _ADMIN41)


def _busy41(rid, phase="stopping"):
    with _ps41._hr_lock:
        _ps41._host_reboots[rid] = {"phase": phase, "sent": None if phase != "rebooting" else 1.0,
                                    "plan": "x", "servers": []}


def _record41(calls, name, ret):
    def _call(*_a, **_k):
        calls.append(name)
        return ret
    return _call


def _gate_stubs41(calls):
    _as_admin41()
    _patch(_SD41, "set_autostart", _record41(calls, "set_autostart", (True, "")))
    _patch(_SD41, "_bg_power_action", _record41(calls, "power", None))
    _patch(_SD41, "_noop_power_refusal", lambda gs, remote, action: None)
    _patch(_RV41, "remote_os_update_start", _record41(calls, "os-update", (True, "ok")))
    _patch(_RV41, "remote_os_run_updates", _record41(calls, "run-updates", (True, "ok")))
    _patch(_so41, "panel_self_update", _record41(calls, "self-update", (True, "ok")))
    _patch(_so41, "os_run_update", _record41(calls, "os-run", (True, "ok")))
    _patch(_RB41, "_begin_bootstrap", _record41(calls, "bootstrap", (True, "")))
    _patch(_RB41, "_refuse_on_panel_host", lambda remote, what: None)
    _patch(_MSR41, "_queue_install_job", _record41(calls, "install", True))
    _patch(_MSR41, "_game_type_refusal", lambda game_type: None)   # the game list is not this part's


def _said41(resp):
    return (resp.status_code, "being rebooted" in ((resp.get_json() or {}).get("message") or ""))


def _gate_posts41(c, r, gs, failed):
    """Every refusable action on the host, through its real route: (status, said why) each."""
    return {
        "autostart": _said41(c.post("/api/server/%d/autostart" % gs.id, json={"enabled": False})),
        "os update": _said41(c.post("/api/remote/%d/os-update/start" % r.id)),
        "run updates": _said41(c.post("/api/remote/%d/run-updates" % r.id)),
        "bootstrap": _said41(c.post("/api/remote/%d/bootstrap" % r.id, json={})),
        "self-update": _said41(c.post("/api/panel/update")),
        "panel os update": _said41(c.post("/api/server-management/os-update-run")),
        "retry install": _said41(c.post("/servers/%d/retry-install" % failed.id, headers=_XHR41)),
        "install": _said41(c.post("/servers/add", data={"remote_id": r.id, "game_type": "gmod",
                                                         "server_name": "newgmod", "port": "27016"},
                                  headers=_XHR41)),
    }


def _gate_route_checks41():
    _fresh41()
    r, _h, rows = _std_host41()
    local, _lh = _remote41("panel", local=True)
    calls = []
    _gate_stubs41(calls)
    _busy41(r.id)
    _busy41(local.id)
    c = _rapp41.test_client()
    failed = _gs41(r, "rustserver", "rust", 28015, status="failed", installed=False)
    results = _gate_posts41(c, r, rows["gmod"], failed)
    action = _SD41._run_action(_app41, rows["gmod"], r, "start", None)
    refused = [k for k, v in results.items() if v != ((400, True) if "install" in k else (409, True))]
    check("gates: while a host's servers are being stopped, a start, an Autostart change, an OS "
          "update, a bootstrap, an install, a retry and the panel's self-update are all refused, "
          "each saying why",
          _all41(action[0] is False, "being rebooted" in action[1], refused == [], calls == []),
          repr((action, results, calls)))
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()
    del calls[:]
    results = {"autostart": c.post("/api/server/%d/autostart" % rows["gmod"].id, json={"enabled": True}).status_code,
               "os update": c.post("/api/remote/%d/os-update/start" % r.id).status_code,
               "self-update": c.post("/api/panel/update").status_code}
    check("gates: ...and allowed again once it is not (control)",
          _all41(results == {"autostart": 200, "os update": 200, "self-update": 200},
                 calls == ["set_autostart", "os-update", "self-update"]), repr((results, calls)))
    _exclude_checks41(c, r, rows, calls)


def _exclude_checks41(c, r, rows, calls):
    """After the reboot is sent, an operator's own action wins: the row leaves the plan."""
    _busy41(r.id, phase="rebooting")
    for g in (rows["gmod"], rows["mc"]):
        g.reboot_restore = _json41.dumps({"v": 1, "owner": "panel", "restore": "pending"})
    db.session.commit()
    del calls[:]
    ok, _msg = _SD41._run_action(_app41, rows["gmod"], r, "stop", None)
    c.post("/api/server/%d/autostart" % rows["mc"].id, json={"enabled": True})
    db.session.expire_all()
    check("exclude: after the reboot is sent, an operator's Stop and Autostart change run, and take "
          "those servers out of the restore (audited)",
          _all41(ok, calls == ["power", "set_autostart"],
                 [db.session.get(GameServer, rows[k].id).reboot_restore for k in ("gmod", "mc")] == [None, None],
                 _actions41("remote_reboot_exclude") == ["remote_reboot_exclude"] * 2),
          repr((calls, _audit41())))
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()


def _sweeps41(seen):
    _SH41._run_due_restarts(_app41)
    _SH41._run_pending_backups(_app41)
    _SH41._run_due_game_backups(_app41)
    return seen


def _sweep_checks41():
    _fresh41()
    r, _h, rows = _std_host41()
    seen = []
    _patch(_SH41, "_settle_queued_action", lambda app, gs: seen.append(("restart", gs.short_name)))
    _patch(_SH41, "_back_up_queued", lambda app, gs: seen.append(("queued", gs.short_name)))
    _patch(_SH41, "_back_up_if_due", lambda app, target: seen.append(("due", target[2])))
    _patch(_SH41, "_backups_blocked_by_config", lambda app, what: False)
    for g in rows.values():
        g.restart_pending = True
        g.backup_pending = True
    rows["gmod"].reboot_restore = _json41.dumps({"v": 1})
    db.session.commit()
    _busy41(r.id)
    check("sweeps: while the host's servers are being stopped, the queued-restart and both backup "
          "sweeps leave every one of them alone", _sweeps41(seen) == [], repr(seen))
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()
    want = {(k, u) for k in ("restart", "queued", "due") for u in ("mcserver", "codserver", "fctrserver")}
    check("sweeps: ...after it, only the server the restore still holds is skipped",
          set(_sweeps41(seen)) == want, repr(seen))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# N. The rest of the ways a reboot is asked for: the API route, and the bots (which may not)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _api_route_checks41():
    _fresh41()
    _r, h, _rows = _std_host41(local=True)
    h.players.update({"gmodserver": 2})
    _as_admin41()
    c = _rapp41.test_client()
    resp = c.post("/api/server-management/reboot", json={"delay": 30})
    check("api: the panel host's reboot route goes through the same gate — players on and no mode "
          "is a 409 with the choices, and nothing touched",
          _all41(resp.status_code == 409, (resp.get_json() or {}).get("needs_choice") is True,
                 not _events41(h, ("stop", "disarm", "reboot"))), repr(resp.get_json()))
    resp = c.post("/api/server-management/reboot", json={"mode": "later"})
    check("api: an unknown mode is a 400", resp.status_code == 400)
    t0 = _CLOCK41.time()
    resp = c.post("/api/server-management/reboot", json={"delay": 30, "mode": "now"})
    check("api: mode now with a delay: 202, the delay waited out by the job before it read the host, "
          "then the clean reboot",
          _all41(resp.status_code == 202, _CLOCK41.time() - t0 >= 30, "reboot" in _events41(h)),
          repr(resp.get_json()))
    _fresh41()
    _as_admin41()
    plain = []
    _patch(_so41, "server_reboot", lambda delay: (plain.append(delay), (True, "Server will reboot"))[1])
    _patch(_PB41, "log_action", lambda *a, **k: None)
    resp = c.post("/api/server-management/reboot", json={"delay": 7})
    check("api: with no local host row it reboots as it always did",
          _all41(resp.status_code == 200, plain == [7]), repr((resp.get_json(), plain)))


def _bot_checks41():
    from panel.services.bots import commands as _cmds41, discord as _dc41, telegram as _tg41
    asked = []
    for name in ("request_reboot", "start_clean_reboot", "arm_wait"):
        _patch(HR, name, _record41(asked, name, None))
    replies = []
    _patch(_tg41, "_tg_reply", lambda token, chat_id, text: replies.append(text))
    _patch(_dc41, "_dc_reply", lambda token, channel, text: replies.append(text))
    _tg41._handle_telegram_command(_app41, "t", "c", "/reboot vps now", sender=1)
    _dc41._handle_discord_command(_app41, "t", "c", "!reboot vps now", sender=1)
    check("bots: there is no reboot command — /reboot and !reboot are unknown commands and ask the "
          "reboot code nothing",
          _all41(asked == [], len(replies) == 2, all("Unknown command 'reboot'" in t for t in replies)),
          repr((asked, replies)))
    check("bots: ...nor is one offered in Telegram's command menu or open to everyone",
          _all41("reboot" not in [c for c, _d in _notif41.TG_COMMANDS], "reboot" not in _cmds41.OPEN_COMMANDS))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# O. The panel's own host: through the helper, or as a per-user install without it
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _helper_flow_checks41():
    ev = _trace41()
    order = [e for e in ev if e in ("helper:stop", "rearm", "reboot", "notify:flush", "notify:host_reboot:Rebooting Panel Server")]
    check("panel host (helper): the stops go through the helper's lgsm-command",
          ev.count("helper:stop") == 3, repr(ev))
    check("panel host (helper): the 'Rebooting' notice is FLUSHED to its channels before the locks "
          "go back and the reboot is sent — the panel goes down with the host",
          _all41(_order41(order, {"notify:host_reboot:Rebooting Panel Server"}, {"notify:flush"}),
                 _order41(order, {"notify:flush"}, {"rearm"}), order[-1:] == ["reboot"]), repr(order))


def _restart_marks41(rows):
    """The host rebooted and took the panel with it: memory is gone; resume reads the rows."""
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()
    _ps41._expected_offline.clear()
    HR.resume_reboot_state(_app41)
    check("panel host: at startup, before the monitor's first pass, every planned server's alerts "
          "are held again from the rows",
          _all41([_ps41._expected_offline.get(rows[k].id) for k in ("gmod", "mc", "fctr")] == [float("inf")] * 3,
                 rows["cod"].id not in _ps41._expected_offline))


def _panel_host_checks41():
    _fresh41()
    r, h, rows = _std_host41(local=True)
    _patch(_core41, "helper_present", lambda recheck=False: True)
    HR.request_reboot(r, "now", None, "web")
    _helper_flow_checks41()
    h.reboot_now()
    _restart_marks41(rows)
    _CLOCK41.sleep(90)
    _restore_until41(r.id, between=_monitor_cron41(h, {}))
    argv = getattr(h, "helper_argv", [])
    action = argv[argv.index("lgsm-command") + 3] if "lgsm-command" in argv else None
    check("panel host (helper): after the boot the panel starts exactly its own, through the helper",
          _all41(_lines41(h, "start ") == ["start mcserver starting_lock=1"], action == "start"),
          repr((h.events(), argv)))


def _per_user_one41(unit, scope_ok):
    _fresh41()
    r, h, _rows = _std_host41(local=True)
    h.user_scope_ok = scope_ok
    _patch(_core41, "_USER_UNIT", unit)
    HR.request_reboot(r, "now", None, "web")
    h.reboot_now()
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()
    boot = _CLOCK41.time()
    _CLOCK41.sleep(70)
    _restore_until41(r.id, between=_monitor_cron41(h, {}))
    at = [t for s_, t in h.timed("start") if s_ == "mcserver"]
    return h, boot, at


def _per_user_checks41():
    unit = os.path.join(_TMP41, "linuxgsm-panel.service")
    open(unit, "w").close()
    h, _boot, _at = _per_user_one41(unit, True)
    check("per-user panel host: the restore asks the user manager again and starts the "
          "server in a scope of its own, out of the panel's cgroup",
          _all41(_lines41(h, "start ") == ["start mcserver starting_lock=1"],
                 any("mcserver" in c and "start" in c for c in h.scoped)), repr((h.events(), h.scoped)))
    h, boot, at = _per_user_one41(unit, False)
    check("per-user panel host: with no user manager to ask yet, the start waits (up to 2 min "
          "after the boot) rather than land in the panel's cgroup; then it starts anyway",
          _all41(_lines41(h, "start ") == ["start mcserver starting_lock=1"], not h.scoped,
                 bool(at) and at[0] - boot >= 120), repr((h.events(), at, boot)))
    _core41._USER_SCOPE.update(ok=None, at=0.0)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# P. A restore that does not fully work, and a lock left aside by a reboot from outside
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _restore_failure_checks41():
    _fresh41()
    r, h, rows = _std_host41()
    HR.request_reboot(r, "now", None, "web")
    h.reboot_now()
    h.flag("fail_start", "mcserver")
    _CLOCK41.sleep(90)
    _restore_until41(r.id, passes=80, between=lambda n: h.run("gmodserver", True) if n == 10 else None)
    summary = "".join(_bodies41("Host reboot"))
    check("restore failures: the panel tries its own start three times, then gives up",
          len(_lines41(h, "start mcserver")) == 3, repr(h.events()))
    check("restore failures: ONE summary, naming each server that did not come back and why — the "
          "panel's start failure in LinuxGSM's words, and the Autostart server the monitor never "
          "restarted (after 12 min)",
          _all41(len(_bodies41("Host reboot")) == 1, "1/3 running again" in summary,
                 "mcserver didn't come back: FAIL: Unable to start mcserver" in summary,
                 "fctrserver didn't come back: LinuxGSM's monitor has not brought it back" in summary),
          repr(_NOTES41))
    check("restore failures: a server reported as not back is recorded down, so the monitor does not "
          "page 'went offline' about it as well",
          [_ps41._monitor_state["servers"].get(rows[k].id) for k in ("mc", "fctr")] == [False, False])
    check("restore failures: audited as a restore that did not fully succeed",
          [(a, ok) for a, ok, _d in _audit41("remote_reboot_restore")] == [("remote_reboot_restore", False)])
    _outside_reboot_checks41()


def _outside_reboot_checks41():
    """A reboot from outside hit between the move aside and the move back."""
    _r, h, _rows = _plan_with_sent41(owner_map={"gmod": "monitor"})
    os.rename(h.lock("gmodserver"), h.lock("gmodserver") + ".panel-reboot")
    h.reboot_now()
    _CLOCK41.sleep(90)
    _pass41()
    check("lock left aside by an outside reboot: put back after the boot, the panel starts nothing",
          _all41(_lockfile41(h, "gmodserver") is not None,
                 not os.path.exists(h.lock("gmodserver") + ".panel-reboot"), not _lines41(h, "start ")),
          repr(h.events()))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# Q. Cancelling, and the plan's own preview and status
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cancel_stop_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    real = _core41.run_as_game_user

    def _cancel_at_stop(server, user, action, timeout=30, selfname=None, **kw):
        out = real(server, user, action, timeout=timeout, selfname=selfname, **kw)
        if action == "stop":
            HR.cancel(r, NS(id=None, username="ops"))
        return out
    _patch(_core41, "run_as_game_user", _cancel_at_stop)
    _patch(HR, "STOP_WORKERS", 1)
    HR.request_reboot(r, "now", None, "web")
    _patch(_core41, "run_as_game_user", real)
    check("cancel during the stops: the stop under way finishes, the rest are not stopped, no "
          "reboot, and what was stopped is brought back",
          _all41(len(_lines41(h, "stop ")) == 1, "reboot" not in _events41(h),
                 _lockfile41(h, "gmodserver") is not None, not HR.plan_rows(r.id),
                 _noted41("did not happen (cancelled by ops)")), repr((h.events(), _NOTES41)))
    with _ps41._hr_lock:
        _ps41._host_reboots[r.id] = {"phase": "arming", "sent": _CLOCK41.time()}
    code, body = HR.cancel(r, None)
    check("cancel after the reboot was sent: refused, saying so",
          _all41(code == 409, "reboot has been sent" in body["message"]), repr(body))
    with _ps41._hr_lock:
        _ps41._host_reboots.clear()


def _cancel_checks41():
    _cancel_stop_checks41()
    _fresh41()
    r, h, _rows = _std_host41()
    real_sleep = _CLOCK41.sleep

    def _sleep_then_cancel(sec):
        real_sleep(sec)
        if HR.job_of(r.id):
            HR.cancel(r, NS(id=None, username="ops"))
    _patch(_CLOCK41, "sleep", _sleep_then_cancel)
    code, _body = HR.request_reboot(r, "now", None, "web", delay=60)
    _patch(_CLOCK41, "sleep", real_sleep)
    check("cancel during the delay: nothing is touched, and the operator is told so",
          _all41(code == 202, not _events41(h, ("stop", "disarm", "reboot")),
                 _noted41("nothing had been stopped yet")), repr(_NOTES41))


def _preview_checks41():
    _fresh41()
    r, h, _rows = _std_host41(local=True)
    pv = {sv["name"]: sv for sv in HR.preview(r)}
    check("preview: says per server who brings it back, without touching anything",
          _all41([pv[n]["owner"] for n in ("gmodserver", "mcserver", "codserver")] == ["monitor", "panel", None],
                 "Autostart about 5 min" in pv["gmodserver"]["text"], "stays stopped" in pv["codserver"]["text"],
                 not _events41(h, ("stop", "disarm", "reboot", "rearm"))), repr(pv))
    _patch(_so41, "panel_starts_at_boot", lambda: False)
    check("preview: on the panel host, when the panel does not start at boot, it says the servers "
          "the PANEL starts would stay down", HR.preflight_warning(r, list(pv.values())) == HR.PANEL_WONT_RETURN)
    code, body = HR.request_reboot(r, "now", None, "web")
    check("preview: ...and the 202 carries the same warning (a warning, not a refusal)",
          (code, body.get("warning")) == (202, HR.PANEL_WONT_RETURN), repr(body))
    db.session.expire_all()
    st = HR.status(r)
    job = st["job"] or {}
    check("status: the job, the rows and nothing secret — what the Power card polls",
          _all41(job.get("phase") == "rebooting", "cancel" not in job,
                 {x["name"] for x in st["rows"]} == {"gmodserver", "mcserver", "fctrserver"}), repr(st))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# R. Startup, the database column, the notification flush and the boot identity
# ════════════════════════════════════════════════════════════════════════════════════════════════
_REAL_FLUSH41 = _notif41.flush


def _startup_rows41():
    from datetime import timedelta
    from panel.core.clock import utcnow
    hosts = {n: _remote41(n)[0] for n in ("alpha", "beta", "gamma", "delta")}
    now = utcnow()
    for name, actions, ago in (("alpha", ["reboot_when_empty_arm"], 2),
                               ("beta", ["reboot_when_empty_arm", "reboot_when_empty_cancel"], 2),
                               ("gamma", ["reboot_when_empty_arm", "remote_reboot"], 2),
                               ("delta", ["reboot_when_empty_arm"], 72)):
        for i, a in enumerate(actions):
            db.session.add(AuditLog(action=a, username="alice", remote_id=hosts[name].id, target=name,
                                    timestamp=now - timedelta(hours=ago) + timedelta(minutes=i)))
    db.session.commit()


def _startup_checks41():
    _fresh41()
    _startup_rows41()
    HR.announce_dropped_waits(_app41)
    drops = [(a.target, a.username) for a in AuditLog.query.filter_by(action="reboot_when_empty_drop")]
    told = _bodies41("Reboot wait cancelled")
    check("startup: a wait the restart dropped is announced — only a host whose newest wait row is "
          "the arm itself, within the wait's own limit",
          _all41(drops == [("alpha", "alice")], len(told) == 1, "alpha" in "".join(told)),
          repr((drops, _NOTES41)))
    HR.announce_dropped_waits(_app41)
    check("startup: ...and only once (the drop row it wrote is now the newest)",
          AuditLog.query.filter_by(action="reboot_when_empty_drop").count() == 1)
    _startup_wiring41()


def _startup_wiring41():
    """app.py's start: the holds go in before the monitor thread exists, and both loops are supervised."""
    with open(os.path.join(_ROOT41, "app.py"), encoding="utf-8") as fh:
        src = fh.read()
    main = src[src.index('if __name__ == "__main__":'):]
    at = {k: main.find(k) for k in ("_host_reboot.resume_reboot_state(app)",
                                     "_host_reboot.announce_dropped_waits(app)",
                                     'target=lambda: _monitor_watch(app), name="monitor"',
                                     '_supervise("host-reboot", lambda: _host_reboot.host_reboot_worker(app))',
                                     '_supervise("reboot-when-empty", '
                                     'lambda: _host_reboot.reboot_when_empty_watch(app))')}
    order = sorted(at, key=at.get)
    check("startup: app.py puts the reboot holds in place (and announces dropped waits) BEFORE it "
          "starts the monitor thread, and runs both reboot loops under the supervisor",
          _all41(-1 not in at.values(),
                 at["_host_reboot.resume_reboot_state(app)"] < at['target=lambda: _monitor_watch(app), name="monitor"']),
          repr(order))


def _columns41():
    return [row[1] for row in db.session.execute(_sa_text41("PRAGMA table_info(game_server)"))]


def _migration_checks41():
    from panel.db.models import _run_light_migrations
    mig = _Flask41("unit_part41_mig")
    mig.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_TMP41, "upgrade.db"),
                      SQLALCHEMY_TRACK_MODIFICATIONS=False)
    db.init_app(mig)
    with mig.app_context():
        db.create_all()
        db.session.execute(_sa_text41("ALTER TABLE game_server DROP COLUMN reboot_restore"))
        db.session.commit()
        before = _columns41()
        _run_light_migrations()
        after = _columns41()
        db.session.remove()
    check("migration: a database from before this change gains game_server.reboot_restore at startup",
          ("reboot_restore" in before, "reboot_restore" in after) == (False, True), repr(after))


def _flush_checks41():
    q, lock, sender = _notif41._alert_queue, _notif41._alert_lock, _notif41._alert_sender
    with lock:
        busy_before = sender[0]
        sender[0] = True
    t0 = _time41.monotonic()
    waited = _REAL_FLUSH41(timeout=0.3)
    with lock:
        sender[0] = busy_before
    check("flush: it waits for the sender to stand down, and says so when it did not in time",
          _all41(waited is False, _time41.monotonic() - t0 >= 0.3))
    check("flush: an empty queue with no sender is flushed at once",
          _all41(q.empty(), _REAL_FLUSH41(timeout=0) is True))


def _flush_identity_checks41():
    _flush_checks41()
    _fresh41()
    r, h = _remote41("ident")
    good = _hosts41.host_boot_identity(r)
    check("boot identity: boot id, machine id, uptime, the host's clock and systemd's state",
          good == {"boot": h.boot, "mid": h.mid, "uptime": h.uptime, "now": int(_CLOCK41.time()),
                   "state": "running"}, repr(good))
    h.boot = "not-a-boot-id"
    h._write_ids()
    check("boot identity: anything but a real boot id is None — never a new boot",
          _hosts41.host_boot_identity(r) is None)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# S. The helper runs LinuxGSM as ./<script>, so LinuxGSM's own guards see it
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _helper41():
    spec = _ilu41.spec_from_loader("panel_helper_p41", _mach41.SourceFileLoader(
        "panel_helper_p41", os.path.join(_ROOT41, "tools", "panel-helper")))
    helper = _ilu41.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper._drop_to = lambda pw_, own_groups=False: True       # not root here: nothing to drop
    return helper


def _helper_checks41():
    import pwd as _pwd41
    helper = _helper41()
    home = _tf41.mkdtemp(prefix="p3home-", dir=_TMP41)
    out = os.path.join(_TMP41, "p3-guard.out")
    # LinuxGSM's own guard (command_monitor.sh): pgrep -fcx "/bin/bash ./<s> start". A name of
    # this run's own, as in the probe-pattern check.
    name = "zq%sserver" % _uuid41.uuid4().hex[:8]
    _write_exec41(os.path.join(home, name),
                  '#!/bin/bash\npgrep -u "$(id -un)" -fcx "/bin/bash ./%s start" > %s\n'
                  % (name, _shlex41.quote(out)))
    os.symlink("/bin/true", os.path.join(home, "escape"))
    pw = _pwd41.getpwuid(os.getuid())
    rc = helper._lgsm_child(pw, home, name, "start", "", False)
    with open(out) as fh:
        seen = fh.read().strip()
    os.remove(out)
    rc_escape = helper._lgsm_child(pw, home, "escape", "start", "", False)
    check("helper: a LinuxGSM start it runs is `/bin/bash ./<s> start` — exactly what LinuxGSM's "
          "monitor looks for before it starts a second copy", (rc, seen) == (0, "1"), repr((rc, seen)))
    check("helper: ...and a script that is a symlink out of the home directory is still refused",
          _all41(rc_escape == 1, not os.path.exists(out)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# T. "Are game servers running?" — the bootstrap's probe and install.sh's, with the real pgrep
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TMUX_NAME41 = ("import ctypes, time; ctypes.CDLL(None).prctl(15, b'tmux: server', 0, 0, 0); "
                "time.sleep(30)")
_STUBS41 = ('ok() { echo "OK $*"; }; warn() { echo "WARN $*"; }; info() { :; }; sleep() { :; }; '
            'reboot() { echo REBOOTING; }; sudo() { "$@"; }; UPG_SUDO=""\n')


def _install_block41(txt, start, end):
    i = txt.index(start)
    return txt[i:txt.index(end, i) + len(end)]


def _install_blocks41():
    """install.sh's game_sessions_running and its two reboot spots, the marker file pointed at ours."""
    with open(os.path.join(_ROOT41, "install.sh"), encoding="utf-8") as fh:
        txt = fh.read()
    marker = os.path.join(_TMP41, "reboot-required")
    open(marker, "w").close()
    fn = _install_block41(txt, "game_sessions_running() {", "\n}\n")
    blocks = [_install_block41(txt, '                if [[ ! -f /var/run/reboot-required ]]; then\n'
                                    '                    ok "System updated', "\n                fi\n"),
              _install_block41(txt, 'if [[ "${PANEL_NO_UPGRADE:-0}" != "1" ]] && [[ "${PANEL_NO_REBOOT:-0}" != "1" ]]; then\n'
                                    '    RB_SUDO=""', "\nfi\n")]
    return [_STUBS41 + fn + b.replace("/var/run/reboot-required", marker) for b in blocks]


def _run_blocks41(blocks):
    return [_run41(["bash", "-c", b]).stdout for b in blocks]


def _session_probe_checks41():
    probe = _hosts41.GAME_SESSIONS_PROBE
    blocks = _install_blocks41()
    pre = _run41(["bash", "-c", probe]).stdout.strip()
    idle = _run_blocks41(blocks)
    proc = _popen41([sys.executable, "-c", _TMUX_NAME41])
    try:
        _time41.sleep(0.4)
        named = _run41(["pgrep", "-x", "tmux: server"]).stdout.split()
        busy_probe = _run41(["bash", "-c", probe]).stdout.strip()
        busy = _run_blocks41(blocks)
    finally:
        proc.kill()
        proc.wait()
    if str(proc.pid) not in named:
        skip("game-session probe: a process named 'tmux: server'", "prctl(PR_SET_NAME) did not take here")
        return
    check("game-session probe: with LinuxGSM's tmux server running (its process is named "
          "'tmux: server'), the bootstrap's probe answers YES — `pgrep -x tmux` answered NO",
          busy_probe == "YES", repr(busy_probe))
    check("install.sh: with it running, neither reboot spot reboots, and both say why",
          all("REBOOTING" not in o and "game servers" in o for o in busy), repr(busy))
    if pre == "NO" and all("REBOOTING" in o for o in idle):
        check("install.sh: ...while an idle host that needs one is still rebooted (control)", True)
    else:
        skip("install.sh: the idle control", "this machine runs a tmux or screen session of its own")


def _bootstrap_run_checks41():
    _fresh41()
    r, _h, rows = _std_host41()
    got = []
    _patch(_SH41, "remote_bootstrap_vps",
           lambda remote, progress=None, **kw: (got.append(kw.get("servers_online")), (True, "done", ""))[1])
    job = {"status": "running", "log": []}
    _SH41._BootstrapRun(_app41, r.id, job)._bootstrap({})
    for g in rows.values():
        g.status = "offline"
    db.session.commit()
    _SH41._BootstrapRun(_app41, r.id, job)._bootstrap({})
    check("bootstrap: it is told whether a server the panel manages on the host was last seen "
          "online (and so never reboots it)", got == [True, False], repr(got))



# ════════════════════════════════════════════════════════════════════════════════════════════════
# U. The plan's edges: a server that starts mid-plan, a lock left aside, a queued stop, an idle
#    host, a lock that cannot be moved
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _rescan_checks41():
    """A server not in the plan starts during the stop phase (a cron, someone at a shell)."""
    _fresh41()
    r, h, rows = _std_host41()
    real = _core41.run_as_game_user

    def _cod_wakes(server, user, action, timeout=30, selfname=None, **kw):
        out = real(server, user, action, timeout=timeout, selfname=selfname, **kw)
        if (action, selfname) == ("stop", "gmodserver"):
            h.run("codserver", True)
        return out
    _patch(_core41, "run_as_game_user", _cod_wakes)
    _patch(HR, "STOP_WORKERS", 1)
    HR.request_reboot(r, "now", None, "web")
    rec = _rr41(rows["cod"].id) or {}
    check("re-scan: a server that started during the stops is found before the reboot, stopped, and "
          "put in the plan (the panel brings it back: it has no lock for the monitor)",
          _all41(_lines41(h, "stop codserver") == ["stop codserver starting_lock=0"],
                 (rec.get("owner"), rec.get("stop")) == ("panel", "stopped"), not h.running("codserver"),
                 _trace41().count("reboot") == 1), repr((h.events(), rec)))


def _leftover_checks41():
    """A lock an interrupted plan left aside is put back before a new plan reads the server."""
    _fresh41()
    r, h, rows = _std_host41()
    os.rename(h.lock("gmodserver"), h.lock("gmodserver") + ".panel-reboot")
    HR.request_reboot(r, "now", None, "web")
    rec = _rr41(rows["gmod"].id) or {}
    rolled = [d for a, _s, d in _audit41("remote_reboot_rollback")]
    check("leftover lock: put back first — the server is the monitor's again, as it was before the "
          "interrupted plan, and its lock is in place for the reboot",
          _all41(rec.get("owner") == "monitor", _lockfile41(h, "gmodserver") is not None,
                 any("left aside by an earlier plan" in d for d in rolled)), repr((rec, rolled)))


def _stop_pending_checks41():
    """A queued "stop when empty": the reboot's stop honours it, and nothing brings it back."""
    _fresh41()
    r, h, rows = _std_host41()
    rows["gmod"].stop_pending = True
    rows["mc"].restart_pending = True
    db.session.commit()
    _code, body = HR.request_reboot(r, "now", None, "web")
    check("queued stop: the answer to the request promises no blanket return",
          _all41("come back after" not in body.get("message", ""),
                 "stopped cleanly first" in body.get("message", "")), repr(body))
    db.session.expire_all()
    check("queued stop: honoured by the reboot — stopped, the flag cleared, and its lock NOT put back "
          "(so LinuxGSM's monitor leaves it stopped)",
          _all41(db.session.get(GameServer, rows["gmod"].id).stop_pending is False,
                 (_rr41(rows["gmod"].id) or {}).get("owner") == "none",
                 _lockfile41(h, "gmodserver") is None, _asides41(h) == []), repr(h.events()))
    told = _bodies41("Rebooting vps")
    check("queued stop: the 'Rebooting' notice says which come back and which stay stopped — not "
          "'they come back' for all of them",
          told == ["Stopped 3 game servers cleanly (0 players disconnected). 2 come back after the "
                   "reboot. 1 stays stopped (a queued stop, or no Autostart with restoring turned off "
                   "in Settings)."], repr(told))
    h.reboot_now()
    _CLOCK41.sleep(120)
    _restore_until41(r.id, between=_monitor_cron41(h, {}))
    db.session.expire_all()
    check("queued stop: ...after the boot it stays stopped, and the summary says so",
          _all41(not h.running("gmodserver"),
                 "1 stayed stopped, as planned (a queued stop" in "".join(_bodies41("Host reboot")),
                 "as before" not in "".join(_bodies41("Host reboot"))),
          repr(_NOTES41))
    check("queued restart: the restore's start does the restart that was waiting, and clears it",
          db.session.get(GameServer, rows["mc"].id).restart_pending is False)


def _bare_job_checks41():
    """A host with no game server running: rebooted at once, and its return reported."""
    _fresh41()
    r, h, _rows = _std_host41()
    for s_ in ("gmodserver", "mcserver", "fctrserver"):
        h.run(s_, False)
    code, _body = HR.request_reboot(r, "now", None, "web")
    check("idle host: nothing to stop — no plan rows, the reboot sent, the job waiting for it",
          _all41(code == 202, not HR.plan_rows(r.id), _trace41().count("reboot") == 1,
                 (HR.job_of(r.id) or {}).get("phase") == "rebooting"))
    eq("idle host: the 'Rebooting' notice says nothing was running (not 'stopped 0 ... they come back')",
       _bodies41("Rebooting vps"), ["No game servers were running, so none were stopped."])
    h.reboot_now()
    _CLOCK41.sleep(30)
    _pass41()
    check("idle host: its return is reported once, and the job ends",
          _all41(_noted41("no game servers were running"), HR.job_of(r.id) is None), repr(_NOTES41))


def _bare_silent_checks41():
    """An idle host that never answers after its reboot: the alert hold ends with the day's notice."""
    _fresh41()
    r, h, _rows = _std_host41()
    for s_ in ("gmodserver", "mcserver", "fctrserver"):
        h.run(s_, False)
    HR.request_reboot(r, "now", None, "web")
    h.down = True
    _CLOCK41.sleep(700)
    _pass41()
    early = _mon41._reboot_alerts_muted(r.id, now=_CLOCK41.time())
    _CLOCK41.sleep(86400)
    _pass41()
    late = _mon41._reboot_alerts_muted(r.id, now=_CLOCK41.time())
    check("idle host that never comes back: its unreachable alerts are held while it may be "
          "rebooting, and the hold ends with the 'not back after a day' notice, so a later outage "
          "alerts again", _all41(early is True, late is False, HR.job_of(r.id) is None,
                                 _noted41("has not come back after a day")), repr((early, late, _NOTES41)))


def _disarm_fail_checks41():
    """A lock that cannot be moved aside: the stop will delete it, so the panel brings it back."""
    _fresh41()
    r, _h, rows = _std_host41()
    real = HR.disarm
    _patch(HR, "disarm", lambda remote, ident: None if _ident41(ident) == "gmodserver" else real(remote, ident))
    HR.request_reboot(r, "now", None, "web")
    check("disarm failed: the server becomes the panel's to start (its lock went with the stop)",
          (_rr41(rows["gmod"].id) or {}).get("owner") == "panel")


def _settings_post41(c, saved, form):
    saved.clear()
    resp = c.post("/settings/save", data=form)
    return resp.status_code, saved.get("reboot_wait_max_hours"), saved.get("reboot_restore_no_autostart")


def _settings_checks41():
    """The Settings page's two reboot fields: saved under the keys the reboot code reads."""
    _as_admin41()
    _patch(_AN41, "current_user", _ADMIN41)
    _patch(_AN41, "log_action", lambda *a, **k: None)
    saved = {}
    _patch(_AN41, "update_config", lambda mutate: mutate(saved))
    c = _rapp41.test_client()
    got = [_settings_post41(c, saved, f) for f in (
        {"reboot_wait_max_hours": "48", "reboot_restore_no_autostart": "on"},
        {"reboot_wait_max_hours": "9999"}, {"reboot_wait_max_hours": "-3"},
        {"reboot_wait_max_hours": "soon", "reboot_restore_no_autostart": "on"})]
    eq("settings: the wait limit and the restore switch are saved; the limit is held to 0-720 h, "
       "an unreadable one is the 24 h default, and an unticked switch is off",
       got, [(302, 48, True), (302, 720, False), (302, 0, False), (302, 24, True)])
    _patch(HR, "load_config", lambda: {"reboot_wait_max_hours": 48, "reboot_restore_no_autostart": False})
    a = (HR.wait_max_hours(), HR.restore_no_autostart())
    _patch(HR, "load_config", dict)
    b = (HR.wait_max_hours(), HR.restore_no_autostart())
    check("settings: ...the reboot code reads those same keys, and an install that never saved "
          "them waits 24 h and restores the servers without Autostart", (a, b) == ((48, False), (24, True)),
          repr((a, b)))


def _debug_report_checks41():
    """The debug report's server line while a plan holds the server (an infinite hold)."""
    from panel.ops.debug_report import servers as _dbs41
    gs = NS(id=4141, restart_pending=False)
    now = _CLOCK41.time()
    st = {"expected": {4141: float("inf")}, "cron_restart": {}}
    try:
        held = _dbs41._flags(gs, st, now, False)
    except (OverflowError, ValueError, TypeError) as exc:
        held = "raised %r" % exc
    st["expected"][4141] = now - 40
    stopped = _dbs41._flags(gs, st, now, False)
    check("debug report: a server held by a host reboot says so (an infinite hold is not 'a panel "
          "stop -inf ago'), and a panel stop still reads as one",
          (held, stopped) == (["expected offline (host reboot)"], ["expected offline (panel stop 40 s ago)"]),
          repr((held, stopped)))


def _ident41(ident):
    return ident["selfname"] if isinstance(ident, dict) else ident.lgsm_name


# ════════════════════════════════════════════════════════════════════════════════════════════════
# W. The page: the reboot dialog, the Power card's state and the banner, run in node on a small DOM
# ════════════════════════════════════════════════════════════════════════════════════════════════
_NODE41 = r'''// node harness.js <nags.js>: drive the reboot dialog, the Power card and the banner on a small DOM.
const fs = require('fs'), vm = require('vm');
class N { constructor(){ this.childNodes = []; this.parentNode = null; } }
class T extends N { constructor(t){ super(); this.nodeType = 3; this.data = String(t); }
  get textContent(){ return this.data; } }
class E extends N {
  constructor(tag){ super(); this.nodeType = 1; this.tagName = tag.toUpperCase(); this.className = '';
    this.attrs = {}; this.style = {}; this.ls = {}; this.disabled = false; this.id = ''; this.type = ''; }
  get children(){ return this.childNodes.filter(c => c.nodeType === 1); }
  get firstChild(){ return this.childNodes[0] || null; }
  _rm(c){ const i = this.childNodes.indexOf(c); if (i >= 0) this.childNodes.splice(i, 1); c.parentNode = null; }
  appendChild(c){ if (c.parentNode) c.parentNode._rm(c); c.parentNode = this; this.childNodes.push(c); return c; }
  insertBefore(c, ref){ if (c.parentNode) c.parentNode._rm(c); c.parentNode = this;
    const i = ref ? this.childNodes.indexOf(ref) : -1; if (i < 0) this.childNodes.push(c); else this.childNodes.splice(i, 0, c); return c; }
  remove(){ if (this.parentNode) this.parentNode._rm(this); }
  get textContent(){ return this.childNodes.map(c => c.textContent).join(''); }
  set textContent(v){ this.childNodes.forEach(c => { c.parentNode = null; }); this.childNodes = [];
    if (v != null && v !== '') this.appendChild(new T(v)); }
  set innerHTML(v){ this.textContent = ''; }
  setAttribute(k, v){ this.attrs[k] = String(v); if (k === 'id') this.id = String(v); }
  getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, f){ (this.ls[t] = this.ls[t] || []).push(f); }
  removeEventListener(t, f){ this.ls[t] = (this.ls[t] || []).filter(x => x !== f); }
  fire(t, ev){ (this.ls[t] || []).slice().forEach(f => f(Object.assign({type: t, target: this}, ev || {}))); }
  click(){ if (!this.disabled) this.fire('click'); }
  focus(){ doc.activeElement = this; }
  _all(){ const out = []; const walk = n => n.children.forEach(c => { out.push(c); walk(c); }); walk(this); return out; }
  _is(sel){ if (sel[0] === '.') return this.className.split(/\s+/).includes(sel.slice(1));
    if (sel[0] === '#') return this.id === sel.slice(1); return this.tagName === sel.toUpperCase(); }
  querySelectorAll(sel){ return this._all().filter(e => e._is(sel)); }
  querySelector(sel){ return this.querySelectorAll(sel)[0] || null; }
}
const doc = new E('#document');
doc.body = doc.appendChild(new E('body'));
doc.createElement = t => new E(t);
doc.createTextNode = t => new T(t);
doc.getElementById = id => doc.body._all().find(e => e.id === id) || null;
doc.hidden = false;
const calls = [], toasts = [], refreshed = [];
let answers = {};
global.window = global; global.document = doc; global.MOUNT = '';
global.toast = (m, k) => toasts.push([m, k]);
global.fetch = (url, opt) => {
  const method = (opt && opt.method) || 'GET';
  calls.push({method, url, body: opt && opt.body ? JSON.parse(opt.body) : null});
  const a = answers[method + ' ' + url];
  if (a === undefined) return Promise.reject(new Error('no answer for ' + method + ' ' + url));
  const [status, body] = a;
  return Promise.resolve({ok: status < 400, status, json: () => Promise.resolve(body)});
};
vm.runInThisContext(fs.readFileSync(process.argv[2], 'utf8'), {filename: 'nags.js'});
const realRefresh = window.rebootStateRefresh;
window.rebootStateRefresh = id => { refreshed.push(id); };
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setTimeout(r, 0)); };
const overlay = () => doc.body.querySelector('.rb-overlay');
const buttons = el => (el ? el.querySelectorAll('button') : []).map(b => b.textContent);
const press = (el, text) => { const b = (el ? el.querySelectorAll('button') : []).find(x => x.textContent === text);
  if (!b) return false; b.click(); return true; };
const posts = path => calls.filter(c => c.method === 'POST' && c.url.endsWith(path)).map(c => c.body);
const P = '/api/remote/7';
const census = {
  busy: {state: 'busy', busy: [{id: 1, name: 'gmod', players: 3}], unknown: [], blockers: []},
  unknown: {state: 'unknown', busy: [], unknown: [{id: 2, name: 'fctr', reason: 'not_queryable'}], blockers: []},
  idle: {state: 'idle', busy: [], unknown: [], blockers: []},
  blocked: {state: 'blocked', busy: [], unknown: [], blockers: [{kind: 'backup', name: 'gmod'}]},
  unreachable: {state: 'unreachable', busy: [], unknown: [], blockers: []},
};
const plan = {servers: [{name: 'gmod', text: 'LinuxGSM’s monitor starts it again (Autostart)'}], wait_hours: 24};
async function dialog(state, opts, postAnswer, planBody){
  doc.body.querySelectorAll('.rb-overlay').forEach(o => o.remove());   // one dialog at a time
  doc.ls = {};
  calls.length = 0; toasts.length = 0; refreshed.length = 0;
  answers = {['GET ' + P + '/players']: state === null ? [500, {}] : [200, census[state]],
             ['GET ' + P + '/reboot-plan?preview=1']: [200, planBody || plan],
             ['POST ' + P + '/reboot']: postAnswer || [202, {success: true, message: 'Rebooting vps'}]};
  window.rebootHost(7, 'vps', false, opts);
  await settle();
  return overlay();
}
(async () => {
  const out = {};
  let ov = await dialog('busy');
  const wrapped = el => el.querySelectorAll('button').every(b => b.className.split(/\s+/).includes('text-wrap'));
  out.busy = {buttons: buttons(ov), primary: (ov.querySelector('.btn-primary') || {}).textContent,
              text: ov.textContent, posted_before: posts('/reboot').length, wrapped: wrapped(ov)};
  press(ov, 'Wait: reboot when everyone has left'); await settle();
  out.busy.posted = posts('/reboot'); out.busy.closed = overlay() === null;
  out.busy.toasts = toasts.slice(); out.busy.refreshed = refreshed.slice();

  ov = await dialog('busy', {prefer: 'now'});
  out.prefer_now = {buttons: buttons(ov)};
  press(ov, 'Reboot now: disconnect them'); await settle();
  out.prefer_now.posted = posts('/reboot');

  ov = await dialog('unknown');
  out.unknown = {buttons: buttons(ov), text: ov.textContent};

  ov = await dialog('idle');
  out.idle = {buttons: buttons(ov), text: ov.textContent};
  press(ov, 'Reboot now'); await settle();
  out.idle.posted = posts('/reboot'); out.idle.closed = overlay() === null;

  ov = await dialog('blocked');
  out.blocked = {buttons: buttons(ov), text: ov.textContent, wrapped: wrapped(ov)};
  press(ov, 'Wait: reboot when it’s finished and everyone has left'); await settle();
  out.blocked.posted = posts('/reboot');

  ov = await dialog('unreachable');
  out.unreachable = {buttons: buttons(ov)};
  press(ov, 'Close'); await settle();
  out.unreachable.closed = overlay() === null; out.unreachable.posted = posts('/reboot').length;

  ov = await dialog(null);
  out.no_census = {buttons: buttons(ov), text: ov.textContent, posted: posts('/reboot').length};
  press(ov, 'Cancel'); await settle();
  out.no_census.closed = overlay() === null;

  // Someone joined between opening and pressing: the 409 re-renders the choice, nothing closes.
  ov = await dialog('idle', null, [409, {success: false, needs_choice: true, players: census.busy}]);
  press(ov, 'Reboot now'); await settle();
  out.joined = {open: overlay() !== null, buttons: buttons(overlay()), posted: posts('/reboot')};
  overlay().remove();

  ov = await dialog('idle', null, [409, {success: false, error: 'in_progress', message: 'vps is already being rebooted (stopping).'}]);
  press(ov, 'Reboot now'); await settle();
  const err = overlay() && overlay().querySelector('.rb-error');
  out.refused = {open: overlay() !== null, error: err ? err.textContent : null,
                 enabled: overlay().querySelectorAll('button').every(b => !b.disabled)};
  overlay().remove();

  ov = await dialog('busy', null, null, {servers: [], wait_hours: 0});
  out.no_limit = ov.textContent; overlay().remove();
  ov = await dialog('busy', null, null, {servers: [], wait_hours: 48});
  out.limit = ov.textContent;
  doc.fire('keydown', {key: 'Escape'}); await settle();
  out.escape_closed = overlay() === null;

  // The Power card's #power-state, from GET /reboot-plan.
  const box = doc.body.appendChild(new E('div')); box.setAttribute('id', 'power-state');
  window.rebootStateRefresh = realRefresh;
  const card = async st => {
    calls.length = 0;
    answers = {['GET ' + P + '/reboot-plan']: [200, st], ['POST ' + P + '/reboot-cancel']: [200, {success: true, message: 'Canceled'}]};
    window.rebootStateWatch(7, 'vps', false); await settle();
    return {text: box.textContent, buttons: buttons(box)};
  };
  const now = Date.now() / 1000;
  out.clock = {near: _rbClock(now + 60), far: _rbClock(now + 86400 * 1.5)};
  doc.documentElement = {lang: 'fr'};
  out.clock.far_fr = _rbClock(now + 86400 * 1.5);
  doc.documentElement = {lang: 'en'};
  out.clock.far_en = _rbClock(now + 86400 * 1.5);
  delete doc.documentElement;
  out.card_wait = await card({wait: {by: 'admin', since: now - 60, expires: now + 3600,
                                     waiting_on: {busy: [{name: 'gmod', players: 2}], unknown: []}}, job: null, rows: []});
  calls.length = 0; press(box, 'Cancel'); await settle();
  out.card_wait.cancel_posted = calls.filter(c => c.method === 'POST' && c.url === P + '/reboot-cancel').length;
  out.card_job = await card({wait: null, job: {phase: 'stopping', done: 2, total: 4, left: null, sent: null}, rows: []});
  out.card_warn = await card({wait: null, job: {phase: 'warning', done: null, total: null, left: 30, sent: null}, rows: []});
  out.card_sent = await card({wait: null, job: {phase: 'rebooting', done: null, total: null, left: null, sent: now}, rows: []});
  out.card_rows = await card({wait: null, job: null, rows: [{restore: 'done'}, {restore: 'pending'}]});
  out.card_idle = await card({wait: null, job: null, rows: [], last: {text: 'vps is back', ok: true}});

  // The banner.
  const nag = doc.body.appendChild(new E('div'));
  window.rebootNagRender(nag, 7, 'vps', {required: true, packages: ['libc6']});
  out.nag_required = buttons(nag);
  let opened = [];
  const realHost = window.rebootHost;
  window.rebootHost = (id, label, local, opts) => opened.push([id, opts && opts.prefer]);
  press(nag, 'Reboot now'); press(nag, 'Reboot when empty');
  out.nag_opened = opened;
  window.rebootHost = realHost;
  window.rebootNagRender(nag, 7, 'vps', {required: false, pending_empty: true});
  out.nag_wait = {text: nag.textContent, buttons: buttons(nag)};
  window.rebootNagRender(nag, 7, 'vps', {required: false, job: {phase: 'stopping', sent: null}});
  out.nag_job = {text: nag.textContent, buttons: buttons(nag)};
  window.rebootNagRender(nag, 7, 'vps', {required: false, job: {phase: 'rebooting', sent: now}});
  out.nag_sent = buttons(nag);
  window.rebootNagRender(nag, 7, 'the panel host', {required: true, packages: []});
  const ph = nag.querySelectorAll('strong').find(e => e.textContent === 'the panel host');
  window.rebootNagRender(nag, 7, 'vps', {required: true, packages: []});
  const nm = nag.querySelectorAll('strong').find(e => e.textContent === 'vps');
  out.nag_label = {phrase: ph ? ph.getAttribute('data-no-i18n') : 'missing', name: nm ? nm.getAttribute('data-no-i18n') : 'missing'};
  console.log(JSON.stringify(out));
  process.exit(0);                  // the Power card keeps a 10 s poll scheduled
})().catch(e => { console.log(JSON.stringify({error: String(e && e.stack || e)})); process.exit(0); });
'''


def _node_run41():
    """static/js/nags.js under _NODE41; None without node, else its JSON (or {"error": ...})."""
    node = _shutil41.which("node")
    if not node:
        return None
    harness = os.path.join(_TMP41, "nags-harness.js")
    with open(harness, "w", encoding="utf-8") as fh:
        fh.write(_NODE41)
    r = _run41([node, harness, os.path.join(_ROOT41, "static", "js", "nags.js")], timeout=60)
    try:
        return _json41.loads((r.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": (r.stdout + r.stderr)[-600:]}


_CHOICE41 = ["Wait: reboot when everyone has left", "Reboot now: disconnect them", "Cancel"]


def _dialog_checks41(out):
    busy, now = out.get("busy") or {}, out.get("prefer_now") or {}
    check("dialog: players on — Wait (the primary) / Reboot now / Cancel, and nothing is sent "
          "until one is pressed", _all41(busy.get("buttons") == _CHOICE41,
                                          busy.get("primary") == _CHOICE41[0],
                                          busy.get("posted_before") == 0), repr(busy))
    check("dialog: its buttons wrap their text (panel.css keeps .btn on one line, and the long labels "
          "overran a 375 px phone, in French by 125 px)",
          _all41(busy.get("wrapped") is True, (out.get("blocked") or {}).get("wrapped") is True),
          repr((busy.get("wrapped"), (out.get("blocked") or {}).get("wrapped"))))
    check("dialog: Wait sends mode when_empty, then closes, says so and refreshes the host's state",
          _all41(busy.get("posted") == [{"mode": "when_empty"}], busy.get("closed") is True,
                 busy.get("toasts") == [["Rebooting vps", "info"]], busy.get("refreshed") == [7]),
          repr(busy))
    check("dialog: opened from a 'Reboot now' button, Reboot now leads, and it sends mode now",
          _all41(now.get("buttons") == [_CHOICE41[1], _CHOICE41[0], _CHOICE41[2]],
                 now.get("posted") == [{"mode": "now"}]), repr(now))
    unk, nc = out.get("unknown") or {}, out.get("no_census") or {}
    check("dialog: a count that can't be read, or no census at all, is the same choice — never a "
          "plain Reboot now", _all41(unk.get("buttons") == _CHOICE41, nc.get("buttons") == _CHOICE41,
                                    "can’t be read" in unk.get("text", ""),
                                    "could not check" in nc.get("text", ""), nc.get("posted") == 0),
          repr((unk, nc)))
    idle = out.get("idle") or {}
    check("dialog: nobody on — Reboot now / Cancel, and it sends mode now",
          _all41(idle.get("buttons") == ["Reboot now", "Cancel"], idle.get("posted") == [{"mode": "now"}],
                 idle.get("closed") is True), repr(idle))
    check("dialog: what comes back is the plan list's to say — no blanket 'they come back' (a setting "
          "keeps a server without Autostart stopped)",
          _all41("Running game servers are stopped cleanly first." in idle.get("text", ""),
                 "come back after the reboot" not in idle.get("text", ""),
                 "After the reboot:" in idle.get("text", "")), repr(idle.get("text")))
    blk, unr = out.get("blocked") or {}, out.get("unreachable") or {}
    check("dialog: work running — no Reboot now; Wait (when it's finished) sends when_empty",
          _all41(blk.get("buttons") == ["Wait: reboot when it’s finished and everyone has left", "Close"],
                 blk.get("posted") == [{"mode": "when_empty"}], "a backup is running" in blk.get("text", "")),
          repr(blk))
    check("dialog: a host that does not answer — Close only, nothing sent",
          _all41(unr.get("buttons") == ["Close"], unr.get("posted") == 0, unr.get("closed") is True),
          repr(unr))


def _dialog_answer_checks41(out):
    j, ref = out.get("joined") or {}, out.get("refused") or {}
    check("dialog: someone joined after it opened (409 needs_choice) — it stays open and offers the "
          "choice", _all41(j.get("open") is True, j.get("buttons") == _CHOICE41), repr(j))
    check("dialog: a refusal (409 in progress) is shown in the dialog, its buttons usable again",
          _all41(ref.get("open") is True, ref.get("error") == "vps is already being rebooted (stopping).",
                 ref.get("enabled") is True), repr(ref))
    check("dialog: the wait limit is the configured one (48 h), or 'no time limit' for 0",
          _all41("The wait gives up after 48 h" in out.get("limit", ""),
                 "The wait has no time limit." in out.get("no_limit", ""),
                 "24 h" not in out.get("limit", "")), repr((out.get("limit"), out.get("no_limit"))))
    check("dialog: Escape closes it", out.get("escape_closed") is True)


def _card_checks41(out):
    w, jb, sent = out.get("card_wait") or {}, out.get("card_job") or {}, out.get("card_sent") or {}
    check("Power card: a pending wait shows who it waits on, Reboot now instead and Cancel; Cancel "
          "POSTs reboot-cancel", _all41(w.get("buttons") == ["Reboot now instead", "Cancel"],
                                       "Waiting on:" in w.get("text", ""), "gmod" in w.get("text", ""),
                                       w.get("cancel_posted") == 1), repr(w))
    check("Power card: a job shows its phase and can be cancelled until the reboot is sent, not after",
          _all41(jb.get("buttons") == ["Cancel the reboot"], "Stopping game servers" in jb.get("text", ""),
                 sent.get("buttons") == [], "waiting for the host to come back" in sent.get("text", "")),
          repr((jb, sent)))
    warn = out.get("card_warn") or {}
    check("Power card: a job's numbers come as numbers (2/4 stopped, 30 s left) beside its translated "
          "phase — no English sentence from the server in an untranslated span",
          _all41("Stopping game servers…" in jb.get("text", ""), "2/4" in jb.get("text", ""),
                 "Warning players in-game…" in warn.get("text", ""), "30 s" in warn.get("text", "")),
          repr((jb, warn)))
    clock = out.get("clock") or {}
    check("Power card: a time that is not today carries its day (a 24 h wait gives up at the same "
          "clock time it was asked)", len(clock.get("far") or "") > len(clock.get("near") or "") + 4,
          repr(clock))
    check("Power card: ...in the page's language, not the browser's (English day names were on a "
          "Spanish page)", _all41(bool(clock.get("far_fr")), clock.get("far_fr") != clock.get("far_en")),
          repr(clock))
    check("Power card: a restore shows how many are back, and the last outcome once it is over",
          _all41((out.get("card_rows") or {}).get("text", "").startswith("Coming back: 1/2"),
                 (out.get("card_idle") or {}).get("text") == "vps is back"), repr(out.get("card_rows")))


def _banner_checks41(out):
    check("banner: a host that needs a reboot offers Reboot now and Reboot when empty, each opening "
          "the dialog with that choice first",
          _all41(out.get("nag_required") == ["Reboot now", "Reboot when empty"],
                 out.get("nag_opened") == [[7, "now"], [7, "when_empty"]]), repr(out.get("nag_opened")))
    lbl = out.get("nag_label") or {}
    check("banner: 'the panel host' is a phrase the page translates (es/fr have it); a host's own "
          "name is never handed to the translator", (lbl.get("phrase"), lbl.get("name")) == (None, ""),
          repr(lbl))
    check("banner: it stays while a wait or a job is under way, with Cancel (not once the reboot "
          "is sent)", _all41((out.get("nag_wait") or {}).get("buttons") == ["Reboot now instead", "Cancel"],
                             (out.get("nag_job") or {}).get("buttons") == ["Cancel"],
                             out.get("nag_sent") == []), repr(out))


def _power_card_copy41():
    with open(os.path.join(_ROOT41, "templates", "remote_manage.html"), encoding="utf-8") as fh:
        src = fh.read()
    card = src[src.index('id="sec-power"'):src.index('id="power-state"')]
    check("Power card: its help text promises no blanket 'they come back' on either host — it points "
          "at the dialog's list", _all41(card.count("the reboot dialog lists which come back after it") == 2,
                                         "come back after the reboot" not in card), card[:600])


def _page_checks41():
    _power_card_copy41()
    out = _node_run41()
    if out is None:
        skip("reboot dialog (node)", "node is not installed here")
        return
    check("reboot dialog (node): the harness ran", "error" not in out, repr(out)[:600])
    if "error" in out:
        return
    _dialog_checks41(out)
    _dialog_answer_checks41(out)
    _card_checks41(out)
    _banner_checks41(out)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# X. "Is apt running?" on a remote: the REAL rendering, a sudo that forks and waits, the real pgrep
# ════════════════════════════════════════════════════════════════════════════════════════════════
# sudo(8) with pam_session (Ubuntu's default) forks the command and the main sudo process WAITS, so
# a `pgrep -f <pattern>` run under `sudo bash -c` sees that sudo's own command line, which holds the
# pattern. This stand-in sudo does exactly that. The pgrep shim keeps the REAL pgrep to this check's
# own session (setsid), so an apt-get running elsewhere on the machine cannot change the answer.
_FORK_SUDO41 = '#!/bin/bash\n"$@"\nexit $?\n'
_FAKE_APT41 = '#!/bin/bash\nsleep 30 & c=$!\ntrap \'kill $c; exit 0\' TERM\nwait $c\n'
_APT_DRIVER41 = r'''#!/bin/bash
# <with|without> <file holding the command the remote's login shell is given> <dir of a fake apt-get>
bg=""
if [ "$1" = with ]; then "$3/apt-get" upgrade -y & bg=$!; sleep 0.3; fi
bash -c "$(cat "$2")"; rc=$?
[ -n "$bg" ] && kill "$bg" 2>/dev/null
echo "RC=$rc"
'''


def _apt_capture41(auth, verb):
    """The command line a remote's login shell is given for `verb`, over the REAL transport."""
    _fresh41()
    r, _h = _remote41("apt", auth=auth)
    got = []

    def _exec(_client, full_cmd, *_a, **_k):
        got.append(full_cmd)
        raise RuntimeError("captured")

    def _popen(argv, **_kw):
        got.append(argv[-1])
        raise RuntimeError("captured")
    _patch(_core41, "_run_via_paramiko", _REAL_PARAMIKO41)
    _patch(_core41, "_run_via_ssh_cli", _REAL_SSHCLI41)
    _patch(_core41, "get_connection", lambda server, **_k: NS())
    _patch(_core41, "exec_bounded", _exec)
    _patch(_core41, "subprocess", NS(Popen=_popen, PIPE=-1, DEVNULL=-3))
    _patch(_core41, "_ssh_mux_opts", lambda: [])
    try:
        _sm41.run_privileged(r, verb, [], timeout=10, merge_stderr=False)
    except ConnectionError:
        pass                      # paramiko's: the capture raised inside the exec
    return got[-1] if got else None


def _apt_rc41(remote_cmd, mode):
    """The exit status `remote_cmd` gives on a host with (`with`) or without a real apt-get running."""
    d = _tf41.mkdtemp(prefix="aptrun-", dir=_TMP41)
    shim, fake = os.path.join(d, "bin"), os.path.join(d, "fake")
    os.makedirs(shim)
    os.makedirs(fake)
    _write_exec41(os.path.join(shim, "sudo"), _FORK_SUDO41)
    _write_exec41(os.path.join(shim, "pgrep"), '#!/bin/bash\nexec %s -s 0 "$@"\n'
                  % _shlex41.quote(_shutil41.which("pgrep")))
    _write_exec41(os.path.join(fake, "apt-get"), _FAKE_APT41)
    _write_exec41(os.path.join(d, "drive"), _APT_DRIVER41)
    with open(os.path.join(d, "cmd"), "w", encoding="utf-8") as fh:
        fh.write(remote_cmd)
    p = _run41(["setsid", "-w", "bash", os.path.join(d, "drive"), mode, os.path.join(d, "cmd"), fake],
               env={"PATH": shim + ":/usr/bin:/bin", "LC_ALL": "C"}, timeout=30)
    rcs = [ln[3:] for ln in p.stdout.splitlines() if ln.startswith("RC=")]
    return rcs[-1] if rcs else "no answer: %r" % (p.stdout + p.stderr)[-200:]


def _apt_checks41():
    if not (_shutil41.which("setsid") and _shutil41.which("pgrep")):
        skip("apt probe through a forking sudo", "setsid or pgrep is not installed here")
        return
    for auth in ("key", "tailscale"):
        for verb in ("apt-any-running", "apt-upgrade-running"):
            cmd = _apt_capture41(auth, verb)
            got = (_apt_rc41(cmd, "without"), _apt_rc41(cmd, "with")) if cmd else (None, None)
            check("apt probe (%s, %s): the REAL remote command, run by a login shell through a sudo "
                  "that forks and waits (as sudo does with pam_session), answers 1 with no apt-get "
                  "running — though that sudo's own command line is on the host — and 0 with one"
                  % (auth, verb), got == ("1", "0"), repr((got, cmd)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# Y. A Cancel is never followed by a reboot
# ════════════════════════════════════════════════════════════════════════════════════════════════
_OPS41 = NS(id=None, username="ops")


def _rescan_cancel41(woken):
    """Reboot now, cancelled while the re-scan reads the host (with `woken` a server it would re-stop)."""
    with _patched():
        return _rescan_cancel_run41(woken)


def _rescan_cancel_run41(woken):
    """_rescan_cancel41's body."""
    _fresh41()
    r, h, _rows = _std_host41()
    answers = []
    real_probe = HR._probe_rows
    real_run = _core41.run_as_game_user

    def _probe(remote, rows):
        if _sys_caller41() == "_rescan" and not answers:
            answers.append(HR.cancel(remote, _OPS41))
        return real_probe(remote, rows)

    def _wakes(server, user, action, timeout=30, selfname=None, **kw):
        out = real_run(server, user, action, timeout=timeout, selfname=selfname, **kw)
        if woken and (action, selfname) == ("stop", "fctrserver"):
            h.run(woken, True)         # a monitor run brought it back during the stops
        return out
    _patch(HR, "_probe_rows", _probe)
    _patch(_core41, "run_as_game_user", _wakes)
    _patch(HR, "STOP_WORKERS", 1)
    HR.request_reboot(r, "now", None, "web")
    return r, h, answers


def _sys_caller41():
    """The name of the function that called the caller (a stub's caller)."""
    return sys._getframe(2).f_code.co_name  # pylint: disable=protected-access


def _rescan_cancel_checks41():
    r, h, answers = _rescan_cancel41(woken=None)
    check("cancel during the re-scan: accepted ('Cancelling'), and then NO reboot — the job's send "
          "sees it — but a rollback and the 'did not happen (cancelled by ops)' notice",
          _all41([a[0] for a in answers] == [200], "Cancelling" in (answers[0][1]["message"] if answers else ""),
                 "reboot" not in _events41(h), not HR.plan_rows(r.id),
                 _noted41("did not happen (cancelled by ops)"),
                 not _bodies41("Rebooting vps")), repr((answers, _events41(h), _NOTES41)))
    _r, h, answers = _rescan_cancel41(woken="gmodserver")
    check("cancel during the re-scan: a server it found running again is not stopped after the "
          "cancel", _all41(bool(answers), _lines41(h, "stop gmodserver") == ["stop gmodserver starting_lock=0"],
                           "reboot" not in _events41(h)), repr(h.events()))


def _fired_wait41(where):
    """A wait whose job is cancelled in its census (a player is back) or at its preflight (refused)."""
    with _patched():                          # its stubs end here: the passes after it are real
        return _fired_wait_run41(where)


def _fired_wait_run41(where):
    """_fired_wait41's body."""
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": 2})
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    _wpass41()
    h.players.update({"gmodserver": 0})
    answers = []
    real_census, real_pre = HR.host_player_state, HR.preflight

    def _census(remote, probes=None):
        if where == "census" and HR.job_of(remote.id) and not answers:
            h.players.update({"gmodserver": 2})          # the player came back
            answers.append(HR.cancel(remote, _OPS41))
        return real_census(remote, probes)

    def _pre(remote, census=None):
        if where == "preflight" and HR.job_of(remote.id) and not answers:
            answers.append(HR.cancel(remote, _OPS41))
            return False, "vps did not answer the boot check."
        return real_pre(remote, census)
    _patch(HR, "host_player_state", _census)
    _patch(HR, "preflight", _pre)
    _wpass41()
    return r, h, answers


def _fired_wait_cancel_checks41():
    for where, what in (("census", "its census (players back)"), ("preflight", "a preflight refusal")):
        r, h, answers = _fired_wait41(where)
        cancelled = _audit41("reboot_when_empty_cancel")
        h.players.update({"gmodserver": 0})
        for _i in range(3):
            _CLOCK41.sleep(700)
            _wpass41()
        check("wait: cancelled while its job ran %s — the Cancel was accepted, the wait is NOT put "
              "back, the cancel is audited, and the host is never rebooted once it empties" % what,
              _all41([a[0] for a in answers] == [200], _wait_entry41(r.id) is None,
                     len(cancelled) == 1, "reboot" not in _events41(h),
                     not _events41(h, ("stop", "disarm"))),
              repr((answers, cancelled, _events41(h))))


def _fire_race41():
    """A Cancel exactly when the wait is handed to its job: the hand-over is one step."""
    _fresh41()
    r, h, _rows = _std_host41()
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    answers, real_uuid, rid = [], HR.uuid, r.id

    def _cancel_now():
        with _app41.test_request_context():
            answers.append(HR.cancel(db.session.get(RemoteServer, rid), _OPS41))
            db.session.remove()

    def _uuid4():
        t = _th41.Thread(target=_cancel_now)
        t.start()
        _join41(t, 2)
        return real_uuid.uuid4()
    _patch(HR, "uuid", NS(uuid4=_uuid4))
    _wpass41()
    _patch(HR, "uuid", real_uuid)
    _CLOCK41.sleep(5)
    msgs = [a[1].get("message") for a in answers]
    check("wait: a Cancel at the moment the wait becomes a job finds the wait (and nothing runs), "
          "never 'Nothing was scheduled' followed by a reboot",
          _all41(msgs == ["Auto-reboot canceled."], "reboot" not in _events41(h),
                 not _events41(h, ("stop", "disarm")), HR.job_of(r.id) is None),
          repr((msgs, _events41(h))))


def _join41(t, timeout):
    """Thread.join with a timeout, under eventlet too: its green join RAISES its Timeout instead."""
    try:
        t.join(timeout)
    except BaseException as exc:  # noqa: BLE001 - eventlet.timeout.Timeout is not an Exception
        if type(exc).__name__ != "Timeout":
            raise


def _census_cancel_checks41():
    """Reboot now (nobody on), cancelled while the job reads the host: nothing is moved at all."""
    _fresh41()
    r, h, _rows = _std_host41()
    answers = []
    real = HR.host_player_state

    def _census(remote, probes=None):
        c = real(remote, probes)
        if HR.job_of(remote.id) and not answers:
            answers.append(HR.cancel(remote, _OPS41))
        return c
    _patch(HR, "host_player_state", _census)
    HR.request_reboot(r, "now", None, "web")
    check("cancel while the job reads the host (no countdown to catch it): no lock is moved and "
          "nothing stopped — the plan is never made — and the operator is told nothing had been stopped",
          _all41(bool(answers), not _events41(h, ("disarm", "stop", "reboot", "rearm")),
                 _noted41("nothing had been stopped yet")), repr((answers, _events41(h), _NOTES41)))


def _bounce_cancel41(when):
    """A wait's job bounces; the operator cancels `before` the bounce's rollback or `after` it."""
    with _patched():                          # each variant's stubs end with it
        return _bounce_cancel_run41(when)


def _bounce_cancel_run41(when):
    """_bounce_cancel41's body (`first`: the very first server bounces, before any stop)."""
    _fresh41()
    r, h, _rows = _std_host41()
    seen = {"n": 0, "stopping": when == "first"}
    _bounce_stubs41(seen)
    if when == "first":
        # Someone is on every server once the stop phase has begun: the first one bounces.
        _patch(_mon41, "_server_slots", lambda gs, allow_console=False, primary=None:
               (1 if (HR.job_of(r.id) or {}).get("total") is not None else 0, 16, None))
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    real_slots, real_rollback = _mon41._server_slots, HR.rollback
    if when == "before":
        def _slots(gs, allow_console=False, primary=None):
            out = real_slots(gs, allow_console=allow_console, primary=primary)
            if out[0] and HR.job_of(r.id):
                HR.cancel(r, _OPS41)          # the join, and the Cancel, in the same moment
            return out
        _patch(_mon41, "_server_slots", _slots)
    else:
        def _rollback(remote_id, reason, wait=75, quiet=False):
            real_rollback(remote_id, reason, wait=wait, quiet=quiet)
            HR.cancel(r, _OPS41)              # just after the bounce undid the stops
        _patch(HR, "rollback", _rollback)
    _wpass41()
    told = [b for b in _bodies41(key="host_reboot") if "ops" in b]
    return r, h, told


def _bounce_cancel_checks41():
    r, h, told = _bounce_cancel41("before")
    check("bounce + Cancel before its rollback: the rollback is the operator's — ONE notice that the "
          "reboot did not happen (cancelled by ops) — and the wait is not put back",
          _all41(len(told) == 1, "did not happen (cancelled by ops)" in "".join(told),
                 _wait_entry41(r.id) is None, "reboot" not in _events41(h)), repr((told, _NOTES41)))
    r, h, told = _bounce_cancel41("first")
    check("bounce on the very first server + Cancel after its rollback: nothing had been stopped, and "
          "the notice says so — not 'the 0 game servers it had stopped'",
          _all41(len(told) == 1, "nothing had been stopped yet" in "".join(told), not _lines41(h, "stop ")),
          repr((told, h.events())))
    r, h, told = _bounce_cancel41("after")
    check("bounce + Cancel just after its (quiet) rollback: ONE notice that the reboot was cancelled "
          "and the stopped servers are coming back — not 'nothing had been stopped' — and the wait "
          "is not put back",
          _all41(len(told) == 1, "The 2 game servers it had stopped are being brought back" in "".join(told),
                 _wait_entry41(r.id) is None,
                 "nothing had been stopped" not in "".join(told)), repr((told, _NOTES41)))


def _lock_order41():
    """cancel() racing the job putting its wait back: a real job, a real put-back, two threads."""
    _fresh41()
    r, _h, _rows = _std_host41()
    rid, info = r.id, {"by": "admin", "since": _CLOCK41.time(), "origin": "web", "expires": None}
    job = {"phase": "preflight", "mode": "when_empty", "sent": None, "cancel": None, "by": "admin"}
    with _ps41._hr_lock:
        _ps41._host_reboots[rid] = job
    runner = HR._Job(_app41, r, job, "admin", info)
    put_back = []

    def _job_puts_back():
        try:
            runner._back_to_waiting(None, bounce=False)  # pylint: disable=protected-access
            put_back.append("back")
        except HR._Cancelled:  # pylint: disable=protected-access
            put_back.append("cancelled")
        with _ps41._hr_lock:
            if _ps41._host_reboots.get(rid) is job:
                _ps41._host_reboots.pop(rid, None)   # what run()'s finally does as the job ends

    class _HookedLock:
        """_rwe_lock, which starts the job's put-back as cancel() lets go of it."""

        def __init__(self, lock):
            self.lock, self.fired = lock, False

        def __enter__(self):
            return self.lock.__enter__()

        def __exit__(self, *exc):
            out = self.lock.__exit__(*exc)
            if not self.fired and _th41.current_thread().name == "p41-cancel":
                self.fired = True
                t = _th41.Thread(target=_job_puts_back)
                t.start()
                _join41(t, 1.0)        # it runs to its end now unless cancel() still holds _hr_lock
                self.thread = t
            return out
    hooked = _HookedLock(_ps41._rwe_lock)
    _patch(HR, "_rwe_lock", hooked)
    answers = []

    def _cancel():
        try:
            with _app41.test_request_context():
                answers.append(HR.cancel(db.session.get(RemoteServer, rid), _OPS41))
                db.session.remove()
        except Exception as exc:  # noqa: BLE001 - shown by the check
            answers.append((0, {"message": "raised %r" % exc}))
    t = _th41.Thread(target=_cancel, name="p41-cancel")
    t.start()
    _join41(t, 10)
    _join41(getattr(hooked, "thread", t), 10)
    return answers, put_back, _wait_entry41(rid)


def _lock_order_checks41():
    answers, put_back, left = _lock_order41()
    msgs = [a[1].get("message", "") for a in answers]
    check("cancel(): it holds _hr_lock across reading the wait AND the job, so a job putting its wait "
          "back cannot slip between them — the Cancel finds the job (and the put-back sees it), never "
          "'Nothing was scheduled' with the wait back in place",
          _all41(len(msgs) == 1, msgs[0].startswith("Cancelling") if msgs else False,
                 put_back == ["cancelled"], left is None), repr((msgs, put_back, left)))


def _job_numbers_checks41():
    _fresh41()
    r, _h, _rows = _std_host41()
    seen = []
    real = _core41.run_as_game_user

    def _peek(server, user, action, timeout=30, selfname=None, **kw):
        if action == "stop":
            seen.append(dict(HR.job_of(r.id) or {}))
        return real(server, user, action, timeout=timeout, selfname=selfname, **kw)
    _patch(_core41, "run_as_game_user", _peek)
    _patch(HR, "STOP_WORKERS", 1)
    HR.request_reboot(r, "now", None, "web")
    got = [(j.get("phase"), j.get("done"), j.get("total")) for j in seen]
    check("job state: the stop phase carries its progress as numbers (done/total), and no English "
          "sentence for the page to show untranslated",
          _all41(got == [("stopping", 0, 3), ("stopping", 1, 3), ("stopping", 2, 3)],
                 not any("msg" in j for j in seen)), repr(seen))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# Z. A wait that goes back, a wait that cannot succeed, and what a restart says about them
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _restart_drops41(rid):
    """The panel restarted: the waits in memory are gone; what does the restart announce?"""
    with _ps41._rwe_lock:
        _ps41._reboot_when_empty.clear()
    del _NOTES41[:]
    HR.announce_dropped_waits(_app41)
    return [b for b in _bodies41("Reboot wait cancelled")], _wait_entry41(rid)


def _back_to_waiting_restart41():
    # A bounce: its fire was audited, then it went back to waiting.
    _fresh41()
    r, _h, _rows = _std_host41()
    _bounce_stubs41({"n": 0, "stopping": False})
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    _wpass41()
    bounced = (_wait_entry41(r.id) or {}).get("bounces")
    told, _w = _restart_drops41(r.id)
    check("restart: a wait that went back to waiting after a bounce is announced as dropped",
          _all41(bounced == 1, len(told) == 1, "vps" in "".join(told)), repr((bounced, _NOTES41, _audit41())))


def _busy_at_job_restart41():
    """The job's own census saw players: the wait went back without a fire ever being audited."""
    _fresh41()
    r, h, _rows = _std_host41()
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    real = HR.host_player_state
    in_job = []

    def _busy_in_job(remote, probes=None):
        if HR.job_of(remote.id):
            in_job.append(1)
        h.players.update({"gmodserver": 2 if HR.job_of(remote.id) else 0})
        return real(remote, probes)
    _patch(HR, "host_player_state", _busy_in_job)
    _wpass41()
    back = _wait_entry41(r.id) is not None
    fires, auto = _actions41("reboot_when_empty_fire"), _bodies41(key="auto_reboot")
    told, _w = _restart_drops41(r.id)
    check("restart: a wait whose job ran, found players and went back is announced as dropped, and "
          "no fire was audited (nor 'auto-rebooting' sent) for a reboot that never started",
          _all41(in_job == [1], back, fires == [], not auto, len(told) == 1),
          repr((in_job, back, fires, auto, _audit41(), _NOTES41)))


def _refused_wait41():
    """A wait armed while the host could reboot, whose job then cannot (sudo stops working)."""
    _fresh41()
    r, h, _rows = _std_host41()
    asked = []
    real = HR.escalation
    _patch(HR, "escalation", lambda remote: (asked.append(1), real(remote))[1])
    code, _body = HR.request_reboot(r, "when_empty", _WAITER41, "web")
    h.root_refused = True
    for _i in range(30):
        _wpass41()
        _CLOCK41.sleep(60)
    return r, h, code, len(asked)


def _refused_wait_checks41():
    r, h, code, asked = _refused_wait41()
    could = [b for b in _bodies41("Host reboot still waiting") if "could not run" in b]
    check("wait refused at its job (sudo stopped working): over 30 min, ONE notice that it could "
          "not run, no 'auto-rebooting' notice and no fire audited, the wait kept, and its job "
          "retried every 10 min — not every minute",
          _all41(code == 200, len(could) == 1, "sudo is refused" in "".join(could),
                 not _bodies41(key="auto_reboot"), _actions41("reboot_when_empty_fire") == [],
                 _wait_entry41(r.id) is not None, "reboot" not in _events41(h), asked <= 4),
          repr((code, asked, _NOTES41)))
    _fresh41()
    r, h, _rows = _std_host41()
    h.root_refused = True
    code, body = HR.request_reboot(r, "when_empty", _WAITER41, "web")
    check("wait: one that could never reboot the host (sudo refused) is refused when it is asked "
          "for (409), not armed for 24 h of retries",
          _all41(code == 409, body.get("error") == "preflight", "sudo is refused" in body.get("message", ""),
                 _wait_entry41(r.id) is None, _actions41("reboot_when_empty_arm") == []), repr((code, body)))
    for auth, silent in (("tailscale", -1), ("tailscale", 255), ("key", "raise")):
        _fresh41()
        r, h, _rows = _std_host41(auth=auth)
        h.sudo_silent = silent
        code, body = HR.request_reboot(r, "now", None, "web")
        check("preflight: a host whose sudo check got no answer (%s %s: a timeout, ssh unable to "
              "connect, paramiko raising) is 'did not answer' — not 'sudo is refused'" % (auth, silent),
              _all41(code == 409, "did not answer" in body.get("message", ""),
                     "sudo is refused" not in body.get("message", "")), repr((code, body)))


def _arm_race_checks41():
    """A second 'when empty' request that saw the wait armed, then lost it to a Cancel."""
    _fresh41()
    r, h, _rows = _std_host41()
    HR.request_reboot(r, "when_empty", _WAITER41, "web")
    real_hours = HR.wait_max_hours
    raced = []

    def _hours():
        if not raced:
            raced.append(HR.cancel(r, _OPS41))     # between its look and its write
        return real_hours()
    _patch(HR, "wait_max_hours", _hours)
    code, _body = HR.request_reboot(r, "when_empty", _WAITER41, "web")
    w = _wait_entry41(r.id) or {}
    check("wait: a request that saw the wait armed and then lost it to a Cancel arms a new one only "
          "after the host's checks (its boot is recorded), never blind",
          _all41(code == 200, bool(raced), w.get("boot") == h.boot,
                 _actions41("reboot_when_empty_arm") == ["reboot_when_empty_arm"] * 2), repr((code, w, raced)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# AA. The window, where the job calls it, and the in-flight read of every plan server
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _armed_at41(start_sec, stop_running=()):
    """Reboot now from second `start_sec` of the minute: [(event, second)] of the re-arms and reboot."""
    _fresh41()
    r, h, _rows = _std_host41()
    for s_ in stop_running:
        h.run(s_, False)
    _CLOCK41.t = 1791000000.0 + start_sec
    HR.request_reboot(r, "now", None, "web")
    return h, [(e, sec) for hn, e, sec in _STAMPS41 if hn == h.name and e in ("rearm", "reboot")]


def _window_job_checks41():
    hi = 40 - 2 * 2                      # two accounts' locks go back: gmodserver and fctrserver
    for start in (45, 3):
        _h, got = _armed_at41(start)
        check("window (job, from second %d): the locks go back, and the reboot is sent, only at a "
              "second of the minute in [10, %d] — never where a */5 monitor run could read them"
              % (start, hi), _all41(bool(got), [e for e, _s in got].count("reboot") == 1,
                                    all(10 <= sec <= hi for _e, sec in got)), repr(got))
    for start in (55, 0):
        _h, got = _armed_at41(start, stop_running=("gmodserver", "fctrserver"))
        check("window (job, only a panel-started server, from second %d): no lock goes back, and the "
              "reboot still waits for a read in [2, 50] of the minute it is sent in, which sees "
              "whatever cron started at :00" % start,
              _all41([e for e, _s in got] == ["reboot"], all(2 <= sec <= 50 for _e, sec in got)), repr(got))


def _inflight_panel_owned_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    for s_ in ("gmodserver", "fctrserver"):
        h.run(s_, False)                 # only mc runs: no Autostart, nothing to put back
    real_census, real_send, real_sleep = HR.host_player_state, HR.send_reboot, _CLOCK41.sleep
    marks = {}

    def _update_starts(remote, probes=None):
        c = real_census(remote, probes)
        h.setn("inflight", "mcserver", 1)      # a cron'd update starts on it after the census...
        marks["census"] = _CLOCK41.time()
        return c

    def _sleep(sec):
        real_sleep(sec)
        if "census" in marks and _CLOCK41.time() - marks["census"] >= 100:
            h.setn("inflight", "mcserver", 0)  # ...and ends 100 s later
    _patch(HR, "host_player_state", _update_starts)
    _patch(HR, "send_reboot", lambda remote: (marks.setdefault("sent", _CLOCK41.time()), real_send(remote))[1])
    _patch(_CLOCK41, "sleep", _sleep)
    HR.request_reboot(r, "now", None, "web")
    _patch(_CLOCK41, "sleep", real_sleep)
    check("window: a LinuxGSM command in flight on a server the PANEL brings back (no lock to put "
          "back at all) holds the reboot too — it is sent only once the command has ended",
          _all41(_trace41().count("reboot") == 1, marks.get("sent", 0) - marks.get("census", 0) >= 100),
          repr(marks))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# AB. A rollback of a server the plan keeps stopped; the warning; the re-scan's budget
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _none_rollback_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    _patch(HR, "restore_no_autostart", lambda: False)        # mc: no Autostart, not restored
    before = _lockfile41(h, "mcserver")
    real = _core41.run_as_game_user

    def _cancel_after_first(server, user, action, timeout=30, selfname=None, **kw):
        out = real(server, user, action, timeout=timeout, selfname=selfname, **kw)
        if action == "stop":
            HR.cancel(r, _OPS41)
        return out
    _patch(_core41, "run_as_game_user", _cancel_after_first)
    _patch(HR, "STOP_WORKERS", 1)
    HR.request_reboot(r, "now", None, "web")
    summary = "".join(_bodies41("Host reboot"))
    check("rollback: a server the plan would keep stopped, but whose stop never ran, is still "
          "running with ITS lock back (the same file) — and the summary says it kept running, not "
          "that it 'stayed stopped'",
          _all41(h.running("mcserver"), _lockfile41(h, "mcserver") == before,
                 not _lines41(h, "stop mcserver"), "2 kept running" in summary,
                 "stayed stopped" not in summary, "1 server coming back" in summary),
          repr((h.events(), summary)))


def _unknown_warning_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"gmodserver": None, "fctrserver": 0, "mcserver": 0})
    t0 = _CLOCK41.time()
    stamps = {}
    _stamp_stops41(stamps)
    HR.request_reboot(r, "now", None, "web")
    says = _lines41(h, "say gmodserver")
    check("countdown: a server whose count can't be read may have players on it — on a game that "
          "can show a message it is warned too, and the stops wait the minute",
          _all41(len(says) == 3, stamps.get("stop", 0) - t0 >= 60), repr((says, stamps)))
    _fresh41()
    r, h, _rows = _std_host41()
    h.players.update({"fctrserver": 2})
    t0 = _CLOCK41.time()
    stamps = {}
    _stamp_stops41(stamps)
    HR.request_reboot(r, "now", None, "web")
    check("countdown: players only on a game with no console message — nothing to warn, so no "
          "minute's wait either (they stop normally)",
          _all41(not _lines41(h, "say "), stamps.get("stop", t0 + 99) - t0 < 60), repr(stamps))


def _warning_text_checks41():
    _fresh41()
    r, h, rows = _std_host41()
    rows["mc"].stop_pending = True                 # a queued stop: it does not come back
    db.session.commit()
    h.players.update({"gmodserver": 1, "mcserver": 1})
    _code, body = HR.request_reboot(r, "now", None, "web")
    gm, mc = _lines41(h, "say gmodserver"), _lines41(h, "say mcserver")
    check("countdown: 'It will be back in a few minutes' only on a server that comes back — not on "
          "one a queued stop keeps stopped",
          _all41(len(gm) == 3, len(mc) == 3, all("will be back" in ln for ln in gm),
                 not any("will be back" in ln for ln in mc)), repr((gm, mc)))
    check("countdown: the answer to the request says the warning is in-game only where the game "
          "can show one", "whose game can show one" in body.get("message", ""),
          repr(body))


def _local_warning_text_checks41():
    """On the panel's own host, when the panel does not start at boot, the servers it starts don't."""
    _fresh41()
    r, h, _rows = _std_host41(local=True)
    _patch(_so41, "panel_starts_at_boot", lambda: False)
    h.players.update({"gmodserver": 1, "mcserver": 1})
    HR.request_reboot(r, "now", None, "web")
    gm, mc = _lines41(h, "say gmodserver"), _lines41(h, "say mcserver")
    check("countdown (panel host, the panel not started at boot): 'back in a few minutes' on the "
          "Autostart server, not on the one the panel would start",
          _all41(len(gm) == 3, len(mc) == 3, all("will be back" in ln for ln in gm),
                 not any("will be back" in ln for ln in mc)), repr((gm, mc)))


def _rescan_budget_checks41():
    _fresh41()
    r, h, _rows = _std_host41()
    real = _core41.run_as_game_user

    def _slow_stop(server, user, action, timeout=30, selfname=None, **kw):
        if action == "stop":
            _CLOCK41.sleep(400)             # each stop runs long
        out = real(server, user, action, timeout=timeout, selfname=selfname, **kw)
        if (action, selfname) == ("stop", "fctrserver"):
            h.run("codserver", True)        # and something starts another server meanwhile
        return out
    _patch(_core41, "run_as_game_user", _slow_stop)
    _patch(HR, "STOP_WORKERS", 1)
    HR.request_reboot(r, "now", None, "web")
    rec = _rr41(_rows["cod"].id) or {}
    check("re-scan: past the stop phase's 15-min budget, a server found running is not stopped "
          "again — recorded as still running (the shutdown ends it) and still in the plan",
          _all41(not _lines41(h, "stop codserver"), (rec.get("owner"), rec.get("stop")) == ("panel", "still_running"),
                 _trace41().count("reboot") == 1), repr((h.events(), rec)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# AC. The reboot command's connection; the panel's own account
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _paramiko_drop41(fail_at):
    """The REAL paramiko transport, failing at `fail_at` ('connect' or 'exec'): what it raises."""
    _fresh41()
    r, _h = _remote41("drop", auth="key")

    def _conn(server, **_k):
        if fail_at == "connect":
            raise ConnectionRefusedError(111, "Connection refused")
        return NS()

    def _exec(*_a, **_k):
        raise EOFError("the session closed")
    _patch(_core41, "get_connection", _conn)
    _patch(_core41, "exec_bounded", _exec)
    try:
        _REAL_PARAMIKO41(r, "true", 10, True, None)
    except Exception as exc:  # noqa: BLE001 - the check is which one
        return exc
    return None


def _connect_fail_checks41():
    on_exec, on_connect = _paramiko_drop41("exec"), _paramiko_drop41("connect")
    check("paramiko: a command that fails once the connection is open raises a ConnectionError marked "
          "command_started (its type unchanged for every caller and message); one that never "
          "connected is not marked",
          _all41(type(on_exec) is ConnectionError, getattr(on_exec, "command_started", False) is True,
                 not getattr(on_connect, "command_started", False)), repr((on_exec, on_connect)))
    _fresh41()
    r, _h, _rows = _std_host41(auth="key")
    real = _core41.run_privileged

    def _no_connect(server, verb, args=(), **kw):
        if verb == "reboot-delayed":
            raise ConnectionRefusedError(111, "Connection refused")
        return real(server, verb, args, **kw)
    _patch(_core41, "run_privileged", _no_connect)
    t0 = _CLOCK41.time()
    HR.request_reboot(r, "now", None, "web")
    check("send: a reboot whose connection never opened sent nothing — rolled back at once (not 5 "
          "min later as 'did not happen' on the same boot), saying it could not connect",
          _all41(not HR.plan_rows(r.id), _CLOCK41.time() - t0 < 300,
                 _noted41("could not connect to send the reboot"), HR.job_of(r.id) is None),
          repr((_CLOCK41.time() - t0, _NOTES41)))


def _own_account_checks41():
    _fresh41()
    r, h = _remote41("panel", local=True)
    h.own, h.no_sudo_self = "panelacct", True
    h.add("panelacct", "gmodserver", running=True, lock="monitoring", autostart=True)
    gs = _gs41(r, "panelacct", "gmod", 27015)
    _patch(HR, "_own_account", lambda: "panelacct")
    _patch(_core41, "helper_present", lambda recheck=False: True)
    before = _lockfile41(h, "gmodserver")
    HR.request_reboot(r, "now", None, "web")
    rec = _rr41(gs.id) or {}
    check("own account: a game the panel runs under its OWN account (where `sudo -u <itself>` is "
          "refused) is read and planned like any other — stopped through the helper, its lock put "
          "back, the reboot sent — not left unread for the shutdown to kill",
          _all41((rec.get("owner"), rec.get("stop")) == ("monitor", "stopped"),
                 "helper:stop" in _trace41(), _lockfile41(h, "gmodserver") == before,
                 _trace41().count("reboot") == 1), repr((rec, _trace41())))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# Run everything under one set of stubs, and put the world back afterwards.
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SECTIONS41 = [
    ("probe", _probe_checks41), ("transports", _transport_checks41),
    ("probe pattern", _probe_pattern_checks41), ("owners", _classify_checks41),
    ("gate", _gate_checks41),
    ("now over tailscale", lambda: _now_flow_checks41("tailscale")),
    ("now over paramiko", lambda: _now_flow_checks41("key")),
    ("stop", _stop_checks41), ("refusals", _refusal_checks41), ("window", _window_checks41),
    ("refused reboot", _refused_reboot_checks41), ("send", _send_reboot_checks41),
    ("same boot", _same_boot_checks41),
    ("stale plans", _stale_checks41), ("safe start", _safe_start_checks41),
    ("wait", _wait_checks41), ("wait edges", _wait_edges41), ("bounce", _bounce_checks41),
    ("countdown", _countdown_checks41), ("alerts", _suppression_checks41),
    ("gates", _gate_route_checks41), ("sweeps", _sweep_checks41), ("api route", _api_route_checks41),
    ("bots", _bot_checks41), ("panel host", _panel_host_checks41), ("per-user", _per_user_checks41),
    ("restore failures", _restore_failure_checks41), ("cancel", _cancel_checks41),
    ("preview", _preview_checks41), ("startup", _startup_checks41), ("migration", _migration_checks41),
    ("flush and identity", _flush_identity_checks41), ("helper", _helper_checks41),
    ("session probe", _session_probe_checks41), ("bootstrap run", _bootstrap_run_checks41),
    ("re-scan", _rescan_checks41), ("leftover lock", _leftover_checks41),
    ("queued stop", _stop_pending_checks41), ("idle host", _bare_job_checks41),
    ("idle host silent", _bare_silent_checks41),
    ("disarm fails", _disarm_fail_checks41), ("settings", _settings_checks41),
    ("page", _page_checks41), ("debug report", _debug_report_checks41),
    ("apt probe", _apt_checks41), ("cancel in the re-scan", _rescan_cancel_checks41),
    ("cancel a fired wait", _fired_wait_cancel_checks41), ("wait hand-over", _fire_race41),
    ("restart after a wait went back", _back_to_waiting_restart41),
    ("restart after a busy job", _busy_at_job_restart41),
    ("wait refused at its job", _refused_wait_checks41), ("wait armed in a race", _arm_race_checks41),
    ("window at the job", _window_job_checks41),
    ("in flight on a panel-started server", _inflight_panel_owned_checks41),
    ("rollback of an unstopped server", _none_rollback_checks41),
    ("warning an unknown count", _unknown_warning_checks41), ("warning text", _warning_text_checks41),
    ("warning text on the panel host", _local_warning_text_checks41),
    ("re-scan budget", _rescan_budget_checks41), ("send's connection", _connect_fail_checks41),
    ("the panel's own account", _own_account_checks41), ("cancel at the census", _census_cancel_checks41),
    ("bounce and cancel", _bounce_cancel_checks41), ("cancel's lock order", _lock_order_checks41),
    ("job numbers", _job_numbers_checks41),
]


def _run_sections41():
    """Every section under the stubs: a section that crashes is a FAILED check, never a skip."""
    import traceback
    for name, fn in _SECTIONS41:
        with _patched():
            _std_patches41()
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - reported by name below
                check("part41 section %r ran to its end" % name, False,
                      "%s: %s" % (type(exc).__name__, traceback.format_exc()[-1500:]))


try:
    _run_sections41()
finally:
    db.session.rollback()
    db.session.remove()
    _ctx41.pop()
    for _m41, _s41 in _pstate_snap41:
        _m41.clear()
        _m41.update(_s41)
    _shutil41.rmtree(_TMP41, ignore_errors=True)
