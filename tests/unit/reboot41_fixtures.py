"""Part 41's fixtures: the stand-in hosts, the clock and the stubs every section runs under.

Imported by part41 (the part, which runs the sections) and by its section modules; see part41's
docstring for how it all runs.
"""
import os
import shlex as _shlex41
import subprocess as _sp41  # nosec B404 - runs this part's own stand-in scripts under bash
import tempfile as _tf41
import threading as _th41
import uuid as _uuid41

from flask import Flask as _Flask41
from sqlalchemy import text as _sa_text41

from unit.part01 import check
from unit.part20 import _patch
from panel.core import panel_state as _ps41
from panel.db.models import AuditLog, GameServer, RemoteServer, db
from panel.ops import ssh_manager as _sm41
from panel.ops import system_ops as _so41
from panel.ops.ssh_manager import _core as _core41
from panel.ops.ssh_manager import cron as _cron41
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
    # A stand-in script in this part's own temp dir, which other accounts' stand-in runs execute.
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
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
# nosemgrep: python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_TESTING -- a throwaway app this test builds
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


