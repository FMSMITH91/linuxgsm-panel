"""Part 31 of the unit suite: game servers, and the helper's own jobs, kept out of the panel's cgroup.

Every LinuxGSM action the panel started on its own host forked from the panel, and nothing on the
way left its cgroup (sudo opens no session; setsid and tmux daemonising do not move a process). So
the game, its tmux server and LinuxGSM's console `cat` lived inside linuxgsm-panel.service, which
is KillMode=control-group: every panel stop, restart, crash and self-update signalled them — on a
system install it killed them silently. The same was true of the helper's "detached" jobs, three
of which stop that very unit, so a database repair, a restore or a self-update ended itself at its
first step and left the panel down.

What this part holds, and how each runs:
* the helper's lgsm-command and cron-run-now give the child a transient scope of its own, and the
  priority it should start at, BEFORE it drops to the game account (drop with initgroups kept).
  Run for real in a subprocess that forks, with busctl/ionice/the drop recorded to a shared log,
  so the ORDER across the two processes is what is asserted. The move is made to land late, as
  the real one does, so the helper's WAIT for it is asserted too (and its limit, and a host with
  no unified cgroup path, where nothing is scoped);
* adopt-game-processes and terminal-scope move only what is in the panel's own cgroup, never the
  panel itself, and a group systemd refused for one exited pid is retried: driven in-process on a
  fresh copy of the helper with /proc and cgroupfs readers stubbed (and cgroup.procs read from a
  hybrid boot's /sys/fs/cgroup/unified, on a stand-in tree);
* the four jobs start as the main process of their own transient service and run in its
  foreground (`--job`, refused anywhere else); the reboot is a transient timer, with the old
  grandchild when the timer cannot be made; no systemd (or no unified cgroup path) keeps the old
  double fork. In-process, with subprocess.run and os.fork replaced by recorders;
* the panel side: the LinuxGSM backup and "Run now" go through those verbs, a per-user install
  without the helper uses `systemd-run --user --scope`, the terminal's shell gets a scope, the
  adoption runs at panel start, a per-user restore no longer uses the helper's system-unit swap
  (and its own launch is checked), and the debug report names game processes in the panel's
  cgroup with the memory split;
* found beside them: an uninstall removes the account's crontab before the account (userdel -r
  leaves it behind, orphaned) — the verb, its refusal of the panel's own account, and an AST gate
  that every account-deleting function in manage_servers.py calls it first;
* a system uninstall stops the web terminal's scopes before it deletes the panel user: the
  function lifted out of uninstall.sh and run under bash with a stand-in systemctl.
Nothing here runs systemd-run, busctl, sudo or a real game; every privileged call is recorded.
"""
import ast as _ast31
import base64 as _b6431
import contextlib as _ctx31
import importlib.machinery as _mach31
import importlib.util as _ilu31
import json as _json31
import os
import shutil as _sh31
import subprocess as _sp31  # nosec B404 - runs this suite's own probe scripts, argv lists only
import sys as _sys31
import tempfile as _tf31
import threading as _thr31
import time as _time31
import types as _types31

from unit.part01 import check, eq
from unit.part05 import _helper_path, _root

import app as _app31
from panel.ops import backup as _bk31
from panel.ops import system_ops as _so31
from panel.ops import terminal_session as _ts31
from panel.ops.debug_report import _src_journal as _sj31
from panel.ops.debug_report import logs as _lg31
from panel.ops.debug_report import process as _pr31
from panel.ops.debug_report._base import Ctx as _Ctx31, Result as _Res31
from panel.ops.ssh_manager import _core as _smc31
from panel.ops.ssh_manager import cron as _smcron31
from panel.ops.ssh_manager import game as _smgame31
from panel.security import privileged as _priv31

_TMP31 = _tf31.mkdtemp(prefix="panel-part31-")


@_ctx31.contextmanager
def _swap31(owner, **attrs):
    """Set attributes on `owner` for the block, and put the old values back whatever happens."""
    saved = {k: getattr(owner, k) for k in attrs}
    try:
        for k, v in attrs.items():
            setattr(owner, k, v)
        yield owner
    finally:
        for k, v in saved.items():
            setattr(owner, k, v)


class _Proxy31(object):
    """A module stand-in: the named attributes overridden, everything else the real module's."""

    def __init__(self, real, **over):
        self._real = real
        self.__dict__.update(over)

    def __getattr__(self, name):
        return getattr(self._real, name)


class _Sink31(object):
    """A stdout/stderr stand-in that keeps what was written."""

    def __init__(self):
        self.text = ""

    def write(self, t):
        self.text += t

    def flush(self):
        return None


def _fresh_helper31():
    """A fresh copy of tools/panel-helper, so nothing here leaks into part05's module.

    Its stdout and stderr are sinks (mod.sys.stdout.text), never the suite's own.
    """
    spec = _ilu31.spec_from_loader("ph31", _mach31.SourceFileLoader("ph31", _helper_path))
    mod = _ilu31.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.SYSTEMD_BOOTED_DIR = _TMP31          # "booted with systemd", whatever runs the suite
    mod.resolve = lambda name: "/usr/bin/" + name
    mod.sys = _Proxy31(_sys31, stdout=_Sink31(), stderr=_Sink31())
    return mod


def _no_fork31():
    raise AssertionError("forked")


# ══ 1. lgsm-command and cron-run-now: scope + priority BEFORE the drop, for real ═══════════════════
# The probe forks for real. The helper's busctl/ionice calls, setpriority and _drop_to are
# recorders writing one JSON line each to a log both processes append to. The move is made to
# land LATE, as the real one does (StartTransientUnit returns once the job is queued; measured,
# the first read after it still showed the old cgroup): the probe's _cgroup_of answers the panel's
# cgroup for _LAND31 seconds after busctl returns, then the new scope, and logs "landed" the first
# time it does. So a child released before the move landed would log its drop BEFORE "landed",
# and a wait that gave up early, or never, would log nothing between. times.log has every event
# and every poll with its monotonic time, for the checks on HOW LONG it waited.
_LAND31, _WAIT31 = 0.25, 1.0
_PROBE31 = r'''
import importlib.util as u, importlib.machinery as m, json, os, sys, time, types
helper, work, mode, landing = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
land_after, wait = float(sys.argv[5]), float(sys.argv[6])
s = u.spec_from_loader("ph31p", m.SourceFileLoader("ph31p", helper))
mod = u.module_from_spec(s); s.loader.exec_module(mod)
LOG, TLOG = os.path.join(work, "events.log"), os.path.join(work, "times.log")
def put(path, parts):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    os.write(fd, (json.dumps(parts) + "\n").encode()); os.close(fd)
def ev(*parts):
    put(LOG, parts); put(TLOG, [parts[0], time.monotonic()])
home = os.path.join(work, "home")
pw = types.SimpleNamespace(pw_name="gm31", pw_dir=home, pw_uid=os.getuid(), pw_gid=os.getgid())
mod.pwd = types.SimpleNamespace(getpwnam=lambda n: pw, getpwuid=lambda u: pw)
mod.SYSTEMD_BOOTED_DIR, mod.SCOPE_WAIT_SECONDS = work, wait
mod.resolve = lambda name: "/usr/bin/" + name
PANEL, ME, moves, seen = "/system.slice/linuxgsm-panel.service", os.getpid(), {}, []
def run(argv, **kw):
    if argv[0].endswith("busctl"):
        ev("scope", os.getpid(), argv[7], argv[10:14])
        if landing == "land":
            moves[argv[7]] = time.monotonic() + land_after
    elif argv[0].endswith("ionice"):
        ev("ionice", os.getpid(), argv[1:])
    return types.SimpleNamespace(returncode=0)
def cgroup_of(pid):
    if pid == ME:
        return PANEL
    for unit, at in moves.items():
        if time.monotonic() >= at:
            if not seen:
                seen.append(pid); ev("landed", pid)
            return "/system.slice/" + unit
    put(TLOG, ["poll", time.monotonic()])
    return PANEL
mod.subprocess.run = run
mod._cgroup_of = cgroup_of
os.setpriority = lambda which, who, prio: ev("nice", who, prio)
mod._drop_to = lambda p, own_groups=False: (ev("drop", os.getpid(), own_groups), True)[1]
if mode.startswith("lgsm-"):
    rc = mod.do_lgsm_command(["gm31", "gmodserver", mode[5:], "-", "no"], "")
else:
    rc = mod.do_cron_run_now(["gm31", "abcdef012345", "ZWNobyBoaQ=="], "")
    time.sleep(0.5)
ev("rc", rc)
'''


def _probe31(mode, runner=True, landing="land"):
    """Run the probe in a fresh work dir; (events, stdout, stderr, times)."""
    work = _tf31.mkdtemp(prefix="p31-", dir=_TMP31)
    home = os.path.join(work, "home")
    os.makedirs(os.path.join(home, ".lgsm-cron"))
    log = os.path.join(work, "events.log")
    for rel, body in (("gmodserver", '#!/bin/sh\necho \'["script", "%s"]\' >> %s\n' % ("$1", log)),
                      (".lgsm-cron/run", '#!/bin/sh\necho "[\\"runner\\", \\"$1\\", \\"$2\\"]" >> %s\n'
                       % log)):
        if rel.startswith(".lgsm") and not runner:
            continue
        with open(os.path.join(home, rel), "w", encoding="utf-8") as fh:
            fh.write(body)
        os.chmod(os.path.join(home, rel), 0o700)  # nosemgrep - owner-only test script
    script = os.path.join(work, "probe.py")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write(_PROBE31)
    r = _sp31.run([_sys31.executable, script, _helper_path, work, mode, landing,  # nosec B603 - own probe
                   str(_LAND31), str(_WAIT31)], capture_output=True, text=True, timeout=60, check=False)
    return (_jsonl31(log), r.stdout, r.stderr, _jsonl31(os.path.join(work, "times.log")))


def _jsonl31(path):
    """The JSON lines of `path`, or [] when it was never written."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [_json31.loads(ln) for ln in fh if ln.strip()]


def _kinds31(events):
    return [e[0] for e in events]


def _start_order31(events):
    """(child pid, the scope event, the order of kinds) for a scoped lgsm-command run."""
    drops = [e for e in events if e[0] == "drop"]
    scopes = [e for e in events if e[0] == "scope"]
    child = drops[0][1] if drops else None
    return child, (scopes[0] if scopes else None), _kinds31(events)


def _when31(times, kind):
    """The monotonic time of the first `kind` in times.log, or None."""
    return next((t for k, t in times if k == kind), None)


_PLACED31 = ["scope", "landed", "nice", "ionice", "drop"]


def _check_lgsm_start31():
    events, _out, err, _t = _probe31("lgsm-start")
    child, scope, kinds = _start_order31(events)
    check("helper lgsm-command start: the child is moved into a scope of its own, the helper WAITS "
          "until the move has landed, then renices it and gives it no I/O class, and only THEN does "
          "it drop to the account and run the script",
          kinds in (_PLACED31 + ["script", "rc"], _PLACED31 + ["rc", "script"]),
          repr((kinds, err[-300:])))
    check("helper lgsm-command start: the scope is new and named for the account and the CHILD's pid, "
          "holds exactly that pid, and the child starts at the game nice with initgroups kept",
          scope is not None and scope[2].startswith("lgsm-gm31-%s-" % child)
          and scope[2].endswith(".scope") and scope[3] == ["PIDs", "au", "1", str(child)]
          and ["nice", child, -1] in events and ["ionice", scope[1], ["-c", "0", "-p", str(child)]]
          in events and ["drop", child, True] in events and ["rc", 0] in events
          and ["landed", child] in events, repr((scope, child, events)))


def _check_scope_wait31():
    """The wait in _start_scope, as the fork sees it: it polls until the move lands, and no longer."""
    _events, _out, err, times = _probe31("lgsm-start")
    t_scope, t_landed, t_nice = (_when31(times, k) for k in ("scope", "landed", "nice"))
    polls = [t for k, t in times if k == "poll"]
    check("helper lgsm-command start: the wait polls the child's cgroup until the move lands (%.2fs "
          "late here) and goes on AT the landing — not after the whole %.1fs limit"
          % (_LAND31, _WAIT31),
          None not in (t_scope, t_landed, t_nice) and len(polls) >= 2
          and t_landed - t_scope >= _LAND31 - 0.02 and t_nice - t_landed < 0.5,
          repr((t_scope, t_landed, t_nice, len(polls), err[-200:])))


def _check_scope_never31():
    """The same fork, with a move that never lands: the limit, and the server still starts."""
    events, _out, err, times = _probe31("lgsm-start", landing="never")
    kinds = _kinds31(events)
    t_scope, t_nice = _when31(times, "scope"), _when31(times, "nice")
    check("helper lgsm-command start: a move that never lands is waited for SCOPE_WAIT_SECONDS and "
          "no longer; the server still starts, where it was, as before scopes existed",
          kinds[:4] == ["scope", "nice", "ionice", "drop"] and "landed" not in kinds
          and ["rc", 0] in events and "script" in kinds and None not in (t_scope, t_nice)
          and _WAIT31 - 0.05 <= t_nice - t_scope < _WAIT31 + 1.5,
          repr((kinds, t_scope, t_nice, err[-200:])))


def _check_lgsm_other31():
    events, _out, err, _t = _probe31("lgsm-update")
    check("helper lgsm-command update: a maintenance action that restarts the server is scoped too, "
          "at LinuxGSM cron's nice 0 (an update's download is not lifted above every other game)",
          _kinds31(events)[:5] == _PLACED31
          and any(e[0] == "nice" and e[2] == 0 for e in events), repr((events, err[-200:])))
    events, _out, err, _t = _probe31("lgsm-details")
    check("helper lgsm-command details: an action that cannot leave a server running is not scoped "
          "and keeps its priority", _kinds31(events) in (["drop", "script", "rc"], ["drop", "rc", "script"])
          , repr((events, err[-200:])))


def _check_cron_now31():
    events, out, err, _t = _probe31("cron")
    child, scope, kinds = _start_order31(events)
    check("helper cron-run-now: the task's own runner runs as the account with the job id and its "
          "base64 command, after its scope has landed and cron's priority, and the verb says it started",
          kinds[:5] == _PLACED31 and ["runner", "abcdef012345", "ZWNobyBoaQ=="]
          in events and ["rc", 0] in events and "CRON_RUN_STARTED" in out
          and scope is not None and scope[2].startswith("lgsm-cron-gm31-%s-" % child)
          and ["nice", child, 0] in events, repr((events, out, err[-300:])))
    events, out, err, _t = _probe31("cron", runner=False)
    check("helper cron-run-now: no runnable ~/.lgsm-cron/run is a failure the caller is told about, "
          "never a 'started' for a task that cannot run",
          ["rc", 1] in events and "CRON_RUN_STARTED" not in out and "could not be started" in err,
          repr((events, out, err[-200:])))


# _start_scope itself, in-process: busctl answers 0, and _cgroup_of is a script of answers.
_SC_UNIT31 = "lgsm-gm31-4242-0a0b0c0d.scope"
_SC_PANEL31 = "/system.slice/linuxgsm-panel.service"


def _scope_helper31(answers, own=_SC_PANEL31):
    """A helper copy whose busctl is recorded and whose _cgroup_of reads `answers`.

    `answers` maps a pid to a list of what its successive reads return (its last answer repeats);
    this process's own cgroup is `own`. Returns (module, busctl calls, reads per pid).
    """
    mod = _fresh_helper31()
    calls, reads = [], {}
    mod.subprocess = _Proxy31(_sp31, run=lambda argv, **kw: (
        calls.append(list(argv)), _sp31.CompletedProcess(argv, 0, "", ""))[1])

    def _cg(pid):
        if pid == os.getpid():
            return own
        reads[pid] = reads.get(pid, 0) + 1
        seq = answers[pid]
        return seq[min(reads[pid], len(seq)) - 1]
    mod._cgroup_of = _cg
    mod.SCOPE_WAIT_SECONDS = 0.3
    return mod, calls, reads


def _check_start_scope31():
    there = "/system.slice/" + _SC_UNIT31
    mod, calls, reads = _scope_helper31({4242: [_SC_PANEL31, _SC_PANEL31, there]})
    got = mod._start_scope(_SC_UNIT31, [4242], "d")
    check("helper _start_scope: True once the pid is seen INSIDE the new scope, read until then "
          "(here: still in the panel's cgroup twice, there on the third read) and not after",
          got is True and reads == {4242: 3} and len(calls) == 1, repr((got, reads, calls)))
    mod, calls, reads = _scope_helper31({4242: [_SC_PANEL31]})
    t0 = _time31.monotonic()
    got = mod._start_scope(_SC_UNIT31, [4242], "d")
    took = _time31.monotonic() - t0
    check("helper _start_scope: a move that never lands is False after SCOPE_WAIT_SECONDS of "
          "polling, never True", got is False and 0.28 <= took < 2.0 and reads[4242] > 2,
          repr((got, took, reads)))
    mod, calls, reads = _scope_helper31({4242: [None], 4243: [_SC_PANEL31, there]})
    got = mod._start_scope(_SC_UNIT31, [4242, 4243], "d")
    check("helper _start_scope: a group whose FIRST pid has exited still counts as moved once another "
          "of its pids is inside the scope", got is True, repr((got, reads)))
    mod, calls, reads = _scope_helper31({4242: [None], 4243: [None]})
    t0 = _time31.monotonic()
    got = mod._start_scope(_SC_UNIT31, [4242, 4243], "d")
    check("helper _start_scope: a group that has entirely exited is False at once, not after the wait",
          got is False and _time31.monotonic() - t0 < 0.25, repr((got, reads)))
    for own in ("/", None):
        mod, calls, reads = _scope_helper31({4242: [there]}, own=own)
        got = mod._start_scope(_SC_UNIT31, [4242], "d")
        check("helper _start_scope: with no unified cgroup path to watch the move by (own cgroup %r, "
              "a legacy-hierarchy boot) no scope is asked for: the placement from before, no 3s wait"
              % own, got is False and calls == [] and reads == {}, repr((got, calls, reads)))


# ══ 2. adopt-game-processes and terminal-scope: only the panel's own cgroup ═══════════════════════
_PANEL_CG31 = "/user.slice/user-1000.slice/user@1000.service/app.slice/linuxgsm-panel.service"
_ME31 = os.getpid()
# pid: (comm, ppid, sid, uid). 999 is the panel's account (SUDO_UID), 1004/1005 game accounts,
# 1006 an account the panel may not act as. 100 is the panel itself: its unit's main process, a
# session leader as systemd starts every one, and the parent of the sudo (200) that ran this
# helper. 800 is the web terminal's shell (a child of the panel, leading its own session) and 801
# what it started; 700 is a panel child in the panel's own session.
_FACTS31 = {
    100: ("python3", 1, 100, 999), 200: ("sudo", 100, 200, 0), _ME31: ("panel-helper", 200, 200, 0),
    300: ("tmux: server", 1, 300, 1004), 301: ("cod_lnxded", 300, 301, 1004), 302: ("cat", 300, 300, 1004),
    400: ("tmux: server", 1, 400, 999), 401: ("sleep", 400, 401, 999),
    500: ("bash", 1, 500, 1005), 501: ("steamcmd", 500, 500, 1005),
    600: ("bash", 1, 600, 1006), 700: ("bash", 100, 100, 999),
    800: ("bash", 100, 800, 999), 801: ("tmux: client", 800, 800, 999),
}
_NAMES31 = {999: "lgsmpanel", 1004: "codserver", 1005: "mcserver", 1006: "postgres"}


def _adopt_helper31(cgroup=_PANEL_CG31):
    """A helper copy whose /proc, cgroupfs and scope calls are stand-ins; (module, scopes made)."""
    mod = _fresh_helper31()
    made = []
    mod._cgroup_of = lambda pid: cgroup if pid in _FACTS31 else None
    mod._cgroup_pids = lambda cg: sorted(_FACTS31)
    mod._proc_facts = _FACTS31.get
    mod._pw_name = lambda uid: _NAMES31.get(uid, "")

    def _v_game(name):
        if name not in ("codserver", "mcserver"):
            raise ValueError("not a game account")
        return name
    mod.v_game_account = _v_game
    mod._start_scope = lambda unit, pids, desc: (made.append((unit, list(pids))), True)[1]
    mod.os = _Proxy31(os, environ={"SUDO_UID": "999"}, getpid=lambda: _ME31)
    return mod, made


def _check_adopt31():
    mod, made = _adopt_helper31()
    rc = mod.do_adopt_game_processes([], "")
    groups = sorted(pids for _u, pids in made)
    check("helper adopt-game-processes: every tmux server tree in the panel's cgroup (the panel's own "
          "account's included) and each game account's other processes become a scope each; the "
          "panel, sudo, this helper and a non-game account are left alone",
          rc == 0 and groups == [[300, 301, 302], [400, 401], [500, 501]],
          repr((rc, made)))
    check("helper adopt-game-processes: the scopes are named for the owning account",
          sorted(u.split("-")[2] for u, _p in made) == ["codserver", "lgsmpanel", "mcserver"],
          repr([u for u, _p in made]))
    mod, made = _adopt_helper31(cgroup="/system.slice/cron.service")
    check("helper adopt-game-processes: run from any cgroup but the panel's unit, it moves nothing",
          mod.do_adopt_game_processes([], "") == 0 and made == [], repr(made))
    mod, made = _adopt_helper31()
    mod._start_scope = lambda unit, pids, desc: False
    check("helper adopt-game-processes: a scope systemd would not make is a failure exit, not a pass",
          mod.do_adopt_game_processes([], "") == 1)
    _check_adopt_retry31()


def _check_adopt_retry31():
    """One pid of a group exits between the cgroup.procs read and the call: systemd refuses it all."""
    mod, made = _adopt_helper31()
    tried, gone = [], {501}
    listing = sorted(_FACTS31)

    def _scope(unit, pids, _desc):
        tried.append(list(pids))
        if gone & set(pids):
            return False              # StartTransientUnit: "No such process" for the whole group
        made.append((unit, list(pids)))
        return True
    reads = []

    def _pids(cg):
        """cgroup.procs: the first read still lists 501, every later one does not."""
        reads.append(cg)
        return listing if len(reads) == 1 else [p for p in listing if p not in gone]
    mod._start_scope = _scope
    mod._cgroup_pids = _pids
    sink = _Sink31()
    with _ctx31.redirect_stdout(sink):          # the verb print()s its tally
        rc = mod.do_adopt_game_processes([], "")
    out = sink.text
    check("helper adopt-game-processes: a group systemd refused because one of its pids had exited "
          "is tried once more with the rest, and the exited pid is no failure",
          rc == 0 and "ADOPTED 6 0" in out and [500, 501] in tried and [500] in tried
          and sorted(p for _u, p in made) == [[300, 301, 302], [400, 401], [500]]
          and [u for u, p in made if p == [500]][0].startswith("lgsm-adopted-mcserver-500-"),
          repr((rc, out, tried, made)))


def _check_cgroup_pids31():
    """cgroup.procs is read from the unified hierarchy wherever it is mounted."""
    mod = _fresh_helper31()
    flat, hybrid = (_tf31.mkdtemp(prefix="cg31-", dir=_TMP31) for _ in range(2))
    cg = "/system.slice/lgsm-part31-%s.service" % os.urandom(4).hex()
    os.makedirs(hybrid + cg)
    with open(hybrid + cg + "/cgroup.procs", "w", encoding="ascii") as fh:
        fh.write("5\n6\n")
    mod.CGROUP_V2_ROOTS = (flat, hybrid)
    try:
        got = mod._cgroup_pids(cg)
    except OSError as exc:              # the crash a hybrid host had: a failure BY NAME, below
        got = "raised %s" % exc
    mod.CGROUP_V2_ROOTS = (flat,)
    try:
        mod._cgroup_pids(cg)
        missing = "read nothing, and said nothing"
    except FileNotFoundError as exc:
        missing = str(exc)
    check("helper _cgroup_pids: on a hybrid boot the panel's cgroup.procs is read under "
          "/sys/fs/cgroup/unified (adoption and the terminal's scope used to crash there), and a "
          "cgroup in neither place is an error, never an empty list",
          got == [5, 6] and missing.startswith("no cgroup.procs for " + cg), repr((got, missing)))


def _check_terminal_scope31():
    mod, made = _adopt_helper31()
    nices = []
    mod._reset_priority = lambda pid, nice: nices.append((pid, nice))
    rc = mod.do_terminal_scope(["800"], "")
    check("helper terminal-scope: the shell and the rest of ITS session move into one new scope, "
          "at an SSH login's priority",
          rc == 0 and [p for _u, p in made] == [[800, 801]] and made[0][0].startswith(
              "linuxgsm-panel-terminal-lgsmpanel-800-") and nices == [(800, 0), (801, 0)],
          repr((rc, made, nices)))
    for pid, why, said in (("300", "another account's process", "not a process of the panel's own"),
                           ("700", "a process that does not lead its own session", "lead its own"),
                           ("100", "the panel's own process (a session leader of its account, in its "
                            "cgroup, and the parent of the sudo that ran the helper)", "the panel itself")):
        mod, made = _adopt_helper31()
        rc = mod.do_terminal_scope([pid], "")
        check("helper terminal-scope: refuses %s, and says which" % why,
              rc == 1 and made == [] and said in mod.sys.stderr.text,
              repr((rc, made, mod.sys.stderr.text)))
    mod, made = _adopt_helper31(cgroup="/system.slice/cron.service")
    check("helper terminal-scope: refuses a process outside the panel's own cgroup",
          mod.do_terminal_scope(["100"], "") == 1 and made == [], repr(made))


# ══ 3. the jobs: their own transient service, in its foreground ═══════════════════════════════════
def _job_helper31(rc=0):
    """A helper copy with subprocess.run recorded (answering `rc`) and fork forbidden."""
    mod = _fresh_helper31()
    calls = []
    mod.subprocess = _Proxy31(_sp31, run=lambda argv, **kw: (
        calls.append(list(argv)), _sp31.CompletedProcess(argv, rc, "", "Unit x already exists"))[1])
    mod.os = _Proxy31(os, fork=_no_fork31, environ={"SUDO_UID": "999", "SUDO_USER": "lgsmpanel",
                                                     "PATH": "/x"})
    # Run from the panel's unit, as the panel runs it: a unified cgroup path, whatever runs the suite.
    mod._cgroup_of = lambda pid: "/system.slice/linuxgsm-panel.service"
    db = os.path.join(_TMP31, "panel.db")
    open(db, "w", encoding="utf-8").close()
    data = os.path.join(_TMP31, "data")
    os.makedirs(os.path.join(data, mod.RESTORE_STAGE), exist_ok=True)
    mod.DBM_PATH = mod.INSTALLER_PATH = db
    mod.panel_conf = lambda: {"db_path": db, "data_dir": data, "panel_dir": _TMP31}
    return mod, calls


_JOB_CASES31 = (("panel-db-repair", "do_panel_db_repair", [], "REPAIR_STARTED"),
                ("os-update-run", "do_os_update_run", [], "__STARTED__"),
                ("panel-restore", "do_panel_restore", [], "RESTORE_STARTED"),
                ("panel-self-update", "do_panel_self_update", ["abc1234", "main"], "UPDATE_STARTED"))


def _run_verb31(mod, fn, args):
    """(rc, stdout) of one verb function on a helper copy; a fork it was not allowed is the rc."""
    mod.sys.stdout.text = ""
    try:
        rc = getattr(mod, fn)(args, "")
    except AssertionError as exc:
        rc = "raised: %s" % exc
    return rc, mod.sys.stdout.text


def _job_argv_ok31(argv, unit, job, args):
    """True when `argv` is the transient-service launch for `job`.

    A fixed head, the caller's SUDO_* identity and nothing else of the environment, and the helper
    itself with --job after `--`.
    """
    tail = argv[argv.index("--"):] if "--" in argv else []
    return (argv[:4] == ["/usr/bin/systemd-run", "--unit=" + unit, "--collect", "--quiet"]
            and tail == ["--", os.path.realpath(_helper_path), "--job", job] + args
            and "--setenv=SUDO_UID=999" in argv and "--setenv=SUDO_USER=lgsmpanel" in argv
            and not any(a.startswith("--setenv=PATH") for a in argv))


def _check_jobs31():
    for job, fn, args, said in _JOB_CASES31:
        mod, calls = _job_helper31()
        rc, out = _run_verb31(mod, fn, args)
        check("helper %s: started as the MAIN process of its own transient service %s, with the "
              "caller's identity passed on, no fork, and reported as started" % (job, mod.JOB_UNITS[job]),
              rc == 0 and said in out and len(calls) == 1
              and _job_argv_ok31(calls[0], mod.JOB_UNITS[job], job, args), repr((rc, out, calls)))
        mod, calls = _job_helper31(rc=1)
        rc, out = _run_verb31(mod, fn, args)
        check("helper %s: a transient service systemd refuses (one already running) is a failure "
              "with systemd's words, never 'started'" % job, rc == 1 and said not in out, repr((rc, out)))


def _check_job_entry31():
    mod, _calls = _job_helper31()
    ran = []
    mod._db_repair_run = lambda db: ran.append(db) or 0
    mod._cgroup_of = lambda pid: "/system.slice/linuxgsm-panel.service"
    check("helper --job: refused from the panel's own cgroup (where the stop would end it again), "
          "and the repair does not run", mod.main(["ph", "--job", "panel-db-repair"]) == 2 and ran == [])
    mod._cgroup_of = lambda pid: "/system.slice/linuxgsm-panel-db-repair.service"
    check("helper --job: inside its own unit the repair runs in the FOREGROUND (no fork)",
          mod.main(["ph", "--job", "panel-db-repair"]) == 0 and len(ran) == 1, repr(ran))
    check("helper --job: an unknown job, or arguments a job does not take, are refused",
          mod.main(["ph", "--job", "rm-rf"]) == 2 and mod.main(["ph", "--job", "panel-db-repair", "x"]) == 2)
    mod._cgroup_of = lambda pid: "/system.slice/linuxgsm-panel-self-update.service"
    check("helper --job panel-self-update: its ref and branch are validated again",
          mod.main(["ph", "--job", "panel-self-update", "-x;", "main"]) == 2)


def _check_os_update_job31():
    mod, _calls = _job_helper31()
    apt = os.path.join(_TMP31, "fake-apt")
    with open(apt, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\necho \"apt $*\"\ncase \"$*\" in *full-upgrade*) exit 7 ;; esac\n")
    os.chmod(apt, 0o700)  # nosemgrep - owner-only test script
    mod.subprocess = _sp31
    mod.resolve = lambda name: apt
    mod.OS_UPDATE_LOG = os.path.join(_TMP31, "os-update.log")
    mod._cgroup_of = lambda pid: "/system.slice/linuxgsm-panel-os-update.service"
    rc = mod.main(["ph", "--job", "os-update-run"])
    with open(mod.OS_UPDATE_LOG, encoding="utf-8") as fh:
        text = fh.read()
    check("helper --job os-update-run: apt runs to its end in the foreground and the sentinel carries "
          "the real exit code", rc == 0 and "apt update" in text and "autoremove" in text
          and (mod.OS_UPDATE_DONE + "7") in text, repr((rc, text[-200:])))


def _forking31(mod):
    """Let `mod` fork: the parent's side only (4242), recorded; returns the record."""
    forked = []
    mod.os = _Proxy31(os, fork=lambda: forked.append(1) or 4242, waitpid=lambda p, f: (p, 0))
    return forked


def _check_no_systemd31():
    mod, calls = _job_helper31()
    mod.SYSTEMD_BOOTED_DIR = os.path.join(_TMP31, "no-such-dir")
    forked = _forking31(mod)
    rc, out = _run_verb31(mod, "do_panel_db_repair", [])
    check("helper panel-db-repair without systemd as PID 1: the detached child, as before",
          rc == 0 and forked == [1] and calls == [] and "REPAIR_STARTED" in out, repr((rc, forked, calls)))
    for own in ("/", None):
        mod, calls = _job_helper31()
        mod._cgroup_of = lambda pid, own=own: own
        forked = _forking31(mod)
        rc, out = _run_verb31(mod, "do_panel_db_repair", [])
        check("helper panel-db-repair with systemd but no unified cgroup path (own cgroup %r: a "
              "legacy-hierarchy boot): the detached child, as before — a job launched there could "
              "never find its own unit, and would only refuse" % own,
              rc == 0 and forked == [1] and calls == [] and "REPAIR_STARTED" in out,
              repr((rc, forked, calls)))
    mod, _calls = _job_helper31()
    seen = {}
    for cg in ("/system.slice/linuxgsm-panel.service", "/", "", None):
        mod._cgroup_of = lambda pid, cg=cg: cg
        seen[cg] = mod._cgroup_v2_placed()
    eq("helper _cgroup_v2_placed: a real unified path is placed; `0::/`, an empty line and an "
       "unreadable /proc are not", seen, {"/system.slice/linuxgsm-panel.service": True, "/": False,
                                          "": False, None: False})


_REBOOT_TIMER31 = ["/usr/bin/systemd-run", "--on-active=2", "--collect", "--quiet", "--", "/usr/bin/reboot"]


def _check_reboot31():
    mod, calls = _job_helper31()
    rc, _out = _run_verb31(mod, "do_reboot_delayed", [])
    check("helper reboot-delayed: a transient timer owned by the system manager, not a sleeping "
          "grandchild in the panel's cgroup", rc == 0 and calls == [_REBOOT_TIMER31], repr((rc, calls)))
    mod, calls = _job_helper31(rc=1)
    forked = _forking31(mod)
    rc, _out = _run_verb31(mod, "do_reboot_delayed", [])
    check("helper reboot-delayed: a timer systemd-run could not create falls back to the detached "
          "grandchild, so the reboot still happens (never a 0 for a reboot nothing will do)",
          rc == 0 and calls == [_REBOOT_TIMER31] and forked == [1], repr((rc, calls, forked)))


# ══ 4. one table, two copies: the gates between the helper and the panel ══════════════════════════
def _helper_src31():
    with open(_helper_path, encoding="utf-8") as fh:
        return fh.read()


def _check_constants31():
    h = _fresh_helper31()
    eq("the helper's GAME_NICE is the panel's GAME_PRIORITY_NICE (the keeper renices to it)",
       h.GAME_NICE, _smc31.GAME_PRIORITY_NICE)
    eq("the panel's scoped LinuxGSM actions are the helper's start and maintenance actions",
       sorted(_smc31.SCOPED_LGSM_ACTIONS), sorted(h.SCOPED_START_ACTIONS | h.SCOPED_MAINT_ACTIONS))
    check("the scoped actions are all LinuxGSM actions the verb accepts",
          set(_smc31.SCOPED_LGSM_ACTIONS) <= set(_priv31.LGSM_ACTIONS))
    check("the three new verbs are local-only: they act on the panel's own host and cgroup",
          {"cron-run-now", "adopt-game-processes", "terminal-scope"} <= _priv31.LOCAL_ONLY_VERBS)
    check("the helper builds a scope with busctl, never `systemd-run --uid` (which keeps root's "
          "groups up to systemd v261)", "--uid" not in _helper_src31()
          .split("def _scope_argv", 1)[1].split("\ndef ", 1)[0])


# ══ 5. the panel side ════════════════════════════════════════════════════════════════════════════
_LOCAL31 = _types31.SimpleNamespace(is_local=True, auth_method="local", sudo_enabled=True)
_REMOTE31 = _types31.SimpleNamespace(is_local=False, auth_method="key", sudo_enabled=True, id=7)


def _recorders31():
    rec = {"argv": [], "cmd": []}

    def _exec(argv, **_kw):
        rec["argv"].append(list(argv))
        return "", "", 0

    def _run(_server, cmd, **_kw):
        rec["cmd"].append(cmd)
        return "", "", 0
    return rec, _exec, _run


def _check_backup31():
    rec, _exec, _run = _recorders31()
    with _swap31(_smc31, helper_present=lambda recheck=False: True, _exec_local_argv=_exec,
                 run_command=_run):
        res = _smgame31._run_linuxgsm_backup(_LOCAL31, "gm", "gmodserver")
    check("LinuxGSM backup on the panel's host: through lgsm-command `backup` with its answers, so the "
          "server it restarts gets a scope — never a `sudo -u … ./gmodserver backup` of its own",
          res[0] is True and rec["argv"] == [["sudo", "-n", _priv31.HELPER_PATH, "lgsm-command", "gm",
                                              "gmodserver", "backup", "y,y,y", "no"]]
          and not any("gmodserver backup" in c for c in rec["cmd"])
          and any("backup.lock" in c and c.startswith("sudo -u gm bash -c") for c in rec["cmd"]),
          repr(rec))


def _check_run_now31():
    rec, _exec, _run = _recorders31()
    raw = "*/5 * * * * /home/gm/gmodserver monitor"
    jid = _smcron31._cron_job_id("/home/gm/gmodserver monitor")
    b64 = _b6431.b64encode(b"/home/gm/gmodserver monitor").decode()
    with _swap31(_smc31, helper_present=lambda recheck=False: True, _exec_local_argv=_exec,
                 run_command=_run):
        res = _smcron31.run_cron_job_now(_LOCAL31, "gm", raw, "gmodserver")
    check("Run now on the panel's host: the recorder is installed as the account, then cron-run-now "
          "runs the task in a scope — no `setsid bash &` from the panel's cgroup",
          res[0] is True and rec["argv"] == [["sudo", "-n", _priv31.HELPER_PATH, "cron-run-now", "gm",
                                              jid, b64]]
          and len(rec["cmd"]) == 1 and ".lgsm-cron" in rec["cmd"][0]
          and not any("setsid" in c for c in rec["cmd"]), repr((res, rec)))
    rec, _exec, _run = _recorders31()
    with _swap31(_smc31, helper_present=lambda recheck=False: True, _exec_local_argv=_exec,
                 run_command=lambda s, c, **k: (rec["cmd"].append(c), ("", "denied", 1))[1]):
        res = _smcron31.run_cron_job_now(_LOCAL31, "gm", raw, "gmodserver")
    check("Run now on the panel's host: a recorder that could not be installed runs nothing and says so",
          res == (False, _smcron31._RUNNER_FAILED_NOW) and rec["argv"] == [], repr((res, rec)))
    rec, _exec, _run = _recorders31()
    with _swap31(_smc31, helper_present=lambda recheck=False: True, _exec_local_argv=_exec,
                 run_command=_run):
        res = _smcron31.run_cron_job_now(_REMOTE31, "gm", raw, "gmodserver")
    check("Run now on a remote: unchanged, the detached shell form over SSH",
          res[0] is True and rec["argv"] == [] and any("setsid bash" in c for c in rec["cmd"]), repr(rec))


def _check_run_now_refused31():
    """A hand-edited crontab line whose recorder id is longer than the verb takes."""
    rec, _exec, _run = _recorders31()
    long_id = "ab" * 35
    b64 = _b6431.b64encode(b"/home/gm/gmodserver monitor").decode()
    raw = "*/5 * * * * /home/gm/.lgsm-cron/run %s %s" % (long_id, b64)
    with _swap31(_smc31, helper_present=lambda recheck=False: True, _exec_local_argv=_exec,
                 run_command=_run):
        res = _smcron31.run_cron_job_now(_LOCAL31, "gm", raw, "gmodserver")
    check("Run now on the panel's host: an argument the verb refuses (here a 70-character job id, "
          "which the crontab parser accepts) is reported with the validator's own reason, not as a "
          "command that is too long, and nothing runs",
          res[0] is False and "not a job id" in res[1] and "too long" not in res[1]
          and rec["argv"] == [], repr((res, rec)))


_PREFIX31 = "systemd-run --user --scope --collect --quiet -- "


def _check_user_scope31():
    rec, _exec, _run = _recorders31()
    with _swap31(_smc31, helper_present=lambda recheck=False: False, run_command=_run,
                 _USER_SCOPE={"ok": True, "at": 0.0}):
        _smc31.run_as_game_user(_LOCAL31, "gm", "restart", selfname="gmodserver")
        _smc31.run_as_game_user(_LOCAL31, "gm", "details", selfname="gmodserver")
        _smc31.run_as_game_user(_REMOTE31, "gm", "start", selfname="gmodserver")
        _smcron31.run_cron_job_now(_LOCAL31, "gm", "* * * * * /home/gm/gmodserver monitor")
    c = rec["cmd"]
    check("no helper, per-user install: a LinuxGSM action that can leave the server running, and "
          "Run now, start in a scope of the user manager; a `details` and any remote do not",
          len(c) == 4 and c[0].startswith(_PREFIX31 + "sudo -u gm bash -c")
          and c[1].startswith("sudo -u gm bash -c") and c[2].startswith("sudo -u gm bash -c")
          and c[3].startswith(_PREFIX31 + "sudo -u gm bash -c") and "setsid" in c[3], repr(c))


def _check_user_scope_probe31():
    unit = os.path.join(_TMP31, "user-unit.service")
    probes = []

    def _exec(argv, **_kw):
        probes.append(list(argv))
        return _exec.answer
    _exec.answer = ("", "", 0)
    with _swap31(_smc31, _USER_UNIT=unit, _exec_local_argv=_exec, _USER_SCOPE={"ok": None, "at": 0.0}):
        first = _smc31.user_scope_argv()
        open(unit, "w", encoding="utf-8").close()
        _smc31._USER_SCOPE.update(ok=None)
        second = _smc31.user_scope_argv()
        third = _smc31.user_scope_argv()
        _exec.answer = ("", "timed out", -1)     # the local/tailscale shape of a failure: no raise
        _smc31._USER_SCOPE.update(ok=None)
        failed = _smc31.user_scope_argv()
        n_after_fail = len(probes)
        again = _smc31.user_scope_argv()
        _smc31._USER_SCOPE["at"] -= _smc31._USER_SCOPE_RETRY + 1
        retried = _smc31.user_scope_argv()
    check("user_scope_argv: not a per-user install → no prefix and nothing run; a probe that runs → "
          "the prefix, asked once; a probe that fails (rc -1, no raise) → no prefix, asked again "
          "only after the retry interval",
          first == [] and second == list(_smc31.USER_SCOPE_ARGV) and third == second
          and probes[0] == list(_smc31.USER_SCOPE_ARGV) + ["true"] and failed == [] and again == []
          and n_after_fail == 2 and retried == [] and len(probes) == 3, repr(probes))


def _probe_shell31():
    path = os.path.join(_TMP31, "probe-shell")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\necho PROBE31\n")
    os.chmod(path, 0o700)  # nosemgrep - owner-only test script
    wrap = os.path.join(_TMP31, "scope-wrap")
    mark = os.path.join(_TMP31, "wrapped")
    with open(wrap, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n[ \"$1\" = -- ] && shift\necho \"$@\" > %s\nexec \"$@\"\n" % mark)
    os.chmod(wrap, 0o700)  # nosemgrep - owner-only test script
    return path, wrap, mark


def _open_terminal31(prefix):
    """Open the real local terminal with the shell replaced by a probe; (session, pids asked about)."""
    shell, _wrap, _mark = _probe_shell31()
    asked, out, done = [], [], _thr31.Event()
    sess = _ts31.Session("local31", "local", lambda s, d: out.append(d), lambda s, r: done.set())
    with _swap31(_ts31, _login_shell=lambda: shell, _user_scope_argv=lambda: list(prefix)), \
            _swap31(_so31, terminal_scope=asked.append):
        _ts31._open_local(sess, 80, 24)
    done.wait(timeout=15)
    pid = sess._proc.pid
    sess.close("")
    return pid, asked, "".join(out)


def _check_terminal31():
    _shell, wrap, mark = _probe_shell31()
    pid, asked, text = _open_terminal31([])
    check("terminal (system install): the shell starts as before and the helper is asked to give "
          "THAT pid a scope of its own", asked == [pid] and "PROBE31" in text, repr((pid, asked, text)))
    pid, asked, text = _open_terminal31([wrap, "--"])
    wrapped = ""
    if os.path.exists(mark):
        with open(mark, encoding="utf-8") as fh:
            wrapped = fh.read()
    check("terminal (per-user install): the shell is started THROUGH the user-scope prefix, and the "
          "helper is not asked", asked == [] and "PROBE31" in text and wrapped.strip().endswith(" -l")
          and wrapped.startswith(os.path.join(_TMP31, "probe-shell")), repr((asked, text, wrapped)))


def _check_restore31():
    calls = []
    for system, want in ((False, "legacy"), (True, "verb")):
        calls[:] = []
        with _swap31(_bk31, _helper_present=lambda: True, _is_system_service=lambda sy=system: sy,
                     _run_verb=lambda verb, args=(), **k: (calls.append("verb"), ("", "", 0))[1],
                     _legacy_restore_dispatch=lambda *a, **k: (calls.append("legacy"), (True, "ok"))[1]):
            _bk31._dispatch_restore(os.path.join(_TMP31, "stage"), "x.tar.gz", "", False)
        check("restore with the helper on a %s install: %s" % (
            "system" if system else "per-user (or unit-less)",
            "the helper's panel-restore" if system else
            "the account's own --user restore (the helper's swap targets a SYSTEM unit that is not "
            "there, and copied under the running panel)"), calls == [want], repr(calls))
    check("restore: chooses the helper by system_ops._is_system_service, the one test the repair and "
          "the self-update use, so a host with neither unit file is not a system install to any of "
          "them", _bk31._is_system_service is _so31._is_system_service)
    _check_restore_launch31()


def _check_restore_launch31():
    """The restore without the helper's verb: a launcher systemd-run refuses is a failure."""
    data = _tf31.mkdtemp(prefix="rs31-", dir=_TMP31)
    stage = os.path.join(data, ".restore-stage")
    os.makedirs(stage)
    with open(os.path.join(stage, "cred_key"), "w", encoding="utf-8") as fh:
        fh.write("k")
    spawned = []
    sp = _Proxy31(_sp31, run=lambda argv, **k: _sp31.CompletedProcess(argv, 1, "", "Failed to connect to bus"),
                  Popen=lambda argv, **k: spawned.append(list(argv)))
    with _swap31(_bk31, DATA_DIR=data, subprocess=sp,
                 _service_restart_launcher=lambda script: ["systemd-run", "--user", "--collect", script]):
        res = _bk31._legacy_restore_dispatch(stage, "x.tar.gz", "", False)
    check("restore through the user manager: a systemd-run that fails (no user bus, sudo refused) is "
          "'could not start', never 'Restoring…', and the staged keys and database are wiped",
          res == (False, "Could not start the restore.") and not os.path.exists(stage) and spawned == [],
          repr((res, os.path.exists(stage), spawned)))


def _check_system_ops31():
    seen = []
    with _swap31(_so31, _helper_present=lambda: False,
                 _run_verb=lambda *a, **k: (seen.append(a), ("", "", 0))[1]):
        none = (_so31.adopt_game_processes(), _so31.terminal_scope(4242))
    with _swap31(_so31, _helper_present=lambda: True,
                 _run_verb=lambda *a, **k: (seen.append((a, k)), ("ADOPTED 3 0", "", 0))[1]):
        got = (_so31.adopt_game_processes(), _so31.terminal_scope(4242))
    check("system_ops: without the helper the adoption and the terminal's scope are not attempted; "
          "with it, the verbs, with the pid as text",
          none == (None, None) and [s[0] for s in seen] == [("adopt-game-processes", []),
                                                            ("terminal-scope", ["4242"])]
          and got[0][2] == 0, repr(seen))


def _main_thread_targets31():
    """The names passed as target= to any call inside app.py's `if __name__ == "__main__":`."""
    with open(os.path.join(_root, "app.py"), encoding="utf-8") as fh:
        tree = _ast31.parse(fh.read())
    main = next(n for n in tree.body if isinstance(n, _ast31.If) and "__main__" in _ast31.dump(n.test))
    calls = [n for n in _ast31.walk(main) if isinstance(n, _ast31.Call)]
    return [kw.value.id for n in calls for kw in n.keywords
            if kw.arg == "target" and isinstance(kw.value, _ast31.Name)]


def _check_app31():
    targets = _main_thread_targets31()
    check("app.py: the panel's start launches the one-time adoption of game processes in its cgroup",
          "_adopt_game_processes" in targets, repr(targets))
    ran = []
    with _swap31(_so31, adopt_game_processes=lambda: ran.append(1) or (_ for _ in ()).throw(
            RuntimeError("boom"))):
        _app31._adopt_game_processes()
    check("app.py: _adopt_game_processes asks system_ops, and a failure there never escapes",
          ran == [1])


# ══ 6. the debug report ══════════════════════════════════════════════════════════════════════════
def _fake_proc31():
    root = os.path.join(_TMP31, "dr")
    proc, cg = os.path.join(root, "proc"), os.path.join(root, "cg")
    unit = "/system.slice/" + _pr31._src_systemd.UNIT
    os.makedirs(os.path.join(cg + unit))
    with open(os.path.join(cg + unit, "cgroup.procs"), "w", encoding="utf-8") as fh:
        fh.write("%d\n300\n301\n302\n400\n450\n460\n999999\n" % os.getpid())
    with open(os.path.join(cg + unit, "memory.stat"), "w", encoding="utf-8") as fh:
        fh.write("anon 104857600\nfile 209715200\nkernel 1\n")
    # The tmux tree started AFTER this process (as one the panel starts does), so only the tmux
    # rule can name it; 460 is older than this process (a left-over), 450 is the unit's MainPID.
    rows = {"self": ("python3", 1, 5000), "300": ("tmux: server", 1, 6000),
            "301": ("cod_lnxded", 300, 6000), "302": ("cat", 300, 6000), "400": ("ssh", 77, 9900),
            "450": ("python3", 1, 100), "460": ("bash", 1, 100)}
    for pid, (comm, ppid, start) in rows.items():
        os.makedirs(os.path.join(proc, pid))
        with open(os.path.join(proc, pid, "stat"), "w", encoding="utf-8") as fh:
            fh.write("%s (%s) S %d 1 1 0 -1 0 0 0 0 0 5 5 0 0 20 0 1 0 %d 0 0\n" % (pid, comm, ppid, start))
    with open(os.path.join(proc, "uptime"), "w", encoding="utf-8") as fh:
        fh.write("100.0 50.0\n")
    return proc, cg, unit


def _cgroup_report31(scope):
    proc, cg, unit = _fake_proc31() if not os.path.isdir(os.path.join(_TMP31, "dr")) else (
        os.path.join(_TMP31, "dr", "proc"), os.path.join(_TMP31, "dr", "cg"),
        "/system.slice/" + _pr31._src_systemd.UNIT)
    res = _Res31()
    with _swap31(_pr31, PROC=proc, CGROUP_ROOT=cg, _cgroup_path=lambda: unit):
        _pr31._cgroup_line(res, {"unit": {"scope": scope, "props": {"MainPID": "450"}}})
        split = _pr31._memory_split()
    return "\n".join(res.lines), [f["text"] for f in res.findings], split


def _check_report31():
    text, finds, split = _cgroup_report31("system")
    check("debug report: a tmux server and what it started in the panel's cgroup, and a left-over "
          "older than the panel, are named as game processes, with a warning that a stop kills them "
          "on a system unit; the unreadable pid is COUNTED; a young ssh and the unit's MainPID are not",
          "Game-server processes in the panel's cgroup** (tmux servers, what they started, and anything "
          "older than this process): 4" in text
          and "1 more could not be read" in text
          and finds == ["4 game-server processes run inside the panel's cgroup: every panel stop, "
                        "restart or self-update kills them, silently"], repr((text, finds)))
    _t, finds, _s = _cgroup_report31("user")
    check("debug report: on a user unit with the game as the panel's own account, the warning says a "
          "stop kills them", finds and "some as the panel's own account" in finds[0], repr(finds))
    game = [{"owner": "another account"}]
    check("debug report: on a user unit with the game as another account, the warning says systemd "
          "fails to stop them (EPERM) and that their memory counts as the panel's",
          "Operation not permitted" in _pr31._game_finding(game, "user")
          and "survive" in _pr31._game_finding(game, "user"), _pr31._game_finding(game, "user"))
    check("debug report: the unit's memory is split into anon and file cache from memory.stat",
          split == " (anon 100 MB, file cache 200 MB)", repr(split))
    procs = [{"pid": 1, "ppid": 0, "comm": "ssh", "owner": "panel", "state": "S", "age": 9000.0,
              "cpu_pct": 0.0},
             {"pid": 2, "ppid": 0, "comm": "ssh", "owner": "panel", "state": "R", "age": 1.0,
              "cpu_pct": 0.0}]
    eq("debug report: a young R process in an older group of the same name is no longer invisible",
       _pr31._group_procs(procs), "ssh ×2 (up 2 h 30 m, R)")


def _check_journal31():
    lines = ["Oct 02 08:40:11 host systemd[1203]: linuxgsm-panel.service: Failed to kill control "
             "group /user.slice/x/linuxgsm-panel.service, ignoring: Operation not permitted",
             "Oct 02 08:40:11 host systemd[1203]: linuxgsm-panel.service: Unit process 4242 (java) "
             "remains running after unit stopped.",
             "Oct 02 08:40:16 host python3[77]: LinuxGSM Panel starting on 127.0.0.1:5000"]
    ctx = _Ctx31()
    with _swap31(_sj31, read=lambda max_lines=5000, timeout=10: {"source": "helper",
                                                                 "lines": list(lines), "why": None}):
        res = _lg31.section_journal_digest(ctx)
    text = "\n".join(res.lines)
    check("debug report journal: systemd's 'could not stop it with the unit' lines are explained, "
          "and raise a warning instead of sitting among the most repeated lines",
          "Processes systemd could not stop with the panel**: 2 lines" in text
          and any("could not stop processes inside the panel's unit" in f["text"] for f in res.findings),
          repr((text, res.findings)))


def _check_keeper31():
    me = __import__("pwd").getpwuid(os.getuid()).pw_name
    calls = []
    with _swap31(_smc31, run_privileged=lambda s, verb, args=(), **k: (
            calls.append((s.is_local, verb, list(args))), ("", "", 0))[1]):
        _smc31.set_game_priority_bulk(_LOCAL31, [me, "mcserver"])
        _smc31.set_game_priority(_LOCAL31, me)
        _smc31.set_game_priority_bulk(_REMOTE31, [me, "mcserver"])
    check("priority keeper: on the panel's own host it never renices the panel's OWN account (that "
          "reniced the panel itself to -1, undoing its Nice=10); other accounts, and every remote "
          "account, as before",
          calls == [(True, "renice-users", ["-1", "mcserver"]),
                    (False, "renice-users", ["-1", me, "mcserver"])], repr(calls))


# ══ 7. an uninstalled server's crontab goes with its account ═════════════════════════════════════
def _is_account_delete31(call):
    """True for a run_privileged(remote, "user-delete" or "user-delete-force", ...) call."""
    verb = call.args[1] if len(call.args) > 1 else None
    return isinstance(verb, _ast31.Constant) and verb.value in ("user-delete", "user-delete-force")


def _deleters31():
    """Every account-deleting function in manage_servers.py, with where it removes the crontab.

    {function name: (line of its first _remove_account_crontab call, or None; line of its first
    account delete)}.
    """
    with open(os.path.join(_root, "panel", "routes", "manage_servers.py"), encoding="utf-8") as fh:
        tree = _ast31.parse(fh.read())
    out = {}
    for fn in [n for n in _ast31.walk(tree) if isinstance(n, _ast31.FunctionDef)]:
        dels, crons = _delete_lines31(fn)
        if dels:
            out[fn.name] = (min(crons) if crons else None, min(dels))
    return out


def _delete_lines31(fn):
    """(lines of account deletes, lines of _remove_account_crontab calls) inside `fn`."""
    dels, crons = [], []
    for c in _ast31.walk(fn):
        if not isinstance(c, _ast31.Call):
            continue
        if _is_account_delete31(c):
            dels.append(c.lineno)
        elif getattr(c.func, "id", None) == "_remove_account_crontab":
            crons.append(c.lineno)
    return dels, crons


def _check_crontab31():
    from panel.routes import manage_servers as _ms31
    dels = _deleters31()
    check("uninstall: every function that deletes a game account removes its crontab FIRST "
          "(userdel -r leaves /var/spool/cron/crontabs/<name> behind)",
          len(dels) >= 2 and all(c is not None and c < d for c, d in dels.values()), repr(dels))
    seen = []
    with _swap31(_smc31, run_privileged=lambda r, verb, args=(), **k: (
            seen.append((verb, list(args))), ("", "no crontab for gm31", 1))[1]):
        _ms31._remove_account_crontab(_REMOTE31, "gm31")
    with _swap31(_smc31, run_privileged=lambda *a, **k: (_ for _ in ()).throw(ConnectionError("x"))):
        _ms31._remove_account_crontab(_REMOTE31, "gm31")
    check("uninstall: the crontab is removed through the crontab-remove verb, and neither 'no "
          "crontab' nor a dropped connection stops the account removal that follows",
          seen == [("crontab-remove", ["gm31"])], repr(seen))
    me = __import__("pwd").getpwuid(os.geteuid()).pw_name
    refused = ""
    try:
        _priv31.helper_argv("crontab-remove", [me])
    except Exception as exc:  # noqa: BLE001 - that it refuses is the check
        refused = str(exc)
    check("crontab-remove: refuses the panel's own account, like userdel, and builds `crontab -u <name> "
          "-r` for a game account",
          bool(refused) and _priv31.tool_argv("crontab-remove", ["codserver"])
          == ["crontab", "-u", "codserver", "-r"], repr(refused))


# ══ 8. an uninstall stops the web terminal's scopes before it deletes the panel user ═════════════
def _uninstall_src31():
    with open(os.path.join(_root, "uninstall.sh"), encoding="utf-8") as fh:
        return fh.read()


def _code_lines31(text):
    """`text` without its comment lines: what the shell runs."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


_FAKE_SYSTEMCTL31 = r"""#!/bin/sh
echo "$*" >> "$LOG31"
case "$1" in
list-units)
  echo "linuxgsm-panel-terminal-lgsmpanel-812-0a0b0c0d.scope loaded active running linuxgsm-panel web terminal shell"
  echo "● linuxgsm-panel-terminal-lgsmpanel-955-1a1b1c1d.scope loaded failed failed linuxgsm-panel web terminal shell"
  echo "linuxgsm-panel-terminal-lgsmpanel-990-2a2b2c2d.scope loaded active running linuxgsm-panel web terminal shell"
  echo "lgsm-mcserver-2137851-2add1ddd.scope loaded active running LinuxGSM mcserver" ;;
esac
"""


def _check_uninstall_scopes31():
    src = _uninstall_src31()
    code = _code_lines31(src)
    fn = src[src.index("\nstop_terminal_scopes() {") + 1:]
    fn = fn[:fn.index("\n}\n") + 3]
    work = _tf31.mkdtemp(prefix="un31-", dir=_TMP31)
    with open(os.path.join(work, "systemctl"), "w", encoding="utf-8") as fh:
        fh.write(_FAKE_SYSTEMCTL31)
    os.chmod(os.path.join(work, "systemctl"), 0o700)  # nosemgrep - owner-only test stand-in
    log = os.path.join(work, "calls.log")
    r = _sp31.run(["bash", "-c", "set -euo pipefail\nwarn() { echo \"WARN $*\"; }\n" + fn  # nosec B603 B607
                   + 'stop_terminal_scopes "/system.slice/linuxgsm-panel-terminal-lgsmpanel-990-2a2b2c2d.scope"\n'
                   + 'echo "[rc=$?]"'], capture_output=True, text=True, timeout=30, check=False,
                  env=dict(os.environ, PATH=work + ":" + os.environ.get("PATH", ""), LOG31=log))
    calls = []
    if os.path.exists(log):
        with open(log, encoding="utf-8") as fh:
            calls = fh.read().splitlines()
    stops = [c for c in calls if c.startswith("stop ")]
    check("uninstall.sh stop_terminal_scopes: every linuxgsm-panel-terminal scope is stopped (a failed "
          "one's bullet included); a game server's scope is not, nor the one the uninstall runs in, "
          "which is named instead",
          stops == ["stop linuxgsm-panel-terminal-lgsmpanel-812-0a0b0c0d.scope",
                    "stop linuxgsm-panel-terminal-lgsmpanel-955-1a1b1c1d.scope"]
          and "WARN Left linuxgsm-panel-terminal-lgsmpanel-990-2a2b2c2d.scope running" in r.stdout
          and "[rc=0]" in r.stdout, repr((calls, r.stdout, r.stderr[-300:])))
    call = 'stop_terminal_scopes "$('
    deluser = 'userdel -r "${PANEL_USER}"'
    check("uninstall.sh: a system uninstall stops the terminal scopes after the panel's unit and "
          "BEFORE it deletes the panel user (userdel refuses an account with a live process)",
          code.count(call) == 1 and code.index("svc disable --now linuxgsm-panel.service")
          < code.index(call) < code.index(deluser)
          and 'if [[ "${MODE}" = "system" ]]; then\n    ' + call in code,
          repr((code.count(call), code.count(deluser))))


for _fn31 in (_check_lgsm_start31, _check_scope_wait31, _check_scope_never31, _check_start_scope31, _check_lgsm_other31,
              _check_cron_now31, _check_adopt31, _check_cgroup_pids31,
              _check_terminal_scope31, _check_jobs31, _check_job_entry31, _check_os_update_job31,
              _check_no_systemd31, _check_reboot31, _check_constants31, _check_backup31,
              _check_run_now31, _check_run_now_refused31, _check_user_scope31,
              _check_user_scope_probe31, _check_terminal31,
              _check_restore31, _check_system_ops31, _check_app31, _check_report31, _check_journal31,
              _check_crontab31, _check_keeper31, _check_uninstall_scopes31):
    try:
        _fn31()
    except Exception as _e31:  # noqa: BLE001 - a crashed block is a FAILED check, by name
        check("part31: %s ran to the end" % _fn31.__name__, False, "%s: %s" % (type(_e31).__name__, _e31))
_sh31.rmtree(_TMP31, ignore_errors=True)
