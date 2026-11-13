"""Part 143 of the unit suite: a suite past its time limit says where it is stuck and fails fast.

The ubuntu-22.04 leg's unit suite froze on 2026-11-05 and was cancelled 32 minutes in with no word
of where: a suite prints its checks only at the end, and a cancelled job prints nothing of a lane
still running. tests/suite_deadline.py gives every suite a limit. Held here:

* every tests/*_test.py runner arms it before it imports the panel or anything else that can block;
* the limits: the unit suite's 35 minutes, the others' 15, the LGSM_SUITE_DEADLINE override;
* run for real in a child interpreter with a 1 s limit: a main thread stuck on a lock is named; under
  eventlet, a parked greenlet and the main greenlet's own wait are named, and a child process is
  listed and killed; with SIGALRM blocked, faulthandler's watchdog still ends it;
* ci.yml's "Run all checks" step has its own timeout-minutes, above the unit limit plus the watchdog
  and the step's work ahead of the lanes, and under the job's.
* the cause the stacks showed: eventlet's green os.write retried EPIPE for ever, so communicate(input)
  to a child that exits unread never returned; panel/core/green_write.py, installed by app.py.
"""
import glob
import importlib.util as _ilu143
import os
import re
import sys
import tempfile as _tf143
import time

from eventlet import patcher as _patcher143
from eventlet.green import os as _green_os143

from unit.part01 import check
from unit.part05 import _root
from unit.part14 import _wf14
from unit.part29 import _CI_ROOT29, _U29, _verdict29
from unit.part06 import _wf_run_block

_sp143 = _patcher143.original("subprocess")
_subprocess143 = sys.modules["subprocess"]  # the suite's own, greened by app.py's monkey_patch
_SD143_PATH = os.path.join(_root, "tests", "suite_deadline.py")
_spec143 = _ilu143.spec_from_file_location("suite_deadline_p143", _SD143_PATH)
SD143 = _ilu143.module_from_spec(_spec143)
_spec143.loader.exec_module(SD143)


# ── every runner arms it, before anything that can block ──────────────────────────────────────
def _code143(text):
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def _armed_early143(path):
    """(arms, line of the arm call, line of the first import that can block) for one runner.

    The unit suite arms after its Landlock block, which needs the process to have one thread
    (faulthandler's watchdog is a second), and so after the two panel imports ahead of it; it must
    still come before the first panel module that starts anything and before any part runs.
    """
    with open(path, encoding="utf-8") as fh:
        code = _code143(fh.read())
    arm = next((i for i, ln in enumerate(code) if re.search(r"\barm\(globals\(\)(, results_from=\"[\w.]+\")?\)\s*(#.*)?$", ln)), -1)
    first_re = (r'importlib\.import_module\("panel\.|^for _part in _PARTS:' if path.endswith("unit_test.py")
                else r"\s*(from (app|panel|manage|smoke|unit)[ .]|import (app|panel|manage|unit)\b)")
    first = next((i for i, ln in enumerate(code) if re.search(first_re, ln)), len(code))
    return arm >= 0, arm, first


_runners143 = sorted(glob.glob(os.path.join(_root, "tests", "*_test.py")))
_armed143 = {os.path.basename(p): _armed_early143(p) for p in _runners143}
check("suite deadline: every tests/*_test.py runner arms the time limit, before it imports the panel, "
      "the app or a part",
      len(_armed143) >= 9 and all(a and i < f for a, i, f in _armed143.values()), repr(_armed143))

# ── the limits ────────────────────────────────────────────────────────────────────────────────
_lims143 = {
    "unit": SD143.limit_for("unit", {}), "smoke": SD143.limit_for("smoke", {}),
    "rbac": SD143.limit_for("rbac", {}), "override": SD143.limit_for("unit", {SD143.ENV: "7"}),
    "off": SD143.limit_for("smoke", {SD143.ENV: "0"}), "junk": SD143.limit_for("unit", {SD143.ENV: "x"}),
    "name": SD143.suite_name("/a/tests/template_actions_test.py"),
}
check("suite deadline: the unit suite gets 35 minutes and every other suite 15; LGSM_SUITE_DEADLINE "
      "sets seconds for all, 0 switches it off, and a value that is no number keeps the default",
      _lims143 == {"unit": 2100.0, "smoke": 900.0, "rbac": 900.0, "override": 7.0, "off": 0.0,
                   "junk": 2100.0, "name": "template_actions"}, repr(_lims143))
check("suite deadline: ...and switched off, arm() starts nothing",
      SD143.arm({"__file__": "x_test.py"}, {SD143.ENV: "0"}) == 0)

# ── fired for real, in a child interpreter ────────────────────────────────────────────────────
_PRE143 = (
    "import importlib.util, os, signal, subprocess, sys, threading, time\n"
    "s = importlib.util.spec_from_file_location('suite_deadline', %r)\n"
    "sd = importlib.util.module_from_spec(s); s.loader.exec_module(sd)\n"
    "results = [(True, 'the check before the hang', '')]\n"
    "_part = 'part99'\n" % _SD143_PATH)
_LOCK143 = _PRE143 + (
    "sd.arm(globals())\n"
    "def _stuck_on_a_lock_143():\n"
    "    lk = threading.Lock(); lk.acquire(); lk.acquire()\n"
    "_stuck_on_a_lock_143()\n")
_GREEN143 = (
    "import eventlet\neventlet.monkey_patch()\n" + _PRE143 +
    "from eventlet import event\n"
    "sd.arm(globals())\n"
    "ev = event.Event()\n"
    "def _parked_greenlet_143():\n"
    "    ev.wait()\n"
    "eventlet.spawn(_parked_greenlet_143)\n"
    "child = subprocess.Popen(['sleep', '30'])\n"
    "print('CHILD', child.pid, flush=True)\n"
    "def _main_greenlet_waits_143():\n"
    "    eventlet.sleep(30)\n"
    "_main_greenlet_waits_143()\n")
_MASKED143 = _PRE143 + (
    "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})\n"
    "sd.arm(globals(), backstop=1)\n"
    "def _deaf_to_signals_143():\n"
    "    time.sleep(30)\n"
    "_deaf_to_signals_143()\n")


def _fire143(source, name):
    """(rc, output, seconds) of `source` run as tests/<name>_test.py with a 1 s limit."""
    work = _tf143.mkdtemp(prefix="p143-")
    path = os.path.join(work, name + "_test.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(source)
    env = dict(os.environ, **{SD143.ENV: "1"})
    t0 = time.monotonic()
    try:
        p = _sp143.run([sys.executable, path], capture_output=True, text=True, timeout=25,  # nosec B603 - this interpreter on the suite's own script
                       env=env, cwd=work)
        return p.returncode, p.stdout + p.stderr, time.monotonic() - t0
    except _sp143.TimeoutExpired as exc:
        return "timed out", str(exc.stdout or "") + str(exc.stderr or ""), time.monotonic() - t0


def _alive143(pid):
    try:
        with open("/proc/%d/stat" % pid) as fh:
            return fh.read().rsplit(")", 1)[-1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


_lk143 = _fire143(_LOCK143, "locked")
check("suite deadline: a main thread stuck on a lock is stopped at the limit with exit 124, and the "
      "report names the suite, the part, the last check and the function it is stuck in",
      _lk143[0] == 124 and _lk143[2] < 15
      and "SUITE TIME LIMIT: tests/locked_test.py ran past 1s" in _lk143[1]
      and "in part: part99" in _lk143[1] and "the check before the hang" in _lk143[1]
      and "_stuck_on_a_lock_143" in _lk143[1], repr((_lk143[0], round(_lk143[2], 1), _lk143[1][-1500:])))

_gr143 = _fire143(_GREEN143, "green")
_child143 = re.search(r"^CHILD (\d+)$", _gr143[1], re.M)
_gr_sec143 = _gr143[1].split("suspended greenlet(s) --", 1)[-1]
check("suite deadline: under eventlet the report shows the parked greenlet and the main greenlet's "
      "own wait, which faulthandler cannot see",
      _gr143[0] == 124 and "_parked_greenlet_143" in _gr_sec143 and "_main_greenlet_waits_143" in _gr_sec143,
      repr((_gr143[0], _gr143[1][-2000:])))
check("suite deadline: ...and the child process it started is listed and killed, so no pipe stays "
      "open behind the suite",
      bool(_child143) and "sleep 30" in _gr143[1] and not _alive143(int(_child143.group(1))),
      repr((_child143 and _child143.group(1), _gr143[1][-800:])))

_mk143 = _fire143(_MASKED143, "masked")
check("suite deadline: with SIGALRM blocked, so the handler cannot run, faulthandler's watchdog still "
      "dumps the threads and ends the process soon after",
      _mk143[0] not in (0, "timed out", 124) and _mk143[2] < 15 and "_deaf_to_signals_143" in _mk143[1]
      and "SUITE TIME LIMIT" not in _mk143[1], repr((_mk143[0], round(_mk143[2], 1), _mk143[1][-800:])))


# ── ci.yml: the step's own limit sits above the unit limit, under the job's ───────────────────
def _step_timeout143(text, job, step):
    """(step timeout-minutes, job timeout-minutes) read from ci.yml's text, 0 when absent."""
    m = re.search(r"^  %s:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)" % re.escape(job), text, re.M | re.S)
    body = m.group(1) if m else ""
    jt = re.search(r"^    timeout-minutes: (\d+)\s*$", body, re.M)
    s = re.search(r"^      - name: %s\n(.*?)(?=^      - |\Z)" % re.escape(step), body, re.M | re.S)
    st = re.search(r"^        timeout-minutes: (\d+)\s*$", s.group(1), re.M) if s else None
    return (int(st.group(1)) if st else 0, int(jt.group(1)) if jt else 0)


_ci143 = _step_timeout143(_wf14("ci.yml"), "checks", "Run all checks (compile, lint, unit, smoke, shellcheck)")
# 120 s: the compile, lint and shellcheck ahead of the lanes took 17-34 s on the 22.04 leg.
check("ci.yml: the \"Run all checks\" step has its own timeout, above the unit suite's limit plus the "
      "watchdog and the work ahead of the lanes, and under the job's",
      _ci143[0] * 60 >= SD143.LIMITS["unit"] + SD143.BACKSTOP + 120 and 0 < _ci143[0] < _ci143[1],
      repr(_ci143))


# ── the end-of-run gate's reader (tests/unit/part15) sees a process that left the tree ────────
# `sleep 600 &` from a shell that then exits is the init process's child: no list of this
# process's descendants has it, yet it holds the suite's stdout, so `| tee` would wait on it.
def _r42t_stand_in143(out_fd, pid_path):
    """Start `sleep 600 &` behind a shell that exits, holding out_fd as its stdout; its pid, or 0."""
    _sp143.Popen(["bash", "-c", 'exec 2>&1; sleep 600 & echo $! >"$1"', "_", pid_path],  # nosec B603 B607 - a fixed stand-in
                 stdout=out_fd).wait()
    try:
        with open(pid_path) as fh:
            return int(fh.read().strip() or 0)
    except (OSError, ValueError):
        return 0


def _r42t_find_kill143():
    """(what leftovers() saw of the stand-in within 5 s, the holders of fd 1, what is left after kill)."""
    deadline, seen = time.monotonic() + 5, []
    while time.monotonic() < deadline and not seen:
        seen = [p for p in SD143.leftovers() if p[2] == "sleep 600"]
        if not seen:
            time.sleep(0.05)
    held = [p[0] for p in SD143.holders(1)]
    SD143.kill(seen)
    time.sleep(0.2)
    return seen, held, [p for p in SD143.leftovers() if p[2] == "sleep 600"]


def _leaked143():
    """What leftovers() saw of a `sleep 600 &` started behind a shell that exited, and after kill.

    The suite's stdout is pointed at a file of the check's own for the probe, so the result does not
    depend on where the suite's output goes (a terminal is never read as a holder), and the stand-in
    is killed by its pid whatever was found.
    """
    tmp = _tf143.mkdtemp(prefix="r42t-leak143-")
    sink = os.open(os.path.join(tmp, "out"), os.O_WRONLY | os.O_CREAT, 0o600)
    sys.stdout.flush()
    real_out, pids = os.dup(1), []
    try:
        os.dup2(sink, 1)
        pids.append(_r42t_stand_in143(sink, os.path.join(tmp, "pid")))
        seen, held, after = _r42t_find_kill143()
    finally:
        sys.stdout.flush()
        os.dup2(real_out, 1)
        os.close(real_out)
        os.close(sink)
        SD143.kill([(p,) for p in pids if p])
    return seen, after, held


_leak143 = _leaked143()
check("suite deadline: leftovers() names a `sleep 600 &` that has left the suite's process tree but "
      "still holds its output (found as a holder of it, the suite itself never one), and kill() ends it",
      len(_leak143[0]) == 1 and not _leak143[1]
      and _leak143[0][0][0] in _leak143[2] and os.getpid() not in _leak143[2], repr(_leak143))


# ── the root run's output is a file nobody prints: the judging step shows how it ended ────────
# 2026-11-05 (#474's own CI): the root unit run hit its limit and the step said only "left no
# tally"; the report suite_deadline wrote went to unit-root.txt and was lost with the runner.
def _root_end143():
    ci = _wf14("ci.yml")
    src = _wf_run_block(ci, _CI_ROOT29) if _CI_ROOT29 in ci else "<<'EOF'\n\nEOF"
    code = src[src.find("<<'EOF'\n") + 8:src.rfind("\nEOF")]
    tmp = _tf143.mkdtemp(prefix="p143-root-")
    stopped = ("PASS  a\n" + "noise\n" * 300 + "!" * 100 + "\nSUITE TIME LIMIT: tests/unit_test.py ran past "
               "2100s\n  in part: part41\nFile \"x.py\", line 9 in _stuck_here_143\n")
    return _verdict29(code, tmp, _U29, stopped), _verdict29(code, tmp, _U29, "PASS  a\n" + "line\n" * 400)


_re143 = _root_end143()
check("ci root step: a root run that stopped without a tally gets its time-limit report printed, "
      "from the report's first line, before the step fails",
      _re143[0][0] == 1 and "SUITE TIME LIMIT" in _re143[0][1] and "_stuck_here_143" in _re143[0][1]
      and "the end of the unit run as root" in _re143[0][1] and "noise" not in _re143[0][1], repr(_re143[0]))
check("ci root step: ...and one with no report gets its last 150 lines",
      _re143[1][0] == 1 and _re143[1][1].count("line\n") == 150, repr((_re143[1][0], _re143[1][1][-300:])))


# ── the cause: eventlet's green os.write retried a broken pipe forever ────────────────────────
# 2026-11-05: the stacks of #474's stopped runs ended in eventlet/green/os.py write() under
# subprocess._communicate: part142 handed `bash tools/sign-release.sh <id>` an input line it exits
# without reading, and a green write to a pipe with no reader goes round its EPIPE retry for ever.
# panel/core/green_write.py lets it raise BrokenPipeError, which _communicate is written to catch.
_EPIPE143 = (
    "import sys\n"
    "sys.path.insert(0, %r)\n"
    "import eventlet\n"
    "eventlet.monkey_patch()\n"
    "from panel.core import green_write\n"
    "print('installed', green_write.install(), green_write.install())\n"
    "import subprocess\n"
    "p = subprocess.Popen(['true'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,\n"
    "                     stderr=subprocess.PIPE)\n"
    "p.wait()\n"
    "p.communicate(b'abc\\n')\n"
    "print('communicate returned', p.returncode)\n"
    "r = subprocess.run(['true'], input='x' * 200000, capture_output=True, text=True, timeout=5)\n"
    "print('run returned', r.returncode)\n") % _root


def _epipe143():
    try:
        p = _sp143.run([sys.executable, "-c", _EPIPE143], capture_output=True, text=True,  # nosec B603 - this interpreter on a fixed probe
                       timeout=20, cwd=_root)
        return p.returncode, p.stdout + p.stderr
    except _sp143.TimeoutExpired as exc:
        return "timed out", str(exc.stdout or "") + str(exc.stderr or "")


_ep143 = _epipe143()
check("green write: under eventlet, communicate(input) and run(input=) to a child that exits without "
      "reading return at once instead of spinning on EPIPE for ever",
      _ep143[0] == 0 and "installed True True" in _ep143[1] and "communicate returned 0" in _ep143[1]
      and "run returned 0" in _ep143[1], repr(_ep143))
check("green write: app.py installs it, so the suite's (and the panel's) os.write, subprocess's and "
      "eventlet's green os module's are all the one that raises",
      all(getattr(w, "lgsm_epipe_raises", False)
          for w in (os.write, _subprocess143.os.write, _green_os143.write)),
      repr((os.write, _subprocess143.os.write, _green_os143.write)))
