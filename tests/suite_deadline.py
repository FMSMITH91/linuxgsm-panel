"""A time limit for one test suite: past it, the suite prints where it is stuck and exits 124.

WHY. The ubuntu-22.04 CI leg's unit suite froze on 2026-11-05 (job 127232926754) and sat until it
was cancelled half an hour later. A suite prints its checks only once it has finished, and a
cancelled job prints nothing of a lane still running, so the log said nothing about where. What the
runner's orphan list did say: the suite's python was alive with no child process, so it was waiting
inside its own process (a lock, a socket, the eventlet hub), not on a command.

WHAT. Each suite runner calls arm(globals()) before anything that could block. At the limit:

  1. SIGALRM runs a handler on the main thread. It prints the suite, the part it was in and the
     last check it recorded, every OS thread's stack (faulthandler), every suspended greenlet's
     stack (the unit and smoke suites run eventlet-patched, where a stuck "thread" is a greenlet
     that faulthandler cannot see), and the processes below it, which it then kills so that no
     pipe stays open behind it. Then it exits 124, which `timeout` uses for the same thing.
  2. A signal handler cannot run while the main thread is inside C code that never returns to the
     interpreter. So faulthandler's own watchdog, a C thread, dumps every thread and exits the
     process BACKSTOP seconds later if the handler has not ended it.

The limits clear the slowest run measured by a wide margin (see LIMITS). LGSM_SUITE_DEADLINE
overrides them: a number of seconds for every suite, or 0 to switch the limit off.
"""

import faulthandler
import gc
import os
import signal
import sys
import traceback

# Seconds. Measured on CI over the 30 ubuntu-22.04 runs of 2026-10-24 to 2026-11-05 (the slowest
# leg): the unit suite took 713-1181 s as root and up to 1164 s in its lane; coverage's unit run took
# 722-855 s. Every other suite takes under 4 minutes (smoke, the slowest, 160-215 s). The unit
# limit is under the step's timeout-minutes in ci.yml, so the suite reports itself before the job is
# killed without a word; tests/unit/part143.py holds the two in that order.
LIMITS = {"unit": 2100}
DEFAULT_LIMIT = 900
BACKSTOP = 60
EXIT_CODE = 124
ENV = "LGSM_SUITE_DEADLINE"

_state = {}


def limit_for(suite, environ=None):
    """The limit in seconds for `suite` (0 = off), from LGSM_SUITE_DEADLINE or LIMITS."""
    raw = (os.environ if environ is None else environ).get(ENV, "").strip()
    if raw:
        try:
            return max(0.0, float(raw))
        except ValueError:
            print("suite_deadline: %s=%r is not a number of seconds; using the default" % (ENV, raw),
                  file=sys.stderr)
    return float(LIMITS.get(suite, DEFAULT_LIMIT))


def suite_name(path):
    """'tests/unit_test.py' -> 'unit'."""
    base = os.path.basename(path)
    return base[:-len("_test.py")] if base.endswith("_test.py") else base.rsplit(".", 1)[0]


def _where(where_globals):
    """The part the suite is in and the last check it recorded, read when the limit fires."""
    lines = []
    part = where_globals.get("_part")
    if part:
        lines.append("in part: %s" % (part,))
    results = where_globals.get("results")
    if isinstance(results, list):
        lines.append("checks recorded so far: %d" % len(results))
        if results:
            lines.append("the last one recorded (the hang is AFTER it): %s" % (repr(results[-1])[:400],))
    return lines


def _greenlet_stacks():
    """The stack of every greenlet that is suspended mid-call (the running one is in the dump)."""
    try:
        import greenlet  # noqa: F401 - only present where eventlet is installed
    except ImportError:
        return []
    out = []
    for obj in gc.get_objects():
        try:
            if isinstance(obj, greenlet.greenlet) and obj.gr_frame is not None:
                out.append((obj, "".join(traceback.format_stack(obj.gr_frame))))
        except Exception:  # nosec B112 - a half-torn-down greenlet must not stop the dump
            continue
    return out


def _descendants(root_pid):
    """[(pid, state, cmdline)] of every process below root_pid, read from /proc."""
    children = {}
    info = {}
    try:
        pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return []
    for pid in pids:
        try:
            with open("/proc/%d/stat" % pid, "rb") as fh:
                stat = fh.read().decode("utf-8", "replace")
            with open("/proc/%d/cmdline" % pid, "rb") as fh:
                cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            continue
        rest = stat.rsplit(")", 1)[-1].split()
        if len(rest) < 2:
            continue
        info[pid] = (rest[0], cmd[:300])
        children.setdefault(int(rest[1]), []).append(pid)
    found, todo = [], list(children.get(root_pid, []))
    while todo:
        pid = todo.pop(0)
        found.append((pid,) + info[pid])
        todo.extend(children.get(pid, []))
    return found


def _unpatched(name, fallback):
    """The module eventlet would have replaced, as it was.

    eventlet's green write trampolines to the hub when the pipe is full, which the handler, running
    on the hub, cannot do.
    """
    try:
        from eventlet import patcher
        return patcher.original(name)
    except ImportError:
        return fallback


def _write(text):
    """All of `text` to the report descriptor, waiting out a full pipe with the unpatched calls."""
    fd, data = _state["fd"], text.encode("utf-8", "replace")
    raw_os, raw_select = _unpatched("os", os), _unpatched("select", None)
    while data:
        try:
            data = data[raw_os.write(fd, data):]
        except BlockingIOError:
            if raw_select is not None:
                raw_select.select([], [fd], [], 5)
        except OSError:
            return


def _fire(signum=None, frame=None):
    w = _write
    w("\n" + "!" * 100 + "\n")
    w("SUITE TIME LIMIT: tests/%s_test.py ran past %ds and is stopped here (exit %d).\n"
      % (_state["suite"], _state["limit"], EXIT_CODE))
    w("Every thread's and every suspended greenlet's stack follows. %s=<seconds> changes the "
      "limit, 0 switches it off.\n" % ENV)
    for line in _where(_state["globals"]):
        w("  " + line + "\n")
    w("\n-- OS threads (the main thread's top frame is this handler; the frame under it is where "
      "it was) --\n")
    faulthandler.dump_traceback(file=_state["fd"], all_threads=True)
    stacks = _greenlet_stacks()
    w("\n-- %d suspended greenlet(s) --\n" % len(stacks))
    for i, (g, stack) in enumerate(stacks, 1):
        w("greenlet %d: %r\n%s\n" % (i, g, stack))
    procs = leftovers()
    w("-- %d process(es) below this one or holding its output (killed now, so none holds a pipe open) --\n" % len(procs))
    for pid, st, cmd in procs:
        w("  pid %d state %s: %s\n" % (pid, st, cmd))
    w("!" * 100 + "\n")
    kill(procs)
    os._exit(EXIT_CODE)


def descendants(root_pid=None):
    """[(pid, state, cmdline)] of every live process below root_pid (default: this one)."""
    return [p for p in _descendants(os.getpid() if root_pid is None else root_pid) if p[1] != "Z"]


def _ancestors():
    # Down to 0, the parent of pid 1: in a container the suite itself can be pid 1.
    pids, pid = set(), os.getpid()
    while pid > 0:
        pids.add(pid)
        try:
            with open("/proc/%d/stat" % pid, "rb") as fh:
                pid = int(fh.read().decode("utf-8", "replace").rsplit(")", 1)[-1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return pids


def _writes_to(pid, fdname, target):
    """Whether pid's descriptor `fdname` is `target` opened for writing."""
    base = "/proc/%d" % pid
    try:
        if os.readlink("%s/fd/%s" % (base, fdname)) != target:
            return False
        with open("%s/fdinfo/%s" % (base, fdname)) as fh:
            flags = next((ln.split()[1] for ln in fh if ln.startswith("flags:")), "0")
        return int(flags, 8) & 3 in (1, 2)
    except (OSError, ValueError, StopIteration):
        return False


def holders(fd=1):
    """[(pid, state, cmdline)] of the other processes holding this one's `fd` open for writing.

    Not this process or its ancestors; only a pipe or a file. A pipe's reader (`| tee`) waits for
    every one of them, even one that has left this process's tree (`sleep 600 &` from a shell that
    exited is the init process's child, and in no list of descendants).
    """
    try:
        target = os.readlink("/proc/self/fd/%d" % fd)
    except OSError:
        return []
    if not (target.startswith("pipe:") or target.startswith("/")) or target.startswith("/dev/"):
        return []
    skip = _ancestors()
    return [(pid, "?", _cmdline(pid)) for pid in _pids()
            if pid not in skip and _holds(pid, target)]


def _pids():
    try:
        return [int(n) for n in os.listdir("/proc") if n.isdigit()]
    except OSError:
        return []


def _holds(pid, target):
    try:
        fds = os.listdir("/proc/%d/fd" % pid)
    except OSError:
        return False
    return any(_writes_to(pid, f, target) for f in fds)


def _cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as fh:
            return fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()[:300]
    except OSError:
        return "?"


def leftovers():
    """Everything that would outlive the suite, each (pid, state, cmdline) once.

    Its live descendants, and any other process holding its stdout or stderr for writing.
    """
    seen, out = set(), []
    for proc in descendants() + holders(1) + holders(2):
        if proc[0] not in seen:
            seen.add(proc[0])
            out.append(proc)
    return out


def kill(procs):
    """SIGKILL each (pid, ...) in procs; one already gone is skipped."""
    for proc in procs:
        try:
            os.kill(proc[0], signal.SIGKILL)
        except OSError:  # nosec B110 - already gone
            pass


def arm(caller_globals, environ=None, backstop=BACKSTOP):
    """Start the limit for the suite whose runner's globals these are. Returns the limit (0 = off).

    `backstop` is how long after the limit faulthandler's watchdog ends the process if the handler
    could not run (tests/unit/part143.py shortens it to watch it fire). The timer stays armed
    through interpreter exit, so a suite that prints its tally and then hangs on the way out (a
    thread it waits for, an atexit hook) is reported the same way.
    """
    suite = suite_name(caller_globals.get("__file__") or sys.argv[0])
    limit = limit_for(suite, environ)
    if limit <= 0:
        return 0
    # A descriptor of its own: a check that swaps sys.stderr, or points fd 2 elsewhere for a while,
    # must not take the report with it. Not inherited by anything the suite starts (PEP 446).
    _state.update(fd=os.dup(2), suite=suite, limit=limit, globals=caller_globals)
    signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, limit)
    faulthandler.dump_traceback_later(limit + backstop, exit=True, file=_state["fd"])
    return limit
