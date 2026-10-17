"""The unit suite's OS-level block on the machine's own `tailscale` (Landlock). Not a test part.

WHY. tests/unit_test.py's tailscale guard reads a shell script's TEXT and predicts whether the shell
will reach the machine's binary. Every review pass from 1011e to 1017b found new shapes it misread
(a nested `bash -o pipefail -c`, a line continuation before `#`, `X=1 . file`, BASH_ENV, a `.` in
backticks), each one running the real CLI against the owner's live node. A reader of shell text
cannot be finished. So the kernel answers instead: Landlock (Linux 5.13+, unprivileged, in Ubuntu's
default LSM list since 22.04 and in this repo's dev machine's) denies EXECUTE and READ_FILE on the
machine's `tailscale`/`tailscaled` files to this process and to everything it starts, whatever
PATH, wrapper, shell or spawner reaches them. The text reader stays in front for fidelity: it
answers "not installed" (FileNotFoundError, rc 127) as CI's runner does, where this block answers
"permission denied"; a shape it misreads now fails a check instead of reading the real node.

Why not a mount namespace bind-mounting a stand-in over the binary: an unprivileged one needs a user
namespace, which (1) maps every other uid/gid to nobody, changing what ownership and group checks
read, and (2) is refused capabilities on GitHub's Ubuntu 24.04 runners by AppArmor's
apparmor_restrict_unprivileged_userns (actions/runner-images#10443). Landlock changes neither ids nor
anything but the two rights on the named files. It sets no_new_privs, so a setuid `sudo` started
under it cannot gain root, which a unit check must never do anyway.

Landlock only ALLOWS, so "deny these files" is written as "allow everything else": every entry of
every directory on the way to a blocked file, other than that way itself, is allowed beneath. An
entry created later directly in one of those directories (/, /usr, /usr/bin for a packaged CLI) is
not allowed: a package update during the run that writes `bash` or `python3.x` as a new file and
renames it in makes every later run of it fail with EACCES, and a CLI in ~/bin makes $HOME a way.
That limit cannot be narrowed without allowing the blocked file (a rule allows a whole tree), so it
is SAID: the runner prints header() once when the block is on, and a failing check whose detail is
a permission error gets failure_note() (both name Landlock).

    python -I tests/unit/ts_landlock.py <job.json> <result.json>   # run_shapes, in its own process
"""
import ctypes
import os
import shutil
import struct
import sys

_SYS_CREATE_RULESET, _SYS_ADD_RULE, _SYS_RESTRICT_SELF = 444, 445, 446  # the same on every arch
_CREATE_RULESET_VERSION = 1
_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
# LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE: run it, or read it to copy it and run it.
RIGHTS = (1 << 0) | (1 << 2)
# LANDLOCK_ACCESS_FS_REFER (ABI 2+), handled and allowed wherever the rest is: under any ruleset that
# does not handle it, the kernel refuses every link or rename across directories (EXDEV), and the
# suite makes such links (part05's restore staging did, the first run under this block).
_REFER = 1 << 13
NAMES = ("tailscale", "tailscaled")
# Where a CLI lives that is not on PATH at start: ~/bin and ~/.local/bin are on Ubuntu's login PATH
# only when they existed at login, and `go install` writes ~/go/bin.
_HOME_DIRS = ("bin", ".local/bin", "go/bin")
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"


def machine_binaries(path=None, home=None):
    """Every `tailscale`/`tailscaled` file the machine has where a command could find it, resolved."""
    _dirs = (path if path is not None else os.environ.get("PATH", os.defpath)).split(os.pathsep)
    _dirs += DEFAULT_PATH.split(os.pathsep)
    _home = home if home is not None else os.path.expanduser("~")
    _dirs += [os.path.join(_home, _d) for _d in _HOME_DIRS]
    _found = set()
    for _d in _dirs:
        for _n in NAMES:
            _p = shutil.which(_n, path=_d or ".")
            if _p is not None:
                _found.add(os.path.realpath(_p))
    return sorted(_found)


def _ways(blocked):
    """Every directory on the way from / to each of `blocked`."""
    _way = set()
    for _b in blocked:
        _d = os.path.dirname(_b)
        while _d not in _way:
            _way.add(_d)
            _d = os.path.dirname(_d)
    return _way


def _allowed_paths(blocked):
    """The paths to allow beneath so that everything but `blocked` (resolved files) is allowed."""
    _blocked = {os.path.realpath(_b) for _b in blocked}
    _way = _ways(_blocked)
    _out = []
    for _d in sorted(_way):
        try:
            _names = os.listdir(_d)
        except OSError:
            continue        # unreadable: nothing in it is allowed, which only denies more
        for _n in _names:
            _p = os.path.join(_d, _n)
            # A link is not a rule: what it resolves to is judged by its own path (/bin -> usr/bin).
            if _p in _blocked or _p in _way or os.path.islink(_p):
                continue
            _out.append(_p)
    return _out


def _libc():
    _c = ctypes.CDLL(None, use_errno=True)
    _c.syscall.restype = ctypes.c_long
    return _c


def abi():
    """The kernel's Landlock ABI version, or 0 with the reason when it has none."""
    _c = _libc()
    _v = _c.syscall(ctypes.c_long(_SYS_CREATE_RULESET), None, ctypes.c_size_t(0),
                    ctypes.c_uint32(_CREATE_RULESET_VERSION))
    if _v < 0:
        return 0, os.strerror(ctypes.get_errno())
    return int(_v), ""


def _rights_here(blocked, refer):
    """(the rights a ruleset here handles, or 0, and why not when 0)."""
    if not blocked:
        raise ValueError("nothing to block")
    _tasks = len(os.listdir("/proc/self/task"))
    if _tasks != 1:
        return 0, "the process has %d threads; only the calling one would be restricted" % _tasks
    _v, _why = abi()
    if _v < 1:
        return 0, "Landlock is not available here (%s; /sys/kernel/security/lsm must list landlock)" % _why
    if _v < 2 and refer:
        return 0, "Landlock ABI %d here; 2 or later is needed to keep links across directories working" % _v
    return RIGHTS | (_REFER if _v >= 2 else 0), ""


def _add_rule(c, rs, path, rights):
    """Allow `rights` beneath `path` in ruleset `rs`; "" when added (or the path cannot be opened)."""
    try:
        _fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        return ""          # not allowed, which only denies more
    try:
        # struct landlock_path_beneath_attr is packed: a u64 then an s32, 12 bytes. REFER is a
        # directory's right: a file's rule holding it is refused (EINVAL).
        _rule = ctypes.create_string_buffer(struct.pack("=Qi", rights if os.path.isdir(path) else RIGHTS, _fd), 12)
        if c.syscall(ctypes.c_long(_SYS_ADD_RULE), ctypes.c_int(rs), ctypes.c_int(_RULE_PATH_BENEATH),
                     _rule, ctypes.c_uint32(0)) < 0:
            return "landlock_add_rule(%s): %s" % (path, os.strerror(ctypes.get_errno()))
        return ""
    finally:
        os.close(_fd)


def block(blocked, refer=True):
    """Deny RIGHTS on `blocked` to this process and its children; "" when held, else why not.

    Only the calling thread is restricted (and what it starts later), so it is called while the
    process has one thread. An empty `blocked` would allow nothing at all, and is refused. A kernel
    with ABI 1 cannot allow cross-directory links under a ruleset, so it is refused unless `refer` is
    False (a child that makes none).
    """
    _rights, _why = _rights_here(blocked, refer)
    if not _rights:
        return _why
    _c = _libc()
    _attr = ctypes.c_uint64(_rights)
    _rs = _c.syscall(ctypes.c_long(_SYS_CREATE_RULESET), ctypes.byref(_attr), ctypes.c_size_t(8),
                     ctypes.c_uint32(0))
    if _rs < 0:
        return "landlock_create_ruleset: %s" % os.strerror(ctypes.get_errno())
    try:
        _err = next((_e for _e in (_add_rule(_c, _rs, _p, _rights) for _p in _allowed_paths(blocked)) if _e), "")
        if _err:
            return _err
        if _c.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            return "prctl(NO_NEW_PRIVS): %s" % os.strerror(ctypes.get_errno())
        if _c.syscall(ctypes.c_long(_SYS_RESTRICT_SELF), ctypes.c_int(_rs), ctypes.c_uint32(0)) < 0:
            return "landlock_restrict_self: %s" % os.strerror(ctypes.get_errno())
    finally:
        os.close(_rs)
    return ""


# A failing check's detail that reads as the kernel's refusal (EACCES).
_EACCES_WORDS = ("Permission denied", "PermissionError", "EACCES", "Errno 13")


def header(blocked):
    """The run's one line when the block is on: what it denies, and the limit _allowed_paths has."""
    _way = sorted(_ways({os.path.realpath(_b) for _b in blocked}))
    return ("Landlock block active: %s cannot be run or read by this run or anything it starts. A file "
            "created or replaced after now directly in %s is denied the same way (EACCES) until the run "
            "ends: a package update during the run does that, so re-run the suite after one."
            % (", ".join(blocked), ", ".join(_way)))


def failure_note(detail, blocked):
    """What a failing check's `detail` gets when it is a permission error under the block, else ""."""
    if not blocked or not any(_w in str(detail) for _w in _EACCES_WORDS):
        return ""
    return ("  (Landlock block active: a file created or replaced since the run began directly in %s "
            "is denied, which may be this; see the run's first line)"
            % ", ".join(sorted(_ways({os.path.realpath(_b) for _b in blocked}))))


def late_entry(directory):
    """Make a script directly in `directory` and run it: "ran", or the error it met (the block's limit)."""
    import subprocess  # nosec B404 - runs only the script it has just written
    _p = os.path.join(directory, "late-entry")
    with open(_p, "w", encoding="utf-8") as _fh:
        _fh.write("#!/bin/sh\necho late\n")
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700, owner-only
    os.chmod(_p, 0o700)  # nosec B103 - the test's own temp dir
    try:
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
        _r = subprocess.run([_p], capture_output=True, timeout=10, check=False)  # nosec B603
        return "ran" if b"late" in _r.stdout else "rc %d" % _r.returncode
    except OSError as _ex:
        return repr(_ex)
    finally:
        os.unlink(_p)


def held(blocked):
    """The blocked files this process can still open for reading (empty: the block holds on all)."""
    _open = []
    for _b in blocked:
        try:
            with open(_b, "rb"):
                _open.append(_b)
        except PermissionError:
            pass            # denied: the block holds on this one
        except OSError:
            _open.append(_b)
    return _open


def run_shapes(blocked, shapes, mark, late=None):
    """Run each shape (args, kw) after blocking `blocked` (none: unblocked); which reached the planted binary.

    Reached: the planted binary left `mark`, or printed its "stand-in" line. Returns (why the block
    did not hold or "", [reached?, ...], [output, ...]); with `late` (a directory), the output list
    ends with late_entry(late), run after the block.
    """
    import subprocess  # nosec B404 - the shapes are the suite's own fixed scripts
    _err = block(blocked, refer=False) if blocked else ""
    if _err:
        return _err, [], []
    _late = [late_entry(late)] if late else []
    _reached, _outs = [], []
    for _args, _kw in shapes:
        if os.path.exists(mark):
            os.unlink(mark)
        try:
            # nosemgrep  (dangerous-subprocess-use-tainted-env-args: the shapes are fixed)
            _p = subprocess.run(  # nosec B602 B603 - fixed shapes from the parent test
                _args, capture_output=True, timeout=10, **_kw)
            _stdout, _out = _p.stdout, _p.stdout + _p.stderr
        except (OSError, subprocess.TimeoutExpired) as _ex:
            _stdout, _out = b"", repr(_ex).encode()
        _reached.append(os.path.exists(mark) or b"stand-in" in _stdout.splitlines())
        _outs.append(_out.decode("utf-8", "replace")[-300:])
    return "", _reached, _outs + _late


if __name__ == "__main__":
    # In a process of its own, so that the block (which cannot be lifted) ends with it.
    import json
    with open(sys.argv[1], encoding="utf-8") as _fh:
        _job = json.load(_fh)
    _res = run_shapes(_job["blocked"], _job["shapes"], _job["mark"], _job.get("late"))
    with open(sys.argv[2], "w", encoding="utf-8") as _fh:
        json.dump(_res, _fh)
