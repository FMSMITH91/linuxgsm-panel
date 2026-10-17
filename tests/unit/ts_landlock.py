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

The shapes the block is proven on are this module's own table (shapes(), which the text reader's
checks use too), never data handed in: the child runs only commands this file defines, in the
planted tree it is started in (its working directory), so nothing it starts comes from its
arguments or a file (PR #445: Codacy's tainted-args rule, which reads no suppression comment).

    cd <planted tree> && python -I tests/unit/ts_landlock.py free|held|late   # JSON on stdout
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


# Files the shapes source, written by the parent before any shape runs: a file made after the block
# directly in a directory on the way to the blocked binary is denied (the limit above), and shapes()
# writes nothing, so the reader's checks and the child see the same text.
_SOURCES = (("r29d-path-%s.sh", "PATH=%s:$PATH\n"), ("r30d-env-%s.sh", "T=tail\n"),
            ("r31d-path-%s.sh", "PATH=%s:$PATH\n"))
# The planted tree (the child's working directory): the "machine's" binary, the directory a link to
# it is found in, a part's own stand-in, the temp area the shapes get, and the mark a run leaves.
_SYS, _LNK, _OWN, TMP, _MARK = "sys", "lnk", "own", "r31d-tmp", "ran"


def write_shape_sources(ctl, dirs):
    """Write every file shapes(d, ctl) sources, for each of `dirs`."""
    for _d in dirs:
        for _name, _text in _SOURCES:
            with open(os.path.join(ctl, _name % os.path.basename(_d)), "w", encoding="utf-8") as _fh:
                _fh.write(_text % _d if "%s" in _text else _text)


def _with_env(specs):
    """`specs` with each `env` built over this process's environment."""
    return tuple((_h, _a, dict(_kw, env=dict(os.environ, **_kw["env"])) if "env" in _kw else _kw)
                 for _h, _a, _kw in specs)


def shapes(d, ctl):
    """Every shape (how, (args,), kw) a handle sees, with the binary found in `d`, in planted tree `ctl`."""
    return _with_env(_shapes_1012(d, ctl))


def shapes_1017b(d, ctl):
    """The review-1017b shapes alone (each must reach the planted binary unblocked)."""
    return _with_env(_shapes_1017b(d, ctl))


def _shapes_1012(d, ctl):
    """Every shape a handle sees, with the binary found in directory `d`.

    A shape's `env` is what it sets over the environment of the process running it (shapes() and
    the child build it there); every other shape starts with `d` first on PATH.
    """
    _ts, _p = os.path.join(d, "tailscale"), "PATH=%s:/usr/bin:/bin" % d
    _own = os.path.join(ctl, "own") + os.pathsep + "/usr/bin:/bin"
    return (("run", (["tailscale", "version"],), {}),
            ("Popen", (["tailscale", "status"],), {}),
            ("run", ("tailscale status --json 2>/dev/null || echo '{}'",), {"shell": True}),
            ("run", ("tailscale set --ssh 2>&1",), {"shell": True}),
            # WHICH-FOUND: `which` letting the binary's path through is a let-through too (the
            # path has no "stand-in" in it, review 1012b).
            ("Popen", (["/bin/bash", "-c", "which tailscale && echo WHICH-FOUND; tailscale version"],), {}),
            # An option before -c, an `env` prefix, a bare string with no shell and the binary
            # named by its path ran unjudged (review 1012c).
            ("run", (["/bin/bash", "-e", "-c", "tailscale version"],), {}),
            ("run", (["/usr/bin/env", "X=1", "sh", "-o", "errexit", "-c", "tailscale version"],), {}),
            ("run", ("tailscale",), {}),
            ("run", ([_ts, "version"],), {}),
            # Behind wrapper commands, and past the shell's function by a wrapper or a path, it
            # ran unjudged too (review 1012d); `env -i` drops the exported functions.
            ("run", (["timeout", "5", "tailscale", "version"],), {}),
            ("run", (["nice", "-n", "5", "/usr/bin/env", "-i", _p, "tailscale"],), {}),
            ("run", (["env", "-i", _p, "bash", "-c", "tailscale version"],), {}),
            ("run", (["setsid", "env", "-u", "X", "sh", "-c", "tailscale version"],), {}),
            ("run", ("timeout 5 tailscale version",), {"shell": True}),
            ("run", ("command tailscale version",), {"shell": True}),
            ("run", (["/bin/bash", "-c", "%s version" % _ts],), {}),
            # Behind a wrapper only the script form knew, as a command line held in one option
            # value, as a tuple, through check_output/call, and past the function by `type -P`, a
            # nested sh, a wrapper named by its path or an unset variable (review 1013a).
            ("run", (["taskset", "1", "tailscale", "version"],), {}),
            ("run", (["flock", "-w", "5", d, "tailscale"],), {}),
            ("run", (["chrt", "-o", "0", "tailscale"],), {}),
            ("run", (["/usr/bin/time", "-o", "/dev/null", "tailscale"],), {}),
            ("run", (["xargs", "-a", "/dev/null", "tailscale"],), {}),
            ("run", (["xargs", "-a", "/dev/null", "bash", "-c", "tailscale version"],), {}),
            ("run", (["env", "-S", "tailscale version"],), {}),
            ("run", (["env", "--split-string=tailscale version"],), {}),
            # A long option by its prefix, as getopt_long takes it (review 1015c).
            ("run", (["env", "--split-str=tailscale version"],), {}),
            ("run", (["env", "--spl=tailscale"],), {}),
            ("run", (["env", "-S", "tail'scale' version"],), {}),
            ("run", (["env", "-Stailscale\\_version"],), {}),
            ("run", (["zsh", "-c", "tailscale version"],), {}),
            ("run", (("env", "--", "tailscale", "version"),), {}),
            ("run", (("env", "--", "bash", "-c", "tailscale version"),), {}),
            ("check_output", (["tailscale", "version"],), {}),
            ("call", (["tailscale", "version"],), {}),
            ("run", ('"$(type -P tailscale)" version',), {"shell": True}),
            ("run", ("sh -c 'tailscale version'",), {"shell": True}),
            ("run", ("/usr/bin/env tailscale version",), {"shell": True}),
            ("run", ("$R20D_UNSET%s version" % _ts,), {"shell": True}),
            ("run", ('t=$(which -a tailscale | head -n 1); [ -n "$t" ] && "$t" version',), {"shell": True}),
            ("run", ('t=$(whereis -b tailscale | cut -d" " -f2); [ -x "$t" ] && "$t" version',), {"shell": True}),
            # -S/-c grouped or attached, and a command line naming the binary by its path while a
            # part's own stand-in is first on PATH (review 1015a).
            ("run", (["env", "-Stailscale version"],), {}),
            ("run", (["env", "-vS", "tailscale version"],), {}),
            ("run", (["zsh", "-ec", "tailscale"],), {}),
            ("run", (["env", "-S", "%s version" % _ts],), {"env": {"PATH": _own}}),
            ("run", (["zsh", "-c", "%s version" % _ts],), {"env": {"PATH": _own}})) + _shapes_1015d(d, ctl)


def _shapes_1015d(d, ctl):
    """shapes(): the long-option and variable shapes (review 1015d)."""
    return (
        # flock reads -c/--command only as the word after the lock file, and by its value in
        # the next word: `--comm=x` was refused by flock itself, so it could not fail; this one
        # runs the binary unless the separate-word reading judges it.
        ("run", (["flock", d, "--command", "tailscale"],), {}),
        ("run", (["env", "--spl", "tailscale\\_version"],), {}),
        # A value-taking long option by its prefix: its value is not the program.
        ("run", (["env", "--ch", d, "tailscale", "version"],), {}),
        ("run", (["timeout", "--sig", "TERM", "5", "tailscale", "version"],), {}),
        ("run", (["xargs", "--arg", "/dev/null", "tailscale"],), {}),
        # A variable env -S or a shell expands to nothing, unset or empty.
        ("run", (["env", "-S", "tail${R23D_UNSET}scale version"],), {}),
        ("run", (["zsh", "-c", "tail$R23D_UNSET'scale' version"],), {})) + _shapes_1016b(d, ctl)


def _shapes_1016b(d, ctl):
    """shapes(): the mixed-reading, built-word and which -a shapes (review 1016b)."""
    _own_then_d = {"PATH": os.pathsep.join((os.path.join(ctl, "own"), d, "/usr/bin:/bin"))}
    return (
        # --f is timeout's --foreground (a flag) and a prefix of --format; --sig needs its value.
        ("run", (["timeout", "--f", "--sig", "KILL", "5", "tailscale", "version"],), {}),
        # A name the script builds: bash, sh and a shell-less shell the guard reads statically.
        ("run", (["bash", "-c", "T=tail; ${T}scale version"],), {}),
        ("run", ("T=tail; ${T}scale version",), {"shell": True}),
        ("run", (["sh", "-c", "T=tail; ${T}scale version"],), {}),
        ("run", (["zsh", "-c", "T=tail; ${T}scale version"],), {}),
        ("run", (["zsh", "-c", "tail${HOME:+scale} version"],), {}),
        ("run", (["zsh", "-c", "tail$(:)scale version"],), {}),
        # ...past the function: a wrapper given the built word, and a path the script builds.
        ("run", ("T=tail; command ${T}scale version",), {"shell": True}),
        ("run", ("sh -c 'T=tail; ${T}scale version'",), {"shell": True}),
        ("run", ('p=%s; t=tail; "$p/${t}scale" version' % d,), {"shell": True}),
        # `which -a` past a part's stand-in first on PATH listed the machine's binary after it.
        ("run", ('t=$(which -a tailscale | grep -v /own/ | head -n 1); [ -n "$t" ] && "$t" version',),
         {"shell": True, "env": _own_then_d})) + _shapes_1016c(d, ctl)


def _shapes_1016c(d, ctl):
    """shapes(): the quoted-name, apostrophe and argv0 shapes, and built words behind the shim (review 1016c)."""
    _apos = 'echo "it\'s" >/dev/null; T=tail; ${T}scale version; echo "don\'t" >/dev/null'
    return (
        # An apostrophe inside "…" opened no string, but was read as one hiding the built word.
        ("run", (_apos,), {"shell": True}),
        ("run", (["bash", "-c", _apos],), {}),
        ("run", (["zsh", "-c", _apos],), {}),
        # The name spelled with quotes: no literal word, so no function was handed over.
        ("run", (["bash", "-c", "tail'scale' version"],), {}),
        ("run", ('tail"scale" version',), {"shell": True}),
        ("run", (["sh", "-c", "ta''ilscale version"],), {}),
        # env's -a/--argv0 takes a value, which was read as the program.
        ("run", (["env", "-a", "x", "tailscale", "version"],), {}),
        ("run", (["env", "--argv0", "x", "tailscale", "version"],), {}),
        # A built word a wrapper execs from PATH, and one `which` finds, in the shell it was given.
        ("run", ("T=tail; timeout 5 ${T}scale version",), {"shell": True}),
        ("run", (["sh", "-c", "T=tail; command ${T}scale version"],), {}),
        ("run", ('T=tail; t=$(which ${T}scale) && "$t" version',), {"shell": True}),
        ("run", (["sh", "-c", 'T=tail; t=$(which -a ${T}scale | tail -n 1) && "$t" version'],), {})
    ) + _shapes_1016e(d, ctl)


def _shapes_1016e(d, ctl):
    """shapes(): the PATH-setting, comment, here-document and set-otherwise shapes (review 1016e).

    Each puts the planted "machine's" directory `d` where the script searches, never the real
    default PATH: a shape that escaped would otherwise run this machine's own binary.
    """
    _hd = "cat >/dev/null <<EOF\nit's\nEOF\nT=tail; ${T}scale version\necho 'x'"
    return (
        # A script that only builds the name and sets its own PATH stepped past the shim.
        ("run", ("PATH=%s:$PATH; T=tail; ${T}scale version" % d,), {"shell": True}),
        ("run", ("export PATH=%s:$PATH; T=tail; ${T}scale version" % d,), {"shell": True}),
        ("run", (["sh", "-c", "PATH=%s:$PATH; T=tail; ${T}scale version" % d],), {}),
        ("run", ("T=tail; PATH=%s ${T}scale version" % d,), {"shell": True}),
        # ...and a wrapper execs from the PATH the script gives it, which was never judged.
        ("run", ("T=tail; env PATH=%s ${T}scale version" % d,), {"shell": True}),
        ("run", ("T=tail; PATH=%s:$PATH; timeout 5 ${T}scale version" % d,), {"shell": True}),
        ("run", (["env", "PATH=%s:/usr/bin:/bin" % d, "bash", "-c", "T=tail; timeout 5 ${T}scale version"],), {}),
        # An expansion the reader cannot model, behind a wrapper given a PATH.
        ("run", ("T=tailx; env PATH=%s ${T%%x}scale version" % d,), {"shell": True}),
        ("run", ("T=X; env PATH=%s ${T/X/tail}scale version" % d,), {"shell": True}),
        ("run", ("A=(tail); env PATH=%s ${A[0]}scale version" % d,), {"shell": True}),
        ("run", ("T=xtailscale; env -i PATH=%s:/usr/bin:/bin ${T#x} version" % d,), {"shell": True}),
        # A name set other than by a plain NAME=, under the bash route (the script names the word).
        ("run", (["bash", "-c", "echo tailscale >/dev/null; printf -v T tail; timeout 5 ${T}scale version"],), {}),
        ("run", (["bash", "-c", "echo tailscale >/dev/null; : ${T:=tail}; timeout 5 ${T}scale version"],), {}),
        ("run", (["bash", "-c", "echo tailscale >/dev/null; T=tail; T+=scale; timeout 5 $T version"],), {}),
        ("run", (["env", "T=tailscale", "bash", "-c", "timeout 5 $T version"],), {}),
        # An apostrophe in a comment or a here-document's body opened no string.
        ("run", ("# it's a comment\nT=tail; ${T}scale version\necho 'x'",), {"shell": True}),
        ("run", (_hd,), {"shell": True}),
        ("run", (["sh", "-c", _hd],), {})) + _shapes_1016f(d, ctl)


def _shapes_1016f(d, ctl):
    """shapes(): the PATH set past the reader, cd-relative and built-path shapes (review 1016f).

    Each reached the planted "machine's" binary in `d` through every handle: a PATH the stripped
    reader could not see (single-quoted inside a nested bash, a quoted or built name, a sourced or
    eval'd text, hidden by `$'…'`, a `#` inside a word or a here-document it did not know), a path
    read against the run's directory instead of the script's `cd`, a path whose last word is built,
    and a value quoted in part.
    """
    _src = os.path.join(ctl, "r29d-path-%s.sh" % os.path.basename(d))
    _tail = "T=$(echo tail); PATH=%s:$PATH; timeout 5 ${T}scale version; echo 'x'" % d
    return (
        ("run", ("bash -c 'PATH=%s:$PATH; tailscale version'" % d,), {"shell": True}),
        ("run", ("bash -c 'export PATH=%s; tailscale version'" % d,), {"shell": True}),
        ("run", ("export 'PATH=%s:/usr/bin:/bin'; T=tail; ${T}scale version" % d,), {"shell": True}),
        ("run", (["bash", "-c", "declare -x 'PATH=%s:/usr/bin'; T=tail; ${T}scale version" % d],), {}),
        ("run", ("T=tail; export 'PATH=%s'; tailscale version" % d,), {"shell": True}),
        ("run", ("P=PA; export ${P}TH=%s; T=tail; ${T}scale version" % d,), {"shell": True}),
        ("run", (". %s; T=tail; ${T}scale version" % _src,), {"shell": True}),
        ("run", (["sh", "-c", ". %s; T=tail; ${T}scale version" % _src],), {}),
        ("run", ('eval "PA""TH=%s:$PATH"; T=tail; ${T}scale version' % d,), {"shell": True}),
        ("run", (["bash", "-c", "x=$'it\\'s'; PATH=%s:$PATH; T=tail; ${T}scale version; echo 'y'" % d],), {}),
        ("run", ("T=tailscalex; echo \\ #; env -i PATH=%s ${T%%x} version" % d,), {"shell": True}),
        ("run", ("T=tailscalex; : $(:)#; env -i PATH=%s ${T%%x} version" % d,), {"shell": True}),
        ("run", ("T=tailscalex; echo a\\\n#; env -i PATH=%s ${T%%x} version" % d,), {"shell": True}),
        ("run", ("echo \\ #; PATH=%s; T=tail; ${T}scale version" % d,), {"shell": True}),
        ("run", ("cat >/dev/null <<\\EOF\nit's\nEOF\n" + _tail,), {"shell": True}),
        ("run", ('cat >/dev/null <<E"OF"\nit\'s\nEOF\n' + _tail,), {"shell": True}),
        ("run", (["bash", "-c", "T=tail; cat <<< END\necho 'abc\nEND\ndef' ; ${T}scale version; echo 'z'\n"],), {}),
        ("run", ("cd %s && ./tailscale version" % d,), {"shell": True}),
        ("run", ("cd %s; T=tail; ./${T}scale version" % d,), {"shell": True}),
        ("run", (["sh", "-c", "cd %s; T=tail; ./${T}scale version" % d],), {}),
        ("run", ("%s/tail$(:)scale version" % d,), {"shell": True}),
        ("run", ("T=tailscalex; %s/${T%%x} version" % d,), {"shell": True}),
        ("run", ('T=ta"il"; env -i PATH=%s ${T}scale version' % d,), {"shell": True}),
        ("run", ("T=ta'il'; env -i PATH=%s ${T}scale version" % d,), {"shell": True})) + _shapes_1017a(d, ctl)


def _shapes_1017a(d, ctl):
    """shapes(): the quoted-path, unresolved-directory, CDPATH, nested-PATH and `#` shapes (review 1017a).

    Each reached the planted "machine's" binary in `d`: a path whose directory or last word is
    quoted or cannot be resolved, a `cd` under CDPATH, past `--` or to a directory the reader cannot
    name, a nested bash building the name PATH, a `#` that only looks like a comment opening a
    quote the reader never saw, and a name set in a sourced file.
    """
    _up, _base = os.path.dirname(d), os.path.basename(d)
    _src = os.path.join(ctl, "r30d-env-%s.sh" % _base)
    _nested = 'P=PA; bash -c "${P}TH=%s; tailscale version"' % d
    return (
        ("run", ("CDPATH=%s; cd %s && ./tailscale version" % (_up, _base),), {"shell": True}),
        ("run", ("export CDPATH=%s; cd %s >/dev/null && ./tailscale version" % (_up, _base),), {"shell": True}),
        ("run", ('cd "$(echo %s)" && ./%s/tailscale version' % (_up, _base),), {"shell": True}),
        ("run", ("cd -- %s && ./tailscale version" % d,), {"shell": True}),
        ("run", ("cd -P -- %s; ./tailscale version" % d,), {"shell": True}),
        ("run", ("%s/tail'scale' version" % d,), {"shell": True}),
        ("run", ('%s/tail""scale version' % d,), {"shell": True}),
        ("run", ('cd %s && ./tail""scale version' % d,), {"shell": True}),
        ("run", ('T=tailscalex; "%s"/${T%%x} version' % d,), {"shell": True}),
        ("run", ("T=tailscalex; '%s'/${T%%x} version" % d,), {"shell": True}),
        ("run", ('D=%s; T=tailscalex; "$D"/${T%%x} version' % d,), {"shell": True}),
        ("run", ('"%s"/tailscale version' % d,), {"shell": True}),
        ("run", ('D=%s; "$D"/tailscale version' % d,), {"shell": True}),
        ("run", ('"$(echo %s)"/tailscale version' % d,), {"shell": True}),
        ("run", ("D=$(echo %s); $D/tailscale version" % d,), {"shell": True}),
        ("run", (["sh", "-c", 'D=$(echo %s); "$D/tailscale" version' % d],), {}),
        ("run", (_nested,), {"shell": True}),
        ("run", (["sh", "-c", _nested],), {}),
        ("run", (["bash", "-c", _nested],), {}),
        ("run", ('echo \\ #"\n"; echo "x\'"; T=tailscalex; env -i PATH=%s ${T%%x} version; echo "\'"' % d,),
         {"shell": True}),
        ("run", ('T=tailscalex; : $(:)#"\n"; echo "x\'"; env -i PATH=%s ${T%%x} version; echo "\'"' % d,),
         {"shell": True}),
        ("run", ("x=$(:)#'\n'\nPATH=%s:$PATH; timeout 5 tail$(:)scale version; echo 'y'" % d,), {"shell": True}),
        ("run", ("echo a\\ #'\n'\nPATH=%s:$PATH; timeout 5 tail$(:)scale version; echo 'y'" % d,),
         {"shell": True}),
        ("run", (". %s; timeout 5 ${T}scale version" % _src,), {"shell": True}),
        ("run", (["sh", "-c", "source %s; timeout 5 ${T}scale version" % _src],), {})) + _shapes_1017b(d, ctl)


def _shapes_1017b(d, ctl):
    """shapes(): the nested-option, continuation, prefixed-dot, BASH_ENV and backtick shapes (review 1017b).

    Each reached the planted "machine's" binary in `d` from a PATH without it: a nested shell with
    an option's value, a long option or `--` before its -c script, a quoted or escaped `cd`, a `#`
    after a line continuation opening a quote the reader never saw, a `.` behind an assignment or a
    redirection, a file BASH_ENV has bash source first, and a `.` that starts a backtick command.
    """
    _src = os.path.join(ctl, "r31d-path-%s.sh" % os.path.basename(d))
    _env = {"PATH": "/usr/bin:/bin"}
    _nested = ['P=PA; bash %s "${P}TH=%s; tailscale version"' % (_o, d)
               for _o in ("-o pipefail -c", "-O extglob -c", "--norc -c", "-c --")]
    _shapes = [("run", (_x,), {"shell": True, "env": _env}) for _x in _nested + [
        '"cd" %s && ./tailscale version' % d, "\\cd %s && ./tailscale version" % d,
        "echo \\\n#'\nPATH=%s:$PATH; timeout 5 tail$(:)scale version; echo 'y'" % d,
        "echo a \\\n#it's\nT=tailscalex; env -i PATH=%s ${T%%x} version; echo 'x'" % d,
        "X=1 . %s; T=tail; ${T}scale version" % _src, "true && X=1 . %s; tailscale version" % _src,
        "LC_ALL=C . %s && tailscale version" % _src, "2>/dev/null . %s; tailscale version" % _src,
        "BASH_ENV=%s bash -c 'tailscale version'" % _src, "export BASH_ENV=%s; bash -c 'tailscale version'" % _src,
        'x=`. %s; tailscale version`; echo "$x"' % _src]]
    _shapes += [("run", (["sh", "-c", _nested[0]],), {"env": _env}),
                ("run", (["bash", "-c", _nested[2]],), {"env": _env}),
                ("run", (["sh", "-c", 'x=`. %s; tailscale version`; echo "$x"' % _src],), {"env": _env}),
                ("run", (["bash", "-c", "tailscale version"],), {"env": dict(_env, BASH_ENV=_src)})]
    return tuple(_shapes)


def _kernel_table(ctl):
    """[(name, args, kw, d)] the child runs: every shape on sys/ and lnk/, then three of its own.

    `d` is the directory put first on the shape's PATH when it sets no env (None: run as written):
    a copy of the binary run from elsewhere (READ_FILE is denied as well as EXECUTE), the planted
    binary by its path (control: it must be reached unblocked), and a part's stand-in on its own
    PATH, which must run blocked as unblocked.
    """
    _sys, _tmp = os.path.join(ctl, _SYS), os.path.join(ctl, TMP)
    _out = [("%r %s" % (_a[0], os.path.basename(_d)), _a[0], _kw, _d)
            for _d in (_sys, os.path.join(ctl, _LNK)) for _h, _a, _kw in _shapes_1012(_d, ctl)]
    _out.append(("a copy run from the run's temp area", ["sh", "-c", 'cp "$1" "$2" && sh "$2"', "sh",
                                                         os.path.join(_sys, "tailscale"), os.path.join(_tmp, "copied")],
                 {}, None))
    _out.append(("the planted binary by its path", [os.path.join(_sys, "tailscale")], {}, None))
    _out.append(("a part's stand-in on its own PATH", ["sh", "-c", "tailscale"],
                 {"env": {"PATH": os.path.join(ctl, _OWN) + os.pathsep + "/usr/bin:/bin"}}, None))
    return _out


def kernel_names(ctl):
    """The name of each shape the child runs, in its order."""
    return [_e[0] for _e in _kernel_table(ctl)]


def _kernel_kw(kw, d, tmp):
    """A table entry's keywords as the child runs it: env over its own, else `d` first on PATH, and TMPDIR."""
    _env = dict(os.environ, **kw["env"]) if "env" in kw else None
    if d is None:
        return kw if _env is None else dict(kw, env=_env)
    if _env is None:
        _env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
    return dict(kw, env=dict(_env, TMPDIR=tmp))


def run_shapes(ctl, blocked, late=False):
    """Block `blocked` (none: unblocked), then run the table (or, with `late`, only late_entry).

    Reached: the planted binary left its mark, or printed its "stand-in" line. Returns (why the
    block did not hold or "", [reached?, ...], [output, ...]); with `late` the output list is
    late_entry() in the planted binary's own directory, run after the block.
    """
    import subprocess  # nosec B404 - runs only this module's own table
    _err = block(blocked, refer=False) if blocked else ""
    if _err:
        return _err, [], []
    if late:
        return "", [], [late_entry(os.path.join(ctl, _SYS))]
    _mark, _tmp = os.path.join(ctl, _MARK), os.path.join(ctl, TMP)
    _reached, _outs = [], []
    for _name, _args, _spec, _d in _kernel_table(ctl):
        if os.path.exists(_mark):
            os.unlink(_mark)
        try:
            # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
            _p = subprocess.run(  # nosec B602 B603 - this module's own table
                _args, capture_output=True, timeout=10, **_kernel_kw(_spec, _d, _tmp))
            _stdout, _out = _p.stdout, _p.stdout + _p.stderr
        except (OSError, subprocess.TimeoutExpired) as _ex:
            _stdout, _out = b"", repr(_ex).encode()
        _reached.append(os.path.exists(_mark) or b"stand-in" in _stdout.splitlines())
        _outs.append(_out.decode("utf-8", "replace")[-300:])
    return "", _reached, _outs


def run_mode(mode, ctl):
    """One child run in planted tree `ctl`: "free" (unblocked), "held" or "late" (planted binary blocked)."""
    _planted = [os.path.realpath(os.path.join(ctl, _SYS, "tailscale"))]
    if mode == "free":
        return run_shapes(ctl, [])
    if mode in ("held", "late"):
        return run_shapes(ctl, _planted, late=mode == "late")
    return "unknown mode %r" % (mode,), [], []


if __name__ == "__main__":
    # In a process of its own, so that the block (which cannot be lifted) ends with it.
    import json
    print(json.dumps(run_mode(sys.argv[1] if len(sys.argv) > 1 else "", os.getcwd())))
