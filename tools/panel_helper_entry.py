#!/usr/bin/python3 -I
"""The command the panel's sudoers rule names: it runs the privileged helper from root's bytecode.

WHY THIS FILE EXISTS
    Python compiles the script it is handed on every run and never caches that script's bytecode.
    tools/panel-helper is over 400 KB, so compiling it was more than half of what every privileged
    call cost in CPU. install.sh therefore places three root-owned files in LIB_DIR:

        panel-helper            this file, at the one path the sudoers rule names (unchanged)
        panel-helper-code.py    tools/panel-helper, byte for byte
        panel-helper-code.pyc   that code's bytecode, compiled by root at install time as a
                                checked-hash pyc (PEP 552)

    The grant is not widened: sudo still runs one command, this file, with -I from the shebang.
    Nothing here reads the environment or the arguments; the helper's code does that itself, as it
    did when it was the file sudo ran.

WHEN THE BYTECODE IS USED
    Only when all of this holds, checked through file descriptors so nothing can be swapped between
    the check and the read:
      * every directory from / down to LIB_DIR, and both files, are owned by root, have neither
        the group nor the other write bit, and are not symbolic links;
      * both files are regular files;
      * the pyc's magic number is this interpreter's, its flags say "checked hash", and its source
        hash is the hash of the code file's bytes as read here.
    When only the bytecode fails a test (missing, stale, another interpreter's, or a pyc that is not
    root's alone), the code file's bytes, already read through the checked descriptor, are compiled
    instead. Nothing is ever read again by its path.

    PEP 552's hash (SipHash with a fixed key) tells a STALE pyc from a current one; it says nothing
    about a forged one. What keeps a forged pyc out is the ownership test: only root can write any
    file here, as only root could write the helper before. A pyc compiled by another Python version,
    after a release upgrade for instance, fails the magic test and the source is compiled instead.

WHEN NOTHING RUNS
    When a directory on the way or the code file itself fails the ownership test, or the code file
    cannot be read, the entry runs nothing: it writes why to stderr and exits 1 (fail securely). A
    file someone other than root could have changed is never run with root's rights. Re-running
    install.sh as root puts the files back, or places the helper whole when the directories above
    LIB_DIR are not root's alone.
"""
import marshal
import os
import stat
import sys
from importlib.util import MAGIC_NUMBER, source_hash

LIB_DIR = "/usr/local/lib/linuxgsm-panel"
CODE = "panel-helper-code.py"
BYTECODE = "panel-helper-code.pyc"
ROOT_UID = 0
TOP = "/"

_CHECKED_HASH = 0b11   # PEP 552 flags: hash-based (bit 0) and check_source (bit 1)
_HEADER = 16           # magic, flags, 8-byte source hash
_DIR_OPEN = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_CodeType = type(compile("", "<entry>", "exec"))


class Untrusted(Exception):
    """A directory or file that someone other than its owner could have changed."""


def _safe(st, uid):
    """Whether `st` belongs to `uid` and neither its group nor others may write it."""
    return st.st_uid == uid and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def _check_dir(fd, uid):
    if not _safe(os.fstat(fd), uid):
        raise Untrusted("a directory on the way is not owned by root or is writable by others")


def open_dir(path, uid=ROOT_UID, top=TOP):
    """Open `path` one component at a time from `top`, each checked; the caller closes the fd."""
    rel = os.path.relpath(path, top)
    parts = [] if rel == "." else rel.split(os.sep)
    if any(p in ("", ".", "..") for p in parts):
        raise Untrusted("not below the top directory")
    fd = os.open(top, _DIR_OPEN)
    try:
        _check_dir(fd, uid)
        for part in parts:
            nfd = os.open(part, _DIR_OPEN, dir_fd=fd)
            os.close(fd)
            fd = nfd
            _check_dir(fd, uid)
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_file(dir_fd, name, uid=ROOT_UID):
    """The bytes of regular file `name` in `dir_fd`, after the same ownership test as a directory."""
    fd = os.open(name, _FILE_OPEN, dir_fd=dir_fd)
    try:
        fh = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)        # the descriptor is not wrapped yet, so nothing else closes it
        raise
    with fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode) or not _safe(st, uid):
            raise Untrusted("%s is not a root-owned file only root can write" % name)
        return fh.read()


def bytecode(data, source):
    """The code object in pyc bytes `data` when it is a checked-hash pyc of `source`, else None."""
    if len(data) < _HEADER or data[:4] != MAGIC_NUMBER:
        return None
    if int.from_bytes(data[4:8], "little") != _CHECKED_HASH or data[8:16] != source_hash(source):
        return None
    try:
        # nosemgrep: python.lang.security.audit.marshal.marshal-usage
        code = marshal.loads(data[_HEADER:])  # nosec B302 - root's own pyc, checked above
    except (ValueError, EOFError, TypeError):
        return None
    return code if isinstance(code, _CodeType) else None


def _trusted_read(lib_dir, uid, top):
    """Return (source, code or None), both read through checked descriptors.

    Raises OSError or Untrusted when the directories or the code file fail; the pyc is optional, so
    any failure reading or checking it only gives None.
    """
    dfd = open_dir(lib_dir, uid, top)
    try:
        source = read_file(dfd, CODE, uid)
        try:
            data = read_file(dfd, BYTECODE, uid)
        except (OSError, Untrusted):
            return source, None
        return source, bytecode(data, source)
    finally:
        os.close(dfd)


def load(lib_dir=LIB_DIR, uid=ROOT_UID, top=TOP):
    """Return (code object, True when it came from the bytecode).

    Raises OSError or Untrusted, and then nothing may run: there is no fallback to the code file's
    path. Without usable bytecode it compiles the source bytes the checked read returned.
    """
    source, code = _trusted_read(lib_dir, uid, top)
    if code is not None:
        return code, True
    return compile(source, os.path.join(lib_dir, CODE), "exec", dont_inherit=True), False


def run_code(code, entry_file):
    """Run the helper's code as the __main__ module, with this file as its __file__.

    __file__ is the path sudo ran, so the helper's own re-exec (systemd-run ... --job) comes back
    through this file and the same grant.
    """
    main = type(sys)("__main__")
    main.__file__ = entry_file
    sys.modules["__main__"] = main
    # Running a module's code object needs exec (it is what `python file.py` does); the code is root's
    # own helper, read only from root-owned files (module docstring).
    # nosemgrep: python.lang.security.audit.exec-detected.exec-detected
    exec(code, main.__dict__)  # nosec B102  # pylint: disable=exec-used


def start(entry_file, lib_dir=LIB_DIR, uid=ROOT_UID, top=TOP):
    """Load the helper's code and run it; exit 1 with a message, running nothing, when it is refused."""
    try:
        code = load(lib_dir, uid, top)[0]
    except Untrusted as exc:
        sys.stderr.write("panel-helper: refusing to run its code at %s: %s; re-run install.sh as root\n"
                         % (os.path.join(lib_dir, CODE), exc))
        sys.exit(1)
    except OSError as exc:
        sys.stderr.write("panel-helper: its code at %s could not be read (%s); re-run install.sh "
                         "as root\n" % (os.path.join(lib_dir, CODE), type(exc).__name__))
        sys.exit(1)
    run_code(code, entry_file)


if __name__ == "__main__":
    start(os.path.abspath(__file__))
