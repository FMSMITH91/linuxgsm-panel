"""The SFTP service's way into a game account's files: OpenSSH's own sftp-server, run AS that account.

The panel's SFTP service (sftp_server.py) never touches a game file itself. For each game server a
session uses it starts the host's `sftp-server` binary as the game account, exactly as the web file
manager runs its reads and writes as that account (ssh_manager._core.game_user_cmd), and talks the
SFTP protocol (version 3, draft-ietf-secsh-filexfer-02) to it:

* the panel's own host: `sudo -n -u <account> <sftp-server>` over pipes (the second line of the
  panel's sudoers grant lets it become a game account; never root, never the panel's own account
  unless that IS the game account);
* a remote host over paramiko: the same command on a new channel of a connection opened like every
  other one (host key pinned, _core.get_connection);
* a remote host over Tailscale SSH: the same command through the system ssh, as downloads do.

So the operating system decides what the account may read or write, and a symlink planted in the
home reaches only what the account could reach anyway. sftp-server is started with `-P
symlink,hardlink`, so it makes no link even if asked.

Requests are pipelined: a write is sent without waiting for its answer (at most WRITE_WINDOW in
flight, the first failure reported on the next write or the close), and a sequential read keeps
READ_AHEAD requests in flight. Nothing holds a whole file: at most the read-ahead window per open
file. This module is plain threads and blocking I/O; it runs only in the service's own process.
"""
import logging
import os
import shutil
import struct
import subprocess  # nosec B404 - argv lists only, built here from validated parts
import threading
from collections import deque

from paramiko.message import Message

_log = logging.getLogger("panel.sftp")

# SFTP v3 packet types and status codes (draft-ietf-secsh-filexfer-02, sections 3 and 7).
INIT, VERSION, OPEN, CLOSE, READ, WRITE, LSTAT, FSTAT, SETSTAT, FSETSTAT = 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
OPENDIR, READDIR, REMOVE, MKDIR, RMDIR, REALPATH, STAT, RENAME, READLINK = 11, 12, 13, 14, 15, 16, 17, 18, 19
STATUS, HANDLE, DATA, NAME, ATTRS, EXTENDED, EXTENDED_REPLY = 101, 102, 103, 104, 105, 200, 201
OK, EOF, NO_SUCH_FILE, PERMISSION_DENIED, FAILURE, BAD_MESSAGE, NO_CONNECTION, CONNECTION_LOST, \
    OP_UNSUPPORTED = range(9)
P_READ, P_WRITE, P_APPEND, P_CREAT, P_TRUNC, P_EXCL = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
A_SIZE, A_UIDGID, A_PERMISSIONS, A_ACMODTIME, A_EXTENDED = 0x01, 0x02, 0x04, 0x08, 0x80000000

WRITE_WINDOW = 64           # writes in flight per open file
READ_AHEAD = 32             # reads in flight per open file, for a client reading it in order...
READ_AHEAD_BYTES = 2 * 1024 * 1024      # ...and never more bytes than this
READ_AHEAD_MAX_CHUNK = 256 * 1024       # the largest read passed on (sftp-server's own cap)
MAX_PACKET = 512 * 1024     # the largest reply accepted from sftp-server (it sends at most 256 KiB of data)
REPLY_TIMEOUT = 300         # seconds a request may wait for its reply (_core.STREAM_IDLE_TIMEOUT)

# Where sftp-server lives: Debian and Ubuntu, Fedora and RHEL, Arch, then the BSD-style path.
SFTP_SERVER_PATHS = ("/usr/lib/openssh/sftp-server", "/usr/libexec/openssh/sftp-server",
                     "/usr/lib/ssh/sftp-server", "/usr/libexec/sftp-server")
SFTP_SERVER_ARGS = ("-P", "symlink,hardlink")


class BackendError(Exception):
    """A request sftp-server answered with a failure status (`code`), or a dead connection."""

    def __init__(self, code, message=""):
        """A failure with SFTP status `code` and sftp-server's own `message`."""
        super().__init__(message or "status %d" % code)
        self.code = code


class _Reply:
    """One request's answer, filled in by the reader thread."""

    __slots__ = ("event", "kind", "msg")

    def __init__(self):
        """An empty answer, not yet arrived."""
        self.event = threading.Event()
        self.kind = None
        self.msg = None


def _attr_flags(attrs):
    """The ATTRS flags for the fields `attrs` holds."""
    have = {k for k, v in attrs.items() if v is not None}
    flags = A_SIZE if "size" in have else 0
    flags |= A_UIDGID if {"uid", "gid"} <= have else 0
    flags |= A_PERMISSIONS if "mode" in have else 0
    return flags | (A_ACMODTIME if {"atime", "mtime"} <= have else 0)


def pack_attrs(msg, attrs):
    """Add an ATTRS structure for `attrs` ({"size", "uid", "gid", "mode", "atime", "mtime"}) to `msg`."""
    flags = _attr_flags(attrs)
    msg.add_int(flags)
    if flags & A_SIZE:
        msg.add_int64(attrs["size"])
    if flags & A_UIDGID:
        msg.add_int(attrs["uid"])
        msg.add_int(attrs["gid"])
    if flags & A_PERMISSIONS:
        msg.add_int(attrs["mode"])
    if flags & A_ACMODTIME:
        msg.add_int(attrs["atime"])
        msg.add_int(attrs["mtime"])


def unpack_attrs(msg):
    """Read an ATTRS structure from `msg` into a dict (the keys pack_attrs takes, present ones only)."""
    flags = msg.get_int()
    out = {}
    if flags & A_SIZE:
        out["size"] = msg.get_int64()
    if flags & A_UIDGID:
        out["uid"], out["gid"] = msg.get_int(), msg.get_int()
    if flags & A_PERMISSIONS:
        out["mode"] = msg.get_int()
    if flags & A_ACMODTIME:
        out["atime"], out["mtime"] = msg.get_int(), msg.get_int()
    if flags & A_EXTENDED:
        for _ in range(msg.get_int()):
            msg.get_string()
            msg.get_string()
    return out


class Backend:
    """An SFTP v3 client over one sftp-server's byte stream; thread-safe, requests pipelined.

    `recv(n)` returns up to n bytes (b"" at the end), `send(data)` writes all of it, `close()` ends
    the transport. A reader thread hands each reply to the request waiting for it.
    """

    def __init__(self, recv, send, close, name="backend"):
        """Start the client: the version handshake, then the reader thread."""
        self._recv, self._send_raw, self._close_raw = recv, send, close
        self._lock = threading.Lock()
        self._waiting = {}
        self._next_id = 1
        self.dead = None
        self.extensions = {}
        self._handshake()
        self._reader = threading.Thread(target=self._read_loop, name="sftp-" + name, daemon=True)
        self._reader.start()

    # ── framing ──
    def _read_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            got = self._recv(n - len(buf))
            if not got:
                raise EOFError("sftp-server closed its stream")
            buf += got
        return bytes(buf)

    def _read_packet(self):
        size = struct.unpack(">I", self._read_exact(4))[0]
        if size < 1 or size > MAX_PACKET:
            raise EOFError("sftp-server sent a packet of %d bytes" % size)
        body = self._read_exact(size)
        return body[0], Message(body[1:])

    def _send_packet(self, kind, payload):
        data = bytes([kind]) + payload
        self._send_raw(struct.pack(">I", len(data)) + data)

    def _handshake(self):
        m = Message()
        m.add_int(3)
        self._send_packet(INIT, m.asbytes())
        kind, msg = self._read_packet()
        if kind != VERSION:
            raise BackendError(BAD_MESSAGE, "sftp-server did not answer the version")
        msg.get_int()
        while msg.get_remainder():
            name = msg.get_text()
            self.extensions[name] = msg.get_text()

    def _read_loop(self):
        try:
            while True:
                kind, msg = self._read_packet()
                rid = msg.get_int()
                with self._lock:
                    slot = self._waiting.pop(rid, None)
                if slot is not None:
                    slot.kind, slot.msg = kind, msg
                    slot.event.set()
        except Exception as exc:  # noqa: BLE001 - any end of the stream ends every request waiting on it
            self._fail_all(exc)

    def _fail_all(self, exc):
        with self._lock:
            self.dead = self.dead or exc
            waiting, self._waiting = self._waiting, {}
        for slot in waiting.values():
            slot.event.set()

    # ── requests ──
    def send(self, kind, build):
        """Send one request (`build(msg)` adds its fields after the id); its _Reply to wait on."""
        slot = _Reply()
        with self._lock:
            if self.dead is not None:
                raise BackendError(CONNECTION_LOST, "the game host's file service has gone")
            rid = self._next_id
            self._next_id = (self._next_id + 1) & 0xFFFFFFFF or 1
            self._waiting[rid] = slot
            m = Message()
            m.add_int(rid)
            build(m)
            try:
                self._send_packet(kind, m.asbytes())
            except Exception as exc:
                self._waiting.pop(rid, None)
                self.dead = self.dead or exc
                raise BackendError(CONNECTION_LOST, "the game host's file service has gone") from exc
        return slot

    def wait(self, slot, timeout=REPLY_TIMEOUT):
        """(kind, msg) of a sent request's reply; BackendError for a failed status or a dead stream."""
        if not slot.event.wait(timeout):
            self.close()
            raise BackendError(CONNECTION_LOST, "the game host's file service stopped answering")
        if slot.kind is None:
            raise BackendError(CONNECTION_LOST, "the game host's file service has gone")
        if slot.kind == STATUS:
            code = slot.msg.get_int()
            text = slot.msg.get_text() if slot.msg.get_remainder() else ""
            if code != OK:
                raise BackendError(code, text)
        return slot.kind, slot.msg

    def call(self, kind, build):
        """Send a request and wait for its reply."""
        return self.wait(self.send(kind, build))

    def close(self):
        """End the stream and the sftp-server behind it."""
        self._fail_all(EOFError("closed"))
        try:
            self._close_raw()
        except Exception:  # noqa: BLE001 - already gone is what closing means here
            _log.debug("sftp backend close", exc_info=True)

    # ── the operations the service uses ──
    def realpath(self, path):
        """The host's canonical form of `path` (links resolved), as sftp-server's realpath gives it."""
        _k, msg = self.call(REALPATH, lambda m: m.add_string(path))
        msg.get_int()
        return msg.get_text()

    def stat(self, path, follow=True):
        """The attributes of `path` (STAT follows a final link; LSTAT does not)."""
        _k, msg = self.call(STAT if follow else LSTAT, lambda m: m.add_string(path))
        return unpack_attrs(msg)

    def listdir(self, path):
        """[(name, attrs)] of the folder `path`, every entry but . and .."""
        _k, msg = self.call(OPENDIR, lambda m: m.add_string(path))
        handle = msg.get_binary()
        out = []
        try:
            while True:
                try:
                    _k, msg = self.call(READDIR, lambda m: m.add_string(handle))
                except BackendError as exc:
                    if exc.code == EOF:
                        break
                    raise
                for _ in range(msg.get_int()):
                    raw = msg.get_string()
                    msg.get_string()        # the long name: the service builds its own
                    attrs = unpack_attrs(msg)
                    if raw in (b".", b".."):
                        continue
                    try:
                        out.append((raw.decode("utf-8"), attrs))
                    except UnicodeDecodeError:
                        continue            # a name that is not UTF-8 is not one the panel handles
        finally:
            self.close_handle(handle)
        return out

    def open(self, path, pflags, attrs=None):
        """A handle for `path` opened with SFTP flags `pflags` (and `attrs` for a new file)."""
        def _b(m):
            m.add_string(path)
            m.add_int(pflags)
            pack_attrs(m, attrs or {})
        _k, msg = self.call(OPEN, _b)
        return msg.get_binary()

    def close_handle(self, handle):
        """Close a file or folder handle."""
        self.call(CLOSE, lambda m: m.add_string(handle))

    def read(self, handle, offset, length):
        """Up to `length` bytes at `offset`; b"" at the end of the file."""
        try:
            _k, msg = self.call(READ, lambda m: (m.add_string(handle), m.add_int64(offset), m.add_int(length)))
        except BackendError as exc:
            if exc.code == EOF:
                return b""
            raise
        return msg.get_binary()

    def send_read(self, handle, offset, length):
        """Send a READ without waiting; wait on it with read_reply."""
        return self.send(READ, lambda m: (m.add_string(handle), m.add_int64(offset), m.add_int(length)))

    def read_reply(self, slot):
        """The data a send_read asked for; b"" at the end of the file."""
        try:
            _k, msg = self.wait(slot)
        except BackendError as exc:
            if exc.code == EOF:
                return b""
            raise
        return msg.get_binary()

    def send_write(self, handle, offset, data):
        """Send a WRITE without waiting; wait on it with wait()."""
        return self.send(WRITE, lambda m: (m.add_string(handle), m.add_int64(offset), m.add_string(data)))

    def setstat(self, path, attrs):
        """Set `attrs` on `path`."""
        self.call(SETSTAT, lambda m: (m.add_string(path), pack_attrs(m, attrs)))

    def fsetstat(self, handle, attrs):
        """Set `attrs` on an open handle."""
        self.call(FSETSTAT, lambda m: (m.add_string(handle), pack_attrs(m, attrs)))

    def fstat(self, handle):
        """The attributes of an open handle."""
        _k, msg = self.call(FSTAT, lambda m: m.add_string(handle))
        return unpack_attrs(msg)

    def remove(self, path):
        """Remove a file (or a link: not what it points at)."""
        self.call(REMOVE, lambda m: m.add_string(path))

    def mkdir(self, path, attrs=None):
        """Make a folder."""
        self.call(MKDIR, lambda m: (m.add_string(path), pack_attrs(m, attrs or {})))

    def rmdir(self, path):
        """Remove an empty folder."""
        self.call(RMDIR, lambda m: m.add_string(path))

    def rename(self, old, new):
        """Rename; refused by sftp-server when `new` exists (SFTP v3 RENAME never replaces)."""
        self.call(RENAME, lambda m: (m.add_string(old), m.add_string(new)))

    def replace(self, old, new):
        """Rename `old` over `new` in one step (posix-rename@openssh.com, rename(2))."""
        if "posix-rename@openssh.com" not in self.extensions:
            raise BackendError(OP_UNSUPPORTED, "This host's sftp-server cannot replace a file in one step.")
        self.call(EXTENDED, lambda m: (m.add_string("posix-rename@openssh.com"), m.add_string(old),
                                       m.add_string(new)))

    def readlink(self, path):
        """What the link `path` points at, as written."""
        _k, msg = self.call(READLINK, lambda m: m.add_string(path))
        msg.get_int()
        return msg.get_text()

    def free_bytes(self, path):
        """Bytes free to the account on `path`'s filesystem (statvfs@openssh.com), or None if unknown."""
        if "statvfs@openssh.com" not in self.extensions:
            return None
        try:
            _k, msg = self.call(EXTENDED, lambda m: (m.add_string("statvfs@openssh.com"), m.add_string(path)))
        except BackendError:
            return None
        msg.get_int64()           # the block size
        frsize = msg.get_int64()
        msg.get_int64()           # blocks
        msg.get_int64()           # free blocks (root's share included)
        avail = msg.get_int64()   # free blocks an unprivileged account may use
        return frsize * avail


class Writer:
    """Pipelined writes to one open handle: send without waiting, at most WRITE_WINDOW in flight."""

    def __init__(self, backend, handle):
        """Writes to `handle` on `backend`, none in flight yet."""
        self.backend, self.handle = backend, handle
        self._inflight = deque()
        self.error = None

    def write(self, offset, data):
        """Queue one write; raise the first failure a previous write reported."""
        self._check()
        while len(self._inflight) >= WRITE_WINDOW:
            self._settle_one()
        self._inflight.append(self.backend.send_write(self.handle, offset, data))
        self._check()

    def _settle_one(self):
        slot = self._inflight.popleft()
        try:
            self.backend.wait(slot)
        except BackendError as exc:
            self.error = self.error or exc

    def _check(self):
        if self.error is not None:
            raise self.error

    def flush(self):
        """Wait for every write in flight; raise the first failure."""
        while self._inflight:
            self._settle_one()
        self._check()


class Reader:
    """Read-ahead over one open handle for a client reading in order; reads anywhere else still work.

    The client's own request size is the chunk: up to READ_AHEAD of them, and never more than
    READ_AHEAD_BYTES, are in flight past the one it asked for. A read anywhere else drops them.
    """

    def __init__(self, backend, handle):
        """Reads of `handle` on `backend`, nothing read ahead yet."""
        self.backend, self.handle = backend, handle
        self._ahead = deque()       # (offset, length, slot) in offset order
        self._eof_at = None

    def read(self, offset, length):
        """Up to `length` bytes at `offset` (b"" at the end)."""
        length = max(1, min(int(length), READ_AHEAD_MAX_CHUNK))
        if self._eof_at is not None and offset >= self._eof_at:
            # Past the end seen so far: asked directly (a log can grow), with nothing read ahead.
            self.drop()
            data = self.backend.read(self.handle, offset, length)
            if data:
                self._eof_at = None
            return data
        if not self._ahead or self._ahead[0][0] != offset or self._ahead[0][1] != length:
            self.drop()
            self._fill(offset, length)
        _off, _len, slot = self._ahead.popleft()
        data = self.backend.read_reply(slot)
        if len(data) < length:
            # The end of the file (or sftp-server's own cap): the client asks again at the new
            # offset, so what was sent beyond it is dropped.
            self.drop()
            if not data:
                self._eof_at = offset
        else:
            self._fill(offset + length, length)
        return data

    def _fill(self, start, length):
        nxt = self._ahead[-1][0] + self._ahead[-1][1] if self._ahead else start
        depth = max(2, min(READ_AHEAD, READ_AHEAD_BYTES // length))
        while len(self._ahead) < depth and (self._eof_at is None or nxt < self._eof_at):
            self._ahead.append((nxt, length, self.backend.send_read(self.handle, nxt, length)))
            nxt += length

    def drop(self):
        """Forget every read in flight (their replies are still read, and thrown away)."""
        while self._ahead:
            _o, _l, slot = self._ahead.popleft()
            try:
                self.backend.read_reply(slot)
            except BackendError:
                _log.debug("read-ahead reply dropped", exc_info=True)


# ── Starting sftp-server as the game account ───────────────────────────────────────────────────
def local_sftp_server():
    """The path of this host's sftp-server, or None."""
    for path in SFTP_SERVER_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def local_argv(user, me):
    """The argv that runs this host's sftp-server as `user` (sudo -n -u, unless `user` is `me`), or None."""
    from panel.ops.ssh_manager import _core
    path = local_sftp_server()
    if path is None or not _core.game_idents_ok(user):
        return None
    if user == me:
        return [path, *SFTP_SERVER_ARGS]
    sudo = shutil.which("sudo") or "/usr/bin/sudo"
    return [sudo, "-n", "-u", user, "--", path, *SFTP_SERVER_ARGS]


def remote_shell(user):
    """The shell command a remote host runs to start its sftp-server as `user` (game_user_cmd's form)."""
    from panel.ops.ssh_manager import _core
    tries = " ".join(SFTP_SERVER_PATHS)
    args = " ".join(SFTP_SERVER_ARGS)
    inner = ('for p in %s; do if [ -x "$p" ]; then exec "$p" %s; fi; done; '
             'echo "no sftp-server on this host" >&2; exit 127' % (tries, args))
    return _core.game_user_cmd(user, inner)


def from_process(argv, name):
    """A Backend over a child process's stdin and stdout (the local form, and the system ssh)."""
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,  # nosec B603 - argv list, no shell
                         stderr=subprocess.DEVNULL, bufsize=0, close_fds=True, start_new_session=True)
    rfd, wpipe = p.stdout.fileno(), p.stdin

    def _recv(n):
        return os.read(rfd, n)

    def _send(data):
        wpipe.write(data)

    def _close():
        for f in (p.stdin, p.stdout):
            try:
                f.close()
            except OSError:
                _log.debug("sftp backend pipe close", exc_info=True)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)
    try:
        return Backend(_recv, _send, _close, name)
    except Exception:
        _close()
        raise


def from_channel(client, command, name, window=4 * 1024 * 1024):
    """A Backend over a new paramiko channel running `command` on a remote host; owns `client`."""
    chan = client.get_transport().open_session(window_size=window, max_packet_size=32768)
    chan.settimeout(REPLY_TIMEOUT)
    chan.exec_command(command)

    def _close():
        try:
            chan.close()
        finally:
            client.close()
    try:
        return Backend(chan.recv, chan.sendall, _close, name)
    except Exception:
        _close()
        raise
