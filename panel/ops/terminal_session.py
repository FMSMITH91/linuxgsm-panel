"""Interactive shell sessions — a real PTY, for the panel host and for remote hosts.

This is NOT the game console. That one is line-oriented, one-way and deliberately so: a poller
tails the game's log over SSH and `tmux send-keys` posts a command. Nothing here touches it, and
nothing here should be made to serve it — see the note in panel/core/terminal.py about why the
console's reliability is not negotiable.

What a terminal needs that the console does not: a pseudo-terminal. Anything full-screen — `top`,
`less`, `nano`, apt's progress bar — drives the cursor directly and uses the alternate screen, so
the bytes only mean anything to a terminal emulator. The browser side runs xterm.js; this side
just moves bytes and never interprets them.

THREE TRANSPORTS, because the panel already has three ways to reach a host:

  local          pty.openpty() + the panel user's login shell.
  key/password   paramiko invoke_shell() on a client this module OWNS.
  tailscale      `ssh -tt` under a pty, because tailscaled holds the credentials and paramiko
                 cannot speak to it.

EVENTLET. The whole app is monkey-patched and the hub is cooperative, so a blocking read starves
every other request in the process. `select.select` IS patched and yields; `os.read` on a pty fd
is NOT, so it is only ever called after select says the fd is ready. Paramiko channels use the
`recv_ready()` + short `time.sleep` shape that _core._drain_exec already uses for the same reason.

WHAT THIS MODULE REFUSES TO DO: escalate. The session runs as the panel user locally, or as the
host's configured SSH user remotely. It does not pass `sudo`, it holds no password, and it types
nothing on the operator's behalf. If they run `sudo` inside the session, that is between them and
the host's own sudoers — which on a root install means it will refuse outright, because the
service account has no general sudo entry and no password at all. `sudo_hint()` exists so the UI
can say that up front instead of letting the operator discover it as a mystery.
"""
import logging
import os
import pty
import select
import signal
import subprocess  # nosec B404 - the tailscale transport needs a real process under a pty
import threading
import time

_log = logging.getLogger("panel.terminal")

# One session's ceiling. A runaway `cat /dev/urandom` must not be able to drown the browser, the
# socket or the panel process, and the operator should be told it was cut rather than left
# wondering why the screen froze.
_MAX_BYTES_PER_SEC = 512 * 1024
_READ_CHUNK = 16 * 1024

# A terminal nobody is typing into is a shell someone left open on a host. Closed after this long
# with no INPUT (output alone does not count — `tail -f` would otherwise hold it open forever).
_IDLE_TIMEOUT = 15 * 60

# Ceilings so a bug or a bored admin cannot spawn shells until the host runs out of pty devices.
# How long each teardown signal gets before the next, harder one. Short: the normal case is the
# child exiting on the pty master's EIO before the first signal is even sent, and this only runs
# when it did not. Three steps, so a process that ignores everything costs 0.75s once.
_KILL_GRACE = 0.25

# How long a teardown waits for the pump thread to notice EOF and close its own fd. The child is
# already dead by then, so this is one select() timeout plus slack.
_PUMP_JOIN = 1.0

_MAX_SESSIONS_TOTAL = 12
_MAX_SESSIONS_PER_USER = 3

_sessions = {}                     # sid -> Session
_sessions_lock = threading.Lock()


class TerminalError(Exception):
    """Anything the operator should be shown as text in the terminal, rather than a traceback."""


def sudo_hint(server, is_local):
    """What to tell the operator about sudo BEFORE they try it, or "" when there is nothing to say.

    A root/system install runs the panel as a dedicated service account created with
    `useradd --system`: no password (the shadow field is `!`) and a sudoers entry naming exactly
    one command, the privileged helper. So `sudo` there does not prompt — it refuses, and an
    operator who does not know that reads it as the terminal being broken.

    Deliberately NOT fixed by widening the grant from in here. That decision belongs to whoever
    installs the panel, it has to survive a self-update (install.sh rewrites the sudoers file on
    every run), and a panel that can grant itself root is the thing the narrow grant exists to
    prevent.
    """
    if not is_local:
        # A remote's sudoers is that host's business and the panel must not speak for it: cloud
        # images commonly ship NOPASSWD for the login user, hardened ones ask for a password, and
        # some accounts have no sudo at all. Saying nothing is more honest than guessing.
        return ""
    try:
        import pwd
        user = pwd.getpwuid(os.geteuid()).pw_name
    except Exception:
        return ""
    if user == "root":
        return ""
    return ("This shell runs as %s. If `sudo` refuses rather than asking for a password, that "
            "account has no general sudo entry — the panel's grant covers only its privileged "
            "helper. To allow it, re-run the installer as root with PANEL_TERMINAL_SUDO=1 and "
            "give %s a password; sudo will then prompt for it every time. Note that you would be "
            "typing that password into a terminal the panel renders." % (user, user))


class Session:
    """One live shell. Owns its transport and is responsible for tearing it down exactly once."""

    def __init__(self, sid, label, on_output, on_exit):
        self.sid = sid
        self.label = label
        self._on_output = on_output
        self._on_exit = on_exit
        self._closed = False
        self._lock = threading.Lock()
        self.last_input = time.time()
        # Rate limiting is per whole seconds: simpler to reason about than a token bucket, and
        # the thing it defends against (a firehose) lasts much longer than a second.
        self._window = 0
        self._window_bytes = 0
        self._throttled = False
        # set by the openers
        self._chan = None          # paramiko Channel
        self._client = None        # paramiko SSHClient we own
        self._fd = None            # pty master fd
        self._proc = None          # subprocess.Popen
        self._pump = None          # the thread reading this session's transport

    # ── output ────────────────────────────────────────────────────────────────────────────────
    def _emit(self, data):
        now = int(time.time())
        if now != self._window:
            self._window, self._window_bytes = now, 0
            self._throttled = False
        self._window_bytes += len(data)
        if self._window_bytes > _MAX_BYTES_PER_SEC:
            if not self._throttled:
                self._throttled = True
                self._on_output(self.sid,
                                "\r\n\x1b[33m[output truncated — more than %d KB/s. The command is "
                                "still running; press Ctrl-C to stop it.]\x1b[0m\r\n"
                                % (_MAX_BYTES_PER_SEC // 1024))
            return
        self._on_output(self.sid, data)

    # ── input ─────────────────────────────────────────────────────────────────────────────────
    def write(self, data):
        """Send keystrokes. Never logged: people type passwords into terminals."""
        if self._closed or not data:
            return
        self.last_input = time.time()
        try:
            if self._chan is not None:
                self._chan.send(data)
            elif self._fd is not None:
                os.write(self._fd, data.encode("utf-8", errors="replace"))
        except Exception:
            _log.debug("terminal write failed for %s", self.label, exc_info=True)
            self.close("the session ended")

    def resize(self, cols, rows):
        """Follow the browser's window. Without this, anything full-screen draws to the wrong box."""
        try:
            cols, rows = int(cols), int(rows)
        except (TypeError, ValueError):
            return
        # Clamped: these reach an ioctl and a remote request, and a terminal 60000 columns wide is
        # not a size anybody's window is.
        cols = max(20, min(cols, 500))
        rows = max(5, min(rows, 200))
        if self._closed:
            return
        try:
            if self._chan is not None:
                self._chan.resize_pty(width=cols, height=rows)
            elif self._fd is not None:
                import fcntl
                import struct
                import termios
                fcntl.ioctl(self._fd, termios.TIOCSWINSZ,
                            struct.pack("HHHH", rows, cols, 0, 0))
        except Exception:
            _log.debug("terminal resize failed for %s", self.label, exc_info=True)

    # ── teardown ──────────────────────────────────────────────────────────────────────────────
    def close(self, reason=""):
        """Idempotent: the browser closing, an idle sweep and the shell exiting can all race."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        # The process goes first, and only then the fd: killing the child closes the pty slave,
        # the pump's next read returns EOF, and the pump closes the master itself. Closing the fd
        # out from under a thread that is select()ing on it is a use-after-free for file
        # descriptors — the number is immediately reusable, so the pump can wake up on some other
        # session's socket and write ITS bytes into this browser.
        for shut in (self._close_chan, self._close_proc, self._close_fd, self._close_client):
            try:
                shut()
            except Exception:  # nosec B110
                _log.debug("terminal teardown step failed for %s", self.label, exc_info=True)
        with _sessions_lock:
            _sessions.pop(self.sid, None)
        try:
            self._on_exit(self.sid, reason)
        except Exception:  # nosec B110
            _log.debug("terminal exit callback failed for %s", self.label, exc_info=True)

    def _close_chan(self):
        if self._chan is not None:
            self._chan.close()

    def _close_proc(self):
        """Make sure the process is actually gone, rather than sending one signal and hoping.

        This used to be a single SIGHUP to the process group, and a closed browser tab left an
        `ssh -tt` to the remote host running for good — one more per session opened, forever.
        The reason is worth writing down: an IGNORED signal disposition survives both fork and
        execve, so if the panel process itself ignores SIGHUP every shell and ssh it spawns
        inherits that, and killpg returns success having done nothing at all. `nohup` sets exactly
        that disposition, and so does anything started from a shell that did. Confirmed by reading
        SigIgn in /proc for the panel and for the orphaned ssh: bit 0 set on both.

        So: escalate, and CHECK. SIGHUP is still first because it is what a login shell wants to
        see, SIGTERM next, SIGKILL last — and nothing here reports success without poll() having
        confirmed it.
        """
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        # The whole group: `ssh -tt` and the local shell both have children, and killing only the
        # leader leaves those attached to a pty nobody is reading.
        try:
            pgid = os.getpgid(proc.pid)
        except (ProcessLookupError, PermissionError):
            pgid = None
        for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGKILL):
            try:
                if pgid is not None:
                    os.killpg(pgid, sig)
                else:
                    proc.send_signal(sig)
            except (ProcessLookupError, PermissionError):
                return                      # already gone, or never ours to kill
            deadline = time.monotonic() + _KILL_GRACE
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    return
                time.sleep(0.05)            # patched by eventlet → yields the hub
        _log.warning("terminal %s: pid %s survived SIGKILL", self.label, proc.pid)

    def _close_fd(self):
        """Let the pump close its own fd; only take it back if the pump is wedged.

        _close_proc has already made sure the child is dead, so the pump is about to read EOF and
        retire. Waiting for it is what keeps this descriptor from being closed under a live
        select().
        """
        t = self._pump
        if t is not None and t is not threading.current_thread():
            t.join(timeout=_PUMP_JOIN)
        fd, self._fd = self._fd, None
        if fd is not None:
            # The pump did not get there — a leaked pty master is worse than a small race, and at
            # this point the thread is not coming back.
            _log.warning("terminal %s: pump did not retire, closing fd %s from the caller",
                         self.label, fd)
            try:
                os.close(fd)
            except OSError:
                pass

    def _close_client(self):
        if self._client is not None:
            self._client.close()

    @property
    def closed(self):
        return self._closed


def _pump_channel(sess):
    """paramiko: the recv_ready + short sleep shape _core._drain_exec uses, for the same reason."""
    chan = sess._chan
    while not sess.closed:
        try:
            if chan.recv_ready():
                data = chan.recv(_READ_CHUNK)
                if not data:
                    break
                sess._emit(data.decode("utf-8", errors="replace"))
                continue
            if chan.exit_status_ready() and not chan.recv_ready():
                break
            time.sleep(0.02)      # patched by eventlet → yields the hub
        except Exception:
            break
    sess.close("the shell exited")


def _pump_fd(sess):
    """Local/tailscale: select yields under eventlet; os.read on a pty fd would not.

    This thread OWNS the pty master. Nothing else closes it while this loop is running, because a
    descriptor closed under a live select() can be handed straight back out by the next open() and
    this loop would go on reading it.
    """
    fd = sess._fd
    try:
        while not sess.closed:
            try:
                r, _, _ = select.select([fd], [], [], 0.2)
                if not r:
                    continue
                data = os.read(fd, _READ_CHUNK)
                if not data:
                    break
                sess._emit(data.decode("utf-8", errors="replace"))
            except (OSError, ValueError):
                break
            except Exception:
                break
    finally:
        # Claim it before closing: _close_fd reads this to decide whether it still has to.
        if sess._fd == fd:
            sess._fd = None
        try:
            os.close(fd)
        except OSError:
            pass
    sess.close("the shell exited")


def _idle_sweeper():
    """Close sessions nobody has typed into. Output does not count — `tail -f` is not activity."""
    while True:
        try:
            now = time.time()
            with _sessions_lock:
                stale = [s for s in _sessions.values() if now - s.last_input > _IDLE_TIMEOUT]
            for s in stale:
                s.close("closed after %d minutes with no input" % (_IDLE_TIMEOUT // 60))
        except Exception:  # nosec B110
            _log.debug("terminal idle sweep failed", exc_info=True)
        time.sleep(30)


def start_idle_sweeper(supervise):
    """Wired from the app factory with the same supervisor the console poller uses."""
    supervise("terminal-idle-sweeper", _idle_sweeper)


def _register(sess, user_key):
    with _sessions_lock:
        if len(_sessions) >= _MAX_SESSIONS_TOTAL:
            raise TerminalError("Too many terminal sessions are open on this panel (%d). Close one "
                                "and try again." % _MAX_SESSIONS_TOTAL)
        mine = sum(1 for s in _sessions.values() if s.user_key == user_key)
        if mine >= _MAX_SESSIONS_PER_USER:
            raise TerminalError("You already have %d terminals open. Close one and try again."
                                % _MAX_SESSIONS_PER_USER)
        _sessions[sess.sid] = sess


def open_session(sid, server, is_local, user_key, on_output, on_exit, cols=80, rows=24):
    """Start a shell and return its Session. Raises TerminalError with text fit to show a user."""
    label = "local" if is_local else getattr(server, "name", "remote")
    sess = Session(sid, label, on_output, on_exit)
    sess.user_key = user_key
    _register(sess, user_key)
    try:
        if is_local:
            _open_local(sess, cols, rows)
        elif getattr(server, "auth_method", "") == "tailscale":
            _open_tailscale(sess, server, cols, rows)
        else:
            _open_paramiko(sess, server, cols, rows)
    except TerminalError:
        sess.close("")
        raise
    except Exception as e:
        sess.close("")
        _log.warning("terminal open failed for %s", label, exc_info=True)
        raise TerminalError("Could not start a shell on %s (%s)." % (label, type(e).__name__))
    return sess


def _open_local(sess, cols, rows):
    """The panel user's own login shell, under a pty.

    No sudo, no `-u`: this is the account the panel already runs as. Escalating here would hand a
    root shell to anything that can reach the panel, which is precisely what the narrow sudoers
    grant is for.
    """
    master, slave = pty.openpty()
    shell = os.environ.get("SHELL") or "/bin/bash"
    env = dict(os.environ)
    env["TERM"] = "xterm-256color"
    # A login shell, so the operator gets their own profile rather than the service unit's stripped
    # environment. start_new_session gives it its own process group for the SIGHUP on teardown.
    proc = subprocess.Popen(  # nosec B603 - fixed argv, no shell=True, no caller input
        [shell, "-l"], stdin=slave, stdout=slave, stderr=slave,
        start_new_session=True, env=env, cwd=os.path.expanduser("~"))
    os.close(slave)
    sess._fd = master
    sess._proc = proc
    sess.resize(cols, rows)
    sess._pump = threading.Thread(target=_pump_fd, args=(sess,), daemon=True)
    sess._pump.start()


def _open_paramiko(sess, server, cols, rows):
    """Key/password remotes. pooled=False so this client is ours to close."""
    from panel.ops.ssh_manager import _core
    client = _core.get_connection(server, force_new=True, pooled=False)
    if client is None:
        raise TerminalError("That host has no SSH connection.")
    sess._client = client
    chan = client.invoke_shell(term="xterm-256color", width=int(cols), height=int(rows))
    chan.settimeout(0.0)
    sess._chan = chan
    sess._pump = threading.Thread(target=_pump_channel, args=(sess,), daemon=True)
    sess._pump.start()


def _open_tailscale(sess, server, cols, rows):
    """Tailscale remotes: tailscaled holds the credentials, so this is the system ssh client.

    `-tt` forces a pty even though our stdin is not one from ssh's point of view, which is what
    makes an interactive shell possible at all here.
    """
    from panel.ops.ssh_manager import _core
    # The SAME resolver the non-interactive tailscale transport uses. A second copy of MagicDNS
    # handling would be one more place to get a hostname subtly wrong.
    host = _core._resolve_ts_host(server)
    user = getattr(server, "username", "") or "root"
    master, slave = pty.openpty()
    env = dict(os.environ)
    env["TERM"] = "xterm-256color"
    argv = ["ssh", "-tt",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=20",
            "-p", str(int(getattr(server, "port", 22) or 22)),
            "%s@%s" % (user, host)]
    proc = subprocess.Popen(  # nosec B603 - argv built here from validated fields, no shell
        argv, stdin=slave, stdout=slave, stderr=slave, start_new_session=True, env=env)
    os.close(slave)
    sess._fd = master
    sess._proc = proc
    sess.resize(cols, rows)
    sess._pump = threading.Thread(target=_pump_fd, args=(sess,), daemon=True)
    sess._pump.start()


def get(sid):
    with _sessions_lock:
        return _sessions.get(sid)


def close_for_sid(sid, reason="the connection closed"):
    s = get(sid)
    if s is not None:
        s.close(reason)


def count():
    with _sessions_lock:
        return len(_sessions)

