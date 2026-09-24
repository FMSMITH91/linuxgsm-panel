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
import codecs
import collections
import fcntl
import logging
import os
import pty
import select
import signal
import socket
import termios
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
# How long a single write may spend waiting for the far side to take the bytes. A pty's input
# queue holds about 8 KB of line-terminated text; past that the write waits for the foreground
# program to read, and a program that never reads stdin (a build, an apt run, a game console)
# never lets it finish. Measured: 8160 bytes went straight through, 12288 blocked indefinitely.
# How long a single paramiko send may spend waiting for the channel to take the bytes. The pty
# path does not need this — its writes are queued and drained by the pump — but a channel send has
# no queue behind it.
_WRITE_BUDGET = 2.0

# The most unwritten input to hold for a program that is not reading. The pty's own queue takes
# about 8 KB, so this is one refused paste plus headroom; past it the operator is told rather than
# the panel growing a buffer without limit.
_MAX_PENDING_INPUT = 256 * 1024

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


def panel_account():
    """The account a LOCAL terminal will run as, or "" if it cannot be read.

    Same source sudo_hint reads. The page used to state "running as the panel's own account — not
    as root" for every local session, which is true of a root install's service account and reads
    as a contradiction on a per-user one, where the hint immediately above it says the account may
    already be root. Naming the account says the same thing without asserting anything about it.
    """
    try:
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_name or ""
    except Exception:
        _log.debug("could not read the panel's own account name", exc_info=True)
        return ""


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
    # WHICH install this is decides the whole answer, and the first version of this hint only knew
    # about one of them. A root install runs as a dedicated service account whose sudoers entry
    # names one command, so sudo refuses. A PER-USER install runs as the operator's own account —
    # and on a cloud image that account usually has NOPASSWD:ALL, so sudo neither refuses nor
    # prompts, it just works. Reported from a live panel: `sudo apt full-upgrade` ran to completion
    # under a banner explaining how to enable sudo.
    from panel.ops.system_ops import _is_system_service
    if not _is_system_service():
        return ("This shell runs as %s — your own account, because this panel is installed "
                "per-user rather than as a system service. It has exactly the sudo %s has, and on "
                "a typical cloud image that is full root with no password prompt. Anyone you give "
                "the terminal permission to gets the same." % (user, user))
    return ("This shell runs as %s. If `sudo` refuses rather than asking for a password, that "
            "account has no general sudo entry — the panel's grant covers only its privileged "
            "helper. To allow it, re-run the installer as root with PANEL_TERMINAL_SUDO=1 and "
            "give %s a password; sudo will then prompt for it every time. Note that you would be "
            "typing that password into a terminal the panel renders." % (user, user))


def _drain_input(sess, fd):
    """Write whatever `write()` queued, from the PUMP — the one greenlet that owns this fd.

    The obvious shape, waiting for writability from the socket-event greenlet, does not work here:
    eventlet allows only one greenlet to wait on a descriptor for a given event, and the pump is
    already select()ing on this one. Doing it anyway raises "Second simultaneous write on fileno
    N", which Session.write caught and turned into a closed session — every keystroke killed the
    terminal. The module docstring already said this thread owns the descriptor; now it does.

    Returns the number of bytes dropped because the far side would not take them.
    """
    dropped = 0
    while sess._inq:
        chunk = sess._inq[0]
        try:
            n = os.write(fd, chunk)
        except BlockingIOError:
            return dropped          # no room right now; the next pass will try again
        except OSError:
            sess._inq.clear()
            raise
        if n >= len(chunk):
            sess._inq.popleft()
        else:
            sess._inq[0] = chunk[n:]
            return dropped          # partial: leave the rest for the next writable pass
    return dropped


def _send_chan(chan, data, budget=_WRITE_BUDGET):
    """The same for a paramiko channel, which is non-blocking (settimeout(0.0)) for the pump.

    Channel.send returns the number of bytes it took and paramiko's own docs put the onus on the
    caller to check it; a short send was being discarded, which silently truncated a paste.
    """
    mv = memoryview(data)
    sent, deadline = 0, time.monotonic() + budget
    while sent < len(mv):
        try:
            n = chan.send(mv[sent:])
        except socket.timeout:
            n = 0
        if n:
            sent += n
        elif time.monotonic() >= deadline:
            return sent
        else:
            time.sleep(0.02)                      # patched by eventlet → yields
    return sent


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
        # ONE decoder for the whole session, not one per chunk. A read boundary falls wherever the
        # kernel or the ssh channel put it, so a multi-byte character — a box-drawing glyph in a
        # TUI, an accented name in a log line, an emoji in a MOTD — is routinely split across two
        # reads. Decoding each chunk on its own turned every one of those into two replacement
        # characters, permanently, because the tail of one chunk and the head of the next were
        # never the same string. An incremental decoder holds the partial sequence instead.
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._inq = collections.deque()        # keystrokes waiting for the pump to write them

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
        payload = data.encode("utf-8", errors="replace")
        if self._chan is not None:
            try:
                sent = _send_chan(self._chan, payload)
            except Exception:
                _log.debug("terminal write failed for %s", self.label, exc_info=True)
                self.close("the session ended")
                return
            if sent < len(payload):
                self._report_dropped(len(payload) - sent)
            return
        if self._fd is None:
            return
        # QUEUED, not written here. The pump owns the descriptor (see _drain_input), and the queue
        # is bounded so a program that never reads its input cannot grow it without limit — the
        # pty's own buffer holds about 8 KB, so this is the paste that did not fit plus room.
        queued = sum(len(c) for c in self._inq)
        if queued + len(payload) > _MAX_PENDING_INPUT:
            self._report_dropped(len(payload))
            return
        self._inq.append(payload)

    def _report_dropped(self, n):
        """Say so. Dropping input silently is how a pasted config ends up half-applied with
        nothing on screen to suggest it."""
        _log.warning("terminal %s: dropped %d input bytes — the program is not reading",
                     self.label, n)
        self._emit("\r\n\x1b[33m[%d bytes of input were dropped — the program running here is "
                   "not reading its input]\x1b[0m\r\n" % n)

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
        self._teardown()
        # Only THIS session's entry. Teardown yields (the kill grace, the pump join), and a newer
        # session can register under the same socket meanwhile — a term_open after the idle
        # sweeper started closing this one. Popping by sid removed that live shell from the map,
        # where input, the disconnect hook, the sweeper and the per-user cap all look for it.
        with _sessions_lock:
            if _sessions.get(self.sid) is self:
                del _sessions[self.sid]
        try:
            self._on_exit(self.sid, reason)
        except Exception:  # nosec B110
            _log.debug("terminal exit callback failed for %s", self.label, exc_info=True)

    def _teardown(self):
        """Release whatever transport is attached. Every step is safe to run twice.

        The process goes first, and only then the fd: killing the child closes the pty slave,
        the pump's next read returns EOF, and the pump closes the master itself. Closing the fd
        out from under a thread that is select()ing on it is a use-after-free for file
        descriptors — the number is immediately reusable, so the pump can wake up on some other
        session's socket and write ITS bytes into this browser.
        """
        for shut in (self._close_chan, self._close_proc, self._close_fd, self._close_client):
            try:
                shut()
            except Exception:  # nosec B110
                _log.debug("terminal teardown step failed for %s", self.label, exc_info=True)

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
                # EBADF: the pump reached it between the join timing out and this line. That is
                # the outcome this branch wanted anyway — the descriptor is closed either way and
                # there is nothing left to do about it.
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
                sess._emit(sess._decoder.decode(data))
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
                # One greenlet, one descriptor, both directions. Asking for writability only when
                # something is queued keeps the common case a plain read wait.
                r, w, _ = select.select([fd], [fd] if sess._inq else [], [], 0.2)
                if w:
                    _drain_input(sess, fd)
                if not r:
                    continue
                data = os.read(fd, _READ_CHUNK)
                if not data:
                    break
                sess._emit(sess._decoder.decode(data))
            except BlockingIOError:
                # The descriptor is non-blocking now (see _write_fd). select said readable and the
                # byte was gone by the time we read: that is not the end of the session.
                continue
            except (OSError, ValueError):
                break
            except Exception:
                break
    finally:
        # Claim it before closing — and close it ONLY if the claim succeeded. os.close used to sit
        # outside this branch, which undid the very race the claim exists for: when _close_fd's
        # join times out it takes the fd and closes it, the kernel hands that NUMBER to the next
        # open() anywhere in the process, and this line then closed a descriptor belonging to
        # something else. The except below cannot catch that — closing a recycled number succeeds.
        if sess._fd == fd:
            sess._fd = None
            try:
                os.close(fd)
            except OSError:
                pass        # already gone; nothing owed
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
        # One shell per socket. A LIVE entry under this sid is refused, never overwritten: an
        # overwritten session keeps running with its pump emitting to the room, but nothing can
        # reach it any more to type into it or close it. An entry that is already closing is only
        # waiting for its teardown and is replaced — and not counted against the caps below.
        prior = _sessions.get(sess.sid)
        if prior is not None and not prior.closed:
            raise TerminalError("A terminal is already open on this connection. Reload the page "
                                "to start another.")
        others = [s for s in _sessions.values() if s is not prior]
        if len(others) >= _MAX_SESSIONS_TOTAL:
            raise TerminalError("Too many terminal sessions are open on this panel (%d). Close one "
                                "and try again." % _MAX_SESSIONS_TOTAL)
        mine = sum(1 for s in others if s.user_key == user_key)
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
    # The session is registered BEFORE its transport opens, and a paramiko connect can take the
    # whole ssh_timeout. A close in that window (the tab closing, term_close, a second term_open)
    # found nothing attached and tore nothing down; the opener then attached a client and a live
    # login shell to a session already marked closed, and close() — idempotent — never ran again.
    # That connection stayed up until the panel restarted, outside the sweeper and the caps. So
    # look again now that the transport exists, and release it here.
    if sess.closed:
        sess._teardown()
        raise TerminalError("The terminal on %s closed while it was opening." % label)
    return sess


def _login_shell():
    """This account's own login shell, from its passwd entry.

    It read os.environ["SHELL"] before. Under systemd that variable is not set at all, so a root
    install always got the /bin/bash fallback no matter what shell the account actually has — and
    on a per-user install it got whatever the launching session happened to export, which is the
    environment's answer rather than the account's.

    A non-interactive shell is rejected: `useradd --system` gives /usr/sbin/nologin by default
    (this installer passes --shell /bin/bash, but an operator who created the account themselves
    may not have), and spawning nologin produces a terminal that prints one line and exits.
    """
    shell = ""
    try:
        import pwd
        shell = pwd.getpwuid(os.geteuid()).pw_shell or ""
    except Exception:
        _log.debug("could not read the account's passwd entry", exc_info=True)
    if os.path.basename(shell) in ("nologin", "false", "sync", ""):
        return "/bin/bash"
    return shell


def _open_local(sess, cols, rows):
    """The panel user's own login shell, under a pty.

    No sudo, no `-u`: this is the account the panel already runs as. Escalating here would hand a
    root shell to anything that can reach the panel, which is precisely what the narrow sudoers
    grant is for.
    """
    master, slave = pty.openpty()
    shell = _login_shell()
    env = dict(os.environ)
    env["TERM"] = "xterm-256color"
    # A login shell, so the operator gets their own profile rather than the service unit's stripped
    # environment. start_new_session gives it its own process group for the SIGHUP on teardown.
    def _attach_ctty():
        """Make the slave this process's CONTROLLING terminal, in the child, after setsid().

        start_new_session=True calls setsid, which is necessary but not sufficient: the child then
        has no controlling terminal at all, because it INHERITS the slave as a descriptor rather
        than opening it. Without one there is no foreground process group, so the line discipline
        has nobody to send SIGINT to — Ctrl-C does nothing.

        It read as working because bash only complains ("cannot set terminal process group", "no
        job control in this shell") and carries on. fish refuses outright: "No TTY for interactive
        shell (tcgetpgrp failed)", and exits immediately — which is how this was finally noticed,
        on a machine whose passwd shell is fish.

        Then SIGINT and SIGQUIT go back to their defaults. An ignored disposition survives fork
        and exec, and the shell hands the dispositions it started with to every job it runs, so a
        panel started with them ignored — from a script with `&`, where the shell ignores both for
        a background command — gave every local terminal a `sleep`, a `tail -f` or a runaway loop
        that ^C and ^\\ could not stop, with the foreground process group set up correctly. It
        worked under systemd only because systemd starts the service with default dispositions.
        """
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        # After the ioctl, and on its own: without a controlling terminal there is no Ctrl-C at
        # all, while a failure here costs only the reset. signal.signal is allowed in this child —
        # subprocess runs PyOS_AfterFork_Child before preexec_fn, making this its main thread.
        try:
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            signal.signal(signal.SIGQUIT, signal.SIG_DFL)
        except (OSError, ValueError):  # nosec B110
            pass

    try:
        proc = subprocess.Popen(  # nosec B603  # nosemgrep - argv list, no shell=True; argv[0] is
            # this account's own passwd shell, never caller input and never read from the
            # environment.
            [shell, "-l"], stdin=slave, stdout=slave, stderr=slave,
            preexec_fn=_attach_ctty,  # nosec B606 - not a shell; see the docstring above
            start_new_session=True, env=env, cwd=os.path.expanduser("~"))
    except Exception:
        # Both ends, or the pair leaks with a /dev/pts device behind it. open_session's handler
        # calls sess.close(), but nothing has been attached to the session yet, so every teardown
        # step is a no-op — and the operator's response to "could not start a shell" is to click
        # again. cwd is a real failure mode here: a service account made without -m has no home.
        os.close(master)
        os.close(slave)
        raise
    os.close(slave)
    os.set_blocking(master, False)      # see _write_fd: a blocking write here stops the whole hub
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


def _ssh_argv(server):
    """The ssh command line for a tailscale remote. Pure, so the property below can be tested.

    ssh has no `--` to end its options, so an argv element that BEGINS with `-` is read as one —
    and `server.host` is stored data. HOST_RE permits a leading dash (`-o` and `--` both match
    it), so the thing that makes this safe is not the host pattern: it is that the destination is
    always `user@host`, and LINUX_USER_RE forces the username to start with a letter or
    underscore. The element therefore never begins with `-` whatever the host says.

    That is a property worth pinning rather than asserting in a comment, so tests/unit drives this
    function with hostile hosts and checks every element.
    """
    # The SAME resolver the non-interactive tailscale transport uses. A second copy of MagicDNS
    # handling would be one more place to get a hostname subtly wrong.
    from panel.ops.ssh_manager import _core
    user = getattr(server, "username", "") or "root"
    host = _core._resolve_ts_host(server)
    return ["ssh", "-tt",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=20",
            "-p", str(int(getattr(server, "port", 22) or 22)),
            "%s@%s" % (user, host)]


def _open_tailscale(sess, server, cols, rows):
    """Tailscale remotes: tailscaled holds the credentials, so this is the system ssh client.

    `-tt` forces a pty even though our stdin is not one from ssh's point of view, which is what
    makes an interactive shell possible at all here.
    """
    master, slave = pty.openpty()
    env = dict(os.environ)
    env["TERM"] = "xterm-256color"
    argv = _ssh_argv(server)
    try:
        proc = subprocess.Popen(  # nosec B603  # nosemgrep - see _ssh_argv: a list, no shell, and
            # the one element carrying stored data cannot be read by ssh as an option.
            argv, stdin=slave, stdout=slave, stderr=slave, start_new_session=True, env=env)
    except Exception:
        os.close(master)      # argv[0] is "ssh": a host without openssh-client leaks a pair each try
        os.close(slave)
        raise
    os.close(slave)
    os.set_blocking(master, False)      # see _write_fd: a blocking write here stops the whole hub
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

