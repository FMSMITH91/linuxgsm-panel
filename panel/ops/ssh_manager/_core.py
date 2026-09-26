"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import logging
import os
import re
import shlex
import signal
import socket
import stat
import subprocess  # nosec B404 - every call site below passes an argv LIST, never a shell string
import tempfile
import threading
import time
import paramiko
from panel.core.config import decrypt_secret
from panel.security import privileged as _priv
# ── Per-remote caches, and forgetting a host that no longer exists ────────────────────────────
# Several modules in this package memoise an answer PER HOST, keyed by RemoteServer.id. SQLite
# hands a deleted row's id straight to the next INSERT (plain INTEGER PRIMARY KEY = rowid, no
# AUTOINCREMENT), so whatever a deleted host left behind is inherited by the next host added —
# and these are read to RENDER its pages and to decide where to send a player query.
#
# game.py already closes this for its version cache, with an after_delete listener and the
# argument for why it belongs there rather than in the delete route ("the invariant belongs where
# the row goes away, not at each of the places that remove one"). Three caches were left out of
# that, and the longest-lived one has no expiry at all (hosts._OS_SLUG_CACHE, found later, has
# none either):
#
#   firewall._specs_cache      the host's CPU/RAM/disk/kernel/OS — cached for the PROCESS's life,
#                              so a recycled id shows the deleted machine's hardware until restart
#   hosts._pro_status_cache    Ubuntu Pro attachment + services, 24h
#   _gamedig_host_cache        the address player queries are sent to, 1h — so a new host's
#                              player counts would come from the OLD host's IP, and those counts
#                              are what "is this server empty?" is decided on
#
# REGISTERED AT THE DECLARATION rather than named in a list here, for the reason panel_state
# gives at length: a hand-kept list is an edit somebody has to remember to make somewhere else,
# and that is exactly how these three were missed.
#
# EVERY per-remote cache is registered now, the short-lived ones included. They used to be left
# out on the grounds that "they self-correct before anyone could add a host, and a tuple-keyed
# entry is not addressable by a bare row id anyway" — the second half of which was true and is the
# real reason to fix forget_remote_caches rather than to keep a list of exceptions. It drops tuple
# keys containing the id now, so registration costs nothing and the exception list is gone. What
# that list actually hid was hosts._OS_SLUG_CACHE: no expiry at all, keyed ("srv", id), and NOT in
# it — a deleted host's distro slug chose the package list for whatever host took its rowid next.
_remote_caches = []


def register_remote_cache(mapping):
    """Mark `mapping` as keyed by RemoteServer.id so a deleted host is forgotten from it.
    Returns `mapping`, so a declaration can wrap itself: `_x = _core.register_remote_cache({})`."""
    _remote_caches.append(mapping)
    return mapping


def forget_remote_caches(remote_id):
    """Drop every per-remote memo for `remote_id`. Safe to call for an id nothing cached.

    TUPLE keys are handled as well as bare ids. Several of these memos are keyed by
    (remote id, port) or (remote id, user) — `m.pop(remote_id)` could never reach those, so
    registering such a cache would have looked like protection while doing nothing, which is
    worse than not registering it. A tuple containing the id is dropped; the worst a coincidence
    costs (a port that happens to equal a deleted host's id) is one re-read."""
    for m in _remote_caches:
        m.pop(remote_id, None)
        for key in [k for k in list(m) if isinstance(k, tuple) and remote_id in k]:
            m.pop(key, None)


from panel.ops.ssh_manager import (cron)  # noqa: E402,F401  (module objects: the
# reference resolves at CALL time, which is what keeps a stub on the definition site
# visible to every caller — see the package docstring.





_log = logging.getLogger("panel.ssh")


class HostKeyMismatch(ConnectionError):
    """The server presented a different SSH host key than the one we pinned (possible
    MITM, or the box was reinstalled). Raised instead of silently trusting the new key."""


class _PinPolicy(paramiko.MissingHostKeyPolicy):
    """Trust-on-first-use SSH host-key pinning, replacing paramiko's AutoAddPolicy (which
    blindly trusts any key and is a MITM risk). We never pre-load keys into the client, so
    paramiko always hands the presented key here and we decide:
      • no key pinned yet → capture it (the caller persists it) and accept — first use
      • matches the pin   → accept
      • differs from pin  → reject, unless reject_on_change is False (e.g. a pre-save probe
        with nothing to compare, or a Tailscale connection already authenticated by
        WireGuard, where the tailnet — not the SSH host key — is the trust anchor)."""

    def __init__(self, expected="", reject_on_change=True):
        self.expected = (expected or "").strip()
        self.reject_on_change = reject_on_change
        self.captured = None

    def missing_host_key(self, client, hostname, key):
        presented = "%s %s" % (key.get_name(), key.get_base64())
        if self.expected:
            if presented != self.expected and self.reject_on_change:
                raise HostKeyMismatch(
                    'The SSH host key for %s has CHANGED since it was first trusted. '
                    'This is either a man-in-the-middle attempt or the server was '
                    'reinstalled. If you reinstalled it, click "Re-trust host key" on the '
                    'server page; otherwise do NOT connect.' % hostname)
        else:
            self.captured = presented   # first contact → caller pins it


# Local subprocess execution must use the *unpatched* subprocess run inside
# eventlet's native thread pool — see _run_local() for the full rationale.
# When eventlet isn't active (standalone/CLI use) these fall back to plain subprocess.
try:
    from eventlet import tpool as _tpool
    from eventlet.patcher import original as _ev_original
    _real_subprocess = _ev_original("subprocess")
    # ...and the unpatched threading to go with it: _finish runs inside a tpool NATIVE thread,
    # where a green thread (what threading.Thread is after monkey_patch) has no hub to run on.
    _real_threading = _ev_original("threading")
except Exception:
    _tpool = None
    _real_subprocess = subprocess
    _real_threading = threading


# In-memory SSH connection cache, keyed by _conn_key() below.
_connections = {}
_conn_lock = threading.Lock()

# Row attributes a pooled client DEPENDS ON. The first three spell its cache key; the last two
# decide what it authenticated with. A change to any of them means the cached client is answering
# for a remote that no longer exists as described — see _register_remote_invalidation().
_CONN_IDENTITY_ATTRS = ("username", "host", "port")
_CONN_AUTH_ATTRS = ("auth_method", "auth_credential")

# remote row id -> the pool key its client was opened under. The pool is keyed by user@host:port
# because that is what identifies a connection; this remembers which key each ROW is currently
# holding, so a row whose host or user has just been rewritten can still name the entry it opened.
#
# Reconstructing the old key from SQLAlchemy attribute history does NOT work here, and the way it
# fails is quiet: after a commit every attribute is expired, so assigning to one of them leaves the
# others with no history at all — `deleted` and `unchanged` both empty. The changed attribute reads
# back correctly and the untouched ones come back None, which builds a key like "None@10.0.0.1:22"
# that matches nothing. Recording the key when it is used needs no inference.
_remote_conn_keys = {}


def _conn_key(username, host, port):
    """The pool key for a remote. One definition, because the bug below was that two call sites
    could disagree about which connection they were naming."""
    return "%s@%s:%s" % (username, host, port)


def _close_key(key):
    """Close and drop one cached client BY KEY. Returns whether there was one.

    close_connection() can only address the key its argument CURRENTLY spells, so it cannot reach
    a client whose row has since been repointed at a different host, port or user — that entry
    stays in the pool, with its socket and keepalive, for the life of the process. Addressing the
    pool by key is what makes the old entry reachable at all."""
    if key is None:
        return False
    with _conn_lock:
        client = _connections.pop(key, None)
        for rid in [r for r, k in _remote_conn_keys.items() if k == key]:
            del _remote_conn_keys[rid]
    if client is None:
        return False
    try:
        client.close()
    except Exception:
        _log.debug("_close_key: closing a stale SSH client failed", exc_info=True)
    return True


def _register_remote_invalidation():
    """Drop a remote's pooled SSH client whenever its row changes in a way the pool cannot see.

    WHY AN EVENT AND NOT ANOTHER CALL IN THE ROUTE. edit_remote rewrote username, host, port,
    auth_method and auth_credential and committed without closing anything. Two consequences, both
    silent: a ROTATED CREDENTIAL kept authenticating with the old one for as long as the 30-second
    keepalive held the socket open — so "I changed the key on that host" did not take effect — and
    a REPOINTED host orphaned its cache entry permanently, because close_connection builds the key
    from the row's current values and the old key was no longer spellable.

    Fixing edit_remote would have fixed edit_remote. The invariant is that a pooled client is valid
    only while the row it was opened from still names the same host and the same credential, and
    that belongs where the row changes rather than at each of the places that change it. Both old
    and new keys are closed: the old one is the orphan, the new one is the case where only the
    credential moved and the key did not.

    Never raises: a pool that failed to prune must not turn into a failed commit."""
    from sqlalchemy import event, inspect as _sa_inspect
    from panel.db.models import RemoteServer

    @event.listens_for(RemoteServer, "after_update")
    def _drop_stale_connection(_mapper, _connection, target):
        try:
            state = _sa_inspect(target)
            if not any(state.attrs[a].history.has_changes()
                       for a in _CONN_IDENTITY_ATTRS + _CONN_AUTH_ATTRS):
                return      # a rename or a stats-cache write must not churn the pool
            # The key this ROW opened (correct even when host/user/port have just been rewritten),
            # and the key it spells NOW (the case where only the credential moved).
            _close_key(_remote_conn_keys.get(target.id))
            _close_key(_conn_key(target.username, target.host, target.port))
        except Exception:
            _log.debug("SSH pool invalidation failed for a remote update", exc_info=True)


_register_remote_invalidation()


def _register_remote_cache_invalidation():
    """Forget a host's cached answers when its row is DELETED. Never raises — a cache that failed
    to prune must not turn into a failed commit."""
    from sqlalchemy import event
    from panel.db.models import RemoteServer

    @event.listens_for(RemoteServer, "after_delete")
    def _forget_remote(_mapper, _connection, target):
        try:
            forget_remote_caches(target.id)
        except Exception:
            _log.debug("per-remote cache prune failed for a deleted remote", exc_info=True)


_register_remote_cache_invalidation()


def _kill_process_tree(p):
    """Kill a Popen and its entire process group, so no grandchildren are left orphaned."""
    try:
        if hasattr(os, "killpg") and hasattr(os, "getpgid"):
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        else:
            p.kill()   # Windows / no process groups
    except Exception:
        try:
            p.kill()
        except Exception:  # nosec B110 - killing an already-dead process is the expected race
            pass           # here, and there is nothing left to do about it either way.
    try:
        p.communicate(timeout=5)   # reap it so it doesn't linger as a zombie
    except Exception:  # nosec B110
        pass


def _already_escalated(cmd):
    """True when `cmd` carries its own escalation, so `sudo bash -c` must not wrap it again.

    A named function rather than an inline condition because it cannot be reached from a test
    otherwise: tools/nosudo_runner replaces _run_local wholesale and blocks anything with
    sudo=True before the real body runs, so the branch this decides is invisible to the suite.

    It used to be `cmd.strip().startswith("sudo") or "sudo -u" in cmd`, and that second half was a
    SUBSTRING match over the whole command. Any command that merely MENTIONED `sudo -u` — inside a
    quoted argument, a grep pattern, a config line being written — skipped the wrap and ran
    UNPRIVILEGED, which for a caller that asked for root is a silent failure rather than an error.
    A caller that builds its own escalation passes sudo=False and never arrives here, so only the
    leading form is a real "already escalated"."""
    return cmd.strip().startswith("sudo ")


def _run_local(cmd, timeout=30, sudo=False, stdin_text=None):
    """Run a command locally on the panel's own machine.
    If the command already uses privilege escalation, don't double-wrap. `stdin_text`, when given,
    is the command's stdin (a secret that must not be in the command — see run_privileged).

    NOTE: eventlet monkey-patches subprocess. Its green subprocess is unreliable
    when called from a WSGI green thread (an API handler) — the child can be
    reaped before it finishes its work, so e.g. a crontab write silently no-ops
    while returncode is still 0. We therefore run the *original* (unpatched)
    subprocess inside eventlet's native thread pool (tpool), which both avoids
    that bug and keeps the event hub from blocking on long commands."""
    if not sudo:
        full_cmd = cmd
    elif _already_escalated(cmd):
        full_cmd = cmd  # already escalated
    else:
        # The test above used to be `startswith("sudo") or "sudo -u" in cmd`, and the second half
        # was a SUBSTRING match against the whole command. Any command that merely mentioned
        # `sudo -u` — inside a quoted argument, a grep pattern, a config line being written —
        # skipped the wrap and ran UNPRIVILEGED, which for a caller that asked for root is a
        # silent failure rather than an error. Nothing reaches it today (every caller that builds
        # its own `sudo -u` passes sudo=False, which never gets here), so this is a landmine
        # removed rather than a bug fixed — but it is exactly the kind that goes off years later.
        #
        # Wrap the WHOLE command in `sudo bash -c` (like the remote path) so pipes and
        # redirects run under root too. `sudo {cmd}` would only elevate the first command
        # in a pipe — e.g. `sudo yes | ufw delete N` runs ufw as the panel user ("need to
        # be root").
        full_cmd = f"sudo bash -c {_quote(cmd)}"

    return _exec_local_shell(full_cmd, timeout=timeout, stdin_text=stdin_text)


# Popen options shared by both local paths. start_new_session puts the child in a NEW process group
# so that on timeout we can kill the whole group — subprocess's own timeout kills only the direct
# child, and grandchildren (a stuck LinuxGSM command) are orphaned and run forever, burning CPU.
# (Observed: mods commands stuck at ~100% CPU for hours.) The pipes are BINARY: _finish reads
# them with a byte ceiling and decodes with errors="replace" itself (see _decode_output), which
# matches the paramiko path — command output is game-server output (player names, mod chatter,
# latin-1 logs) and is NOT guaranteed valid UTF-8; a strict decode would raise, get swallowed, and
# return rc=-1 with empty output — indistinguishable from "the command printed nothing".
# stdin=DEVNULL, not the default of inheriting: a privileged child must never be handed the
# panel's own stdin. The helper's Python-implemented verbs used to read stdin to EOF whether or
# not they wanted a payload, so a panel whose fd 0 was a pipe or tty -- anything but the systemd
# unit -- hung every such verb for its caller's full timeout. Both ends are fixed; this one stops
# a child from reaching the panel's input at all, which is right regardless of what it does with it.
_POPEN_KW = dict(stdout=_real_subprocess.PIPE, stderr=_real_subprocess.PIPE,
                 start_new_session=True, stdin=_real_subprocess.DEVNULL)


def _decode_output(b):
    """Bytes from a pipe -> the text Popen(text=True) would have produced from them: UTF-8 with
    errors="replace", and universal newlines (CRLF and a bare CR both become LF)."""
    return b.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


def _collect_capped(p, timeout, kill, thread_cls, stdin_bytes=None, cap=None):
    """communicate(), with a ceiling on what is KEPT. -> (out, err, rc, truncated) as bytes, or
    None when the command outlived `timeout` (it has been killed by then).

    communicate() buffers everything a command writes until it exits, and the two subprocess
    transports used it: a remote reached over Tailscale that answers a five-second metrics probe
    with gigabytes grew the panel until the OOM killer ended it, taking every other host's
    management with it — and the next poll did it again. The paramiko path has had an 8 MB
    ceiling all along. This is the same rule for these two: each stream is read to EOF in its own
    thread (reading one to EOF first deadlocks the moment the other fills its pipe), the first
    `cap` bytes are kept, and the rest is read and DISCARDED rather than left unread, so a command
    still writing is not blocked into outliving its timeout.

    `thread_cls` is the caller's to choose: a native thread inside tpool, where a green one has no
    hub to run on; the patched (green) one in a request greenlet, where a native one would block
    the hub on every read."""
    cap = _MAX_OUTPUT_BYTES if cap is None else cap
    out, err = bytearray(), bytearray()
    flags = {"truncated": False}

    def _pump(stream, buf):
        rd = getattr(stream, "read1", None) or stream.read
        try:
            while True:
                chunk = rd(65536)
                if not chunk:
                    return
                room = cap - len(buf)
                if room > 0:
                    buf.extend(chunk[:room])
                if len(chunk) > max(room, 0):
                    flags["truncated"] = True
        except (OSError, ValueError):
            return          # the pipe was closed under us (a kill); what was read is kept

    def _feed():
        try:
            if stdin_bytes:
                p.stdin.write(stdin_bytes)
        except (OSError, ValueError):
            pass            # the command exited without reading it all; its rc says what happened
        finally:
            try:
                p.stdin.close()
            except (OSError, ValueError):
                # Already closed by the exit or a kill — there is nothing left to close.
                pass

    workers = []
    for stream, buf in ((p.stdout, out), (p.stderr, err)):
        if stream is not None:
            workers.append(thread_cls(target=_pump, args=(stream, buf), daemon=True))
    if p.stdin is not None:
        workers.append(thread_cls(target=_feed, daemon=True))
    for w in workers:
        w.start()
    try:
        rc = p.wait(timeout=timeout)
    except (_real_subprocess.TimeoutExpired, subprocess.TimeoutExpired):
        kill()
        for w in workers:
            w.join(timeout=5)
        return None
    # The direct child has exited. Its output normally reaches EOF with it; a grandchild still
    # holding the pipe open gets five seconds, not the caller's whole timeout over again.
    for w in workers:
        w.join(timeout=5)
    return bytes(out), bytes(err), rc, flags["truncated"]


def _finish(p, timeout, stdin_text=None):
    """Collect a started process: (stdout, stderr, rc), killing the whole group on timeout."""
    res = _collect_capped(p, timeout, kill=lambda: _kill_process_tree(p),
                          thread_cls=_real_threading.Thread,
                          stdin_bytes=(stdin_text.encode("utf-8")
                                       if stdin_text is not None else None))
    if res is None:
        return "", "Command timed out", -1
    out, err, rc, truncated = res
    if truncated:
        _log.warning("local command output exceeded %d bytes and was truncated",
                     _MAX_OUTPUT_BYTES)
    return _decode_output(out).strip(), _decode_output(err).strip(), rc


def _in_tpool(fn):
    """Run `fn` in eventlet's native thread pool when eventlet is active — see _run_local()."""
    if _tpool is not None:
        return _tpool.execute(fn)
    return fn()


def _exec_local_shell(shell_cmd, timeout=30, stdin_text=None):
    """Run a composed SHELL command on the panel's own machine.

    The literal ["/bin/bash", "-c", ...] is written out here rather than passed in: an argv that
    arrives as a variable reads to CodeQL as an arbitrary command line, and this is the path where
    a composed string genuinely does reach a shell. Keeping the list literal at the call keeps the
    two local paths distinguishable — this one interprets a command, _exec_local_argv() does not."""
    def _do():
        p = None
        try:
            kw = dict(_POPEN_KW)
            if stdin_text is not None:
                kw["stdin"] = _real_subprocess.PIPE
            p = _real_subprocess.Popen(["/bin/bash", "-c", shell_cmd], **kw)
            return _finish(p, timeout, stdin_text=stdin_text)
        except Exception:
            # Never surface raw exception text — it can flow into API responses
            # (CodeQL py/stack-trace-exposure). Log it; callers act on rc == -1.
            _log.debug("local command failed", exc_info=True)
            if p is not None:
                _kill_process_tree(p)
            return "", "command execution error", -1

    return _in_tpool(_do)


def _exec_local_argv(argv, timeout=30, stdin_text=None):
    """Run an ARGUMENT VECTOR on the panel's own machine — no shell involved at any point.

    Only privileged.py builds the vectors that reach here, from its fixed verb table, so every
    element is either a literal or a value that passed a validator."""
    def _do():
        p = None
        try:
            kw = dict(_POPEN_KW)
            if stdin_text is not None:
                kw["stdin"] = _real_subprocess.PIPE
            p = _real_subprocess.Popen(argv, **kw)
            return _finish(p, timeout, stdin_text=stdin_text)
        except Exception:
            _log.debug("local command failed", exc_info=True)
            if p is not None:
                _kill_process_tree(p)
            return "", "command execution error", -1

    return _in_tpool(_do)


def _last_lines(text, n):
    """The last `n` lines of `text` — what `| tail -n` did, without needing a shell to do it."""
    return "\n".join((text or "").splitlines()[-n:])


def _wait_for_dpkg_lock(server, timeout=180):
    """Block until apt/dpkg has released its frontend lock, or `timeout` passes.

    Was `while fuser /var/lib/dpkg/lock-frontend; do sleep 1; done` — a loop running as root, whose
    only exit was the outer command timeout. The Python version has an explicit deadline, so a host
    whose lock never clears stops waiting instead of holding the connection open to the last second."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, _, rc = run_privileged(server, "dpkg-lock-held", [], timeout=10, merge_stderr=False)
        if rc != 0:          # fuser exits non-zero when nothing holds the file
            return True
        time.sleep(1)
    return False


def _restart_sshd(server, timeout=20):
    """Restart the SSH daemon. Debian/Ubuntu call the unit `ssh`, others `sshd`, and the panel has
    always tried both — that was `systemctl restart ssh || systemctl restart sshd`, one shell
    string. Two verbs and an `if` say the same thing without one."""
    out, err, rc = run_privileged(server, "service-restart", ["ssh"], timeout=timeout)
    if rc != 0:
        out, err, rc = run_privileged(server, "service-restart", ["sshd"], timeout=timeout)
    return out, err, rc


def _f2b_reload(server, timeout=30):
    """Make fail2ban pick up a changed config: ask it to reload, then fall back to the unit's own
    reload and finally a restart. Was a `a || b || c` chain in one root shell."""
    for verb, args in (("f2b-reload", []), ("service-reload", ["fail2ban"]),
                       ("service-restart", ["fail2ban"])):
        out, err, rc = run_privileged(server, verb, args, timeout=timeout)
        if rc == 0:
            return out, err, rc
    return out, err, rc


def is_local_server(server):
    """Check if a server record represents the local machine.

    Total on purpose: getattr for both attributes, so a partial record (or None) answers "not
    local" instead of raising. This is consulted before every command now, including from
    run_privileged, and an AttributeError here would surface as a failed firewall action rather
    than as the malformed record it actually is."""
    return bool(getattr(server, "is_local", False)
                or getattr(server, "auth_method", None) == "local")


_HELPER_STATE = {"present": None}


def helper_present(recheck=False):
    """Whether the root-owned privileged helper is installed on THIS machine.

    Cached: this is consulted on every privileged call and the answer only changes when the
    operator re-runs install.sh."""
    if recheck or _HELPER_STATE["present"] is None:
        try:
            _HELPER_STATE["present"] = (os.path.isfile(_priv.HELPER_PATH)
                                        and os.access(_priv.HELPER_PATH, os.X_OK))
        except Exception:
            _HELPER_STATE["present"] = False
    return _HELPER_STATE["present"]


def write_root_file(server, target, content, timeout=15):
    """Write `content` to a NAMED root-owned destination (see privileged.WRITE_TARGETS).

    The name is the only argument. Locally the helper does the write itself, reading the content
    from its stdin — so the content never becomes part of a command at all, which is what the old
    `echo '<base64>' | base64 -d > <path>` did to it. Remotely there is no helper, so the base64
    form remains, but the path is looked up rather than interpolated from a call site."""
    if not is_local_server(server):
        return run_command(server, _priv.remote_write_command(target, content),
                           timeout=timeout, sudo=True)
    if helper_present():
        return _exec_local_argv(_priv.helper_argv("write-file", [target]), timeout=timeout,
                                stdin_text=content)
    # Pre-helper hosts: the path still comes from the table, not from the caller.
    return _run_local(_priv.remote_write_command(target, content), timeout=timeout, sudo=True)


def write_content_cron(server, content_user, body, timeout=15):
    """Write one content user's weekly update cron. Per-user destination, so it cannot be a
    WRITE_TARGETS name — the path is still built from the validated user name, never passed in."""
    if not is_local_server(server):
        return run_command(server, _priv.remote_content_cron_command(content_user, body),
                           timeout=timeout, sudo=True)
    if helper_present():
        return _exec_local_argv(_priv.helper_argv("content-cron-write", [content_user]),
                                timeout=timeout, stdin_text=body)
    return _run_local(_priv.remote_content_cron_command(content_user, body),
                      timeout=timeout, sudo=True)


def run_privileged(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True):
    """Run a privileged VERB (see privileged.py) against `server`.

    Local, helper installed:  sudo -n <helper> <verb> <args...>   — argv, no shell anywhere.
    Local, helper missing:    the old `sudo bash -c '<command>'` path.
    Remote:                   the same verb rendered as a command over SSH.

    The fallback is not decoration. An existing install only gains the helper when install.sh is
    next run, and the panel's own self-update cannot place a root-owned file outside its checkout —
    so between an upgrade and that run, a host has the new code and no helper. Without the fallback
    every privileged action on that host would fail.

    What that means for the sudoers grant depends on the host, and install.sh decides per host:
    where the three root-owned pieces landed (the helper, db_maintenance.py and the installer
    itself) it writes a grant permitting exactly one command, the helper, and the boundary is real.
    Where they did not, the host keeps NOPASSWD:ALL, because it still falls back to the line below
    and narrowing under that would break every privileged action rather than secure anything. The
    installer prints which one it wrote; SECURITY.md carries the full account."""
    # A verb with a SECRET argument (privileged.SECRET_STDIN) sends it on stdin on every path
    # below, and no command line carries it. Passed only when there is one, so a transport stubbed
    # without the keyword still sees exactly the call it always did.
    _secret_in = _priv.remote_stdin(verb, args)
    _secret_kw = {"stdin_text": _secret_in} if _secret_in is not None else {}
    if not is_local_server(server):
        return run_command(server, _priv.remote_command(verb, args, merge_stderr=merge_stderr),
                           timeout=timeout, sudo=sudo, **_secret_kw)

    # sudo=None means "whatever this host is configured for", the same defaulting run_command does.
    # A host with sudo disabled runs the tool directly — still argv, still no shell, just no root.
    use_sudo = sudo if sudo is not None else getattr(server, "sudo_enabled", False)
    if not use_sudo:
        return _exec_local_argv(_priv.tool_argv(verb, args), timeout=timeout,
                                stdin_text=_priv.stdin_for(verb, args))

    if helper_present():
        out, err, rc = _exec_local_argv(_priv.helper_argv(verb, args), timeout=timeout,
                                        stdin_text=_priv.helper_stdin(verb, args))
        if merge_stderr:
            # The shell form used `2>&1`, and callers read tool errors out of stdout. Merge here so
            # switching transport does not move a message from one stream to the other.
            return ("\n".join(x for x in (out, err) if x)).strip(), "", rc
        return out, err, rc

    # No helper on this host yet: the pre-helper path, byte-for-byte.
    return _run_local(_priv.remote_command(verb, args, merge_stderr=merge_stderr),
                      timeout=timeout, sudo=True, **_secret_kw)



def _ssh_connect_timeout():
    """Connection timeout in seconds, from config's `ssh_timeout`. It is documented in the README
    and has always been declared in DEFAULT_CONFIG, but nothing read it: the paramiko path hardcoded
    15 and the ssh-CLI path 12, so the documented knob did nothing and the two disagreed."""
    try:
        from panel.core.config import load_config
        return max(1, min(int(load_config().get("ssh_timeout", 10)), 120))
    except Exception:
        return 10


def get_connection(server, force_new=False, pooled=True):
    """Get or create a cached SSH connection to a remote server.
    For local servers, returns None (no SSH needed).

    `pooled=False` builds the client exactly the same way — same auth methods, same host-key
    pinning, same timeouts — and then does NOT put it in the pool. The caller owns it and must
    close it.

    That exists for the interactive terminal, and the reason is the line at the bottom of this
    function: `_connections[key] = client` runs even under force_new, so a caller that took a
    "fresh" client and later closed it would be closing the one every other panel operation had
    started using. A long-lived shell channel needs its own client for the same reason — an
    `invoke_shell` sitting on the pooled transport ties every command on that host to the lifetime
    of somebody's browser tab. Duplicating the connect logic here instead would mean a second
    implementation of host-key pinning, which is the last thing that should have two copies."""
    if is_local_server(server):
        return None

    key = _conn_key(server.username, server.host, server.port)
    with _conn_lock:
        if not force_new and key in _connections:
            conn = _connections[key]
            try:
                transport = conn.get_transport()
                if transport and transport.is_active():
                    transport.send_ignore()
                    return conn
            except Exception:  # nosec B110
                _log.debug("probing a possibly-dead cached client → reconnect below", exc_info=True)
            try:
                conn.close()
            except Exception:  # nosec B110
                _log.debug("already closed / unusable; nothing to clean up", exc_info=True)
            del _connections[key]

    client = paramiko.SSHClient()
    # Pin the server's SSH host key (TOFU). Tailscale connections are already
    # authenticated by WireGuard, so there the tailnet is the trust anchor, not the SSH
    # host key — capture it but don't reject a change (tailscaled may rotate it).
    enforce_pin = server.auth_method not in ("tailscale", "local")
    # A pin that EXISTS but cannot be decrypted is not "no pin". EncryptedString answers "" for
    # both, and _PinPolicy reads "" as first contact: it accepts whatever key is presented and
    # _persist_host_key then overwrites the stored pin with it. So a rotated or restored cred_key
    # silently turned the one control that detects a man-in-the-middle into a control that trusts
    # one and remembers it. Refuse instead, and say which of the two it is.
    from panel.db.models import UnreadableSecret
    if enforce_pin and isinstance(server.host_key, UnreadableSecret):
        raise HostKeyMismatch(
            'The stored SSH host key for %s cannot be decrypted on this host, so it cannot be '
            'checked against the key this server is presenting. That usually means data/cred_key '
            'was replaced or restored from elsewhere. Refusing to connect rather than trusting an '
            'unverified key — click "Re-trust host key" on the server page if you are certain this '
            'is the right server.' % getattr(server, "name", "this server"))
    policy = _PinPolicy(expected=(server.host_key or ""), reject_on_change=enforce_pin)
    client.set_missing_host_key_policy(policy)

    timeout = _ssh_connect_timeout()
    cred = decrypt_secret(server.auth_credential)  # stored encrypted at rest
    try:
        if server.auth_method == "password" and cred:
            client.connect(
                server.host,
                port=server.port or 22,
                username=server.username,
                password=cred,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )
        elif server.auth_method == "tailscale":
            # Tailscale SSH — use the hostname as-is (Tailscale resolves it),
            # connect via the SSH agent (the Tailscale SSH agent handles auth)
            resolved_host = server.host
            # If the host is a plain name, try resolving via MagicDNS
            if "." not in server.host and not server.host.startswith("100."):
                from panel.ops import tailscale_integration as ts
                ts_info = ts.get_tailscale_info()
                if ts_info.dns_name:
                    domain = ts_info.dns_name.split(".", 1)[1] if "." in ts_info.dns_name else "ts.net"
                    resolved_host = f"{server.host}.{domain}"
            client.connect(
                resolved_host,
                port=server.port or 22,
                username=server.username,
                timeout=timeout,
                allow_agent=True,
                look_for_keys=True,
            )
        else:
            key_path = cred or os.path.expanduser("~/.ssh/id_rsa")
            client.connect(
                server.host,
                port=server.port or 22,
                username=server.username,
                key_filename=key_path,
                timeout=timeout,
            )
    except HostKeyMismatch:
        raise   # surface the clear "host key changed" message unwrapped
    except paramiko.AuthenticationException:
        raise ConnectionError("SSH authentication failed. Check credentials.")
    except socket.timeout:
        raise ConnectionError(f"Connection to {server.host}:{server.port} timed out.")
    except socket.gaierror:
        raise ConnectionError(f"Cannot resolve hostname: {server.host}")
    except Exception as e:
        raise ConnectionError(f"SSH connection failed: {e}")

    # First successful contact with a direct-SSH host → pin the key we just saw.
    if policy.captured and enforce_pin:
        _persist_host_key(server, policy.captured)

    # Keep the pooled connection warm: a periodic keepalive stops the server/NAT silently
    # dropping it while idle, so the next command reuses this connection instead of paying a
    # fresh handshake. Also lets paramiko notice a dead peer promptly.
    try:
        _tr = client.get_transport()
        if _tr:
            _tr.set_keepalive(30)
    except Exception:  # nosec B110
        _log.debug("set_keepalive failed (non-fatal)", exc_info=True)

    if not pooled:
        return client      # caller owns it — see the docstring

    with _conn_lock:
        existing = _connections.get(key)
        if existing is not None and not force_new:
            # Another green thread finished connecting to the same host while we were busy
            # doing our own (yielding) network I/O. Keep theirs and close ours so the extra
            # client doesn't leak a socket/transport thread.
            try:
                client.close()
            except Exception:  # nosec B110
                _log.debug("closing redundant duplicate connection", exc_info=True)
            if getattr(server, "id", None) is not None:
                _remote_conn_keys[server.id] = key   # this row is holding THEIR client now
            return existing
        _connections[key] = client
        if getattr(server, "id", None) is not None:
            _remote_conn_keys[server.id] = key

    return client


def _persist_host_key(server, keystr):
    """Store the pinned host key on the server row (best-effort; if there's no DB session
    in scope it simply pins on the next connection instead)."""
    try:
        from panel.db.models import db
        server.host_key = keystr
        db.session.commit()
    except Exception:
        try:
            from panel.db.models import db
            db.session.rollback()
        except Exception:
            # no usable session; the key just pins on the next connection instead
            _log.debug("host-key pin: session rollback unavailable", exc_info=True)


def close_connection(server):
    """Close and remove a cached connection. No-op for local servers."""
    if is_local_server(server):
        return
    _close_key(_conn_key(server.username, server.host, server.port))


def _resolve_ts_host(server):
    """Resolve a Tailscale remote's hostname (MagicDNS if a bare name)."""
    host = server.host
    if "." not in host and not host.startswith("100."):
        try:
            from panel.ops import tailscale_integration as ts
            info = ts.get_tailscale_info()
            if info.dns_name:
                domain = info.dns_name.split(".", 1)[1] if "." in info.dns_name else "ts.net"
                host = f"{host}.{domain}"
        except Exception:
            _log.debug("_resolve_ts_host: ignored non-fatal error", exc_info=True)
    return host


# Connection-multiplexing socket dir for the ssh-CLI path (Tailscale remotes). Per-uid so the
# sockets aren't shared across users. The first command to a host opens a master connection that
# stays warm; follow-ups (polls, actions, navigating between pages) reuse it instead of re-handshaking.
_SSH_CM_DIR = os.path.join(tempfile.gettempdir(),
                           ".lgsm-ssh-cm-%d" % (os.getuid() if hasattr(os, "getuid") else 0))


def _cm_dir_is_ours(path):
    """Is the control-socket directory one only this account can reach? A real directory (not a
    symlink), owned by this uid, with no group or other permission bits.

    makedirs(exist_ok=True) accepts whatever is already at the path, and the path is a fixed name
    in world-writable /tmp: any local account (a game-server user) can create it first — after a
    reboot empties /tmp — and own it. ControlMaster=auto CONNECTS to an existing socket before it
    makes one, and the client does not check who is listening, so a socket planted there would be
    handed every command the panel sends that host (as root on most remotes) and could answer with
    whatever output it liked. Without the check ssh simply connects without multiplexing: slower,
    never wrong."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    ok = (stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid()
          and (st.st_mode & 0o077) == 0)
    if not ok:
        _log.warning("ssh multiplexing disabled: %s is not a private directory owned by this "
                     "account (mode %o, uid %d)", path, st.st_mode, st.st_uid)
    return ok


def _ssh_mux_opts():
    """SSH options that reuse one persistent connection per host. ControlMaster=auto falls back to a
    fresh connection automatically if the master died, so it's safe. Returns [] if the socket dir
    can't be created (then ssh just connects normally).

    ControlPersist=10m keeps the master warm well past the poll cadence AND across page
    navigations / short idle gaps, so you rarely pay for a fresh handshake. ServerAlive* pings keep
    that idle master from being dropped by a NAT/firewall and reap it promptly if the peer dies."""
    try:
        os.makedirs(_SSH_CM_DIR, mode=0o700, exist_ok=True)
    except OSError:
        return []
    if not _cm_dir_is_ours(_SSH_CM_DIR):
        return []
    return ["-o", "ControlMaster=auto",
            "-o", f"ControlPath={_SSH_CM_DIR}/%C",   # %C = short fixed-length hash of host/port/user
            "-o", "ControlPersist=10m",
            "-o", "ServerAliveInterval=20",
            "-o", "ServerAliveCountMax=3"]


def _run_via_ssh_cli(server, command, timeout=30, sudo=None, stdin_text=None):
    """Run a command over the system `ssh` binary — used for Tailscale SSH remotes,
    where auth happens at the tailscaled level (paramiko can't do it, but the ssh CLI,
    running from this tailnet node, can — exactly like PuTTY does). Uses connection
    multiplexing so back-to-back commands don't each pay a fresh SSH handshake."""
    use_sudo = sudo if sudo is not None else server.sudo_enabled
    # ROOT, not the remote's optional linuxgsm_user — see run_command for what that demotion did.
    remote_cmd = f"sudo bash -c {_quote(command)}" if use_sudo else command
    host = _resolve_ts_host(server)
    ssh_cmd = [
        "ssh", "-T",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=%d" % _ssh_connect_timeout(),
    ] + _ssh_mux_opts() + [
        "-p", str(server.port or 22),
        f"{server.username}@{host}", remote_cmd,
    ]
    try:
        # errors="replace" like the other two transports — a game server's bytes are not
        # necessarily valid UTF-8, and a strict decode would blank the whole result (see _run_local).
        #
        # stdin=DEVNULL, like _POPEN_KW gives both local paths and files.py gives its own ssh argv.
        # capture_output= redirects stdout and stderr ONLY, and there is no `-n` in ssh_cmd, so the
        # child ssh inherited the panel's fd 0 and FORWARDED it to the remote session: every
        # command this transport runs was reading the panel's own stdin. Production survived it
        # only because the systemd unit sets StandardInput=null. Started from a shell, a tmux pane
        # or the dev runner — how it is run in development and after a manual restart — the
        # monitoring poller's ssh calls race to drain the operator's tty, and bytes typed there are
        # forwarded to the remote instead, where a LinuxGSM prompt happily accepts them as its
        # answer. A privileged child must never be handed the panel's input; see _POPEN_KW.
        #
        # Read through _collect_capped, not capture_output=: that buffered EVERYTHING the remote
        # wrote until the timeout, and a hostile Tailscale remote could answer a routine metrics
        # probe with gigabytes. The paramiko path's 8 MB ceiling applies here too now. The pipes
        # are binary and _decode_output does the lenient decode itself, which also sidesteps the
        # green Popen re-opening text pipes without the `errors=` it was given.
        # stdin_text is the one exception: a secret run_privileged keeps off the command line,
        # written to the pipe and then closed, so the remote still sees EOF.
        p = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,  # nosec B603  # nosemgrep - argv list, no shell; ssh_cmd is built here from validated parts
                             stdin=(subprocess.PIPE if stdin_text is not None
                                    else subprocess.DEVNULL))
        res = _collect_capped(p, timeout, kill=p.kill, thread_cls=threading.Thread,
                              stdin_bytes=(stdin_text.encode("utf-8")
                                           if stdin_text is not None else None))
        if res is None:
            return "", "SSH command timed out", -1
        out, err, rc, truncated = res
        if truncated:
            _log.warning("ssh command output exceeded %d bytes and was truncated",
                         _MAX_OUTPUT_BYTES)
        return _decode_output(out).strip(), _decode_output(err).strip(), rc
    except Exception:
        # Generic message only; the real error is logged, not returned (it can
        # reach API responses — CodeQL py/stack-trace-exposure).
        _log.debug("ssh command failed", exc_info=True)
        return "", "ssh command error", -1


# Paramiko's per-channel window is 2 MiB (DEFAULT_WINDOW_SIZE = 64 * 2**15). A command that
# writes more than that with nobody reading blocks in the remote's write() — so it never exits, so
# recv_exit_status(), which is `status_event.wait()` with NO timeout, never returns. The `timeout=`
# handed to exec_command sets the channel's recv timeout; it is not a deadline for the exit status,
# so nothing ends the wait. run_command used to call recv_exit_status BEFORE reading, which is
# precisely the ordering paramiko's own recv_exit_status docstring warns about, and the greenthread,
# its request, its DB session and the channel then leaked permanently.
#
# It is not only a hostile-host problem. Three ordinary things here clear 2 MiB: the cron tab's
# `journalctl _COMM=cron --since "-14 days"` (no -n, and the [-800:] slice happens after the whole
# thing is read), the security page's `zcat -f /var/log/fail2ban.log* | grep -E 'Ban|Found'` on a
# host under sustained SSH brute force, and a long update's `cat` of the full SteamCMD log.
#
# So drain both streams WHILE the command runs and take the exit status afterwards. Both halves
# matter: draining stdout to EOF first would deadlock the same way the moment stderr filled its own
# window.
#
# Deliberately NOT a new deadline. On this path `timeout` never bounded a command's DURATION —
# recv_exit_status blocked for as long as the command took — so imposing one now would newly fail
# long-running work that has always succeeded (an `apt full-upgrade` under a nominal 30s timeout).
# Past the byte cap the loop keeps reading and DISCARDS rather than stopping: continuing to read is
# what keeps the remote's flow control moving, and stopping would re-create the hang this fixes.
#
# What IS bounded is SILENCE. "No deadline" was right for a command that keeps making progress and
# wrong for one that never does: a remote that accepts the exec and then sends neither a byte nor
# an exit status (a compromised host, or one wedged by OOM or a fork bomb) held the loop below
# forever. Keepalives do not help, because the remote answers those. The monitor sweep iterates its
# probes with ex.map(), so ONE such host stalled monitoring and alerting for every host until a
# restart, and every request greenlet asking that host held a DB connection until the pool ran dry.
# So the drain gives up after _DRAIN_IDLE_FLOOR seconds (or the caller's own timeout, if longer)
# in which neither stream moved and no exit status arrived — the rc=-1 "timed out" answer the other
# two transports already give. A long command that is still talking is not affected; the callers
# that run long QUIET work (backups, installs, apt) already pass timeouts of 600-7200 s, and the
# local and Tailscale transports hold those same timeouts as WALL-CLOCK limits. A command whose
# output goes to a file is silent by construction, which is why run_as_game_user(tee_log=True)
# streams its log back while the action runs rather than `cat`ing it at the end.
_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_DRAIN_IDLE_FLOOR = 300


def _drain_exec(chan, max_bytes=_MAX_OUTPUT_BYTES, idle_limit=None):
    """Read stdout+stderr to EOF, then the exit status. Returns (out, err, rc, truncated).

    `idle_limit` (seconds): give up when neither stream has moved and no exit status has arrived
    for that long — close the channel and answer rc -1. None waits as long as the remote keeps the
    channel open, which is what the loop did before it had a bound."""
    out, err = bytearray(), bytearray()
    truncated = False
    chan.settimeout(0.0)          # non-blocking; we poll and yield rather than block on one stream
    last_moved = time.monotonic()
    while True:
        moved = False
        try:
            while chan.recv_ready():
                b = chan.recv(65536)
                if not b:
                    break
                moved = True
                if len(out) < max_bytes:
                    out += b[:max_bytes - len(out)]
                else:
                    truncated = True
            while chan.recv_stderr_ready():
                b = chan.recv_stderr(65536)
                if not b:
                    break
                moved = True
                if len(err) < max_bytes:
                    err += b[:max_bytes - len(err)]
                else:
                    truncated = True
        except (socket.timeout, OSError):
            pass                  # raced recv_ready(); the loop re-checks
        if moved:
            last_moved = time.monotonic()
            continue
        if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
            break
        if idle_limit is not None and time.monotonic() - last_moved > idle_limit:
            try:
                chan.close()
            except Exception:
                _log.debug("could not close a silent exec channel", exc_info=True)
            _log.warning("remote command sent nothing and no exit status for %ds; gave up",
                         int(idle_limit))
            msg = b"command timed out: no output and no exit status for %ds" % int(idle_limit)
            return bytes(out), (bytes(err) + b"\n" + msg).lstrip(), -1, truncated
        time.sleep(0.01)          # eventlet-patched, so this yields rather than burning the worker
    return bytes(out), bytes(err), chan.recv_exit_status(), truncated


def run_command(server, command, timeout=30, sudo=None, stdin_text=None):
    """Run a command on the remote server via SSH, or locally if it's the local machine.
    Returns (stdout, stderr, exit_code). `stdin_text`, when given, is written to the command's
    stdin and then closed — how run_privileged sends a secret that must not be in `command`.
    """
    _stdin_kw = {"stdin_text": stdin_text} if stdin_text is not None else {}
    if is_local_server(server):
        # NO IMPLICIT ESCALATION on the panel's own host. `sudo` defaulted to server.sudo_enabled,
        # and the local host row is created with sudo_enabled=True (panel/routes/host_local.py,
        # panel/routes/remotes.py) — so every caller that did not pass `sudo=` sent its command as
        # `sudo bash -c '<cmd>'`. About twenty of them need no privilege whatsoever: the dashboard
        # port scan, disk and load, uptime, /etc/os-release, `id`, `tailscale status`. Measured on
        # a test host with this code, as the panel user:
        #     run_command(local, "echo ok")     -> sudo: a password is required
        #     run_command(local, "ss -H -lntu") -> sudo: a password is required
        # so under the narrow grant the dashboard, the host cards and the console all failed, and
        # under the wide grant they were quietly running as root to read /proc.
        #
        # sudo_enabled still means what it says for a REMOTE host, which is the only place it was
        # ever a useful default: there it records whether the operator's account can escalate at
        # all. Locally the privileged path is run_privileged() and the helper — that is the entire
        # point of the verb table — so an escalation here has to be asked for explicitly.
        #
        # The reads that genuinely need more than the panel user were converted FIRST, in the same
        # change: the console log reads go through read_as_game_user (a 0750 home), and the cron
        # restart flags through the restart-flags verb. Flipping this default without them would
        # have broken the console on every host with the wide grant, where it works today.
        return _run_local(command, timeout=timeout, sudo=bool(sudo), **_stdin_kw)

    # Tailscale SSH is not doable with paramiko (auth is handled by tailscaled),
    # so use the system ssh client for those remotes.
    if server.auth_method == "tailscale":
        return _run_via_ssh_cli(server, command, timeout=timeout, sudo=sudo, **_stdin_kw)

    client = get_connection(server)
    use_sudo = sudo if sudo is not None else server.sudo_enabled

    # sudo=True means ROOT. It used to mean "sudo -u <the remote's linuxgsm_user> when that
    # optional field is set", which silently demoted every privileged operation this module has:
    # ufw, apt, fail2ban, the sshd hardening and its drop-in write, the node-tools cron, and the
    # whole VPS bootstrap — which still reported "VPS bootstrap complete". Nothing else in the
    # codebase reads that field: game operations build their own `sudo -u <GameServer.username>`
    # and pass sudo=False, so the demotion was its only surviving effect, on a form the Add Remote
    # page invited the operator to fill in.
    full_cmd = f"sudo bash -c {_quote(command)}" if use_sudo else command

    try:
        # nosec B601 - full_cmd is assembled HERE from _quote()d components; there is no
        # interpolation of caller text into it that has not been through _quote first.
        stdin, stdout, stderr = client.exec_command(full_cmd, timeout=timeout)  # nosec B601  # nosemgrep
        # EOF on the remote's fd 0, immediately. `stdin` was bound and thrown away: nothing was
        # ever written to it and it was never closed, so the remote process's stdin was an open SSH
        # channel that receives nothing and never ends. Any command that READS stdin — a LinuxGSM
        # action that prompts, run with no `answers` — blocked there forever, and nothing bounded
        # it: _drain_exec's `settimeout(0.0)` replaces the channel timeout exec_command just set,
        # and its only exit is exit_status_ready(), so the `timeout=` all 65 call sites pass bounds
        # this transport not at all. The greenlet, its request, its DB session and the channel then
        # leaked for the life of the process. This is the stdin=DEVNULL property the local
        # transport has from _POPEN_KW, and the same shutdown_write files.py:911 already sends —
        # and it is what the "deliberately no deadline" note above _drain_exec rests on.
        # A secret from run_privileged goes down the channel first; the EOF still follows.
        if stdin_text is not None:
            stdin.write(stdin_text)
            stdin.flush()
        try:
            stdin.channel.shutdown_write()
        except Exception:
            _log.debug("could not shut down the exec channel's stdin", exc_info=True)
        out_b, err_b, exit_code, truncated = _drain_exec(
            stdout.channel, idle_limit=max(timeout or 0, _DRAIN_IDLE_FLOOR))
        out = out_b.decode("utf-8", errors="replace")
        err = err_b.decode("utf-8", errors="replace")
        if truncated:
            _log.warning("remote command output exceeded %d bytes and was truncated",
                         _MAX_OUTPUT_BYTES)
        return out.strip(), err.strip(), exit_code
    except Exception as e:
        raise ConnectionError(f"Command failed: {e}")




def _quote(s):
    """Shell-quote a string for safe use in remote commands.

    `shlex.quote` rather than the hand-rolled `'` + escape this used to be. The two produce
    equivalent shell words — shlex leaves a string that needs no quoting unquoted, and quotes the
    rest identically — but this is the STANDARD LIBRARY's implementation of the one thing every
    command in this module depends on being right, and static analysis recognises it as a
    sanitiser where it cannot know anything about a local function that returns an f-string.
    """
    return shlex.quote(s)


def discover_linuxgsm_servers(server):
    """Find LinuxGSM instances ALREADY installed on `server`, across every user account (each
    LinuxGSM server usually lives under its own Ubuntu user). One sudo round trip: for each
    /home/<user> that has an lgsm/config-lgsm/<gameservername>/ dir and a matching executable
    ./<gameservername> script, report (user, lgsm_name, port). The port is read from the LinuxGSM
    config as a hint — the panel re-reads the authoritative port(s) after import. The caller maps
    <gameservername> to the panel's game_type and skips servers already added. Sudo is required
    because game-user home dirs aren't world-readable. Best-effort — returns [] on any failure."""
    # A single POSIX-sh script so the whole scan is one SSH command. For each instance it also
    # counts what already exists — LinuxGSM backups (~/lgsm/backup), installed mods
    # (~/lgsm/mods/installed-mods.txt), the user's cron lines, and whether an @reboot autostart
    # is set — so the preview shows the full picture and import can adopt the autostart state.
    # The crontab is read once per user. Variables are quoted; the only inputs are on-host
    # filenames (users / LinuxGSM dirs), never anything panel-supplied.
    script = (
        'for u in $(ls -1 /home/ 2>/dev/null); do '
        '  d="/home/$u/lgsm/config-lgsm"; [ -d "$d" ] || continue; '
        '  cj=$(crontab -u "$u" -l 2>/dev/null); '
        '  for g in $(ls -1 "$d" 2>/dev/null); do '
        '    [ -x "/home/$u/$g" ] || continue; '
        '    p=$(grep -hE "^[[:space:]]*port=" "$d/$g/$g.cfg" "$d/$g/common.cfg" '
        '        "$d/$g/_default.cfg" 2>/dev/null | grep -oE "[0-9]+" | head -1); '
        '    b=$(ls -1 "/home/$u/lgsm/backup/" 2>/dev/null | grep -cE "\\.(tar|tgz|zip)"); '
        '    m=$(grep -c . "/home/$u/lgsm/mods/installed-mods.txt" 2>/dev/null); '
        '    c=$(printf "%s\\n" "$cj" | grep -vE "^[[:space:]]*(#|$)" | grep -c .); '
        '    a=$(printf "%s\\n" "$cj" | grep -cE "@reboot|monitor"); '
        '    echo "FOUND|$u|$g|${p:-0}|${b:-0}|${m:-0}|${c:-0}|${a:-0}"; '
        '  done; '
        'done'
    )
    try:
        # On the panel's OWN host with the helper installed, this is a verb: the helper walks /home
        # itself and reads the crontabs, which is the only part that ever needed root. Remote hosts
        # keep the shell form — it travels over SSH and never touches the local sudoers file.
        if is_local_server(server) and helper_present():
            out, _, rc = _exec_local_argv(_priv.helper_argv("lgsm-discover", []), timeout=45)
        else:
            out, _, rc = run_command(server, script, timeout=45, sudo=True)
    except Exception:
        _log.debug("discover_linuxgsm_servers: scan command failed", exc_info=True)
        return []
    if rc != 0:
        return []

    def _n(x):
        x = (x or "").strip()
        return int(x) if x.isdecimal() else 0

    found = []
    for line in (out or "").splitlines():
        if not line.startswith("FOUND|"):
            continue
        parts = line.split("|")
        if len(parts) >= 8:
            user, lgsm_name = parts[1].strip(), parts[2].strip()
            port = _n(parts[3])
            if user and lgsm_name:
                found.append({
                    "user": user,
                    "lgsm_name": lgsm_name,
                    "port": port or None,
                    "backups": _n(parts[4]),
                    "mods": _n(parts[5]),
                    "cron": _n(parts[6]),
                    "autostart": _n(parts[7]) > 0,
                })
    return found


# Same charset files._SAFE_UNIX_USER_RE enforces, and for the same reason it gives.
_SAFE_GAME_IDENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}\Z")


def create_game_user(server, user, timeout=30):
    """Create an account the panel will act AS, and put it in the group its grant names.

    Every caller of `user-create` creates an account the panel then drives with `sudo -u` — a game
    instance's user, or the shared GMod content user. On the panel's own host with the narrow
    sudoers grant, being able to become that account is exactly what the second grant line allows,
    and that line names a GROUP (see privileged.GAME_GROUP). An account created outside the group
    is one the panel cannot drive, which is the bug this pairing exists to stop happening again —
    silently, one new server at a time.

    The group step is local-only and best-effort: a remote host's sudoers is the operator's to
    arrange and the group means nothing there, and an older helper without the verb must not turn
    a working server install into a failed one. Returns user-create's own (out, err, rc)."""
    out, err, rc = run_privileged(server, "user-create", [user], timeout=timeout)
    if rc == 0:
        enrol_game_user(server, user)
    return out, err, rc


def enrol_game_user(server, user):
    """Put an EXISTING account in the group the panel's narrow sudoers grant names, on the panel's
    own host. Returns None when that is done or not needed, else the reason it was not — the
    helper's own words when it refused (an account that can already reach root is never enrolled).

    Two callers, because an account reaches the panel two ways: create_game_user makes one, and
    discovery IMPORTS one somebody else made. The import used to add a GameServer row and nothing
    else, and every per-account helper verb (lgsm-command, the file and backup reads, crontab-list)
    refuses an account outside the group on a narrow-grant install — so an imported server showed
    up, could not be started, stopped or downloaded from, and nothing said why until install.sh
    next ran as root and enrolled it.

    Not needed: a remote host (the group means nothing there), and the panel's OWN account — the
    helper already accepts the account that invoked it, and would refuse to enrol it anyway, since
    the panel user holds sudo rules of its own. Never raises: the caller's own work has succeeded
    by the time this runs, and an older helper without the verb must not turn that into a failure."""
    if not is_local_server(server):
        return None
    try:
        import pwd
        if user == pwd.getpwuid(os.getuid()).pw_name:
            return None
    except (ImportError, KeyError):
        # No passwd entry for our own uid: it cannot be the panel's own account, so enrol it.
        pass
    try:
        _, g_err, g_rc = run_privileged(server, "gameuser-group", [user], timeout=15,
                                        merge_stderr=False)
    except Exception:
        _log.debug("gameuser-group failed (non-fatal)", exc_info=True)
        return "the enrolment could not be run"
    if g_rc != 0:
        reason = (g_err or "").strip()[:200] or ("exit status %s" % g_rc)
        _log.warning("could not add %s to %s: %s", user, _priv.GAME_GROUP, reason)
        return reason
    return None


def read_as_game_user(server, user, sh, timeout=30):
    """Run a READ-ONLY shell snippet as a game account, and return (out, err, rc).

    For the reads that genuinely need that account's permissions rather than root: a game user's
    home is 0750, so the panel user cannot traverse it, and the console log lives three levels
    inside it. These used to be plain `run_command(server, "tail …")` calls with no `sudo=`, which
    means they inherited `server.sudo_enabled` — True on the panel's own host row — and went out
    as `sudo bash -c 'tail …'`. Root could read the file, so it worked, and under the narrow
    sudoers grant it is refused outright.

    Running as the ACCOUNT is both the fix and the smaller privilege: it is what the narrow grant
    permits, it works unchanged on a host with the wide grant, and a console read stops being a
    root operation. `sh` is panel-built text, never user input; `user` is validated here for the
    reason run_as_game_user gives at length.
    """
    if not _SAFE_GAME_IDENT.match(user or ""):
        _log.warning("refusing to read as an unsafe account name")
        return "", "invalid account name", 1
    return run_command(server, "sudo -u %s bash -c %s" % (_quote(user), _quote(sh)),
                       timeout=timeout, sudo=False)


def run_as_game_user(server, user, action, timeout=30, selfname=None, answers=None,
                     tee_log=False):
    """Run ONE LinuxGSM action as the instance's Ubuntu user, from its home dir.

    `user` is the (possibly custom) account name; `selfname` is the LinuxGSM script name (always
    '{game_type}server' — canonical). They differ when the instance was given a custom name: only
    the user is renamed, the script stays canonical. Defaults selfname to user for standard
    installs.

    `action` is ONE word from privileged.LGSM_ACTIONS — not a command line. It used to be a shell
    fragment the callers assembled ("details 2>&1", 'mods-install <<< "abort"', a redirect into a
    log file followed by `cat`), which is why this function could not route through a privileged
    verb and had to shell out. `answers` and `tee_log` carry what those fragments were really for:
    the keystrokes LinuxGSM prompts for, and the tail-able log a long action writes.

    TWO TRANSPORTS, and the local one is why this changed at all. On the panel's own host with the
    helper installed it is now the `lgsm-command` verb, because the narrow sudoers grant install.sh
    writes permits the helper and nothing else — the old `sudo -u <user> bash -c ...` was not
    covered by it, so on a hardened install every server control silently failed while the
    dashboard's port-scan path still showed servers online. See tools/panel-helper:do_lgsm_command.
    Remote hosts keep the shell form: their sudoers is the operator's business, and nothing about
    it changed."""
    selfname = selfname or user
    # Validated HERE, at the one choke point every mods_* call goes through. files.py explains at
    # length why the model's @validates hook is not enough: it fires on ASSIGNMENT and never on a
    # row loaded from the database, so a row written before the validator existed, or restored
    # from a tampered backup, reaches this code unchecked. `user` is interpolated ahead of `sudo`,
    # so it breaks out as the PANEL user, and `selfname` lands inside the bash -c script body.
    # Demonstrated: user="x; id > /tmp/pwned; #" produced `sudo -u x; id > /tmp/pwned; # bash -c`.
    if not (_SAFE_GAME_IDENT.match(user or "") and _SAFE_GAME_IDENT.match(selfname or "")):
        _log.warning("refusing to run as an unsafe account/script name")
        return "", "invalid account or script name", 1
    answers = [str(a) for a in (answers or [])]
    arg_answers = ",".join(answers) if answers else "-"
    verb_args = [user, selfname, action, arg_answers, "yes" if tee_log else "no"]
    # Both transports are held to the SAME table, so a value one would refuse cannot reach the
    # other. Without this the shell path would keep accepting whatever it could quote.
    try:
        _priv.check_args("lgsm-command", verb_args)
    except Exception as exc:
        _log.warning("refusing LinuxGSM action: %s", exc)
        return "", str(exc), 1

    if is_local_server(server) and helper_present():
        try:
            argv = _priv.helper_argv("lgsm-command", verb_args)
        except Exception as exc:
            # Unreachable while check_args above agrees with it — they read the same table. It is
            # here because this function's contract is a TUPLE and never a raise: every caller
            # unpacks (out, err, rc), and several run inside a background thread whose only
            # report to the user is that rc. A raise here reached them as silence.
            _log.warning("refusing LinuxGSM action: %s", exc)
            return "", str(exc), 1
        out, err, rc = _exec_local_argv(argv, timeout=timeout)
        # The shell form used `2>&1` and every caller reads LinuxGSM's errors out of stdout, so
        # merge here too — switching transport must not move a message from one stream to the other.
        return ("\n".join(x for x in (out, err) if x)).strip(), "", rc

    # Remote, or a host whose install.sh run predates the helper: the pre-helper shell form.
    body = f"./{_quote(selfname)} {_quote(action)}"
    if answers:
        # `printf` rather than a here-string: the answers are arguments to it, so none of them is
        # ever part of the text bash parses.
        body = "printf '%s\\n' " + " ".join(_quote(a) for a in answers) + " | " + body
    if tee_log:
        # Mirrors panel/routes/_shared.py:_action_log_path, which is what the live console tails.
        # `: >` truncates so each run starts the tail at byte 0, BEFORE the follower opens it, so
        # it never replays the previous run's output.
        #
        # The output is streamed back WHILE the action runs, by a follower (`tail --pid`) rather
        # than a `cat` at the end. With the `cat`, the SSH channel carried nothing for the whole
        # action, and _drain_exec's silence bound — which exists for a remote that never answers
        # — turned the caller's timeout into a hard wall-clock limit on paramiko hosts: a 40-minute
        # validate was cut off at 30 and reported as failed while LinuxGSM kept running. Now the
        # channel goes quiet only when the console the operator is watching does.
        #
        # The ACTION writes to the file, never to the channel: `tee` in its pipeline would kill
        # LinuxGSM with SIGPIPE on its next line once the channel is closed (the drain giving up,
        # or the panel restarting), mid-update. Here only the follower dies; the action finishes
        # and the file keeps its output. `wait` keeps LinuxGSM's exit code rather than tail's.
        logf = _quote(f"/home/{user}/.panel-{action}.log")
        body = (f": > {logf}; {{ {body}; }} >> {logf} 2>&1 & pid=$!; "
                f"tail -n +1 -f --pid=$pid {logf} 2>/dev/null; wait $pid; exit $?")
    else:
        body = f"{body} 2>&1"
    # `export`, not a `TERM=xterm cmd` prefix: with `answers` the command is a PIPELINE, and a
    # prefix would set TERM for printf and leave LinuxGSM emitting `tput: unknown terminal`.
    inner = f"cd /home/{_quote(user)} && export TERM=xterm && {body}"
    cmd = f"sudo -u {_quote(user)} bash -c {_quote(inner)}"
    # The command self-escalates via `sudo -u`, so don't double-wrap with sudo.
    return run_command(server, cmd, timeout=timeout, sudo=False)


GAME_PRIORITY_NICE = -1   # slight CPU priority edge for game processes (root-only to set negative)


def set_game_priority(server, user, nice=GAME_PRIORITY_NICE):
    """Give a game user's processes a small CPU-priority edge by renicing them. A NEGATIVE nice is
    root-only, so this runs via sudo (as root, NOT the game user). Best-effort — a failure just
    leaves the game at its default nice. Called right after a panel start/restart so the freshly
    spawned game process gets the boost; the periodic keeper (set_game_priority_bulk) then holds it
    there even for servers the LinuxGSM monitor cron restarts as the game user."""
    try:
        run_privileged(server, "renice-users", [str(int(nice)), user], timeout=15,
                       merge_stderr=False)
    except Exception:
        _log.debug("set_game_priority failed (non-fatal)", exc_info=True)


# tools/panel-helper's exit status when it refuses an argument (main(): validate() raised). Nothing
# it runs exits with it for a verb here: renice reports failure as 1.
_HELPER_REFUSED_ARGS = 2


def set_game_priority_bulk(server, users, nice=GAME_PRIORITY_NICE):
    """Renice ALL processes of several game users in ONE root command (negative nice needs root).
    The panel boosts a game on its own start/restart, but the LinuxGSM monitor cron restarts a
    crashed server AS the game user — which can't lower its own nice — so it drops back to 0. The
    periodic keeper calls this to re-apply the edge to every game, however it (re)started. A user
    with no running processes is a harmless no-op. `users` are validated instance names (no
    injection risk). Best-effort."""
    users = [u for u in users if u]
    if not users:
        return
    try:
        _, _, rc = run_privileged(server, "renice-users", [str(int(nice))] + list(users),
                                  timeout=20, merge_stderr=False)
    except Exception:
        _log.debug("set_game_priority_bulk failed (non-fatal)", exc_info=True)
        return
    if rc == _HELPER_REFUSED_ARGS and len(users) > 1 and is_local_server(server):
        # The helper validates the whole argument list or none of it, and it refuses an account
        # outside the panel's game-account group — an imported sudo-capable install, or one
        # install.sh took out of the group. One such account on the panel host left EVERY game
        # there at nice 0, every pass, silently. So when the batch is refused, go one account at a
        # time: a refusal then costs only the account it is about.
        #
        # ONLY on that refusal. renice itself exits 1 whenever one listed account has no process
        # ("failed to get priority ... No such process") — any stopped server — having reniced the
        # rest; retrying on that would turn every keeper pass into one sudo call per server.
        for user in users:
            set_game_priority(server, user, nice)


def _tmux_live_socket_sh(selfname):
    """Shell that sets $SOCK to the tmux socket holding a LIVE `<selfname>` session. LinuxGSM makes a
    fresh `<selfname>-<random>` socket on every (re)start and the dead ones linger, so picking the
    first match blindly can land on a STALE socket — then send-keys/capture-pane silently no-op,
    which breaks console reads AND kick/ban/say for any server that has ever restarted. Iterate the
    matches and take the one with a live session; emit NO_SESSION + exit 3 when none is live."""
    return (
        'D=/tmp/tmux-$(id -u); SOCK=""; '
        f'for s in $(ls -1 "$D" 2>/dev/null | grep "^{selfname}-"); do '
        f'tmux -L "$s" has-session -t {selfname} 2>/dev/null && {{ SOCK="$s"; break; }}; done; '
        '[ -z "$SOCK" ] && { echo NO_SESSION; exit 3; }; '
    )


def send_console_command(server, user, command, timeout=20, selfname=None):
    """Inject a command into a LinuxGSM instance's live console.

    LinuxGSM runs every server inside a tmux session named `<selfname>` on a
    private socket `<selfname>-<random>` in the user's tmux dir. We drive that
    with `tmux send-keys`, which works for EVERY game — including ones (e.g. cod)
    that don't expose LinuxGSM's own `send` subcommand. Returns rc 3 with
    NO_SESSION when the server isn't running (no tmux session to send to)."""
    selfname = selfname or user
    # The same guard run_as_game_user applies, for the same reason it gives at length: the model's
    # @validates hook fires on ASSIGNMENT and never on a row loaded from the database, so a row
    # written before the validator existed, restored from a backup, or edited straight in
    # data/panel.db reaches here unchecked. `user` sits AHEAD of the `bash -c`, so it breaks out at
    # the shell that runs sudo — as the panel's SSH account, which on a remote host is the identity
    # the panel escalates with — and `selfname` lands inside the script body via the grep and the
    # has-session in _tmux_live_socket_sh. `command` was already quoted; these two were not, and
    # this was the one `sudo -u <account>` builder in this file with no check at all. Returns the
    # tuple every caller unpacks, never a raise (game.py reads out[2] as the rc).
    if not (_SAFE_GAME_IDENT.match(user or "") and _SAFE_GAME_IDENT.match(selfname or "")):
        _log.warning("refusing to send to an unsafe account/script name")
        return "", "invalid account or script name", 1
    inner = _tmux_live_socket_sh(selfname) + f'tmux -L "$SOCK" send-keys -t {selfname} {_quote(command)} Enter'
    cmd = f"sudo -u {_quote(user)} bash -c {_quote(inner)}"
    return run_command(server, cmd, timeout=timeout, sudo=False)


def remote_public_ip(server):
    """Best-effort public IPv4 of the remote (or the panel host for local)."""
    for cmd in ("curl -fsS --max-time 5 https://api.ipify.org",
                "curl -fsS --max-time 5 https://ifconfig.me",
                "dig +short myip.opendns.com @resolver1.opendns.com"):
        try:
            out, _, rc = run_command(server, cmd, timeout=8)
            ip = (out or "").strip().split("\n")[0].strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}\Z", ip):
                return ip
        except Exception:  # nosec B112
            continue   # best-effort: fall through to the next IP-detection command
    return ""


_live_metrics_cache = register_remote_cache({})   # (server.id, short_name, port) -> (exp, dict)
_LIVE_METRICS_TTL = 2      # de-dups concurrent viewers of the SAME server (the detail page polls
#                            every 4s, so a single viewer still gets a fresh read each poll)


# /proc/<pid>/stat, after splitting on the LAST ')' (comm can contain spaces and parens):
# b[1] is STATE, because awk's split(s, b, " ") drops the leading blank. That puts utime at 12 and
# stime at 13. The samplers below summed b[13]+b[14] — stime + CUTIME — and cutime only counts
# reaped children, so a game server burning a core reported ~0% CPU. Named here, and asserted
# against a known stat line in the unit suite, because the off-by-one is invisible in review and
# the symptom is a plausible-looking small number rather than an error.
_STAT_UTIME_IDX, _STAT_STIME_IDX = 12, 13
_STAT_JIFFIES_EXPR = "b[%d]+b[%d]" % (_STAT_UTIME_IDX, _STAT_STIME_IDX)


# ── One sample per HOST, not per game ─────────────────────────────────────────────────────────
# server_live_metrics takes ONE round trip per GAME, and the dashboard polls it for every game the
# viewer can see. Measured against an 80ms link, /api/dashboard/metrics cost
# ceil(servers / _PLAYER_POLL_WORKERS) x latency — 1.05s at 100 servers, ~5s at 500, every 10
# seconds, per open dashboard. (Predicted 400ms at 40 servers; measured 408ms.) Most of that work
# is redundant: each call returns the WHOLE HOST's figures alongside one game's share, so twenty
# games on a host fetched the same host numbers twenty times.
#
# This asks once per host and gets everything. The per-game figures are all keyed on the game's
# Linux user, so a single pass over `ps -eo user=,...` yields every user at once — which means the
# command is a FIXED SIZE no matter how many games run there, rather than growing a fragment per
# game until it stops fitting in a shell. Every game's CPU share is also measured across the same
# 0.25s window as the host's, which the per-game version could not do.
_host_metrics_cache = register_remote_cache({})   # remote id -> (expiry_epoch, parsed dict)

# Sum utime+stime per user in ONE awk pass: ps gives pid -> user, getline reads each
# /proc/<pid>/stat. comm can contain spaces and ')', so split on the LAST ')' — the same rule the
# per-game version uses, for the same reason.
_JIFFIES_BY_USER = (
    "ps -eo user:32=,pid= | awk -v TAG=%s '"
    "{ gsub(/^ +| +$/, \"\", $1); u[$2] = $1 } "
    "END { for (p in u) { f = \"/proc/\" p \"/stat\"; "
    "if ((getline line < f) > 0) { n = split(line, a, \")\"); split(a[n], b, \" \"); "
    "s[u[p]] += " + _STAT_JIFFIES_EXPR + " } close(f) } "
    "for (x in s) print TAG, x, s[x] }'"
)


def host_live_metrics(server, force=False):
    """Whole-host figures plus EVERY user's process figures, in one round trip.

    Returns {"host": {...}, "users": {username: {...}}, "ports": set(int)} — the caller picks out
    the users and ports it cares about. Cached for the same couple of seconds as the per-game
    version, keyed on the host alone, so which games a particular viewer can see does not change
    whether the sample is reusable.

    No sudo, exactly as server_live_metrics established: every part reads world-readable state."""
    now = time.time()
    ck = getattr(server, "id", None)
    if not force:
        hit = _host_metrics_cache.get(ck)
        if hit and hit[0] > now:
            return hit[1]
    parts = [
        "grep '^cpu ' /proc/stat",
        _JIFFIES_BY_USER % "GJA",
        "sleep 0.25",
        "grep '^cpu ' /proc/stat",
        _JIFFIES_BY_USER % "GJB",
        "free -b | awk '/Mem:/{print \"MEM\",$2,$3}'",
        "awk '{print \"LOAD\",$1,$2,$3}' /proc/loadavg",
        "df -B1 / | tail -1 | awk '{print \"DISK\",$2,$3}'",
        "echo CORES $(nproc)",
        "echo UPTIME $(awk '{print int($1)}' /proc/uptime)",
        ("ps -eo user:32=,rss= --no-headers 2>/dev/null | awk '{gsub(/^ +| +$/,\"\",$1); "
         "s[$1]+=$2; n[$1]++} END{for(u in s) print \"GAMERAM\", u, s[u], n[u]}'"),
        ("ps -eo user:32=,etimes= --no-headers 2>/dev/null | awk '{gsub(/^ +| +$/,\"\",$1); "
         "if($2>m[$1]) m[$1]=$2} END{for(u in m) print \"GUP\", u, m[u]}'"),
        "ss -H -ltnu 2>/dev/null | awk '{n=split($5,a,\":\"); print \"PORT\", a[n]}' | sort -u",
    ]
    out, _, _ = run_command(server, " ; ".join(parts), timeout=20, sudo=False)

    host = {"cpu_percent": 0.0, "ram_used": 0, "ram_total": 0, "ram_percent": 0.0,
            "disk_used": 0, "disk_total": 0, "disk_percent": 0.0, "load": [0, 0, 0],
            "cores": 1, "uptime_secs": 0}
    gja, gjb, ram, procs, up, ports = {}, {}, {}, {}, {}, set()
    cpu_lines = []
    for line in (out or "").splitlines():
        f = line.split()
        if not f:
            continue
        tag = f[0]
        if tag == "cpu" and len(f) >= 8:
            cpu_lines.append([int(x) for x in f[1:8] if x.lstrip("-").isdecimal()])
        elif tag in ("GJA", "GJB") and len(f) >= 3 and f[2].lstrip("-").isdecimal():
            (gja if tag == "GJA" else gjb)[f[1]] = int(f[2])
        elif tag == "MEM" and len(f) >= 3:
            host["ram_total"], host["ram_used"] = int(f[1]), int(f[2])
        elif tag == "LOAD" and len(f) >= 4:
            host["load"] = [float(f[1]), float(f[2]), float(f[3])]
        elif tag == "DISK" and len(f) >= 3:
            host["disk_total"], host["disk_used"] = int(f[1]), int(f[2])
        elif tag == "CORES" and len(f) > 1 and f[1].isdecimal():
            host["cores"] = int(f[1])
        elif tag == "UPTIME" and len(f) > 1 and f[1].isdecimal():
            host["uptime_secs"] = int(f[1])
        elif tag == "GAMERAM" and len(f) >= 4 and f[2].isdecimal() and f[3].isdecimal():
            ram[f[1]], procs[f[1]] = int(f[2]), int(f[3])
        elif tag == "GUP" and len(f) >= 3 and f[2].isdecimal():
            up[f[1]] = int(f[2])
        elif tag == "PORT" and len(f) >= 2 and f[1].isdecimal():
            ports.add(int(f[1]))

    total_delta = 0
    if len(cpu_lines) >= 2 and len(cpu_lines[0]) >= 7 and len(cpu_lines[1]) >= 7:
        a, b = cpu_lines[0], cpu_lines[1]
        idle, total_delta = b[3] - a[3], sum(b) - sum(a)
        if total_delta > 0:
            host["cpu_percent"] = round((1 - idle / total_delta) * 100, 1)
    if host["ram_total"]:
        host["ram_percent"] = round(host["ram_used"] / host["ram_total"] * 100, 1)
    if host["disk_total"]:
        host["disk_percent"] = round(host["disk_used"] / host["disk_total"] * 100, 1)

    users = {}
    for name in set(gja) | set(gjb) | set(ram) | set(up):
        ram_mb = int(ram.get(name, 0) / 1024)
        cpu = 0.0
        if name in gja and name in gjb and total_delta > 0:
            cpu = round(max(0, gjb[name] - gja[name]) / total_delta * 100, 1)
        users[name] = {"game_cpu_percent": cpu, "game_ram_mb": ram_mb,
                       "game_procs": procs.get(name, 0), "game_uptime_secs": up.get(name, 0),
                       "game_ram_percent": (round(ram_mb * 1024 * 1024 / host["ram_total"] * 100, 1)
                                            if host["ram_total"] else 0.0)}
    result = {"host": host, "users": users, "ports": ports}
    if out:   # cache a real read only — an empty result is an SSH blip, not a host at 0%
        _host_metrics_cache[ck] = (now + _LIVE_METRICS_TTL, result)
    return result


def metrics_for_game(sample, short_name, game_port):
    """One game's slice of a host_live_metrics() sample, shaped like server_live_metrics()."""
    m = dict(sample["host"])
    m.update(sample["users"].get(short_name or "",
                                 {"game_cpu_percent": 0.0, "game_ram_mb": 0, "game_procs": 0,
                                  "game_uptime_secs": 0, "game_ram_percent": 0.0}))
    m["port_open"] = bool(game_port) and int(game_port) in sample["ports"]
    return m


def server_live_metrics(server, short_name=None, game_port=None, force=False):
    """One-round-trip live metrics for polling. Reports both whole-VPS figures
    (CPU%% via /proc/stat delta, RAM, disk, load, uptime) AND — when a game user
    is given — that GAME's own CPU%%, RAM, process count and uptime, plus a
    port-listening online check. Per-game CPU is sampled by diffing the game
    processes' utime+stime jiffies across the same 0.25s window as the VPS CPU
    sample, expressed as a share of total machine capacity (same basis as
    cpu_percent). Kept to a single SSH command for speed, and cached for a couple
    of seconds so two open tabs/viewers of one server don't each run the sample."""
    _now = time.time()
    _ck = (getattr(server, "id", None), short_name, game_port)
    if not force:
        _hit = _live_metrics_cache.get(_ck)
        if _hit and _hit[0] > _now:
            return _hit[1]
    # Re-validated HERE, like run_as_game_user, send_console_command and _rewrite_crontab: both
    # values below are interpolated into the shell command unquoted, and GameServer's @validates
    # fires on assignment only — never on a row loaded from the database, so a row written before
    # the validator existed or restored from a tampered backup reaches this code unchecked. This
    # one runs by itself on every dashboard and status poll, as server.username (root on most
    # remotes). A name that fails is dropped rather than refused: the host's own figures are
    # still worth reporting, and the game's read as zero instead of as a command.
    if short_name and not _SAFE_GAME_IDENT.match(str(short_name)):
        _log.warning("live metrics: refusing to interpolate game user %r", short_name)
        short_name = None
    if game_port:
        try:
            game_port = int(game_port)
        except (TypeError, ValueError):
            _log.warning("live metrics: refusing to interpolate game port %r", game_port)
            game_port = None
    # Robust per-process jiffie sum (utime+stime). /proc/pid/stat's comm field can
    # contain spaces/parens, so split on the LAST ')' before reading numeric fields.
    def _gjiffies(tag):
        # b[12]+b[13], NOT b[13]+b[14]. awk's split(s, b, " ") drops the leading blank, so after the
        # comm field b[1] is STATE — which puts utime at 12 and stime at 13. The old indices summed
        # stime + CUTIME instead: cutime only counts reaped children, and a game server spends
        # almost everything in user time, so this reported ~0% CPU per game no matter how hard a
        # server was working. Verified against a process burning a known second of CPU: b[12]=99,
        # b[13]=0, b[14]=0.
        return (f"for p in $(ps -u {short_name} -o pid= 2>/dev/null); do "
                f"awk '{{n=split($0,a,\")\"); split(a[n],b,\" \"); print {_STAT_JIFFIES_EXPR}}}' "
                f"/proc/$p/stat 2>/dev/null; done | awk '{{s+=$1}} END{{print \"{tag}\",s+0}}'")

    parts = ["grep '^cpu ' /proc/stat"]
    if short_name:
        parts.append(_gjiffies("GJA"))
    parts += ["sleep 0.25", "grep '^cpu ' /proc/stat"]
    if short_name:
        parts.append(_gjiffies("GJB"))
    parts += [
        "free -b | awk '/Mem:/{print \"MEM\",$2,$3}'",
        "awk '{print \"LOAD\",$1,$2,$3}' /proc/loadavg",
        "df -B1 / | tail -1 | awk '{print \"DISK\",$2,$3}'",
        "echo CORES $(nproc)",
        "echo UPTIME $(awk '{print int($1)}' /proc/uptime)",
    ]
    if short_name:
        parts.append(f"ps -u {short_name} -o rss= --no-headers 2>/dev/null | awk '{{s+=$1}} END{{print \"GAMERAM\",s+0,NR+0}}'")
        parts.append(f"echo GUP $(ps -u {short_name} -o etimes= --no-headers 2>/dev/null | sort -rn | head -1)")
    if game_port:
        parts.append(f"echo PORT $(ss -H -ltnu 'sport = :{game_port}' 2>/dev/null | wc -l)")
    # No sudo: every part of this reads world-readable state — /proc/stat, /proc/loadavg,
    # /proc/uptime, free, df, nproc, `ps -u <user>` and a listening-socket count. It was asking for
    # root it never needed, and on the panel's own host that was a local sudo call on every poll.
    out, _, _ = run_command(server, " ; ".join(parts), timeout=15, sudo=False)

    m = {"cpu_percent": 0.0, "ram_used": 0, "ram_total": 0, "ram_percent": 0.0,
         "disk_used": 0, "disk_total": 0, "disk_percent": 0.0, "load": [0, 0, 0],
         "cores": 1, "uptime_secs": 0, "game_ram_mb": 0, "game_procs": 0,
         "game_cpu_percent": 0.0, "game_uptime_secs": 0, "port_open": False}
    cpu_lines = []
    gja = gjb = None
    for line in (out or "").splitlines():
        f = line.split()
        if not f:
            continue
        if f[0] == "cpu" and len(f) >= 8:
            cpu_lines.append([int(x) for x in f[1:8]])
        elif f[0] == "GJA" and len(f) >= 2:
            gja = int(f[1]) if f[1].lstrip("-").isdecimal() else 0
        elif f[0] == "GJB" and len(f) >= 2:
            gjb = int(f[1]) if f[1].lstrip("-").isdecimal() else 0
        elif f[0] == "MEM" and len(f) >= 3:
            m["ram_total"], m["ram_used"] = int(f[1]), int(f[2])
        elif f[0] == "LOAD" and len(f) >= 4:
            m["load"] = [float(f[1]), float(f[2]), float(f[3])]
        elif f[0] == "DISK" and len(f) >= 3:
            m["disk_total"], m["disk_used"] = int(f[1]), int(f[2])
        elif f[0] == "CORES":
            m["cores"] = int(f[1]) if len(f) > 1 and f[1].isdecimal() else 1
        elif f[0] == "UPTIME":
            m["uptime_secs"] = int(f[1]) if len(f) > 1 and f[1].isdecimal() else 0
        elif f[0] == "GAMERAM" and len(f) >= 3:
            m["game_ram_mb"] = int(int(f[1]) / 1024); m["game_procs"] = int(f[2])
        elif f[0] == "GUP":
            m["game_uptime_secs"] = int(f[1]) if len(f) > 1 and f[1].isdecimal() else 0
        elif f[0] == "PORT":
            m["port_open"] = len(f) > 1 and f[1].isdecimal() and int(f[1]) > 0
    total_delta = 0
    if len(cpu_lines) >= 2:
        a, b = cpu_lines[0], cpu_lines[1]
        idle = (b[3] - a[3]); total_delta = sum(b) - sum(a)
        if total_delta > 0:
            m["cpu_percent"] = round((1 - idle / total_delta) * 100, 1)
    if gja is not None and gjb is not None and total_delta > 0:
        m["game_cpu_percent"] = round(max(0, gjb - gja) / total_delta * 100, 1)
    if m["ram_total"]:
        m["ram_percent"] = round(m["ram_used"] / m["ram_total"] * 100, 1)
        m["game_ram_percent"] = round(m["game_ram_mb"] * 1024 * 1024 / m["ram_total"] * 100, 1)
    if m["disk_total"]:
        m["disk_percent"] = round(m["disk_used"] / m["disk_total"] * 100, 1)
    if out:   # cache a real read only (an empty result == SSH blip; don't pin stale zeros)
        _live_metrics_cache[_ck] = (_now + _LIVE_METRICS_TTL, m)
    return m


def remote_live_metrics(server):
    """Per-core + overall CPU%% and RAM/swap for a server, in the SAME shape as
    system_ops.live_metrics() — so the remote management page can reuse the Panel
    Server's live bar graphs. One SSH round trip (two /proc/stat samples 0.25s
    apart + /proc/meminfo). For the local machine, delegates to system_ops."""
    if is_local_server(server):
        try:
            from panel.ops import system_ops
            return system_ops.live_metrics()
        except Exception:
            _log.debug("remote_live_metrics: ignored non-fatal error", exc_info=True)
    cmd = ("echo ===A; grep '^cpu' /proc/stat; echo ===B; sleep 0.25; grep '^cpu' /proc/stat; "
           "echo ===MEM; grep -E 'MemTotal|MemAvailable|SwapTotal|SwapFree' /proc/meminfo; "
           "echo ===DISK; df -PB1 /")
    out, _, _lm_rc = run_command(server, cmd, timeout=12)
    section = None
    A, B, mem = {}, {}, {}
    disk_total = disk_used = 0
    for line in (out or "").splitlines():
        if line.startswith("==="):
            section = line[3:]
            continue
        parts = line.split()
        if not parts:
            continue
        if section in ("A", "B") and parts[0].startswith("cpu") and len(parts) >= 8:
            (A if section == "A" else B)[parts[0]] = [int(x) for x in parts[1:8]]
        elif section == "MEM" and len(parts) >= 2:
            try:
                mem[parts[0].rstrip(":")] = int(parts[1]) * 1024  # kB → bytes
            except ValueError:
                _log.debug("remote_live_metrics: ignored non-fatal error", exc_info=True)
        elif section == "DISK" and len(parts) >= 4 and parts[1].isdecimal():
            # df -PB1 data row: Filesystem 1B-blocks Used Available Use% Mounted (skip the header)
            disk_total, disk_used = int(parts[1]), int(parts[2])

    def _pct(n):
        if n not in A or n not in B:
            return 0.0
        idle = B[n][3] - A[n][3]
        total = sum(B[n]) - sum(A[n])
        return round((1 - idle / total) * 100, 1) if total > 0 else 0.0

    core_names = sorted((n for n in A if n != "cpu" and n.startswith("cpu")),
                        key=lambda x: int(x[3:]) if x[3:].isdecimal() else 0)
    cores = [_pct(n) for n in core_names]
    ram_total = mem.get("MemTotal", 0)
    ram_used = ram_total - mem.get("MemAvailable", 0)
    swap_total = mem.get("SwapTotal", 0)
    swap_used = swap_total - mem.get("SwapFree", 0)
    # read_ok, because every number below is 0 when NOTHING was read: run_command returns
    # ("", "...timed out", -1) rather than raising, "".splitlines() is empty, and the dict comes
    # back cpu 0%, 0 cores, RAM 0 of 0 — an idle, healthy-looking host that is in fact
    # unreachable. remote_uptime beside this already carries the same flag for the same reason
    # ("don't cache a failed/empty read"); this one had no way to say it.
    #
    # The test is the two readings the whole dict is derived from: a CPU sample in BOTH /proc/stat
    # passes, and a MemTotal. A host that answered has them; nothing else produces them.
    read_ok = bool(_lm_rc == 0 and "cpu" in A and "cpu" in B and ram_total)
    return {
        "read_ok": read_ok,
        "cpu_overall": _pct("cpu"),
        "cpu_cores": cores,
        "core_count": len(cores),
        "ram_used": ram_used, "ram_total": ram_total,
        "ram_percent": round(ram_used / ram_total * 100, 1) if ram_total else 0,
        "swap_used": swap_used, "swap_total": swap_total,
        "swap_percent": round(swap_used / swap_total * 100, 1) if swap_total else 0,
        "disk_used": disk_used, "disk_total": disk_total,
        "disk_percent": round(disk_used / disk_total * 100, 1) if disk_total else 0,
    }


# Drops the one line whose content — leading and trailing whitespace ignored — equals
# $CRON_DROP. Through ENVIRON, not `-v`: awk expands backslash escapes in a `-v` value, and a
# cron command may legitimately contain one.
_CRON_DROP_AWK = (
    'awk \'BEGIN{w=ENVIRON["CRON_DROP"]} '
    '{t=$0; gsub(/^[ \\t]+|[ \\t]+$/,"",t); if (t!=w) print}\' '
)


def _rewrite_crontab(server, user, grep_args, add_lines, extra_pre="", drop_line=None):
    """Reliably rewrite `user`'s crontab: keep every existing line except those
    matched by `grep_args` (arguments passed to grep, already quoted, e.g.
    "-vF <pat>"; empty keeps all), then append `add_lines`.

    Installs via `crontab -u user FILE` (a tempfile) instead of piping the new
    content to `crontab -u user -`. The stdin-pipe form is unreliable under
    eventlet's green subprocess — the shell can be reaped before crontab finishes
    reading stdin, so the write silently no-ops while returncode stays 0 — whereas
    reads and file-argument installs work correctly. `extra_pre` runs first (used
    to clean up flag files).

    `drop_line` removes one line by its content IGNORING LEADING AND TRAILING WHITESPACE, which is
    what the cron editor needs and what `grep -vxF` could not give it. Every transport returns
    `out.strip()` — the whole listing as one blob — so the FIRST line of a crontab comes back
    without its indentation, and indentation is legal and common in a hand-edited crontab. That
    stripped text is the `raw` the panel hands the browser, and the browser hands it back as the
    identity to delete or update; a whole-line fixed-string match then missed the real line.
    delete_cron_job reported success and removed nothing, and update_cron_job appended its rewrite
    beside the original, so the job ran on two schedules. Compared through awk's ENVIRON rather
    than `-v`, because `-v` processes backslash escapes in the value and a cron command may
    contain one."""
    env_pre = ""
    if drop_line is not None:
        env_pre = "CRON_DROP=%s; export CRON_DROP; " % _quote(str(drop_line).strip())
        filt = _CRON_DROP_AWK
    else:
        filt = f"grep {grep_args} " if grep_args else "cat "
    appends = "".join(f'printf \'%s\\n\' {_quote(l)} >> "$T"; ' for l in (add_lines or []))
    # Validated and quoted HERE, for the reason run_as_game_user spells out above: the model's
    # @validates hook fires on ASSIGNMENT and never on a row loaded from the database, so a row
    # written before that validator existed — or restored from a tampered backup — reaches this
    # function unchecked. It matters more here than there: `user` went in UNQUOTED, and the
    # pipeline below runs as ROOT, so `crontab -u <user>` was a root command-injection point one
    # bad row away. Five cron routes reach this.
    if not _SAFE_GAME_IDENT.match(user or ""):
        _log.warning("refusing to rewrite a crontab for an unsafe account name")
        return False, "invalid account name"
    _u = _quote(user)
    # No `-u`, and no root. `crontab -l` and `crontab <file>` run AS the account operate on that
    # account's own crontab, which is exactly what all five callers want — so this ran as ROOT for
    # no reason at all.
    pipeline = (
        f'{env_pre}{extra_pre}T=$(mktemp); crontab -l 2>/dev/null | {filt}> "$T"; '
        f'{appends}crontab "$T"; RC=$?; rm -f "$T"; exit $RC'
    )
    # It WAS a hand-built `sudo bash -c …` passed with sudo=False — the exact shape SECURITY.md
    # records as gone ("_sudo_sh | 0 — the route is gone"), and invisible to all three escalation
    # ratchets: one counts calls to a function named _sudo_sh, one counts the sudo=True keyword,
    # and one looks for an argv list starting with "sudo". This was none of those.
    #
    # Dropping it to the game user removes that root escalation outright, and is also what makes
    # cron work on a narrow-grant host: there the panel reaches root only by running the helper,
    # so the old form was refused and every cron write — autostart, scheduled restarts, backup
    # schedules — failed. Measured on a test host, as the panel user:
    #     sudo -n bash -c 'crontab -u gmodserver -l'  -> sudo: a password is required
    #     sudo -n -u gmodserver crontab -l            -> the crontab, and `crontab <file>` wrote it
    #
    # It stays a shell pipeline because `crontab -l | filter > tmp; crontab tmp` is genuinely a
    # pipeline, but every value interpolated into it is validated and quoted.
    cmd = f"sudo -u {_u} bash -c {_quote(pipeline)}"
    out, err, rc = run_command(server, cmd, timeout=20, sudo=False)
    return rc == 0, (err or out or "")


def set_autostart(server, user, enabled, selfname=None):
    """Enable/disable autostart via LinuxGSM's `monitor` cron (every 5 min), NOT a
    `@reboot ... start` line.

    `monitor` keeps a server in its INTENDED state: `start` writes a persistent lockfile and
    `stop` removes it, so monitor brings back one that should be running — including after a
    reboot, since the lockfile survives — and leaves a deliberately-stopped server (no lockfile)
    down. A `@reboot start` would instead force-start even a server the operator had stopped, so
    we no longer use it and strip any legacy one. Enabling ensures the monitor line exists;
    disabling removes it."""
    selfname = selfname or user
    base = f"/home/{user}/{selfname}"
    monitor_line = f"*/5 * * * * {cron._record_managed_cmd(user, f'{base} monitor')}"
    add = [monitor_line] if enabled else []
    # Strip any existing monitor line AND any legacy '@reboot ... start' autostart line in one
    # pass, then re-add monitor when enabling.
    remove_re = f"({base} monitor |@reboot .*{selfname} start)"
    return _rewrite_crontab(server, user, f"-vE {_quote(remove_re)}", add)


def install_game_cron(server, user, selfname=None, supported=None):
    """Set up LinuxGSM maintenance cron for a game instance — only for the commands
    that game supports. Also strips any legacy '@reboot ... start' line — autostart is now the
    monitor cron below (see set_autostart), which respects the server's intended state. Idempotent.
      monitor      every 5 min   (autostart + restart if crashed)
      mods-update  daily 05:00   (before update)
      update       daily 05:15
      update-lgsm  weekly Sun 05:30
    """
    selfname = selfname or user
    supported = supported or set()
    base = f"/home/{user}/{selfname}"

    def sc(cmd):
        # Record each maintenance run's exit code + output (keeps the command visible so the
        # managed-line grep still matches), so the panel can show update/monitor success.
        return cron._record_managed_cmd(user, f"{base} {cmd}")

    lines = []
    if "monitor" in supported:
        lines.append(f"*/5 * * * * {sc('monitor')}")
    if "mods-update" in supported:
        lines.append(f"0 5 * * * {sc('mods-update')}")
    if "update" in supported:
        lines.append(f"15 5 * * * {sc('update')}")
    if "update-lgsm" in supported:
        lines.append(f"30 5 * * 0 {sc('update-lgsm')}")
    if not lines:
        return True, "no maintenance commands to schedule"

    remove_re = f"({base} (monitor|mods-update|update|update-lgsm) |@reboot .*{selfname} start)"
    return _rewrite_crontab(server, user, f"-vE {_quote(remove_re)}", lines)


# Panel game_type -> gamedig query type (best effort). Unmapped games skip the
# player check and just restart at the daily time.
GAMEDIG_TYPE = {
    "gmod": "garrysmod", "cs": "cs16", "css": "css", "cs2": "cs2", "tf2": "tf2",
    "hl2dm": "hl2dm", "dods": "dods", "left4dead2": "left4dead2", "l4d2": "left4dead2",
    "insurgency": "insurgency", "ins": "insurgency", "rust": "rust",
    "valheim": "valheim", "vh": "valheim",
    "sdtd": "sdtd", "7d2d": "sdtd",
    # Minecraft: Java editions (vanilla + Paper/Velocity/Waterfall, which answer Server List Ping)
    # use "minecraft"; Bedrock uses "minecraftpe". This is what yields count AND max-players (Minecraft
    # keeps max in server.properties, not the LinuxGSM config, so the config-fallback can't see it).
    "mc": "minecraft", "pmc": "minecraft", "vmc": "minecraft", "wmc": "minecraft",
    "mcb": "minecraftpe", "mcbe": "minecraftpe",
    "squad": "squad", "arma3": "arma3", "mumble": "mumble",
    # Call of Duty family — gamedig CAN query these (protocol names match the LinuxGSM shortnames),
    # so the player count (restart/backup guards + daily-restart-when-empty) works for them too.
    "cod": "cod", "coduo": "coduo", "cod2": "cod2", "cod4": "cod4", "codwaw": "codwaw",
}


# Registered: a deleted host's id is reused, and this decides where a player query is SENT — so a
# stale entry points the new host's queries at the old machine. See register_remote_cache.
_gamedig_host_cache = register_remote_cache({})   # {remote_id: (expiry_ts, ip)}
_GAMEDIG_HOST_TTL = 3600


def _gamedig_host(server):
    """The address to point gamedig at for a game on `server` (a remote). A Source-engine server
    replies to an A2S query FROM the host's real IP, so a query sent to 127.0.0.1 comes back from a
    different source address and gamedig discards it ('Failed all attempts') even though the server
    is up and answering fine on its real IP. So query the host's primary (default-route) IP — a
    0.0.0.0-bound server answers there. Cached per remote for an hour; falls back to 127.0.0.1 when
    the IP can't be resolved (so any host where loopback does answer keeps working). Never raises."""
    rid = getattr(server, "id", None)
    now = time.time()
    hit = _gamedig_host_cache.get(rid)
    if hit and hit[0] > now:
        return hit[1]
    ip = "127.0.0.1"
    try:
        out, _, _ = run_command(
            server,
            "ip route get 1.1.1.1 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++)if($i==\"src\")print $(i+1)}'",
            timeout=8)
        cand = (out or "").strip()
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}\Z", cand):
            ip = cand
    except Exception:
        _log.debug("gamedig-host: default-route IP lookup failed", exc_info=True)
    if rid is not None and ip != "127.0.0.1":
        _gamedig_host_cache[rid] = (now + _GAMEDIG_HOST_TTL, ip)
    return ip


# The PATH the hourly restart-when-empty check looks gamedig up on. A crontab with no PATH= line of
# its own runs with cron's compiled-in default, /usr/bin:/bin (read out of /usr/sbin/cron on the
# test host, Ubuntu 24.04's cron 3.0pl1-184ubuntu2). Where npm puts a global gamedig depends on
# which npm it was: NodeSource's has prefix /usr, so /usr/bin/gamedig, which cron finds; Debian and
# Ubuntu's own npm is configured prefix=/usr/local (debian/npmrc, installed as
# /usr/share/nodejs/npm/npmrc), so /usr/local/bin/gamedig, which cron does NOT. Every host whose
# Node came from Ubuntu — install.sh's distro path on 24.04 and 26.04, and a remote that already
# had Ubuntu's Node 18+ when it was prepared — therefore ran `gamedig: not found` every hour, P
# stayed empty, and `[ "$P" = 0 ]` never held: the daily restart waited for an empty server
# forever. The player readers never saw it: they run gamedig through `sudo -u <user>`, and
# Ubuntu's sudoers sets a secure_path listing /usr/local/bin (classic sudo and sudo-rs both apply
# it). On the test host (NodeSource Node, /usr/bin/gamedig) the line counted 0 under cron's env.
# (gamedig is no longer an npm global: install-gamedig.sh links /usr/local/bin/gamedig AND
# /usr/bin/gamedig to its pinned tree, so lines that predate this PATH find it too. This stays, so
# the check does not depend on that link.)
#
# Set INSIDE the command substitution, so it reaches gamedig, jq and gamedig's `env node` and
# nothing else: the restart itself still runs with the environment cron gave it. /usr/local/bin
# first, the order sudo's secure_path uses, so this check and the player readers pick the same
# gamedig on a host that somehow has both.
CRON_TOOL_PATH = "/usr/local/bin:/usr/bin:/bin"
# What set_daily_restart wrote before, and what it writes now. cron.upgrade_managed_cron_tracking
# heals an existing line from the one to the other in place (an existing crontab line is otherwise
# only rewritten when the operator toggles the setting).
GAMEDIG_CRON_BARE = "P=$(gamedig "


def gamedig_cron_call():
    """The start of the hourly check's player query: `P=$(PATH=...; gamedig `."""
    return "P=$(PATH=%s; gamedig " % CRON_TOOL_PATH


def set_daily_restart(server, user, selfname=None, game_type=None, port=None, enabled=True,
                      hour=5, minute=0):
    """Enable/disable a daily restart that only fires when the server is EMPTY.
    A daily cron sets a 'restart-pending' flag; an hourly cron checks the player
    count (via gamedig) and restarts + clears the flag once it hits 0. So if players
    are on at the daily time, it waits and rechecks each hour until they leave.

    `hour`/`minute` are in the HOST's local time, because that is the clock cron reads — the
    caller converts from whatever the operator entered. They used to be a hardcoded 05:00, which
    on a VPS bootstrapped to UTC (the panel's own default) meant 23:00 for someone in US Central,
    with no time shown anywhere in the UI to notice it by."""
    hour, minute = int(hour) % 24, int(minute) % 60
    selfname = selfname or user
    flag = f"/home/{user}/.restart-pending"
    gdtype = GAMEDIG_TYPE.get(game_type or "", "")

    # Crontab-only (no separate script file — file writes inside a `sudo bash -c`
    # pipeline misbehave under eventlet's green subprocess; crontab-only works).
    #   daily <hour>:<minute>: set the "pending" flag
    #   hourly :10           : if flag set and server empty (gamedig), restart + clear flag
    # The player test is "did we COUNT zero", not "did we fail to count". gamedig writes its
    # failure to stdout as a JSON object ({"error":"Failed all 1 attempts"}), so `.players` is null
    # and jq reports the length of null as 0 — and the old condition,
    # `[ -z "$P" ] || [ "$P" = 0 ] || [ "$P" = null ]`, restarted on all three. Every way the query
    # could fail (packet loss, a world save stalling the query thread, a rate-limited Source server,
    # a firewalled query port, gamedig or jq not installed) therefore restarted a server full of
    # players, from an unattended hourly cron, and this is the one decision the feature exists to
    # avoid. `if … then … else empty end` makes jq print NOTHING unless it really saw a player
    # array, which is the same `ok:(.players|type=="array")` guard the three python-side readers in
    # cron.py use; the shell then only acts on an exact 0.
    #
    # The no-query case stays unconditional, and that is not the same thing: when the panel knows
    # at cron-writing time that the game has no gamedig type or no port, there is no reading to
    # fail, and restarting at the daily time is the behaviour the operator asked for.
    if gdtype and port:
        jqf = 'if (.players|type=="array") then (.players|length) else empty end'
        # gamedig by the PATH above, not cron's: see CRON_TOOL_PATH.
        getp = (f"{gamedig_cron_call()}--type {gdtype} {_gamedig_host(server)}:{port} 2>/dev/null "
                f"| jq -r {_quote(jqf)} 2>/dev/null); ")
        cond = '[ "$P" = 0 ]'
    else:
        getp, cond = "", "true"
    check_cmd = (
        f"[ -f {flag} ] && {{ {getp}"
        f"if {cond}; then "
        f"/home/{user}/{selfname} restart >/dev/null 2>&1; rm -f {flag}; fi; }}"
    )
    touch_line = f"{minute} {hour} * * * {cron._record_managed_cmd(user, f'touch {flag}')}"
    check_line = f"10 * * * * {check_cmd}"
    # Both lines contain the flag path — strip by that to remove/rebuild idempotently.
    grep_args = f"-vF {_quote(flag)}"
    if enabled:
        return _rewrite_crontab(server, user, grep_args, [touch_line, check_line])
    return _rewrite_crontab(server, user, grep_args, [], extra_pre=f"rm -f {flag}; ")
