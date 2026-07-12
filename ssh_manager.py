"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import logging
import os
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import paramiko

from config import decrypt_secret

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
except Exception:
    _tpool = None
    _real_subprocess = subprocess

# In-memory SSH connection cache
_connections = {}
_conn_lock = threading.Lock()


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
        except Exception:  # nosec B110
            pass
    try:
        p.communicate(timeout=5)   # reap it so it doesn't linger as a zombie
    except Exception:  # nosec B110
        pass


def _run_local(cmd, timeout=30, sudo=False):
    """Run a command locally on the panel's own machine.
    If the command already uses privilege escalation, don't double-wrap.

    NOTE: eventlet monkey-patches subprocess. Its green subprocess is unreliable
    when called from a WSGI green thread (an API handler) — the child can be
    reaped before it finishes its work, so e.g. a crontab write silently no-ops
    while returncode is still 0. We therefore run the *original* (unpatched)
    subprocess inside eventlet's native thread pool (tpool), which both avoids
    that bug and keeps the event hub from blocking on long commands."""
    if not sudo:
        full_cmd = cmd
    elif cmd.strip().startswith("sudo") or "sudo -u" in cmd:
        full_cmd = cmd  # already escalated
    else:
        # Wrap the WHOLE command in `sudo bash -c` (like the remote path) so pipes and
        # redirects run under root too. `sudo {cmd}` would only elevate the first command
        # in a pipe — e.g. `sudo yes | ufw delete N` runs ufw as the panel user ("need to
        # be root").
        full_cmd = f"sudo bash -c {_quote(cmd)}"

    def _do():
        p = None
        try:
            # Run in a NEW process group (start_new_session) so that on timeout we can kill the
            # whole group — otherwise subprocess's timeout only kills the direct `sh -c` child and
            # any grandchildren (e.g. a stuck LinuxGSM command) get orphaned and run forever,
            # burning CPU. (Observed: mods commands stuck at ~100% CPU for hours.)
            # Explicit ["/bin/bash","-c",cmd] instead of shell=True — identical behaviour (a shell
            # interprets the composed command, with the panel's own _quote-escaping upstream) but
            # not the subprocess-shell-injection sink shape.
            p = _real_subprocess.Popen(["/bin/bash", "-c", full_cmd], stdout=_real_subprocess.PIPE,
                                       stderr=_real_subprocess.PIPE, text=True, start_new_session=True)
            try:
                out, err = p.communicate(timeout=timeout)
                return (out or "").strip(), (err or "").strip(), p.returncode
            except _real_subprocess.TimeoutExpired:
                _kill_process_tree(p)
                return "", "Command timed out", -1
        except Exception:
            # Never surface raw exception text — it can flow into API responses
            # (CodeQL py/stack-trace-exposure). Log it; callers act on rc == -1.
            _log.debug("local command failed", exc_info=True)
            if p is not None:
                _kill_process_tree(p)
            return "", "command execution error", -1

    if _tpool is not None:
        return _tpool.execute(_do)
    return _do()


def is_local_server(server):
    """Check if a server record represents the local machine."""
    return getattr(server, 'is_local', False) or server.auth_method == "local"


def get_connection(server, force_new=False):
    """Get or create a cached SSH connection to a remote server.
    For local servers, returns None (no SSH needed)."""
    if is_local_server(server):
        return None

    key = f"{server.username}@{server.host}:{server.port}"
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
    policy = _PinPolicy(expected=(server.host_key or ""), reject_on_change=enforce_pin)
    client.set_missing_host_key_policy(policy)

    timeout = 15
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
                import tailscale_integration as ts
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
            return existing
        _connections[key] = client

    return client


def _persist_host_key(server, keystr):
    """Store the pinned host key on the server row (best-effort; if there's no DB session
    in scope it simply pins on the next connection instead)."""
    try:
        from models import db
        server.host_key = keystr
        db.session.commit()
    except Exception:
        try:
            from models import db
            db.session.rollback()
        except Exception:
            # no usable session; the key just pins on the next connection instead
            _log.debug("host-key pin: session rollback unavailable", exc_info=True)


def close_connection(server):
    """Close and remove a cached connection. No-op for local servers."""
    if is_local_server(server):
        return
    key = f"{server.username}@{server.host}:{server.port}"
    with _conn_lock:
        if key in _connections:
            try:
                _connections[key].close()
            except Exception:
                _log.debug("close_connection: closing a stale SSH client failed", exc_info=True)
            del _connections[key]


def _resolve_ts_host(server):
    """Resolve a Tailscale remote's hostname (MagicDNS if a bare name)."""
    host = server.host
    if "." not in host and not host.startswith("100."):
        try:
            import tailscale_integration as ts
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
    return ["-o", "ControlMaster=auto",
            "-o", f"ControlPath={_SSH_CM_DIR}/%C",   # %C = short fixed-length hash of host/port/user
            "-o", "ControlPersist=10m",
            "-o", "ServerAliveInterval=20",
            "-o", "ServerAliveCountMax=3"]


def _run_via_ssh_cli(server, command, timeout=30, sudo=None):
    """Run a command over the system `ssh` binary — used for Tailscale SSH remotes,
    where auth happens at the tailscaled level (paramiko can't do it, but the ssh CLI,
    running from this tailnet node, can — exactly like PuTTY does). Uses connection
    multiplexing so back-to-back commands don't each pay a fresh SSH handshake."""
    use_sudo = sudo if sudo is not None else server.sudo_enabled
    if use_sudo:
        if server.linuxgsm_user:
            remote_cmd = f"sudo -u {server.linuxgsm_user} bash -c {_quote(command)}"
        else:
            remote_cmd = f"sudo bash -c {_quote(command)}"
    else:
        remote_cmd = command
    host = _resolve_ts_host(server)
    ssh_cmd = [
        "ssh", "-T",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=12",
    ] + _ssh_mux_opts() + [
        "-p", str(server.port or 22),
        f"{server.username}@{host}", remote_cmd,
    ]
    try:
        r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "SSH command timed out", -1
    except Exception:
        # Generic message only; the real error is logged, not returned (it can
        # reach API responses — CodeQL py/stack-trace-exposure).
        _log.debug("ssh command failed", exc_info=True)
        return "", "ssh command error", -1


def run_command(server, command, timeout=30, sudo=None):
    """Run a command on the remote server via SSH, or locally if it's the local machine.
    Returns (stdout, stderr, exit_code).
    """
    if is_local_server(server):
        use_sudo = sudo if sudo is not None else server.sudo_enabled
        return _run_local(command, timeout=timeout, sudo=use_sudo)

    # Tailscale SSH is not doable with paramiko (auth is handled by tailscaled),
    # so use the system ssh client for those remotes.
    if server.auth_method == "tailscale":
        return _run_via_ssh_cli(server, command, timeout=timeout, sudo=sudo)

    client = get_connection(server)
    use_sudo = sudo if sudo is not None else server.sudo_enabled

    if use_sudo:
        if server.linuxgsm_user:
            full_cmd = f"sudo -u {server.linuxgsm_user} bash -c {_quote(command)}"
        else:
            full_cmd = f"sudo bash -c {_quote(command)}"
    else:
        full_cmd = command

    try:
        stdin, stdout, stderr = client.exec_command(full_cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return out.strip(), err.strip(), exit_code
    except Exception as e:
        raise ConnectionError(f"Command failed: {e}")


def run_interactive(server, command, timeout=60, sudo=None):
    """Run a command and get output as it streams.
    For local servers, falls back to regular run_command."""
    if is_local_server(server):
        return run_command(server, command, timeout=timeout, sudo=sudo)

    client = get_connection(server)
    use_sudo = sudo if sudo is not None else server.sudo_enabled

    if use_sudo and server.linuxgsm_user:
        full_cmd = f"sudo -u {server.linuxgsm_user} bash -c {_quote(command)}"
    elif use_sudo:
        full_cmd = f"sudo bash -c {_quote(command)}"
    else:
        full_cmd = command

    try:
        stdin, stdout, stderr = client.exec_command(full_cmd, timeout=timeout)
        output = []
        for line in iter(stdout.readline, ""):
            output.append(line.rstrip())
        exit_code = stdout.channel.recv_exit_status()
        err = stderr.read().decode("utf-8", errors="replace")
        return "\n".join(output), err.strip(), exit_code
    except Exception as e:
        raise ConnectionError(f"Command failed: {e}")


def _quote(s):
    """Shell-quote a string for safe use in remote commands."""
    escaped = s.replace("'", "'\\''")
    return f"'{escaped}'"


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
        out, _, rc = run_command(server, script, timeout=45, sudo=True)
    except Exception:
        _log.debug("discover_linuxgsm_servers: scan command failed", exc_info=True)
        return []
    if rc != 0:
        return []

    def _n(x):
        x = (x or "").strip()
        return int(x) if x.isdigit() else 0

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


def run_as_game_user(server, user, action_cmd, timeout=30, selfname=None):
    """Run a LinuxGSM command as the instance's Ubuntu user, from its home dir.
    `user` is the (possibly custom) account name; `selfname` is the LinuxGSM script
    name (always '{game_type}server' — canonical). They differ when the instance was
    given a custom name: only the user is renamed, the script stays canonical.
    Defaults selfname to user for standard installs."""
    selfname = selfname or user
    # TERM=xterm avoids LinuxGSM's `tput: unknown terminal "unknown"` noise.
    inner = f"cd /home/{user} && TERM=xterm ./{selfname} {action_cmd}"
    cmd = f"sudo -u {user} bash -c {_quote(inner)}"
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
        run_command(server, _sudo_sh("renice -n %d -u %s" % (int(nice), user)),
                    timeout=15, sudo=False)
    except Exception:
        _log.debug("set_game_priority failed (non-fatal)", exc_info=True)


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
        run_command(server, _sudo_sh("renice -n %d -u %s" % (int(nice), " ".join(users))),
                    timeout=20, sudo=False)
    except Exception:
        _log.debug("set_game_priority_bulk failed (non-fatal)", exc_info=True)


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
    inner = _tmux_live_socket_sh(selfname) + f'tmux -L "$SOCK" send-keys -t {selfname} {_quote(command)} Enter'
    cmd = f"sudo -u {user} bash -c {_quote(inner)}"
    return run_command(server, cmd, timeout=timeout, sudo=False)


def remote_public_ip(server):
    """Best-effort public IPv4 of the remote (or the panel host for local)."""
    for cmd in ("curl -fsS --max-time 5 https://api.ipify.org",
                "curl -fsS --max-time 5 https://ifconfig.me",
                "dig +short myip.opendns.com @resolver1.opendns.com"):
        try:
            out, _, rc = run_command(server, cmd, timeout=8)
            ip = (out or "").strip().split("\n")[0].strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return ip
        except Exception:  # nosec B112
            continue   # best-effort: fall through to the next IP-detection command
    return ""


_live_metrics_cache = {}   # (server.id, short_name, game_port) -> (expiry_epoch, dict)
_LIVE_METRICS_TTL = 2      # de-dups concurrent viewers of the SAME server (the detail page polls
#                            every 4s, so a single viewer still gets a fresh read each poll)


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
    # Robust per-process jiffie sum (utime+stime). /proc/pid/stat's comm field can
    # contain spaces/parens, so split on the LAST ')' before reading numeric fields.
    def _gjiffies(tag):
        return (f"for p in $(ps -u {short_name} -o pid= 2>/dev/null); do "
                f"awk '{{n=split($0,a,\")\"); split(a[n],b,\" \"); print b[13]+b[14]}}' "
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
    out, _, _ = run_command(server, " ; ".join(parts), timeout=15, sudo=True)

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
            gja = int(f[1]) if f[1].lstrip("-").isdigit() else 0
        elif f[0] == "GJB" and len(f) >= 2:
            gjb = int(f[1]) if f[1].lstrip("-").isdigit() else 0
        elif f[0] == "MEM" and len(f) >= 3:
            m["ram_total"], m["ram_used"] = int(f[1]), int(f[2])
        elif f[0] == "LOAD" and len(f) >= 4:
            m["load"] = [float(f[1]), float(f[2]), float(f[3])]
        elif f[0] == "DISK" and len(f) >= 3:
            m["disk_total"], m["disk_used"] = int(f[1]), int(f[2])
        elif f[0] == "CORES":
            m["cores"] = int(f[1]) if len(f) > 1 and f[1].isdigit() else 1
        elif f[0] == "UPTIME":
            m["uptime_secs"] = int(f[1]) if len(f) > 1 and f[1].isdigit() else 0
        elif f[0] == "GAMERAM" and len(f) >= 3:
            m["game_ram_mb"] = int(int(f[1]) / 1024); m["game_procs"] = int(f[2])
        elif f[0] == "GUP":
            m["game_uptime_secs"] = int(f[1]) if len(f) > 1 and f[1].isdigit() else 0
        elif f[0] == "PORT":
            m["port_open"] = len(f) > 1 and f[1].isdigit() and int(f[1]) > 0
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
            import system_ops
            return system_ops.live_metrics()
        except Exception:
            _log.debug("remote_live_metrics: ignored non-fatal error", exc_info=True)
    cmd = ("echo ===A; grep '^cpu' /proc/stat; echo ===B; sleep 0.25; grep '^cpu' /proc/stat; "
           "echo ===MEM; grep -E 'MemTotal|MemAvailable|SwapTotal|SwapFree' /proc/meminfo; "
           "echo ===DISK; df -PB1 /")
    out, _, _ = run_command(server, cmd, timeout=12)
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
        elif section == "DISK" and len(parts) >= 4 and parts[1].isdigit():
            # df -PB1 data row: Filesystem 1B-blocks Used Available Use% Mounted (skip the header)
            disk_total, disk_used = int(parts[1]), int(parts[2])

    def _pct(n):
        if n not in A or n not in B:
            return 0.0
        idle = B[n][3] - A[n][3]
        total = sum(B[n]) - sum(A[n])
        return round((1 - idle / total) * 100, 1) if total > 0 else 0.0

    core_names = sorted((n for n in A if n != "cpu" and n.startswith("cpu")),
                        key=lambda x: int(x[3:]) if x[3:].isdigit() else 0)
    cores = [_pct(n) for n in core_names]
    ram_total = mem.get("MemTotal", 0)
    ram_used = ram_total - mem.get("MemAvailable", 0)
    swap_total = mem.get("SwapTotal", 0)
    swap_used = swap_total - mem.get("SwapFree", 0)
    return {
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


def _rewrite_crontab(server, user, grep_args, add_lines, extra_pre=""):
    """Reliably rewrite `user`'s crontab: keep every existing line except those
    matched by `grep_args` (arguments passed to grep, already quoted, e.g.
    "-vF <pat>"; empty keeps all), then append `add_lines`.

    Installs via `crontab -u user FILE` (a tempfile) instead of piping the new
    content to `crontab -u user -`. The stdin-pipe form is unreliable under
    eventlet's green subprocess — the shell can be reaped before crontab finishes
    reading stdin, so the write silently no-ops while returncode stays 0 — whereas
    reads and file-argument installs work correctly. `extra_pre` runs first (used
    to clean up flag files)."""
    filt = f"grep {grep_args} " if grep_args else "cat "
    appends = "".join(f'printf \'%s\\n\' {_quote(l)} >> "$T"; ' for l in (add_lines or []))
    pipeline = (
        f'{extra_pre}T=$(mktemp); crontab -u {user} -l 2>/dev/null | {filt}> "$T"; '
        f'{appends}crontab -u {user} "$T"; RC=$?; rm -f "$T"; exit $RC'
    )
    cmd = f"sudo bash -c {_quote(pipeline)}"
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
    monitor_line = f"*/5 * * * * {_record_managed_cmd(user, f'{base} monitor')}"
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
        return _record_managed_cmd(user, f"{base} {cmd}")

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


_gamedig_host_cache = {}          # {remote_id: (expiry_ts, ip)} — where to point gamedig for a host
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
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", cand):
            ip = cand
    except Exception:
        _log.debug("gamedig-host: default-route IP lookup failed", exc_info=True)
    if rid is not None and ip != "127.0.0.1":
        _gamedig_host_cache[rid] = (now + _GAMEDIG_HOST_TTL, ip)
    return ip


def set_daily_restart(server, user, selfname=None, game_type=None, port=None, enabled=True):
    """Enable/disable a daily restart that only fires when the server is EMPTY.
    A daily cron sets a 'restart-pending' flag; an hourly cron checks the player
    count (via gamedig) and restarts + clears the flag once it hits 0. So if players
    are on at the daily time, it waits and rechecks each hour until they leave."""
    selfname = selfname or user
    flag = f"/home/{user}/.restart-pending"
    gdtype = GAMEDIG_TYPE.get(game_type or "", "")

    # Crontab-only (no separate script file — file writes inside a `sudo bash -c`
    # pipeline misbehave under eventlet's green subprocess; crontab-only works).
    #   daily 05:00: set the "pending" flag
    #   hourly :10 : if flag set and server empty (gamedig), restart + clear flag
    getp = (f"P=$(gamedig --type {gdtype} {_gamedig_host(server)}:{port} 2>/dev/null | jq -r '.players|length' 2>/dev/null); "
            if (gdtype and port) else "P=; ")
    check_cmd = (
        f"[ -f {flag} ] && {{ {getp}"
        f'if [ -z "$P" ] || [ "$P" = 0 ] || [ "$P" = null ]; then '
        f"/home/{user}/{selfname} restart >/dev/null 2>&1; rm -f {flag}; fi; }}"
    )
    touch_line = f"0 5 * * * {_record_managed_cmd(user, f'touch {flag}')}"
    check_line = f"10 * * * * {check_cmd}"
    # Both lines contain the flag path — strip by that to remove/rebuild idempotently.
    grep_args = f"-vF {_quote(flag)}"
    if enabled:
        return _rewrite_crontab(server, user, grep_args, [touch_line, check_line])
    return _rewrite_crontab(server, user, grep_args, [], extra_pre=f"rm -f {flag}; ")


def get_autostart(server, user, selfname=None):
    """Return True if autostart is on — i.e. the LinuxGSM `monitor` cron exists for the game
    user. monitor (not a @reboot line) is what keeps the server in its intended state across
    crashes and reboots."""
    selfname = selfname or user
    marker = f"/home/{user}/{selfname} monitor"
    out, _, _ = run_command(
        server, f"crontab -u {user} -l 2>/dev/null | grep -cF {_quote(marker)}",
        timeout=10, sudo=True,
    )
    try:
        return int((out or "0").strip()) > 0
    except ValueError:
        return False


# ── Generic per-server cron manager ──────────────────────────────────────────
# NOTHING is locked in the generic editor any more — the admin can edit or delete EVERY line, even the
# panel-installed ones (the LinuxGSM monitor/update jobs, the Autostart line, the daily-restart flag).
# The two toggle-backed lines stay safe because (a) _wrap_cron_command keeps them VISIBLE in the raw
# crontab, so the Autostart/daily-restart detection (which greps it) still works after a reschedule,
# and (b) their state is derived live from the crontab, so deleting one just reads back as "off".
# `_cron_role` gives them a non-blocking LABEL so the admin knows what a panel line is.

_CRON_FIELD = r"[-0-9*,/A-Za-z]+"
_CRON_SCHED_RE = re.compile(
    r"^(@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|"
    + r"\s+".join([_CRON_FIELD] * 5) + r")$"
)


def _cron_managed_patterns(user, selfname):
    """No cron line is locked any more — every entry is editable/deletable (see the block comment
    above). Kept as an (empty) hook so update/delete keep a harmless guard and a future 'lock this'
    need has a single place to wire it."""
    return []


def _cron_line_managed(line, user, selfname):
    return any(p in line for p in _cron_managed_patterns(user, selfname))


def _cron_role(command, user, selfname):
    """A non-blocking LABEL for a panel-installed line so the admin knows what it is (they can still
    edit or delete it): 'autostart' for the LinuxGSM `monitor` cron, 'daily-restart' for the
    `.restart-pending` flag line, else ''. Unlike the old `managed`, this never locks the row."""
    selfname = selfname or user
    cmd = (command or "").strip()
    if cmd == f"/home/{user}/{selfname} monitor":
        return "autostart"
    if ".restart-pending" in cmd:
        return "daily-restart"
    return ""


def _split_cron_line(line):
    """Split a crontab entry into (schedule, command). Returns (None, None) for a
    line that isn't a valid schedule+command entry."""
    line = line.strip()
    if line.startswith("@"):
        parts = line.split(None, 1)
        return parts[0], (parts[1] if len(parts) > 1 else "")
    parts = line.split(None, 5)
    if len(parts) < 6:
        return None, None
    return " ".join(parts[:5]), parts[5]


def _validate_cron(schedule, command):
    """Return (ok, message, line). Rejects anything that would break the crontab's
    one-entry-per-line structure. The command itself is free-form — it runs as the
    unprivileged game user via cron, exactly like the file editor writes arbitrary
    content — so only the schedule's charset and newlines are constrained."""
    schedule = (schedule or "").strip()
    command = (command or "").strip()
    if not schedule or not command:
        return False, "Schedule and command are both required.", None
    if any(c in (schedule + command) for c in ("\n", "\r", "\x00")):
        return False, "A cron entry can't contain line breaks.", None
    schedule = " ".join(schedule.split())   # normalise inner whitespace
    if not _CRON_SCHED_RE.match(schedule):
        return False, ("Invalid schedule — use 5 fields (min hour day month weekday) "
                       "or a @shortcut like @reboot / @daily / @hourly."), None
    return True, "", f"{schedule} {command}"


# ── Cron run-history: wrap user commands through a recorder so the panel can show each
# job's last-run time and success/error. The command runs via a tiny per-user script that
# writes "<rc> <start> <end>" to ~/.lgsm-cron/<id>.status and its output to <id>.log. The
# command is base64-encoded in the crontab line so nothing has to be escaped for cron
# (notably `%`, which cron treats specially) or the shell.
_CRON_RUNNER_SCRIPT = (
    "#!/bin/bash\n"
    "# LinuxGSM Panel cron wrapper — records a scheduled job's last-run time, exit code,\n"
    "# and (the tail of) its output so the panel can show success/error. Args: <id> <b64cmd>.\n"
    'D="$HOME/.lgsm-cron"; mkdir -p "$D"; chmod 700 "$D" 2>/dev/null\n'
    'ID="$1"; CMD="$(printf %s "$2" | base64 -d 2>/dev/null)"\n'
    'S=$(date +%s)\n'
    'bash -c "$CMD" > "$D/$ID.log" 2>&1\n'
    'R=$?\n'
    'printf "%s %s %s\\n" "$R" "$S" "$(date +%s)" > "$D/$ID.status"\n'
    "exit $R\n"
)
_CRON_WRAP_RE = re.compile(r"^/home/[^/\s]+/\.lgsm-cron/run\s+([0-9a-f]{6,})\s+([A-Za-z0-9+/=]+)\s*$")


def _cron_job_id(command):
    import hashlib
    return hashlib.sha256((command or "").encode("utf-8", "replace")).hexdigest()[:12]


def _install_cron_runner(server, user):
    """Install the per-user cron wrapper script (idempotent). Runs AS THE GAME USER (like the
    file manager) — never as root — so it can only ever touch that user's own home. Writing
    the runner as root could be redirected through a symlink a compromised game process
    planted in ~/.lgsm-cron; dropping to the user removes that escalation. Best-effort."""
    import base64
    b64 = base64.b64encode(_CRON_RUNNER_SCRIPT.encode()).decode()
    # Absolute path (not ~) — `sudo -u` doesn't reliably set $HOME, and the game user's home
    # is /home/<user> by construction (useradd -m). Cron itself sets $HOME correctly when it
    # later runs the script, so the runner's own $HOME use resolves to the same dir.
    d = "/home/%s/.lgsm-cron" % user
    inner = ('mkdir -p {d} && chmod 700 {d} && '
             'printf %s {b} | base64 -d > {d}/run && chmod 700 {d}/run'
             ).format(d=_quote(d), b=_quote(b64))
    run_command(server, f"sudo -u {user} bash -c {_quote(inner)}", timeout=15, sudo=False)


# A plain command — a path plus simple args, with no shell operators, quotes, or cron-special `%`. Such
# a command is safe to keep VISIBLE via the inline recorder, so the Autostart detection (which greps
# the raw crontab for `<base> monitor`) still finds it after the admin reschedules it here.
_SIMPLE_CMD_RE = re.compile(r"^[\w./ @:+=,-]+$")


def _wrap_cron_command(server, user, command):
    """Return the crontab command that records `command`'s runs. Toggle-backed and plain commands are
    kept VISIBLE (inline recorder) so the Autostart / daily-restart detection still works after a
    reschedule; anything with `%`, quotes, or shell operators uses the base64 runner (robust, no
    escaping needed)."""
    cmd = (command or "").strip()
    if ".restart-pending" in cmd:
        return cmd                              # daily-restart flag line: keep it verbatim + visible
    if _SIMPLE_CMD_RE.match(cmd):
        return _record_managed_cmd(user, cmd)   # plain command (incl. `<base> monitor`): visible + tracked
    import base64
    _install_cron_runner(server, user)
    b64 = base64.b64encode(cmd.encode()).decode()
    return "/home/%s/.lgsm-cron/run %s %s" % (user, _cron_job_id(cmd), b64)


# Inline recorder for the panel's OWN managed jobs (autostart/monitor/update/restart-flag).
# Unlike the base64 form, it keeps the command VISIBLE so the managed-line detection (which
# greps for `<base> monitor` etc.) still matches — panel commands carry no `%` for cron to
# mangle, so it's safe to write the status suffix inline.
_CRON_REC_RE = re.compile(
    r"^mkdir -p /home/[^/\s]+/\.lgsm-cron && (.+?) > "
    r"/home/[^/\s]+/\.lgsm-cron/([0-9a-f]{6,})\.log 2>&1; R=\$\?;")


def _record_managed_cmd(user, core):
    """Wrap a FIXED panel command so cron records its exit code + time + output, keeping the
    command itself readable in the crontab line. Pairs with _unwrap_cron_command /
    _read_cron_status. Panel-generated commands only (no user `%`)."""
    d = "/home/%s/.lgsm-cron" % user
    jid = _cron_job_id(core)
    # \% because cron treats % specially; mkdir keeps the status dir self-healing.
    return (f"mkdir -p {d} && {core} > {d}/{jid}.log 2>&1; "
            f"R=$?; T=$(date +\\%s); echo \"$R $T $T\" > {d}/{jid}.status")


def _unwrap_cron_command(command):
    """(original_command, job_id) if `command` is a panel-wrapped cron command (either the
    base64 recorder for user jobs or the inline recorder for managed jobs), else
    (command, None) so plain/legacy entries display and behave unchanged."""
    import base64
    c = (command or "").strip()
    m = _CRON_WRAP_RE.match(c)
    if m:
        try:
            return base64.b64decode(m.group(2)).decode("utf-8", "replace"), m.group(1)
        except Exception:
            return command, None
    m2 = _CRON_REC_RE.match(c)
    if m2:
        return m2.group(1).strip(), m2.group(2)
    return command, None


def _read_cron_status(server, user):
    """{job_id: {last_run(epoch), ok(bool), error(str), rc(int)}} from the recorder's status
    files for `user`. Runs AS THE GAME USER so reading a job's log can't be redirected through
    a symlink to a root-only file (info leak) — it only ever reads that user's own files. One
    shell round-trip; best-effort (empty on any error)."""
    d = "/home/%s/.lgsm-cron" % user
    inner = (f'cd {_quote(d)} 2>/dev/null || exit 0; '
             'for s in *.status; do [ -e "$s" ] || continue; id="${s%.status}"; '
             'read rc st en < "$s" 2>/dev/null; err=""; '
             '[ "$rc" != "0" ] && err="$(tail -n 3 "$id.log" 2>/dev/null | tr "\\n\\t" "  " | tail -c 240)"; '
             'printf "%s\\t%s\\t%s\\t%s\\t%s\\n" "$id" "$rc" "$st" "$en" "$err"; done')
    out, _, _ = run_command(server, f"sudo -u {user} bash -c {_quote(inner)}", timeout=12, sudo=False)
    status = {}
    for line in (out or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        jid, rc, en = parts[0], parts[1], parts[3]
        err = parts[4] if len(parts) > 4 else ""
        try:
            status[jid] = {"last_run": int(en), "ok": rc == "0", "rc": int(rc),
                           "error": err.strip()}
        except ValueError:
            continue
    return status


def _read_cron_run_times(server, user):
    """{command_string: last_run_epoch} from cron's OWN execution log (journald), so that
    panel-managed and legacy entries — which the recorder doesn't wrap — still show WHEN they
    last ran. Cron logs the command it ran but not its exit status, so this is time-only.
    Best-effort (empty if cron logging is off/unavailable)."""
    q = ("journalctl _COMM=cron --since '-14 days' -o short-unix --no-pager 2>/dev/null "
         f"| grep -F '({user}) CMD ' | tail -n 800")
    out, _, _ = run_command(server, q, timeout=12, sudo=True)
    times = {}
    for line in (out or "").splitlines():
        head = line.split(None, 1)
        if not head:
            continue
        try:
            epoch = int(float(head[0]))
        except ValueError:
            continue
        m = re.search(r"\)\s+CMD\s+\((.*)\)\s*$", line)
        if m:
            times[m.group(1).strip()] = epoch   # chronological log → last occurrence wins
    return times


def upgrade_managed_cron_tracking(server, user, selfname=None):
    """One-time, IN-PLACE upgrade: re-wrap existing panel-managed cron lines through the inline
    recorder so their runs start reporting success/error — without changing schedules, on/off
    state, or behaviour (each existing line is transformed, not re-derived from state, so it
    can't accidentally toggle anything). Only the simple managed commands are wrapped; the
    compound restart-when-empty check is left alone. No-op once everything is wrapped. Returns
    True if it changed anything. Best-effort."""
    selfname = selfname or user
    base = f"/home/{user}/{selfname}"
    flag = f"/home/{user}/.restart-pending"
    simple_cores = {f"{base} {c}" for c in ("start", "monitor", "mods-update", "update", "update-lgsm")}
    simple_cores.add(f"touch {flag}")
    suffix = " > /dev/null 2>&1"
    out, _, _ = run_command(server, f"crontab -u {user} -l 2>/dev/null", timeout=10, sudo=True)
    new_lines, changed = [], False
    for raw in (out or "").splitlines():
        s = raw.strip()
        sched, cmd = (None, None) if (not s or s.startswith("#")) else _split_cron_line(s)
        if sched is None:
            new_lines.append(raw)
            continue
        _disp, jid = _unwrap_cron_command(cmd)
        core = cmd[:-len(suffix)].strip() if cmd.endswith(suffix) else cmd
        if jid is None and core in simple_cores:   # unwrapped simple managed line → wrap it
            new_lines.append(f"{sched} {_record_managed_cmd(user, core)}")
            changed = True
        else:
            new_lines.append(raw)
    if not changed:
        return False
    # Replace the whole crontab: drop everything (grep -vE '^' matches every line), re-add ours.
    ok, _ = _rewrite_crontab(server, user, "-vE '^'", new_lines)
    return ok


def _match_run_time(run_times, cmd):
    """Last-run epoch for `cmd` from the cron-log map. Exact match first; then substring, so a
    wrapped job's CORE command (e.g. `<base> monitor`) still matches its logged line whether it
    was the old `… > /dev/null 2>&1` form or the new recorder form. Newest match wins."""
    if not cmd:
        return None
    if cmd in run_times:
        return run_times[cmd]
    best = None
    for logged, epoch in run_times.items():
        if cmd in logged and (best is None or epoch > best):
            best = epoch
    return best


def list_cron_jobs(server, user, selfname=None):
    """Read the game user's crontab as a list of jobs. Comment/blank lines are
    skipped. Each job: {raw, schedule, command, managed, last_run, ok, error}. `raw` is the
    exact line (identity for edit/delete); `command` is the un-wrapped, human-readable form.
    Run history comes from the recorder for user-added jobs (time + ok/error) and from cron's
    own log for managed/legacy jobs (time only — ok stays None, cron doesn't log exit status)."""
    selfname = selfname or user
    out, _, _ = run_command(server, f"crontab -u {user} -l 2>/dev/null", timeout=10, sudo=True)
    status = _read_cron_status(server, user)
    run_times = _read_cron_run_times(server, user)
    jobs = []
    for raw in (out or "").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        sched, cmd = _split_cron_line(s)
        if sched is None:
            continue
        display_cmd, jid = _unwrap_cron_command(cmd)
        # Status is keyed by the wrapped id, or — so an on-demand "Run now" updates the row even
        # for an unwrapped job — the hash of the (display) command.
        st = status.get(jid or _cron_job_id(display_cmd))
        if st:                       # wrapped job that has RUN → full status from the recorder
            last_run, ok, error = st.get("last_run"), st.get("ok"), st.get("error", "")
        else:
            # No recorder status yet (unwrapped job, or a freshly-wrapped one that hasn't run in
            # the new form). Show the last-run TIME from cron's own log so it never regresses to
            # "—"; the core command matches both the old redirect form and the wrapped form.
            last_run, ok, error = _match_run_time(run_times, display_cmd or cmd), None, ""
        jobs.append({
            "raw": raw, "schedule": sched, "command": display_cmd,
            "managed": _cron_line_managed(s, user, selfname),   # always False now — every line is editable
            "role": _cron_role(display_cmd, user, selfname),    # informational label only (autostart/daily-restart)
            "last_run": last_run, "ok": ok, "error": error,
        })
    return jobs


def run_cron_job_now(server, user, raw, selfname=None):
    """Run a cron job's command NOW, DETACHED, as the game user — recording its exit code +
    output to the same status/log files a scheduled run uses, so the Last-run column updates
    (even for a slow job like `update`, which the detach keeps from hanging the request). The
    command is taken from the crontab line `raw` and un-wrapped to its core first. Best-effort;
    returns (ok, message)."""
    import base64
    _sched, cmd = _split_cron_line((raw or "").strip())
    core, jid = _unwrap_cron_command(cmd if cmd is not None else (raw or "").strip())
    core = (core or "").strip()
    if not core:
        return False, "Nothing to run."
    d = "/home/%s/.lgsm-cron" % user
    jid = jid or _cron_job_id(core)
    rec = (f"{core} > {d}/{jid}.log 2>&1; R=$?; T=$(date +%s); "
           f'echo "$R $T $T" > {d}/{jid}.status')
    b64 = base64.b64encode(rec.encode()).decode()
    # setsid detaches the run so a long command records its result later instead of blocking;
    # `sudo -u` confines it to the game user's own privileges (same as a scheduled run).
    inner = f"mkdir -p {d}; echo {b64} | base64 -d | setsid bash >/dev/null 2>&1 &"
    run_command(server, f"sudo -u {user} bash -c {_quote(inner)}", timeout=15, sudo=False)
    return True, "Started — the result will appear under Last run shortly."


def add_cron_job(server, user, schedule, command, selfname=None):
    """Append a new cron entry to the game user's crontab (keeps all existing lines). The
    command is wrapped through the recorder so its runs are tracked."""
    ok, msg, _line = _validate_cron(schedule, command)
    if not ok:
        return False, msg
    schedule = " ".join(schedule.split())
    wrapped = _wrap_cron_command(server, user, command)
    return _rewrite_crontab(server, user, "", [f"{schedule} {wrapped}"])


def update_cron_job(server, user, old_raw, schedule, command, selfname=None):
    """Replace an existing user cron entry (matched exactly by `old_raw`) with a new
    schedule+command. Refuses to touch a panel-managed line."""
    selfname = selfname or user
    old_raw = old_raw or ""
    if _cron_line_managed(old_raw, user, selfname):
        return False, "That entry is managed by the panel — use its own toggle to change it."
    ok, msg, _line = _validate_cron(schedule, command)
    if not ok:
        return False, msg
    schedule = " ".join(schedule.split())
    wrapped = _wrap_cron_command(server, user, command)
    # -vxF: drop the line that exactly (whole-line, fixed-string) matches old_raw,
    # keep everything else, then append the rewritten (recorder-wrapped) entry.
    return _rewrite_crontab(server, user, f"-vxF {_quote(old_raw)}", [f"{schedule} {wrapped}"])


def delete_cron_job(server, user, old_raw, selfname=None):
    """Remove a user cron entry (matched exactly by `old_raw`). Refuses to remove a
    panel-managed line."""
    selfname = selfname or user
    old_raw = old_raw or ""
    if _cron_line_managed(old_raw, user, selfname):
        return False, "That entry is managed by the panel — use its own toggle to change it."
    return _rewrite_crontab(server, user, f"-vxF {_quote(old_raw)}", [])


def list_game_backups(server, user):
    """A game server's LinuxGSM backups (~/lgsm/backup/*.tar.*): [{name, size, created}],
    newest first. Read as the game user; best-effort (empty on error). LinuxGSM compresses with
    zstd when available (.tar.zst), else gzip (.tar.gz) — match all archive types like LinuxGSM's
    own tooling does, not just .tar.gz."""
    bdir = "/home/%s/lgsm/backup" % user
    # Also report the backup.lock's start time (LinuxGSM holds it only while a backup runs, and
    # writes the archive under its final name while it's still growing). We report the lock's mtime
    # (= backup start) so we can flag ONLY an archive written AFTER the backup began as in-progress —
    # not a pre-existing backup that merely happens to be the newest. Bound to the last 60 min so a
    # stale lock from a crash doesn't hide a real backup forever.
    cmd = ('for f in %s/*.tar.*; do [ -e "$f" ] || continue; '
           'printf "F\\t%%s\\t%%s\\t%%s\\n" "$(basename "$f")" "$(stat -c%%s "$f")" "$(stat -c%%Y "$f")"; '
           'done; '
           'find /home/%s -maxdepth 4 -name "*backup.lock" -mmin -60 -printf "LOCK\\t%%T@\\n" '
           '2>/dev/null | head -1') % (bdir, user)
    out, _, _ = run_command(server, f"sudo -u {user} bash -c {_quote(cmd)}", timeout=20, sudo=False)
    res = []
    lock_mtime = None
    for line in (out or "").splitlines():
        parts = line.split("\t")
        if parts[0] == "LOCK":
            try:
                lock_mtime = int(float(parts[1]))
            except (ValueError, IndexError):
                lock_mtime = 0   # lock exists but its mtime is unreadable — see below
            continue
        if len(parts) >= 4 and parts[0] == "F":
            try:
                res.append({"name": parts[1], "size": int(parts[2]), "created": int(parts[3])})
            except ValueError:
                continue
    res.sort(key=lambda b: b["created"], reverse=True)
    # Only the archive being written NOW is in-progress: a backup is running (lock present) AND the
    # newest file was created at/after the backup started (2s slack for clock granularity). A backup
    # that existed before the run keeps showing. lock_mtime==0 means "lock present, time unknown" —
    # fall back to flagging the newest so a partial can't masquerade as complete.
    if lock_mtime is not None and res:
        if lock_mtime == 0 or res[0]["created"] >= lock_mtime - 2:
            res[0]["in_progress"] = True
    return res


def prune_game_backups(server, user, keep=3):
    """Keep only the newest `keep` LinuxGSM backups for a game server; delete the rest.
    Matches every archive type LinuxGSM produces (.tar.zst / .tar.gz / …), not just .tar.gz —
    otherwise large zstd backups would never be pruned and could fill the disk."""
    bdir = "/home/%s/lgsm/backup" % user
    keep = max(1, int(keep))
    cmd = "ls -1t %s/*.tar.* 2>/dev/null | tail -n +%d | xargs -r rm -f" % (bdir, keep + 1)
    run_command(server, f"sudo -u {user} bash -c {_quote(cmd)}", timeout=30, sudo=False)


def _fmt_size(nbytes):
    """Human-readable size (e.g. '1.2 GB', '640 MB') for backup/disk messages."""
    n = float(nbytes or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d %s" % (n, unit)) if unit in ("B", "KB") else ("%.1f %s" % (n, unit))
        n /= 1024
    return "%d B" % (nbytes or 0)


def backup_disk_info(server, user):
    """Free/total bytes of the filesystem that holds this game user's LinuxGSM backups
    (~/lgsm/backup lives under the home dir). Best-effort — returns zeros on error."""
    out, _, _ = run_command(server, "df -PB1 %s" % _quote("/home/%s" % user), timeout=15, sudo=False)
    lines = [ln for ln in (out or "").splitlines() if ln.strip()]
    if len(lines) >= 2:
        parts = lines[-1].split()
        if len(parts) >= 4:
            try:
                return {"free": int(parts[3]), "total": int(parts[1])}
            except ValueError:
                pass
    return {"free": 0, "total": 0}


# Game-backup file names are "<selfname>-YYYY-MM-DD-HHMMSS.tar.<ext>" — a strict shape we
# require before ever touching a path (callers ALSO check the name is in the real backup list).
_GAME_BACKUP_NAME = re.compile(r"^[A-Za-z0-9._-]+\.tar\.[A-Za-z0-9.]+$")


def delete_game_backup(server, user, name):
    """Delete one game backup by file name from ~/lgsm/backup/, as the game user. Returns True on
    success. `name` is shape-validated here; the caller validates it against the actual listing."""
    if not _GAME_BACKUP_NAME.match(name or ""):
        return False
    path = "/home/%s/lgsm/backup/%s" % (user, name)
    _, _, rc = run_command(server, f"sudo -u {user} rm -f -- {_quote(path)}", timeout=30, sudo=False)
    return rc == 0


def stream_game_backup(server, user, name, chunk=262144):
    """Yield the bytes of ~/lgsm/backup/<name> as the game user, for a browser download. Works for
    local, paramiko and Tailscale-CLI remotes. `name` MUST already be validated by the caller
    (checked against the real backup list); we also re-check its shape here. Uses the (green,
    eventlet-patched) subprocess/paramiko IO so a multi-GB download doesn't block the event hub."""
    if not _GAME_BACKUP_NAME.match(name or ""):
        return
    path = "/home/%s/lgsm/backup/%s" % (user, name)

    if is_local_server(server) or getattr(server, "auth_method", "") == "tailscale":
        if is_local_server(server):
            argv = ["sudo", "-u", user, "cat", path]
        else:
            host = _resolve_ts_host(server)
            argv = ["ssh", "-T", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
                    "-p", str(server.port or 22), f"{server.username}@{host}",
                    f"sudo -u {user} cat {_quote(path)}"]
        p = subprocess.Popen(argv, stdout=subprocess.PIPE)
        try:
            while True:
                b = p.stdout.read(chunk)
                if not b:
                    break
                yield b
        finally:
            try:
                p.stdout.close()
            except Exception:  # nosec B110
                pass
            p.wait()
        return

    # paramiko remote
    client = get_connection(server)
    _in, out, _err = client.exec_command(f"sudo -u {user} cat {_quote(path)}")
    while True:
        b = out.read(chunk)
        if not b:
            break
        yield b


def _ensure_backup_headroom(server, user, keep):
    """Make room for a new backup on a tight disk by deleting the OLDEST backups first (keeping the
    newest keep-1), so a nearly-full host can still take a fresh backup instead of LinuxGSM aborting
    on "not enough disk space". Normally backups prune AFTER the run (peak = keep+1); this only
    kicks in when free disk is below ~1.15× the expected new-backup size. Returns a short note."""
    try:
        backups = list_game_backups(server, user)   # newest first
        if not backups:
            return ""   # first backup — nothing to prune; let LinuxGSM/disk decide
        # Estimate the next backup from the LARGEST existing one (worst case), ignoring 0-byte
        # failed archives — the newest can be tiny or empty and badly underestimate the need.
        est = max((b.get("size", 0) for b in backups), default=0)
        free = backup_disk_info(server, user).get("free", 0)
        if not est or free >= int(est * 1.15):
            return ""   # plenty of room — keep full safety (old backup survives if the new fails)
        # 0-byte archives are failed backups (junk) — delete them first and never protect one.
        # Protect the newest keep-1 VALID backups; delete the oldest valid ones beyond that.
        valid = [b for b in backups if b.get("size", 0) > 0]        # newest first
        junk = [b for b in backups if b.get("size", 0) == 0]
        keep_newest = max(1, int(keep) - 1)
        candidates = junk + list(reversed(valid[keep_newest:]))     # junk first, then oldest valid
        deleted = 0
        for b in candidates:
            if delete_game_backup(server, user, b["name"]):
                free += b.get("size", 0)
                deleted += 1
            if free >= int(est * 1.15):
                break
        if deleted:
            _log.info("freed disk before backing up %s: removed %d old backup(s)", user, deleted)
            return "freed space first (removed %d old backup%s)" % (deleted, "" if deleted == 1 else "s")
    except Exception:
        _log.debug("backup headroom check failed", exc_info=True)
    return ""


def _gamedig_type(game_type, query_type=None):
    """The gamedig `--type` to use for a server: an explicit per-server override when set (the
    panel's GAMEDIG_TYPE map is only a default and can be wrong/missing, e.g. cod), else the map.
    The override is sanitised to a safe charset here too, so it can never break out of the query
    command regardless of upstream validation. Returns '' when the game isn't queryable."""
    qt = re.sub(r"[^a-z0-9_-]", "", (query_type or "").strip().lower())[:40]
    return qt or GAMEDIG_TYPE.get(game_type or "", "")


def player_count(server, user, game_type=None, port=None, query_type=None):
    """Best-effort CURRENT player count for a running instance, via gamedig (the same
    tool the empty-only daily restart uses). Returns an int, or None when the game
    isn't queryable (no gamedig type / no port) or the query fails — callers treat
    None as 'unknown' and don't block on it. gamedig is a bare command on PATH exactly
    as the restart cron invokes it (installed globally via npm at setup)."""
    gdtype = _gamedig_type(game_type, query_type)
    if not gdtype or not port:
        return None
    cmd = f"gamedig --type {gdtype} {_gamedig_host(server)}:{int(port)} 2>/dev/null | jq -r '.players|length' 2>/dev/null"
    try:
        out, _, _ = run_command(server, f"sudo -u {user} bash -c {_quote(cmd)}", timeout=25, sudo=False)
    except Exception:
        return None
    s = (out or "").strip().splitlines()[-1].strip() if (out or "").strip() else ""
    if not s or s == "null" or not s.isdigit():
        return None
    return int(s)


def player_slots(server, user, game_type=None, port=None, query_type=None):
    """(current, max, name) from a SINGLE gamedig query: player count, the capacity the game reports
    (or None), and the server's own advertised in-game name/hostname (what players see in the server
    browser, or None). (None, None, None) when the game isn't gamedig-queryable or the query fails,
    so the caller can fall back to the console / LinuxGSM config. Never raises."""
    import json
    gdtype = _gamedig_type(game_type, query_type)
    if not gdtype or not port:
        return None, None, None
    # One query -> compact JSON {c:count, m:maxplayers, n:name, ok:<did it actually respond?>}. `ok`
    # (players is an array) distinguishes a real reply from gamedig's {"error":...} — otherwise a
    # FAILED query reads as "0 players", which both shows a bogus 0 and blocks the console fallback.
    # JSON escaping lets a server name with any character round-trip safely.
    jqf = '{c:(.players|length), m:.maxplayers, n:(.name // ""), ok:(.players|type=="array")}'
    cmd = (f"gamedig --type {gdtype} {_gamedig_host(server)}:{int(port)} 2>/dev/null "
           f"| jq -c {_quote(jqf)} 2>/dev/null")
    try:
        out, _, _ = run_command(server, f"sudo -u {user} bash -c {_quote(cmd)}", timeout=25, sudo=False)
    except Exception:
        return None, None, None
    line = (out or "").strip().splitlines()[-1].strip() if (out or "").strip() else ""
    if not line:
        return None, None, None
    try:
        d = json.loads(line)
    except (ValueError, TypeError):
        return None, None, None
    if not (isinstance(d, dict) and d.get("ok")):
        return None, None, None   # gamedig couldn't read the server (error / no A2S response) -> unknown
    cur = d.get("c") if isinstance(d.get("c"), int) else None
    mx = d.get("m") if isinstance(d.get("m"), int) else None
    nm = d.get("n")
    nm = (" ".join(str(nm).split())[:120] or None) if nm else None
    return cur, mx, nm


_game_map_cache = {}          # {(remote_id, port): (expiry_ts, mapname)}
_GAME_MAP_TTL = 30


def game_map(server, user, game_type=None, port=None, query_type=None):
    """The map/level a gamedig-queryable server is currently running, or "" if unknown/unqueryable.
    A separate, cached (~30s — maps change rarely) gamedig read, kept OUT of the player-count path so
    it can't perturb the counts. Never raises."""
    gdtype = _gamedig_type(game_type, query_type)
    if not gdtype or not port:
        return ""
    key = (getattr(server, "id", None), int(port))
    now = time.time()
    hit = _game_map_cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    cmd = (f"gamedig --type {gdtype} {_gamedig_host(server)}:{int(port)} 2>/dev/null "
           f"| jq -r '.map // \"\"' 2>/dev/null")
    val = ""
    try:
        out, _, _ = run_command(server, f"sudo -u {user} bash -c {_quote(cmd)}", timeout=25, sudo=False)
        s = (out or "").strip().splitlines()[-1].strip() if (out or "").strip() else ""
        # game-supplied text -> collapse whitespace and drop angle brackets (it's rendered as HTML)
        val = "" if s in ("", "null") else " ".join(s.split()).replace("<", "").replace(">", "")[:40]
    except Exception:
        val = ""
    _game_map_cache[key] = (now + _GAME_MAP_TTL, val)
    return val

def player_count_via_lgsm_query(server, user, selfname, fallback_port=None):
    """Player count using the game's OWN LinuxGSM query settings — this covers games the panel's
    26-entry gamedig map doesn't. Reads querymode/querytype/queryport from the merged LinuxGSM
    config and, when LinuxGSM queries the game with gamedig (querymode 2), runs gamedig with
    LinuxGSM's own type. `fallback_port` (the port the panel already knows) is used when the query
    port isn't in the LinuxGSM .cfg — e.g. Minecraft keeps it in server.properties. Returns int, or
    None when LinuxGSM has no usable network query for the game (querymode 1 = process-check only,
    e.g. Factorio; querymode 3 = the legacy gsquery, not parsed here yet) or the query fails. None =>
    'unknown', which the reboot poller treats as 'don't reboot'. querytype is charset-sanitised and
    the port is an int, so nothing user/config-supplied reaches the shell unchecked."""
    try:
        vals = lgsm_get_values(server, user, selfname, ["querymode", "querytype", "queryport", "port"])
    except Exception:
        return None
    if (vals.get("querymode") or "").strip() != "2":   # only the gamedig querymode is handled here
        return None
    qtype = re.sub(r"[^A-Za-z0-9_-]", "", (vals.get("querytype") or "").strip())[:40]
    qport = ((vals.get("queryport") or "").strip() or (vals.get("port") or "").strip()
             or str(fallback_port or "").strip())
    if not qtype or not qport.isdigit():
        return None
    cmd = ("gamedig --type %s %s:%d 2>/dev/null | jq -r '.players|length' 2>/dev/null"
           % (qtype, _gamedig_host(server), int(qport)))
    try:
        out, _, _ = run_command(server, "sudo -u %s bash -c %s" % (user, _quote(cmd)), timeout=25, sudo=False)
    except Exception:
        return None
    s = (out or "").strip().splitlines()[-1].strip() if (out or "").strip() else ""
    return int(s) if s.isdigit() else None


# ── Engine families ──────────────────────────────────────────────────────────
# Moderation (kick/ban/say) and the way we read a player list are per game ENGINE, not per game, so
# one classifier covers every LinuxGSM game of a family instead of a per-game table. Source and
# GoldSrc share the SAME console syntax (`status`, `kick "<name>"`, `banid`, `say`) and both print
# SteamIDs in `status`, so they're one "valve" family here. Anything not classified has no console
# moderation — its player list still shows via gamedig where available, just with no kick/ban/say.
_ENG_VALVE = frozenset({
    # Source
    "gmod", "css", "cs2", "csgo", "tf2", "hl2dm", "hl2mp", "dods", "l4d", "l4d2",
    "ins", "insurgency", "nmrih", "zps", "fof", "gesource", "bb2", "ship", "doi", "nd", "bm",
    # GoldSrc
    "cs", "cscz", "tfc", "dmc", "ns", "ricochet", "hldm", "hldms", "ahl", "sfc", "dod", "og", "ag",
})
_ENG_IDTECH3 = frozenset({           # Quake3 / idTech3 — `status` gives slot numbers, kick/ban by slot
    "cod", "coduo", "cod2", "cod4", "codwaw", "q3", "quakelive", "et", "etl", "rtcw", "wet", "jamp",
})
_ENG_MINECRAFT = frozenset({         # Minecraft — `list` gives names, kick/ban by name
    "mc", "pmc", "spigot", "paper", "bukkit", "forge", "fabric", "purpur", "mcbe", "mcb", "pocketmine",
})


def game_engine(game_type):
    """The moderation/query engine family for a LinuxGSM game: 'valve', 'idtech3', 'minecraft',
    or '' when the game has no console-based moderation the panel understands."""
    gt = (game_type or "").lower()
    if gt in _ENG_VALVE:
        return "valve"
    if gt in _ENG_IDTECH3:
        return "idtech3"
    if gt in _ENG_MINECRAFT:
        return "minecraft"
    return ""


# A Steam ID in either legacy (STEAM_0:1:2) or modern ([U:1:5]) form — the only shape we accept as a
# ban target, so a hostile name in a `status` line can never smuggle anything else into `banid`.
_STEAMID_RE = re.compile(r"STEAM_[0-9]:[0-9]:[0-9]+|\[U:[0-9]:[0-9]+\]")


def _strip_q3_colors(s):
    return re.sub(r"\^[0-9]", "", s or "")


def _int_or_none(s):
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return None


def _sanitize_steamid(s):
    m = _STEAMID_RE.search(str(s or ""))
    return m.group(0) if m else ""


def _sanitize_slotnum(s):
    n = _int_or_none(s)
    return n if (n is not None and 0 <= n <= 128) else None


def capture_console(server, user, selfname=None, lines=180):
    """Read-only snapshot of the last `lines` of a LinuxGSM instance's live tmux console. Used to
    read a `status`/`list` reply back. rc 3 + NO_SESSION when the server isn't running."""
    selfname = selfname or user
    inner = _tmux_live_socket_sh(selfname) + f'tmux -L "$SOCK" capture-pane -p -t {selfname} -S -{int(lines)}'
    cmd = f"sudo -u {user} bash -c {_quote(inner)}"
    return run_command(server, cmd, timeout=15, sudo=False)


def _parse_valve_status(text):
    """Parse a Source/GoldSrc `status` reply into [{name, steamid, num, score, time}]. Player rows
    start with '#' and carry a quoted name + a STEAM_/[U:..] id; bots have no id. Only the MOST
    RECENT table is used (rows after the last 'uniqueid' header), so players who left don't linger."""
    lines = (text or "").splitlines()
    start = 0
    for i, ln in enumerate(lines):
        if "uniqueid" in ln.lower():
            start = i + 1
    players, seen = [], set()
    for ln in lines[start:]:
        # A real player row is '#<userid> "<name>" …'. Requiring the leading '#' + number rejects the
        # '# userid name uniqueid' header AND stray chat/console lines that merely contain quotes.
        m = re.match(r'\s*#\s*\d+\s+"([^"]*)"', ln)
        if not m:
            continue
        name = m.group(1).strip()
        if not name:
            continue
        steamid = _sanitize_steamid(ln)
        key = (name, steamid)
        if key in seen:
            continue
        seen.add(key)
        players.append({"name": name[:64], "steamid": steamid, "num": None,
                        "score": None, "time": None})
    return players


def _parse_idtech3_status(text):
    """Parse a Quake3/CoD `status` reply into [{name, num, guid, steamid, score, time}]. Rows are
    'num score ping guid name … address …'; the name can contain spaces + ^-colour codes. Only the
    most recent table (rows after the last 'num…score…ping' header) is kept."""
    lines = (text or "").splitlines()
    start = 0
    for i, ln in enumerate(lines):
        low = ln.lower()
        if "num" in low and "score" in low and "ping" in low:
            start = i + 1
    players, seen = [], set()
    for ln in lines[start:]:
        # Preferred: name is everything between the guid and the trailing 'lastmsg address' columns.
        m = re.match(r"\s*(\d+)\s+(-?\d+)\s+(\d+)\s+(\S+)\s+(.+?)\s+\d+\s+\d{1,3}(?:\.\d{1,3}){3}:\d+", ln)
        if not m:
            # Fallback for formats without an address column: num score ping guid name(rest).
            m = re.match(r"\s*(\d+)\s+(-?\d+)\s+(\d+)\s+([0-9A-Fa-f]{6,})\s+(.+)$", ln)
            if not m:
                continue
        num = _int_or_none(m.group(1))
        if num is None or num in seen:
            continue
        name = _strip_q3_colors(m.group(5)).strip()
        if not name:
            continue
        seen.add(num)
        players.append({"name": name[:64], "num": num, "guid": m.group(4), "steamid": "",
                        "score": _int_or_none(m.group(2)), "time": None})
    return players


def _parse_minecraft_list(text):
    """Parse a Minecraft `list` reply ('There are N of M players online: Alice, Bob') into
    [{name, …}]. Splits on the last 'online:' so a log-line timestamp prefix can't confuse it."""
    line = ""
    for ln in (text or "").splitlines():
        if "online:" in ln.lower():
            line = ln
    idx = line.lower().rfind("online:")
    if idx == -1:
        return []
    after = line[idx + len("online:"):]
    players, seen = [], set()
    for chunk in after.split(","):
        nm = re.sub(r"[^A-Za-z0-9_]", "", chunk)[:32]
        if nm and nm not in seen:
            seen.add(nm)
            players.append({"name": nm, "steamid": "", "num": None, "score": None, "time": None})
    return players


def console_player_list(server, user, game_type, selfname=None):
    """Player list from the game's OWN console — the only source that yields the identifiers needed
    to kick/ban precisely (SteamIDs for valve, slot numbers for idTech3). Sends the list command,
    then captures + parses the pane. Returns a list (possibly empty), or None for a non-console
    game. Never raises."""
    eng = game_engine(game_type)
    if not eng:
        return None
    cmd = "list" if eng == "minecraft" else "status"
    try:
        send_console_command(server, user, cmd, timeout=12, selfname=selfname)
        time.sleep(0.8)   # let the server print its reply into the pane before we capture it
        out, _, rc = capture_console(server, user, selfname=selfname, lines=180)
    except Exception:
        return []
    if rc != 0 or not out:
        return []
    if eng == "idtech3":
        return _parse_idtech3_status(out)
    if eng == "minecraft":
        return _parse_minecraft_list(out)
    return _parse_valve_status(out)


_HOSTNAME_RE = re.compile(r"^\s*(?:hostname|sv_hostname)\s*:?\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)


def console_status(server, user, game_type, selfname=None):
    """One console `status`/`list` capture → (players, name): the parsed player list AND the server's
    advertised in-game name (the valve/idTech3 `hostname:` line), from a SINGLE round-trip. Used by
    the background poller so a server gamedig can't query (e.g. no GSLT) isn't hit with two separate
    `status` sends per pass — which would spam the very console an admin is watching. Returns
    ([], None) for a non-console game or on failure. Never raises."""
    eng = game_engine(game_type)
    if not eng:
        return [], None
    cmd = "list" if eng == "minecraft" else "status"
    try:
        send_console_command(server, user, cmd, timeout=12, selfname=selfname)
        time.sleep(0.8)   # let the server print its reply into the pane
        out, _, rc = capture_console(server, user, selfname=selfname, lines=180)
    except Exception:
        return [], None
    if rc != 0 or not out:
        return [], None
    if eng == "idtech3":
        players = _parse_idtech3_status(out)
    elif eng == "minecraft":
        players = _parse_minecraft_list(out)
    else:
        players = _parse_valve_status(out)
    name = None
    if eng in ("valve", "idtech3"):
        m = _HOSTNAME_RE.search(out)
        if m:
            name = " ".join(_strip_q3_colors(m.group(1)).split())[:120] or None
    return players, name


def _gamedig_player_list(server, user, game_type=None, port=None, query_type=None):
    """Player list via gamedig — the PRIMARY source. Returns a list ([{name, …}], possibly empty
    for a confirmed-empty server) when gamedig could query the game, or None when it couldn't (no
    gamedig type, no port, or the query failed) so the caller can fall back to the console. Never
    raises. Names carry score/time where the game reports them; no kick/ban ids (those come from the
    console on demand)."""
    gdtype = _gamedig_type(game_type, query_type)
    if not gdtype or not port:
        return None
    # Player fields are protocol-specific in gamedig: Source/valve exposes score + time (seconds
    # connected); Quake3/idTech3 (cod) exposes `frags` and no time. Pull score from score OR frags
    # so cod shows a score too; time stays null where the game doesn't report it.
    jqf = ('[.players[] | {name:(.name // ""), '
           'score:(.raw.score // .score // .raw.frags // .frags // null), '
           'time:(.raw.time // .time // null)}]')
    cmd = f"gamedig --type {gdtype} {_gamedig_host(server)}:{int(port)} 2>/dev/null | jq -c {_quote(jqf)} 2>/dev/null"
    try:
        out, _, _ = run_command(server, f"sudo -u {user} bash -c {_quote(cmd)}", timeout=25, sudo=False)
    except Exception:
        return None
    line = next((ln.strip() for ln in (out or "").splitlines() if ln.strip().startswith("[")), "")
    if not line:
        return None
    try:
        import json as _json
        data = _json.loads(line)
    except (ValueError, TypeError):
        return None
    players = []
    for p in (data if isinstance(data, list) else []):
        if isinstance(p, dict):
            name = str(p.get("name") or "").strip()
            if name:
                players.append({"name": name[:64], "steamid": "", "num": None,
                                "score": p.get("score"), "time": p.get("time")})
    return players


def player_list(server, user, game_type=None, port=None, query_type=None, selfname=None,
                allow_console=False):
    """Connected players for the Players panel. gamedig is the PRIMARY source (names + score/time,
    and it never touches the game console). The game's own console (`status`/`list`) is only used
    when gamedig can't query the game AND the caller explicitly opts in with allow_console=True —
    so a background/timer poll never issues a console command; only an on-demand user action does.
    Returns [{name, steamid, num, score, time}] (steamid/num set only when the list came from the
    console), an empty list for a confirmed-empty server, or None when it can't be read over the
    network and the console wasn't allowed. Never raises."""
    pl = _gamedig_player_list(server, user, game_type, port, query_type)
    if pl is not None:
        return pl                       # gamedig answered (players, or a confirmed-empty server)
    if allow_console and game_engine(game_type):   # explicit, on-demand console read only
        return console_player_list(server, user, game_type, selfname=selfname) or []
    return None                         # can't read over the network; console not requested


def is_player_queryable(game_type, query_type=None):
    """True if the panel can show a live player list: a console engine (valve/idTech3/Minecraft)
    or a gamedig type (built-in map or a per-server override)."""
    return bool(game_engine(game_type)) or bool(_gamedig_type(game_type, query_type))


def moderation_caps(game_type):
    """Which moderation actions this game's console supports: {kick, ban, say}. Driven by the engine
    family, so every game of a family is covered. Non-console games get nothing (view-only)."""
    if game_engine(game_type):      # valve, idtech3 and minecraft all support all three
        return {"kick": True, "ban": True, "say": True}
    return {"kick": False, "ban": False, "say": False}


# SECURITY: player names come FROM the game, so a hostile player can set a name containing console
# metacharacters. ';' chains commands (Source), quotes/backticks break arg parsing, and CR/LF would
# inject a whole new console line — strip them before the name/message goes into a console command.
_MOD_BAD_CHARS = str.maketrans({c: None for c in ';"`\r\n\t\x00'})


def _mod_sanitize(s, maxlen=64):
    return str(s or "").translate(_MOD_BAD_CHARS).strip()[:maxlen]


def _resolve_from_console(server, user, game_type, name, selfname):
    """Find a player by name in the game's console list and return their {name, num, steamid, …}.
    Used to resolve the kick/ban identifier (slot number / SteamID) when the list on screen came
    from gamedig, which doesn't carry those ids. Matches on the colour-code-stripped name; returns
    None if not found. Only runs when someone actually clicks kick/ban — no continuous polling."""
    want = _strip_q3_colors(name or "").strip()
    if not want:
        return None
    for p in (console_player_list(server, user, game_type, selfname=selfname) or []):
        if _strip_q3_colors(p.get("name") or "").strip() == want:
            return p
    return None


def moderate(server, user, game_type, action, target="", message="", selfname=None,
             steamid="", num=""):
    """Kick/ban a player or announce a message through the game's own console, dispatched by engine:
      • valve (Source/GoldSrc): kick by name, ban by SteamID, say
      • idTech3 (CoD/Quake3):   kick/ban by slot number, say
      • minecraft:              kick/ban by name, say
    Names/messages are sanitized (and the SteamID/slot re-validated) so a hostile name can't inject
    a console command. Returns (ok, msg)."""
    eng = game_engine(game_type)
    if action not in ("kick", "ban", "say") or not moderation_caps(game_type).get(action):
        return False, "That action isn't supported for this game."

    if action == "say":
        msg = _mod_sanitize(message, 200)
        if not msg:
            return False, "Nothing to announce."
        cmd = "say %s" % msg
    elif eng == "valve":
        if action == "kick":
            nm = _mod_sanitize(target, 64)
            if not nm:
                return False, "No player selected."
            cmd = 'kick "%s"' % nm
        else:
            sid = _sanitize_steamid(steamid)
            if not sid:      # list came from gamedig (no SteamID) — resolve it on the console now
                p = _resolve_from_console(server, user, game_type, target, selfname)
                sid = _sanitize_steamid(p.get("steamid")) if p else ""
            if not sid:
                return False, "Couldn't find that player's SteamID to ban them."
            # banid <0=permanent> <id> kick — the `kick` keyword boots them if they're connected
            # right now (banid without it only blocks future joins); writeid persists to the ban file.
            cmd = "banid 0 %s kick; writeid" % sid
    elif eng == "idtech3":
        slot = _sanitize_slotnum(num)
        if slot is None:     # list came from gamedig (no slot number) — resolve it on the console now
            p = _resolve_from_console(server, user, game_type, target, selfname)
            slot = _sanitize_slotnum(p.get("num")) if p else None
        if slot is None:
            return False, "Couldn't find that player on the server."
        cmd = "%s %d" % ("clientkick" if action == "kick" else "banclient", slot)
    elif eng == "minecraft":
        nm = _mod_sanitize(target, 64)
        if not nm:
            return False, "No player selected."
        cmd = "%s %s" % ("kick" if action == "kick" else "ban", nm)
    else:
        return False, "That action isn't supported for this game."

    out = send_console_command(server, user, cmd, timeout=15, selfname=selfname)
    rc = out[2] if isinstance(out, tuple) and len(out) >= 3 else 1
    return (rc == 0), ("Done." if rc == 0 else "Console not reachable — is the server running?")


def console_steamid_ban(server, user, selfname, steamid, unban=False):
    """Ban (or unban) a SteamID on ONE Source/GoldSrc server via its console — `banid 0 <id>; writeid`
    to ban, `removeid <id>; writeid` to lift, using the game's native persistent ban list. The
    SteamID is re-validated to STEAM_x:y:z / [U:x:y] so nothing injectable reaches the console.
    Only affects a RUNNING server (needs a live console). (ok, reason) where reason is a fixed word:
    'banned' / 'unbanned' / 'invalid' / 'offline' / 'failed'."""
    sid = _sanitize_steamid(steamid)
    if not sid:
        return False, "invalid"
    # the `kick` keyword boots a connected player too (banid alone only blocks future joins); unban lifts it
    cmd = ("removeid %s; writeid" % sid) if unban else ("banid 0 %s kick; writeid" % sid)
    out = send_console_command(server, user, cmd, timeout=15, selfname=selfname)
    rc = out[2] if isinstance(out, tuple) and len(out) >= 3 else 1
    if rc == 3:
        return False, "offline"
    return (rc == 0), ("unbanned" if unban and rc == 0 else "banned" if rc == 0 else "failed")


def ensure_persistent_bans(server, user, selfname):
    """Make a Source server RELOAD its ban list on every (re)start. `banid`/`writeid` persist a
    SteamID ban to cfg/banned_user.cfg, but the engine only loads that file if the server config
    execs it — without the exec line a ban is silently lost on the next map change / restart and the
    player can rejoin (exactly what bit us: a flapping server dropped every ban). Append the exec
    lines to the LinuxGSM servercfg (`${selfname}.cfg` in the game's cfg dir), idempotently. Best-
    effort; returns True when the line is present/added, False on any failure or non-Source layout."""
    try:
        raw = (lgsm_get_values(server, user, selfname, ["servercfg"]).get("servercfg") or "").strip()
        fname = (raw.replace("${selfname}", selfname).replace("$selfname", selfname)
                 or "%s.cfg" % selfname)
        if not re.match(r"^[A-Za-z0-9_.-]+\.cfg$", fname):     # guard the value going into `find`
            fname = "%s.cfg" % selfname
        inner = (
            f"F=$(find ~/serverfiles -maxdepth 4 -path '*/cfg/{fname}' 2>/dev/null | head -1); "
            '[ -z "$F" ] && exit 1; '
            'grep -qiE "^[[:space:]]*exec[[:space:]]+banned_user" "$F" && exit 0; '
            'printf "\\n// panel: load persistent bans on every (re)start\\n'
            'exec banned_user.cfg\\nexec banned_ip.cfg\\n" >> "$F"'
        )
        _, _, rc = run_command(server, f"sudo -u {user} bash -c {_quote(inner)}", timeout=15, sudo=False)
        return rc == 0
    except Exception:
        return False


def mod_restart_decision(status, players, force=False):
    """Decide how to handle the restart a mod change needs, given the server `status`
    ('online'/'offline'/'unknown'), the current player count (int, or None when unknown),
    and whether the admin forced it. Pure/side-effect-free so it can be tested directly:
      'idle'    — server is stopped; nothing to do (the change loads on next start)
      'restart' — restart now (server is confirmed empty, or the admin forced it)
      'pending' — defer: players are online, or we can't confirm it's empty."""
    if status == "offline":
        return "idle"
    if force:
        return "restart"
    if status == "online" and players == 0:
        return "restart"
    return "pending"


def run_game_backup(server, user, selfname=None, keep=3, game_type=None, port=None, force=False):
    """Run LinuxGSM's own `backup` for a game instance (archives serverfiles into
    ~/lgsm/backup/), then prune to the newest `keep`. Runs AS THE GAME USER, non-interactively
    (like a cron backup). Long-running — archives can be large.

    LinuxGSM's `backup` STOPS a running server for the duration, which disconnects
    anyone playing. So unless `force=True`, we first check the live player count and,
    if anyone is on, SKIP rather than kick them. Returns (ok, message, skipped):
      - (True, note, False)   backup completed
      - (False, reason, False) backup attempted but failed
      - (False, "N player(s) online …", True) skipped because players were connected
    An unknown/unqueryable player count (None) is treated as empty, so games gamedig
    can't query still back up on schedule (matching the daily-restart behaviour)."""
    selfname = selfname or user
    keep = max(1, int(keep))
    if not force:
        pc = player_count(server, user, game_type, port)
        if pc is not None and pc > 0:
            return (False,
                    f"{pc} player(s) online — backup skipped so nobody gets disconnected",
                    True)
    # Smart retention: if the disk is nearly full, delete old backups BEFORE creating the new one
    # so the backup succeeds instead of aborting for lack of space.
    headroom_note = _ensure_backup_headroom(server, user, keep)
    # Pre-flight space check: if there STILL isn't room for the archive after freeing what we can,
    # don't even start LinuxGSM's backup. A backup that runs out of space mid-write half-fills the
    # disk with a partial archive and can leave a stale lock behind — far worse than not starting.
    # We estimate the next archive from the largest existing one; with none to go by we let it try.
    try:
        _bks = list_game_backups(server, user)
        _est = max((b.get("size", 0) for b in _bks), default=0)
        _disk = backup_disk_info(server, user)
        _free, _total = _disk.get("free", 0), _disk.get("total", 0)
        # Only enforce when we actually read the disk (total > 0); a failed df reads as 0/0 and must
        # NOT block an otherwise-fine backup.
        if _est and _total and _free < int(_est * 1.05):
            note = " after clearing what old backups it could" if headroom_note else ""
            return (False,
                    f"Not enough disk space to back up{note}: the archive needs about "
                    f"{_fmt_size(int(_est * 1.05))} but only {_fmt_size(_free)} is free on the host. "
                    f"Lower this server's 'keep' count, remove old backups, or free space on the disk.",
                    False)
    except Exception:
        _log.debug("backup pre-flight space check failed", exc_info=True)
    # A crashed/killed/timed-out earlier backup can leave LinuxGSM's backup.lock behind, after
    # which every backup refuses with "Lockfile found: Backup is currently running". The panel
    # only ever runs one game backup at a time (serialised by a lock in app.py), so if we're here
    # and a backup.lock exists that hasn't been touched in >5 min, it's orphaned — delete it.
    # LinuxGSM writes the lock once at start and removes it on completion, so its mtime is the
    # backup's start time; a real, freshly-started backup (<5 min) is left untouched.
    precheck = (
        f"find /home/{user} -maxdepth 4 -name '*backup.lock' -mmin +5 -delete 2>/dev/null; "
    )
    # When the instance is running, LinuxGSM's `backup` warns + counts down, then STOPS the
    # server, archives it, and RESTARTS it (verified on a live box: ~1.5 min outage for a 6.5G
    # GMod install). It doesn't strictly need a y/N answer, but we feed a few harmless "y"s as a
    # safety net for any version that does prompt. The stream is bounded, so it can't hang.
    inner = precheck + f"cd /home/{user} && printf 'y\\ny\\ny\\n' | ./{selfname} backup"
    out, err, rc = run_command(server, f"sudo -u {user} bash -c {_quote(inner)}",
                               timeout=3600, sudo=False)
    ok = rc == 0
    # LinuxGSM can exit 0 while REFUSING to back up because a (possibly stale) lock exists —
    # "Lockfile found: Backup is currently running". No archive is created, so this is NOT a
    # success; reporting it as one is what makes the UI show "✓ Backed up" with no actual backup.
    _blob = ((out or "") + " " + (err or "")).lower()
    lock_refused = "lockfile found" in _blob or "backup is currently running" in _blob
    if lock_refused:
        ok = False
    try:
        prune_game_backups(server, user, keep)
    except Exception:
        _log.debug("game backup prune failed", exc_info=True)
    if ok:
        return True, ("Backed up — " + headroom_note if headroom_note else "Backed up"), False
    if lock_refused:
        return False, ("A backup lock was in the way — a previous backup may still be running, or it "
                       "left a stale lock. Try again in a minute."), False
    # Surface the most relevant LinuxGSM line so the panel can show WHY it failed.
    clean = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", ((out or "") + "\n" + (err or ""))).strip()
    reason = ""
    for line in reversed(clean.splitlines()):
        low = line.lower()
        if any(k in low for k in ("fail", "error", "unable", "no space", "not enough", "denied", "cannot")):
            reason = line.strip()
            break
    if not reason and clean.splitlines():
        reason = clean.splitlines()[-1].strip()
    return False, (reason or "backup failed")[-200:], False


def list_server_commands(server, user, selfname=None):
    """Run the LinuxGSM instance script with no arguments to read its command list,
    which varies per game. Returns a list of {"cmd", "short", "desc"} dicts."""
    selfname = selfname or user
    out, err, rc = run_command(
        server,
        f"sudo -u {user} bash -c {_quote(f'cd /home/{user} && ./{selfname}')}",
        timeout=30, sudo=False,
    )
    text = re.sub(r"\x1b\[[0-9;]*m", "", (out or "") + "\n" + (err or ""))
    cmds, seen = [], set()
    for line in text.splitlines():
        # "start         st   | Start the server."
        m = re.match(r"^\s*([a-z][a-z0-9-]*)\s+([a-z]{1,4})\s+\|\s+(.+?)\s*$", line)
        if m:
            cmd, short, desc = m.group(1), m.group(2), m.group(3)
            if cmd not in seen:
                seen.add(cmd)
                cmds.append({"cmd": cmd, "short": short, "desc": desc})
    return cmds


def detect_game_port(server, user, selfname=None):
    """Read a game server's ACTUAL port from LinuxGSM `details` (which reports the
    configured port, e.g. "Server IP: 0.0.0.0:27015"). The panel's stored port must
    match LinuxGSM's real port or status/firewall/connect are all wrong. Returns int
    or None."""
    out, _, _ = run_as_game_user(server, user, "details 2>&1", timeout=30, selfname=selfname)
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", out or "")
    for line in text.splitlines():
        if re.search(r"(server|internet)\s+ip:", line, re.I):
            m = re.search(r":(\d{2,5})\b", line)
            if m:
                return int(m.group(1))
    return None


# Port descriptions we DON'T open by default — only the ports players actually need
# to connect should be exposed. 'Client' is outbound (nothing listens). SourceTV is
# an optional spectator relay. RCON/telnet is remote admin and a security risk to
# expose to the internet (and on Source it rides the game port anyway). Users can
# still open any of these manually from the firewall page if they want them.
_NONESSENTIAL_PORT_DESCS = ("client", "sourcetv", "source tv", "rcon", "telnet")


def detect_game_ports(server, user, selfname=None):
    """Parse LinuxGSM `details` for a server's ports and decide which to open.

    We open only what a player needs to reach the server: the Game port and, if the
    game lists a separate Query port (for server-browser visibility). Optional/admin/
    outbound ports (SourceTV, RCON/telnet, Client) are deliberately left CLOSED — e.g.
    Garry's Mod lists Game 27015 + SourceTV 27020, but only 27015 is needed. Returns:
      {"game_port": int|None, "open_ports": [ports to open], "ports": [all parsed]}.
    """
    out, _, _ = run_as_game_user(server, user, "details 2>&1", timeout=45, selfname=selfname)
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", out or "")
    ports, game_port, in_table = [], None, False
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"DESCRIPTION\s+PORT\s+PROTOCOL", s, re.I):
            in_table = True
            continue
        if in_table:
            m = re.match(r"([A-Za-z][A-Za-z0-9/+ .-]*?)\s+(\d{2,5})\s+(tcp|udp|both|raw)\b", s, re.I)
            if m:
                desc, port, proto = m.group(1).strip(), int(m.group(2)), m.group(3).lower()
                ports.append({"desc": desc, "port": port, "protocol": proto})
                if game_port is None and desc.lower().startswith("game"):
                    game_port = port
            else:
                in_table = False  # blank/other line → table ended
    # Open only the essential inbound ports: Game + Query. Everything else (SourceTV,
    # RCON, Client, …) is left closed so we don't expose more than the game needs.
    open_ports = sorted({
        p["port"] for p in ports
        if not p["desc"].lower().startswith(_NONESSENTIAL_PORT_DESCS)
        and (p["desc"].lower().startswith(("game", "query")))
    })
    if game_port is None:
        m = re.search(r"(?:server|internet)\s+ip:.*?:(\d{2,5})", text, re.I)
        game_port = int(m.group(1)) if m else (open_ports[0] if open_ports else None)
    # Always ensure the game port itself is opened, even if the details table used an
    # unexpected description for it.
    if game_port and game_port not in open_ports:
        open_ports = sorted(set(open_ports) | {game_port})
    return {"game_port": game_port, "open_ports": open_ports, "ports": ports}


def get_server_status(server, game_server):
    """Get the status of a LinuxGSM game server.

    LinuxGSM has no `status` command; `details` prints a "Status: STARTED/STOPPED"
    line, so we run that and parse it."""
    out, err, rc = run_as_game_user(
        server, game_server.short_name, "details 2>&1", timeout=30,
        selfname=game_server.lgsm_name,
    )
    text = (out or "") + "\n" + (err or "")
    # Strip ANSI color codes, then read the "Status:" line specifically. (Scanning
    # the whole blob is unsafe: the details output includes a query-check URL
    # containing "ismygameserver.online", which collides with a naive "online" check.)
    clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
    for line in clean.splitlines():
        low = line.lower()
        if "status:" in low:
            if "started" in low:
                return "online"
            if "stopped" in low:
                return "offline"
    return "unknown"


# ─── Remote Firewall Management (UFW) ─────────────────────────


def _parse_ufw_rule(detail):
    """Parse one `ufw status numbered` rule line into structured fields, so the UI can
    show clean columns instead of the raw string. Handles the optional `on <iface>`
    clause, the `# comment` suffix, and the `(v6)` family markers."""
    v6 = "(v6)" in detail
    s = detail.replace("(v6)", " ")
    comment = ""
    if "#" in s:
        s, comment = s.split("#", 1)
        comment = comment.strip()
    iface = ""
    m = re.search(r"\bon\s+(\S+)", s)
    if m:
        iface = m.group(1)
        s = s[:m.start()] + s[m.end():]
    toks = s.split()
    action = direction = ""
    ai = None
    for a in ("ALLOW", "DENY", "REJECT", "LIMIT"):
        if a in toks:
            action = a
            ai = toks.index(a)
            break
    if ai is not None:
        to = " ".join(toks[:ai])
        rest = toks[ai + 1:]
        if rest and rest[0] in ("IN", "OUT", "FWD"):
            direction = rest[0]
            rest = rest[1:]
        frm = " ".join(rest)
    else:
        to = " ".join(toks)
        frm = ""
    return {
        "v6": v6, "to": to.strip(), "action": action, "direction": direction,
        "from": frm.strip(), "iface": iface, "comment": comment,
    }


def _group_ufw_rules(rules):
    """Collapse the raw numbered rules into user-friendly groups, merging the separate
    IPv4 and IPv6 entries UFW keeps for the same rule into a single row (with the list
    of underlying rule numbers so a group can be deleted as a unit)."""
    groups = []
    index = {}
    for r in rules:
        p = _parse_ufw_rule(r["detail"])
        key = (p["to"], p["action"], p["direction"], p["from"], p["iface"], p["comment"])
        g = index.get(key)
        if not g:
            # Friendly derived fields.
            iface = p["iface"]
            to = p["to"]
            is_iface = bool(iface)
            if is_iface and to.lower() in ("anywhere", ""):
                port_label = "All ports"
            else:
                port_label = to or "—"
            # Split the protocol out of the port so the UI can show it in its own
            # column (e.g. "5000/tcp" -> port "5000", protocol "TCP"). A bare
            # numeric port with no suffix means UFW allowed both TCP and UDP.
            m_proto = re.match(r"^(.*)/(tcp|udp)$", port_label, re.IGNORECASE)
            if m_proto:
                port_num = m_proto.group(1)
                proto_label = m_proto.group(2).upper()
            elif re.search(r"\d", port_label):
                port_num = port_label
                proto_label = "BOTH"
            else:
                port_num = port_label
                proto_label = "—"
            if iface:
                scope = iface + (" (Tailscale)" if iface.startswith("tailscale") else "")
            else:
                scope = "Any address" if p["from"].lower() == "anywhere" else (p["from"] or "—")
            # A "deny/reject from <specific IP>" rule is an IP block (its own UI section), as opposed
            # to an open-port / access rule. Interface rules and "deny to a port" (no from-IP) aren't.
            from_ip = "" if p["from"].lower() == "anywhere" else (p["from"] or "")
            is_block = ((p["action"] or "").upper() in ("DENY", "REJECT")
                        and bool(from_ip) and not iface)
            g = {
                "nums": [], "families": [], "port_label": port_label,
                "port_num": port_num, "proto_label": proto_label,
                "comment": p["comment"], "scope": scope, "iface": iface,
                "action": p["action"] or "ALLOW", "direction": p["direction"] or "IN",
                "is_iface": is_iface, "is_block": is_block,
                "block_ip": from_ip if is_block else "",
            }
            index[key] = g
            groups.append(g)
        g["nums"].append(int(r["num"]))
        fam = "IPv6" if p["v6"] else "IPv4"
        if fam not in g["families"]:
            g["families"].append(fam)
    # Stable, readable family label.
    for g in groups:
        fams = g["families"]
        g["family_label"] = " + ".join(sorted(fams)) if len(fams) > 1 else (fams[0] if fams else "")
        g["nums"].sort()
    return groups


def _ssh_ports(server):
    """Ports whose firewall rule keeps SSH reachable. Always includes 22 (the default)
    and the port the panel actually connects on — which covers a CUSTOM SSH port,
    since that's exactly what's stored on the remote."""
    ports = {22}
    try:
        if getattr(server, "port", None):
            ports.add(int(server.port))
    except (TypeError, ValueError):
        _log.debug("a non-numeric stored port just means there's no extra SSH port to track", exc_info=True)
    return ports


def _panel_web_port(server):
    """If `server` is the panel's OWN host and the panel UI isn't reachable over Tailscale
    yet, the public web port is the only way in — return it so its rule can be protected.
    Returns None for a remote, or once Tailscale Serve is actually serving the panel.

    Note: a `tailscale0` UFW rule (Tailscale SSH being reachable) is NOT enough to unprotect
    it — that's only a recovery path, not panel-UI access. The panel UI is only reachable
    over the tailnet once Serve is configured (tailscale_setup_done), so gate on that."""
    if not is_local_server(server):
        return None
    try:
        from config import load_config
        cfg = load_config()
    except Exception:
        return None
    if cfg.get("tailscale_setup_done"):
        return None  # served via Tailscale; the public port isn't the only way in
    try:
        return int(cfg.get("port", 5000))
    except (TypeError, ValueError):
        return 5000


def _panel_served_over_tailscale(server):
    """True when THIS host is the panel AND its web UI is published over Tailscale Serve
    (tailscale_setup_done). In that case the *inbound* tailscale0 UFW rule is exactly what
    keeps the panel reachable over the tailnet — with UFW default-deny, deleting it drops
    inbound tailnet traffic to Serve and locks you out of the panel. It's the mirror image
    of _panel_web_port: once Serve is the way in, the public port is free to close BUT the
    tailscale0 rule becomes load-bearing and must be protected."""
    try:
        if not is_local_server(server):
            return False
        from config import load_config
        return bool(load_config().get("tailscale_setup_done"))
    except Exception:
        return False


def _annotate_firewall_protection(server, enabled, groups):
    """Flag rules whose removal could LOCK YOU OUT, so the UI and API can refuse to
    delete the last way in. Access rules: the SSH-port ALLOW and the Tailscale-
    interface ALLOW — a rule is *blocked* only when it's the sole remaining one (no
    SSH and no Tailscale would be left); otherwise it's flagged to warn on. On the
    panel's OWN host, the panel's web port is also protected when Tailscale isn't an
    alternate route (otherwise you'd delete your only way into the panel UI). If UFW
    is disabled it isn't enforcing anything, so nothing is protected."""
    ssh_ports = _ssh_ports(server)
    for g in groups:
        pn = str(g.get("port_num", ""))
        # Only an INCOMING rule is a "way in". An `allow out on tailscale0` rule (or any
        # OUT rule) must not count. A rate-limited SSH rule (`ufw limit`, action LIMIT) is
        # just as much a way in as an ALLOW — miss it and the panel would let you delete
        # your only SSH access.
        inbound = g.get("direction", "IN") != "OUT"
        g["is_ssh"] = (not g.get("is_iface") and g.get("action") in ("ALLOW", "LIMIT") and inbound
                       and pn.isdigit() and int(pn) in ssh_ports)
        g["is_tailscale"] = (bool(g.get("is_iface")) and g.get("action") == "ALLOW" and inbound
                             and str(g.get("iface", "")).startswith("tailscale"))
        g["is_access"] = g["is_ssh"] or g["is_tailscale"]

    panel_port = _panel_web_port(server)
    served_over_ts = _panel_served_over_tailscale(server)
    ssh_count = sum(1 for g in groups if g.get("is_ssh"))
    has_ts_iface = any(g.get("is_tailscale") for g in groups)

    # A Tailscale rule only counts as a real fallback when Tailscale is ACTUALLY running —
    # a lingering `allow tailscale0` UFW rule with Tailscale down/uninstalled is no route at
    # all. Query the live state once (only when it could change a decision).
    ts_running = ts_ssh_enabled = False
    if enabled and any(g.get("is_access") for g in groups):
        ts_running, ts_ssh_enabled = _tailscale_conn_state(server)
    ts_ssh_ok = ts_running and ts_ssh_enabled    # Tailscale SSH → a way in regardless of UFW
    ts_iface_ok = ts_running and has_ts_iface     # regular SSH over the tailnet (needs the iface rule)

    for g in groups:
        g["protected"] = False
        g["warn"] = False
        g["protect_reason"] = ""
        g["is_panel"] = (panel_port is not None and not g.get("is_iface")
                         and g.get("action") == "ALLOW"
                         and str(g.get("port_num", "")).isdigit()
                         and int(g["port_num"]) == panel_port)
        if not enabled:
            continue
        if g["is_panel"]:
            # No Tailscale route, so this public port is the only way into the panel.
            g["protected"] = True
            g["protect_reason"] = (
                "Port %d is where this panel's own web interface listens, and it isn't reachable "
                "over Tailscale — removing it would lock you out of the panel. Set up Tailscale "
                "first if you want to close it." % panel_port)
            continue
        if not g["is_access"]:
            continue
        if g["is_ssh"]:
            # Deleting this SSH rule is safe only if another way in remains: another SSH rule,
            # Tailscale SSH, or regular SSH over a running tailnet (Tailscale isn't affected).
            other_way = (ssh_count > 1) or ts_ssh_ok or ts_iface_ok
            reason_last = (
                "Port %s is the SSH port used to reach this host, and there's no working Tailscale "
                "route to fall back on — removing it would lock you out. Enable Tailscale SSH, or "
                "connect Tailscale and allow the tailscale0 interface, first." % g["port_num"])
        else:  # is_tailscale — deleting it drops regular SSH over the tailnet; Tailscale SSH is unaffected
            if served_over_ts:
                # This is the panel host and its UI is published over Tailscale Serve, so this
                # inbound tailscale0 rule is what keeps the PANEL reachable over the tailnet —
                # not just SSH. With UFW default-deny, removing it drops inbound tailnet traffic
                # to Serve and locks you out of the panel, and an available SSH path doesn't save
                # the UI. Protect it outright (blocks the UI's × and any direct delete API call).
                g["protected"] = True
                g["protect_reason"] = (
                    "This Tailscale interface rule keeps the panel reachable over your tailnet "
                    "(Tailscale Serve). With the firewall's default-deny, removing it would drop "
                    "inbound tailnet traffic and lock you out of the panel — so it can't be "
                    "deleted here.")
                continue
            other_way = (ssh_count > 0) or ts_ssh_ok
            reason_last = (
                "This is the Tailscale interface rule and currently the only way in — removing it "
                "would lock you out. Open your SSH port (or enable Tailscale SSH) first.")
        if not other_way:
            g["protected"] = True
            g["protect_reason"] = reason_last
        else:
            g["warn"] = True
            g["protect_reason"] = (
                "This keeps you connected (SSH or Tailscale). Another way in exists so it can be "
                "removed, but make sure you won't lock yourself out.")
    return groups


def remote_ufw_status(server):
    """Get UFW status and rules from the remote server."""
    out, err, rc = run_command(server, "ufw status numbered 2>&1 || echo 'NOTINSTALLED'", timeout=15)
    if "NOTINSTALLED" in out or "not found" in err or "not installed" in err:
        return {"installed": False, "enabled": False, "rules": [], "groups": []}
    # `ufw status` always prints a "Status:" line when it actually runs. If it's missing (or the
    # command failed), the host is unreachable / the command errored — don't claim UFW is installed
    # (that would show a misleading empty-rules "installed" firewall for a down remote).
    if rc != 0 or "Status:" not in out:
        return {"installed": False, "enabled": False, "rules": [], "groups": [], "unreachable": True}

    enabled = "Status: active" in out
    rules = []
    # `ufw status numbered` prints each rule as "[ N] <to>  <action>  <from>".
    # Collapse runs of spaces so the detail reads cleanly.
    for line in out.split("\n"):
        m = re.match(r"^\s*\[\s*(\d+)\]\s*(.*)$", line)
        if m:
            detail = re.sub(r"\s{2,}", "  ", m.group(2).strip())
            rules.append({"num": m.group(1), "detail": detail})

    groups = _annotate_firewall_protection(server, enabled, _group_ufw_rules(rules))
    return {"installed": True, "enabled": enabled, "rules": rules, "groups": groups}


# Single shell script that prints static host specs as TAB-separated KEY<TAB>VALUE
# lines. POSIX-sh compatible (no sudo needed — everything read here is world-readable),
# with fallbacks so it works on x86 servers and ARM SBCs (Raspberry Pi) alike.
_SPECS_CMD = (
    r'''OS=$(. /etc/os-release 2>/dev/null; printf '%s' "$PRETTY_NAME"); '''
    r'''CPU=$(lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -1); '''
    r'''[ -z "$CPU" ] && CPU=$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1); '''
    r'''[ -z "$CPU" ] && CPU=$(sed -n 's/^Model[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1); '''
    r'''MAXMHZ=$(lscpu 2>/dev/null | sed -n 's/^CPU max MHz:[[:space:]]*//p' | head -1); '''
    r'''MEM=$(awk '/MemTotal/{printf "%.1f", $2/1048576}' /proc/meminfo); '''
    r'''DISK=$(df -hP / 2>/dev/null | awk 'NR==2{print $2}'); '''
    r'''VIRT=$(systemd-detect-virt 2>/dev/null || true); '''
    r'''printf 'OS\t%s\nKERNEL\t%s\nARCH\t%s\nHOST\t%s\nCPU\t%s\nCORES\t%s\nMAXMHZ\t%s\nMEM\t%s\nDISK\t%s\nVIRT\t%s\n' '''
    r'''"$OS" "$(uname -r)" "$(uname -m)" "$(hostname)" "$CPU" "$(nproc)" "$MAXMHZ" "$MEM" "$DISK" "$VIRT"'''
)


_specs_cache = {}   # key -> result; hardware/OS specs don't change without a reboot (which restarts us)


def host_specs(server, force=False):
    """Static hardware/OS specs for a host (OS, CPU, cores, RAM, disk, kernel, arch, virt). Probed
    ONCE and cached for the panel's whole lifetime — these don't change while the machine is up, and
    a reboot/resize restarts the panel anyway, so there's no periodic re-check. force=True re-probes
    (e.g. after resizing the box without a reboot)."""
    key = _pro_key(server)
    if not force and key in _specs_cache:
        return _specs_cache[key]
    result = _compute_host_specs(server)
    if not result.get("error"):     # cache only a good read; a transient failure retries next time
        _specs_cache[key] = result
    return result


def _compute_host_specs(server):
    """Probe hardware/OS specs (OS, CPU model, cores, RAM, disk, kernel, arch, virt)."""
    try:
        out, err, rc = run_command(server, _SPECS_CMD, timeout=20, sudo=False)
    except Exception:
        # Never surface raw exception text — it flows to a JSON response (CodeQL
        # py/stack-trace-exposure). Log it server-side; the caller shows a generic message.
        _log.warning("host specs probe failed", exc_info=True)
        return {"error": "Could not read system specs"}
    if not out:
        _log.debug("host specs: empty output (stderr: %s)", (err or "")[:200])
        return {"error": "Could not read system specs"}
    d = {}
    for line in out.splitlines():
        if "\t" in line:
            k, v = line.split("\t", 1)
            d[k.strip()] = v.strip()
    mhz = d.get("MAXMHZ", "")
    ghz = ""
    try:
        if mhz:
            ghz = f"{float(mhz) / 1000:.1f} GHz"
    except ValueError:
        ghz = ""
    mem = d.get("MEM", "")
    virt = d.get("VIRT", "")
    return {
        "os": d.get("OS", "") or "Unknown",
        "kernel": d.get("KERNEL", ""),
        "arch": d.get("ARCH", ""),
        "hostname": d.get("HOST", ""),
        "cpu": d.get("CPU", "") or "Unknown CPU",
        "cores": d.get("CORES", ""),
        "cpu_speed": ghz,
        "ram": (mem + " GB") if mem else "",
        "disk": d.get("DISK", ""),
        "virt": "" if virt in ("none", "") else virt,
    }


# ── Ubuntu Pro (ubuntu-advantage-tools / `pro`) ────────────────────────────
# The security-relevant services we surface (the rest — fips/cis/anbox/etc. —
# aren't relevant to a game-server host and just add noise).
_PRO_FEATURED = ["esm-infra", "esm-apps", "livepatch"]
_PRO_SERVICES = {
    "esm-infra", "esm-apps", "livepatch", "fips", "fips-updates", "fips-preview",
    "cis", "usg", "realtime-kernel", "landscape", "anbox-cloud", "ros", "ros-updates",
}


def _pro_trim(blob):
    """Collapse a pro CLI output blob to a short, single-line message."""
    import re as _re
    return _re.sub(r"\s+", " ", blob or "").strip()[-300:]


def _sudo_sh(inner):
    """Wrap a full shell pipeline so it ALL runs under sudo. `run_command`/`_run_local`
    with sudo=True only escalates the first token, which breaks compound commands
    (`a && b`, subshells) — so we build `sudo bash -c '…'` ourselves and pass
    sudo=False. Works uniformly for local, paramiko, and Tailscale-SSH hosts."""
    return f"sudo bash -c {_quote(inner)}"


# ── Keep the node player-query tools (npm + gamedig) current ───────────────────
# gamedig is installed once (bootstrap / install.sh) and never updates itself, so player queries can
# silently break as games and gamedig evolve. This weekly ROOT cron refreshes npm + gamedig alongside
# the host's other automatic updates (unattended-upgrades). Written to /etc/cron.d as root, idempotent;
# the `command -v npm` guard makes it a harmless no-op on a host that never got node.
_NODE_TOOLS_CRON_PATH = "/etc/cron.d/lgsm-node-tools"
_NODE_TOOLS_CRON = (
    "# LinuxGSM Panel - keep npm + gamedig current for player queries (managed by the panel).\n"
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    "30 4 * * 0 root command -v npm >/dev/null 2>&1 && "
    "npm install -g npm gamedig >/var/log/lgsm-node-tools.log 2>&1\n"
)


def ensure_node_tools_cron(server):
    """Idempotently install the weekly root cron that keeps npm + gamedig current on `server`, so the
    panel's player queries don't rot. Best-effort; never raises. Returns True if the write succeeded.
    The cron file is written under `sudo bash -c` (root) so it lands root-owned regardless of any
    per-remote linuxgsm_user, and base64-piped so no quoting/`%` can mangle it."""
    try:
        import base64
        b64 = base64.b64encode(_NODE_TOOLS_CRON.encode()).decode()
        inner = "printf %s {b} | base64 -d > {f} && chmod 644 {f}".format(
            b=_quote(b64), f=_quote(_NODE_TOOLS_CRON_PATH))
        _out, _err, rc = run_command(server, _sudo_sh(inner), timeout=20, sudo=False)
        return rc == 0
    except Exception:
        _log.debug("ensure_node_tools_cron failed", exc_info=True)
        return False


# `pro status` spawns Ubuntu's heavy advantage-tools client (slow + CPU-hungry, especially on a
# small VPS). Its result changes ONLY when someone attaches/detaches/toggles a service — all of
# which go through this module and invalidate the cache — so there's no reason to re-run it on a
# timer. The long TTL is just a safety net to eventually catch an out-of-band change (a lapsed
# subscription, or a manual `pro detach` on the host); day-to-day it's effectively set-and-forget.
_pro_status_cache = {}   # key -> (expiry_epoch, result)
_PRO_STATUS_TTL = 86400  # 24h


def _pro_key(server):
    return getattr(server, "id", None) or getattr(server, "host", None) or "local"


def _pro_cache_invalidate(server):
    _pro_status_cache.pop(_pro_key(server), None)


def pro_status(server, force=False):
    """Ubuntu Pro attachment/service status for a host (cached ~5 min; pass force=True to refresh)."""
    key = _pro_key(server)
    now = time.time()
    if not force:
        cached = _pro_status_cache.get(key)
        if cached and cached[0] > now:
            return cached[1]
    result = _compute_pro_status(server)
    _pro_status_cache[key] = (now + _PRO_STATUS_TTL, result)
    return result


def _compute_pro_status(server):
    """Run `pro status` and shape the result. Returns installed/attached plus the featured
    security services and their enabled/disabled state."""
    import json
    out, _, _ = run_command(
        server, _sudo_sh("pro status --format json 2>/dev/null || true"),
        timeout=25, sudo=False,
    )
    if not out.strip() or not out.strip().startswith("{"):
        return {"installed": False, "attached": False, "services": []}
    try:
        data = json.loads(out)
    except Exception:
        return {"installed": True, "attached": False, "services": [],
                "error": "Could not parse pro status"}
    by_name = {s.get("name"): s for s in (data.get("services") or [])}
    featured = []
    for name in _PRO_FEATURED:
        s = by_name.get(name)
        if s:
            featured.append({
                "name": name,
                "description": s.get("description", ""),
                "status": s.get("status", ""),
                "entitled": s.get("entitled", ""),
                "available": s.get("available", ""),
            })
    contract = data.get("contract") or {}
    account = data.get("account") or {}
    expires = data.get("expires", "") or ""
    if expires.startswith("9999"):  # perpetual free sub — don't show a scary date
        expires = ""
    return {
        "installed": True,
        "attached": bool(data.get("attached")),
        "account": account.get("name", "") if isinstance(account, dict) else "",
        "contract": contract.get("name", "") if isinstance(contract, dict) else "",
        "expires": expires,
        "services": featured,
    }


def pro_attach(server, token):
    """Attach a host to Ubuntu Pro with a subscription token. Installs the pro client
    first if it's somehow missing. The token is NEVER echoed back in messages/logs."""
    token = (token or "").strip()
    if not token:
        return False, "No token provided"
    _pro_cache_invalidate(server)   # state is about to change; next status read must be fresh
    inner = ("(command -v pro >/dev/null 2>&1 || (apt-get update -qq && "
             "DEBIAN_FRONTEND=noninteractive apt-get install -y ubuntu-advantage-tools)) ; "
             f"pro attach {_quote(token)} 2>&1")
    out, err, rc = run_command(server, _sudo_sh(inner), timeout=240, sudo=False)
    blob = ((out or "") + " " + (err or "")).replace(token, "<token>")
    low = blob.lower()
    if rc == 0 or "this machine is now attached" in low or "already attached" in low:
        return True, "Attached to Ubuntu Pro."
    return False, _pro_trim(blob) or "Attach failed"


def pro_service(server, service, action):
    """Enable or disable an Ubuntu Pro service (esm-infra, esm-apps, livepatch, …)."""
    if service not in _PRO_SERVICES:
        return False, "Unknown service"
    if action not in ("enable", "disable"):
        return False, "Unknown action"
    _pro_cache_invalidate(server)
    out, err, rc = run_command(server, _sudo_sh(f"pro {action} {service} --assume-yes 2>&1"),
                               timeout=300, sudo=False)
    blob = (out or "") + " " + (err or "")
    low = blob.lower()
    if rc == 0 or "is already enabled" in low or "is already disabled" in low \
            or "now enabled" in low or "updating package lists" in low:
        return True, _pro_trim(blob) or f"{service} {action}d"
    return False, _pro_trim(blob) or f"Could not {action} {service}"


def pro_detach(server):
    """Detach a host from Ubuntu Pro."""
    _pro_cache_invalidate(server)
    out, err, rc = run_command(server, _sudo_sh("pro detach --assume-yes 2>&1"), timeout=120, sudo=False)
    blob = (out or "") + " " + (err or "")
    if rc == 0 or "detach" in blob.lower():
        return True, "Detached from Ubuntu Pro."
    return False, _pro_trim(blob) or "Detach failed"


def _ufw_port_int(port):
    """Coerce a UFW port to a validated int (1-65535), or raise ValueError. Ports and
    protocols are interpolated straight into a root shell command, so they must never
    carry anything but a number / a known protocol keyword."""
    p = int(port)   # rejects non-numeric ("abc", "22; rm -rf /") with ValueError
    if not (1 <= p <= 65535):
        raise ValueError("port out of range")
    return p


def _ufw_proto(protocol):
    """Normalise a UFW protocol to one of tcp/udp/both, or None for an invalid value.
    Anything outside the allowlist is rejected — it must never reach the shell."""
    p = (protocol or "").strip().lower()
    if p in ("", "both", "any"):
        return "both"
    if p in ("tcp", "udp"):
        return p
    return None


def remote_ufw_open_port(server, port, protocol="tcp", comment=""):
    """Open a port on the remote server via UFW. protocol 'both'/'any' opens TCP+UDP
    in a single rule (a bare `ufw allow <port>` covers both)."""
    try:
        port = _ufw_port_int(port)
    except (TypeError, ValueError):
        return False, "Invalid port"
    proto = _ufw_proto(protocol)
    if proto is None:
        return False, "Invalid protocol"
    cmt = f" comment {_quote(comment)}" if comment else ""
    if proto == "both":
        cmd = f"ufw allow {port}{cmt} 2>&1"
        label = f"{port} (TCP+UDP)"
    else:
        cmd = f"ufw allow proto {proto} to any port {port}{cmt} 2>&1"
        label = f"{port}/{proto}"
    out, err, rc = run_command(server, cmd, timeout=15, sudo=True)
    if rc == 0:
        return True, f"Port {label} opened on remote"
    return False, err or out or "Unknown error"


def remote_ufw_close_port(server, port, protocol=None):
    """Close a port on the remote server via UFW. With protocol=None (or 'both'/'any'),
    deletes the bare `allow <port>` rule (both protocols); otherwise the proto-specific rule."""
    try:
        port = _ufw_port_int(port)
    except (TypeError, ValueError):
        return False, "Invalid port"
    proto = _ufw_proto(protocol)
    if proto is None:
        return False, "Invalid protocol"
    if proto in ("tcp", "udp"):
        cmd = f"ufw delete allow proto {proto} to any port {port} 2>&1"
    else:
        cmd = f"ufw delete allow {port} 2>&1"
    out, err, rc = run_command(server, cmd, timeout=15, sudo=True)
    if rc == 0:
        return True, f"Port {port}{('/' + proto) if proto in ('tcp', 'udp') else ''} closed on remote"
    return False, err or out or "Unknown error"


def remote_ufw_delete_rule(server, num, force=False):
    """Delete a UFW rule by its number (as shown by `ufw status numbered`). This is
    the reliable way to remove any rule — deleting by spec requires an exact match.

    Unless force=True, refuses to delete a rule that is the last thing keeping SSH or
    Tailscale access open, so a click (or a direct API call) can't lock you out."""
    try:
        n = int(num)
    except (TypeError, ValueError):
        return False, "Invalid rule number"
    if n < 1:
        return False, "Invalid rule number"
    if not force:
        try:
            for g in remote_ufw_status(server).get("groups", []):
                if n in g.get("nums", []) and g.get("protected"):
                    return False, g.get("protect_reason") or \
                        "This rule protects your access to the host and can't be removed here."
        except Exception:
            _log.debug("don't let the safety check itself block a legitimate delete on error", exc_info=True)
    out, err, rc = run_command(server, f"yes | ufw delete {n} 2>&1", timeout=15, sudo=True)
    if rc == 0:
        return True, f"Rule {n} deleted"
    return False, err or out or "Failed to delete rule"


def remote_ufw_allow_game_port(server, port, name="Game"):
    """Open the game server port for BOTH TCP and UDP in ONE UFW rule, tagging the
    rule with the game server's name (its LinuxGSM username) so the firewall list
    shows which server each port belongs to. A bare `ufw allow <port>` covers tcp+udp."""
    comment = re.sub(r"[^A-Za-z0-9 _.-]", "", name or "Game")[:60] or "Game"
    out, err, rc = run_command(server, f"ufw allow {port} comment {_quote(comment)} 2>&1", timeout=15, sudo=True)
    ok = rc == 0
    return (1 if ok else 0), f"Port {port}: {'opened (TCP+UDP)' if ok else (err or out or 'failed')}"


def remote_ufw_allow_game_ports(server, ports, name="Game"):
    """Open a LIST of ports (each bare rule = TCP+UDP), all tagged with the game
    server's name. Idempotent — re-opening an existing port is a no-op. Used to open
    every port a game actually needs (game/query/rcon/etc.), not just the main one."""
    opened = []
    for p in sorted({int(x) for x in ports if x}):
        cnt, _ = remote_ufw_allow_game_port(server, p, name)
        if cnt:
            opened.append(p)
    return opened, f"opened {len(opened)} port(s): {', '.join(map(str, opened)) or 'none'}"


def remote_ufw_close_by_name(server, name):
    """Delete ALL UFW rules tagged with a game server's name (its comment). Used on
    uninstall so multi-port games are fully cleaned up. Deletes highest-numbered
    rule first so the numbering stays valid as rules are removed."""
    comment = re.sub(r"[^A-Za-z0-9 _.-]", "", name or "")[:60]
    if not comment:
        return 0, "no name"
    out, _, _ = run_command(server, "ufw status numbered 2>&1", timeout=15, sudo=True)
    nums = []
    for line in (out or "").splitlines():
        m = re.match(r"^\s*\[\s*(\d+)\]\s*(.*)$", line)
        if m and re.search(r"#\s*" + re.escape(comment) + r"\s*$", m.group(2)):
            nums.append(int(m.group(1)))
    deleted = sum(1 for n in sorted(nums, reverse=True) if remote_ufw_delete_rule(server, n)[0])
    return deleted, f"{deleted} rule(s) removed for {comment}"


def remote_ufw_close_game_port(server, port):
    """Remove the game server port rule (used on uninstall). Handles the new
    single bare rule plus any legacy proto-specific / port+1 rules from older installs."""
    n = 0
    ok, _ = remote_ufw_close_port(server, port)  # new-style bare rule (both protocols)
    n += 1 if ok else 0
    for p in (port, port + 1):  # legacy cleanup: old proto-specific + port+1 rules
        for proto in ("tcp", "udp"):
            ok, _ = remote_ufw_close_port(server, p, proto)
            n += 1 if ok else 0
    return n, f"Port {port}: {n} rule(s) removed"


# LinuxGSM dependencies common to most game servers on Debian/Ubuntu. The game
# user has no sudo, so the panel installs these as root before/around auto-install.
LGSM_COMMON_DEPS = (
    "curl wget ca-certificates file bzip2 gzip xz-utils unzip bsdmainutils pigz "
    "python3 binutils bc jq tmux netcat-openbsd distro-info "
    # 32-bit runtimes for SteamCMD + game binaries. libstdc++5:i386 (universe) is the
    # ancient libstdc++.so.5 that old titles like Call of Duty need to start.
    "lib32gcc-s1 lib32stdc++6 lib32z1 libsdl2-2.0-0:i386 libc6:i386 libstdc++5:i386"
)


_DEPS_CSV_CACHE = {"data": None}


def _load_deps_csv():
    """Parse LinuxGSM's bundled ubuntu-24.04.csv into {key: [packages]}.
    Keys are 'all', 'steamcmd', and each game shortname."""
    if _DEPS_CSV_CACHE["data"] is not None:
        return _DEPS_CSV_CACHE["data"]
    data = {}
    path = Path(__file__).parent / "lgsm" / "data" / "ubuntu-24.04.csv"
    try:
        with open(path) as f:
            for line in f:
                parts = [p.strip() for p in line.strip().split(",") if p.strip()]
                if parts:
                    data[parts[0]] = parts[1:]
    except Exception:
        data = {}
    _DEPS_CSV_CACHE["data"] = data
    return data


def deps_for_game(game_type):
    """Exact packages LinuxGSM needs for a game on Ubuntu 24.04: the 'all' base
    deps + steamcmd deps + the game's own extra deps (e.g. cod → libstdc++5:i386,
    mc → openjdk). Returns (packages, needs_steamcmd) — steamcmd is handled
    separately because it lives in `multiverse` and needs its EULA pre-accepted."""
    csv = _load_deps_csv()
    pkgs = []
    needs_steamcmd = False
    for key in ("all", "steamcmd", game_type or ""):
        for p in csv.get(key, []):
            if not p:
                continue
            if p == "steamcmd":
                needs_steamcmd = True
                continue
            if p not in pkgs:
                pkgs.append(p)
    return pkgs, needs_steamcmd


def install_game_dependencies(server, game_type=None, extra=""):
    """Install the exact LinuxGSM dependencies for a game (from ubuntu-24.04.csv),
    plus any extras, as root. Falls back to the common set if the CSV is missing.
    Enables i386 + universe + multiverse first, then installs the batch, and if that
    fails (apt-get install is atomic — one unavailable package aborts everything)
    falls back to installing each package individually so the critical libs still
    land. `steamcmd` (needed by every Steam game — gmod/cs/tf2/rust/…) is installed
    specially: it's in `multiverse` and its Steam license must be pre-accepted via
    debconf or apt hangs waiting for interactive input."""
    if game_type:
        per_game, needs_steamcmd = deps_for_game(game_type)
    else:
        per_game, needs_steamcmd = [], True  # unknown game → make sure steamcmd is present
    # A retry may pass "steamcmd" back via `extra` (LinuxGSM lists it as missing).
    extra_pkgs = (extra or "").split()
    if "steamcmd" in extra_pkgs:
        needs_steamcmd = True
        extra_pkgs = [p for p in extra_pkgs if p != "steamcmd"]
    base = " ".join(per_game) if per_game else LGSM_COMMON_DEPS
    pkgs = (base + (" " + " ".join(extra_pkgs) if extra_pkgs else "")).strip()
    steam_block = ""
    if needs_steamcmd:
        steam_block = (
            "echo steam steam/question select 'I AGREE' | debconf-set-selections ; "
            "echo steam steam/license note '' | debconf-set-selections ; "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y steamcmd steamcmd:i386 2>&1 | tail -3 "
            "|| DEBIAN_FRONTEND=noninteractive apt-get install -y steamcmd 2>&1 | tail -3 || true ; "
        )
    pipeline = (
        "dpkg --add-architecture i386 >/dev/null 2>&1 ; "
        "add-apt-repository -y universe >/dev/null 2>&1 || true ; "
        "add-apt-repository -y multiverse >/dev/null 2>&1 || true ; "
        "apt-get update -qq >/dev/null 2>&1 ; "
        f"{steam_block}"
        f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pkgs} 2>&1 | tail -4 "
        f"|| for p in {pkgs} ; do DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \"$p\" >/dev/null 2>&1 || true ; done ; "
        "echo deps-done"
    )
    cmd = f"sudo bash -c {_quote(pipeline)}"
    out, err, rc = run_command(server, cmd, timeout=1200, sudo=False)
    return rc == 0, (out or err)


def parse_missing_deps(output):
    """Extract package names LinuxGSM reported as missing (from its
    'Missing dependencies: pkg1 pkg2 ... Run:' warning)."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    deps = []
    for m in re.finditer(r"[Mm]issing dependencies:\s*(.+?)(?:\s+Run:|[\r\n]|$)", text):
        for pkg in m.group(1).split():
            if re.match(r"^[a-z0-9][a-z0-9+._:-]*$", pkg) and pkg not in deps:
                deps.append(pkg)
    return deps


def port_in_use(server, port):
    """True if something is already listening on `port` (tcp or udp) on the remote."""
    try:
        out, _, _ = run_command(
            server, f"ss -Hlntu 'sport = :{port}' 2>/dev/null | wc -l", timeout=8
        )
        return out.strip().isdigit() and int(out.strip()) > 0
    except Exception:
        return False


def check_port_open(server, port):
    """Check if a port is allowed through UFW on the remote."""
    out, _, rc = run_command(server, f"ufw status verbose 2>&1 | grep -E '\\b{port}\\b'", timeout=10, sudo=True)
    return bool(out.strip())


# ─── Remote OS Commands ───────────────────────────────────────


def _parse_upgradable(out):
    """Parse `apt list --upgradable` output into [{name, version, from}]. Each line looks like
    'pkg/repo 1.2.3 amd64 [upgradable from: 1.2.2]' — we pull the package name, the NEW version,
    and the currently-installed version so the UI can show 'name  old → new'."""
    pkgs = []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line or line.startswith("Listing"):
            continue
        parts = line.split()
        if not parts:
            continue
        name = parts[0].split("/")[0]
        new_ver = parts[1] if len(parts) > 1 else ""
        old_ver = ""
        if "upgradable from:" in line:
            old_ver = line.split("upgradable from:", 1)[1].strip().rstrip("]").strip()
        pkgs.append({"name": name, "version": new_ver, "from": old_ver})
    pkgs.sort(key=lambda p: p["name"])
    return pkgs


def remote_os_check_updates(server):
    """Check for OS updates on the remote server. Returns {count, packages:[{name,version,from}]}."""
    run_command(server, "apt update -qq 2>/dev/null", timeout=60, sudo=True)
    out, _, _ = run_command(server,
        "apt list --upgradable 2>/dev/null | grep -v 'Listing...' | grep -v '^$'",
        timeout=30
    )
    pkgs = _parse_upgradable(out)
    return {"count": len(pkgs), "packages": pkgs}


def remote_os_run_updates(server):
    """Run apt upgrade on the remote server (blocking; kept for callers that want a one-shot).
    The UI uses the streaming remote_os_update_start/_status pair instead."""
    out, err, rc = run_command(server,
        "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y "
        "-o APT::Get::Always-Include-Phased-Updates=true "
        "-o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' 2>&1",
        timeout=600, sudo=True
    )
    return rc == 0, out[-300:] if out else err[:300]


# Host-side log the detached OS-update job streams to, so the popup can watch it live. Kept in /run
# (root-owned, not world-writable) rather than /tmp so a local user can't pre-plant a symlink there
# and redirect root's write — and it's cleared on reboot, which is fine for an ephemeral update log.
_OS_UPDATE_LOG = "/run/panel-os-update.log"
_OS_UPDATE_DONE = "PANEL_OS_UPDATE_DONE:"   # sentinel line the job appends with the exit code


def remote_os_update_start(server):
    """Kick off `apt upgrade` DETACHED, streaming output to a log the UI polls, so it survives the
    request and can be watched live. Fully non-interactive with SAFE auto-answers — keep any existing
    config file on a conflict (never clobber your edits) and assume-yes — so it can't hang waiting on
    a prompt; the log records what it decided. Returns (ok, message)."""
    # Don't launch a second run on top of one already going.
    chk, _, _ = run_command(
        server, "pgrep -f 'apt-get (upgrade|dist-upgrade|full-upgrade)' >/dev/null 2>&1 && echo RUN || echo IDLE",
        timeout=10, sudo=True)
    if "RUN" in (chk or ""):
        return True, "An update is already running — watching it."
    log = _OS_UPDATE_LOG
    inner = (
        ": > {L} 2>/dev/null || true; "
        "echo \"=== OS update started $(date) ===\" >> {L} 2>&1; "
        "export DEBIAN_FRONTEND=noninteractive; "
        "apt-get update >> {L} 2>&1; "
        # An explicit "Install updates" should apply everything the Check list shows. Two things
        # otherwise leave "N still available" after a run: plain `upgrade` holds back packages needing
        # a new dependency/removal (so use full-upgrade), and BOTH defer Ubuntu "phased" updates (a
        # gradual rollout) — Always-Include-Phased-Updates=true installs those too, so the re-check
        # actually reaches 0.
        "apt-get -y -o APT::Get::Always-Include-Phased-Updates=true "
        "-o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef' full-upgrade >> {L} 2>&1; "
        "rc=$?; "
        "apt-get -y autoremove >> {L} 2>&1 || true; "
        "echo \"{S}$rc\" >> {L} 2>&1"
    ).format(L=log, S=_OS_UPDATE_DONE)
    # setsid + detached stdio + & so it outlives the SSH channel / this request.
    cmd = "setsid bash -c {} </dev/null >/dev/null 2>&1 & echo __STARTED__".format(_quote(inner))
    out, _, _ = run_command(server, cmd, timeout=20, sudo=True)
    if "__STARTED__" in (out or ""):
        return True, "Update started."
    return False, "Couldn't start the update."


def remote_os_update_status(server):
    """Live status of the running/last OS update: {running, done, rc, log}. `done` is set once the
    detached job appends its sentinel; `running` reflects whether apt is still working."""
    out, _, _ = run_command(server, "tail -c 20000 {} 2>/dev/null".format(_OS_UPDATE_LOG),
                            timeout=15, sudo=True)
    log = out or ""
    m = re.search(re.escape(_OS_UPDATE_DONE) + r"(-?\d+)", log)
    done = m is not None
    rc = int(m.group(1)) if m else None
    if done:
        log = re.sub(r"\n?" + re.escape(_OS_UPDATE_DONE) + r"-?\d+\s*$", "", log)
        return {"running": False, "done": True, "rc": rc, "log": log}
    # No sentinel yet — is apt still working?
    alive, _, _ = run_command(server, "pgrep -f apt-get >/dev/null 2>&1 && echo Y || echo N",
                              timeout=10, sudo=True)
    return {"running": "Y" in (alive or ""), "done": False, "rc": None, "log": log}


def remote_reboot(server):
    """Reboot the remote server."""
    run_command(server, "reboot 2>&1", timeout=10, sudo=True)
    return True, "Reboot command sent to remote"


def remote_reboot_required(server):
    """Whether a host needs a reboot to finish applying updates. Debian/Ubuntu drop
    /var/run/reboot-required after a kernel/libc upgrade, and list the responsible packages in
    /var/run/reboot-required.pkgs. Works for the panel host too (run_command runs it locally when
    the server is is_local). Returns {'required': bool, 'packages': [str, ...]}. Best-effort."""
    try:
        out, _, _ = run_command(server, "test -f /var/run/reboot-required && echo YES || echo NO", timeout=12)
    except Exception:
        return {"required": False, "packages": []}
    if "YES" not in (out or ""):
        return {"required": False, "packages": []}
    packages = []
    try:
        pk, _, _ = run_command(server, "cat /var/run/reboot-required.pkgs 2>/dev/null", timeout=12)
        packages = sorted({p.strip() for p in (pk or "").splitlines() if p.strip()})
    except Exception:
        packages = []
    return {"required": True, "packages": packages}


_uptime_cache = {}   # server.id -> (expiry_epoch, dict) — de-dups concurrent viewers of the card
_UPTIME_TTL = 8      # the manage-remotes card polls ~every 15s; this only collapses overlap


def remote_uptime(server, force=False):
    """Uptime, CPU%, RAM, disk, kernel from the remote — in a SINGLE SSH round-trip (this used
    to be EIGHT separate commands, incl. a `top -bn1`, on every 15s poll). CPU% is a /proc/stat
    delta over 0.25s, which is far lighter than spawning top. Cached briefly so several viewers
    of the Remotes page share one read instead of each doing their own."""
    now = time.time()
    if not force and server is not None:
        hit = _uptime_cache.get(server.id)
        if hit and hit[0] > now:
            return hit[1]
    # One composite command with tagged lines, parsed below — one round-trip, one process spawn.
    parts = [
        "echo UPTIME $(uptime -p)",
        "awk '{print \"LOAD\",$1,$2,$3}' /proc/loadavg",
        "df -h / | tail -1 | awk '{print \"DISK\",$3\"/\"$2}'",
        "free -h | awk '/Mem:/{print \"MEM\",$3\"/\"$2}'",
        "free | awk '/Mem:/{printf \"MEMPCT %.1f\\n\", $3/$2*100}'",
        "echo KERNEL $(uname -r)",
        "echo CORES $(nproc)",
        "grep '^cpu ' /proc/stat", "sleep 0.25", "grep '^cpu ' /proc/stat",
    ]
    out, _, _ = run_command(server, " ; ".join(parts), timeout=15)
    d = {"uptime": "unknown", "load": "?", "disk": "?", "memory": "?", "memory_percent": "?",
         "kernel": "?", "cpu_percent": "?", "cpu_cores": "?", "cpu_per_core": ""}
    cpu_lines = []
    for line in (out or "").splitlines():
        f = line.split()
        if not f:
            continue
        tag = f[0]
        if tag == "cpu" and len(f) >= 8:
            cpu_lines.append([int(x) for x in f[1:8]])
        elif tag == "UPTIME":
            d["uptime"] = line[7:].replace("up ", "").strip() or "unknown"
        elif tag == "LOAD" and len(f) >= 4:
            d["load"] = f"{f[1]} {f[2]} {f[3]}"
        elif tag == "DISK" and len(f) >= 2:
            d["disk"] = f[1]
        elif tag == "MEM" and len(f) >= 2:
            d["memory"] = f[1]
        elif tag == "MEMPCT" and len(f) >= 2:
            d["memory_percent"] = f[1]
        elif tag == "KERNEL" and len(f) >= 2:
            d["kernel"] = f[1]
        elif tag == "CORES" and len(f) >= 2:
            d["cpu_cores"] = f[1]
    if len(cpu_lines) >= 2:
        a, b = cpu_lines[0], cpu_lines[1]
        idle = b[3] - a[3]
        total = sum(b) - sum(a)
        if total > 0:
            d["cpu_percent"] = f"{round((1 - idle / total) * 100, 1)}"
    if d["cpu_percent"] not in ("?", "") and d["cpu_cores"].isdigit():
        try:
            d["cpu_per_core"] = f"{float(d['cpu_percent']) / int(d['cpu_cores']):.1f}"
        except (ValueError, ZeroDivisionError):
            _log.debug("remote_uptime: per-core calc skipped", exc_info=True)
    if server is not None and out:   # don't cache a failed/empty read
        _uptime_cache[server.id] = (now + _UPTIME_TTL, d)
    return d


# ─── Full VPS Bootstrap ─────────────────────────────────


def _wait_for_reboot(server, on_wait=None, down_timeout=150, up_timeout=480):
    """After issuing a reboot, wait for the remote to drop then come back on SSH.
    Returns True if it came back online within the timeout."""
    def _up():
        try:
            ok, _ = ssh_test_connection(
                server.host, server.port or 22, server.username,
                server.auth_method, decrypt_secret(server.auth_credential),
            )
            return ok
        except Exception:
            return False

    # Phase 1: wait for it to actually go down (confirms the reboot began).
    t0 = time.time()
    while time.time() - t0 < down_timeout:
        if not _up():
            break
        if on_wait:
            on_wait("Waiting for server to go down for reboot…")
        time.sleep(5)

    # Phase 2: wait for SSH to come back.
    t0 = time.time()
    while time.time() - t0 < up_timeout:
        if _up():
            return True
        if on_wait:
            on_wait("Rebooting — waiting for server to come back online…")
        time.sleep(5)
    return False


def remote_bootstrap_vps(server, set_timezone="UTC", enable_ufw=True, install_lgsm_deps=True,
                           username="", install_fail2ban=True, do_reboot=True,
                           progress=None):
    """One-shot bootstrap of a fresh Ubuntu VPS.

    Runs: system updates → essential packages → timezone → UFW firewall →
    SSH hardening → swap → disable bloat → LinuxGSM user → fail2ban → reboot.

    `progress`, if given, is called as progress(step, total, name, status) after
    each step so the caller can stream live status ("running" / "rebooting" / ...).

    Returns (success, message, log).
    """
    log = []
    step = 0

    # Precompute the total step count so the progress bar is accurate.
    is_local = is_local_server(server)
    total = 8  # lock, update, full-upgrade, autoremove, install, node-lts, gamedig, unattended-upgrades
    total += 1 if set_timezone else 0
    total += 1 if enable_ufw else 0
    total += 2  # ssh hardening, swap
    total += 1  # disable services
    total += 1 if username else 0
    total += 1 if install_fail2ban else 0
    total += 1 if not is_local else 0   # a reboot-check step (may reboot, skip, or report none needed)

    def emit(name, status="running", detail=None):
        nonlocal step
        step += 1
        log.append(f"[{step}/{total}] {name}")
        if detail:
            log.append(f"   {detail}")
        if progress:
            try:
                progress(step, total, name, status)
            except Exception:
                _log.debug("emit: ignored non-fatal error", exc_info=True)

    def note(text, status="running"):
        log.append(f"   {text}")
        if progress:
            try:
                progress(step, total, text, status)
            except Exception:
                _log.debug("note: ignored non-fatal error", exc_info=True)

    # ── 1. Wait for cloud-init / apt to settle ──
    emit("Waiting for package manager to be free")
    run_command(server, "while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 1; done", timeout=180, sudo=True)

    # ── 2. Update apt cache + full upgrade ──
    emit("Updating package lists (apt update)")
    run_command(server, "apt-get update 2>&1 | tail -5", timeout=180, sudo=True)

    emit("Full-upgrading all packages (apt full-upgrade — may take several minutes)")
    out, _, _ = run_command(server,
        "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y "
        "-o Dpkg::Options::='--force-confdef' "
        "-o Dpkg::Options::='--force-confold' 2>&1 | tail -8",
        timeout=1800, sudo=True
    )
    note(out or "OK")

    emit("Removing unused packages (autoremove)")
    run_command(server, "apt-get autoremove -y 2>&1 | tail -3", timeout=180, sudo=True)

    # ── 3. Install essential packages (jq parses gamedig's JSON output) ──
    emit("Installing essential packages")
    pkgs = ("curl wget git ufw tmux htop net-tools unzip jq ca-certificates "
            "software-properties-common unattended-upgrades apt-listchanges")
    if install_lgsm_deps:
        # LinuxGSM base dependencies (32-bit libs for SteamCMD, etc.)
        pkgs += " python3 python3-pip bc lib32gcc-s1 lib32stdc++6 libsdl2-2.0-0:i386"
    if install_fail2ban:
        pkgs += " fail2ban"
    run_command(server, "dpkg --add-architecture i386 2>/dev/null; add-apt-repository -y universe 2>/dev/null; apt-get update -qq 2>/dev/null", timeout=120, sudo=True)
    out, _, _ = run_command(server, f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkgs} 2>&1 | tail -6", timeout=600, sudo=True)
    note(out or "OK")

    # ── 3a. Node.js LTS via NodeSource — apt's own nodejs is too old for current gamedig
    # (gamedig v5 needs Node >=18; e.g. Ubuntu 22.04's apt ships Node 12). Idempotent. ──
    emit("Installing Node.js LTS")
    node_cmd = (
        'n=$(node -v 2>/dev/null | grep -oE "[0-9]+" | head -1); '
        'if [ "${n:-0}" -lt 18 ]; then '
        'curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - >/dev/null 2>&1 && '
        'DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs 2>&1 | tail -3; '
        'else echo "Node $(node -v) already present"; fi'
    )
    nd_out, _, _ = run_command(server, node_cmd, timeout=300, sudo=True)
    note(nd_out or "Node.js LTS installed")

    # ── 3b. gamedig (game-server query tool) via npm — idempotent (skip if already present) ──
    emit("Installing gamedig (game server query tool)")
    gd_out, _, _ = run_command(
        server,
        "if command -v gamedig >/dev/null 2>&1; then echo 'gamedig already installed'; "
        "else npm install -g gamedig 2>&1 | tail -3; fi",
        timeout=300, sudo=True)
    note(gd_out or "gamedig installed")
    ensure_node_tools_cron(server)   # weekly auto-update for npm + gamedig, alongside apt auto-updates
    note("weekly npm/gamedig auto-update scheduled")

    # ── 3c. Enable + configure unattended-upgrades (auto security updates) ──
    emit("Enabling automatic security updates (unattended-upgrades)")
    import base64 as _b64
    au_conf = (
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'
        'APT::Periodic::AutocleanInterval "7";\n'
        'APT::Periodic::Download-Upgradeable-Packages "1";\n'
    )
    b64 = _b64.b64encode(au_conf.encode()).decode()
    run_command(server,
        f"echo '{b64}' | base64 -d > /etc/apt/apt.conf.d/20auto-upgrades ; "
        "systemctl enable --now unattended-upgrades 2>&1 | tail -1",
        timeout=30, sudo=True)

    # ── 4. Set timezone ──
    if set_timezone:
        emit(f"Setting timezone to {set_timezone}")
        # set_timezone is user-supplied and runs as root — quote it against injection.
        run_command(server, f"timedatectl set-timezone {_quote(set_timezone)} 2>&1", timeout=10, sudo=True)

    # ── 5. Configure UFW ──
    if enable_ufw:
        emit("Configuring UFW firewall (deny incoming, rate-limit SSH)")
        # Rate-limit SSH by default — `ufw limit` allows SSH (so we never lock ourselves
        # out) while throttling brute-force sources. We do NOT add a plain `allow 22`:
        # a lower-numbered allow rule would match first and shadow the limit, leaving SSH
        # effectively unthrottled.
        run_command(server, "ufw limit 22/tcp 2>&1", timeout=15, sudo=True)
        run_command(server, "ufw default deny incoming 2>&1", timeout=15, sudo=True)
        run_command(server, "ufw default allow outgoing 2>&1", timeout=15, sudo=True)
        run_command(server, "ufw --force enable 2>&1", timeout=15, sudo=True)

    # ── 6. Basic SSH hardening ──
    emit("Hardening SSH configuration")
    # These keepalive tweaks are always safe (they never affect how you log in).
    hardening = [
        "sed -i 's/^#\\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config",
        "sed -i 's/^#\\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config",
    ]
    if server.auth_method != "password":
        # Only lock down root-password + password login when we authenticate with a
        # key or Tailscale. NEVER touch these on a password-auth remote or the reboot
        # would lock everyone (including you via PuTTY) out of the box.
        hardening.append("sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config")
        hardening.append("sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config")
        run_command(server, "; ".join(hardening), timeout=20, sudo=True)
        run_command(server, "systemctl restart ssh 2>&1 || systemctl restart sshd 2>&1", timeout=15, sudo=True)
    else:
        run_command(server, "; ".join(hardening), timeout=20, sudo=True)
        note("Password + root-password SSH login left ENABLED — this remote authenticates with a password, so SSH access was not restricted.")

    # ── 7. Create swap if none exists ──
    emit("Ensuring swap space exists")
    swap_out, _, _ = run_command(server, "swapon --show | wc -l", timeout=10)
    if swap_out.strip() == "0":
        run_command(server,
            "fallocate -l 2G /swapfile && chmod 600 /swapfile && "
            "mkswap /swapfile && swapon /swapfile && "
            "grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab",
            timeout=60, sudo=True
        )
        note("2G swap file created")
    else:
        note("Swap already present")

    # ── 8. Disable unnecessary services ──
    emit("Disabling unnecessary services")
    for svc in ["whoopsie", "cups", "modemmanager"]:
        run_command(server, f"systemctl disable --now {svc} 2>/dev/null; echo done", timeout=10, sudo=True)

    # ── 9. Create linuxgsm user if username provided ──
    # `username` arrives raw from the bootstrap request (it doesn't pass through the model's
    # @validates), and it's interpolated into root-run useradd/id/passwd — so validate it to a
    # safe Linux-username charset (must start with a letter/underscore; no shell metacharacters,
    # no leading dash) and refuse anything else rather than let it reach the shell.
    if username and not re.match(r"^[A-Za-z_][A-Za-z0-9._-]*$", username):
        note(f"Skipped account creation: '{username[:32]}' isn't a valid username")
    elif username:
        emit(f"Creating LinuxGSM user: {username}")
        out, _, _ = run_command(server, f"id {_quote(username)} 2>/dev/null && echo 'EXISTS' || echo 'NOTEXISTS'", timeout=10)
        if "NOTEXISTS" not in out:
            note(f"User {username} already exists")
        else:
            run_command(server, f"useradd -m -s /bin/bash {_quote(username)} 2>&1", timeout=15, sudo=True)
            run_command(server, f"passwd -l {_quote(username)} 2>&1", timeout=10, sudo=True)
            note(f"User {username} created (login password locked)")

    # ── 10. Configure fail2ban ──
    if install_fail2ban:
        emit("Configuring fail2ban (SSH brute-force protection)")
        import base64
        jail_content = (
            "[DEFAULT]\nbantime = 1h\nfindtime = 10m\nmaxretry = 5\n\n"
            "[sshd]\nenabled = true\nport = 22\n"
        )
        b64 = base64.b64encode(jail_content.encode()).decode()
        run_command(server, f"echo '{b64}' | base64 -d > /etc/fail2ban/jail.local", timeout=15, sudo=True)
        run_command(server, "systemctl enable --now fail2ban 2>&1; systemctl restart fail2ban 2>&1", timeout=20, sudo=True)

    # ── 11. Reboot ONLY if an update actually requires one, and NEVER out from under running game
    #        servers (a reboot would drop the players). We check /var/run/reboot-required and, before
    #        rebooting, that no tmux/screen game-server sessions are live — otherwise we just flag the
    #        pending reboot so the operator can do it when the host is empty. ──
    if not is_local:
        reboot_req, _, _ = run_command(server, "test -f /var/run/reboot-required && echo YES || echo NO", timeout=10)
        needs_reboot = "YES" in (reboot_req or "")
        gs_out, _, _ = run_command(server, "if pgrep -x tmux >/dev/null 2>&1 || pgrep -x SCREEN "
                                   ">/dev/null 2>&1; then echo YES; else echo NO; fi", timeout=10)
        servers_running = "YES" in (gs_out or "")
        if not needs_reboot:
            emit("No reboot needed", detail="Updates applied without requiring a reboot.")
        elif servers_running or not do_reboot:
            emit("Reboot required — skipped to protect running servers", status="reboot-required",
                 detail="A kernel/library update needs a reboot. Reboot this host from its page "
                        "once its game servers are empty.")
        else:
            emit("Rebooting to apply a kernel/library update", status="rebooting",
                 detail="A system update requires a reboot and no game servers are running.")
            # Schedule the reboot slightly in the future so this command returns cleanly.
            run_command(server, "( sleep 2 ; reboot ) >/dev/null 2>&1 & echo scheduled", timeout=15, sudo=True)
            close_connection(server)
            came_back = _wait_for_reboot(server, on_wait=lambda t: note(t, status="rebooting"))
            if not came_back:
                return False, "Server was rebooted but did not come back online within the timeout.", "\n".join(log)
            note("Server is back online.", status="running")
    else:
        note("Reboot check skipped — this is the panel's own host.")

    if progress:
        try:
            progress(total, total, "Bootstrap complete", "done")
        except Exception:
            _log.debug("remote_bootstrap_vps: ignored non-fatal error", exc_info=True)
    return True, f"VPS bootstrap complete ({step}/{total} steps).", "\n".join(log)


# ─── Remote Tailscale Bootstrap ─────────────────────────────


def remote_check_tailscale(server):
    """Check if Tailscale is already installed and running on the remote."""
    installed_out, _, installed_rc = run_command(server, "which tailscale 2>/dev/null && echo 'INSTALLED' || echo 'NOTINSTALLED'", timeout=10)
    installed = "NOTINSTALLED" not in installed_out  # "INSTALLED" is a substring of "NOTINSTALLED"

    running = False
    ts_ip = ""
    dns_name = ""
    if installed:
        out, _, rc = run_command(server, "tailscale status --json 2>/dev/null || echo '{}'", timeout=10)
        if rc == 0 and out:
            try:
                import json
                data = json.loads(out)
                running = data.get("BackendState") == "Running"
                self_data = data.get("Self", {})
                if self_data:
                    dns = self_data.get("DNSName", "")
                    dns_name = dns.rstrip(".") if dns else ""
                    ts_ip = ", ".join(self_data.get("TailscaleIPs", []))
            except Exception:
                _log.debug("remote_check_tailscale: ignored non-fatal error", exc_info=True)

    return {
        "installed": installed,
        "running": running,
        "tailscale_ip": ts_ip,
        "dns_name": dns_name,
    }


def remote_install_tailscale(server):
    """Install Tailscale on a remote Ubuntu/Debian VPS.
    Returns (success, message, log).
    """
    log = []

    # 1. Detect OS/distro
    os_out, _, _ = run_command(server, "cat /etc/os-release 2>/dev/null | head -5", timeout=10)
    log.append(f"OS: {os_out[:200]}")

    # 2. Install curl if missing
    out, _, _ = run_command(server, "apt install -y curl 2>&1 | tail -3", timeout=60, sudo=True)
    log.append(f"curl: {out}")

    # 3. Add Tailscale repo and install
    cmds = [
        "curl -fsSL https://tailscale.com/install.sh | sh 2>&1",
    ]
    for cmd in cmds:
        out, _, rc = run_command(server, cmd, timeout=120, sudo=True)
        log.append(out[-200:])
        if rc != 0:
            return False, "Tailscale install script failed", "\n".join(log)

    # 4. Verify install
    out, _, rc = run_command(server, "which tailscale && tailscale version 2>&1 | head -1", timeout=10)
    log.append(f"Installed: {out}")
    if rc != 0:
        return False, "Tailscale binary not found after install", "\n".join(log)

    return True, "Tailscale installed successfully", "\n".join(log)


def remote_tailscale_up_url(server, enable_ssh=True, advertise_routes=""):
    """Run `tailscale up` (no auth key) in the background and return the browser
    login URL — the user just pastes it into their browser to authorize the node,
    exactly like `tailscale up` on the CLI. tailscale up keeps waiting for auth."""
    up = "tailscale up --accept-routes --timeout=600s"
    if enable_ssh:
        up += " --ssh"
    if advertise_routes:
        up += f" --advertise-routes={_quote(advertise_routes)}"
    if advertise_routes:
        run_command(server,
            "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-tailscale.conf && "
            "sysctl -p /etc/sysctl.d/99-tailscale.conf 2>&1", timeout=15, sudo=True)
    # Start tailscale up detached; poll its log for the login URL (appears quickly).
    cmd = (
        "rm -f /tmp/tsup.log ; "
        f"nohup {up} > /tmp/tsup.log 2>&1 & "
        "for i in $(seq 1 20); do "
        "u=$(grep -oE 'https://login\\.tailscale\\.com/[A-Za-z0-9/]+' /tmp/tsup.log | head -1) ; "
        "[ -n \"$u\" ] && { echo \"$u\" ; break ; } ; "
        "grep -qi 'success' /tmp/tsup.log && { echo ALREADY_CONNECTED ; break ; } ; "
        "sleep 1 ; done"
    )
    out, err, rc = run_command(server, cmd, timeout=40, sudo=True)
    line = (out or "").strip().split("\n")[-1].strip() if out else ""
    if line.startswith("https://login.tailscale.com/"):
        return True, line
    status = remote_check_tailscale(server)
    if status.get("running") or line == "ALREADY_CONNECTED":
        return True, "ALREADY_CONNECTED"
    return False, (err or out or "Could not get a Tailscale login link — is Tailscale installed on the remote?")


def remote_bootstrap_tailscale(server, auth_key="", enable_ssh=True, advertise_routes="", tags=""):
    """Authenticate and configure Tailscale on a remote VPS.
    Args:
        auth_key: Tailscale pre-auth key (required for headless setup)
        enable_ssh: Whether to enable Tailscale SSH
        advertise_routes: subnet routes to advertise (e.g. "192.168.1.0/24")
        tags: Comma-separated ACL tags (e.g. "tag:server,tag:lgsm")
    Returns:
        (success, message, full_log)
    """
    log = []

    if not auth_key:
        return False, "Auth key is required. Generate one at https://login.tailscale.com/admin/keys", "\n".join(log)

    # 1. Enable IP forwarding for subnet routing
    if advertise_routes:
        run_command(server,
            "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-tailscale.conf && "
            "echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-tailscale.conf && "
            "sysctl -p /etc/sysctl.d/99-tailscale.conf 2>&1",
            timeout=15, sudo=True
        )
        log.append("IP forwarding enabled")

    # 2. Build the up command. auth_key / advertise_routes / tags are user-supplied and run
    # in a root shell, so every one is shell-quoted to prevent command injection.
    up_cmd = f"tailscale up --auth-key {_quote(auth_key)} --accept-routes"
    if enable_ssh:
        up_cmd += " --ssh"
    if advertise_routes:
        up_cmd += f" --advertise-routes={_quote(advertise_routes)}"
    if tags:
        up_cmd += f" --advertise-tags={_quote(tags)}"

    out, err, rc = run_command(server, up_cmd, timeout=60, sudo=True)
    log.append(f"tailscale up: {out[-300:] if out else ''}")
    if rc != 0:
        return False, f"Tailscale auth failed: {err or out[-200:]}", "\n".join(log)

    # 3. Enable UFW for Tailscale if UFW is active
    ufw_out, _, ufw_rc = run_command(server, "ufw status 2>&1 | grep -q active && echo 'ACTIVE' || echo 'INACTIVE'", timeout=10, sudo=True)
    if "INACTIVE" not in ufw_out:  # "ACTIVE" is a substring of "INACTIVE"
        run_command(server, "ufw allow in on tailscale0 2>&1", timeout=15, sudo=True)
        log.append("UFW: allowed tailscale0 interface")

    # 4. Get status
    status = remote_check_tailscale(server)
    log.append(f"Status: ip={status['tailscale_ip']} dns={status['dns_name']}")

    if status["running"]:
        return True, f"Tailscale connected! IP: {status['tailscale_ip']} DNS: {status['dns_name']}", "\n".join(log)
    else:
        return False, "Tailscale installed but not running after auth", "\n".join(log)


def remote_migrate_to_tailscale(server, new_auth_method="tailscale"):
    """After Tailscale is bootstrapped on a remote, update the local RemoteServer
    record to use Tailscale SSH instead of raw SSH. Also closes port 22 on UFW
    since we've verified the tailscale0 interface is allowed.
    This is done via the caller, not here, since we need the DB session.
    Returns the new host IP/hostname to use.
    """
    status = remote_check_tailscale(server)
    if not status["running"]:
        return None, "Tailscale is not running on the remote"
    # Prefer MagicDNS name, fall back to Tailscale IP
    new_host = status["dns_name"] or status["tailscale_ip"].split(", ")[0] if status["tailscale_ip"] else server.host

    # Safely close port 22 on UFW since tailscale0 is already allowed
    try:
        remote_ufw_close_port_22(server)
    except Exception:
        _log.debug("Non-fatal — might already be removed", exc_info=True)

    return new_host, status


def remote_tailscale_finalize(server):
    """Run right after a node joins the tailnet (login-URL flow): ensure the
    tailscale0 interface is allowed through UFW so tailnet traffic and Tailscale
    SSH are never blocked. Idempotent. Returns (status_dict, log)."""
    log = []
    ufw_out, _, _ = run_command(
        server, "ufw status 2>&1 | grep -q active && echo ACTIVE || echo INACTIVE",
        timeout=10, sudo=True,
    )
    if "INACTIVE" not in ufw_out:  # "ACTIVE" is a substring of "INACTIVE"
        run_command(server, "ufw allow in on tailscale0 2>&1", timeout=15, sudo=True)
        log.append("UFW: allowed tailscale0 interface (in)")
    status = remote_check_tailscale(server)
    return status, "\n".join(log)


def remote_ufw_close_port_22(server):
    """Remove port 22/tcp UFW rule (safe if Tailscale SSH is active)."""
    out, err, rc = run_command(server, "ufw delete allow 22/tcp 2>&1", timeout=15, sudo=True)
    if rc == 0:
        return True, "Port 22 rule removed from UFW"
    return False, err or out or "Failed to remove port 22"


def _sshd_current_ports(server):
    """The ports sshd currently listens on (from its *effective* config). Empty on failure."""
    out, _, _ = run_command(server, "sshd -T 2>/dev/null | awk 'tolower($1)==\"port\"{print $2}'",
                            timeout=15, sudo=True)
    return [p for p in (out or "").split() if p.isdigit()]


def _valid_ip(s):
    """True if `s` is a valid IPv4 or IPv6 literal."""
    import ipaddress
    try:
        ipaddress.ip_address(str(s).strip())
        return True
    except ValueError:
        return False


_F2B_JAIL_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def remote_fail2ban_overview(server):
    """fail2ban jails + their current bans on a REMOTE host, over SSH. Mirrors the panel-host version
    but runs fail2ban-client on the remote. {'installed': bool, 'jails': [detail,...]}."""
    import shlex
    have, _, _ = run_command(server, "command -v fail2ban-client >/dev/null 2>&1 && echo yes || echo no", timeout=15)
    if "yes" not in (have or ""):
        return {"installed": False, "jails": []}
    out, _, _ = run_command(server, "fail2ban-client status 2>/dev/null", timeout=15, sudo=True)
    m = re.search(r"Jail list:\s*(.*)", out or "")
    jails = [j.strip() for j in (m.group(1).split(",") if m else []) if _F2B_JAIL_RE.match(j.strip())]
    details = []
    for jail in jails:
        jo, _, jrc = run_command(server, "fail2ban-client status %s 2>/dev/null" % shlex.quote(jail),
                                 timeout=15, sudo=True)
        if jrc != 0 or not jo:
            continue

        def _num(label):
            mm = re.search(label + r":\s*(\d+)", jo)
            return int(mm.group(1)) if mm else 0
        mi = re.search(r"Banned IP list:\s*(.*)", jo)
        ips = [ip for ip in (mi.group(1).split() if mi else []) if ip]
        details.append({"jail": jail, "currently_banned": _num("Currently banned"),
                        "total_banned": _num("Total banned"), "total_failed": _num("Total failed"),
                        "banned_ips": ips})
    return {"installed": True, "jails": details}


# Default UFW comment tag so the panel recognises its OWN deny rules. The rolling-auto-block tag
# ("panel-autoblock") is passed in by the caller (app.py) when it reconciles.
_UFW_BLOCK_TAG = "panel-block"          # a one-off manual block


def remote_ufw_deny_ip(server, ip, tag=_UFW_BLOCK_TAG):
    """Firewall-block an IP on ALL ports via a UFW deny rule, inserted at the top so it beats any
    allow, and tagged in the rule comment so the panel recognises its own blocks. The IP is reparsed
    to its canonical ipaddress form so nothing request-supplied reaches the shell unchecked. (ok, msg)."""
    import ipaddress
    try:
        ip = str(ipaddress.ip_address((ip or "").strip()))
    except (ValueError, TypeError):
        return False, "Invalid IP address."
    tag = re.sub(r"[^a-z0-9-]", "", (tag or ""))[:32] or _UFW_BLOCK_TAG
    # Drop any existing deny for this IP first (no duplicate rules), then insert at position 1.
    # run_command wraps the whole compound in `sudo bash -c`, so both parts run as root and rc is
    # the insert's exit status.
    out, err, rc = run_command(server, "ufw delete deny from %s >/dev/null 2>&1; "
                        "ufw insert 1 deny from %s comment %s 2>&1"
                % (_quote(ip), _quote(ip), _quote(tag)), timeout=20, sudo=True)
    if rc == 0:
        return True, "Blocked %s (all ports)." % ip
    return False, ((out or err or "Block failed").replace("\n", " ")[:200])


def remote_ufw_undeny_ip(server, ip):
    """Remove a UFW deny rule for an IP (canonicalised first). (ok, msg)."""
    import ipaddress
    try:
        ip = str(ipaddress.ip_address((ip or "").strip()))
    except (ValueError, TypeError):
        return False, "Invalid IP address."
    run_command(server, "ufw delete deny from %s 2>&1" % _quote(ip), timeout=15, sudo=True)
    return True, "Unblocked %s." % ip


def remote_ufw_blocked_ips(server):
    """{ip: tag} for the panel's own UFW deny rules — tag read from the rule comment. Best-effort."""
    out, _, _ = run_command(server, "ufw status 2>/dev/null", timeout=15, sudo=True)
    blocked = {}
    for line in (out or "").splitlines():
        if "DENY" not in line or "panel-" not in line:
            continue
        mi = re.search(r"DENY(?:\s+IN)?\s+([0-9a-fA-F:.]+)", line)
        mt = re.search(r"#\s*(panel-[a-z-]+)", line)
        if mi and mt:
            blocked[mi.group(1)] = mt.group(1)
    return blocked


def remote_fail2ban_top_ips(server, limit=20, days=7):
    """Top offending IPs from a REMOTE host's fail2ban log over the last `days` days (current +
    rotated logs), ranked by detected attempts. Each: {ip, attempts, bans, banned_now, blocked}.
    Fixed counting pipeline (no request input in the shell). Best-effort ([] on failure)."""
    from datetime import datetime, timedelta
    try:
        limit = max(1, min(int(limit or 20), 100))
    except (TypeError, ValueError):
        limit = 20
    try:
        days = max(1, min(int(days or 7), 90))
    except (TypeError, ValueError):
        days = 7
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")   # panel clock; no shell input
    pipeline = (
        "zcat -f /var/log/fail2ban.log* 2>/dev/null | "
        "awk -v c='%s' '$1 >= c' | "
        "grep -oE '\\[[A-Za-z0-9._-]+\\] (Ban|Found) [0-9a-fA-F:.]+' | "
        "awk '{jail=$1; gsub(/[][]/,\"\",jail); a=$(NF-1); ip=$NF; "
        "if(a==\"Found\") f[ip]++; else if(a==\"Ban\") b[ip]++; s[ip]=1; "
        "k=ip\"|\"jail; if(!(k in js)){js[k]=1; jl[ip]=jl[ip](jl[ip]==\"\"?\"\":\",\")jail}} "
        "END{for(ip in s) print (f[ip]+0)\"\\t\"(b[ip]+0)\"\\t\"ip\"\\t\"jl[ip]}' | "
        "sort -rn | head -%d" % (cutoff, limit)
    )
    out, _, _ = run_command(server, pipeline, timeout=25, sudo=True)
    banned = set()
    try:
        for j in remote_fail2ban_overview(server).get("jails", []):
            banned.update(j.get("banned_ips", []))
    except Exception:
        _log.debug("remote top-ips: couldn't read current bans", exc_info=True)
    try:
        blocked = remote_ufw_blocked_ips(server)
    except Exception:
        _log.debug("remote top-ips: couldn't read ufw blocks", exc_info=True)
        blocked = {}
    rows = []
    for line in (out or "").splitlines():
        p = line.split("\t")
        if len(p) >= 3 and p[2].strip():
            ip = p[2].strip()
            jails = [j for j in (p[3].split(",") if len(p) > 3 and p[3] else []) if j]
            rows.append({"ip": ip,
                         "attempts": int(p[0]) if p[0].isdigit() else 0,
                         "bans": int(p[1]) if p[1].isdigit() else 0,
                         "banned_now": ip in banned,
                         "blocked": ip in blocked,
                         "jails": jails})
    return rows


def remote_fail2ban_unban(server, jail, ip):
    """Lift a fail2ban ban on a REMOTE host (jail + IP validated). (ok, msg)."""
    import shlex
    if not _F2B_JAIL_RE.match(jail or ""):
        return False, "Invalid jail name."
    ip = (ip or "").strip()
    if not _valid_ip(ip):
        return False, "Invalid IP address."
    out, err, rc = run_command(server, "fail2ban-client set %s unbanip %s 2>&1"
                               % (shlex.quote(jail), shlex.quote(ip)), timeout=20, sudo=True)
    if rc == 0:
        return True, "Unbanned %s from %s." % (ip, jail)
    return False, ((out or err or "Unban failed").replace("\n", " ")[:200])


def _f2b_dropin_ignoreip_body(ignore_ips):
    """A fail2ban `[DEFAULT] ignoreip` drop-in body built from validated entries only (localhost is
    always included). Every entry is re-parsed through ipaddress, so a non-IP token can never reach
    the file."""
    import ipaddress
    entries = ["127.0.0.1/8", "::1"]
    for raw in (ignore_ips or []):
        s = (str(raw) or "").strip()
        try:
            entries.append(str(ipaddress.ip_network(s, strict=False)) if "/" in s
                           else str(ipaddress.ip_address(s)))
        except ValueError:
            continue
    seen, uniq = set(), []
    for e in entries:
        if e not in seen:
            seen.add(e)
            uniq.append(e)
    return "[DEFAULT]\nignoreip = %s\n" % " ".join(uniq)


_F2B_PANEL_WHITELIST_DROPIN = "/etc/fail2ban/jail.d/zz-panel-whitelist.local"


def remote_set_fail2ban_ignoreip(server, ignore_ips, unban_ip=None):
    """Make a REMOTE host's fail2ban ignore the panel whitelist, so a whitelisted IP is never banned
    on ANY of that host's jails (sshd included) — the remote counterpart of the panel's own
    ignoreip. Writes a dedicated panel-owned drop-in (`jail.d/zz-panel-whitelist.local`) — its own
    file, so it never clobbers the host's existing config — and reloads. Optionally lifts one IP that
    is already banned (used when whitelisting). No-op if fail2ban isn't installed. (ok, msg)."""
    have, _, _ = run_command(server, "command -v fail2ban-client >/dev/null 2>&1 && echo yes || echo no", timeout=10)
    if "yes" not in (have or ""):
        return False, "fail2ban not installed on this host"
    import base64
    b64 = base64.b64encode(_f2b_dropin_ignoreip_body(ignore_ips).encode()).decode()
    run_command(server, f"echo '{b64}' | base64 -d > {_quote(_F2B_PANEL_WHITELIST_DROPIN)}", timeout=15, sudo=True)
    run_command(server, "fail2ban-client reload 2>&1 || systemctl reload fail2ban 2>&1 || "
                        "systemctl restart fail2ban 2>&1", timeout=30, sudo=True)
    # ignoreip only stops FUTURE bans; lift a current ban across every jail so a just-whitelisted
    # admin isn't left banned until it expires. `$J` is a jail name from fail2ban's own output.
    if unban_ip and _valid_ip(unban_ip):
        run_command(server, "for J in $(fail2ban-client status 2>/dev/null | "
                            "sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do "
                            "fail2ban-client set \"$J\" unbanip %s 2>/dev/null; done" % _quote(unban_ip),
                    timeout=30, sudo=True)
    return True, "ignoreip applied on %s" % getattr(server, "name", "remote")


def remote_security_log(server, which, lines=200, jail=None):
    """Tail of a whitelisted security log on a REMOTE host: 'fail2ban' or 'ssh'. `which` is a fixed
    set, never a path from the request. For 'fail2ban', an optional charset-validated `jail` narrows
    the activity to that one jail. Returns text."""
    lines = max(20, min(int(lines or 200), 1000))
    if which == "fail2ban":
        # /var/log/fail2ban.log holds the real Ban/Unban/Found activity (journalctl only has the
        # unit's start/stop noise), so read the file first and fall back to the journal.
        out, _, _ = run_command(server, "tail -n 4000 /var/log/fail2ban.log 2>/dev/null", timeout=20, sudo=True)
        if not out:
            out, _, _ = run_command(server, "journalctl -u fail2ban --no-pager -n 4000 2>/dev/null",
                                    timeout=20, sudo=True)
        rows = (out or "").splitlines()
        if jail and _F2B_JAIL_RE.match(jail):   # charset-only guard; used solely for in-Python filtering
            tag = "[%s]" % jail
            rows = [ln for ln in rows if tag in ln]
        return "\n".join(rows[-lines:])
    if which == "ssh":
        out, _, _ = run_command(server, "journalctl -u ssh -u sshd --no-pager -n %d 2>/dev/null || "
                                "tail -n %d /var/log/auth.log 2>/dev/null" % (lines * 2, lines),
                                timeout=20, sudo=True)
        return "\n".join((out or "").splitlines()[-lines:])
    return ""


def _tcp_reachable(host, port, timeout=8):
    """Whether the panel can open a TCP connection to host:port — used to confirm it won't lose its
    way in before committing an SSH bind-address change. Best-effort; False on any error."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def change_ssh_port(server, new_port, bind_addr=""):
    """Move this host's sshd onto `new_port`, optionally restricting it to a single `bind_addr` IP
    (for hosts with several IPs), WITHOUT risking a lockout.

    Port-only change: every current port stays open on all interfaces the whole time, so a bad new
    port can't cut the panel off — we open the new port in UFW, add it (alongside the old ones) via
    an sshd drop-in, validate with `sshd -t`, repoint fail2ban's [sshd] jail, restart sshd and
    confirm the new port is listening (reverting if not).

    Bind-address change: sshd's ListenAddress is all-or-nothing (once set, sshd listens ONLY on the
    given addresses), so the always-open fallback doesn't apply. Instead we snapshot the current
    drop-in, apply the binding, restart, and verify the panel can still REACH SSH on the host —
    reverting to the snapshot if it can't. So a bind address that would cut the panel off is rolled
    back automatically; the operator must include the address the panel connects on.

    Works for a remote (over SSH) and the panel host itself. Returns (ok, message)."""
    try:
        new_port = int(new_port)
    except (TypeError, ValueError):
        return False, "Enter a valid port number."
    if not (1 <= new_port <= 65535):
        return False, "Port must be between 1 and 65535."
    bind_addr = (str(bind_addr) if bind_addr else "").strip()
    if bind_addr and not _valid_ip(bind_addr):
        return False, "Bind address must be a valid IP address, or blank for all interfaces."

    old_ports = _sshd_current_ports(server) or [str(int(getattr(server, "port", 22) or 22))]
    if not bind_addr and old_ports == [str(new_port)]:
        return False, "SSH is already on port %d." % new_port

    # Keep every current port plus the new one (new first).
    ports = []
    for p in [str(new_port)] + old_ports:
        if p not in ports:
            ports.append(p)

    # 1. Open the new port in the firewall FIRST (best-effort; a host without UFW just no-ops).
    remote_ufw_open_port(server, new_port, "tcp", comment="SSH (panel)")

    # 2. Snapshot any existing drop-in (so a failed bind change restores the EXACT prior state),
    #    then write the new one. Ubuntu 22.04/24.04 Include /etc/ssh/sshd_config.d/*.conf by default.
    import base64
    dropin = "/etc/ssh/sshd_config.d/99-panel-sshport.conf"
    bak = dropin + ".bak"
    run_command(server, f"[ -f {_quote(dropin)} ] && cp -f {_quote(dropin)} {_quote(bak)} || true",
                timeout=10, sudo=True)
    header = ("# Managed by LinuxGSM Panel. The previous SSH port is kept as a fallback; close it\n"
              "# from the panel's Firewall page once you've confirmed the new port works.\n")
    if bind_addr:
        # sshd needs an IPv6 literal bracketed when a port follows: ListenAddress [::1]:22.
        _a = "[%s]" % bind_addr if ":" in bind_addr else bind_addr
        body = "".join("ListenAddress %s:%s\n" % (_a, p) for p in ports)
    else:
        body = "".join("Port %s\n" % p for p in ports)
    b64 = base64.b64encode((header + body).encode()).decode()
    run_command(server, f"echo '{b64}' | base64 -d > {_quote(dropin)}", timeout=15, sudo=True)

    def _revert(msg):
        # Restore the snapshot if we took one, else drop the file, then restart sshd. The prior
        # binding is untouched the whole time, so SSH keeps working.
        run_command(server,
                    f"if [ -f {_quote(bak)} ]; then mv -f {_quote(bak)} {_quote(dropin)}; "
                    f"else rm -f {_quote(dropin)}; fi",
                    timeout=10, sudo=True)
        run_command(server, "systemctl restart ssh 2>&1 || systemctl restart sshd 2>&1", timeout=20, sudo=True)
        return False, msg

    # 3. Validate the WHOLE sshd config; if the drop-in breaks it, roll back and abort (no restart).
    _, terr, trc = run_command(server, "sshd -t 2>&1", timeout=15, sudo=True)
    if trc != 0:
        return _revert("sshd rejected the new config — nothing changed. (%s)" % ((terr or "invalid")[:120]))

    # 4. Point fail2ban's [sshd] jail at the new + old ports so its bans target the right port.
    f2b_ports = ",".join(ports)
    run_command(server,
                "if [ -f /etc/fail2ban/jail.local ]; then "
                f"sed -i '/^\\[sshd\\]/,/^\\[/{{s/^port *=.*/port = {f2b_ports}/}}' /etc/fail2ban/jail.local; "
                "systemctl restart fail2ban 2>&1 || true; fi",
                timeout=20, sudo=True)

    # 5. Restart sshd (Ubuntu's unit is 'ssh'; fall back to 'sshd'). Established sessions survive.
    run_command(server, "systemctl restart ssh 2>&1 || systemctl restart sshd 2>&1", timeout=20, sudo=True)

    # 6. Verify. A bind change must confirm the panel can still REACH the host (no all-interfaces
    #    fallback); a port-only change just confirms sshd bound the new port.
    if bind_addr and not is_local_server(server):
        if not _tcp_reachable(server.host, new_port, timeout=8):
            return _revert("After binding SSH to %s, the panel couldn't reach it on %s:%d — reverted. "
                           "The bind address has to be the one the panel connects to."
                           % (bind_addr, server.host, new_port))
    else:
        out, _, _ = run_command(
            server, f"ss -lnt 2>/dev/null | grep -qE '[:.]{new_port}[[:space:]]' && echo OK || echo NO",
            timeout=15, sudo=True)
        if "OK" not in (out or ""):
            return _revert("sshd didn't come up on port %d — reverted. Your existing SSH still works." % new_port)

    run_command(server, f"rm -f {_quote(bak)}", timeout=10, sudo=True)   # success — drop the snapshot
    where = (" on %s" % bind_addr) if bind_addr else ""
    return True, ("SSH now listens on port %d%s (firewall + fail2ban updated). The previous port is "
                  "still available as a fallback — once you've confirmed you can reach SSH on %d, "
                  "close the old one from the Firewall page." % (new_port, where, new_port))


def remote_public_ssh_status(server, panel_port=None):
    """Report public SSH state on port 22: 'allow', 'limit', or 'off' (no rule —
    reachable only over tailscale0), plus whether UFW is active at all. When
    `panel_port` is given, also report whether that port has a public ALLOW rule
    (`panel_port_open`) so the UI can disable "Close public panel port" once it's
    already closed."""
    out, _, _ = run_command(server, "ufw status 2>&1", timeout=12, sudo=True)
    active = "Status: active" in (out or "")
    mode = "off"
    panel_open = False
    port_re = re.compile(r"\b%d\b" % int(panel_port)) if panel_port else None
    for line in (out or "").splitlines():
        low = line.lower()
        if ("22/tcp" in low or "openssh" in low) and " (v6)" not in low:
            if "limit" in low:
                mode = "limit"
            elif "allow" in low:
                mode = "allow" if mode != "limit" else mode
        # A public ALLOW rule for the panel port (ignore IPv6 duplicates and the
        # tailscale0 interface rule, which isn't the *public* port).
        if (port_re and "allow" in low and " (v6)" not in low
                and "tailscale" not in low and port_re.search(line)):
            panel_open = True
    res = {"active": active, "mode": mode}
    if panel_port:
        res["panel_port"] = int(panel_port)
        res["panel_port_open"] = panel_open
    return res


def _tailscale_conn_state(server):
    """(running, ssh_enabled) — whether Tailscale is up on this host and advertises its
    SSH server. Tailscale SSH works regardless of UFW, so when it's on the host always
    has a way in. Best-effort; fails safe to (False, False)."""
    import json as _json
    running = ssh_enabled = False
    try:
        out, _, _ = run_command(server, "tailscale status --json 2>/dev/null || echo '{}'", timeout=10)
        running = _json.loads(out or "{}").get("BackendState") == "Running"
    except Exception:
        running = False   # can't confirm → treat as not running (fail safe)
    if running:
        try:  # authoritative: prefs RunSSH
            out, _, _ = run_command(server, "tailscale debug prefs 2>/dev/null || echo '{}'", timeout=10)
            ssh_enabled = bool(_json.loads(out or "{}").get("RunSSH", False))
        except Exception:
            ssh_enabled = False   # fail safe
    return running, ssh_enabled


# Tailscale peers get CGNAT addresses from 100.64.0.0/10. A public attacker can't have a source in
# that range, so the panel never firewall-blocks a tailnet IP while Tailscale is up — blocking one
# would cut off tailnet access (and, inserted at UFW position 1, it would override the tailscale0
# allow rule).
_TAILNET_CGNAT = "100.64.0.0/10"


def tailnet_exempt_ips(server, ips):
    """Of `ips`, the Tailscale-range (100.64.0.0/10) addresses that must NOT be firewall-blocked —
    but only when Tailscale is actually running on this host. Returns a set of canonical IP strings
    (empty if Tailscale is down or nothing is in range). Works for local + remote (run_command
    dispatches). Best-effort; fails safe to no exemptions."""
    import ipaddress
    try:
        net = ipaddress.ip_network(_TAILNET_CGNAT)
    except ValueError:
        return set()
    cand = set()
    for ip in ips or ():
        try:
            addr = ipaddress.ip_address((ip or "").strip())
        except (ValueError, TypeError):
            continue
        if addr in net:
            cand.add(str(addr))
    if not cand:
        return set()   # nothing in the tailnet range → skip the (relatively costly) tailscale probe
    try:
        return cand if _tailscale_conn_state(server)[0] else set()
    except Exception:
        return set()   # can't confirm Tailscale → don't exempt


def _tailnet_ssh_state(server):
    """(running, ssh_enabled, iface_allowed) — the inputs to deciding whether removing
    public SSH is safe. iface_allowed = the tailscale0 interface is allowed in UFW (so
    sshd is reachable over the tailnet). Works for local + remote hosts; fails safe."""
    running, ssh_enabled = _tailscale_conn_state(server)
    iface_allowed = False
    if running:
        try:  # tailscale interface allowed in UFW → sshd is reachable over the tailnet
            out, _, _ = run_command(server, "ufw status verbose 2>/dev/null | grep -i tailscale || true",
                                    timeout=12, sudo=True)
            iface_allowed = bool((out or "").strip())
        except Exception:
            iface_allowed = False   # fail safe
    return running, ssh_enabled, iface_allowed


def remote_set_public_ssh(server, mode):
    """Control PUBLIC (non-tailnet) SSH on port 22 via UFW:
      allow → `ufw allow 22/tcp`  (open to the internet)
      limit → `ufw limit 22/tcp`  (rate-limited brute-force protection; recommended)
      off   → remove the allow/limit rules (SSH only via the tailscale0 interface)
    tailscale0 SSH is unaffected either way. `off` is REFUSED unless there is a working
    Tailscale path back in (Tailscale running + SSH enabled or the tailscale0 interface
    allowed in UFW) — otherwise it would strand you with no way to reach the host."""
    mode = (mode or "").lower()
    if mode == "allow":
        cmds = ["ufw delete limit 22/tcp", "ufw allow 22/tcp"]
    elif mode == "limit":
        cmds = ["ufw delete allow 22/tcp", "ufw limit 22/tcp"]
    elif mode == "off":
        running, ssh_enabled, iface_allowed = _tailnet_ssh_state(server)
        if not (running and (ssh_enabled or iface_allowed)):
            return False, ("Refused — there's no Tailscale way back into this host, so disabling "
                           "public SSH would lock you out. Enable Tailscale SSH, or make sure "
                           "Tailscale is running and the tailscale0 interface is allowed in UFW, first.")
        cmds = ["ufw delete allow 22/tcp", "ufw delete limit 22/tcp", "ufw delete allow OpenSSH"]
    else:
        return False, "Invalid mode"
    for c in cmds:
        run_command(server, f"{c} 2>&1", timeout=15, sudo=True)  # deletes of absent rules are harmless
    labels = {"allow": "open (allow)", "limit": "rate-limited", "off": "disabled (tailnet-only)"}
    return True, f"Public SSH is now {labels[mode]}"


def ssh_test_connection(host, port=22, username="root", auth_method="key", credential=""):
    """Test an SSH connection and return (success, message)."""
    # Tailscale SSH must use the system ssh client (tailscaled handles auth).
    if auth_method == "tailscale":
        class _S:
            pass
        s = _S()
        s.host, s.port, s.username = host, port, username
        s.auth_method, s.linuxgsm_user, s.sudo_enabled = "tailscale", "", False
        out, err, rc = _run_via_ssh_cli(s, "echo ok && whoami", timeout=15, sudo=False)
        if rc == 0:
            return True, "Tailscale SSH connection successful"
        low = (err or "").lower()
        if "permission denied" in low:
            return False, "Tailscale SSH denied — check the tailnet ACL allows SSH to this node/user."
        if "timed out" in low or "timeout" in low:
            return False, f"Timed out reaching {host} over Tailscale. Is the node online?"
        return False, f"Tailscale SSH failed: {(err or out or 'unknown')[:150]}"

    client = paramiko.SSHClient()
    # Pre-save connectivity probe: nothing to compare against yet, so capture-only (no
    # AutoAddPolicy). The key gets pinned for real on the first operational connection.
    client.set_missing_host_key_policy(_PinPolicy(reject_on_change=False))
    try:
        if auth_method == "password" and credential:
            client.connect(
                host, port=port, username=username,
                password=credential, timeout=10,
                allow_agent=False, look_for_keys=False,
            )
        else:
            key_path = credential or os.path.expanduser("~/.ssh/id_rsa")
            client.connect(
                host, port=port, username=username,
                key_filename=key_path, timeout=10,
            )
        client.close()
        return True, "Connection successful"
    except paramiko.AuthenticationException:
        return False, "SSH authentication failed. Check your credentials."
    except socket.timeout:
        return False, f"Connection to {host}:{port} timed out. Is the host reachable?"
    except socket.gaierror:
        return False, f"Cannot resolve hostname: {host}"
    except Exception:
        # Don't surface the raw exception text to the browser — it can carry internal detail
        # (key paths, host internals). Log the full trace server-side (no user-supplied host/port
        # in the message — exc_info already carries the detail), show a generic message.
        _log.warning("ssh_test_connection failed", exc_info=True)
        return False, "Connection failed. Check the host, port, credentials, and that SSH is reachable."


# ── LinuxGSM config + file management ──────────────────────────
# All operations run AS THE GAME USER (`sudo -u <user>`) and are confined to that
# user's home dir, so they can never touch the panel host or other accounts.
import posixpath as _pp

# Curated "common settings" surfaced as a form (only those present in the game's
# _default.cfg are shown). Everything else is editable via the raw config editor.
_COMMON_CFG_KEYS = [
    ("servername", "Server name"), ("hostname", "Hostname"),
    ("ip", "Bind IP"), ("port", "Game port"), ("queryport", "Query port"),
    ("clientport", "Client port"), ("rconport", "RCON port"),
    ("maxplayers", "Max players"), ("slots", "Slots"), ("maxclients", "Max clients"),
    ("defaultmap", "Default map"), ("map", "Map"), ("gamemode", "Game mode"),
    ("gametype", "Game type"), ("tickrate", "Tickrate"),
    ("serverpassword", "Server password"), ("rconpassword", "RCON password"),
    ("adminpassword", "Admin password"), ("steamuser", "Steam user"),
]
_CFG_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _parse_cfg(text):
    """Parse LinuxGSM-style `key="value"` lines (uncommented only) into a dict."""
    out = {}
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _CFG_LINE_RE.match(line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
                val = val[1:-1]
            out[key] = val
    return out


def _safe_abspath(user, relpath):
    """Resolve a user-supplied relative path under /home/<user>, rejecting any
    traversal outside it. Returns the absolute path or None."""
    home = f"/home/{user}"
    rel = str(relpath) if relpath else ""   # tolerate non-str input without crashing
    ap = _pp.normpath(_pp.join(home, rel.lstrip("/")))
    if ap == home or ap.startswith(home + "/"):
        return ap
    return None


def _write_file_as_user(server, user, abspath, data_bytes):
    """Write bytes to a file as the game user, via chunked base64 (each command
    stays well under the shell's per-arg limit, so large uploads work too)."""
    import base64 as _b64
    b64 = _b64.b64encode(data_bytes).decode()
    tmp = abspath + ".paneltmp"
    # Ensure the parent directory exists (uploads to a fresh folder, new files).
    parent = _pp.dirname(abspath)
    run_command(server, f"sudo -u {user} bash -c {_quote('mkdir -p ' + _quote(parent))}", timeout=15, sudo=False)
    CH = 50000
    op = ">"
    for i in range(0, max(len(b64), 1), CH):
        chunk = b64[i:i + CH]
        inner = f"printf %s {_quote(chunk)} {op} {_quote(tmp)}"
        _, e, rc = run_command(server, f"sudo -u {user} bash -c {_quote(inner)}", timeout=30, sudo=False)
        if rc != 0:
            return False, e or "write failed"
        op = ">>"
    fin = f"base64 -d {_quote(tmp)} > {_quote(abspath)} && rm -f {_quote(tmp)}"
    o, e, rc = run_command(server, f"sudo -u {user} bash -c {_quote(fin)}", timeout=30, sudo=False)
    return (rc == 0), (e or o or "")


def _lgsm_cfg_dir(user, selfname):
    return f"/home/{user}/lgsm/config-lgsm/{selfname}"


def lgsm_read_config(server, user, selfname):
    """Read a game's LinuxGSM config: the curated common settings (merged from
    _default.cfg < common.cfg < instance <selfname>.cfg) plus the raw instance cfg
    text for the advanced editor."""
    d = _lgsm_cfg_dir(user, selfname)
    inst = f"{d}/{selfname}.cfg"
    inner = (f"echo ===DEFAULT; cat {_quote(d + '/_default.cfg')} 2>/dev/null; "
             f"echo ===COMMON; cat {_quote(d + '/common.cfg')} 2>/dev/null; "
             f"echo ===INSTANCE; cat {_quote(inst)} 2>/dev/null")
    out, _, _ = run_command(server, f"sudo -u {user} bash -c {_quote(inner)}", timeout=20, sudo=False)
    sec = {"DEFAULT": [], "COMMON": [], "INSTANCE": []}
    cur = None
    for line in (out or "").splitlines():
        if line in ("===DEFAULT", "===COMMON", "===INSTANCE"):
            cur = line[3:]
            continue
        if cur is not None:
            sec[cur].append(line)
    defaults = _parse_cfg("\n".join(sec["DEFAULT"]))
    common = _parse_cfg("\n".join(sec["COMMON"]))
    instance_text = "\n".join(sec["INSTANCE"])
    instance = _parse_cfg(instance_text)
    merged = dict(defaults); merged.update(common); merged.update(instance)
    # Curated "common" quick list.
    settings = []
    for key, label in _COMMON_CFG_KEYS:
        if key in merged:
            settings.append({
                "key": key, "label": label, "value": merged[key],
                "default": defaults.get(key, ""),
                "overridden": key in instance or key in common,
            })
    # EVERY setting, grouped by _default.cfg's "#### Section ####" headers, so any
    # LinuxGSM setting is editable (not just the curated ones).
    groups = []
    cur = None
    for line in sec["DEFAULT"]:
        h = re.match(r"^#{3,}\s+(.+?)\s+#{3,}\s*$", line.strip())
        if h:
            cur = {"section": h.group(1), "settings": []}
            groups.append(cur)
            continue
        if line.strip().startswith("#"):
            continue
        m = _CFG_LINE_RE.match(line)
        if m:
            key = m.group(1)
            if cur is None:
                cur = {"section": "Server Settings", "settings": []}
                groups.append(cur)
            cur["settings"].append({
                "key": key, "value": merged.get(key, ""),
                "default": defaults.get(key, ""),
                "overridden": key in instance or key in common,
            })
    groups = [g for g in groups if g["settings"]]
    return {"path": inst, "raw": instance_text, "settings": settings, "groups": groups}


def lgsm_game_config(server, user, selfname):
    """Locate and read the game's OWN server config file (e.g. a Source server.cfg
    or cod's serverfiles/main/<name>.cfg) by parsing LinuxGSM `details`. This is the
    file where in-game settings like sv_maxclients actually live for many games.
    Returns {rel, content, exists, error}."""
    o, _, _ = run_command(
        server, f"sudo -u {user} bash -c {_quote(f'cd /home/{user} && ./{selfname} details 2>&1')}",
        timeout=45, sudo=False,
    )
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", o or "")
    home = f"/home/{user}/"
    path = None
    for line in text.splitlines():
        m = re.search(r"config file[^:]*:\s*(/\S+\.cfg)", line, re.I)
        if m:
            path = m.group(1)
            break
    if not path or not path.startswith(home):
        return {"rel": None, "content": "", "exists": False,
                "error": "No editable game config file was reported for this game."}
    rel = path[len(home):]
    content, err = read_file(server, user, rel)
    return {"rel": rel, "content": content or "", "exists": err is None, "error": err}


def lgsm_get_values(server, user, selfname, keys):
    """Return {key: value} for `keys` from the merged LinuxGSM config (_default < common <
    instance — instance wins). Missing keys come back as "". Used by focused editors (alerts)."""
    d = _lgsm_cfg_dir(user, selfname)
    inner = (f"cat {_quote(d + '/_default.cfg')} 2>/dev/null; "
             f"cat {_quote(d + '/common.cfg')} 2>/dev/null; "
             f"cat {_quote(d + '/' + selfname + '.cfg')} 2>/dev/null")
    out, _, _ = run_command(server, f"sudo -u {user} bash -c {_quote(inner)}", timeout=20, sudo=False)
    merged = _parse_cfg(out or "")
    return {k: merged.get(k, "") for k in keys}


def lgsm_write_config(server, user, selfname, updates):
    """Apply key→value updates to the instance <selfname>.cfg (replace an existing
    uncommented line, else append). Other files (_default/common) are left alone."""
    d = _lgsm_cfg_dir(user, selfname)
    inst = f"{d}/{selfname}.cfg"
    out, _, _ = run_command(server, f"sudo -u {user} bash -c {_quote('cat ' + _quote(inst) + ' 2>/dev/null')}", timeout=15, sudo=False)
    lines = (out or "").splitlines()
    for key, val in (updates or {}).items():
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key or ""):
            continue
        val = str(val).replace('"', '\\"').replace("\n", " ")
        newline = f'{key}="{val}"'
        pat = re.compile(r"^\s*" + re.escape(key) + r"\s*=")
        replaced = False
        for i, ln in enumerate(lines):
            if pat.match(ln) and not ln.strip().startswith("#"):
                lines[i] = newline
                replaced = True
                break
        if not replaced:
            lines.append(newline)
    content = "\n".join(lines).rstrip("\n") + "\n"
    return _write_file_as_user(server, user, inst, content.encode())


# --- Mods / addons (LinuxGSM mods-install / mods-remove) --------------------
# LinuxGSM's mods-install/mods-remove print a list of mods and `read` one selection — the mod's
# text id (e.g. "sourcemod"), NOT a number. Typing "abort"/"exit" makes the command print the
# list then exit cleanly, so we list by feeding "abort" and act by feeding the chosen id — via a
# bash here-string. The two lists use DIFFERENT formats (verified on a live Garry's Mod server):
#   mods-install (available): a description line, then a " * <id>" line under it.
#   mods-remove  (installed):  one line per mod, "<id> - <name> - <desc>".
_MOD_AVAIL_RE = re.compile(r"^\s*\*\s+(\S+)\s*$")               # available: " * <id>"
_MOD_INST_RE = re.compile(r"^([A-Za-z0-9._-]+)\s+-\s+(.+)$")    # installed: "<id> - <name> - …"
_MOD_ID_OK = re.compile(r"^[A-Za-z0-9._-]+$")                   # safe id charset (guards here-string)


def _strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", s or "")


def _parse_mods_available(out):
    """Parse the mods-install list: id is on a ' * <id>' line, name from the description line above.

    LinuxGSM prints TWO sections: an 'Installed addons/mods' block of bare ' * <id>' lines (already
    installed, NO description above them) and then 'Available addons/mods' where each ' * <id>' is
    preceded by a 'Name - desc - url' line. Only the Available block carries real, named entries — the
    Installed block's ids would otherwise be emitted named after the section header ('Installed
    addons/mods') AND duplicate the real Available rows, so we skip that section and de-dupe by id."""
    mods = []
    prev = ""
    in_installed = False
    seen = set()
    for raw in (out or "").splitlines():
        line = _strip_ansi(raw).rstrip()
        low = line.strip().lower()
        if low == "installed addons/mods":   # enter the skip section (its ' * <id>' lines have no name)
            in_installed, prev = True, ""
            continue
        if low == "available addons/mods":    # back to the real, described list
            in_installed, prev = False, ""
            continue
        m = _MOD_AVAIL_RE.match(line)
        if m and _MOD_ID_OK.match(m.group(1)):
            mod_id = m.group(1)
            if not in_installed and mod_id not in seen:
                seen.add(mod_id)
                name = prev.split(" - ")[0].strip() if prev else mod_id
                mods.append({"id": mod_id, "name": name or mod_id, "desc": prev})
        else:
            t = line.strip()
            if t and set(t) != {"="}:   # remember the latest real description line, skip === rules
                prev = t
    return mods


def _game_supports_mods(text):
    """False for games with no LinuxGSM mods installer (e.g. cod): running mods-install/-remove
    on them prints 'Error! Unknown command' followed by a usage banner ('LinuxGSM - <Game> -
    Version v…') that would otherwise be misparsed as an installed mod."""
    return "unknown command" not in (text or "").lower()


def _parse_mods_installed(out):
    """Parse the mods-remove list: one '<id> - <name> - <desc>' line per installed mod."""
    mods = []
    for raw in (out or "").splitlines():
        m = _MOD_INST_RE.match(_strip_ansi(raw).strip())
        if m and m.group(1) != "LinuxGSM":   # skip the 'LinuxGSM - <Game> - Version …' banner line
            name = m.group(2).split(" - ")[0].strip()
            mods.append({"id": m.group(1), "name": name or m.group(1), "desc": m.group(2)})
    return mods


def mods_available(server, user, selfname, timeout=60):
    """Returns (available_mods, supported). `supported` is False for games with no LinuxGSM mods
    installer (e.g. cod), where mods-install answers 'Unknown command' — so the UI can hide the
    whole card rather than show an empty one."""
    out, err, _ = run_as_game_user(server, user, 'mods-install <<< "abort"', timeout=timeout, selfname=selfname)
    text = (out or "") + "\n" + (err or "")
    supported = _game_supports_mods(text)
    return (_parse_mods_available(text) if supported else []), supported


def mods_installed(server, user, selfname, timeout=60):
    """Returns (installed_mods, supported). See mods_available for `supported`."""
    out, err, _ = run_as_game_user(server, user, 'mods-remove <<< "abort"', timeout=timeout, selfname=selfname)
    text = (out or "") + "\n" + (err or "")
    supported = _game_supports_mods(text)
    return (_parse_mods_installed(text) if supported else []), supported


def mods_action(server, user, selfname, which, mod_id, timeout=600):
    """Install or remove a mod by its LinuxGSM id (e.g. "sourcemod"). `which` is 'install' or
    'remove'. Returns (out, err, rc). We feed the id then a "Y": mods-remove always asks
    "Continue?" before deleting files, and mods-install asks it too when the mod is already
    installed (both default to Y). The id is validated to a safe charset first, so nothing but a
    bare id + Y is ever fed to the command. Verified install+remove on a live Garry's Mod box."""
    if not _MOD_ID_OK.match(mod_id or ""):
        return "", "invalid mod id", 1
    cmd = "mods-install" if which == "install" else "mods-remove"
    out, err, rc = run_as_game_user(server, user, f"{cmd} <<< $'{mod_id}\\nY'", timeout=timeout, selfname=selfname)
    return out, err, rc


# Files/dirs whose deletion would break LinuxGSM or the game install — protected
# from the file browser's delete (they can still be edited where that makes sense).
def _is_protected_path(relpath, selfname):
    """True if `relpath` (relative to the game user's home) must not be deleted."""
    r = (relpath or "").strip("/")
    if not r:
        return True  # the home dir itself
    parts = r.split("/")
    top = parts[0]
    # The whole LinuxGSM control tree (script data, module cache, configs).
    if top == "lgsm":
        return True
    # Critical top-level entries (deleting these bricks the server or your login).
    if len(parts) == 1 and r in {
        "serverfiles", "linuxgsm.sh", selfname or "",
        ".ssh", ".bashrc", ".profile", ".bash_logout", ".bash_history", ".wget-hsts",
    }:
        return True
    return False


def browse_dir(server, user, relpath="", selfname=None):
    """List a directory in the game user's home (dirs first). Each entry is flagged
    `protected` when deleting it would break LinuxGSM/the game. Returns None on a
    path-traversal attempt."""
    ap = _safe_abspath(user, relpath)
    if ap is None:
        return None
    inner = f"find {_quote(ap)} -maxdepth 1 -mindepth 1 -printf '%y\\t%s\\t%f\\n' 2>/dev/null"
    out, _, _ = run_command(server, f"sudo -u {user} bash -c {_quote(inner)}", timeout=20, sudo=False)
    base = (relpath or "").strip("/")
    entries = []
    for line in (out or "").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            typ, size = parts[0], parts[1]
            name = "\t".join(parts[2:])
            rel = f"{base}/{name}" if base else name
            entries.append({"name": name, "is_dir": typ == "d",
                            "size": int(size) if size.isdigit() else 0,
                            "protected": _is_protected_path(rel, selfname)})
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    return {"path": base, "entries": entries}


def read_file(server, user, relpath, max_bytes=1048576):
    """Read a text file from the game user's home. Returns (content, error).
    Refuses binaries and files larger than max_bytes."""
    ap = _safe_abspath(user, relpath)
    if ap is None:
        return None, "Invalid path"
    inner = (
        f"if [ ! -f {_quote(ap)} ]; then echo __NOFILE__; exit 0; fi; "
        f"sz=$(stat -c %s {_quote(ap)} 2>/dev/null); "
        f"if [ \"$sz\" -gt {int(max_bytes)} ]; then echo __TOOBIG__; exit 0; fi; "
        f"if [ ! -s {_quote(ap)} ] || grep -qI . {_quote(ap)} 2>/dev/null; then cat {_quote(ap)}; else echo __BINARY__; fi"
    )
    out, _, _ = run_command(server, f"sudo -u {user} bash -c {_quote(inner)}", timeout=20, sudo=False)
    stripped = (out or "").strip()
    if stripped == "__NOFILE__":
        return None, "File not found"
    if stripped == "__TOOBIG__":
        return None, "File is too large to edit in the browser"
    if stripped == "__BINARY__":
        return None, "Binary file — download/replace via upload instead"
    return (out or ""), None


def write_file(server, user, relpath, content):
    """Write text content to a file in the game user's home."""
    ap = _safe_abspath(user, relpath)
    if ap is None:
        return False, "Invalid path"
    return _write_file_as_user(server, user, ap, (content or "").encode())


def upload_file(server, user, reldir, filename, data_bytes):
    """Upload a file into a directory in the game user's home."""
    apdir = _safe_abspath(user, reldir)
    if apdir is None:
        return False, "Invalid path"
    fn = _pp.basename((filename or "").replace("\x00", ""))
    if not fn or fn in (".", ".."):
        return False, "Invalid filename"
    target = _pp.join(apdir, fn)
    if not (target.startswith(f"/home/{user}/")):
        return False, "Invalid path"
    return _write_file_as_user(server, user, target, data_bytes)


def delete_path(server, user, relpath, selfname=None):
    """Delete a file or directory (recursively) in the game user's home. Refuses
    the home root, anything outside it, and protected LinuxGSM/game paths."""
    ap = _safe_abspath(user, relpath)
    home = f"/home/{user}"
    if ap is None or ap == home or not (relpath or "").strip("/"):
        return False, "Refusing to delete this path"
    if _is_protected_path(relpath, selfname):
        return False, "This file/folder is protected — deleting it would break the server."
    inner = f"rm -rf -- {_quote(ap)} && echo __OK__"
    out, e, rc = run_command(server, f"sudo -u {user} bash -c {_quote(inner)}", timeout=30, sudo=False)
    if rc == 0 and "__OK__" in (out or ""):
        return True, "Deleted"
    return False, e or out or "Delete failed"


# ── GMod mountable game content ────────────────────────────────────────────────────────────────
# Garry's Mod renders another Source game's maps/props only if that game's content is present AND
# mounted. We keep ONE shared copy per host under a "content user" and mount it read-only into each
# GMod server via garrysmod/cfg/mount.cfg (+ mountdepots.txt), so multiple GMod servers share it
# instead of each carrying gigabytes. Content is fetched with SteamCMD using the game's dedicated-
# content app id. Counter-Strike: Source is the essential one (the vast majority of GMod maps/addons
# expect it); more can be added to this map later.
GMOD_CONTENT_GAMES = {
    # mount-folder -> (label, steamcmd dedicated-content app id or None). A NUMERIC app id means the
    # panel can download it (free anonymous SteamCMD; ids verified against LinuxGSM's own configs).
    # None means MOUNT-ONLY: the game needs a purchased license so SteamCMD can't fetch it anonymously
    # — the panel only mounts it when its content is already on the host (copied from an owned install).
    "cstrike":    ("Counter-Strike: Source", 232330),
    "tf":         ("Team Fortress 2", 232250),
    "dod":        ("Day of Defeat: Source", 232290),
    "hl2mp":      ("Half-Life 2: Deathmatch", 232370),
    "left4dead":  ("Left 4 Dead", 222840),
    "left4dead2": ("Left 4 Dead 2", 222860),
    "hl1":        ("Half-Life: Source", None),
    "hl1mp":      ("Half-Life Deathmatch: Source", None),
    "hl2":        ("Half-Life 2", None),
    "episodic":   ("Half-Life 2: Episode One", None),
    "ep2":        ("Half-Life 2: Episode Two", None),
    "lostcoast":  ("Half-Life 2: Lost Coast", None),
    "portal":     ("Portal", None),
    "portal2":    ("Portal 2", None),
    "csgo":       ("Counter-Strike: Global Offensive", None),
    "insurgency": ("Insurgency", None),
}
# Rough download sizes for the UI so nobody accidentally pulls 13GB (downloadable games only).
GMOD_CONTENT_SIZES = {"cstrike": "~1.6 GB", "tf": "~13 GB", "dod": "~1.1 GB",
                      "hl2mp": "~2 GB", "left4dead": "~3 GB", "left4dead2": "~9 GB"}
_CONTENT_USER = "gmodcontent"                         # panel-managed content user, created if none exists
_CU_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]*$")   # Linux username charset (reaches root-run cmds)


def _valid_content_games(games):
    """Keep only known content keys (each a constant [a-z] folder name), de-duped, order preserved."""
    seen, out = set(), []
    for g in (games or []):
        if g in GMOD_CONTENT_GAMES and g not in seen:
            seen.add(g)
            out.append(g)
    return out


def _user_primary_group(server, user):
    grp, _, _ = run_command(server, f"id -gn {_quote(user)} 2>/dev/null", timeout=10)
    return (grp or "").strip() or user


def detect_content_user(server, games=("cstrike",)):
    """Find a host user whose serverfiles already hold the wanted game content (e.g. an existing
    srcds / LinuxGSM cssserver). Returns {"user", "group", "present": {game: path}} for the user with
    the MOST wanted games present, else None — so a GMod install can reuse content already on the host
    instead of re-downloading gigabytes. One sudo scan; only constant game keys reach the shell."""
    wanted = _valid_content_games(games) or list(GMOD_CONTENT_GAMES)
    script = (
        'for u in $(ls -1 /home 2>/dev/null); do '
        '  d="/home/$u/serverfiles"; [ -d "$d" ] || continue; '
        '  for g in ' + " ".join(wanted) + '; do [ -d "$d/$g" ] && echo "HIT|$u|$g"; done; '
        'done'
    )
    try:
        out, _, _ = run_command(server, _sudo_sh(script), timeout=30, sudo=False)
    except Exception:
        _log.debug("detect_content_user scan failed", exc_info=True)
        return None
    by_user = {}
    for line in (out or "").splitlines():
        parts = line.strip().split("|")
        if len(parts) == 3 and parts[0] == "HIT" and _CU_NAME_RE.match(parts[1]) and parts[2] in GMOD_CONTENT_GAMES:
            by_user.setdefault(parts[1], set()).add(parts[2])
    if not by_user:
        return None
    user = max(by_user, key=lambda u: len(by_user[u]))
    return {"user": user, "group": _user_primary_group(server, user),
            "present": {g: f"/home/{user}/serverfiles/{g}" for g in sorted(by_user[user])}}


def ensure_content_user(server):
    """Return an existing content user (reuse), else create a locked, non-login content user with an
    empty serverfiles dir to install content into. Returns {"user", "group", "present"} or None on
    failure. Never downloads here — just guarantees a home."""
    found = detect_content_user(server, tuple(GMOD_CONTENT_GAMES))
    if found:
        return found
    u = _CONTENT_USER
    exists, _, _ = run_command(server, f"id {_quote(u)} >/dev/null 2>&1 && echo Y || echo N", timeout=10)
    if "Y" not in (exists or ""):
        _, err, rc = run_command(server, _sudo_sh(
            f"useradd -m -s /bin/bash {_quote(u)} && passwd -l {_quote(u)} >/dev/null 2>&1; "
            f"install -d -o {u} -g {u} -m 750 /home/{u}/serverfiles"), timeout=30, sudo=False)
        if rc != 0:
            _log.warning("ensure_content_user: could not create %s: %s", u, (err or "")[:200])
            return None
    return {"user": u, "group": _user_primary_group(server, u), "present": {}}


def content_present(server, content_user, game):
    """True if <content_user>/serverfiles/<game> already exists on the host."""
    if not (_CU_NAME_RE.match(content_user or "") and game in GMOD_CONTENT_GAMES):
        return False
    out, _, _ = run_command(
        server, _sudo_sh(f"test -d /home/{content_user}/serverfiles/{game}/. && echo Y || echo N"),
        timeout=10)
    return "Y" in (out or "")


def install_gmod_content(server, content_user, games, on_progress=None):
    """SteamCMD-download each game's content into the content user's serverfiles, SKIPPING any already
    present (reuse-existing / safe re-run). Long-running — CS:S is ~1.6GB. Returns (ok, installed_list,
    msg). Requires steamcmd on the host (installed with GMod's own deps)."""
    games = _valid_content_games(games)
    if not _CU_NAME_RE.match(content_user or ""):
        return False, [], "invalid content user"
    installed = []
    for g in games:
        if content_present(server, content_user, g):
            continue
        raw_appid = GMOD_CONTENT_GAMES[g][1]
        if raw_appid is None:
            continue   # mount-only (owned game): can't fetch anonymously — only mounts if already present
        appid = int(raw_appid)
        if on_progress:
            on_progress("Downloading %s content (SteamCMD)" % GMOD_CONTENT_GAMES[g][0])
        inner = (f"steamcmd +force_install_dir /home/{content_user}/serverfiles "
                 f"+login anonymous +app_update {appid} validate +quit")
        run_command(server, f"sudo -u {_quote(content_user)} bash -c {_quote(inner)}",
                    timeout=3600, sudo=False)
        if content_present(server, content_user, g):
            installed.append(g)
    return True, installed, ("installed: " + ", ".join(installed) if installed else "already present")


def _gmod_mount_files(content_user, games):
    """Build the (mount.cfg, mountdepots.txt) text GMod reads to mount each game's content from the
    content user's serverfiles. Pure — content_user is a validated Linux username and every game is a
    constant key, so the output is safe to write verbatim. hl2 depot is always enabled (base content)."""
    mountcfg = '"mountcfg"\n{\n' + "".join(
        '\t"%s"\t"/home/%s/serverfiles/%s"\n' % (g, content_user, g) for g in games) + "}\n"
    depots = ('"gamedepotsystem"\n{\n\t"hl2"\t\t"1"\n'
              + "".join('\t"%s"\t\t"1"\n' % g for g in games) + "}\n")
    return mountcfg, depots


def gmod_mount_setup(server, gmod_user, content_user, games):
    """Write a GMod server's mount config to mount exactly `games` from the content user, granting the
    GMod user read access first. An EMPTY `games` writes an empty mount.cfg (unmounts everything).
    Idempotent. Returns (ok, msg). Group membership takes effect when the GMod server (re)starts."""
    import base64
    games = _valid_content_games(games)
    if not _CU_NAME_RE.match(gmod_user or ""):
        return False, "invalid gmod user"
    if games and not _CU_NAME_RE.match(content_user or ""):
        return False, "invalid content user"
    if games:
        group = _user_primary_group(server, content_user)
        # Read access: add the GMod user to the content group, and make the content group-traversable
        # (home) + group-readable (each game tree). Best-effort per command.
        perms = ("usermod -aG %s %s; chmod g+x /home/%s; " % (_quote(group), _quote(gmod_user), content_user)
                 + "; ".join("chmod -R g+rX /home/%s/serverfiles/%s" % (content_user, g) for g in games))
        run_command(server, _sudo_sh(perms), timeout=180, sudo=False)
    # Write mount.cfg + mountdepots.txt AS the GMod user (base64 so no quoting/interpolation risk).
    mountcfg, depots = _gmod_mount_files(content_user or "", games)
    cfgdir = f"/home/{gmod_user}/serverfiles/garrysmod/cfg"
    b64c = base64.b64encode(mountcfg.encode()).decode()
    b64d = base64.b64encode(depots.encode()).decode()
    inner = (f"mkdir -p {cfgdir} && echo {b64c} | base64 -d > {cfgdir}/mount.cfg && "
             f"echo {b64d} | base64 -d > {cfgdir}/mountdepots.txt && echo __OK__")
    out, err, rc = run_command(server, f"sudo -u {_quote(gmod_user)} bash -c {_quote(inner)}",
                               timeout=30, sudo=False)
    if rc != 0 or "__OK__" not in (out or ""):
        return False, (err or out or "mount write failed")[:200]
    if not games:
        return True, "Unmounted all content"
    return True, "Mounted: " + ", ".join(GMOD_CONTENT_GAMES[g][0] for g in games)


_MOUNT_LINE_RE = re.compile(r'"([a-z0-9_]+)"\s+"/')


def gmod_current_mounts(server, gmod_user):
    """Which content games a GMod server currently mounts, parsed from its garrysmod/cfg/mount.cfg.
    Returns a list of known game keys (order as written). [] if no file / none. Read-only."""
    if not _CU_NAME_RE.match(gmod_user or ""):
        return []
    path = f"/home/{gmod_user}/serverfiles/garrysmod/cfg/mount.cfg"
    out, _, _ = run_command(server, _sudo_sh("cat %s 2>/dev/null || true" % path), timeout=10)
    found = []
    for m in _MOUNT_LINE_RE.finditer(out or ""):
        g = m.group(1)
        if g in GMOD_CONTENT_GAMES and g not in found:
            found.append(g)
    return found


def gmod_content_options(server):
    """The content picker for the UI: every known game with its label, size hint, whether it's
    already downloaded on the host's content user (mountable now), and its steamcmd app id. Used by
    both the install form and the per-server content manager."""
    cu = detect_content_user(server, tuple(GMOD_CONTENT_GAMES))
    present = set((cu or {}).get("present", {}))
    return [{"key": k, "label": GMOD_CONTENT_GAMES[k][0], "size": GMOD_CONTENT_SIZES.get(k, ""),
             "present": k in present, "downloadable": GMOD_CONTENT_GAMES[k][1] is not None}
            for k in GMOD_CONTENT_GAMES]
