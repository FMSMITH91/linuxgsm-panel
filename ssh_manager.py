"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import logging
import os
import re
import socket
import subprocess
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
        try:
            r = _real_subprocess.run(full_cmd, shell=True, capture_output=True,
                                     text=True, timeout=timeout)
            return r.stdout.strip(), r.stderr.strip(), r.returncode
        except _real_subprocess.TimeoutExpired:
            return "", "Command timed out", -1
        except Exception:
            # Never surface raw exception text — it can flow into API responses
            # (CodeQL py/stack-trace-exposure). Log it; callers act on rc == -1.
            _log.debug("local command failed", exc_info=True)
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
                pass  # probing a possibly-dead cached client → reconnect below
            try:
                conn.close()
            except Exception:  # nosec B110
                pass  # already closed / unusable; nothing to clean up
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

    with _conn_lock:
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
                pass
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
            pass
    return host


def _run_via_ssh_cli(server, command, timeout=30, sudo=None):
    """Run a command over the system `ssh` binary — used for Tailscale SSH remotes,
    where auth happens at the tailscaled level (paramiko can't do it, but the ssh CLI,
    running from this tailnet node, can — exactly like PuTTY does)."""
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


def list_linuxgsm_servers(server):
    """List LinuxGSM servers found on the remote machine."""
    out, err, rc = run_command(server, "ls -1 /home/ 2>/dev/null", timeout=10)
    if rc != 0:
        return []
    users = [u.strip() for u in out.split("\n") if u.strip()]

    servers = []
    for user in users:
        script_path = f"/home/{user}/{user}"
        check, _, rc = run_command(server, f"test -x {script_path} && echo 'exists'", timeout=5)
        if rc == 0 and check == "exists":
            details, _, _ = run_command(server, f"{script_path} details 2>/dev/null | head -50", timeout=15)
            name = user
            game_type = "unknown"
            port = "27015"

            for line in details.split("\n"):
                l = line.strip()
                if "port" in l.lower() and "=" in l:
                    m = re.search(r'port\s*=\s*["\']?(\d+)', l, re.IGNORECASE)
                    if m:
                        port = m.group(1)

            installed_check, _, _ = run_command(
                server, f"{script_path} check-installed 2>&1 | tail -1", timeout=15
            )
            installed = "installed" in installed_check.lower()

            servers.append({
                "short_name": name,
                "script_path": script_path,
                "game_type": game_type,
                "port": port,
                "installed": installed,
            })
    return servers


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


def send_console_command(server, user, command, timeout=20, selfname=None):
    """Inject a command into a LinuxGSM instance's live console.

    LinuxGSM runs every server inside a tmux session named `<selfname>` on a
    private socket `<selfname>-<random>` in the user's tmux dir. We drive that
    with `tmux send-keys`, which works for EVERY game — including ones (e.g. cod)
    that don't expose LinuxGSM's own `send` subcommand. Returns rc 3 with
    NO_SESSION when the server isn't running (no tmux session to send to)."""
    selfname = selfname or user
    inner = (
        'D=/tmp/tmux-$(id -u); '
        f"SOCK=$(ls -1 \"$D\" 2>/dev/null | grep -m1 '^{selfname}-'); "
        '[ -z "$SOCK" ] && { echo NO_SESSION; exit 3; }; '
        f'tmux -L "$SOCK" send-keys -t {selfname} {_quote(command)} Enter'
    )
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


def server_live_metrics(server, short_name=None, game_port=None):
    """One-round-trip live metrics for polling. Reports both whole-VPS figures
    (CPU%% via /proc/stat delta, RAM, disk, load, uptime) AND — when a game user
    is given — that GAME's own CPU%%, RAM, process count and uptime, plus a
    port-listening online check. Per-game CPU is sampled by diffing the game
    processes' utime+stime jiffies across the same 0.25s window as the VPS CPU
    sample, expressed as a share of total machine capacity (same basis as
    cpu_percent). Kept to a single SSH command for speed."""
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
            pass
    cmd = ("echo ===A; grep '^cpu' /proc/stat; echo ===B; sleep 0.25; grep '^cpu' /proc/stat; "
           "echo ===MEM; grep -E 'MemTotal|MemAvailable|SwapTotal|SwapFree' /proc/meminfo")
    out, _, _ = run_command(server, cmd, timeout=12)
    section = None
    A, B, mem = {}, {}, {}
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
                pass

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
    """Enable/disable auto-start on boot via the game user's crontab
    (@reboot ... start). This is LinuxGSM's recommended autostart method."""
    selfname = selfname or user
    marker = f"/home/{user}/{selfname} start"
    add = [f"@reboot {_record_managed_cmd(user, marker)}"] if enabled else []
    return _rewrite_crontab(server, user, f"-vF {_quote(marker)}", add)


def install_game_cron(server, user, selfname=None, supported=None):
    """Set up LinuxGSM maintenance cron for a game instance — only for the commands
    that game supports. Preserves the @reboot autostart line. Idempotent.
      monitor      every 5 min   (restart if crashed)
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

    remove_re = f"{base} (monitor|mods-update|update|update-lgsm) "
    return _rewrite_crontab(server, user, f"-vE {_quote(remove_re)}", lines)


# Panel game_type -> gamedig query type (best effort). Unmapped games skip the
# player check and just restart at the daily time.
GAMEDIG_TYPE = {
    "gmod": "garrysmod", "cs": "cs16", "css": "css", "cs2": "cs2", "tf2": "tf2",
    "hl2dm": "hl2dm", "dods": "dods", "left4dead2": "left4dead2", "l4d2": "left4dead2",
    "insurgency": "insurgency", "rust": "rust", "valheim": "valheim", "vh": "valheim",
    "sdtd": "sdtd", "7d2d": "sdtd", "mc": "minecraft", "mcb": "minecraftpe",
    "squad": "squad", "arma3": "arma3", "mumble": "mumble",
}


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
    getp = (f"P=$(gamedig --type {gdtype} 127.0.0.1:{port} 2>/dev/null | jq -r '.players|length' 2>/dev/null); "
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
    """Return True if the @reboot autostart cron entry exists for the game user."""
    selfname = selfname or user
    marker = f"/home/{user}/{selfname} start"
    out, _, _ = run_command(
        server, f"crontab -u {user} -l 2>/dev/null | grep -cF {_quote(marker)}",
        timeout=10, sudo=True,
    )
    try:
        return int((out or "0").strip()) > 0
    except ValueError:
        return False


# ── Generic per-server cron manager ──────────────────────────────────────────
# The panel manages three kinds of cron entry itself (the @reboot autostart line,
# the LinuxGSM maintenance jobs, and the daily restart-when-empty pair). Those are
# driven by their own toggles, so the generic cron editor below MUST NOT let anyone
# edit or delete them through here — that would silently desync the toggles. Such
# lines are flagged `managed` (shown read-only) and rejected by update/delete.

_CRON_FIELD = r"[-0-9*,/A-Za-z]+"
_CRON_SCHED_RE = re.compile(
    r"^(@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|"
    + r"\s+".join([_CRON_FIELD] * 5) + r")$"
)


def _cron_managed_patterns(user, selfname):
    """Substrings that identify a panel-managed crontab line for this game user."""
    selfname = selfname or user
    base = f"/home/{user}/{selfname}"
    return [
        f"{base} start",          # @reboot autostart
        f"{base} monitor", f"{base} mods-update",
        f"{base} update", f"{base} update-lgsm",   # LinuxGSM maintenance
        f"/home/{user}/.restart-pending",          # daily restart-when-empty
    ]


def _cron_line_managed(line, user, selfname):
    return any(p in line for p in _cron_managed_patterns(user, selfname))


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


def _wrap_cron_command(server, user, command):
    """Return the crontab command that runs `command` through the recorder (installing it
    first). base64 keeps the crontab line free of quotes and cron's special `%`."""
    import base64
    _install_cron_runner(server, user)
    b64 = base64.b64encode((command or "").encode()).decode()
    return "/home/%s/.lgsm-cron/run %s %s" % (user, _cron_job_id(command), b64)


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
        st = status.get(jid) if jid else None
        if st:                       # wrapped user job → full status from the recorder
            last_run, ok, error = st.get("last_run"), st.get("ok"), st.get("error", "")
        else:                        # managed/legacy → time only, matched by the raw command
            last_run, ok, error = run_times.get((cmd or "").strip()), None, ""
        jobs.append({
            "raw": raw, "schedule": sched, "command": display_cmd,
            "managed": _cron_line_managed(s, user, selfname),
            "last_run": last_run, "ok": ok, "error": error,
        })
    return jobs


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
            g = {
                "nums": [], "families": [], "port_label": port_label,
                "port_num": port_num, "proto_label": proto_label,
                "comment": p["comment"], "scope": scope, "iface": iface,
                "action": p["action"] or "ALLOW", "direction": p["direction"] or "IN",
                "is_iface": is_iface,
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
        pass  # a non-numeric stored port just means there's no extra SSH port to track
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


def host_specs(server):
    """Static hardware/OS specs for a host (local or remote): OS, CPU model, cores,
    RAM, disk, kernel, arch, virtualization. Returns {} keys or {'error': ...}."""
    try:
        out, err, rc = run_command(server, _SPECS_CMD, timeout=20, sudo=False)
    except Exception as e:
        return {"error": str(e)}
    if not out:
        return {"error": err or "Could not read system specs"}
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


def pro_status(server):
    """Ubuntu Pro attachment/service status for a host. Returns installed/attached
    plus the featured security services and their enabled/disabled state."""
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
    out, err, rc = run_command(server, _sudo_sh("pro detach --assume-yes 2>&1"), timeout=120, sudo=False)
    blob = (out or "") + " " + (err or "")
    if rc == 0 or "detach" in blob.lower():
        return True, "Detached from Ubuntu Pro."
    return False, _pro_trim(blob) or "Detach failed"


def remote_ufw_open_port(server, port, protocol="tcp", comment=""):
    """Open a port on the remote server via UFW. protocol 'both'/'any' opens TCP+UDP
    in a single rule (a bare `ufw allow <port>` covers both)."""
    cmt = f" comment {_quote(comment)}" if comment else ""
    if protocol in ("both", "any", "", None):
        cmd = f"ufw allow {port}{cmt} 2>&1"
        label = f"{port} (TCP+UDP)"
    else:
        cmd = f"ufw allow proto {protocol} to any port {port}{cmt} 2>&1"
        label = f"{port}/{protocol}"
    out, err, rc = run_command(server, cmd, timeout=15, sudo=True)
    if rc == 0:
        return True, f"Port {label} opened on remote"
    return False, err or out or "Unknown error"


def remote_ufw_close_port(server, port, protocol=None):
    """Close a port on the remote server via UFW. With protocol=None (or 'both'/'any'),
    deletes the bare `allow <port>` rule (both protocols); otherwise the proto-specific rule."""
    if protocol and protocol not in ("both", "any"):
        cmd = f"ufw delete allow proto {protocol} to any port {port} 2>&1"
    else:
        cmd = f"ufw delete allow {port} 2>&1"
    out, err, rc = run_command(server, cmd, timeout=15, sudo=True)
    if rc == 0:
        return True, f"Port {port}{('/' + protocol) if protocol else ''} closed on remote"
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
            pass  # don't let the safety check itself block a legitimate delete on error
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


def remote_os_check_updates(server):
    """Check for OS updates on the remote server."""
    run_command(server, "apt update -qq 2>/dev/null", timeout=60, sudo=True)
    out, _, rc = run_command(server,
        "apt list --upgradable 2>/dev/null | grep -v 'Listing...' | grep -v '^$' | wc -l",
        timeout=30
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    return count


def remote_os_run_updates(server):
    """Run apt upgrade on the remote server."""
    out, err, rc = run_command(server,
        "DEBIAN_FRONTEND=noninteractive apt upgrade -y "
        "-o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' 2>&1",
        timeout=600, sudo=True
    )
    return rc == 0, out[-300:] if out else err[:300]


def remote_reboot(server):
    """Reboot the remote server."""
    run_command(server, "reboot 2>&1", timeout=10, sudo=True)
    return True, "Reboot command sent to remote"


def remote_uptime(server):
    """Get uptime, CPU, RAM, disk from the remote server."""
    out, _, _ = run_command(server, "uptime -p", timeout=10)
    load, _, _ = run_command(server, "cat /proc/loadavg | awk '{print $1, $2, $3}'", timeout=10)
    disk, _, _ = run_command(server, "df -h / | tail -1 | awk '{print $3\"/\"$2}'", timeout=10)
    mem, _, _ = run_command(server, "free -h | grep Mem | awk '{print $3\"/\"$2}'", timeout=10)
    mem_percent, _, _ = run_command(server, "free | grep Mem | awk '{printf \"%.1f\", $3/$2 * 100}'", timeout=10)
    kernel, _, _ = run_command(server, "uname -r", timeout=10)
    cpu_percent, _, _ = run_command(server, "top -bn1 | grep 'Cpu(s)' | awk '{print $2+$4}'", timeout=10)
    cpu_cores, _, _ = run_command(server, "nproc", timeout=5)
    cpu_per_core = ""
    if cpu_percent and cpu_cores and cpu_cores.strip().isdigit():
        try:
            cpu_per_core = f"{float(cpu_percent)/int(cpu_cores):.1f}"
        except ValueError:
            pass
    return {
        "uptime": (out or "unknown").replace("up ", ""),
        "load": load or "?",
        "disk": disk or "?",
        "memory": mem or "?",
        "memory_percent": mem_percent or "?",
        "kernel": kernel or "?",
        "cpu_percent": cpu_percent or "?",
        "cpu_cores": cpu_cores.strip() if cpu_cores else "?",
        "cpu_per_core": cpu_per_core,
    }


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
    total = 7  # lock, update, full-upgrade, autoremove, install, gamedig, unattended-upgrades
    total += 1 if set_timezone else 0
    total += 1 if enable_ufw else 0
    total += 2  # ssh hardening, swap
    total += 1  # disable services
    total += 1 if username else 0
    total += 1 if install_fail2ban else 0
    total += 1 if (do_reboot and not is_local) else 0

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
                pass

    def note(text, status="running"):
        log.append(f"   {text}")
        if progress:
            try:
                progress(step, total, text, status)
            except Exception:
                pass

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

    # ── 3. Install essential packages (incl Node.js for gamedig) ──
    emit("Installing essential packages")
    pkgs = ("curl wget git ufw tmux htop net-tools unzip jq ca-certificates "
            "software-properties-common nodejs npm unattended-upgrades apt-listchanges")
    if install_lgsm_deps:
        # LinuxGSM base dependencies (32-bit libs for SteamCMD, etc.)
        pkgs += " python3 python3-pip bc lib32gcc-s1 lib32stdc++6 libsdl2-2.0-0:i386"
    if install_fail2ban:
        pkgs += " fail2ban"
    run_command(server, "dpkg --add-architecture i386 2>/dev/null; add-apt-repository -y universe 2>/dev/null; apt-get update -qq 2>/dev/null", timeout=120, sudo=True)
    out, _, _ = run_command(server, f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkgs} 2>&1 | tail -6", timeout=600, sudo=True)
    note(out or "OK")

    # ── 3b. gamedig (game-server query tool) via npm ──
    emit("Installing gamedig (game server query tool)")
    gd_out, _, _ = run_command(server, "npm install -g gamedig 2>&1 | tail -3", timeout=300, sudo=True)
    note(gd_out or "gamedig installed")

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
        run_command(server, f"timedatectl set-timezone {set_timezone} 2>&1", timeout=10, sudo=True)

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
    if username:
        emit(f"Creating LinuxGSM user: {username}")
        out, _, _ = run_command(server, f"id {username} 2>/dev/null && echo 'EXISTS' || echo 'NOTEXISTS'", timeout=10)
        if "NOTEXISTS" not in out:
            note(f"User {username} already exists")
        else:
            run_command(server, f"useradd -m -s /bin/bash {username} 2>&1", timeout=15, sudo=True)
            run_command(server, f"passwd -l {username} 2>&1", timeout=10, sudo=True)
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

    # ── 11. Reboot to apply kernel/library updates, then wait for reconnect ──
    if do_reboot and not is_local:
        reboot_req, _, _ = run_command(server, "test -f /var/run/reboot-required && echo YES || echo NO", timeout=10)
        emit("Rebooting server to apply updates", status="rebooting",
             detail=("Kernel/library update requires a reboot." if "YES" in reboot_req
                     else "Rebooting to finalize the fresh setup."))
        # Schedule the reboot slightly in the future so this command returns cleanly.
        run_command(server, "( sleep 2 ; reboot ) >/dev/null 2>&1 & echo scheduled", timeout=15, sudo=True)
        close_connection(server)
        came_back = _wait_for_reboot(server, on_wait=lambda t: note(t, status="rebooting"))
        if not came_back:
            return False, "Server was rebooted but did not come back online within the timeout.", "\n".join(log)
        note("Server is back online.", status="running")
    elif do_reboot and is_local:
        note("Reboot skipped — this is the panel's own host.")

    if progress:
        try:
            progress(total, total, "Bootstrap complete", "done")
        except Exception:
            pass
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
                pass

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
        up += f" --advertise-routes={advertise_routes}"
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

    # 2. Build the up command
    up_cmd = f"tailscale up --auth-key {auth_key} --accept-routes"
    if enable_ssh:
        up_cmd += " --ssh"
    if advertise_routes:
        up_cmd += f" --advertise-routes={advertise_routes}"
    if tags:
        up_cmd += f" --advertise-tags={tags}"

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
        pass  # Non-fatal — might already be removed

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
    except Exception as e:
        return False, f"Connection failed: {e}"


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
    ap = _pp.normpath(_pp.join(home, (relpath or "").lstrip("/")))
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
