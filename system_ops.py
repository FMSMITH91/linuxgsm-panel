"""System operations for the local server — UFW, Tailscale SSH, OS updates, reboot."""
import json
import logging
import os
import shlex
import subprocess
import threading
import time

_log = logging.getLogger("panel.system_ops")

# The panel's own install directory (this module lives inside it) — used for the
# git-based self-update feature.
PANEL_DIR = os.path.dirname(os.path.abspath(__file__))


def live_metrics():
    """Fast realtime metrics for the local host: per-core + overall CPU%% (via a
    short /proc/stat delta) and RAM/swap (from /proc/meminfo). Reads /proc directly
    — no subprocess — so it's cheap enough to poll every 1-2s."""
    def _read_stat():
        cpus = {}
        try:
            with open("/proc/stat") as f:
                for line in f:
                    if line.startswith("cpu"):
                        parts = line.split()
                        if len(parts) >= 8:
                            cpus[parts[0]] = [int(x) for x in parts[1:8]]
        except (OSError, ValueError, IndexError):
            pass   # unreadable/odd /proc/stat → return whatever parsed
        return cpus

    a = _read_stat()
    time.sleep(0.25)
    b = _read_stat()

    def _pct(name):
        if name not in a or name not in b:
            return 0.0
        idle = b[name][3] - a[name][3]
        total = sum(b[name]) - sum(a[name])
        return round((1 - idle / total) * 100, 1) if total > 0 else 0.0

    core_names = sorted(
        (n for n in a if n != "cpu" and n.startswith("cpu")),
        key=lambda x: int(x[3:]) if x[3:].isdigit() else 0,
    )
    cores = [_pct(n) for n in core_names]
    overall = _pct("cpu")

    mem = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, rest = line.partition(":")
                mem[k.strip()] = int(rest.strip().split()[0]) * 1024  # kB → bytes
    except Exception:  # nosec B110
        pass  # /proc/meminfo unreadable or oddly formatted — fall back to zeros below
    ram_total = mem.get("MemTotal", 0)
    ram_used = ram_total - mem.get("MemAvailable", 0)
    swap_total = mem.get("SwapTotal", 0)
    swap_used = swap_total - mem.get("SwapFree", 0)

    return {
        "cpu_overall": overall,
        "cpu_cores": cores,
        "core_count": len(cores),
        "ram_used": ram_used,
        "ram_total": ram_total,
        "ram_percent": round(ram_used / ram_total * 100, 1) if ram_total else 0,
        "swap_used": swap_used,
        "swap_total": swap_total,
        "swap_percent": round(swap_used / swap_total * 100, 1) if swap_total else 0,
    }

# ─── Helpers ──────────────────────────────────────────────────

def _run(cmd, timeout=30, sudo=False, text=True):
    """Run a shell command. Returns (stdout, stderr, exit_code)."""
    # os.geteuid() is Unix-only; guard it so callers don't crash off-Linux (tests).
    if sudo and hasattr(os, "geteuid") and os.geteuid() != 0:
        cmd = f"sudo {cmd}"
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=text, timeout=timeout,
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except FileNotFoundError:
        return "", "Command not found", -1
    except Exception:
        # Don't surface the raw exception text — it can flow to API responses. Log it
        # server-side; callers only act on the -1 return code anyway.
        _log.debug("local command failed", exc_info=True)
        return "", "command execution error", -1


def _check_sudo():
    """Check if we can sudo without a password prompt."""
    out, err, rc = _run("sudo -n true 2>/dev/null && echo 'OK' || echo 'NOPASS'", timeout=10)
    return "OK" in out


# ─── UFW ──────────────────────────────────────────────────────

def ufw_status():
    """Get UFW status and rules."""
    out, err, rc = _run("ufw status verbose 2>&1", timeout=15, sudo=True)
    if rc != 0:
        return {"enabled": False, "status_text": "not_installed" if "not found" in err or "not installed" in err else "inactive", "rules": []}

    enabled = "Status: active" in out
    status_text = "active" if enabled else "inactive"
    rules = []

    # Parse rules
    for line in out.split("\n"):
        line = line.strip()
        # Match: "Anywhere on <interface>" or "Anywhere                   ALLOW      192.168.1.0/24"
        if not line or "Status:" in line or "Logging:" in line or "Default:" in line or "New:" in line:
            continue
        if "(" in line and ")" in line:
            continue  # Skip header lines like (v6)

        parts = line.split()
        if len(parts) >= 3 and parts[0][0].isdigit():
            # Numbered rule
            num = parts[0]
            action = parts[1] if len(parts) > 1 else ""
            rest = " ".join(parts[2:])
            rules.append({"num": num, "action": action, "detail": rest})

    return {"enabled": enabled, "status_text": status_text, "rules": rules}


def ufw_allow_tailscale(ts_interface=None):
    """Allow traffic on the Tailscale interface via UFW.

    Detects the Tailscale interface name automatically if not provided.
    Creates: ufw allow in on <interface> && ufw allow out on <interface>
    """
    # Auto-detect Tailscale interface
    if not ts_interface:
        ts_interface = detect_tailscale_interface()

    if not ts_interface:
        return False, "Could not detect Tailscale interface. Is Tailscale running?"

    # Allow INCOMING on the tailscale interface — that's the "way in" (reachability). We do
    # NOT add a separate `allow out` rule: UFW's default outgoing policy is allow, so it's
    # redundant, and a second rule just shows up as a confusing duplicate `tailscale0` row
    # in the firewall list. (This matches the remote bootstrap, which adds `in` only.)
    out1, err1, rc1 = _run(
        f"ufw allow in on {ts_interface} 2>&1", timeout=15, sudo=True
    )
    if rc1 == 0:
        return True, f"UFW rule added for interface '{ts_interface}'"
    return False, err1 or out1 or "Failed to add UFW rule"


def detect_tailscale_interface():
    """Detect the Tailscale network interface name."""
    # Method 1: ip link show type wireguard
    out, _, rc = _run("ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}'", timeout=5)
    if rc == 0 and out:
        for iface in out.split("\n"):
            if "tailscale" in iface.lower() or "wg" in iface.lower():
                return iface.strip()

    # Method 2: Look for tailscale interface in ip link
    out, _, rc = _run("ip -o link show 2>/dev/null | grep -i tailscale | awk -F': ' '{print $2}'", timeout=5)
    if rc == 0 and out:
        return out.strip().split("\n")[0]

    # Method 3: Check common names
    for name in ["tailscale0", "wg0", "utun"]:
        out, _, rc = _run(f"ip link show {name} 2>/dev/null && echo 'FOUND' || echo 'NOTFOUND'", timeout=5)
        if "NOTFOUND" not in out:  # "FOUND" is a substring of "NOTFOUND"
            return name

    # Method 4: Parse tailscale status for interface info
    out, _, rc = _run("tailscale status --json 2>/dev/null || echo '{}'", timeout=5)
    if rc == 0:
        try:
            data = json.loads(out)
            if data.get("TUN"):
                return "tailscale0"
        except Exception:
            pass

    return None


# ─── Tailscale SSH ─────────────────────────────────────────────

def tailscale_ssh_status():
    """Check if this node runs the Tailscale SSH server.
    The authoritative source is the local prefs (`RunSSH`), not `status --json`
    (which has no SSHEnabled field — the old check always reported disabled)."""
    # Is tailscale even up? (installed AND backend running)
    st, _, rc = _run("tailscale status --json 2>/dev/null", timeout=10)
    if rc != 0 or not st:
        return {"enabled": False, "running": False, "error": "Tailscale not running"}
    running = False
    try:
        running = json.loads(st).get("BackendState") == "Running"
    except Exception:
        running = False   # unparseable status → treat as not running (fail safe)
    out, _, prc = _run("tailscale debug prefs 2>/dev/null", timeout=10)
    if prc == 0 and out:
        try:
            return {"enabled": bool(json.loads(out).get("RunSSH", False)), "running": running, "method": "prefs"}
        except Exception:
            pass
    return {"enabled": False, "running": running, "error": "Could not read Tailscale prefs"}


def tailscale_ssh_enable():
    """Enable Tailscale SSH by re-authenticating with --ssh flag."""
    out, err, rc = _run(
        "tailscale up --ssh --accept-routes --accept-dns --reset 2>&1",
        timeout=30
    )
    if rc == 0:
        return True, "Tailscale SSH enabled"
    return False, err or out or "Failed to enable Tailscale SSH"


def tailscale_ssh_disable():
    """Disable Tailscale SSH by re-authenticating without --ssh flag."""
    out, err, rc = _run(
        "tailscale up --accept-routes --accept-dns --reset 2>&1",
        timeout=30
    )
    if rc == 0:
        return True, "Tailscale SSH disabled"
    return False, err or out or "Failed to disable Tailscale SSH"


# ─── OS Updates ───────────────────────────────────────────────

def os_update_available(refresh=True):
    """Check if OS updates are available (apt list --upgradable).
    refresh=False skips the network `apt update` (uses the cached package lists),
    which keeps page loads fast — the dedicated "check for updates" action passes
    refresh=True to force a fresh sync."""
    if refresh:
        _run("apt update -qq 2>/dev/null", timeout=60, sudo=True)

    out, _, rc = _run(
        "apt list --upgradable 2>/dev/null | grep -v 'Listing...' | grep -v '^$'",
        timeout=30
    )
    if not out.strip():
        return {"updates_available": False, "count": 0, "packages": []}

    packages = []
    for line in out.strip().split("\n"):
        # Format: pkg-name/stable 1.2.3 amd64 [upgradable from: 1.2.2]
        parts = line.split()
        if parts:
            name = parts[0].split("/")[0] if "/" in parts[0] else parts[0]
            version = parts[1] if len(parts) > 1 else ""
            packages.append({"name": name, "version": version})

    return {"updates_available": len(packages) > 0, "count": len(packages), "packages": packages}


def os_run_update():
    """Run apt upgrade in background. Returns (success, message)."""
    has_sudo = _check_sudo()
    if not has_sudo:
        return False, "Sudo access required. Configure passwordless sudo for the panel user."

    # Run in background thread
    def _bg_update():
        _run("apt upgrade -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' 2>&1",
             timeout=600, sudo=True)

    thread = threading.Thread(target=_bg_update, daemon=True)
    thread.start()
    return True, "OS update started in background. This may take several minutes."


def os_update_log():
    """Get recent apt history."""
    log_file = "/var/log/apt/history.log"
    if not os.path.exists(log_file):
        return []
    out, _, rc = _run(f"tail -50 {log_file}", timeout=5)
    lines = out.split("\n") if out else []
    entries = []
    current = {}
    for line in lines:
        if line.startswith("Start-Date:"):
            if current:
                entries.append(current)
            current = {"start": line.replace("Start-Date: ", ""), "command": "", "packages": []}
        elif line.startswith("Commandline:"):
            current["command"] = line.replace("Commandline: ", "")
        elif line.startswith("Packages:"):
            current["packages"] = line.replace("Packages: ", "").split()
    if current:
        entries.append(current)
    return entries[-10:]  # Last 10


# ─── Reboot ───────────────────────────────────────────────────

def server_reboot(delay_seconds=5):
    """Reboot the server with an optional delay."""
    has_sudo = _check_sudo()
    if not has_sudo:
        return False, "Sudo access required for reboot."

    # Schedule reboot in background
    def _do_reboot():
        import time
        time.sleep(delay_seconds)
        _run("reboot", timeout=30, sudo=True)

    thread = threading.Thread(target=_do_reboot, daemon=True)
    thread.start()
    return True, f"Server will reboot in {delay_seconds} seconds."


def server_uptime():
    """Get server uptime."""
    out, _, rc = _run("uptime -p", timeout=5)
    uptime_str = out.replace("up ", "") if out else "unknown"

    # Also get load average
    load, _, _ = _run("cat /proc/loadavg 2>/dev/null | awk '{print $1, $2, $3}'", timeout=5)
    load_parts = load.split() if load else ["?", "?", "?"]

    # Get disk
    disk, _, _ = _run("df -h / | tail -1 | awk '{print $3 \"/\" $2 \" (\" $5 \")\"}'", timeout=5)

    # Memory
    mem, _, _ = _run("free -h | grep Mem | awk '{print $3 \"/\" $2}'", timeout=5)
    mem_percent, _, _ = _run("free | grep Mem | awk '{printf \"%.1f\", $3/$2 * 100}'", timeout=5)

    # Kernel
    kernel, _, _ = _run("uname -r", timeout=5)

    # CPU
    cpu_percent, _, _ = _run(
        "top -bn1 | grep 'Cpu(s)' | awk '{print $2 + $4}'",
        timeout=5
    )
    # CPU load / core count
    cpu_cores, _, _ = _run("nproc", timeout=3)
    cpu_per_core = ""
    if cpu_percent and cpu_cores and cpu_cores.strip().isdigit():
        try:
            cpu_per_core = f"{float(cpu_percent)/int(cpu_cores):.1f}"
        except ValueError:
            pass

    return {
        "uptime": uptime_str,
        "load_1m": load_parts[0] if len(load_parts) > 0 else "?",
        "load_5m": load_parts[1] if len(load_parts) > 1 else "?",
        "load_15m": load_parts[2] if len(load_parts) > 2 else "?",
        "disk_root": disk or "?",
        "memory": mem or "?",
        "memory_percent": mem_percent or "?",
        "kernel": kernel or "?",
        "cpu_percent": cpu_percent or "?",
        "cpu_cores": cpu_cores.strip() if cpu_cores else "?",
        "cpu_per_core": cpu_per_core,
    }


# ─── Combined status ──────────────────────────────────────────

def get_server_status():
    """Get combined server status for the management page.
    Uses the cached update list (no network apt-update) so the page loads fast;
    the user can trigger a fresh check separately."""
    ufw = ufw_status()
    ts_ssh = tailscale_ssh_status()
    updates = os_update_available(refresh=False)
    uptime = server_uptime()
    has_sudo = _check_sudo()
    ts_iface = detect_tailscale_interface()

    # Check if tailscale interface is already allowed in UFW
    tailscale_ufw_allowed = False
    if ts_iface and ufw["enabled"]:
        out, _, _ = _run(f"ufw status verbose 2>&1 | grep -i '{ts_iface}'", timeout=10, sudo=True)
        tailscale_ufw_allowed = bool(out.strip())

    return {
        "has_sudo": has_sudo,
        "ufw": ufw,
        "tailscale_ssh": ts_ssh,
        "tailscale_interface": ts_iface,
        "tailscale_ufw_allowed": tailscale_ufw_allowed,
        "updates": updates,
        "uptime": uptime,
    }


# ─── Panel self-update (git-based) ─────────────────────────────
_update_cache = {"ts": 0.0, "data": None}
_UPDATE_TTL = 300  # re-check GitHub at most every 5 min for the sidebar badge


def panel_version():
    try:
        with open(os.path.join(PANEL_DIR, "VERSION")) as f:
            return f.read().strip() or "0.0.0"
    except Exception:
        return "0.0.0"


def _git(args, timeout=45):
    """Run a git command inside the panel dir (as the panel user, no sudo).

    GIT_TERMINAL_PROMPT=0 / GIT_ASKPASS=true stop git from blocking on a
    credential prompt when the remote is private or unreachable (e.g. checking
    for updates before the repo is public) — it fails fast instead of hanging."""
    env = "GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=true "
    cmd = env + "git -C " + shlex.quote(PANEL_DIR) + " " + " ".join(shlex.quote(a) for a in args)
    return _run(cmd, timeout=timeout, sudo=False)


def _is_git_checkout():
    return os.path.isdir(os.path.join(PANEL_DIR, ".git"))


def _compute_update_status():
    cur_ver = panel_version()
    if not _is_git_checkout():
        return {"git": False, "update_available": False, "current_version": cur_ver,
                "message": "The panel isn't a git checkout, so it can't self-update."}
    cur_sha, _, _ = _git(["rev-parse", "--short", "HEAD"])
    _, ferr, frc = _git(["fetch", "--quiet", "origin", "main"], timeout=45)
    if frc != 0:
        # Couldn't reach the remote (private repo without creds, or offline). Do NOT
        # report an update from a stale remote-tracking ref — that would show a phantom
        # "update available" that can never be applied.
        return {"git": True, "fetched": False, "update_available": False,
                "current_version": cur_ver, "current_sha": cur_sha.strip(),
                "message": "Couldn't reach the update source — it may be private or offline."}
    behind, _, _ = _git(["rev-list", "--count", "HEAD..origin/main"])
    behind_n = int(behind.strip()) if behind.strip().isdigit() else 0
    rem_sha, _, _ = _git(["rev-parse", "--short", "origin/main"])
    rem_ver, _, rv_rc = _git(["show", "origin/main:VERSION"])
    log, _, _ = _git(["log", "--oneline", "--no-decorate", "-10", "HEAD..origin/main"])
    return {
        "git": True,
        "fetched": frc == 0,
        "update_available": behind_n > 0,
        "behind": behind_n,
        "current_version": cur_ver,
        "current_sha": cur_sha.strip(),
        "remote_version": ((rem_ver.strip() if rv_rc == 0 else "") or "?"),
        "remote_sha": rem_sha.strip(),
        "changes": [ln for ln in log.splitlines() if ln.strip()][:10],
        "checked_at": int(time.time()),
    }


def panel_update_status(force=False):
    """Whether the panel is behind its GitHub remote. Cached ~5 min (each check does
    a network `git fetch`) unless `force` is set."""
    now = time.time()
    if not force and _update_cache["data"] is not None and (now - _update_cache["ts"]) < _UPDATE_TTL:
        return _update_cache["data"]
    data = _compute_update_status()
    _update_cache["ts"] = now
    _update_cache["data"] = data
    return data


def panel_self_update():
    """Update the panel with the SAME safety as the SSH installer.

    Instead of a bare `git pull + restart`, this runs install.sh's update path,
    which snapshots the current code AND database, pulls the new version,
    restarts, health-checks that the panel actually comes back up, and
    AUTO-ROLLS-BACK (code + database) if it doesn't. So clicking Update in the UI
    can't leave you with a dead panel — exactly like updating over SSH.

    Runs DETACHED via `systemd-run --user` so it lives in its own cgroup and
    survives the panel's own restart (the service uses KillMode=control-group,
    which would otherwise kill a normal child mid-update). Returns immediately;
    progress is written to data/self-update.log under the panel dir."""
    if not _is_git_checkout():
        return False, "The panel isn't a git checkout, so it can't self-update."
    installer = os.path.join(PANEL_DIR, "install.sh")
    if not os.path.isfile(installer):
        return False, "install.sh is missing, so the panel can't self-update safely."
    # Write the wrapper + its log inside the panel's own data dir (owned by the service
    # user, not world-writable) rather than /tmp. This script is later executed as root
    # via `sudo systemd-run`, so a predictable /tmp path would let a local user pre-plant
    # a symlink/file and get root code execution.
    _upd_dir = os.path.join(PANEL_DIR, "data")
    os.makedirs(_upd_dir, exist_ok=True)
    _log_path = os.path.join(_upd_dir, "self-update.log")
    # Thin wrapper so the UI can tail one predictable log file. The installer does
    # the real work: snapshot → update → health-check → rollback-on-failure.
    script = (
        "#!/bin/bash\n"
        f"LOG={shlex.quote(_log_path)}\n"
        f"cd {shlex.quote(PANEL_DIR)} || exit 1\n"
        'echo "=== panel self-update $(date) ===" > "$LOG"\n'
        f"bash {shlex.quote(installer)} >> \"$LOG\" 2>&1\n"
        'echo "=== installer exit $? ===" >> "$LOG"\n'
    )
    path = os.path.join(_upd_dir, "self-update.sh")
    # Launch the updater in a transient unit that OUTLIVES the panel's own restart.
    # Match the install's service model: a per-user service uses `systemd-run --user`;
    # a system service (root install → dedicated service user) is launched as root via
    # `sudo systemd-run` (the service user has NOPASSWD sudo) so install.sh can drive
    # the system unit. Falls back to --user.
    user_unit = os.path.expanduser("~/.config/systemd/user/linuxgsm-panel.service")
    system_unit = "/etc/systemd/system/linuxgsm-panel.service"
    if os.path.exists(user_unit) or not os.path.exists(system_unit):
        launcher = ["systemd-run", "--user"]
    else:
        launcher = ["sudo", "systemd-run"]
    launcher += ["--no-block", "--collect", "--unit", "panel-selfupdate", "/bin/bash", path]
    try:
        with open(path, "w") as f:
            f.write(script)
        os.chmod(path, 0o700)  # owner-only; root (sudo path) can still read it
        subprocess.Popen(
            launcher,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=os.environ.copy(),
        )
        # Invalidate the cache so the badge clears after the restart.
        _update_cache["ts"] = 0.0
        return True, ("Update started — the panel is backing up, updating, and verifying it "
                      "restarts cleanly. If the new version fails to come up it rolls back "
                      "automatically. This takes up to a minute.")
    except Exception:
        _log.exception("panel self-update failed to start")
        return False, "Could not start the updater — check the panel logs."


def restart_panel(delay_seconds=2):
    """Restart the panel's OWN systemd service via a DETACHED transient timer so it survives
    the panel process being killed mid-restart (the unit is KillMode=control-group, which
    would otherwise kill a normal child). Used after a config change that only takes effect on
    a rebind — notably the listen port. The `--on-active` delay lets the triggering HTTP
    response flush to the browser before the server goes down. Mirrors the self-update
    launcher's service-model detection. Best-effort; returns (ok, msg)."""
    delay = "--on-active=%d" % max(1, int(delay_seconds))
    user_unit = os.path.expanduser("~/.config/systemd/user/linuxgsm-panel.service")
    system_unit = "/etc/systemd/system/linuxgsm-panel.service"
    if os.path.exists(user_unit) or not os.path.exists(system_unit):
        launcher = ["systemd-run", "--user", delay, "--collect",
                    "systemctl", "--user", "restart", "linuxgsm-panel.service"]
    else:
        launcher = ["sudo", "systemd-run", delay, "--collect",
                    "systemctl", "restart", "linuxgsm-panel.service"]
    try:
        subprocess.Popen(launcher, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         env=os.environ.copy())
        return True, "Panel restart scheduled."
    except Exception:
        _log.exception("panel restart failed to dispatch")
        return False, "Could not restart the panel — check the panel logs."


def port_in_use(port):
    """True if something is already listening on `port` (tcp or udp) on this host — used to
    refuse changing the panel to a port that's already taken (which would fail to bind and
    leave the panel down). Best-effort: on any error, returns False (don't block a change on
    a flaky check; the restart's own health path is the backstop)."""
    try:
        out, _, _ = _run("ss -H -lntu 2>/dev/null | awk '{print $5}'", timeout=8)
        for addr in (out or "").split():
            if ":" in addr and addr.rsplit(":", 1)[1] == str(int(port)):
                return True
    except Exception:
        return False
    return False


def panel_update_log(max_bytes=20000):
    """Tail of the self-update log (ANSI stripped) so the UI can show live progress while
    the panel updates and restarts. The detached updater keeps writing to this file across
    the restart, so the new process can read the final steps too."""
    import re as _re
    path = os.path.join(PANEL_DIR, "data", "self-update.log")
    try:
        with open(path, "r", errors="replace") as f:
            data = f.read()[-max_bytes:]
    except OSError:
        return {"exists": False, "lines": []}
    data = _re.sub(r"\x1b\[[0-9;]*m", "", data)          # strip ANSI colour codes
    lines = [ln.rstrip() for ln in data.splitlines() if ln.strip()]
    return {"exists": True, "lines": lines}


# ─── Panel self-diagnostics + file integrity/repair ────────────
# Integrity and repair lean entirely on git: a deployed panel is a checkout, so
# any TRACKED file that differs from HEAD is unexpected (nobody edits panel code
# in place), and `git checkout -- <file>` restores it byte-for-byte from the
# installed version. User data lives in data/, which is gitignored, so none of
# this ever sees or touches the database, secrets or config.

_STATUS_WORD = {"M": "modified", "D": "deleted", "A": "added",
                "R": "renamed", "T": "type-changed", "C": "copied"}


def panel_integrity():
    """Which of the panel's own git-tracked files have been modified or deleted
    since install. Returns {git, clean, current_sha, modified:[{path,status}],
    count, message}."""
    if not _is_git_checkout():
        return {"git": False, "clean": True, "verified": False, "modified": [], "count": 0,
                "current_sha": "",
                "message": "The panel isn't a git checkout, so file integrity "
                           "can't be verified or repaired here."}
    sha, _, _ = _git(["rev-parse", "--short", "HEAD"])
    # --name-status vs HEAD catches both staged and unstaged tampering; data/ is
    # gitignored so user data never shows up.
    out, _, rc = _git(["diff", "--name-status", "HEAD"])
    if rc != 0:
        # git itself failed (not installed, unreadable repo, …). Fail SAFE: never
        # claim the files are verified-clean when we couldn't actually run the check.
        return {"git": True, "clean": True, "verified": False, "modified": [], "count": 0,
                "current_sha": sha.strip(),
                "message": "Couldn't run git to verify file integrity."}
    modified = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        status = _STATUS_WORD.get(parts[0][:1], "changed")
        modified.append({"path": parts[-1], "status": status})
    modified.sort(key=lambda x: x["path"])
    return {"git": True, "clean": not modified, "verified": True, "current_sha": sha.strip(),
            "modified": modified, "count": len(modified)}


def panel_repair(paths=None):
    """Restore tampered panel files from git (`git checkout HEAD -- <file>`).

    Only files that panel_integrity() reports as modified/deleted are eligible,
    so this can never be used to check out arbitrary paths — each requested path
    must exactly match one git itself reported as changed. paths=None restores
    them all. Returns (ok, message, restored:list)."""
    info = panel_integrity()
    if not info["git"]:
        return False, info.get("message", "Not a git checkout."), []
    if not info.get("verified", True):
        return False, "Couldn't verify file integrity with git — repair is unavailable right now.", []
    # `tampered` is built from git's OWN output (panel_integrity → git diff), never
    # from caller input. The request's `paths` is used ONLY as a membership filter,
    # and the strings we hand to git are taken from `tampered` — so nothing from the
    # HTTP request ever reaches the git command line (defeats path-traversal /
    # command-injection; git also only touches tracked files, and _git shlex-quotes).
    tampered = sorted(m["path"] for m in info["modified"])
    if not tampered:
        return True, "Nothing to repair — all panel files match the installed version.", []
    if paths:
        requested = set(paths)
        targets = [p for p in tampered if p in requested]
        if not targets:
            return False, "None of the requested files are currently modified.", []
    else:
        targets = list(tampered)
    # Restore from HEAD. The explicit '--' plus paths validated against git's own
    # changed-file list means git only ever touches files in that set.
    _, err, rc = _git(["checkout", "HEAD", "--"] + targets)
    if rc != 0:
        _log.error("panel repair failed: %s", (err or "").strip())
        return False, "Repair failed — see the panel logs.", []
    return True, ("Restored %d file(s) from the installed version. Restart the panel "
                  "to load the corrected code." % len(targets)), targets


def unattended_upgrades_status():
    """Whether automatic security updates (the unattended-upgrades package) are
    installed AND actually enabled. Read-only, no sudo. Returns
    {installed, enabled, detail}. Non-Debian systems report not-installed."""
    _, _, prc = _run(
        "dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null "
        "| grep -q 'install ok installed'", timeout=10)
    installed = (prc == 0)
    # The package being present isn't enough — APT's periodic flag must be "1".
    out, _, _ = _run("apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null", timeout=10)
    enabled = installed and ('"1"' in (out or ""))
    if not installed:
        detail = "The unattended-upgrades package isn't installed."
    elif enabled:
        detail = "Installed and enabled — the OS applies security updates automatically."
    else:
        detail = "Installed but not enabled (APT periodic upgrade flag is off)."
    return {"installed": installed, "enabled": enabled, "detail": detail}


def enable_unattended_upgrades():
    """Install + enable automatic security updates. Needs sudo (NOPASSWD, same path
    as the OS-update actions). Returns (ok, message)."""
    # 1) install the package (no-op if already present); noninteractive avoids prompts.
    _run("DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades 2>&1",
         timeout=300, sudo=True)
    # 2) write the APT periodic config that actually turns it on. printf is
    # unprivileged; only the file write (via `sudo tee`) needs root.
    conf = ('APT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "1";\n')
    _run("printf %s " + shlex.quote(conf) +
         " | sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null", timeout=30)
    st = unattended_upgrades_status()
    if st.get("enabled"):
        return True, "Automatic security updates are now enabled."
    return False, "Could not confirm automatic security updates were enabled — check the panel logs."


def panel_diagnostics():
    """A fast, local self-check of the panel's own health: file integrity, data
    dir, database, encryption keys, config, disk space, TLS cert and service
    unit. No SSH/network. Returns {checks:[{name,level,detail}], summary, counts}."""
    import shutil
    import config as _cfg
    from datetime import datetime, timezone
    checks = []

    def add(name, level, detail):
        checks.append({"name": name, "level": level, "detail": detail})

    # 1. file integrity (git)
    integ = panel_integrity()
    if not integ["git"]:
        add("File integrity", "warn", integ["message"])
    elif not integ.get("verified", True):
        add("File integrity", "warn", integ.get("message", "Couldn't verify file integrity."))
    elif integ["clean"]:
        add("File integrity", "ok",
            "All panel files match the installed version (%s)." % (integ["current_sha"] or "?"))
    else:
        add("File integrity", "fail",
            "%d panel file(s) differ from the installed version." % integ["count"])

    # 2. data directory writable
    data_dir = str(_cfg.DATA_DIR)
    if os.path.isdir(data_dir) and os.access(data_dir, os.W_OK):
        add("Data directory", "ok", "Writable.")
    else:
        add("Data directory", "fail", "Not writable: %s" % data_dir)

    # 3. database present
    try:
        sz = os.path.getsize(str(_cfg.DB_PATH))
        if sz > 0:
            human = "%.1f MB" % (sz / 1048576) if sz >= 1048576 else "%d KB" % max(1, sz // 1024)
            add("Database", "ok", "Present (%s)." % human)
        else:
            add("Database", "fail", "Database file is empty.")
    except OSError:
        add("Database", "fail", "Database file is missing.")

    # 3b. database integrity (corruption from a bad drive / power loss)
    try:
        import sqlite3
        dbp = str(_cfg.DB_PATH)
        if os.path.exists(dbp) and os.path.getsize(dbp) > 0:
            con = sqlite3.connect(dbp, timeout=5)
            try:
                row = con.execute("PRAGMA quick_check").fetchone()
            finally:
                con.close()
            if row and row[0] == "ok":
                bak = " (a rolling backup is kept for recovery)" if os.path.exists(dbp + ".backup") else ""
                add("Database integrity", "ok", "No corruption detected%s." % bak)
            else:
                add("Database integrity", "fail",
                    "Corruption detected — the panel restores from backup automatically on restart.")
    except Exception:
        add("Database integrity", "warn", "Couldn't run the integrity check.")

    # 4. encryption keys. The session secret is always needed (Flask signs cookies
    # with it), so its absence is a real fault. The credential key is created ONLY
    # when the first password-based credential is saved, so a missing cred_key is
    # normal (e.g. all remotes use SSH-key / Tailscale / local auth) — not a fault.
    if not _cfg.SECRET_FILE.exists():
        add("Encryption keys", "fail", "Session secret key is missing.")
    elif not _cfg.CRED_KEY_FILE.exists():
        add("Encryption keys", "ok",
            "Session key present; the credential key is created when the first "
            "saved password/credential needs it.")
    else:
        add("Encryption keys", "ok", "Session + credential keys present.")

    # 5. config loads
    try:
        _cfg.load_config()
        add("Configuration", "ok", "config.json loads cleanly.")
    except Exception:
        add("Configuration", "fail", "config.json could not be read or parsed.")

    # 6. disk space
    try:
        du = shutil.disk_usage(PANEL_DIR)
        free_gb, used_pct = du.free / (1024 ** 3), du.used / du.total * 100
        detail = "%.1f GB free (%.0f%% used)." % (free_gb, used_pct)
        add("Disk space", "warn" if (free_gb < 1 or used_pct > 92) else "ok", detail)
    except OSError:
        add("Disk space", "warn", "Couldn't read disk usage.")

    # 7. TLS certificate (only when the panel terminates TLS itself)
    cert_path = os.path.join(str(_cfg.DATA_DIR), "ssl", "cert.pem")
    if os.path.exists(cert_path):
        try:
            from cryptography import x509
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            na = getattr(cert, "not_valid_after_utc", None)
            if na is None:
                na = cert.not_valid_after.replace(tzinfo=timezone.utc)
            days = (na - datetime.now(timezone.utc)).days
            if days < 0:
                add("TLS certificate", "fail", "Expired %d day(s) ago." % -days)
            elif days < 14:
                add("TLS certificate", "warn", "Expires in %d day(s)." % days)
            else:
                add("TLS certificate", "ok", "Valid for %d more day(s)." % days)
        except Exception:
            add("TLS certificate", "warn", "Present but couldn't be parsed.")

    # 8. systemd service unit
    user_unit = os.path.expanduser("~/.config/systemd/user/linuxgsm-panel.service")
    system_unit = "/etc/systemd/system/linuxgsm-panel.service"
    if os.path.exists(user_unit) or os.path.exists(system_unit):
        add("Service", "ok", "systemd unit installed (auto-starts on boot).")
    else:
        add("Service", "warn", "No systemd unit found — the panel may not auto-start on boot.")

    # 9. automatic security updates (hardening — a warn, not a fault: the panel runs
    # fine either way, but for an unattended box you want the OS patching itself).
    try:
        au = unattended_upgrades_status()
        add("Automatic security updates", "ok" if au["enabled"] else "warn", au["detail"])
    except Exception:
        add("Automatic security updates", "warn", "Couldn't determine the update status.")

    levels = [c["level"] for c in checks]
    summary = "fail" if "fail" in levels else ("warn" if "warn" in levels else "ok")
    return {"checks": checks, "summary": summary,
            "ok": levels.count("ok"), "warn": levels.count("warn"),
            "fail": levels.count("fail")}


# ─── Debug report (safe to share on a GitHub issue) ────────────
# Config keys that are settings/behaviour, never secrets. Everything else in
# config.json (secret_key, cred_key, credentials, host keys, TOTP, …) is excluded
# by construction — this is a whitelist, not a "strip the secrets" blacklist.
_DEBUG_CONFIG_KEYS = (
    "port", "bind_host", "use_https", "trust_proxy", "cookie_secure",
    "tailscale_setup_done", "tailscale_auto_setup", "tailscale_mount",
    "setup_complete", "remember_days", "session_lifetime_hours",
    "session_protection", "audit_log_retention_days", "site_title", "site_domain",
)


def _redact(text):
    """Best-effort scrub of anything secret-looking from free text (a log tail). The
    report is whitelist-built so this is defence-in-depth: emails, long token/key/hash
    strings, and key=value secrets get masked before an admin reviews + shares it."""
    import re
    text = re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "[email]", text)
    # key=value / key: value where the key name contains a secret-ish word (incl.
    # prefixed forms like auth_token, access_key) — redact the value, keep the key.
    text = re.sub(r"(?i)\b([\w-]*(?:password|passwd|secret|token|api[_-]?key|auth[_-]?key|"
                  r"cred(?:ential)?|cookie|bearer)[\w-]*)(\s*[=:]\s*)\S+", r"\1\2[redacted]", text)
    text = re.sub(r"\b[A-Za-z0-9+/_-]{28,}={0,2}\b", "[redacted]", text)
    return text


def _dedupe_log_tracebacks(text):
    """Collapse repeated identical Python tracebacks in a journal tail so one recurring
    error (e.g. an internet scanner tripping the panel's self-signed TLS cert) doesn't
    crowd out everything else in a debug report. The FIRST full occurrence of each
    distinct traceback is kept; later identical ones are replaced with a one-line note.
    The dedup signature ignores the syslog 'time host proc[pid]:' prefix, so the same
    traceback logged at different times still matches."""
    import re
    prefix_re = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+\S+\s+[^:]+:\s?")

    def body(ln):
        return prefix_re.sub("", ln)

    lines = text.split("\n")
    n = len(lines)
    out = []           # list of str, or dict placeholders {"n": repeat_count}
    note_idx = {}      # traceback signature -> index of its placeholder in `out`
    i = 0
    while i < n:
        if body(lines[i]).startswith("Traceback (most recent call last):"):
            block = [lines[i]]
            j = i + 1
            while j < n and body(lines[j]).startswith(" "):   # indented frame lines
                block.append(lines[j])
                j += 1
            if j < n:                                          # the exception line
                block.append(lines[j])
                j += 1
            sig = "\n".join(body(b) for b in block)
            if sig in note_idx:
                out[note_idx[sig]]["n"] += 1                   # seen before → bump count
            else:
                out.extend(block)
                note_idx[sig] = len(out)
                out.append({"n": 1})                           # placeholder for a repeat note
            i = j
            continue
        out.append(lines[i])
        i += 1

    rendered = []
    for item in out:
        if isinstance(item, dict):
            if item["n"] > 1:   # only annotate when it actually repeated
                rendered.append("    ↳ (the same traceback repeated %d× more — collapsed)"
                                % (item["n"] - 1))
        else:
            rendered.append(item)
    return "\n".join(rendered)


def _github_issues_url():
    """New-issue URL for wherever this checkout's origin points (upstream for most,
    a fork if they forked). Falls back to the canonical repo."""
    import re
    fallback = "https://github.com/FMSMITH91/linuxgsm-panel/issues/new"
    try:
        out, _, rc = _git(["config", "--get", "remote.origin.url"])
        m = re.search(r"github\.com[:/]([^/\s]+/[^/\s.]+)", out.strip()) if rc == 0 else None
        return "https://github.com/%s/issues/new" % m.group(1) if m else fallback
    except Exception:
        return fallback


def generate_debug_report():
    """Build a diagnostic report an operator can attach to a GitHub issue. Whitelisted
    fields only + a redacted log tail. Returns {report, summary, issues_url, filename}."""
    import sys
    import time as _t
    import platform
    import config as _cfg
    diag = panel_diagnostics()
    ver = panel_version()
    integ = panel_integrity()
    sha = integ.get("current_sha") or "unknown"
    ts = _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime())

    # OS / runtime
    osname = ""
    try:
        with open("/etc/os-release") as f:
            kv = dict(ln.strip().split("=", 1) for ln in f if "=" in ln)
        osname = (kv.get("PRETTY_NAME", "") or kv.get("NAME", "")).strip('"')
    except OSError:
        osname = platform.system()
    kernel, _, _ = _run("uname -r", timeout=5)
    pyver = "%d.%d.%d" % sys.version_info[:3]

    # Key dependency versions
    deps = {}
    try:
        from importlib.metadata import version as _v, PackageNotFoundError
        for pkg in ("flask", "flask-socketio", "python-socketio", "paramiko",
                    "sqlalchemy", "cryptography", "eventlet"):
            try:
                deps[pkg] = _v(pkg)
            except PackageNotFoundError:
                continue  # optional dep not installed — just omit it from the report
    except Exception:
        pass  # importlib.metadata unavailable — deps section stays empty, non-fatal

    # Whitelisted config + object counts
    conf = {}
    try:
        c = _cfg.load_config()
        conf = {k: c.get(k) for k in _DEBUG_CONFIG_KEYS if k in c}
    except Exception:
        pass  # config unreadable — omit the config section, non-fatal
    counts = {}
    try:
        from models import RemoteServer, GameServer
        counts = {"remotes": RemoteServer.query.count(), "game_servers": GameServer.query.count()}
    except Exception:
        pass  # DB not queryable here — omit counts, non-fatal
    try:
        from models import database_stats
        dbs = database_stats()
    except Exception:
        dbs = {}

    def _tbl(d):
        return "\n".join("- **%s**: %s" % (k, v) for k, v in d.items()) or "- (none)"

    diag_lines = "\n".join("- [%s] **%s** — %s" % (c["level"], c["name"], c["detail"])
                           for c in diag.get("checks", []))
    header = ("## LinuxGSM Panel debug report\n\n"
              "- **Generated**: %s\n- **Panel version**: %s\n- **Commit**: %s\n"
              "- **OS**: %s\n- **Kernel**: %s\n- **Python**: %s\n\n"
              % (ts, ver, sha, osname or "?", kernel.strip() or "?", pyver))
    summary = (header + "### Diagnostics\n%s\n\n### Counts\n%s\n"
               % (diag_lines or "- (none)", _tbl(counts)))

    # Redacted recent log (user service first, then system unit). Grab a generous window
    # and collapse repeated tracebacks so one recurring benign error doesn't drown out the
    # useful lines, then redact and keep the tail.
    log, _, _ = _run("journalctl --user -u linuxgsm-panel -n 200 --no-pager 2>/dev/null", timeout=10)
    if not log.strip():
        log, _, _ = _run("journalctl -u linuxgsm-panel -n 200 --no-pager 2>/dev/null", timeout=10, sudo=True)
    log_block = _redact(_dedupe_log_tracebacks(log))[-6000:] if log.strip() else "(no journal available)"

    report = (summary
              + "\n### Dependencies\n%s\n" % _tbl(deps)
              + "\n### Database\n%s\n" % _tbl(dbs)
              + "\n### Config (non-secret settings only)\n%s\n" % _tbl(conf)
              + "\n### Recent log (redacted)\n```\n%s\n```\n"
              "\n<!-- This report was generated by the panel. It contains no secrets "
              "(credentials, keys, tokens, and emails are excluded/redacted). Review "
              "before sharing. -->\n" % log_block)

    return {"report": report, "summary": summary,
            "issues_url": _github_issues_url(),
            "filename": "linuxgsm-panel-debug-%s-%s.md" % (sha, _t.strftime("%Y%m%d-%H%M%S"))}
