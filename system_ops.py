"""System operations for the local server — UFW, Tailscale SSH, OS updates, reboot."""
import json
import logging
import os
import shlex
import subprocess
import threading
import time
import urllib.error
import urllib.request

_log = logging.getLogger("panel.system_ops")

# The panel's own install directory (this module lives inside it) — used for the
# git-based self-update feature.
PANEL_DIR = os.path.dirname(os.path.abspath(__file__))

# The branch the panel tracks out of the box. Switching to any other branch is opt-in
# (panel_switch_branch) and stored in config as "panel_branch".
_DEFAULT_BRANCH = "main"
# A deliberately strict git-ref charset: no spaces, no leading dash (option injection) and
# no ".." (traversal). Defence-in-depth — git is invoked without a shell (see _git) and the
# installer re-validates PANEL_BRANCH — but we still refuse anything outside this shape.
_BRANCH_RE = r"^[A-Za-z0-9._/-]{1,100}$"


def _valid_branch(name):
    import re
    name = (name or "").strip()
    return bool(name) and bool(re.match(_BRANCH_RE, name)) and not name.startswith("-") and ".." not in name


def _tracked_branch():
    """Branch the panel follows for updates/self-update. Defaults to 'main'; a superadmin can
    point it at another branch via panel_switch_branch (stored in config as 'panel_branch')."""
    try:
        import config as _cfg
        b = (_cfg.load_config().get("panel_branch") or _DEFAULT_BRANCH).strip()
    except Exception:
        b = _DEFAULT_BRANCH
    return b if _valid_branch(b) else _DEFAULT_BRANCH


_last_cpu_stat = {"cpus": None, "ts": 0.0}   # previous /proc/stat snapshot for a sleepless delta


def live_metrics():
    """Fast realtime metrics for the local host: per-core + overall CPU%% (via a
    /proc/stat delta) and RAM/swap (from /proc/meminfo). Reads /proc directly — no
    subprocess. The CPU delta is taken against the PREVIOUS poll's snapshot, so a
    steady poll (the page refreshes every couple of seconds) needs only ONE /proc read
    and NO in-call sleep; the % is then a smooth average over the real poll interval."""
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
            _log.debug("unreadable/odd /proc/stat → return whatever parsed", exc_info=True)
        return cpus

    now = time.time()
    b = _read_stat()
    prev, age = _last_cpu_stat["cpus"], now - _last_cpu_stat["ts"]
    if prev is not None and 0.5 <= age < 30:
        # Steady polling: diff against the last snapshot — no sleep, one read.
        a = prev
        _last_cpu_stat["cpus"], _last_cpu_stat["ts"] = b, now
    else:
        # Cold start, a long gap, or a near-simultaneous second caller: take an independent
        # 0.25s sample so the reading is always accurate (and never chains a tiny interval).
        a = b
        time.sleep(0.25)
        b = _read_stat()
        if prev is None or age >= 0.5:
            _last_cpu_stat["cpus"], _last_cpu_stat["ts"] = b, now

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
        _log.debug("/proc/meminfo unreadable or oddly formatted — fall back to zeros below", exc_info=True)
    ram_total = mem.get("MemTotal", 0)
    ram_used = ram_total - mem.get("MemAvailable", 0)
    swap_total = mem.get("SwapTotal", 0)
    swap_used = swap_total - mem.get("SwapFree", 0)

    # Root-filesystem usage (where installs/backups live). shutil.disk_usage is a cheap statvfs,
    # no subprocess — fine to poll alongside the CPU/RAM sample.
    import shutil
    disk_total = disk_used = 0
    try:
        du = shutil.disk_usage("/")
        disk_total, disk_used = du.total, du.used
    except OSError:
        _log.debug("disk_usage('/') failed — reporting zeros", exc_info=True)

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
        "disk_used": disk_used,
        "disk_total": disk_total,
        "disk_percent": round(disk_used / disk_total * 100, 1) if disk_total else 0,
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
            _log.debug("detect_tailscale_interface: could not parse status", exc_info=True)

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
            _log.debug("tailscale_ssh_status: could not parse prefs", exc_info=True)
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
            old = ""
            if "upgradable from:" in line:
                old = line.split("upgradable from:", 1)[1].strip().rstrip("]").strip()
            packages.append({"name": name, "version": version, "from": old})

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
            _log.debug("server_uptime: ignored non-fatal error", exc_info=True)

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

_status_cache = {"ts": 0.0, "data": None}
_STATUS_TTL = 15   # ufw/tailscale/sudo state changes rarely (and via the panel) — no need to
#                    re-probe (~1.2s of CPU across sudo ufw + tailscale subprocesses) every render


def get_server_status(force=False):
    """Get combined server status for the management page.
    Uses the cached update list (no network apt-update) so the page loads fast;
    the user can trigger a fresh check separately. The whole result is cached ~15s so a page
    render + its follow-up poll don't each re-run the sudo ufw / tailscale probes."""
    now = time.time()
    if not force and _status_cache["data"] is not None and (now - _status_cache["ts"]) < _STATUS_TTL:
        return _status_cache["data"]
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

    result = {
        "has_sudo": has_sudo,
        "ufw": ufw,
        "tailscale_ssh": ts_ssh,
        "tailscale_interface": ts_iface,
        "tailscale_ufw_allowed": tailscale_ufw_allowed,
        "updates": updates,
        "uptime": uptime,
    }
    _status_cache["ts"] = now
    _status_cache["data"] = result
    return result


def invalidate_server_status():
    """Drop the cached management-page status so the next read re-probes — call after a firewall
    or Tailscale-SSH change so the page reflects it immediately instead of up to _STATUS_TTL later."""
    _status_cache["data"] = None


# ─── Panel self-update (git-based) ─────────────────────────────
_update_cache = {"ts": 0.0, "data": None}
_UPDATE_TTL = 300  # re-check GitHub at most every 5 min for the sidebar badge


def panel_version():
    try:
        with open(os.path.join(PANEL_DIR, "VERSION")) as f:
            return f.read().strip() or "0.0.0"
    except Exception:
        return "0.0.0"


def panel_commit():
    """The short git commit the panel is running, with a trailing '+' when the tracked working
    tree has local modifications (e.g. a hand-edit or a partial update). Empty string if this
    isn't a git checkout. Cheap; the app reads it once at startup (it can't change until a
    restart)."""
    if not _is_git_checkout():
        return ""
    sha, _, rc = _git(["rev-parse", "--short", "HEAD"], timeout=10)
    sha = sha.strip()
    if rc != 0 or not sha:
        return ""
    dirty, _, drc = _git(["status", "--porcelain", "--untracked-files=no"], timeout=10)
    return sha + ("+" if (drc == 0 and dirty.strip()) else "")


def _git(args, timeout=45):
    """Run a git command inside the panel dir (as the panel user, no sudo). Returns
    (stdout, stderr, returncode).

    Invoked WITHOUT a shell (argument list) so a value flowing into `args` — e.g. a
    branch name from config/UI — is always a single literal argument and can never be
    parsed as an option or a second command. GIT_TERMINAL_PROMPT=0 / GIT_ASKPASS=true stop
    git from blocking on a credential prompt when the remote is private or unreachable
    (e.g. checking for updates before the repo is public) — it fails fast instead."""
    genv = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="true")
    # No shell, fixed 'git' exe, list args (each literal); refs are validated by callers.
    # B603 is the generic "you used subprocess" note, not a real finding for this no-shell call.
    gitcmd = ["git", "-C", PANEL_DIR, *args]
    try:
        r = subprocess.run(gitcmd, capture_output=True, check=False,  # nosec B603  # nosemgrep
                           text=True, timeout=timeout, env=genv)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "git timed out", -1
    except (FileNotFoundError, OSError):
        return "", "git not found", -1


def _is_git_checkout():
    return os.path.isdir(os.path.join(PANEL_DIR, ".git"))


def _repo_slug():
    """owner/repo parsed from origin's URL, so the CI-gate check works on forks too."""
    import re
    url, _, rc = _git(["remote", "get-url", "origin"], timeout=10)
    if rc != 0:
        return None
    m = re.search(r"github\.com[/:]([^/]+/[^/]+?)(?:\.git)?/?\s*$", url.strip())
    return m.group(1) if m else None


# Conclusions that mean a completed check did NOT pass.
_CI_BAD = {"failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"}
# Checks that don't gate the update-offer: `deploy` is the deployment action itself (gating on
# it would be circular, and it only exists when auto-deploy is enabled), not a verification.
_CI_IGNORE = {"deploy"}


def _remote_ci_state(sha):
    """Best-effort: have ALL of the remote commit `sha`'s checks passed on GitHub yet?

    Returns 'passing' | 'pending' | 'failing' | 'unknown'. The panel offers an update only once
    EVERY check on the commit has completed successfully — CI plus the security scans (CodeQL,
    Bandit, Semgrep, Gitleaks, pip-audit) and Lighthouse — so "check for updates" never surfaces
    a commit while anything is still running or after any check failed. (The `deploy` action is
    ignored: it's the deployment, not a verification.) Reads GitHub's public check-runs API
    anonymously (the production panel has no token); any network/parse error → 'unknown', which
    the caller treats leniently so an API hiccup never hides a real update.

    Registration timing isn't a problem in practice: every check here is push-triggered, so they
    all register within seconds of the push — long before CI (minutes) completes — so seeing
    'all completed' really does mean all of them, not just the fast ones."""
    slug = _repo_slug()
    if not slug:
        return "unknown"
    url = ("https://api.github.com/repos/%s/commits/%s/check-runs?per_page=100" % (slug, sha))
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "linuxgsm-panel-update-check",
    })
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:  # nosec B310 - fixed https host
            runs = json.loads(resp.read().decode("utf-8")).get("check_runs", [])
    except (urllib.error.URLError, ValueError, OSError):
        _log.debug("CI-gate: couldn't read check-runs for %s", sha, exc_info=True)
        return "unknown"
    runs = [r for r in runs if r.get("name") not in _CI_IGNORE]
    if not runs:
        return "pending"  # push landed but no checks have registered yet
    if any(r.get("status") != "completed" for r in runs):
        return "pending"  # at least one check still queued/running
    if any((r.get("conclusion") or "") in _CI_BAD for r in runs):
        return "failing"  # every check finished, but one didn't pass
    return "passing"


# Paths that DON'T affect the running panel — changes touching only these shouldn't raise the
# "update available" badge (e.g. editing the README or a workflow). Denylist (not allowlist) so a
# new kind of runtime file is never accidentally treated as noise: anything not listed here counts.
_NOISE_DIRS = (".github/", "docs/", "tests/", "tools/", ".vscode/")
_NOISE_FILES = {".gitignore", ".gitattributes", ".editorconfig", ".dockerignore",
                ".pre-commit-config.yaml", "codecov.yml", ".flake8", "mypy.ini"}


def _is_runtime_path(path):
    """True if this repo path affects the RUNNING panel (code, templates, static, requirements,
    install.sh, …). Docs/CI/test-scaffolding paths return False."""
    p = path.strip()
    if p.startswith("./"):      # a literal "./" prefix only — NOT lstrip("./"), which would also
        p = p[2:]               # eat the leading dot of dotfiles/dotdirs (.github, .gitignore).
    if not p:
        return False
    low = p.lower()
    if low.endswith(".md") or low == "license" or low.startswith("license."):
        return False
    if any(p.startswith(d) for d in _NOISE_DIRS):
        return False
    if p in _NOISE_FILES:
        return False
    return True


def _update_touches_runtime(target_ref):
    """Whether updating from HEAD to `target_ref` would change any file the panel actually uses.
    A pure-docs/CI/test diff returns False so the badge stops nagging about changes that don't
    affect the panel. Fails safe: if we can't compute the diff, assume it matters."""
    out, _, rc = _git(["diff", "--name-only", "HEAD.." + target_ref])
    if rc != 0:
        return True
    files = [f for f in (out or "").splitlines() if f.strip()]
    if not files:
        return True
    return any(_is_runtime_path(f) for f in files)


def _runtime_changelog(rev_range):
    """ALL commits in `rev_range` that actually change files the panel RUNS, newest first, as
    'shorthash subject' lines. Docs-only / CI-only / test-only commits are dropped, so both the
    'N commits behind' count (len) and the update card's changelog (capped by the caller) ignore
    e.g. a README edit. One `git log` call; a commit is kept only if a file it touched is runtime."""
    import re
    out, _, rc = _git(["log", "--no-decorate", "--format=%h%x09%s", "--name-only", rev_range])
    if rc != 0 or not out:
        return []
    header = re.compile(r"^([0-9a-f]{7,40})\t(.*)$")
    result, cur, runtime = [], None, False
    for line in out.splitlines():
        m = header.match(line)
        if m:
            if cur and runtime:
                result.append(cur)
            cur, runtime = "%s %s" % (m.group(1), m.group(2)), False
        elif line.strip() and _is_runtime_path(line):
            runtime = True
    if cur and runtime:
        result.append(cur)
    return result


def _compute_update_status():
    cur_ver = panel_version()
    if not _is_git_checkout():
        return {"git": False, "update_available": False, "current_version": cur_ver,
                "message": "The panel isn't a git checkout, so it can't self-update."}
    cur_sha, _, _ = _git(["rev-parse", "--short", "HEAD"])
    branch = _tracked_branch()
    ref = "origin/" + branch
    _, ferr, frc = _git(["fetch", "--quiet", "origin", branch], timeout=45)
    if frc != 0:
        # Couldn't reach the remote (private repo without creds, or offline). Do NOT
        # report an update from a stale remote-tracking ref — that would show a phantom
        # "update available" that can never be applied.
        return {"git": True, "fetched": False, "update_available": False,
                "current_version": cur_ver, "current_sha": cur_sha.strip(), "branch": branch,
                "message": "Couldn't reach the update source — it may be private or offline."}
    behind, _, _ = _git(["rev-list", "--count", "HEAD.." + ref])
    behind_n = int(behind.strip()) if behind.strip().isdigit() else 0
    rem_sha, _, _ = _git(["rev-parse", "--short", ref])

    base = {"git": True, "fetched": True, "current_version": cur_ver,
            "current_sha": cur_sha.strip(), "remote_sha": rem_sha.strip(),
            "branch": branch, "checked_at": int(time.time())}
    if behind_n == 0:
        return {**base, "update_available": False, "ci_state": "passing", "behind": 0}

    # Tracking a NON-default branch is an explicit, opt-in test mode. Those branches don't run
    # the CI/security suite on this repo (it's gated to main + PRs), so the CI-gate below would
    # show a permanent "verifying" and never apply. Offer the branch tip directly instead —
    # the snapshot + health-check + auto-rollback still guards against a branch that won't boot.
    if branch != _DEFAULT_BRANCH:
        if not _update_touches_runtime(ref):
            return {**base, "update_available": False, "ci_state": "unverified", "behind": behind_n,
                    "docs_only": True,
                    "message": "New commits on this branch only change docs/CI — nothing the panel runs."}
        tgt_ver, _, tv_rc = _git(["show", "%s:VERSION" % ref])
        rem_full, _, _ = _git(["rev-parse", ref])
        rc_log = _runtime_changelog("HEAD.." + ref)
        return {**base, "update_available": True, "ci_state": "unverified",
                "behind": len(rc_log) or behind_n, "behind_tip": behind_n,
                "remote_version": ((tgt_ver.strip() if tv_rc == 0 else "") or "?"),
                "target_sha": rem_full.strip(),
                "changes": rc_log[:10]}

    # Don't surface an update until the target commit has cleared CI on GitHub — otherwise
    # the badge pops the instant a push lands, before the workflows finish (or even if they
    # go on to fail). But if the TIP is still verifying while an EARLIER commit has already
    # passed, offer that earlier verified commit instead of blocking entirely. So: walk the
    # commits we're behind by, newest first, and update to the first one that's passed CI.
    # 'unknown' (API unreachable) counts as acceptable so a transient API error never hides a
    # legitimate update. Capped so a long-offline panel can't fire dozens of API calls.
    revs, _, _ = _git(["rev-list", "-n", "25", "HEAD.." + ref])
    commits = [c for c in (revs or "").split() if c]
    tip_state = _remote_ci_state(commits[0]) if commits else "unknown"

    target_sha, target_state, newer_unverified = None, tip_state, 0
    for idx, sha in enumerate(commits):
        st = tip_state if idx == 0 else _remote_ci_state(sha)
        if st in ("passing", "unknown"):
            target_sha, target_state, newer_unverified = sha, st, idx
            break   # newest verified commit — anything above it is still unverified

    if not target_sha:
        # Nothing in range has passed yet (all still pending, or failed).
        msg = ("An update is being verified — its checks are still running."
               if tip_state == "pending"
               else "The latest commit didn't pass its checks; holding off on this update.")
        return {**base, "update_available": False, "ci_state": tip_state,
                "behind": behind_n, "message": msg}

    # We have a verified target (possibly older than the tip if newer commits are still verifying).
    behind_target = behind_n - newer_unverified   # commits from HEAD up to & including the target
    # Don't nag if everything between here and the verified target is docs/CI/tests only — those
    # changes don't affect the running panel. (A later commit with real code will move the target
    # up and re-trigger the badge once it passes CI.)
    if not _update_touches_runtime(target_sha):
        return {**base, "update_available": False, "ci_state": target_state,
                "behind": behind_target, "behind_tip": behind_n, "docs_only": True,
                "message": "Newer commits only change docs/CI — nothing the panel runs."}
    tgt_ver, _, tv_rc = _git(["show", f"{target_sha}:VERSION"])
    rc_log = _runtime_changelog(f"HEAD..{target_sha}")   # runtime commits only (drops docs/CI)
    msg = None
    if newer_unverified > 0:
        msg = ("Updating to the latest verified version — %d newer commit%s still being verified."
               % (newer_unverified, "" if newer_unverified == 1 else "s"))
    return {
        **base,
        "update_available": True,
        "ci_state": target_state,
        "behind": len(rc_log) or behind_target,   # count only commits that change what the panel runs
        "behind_tip": behind_n,
        "newer_unverified": newer_unverified,
        "remote_version": ((tgt_ver.strip() if tv_rc == 0 else "") or "?"),
        "remote_sha": target_sha[:7],
        "target_sha": target_sha,
        "changes": rc_log[:10],
        **({"message": msg} if msg else {}),
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
    import re
    if not _is_git_checkout():
        return False, "The panel isn't a git checkout, so it can't self-update."
    # Enforce the CI gate server-side, not just by hiding the button. Re-check fresh so we
    # also catch the race where a newer, unverified commit landed between page-load and the
    # click. Refuse to pull onto a commit whose CI is still running or has FAILED — updating
    # to it could bring up an unstable panel. 'unknown' (GitHub unreachable) stays allowed so
    # a transient API outage can't lock the admin out of a legitimate update.
    try:
        st = panel_update_status(force=True)
    except Exception:
        # A failure to compute status must not crash the endpoint or block a legitimate
        # update — fall through as if the CI state were unknown (lenient).
        _log.warning("self-update CI-gate: status check failed; allowing", exc_info=True)
        st = {}
    if st.get("behind", 0) > 0 and st.get("ci_state") in ("pending", "failing"):
        if st.get("ci_state") == "failing":
            return False, ("This update is blocked: the latest commit didn't pass its "
                           "automated checks. It'll be offered once a fixed version passes CI.")
        return False, ("This update is still being verified — its checks are running. "
                       "Try again once they've passed (usually a couple of minutes).")
    installer = os.path.join(PANEL_DIR, "install.sh")
    if not os.path.isfile(installer):
        return False, "install.sh is missing, so the panel can't self-update safely."
    # The commit we're cleared to move to — the newest CI-verified one, which may be BELOW the
    # tip when newer commits are still verifying. install.sh resets to it (validated there as an
    # ancestor of the fetched tip). Only ever a bare hex SHA from git rev-list; guard the shape
    # anyway before it's exported into a root-run script.
    target_ref = (st.get("target_sha") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", target_ref):
        target_ref = ""   # fall back to install.sh's default (origin/<branch> tip)
    # Follow whatever branch the panel is tracking (default 'main'); the launcher passes it to
    # install.sh so a panel that has switched branches keeps updating on THAT branch.
    return _launch_installer(target_ref=target_ref, branch=_tracked_branch())


def _launch_installer(target_ref="", branch="", started_msg=None):
    """Write the self-update wrapper and launch it in a transient unit that OUTLIVES the panel's
    own restart. The wrapper exports PANEL_UPDATE_REF (a CI-verified commit, or empty for the
    branch tip) and PANEL_BRANCH (the branch install.sh fetches/resets to). install.sh does the
    real work: snapshot → update → health-check → rollback-on-failure. Returns (ok, message).

    Match the install's service model: a per-user service uses `systemd-run --user`; a system
    service (root install → dedicated service user) is launched as root via `sudo systemd-run`
    (the service user has NOPASSWD sudo) so install.sh can drive the system unit."""
    installer = os.path.join(PANEL_DIR, "install.sh")
    if not os.path.isfile(installer):
        return False, "install.sh is missing, so the panel can't self-update safely."
    if branch and not _valid_branch(branch):
        return False, "Invalid branch name."
    # Write the wrapper + its log inside the panel's own data dir (owned by the service user,
    # not world-writable) rather than /tmp. This script is later executed as root via
    # `sudo systemd-run`, so a predictable /tmp path would let a local user pre-plant a
    # symlink/file and get root code execution.
    _upd_dir = os.path.join(PANEL_DIR, "data")
    os.makedirs(_upd_dir, exist_ok=True)
    _log_path = os.path.join(_upd_dir, "self-update.log")
    script = (
        "#!/bin/bash\n"
        f"LOG={shlex.quote(_log_path)}\n"
        f"cd {shlex.quote(PANEL_DIR)} || exit 1\n"
        f"export PANEL_UPDATE_REF={shlex.quote(target_ref or '')}\n"
        f"export PANEL_BRANCH={shlex.quote(branch or '')}\n"
        'echo "=== panel self-update $(date) ===" > "$LOG"\n'
        f"bash {shlex.quote(installer)} >> \"$LOG\" 2>&1\n"
        'echo "=== installer exit $? ===" >> "$LOG"\n'
    )
    path = os.path.join(_upd_dir, "self-update.sh")
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
        _update_cache["ts"] = 0.0   # invalidate so the badge re-checks after the restart
        return True, (started_msg or
                      ("Update started — the panel is backing up, updating, and verifying it "
                       "restarts cleanly. If the new version fails to come up it rolls back "
                       "automatically. This takes up to a minute."))
    except Exception:
        _log.exception("panel installer launch failed to start")
        return False, "Could not start the updater — check the panel logs."


def _fetch_all_branches():
    """Make EVERY remote branch visible + switchable, then fetch them. install.sh clones with
    `--depth 1 --branch main`, i.e. a SHALLOW, SINGLE-BRANCH clone whose remote only tracks main —
    so a plain fetch never sees other branches. Widen the refspec to all branches and unshallow so
    the history a switch/rollback needs is present. Idempotent; each step is best-effort."""
    _git(["remote", "set-branches", "origin", "*"], timeout=15)   # track every branch, not just main
    # Unshallow if the clone was shallow (errors + no-ops on a complete repo); then a normal fetch
    # covers the already-complete case.
    _, _, rc = _git(["fetch", "--prune", "--tags", "--unshallow", "origin"], timeout=120)
    if rc != 0:
        _git(["fetch", "--prune", "--tags", "origin"], timeout=90)


def list_panel_branches():
    """Remote branches available to switch to, most-recently-updated first, plus the currently
    tracked branch. Returns (branches, current). Best-effort: ([current], current) on failure."""
    branch = _tracked_branch()
    if not _is_git_checkout():
        return [branch], branch
    _fetch_all_branches()   # widen a single-branch/shallow clone so ALL branches show up + refresh
    out, _, rc = _git(["for-each-ref", "--format=%(refname:short)", "--sort=-committerdate",
                       "refs/remotes/origin"], timeout=20)
    branches = []
    if rc == 0:
        for line in (out or "").splitlines():
            name = line.strip()
            if not name.startswith("origin/"):
                continue
            name = name[len("origin/"):]
            if name and name != "HEAD" and _valid_branch(name) and name not in branches:
                branches.append(name)
    if branch not in branches:
        branches.insert(0, branch)
    return branches, branch


def panel_switch_branch(branch):
    """Point the panel at a different branch and check it out, with the SAME snapshot / health-check
    / auto-rollback safety as a normal update. Superadmin-gated at the route. Returns (ok, message)."""
    branch = (branch or "").strip()
    if not _valid_branch(branch):
        return False, "Invalid branch name."
    if not _is_git_checkout():
        return False, "The panel isn't a git checkout, so it can't switch branches."
    # Confirm the branch exists on the remote before committing the config to it.
    _, _, rc = _git(["ls-remote", "--exit-code", "--heads", "origin", branch], timeout=20)
    if rc != 0:
        return False, "Branch '%s' doesn't exist on the remote." % branch
    try:
        import config as _cfg
        cfg = _cfg.load_config()
        cfg["panel_branch"] = branch
        _cfg.save_config(cfg)
    except Exception:
        _log.exception("switch-branch: could not save tracked branch")
        return False, "Could not save the branch selection."
    msg = ("Switching to '%s' — the panel is backing up, checking out that branch and verifying it "
           "restarts cleanly (auto-rollback if it doesn't). This takes up to a minute." % branch)
    # target_ref empty → install.sh resets to the tip of PANEL_BRANCH.
    return _launch_installer(target_ref="", branch=branch, started_msg=msg)


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


def panel_repair_database():
    """Repair the panel database on-demand, OFFLINE and safely. A live DB can't be rebuilt while the
    running panel holds it open, so a DETACHED transient job stops the panel service, runs
    db_maintenance (health-check → rebuild readable data via SQLite .recover, else restore the last
    healthy backup → optimize → re-check), then starts the service again — the flagged database is
    copied aside first and never deleted. Same stop/repair/start the auto-updater uses. (ok, msg)."""
    base = os.path.dirname(os.path.abspath(__file__))
    py = os.path.join(base, "venv", "bin", "python3")
    if not os.path.exists(py):
        py = os.path.join(base, "venv", "bin", "python")
    dbm = os.path.join(base, "db_maintenance.py")
    if not os.path.exists(py) or not os.path.exists(dbm):
        return False, "The repair tool isn't available on this install."
    user_unit = os.path.expanduser("~/.config/systemd/user/linuxgsm-panel.service")
    system_unit = "/etc/systemd/system/linuxgsm-panel.service"
    if os.path.exists(user_unit) or not os.path.exists(system_unit):
        sc = "systemctl --user"
        run = ["systemd-run", "--user", "--collect", "--on-active=2"]
    else:
        sc = "sudo systemctl"
        run = ["sudo", "systemd-run", "--collect", "--on-active=2"]
    # ONE detached unit (survives the panel going down): stop → repair offline → start.
    script = ("%s stop linuxgsm-panel.service; ( cd %s && %s %s update ); %s start linuxgsm-panel.service"
              % (sc, shlex.quote(base), shlex.quote(py), shlex.quote(dbm), sc))
    try:
        subprocess.Popen(run + ["bash", "-c", script],  # nosec B603  # nosemgrep - internal paths, shlex-quoted, no user input
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=os.environ.copy())
        return True, ("Repairing the database — the panel stops, repairs it offline (your data is copied "
                      "aside first), and restarts. Give it about a minute, then reload the page.")
    except Exception:
        _log.exception("db repair failed to dispatch")
        return False, "Couldn't start the repair job — check the panel logs."


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


def host_has_ip(ip):
    """True if `ip` is assigned to an interface on this host, so the panel could actually bind
    to it. Used to refuse binding the panel to an address that isn't local (a typo would fail
    to bind and take the panel down). Best-effort: on any error returns True, so a flaky check
    never blocks a legitimate change — the caller still guards the risky loopback case."""
    try:
        out, _, _ = _run("ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1", timeout=8)
        return str(ip) in set(out.split())
    except Exception:
        return True


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


_integrity_cache = {"ts": 0.0, "data": None}
_INTEGRITY_TTL = 60


def panel_integrity(force=False):
    """File-integrity check (git diff), cached ~60s so a page load / debug report doesn't spawn
    git every time. pass force=True to re-check immediately (e.g. right after a repair)."""
    now = time.time()
    if not force and _integrity_cache["data"] is not None and (now - _integrity_cache["ts"]) < _INTEGRITY_TTL:
        return _integrity_cache["data"]
    data = _compute_panel_integrity()
    _integrity_cache["ts"] = now
    _integrity_cache["data"] = data
    return data


def _compute_panel_integrity():
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
    info = panel_integrity(force=True)   # repair must act on the CURRENT state, not a cached one
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
    _integrity_cache["data"] = None   # files changed on disk — next check must re-read
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


# ─── fail2ban jail for the panel's own web login ──────────────────────────────
_F2B_PANEL_FILTER = "/etc/fail2ban/filter.d/linuxgsm-panel.conf"
_F2B_PANEL_JAIL = "/etc/fail2ban/jail.d/linuxgsm-panel.conf"


def _panel_f2b_filter_body():
    """fail2ban filter matching the panel's own auth.log lines; <HOST> captures the offender."""
    return ("[Definition]\n"
            "failregex = panel login (?:failed|blocked) from <HOST>$\n"
            "ignoreregex =\n")


def _panel_f2b_jail_body(auth_log, web_port):
    """Jail: 5 failures in 10 min → 1-hour ban, on the panel's web port. In jail.d/ so it sits
    alongside (doesn't conflict with) any [sshd] jail."""
    return ("[linuxgsm-panel]\n"
            "enabled = true\n"
            "port = %d\n"
            "filter = linuxgsm-panel\n"
            "logpath = %s\n"
            "maxretry = 5\n"
            "findtime = 10m\n"
            "bantime = 1h\n" % (web_port, auth_log))


def _panel_f2b_jail_port():
    """Port the current panel jail file is set to, or None. The jail file is root-owned but
    world-readable, so the panel process can read it without sudo. Best-effort."""
    import re
    try:
        with open(_F2B_PANEL_JAIL) as f:
            for line in f:
                m = re.match(r"\s*port\s*=\s*(\d+)\s*$", line)
                if m:
                    return int(m.group(1))
    except OSError:
        _log.debug("f2b: could not read jail port", exc_info=True)
    return None


def _write_root_file(path, content):
    """Write `content` to a root-owned path. The WRITE must be elevated: a plain `sudo echo … > path`
    elevates only `echo` while the shell does the `>` redirect as the (unprivileged) panel user —
    which fails on a root-owned dir, because the panel runs as a non-root systemd --user service.
    Pipe into `sudo tee` so the write lands as root. base64 keeps any shell metacharacter in
    `content` inert; the path is shell-quoted. Returns the _run tuple."""
    import base64
    b64 = base64.b64encode(content.encode()).decode()
    tee = "tee" if (hasattr(os, "geteuid") and os.geteuid() == 0) else "sudo tee"
    return _run("echo %s | base64 -d | %s %s >/dev/null"
                % (shlex.quote(b64), tee, shlex.quote(path)), timeout=15, sudo=False)


def panel_fail2ban_status():
    """Whether the panel-login fail2ban jail is active on this host, and how many IPs it's banning.
    Best-effort; {'installed': bool, 'enabled': bool, 'banned': int}."""
    have, _, _ = _run("command -v fail2ban-client >/dev/null 2>&1 && echo yes || echo no", timeout=10)
    if "yes" not in (have or ""):
        return {"installed": False, "enabled": False, "banned": 0}
    out, _, rc = _run("fail2ban-client status linuxgsm-panel 2>/dev/null", timeout=10, sudo=True)
    if rc != 0 or not out:
        return {"installed": True, "enabled": False, "banned": 0}
    import re
    m = re.search(r"Currently banned:\s*(\d+)", out)
    return {"installed": True, "enabled": True, "banned": int(m.group(1)) if m else 0}


def panel_fail2ban_banned_ips():
    """The set of IPs the panel-login jail is currently banning (empty if the jail isn't up).
    Used by the ban-watcher to record new bans/unbans in the audit log."""
    import re
    out, _, rc = _run("fail2ban-client status linuxgsm-panel 2>/dev/null", timeout=10, sudo=True)
    if rc != 0 or not out:
        return set()
    m = re.search(r"Banned IP list:\s*(.*)", out)
    return set(p for p in (m.group(1).split() if m else []) if p)


def configure_panel_fail2ban(auth_log, web_port):
    """Install fail2ban (if needed) and configure a jail that bans IPs which repeatedly fail the
    PANEL's web login — it tails the panel's auth.log and bans on the web port. Idempotent.
    Returns (ok, message)."""
    try:
        web_port = int(web_port)
    except (TypeError, ValueError):
        return False, "Invalid web port."
    if not (1 <= web_port <= 65535):
        return False, "Invalid web port."
    if not auth_log or "\n" in auth_log:
        return False, "Invalid auth-log path."

    # fail2ban 0.11 (Ubuntu 22.04) REFUSES to start a jail whose logpath doesn't exist yet, and a
    # brand-new panel has no failed logins, so auth.log may be absent — that's the usual "jail
    # didn't come up" cause. Create it now (as the panel user, which owns it, so the panel can still
    # write to it) so the jail always has a file to tail.
    try:
        os.makedirs(os.path.dirname(auth_log) or ".", exist_ok=True)
        with open(auth_log, "a"):
            pass
    except OSError:
        _log.debug("f2b: could not pre-create auth log", exc_info=True)

    have, _, _ = _run("command -v fail2ban-client >/dev/null 2>&1 && echo yes || echo no", timeout=10)
    if "yes" not in (have or ""):
        _run("DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null", timeout=120, sudo=True)
        _run("DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban 2>&1", timeout=300, sudo=True)
        have2, _, _ = _run("command -v fail2ban-client >/dev/null 2>&1 && echo yes || echo no", timeout=10)
        if "yes" not in (have2 or ""):
            return False, "Couldn't install fail2ban on this host."

    _write_root_file(_F2B_PANEL_FILTER, _panel_f2b_filter_body())
    _write_root_file(_F2B_PANEL_JAIL, _panel_f2b_jail_body(auth_log, web_port))

    _run("systemctl enable --now fail2ban 2>&1", timeout=45, sudo=True)
    _run("fail2ban-client reload 2>&1 || systemctl restart fail2ban 2>&1", timeout=45, sudo=True)

    _f2b_ok_msg = ("fail2ban is now protecting the panel login — 5 failed logins from an IP in "
                   "10 minutes get it banned for an hour.")
    # fail2ban's reload is ASYNCHRONOUS — on a busy host the jail can take a moment to register, so
    # poll instead of checking once (the old single check was the "didn't come up" false alarm).
    for _ in range(6):
        if panel_fail2ban_status().get("enabled"):
            return True, _f2b_ok_msg
        time.sleep(1)
    # Still down after a reload: one hard restart, then a final look.
    _run("systemctl restart fail2ban 2>&1", timeout=45, sudo=True)
    time.sleep(2)
    if panel_fail2ban_status().get("enabled"):
        return True, _f2b_ok_msg
    # Give up — but surface the REAL reason instead of a generic message.
    detail, derr, _ = _run("fail2ban-client status linuxgsm-panel 2>&1", timeout=10, sudo=True)
    reason = (detail or derr or "").strip()
    if not reason:
        reason, _, _ = _run("journalctl -u fail2ban --no-pager -n 25 2>/dev/null | "
                            "grep -iE 'linuxgsm-panel|have not found|log file|error' | tail -2",
                            timeout=10, sudo=True)
    reason = (reason or "").replace("\n", " ").strip()[:200]
    return False, ("Configured fail2ban, but the jail didn't come up. %s"
                   % (reason or "Check `fail2ban-client status linuxgsm-panel` and the panel logs."))


def ensure_panel_fail2ban(auth_log, web_port):
    """Idempotently make sure the panel-login jail is active on the CURRENT web port. Safe to call
    on EVERY startup and after a port change: a healthy jail on the right port costs just a status
    read (no reload), while a missing jail or a stale port triggers a rewrite + reload. Does NOT
    install fail2ban (that's the installer's job) — no-ops when it isn't present. Returns (ok, msg)."""
    try:
        web_port = int(web_port)
    except (TypeError, ValueError):
        return False, "Invalid web port."
    st = panel_fail2ban_status()
    if not st.get("installed"):
        return False, "fail2ban isn't installed on this host."
    if st.get("enabled") and _panel_f2b_jail_port() == web_port:
        return True, "panel-login jail already active on port %d" % web_port
    return configure_panel_fail2ban(auth_log, web_port)


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
        _log.debug("importlib.metadata unavailable — deps section stays empty, non-fatal", exc_info=True)

    # Whitelisted config + object counts
    conf = {}
    try:
        c = _cfg.load_config()
        conf = {k: c.get(k) for k in _DEBUG_CONFIG_KEYS if k in c}
    except Exception:
        _log.debug("config unreadable — omit the config section, non-fatal", exc_info=True)
    counts = {}
    try:
        from models import RemoteServer, GameServer
        counts = {"remotes": RemoteServer.query.count(), "game_servers": GameServer.query.count()}
    except Exception:
        _log.debug("DB not queryable here — omit counts, non-fatal", exc_info=True)
    # DB health first (PRAGMA integrity_check), then size/WAL/row stats — so a corrupt or
    # flagged database is obvious near the top of the Database section of an issue report.
    dbs = {}
    try:
        import db_maintenance
        _db_ok, _db_detail = db_maintenance.integrity_check(str(_cfg.DB_PATH))
        dbs["health"] = "ok" if _db_ok else ("PROBLEM — %s" % _db_detail)
    except Exception:
        _log.debug("db integrity_check unavailable for debug report, non-fatal", exc_info=True)
    try:
        from models import database_stats
        dbs.update(database_stats())
    except Exception:
        _log.debug("database_stats unavailable for debug report, non-fatal", exc_info=True)

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
    # Grab a wide window (400 lines) so a recent restart's shutdown AND startup lines both land in
    # the report — that "before + after it came back up" context is usually what's needed.
    log, _, _ = _run("journalctl --user -u linuxgsm-panel -n 400 --no-pager 2>/dev/null", timeout=10)
    if not log.strip():
        log, _, _ = _run("journalctl -u linuxgsm-panel -n 400 --no-pager 2>/dev/null", timeout=10, sudo=True)
    if log.strip():
        log_block = _redact(_dedupe_log_tracebacks(log))
        if len(log_block) > 8000:                       # keep the tail, but never start mid-line
            log_block = log_block[-8000:]
            log_block = log_block[log_block.find("\n") + 1:]   # drop the partial first line
    else:
        log_block = "(no journal available)"

    # Last self-update outcome (from data/self-update.log): explicitly surface a FAILED /
    # rolled-back update — exactly the case an operator needs help diagnosing — plus the log
    # tail so the failing step is visible.
    try:
        upd = panel_update_log()
    except Exception:
        upd = {"exists": False}
    if upd.get("exists"):
        u_lines = upd.get("lines", [])
        u_text = "\n".join(u_lines)
        if "could not confirm health" in u_text:
            u_outcome = "FAILED — update broke health AND the automatic rollback couldn't confirm health"
        elif "failed its health check and was rolled back" in u_text or "Rolling back" in u_text:
            u_outcome = "FAILED — update failed its health check and was rolled back to the previous version"
        elif "Update complete" in u_text or "Health check passed" in u_text:
            u_outcome = "succeeded"
        else:
            u_outcome = "unknown (in progress, or the log doesn't show a final outcome)"
        update_section = ("\n### Last update\n- **Outcome**: %s\n```\n%s\n```\n"
                          % (u_outcome, _redact("\n".join(u_lines[-25:])) or "(empty)"))
    else:
        update_section = "\n### Last update\n- No panel update has been run through the panel yet.\n"

    report = (summary
              + "\n### Dependencies\n%s\n" % _tbl(deps)
              + "\n### Database\n%s\n" % _tbl(dbs)
              + "\n### Config (non-secret settings only)\n%s\n" % _tbl(conf)
              + update_section
              + "\n### Recent log (redacted)\n```\n%s\n```\n"
              "\n<!-- This report was generated by the panel. It contains no secrets "
              "(credentials, keys, tokens, and emails are excluded/redacted). Review "
              "before sharing. -->\n" % log_block)

    return {"report": report, "summary": summary,
            "issues_url": _github_issues_url(),
            "filename": "linuxgsm-panel-debug-%s-%s.md" % (sha, _t.strftime("%Y%m%d-%H%M%S"))}
