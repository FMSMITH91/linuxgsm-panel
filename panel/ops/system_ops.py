"""System operations for the local server — UFW, Tailscale SSH, OS updates, reboot."""
import json
import logging
import os
import re
import shlex
import subprocess
from panel.core import terminal
import threading
import time
import urllib.error
import urllib.request

_log = logging.getLogger("panel.system_ops")

# The panel's own install directory — used for the git-based self-update feature. Taken from
# panel/__init__.py rather than this file's dirname: this module lives in panel/ops/ now, and
# self-update, integrity-repair and the db_maintenance lookup all need the CHECKOUT root.
from panel import REPO_ROOT as _REPO_ROOT
PANEL_DIR = str(_REPO_ROOT)

# The branch the panel tracks out of the box. Switching to any other branch is opt-in
# (panel_switch_branch) and stored in config as "panel_branch".
_DEFAULT_BRANCH = "main"
# A deliberately strict git-ref charset: no spaces, no leading dash (option injection) and
# no ".." (traversal). Defence-in-depth — git is invoked without a shell (see _git) and the
# installer re-validates PANEL_BRANCH — but we still refuse anything outside this shape.
_BRANCH_RE = r"^[A-Za-z0-9._/-]{1,100}$"


def _is_system_service():
    """True when the panel runs as a SYSTEM systemd unit (root install), False for a per-user one.

    Five copies of this three-line test had accumulated. Extracting it is worth doing on its own,
    but there is a second reason: CodeQL's py/uninitialized-local-variable reported the `if` after
    the inline form as reading a possibly-uninitialized local, on an assignment that is plainly
    unconditional. The report was wrong; the duplication that produced the shape was not. One
    function, one answer, and nothing for the analysis to be confused by."""
    user_unit = os.path.expanduser("~/.config/systemd/user/linuxgsm-panel.service")
    return (not os.path.exists(user_unit)) and os.path.exists("/etc/systemd/system/linuxgsm-panel.service")


def _valid_branch(name):
    name = (name or "").strip()
    return bool(name) and bool(re.match(_BRANCH_RE, name)) and not name.startswith("-") and ".." not in name


def _tracked_branch():
    """Branch the panel follows for updates/self-update. Defaults to 'main'; a superadmin can
    point it at another branch via panel_switch_branch (stored in config as 'panel_branch')."""
    try:
        from panel.core import config as _cfg
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
        key=lambda x: int(x[3:]) if x[3:].isdecimal() else 0,
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
        # Same flag as the remote twin (ssh_manager._core.remote_live_metrics), and the same
        # meaning: every number here is 0 when nothing could be read, and a caller cannot tell
        # that from a genuinely idle host. /proc is local, so this is almost always True — but
        # remote_live_metrics DELEGATES here for the panel's own host, and a dict without the
        # flag would read as "unreadable" the moment anyone checks it.
        "read_ok": bool(ram_total and cores),
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

from panel.security import privileged as _priv

_HELPER_STATE = {"present": None}


def _helper_present():
    """Whether the root-owned privileged helper is installed on this machine (cached)."""
    if _HELPER_STATE["present"] is None:
        try:
            _HELPER_STATE["present"] = (os.path.isfile(_priv.HELPER_PATH)
                                        and os.access(_priv.HELPER_PATH, os.X_OK))
        except Exception:
            _HELPER_STATE["present"] = False
    return _HELPER_STATE["present"]


def _can_escalate():
    """Whether this host can run a privileged verb at all — the helper, being root already, or
    passwordless sudo.

    `_check_sudo()` alone was the gate on the OS update and the reboot, and it is the WRONG
    question on a hardened host: install.sh writes `<user> ALL=(root) NOPASSWD: <helper>` once the
    root-owned pieces are in place, and under that grant `sudo -n true` is DENIED while
    `sudo -n <helper> apt-upgrade` works perfectly. So the two actions refused, with a message
    telling the admin to configure passwordless sudo — that is, to undo the hardening the
    installer had just applied. Every other privileged path here already branches on the helper;
    these two did not."""
    return _helper_present() or (hasattr(os, "geteuid") and os.geteuid() == 0) or _check_sudo()


def _run_verb(verb, args=(), timeout=30, merge_stderr=True):
    """Run a privileged VERB (privileged.py) on this host. system_ops is always the panel's own
    machine, so there is no remote transport here — just the helper when it is installed, the tool
    directly when we are already root, and the pre-helper shell form otherwise.

    That last branch is why this is not yet a privilege boundary: see run_privileged() in
    ssh_manager for the same caveat. It exists so a host that has the new code but has not had
    install.sh re-run as root keeps working."""
    if _helper_present():
        argv = _priv.helper_argv(verb, args)
    elif hasattr(os, "geteuid") and os.geteuid() == 0:
        argv = _priv.tool_argv(verb, args)
    else:
        return _run(_priv.remote_command(verb, args, merge_stderr=merge_stderr),
                    timeout=timeout, sudo=True)
    try:
        # Semgrep's dangerous-subprocess-use rules flag any subprocess call whose first argument is
        # not a literal string. That is the shape here and it is the point of the change: `argv`
        # comes from privileged.py's fixed verb table, where every element is a literal or a value
        # that passed a validator, and shell=False means no element is ever interpreted. Replacing
        # it with a literal string would mean going back to composing a command, which is the thing
        # being removed. Reviewed and suppressed rather than silently left red.
        #
        # BOTH rule ids, ON ONE LINE. They are separate rules with separate suppressions, and
        # semgrep reads only the comment IMMEDIATELY above a finding — so when these were two
        # stacked nosemgrep lines, the upper one (-audit) was inert and Codacy reported it as a
        # standing Error while the lower one worked. Comma-separated on a single line is what
        # actually suppresses both. -audit fires on "not a static string", -tainted-env-args on
        # "user controlled data".
        # stdin: the verb's own text when it has one, else DEVNULL. NOT the default of
        # inheriting -- see _POPEN_KW in ssh_manager/_core.py for what that cost.
        _in = _priv.stdin_for(verb)
        _stdin_kw = {"input": _in} if _in is not None else {"stdin": subprocess.DEVNULL}
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit,python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        r = subprocess.run(argv, shell=False,  # nosec B603 - argv from privileged.py's fixed table
                           capture_output=True, text=True,
                           timeout=timeout, **_stdin_kw)
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except FileNotFoundError:
        return "", "Command not found", -1
    except Exception:
        _log.debug("privileged verb failed", exc_info=True)
        return "", "command execution error", -1
    out, err = (r.stdout or "").strip(), (r.stderr or "").strip()
    if merge_stderr:
        # The shell form ended in `2>&1` and callers read tool errors out of stdout; merging keeps
        # a message on the stream its caller already reads.
        return ("\n".join(x for x in (out, err) if x)).strip(), "", r.returncode
    return out, err, r.returncode


def _run(cmd, timeout=30, sudo=False, text=True):
    """Run a shell command. Returns (stdout, stderr, exit_code)."""
    # os.geteuid() is Unix-only; guard it so callers don't crash off-Linux (tests).
    if sudo and hasattr(os, "geteuid") and os.geteuid() != 0:
        cmd = f"sudo {cmd}"
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=text, timeout=timeout,
            stdin=subprocess.DEVNULL,
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


_SUDO_PROBE = {"at": 0.0, "ok": None}
_SUDO_PROBE_TTL = 300     # seconds; passwordless-sudo status does not change minute to minute


def _check_sudo(force=False):
    """Whether we can sudo without a password prompt. CACHED for _SUDO_PROBE_TTL.

    Each probe is a real `sudo -n true`, and a failure is recorded by pam_faillock as an
    authentication failure — so repeatedly asking (this is reached from several page renders) can
    count a user towards a lockout on their own machine. The answer changes about as often as
    /etc/sudoers does, so probing once every few minutes is plenty."""
    import time as _time
    now = _time.time()
    if not force and _SUDO_PROBE["ok"] is not None and (now - _SUDO_PROBE["at"]) < _SUDO_PROBE_TTL:
        return _SUDO_PROBE["ok"]
    out, err, rc = _run("sudo -n true 2>/dev/null && echo 'OK' || echo 'NOPASS'", timeout=10)
    _SUDO_PROBE["ok"] = "OK" in out
    _SUDO_PROBE["at"] = now
    return _SUDO_PROBE["ok"]


# ─── UFW ──────────────────────────────────────────────────────

# `ufw status` runs through gettext, and its Status line is translated whole: a Dutch host prints
# `Status: actief`. Testing for the English word read that host's LIVE firewall as inactive — the
# badge said "Inactive", and the lockout guard (which skips every rule when the firewall is off)
# let the last SSH rule be deleted. What ufw never translates is the rule rows' actions and the
# dashed underline of its rules header, and it prints those ONLY while the firewall is loaded
# (backend_iptables.get_status returns the bare inactive line before listing anything).
_UFW_RULES_UNDERLINE_RE = re.compile(r"(?m)^[ \t]*-+[ \t]+-+[ \t]+-+[ \t]*(?=\r?\n|\Z)")


def ufw_status_active(status_out):
    """True when `ufw status` (any format) reports a loaded firewall, in any locale.

    The English Status value answers directly. A translated one answers through the rules listing:
    present means active. A translated firewall that is active with NO rules is indistinguishable
    from an inactive one and reads False — there is nothing on it to protect or parse. A rule
    comment cannot forge either answer: the Status test reads only the line's value, and a comment
    shares its line with the rule, so it can never be a line of dashes on its own."""
    text = status_out or ""
    for line in text.splitlines():
        if line.strip().lower().startswith("status:"):
            value = line.split(":", 1)[1].strip().lower()
            if value == "active":
                return True
            if value == "inactive":
                return False
            break
    return bool(_UFW_RULES_UNDERLINE_RE.search(text))


def ufw_status():
    """Get UFW status and rules."""
    out, err, rc = _run_verb("ufw-status", ["verbose"], timeout=15)
    if rc != 0:
        return {"enabled": False, "status_text": "not_installed" if "not found" in err or "not installed" in err else "inactive", "rules": []}

    enabled = ufw_status_active(out)
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

        # The verb runs `ufw status verbose`, whose columns are "To  Action  From" — there are
        # NO rule numbers (only `ufw status numbered` has those). The branch here tested
        # parts[0][0].isdecimal() and called the result "num", so a port landed in the number
        # field and EVERY rule whose To column is not numeric was dropped entirely: the
        # tailscale0 allow, app profiles like OpenSSH, and every `panel-block` DENY. Split on the
        # ACTION instead, which is the one column with a fixed vocabulary.
        m = _UFW_RULE_RE.match(line)
        if m:
            rules.append({"to": m.group(1).strip(), "action": m.group(2),
                          "direction": m.group(3), "from": m.group(4).strip()})

    return {"enabled": enabled, "status_text": status_text, "rules": rules}


# "<to>  <ACTION> <DIR>  <from>" — the shape of every rule row in `ufw status verbose`.
# ALLOW/DENY/REJECT/LIMIT is the only column with a closed vocabulary, so it is the anchor.
_UFW_RULE_RE = re.compile(r"^(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s*(.*)$")


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
    # _run_verb, not _run: this is a VERB plus its argument list, not a shell string. Written as
    # `_run(...)` it passed [ts_interface] as the positional `timeout` AND timeout=15 by keyword,
    # so every call raised TypeError before reaching UFW — see the regression test in unit_test.py.
    out1, err1, rc1 = _run_verb("ufw-allow-iface", [ts_interface], timeout=15)
    if rc1 == 0:
        return True, f"UFW rule added for interface '{ts_interface}'"
    return False, err1 or out1 or "Failed to add UFW rule"


def detect_tailscale_interface():
    """Detect the Tailscale network interface name.

    Every method here must return a TAILSCALE interface or nothing. The first one used to list
    kernel-WireGuard devices (`ip link show type wireguard`) and accept any name containing "wg" —
    but Tailscale on Linux is USERSPACE WireGuard over a TUN, so that listing can never contain
    tailscale0 and the branch could only ever return something else. On a host running both
    Tailscale and plain WireGuard it returned wg0, and the "Allow Tailscale" button then ran
    `ufw allow in on wg0` — opening all inbound traffic on an unrelated VPN — and reported success
    naming it, while tailscale0 stayed blocked and get_server_status()["tailscale_ufw_allowed"]
    (a substring match on that name) read True.
    """
    # Method 1: a wireguard-type device that is actually Tailscale's (some setups do run
    # tailscaled against the kernel module). The name must say so — "wg" does not.
    out, _, rc = _run("ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}'", timeout=5)
    if rc == 0 and out:
        for iface in out.split("\n"):
            if "tailscale" in iface.lower():
                return iface.strip()

    # Method 2: Look for tailscale interface in ip link
    out, _, rc = _run("ip -o link show 2>/dev/null | grep -i tailscale | awk -F': ' '{print $2}'", timeout=5)
    if rc == 0 and out:
        return out.strip().split("\n")[0]

    # Method 3: Check Tailscale's OWN device names. This list used to be
    # ["tailscale0", "wg0", "utun"], and neither of the last two is Tailscale's: `wg0` is simply
    # what `wg-quick up wg0` creates. So the one method that never got the docstring's name test
    # broke the invariant the other three keep — on a host running plain WireGuard with no
    # tailscale0 (Tailscale not installed, or tailscaled running --tun=userspace-networking, the
    # container default, where there is no TUN device at all) it answered "wg0". That is the exact
    # incident above, still live: the button ran `ufw allow in on wg0`, opening all inbound traffic
    # on an unrelated VPN and reporting success naming it, and it ran BEFORE method 4, which reads
    # `tailscale status --json` and would have answered tailscale0 correctly.
    for name in ["tailscale0", "tailscale1"]:
        out, _, rc = _run(f"ip link show {name} 2>/dev/null && echo 'FOUND' || echo 'NOTFOUND'", timeout=5)
        # Both halves: "NOTFOUND" is not in "" either, so a probe that did not run named this
        # interface as present. rc is already captured here; the positive token is the cheaper
        # and more direct test, and matches the `id` probe in manage_servers.py.
        if "NOTFOUND" not in out and "FOUND" in out:   # "FOUND" is a substring of "NOTFOUND"
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

def parse_upgradable(out):
    """Parse `apt list --upgradable` output into [{name, version, from, suite}], sorted by name.

    Each line looks like 'pkg/repo 1.2.3 amd64 [upgradable from: 1.2.2]' — we pull the package name,
    the NEW version, the currently-installed version (so the UI can show 'name  old → new'), and the
    suite. The suite is the only thing in this output that says an update is a SECURITY one
    ("jammy-security"), which is what lets the alerts call those out separately.

    Shared by the local check here and ssh_manager's remote one so the two can't drift: it also has
    to skip apt's header, blank lines, and the "N: ..." notices apt sometimes writes to stdout.
    """
    pkgs = []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line or line.startswith("Listing"):
            continue
        parts = line.split()
        if not parts:
            continue
        # partition, not split: a line with no slash is apt's "N: ..." notice or some other
        # non-package output, and this parser reads a remote host's stdout — it must skip that
        # line, not raise on it.
        name, _slash, suite = parts[0].partition("/")
        if not suite:
            continue
        old_ver = ""
        if "upgradable from:" in line:
            old_ver = line.split("upgradable from:", 1)[1].strip().rstrip("]").strip()
        pkgs.append({"name": name, "version": parts[1] if len(parts) > 1 else "",
                     "from": old_ver, "suite": suite})
    pkgs.sort(key=lambda p: p["name"])
    return pkgs


def os_update_available(refresh=True):
    """Check if OS updates are available (apt list --upgradable).
    refresh=False skips the network `apt update` (uses the cached package lists),
    which keeps page loads fast — the dedicated "check for updates" action passes
    refresh=True to force a fresh sync.

    "ok" is apt's own exit status. A failed check produces no output, which is
    indistinguishable from a clean host unless the caller can see that the check
    itself did not run — and a caller that reads a failure as "nothing waiting"
    will re-announce the same packages later."""
    if refresh:
        _run_verb("apt-update", [], timeout=60, merge_stderr=False)

    # No filtering greps in the pipeline: their exit status would mask apt's own, and a clean host
    # (grep matches nothing → exit 1) would be indistinguishable from a failed check. parse_upgradable
    # drops the header and any non-package line itself, so `rc` here is apt's.
    out, _, rc = _run("apt list --upgradable 2>/dev/null", timeout=30)
    packages = parse_upgradable(out)
    return {"ok": rc == 0, "updates_available": len(packages) > 0,
            "count": len(packages), "packages": packages}


def os_run_update():
    """Run apt upgrade in background. Returns (success, message)."""
    if not _can_escalate():
        return False, "Sudo access required. Configure passwordless sudo for the panel user."

    # Run in background thread
    def _bg_update():
        # The tuple used to be dropped. _run_verb never raises — it turns every failure into a
        # non-zero rc or ("", "...", -1) — so apt failing on a held dpkg lock, a full disk, a
        # missing helper verb or a sudo refusal left NO trace anywhere: the route had already
        # answered "OS update started in background" and written an os_update_run audit row.
        # This thread outlives the HTTP response, so the log is the only place the outcome can
        # still be reported; every other _run_verb call site in this file already checks rc.
        _out, _err, _rc = _run_verb("apt-upgrade", [], timeout=600)
        if _rc != 0:
            _log.error("apt-upgrade verb failed: rc=%s %s", _rc, (_err or _out or "")[:200])

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
    current = None
    for line in lines:
        if line.startswith("Start-Date:"):
            if current:
                entries.append(current)
            current = {"start": line.replace("Start-Date: ", ""), "command": "", "packages": []}
            continue
        if current is None:
            # `tail -50` almost always starts mid-record, so the first lines belong to an entry
            # whose Start-Date was cut off. It used to be emitted anyway, with no "start" key at
            # all, which a caller reading e["start"] would raise on.
            continue
        if line.startswith("Commandline:"):
            current["command"] = line.replace("Commandline: ", "")
        elif line.split(":", 1)[0] in _APT_PACKAGE_FIELDS:
            # apt writes Install:/Upgrade:/Remove:/Purge:, never "Packages:" — so this list was
            # always empty. Each field is "name:arch (ver), name:arch (old, new), …", and a
            # version can itself contain a comma, so split on "), " rather than on every comma.
            body = line.split(":", 1)[1].strip()
            for item in body.split("), "):
                name = item.strip().split(" ", 1)[0].split(":", 1)[0]
                if name and name not in current["packages"]:
                    current["packages"].append(name)
    if current:
        entries.append(current)
    return entries[-10:]  # Last 10


# ─── Reboot ───────────────────────────────────────────────────

# What apt's /var/log/apt/history.log actually calls its package lists.
_APT_PACKAGE_FIELDS = ("Install", "Upgrade", "Remove", "Purge", "Downgrade", "Reinstall")


def server_reboot(delay_seconds=5):
    """Reboot the server with an optional delay."""
    if not _can_escalate():
        return False, "Sudo access required for reboot."

    # Clamped, as restart_panel's is. delay_seconds arrives raw from the request body and went
    # straight into time.sleep() in a daemon thread: a non-numeric value killed that thread with a
    # TypeError AFTER the route had already answered success and written a server_reboot audit
    # entry — a reboot that is logged and never happens.
    try:
        delay = max(0, min(300, int(delay_seconds)))
    except (TypeError, ValueError):
        return False, "The reboot delay must be a number of seconds (0-300)."

    # Schedule reboot in background
    def _do_reboot():
        import time
        time.sleep(delay)
        # Same omission the clamp above fixed from the other direction, and the same outcome: "a
        # reboot that is logged and never happens". _run_verb never raises, so a sudoers.d rule
        # sorting after the panel's narrow NOPASSWD grant ("a password is required", rc 1) or a
        # helper too old to know the verb (rc 2) produced no exception, no log line and no
        # user-visible trace — while the route had already answered success and written a
        # server_reboot audit row. An admin rebooting to clear a hung game server believes it
        # happened. The thread outlives the response, so the log is where the truth can land.
        _out, _err, _rc = _run_verb("reboot", [], timeout=30)
        if _rc != 0:
            _log.error("reboot verb failed: rc=%s %s", _rc, (_err or _out or "")[:200])

    thread = threading.Thread(target=_do_reboot, daemon=True)
    thread.start()
    return True, f"Server will reboot in {delay} seconds."


# Host CPU% without shelling out to `top`. Measured: `top -bn1` was 208ms of /server-management's
# 272ms cold render, because top takes its OWN delta and sleeps to do it. /proc/stat is the same
# numbers for free, and get_server_status already runs on a 15s cache — so the previous call IS
# the sample window, and the steady-state cost is zero processes and zero sleep.
#
# Same arithmetic the REMOTE path has used all along (ssh_manager/_core.host_live_metrics reads
# `grep '^cpu ' /proc/stat`); only the local path was still paying for top.
_CPU_SAMPLE = {"idle": 0, "total": 0}


def _read_cpu_jiffies():
    """(idle, total) from /proc/stat's aggregate `cpu` line, or (0, 0) if unreadable."""
    try:
        with open("/proc/stat", "r") as fh:
            for line in fh:
                if line.startswith("cpu "):
                    f = [int(x) for x in line.split()[1:]]
                    # idle + iowait, exactly as the remote sampler counts it
                    return (f[3] + (f[4] if len(f) > 4 else 0)), sum(f)
    except (OSError, ValueError):
        # A missing or unparseable /proc/stat is not an error worth surfacing: the caller renders
        # the "?" it already renders on any host that cannot answer, and this runs every 15s.
        _log.debug("_read_cpu_jiffies: ignored non-fatal error", exc_info=True)
    return 0, 0


def _local_cpu_percent():
    """Host CPU% as a delta against the previous call. "" when it cannot be read.

    The first call after a restart has nothing to diff against, and rendering "?%" there would be
    a visible regression from top — so it takes its own short delta once (100ms, still under half
    of top's 208ms) and every later call is free."""
    idle, total = _read_cpu_jiffies()
    if not total:
        return ""
    prev_idle, prev_total = _CPU_SAMPLE["idle"], _CPU_SAMPLE["total"]
    if not prev_total or total <= prev_total:
        time.sleep(0.1)                      # cooperative under eventlet; only ever the first call
        prev_idle, prev_total = idle, total
        idle, total = _read_cpu_jiffies()
        if not total or total <= prev_total:
            return ""
    _CPU_SAMPLE["idle"], _CPU_SAMPLE["total"] = idle, total
    d_total = total - prev_total
    if d_total <= 0:
        return ""
    return "%.1f" % max(0.0, min(100.0, (1 - (idle - prev_idle) / d_total) * 100))


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

    # CPU — /proc/stat, not `top` (see _local_cpu_percent); no process, no sleep after the first.
    cpu_percent = _local_cpu_percent()
    # Core count from the kernel rather than a `nproc` process — same answer.
    cpu_cores = str(os.cpu_count() or "")
    cpu_per_core = ""
    if cpu_percent and cpu_cores and cpu_cores.strip().isdecimal():
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
        out, _, _ = _run_verb("ufw-status", ["verbose"], timeout=10)
        # The grep interpolated an interface name into a root command line; matching in Python is
        # the same answer without that.
        tailscale_ufw_allowed = any(ts_iface.lower() in ln.lower() for ln in (out or "").splitlines())

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
    # PAGED. One page of 100 was "enough for now", and the failure mode if it ever stopped being
    # enough is the wrong one: a check that did not fit on page 1 is simply not seen, so a commit
    # whose only failure sits on page 2 reads as 'passing' and the panel offers the update. This
    # gate exists to stop exactly that. 5 pages (500 checks) is far past any plausible matrix, and
    # the cap is what keeps a malformed response from looping.
    runs = []
    try:
        for page in range(1, 6):
            url = ("https://api.github.com/repos/%s/commits/%s/check-runs?per_page=100&page=%d"
                   % (slug, sha, page))
            req = urllib.request.Request(url, headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "linuxgsm-panel-update-check",
            })
            with urllib.request.urlopen(req, timeout=8) as resp:  # nosec B310 - fixed https host
                batch = json.loads(resp.read().decode("utf-8")).get("check_runs", [])
            runs.extend(batch)
            if len(batch) < 100:
                break        # short page = last page
    except (urllib.error.URLError, ValueError, OSError):
        _log.debug("CI-gate: couldn't read check-runs for %s", sha, exc_info=True)
        return "unknown"     # a partial read must not be judged: 'unknown' is treated leniently
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
# Files that live inside a noise directory but DO affect the running host, checked before the
# directory rule. A denylist of directories cannot express "this one file matters".
#
# tools/panel-helper is the reason this exists. It is the root-owned end of the sudo boundary, it
# lives outside the panel's checkout once installed, and only install.sh — run as root — can
# refresh it. The update badge is what tells the operator to do that. Classified as noise, a
# commit that changed ONLY the helper raised no badge and appeared in no changelog, so the panel
# moved on while the installed helper did not: it then answers an unknown verb with rc 2 and no
# fallback, and the feature behind that verb fails silently. That is precisely the drift the
# helper's own docstring warns about, and the signal for it was suppressed.
_RUNTIME_EXCEPTIONS = {"tools/panel-helper"}


def _is_runtime_path(path):
    """True if this repo path affects the RUNNING panel (code, templates, static, requirements,
    install.sh, …). Docs/CI/test-scaffolding paths return False."""
    p = path.strip()
    if p.startswith("./"):      # a literal "./" prefix only — NOT lstrip("./"), which would also
        p = p[2:]               # eat the leading dot of dotfiles/dotdirs (.github, .gitignore).
    if not p:
        return False
    if p in _RUNTIME_EXCEPTIONS:
        return True             # checked FIRST: it sits inside a noise directory by design
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


def _runtime_changelog(rev_range, runtime_only=True):
    """Commits in `rev_range`, newest first, as 'shorthash subject' lines.

    With runtime_only (the default) a commit is kept only if it touches a file the panel RUNS, so
    a README edit does not make the card nag. Callers that are about to SHOW the list pass False
    when the filtered list comes back empty: the card used to report "1 commit behind" from the
    unfiltered count while listing the filtered one, so an update consisting of a tests-only
    commit announced itself and then had nothing to show. Reported from a live panel sitting one
    commit behind a change to tests/ and tools/."""
    out, _, rc = _git(["log", "--no-decorate", "--format=%h%x09%s", "--name-only", rev_range])
    if rc != 0 or not out:
        return []
    header = re.compile(r"^([0-9a-f]{7,40})\t(.*)\Z")
    if not runtime_only:
        return [("%s %s" % (m.group(1), m.group(2)))
                for m in (header.match(ln) for ln in out.splitlines()) if m]
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
    behind_n = int(behind.strip()) if behind.strip().isdecimal() else 0
    rem_sha, _, _ = _git(["rev-parse", "--short", ref])

    base = {"git": True, "fetched": True, "current_version": cur_ver,
            "current_sha": cur_sha.strip(), "remote_sha": rem_sha.strip(),
            "branch": branch, "checked_at": int(time.time()),
            # So the card can link each changelog line to the commit it names. Resolved from THIS
            # checkout's origin, so a fork links to the fork rather than upstream — the same
            # source the footer's linked SHA already uses.
            "repo_url": github_repo_url()}
    if behind_n == 0:
        return {**base, "update_available": False, "ci_state": "passing", "behind": 0}

    # Tracking a NON-default branch is an explicit, opt-in test mode. Those branches don't run
    # the CI/security suite on this repo (it's gated to main + PRs), so the CI-gate below would
    # show a permanent "verifying" and never apply. Offer the branch tip directly instead —
    # the snapshot + health-check + auto-rollback still guards against a branch that won't boot.
    if branch != _DEFAULT_BRANCH:
        # docs_only is still REPORTED (the card can note it), but it no longer suppresses the
        # badge: the question this card answers is "am I running the latest?", and the answer to
        # that does not depend on what the newer commits happen to touch.
        tgt_ver, _, tv_rc = _git(["show", "%s:VERSION" % ref])
        rem_full, _, _ = _git(["rev-parse", ref])
        runtime_log = _runtime_changelog("HEAD.." + ref)
        # Same fallback as the verified branch below, and docs_only reported here too — the card's
        # "none of these change what the panel runs" note keys off it, and leaving it out of one
        # of the two update branches meant the note appeared or not depending on which one the
        # panel happened to be in.
        rc_log = runtime_log or _runtime_changelog("HEAD.." + ref, runtime_only=False)
        return {**base, "update_available": True, "ci_state": "unverified",
                "docs_only": not runtime_log,
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
        # Nothing in range has cleared CI. Do NOT offer an update here, because the installer will
        # not install one: _do_panel_update refuses while ci_state is "pending" or "failing". The
        # card was announcing "Update available: v0.10.0-alpha (1 commit behind)" and, in the same
        # card, "This update is still being verified — try again once they've passed". An offer the
        # panel answers with a refusal is worse than no offer.
        #
        # The invariant is simply: update_available is true exactly when the update would be
        # allowed to install. Everything else belongs in the sentence underneath.
        #
        # And NO message. The card has two states and nothing in between: there is an update to
        # install, or there is not. A third "…but something is being verified" line is noise on a
        # card that is glanced at — it appears for a few minutes after every push, says nothing
        # anyone can act on, and the next glance shows something different again. Leaving `message`
        # out drops this state into the card's plain up-to-date line, which prints the running SHA,
        # so the exact commit is still on screen for anyone who wants to check it.
        #
        # ci_state and behind_tip are still reported for the API and the tests; only the card's
        # wording is deliberately silent.
        full_tip = commits[0] if commits else ""
        tip_ver, _, tv_rc = _git(["show", "%s:VERSION" % ref])
        return {**base, "update_available": False, "ci_state": tip_state,
                "behind": behind_n, "behind_tip": behind_n,
                "target_sha": full_tip,
                "remote_version": ((tip_ver.strip() if tv_rc == 0 else "") or "?"),
                "changes": _runtime_changelog("HEAD.." + ref)[:10]}

    # We have a verified target (possibly older than the tip if newer commits are still verifying).
    behind_target = behind_n - newer_unverified   # commits from HEAD up to & including the target
    # Don't nag if everything between here and the verified target is docs/CI/tests only — those
    # changes don't affect the running panel. (A later commit with real code will move the target
    # up and re-trigger the badge once it passes CI.)
    # docs_only is reported, not used to suppress — see the branch case above.
    _docs_only = not _update_touches_runtime(target_sha)
    tgt_ver, _, tv_rc = _git(["show", f"{target_sha}:VERSION"])
    rc_log = _runtime_changelog(f"HEAD..{target_sha}")   # runtime commits only (drops docs/CI)
    # What is COUNTED and what is LISTED must be the same set. `len(rc_log) or behind_target` used
    # the filtered count when it had one and the raw count when it did not — so an update made
    # only of test or tooling commits said "1 commit behind" and then showed an empty list,
    # because `changes` stayed filtered. When nothing runtime changed, show the commits that DID
    # change and let docs_only say what they are.
    shown_log = rc_log or _runtime_changelog(f"HEAD..{target_sha}", runtime_only=False)
    msg = None
    if newer_unverified > 0:
        msg = ("Updating to the latest verified version — %d newer commit%s still being verified."
               % (newer_unverified, "" if newer_unverified == 1 else "s"))
    return {
        **base,
        "update_available": True,
        "docs_only": _docs_only,
        "ci_state": target_state,
        "behind": len(shown_log) or behind_target,   # always the number of commits listed below
        "behind_tip": behind_n,
        "newer_unverified": newer_unverified,
        "remote_version": ((tgt_ver.strip() if tv_rc == 0 else "") or "?"),
        "remote_sha": target_sha[:7],
        "target_sha": target_sha,
        "changes": shown_log[:10],
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
        # A panel update / branch-switch updates panel code + restarts the panel ONLY. It must never
        # apply host OS packages or reboot the machine (that would take every game server down mid-
        # update). PANEL_NO_UPGRADE=1 makes install.sh skip its OS-upgrade+reboot step; OS updates
        # stay a separate, explicit action (the OS Updates card, which warns about online players).
        "export PANEL_NO_UPGRADE=1\n"
        'echo "=== panel self-update $(date) ===" > "$LOG"\n'
        f"bash {shlex.quote(installer)} >> \"$LOG\" 2>&1\n"
        'echo "=== installer exit $? ===" >> "$LOG"\n'
    )
    path = os.path.join(_upd_dir, "self-update.sh")

    if _is_system_service() and _helper_present():
        # The helper runs the ROOT-OWNED installer with the three variables in its environment,
        # detached. The wrapper script below — written by the panel, into a directory the panel
        # owns, then executed by root — is what this replaces.
        #
        # Being clear about what this does and does not buy: self-update means "fetch new code and
        # run it", and no argv discipline makes that untrusted-safe. What changes is that the
        # ROOT-run part is now fixed and small. The code the installer pulls goes on to run as the
        # panel user, and its trustworthiness rests on the signed, CI-verified commit — which
        # panel_update_status() has already checked before we get here.
        out, err, rc = _run_verb("panel-self-update",
                                 [target_ref or "-", branch or "-"], timeout=20)
        if rc == 0:
            _update_cache["ts"] = 0.0
            return True, (started_msg or
                          ("Update started — the panel is backing up, updating, and verifying it "
                           "restarts cleanly. If the new version fails to come up it rolls back "
                           "automatically. This takes up to a minute."))
        _log.error("self-update verb failed: rc=%s %s", rc, (err or out or "")[:200])
        return False, "Could not start the updater — check the panel logs."

    if _is_system_service():
        launcher = ["sudo", "systemd-run"]
    else:
        launcher = ["systemd-run", "--user"]
    launcher += ["--no-block", "--collect", "--unit", "panel-selfupdate", "/bin/bash", path]
    try:
        with open(path, "w") as f:
            f.write(script)
        os.chmod(path, 0o700)  # owner-only; root (sudo path) can still read it
        # argv is literals (systemd-run, --no-block, --collect, --unit, /bin/bash) plus `path`,
        # a fixed location under DATA_DIR written at 0700 just above. No shell. Not a static
        # string only because the sudo/--user prefix varies with whether the panel runs as root.
        #
        # CHECKED, like the helper branch 25 lines up. This was subprocess.Popen with both streams
        # to DEVNULL and the status never collected, so it only ever reported that the child was
        # SPAWNED. `--no-block` means systemd-run schedules the unit and exits within milliseconds
        # with a real exit status, so a refusal — unit name still held by a running
        # panel-selfupdate, no user D-Bus session, a later sudoers.d rule re-imposing a password —
        # was completely silent, and this returned True asserting the whole
        # snapshot/update/health-check/auto-rollback sequence. That is also what defeated
        # panel_switch_branch: it writes panel_branch to config FIRST and rolls it back only when
        # this returns False, so a launcher that never ran left the config naming a branch the
        # checkout was never moved to, which the next ordinary Update then reset onto.
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
        _r = subprocess.run(  # nosec B603
            launcher,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            text=True, timeout=15, check=False, env=os.environ.copy(),
        )
        if _r.returncode != 0:
            _log.error("self-update launcher failed: rc=%s %s",
                       _r.returncode, (_r.stderr or "")[:200])
            return False, "Could not start the updater — check the panel logs."
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
        from panel.core import config as _cfg
        _previous = (_cfg.load_config().get("panel_branch") or "").strip()
        _cfg.update_config(lambda cfg: cfg.update({"panel_branch": branch}))
    except Exception:
        _log.exception("switch-branch: could not save tracked branch")
        return False, "Could not save the branch selection."
    msg = ("Switching to '%s' — the panel is backing up, checking out that branch and verifying it "
           "restarts cleanly (auto-rollback if it doesn't). This takes up to a minute." % branch)
    # target_ref empty → install.sh resets to the tip of PANEL_BRANCH.
    ok, launch_msg = _launch_installer(target_ref="", branch=branch, started_msg=msg)
    if not ok:
        # Put the tracked branch back. The config write above happens BEFORE the launch, and the
        # launch really can fail ("install.sh is missing, so the panel can't self-update safely").
        # Leaving the new value behind means the panel TRACKS a branch its checkout is not on,
        # while the route and the audit row both report that nothing happened. _tracked_branch()
        # reads this key, so the next ordinary "Update" would hand install.sh the branch nobody
        # switched to and reset the checkout onto it — and the update-status CI gate refuses only
        # "pending"/"failing", while a non-default branch reports "unverified", which passes.
        try:
            _cfg.update_config(lambda cfg: cfg.update({"panel_branch": _previous})
                               if _previous else cfg.pop("panel_branch", None))
        except Exception:
            # The branch name is deliberately NOT interpolated here. It arrives from a request,
            # and this is the only place it would reach a log; CodeQL flags that as
            # py/log-injection. It cannot actually forge an entry — it has already cleared
            # _valid_branch, ^[A-Za-z0-9._/-]{1,100}$, which admits no newline — and an explicit
            # re.sub() at the log site did not satisfy the query either. The value adds nothing
            # an operator cannot read straight from panel_branch in config.json, which is exactly
            # what this message tells them to check, so the simplest correct answer is not to
            # echo it.
            _log.exception("switch-branch: could not restore the tracked branch after a failed "
                           "launch — panel_branch in config.json now names a branch the checkout "
                           "was NOT switched to, and the next update would follow it. Check that "
                           "key.")
    return ok, launch_msg


def restart_panel(delay_seconds=2):
    """Restart the panel's OWN systemd service via a DETACHED transient timer so it survives
    the panel process being killed mid-restart (the unit is KillMode=control-group, which
    would otherwise kill a normal child). Used after a config change that only takes effect on
    a rebind — notably the listen port. The `--on-active` delay lets the triggering HTTP
    response flush to the browser before the server goes down. Mirrors the self-update
    launcher's service-model detection. Best-effort; returns (ok, msg)."""
    delay = str(max(1, min(300, int(delay_seconds))))
    if not _is_system_service():
        # A per-user unit needs no root at all, so there is nothing to escalate and nothing to
        # scope — this branch keeps building its own argv.
        try:
            # B603/B607: the argv is a literal and `delay` is int-clamped to 1..300 before it gets
            # here. B607 (partial path) is deliberate — systemd-run is found on PATH, exactly as
            # this branch has always done; it runs as the panel user with no escalation at all.
            #
            # CHECKED, like the verb branch below. This was Popen with both streams to DEVNULL,
            # so it reported only that the child was spawned: `--on-active` makes systemd-run
            # schedule a timer and exit at once with a real status, and a refusal (no user D-Bus
            # session, a unit name still held) answered "Panel restart scheduled." to a user whose
            # port change then silently never took effect.
            _r = subprocess.run(  # nosec B603 B607  # nosemgrep
                ["systemd-run", "--user", "--on-active=%s" % delay, "--collect",
                 "systemctl", "--user", "restart", "linuxgsm-panel.service"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                text=True, timeout=15, check=False, env=os.environ.copy())
            if _r.returncode != 0:
                _log.error("panel restart launcher failed: rc=%s %s",
                           _r.returncode, (_r.stderr or "")[:200])
                return False, "Could not restart the panel — check the panel logs."
            return True, "Panel restart scheduled."
        except Exception:
            _log.exception("panel restart failed to dispatch")
            return False, "Could not restart the panel — check the panel logs."
    # The system-unit branch needs root. It used to be `sudo systemd-run …`, and a sudoers rule
    # permitting systemd-run is equivalent to NOPASSWD:ALL — systemd-run will run anything you hand
    # it. Through the verb the only thing the caller supplies is the delay, bounded 1..300; the unit
    # name and every flag are fixed on the far side of the boundary.
    #
    # `--on-active` means systemd-run schedules a timer and returns immediately, so waiting for it
    # (as _run_verb does) does not block on the restart itself.
    try:
        _out, _err, rc = _run_verb("panel-restart", [delay], timeout=15)
        if rc == 0:
            return True, "Panel restart scheduled."
        _log.error("panel restart verb failed: rc=%s %s", rc, (_err or _out or "")[:200])
        return False, "Could not restart the panel — check the panel logs."
    except Exception:
        _log.exception("panel restart failed to dispatch")
        return False, "Could not restart the panel — check the panel logs."


def panel_repair_database():
    """Repair the panel database on-demand, OFFLINE and safely. A live DB can't be rebuilt while the
    running panel holds it open, so a DETACHED transient job stops the panel service, runs
    db_maintenance (health-check → rebuild readable data via SQLite .recover, else restore the last
    healthy backup → optimize → re-check), then starts the service again — the flagged database is
    copied aside first and never deleted. Same stop/repair/start the auto-updater uses. (ok, msg)."""
    base = PANEL_DIR          # the checkout root: venv/ and db_maintenance.py both live there
    py = os.path.join(base, "venv", "bin", "python3")
    if not os.path.exists(py):
        py = os.path.join(base, "venv", "bin", "python")
    dbm = os.path.join(base, "db_maintenance.py")
    if not os.path.exists(py) or not os.path.exists(dbm):
        return False, "The repair tool isn't available on this install."

    if _is_system_service() and _helper_present():
        # The helper does the whole stop -> repair -> start itself, detached, as three argv calls
        # with no shell between them. It reads the database path from the root-owned panel.conf and
        # runs a root-owned copy of db_maintenance.py with the SYSTEM interpreter.
        #
        # That last part is the reason this conversion exists. The fallback below composes a script
        # naming THIS directory's venv python and THIS directory's db_maintenance.py, and hands it
        # to `sudo systemd-run` — so root executes the panel user's interpreter running the panel
        # user's script, out of a checkout `git pull` rewrites on every self-update. Narrowing the
        # sudoers grant would not have fixed that; only moving the executed code out of the
        # checkout does.
        out, err, rc = _run_verb("panel-db-repair", [], timeout=20)
        if rc == 0:
            return True, ("Repairing the database — the panel stops, repairs it offline (your data "
                          "is copied aside first), and restarts. Give it about a minute, then "
                          "reload the page.")
        _log.error("db repair verb failed: rc=%s %s", rc, (err or out or "")[:200])
        return False, "Couldn't start the repair job — check the panel logs."

    if _is_system_service():
        sc = "sudo systemctl"
        run = ["sudo", "systemd-run", "--collect", "--on-active=2"]
    else:
        sc = "systemctl --user"
        run = ["systemd-run", "--user", "--collect", "--on-active=2"]
    # ONE detached unit (survives the panel going down): stop → repair offline → start.
    script = ("%s stop linuxgsm-panel.service; ( cd %s && %s %s update ); %s start linuxgsm-panel.service"
              % (sc, shlex.quote(base), shlex.quote(py), shlex.quote(dbm), sc))
    try:
        # CHECKED, like the helper branch above. `--on-active=2` schedules a transient timer and
        # returns at once with a real status, so Popen-with-DEVNULL reported only that the child
        # was spawned: a systemd-run that refused (no user bus, `sudo systemd-run` denied) told the
        # user their database was being repaired and nothing ever ran, while the flagged database
        # stayed flagged.
        _r = subprocess.run(run + ["bash", "-c", script],  # nosec B603  # nosemgrep - internal paths, shlex-quoted, no user input
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, text=True, timeout=15, check=False,
                            env=os.environ.copy())
        if _r.returncode != 0:
            _log.error("db repair launcher failed: rc=%s %s", _r.returncode, (_r.stderr or "")[:200])
            return False, "Couldn't start the repair job — check the panel logs."
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
    path = os.path.join(PANEL_DIR, "data", "self-update.log")
    try:
        with open(path, "r", errors="replace") as f:
            data = f.read()[-max_bytes:]
    except OSError:
        return {"exists": False, "lines": []}
    data = terminal.strip_escapes(data)   # strip ANSI/OSC/two-byte escapes, not just colour
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
    # `paths is not None`, not `if paths`. An empty LIST is a caller who asked for nothing, and
    # it took the else-branch: "restore these files" with an empty selection restored EVERY
    # modified file, and the audit row then recorded a mass checkout nobody asked for. Only
    # `paths=None` — the documented "restore all" — may mean all.
    if paths is not None:
        requested = set(paths)
        targets = [p for p in tampered if p in requested]
        if not targets:
            return False, ("No files were selected to restore."
                           if not requested else
                           "None of the requested files are currently modified."), []
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
    _run_verb("apt-install", ["unattended-upgrades"], timeout=300)
    # 2) write the APT periodic config that actually turns it on. printf is
    # unprivileged; only the file write (via `sudo tee`) needs root.
    # Through the write verb, like every other root-owned write here and like the REMOTE form of
    # this same operation (hosts.py uses write_root_file("apt-auto-upgrades", …)). The hand-rolled
    # `sudo tee` was the last one left: on a host with the narrow sudoers grant it is simply
    # refused, so the file was never written and this always answered "Could not confirm…" while
    # the identical action on a remote worked.
    conf = ('APT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "1";\n')
    _write_root_file("/etc/apt/apt.conf.d/20auto-upgrades", conf)
    st = unattended_upgrades_status()
    if st.get("enabled"):
        return True, "Automatic security updates are now enabled."
    return False, "Could not confirm automatic security updates were enabled — check the panel logs."


# ─── fail2ban jail for the panel's own web login ──────────────────────────────
# Both paths come from privileged.WRITE_TARGETS so the write verb and these constants cannot
# drift apart, and _WRITE_TARGET_BY_PATH lets _write_root_file find the verb for a path it is given.
_F2B_PANEL_FILTER = _priv.WRITE_TARGETS["fail2ban-panel-filter"][0]
_F2B_PANEL_JAIL = _priv.WRITE_TARGETS["fail2ban-panel-jail"][0]
_WRITE_TARGET_BY_PATH = {p: name for name, (p, _m) in _priv.WRITE_TARGETS.items()}


def _panel_f2b_filter_body():
    """fail2ban filter matching the panel's own auth.log lines; <HOST> captures the offender."""
    return ("[Definition]\n"
            "failregex = panel login (?:failed|blocked) from <HOST>$\n"
            "ignoreregex =\n")


def _f2b_ignoreip_line(ignore_ips):
    """Space-separated ignoreip value: always localhost, plus the caller's whitelist. EVERY entry is
    re-parsed through ipaddress (IP or CIDR) so an unvalidated token can never reach the jail file —
    a bad entry is dropped, not written. Deduped, order-stable."""
    import ipaddress
    entries = ["127.0.0.1/8", "::1"]
    for raw in (ignore_ips or []):
        s = (str(raw) or "").strip()
        try:
            canon = (str(ipaddress.ip_network(s, strict=False)) if "/" in s
                     else str(ipaddress.ip_address(s)))
        except ValueError:
            continue
        # Parsing is not enough: ipaddress keeps an IPv6 zone id verbatim — `::1%\nbantime = 1`
        # parses, newline and all — so a stored entry could still add lines to the jail. A value
        # carrying a zone id or any whitespace/control character is dropped like any other bad one.
        if "%" in canon or any(c.isspace() or not c.isprintable() for c in canon):
            continue
        entries.append(canon)
    seen, out = set(), []
    for e in entries:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return " ".join(out)


# A FILE backend, stated explicitly. Debian and Ubuntu ship
# /etc/fail2ban/jail.d/defaults-debian.conf containing `[DEFAULT] backend = systemd`, and that
# DEFAULT applies to every jail — including this one. A jail on the systemd backend reads the
# JOURNAL and ignores `logpath` entirely, so this jail reported itself active while monitoring no
# file at all: `fail2ban-client get linuxgsm-panel logpath` answered "No file is currently
# monitored", and the panel writes its failures to data/auth.log, which is a file. Measured on
# Ubuntu 24.04.5 — 0 bans ever possible, with the panel UI showing "Active" the whole time.
# "auto" rather than "polling": it picks pyinotify where available (confirmed on the same host)
# and falls back to polling, and either way it is a file backend, which is the point.
_F2B_PANEL_BACKEND = "auto"


# The ban action for a panel reached THROUGH something: every port, not the web port. A plain name,
# not `%(banaction_allports)s` — the helper admits a banaction line only with exactly this value
# (tools/panel-helper, _F2B_JAIL_KEYS["banaction"]), and iptables is present wherever ufw is. Change
# one and you must change the other, or the helper refuses the jail and the panel is not protected.
_F2B_PANEL_ALLPORTS_ACTION = "iptables-allports"


def _panel_login_proxied():
    """Does a panel login arrive through something in front of the panel rather than straight at
    its web port? Then the address in auth.log is the X-Forwarded-For client (auth.client_ip), whose
    packets go to the PROXY's port — so a ban on the web port matches none of them. That is
    trust_proxy (nginx/Caddy), Tailscale Serve, or a loopback bind nothing else can reach.

    Unreadable config answers True: the wider ban is the one that is sure to take effect."""
    try:
        from panel.core import config as _cfg
        cfg = _cfg.load_config()
    except Exception:
        _log.debug("f2b: config unreadable; banning on all ports", exc_info=True)
        return True
    bind = (cfg.get("bind_host") or "").strip().lower()
    return bool(cfg.get("trust_proxy") or cfg.get("tailscale_setup_done")
                or bind in ("127.0.0.1", "::1", "localhost"))


# Every tailnet peer's address: Tailscale's CGNAT IPv4 range and its IPv6 ULA prefix.
_TAILNET_RANGES = ("100.64.0.0/10", "fd7a:115c:a1e0::/48")


def _panel_f2b_ignore(ignore_ips, allports):
    """The panel jail's ignoreip entries (before _f2b_ignoreip_line validates them): the whitelist,
    plus — when the ban is on EVERY port — the tailnet.

    An all-ports ban on a tailnet peer is a ban on its way in: under Serve the forwarded client IS
    a tailnet address, and five mistyped panel passwords from an admin's laptop REJECTed that
    100.x address on every TCP port for an hour — sshd over tailscale0 (the way back in once public
    SSH is off), game and RCON ports. The panel never firewall-blocks a tailnet IP anywhere else
    (ssh_manager's note above _TAILNET_CGNAT; the auto-block exempts them), and a public attacker
    cannot have one. A web-port-only ban takes only the panel login from them, as it always did."""
    return list(ignore_ips or []) + (list(_TAILNET_RANGES) if allports else [])


def _panel_f2b_jail_body(auth_log, web_port, ignore_ips=None, allports=None):
    """Jail: 5 failures in 10 min → 1-hour ban, on the panel's web port. In jail.d/ so it sits
    alongside (doesn't conflict with) any [sshd] jail. `ignore_ips` (validated) are never banned.

    On the web port ONLY when clients connect to it directly. Behind nginx/Caddy or Serve the
    banned address is the forwarded client, whose traffic reaches the proxy's port: the ban
    matched nothing, while the panel audited "banned after 5 failed panel logins" and notified
    "IP banned on the panel login" — and the attacker carried on through :443. There the ban is
    on every port (`allports`, default _panel_login_proxied())."""
    if allports is None:
        allports = _panel_login_proxied()
    return ("[linuxgsm-panel]\n"
            "enabled = true\n"
            "backend = " + _F2B_PANEL_BACKEND + "\n"
            + ("banaction = %s\n" % _F2B_PANEL_ALLPORTS_ACTION if allports else "") +
            "port = %d\n"
            "filter = linuxgsm-panel\n"
            "logpath = %s\n"
            "maxretry = 5\n"
            "findtime = 10m\n"
            "bantime = 1h\n"
            "ignoreip = %s\n" % (web_port, auth_log,
                                 _f2b_ignoreip_line(_panel_f2b_ignore(ignore_ips, allports))))


def _panel_f2b_jail_value(key):
    """The value of a simple `key = value` line in the current panel jail file, or None.

    Used to notice a jail that is present and enabled but no longer describes THIS install —
    a logpath left behind by a move (the panel reinstalled under a different account leaves
    `logpath = /home/<old>/…`, which fail2ban tails forever without complaining) or a jail written
    before this backend was pinned. Both look healthy to a status read."""
    try:
        with open(_F2B_PANEL_JAIL) as f:
            for line in f:
                m = re.match(r"\s*%s\s*=\s*(\S+)\s*$" % re.escape(key), line)
                if m:
                    return m.group(1)
    except OSError:
        _log.debug("f2b: could not read jail %s", key, exc_info=True)
    return None


def _panel_f2b_jail_ignoreip():
    """The ignoreip tokens the current jail file carries (or None if unreadable). Used to decide
    whether the whitelist changed and the jail needs a rewrite."""
    try:
        with open(_F2B_PANEL_JAIL) as f:
            for line in f:
                # Require the '=' too: a bare "ignoreip" line (hand-edited, or a truncated write)
                # would otherwise IndexError past the OSError handler below.
                if line.strip().startswith("ignoreip") and "=" in line:
                    return line.split("=", 1)[1].split()
    except OSError:
        _log.debug("f2b: could not read jail ignoreip", exc_info=True)
    return None


def _panel_f2b_jail_port():
    """Port the current panel jail file is set to, or None. The jail file is root-owned but
    world-readable, so the panel process can read it without sudo. Best-effort."""
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
    if _helper_present():
        # The content goes on the helper's stdin and the destination is a NAME, so neither the
        # content nor the path is ever part of a command line.
        target = _WRITE_TARGET_BY_PATH.get(path)
        if target:
            try:
                # Same audit rule, same answer as _run_verb above: the first argument is not a
                # literal string because it comes from privileged.py's fixed verb table, which is
                # the point. shell=False, and `content` is stdin rather than argv.
                # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
                r = subprocess.run(  # nosec B603 - argv from privileged.py's fixed table
                    _priv.helper_argv("write-file", [target]), shell=False, input=content,
                    capture_output=True, text=True, timeout=15)
                return (r.stdout or "").strip(), (r.stderr or "").strip(), r.returncode
            except Exception:
                _log.debug("helper write failed; falling back", exc_info=True)
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
    out, _, rc = _run_verb("f2b-status-jail", ["linuxgsm-panel"], timeout=10, merge_stderr=False)
    if rc != 0 or not out:
        return {"installed": True, "enabled": False, "banned": 0}
    m = re.search(r"Currently banned:\s*(\d+)", out)
    return {"installed": True, "enabled": True, "banned": int(m.group(1)) if m else 0}


def panel_fail2ban_banned_ips():
    """The set of IPs the panel-login jail is currently banning, or **None** if it could not be
    read. Used by the ban-watcher to record new bans/unbans in the audit log.

    None, not set(), and the sibling two functions below settles it: fail2ban_jail_detail runs the
    IDENTICAL `_run_verb("f2b-status-jail", ...)` and answers None on the IDENTICAL
    `rc != 0 or not out`. Same verb, same failure test, opposite answer — and this was the one the
    ban-watcher believed.

    It diffs consecutive readings, so an empty set is not a quiet moment, it is "every ban was
    lifted": one failed tick wrote a fail2ban_unban row for every live ban ("ban expired or
    lifted"), and the next good tick re-logged all of them as NEW bans, each with an "IP banned on
    the panel login" notification, plus a "Login attack in progress" alert once three or more
    landed together. A blip in reading the jail thereby manufactured the exact event the alert
    exists to report.

    It also fixes the seeding race: the watcher starts alongside _f2b_autostart, which can reload
    fail2ban — and fail2ban-client exits non-zero during a reload — so the very first reading could
    seed `seen` from a failed read. None leaves it unseeded until a real one arrives."""
    out, _, rc = _run_verb("f2b-status-jail", ["linuxgsm-panel"], timeout=10, merge_stderr=False)
    if rc != 0 or not out:
        return None
    m = re.search(r"Banned IP list:\s*(.*)", out)
    return set(p for p in (m.group(1).split() if m else []) if p)


_JAIL_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}\Z")


def _fail2ban_jails():
    """Names of all configured fail2ban jails on this host ([] if fail2ban isn't up)."""
    out, _, rc = _run_verb("f2b-status", [], timeout=10, merge_stderr=False)
    if rc != 0 or not out:
        return []
    m = re.search(r"Jail list:\s*(.*)", out)
    return [j.strip() for j in (m.group(1).split(",") if m else []) if _JAIL_RE.match(j.strip())]


def fail2ban_jail_detail(jail):
    """Ban stats for one jail: {jail, currently_banned, total_banned, total_failed, banned_ips[]}
    or None. Jail name is validated before it reaches the command."""
    if not _JAIL_RE.match(jail or ""):
        return None
    out, _, rc = _run_verb("f2b-status-jail", [jail], timeout=10, merge_stderr=False)
    if rc != 0 or not out:
        return None

    def _num(label):
        m = re.search(label + r":\s*(\d+)", out)
        return int(m.group(1)) if m else 0
    m = re.search(r"Banned IP list:\s*(.*)", out)
    ips = [ip for ip in (m.group(1).split() if m else []) if ip]
    return {"jail": jail, "currently_banned": _num("Currently banned"),
            "total_banned": _num("Total banned"), "total_failed": _num("Total failed"),
            "banned_ips": ips}


def fail2ban_overview():
    """Every jail with its ban stats. {'installed': bool, 'jails': [detail,...]}. Best-effort."""
    have, _, _ = _run("command -v fail2ban-client >/dev/null 2>&1 && echo yes || echo no", timeout=10)
    if "yes" not in (have or ""):
        return {"installed": False, "jails": []}
    details = [d for d in (fail2ban_jail_detail(j) for j in _fail2ban_jails()) if d]
    return {"installed": True, "jails": details}


# The fail2ban aggregation is a pure counting pipeline over the (root-owned) fail2ban logs — no input
# from the request reaches the shell, so it's a fixed command. Panel-host only. ssh_manager.remote_fail2ban_top_ips inlines its own copy of this pipeline and of the row parsing below — keep the two in step by hand.

# Default UFW comment tag so the panel manages only its OWN deny rules. The rolling-auto-block tag
# ("panel-autoblock") is passed in by app.py's reconcile.
_UFW_BLOCK_TAG = "panel-block"          # one-off manual block


# A deny rule's tag when the panel did not write it — no comment, or an operator's own.
_UFW_EXTERNAL_TAG = ""


def _ufw_deny_tag_rank(tag):
    """Which tag an address reports when several rules block it. A rule the panel did not write
    wins: the reconcile must count that address as blocked and never "release" it (a release is
    `ufw delete deny from <ip>`, which removes every deny for the address, the operator's too).
    A manual block beats an auto-block for the same reason — it is not the reconcile's to lift."""
    if not tag.startswith("panel-"):
        return 0
    return 2 if tag == "panel-autoblock" else 1


def _ufw_shadowing_allows(allows, net):
    """True when an inbound ALLOW/LIMIT already seen — `allows`, [(version, source network, or
    None for Anywhere)] in rule order — matches traffic from `net`: same family, and a source that
    covers any of it. ufw stops at the first rule a packet matches, so a deny below one of those
    is never reached for the ports that rule lets in."""
    return any(ver == net.version and (src is None or src.overlaps(net)) for ver, src in allows)


def _ufw_deny_sources(status_out, shadowed=None):
    """{source: tag} for every INBOUND DENY/REJECT rule in `ufw status` output that blocks one
    address (or network) on ALL ports — the shape `ufw deny from <ip>` writes, whoever wrote it.

    The tag is the rule's `panel-…` comment, or _UFW_EXTERNAL_TAG for a rule the panel did not
    write. Those used to be skipped (`"panel-" not in line`), so an operator's own
    `ufw deny from <ip>` read as "not blocked": the reconcile then ran `ufw delete deny from <ip>` —
    which removes a rule regardless of its comment — inserted a `panel-autoblock` rule in its place,
    and later RELEASED it once the (now firewalled, so silent) address aged below the threshold.

    ...but only where ufw reaches it. ufw stops at the FIRST rule a packet matches, and a
    hand-typed `ufw deny from <ip>` is APPENDED — below `22/tcp LIMIT`, `27015 ALLOW` and the
    rest — so every packet to those ports meets the allow first and the deny blocks nothing.
    Reporting it as a block made the reconcile skip the address, the offenders table badge it
    "blocked", and the Block button answer "already blocked … (left as it is)", while the attacker
    kept reaching SSH and every open port. So an operator's deny that sits below an inbound
    ALLOW/LIMIT of its family covering its source is NOT a block here: it is left out, and put in
    `shadowed` (a dict, when given) as {source: {"comment", "action"}} for _ufw_deny_with to move
    to the top. The panel's own rules go in at position 1 and are reported wherever they sit.

    A single address is keyed by its canonical form; a network by its CIDR. Port-specific denies,
    interface rules and outbound rules are not blocks of an address and are left out."""
    import ipaddress
    found = {}
    late = {}           # operator denies an allow above them shadows
    allows = []         # (version, source network or None) of every inbound ALLOW/LIMIT so far
    for line in (status_out or "").splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s*(.*)\Z", line)
        body, _, comment = (m.group(1) if m else line).partition("#")
        v6 = "(v6)" in body
        toks = body.replace("(v6)", " ").split()
        act = next((i for i, t in enumerate(toks) if t in ("DENY", "REJECT", "ALLOW", "LIMIT")), None)
        if act is None:
            continue
        rest = toks[act + 1:]
        direction = "IN"
        if rest and rest[0] in ("IN", "OUT", "FWD"):
            direction, rest = rest[0], rest[1:]
        if direction != "IN":
            continue
        if toks[act] in ("ALLOW", "LIMIT"):
            nets = []
            for t in toks[:act] + rest:
                try:
                    nets.append(ipaddress.ip_network(t, strict=False))
                except ValueError:
                    # A token that is not a network (a port, an interface) is not a source.
                    pass
            try:
                src = (None if not rest or rest[0] == "Anywhere"
                       else ipaddress.ip_network(rest[0], strict=False))
            except ValueError:
                src = None      # an app profile or anything unparsed: assume it covers everyone
            ver = 6 if v6 or any(n.version == 6 for n in nets) else 4
            # `ufw allow in on tailscale0` — which the panel itself adds, usually before any deny —
            # only ever sees tailnet sources, so it shadows no public address. Read as "Anywhere",
            # it made every operator deny below it look shadowed: badged unblocked, and moved.
            _on = toks.index("on") if "on" in toks[:act] else -1
            if src is None and 0 <= _on < act - 1 and toks[_on + 1].startswith("tailscale"):
                src = ipaddress.ip_network(_TAILNET_RANGES[1 if ver == 6 else 0])
            allows.append((ver, src))
            continue
        if toks[:act] != ["Anywhere"] or len(rest) != 1:
            continue
        try:
            net = ipaddress.ip_network(rest[0], strict=False)
        except ValueError:
            continue
        key = str(net.network_address) if net.num_addresses == 1 else str(net)
        comment = comment.strip()
        tag = comment if re.fullmatch(r"panel-[a-z-]+", comment) else _UFW_EXTERNAL_TAG
        if _ufw_deny_tag_rank(tag) == 0 and _ufw_shadowing_allows(allows, net):
            late.setdefault(key, {"comment": comment, "action": toks[act]})
            continue
        if key not in found or _ufw_deny_tag_rank(tag) < _ufw_deny_tag_rank(found[key]):
            found[key] = tag
    for key, rule in late.items():
        if key in found:
            # A panel rule blocks it, but the operator's intent is there too: report theirs, so the
            # reconcile never "releases" it (`ufw delete deny from <ip>` would take both).
            found[key] = _UFW_EXTERNAL_TAG
        elif shadowed is not None:
            shadowed[key] = rule
    return found


def ufw_blocked_ips(shadowed=None):
    """{ip: tag} for the panel host's UFW all-ports deny rules — the panel's own, tagged from the
    rule comment, AND anyone else's, tagged _UFW_EXTERNAL_TAG (see _ufw_deny_sources, which also
    fills `shadowed` with the operator denies that block nothing where they sit).

    None — NOT {} — when the firewall could not be read. The two are completely different answers
    and the caller that matters cannot tell them apart otherwise: _autoblock_reconcile treats
    "not in blocked" as "needs blocking", so a failed read made every offender look unblocked and
    re-issued a delete+add for each one, every cycle, forever. It already guards its other read
    (`if top is None`) for the same reason.
    """
    out, _, rc = _run_verb("ufw-status", ["plain"], timeout=15)
    if rc != 0:
        _log.debug("ufw_blocked_ips: the firewall read failed (rc=%s)", rc)
        return None
    # A DISABLED firewall reaches here through the SUCCESSFUL path the rc guard does not cover:
    # `ufw status` on an installed-but-inactive host exits 0 and prints exactly one line,
    # "Status: inactive", with no rule rows at all. The parse loop below then found no DENY lines
    # and this returned {} — "the panel has blocked nobody" — for a firewall whose stored rules it
    # simply cannot see. _autoblock_reconcile reads "not in blocked" as "needs blocking", and
    # `ufw deny from <ip>` STORES a rule and exits 0 while inactive, so every offender was
    # re-blocked and audited as applied, every hour, forever, with no packet being dropped.
    # An inactive firewall cannot answer which IPs are blocked, so it is the None case — which
    # makes monitoring's existing `if blocked is None` skip fire. ufw_status() draws the same
    # distinction from the same text (ufw_status_active, which also reads a translated Status
    # line — a Dutch `Status: inactief` is not the English substring this used to look for).
    if not ufw_status_active(out):
        _log.debug("ufw_blocked_ips: UFW is inactive — its rule list is not readable")
        return None
    return _ufw_deny_sources(out, shadowed)


def _ufw_raise_shadowed_deny(ip, rule, run):
    """Move the operator's own deny for `ip` — `rule`, from _ufw_deny_sources' `shadowed` — from
    below the rules that allow traffic, where it blocks nothing, to the top. (ok, msg).

    ufw keeps one rule per match (a second `deny from <ip>` is "Skipping inserting existing
    rule", exit 0 — a success that changed nothing), so a move is a delete and an insert. It goes
    back in as THEIRS: their comment, cut to what the helper accepts, never a `panel-` tag, so the
    reconcile still reads it as the operator's and never releases it. Only an IPv4 DENY is moved:
    `ufw delete deny` does not match a REJECT, and an IPv6 rule cannot be put back at all — the
    helper's only insert is `insert 1`, which ufw refuses for IPv6 while IPv4 rules exist."""
    import ipaddress
    if rule.get("action") != "DENY" or ipaddress.ip_address(ip).version != 4:
        return False, ("%s already has a firewall rule of its own denying it, but the rule sits "
                       "below rules that allow traffic, so it blocks nothing. The panel cannot "
                       "move this one — put it above them on the host (`ufw prepend`)." % ip)
    keep = re.sub(r"[^A-Za-z0-9 _.-]", "", rule.get("comment") or "")[:60].strip()
    if re.fullmatch(r"panel-[a-z-]+", keep):
        keep = ""       # stripping made it read as a panel tag, which the reconcile may release
    out, err, rc = run("ufw-delete-deny-ip", [ip])
    if rc != 0:
        return False, ((out or err or "Could not move the existing deny rule for %s" % ip)
                       .replace("\n", " ")[:200])
    # The second attempt is the put-back: an insert at the top is the only write of a deny the
    # helper has, so restoring the rule and retrying the move are the same command.
    for _attempt in range(2):
        out, err, rc = run("ufw-deny-ip", [ip, keep])
        if rc == 0:
            return True, ("Moved the existing deny rule for %s to the top — it sat below rules "
                          "that allow traffic, so it was blocking nothing." % ip)
    _log.warning("ufw: the deny rule for %s was removed to move it and could not be put back", ip)
    return False, (("The existing deny rule for %s was removed to move it above the allow rules, "
                    "and could not be put back: " % ip)
                   + (out or err or "unknown error").replace("\n", " ")[:160])


def _ufw_deny_with(ip, tag, existing, run, shadowed=None):
    """Block `ip` (canonical) under `tag`, given what already blocks it — the one implementation
    behind ufw_deny_ip and ssh_manager's remote_ufw_deny_ip. (ok, msg).

    `existing` is that address's tag from a blocked-IPs read: _UFW_EXTERNAL_TAG for a rule the
    panel did not write, a `panel-…` tag for its own, None for none — or for a read that failed,
    which is why None only ever ADDS. `shadowed` is the same read's entry for an operator's deny
    that blocks nothing where it sits: that one is moved (_ufw_raise_shadowed_deny), since a
    plain insert would be skipped by ufw as a duplicate and report success.
    `run(verb, args)` returns (out, err, rc).

    This deleted first and inserted second, every time. `ufw delete deny from <ip>` matches a rule
    whatever its comment, so the operator's own block was removed and replaced with a panel one
    the reconcile would later release; and when the insert then failed (`insert 1` is refused for
    an IPv6 address while IPv4 rules exist) the address was left with no block at all. Now a rule
    the panel did not write is left alone where it blocks, moved (never re-tagged) where it does
    not, and the only other delete is of the panel's own rule when it is re-tagged (auto-block →
    manual) — put back if the new one does not go in."""
    if existing is not None and _ufw_deny_tag_rank(existing) == 0:
        return True, "%s is already blocked by an existing firewall rule (left as it is)." % ip
    if existing is None and shadowed:
        return _ufw_raise_shadowed_deny(ip, shadowed, run)
    if existing == tag:
        return True, "%s is already blocked." % ip
    if existing:
        run("ufw-delete-deny-ip", [ip])
    out, err, rc = run("ufw-deny-ip", [ip, tag])
    if rc == 0:
        return True, "Blocked %s (all ports)." % ip
    if existing:
        run("ufw-deny-ip", [ip, existing])
    return False, ((out or err or "Block failed").replace("\n", " ")[:200])


def ufw_deny_ip(ip, tag=_UFW_BLOCK_TAG):
    """Block an IP on ALL ports (UFW deny inserted at the top, tagged). The IP is reparsed to its
    canonical ipaddress form so nothing request-supplied reaches the shell unchecked. (ok, msg)."""
    import ipaddress
    try:
        ip = str(ipaddress.ip_address((ip or "").strip()))
    except (ValueError, TypeError):
        return False, "Invalid IP address."
    tag = re.sub(r"[^a-z0-9-]", "", (tag or ""))[:32] or _UFW_BLOCK_TAG
    # Separate verbs, never a "a; b" compound: _run prepends `sudo` to the FIRST command only.
    shadowed = {}
    existing = (ufw_blocked_ips(shadowed) or {}).get(ip)
    return _ufw_deny_with(ip, tag, existing,
                          lambda verb, args: _run_verb(verb, args, timeout=15),
                          shadowed.get(ip))


def ufw_undeny_ip(ip):
    """Remove a UFW deny rule for an IP (canonicalised first). (ok, msg)."""
    import ipaddress
    try:
        ip = str(ipaddress.ip_address((ip or "").strip()))
    except (ValueError, TypeError):
        return False, "Invalid IP address."
    # Read the result. This discarded the tuple and returned True unconditionally, while its
    # sibling ufw_deny_ip five lines up captures (out, err, rc) and fails on non-zero — so a
    # timeout ("", "Command timed out", -1), a missing helper binary, or a sudo refusal all
    # reported "Unblocked", showed a green toast, and wrote an audit row saying the unblock
    # succeeded, for a deny rule that is still in the firewall.
    out, err, rc = _run_verb("ufw-delete-deny-ip", [ip], timeout=15)
    if rc == 0:
        return True, "Unblocked %s." % ip
    return False, ((out or err or "Unblock failed").replace("\n", " ")[:200])


_F2B_EVENT_RE = re.compile(r"\[([A-Za-z0-9._-]+)\] (Ban|Found) ([0-9a-fA-F:.]+)")


def _tally_f2b_events(text):
    """(found, bans, jails) per IP from raw fail2ban log lines: for each `[jail] Ban|Found <ip>`
    match, count Founds and Bans and collect the distinct jails. Every IP — no ranking, no cut."""
    found, bans, jails = {}, {}, {}
    for line in (text or "").splitlines():
        m = _F2B_EVENT_RE.search(line)
        if not m:
            continue
        jail, action, ip = m.group(1), m.group(2), m.group(3)
        if action == "Found":
            found[ip] = found.get(ip, 0) + 1
        else:
            bans[ip] = bans.get(ip, 0) + 1
        seen = jails.setdefault(ip, [])
        if jail not in seen:
            seen.append(jail)
    return found, bans, jails


def _tally_f2b_lines(text, limit):
    """Tally Ban/Found events per IP from raw fail2ban log lines.

    This is what the awk half of the old shell pipeline did: count per IP (_tally_f2b_events),
    then rank by attempts and take the top `limit`. Emitted in the same tab-separated shape
    _parse_top_ips already reads."""
    found, bans, jails = _tally_f2b_events(text)
    rows = sorted(found.keys() | bans.keys(),
                  key=lambda ip: (found.get(ip, 0), bans.get(ip, 0)), reverse=True)
    return "\n".join("%d\t%d\t%s\t%s" % (found.get(ip, 0), bans.get(ip, 0), ip,
                                           ",".join(jails.get(ip, [])))
                     for ip in rows[:max(1, int(limit))])


def _parse_top_ips(out, banned_now, blocked):
    rows = []
    for line in (out or "").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2].strip():
            ip = parts[2].strip()
            jails = [j for j in (parts[3].split(",") if len(parts) > 3 and parts[3] else []) if j]
            rows.append({
                "ip": ip,
                "attempts": int(parts[0]) if parts[0].isdecimal() else 0,
                "bans": int(parts[1]) if parts[1].isdecimal() else 0,
                "banned_now": ip in banned_now,
                "blocked": ip in blocked,
                "jails": jails,
            })
    return rows


def fail2ban_top_ips(limit=20, days=7):
    """The most-active offending IPs from the fail2ban log over the last `days` days (current +
    rotated), ranked by detected attempts. Each: {ip, attempts, bans, banned_now, blocked}.
    [] when fail2ban/the log is absent — the verb exits 0 with nothing to report. NONE when the
    read FAILED (helper missing, sudo refused, the 25s timeout on a large log): those also produce
    no output, and returning [] for them made "the read broke" indistinguishable from "there are
    no offenders". _autoblock_reconcile takes the second to mean every auto-block should be
    released, so one failed read unblocked every brute-forcer the panel had firewalled — and wrote
    an audit row saying so as though it were the intended reconciliation."""
    from datetime import datetime, timedelta
    limit = max(1, min(int(limit or 20), 100))
    try:
        days = max(1, min(int(days or 7), 90))
    except (TypeError, ValueError):
        days = 7
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    # Was a five-stage zcat|awk|grep|awk|sort|head pipeline running as root, with the cutoff date
    # and the limit interpolated into it. The verb reads the rotated logs and returns the lines;
    # everything the awk did — filter by date, extract Ban/Found, tally per IP — is Python now.
    out, _, rc = _run_verb("f2b-log-lines", [cutoff], timeout=25, merge_stderr=False)
    if rc != 0:
        _log.debug("top-ips: the fail2ban log read failed (rc=%s)", rc)
        return None
    out = _tally_f2b_lines(out, limit)
    banned_now = set()
    try:
        for j in fail2ban_overview().get("jails", []):
            banned_now.update(j.get("banned_ips", []))
    except Exception:
        _log.debug("top-ips: couldn't read current bans", exc_info=True)
    try:
        blocked = ufw_blocked_ips() or {}      # None = unreadable; for an annotation, blank is fine
    except Exception:
        _log.debug("top-ips: couldn't read ufw blocks", exc_info=True)
        blocked = {}
    return _parse_top_ips(out, banned_now, blocked)


def _f2b_cutoff(days):
    """The fail2ban log cutoff date, `days` (clamped 1..90, default 7) before now."""
    from datetime import datetime, timedelta
    try:
        days = max(1, min(int(days or 7), 90))
    except (TypeError, ValueError):
        days = 7
    return (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")


def fail2ban_attempt_counts(days=7):
    """{ip: detected attempts} for EVERY offender in the fail2ban log over the last `days` days.
    None when the read failed, exactly as fail2ban_top_ips answers it.

    For the auto-block reconcile, which read the DISPLAY list instead — fail2ban_top_ips(100), cut
    at the top 100 by attempts. Anything over the threshold ranked below 100 was never blocked;
    and a blocked address, which logs nothing more and so stops climbing, dropped out of the top
    100 as a wave of new ones passed it and was RELEASED while still over the threshold. The
    threshold is a count, so the reconcile needs every count."""
    out, _, rc = _run_verb("f2b-log-lines", [_f2b_cutoff(days)], timeout=25, merge_stderr=False)
    if rc != 0:
        _log.debug("attempt counts: the fail2ban log read failed (rc=%s)", rc)
        return None
    return _tally_f2b_events(out)[0]


def fail2ban_unban(jail, ip):
    """Lift a ban: `fail2ban-client set <jail> unbanip <ip>`. The request-supplied values are
    neutralised BEFORE they reach the command: `jail` must be one of the host's actual jails (an
    allowlist — not a free string), and `ip` is reparsed to the canonical form produced by
    ipaddress (which rejects anything that isn't a real IP). Then shell-quoted. (ok, msg)."""
    import ipaddress
    jail = (jail or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", jail):   # metacharacter-free guard
        return False, "Invalid jail name."
    # Rebind `jail` to the matching entry from the host's actual jail list (fail2ban-client output,
    # not the request), so the value interpolated into the command is sourced from trusted data and
    # is never the raw request string. A guard/allowlist alone did not clear the taint for CodeQL —
    # this rebind (mirroring how the ip guard reparses through ipaddress) does.
    jail = next((j for j in _fail2ban_jails() if j == jail), None)
    if jail is None:
        return False, "Unknown jail."
    ip = (ip or "").strip()
    try:
        ip = str(ipaddress.ip_address(ip))   # canonical form; rejects anything that isn't a real IP
    except ValueError:
        return False, "Invalid IP address."
    if not re.fullmatch(r"[0-9A-Fa-f:.]{1,45}", ip):   # metacharacter-free guard (a barrier CodeQL recognises)
        return False, "Invalid IP address."
    out, err, rc = _run_verb("f2b-unban", [jail, ip], timeout=15)
    if rc == 0:
        return True, "Unbanned %s from %s." % (ip, jail)
    return False, ((out or err or "Unban failed").replace("\n", " ")[:200])


def fail2ban_unban_ip_everywhere(ip):
    """Best-effort: lift `ip` from EVERY jail that currently bans it. Used when an IP is whitelisted,
    so an existing ban is cleared immediately instead of waiting for it to expire. (ok, msg)."""
    import ipaddress
    try:
        ip = str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        return False, "Invalid IP address."
    lifted = 0
    try:
        for j in fail2ban_overview().get("jails", []):
            if ip in (j.get("banned_ips") or []):
                ok, _msg = fail2ban_unban(j.get("jail"), ip)
                lifted += 1 if ok else 0
    except Exception:
        _log.debug("f2b: unban-everywhere failed", exc_info=True)
    return True, "lifted %s from %d jail(s)" % (ip, lifted)


def security_log_tail(which, lines=200, jail=None):
    """Tail of a WHITELISTED security log for the raw-log viewer. `which` is one of a fixed set —
    never a path from the request — so there's no traversal. For 'fail2ban', an optional `jail`
    (allowlisted against the host's real jails) narrows the activity to that one jail. Returns text
    (may be empty)."""
    lines = max(20, min(int(lines or 200), 1000))
    if which == "panel":
        from panel.core import config as _cfg
        p = os.path.join(str(_cfg.DATA_DIR), "auth.log")
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                return "".join(f.readlines()[-lines:])
        except OSError:
            return ""
    if which == "fail2ban":
        # The real jail activity — Ban / Unban / Found, one line per event, each tagged with its
        # jail — lives in /var/log/fail2ban.log (fail2ban's default logtarget). `journalctl -u
        # fail2ban` only carries the systemd unit's start/stop noise, so read the file first and
        # fall back to the journal only if it isn't there.
        out, _, _ = _run_verb("log-tail", ["fail2ban", "4000"], timeout=15, merge_stderr=False)
        if not out:
            out, _, _ = _run_verb("journal", ["fail2ban", "4000"], timeout=15, merge_stderr=False)
        rows = (out or "").splitlines()
        if jail and jail in _fail2ban_jails():   # allowlist; used only for in-Python filtering, never a command
            tag = "[%s]" % jail
            rows = [ln for ln in rows if tag in ln]
        return "\n".join(rows[-lines:])
    if which == "ssh":
        out, _, _ = _run_verb("journal", ["ssh", str(lines * 2)], timeout=15, merge_stderr=False)
        if not out:
            out, _, _ = _run_verb("log-tail", ["auth", str(lines)], timeout=15, merge_stderr=False)
        return "\n".join((out or "").splitlines()[-lines:])
    return ""


def configure_panel_fail2ban(auth_log, web_port, ignore_ips=None):
    """Install fail2ban (if needed) and configure a jail that bans IPs which repeatedly fail the
    PANEL's web login — it tails the panel's auth.log and bans on the web port. `ignore_ips` are
    whitelisted (never banned). Idempotent. Returns (ok, message)."""
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
        _run_verb("apt-update", [], timeout=120, merge_stderr=False)
        _run_verb("apt-install", ["fail2ban"], timeout=300)
        have2, _, _ = _run("command -v fail2ban-client >/dev/null 2>&1 && echo yes || echo no", timeout=10)
        if "yes" not in (have2 or ""):
            return False, "Couldn't install fail2ban on this host."

    _write_root_file(_F2B_PANEL_FILTER, _panel_f2b_filter_body())
    _write_root_file(_F2B_PANEL_JAIL, _panel_f2b_jail_body(auth_log, web_port, ignore_ips))

    _run_verb("service-enable-now", ["fail2ban"], timeout=45)
    # Was `fail2ban-client reload || systemctl restart fail2ban` in one root shell.
    if _run_verb("f2b-reload", [], timeout=45)[2] != 0:
        _run_verb("service-restart", ["fail2ban"], timeout=45)

    _f2b_ok_msg = ("fail2ban is now protecting the panel login — 5 failed logins from an IP in "
                   "10 minutes get it banned for an hour.")
    # fail2ban's reload is ASYNCHRONOUS — on a busy host the jail can take a moment to register, so
    # poll instead of checking once (the old single check was the "didn't come up" false alarm).
    for _ in range(6):
        if panel_fail2ban_status().get("enabled"):
            return True, _f2b_ok_msg
        time.sleep(1)
    # Still down after a reload: one hard restart, then a final look.
    _run_verb("service-restart", ["fail2ban"], timeout=45)
    time.sleep(2)
    if panel_fail2ban_status().get("enabled"):
        return True, _f2b_ok_msg
    # Give up — but surface the REAL reason instead of a generic message.
    detail, derr, _ = _run_verb("f2b-status-jail", ["linuxgsm-panel"], timeout=10)
    reason = (detail or derr or "").strip()
    if not reason:
        # Was `journalctl … | grep -iE '…' | tail -2` in a root shell. The filtering is the same
        # in Python, and the pattern stops being something a root command line has to carry.
        _j, _, _ = _run_verb("journal", ["fail2ban", "25"], timeout=10, merge_stderr=False)
        _hits = [ln for ln in (_j or "").splitlines()
                 if re.search(r"linuxgsm-panel|have not found|log file|error", ln, re.I)]
        reason = "\n".join(_hits[-2:])
    reason = (reason or "").replace("\n", " ").strip()[:200]
    return False, ("Configured fail2ban, but the jail didn't come up. %s"
                   % (reason or "Check `fail2ban-client status linuxgsm-panel` and the panel logs."))


def ensure_panel_fail2ban(auth_log, web_port, ignore_ips=None):
    """Idempotently make sure the panel-login jail is active on the CURRENT web port with the CURRENT
    whitelist. Safe to call on EVERY startup, after a port change, and after a whitelist edit: a
    healthy jail on the right port with the right ignoreip costs just a status read (no reload),
    while a missing jail, a stale port, or a changed whitelist triggers a rewrite + reload. Does NOT
    install fail2ban (that's the installer's job) — no-ops when it isn't present. Returns (ok, msg)."""
    try:
        web_port = int(web_port)
    except (TypeError, ValueError):
        return False, "Invalid web port."
    st = panel_fail2ban_status()
    if not st.get("installed"):
        return False, "fail2ban isn't installed on this host."
    # The logpath and the backend are part of "healthy", not just the port and the whitelist.
    # Checking only the latter two let a jail that monitors NOTHING report itself as already
    # active, forever: this function is the only thing that would ever rewrite it, and it returned
    # early. Found on a host whose jail still carried a logpath from a previous install path.
    allports = _panel_login_proxied()
    want_action = _F2B_PANEL_ALLPORTS_ACTION if allports else None
    # Built exactly as _panel_f2b_jail_body builds it — tailnet included on an all-ports jail — or
    # a jail written without it would read as healthy and never be rewritten.
    want_ignore = _f2b_ignoreip_line(_panel_f2b_ignore(ignore_ips, allports)).split()
    if (st.get("enabled") and _panel_f2b_jail_port() == web_port
            and _panel_f2b_jail_value("banaction") == want_action
            and _panel_f2b_jail_value("logpath") == str(auth_log)
            and _panel_f2b_jail_value("backend") == _F2B_PANEL_BACKEND
            and (_panel_f2b_jail_ignoreip() or []) == want_ignore):
        return True, "panel-login jail already active on port %d" % web_port
    return configure_panel_fail2ban(auth_log, web_port, ignore_ips)


def panel_diagnostics():
    """A fast, local self-check of the panel's own health: file integrity, data
    dir, database, encryption keys, config, disk space, TLS cert and service
    unit. No SSH/network. Returns {checks:[{name,level,detail}], summary, counts}."""
    import shutil
    from panel.core import config as _cfg
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

    # 4b. the INSTALLED privileged helper matches this version's verb table.
    #
    # The helper lives outside the checkout and is placed only by install.sh as root, so the panel
    # cannot refresh it. Nothing surfaced a mismatch: _helper_present() checks the file exists and
    # is executable, and an unknown verb comes back as rc 2 with `unknown verb` on stderr and no
    # fallback — so a stale helper made the feature behind each new verb fail silently. Compare the
    # two tables here so the Diagnostics card says which verbs are missing and what to run.
    if _helper_present():
        try:
            # Same suppression, and the same reasoning, as the subprocess.run in _run_verb above —
            # which is the only other place the panel executes the helper. This argv is narrower
            # still: BOTH elements are module constants (privileged.HELPER_PATH and the literal
            # "--list-verbs"), nothing here is derived from a request, and shell=False means no
            # element is ever interpreted. The scanners flag any call whose first argument is not a
            # literal string; making it one would mean composing a command, which is the thing the
            # verb table exists to remove. Reviewed and suppressed rather than silently left red.
            # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
            _hv = subprocess.run([_priv.HELPER_PATH, "--list-verbs"], shell=False,  # nosec B603
                                 capture_output=True, text=True, timeout=10)
            _installed = {ln.split("\t")[0] for ln in (_hv.stdout or "").splitlines() if ln.strip()}
            _missing = sorted(set(_priv.verbs()) - _installed)
            if _hv.returncode != 0 or not _installed:
                add("Privileged helper", "warn",
                    "Installed, but its verb table could not be read.")
            elif _missing:
                add("Privileged helper", "fail",
                    "Out of date — %d verb(s) this version needs are missing (%s%s). "
                    "Re-run install.sh as root on this host to refresh it."
                    % (len(_missing), ", ".join(_missing[:4]),
                       ", …" if len(_missing) > 4 else ""))
            else:
                add("Privileged helper", "ok",
                    "Installed and current (%d verbs)." % len(_installed))
        except Exception:
            add("Privileged helper", "warn", "Installed, but could not be queried.")
    else:
        add("Privileged helper", "warn",
            "Not installed — privileged actions fall back to the pre-helper path and the "
            "sudoers grant cannot be narrowed. Re-run install.sh as root to place it.")

    # 5. config loads
    # load_config() never raises: an unreadable file comes back as defaults, MARKED. The except
    # alone reported "loads cleanly" for any corrupt file, because it could never fire.
    try:
        _unreadable = _cfg.is_unreadable(_cfg.load_config())
    except Exception:
        _unreadable = True
    if _unreadable:
        add("Configuration", "fail", "config.json could not be read or parsed.")
    else:
        add("Configuration", "ok", "config.json loads cleanly.")

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
    "session_protection", "audit_log_retention_days", "audit_ip_retention_days",
    "site_title", "site_domain",
)


def _redact(text):
    """Best-effort scrub of anything secret-looking from free text (a log tail). The
    report is whitelist-built so this is defence-in-depth: emails, long token/key/hash
    strings, and key=value secrets get masked before an admin reviews + shares it."""
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


_CANONICAL_REPO = "https://github.com/FMSMITH91/linuxgsm-panel"


def github_repo_url():
    """Web URL of wherever this checkout's origin points (upstream for most, a fork if they
    forked). Falls back to the canonical repo. No trailing slash, so callers can append a path."""
    try:
        out, _, rc = _git(["config", "--get", "remote.origin.url"])
        m = re.search(r"github\.com[:/]([^/\s]+/[^/\s.]+)", out.strip()) if rc == 0 else None
        return "https://github.com/%s" % m.group(1) if m else _CANONICAL_REPO
    except Exception:
        return _CANONICAL_REPO


def _github_issues_url():
    """New-issue URL for wherever this checkout's origin points (upstream for most,
    a fork if they forked). Falls back to the canonical repo."""
    return github_repo_url() + "/issues/new"


def generate_debug_report():
    """Build a diagnostic report an operator can attach to a GitHub issue. Whitelisted
    fields only + a redacted log tail. Returns {report, summary, issues_url, filename}."""
    import sys
    import time as _t
    import platform
    from panel.core import config as _cfg
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
        from panel.db.models import RemoteServer, GameServer
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
        from panel.db.models import database_stats
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
        log, _, _ = _run_verb("journal", ["panel", "400"], timeout=10, merge_stderr=False)
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
