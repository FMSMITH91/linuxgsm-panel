"""System operations for the local server — UFW, Tailscale SSH, OS updates, reboot."""
import fnmatch
import http.client
import json
import logging
import os
import re
import shlex
import subprocess
from panel.core import terminal
from panel.core.validation import canonical_ip, canonical_ip_or_network, ip_address_or_none
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
# Where a fetched branch lives, always used IN FULL: a bare `origin/<branch>` is resolved by git as
# refs/tags/origin/<branch> first, so a tag of that name would stand in for the branch.
_REMOTE_TRACKING = "refs/remotes/origin/"
# A deliberately strict git-ref charset: no spaces, no leading dash (option injection) and
# no ".." (traversal). Defence-in-depth — git is invoked without a shell (see _git) and the
# installer re-validates PANEL_BRANCH — but we still refuse anything outside this shape.
# First character alphanumeric, like the helper's v_branch_name and privileged._branch_name: this
# accepted a leading "_" or "." that the verb then refused, so a branch named `_wip` was saved as
# the tracked branch and every update after it failed the same way.
_BRANCH_RE = r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}\Z"


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

# Verbs whose output is all or nothing: every caller discards a partial answer rather than act on
# it. The helper's f2b-log-lines stops past its own ceiling and exits 3 (F2B_LOG_MAX_BYTES, one
# read chunk under this process's collector cap, so the collector never cuts the helper first).
# The shell form (the pre-helper fallback, and every remote host) stops at the same ceiling with the
# same rc 3 itself. When this process's collector does the cutting -- a helper that predates that
# exit -- _collect_verb_output answers the SAME rc 3. So "cut" means one thing whichever side
# stopped reading, and an answer the helper called complete is complete here too.
_WHOLE_OUTPUT_VERBS = frozenset({"f2b-log-lines"})
_CUT_RC = 3


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
    install.sh re-run as root keeps working.

    Every finished call is counted for the debug report (ssh_manager._core.note_privileged, which
    cannot raise), by the path it took and how it ended."""
    path, res = _run_verb_once(verb, args, timeout, merge_stderr)
    if path:
        from panel.ops.ssh_manager import _core as _smc     # lazy: ssh_manager imports this module
        _smc.note_privileged(verb, path, res)
    return res


def _run_verb_once(verb, args, timeout, merge_stderr):
    """_run_verb's body: (the path taken -- "helper" / "root" / "shell", or "" for a refused
    argument --, (stdout, stderr, rc))."""
    # NEVER RAISES, which its callers are written on (see os_run_update, server_reboot):
    # the argv builders validate the arguments and raise VerbError on a refusal, and that used to
    # escape from here into callers with no handler for it — a 500, with no audit row.
    try:
        if _helper_present():
            path, argv = "helper", _priv.helper_argv(verb, args)
        elif hasattr(os, "geteuid") and os.geteuid() == 0:
            path, argv = "root", _priv.tool_argv(verb, args)
        else:
            return "shell", _run_verb_shell(
                _priv.remote_command(verb, args, merge_stderr=merge_stderr),
                timeout=timeout, sudo=True, whole=verb in _WHOLE_OUTPUT_VERBS)
    except _priv.VerbError:
        _log.warning("privileged verb %s refused its arguments", verb)
        return "", ("", "invalid argument", -1)
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
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit,python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        p = subprocess.Popen(argv, shell=False,  # nosec B603 - argv from privileged.py's fixed table
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=(subprocess.PIPE if _in is not None else subprocess.DEVNULL),
                             start_new_session=True)
        out, err, rc = _collect_verb_output(p, argv, timeout, _in,
                                            whole=verb in _WHOLE_OUTPUT_VERBS)
    except subprocess.TimeoutExpired:
        return path, ("", "Command timed out", -1)
    except FileNotFoundError:
        return path, ("", "Command not found", -1)
    except Exception:
        _log.debug("privileged verb failed", exc_info=True)
        return path, ("", "command execution error", -1)
    return path, _verb_result(out, err, rc, merge_stderr)


def _collect_verb_output(p, cmd, timeout, stdin_text=None, whole=False):
    """A started verb's (stdout, stderr, rc) as text, KEEPING at most the transports' ceiling.

    subprocess.run(capture_output=True) — what both branches of _run_verb used — buffers every
    byte a command writes until it exits. On the panel host that is the one process running every
    host's management, and a verb's output is not always the panel's to size: f2b-log-lines prints
    the fail2ban log, which an unauthenticated attacker grows (a million lines, 124 MB, took this
    process from 12 MB to 656 MB). Remotes were already capped at ssh_manager._core's
    _MAX_OUTPUT_BYTES; this is the same reader and the same ceiling, so no caller can depend on
    more here than it gets from a remote. Raises TimeoutExpired, like subprocess.run, when the
    verb outlives `timeout` (it has been killed, its whole process group with it) -- within about
    a second of it, however the verb's descendants behave: see _collect_capped.

    `whole`: the verb is all-or-nothing (_WHOLE_OUTPUT_VERBS), so output this cut short is
    answered as the helper answers its own: rc 3, and a message on stderr.
    """
    from panel.ops.ssh_manager import _core as _smc     # lazy: ssh_manager imports this module
    # The kill only SIGNALS: _collect_capped reaps, after its readers have let go of the pipes.
    # It was _kill_process_tree, whose communicate() read the same pipes as those readers.
    res = _smc._collect_capped(p, timeout, kill=lambda: _smc._signal_process_tree(p),
                               threads=threading,
                               stdin_bytes=(stdin_text.encode("utf-8")
                                            if stdin_text is not None else None))
    if res is None:
        raise subprocess.TimeoutExpired(cmd, timeout)
    out, err, rc, truncated = res
    if truncated:
        _log.warning("privileged verb output exceeded %d bytes and was truncated",
                     _smc._MAX_OUTPUT_BYTES)
        if whole and rc == 0:
            return (_smc._decode_output(out),
                    "output passed the panel's %d-byte read limit; truncated, so it must be "
                    "treated as unread" % _smc._MAX_OUTPUT_BYTES, _CUT_RC)
    return _smc._decode_output(out), _smc._decode_output(err), rc


def _verb_result(out, err, rc, merge_stderr):
    """_run_verb's answer from a finished verb: stripped, with stderr merged in unless asked not."""
    out, err = (out or "").strip(), (err or "").strip()
    if merge_stderr:
        # The shell form ended in `2>&1` and callers read tool errors out of stdout; merging keeps
        # a message on the stream its caller already reads.
        return ("\n".join(x for x in (out, err) if x)).strip(), "", rc
    return out, err, rc


def _run_verb_shell(cmd, timeout=30, sudo=False, whole=False):
    """_run_verb's pre-helper fallback: a composed shell form, with the same ceiling as the rest.

    It used to go through _run, i.e. subprocess.run(shell=True, capture_output=True), which keeps
    everything — and this branch is the one a panel host whose helper predates a fix still takes,
    so it needs the ceiling most. Merging stderr is the command's own business here (the shell
    form ends in `2>&1` when asked to). `whole` as for _collect_verb_output.
    """
    # os.geteuid() is Unix-only; guard it so callers don't crash off-Linux (tests).
    if sudo and hasattr(os, "geteuid") and os.geteuid() != 0:
        cmd = f"sudo {cmd}"
    try:
        # nosemgrep: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true -- the pre-helper verb form, built by privileged.py from its fixed table
        p = subprocess.Popen(cmd, shell=True,  # nosec B602 - privileged.py's own shell form
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, start_new_session=True)
        out, err, rc = _collect_verb_output(p, cmd, timeout, whole=whole)
        return out.strip(), err.strip(), rc
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except FileNotFoundError:
        return "", "Command not found", -1
    except Exception:
        _log.debug("privileged verb (shell form) failed", exc_info=True)
        return "", "command execution error", -1


def _run(cmd, timeout=30, sudo=False, text=True):
    """Run a shell command. Returns (stdout, stderr, exit_code)."""
    # os.geteuid() is Unix-only; guard it so callers don't crash off-Linux (tests).
    if sudo and hasattr(os, "geteuid") and os.geteuid() != 0:
        cmd = f"sudo {cmd}"
    try:
        r = subprocess.run(
            # nosemgrep: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true -- the panel's shell runner by design; every caller quotes what it interpolates
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
        # _run_verb merges stderr into stdout, so the "not installed" answer is looked for in both.
        # Any OTHER failure is not a reading: `enabled` stays False, which is what every caller
        # branches on, and `unreadable` says the False was not measured (R42).
        said = "%s\n%s" % (out or "", err or "")
        if "not found" in said or "not installed" in said:
            return {"enabled": False, "status_text": "not_installed", "rules": []}
        return {"enabled": False, "status_text": "inactive", "rules": [], "unreadable": True}

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
        rule = _ufw_rule_split(line)
        if rule:
            rules.append(rule)

    return {"enabled": enabled, "status_text": status_text, "rules": rules}


# "<to>  <ACTION> <DIR>  <from>" — the shape of every rule row in `ufw status verbose`.
# ALLOW/DENY/REJECT/LIMIT is the only column with a closed vocabulary, so it is the anchor: the To
# column ends at the first gap of two or more blanks that an action follows.
#
# Two passes, not the one `^(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s*(.*)$` this
# was. There the lazy `.+?` stepped onto every blank of a gap and `\s{2,}` re-read the rest of the
# gap from each one, so a row with a long run of blanks cost the square of its length (20,000
# blanks: 1.3s, and 4x that for twice as many). finditer reads each gap once, from its first
# blank — the only place the old pattern could end the To column, since a later blank of the same
# gap reaches the same action — and the action is tried where `\s{2,}` left off, the gap's end.
_UFW_RULE_GAP_RE = re.compile(r"\s{2,}")
_UFW_RULE_TAIL_RE = re.compile(r"(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)")


def _ufw_rule_split(line):
    """One `ufw status verbose` row as {to, action, direction, from}, or None when it is not one.

    `line` is one line (no newline in it). The search starts at 1 because the To column is never
    empty, which is what the old pattern's `.+` said."""
    for gap in _UFW_RULE_GAP_RE.finditer(line, 1):
        m = _UFW_RULE_TAIL_RE.match(line, gap.end())
        if m:
            return {"to": line[:gap.start()].strip(), "action": m.group(1),
                    "direction": m.group(2), "from": line[m.end():].strip()}
    return None


def ufw_allows_iface_in(rules, iface):
    """True when UFW's rules (ufw_status()["rules"], in the order UFW evaluates them) let all
    inbound traffic in on `iface` — the `ufw allow in on <iface>` rule the panel's Allow button adds.

    This decides whether the management page may offer "Disable (tailnet-only)", which removes
    public port 22, so every doubt answers False. It used to be a substring match over the raw
    `ufw status verbose` text, and any row naming the interface counted: `ALLOW OUT ... on
    tailscale0` (which early installs added beside the IN rule, and which survives deleting it),
    `on tailscale0 DENY IN`, or a comment. Any of those read "Allowed" and unlocked the lockdown
    that then cut SSH off over the tailnet too.

    UFW takes the first matching rule, so a DENY or REJECT IN on the interface above the allow
    wins. A rule for one port on the interface is not "all traffic" and does not count."""
    if not iface:
        return False
    whole = ("anywhere on " + iface).lower()
    suffix = (" on " + iface).lower()
    for r in rules or []:
        if r.get("direction") != "IN":
            continue
        to = (r.get("to") or "").strip().lower()
        if not to.endswith(suffix):
            continue
        if r.get("action") in ("DENY", "REJECT"):
            return False
        if to == whole and r.get("action") in ("ALLOW", "LIMIT"):
            return True
    return False


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


# `tailscale set` changes the one pref it is given. This toggle used to run `tailscale up --ssh
# --accept-routes --accept-dns --reset`, and `--reset` puts every pref NOT on the command line back
# to its default: a hand-set hostname (and with it the Serve URL the admins reach the panel on),
# advertised subnet routes, an exit node, shields-up and advertised tags were all withdrawn, and
# accept-routes was forced on, while the panel reported only "Tailscale SSH enabled".
def tailscale_ssh_enable():
    """Turn this node's Tailscale SSH server on, and change nothing else (see above)."""
    out, err, rc = _run("tailscale set --ssh 2>&1", timeout=30)
    if rc == 0:
        return True, "Tailscale SSH enabled"
    return False, err or out or "Failed to enable Tailscale SSH"


def tailscale_ssh_disable():
    """Turn this node's Tailscale SSH server off, and change nothing else."""
    out, err, rc = _run("tailscale set --ssh=false 2>&1", timeout=30)
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
    #
    # OverflowError too: a JSON body is not limited to finite numbers — Python's json reads
    # `Infinity` and `1e400` as float('inf'), and int() of that raises OverflowError, which this
    # did not catch. POST {"delay": 1e400} answered a 500 instead of this sentence.
    try:
        delay = max(0, min(300, int(delay_seconds)))
    except (TypeError, ValueError, OverflowError):
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
    # Always > 0: both branches above return unless total > prev_total, and all four are this
    # call's own locals. The `if d_total <= 0: return ""` that sat here could never run.
    d_total = total - prev_total
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

    # Is the Tailscale interface already let in by UFW? Read from the rules ufw_status() parsed.
    tailscale_ufw_allowed = bool(ts_iface and ufw["enabled"]
                                 and ufw_allows_iface_in(ufw["rules"], ts_iface))

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


def _version_from_epoch(text):
    """The calendar version for a Unix time given as text: its UTC date as YYYY.M.D.

    No leading zeros (2026.9.26), and UTC whatever the host's timezone. "" for anything that is
    not a plain run of ASCII digits, or that the platform cannot convert.
    """
    text = (text or "").strip()
    if not re.fullmatch(r"[0-9]{1,12}", text):
        return ""
    try:
        t = time.gmtime(int(text))
    except (OverflowError, OSError, ValueError):
        return ""
    return "%d.%d.%d" % (t.tm_year, t.tm_mon, t.tm_mday)


def version_for_commit(commit="HEAD"):
    """The panel's version for one commit: the date it was committed, in UTC, as YYYY.M.D.

    Read as the committer time in seconds (%ct), so neither the host's timezone nor the offset the
    commit was made in moves it. Every commit of a day shares the date, which is why the panel
    shows it beside the short commit. "" when git cannot say. The trailing `--` makes git take the
    name as a revision only: without it, a name that is not one but is a file in the checkout
    answered with the last commit that touched that file.
    """
    if not commit or commit.startswith("-"):
        return ""
    out, _, rc = _git(["log", "-1", "--no-show-signature", "--format=%ct", commit, "--"],
                      timeout=10)
    return _version_from_epoch(out) if rc == 0 else ""


def _version_file():
    """The version from the VERSION file, for a copy of the panel that is not a git checkout.

    The repository's VERSION holds git's export-subst placeholder, which `git archive` (so also a
    GitHub "Download ZIP") replaces with the commit's epoch. An epoch reads as its date; the
    placeholder itself, or an empty or unreadable file, as "unknown"; anything else is a version
    kept by hand before dates (a snapshot or rollback of an older install) and is shown as it is.
    """
    try:
        with open(os.path.join(PANEL_DIR, "VERSION"), encoding="utf-8") as f:
            raw = f.read().strip()
    except (OSError, UnicodeDecodeError):
        return "unknown"
    if raw.isascii() and raw.isdecimal():
        return _version_from_epoch(raw) or "unknown"
    if not raw or raw.startswith("$Format:"):
        return "unknown"
    return raw


def panel_version():
    """The running panel's version: the checked-out commit's date (see version_for_commit).

    Without a .git, or when git cannot answer, it is read from the VERSION file instead.
    """
    if _is_git_checkout():
        ver = version_for_commit("HEAD")
        if ver:
            return ver
    return _version_file()


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
    # \Z where this had `\s*$`: the URL is stripped, so nothing but its end can follow, and `\s*`
    # there only let the lazy repo name re-scan a run of blanks from each of its characters.
    #
    # `(?::\d+)?` — a PORT after the host. GitHub's documented SSH-over-HTTPS form is
    # ssh://git@ssh.github.com:443/owner/repo.git (for hosts whose firewall blocks port 22), and
    # the pattern read "443/owner" as the owner, failed on the rest, and returned None. None is
    # "no repository to ask", so the CI gate could never read a check on such a host — which used
    # to mean every commit was 'unknown' and installable, silently. The group is optional and
    # backtracks, so a scp-style `git@github.com:123/repo` still names owner 123.
    m = re.search(r"github\.com(?::\d+)?[/:]([^/]+/[^/]+?)(?:\.git)?/?\Z", url.strip())
    return m.group(1) if m else None


# install.sh's REPO_URL: check_origin_trusted compares origin's URL with it, and with it minus
# ".git", as EXACT strings (a unit check holds this to install.sh's line).
_TRUSTED_ORIGIN = "https://github.com/FMSMITH91/linuxgsm-panel.git"


def origin_category():
    """How install.sh judges this checkout's origin, as a category -- never the URL, which can
    carry user:token@ or a fork owner's name.

    'canonical-https'      exactly what install.sh trusts: root's pieces are refreshed from it.
    'canonical-other-form' the canonical repository in a form install.sh does not accept (ssh, a
                           port, another case): it is UNTRUSTED there and root's pieces go stale,
                           while _repo_slug still reads it, so the CI gate works.
    'fork'                 any other repository.
    'unreadable'           the read failed; install.sh would treat it as untrusted."""
    url, _, rc = _git(["remote", "get-url", "origin"], timeout=5)
    url = (url or "").strip()
    if rc != 0 or not url:
        return "unreadable"
    if url in (_TRUSTED_ORIGIN, _TRUSTED_ORIGIN[:-len(".git")]):
        return "canonical-https"
    m = re.search(r"github\.com(?::\d+)?[/:]([^/]+/[^/]+?)(?:\.git)?/?\Z", url)
    if m and m.group(1).lower() == "fmsmith91/linuxgsm-panel":
        return "canonical-other-form"
    return "fork"


# Conclusions that mean a completed check did NOT pass.
_CI_BAD = {"failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"}
# Checks that don't gate the update-offer: `deploy` is the deployment action itself (gating on
# it would be circular, and it only exists when auto-deploy is enabled), not a verification.
# "Upload coverage to Codacy" (codacy-coverage.yml) sends a report somewhere; it verifies nothing.
# Both are workflow_run jobs, and GitHub files a workflow_run job's check run under main's NEWEST
# commit even when the run is for a pull request, so without this a PR whose coverage upload
# failed (no artifact, a Codacy outage, an expired token) marked main's tip failing, and no panel
# was offered it until the next merge. tests/unit ties this name to the workflow's job name.
#
# "Code-scanning alerts gate" is codeql-alerts.yml's job, and the same kind of misfiled run: it
# judges ONE commit (the head of the CodeQL run that triggered it) and GitHub files the job under
# whatever main's tip is when it runs. Its verdict reaches the commit it is about as a check run
# the job posts itself, named "Open code-scanning alerts" (see _CI_REQUIRED); the job's own run
# says nothing about the commit it lands on.
_CI_IGNORE = {"deploy", "Upload coverage to Codacy", "Code-scanning alerts gate"}
# Checks a commit must CARRY before it can be 'passing', when it changed anything the CI and
# CodeQL workflows run for (see _ci_suite_expected). "Every check that exists is green" was the
# rule, and it is only a rule about the checks that exist so far. "Open code-scanning alerts" is
# posted after CodeQL completes, a minute or two after everything else has gone green, so for
# that minute a commit with a new alert read 'passing' and was installed. The same holds for any
# check that has not registered yet. So the set is named, and a commit missing any of it is
# 'pending'.
#
# A name ending in "(" is a PREFIX, for a matrix job: `checks (ubuntu-24.04 · py3.12)`. The
# matrix changes (a Python is added, an image retired) and the panel judging a NEW commit is
# running the OLD code, so an exact matrix name would strand every installed panel on its version
# the day the matrix moved. The same is true of renaming any job here: it holds every panel back
# until it is updated by hand. tests/unit holds this list to the workflow files, and deploy.yml's
# verify step carries the same list (a unit test holds the two equal).
_CI_REQUIRED = ("checks (", "coverage", "js coverage", "gamedig lockfile (", "Analyze (",
                "Open code-scanning alerts")
# ci.yml's and codeql.yml's shared paths-ignore (a unit test holds the three equal): a commit
# that changed only these runs neither workflow, so none of _CI_REQUIRED will ever appear on it.
_CI_PATHS_IGNORED_FILES = {"LICENSE", ".gitignore", ".gitattributes", ".editorconfig"}


def _ci_path_ignored(path):
    """True for a path ci.yml and codeql.yml do not run for ('**/*.md', 'docs/**', and the files)."""
    return path.endswith(".md") or path.startswith("docs/") or path in _CI_PATHS_IGNORED_FILES


def _ci_name_matches(required, name):
    """Whether check-run `name` is the _CI_REQUIRED entry `required` (a trailing '(' is a prefix)."""
    return name == required or (required.endswith("(") and name.startswith(required))


def _ci_suite_expected(sha, runs):
    """Whether `sha` must carry every check in _CI_REQUIRED before it can pass.

    Yes when any of them is already on it (the suite ran: the rest is on its way), and yes when
    the commit changed a path the suite runs for. A docs-only commit runs neither CI nor CodeQL,
    and demanding their checks of it would hold it 'pending' for ever. Fails SAFE: a diff the
    checkout cannot produce (a root commit, one not fetched) expects the whole suite."""
    if any(_ci_name_matches(req, r.get("name") or "") for r in runs for req in _CI_REQUIRED):
        return True
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", sha or ""):
        return True
    out, _, rc = _git(["diff", "--name-only", sha + "^1", sha, "--"], timeout=20)
    if rc != 0:
        return True
    return any(not _ci_path_ignored(f.strip()) for f in (out or "").splitlines() if f.strip())


# Why the last _remote_ci_state answer was 'unknown', in words for the update card. Written by
# _remote_ci_state, read by _compute_update_status straight after its call; both run under
# _update_lock (panel_update_status), so one computation's reason is never another's.
_ci_unknown_why = {"reason": ""}
_CI_WHY_NO_SLUG = ("this panel's origin is not a github.com repository address it recognises, "
                   "so its automated checks cannot be looked up")
_CI_WHY_NOT_FOUND = ("GitHub did not show this repository's automated checks (a private "
                     "repository cannot be checked without a token)")
_CI_WHY_UNREACHABLE = "GitHub could not be reached to read its automated checks"


def _remote_ci_state(sha):
    """Best-effort: have ALL of the remote commit `sha`'s checks passed on GitHub yet?

    Returns 'passing' | 'pending' | 'failing' | 'unknown'. The panel offers an update only once
    EVERY check on the commit has completed successfully AND the commit carries the checks it is
    expected to (_CI_REQUIRED) — CI, CodeQL, and the code-scanning alerts check, which is where
    CodeQL's, Bandit's and Semgrep's findings gate (all three upload to code scanning); plus
    pip-audit, Gitleaks and Lighthouse, which fail their own checks. So "check for updates" never
    surfaces a commit while anything is still running, before a late check has appeared, or after
    any check failed. (The _CI_IGNORE checks are ignored: they are not verifications.) Reads
    GitHub's public check-runs API anonymously (the production panel has no token).

    'unknown' means the checks could not be READ — no github.com origin, GitHub unreachable, a
    404 from a private repository — and is NOT installable: the caller stops and says why (the
    reason is left in _ci_unknown_why). It used to be accepted "so an API hiccup never hides a
    real update", and what that bought was the reverse: the walk takes the tip first, so any
    panel that could not read GitHub — including every panel whose origin the slug pattern did
    not recognise, permanently and without a word — was offered the one commit nobody had
    verified. GitHub's rate limit is not 'unknown' but 'pending' (see the handler below).

    Registration timing: the push-triggered checks all register within seconds of the push, long
    before CI (minutes) completes. The one that does not is "Open code-scanning alerts", posted
    after CodeQL finishes — which is why presence is REQUIRED rather than inferred.

    What held the commit (failing, pending and missing check names) and GitHub's rate-limit
    headers are recorded for the debug report (_ci_record, R31) after the answer is decided; the
    recording cannot raise and never changes it."""
    seen = {}
    state = _remote_ci_state_read(sha, seen)
    _ci_record(sha, state, seen)
    return state


# A check name the report may print: GitHub's public check names are this shape; anything else
# (a fork can name a job anything) is printed as a placeholder.
_CI_NAME_RE = re.compile(r"^[\w .,:/()+·-]{1,80}\Z")
_CI_NAMES_MAX = 8


def _ci_name(name):
    return name if isinstance(name, str) and _CI_NAME_RE.match(name) else "(unnamed check)"


def _ci_note_rate(resp, seen):
    """Keep GitHub's X-RateLimit-* answer (and the HTTP status) from a response already received.
    Only those headers: nothing else of the request or the response is kept."""
    try:
        hdr = getattr(resp, "headers", None)
        get = hdr.get if hdr is not None else (lambda _k: None)

        def _int(name):
            v = get(name)
            return int(v) if v is not None and str(v).strip().isdigit() else None
        seen["rate"] = {"code": getattr(resp, "code", None) or getattr(resp, "status", None),
                        "remaining": _int("X-RateLimit-Remaining"),
                        "limit": _int("X-RateLimit-Limit"), "reset": _int("X-RateLimit-Reset")}
    except Exception:  # noqa: BLE001 - recording must never touch the gate  # nosec B110
        pass


def _ci_failed(run):
    return run.get("status") == "completed" and (run.get("conclusion") or "") in _CI_BAD


def _ci_running(run):
    return run.get("status") != "completed"


def _ci_held_by(runs):
    """(failing names, pending names, required names absent) of one commit's check runs."""
    return ([_ci_name(r.get("name")) for r in runs if _ci_failed(r)][:_CI_NAMES_MAX],
            [_ci_name(r.get("name")) for r in runs if _ci_running(r)][:_CI_NAMES_MAX],
            _ci_required_absent(runs))


def _ci_record(sha, state, seen):
    """Record one commit's CI answer in runtime_stats' "ci_walk" group (R31). CANNOT RAISE.

    Its own store, never _update_lock: this runs INSIDE `with _update_lock` (panel_update_status
    holds it across the whole walk), and that lock is not re-entrant."""
    try:
        from panel.core import runtime_stats as _rs
        if not re.fullmatch(r"[0-9a-fA-F]{7,40}", sha or ""):
            return
        failing, pending, absent = _ci_held_by(seen.get("runs") or [])
        _rs.put("ci_walk", sha[:7].lower(), {"state": state, "failing": failing,
                                             "pending": pending, "absent": absent,
                                             "checks": len(seen.get("runs") or [])})
        if seen.get("rate"):
            _rs.put("ci_walk", "ratelimit", seen["rate"])
    except Exception:  # noqa: BLE001 - instrumentation must never touch the gate  # nosec B110
        pass


def _ci_note_walk(started, commits, offered):
    """Record which commits one walk looked at and which it offered (R31). CANNOT RAISE."""
    try:
        from panel.core import runtime_stats as _rs
        _rs.put("ci_walk", "walk", {
            "started": started, "commits": [c[:7].lower() for c in commits[:25]
                                            if re.fullmatch(r"[0-9a-fA-F]{7,40}", c or "")],
            "offered": (offered or "")[:7].lower() or None})
    except Exception:  # noqa: BLE001  # nosec B110
        pass


def _remote_ci_state_read(sha, seen):
    """_remote_ci_state's answer. `seen` receives the check runs read and the rate-limit answer."""
    _ci_unknown_why["reason"] = ""
    slug = _repo_slug()
    if not slug:
        _ci_unknown_why["reason"] = _CI_WHY_NO_SLUG
        return "unknown"
    runs = _ci_fetch_runs(slug, sha, seen)
    if isinstance(runs, str):
        return runs          # GitHub did not hand over the checks: 'pending' or 'unknown'
    runs = [r for r in runs if r.get("name") not in _CI_IGNORE]
    seen["runs"] = runs
    return _ci_judge(sha, runs)


def _ci_fetch_page(slug, sha, page, seen):
    url = ("https://api.github.com/repos/%s/commits/%s/check-runs?per_page=100&page=%d"
           % (slug, sha, page))
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "linuxgsm-panel-update-check",
    })
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- a fixed https://api.github.com URL
    with urllib.request.urlopen(req, timeout=8) as resp:  # nosec B310 - fixed https host
        _ci_note_rate(resp, seen)
        return json.loads(resp.read().decode("utf-8")).get("check_runs", [])


def _ci_fetch_runs(slug, sha, seen):
    """Every check run on `sha`, or the state to answer when GitHub did not give them."""
    # PAGED. One page of 100 was "enough for now", and the failure mode if it ever stopped being
    # enough is the wrong one: a check that did not fit on page 1 is simply not seen, so a commit
    # whose only failure sits on page 2 reads as 'passing' and the panel offers the update. This
    # gate exists to stop exactly that. 5 pages (500 checks) is far past any plausible matrix, and
    # the cap is what keeps a malformed response from looping.
    runs = []
    try:
        for page in range(1, 6):
            batch = _ci_fetch_page(slug, sha, page, seen)
            runs.extend(batch)
            if len(batch) < 100:
                break        # short page = last page
    except urllib.error.HTTPError as e:
        # GitHub ANSWERED, and the answer was not the checks. 403 and 429 are its anonymous rate
        # limit (60 requests an hour per IP), which this gate's own polling reaches during a red
        # streak on main: every recompute re-queries the tip and each commit under it. A limit
        # that lasts the rest of the hour is not an outage; it means "not verified yet".
        # 404 (and 401) is a private repository asked anonymously: 'unknown', with that reason.
        _log.debug("CI-gate: GitHub answered HTTP %s for %s", e.code, sha, exc_info=True)
        _ci_note_rate(e, seen)
        if e.code in (403, 429):
            return "pending"
        _ci_unknown_why["reason"] = (_CI_WHY_NOT_FOUND if e.code in (401, 404)
                                     else _CI_WHY_UNREACHABLE)
        return "unknown"
    except (urllib.error.URLError, ValueError, OSError, http.client.HTTPException):
        # HTTPException: a truncated body (IncompleteRead) is not an OSError, and escaped this
        # function entirely.
        _log.debug("CI-gate: couldn't read check-runs for %s", sha, exc_info=True)
        _ci_unknown_why["reason"] = _CI_WHY_UNREACHABLE
        return "unknown"     # a partial read must not be judged
    return runs


def _ci_required_absent(runs):
    """The _CI_REQUIRED entries no run that judged anything matches. A SKIPPED run does not count
    as present: main's tip carries skipped workflow_run runs filed there for other events (a fork
    PR's), and "skipped" judged nothing."""
    judged = [r.get("name") or "" for r in runs if r.get("conclusion") != "skipped"]
    return [req for req in _CI_REQUIRED if not any(_ci_name_matches(req, n) for n in judged)]


def _ci_judge(sha, runs):
    """'passing' | 'pending' | 'failing' for the check runs GitHub returned for `sha`."""
    if not runs:
        return "pending"  # push landed but no checks have registered yet
    if any(r.get("status") != "completed" for r in runs):
        return "pending"  # at least one check still queued/running
    if any((r.get("conclusion") or "") in _CI_BAD for r in runs):
        return "failing"  # every check finished, but one didn't pass
    # Every check that EXISTS passed; now the ones that must exist.
    if _ci_suite_expected(sha, runs) and _ci_required_absent(runs):
        return "pending"  # a check it must carry has not appeared yet
    return "passing"


# Which repository files a host RUNS, and which it does not, is DATA: .github/update-paths.txt,
# read from the commit being offered (_update_rules). Only a change to a file it names `runtime`
# raises "Update available" (the owner's rule). The lists were here once, and naming a new tool's
# config file in them (.sonarcloud.properties, #382) was then a change to a file the panel runs:
# every panel was offered that one line as an update. A file in .github/, the rules name
# themselves noise, and a commit's own rules decide what that commit changes.
_UPDATE_PATHS_FILE = ".github/update-paths.txt"
_RULE_KINDS = ("runtime", "noise")      # runtime FIRST: on a tie it is the one kept
_LOCAL_RULES = {}


def _parse_update_paths(text):
    """{'runtime': [...], 'noise': [...]} from update-paths.txt's text; None for text that is not.

    One malformed line rejects the whole file: a list read in part could leave a file the host
    runs named as noise by a broader entry."""
    rules = {k: [] for k in _RULE_KINDS}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2 or parts[0] not in rules:
            return None
        rules[parts[0]].append(parts[1])
    return rules if rules["runtime"] and rules["noise"] else None


def _local_update_rules():
    """This checkout's own rules; {} (every path unnamed, so every path counts) if unreadable."""
    if "rules" not in _LOCAL_RULES:
        try:
            with open(os.path.join(PANEL_DIR, _UPDATE_PATHS_FILE), encoding="utf-8") as fh:
                _LOCAL_RULES["rules"] = _parse_update_paths(fh.read()) or {}
        except OSError:
            _LOCAL_RULES["rules"] = {}
    return _LOCAL_RULES["rules"]


def _update_rules(ref):
    """The rules as commit `ref` states them -- the commit an update would install -- or this
    checkout's own when `ref`'s cannot be read. `ref` is validated by the callers, as for the diff."""
    out, _, rc = _git(["show", "%s:%s" % (ref, _UPDATE_PATHS_FILE)])
    return (_parse_update_paths(out) if rc == 0 else None) or _local_update_rules()


def _rule_weight(entry, p):
    """How specifically `entry` names path `p` (a file > a glob > a directory, then the longer);
    None when it does not name it."""
    if entry.endswith("/"):
        return (0, len(entry)) if p.startswith(entry) else None
    if any(c in entry for c in "*?["):
        return (1, len(entry)) if fnmatch.fnmatchcase(p.lower(), entry.lower()) else None
    return (2, 0) if p == entry else None


def _best_rule(rules, p):
    """The kind of the most specific entry naming `p`, runtime on a tie; None if none names it."""
    best = None
    for kind in _RULE_KINDS:
        for entry in rules.get(kind, ()):
            w = _rule_weight(entry, p)
            if w is not None and (best is None or w > best[0]):
                best = (w, kind)
    return best[1] if best else None


def _path_class(path, rules=None):
    """'runtime' or 'noise' for a repo path the rules name; None for one they do not.

    `rules` defaults to this checkout's own (_local_update_rules)."""
    p = path.strip()
    if p.startswith("./"):      # a literal "./" prefix only -- NOT lstrip("./"), which would also
        p = p[2:]               # eat the leading dot of dotfiles/dotdirs (.github, .gitignore).
    if not p:
        return "noise"
    return _best_rule(_local_update_rules() if rules is None else rules, p)


def _is_runtime_path(path, rules=None):
    """True if this repo path affects the RUNNING panel (code, templates, static, requirements,
    install.sh, …). Docs/CI/test-scaffolding paths return False, and so does an empty one.

    A path named on neither side counts as runtime: a host must never miss a change to a file it
    runs because nobody classified it. The unit gate keeps every tracked file named."""
    return _path_class(path, rules) != "noise"


def _update_touches_runtime(target_ref):
    """Whether updating from HEAD to `target_ref` would change any file the panel actually uses.
    A pure-docs/CI/test diff returns False so the badge stops nagging about changes that don't
    affect the panel. Fails safe: if we can't compute the diff, assume it matters.

    --no-renames: git names only a rename's DESTINATION, so a file the host runs moved into tools/
    or docs/ read as docs-only, though installing it removes that file. Both sides are listed now.
    An empty listing git returned cleanly is two identical trees (a change and its revert): nothing
    to install. A failed git call is non-zero (_git returns -1 on a timeout too), so that stays the
    fail-safe case."""
    out, _, rc = _git(["diff", "--no-renames", "--name-only", "HEAD.." + target_ref])
    if rc != 0:
        return True
    files = [f for f in (out or "").splitlines() if f.strip()]
    if not files:
        return False
    rules = _update_rules(target_ref)
    return any(_is_runtime_path(f, rules) for f in files)


def _no_runtime_update(base, target_sha, ci_state, behind, behind_tip):
    """The status for a checkout that is behind only by docs, CI, test or tooling commits.

    NOT an update: the badge, the card, the bots and the update notification all read
    update_available, and nothing the panel runs would change. #276 (2026-09-19) made every commit
    count ("am I running the latest?"), and from then on a CI-only merge raised "Update available"
    on every panel, with an install that changed nothing. The owner's rule is the one restored: an
    update is offered only when a file the panel runs changes. The first commit that does is
    offered, with these behind it in the same pull. behind/target stay in the API for anything
    that wants them; the card shows its up-to-date line, which prints the running commit.
    """
    return {**base, "update_available": False, "docs_only": True, "ci_state": ci_state,
            "behind": behind, "behind_tip": behind_tip, "target_sha": target_sha,
            "remote_version": version_for_commit(target_sha) or "?", "changes": []}


def _runtime_changelog(rev_range, runtime_only=True):
    """Commits in `rev_range`, newest first, as 'shorthash subject' lines.

    With runtime_only (the default) a commit is kept only if it touches a file the panel RUNS, so
    a README edit does not make the card nag. Callers that are about to SHOW the list pass False
    when the filtered list comes back empty: the card used to report "1 commit behind" from the
    unfiltered count while listing the filtered one, so an update consisting of a tests-only
    commit announced itself and then had nothing to show. Reported from a live panel sitting one
    commit behind a change to tests/ and tools/."""
    out, _, rc = _git(["log", "--no-decorate", "--no-renames", "--format=%h%x09%s", "--name-only",
                       rev_range])
    if rc != 0 or not out:
        return []
    header = re.compile(r"^([0-9a-f]{7,40})\t(.*)\Z")
    if not runtime_only:
        return [("%s %s" % (m.group(1), m.group(2)))
                for m in (header.match(ln) for ln in out.splitlines()) if m]
    rules = _update_rules(rev_range.split("..", 1)[-1])     # the commits' own: _update_rules
    result, cur, runtime = [], None, False
    for line in out.splitlines():
        m = header.match(line)
        if m:
            if cur and runtime:
                result.append(cur)
            cur, runtime = "%s %s" % (m.group(1), m.group(2)), False
        elif line.strip() and _is_runtime_path(line, rules):
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
    # Both names IN FULL. git resolves a bare `origin/main` as refs/tags/origin/main before
    # refs/remotes/origin/main (gitrevisions), so a tag pushed under that name answered every
    # question below — how far behind, which commit to offer, its version and changelog — about a
    # commit that was never on the branch, and the verified target handed to install.sh came from
    # it. A fetch SOURCE is looked up the same way on the remote: `fetch origin main` takes a TAG
    # named `main` over the branch and then never moves the remote-tracking ref, so the card sat on
    # a stale tip. install.sh names both in full too.
    #
    # And the DESTINATION is spelled out. Without one, git moves refs/remotes/origin/<branch> only
    # when the remote's configured refspec covers it, and a single-branch clone of main that tracks
    # another branch has no such refspec: the fetch landed in FETCH_HEAD alone, the tracking ref
    # never appeared, and the card read that as "up to date". --no-tags because a fetch with a
    # destination would otherwise follow tags into the history it brings, and nothing here reads one.
    ref = _REMOTE_TRACKING + branch
    _, ferr, frc = _git(["fetch", "--quiet", "--no-tags", "origin",
                         "+refs/heads/%s:%s" % (branch, ref)], timeout=45)
    if frc != 0:
        # Couldn't reach the remote (private repo without creds, or offline). Do NOT
        # report an update from a stale remote-tracking ref — that would show a phantom
        # "update available" that can never be applied.
        return {"git": True, "fetched": False, "update_available": False,
                "current_version": cur_ver, "current_sha": cur_sha.strip(), "branch": branch,
                "message": "Couldn't reach the update source — it may be private or offline."}
    # The ref must exist BY THAT NAME before anything below reads it. A full name is still only a
    # name to git's lookup: with refs/remotes/origin/<branch> missing, git goes on to try
    # refs/tags/refs/remotes/origin/<branch>, so a tag of that name would answer for the branch —
    # and with neither, every read below fails and "0 behind" reads as up to date. Neither is.
    _, _, xrc = _git(["show-ref", "--verify", "--quiet", ref])
    if xrc != 0:
        return {"git": True, "fetched": False, "update_available": False,
                "current_version": cur_ver, "current_sha": cur_sha.strip(), "branch": branch,
                "message": "The update source has no branch '%s' to compare against." % branch}
    # FIRST-PARENT, here and in the walk below: the chain of first parents from the tip — each
    # commit of a push or rebase merge, and each merge commit — not everything the tip reaches, and
    # never what a merge brought in through its second parent. A pull request merged with a merge
    # commit brings all of its commits into the branch's ancestry, including an intermediate one
    # whose change was reverted before the merge. That commit was never the branch's tip, the CI
    # state the walk asks about is its pull-request run (or none: "unknown", accepted then), and a walk
    # over plain ancestry offered it as the verified target while the merge was still being
    # checked. install.sh honours a pin only on the first-parent line too, so the two agree on what
    # can be installed.
    behind, _, _ = _git(["rev-list", "--first-parent", "--count", "HEAD.." + ref])
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
        rem_full, _, _ = _git(["rev-parse", ref])
        # Nothing the panel runs changed: not an update, on a test branch either (see
        # _no_runtime_update). Judged on the diff, which fails safe: unreadable reads as a change.
        if not _update_touches_runtime(ref):
            return _no_runtime_update(base, rem_full.strip() or ref, "unverified",
                                      behind_n, behind_n)
        tgt_ver = version_for_commit(ref)
        runtime_log = _runtime_changelog("HEAD.." + ref)
        # Same fallback as the verified branch below: what is counted is what is listed.
        rc_log = runtime_log or _runtime_changelog("HEAD.." + ref, runtime_only=False)
        return {**base, "update_available": True, "ci_state": "unverified",
                "docs_only": False,
                "runtime_sha": runtime_log[0].split(" ", 1)[0] if runtime_log else "",
                "behind": len(rc_log) or behind_n, "behind_tip": behind_n,
                "remote_version": tgt_ver or "?",
                "target_sha": rem_full.strip(),
                "changes": rc_log[:10]}

    # Don't surface an update until the target commit has cleared CI on GitHub — otherwise
    # the badge pops the instant a push lands, before the workflows finish (or even if they
    # go on to fail). But if the TIP is still verifying while an EARLIER commit has already
    # passed, offer that earlier verified commit instead of blocking entirely. So: walk the
    # commits we're behind by, newest first, and update to the first one that's passed CI.
    # Capped so a long-offline panel can't fire dozens of API calls.
    #
    # 'unknown' (the checks could not be READ) is NOT acceptable, and it ends the walk. It used to
    # count as passing "so a transient API error never hides a legitimate update" — and since the
    # walk starts at the tip, every panel that could not read GitHub was offered the tip, the one
    # commit nobody had verified: a panel offline from api.github.com, one on a private fork, and
    # one whose origin _repo_slug did not recognise, which was that way permanently and silently.
    # The walk stops rather than going on down: whatever stopped one read stops the next (another
    # 8-second timeout each, up to 25 of them), and the card says why instead (below).
    revs, _, _ = _git(["rev-list", "--first-parent", "-n", "25", "HEAD.." + ref])
    commits = [c for c in (revs or "").split() if c]
    _ci_unknown_why["reason"] = ""
    walk_started = time.time()
    tip_state = _remote_ci_state(commits[0]) if commits else "unknown"
    unknown_why = _ci_unknown_why["reason"] if tip_state == "unknown" else ""
    # Only a commit that CONTAINS this checkout is an update to it, while the checkout is on the
    # branch — install.sh moves such a checkout only forward, and holds rather than move it
    # sideways (see _choose_update_target). After a foxtrot push (main fast-forwarded onto a branch
    # that had main merged in) the first-parent walk from HEAD lists the other branch's commits
    # too, and one of them could be offered while the merge itself was still in CI: the card said
    # "Update available", and the installer held. update_available is true exactly when the update
    # would install, so those are passed over. A checkout NOT on the branch (a local commit) is
    # reset to whatever it is given, as install.sh does, so nothing is filtered for it.
    _, _, on_branch_rc = _git(["merge-base", "--is-ancestor", "HEAD", ref])

    def _contains_head(sha):
        if on_branch_rc != 0:
            return True
        _, _, arc = _git(["merge-base", "--is-ancestor", "HEAD", sha])
        return arc == 0

    # Asked BEFORE the check-runs call, which is one anonymous GitHub request (60 an hour per IP)
    # per commit: after a foxtrot push the walk is the other branch's whole line, and asking
    # about each of them on every recheck while the merge was in CI spent the hour's limit, which
    # then read as "pending" for the merge itself once it had passed.
    target_sha, target_state, newer_unverified = None, tip_state, 0
    unreadable = False
    for idx, sha in enumerate(commits):
        if not _contains_head(sha):
            continue
        if idx == 0:
            st = tip_state
        else:
            _ci_unknown_why["reason"] = ""
            st = _remote_ci_state(sha)
            if st == "unknown":
                unknown_why = _ci_unknown_why["reason"]
        if st == "passing":
            target_sha, target_state, newer_unverified = sha, st, idx
            break   # newest verified commit — anything above it is still unverified
        if st == "unknown":
            unreadable = True
            break   # the checks cannot be read: nothing below can be verified either
    _ci_note_walk(walk_started, commits, target_sha)

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
        #
        # EXCEPT when the checks could not be read at all. That is not a state that passes in a
        # few minutes: an origin the panel does not recognise, or a private repository, stays
        # that way, and a silent card would sit on "You're up to date" while the install fell
        # further behind for good. So this one says so, and why. ci_state is 'unknown' for it.
        full_tip = commits[0] if commits else ""
        tip_ver = version_for_commit(ref)
        out = {**base, "update_available": False,
               "ci_state": "unknown" if unreadable else tip_state,
               "behind": behind_n, "behind_tip": behind_n,
               "target_sha": full_tip,
               "remote_version": tip_ver or "?",
               "changes": _runtime_changelog("HEAD.." + ref)[:10]}
        if unreadable:
            out["unverified_reason"] = unknown_why or _CI_WHY_UNREACHABLE
            out["message"] = ("A newer version exists, but it couldn't be verified: %s. It will "
                              "be offered once its automated checks can be confirmed."
                              % out["unverified_reason"])
        return out

    # We have a verified target (possibly older than the tip if newer commits are still verifying).
    behind_target = behind_n - newer_unverified   # commits from HEAD up to & including the target
    # Don't nag if everything between here and the verified target is docs/CI/tests only — those
    # changes don't affect the running panel. (A later commit with real code will move the target
    # up and re-trigger the badge once it passes CI.) See _no_runtime_update.
    if not _update_touches_runtime(target_sha):
        return _no_runtime_update(base, target_sha, target_state, behind_target, behind_n)
    tgt_ver = version_for_commit(target_sha)
    rc_log = _runtime_changelog(f"HEAD..{target_sha}")   # runtime commits only (drops docs/CI)
    # What is COUNTED and what is LISTED must be the same set. `len(rc_log) or behind_target` used
    # the filtered count when it had one and the raw count when it did not — so an update made
    # only of test or tooling commits said "1 commit behind" and then showed an empty list,
    # because `changes` stayed filtered. When nothing runtime changed, show the commits that DID
    # change (a runtime diff whose commits each looked like noise, e.g. a change and its revert).
    shown_log = rc_log or _runtime_changelog(f"HEAD..{target_sha}", runtime_only=False)
    return {
        **base,
        "update_available": True,
        "docs_only": False,
        "ci_state": target_state,
        "behind": len(shown_log) or behind_target,   # always the number of commits listed below
        "behind_tip": behind_n,
        "newer_unverified": newer_unverified,
        # The newest commit in this update that changes a file the panel runs. The update
        # notification is de-duplicated on it, not on target_sha: a docs or CI commit landing on
        # top of an update not yet installed moves the target, and re-announced the same change.
        "runtime_sha": rc_log[0].split(" ", 1)[0] if rc_log else "",
        "remote_version": tgt_ver or "?",
        "remote_sha": target_sha[:7],
        "target_sha": target_sha,
        "changes": shown_log[:10],
    }


# ONE status computation at a time. Each is a `git fetch` of refs/heads/<branch> into
# refs/remotes/origin/<branch> plus up to 25 anonymous GitHub requests, and nothing serialised
# them: the update card's restart watcher asked for the status every 1.5 seconds, the badge, the
# bots and the card itself on top, and each miss started its own. Two fetches of the same ref
# collide on its lock ("cannot lock ref"), and the second one fails — the card cached THAT for
# five minutes as "Couldn't reach the update source". A caller that arrives while one is running
# waits for it and takes its answer (see panel_update_status).
_update_lock = threading.Lock()
# When this process last launched the installer. Until the new run's log exists (the launcher
# replaces it a moment after _launch_installer returns), this is the only witness that a run is
# under way. See _update_in_progress.
_update_launched = {"ts": 0.0, "log": ""}
_UPDATE_LAUNCH_GRACE = 120
# A log that has not been written for this long, with no exit line, is a run that died (a reboot
# mid-update, the unit killed) — not one in progress. install.sh writes a line at every step, and
# none of its steps is silent this long, so a live run always looks live.
_UPDATE_STALE_LOG = 20 * 60


def _update_in_progress():
    """Whether a self-update (or branch switch) is running right now.

    Read from the run's own log, which outlives the panel's restart: it exists, was written
    recently, and has no "=== installer exit N ===" line yet. Before that log exists, the launch
    this process made in the last _UPDATE_LAUNCH_GRACE seconds counts. Cheap: a stat and a read of
    the log's tail, no git and no network."""
    now = time.time()
    path = _update_log_path()
    # The launch counts only for the log it was made for (a launch under another PANEL_DIR, as the
    # tests make, says nothing about this one).
    launched = (_update_launched["ts"] if _update_launched.get("log") == path else 0.0)
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        return (now - launched) < _UPDATE_LAUNCH_GRACE
    if mtime < launched - 1:
        return (now - launched) < _UPDATE_LAUNCH_GRACE   # the previous run's log
    if (now - mtime) > _UPDATE_STALE_LOG:
        return False
    try:
        return not panel_update_log().get("finished")
    except Exception:
        return False


def _update_running_status():
    """The status to answer with while an update is running — computed WITHOUT git fetch or GitHub.

    install.sh fetches `+refs/heads/<branch>:refs/remotes/origin/<branch>` too, into the same ref,
    and the restart watcher on the update card used to ask for a full status every 1.5 seconds for
    the whole of the run. Each of those was a fetch of that ref (when the five-minute cache was
    cold, and _launch_installer had just emptied it) and GitHub requests: a fetch that took the
    ref's lock first made install.sh's fetch fail and the UPDATE abort; the anonymous API limit
    (60 an hour) was spent in about a minute and a half, and every check after that read
    'pending' for the rest of the hour. And the failure was then cached for five minutes.

    So nothing is fetched or asked while a run is going, and nothing here is cached: once it ends
    the next call computes afresh. update_available is False (an install is not allowed while one
    is running — the invariant _compute_update_status keeps). current_sha and branch are what the
    card's watcher compares after the restart; read with rev-parse only, never `git status`, which
    may take the index lock the installer's reset needs."""
    sha, _, _ = _git(["rev-parse", "--short", "HEAD"], timeout=10)
    return {"git": True, "update_available": False, "update_running": True,
            "current_version": panel_version(), "current_sha": sha.strip(),
            "branch": _tracked_branch(),
            "message": "An update is being installed right now — check again once it has finished."}


def panel_update_status(force=False):
    """Whether the panel is behind its GitHub remote. Cached ~5 min (each check does
    a network `git fetch`) unless `force` is set.

    Single-flight (_update_lock): a caller that arrives while another computation is running waits
    for it and returns ITS answer — with force too, since a status computed while this caller
    waited is as fresh as the one it would compute. And while an update is running nothing is
    computed at all (see _update_running_status)."""
    if _update_in_progress():
        return _update_running_status()
    if not force and _update_cache["data"] is not None and \
            (time.time() - _update_cache["ts"]) < _UPDATE_TTL:
        return _update_cache["data"]
    seen = _update_cache.get("seq", 0)
    with _update_lock:
        if _update_cache.get("seq", 0) != seen and _update_cache["data"] is not None:
            return _update_cache["data"]      # finished while this caller waited for the lock
        if _update_in_progress():             # an update was launched while it waited
            return _update_running_status()
        now = time.time()
        data = _compute_update_status()
        _update_cache["ts"] = now
        _update_cache["data"] = data
        _update_cache["seq"] = seen + 1
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
    # to it could bring up an unstable panel. 'unknown' (the checks could not be read) is refused
    # too: it used to be allowed "so an API outage can't lock the admin out", which installed the
    # unverified tip on every panel that could not read GitHub. It has no target, so the
    # update_available test below refuses it, with the status's own reason.
    try:
        st = panel_update_status(force=True)
    except Exception:
        # REFUSE. This used to carry on with st = {}, which skipped the gate below AND left no
        # target, so install.sh reset onto the origin tip — the one commit nobody had verified.
        # Status could not be computed, so nothing here knows what would be installed.
        _log.warning("self-update CI-gate: status check failed; refusing", exc_info=True)
        return False, ("Couldn't check the update just now, so it wasn't started. "
                       "Try again in a minute.")
    if st.get("behind", 0) > 0 and st.get("ci_state") in ("pending", "failing"):
        if st.get("ci_state") == "failing":
            return False, ("This update is blocked: the latest commit didn't pass its "
                           "automated checks. It'll be offered once a fixed version passes CI.")
        return False, ("This update is still being verified — its checks are running. "
                       "Try again once they've passed (usually a couple of minutes).")
    if st.get("behind", 0) > 0 and st.get("ci_state") == "unknown":
        return False, (st.get("message") or "This update couldn't be verified, so it wasn't "
                       "started: its automated checks could not be read from GitHub.")
    installer = os.path.join(PANEL_DIR, "install.sh")
    if not os.path.isfile(installer):
        return False, "install.sh is missing, so the panel can't self-update safely."
    # The commit we're cleared to move to — the newest CI-verified one, which may be BELOW the
    # tip when newer commits are still verifying. install.sh resets to it (validated there as an
    # ancestor of the fetched tip). Only ever a bare hex SHA from git rev-list; guard the shape
    # anyway before it's exported into a root-run script.
    #
    # No target means no update: nothing is behind, the remote could not be fetched, or no commit
    # cleared the gate. Each of those used to fall back to install.sh's default, the origin/<branch>
    # tip — which install.sh fetches AFTER this check, so it could be a commit that landed a moment
    # ago and was never verified at all. update_available is true exactly when an install is allowed.
    if not st.get("update_available"):
        return False, (st.get("message") or "The panel is already up to date.")
    target_ref = (st.get("target_sha") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", target_ref):
        return False, "Couldn't tell which commit to update to, so the update wasn't started."
    # Follow whatever branch the panel is tracking (default 'main'); the launcher passes it to
    # install.sh so a panel that has switched branches keeps updating on THAT branch.
    return _launch_installer(target_ref=target_ref, branch=_tracked_branch())


def _mark_update_launched():
    """Record a launch that succeeded, so the status check stands down for the run.

    This used to be only `_update_cache["ts"] = 0.0`, "so the badge re-checks after the restart"
    — which made the very next status request a full recompute, a `git fetch` of the same ref
    install.sh was about to fetch, while the update card polled every 1.5 seconds. Now
    panel_update_status answers from _update_running_status until the run's log says it ended; the
    cache is still emptied, so the first status after that is computed afresh."""
    _update_launched.update(ts=time.time(), log=_update_log_path())
    _update_cache["ts"] = 0.0


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
    _log_path = _update_log_path()
    # The update card finishes on the first "=== installer exit N ===" it reads while the panel has
    # not restarted (see _update_log_outcome). The PREVIOUS run's log ends in one, and it is still
    # there between this call returning and the launcher replacing it — the helper's detached run
    # and systemd-run's unit both start a moment later — so a card polling in that gap read the
    # last run's ending as this one's. Remove it first: until the new log exists, the card reads
    # "not started yet". Unlinking a name in the panel's own data dir never touches another file.
    try:
        os.unlink(_log_path)
    except FileNotFoundError:
        pass   # first update on this install, or already cleared
    except OSError:
        _log.warning("self-update: couldn't remove the previous run's log", exc_info=True)
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
            _mark_update_launched()
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
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700 is owner-only
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
        _mark_update_launched()
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
    #
    # --no-tags, where this used to say --tags. The panel reads no tag anywhere, and --tags fetched
    # EVERY tag the repository has, even one pointing at a commit on no branch at all — which is
    # what a tag named `origin/main` would be made of, and git resolves a bare `origin/main` to that
    # tag ahead of the remote-tracking branch. Every read here is spelled out in full now, so such a
    # tag decides nothing, but there is no reason to go and fetch it.
    _, _, rc = _git(["fetch", "--prune", "--no-tags", "--unshallow", "origin"], timeout=120)
    if rc != 0:
        _git(["fetch", "--prune", "--no-tags", "origin"], timeout=90)


def list_panel_branches():
    """Remote branches available to switch to, most-recently-updated first, plus the currently
    tracked branch. Returns (branches, current). Best-effort: ([current], current) on failure."""
    branch = _tracked_branch()
    if not _is_git_checkout():
        return [branch], branch
    _fetch_all_branches()   # widen a single-branch/shallow clone so ALL branches show up + refresh
    # The FULL refname, stripped here. `%(refname:short)` is the shortest UNAMBIGUOUS name, so the
    # moment a tag `origin/main` existed, main came back as `remotes/origin/main`, failed the prefix
    # test and vanished from the switcher.
    out, _, rc = _git(["for-each-ref", "--format=%(refname)", "--sort=-committerdate",
                       "refs/remotes/origin"], timeout=20)
    branches = []
    if rc == 0:
        for line in (out or "").splitlines():
            name = line.strip()
            if not name.startswith(_REMOTE_TRACKING):
                continue
            name = name[len(_REMOTE_TRACKING):]
            if name and name != "HEAD" and _valid_branch(name) and name not in branches:
                branches.append(name)
    if branch not in branches:
        branches.insert(0, branch)
    return branches, branch


def _verified_branch_target(branch):
    """The newest commit of `branch` that passed the CI gate, for a SWITCH to it: (sha, "") or
    ("", why not). Call under _update_lock (it fetches the ref a status check fetches).

    Not _compute_update_status: that walks HEAD..tip and skips commits that do not contain HEAD,
    because an update moves a checkout forward. A switch comes from another branch, so HEAD says
    nothing about which of the branch's commits may be installed; the walk is the branch's own
    first-parent line from its tip, judged by the same _remote_ci_state (required checks and all),
    newest first, and 'unknown' ends it exactly as it ends an update's."""
    ref = _REMOTE_TRACKING + branch
    _, _, frc = _git(["fetch", "--quiet", "--no-tags", "origin",
                      "+refs/heads/%s:%s" % (branch, ref)], timeout=45)
    _, _, xrc = _git(["show-ref", "--verify", "--quiet", ref])
    if frc != 0 or xrc != 0:
        return "", ("Couldn't fetch '%s' from the update source, so there is no verified version "
                    "to switch to." % branch)
    revs, _, _ = _git(["rev-list", "--first-parent", "-n", "25", ref])
    states = []
    for sha in [c for c in (revs or "").split() if c]:
        _ci_unknown_why["reason"] = ""
        st = _remote_ci_state(sha)
        if st == "passing":
            return sha, ""
        if st == "unknown":
            return "", ("Not switched: '%s' couldn't be verified — %s." %
                        (branch, _ci_unknown_why["reason"] or _CI_WHY_UNREACHABLE))
        states.append(st)
    if "pending" in states:
        return "", ("Not switched: no version of '%s' has finished its automated checks yet. Try "
                    "again once they've passed (usually a few minutes)." % branch)
    return "", ("Not switched: none of the recent versions of '%s' passed its automated checks."
                % branch)


def panel_switch_branch(branch):
    """Point the panel at a different branch and check it out, with the SAME snapshot / health-check
    / auto-rollback safety as a normal update. Superadmin-gated at the route. Returns (ok, message)."""
    branch = (branch or "").strip()
    if not _valid_branch(branch):
        return False, "Invalid branch name."
    if not _is_git_checkout():
        return False, "The panel isn't a git checkout, so it can't switch branches."
    # Confirm the branch exists on the remote before committing the config to it. By EXACT name:
    # ls-remote matches a pattern against the TAIL of each ref, so `dev` was confirmed by a branch
    # `feature/dev` alone, and the panel then tracked a branch that does not exist.
    out, _, rc = _git(["ls-remote", "--heads", "origin", "refs/heads/" + branch], timeout=20)
    if rc != 0 or ("refs/heads/" + branch) not in [
            ln.split("\t", 1)[-1].strip() for ln in (out or "").splitlines()]:
        return False, "Branch '%s' doesn't exist on the remote." % branch
    # WHICH commit of that branch. The switch always launched with an empty target, and install.sh
    # resets an empty target to the branch's tip — so switching (back) to main installed main's
    # newest commit whether or not its checks had finished, or passed: the one path around the CI
    # gate panel_self_update enforces. A branch the gate covers now gets the gate's answer (the
    # newest verified commit, or a refusal saying why); any other branch is the explicit testing
    # escape hatch it always was, and the messages say it installs an unverified tip.
    target = ""
    if branch == _DEFAULT_BRANCH:
        if _update_in_progress():
            return False, "An update is being installed right now — switch once it has finished."
        with _update_lock:
            target, why = _verified_branch_target(branch)
        if not target:
            return False, why
        msg = ("Switching to '%s' at %s, its newest version that passed its automated checks — the "
               "panel is backing up, checking it out and verifying it restarts cleanly (auto-rollback "
               "if it doesn't). This takes up to a minute." % (branch, target[:7]))
    else:
        msg = ("Switching to '%s' — this installs that branch's newest commit AS IT IS: branches "
               "other than %s are not checked by the panel's update gate, so it is unverified code, "
               "for testing. The panel is backing up and verifying it restarts cleanly "
               "(auto-rollback if it doesn't). This takes up to a minute." % (branch, _DEFAULT_BRANCH))
    try:
        from panel.core import config as _cfg
        _previous = (_cfg.load_config().get("panel_branch") or "").strip()
        _cfg.update_config(lambda cfg: cfg.update({"panel_branch": branch}))
    except Exception:
        _log.exception("switch-branch: could not save tracked branch")
        return False, "Could not save the branch selection."
    # target_ref empty (a non-gated branch only) → install.sh resets to the tip of PANEL_BRANCH. A
    # pin is honoured only on that branch's first-parent line, which is where the walk found it.
    ok, launch_msg = _launch_installer(target_ref=target, branch=branch, started_msg=msg)
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
            # _valid_branch, whose pattern admits no newline — and an explicit
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
    to it; False when it is not, or when that cannot be established.

    Both callers are lockout guards, and neither has a backstop: /api/panel/change-port saves the
    bind and restarts onto it (an address the host lacks fails to bind and the panel does not come
    back), and change_ssh_port on the panel's own host, where socket activation binds a missing
    address anyway. So "could not tell" must not read as yes. It did for a while: an unreadable
    list answered True, and a typo'd bind made while `ip` timed out was accepted by both.

    Nor may it read as a bare no, which is what it did before THAT: _run never raises — a timeout,
    a missing iproute2 or an exec error comes back as ("", ..., -1) — and `ip in set()` called the
    host's own Tailscale IP "not an address on this host". A host always has loopback, so nothing
    read means the list was not read, and the kernel is asked instead (_kernel_has_ip). The
    comparison is on parsed addresses: an IPv6 address typed in upper case ("FD7A:115C:A1E0::1")
    never equalled `ip`'s lowercase output. A zone id is refused outright, rather than left to
    IPv6Address's equality (which counts the zone) to answer no."""
    import ipaddress
    want = ip_address_or_none(ip)
    if want is None:
        return False        # not an IP at all: it cannot be one of this host's addresses
    try:
        out, _, _ = _run("ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1", timeout=8)
    except Exception:
        out = ""
    have = set()
    for tok in (out or "").split():
        try:
            have.add(ipaddress.ip_address(tok))
        except ValueError:
            continue
    if have:
        return want in have
    return _kernel_has_ip(want)


def _nonlocal_bind_allowed(version):
    """Whether this host lets a process bind an address it does not have (net.ipv4/ipv6
    ip_nonlocal_bind). An absent sysctl is the kernel default: off."""
    try:
        with open("/proc/sys/net/ipv%d/ip_nonlocal_bind" % version) as f:
            return f.read().strip() not in ("", "0")
    except OSError:
        return False


def _kernel_has_ip(addr):
    """host_has_ip's answer when the address list could not be read: whether the kernel lets this
    process bind `addr` (an ipaddress object) on port 0. EADDRNOTAVAIL is the kernel's "not an
    address on this host", with no command output to parse.

    Only a successful bind is a yes — any other error is "could not tell", and both callers are
    lockout guards. And a host with ip_nonlocal_bind set binds ANY address, so there a bind proves
    nothing and the answer is no."""
    import socket
    # A wildcard is not an address this host HAS: binding it always succeeds.
    if addr.is_unspecified or _nonlocal_bind_allowed(addr.version):
        return False
    fam = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
    try:
        with socket.socket(fam, socket.SOCK_STREAM) as sock:
            sock.bind((str(addr), 0))
        return True
    except OSError:
        return False


def _update_log_path():
    return os.path.join(PANEL_DIR, "data", "self-update.log")


# The line both launchers append when install.sh returns: the helper's detached run
# (_run_installer_to in tools/panel-helper) and the wrapper script _launch_installer writes.
_INSTALLER_EXIT_RE = re.compile(r"^=== installer exit (\d+)\b")


def _update_log_outcome(lines):
    """How a self-update run ended, read from its log lines (ANSI already stripped).

    An update that stops BEFORE the panel restarts never flips the panel's boot id, which is all
    the update card used to watch: the source unreachable, a pinned commit that cannot be verified,
    a hold. The [ERROR] line was in the log, and after three minutes the card said "Still working —
    reload the page to check." So the card also reads THIS, and finishes on it when the process
    answering is still the one that started the update (see watchPanelRestart).

    Returns {"finished", "exit_code", "outcome", "reason"}. outcome is:
      running  no exit line yet;
      failed   a non-zero exit — reason is the last [ERROR] message, continuation lines joined;
      held     exit 0 on install.sh's "Not updated: ..." line (update_noop_line) — the reason;
      current  exit 0 on "Already up to date" — nothing to install;
      done     exit 0 otherwise: the run went through the restart, which the boot id reports.
    """
    exit_code = None
    for ln in reversed(lines):
        m = _INSTALLER_EXIT_RE.match(ln)
        if m:
            exit_code = int(m.group(1))
            break
    if exit_code is None:
        return {"finished": False, "exit_code": None, "outcome": "running", "reason": ""}
    res = {"finished": True, "exit_code": exit_code, "outcome": "done", "reason": ""}
    if exit_code != 0:
        res["outcome"] = "failed"
        # die() prints "[ERROR] <message>" and indents every further line of the message.
        for i in range(len(lines) - 1, -1, -1):
            if lines[i].startswith("[ERROR]"):
                parts = [lines[i][len("[ERROR]"):].strip()]
                for cont in lines[i + 1:]:
                    if not cont[:1].isspace():
                        break
                    parts.append(cont.strip())
                res["reason"] = " ".join(p for p in parts if p)
                break
        return res
    for ln in reversed(lines):
        if ln.startswith("[!] Not updated:"):
            res["outcome"], res["reason"] = "held", ln[len("[!] "):].strip()
            return res
        if ln.startswith("✓ Already up to date"):
            res["outcome"], res["reason"] = "current", ln[len("✓ "):].strip()
            return res
    return res


def panel_update_log(max_bytes=20000):
    """Tail of the self-update log (ANSI stripped) so the UI can show live progress while
    the panel updates and restarts. The detached updater keeps writing to this file across
    the restart, so the new process can read the final steps too. Also says how the run ended,
    once it has (see _update_log_outcome)."""
    path = _update_log_path()
    try:
        with open(path, "r", errors="replace") as f:
            data = f.read()[-max_bytes:]
    except OSError:
        return {"exists": False, "lines": [], "finished": False, "exit_code": None,
                "outcome": "running", "reason": ""}
    data = terminal.strip_escapes(data)   # strip ANSI/OSC/two-byte escapes, not just colour
    lines = [ln.rstrip() for ln in data.splitlines() if ln.strip()]
    return dict({"exists": True, "lines": lines}, **_update_log_outcome(lines))


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
    # NOT while an update runs. `git diff` is not read-only: on stat-dirty files whose content is
    # unchanged -- exactly the state install.sh's reset or a snapshot restore leaves -- it takes
    # .git/index.lock to refresh the index (with --no-optional-locks too, tested on git 2.56), and
    # install.sh's own `git reset --hard` then fails on that lock. A Diagnostics click or a debug
    # report during an update is the likeliest time for this read, so it stands down and says so,
    # as _update_running_status does. Unverified, never "clean".
    if _update_in_progress():
        return {"git": True, "clean": True, "verified": False, "modified": [], "count": 0,
                "current_sha": sha.strip(),
                "message": "An update is being installed right now; file integrity is checked "
                           "once it has finished."}
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


def _apt_periodic_on(dump):
    """Whether `apt-config dump` output turns APT::Periodic::Unattended-Upgrade ON.

    The value is an INTERVAL (days, or with apt.systemd.daily's s/m/h/d suffixes, or "always"),
    and anything but zero runs it. This tested for the exact text "1", so a host set to "7" in a
    later apt.conf.d file (the last file read wins) was reported "not enabled", raised a
    diagnostics warning, and made Enable answer "Could not confirm" while the host was applying
    security updates every week. Absent, "0", or unreadable is off."""
    m = None
    for line in (dump or "").splitlines():
        m = re.match(r'^\s*APT::Periodic::Unattended-Upgrade\s+"([^"]*)";', line) or m
    if not m:
        return False
    val = m.group(1).strip().lower()
    if val == "always":
        return True
    num = re.fullmatch(r"(\d+)[smhd]?", val)
    return bool(num) and int(num.group(1)) > 0


def unattended_upgrades_status():
    """Whether automatic security updates (the unattended-upgrades package) are
    installed AND actually enabled. Read-only, no sudo. Returns
    {installed, enabled, detail}. Non-Debian systems report not-installed."""
    _, _, prc = _run(
        "dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null "
        "| grep -q 'install ok installed'", timeout=10)
    installed = (prc == 0)
    # The package being present isn't enough — APT's periodic interval must be on.
    out, _, _ = _run("apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null", timeout=10)
    enabled = installed and _apt_periodic_on(out)
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
_F2B_PANEL_WHITELIST = _priv.WRITE_TARGETS["fail2ban-panel-whitelist"][0]
_WRITE_TARGET_BY_PATH = {p: name for name, (p, _m) in _priv.WRITE_TARGETS.items()}


def _panel_f2b_filter_body():
    """fail2ban filter matching the panel's own auth.log lines; <HOST> captures the offender. A
    failed or throttled password login, and a bearer-token attempt the token throttle refused
    (auth._token_auth_note_blocked)."""
    return ("[Definition]\n"
            "failregex = panel (?:login|api token) (?:failed|blocked) from <HOST>$\n"
            "ignoreregex =\n")


def _panel_f2b_filter_current():
    """The panel filter file as it is on disk, or None if it cannot be read (it is world-readable,
    so no sudo). Compared whole: a filter written before a line was added matches nothing new."""
    try:
        with open(_F2B_PANEL_FILTER) as f:
            return f.read()
    except OSError:
        _log.debug("f2b: could not read the panel filter", exc_info=True)
    return None


def _f2b_ignoreip_line(ignore_ips):
    """Space-separated ignoreip value: always localhost, plus the caller's whitelist. EVERY entry is
    re-parsed through ipaddress (IP or CIDR) so an unvalidated token can never reach the jail file —
    a bad entry is dropped, not written. Deduped, order-stable."""
    entries = ["127.0.0.1/8", "::1"]
    for raw in (ignore_ips or []):
        canon = canonical_ip_or_network(raw)
        if canon is None:
            continue
        # Parsing was not enough: ipaddress keeps an IPv6 zone id verbatim — `::1%\nbantime = 1`
        # parses, newline and all — so a stored entry could still add lines to the jail. The
        # validator refuses a zone now; this stays as the jail file's own last check.
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


# Every tailnet peer's address: Tailscale's CGNAT IPv4 range and its IPv6 ULA prefix. These are
# the ranges Tailscale assigns EVERY node from, fixed by Tailscale, not a host or a setting.
_TAILNET_RANGES = ("100.64.0.0/10", "fd7a:115c:a1e0::/48")  # NOSONAR - Tailscale's fixed ranges


def _panel_f2b_ignore(ignore_ips):
    """The panel jail's ignoreip entries (before _f2b_ignoreip_line validates them): the whitelist,
    plus the tailnet — on every jail, whichever port it bans on.

    An all-ports ban on a tailnet peer is a ban on its way in: under Serve the forwarded client IS
    a tailnet address, and five mistyped panel passwords from an admin's laptop REJECTed that
    100.x address on every TCP port for an hour — sshd over tailscale0 (the way back in once public
    SSH is off), game and RCON ports. The panel never firewall-blocks a tailnet IP anywhere else
    (ssh_manager's note above _TAILNET_CGNAT; the auto-block exempts them), and a public attacker
    cannot have one.

    A web-port-only jail exempts them too. It used not to, on the reasoning that it took only the
    panel login away — but that is the panel, from the admin's own laptop, for an hour, and the
    README has always promised "your Tailscale peers are never banned". A tailnet peer mistyping
    its password is still held to the login throttle (auth_routes), which fail2ban never replaced."""
    return list(ignore_ips or []) + list(_TAILNET_RANGES)


def _panel_f2b_jail_body(auth_log, web_port, ignore_ips=None, allports=None):
    """Jail: 5 failures in 10 min → 1-hour ban, on the panel's web port. In jail.d/ so it sits
    alongside (doesn't conflict with) any [sshd] jail. `ignore_ips` (validated) and the tailnet
    are never banned.

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
                                 _f2b_ignoreip_line(_panel_f2b_ignore(ignore_ips))))


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


# fail2ban-client's answer for a jail that is not configured: a READING ("no such jail"), unlike a
# stopped server or a refused read, which say nothing about the jail.
_F2B_NO_JAIL_RE = re.compile(r"does not exist|no such jail|unknown jail", re.IGNORECASE)


def panel_fail2ban_status():
    """Whether the panel-login fail2ban jail is active on this host, and how many IPs it's banning.
    Best-effort; {'installed': bool, 'enabled': bool, 'banned': int}, plus 'unreadable': True when
    the jail's state could not be READ (fail2ban stopped, the socket refused, a timeout).

    `enabled` keeps its meaning for every caller that branches on it -- ensure_panel_fail2ban's
    self-heal and configure's reload poll rewrite and reload the jail on False, which is still the
    right thing to try when the read failed. `unreadable` is what lets a display tell "the jail is
    off" from "the jail could not be read" (R42)."""
    have, _, _ = _run("command -v fail2ban-client >/dev/null 2>&1 && echo yes || echo no", timeout=10)
    if "yes" not in (have or ""):
        return {"installed": False, "enabled": False, "banned": 0}
    out, err, rc = _run_verb("f2b-status-jail", ["linuxgsm-panel"], timeout=10, merge_stderr=False)
    if rc != 0 or not out:
        res = {"installed": True, "enabled": False, "banned": 0}
        if not _F2B_NO_JAIL_RE.search("%s\n%s" % (out or "", err or "")):
            res["unreadable"] = True
        return res
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
    """Names of all configured fail2ban jails on this host; None when they could not be READ.

    None, not []: a stopped fail2ban, a refused or timed-out read all came back [] and the Security
    card said "No fail2ban jails found." -- the answer a healthy host with nothing configured gives.
    `fail2ban-client status` always prints "Jail list:" when it really ran, which is the positive
    test hosts.remote_fail2ban_overview already makes on a remote (R42)."""
    out, _, rc = _run_verb("f2b-status", [], timeout=10, merge_stderr=False)
    m = re.search(r"Jail list:\s*(.*)", out or "")
    if rc != 0 or not m:
        return None
    return [j.strip() for j in m.group(1).split(",") if _JAIL_RE.match(j.strip())]


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
    jails = _fail2ban_jails()
    if jails is None:
        return {"installed": True, "jails": [], "unreadable": True}
    details = [d for d in (fail2ban_jail_detail(j) for j in jails) if d]
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
        # The row after its `[ N]` number. Sliced off rather than captured with `\s*(.*)\Z`: a
        # line from splitlines() holds no newline, so that capture was always the rest of the line,
        # and `\s*` beside `.*` in front of an anchor is a scan the pattern never needed.
        m = re.match(r"\s*\[\s*\d+\]\s*", line)
        body, _, comment = (line[m.end():] if m else line).partition("#")
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
    reconcile still reads it as the operator's and never releases it. Only a DENY is moved:
    `ufw delete deny` does not match a REJECT. IPv6 is moved like IPv4 — ufw-deny-ip is
    `ufw prepend`, which puts a rule at the top of its own address family. (It was `insert 1`,
    which ufw refuses for IPv6 while IPv4 rules exist, and IPv6 was refused here for that reason
    after the verb stopped using it: the answer told the operator to run `ufw prepend` by hand.)"""
    if rule.get("action") != "DENY":
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
    the reconcile would later release; and when the insert then failed (as `insert 1`, the verb
    then, did for an IPv6 address while IPv4 rules existed) the address was left with no block at
    all. Now a rule
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
    canonical ipaddress form so nothing request-supplied reaches the shell unchecked. (ok, msg).

    That claim needs a zone id refused, and it is (panel/core/validation.py): ipaddress kept one
    verbatim, so 'fe80::1%$(id) x;reboot' went through as its own "canonical form" and reached the
    root helper intact, stopped only by ufw's own address check."""
    ip = canonical_ip(ip)
    if ip is None:
        return False, "Invalid IP address."
    tag = re.sub(r"[^a-z0-9-]", "", (tag or ""))[:32] or _UFW_BLOCK_TAG
    # Separate verbs, never a "a; b" compound: _run prepends `sudo` to the FIRST command only.
    shadowed = {}
    existing = (ufw_blocked_ips(shadowed) or {}).get(ip)
    return _ufw_deny_with(ip, tag, existing,
                          lambda verb, args: _run_verb(verb, args, timeout=15),
                          shadowed.get(ip))


def ufw_undeny_ip(ip):
    """Remove a UFW deny rule for an IP (canonicalised first, a zone id refused). (ok, msg)."""
    ip = canonical_ip(ip)
    if ip is None:
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
    except (TypeError, ValueError, OverflowError):
        days = 7
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    # Was a five-stage zcat|awk|grep|awk|sort|head pipeline running as root, with the cutoff date
    # and the limit interpolated into it. The verb reads the rotated logs and returns the lines;
    # everything the awk did — filter by date, extract Ban/Found, tally per IP — is Python now.
    out, _, rc = _run_verb("f2b-log-lines", [cutoff], timeout=25, merge_stderr=False)
    if _f2b_unread(rc, "top-ips"):
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
    except (TypeError, ValueError, OverflowError):
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
    if _f2b_unread(rc, "attempt counts"):
        return None
    return _tally_f2b_events(out)[0]


def _f2b_unread(rc, what):
    """Whether a fail2ban log read must be treated as unread: it failed, or it was cut (rc 3).

    Cut means the helper, or the shell form standing in for it (privileged._f2b_log_lines_remote),
    stopped at its own ceiling, or this process's collector stopped keeping bytes at
    _MAX_OUTPUT_BYTES (a helper that predates the ceiling); all answer _CUT_RC, and the remote
    readers in ssh_manager.hosts decide from this too. The bytes a cut read keeps are the FIRST
    ones — the oldest days — so a partial tally undercounts exactly the recent offenders, and the
    auto-block reconcile RELEASES any block that falls under the threshold: a cut read is unread,
    never smaller. Under a flood the host's auto-block therefore holds still (no new blocks, no
    releases) — fail2ban's own bans are unaffected.

    The rc, and not the answer's length: that was `len >= F2B_LOG_MAX_BYTES`, while the helper
    prints up to AND INCLUDING that many bytes with rc 0, so an answer the helper called complete
    was discarded here.
    """
    if rc == _CUT_RC:
        _log.warning("%s: the fail2ban log passed the read ceiling; treated as unread so no block "
                     "is released on a partial tally", what)
    elif rc != 0:
        _log.debug("%s: the fail2ban log read failed (rc=%s)", what, rc)
    return rc != 0


def fail2ban_unban(jail, ip):
    """Lift a ban: `fail2ban-client set <jail> unbanip <ip>`. The request-supplied values are
    neutralised BEFORE they reach the command: `jail` must be one of the host's actual jails (an
    allowlist — not a free string), and `ip` is reparsed to the canonical form produced by
    ipaddress (which rejects anything that isn't a real IP, a zone id included). Then shell-quoted.
    (ok, msg)."""
    jail = (jail or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", jail):   # metacharacter-free guard
        return False, "Invalid jail name."
    # Rebind `jail` to the matching entry from the host's actual jail list (fail2ban-client output,
    # not the request), so the value interpolated into the command is sourced from trusted data and
    # is never the raw request string. A guard/allowlist alone did not clear the taint for CodeQL —
    # this rebind (mirroring how the ip guard reparses through ipaddress) does.
    jails = _fail2ban_jails()
    if jails is None:
        return False, "Couldn't read fail2ban's jails, so nothing was unbanned."
    jail = next((j for j in jails if j == jail), None)
    if jail is None:
        return False, "Unknown jail."
    ip = canonical_ip(ip)   # canonical form; rejects anything that isn't a real IP
    if ip is None:
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
    ip = canonical_ip(ip)
    if ip is None:
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
        if jail and jail in (_fail2ban_jails() or []):   # allowlist; used only for in-Python filtering, never a command
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
    except (TypeError, ValueError, OverflowError):
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
    except (TypeError, ValueError, OverflowError):
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
    # Built exactly as _panel_f2b_jail_body builds it — tailnet included — or a jail written
    # without it would read as healthy and never be rewritten.
    want_ignore = _f2b_ignoreip_line(_panel_f2b_ignore(ignore_ips)).split()
    if (st.get("enabled") and _panel_f2b_jail_port() == web_port
            and _panel_f2b_jail_value("banaction") == want_action
            and _panel_f2b_jail_value("logpath") == str(auth_log)
            and _panel_f2b_jail_value("backend") == _F2B_PANEL_BACKEND
            and (_panel_f2b_jail_ignoreip() or []) == want_ignore
            and _panel_f2b_filter_current() == _panel_f2b_filter_body()):
        return True, "panel-login jail already active on port %d" % web_port
    return configure_panel_fail2ban(auth_log, web_port, ignore_ips)


def f2b_whitelist_dropin_body(ignore_ips):
    """The `[DEFAULT] ignoreip` drop-in that makes every jail on a host (sshd included) ignore the
    whitelist. Built by _f2b_ignoreip_line, so it gets the same validation as the panel jail's own
    line — ssh_manager's remote copy of this file too."""
    return "[DEFAULT]\nignoreip = %s\n" % _f2b_ignoreip_line(ignore_ips)


def ensure_panel_host_whitelist(ignore_ips):
    """Make EVERY fail2ban jail on the panel's own host ignore the whitelist, not only the panel
    login's. Returns (ok, msg); no-ops when fail2ban is absent or the file already says this.

    Remotes had this for a long time (ssh_manager remote_set_fail2ban_ignoreip writes the same
    drop-in). The panel host did not: only the panel-login jail carried the whitelist, so an admin
    whose own address was whitelisted could still be banned from SSH on the very host the panel
    runs on — while the Security page said "never banned or blocked".

    Nothing is written for an empty whitelist unless a drop-in is already there to be emptied: a
    [DEFAULT] ignoreip in a later-read file overrides one the operator set in jail.local."""
    if not panel_fail2ban_status().get("installed"):
        return False, "fail2ban isn't installed on this host."
    want = f2b_whitelist_dropin_body(ignore_ips)
    try:
        with open(_F2B_PANEL_WHITELIST) as f:
            have = f.read()
    except OSError:
        have = None
    if have == want:
        return True, "fail2ban whitelist already applied to every jail"
    if have is None and not ignore_ips:
        return True, "no whitelist to apply"
    if _write_root_file(_F2B_PANEL_WHITELIST, want)[2] != 0:
        return False, "could not write the fail2ban whitelist"
    _run_verb("f2b-reload", [], timeout=45)
    return True, "fail2ban whitelist applied to every jail"


# The checks below each answer (level, detail), or None when they have nothing to say on this host.
# A DETAIL IS PRINTED IN THE PUBLIC DEBUG REPORT (the GitHub issue body), so it carries fixed text,
# counts, repo-relative paths, octal modes and exception CLASS names only: never an absolute path,
# an account name, a host, or str(exc).
_DIAG_LIST_MAX = 20          # repo-relative paths named in one detail
_ERR_CLASS_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,63}\Z")


def _cls_token(name):
    """`name` when it is shaped like an exception class name, else 'error'."""
    return name if isinstance(name, str) and _ERR_CLASS_RE.match(name) else "error"


def _diag_hidden_paths():
    """(skip-worktree paths, assume-unchanged paths) from `git ls-files -v`; None if git failed.

    These are the tracked paths `git diff` cannot see (install.sh names --skip-worktree as a way to
    make `reset --hard` leave one alone). ls-files only READS the index: no lock is taken."""
    out, _, rc = _git(["ls-files", "-v"], timeout=10)
    if rc != 0:
        return None
    skip, assume = [], []
    for line in (out or "").splitlines():
        tag, _, path = line.partition(" ")
        if tag in ("S", "s"):
            skip.append(path)
        elif tag[:1].islower():
            assume.append(path)
    return skip, assume


def _diag_hidden_note():
    """(a sentence for the File integrity detail, whether it is a problem)."""
    hidden = _diag_hidden_paths()
    if hidden is None:
        return " Could not check for paths hidden from git (git ls-files failed).", True
    skip, assume = hidden
    if not skip and not assume:
        return "", False
    return (" %d tracked path(s) are hidden from git (skip-worktree %d, assume-unchanged %d): %s."
            % (len(skip) + len(assume), len(skip), len(assume),
               ", ".join((skip + assume)[:_DIAG_LIST_MAX]))), True


def _diag_file_integrity():
    integ = panel_integrity()
    if not integ["git"]:
        return "warn", integ["message"]
    if not integ.get("verified", True):
        return "warn", integ.get("message", "Couldn't verify file integrity.")
    note, hidden = _diag_hidden_note()
    if integ["clean"]:
        return ("warn" if hidden else "ok",
                "All panel files match the installed version (%s).%s"
                % (integ["current_sha"] or "?", note))
    listed = ["%s (%s)" % (m.get("path"), m.get("status"))
              for m in (integ.get("modified") or [])][:_DIAG_LIST_MAX]
    return "fail", ("%d panel file(s) differ from the installed version%s.%s"
                    % (integ["count"], (": " + ", ".join(listed)) if listed else "", note))


def _owner_role(uid):
    """The owner of a file as a ROLE, never a name: root, the panel account, or another account."""
    if uid == 0:
        return "root"
    if hasattr(os, "geteuid") and uid == os.geteuid():
        return "the panel account"
    return "another account"


def _diag_data_dir(data_dir):
    if os.path.isdir(data_dir) and os.access(data_dir, os.W_OK):
        return "ok", "Writable."
    try:
        st = os.stat(data_dir)
    except FileNotFoundError:
        return "fail", "data/ under the panel checkout does not exist."
    except OSError:
        return "fail", "data/ under the panel checkout is not writable (owner unreadable)."
    return "fail", ("data/ under the panel checkout is not writable (owner: %s, mode %04o; the "
                    "panel runs as %s)." % (_owner_role(st.st_uid), st.st_mode & 0o7777,
                                            "root" if _owner_role(os.geteuid()) == "root"
                                            else "its service account"))


def _diag_database(dbp):
    try:
        sz = os.path.getsize(dbp)
    except OSError:
        return "fail", "Database file is missing."
    if sz > 0:
        human = "%.1f MB" % (sz / 1048576) if sz >= 1048576 else "%d KB" % max(1, sz // 1024)
        return "ok", "Present (%s)." % human
    return "fail", "Database file is empty."


# What a restart does with a damaged database, by the state of its rolling backup: it restores a
# backup that passes quick_check, starts EMPTY when there is none or it fails (models.
# _set_corrupt_db_aside), and repairs nothing when the backup cannot be checked (the check raises
# out of the self-heal, which logs it and starts on the damaged file).
_DB_DAMAGED_TEXT = {
    "ok": "Corruption detected. A healthy rolling backup exists, so a restart restores it (the "
          "damaged copy is kept beside it).",
    "not_checked": "Corruption detected, and the rolling backup could not be checked, so a "
                   "restart will not repair it. Run the repair tool.",
    None: "Corruption detected and NO healthy backup. A restart moves the database aside and "
          "starts EMPTY; run the repair tool first.",
}


def _db_has_content(dbp):
    try:
        return os.path.exists(dbp) and os.path.getsize(dbp) > 0
    except OSError:
        return False


def _db_check_verdict(db_check, dbp):
    """(level, detail) for an _src_db.integrity() result."""
    state = db_check.get("state")
    if state == "ok":
        bak = " (a rolling backup is kept for recovery)" if os.path.exists(dbp + ".backup") else ""
        return "ok", "No corruption detected%s." % bak
    if state == "damaged":
        backup = db_check.get("backup")
        return "fail", _DB_DAMAGED_TEXT.get(backup if backup in ("ok", "not_checked") else None)
    return "warn", "Couldn't run the integrity check (%s)." % _cls_token(
        db_check.get("detail_class") or "NoAnswer")


def _diag_db_integrity(db_check, dbp):
    """R12/R57: ONE read-only quick_check, off the hub (debug_report._src_db), or the result the
    caller already has. Locked or busy is 'not checked', never damage."""
    if not _db_has_content(dbp):
        return None
    if db_check is None:
        from panel.ops.debug_report import _src_db
        db_check = _src_db.integrity()
    return _db_check_verdict(db_check or {}, dbp)


def _diag_encryption_keys():
    # The session secret is always needed (Flask signs cookies with it), so its absence is a real
    # fault. The credential key is created ONLY when the first password-based credential is
    # saved, so a missing cred_key is normal (e.g. all remotes use SSH-key / Tailscale / local
    # auth) — not a fault. Whether the stored values DECRYPT is the Host credentials check.
    from panel.core import config as _cfg
    if not _cfg.SECRET_FILE.exists():
        return "fail", "Session secret key is missing."
    if not _cfg.CRED_KEY_FILE.exists():
        return "ok", ("Session key present; the credential key is created when the first "
                      "saved password/credential needs it.")
    return "ok", "Session + credential keys present."


def _cred_state(raw, key_present):
    """'empty' | 'plain' | 'ok' | 'bad' for one RAW stored value. Decrypts only when the key file
    exists: decrypt_secret goes through _cred_fernet, which CREATES a missing cred_key — on the
    very host this check is for, that would mint a new key over the lost one's ciphertext."""
    from panel.core import config as _cfg
    if not raw:
        return "empty"
    if not _cfg.is_encrypted(raw):
        return "plain"
    if not key_present:
        return "bad"
    return "ok" if _cfg.decrypt_secret(raw) else "bad"


def _read_host_fields():
    """([(host id, {column: raw value})], [raw session values]) read RAW (type_coerce to Text, as
    models.encrypt_at_rest_columns does), so nothing is decrypted on the way out."""
    from sqlalchemy import Text as _SAText, select, type_coerce
    from panel.db.models import ENCRYPTED_AT_REST_COLUMNS, RemoteServer, UserSession, db
    cols = tuple(ENCRYPTED_AT_REST_COLUMNS["remote_server"]) + ("auth_credential",)
    tbl = RemoteServer.__table__
    rows = db.session.execute(select(tbl.c.id, *[type_coerce(tbl.c[c], _SAText).label(c)
                                                  for c in cols])).fetchall()
    st = UserSession.__table__
    srows = db.session.execute(select(*[type_coerce(st.c[c], _SAText).label(c)
                                        for c in ENCRYPTED_AT_REST_COLUMNS["user_session"]]))
    return ([(r.id, {c: getattr(r, c) for c in cols}) for r in rows],
            [v for r in srows.fetchall() for v in r])


def _cred_tally(hosts, session_vals, key_present):
    """{'ok', 'bad', 'plain', 'session_bad'} counts and [(host id, [undecryptable columns])]."""
    tally = {"ok": 0, "bad": 0, "plain": 0, "session_bad": 0}
    bad_hosts = []
    for hid, vals in hosts:
        bad_cols = []
        for col, raw in vals.items():
            st = _cred_state(raw, key_present)
            if st == "plain" and col == "auth_credential":
                continue            # a plain Text column: plaintext is not "still unencrypted"
            if st in tally:
                tally[st] += 1
            if st == "bad":
                bad_cols.append(col)
        if bad_cols:
            bad_hosts.append((hid, bad_cols))
    for raw in session_vals:
        if _cred_state(raw, key_present) == "bad":
            tally["session_bad"] += 1
    return tally, bad_hosts


def _diag_host_credentials():
    """R10: whether the stored host fields DECRYPT with this cred_key (field names, host ids and
    counts only, never a value). A read error is a warning, never 'every field decrypts'."""
    from panel.core import config as _cfg
    try:
        hosts, session_vals = _read_host_fields()
        key = _cfg.CRED_KEY_FILE.exists()
        tally, bad_hosts = _cred_tally(hosts, session_vals, key)
    except Exception as exc:  # noqa: BLE001 - reported by class
        return "warn", "Could not read the hosts table (%s)." % type(exc).__name__
    if bad_hosts:
        named = "; ".join("host %d: %s" % (hid, ", ".join(cols)) for hid, cols in bad_hosts[:10])
        why = ("data/cred_key is MISSING, so" if not key else "with this data/cred_key")
        return "fail", ("%d of %d hosts have fields that cannot be decrypted %s (%s). Commands to "
                        "them will fail; restore the matching data/cred_key."
                        % (len(bad_hosts), len(hosts), why, named))
    if tally["session_bad"]:
        return "warn", ("%d stored sign-in session value(s) cannot be decrypted with this "
                        "data/cred_key." % tally["session_bad"])
    return "ok", ("Every stored host field decrypts (%d encrypted value(s); 0 undecryptable, %d "
                  "still plaintext)." % (tally["ok"], tally["plain"]))


# R9: `sudo -n <helper> --list-verbs` -- what every real privileged call is shaped like. The check
# ran the helper WITHOUT sudo, so a sudoers rule that made sudo refuse it (a general rule sorting
# after the grant, see _sudoers_after_grant) left this green while every privileged action waited
# for a password. Cached like _check_sudo: a refused `sudo -n` is logged by sudo every time, and
# the Diagnostics card and the debug report both ask.
_HELPER_PROBE = {"at": 0.0, "res": None}
_HELPER_PROBE_TTL = 300
# A refusal as a CLASS: the matched line can name the account ("alice is not in the sudoers file").
_SUDO_REFUSAL_CLASSES = (("password", "a password is required"),
                         ("authentication", "a password is required"),
                         ("terminal", "a terminal is required"), ("tty", "a terminal is required"),
                         ("sudoers", "the account is not in the sudoers file"),
                         ("incorrect", "too many password attempts"),
                         ("afraid", "the account may not run it"),
                         ("root", "it must be run as root"),
                         ("permissionerror", "the helper was refused a permission"))


def _sudo_refusal_class(text):
    """A fixed phrase for the sudo refusal in `text`, or None when it holds none."""
    from panel.ops.ssh_manager import firewall as _fw   # lazy: ssh_manager imports this module
    m = _fw._SUDO_REFUSED_RE.search(text or "")
    if not m:
        return None
    low = m.group(0).lower()
    return next((cls for key, cls in _SUDO_REFUSAL_CLASSES if key in low), "refused by sudo")


def _helper_probe_argv():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return [_priv.HELPER_PATH, "--list-verbs"]
    return ["sudo", "-n", _priv.HELPER_PATH, "--list-verbs"]


def _helper_probe_run():
    """{"outcome": ok | refused | timeout | unreadable | error, "verbs": set, "refusal": phrase}."""
    try:
        # Both elements past sudo's are module constants (privileged.HELPER_PATH and the literal
        # "--list-verbs"); shell=False, so nothing is interpreted. See _run_verb for why the
        # scanners' "not a literal string" finding is suppressed rather than "fixed".
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
        r = subprocess.run(_helper_probe_argv(), shell=False,  # nosec B603
                           capture_output=True, text=True, timeout=10,
                           stdin=subprocess.DEVNULL, start_new_session=True)
    except subprocess.TimeoutExpired:
        return {"outcome": "timeout", "verbs": set(), "refusal": None}
    except Exception as exc:  # noqa: BLE001 - reported by class
        return {"outcome": "error", "verbs": set(), "refusal": None, "error": type(exc).__name__}
    verbs = {ln.split("\t")[0] for ln in (r.stdout or "").splitlines() if ln.strip()}
    if r.returncode == 0 and verbs:
        return {"outcome": "ok", "verbs": verbs, "refusal": None}
    refusal = _sudo_refusal_class(r.stderr) if r.returncode != 0 else None
    return {"outcome": "refused" if refusal else "unreadable", "verbs": verbs, "refusal": refusal}


def helper_probe(force=False):
    """The cached result of `sudo -n <helper> --list-verbs` (see _HELPER_PROBE); None when the
    probe is not run here -- the helper is absent (the caller checks that)."""
    now = time.time()
    if not force and _HELPER_PROBE["res"] is not None and \
            (now - _HELPER_PROBE["at"]) < _HELPER_PROBE_TTL:
        return _HELPER_PROBE["res"]
    res = _helper_probe_run()
    _HELPER_PROBE.update(at=now, res=res)
    return res


# /etc/sudoers.d names the report may print as they are. Any other name can be an account's
# ("alice", "bob-nopasswd"), so it is only counted.
_SUDOERS_D = "/etc/sudoers.d"
_PANEL_GRANT = "linuxgsm-panel"
_SUDOERS_KNOWN = frozenset({"README", "90-cloud-init-users", "linuxgsm-panel",
                            "00-linuxgsm-panel-terminal"})


def _sudoers_after_grant():
    """A sentence on which /etc/sudoers.d files sort AFTER the panel's grant: sudo reads them in
    lexical order and the LAST match wins, so a general rule there makes the helper prompt."""
    try:
        names = sorted(n for n in os.listdir(_SUDOERS_D) if _sudo_reads(n))
    except OSError:
        return "/etc/sudoers.d is not readable by the panel account."
    if _PANEL_GRANT not in names:
        return "There is no /etc/sudoers.d/linuxgsm-panel grant (a per-user install has none)."
    return _sudoers_after_sentence([n for n in names if n > _PANEL_GRANT])


def _sudoers_after_sentence(after):
    """The sentence for the /etc/sudoers.d names `after` the grant: known names, others counted."""
    if not after:
        return "No /etc/sudoers.d file sorts after the panel's grant."
    known = [n for n in after if n in _SUDOERS_KNOWN]
    others = ["%d other file(s)" % (len(after) - len(known))] if len(after) > len(known) else []
    return ("Files in /etc/sudoers.d sorting after the panel's grant (the last match wins): %s."
            % ", ".join(known + others))


def _sudo_reads(name):
    """Whether sudo reads /etc/sudoers.d/<name>: it skips names with a '.' or ending in '~'."""
    return "." not in name and not name.endswith("~")


def _helper_blob_note():
    piece = root_piece_state().get("panel-helper", {})
    return {"same": " The installed file is HEAD's tools/panel-helper.",
            "differs": " The installed file DIFFERS from HEAD's tools/panel-helper.",
            "unreadable": " The installed file could not be read to compare with HEAD's.",
            }.get(piece.get("state"), "")


def _diag_helper_refused(probe):
    remedy = ("root withholds its pieces from this origin or branch by design (see Origin under "
              "Install & privilege)" if (origin_category() != "canonical-https"
                                         or _tracked_branch() != _DEFAULT_BRANCH)
              else "remove or reorder the rule that matches after it, or re-run install.sh as root")
    return "fail", ("Installed, but sudo REFUSES it (%s). %s Every privileged action will wait "
                    "for a password; %s." % (probe.get("refusal"), _sudoers_after_grant(), remedy))


def _diag_helper_verbs(probe):
    installed = probe.get("verbs") or set()
    missing = sorted(set(_priv.verbs()) - installed)
    if missing:
        return "fail", ("Out of date — %d verb(s) this version needs are missing (%s%s). "
                        "Re-run install.sh as root on this host to refresh it."
                        % (len(missing), ", ".join(missing[:4]), ", …" if len(missing) > 4 else ""))
    return "ok", "Installed and current (%d verbs).%s" % (len(installed), _helper_blob_note())


def _diag_privileged_helper():
    """R9: the installed helper, through sudo -n as every real call is, and its verb table."""
    if not _helper_present():
        from panel.ops.ssh_manager import _core as _smc     # lazy: ssh_manager imports this module
        if _smc.helper_on_disk():
            return "warn", ("Installed, but this process started before it was placed and is not "
                            "using it. Restart the panel.")
        return "warn", ("Not installed — privileged actions fall back to the pre-helper path and "
                        "the sudoers grant cannot be narrowed. Re-run install.sh as root to place "
                        "it.")
    probe = helper_probe()
    outcome = probe.get("outcome")
    if outcome == "refused":
        return _diag_helper_refused(probe)
    if outcome == "timeout":
        return "warn", ("Installed, but `sudo -n` did not answer within 10 s: a sudo stall "
                        "(hostname lookup, SSSD), not a refusal.")
    if outcome == "error":
        return "warn", "Installed, but could not be queried."
    if outcome != "ok":
        return "warn", "Installed, but its verb table could not be read."
    return _diag_helper_verbs(probe)


def _diag_configuration():
    # load_config() never raises: an unreadable file comes back as defaults, MARKED. The except
    # alone reported "loads cleanly" for any corrupt file, because it could never fire.
    from panel.core import config as _cfg
    try:
        unreadable = _cfg.is_unreadable(_cfg.load_config())
    except Exception:  # noqa: BLE001
        unreadable = True
    if unreadable:
        return "fail", "config.json could not be read or parsed."
    return "ok", "config.json loads cleanly."


def _diag_disk_space():
    import shutil
    try:
        du = shutil.disk_usage(PANEL_DIR)
    except OSError:
        return "warn", "Couldn't read disk usage."
    free_gb, used_pct = du.free / (1024 ** 3), du.used / du.total * 100
    return ("warn" if (free_gb < 1 or used_pct > 92) else "ok",
            "%.1f GB free (%.0f%% used)." % (free_gb, used_pct))


def _boot_tls():
    """(tls, error class) from the boot record app.py keeps in current_app.config (R20), or
    (None, None) without one -- never recomputed from the stored config, whose bind can differ
    from the one this process booted with."""
    try:
        from flask import current_app
        cfg = current_app.config
        if "BOOT_TLS" not in cfg:
            return None, None
        return cfg.get("BOOT_TLS"), cfg.get("BOOT_TLS_ERROR")
    except Exception:  # noqa: BLE001 - no app context: no boot record
        return None, None


def _cert_days(cert_path):
    """Whole days until the PEM certificate at `cert_path` expires (negative once it has)."""
    from datetime import datetime, timezone
    from cryptography import x509
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    na = getattr(cert, "not_valid_after_utc", None)
    if na is None:
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return (na - datetime.now(timezone.utc)).days


def _cert_verdict(days, tls):
    """(level, detail) for a cert `days` from expiry. A cert whose use is unknown is never 'fail'."""
    prefix = ("In use (the panel terminates TLS). " if tls
              else "In use: unknown (no boot record; this process was not started by app.py). ")
    if days < 0:
        return ("fail" if tls else "warn"), prefix + "Expired %d day(s) ago." % -days
    if days < 14:
        return "warn", prefix + "Expires in %d day(s)." % days
    return "ok", prefix + "Valid for %d more day(s)." % days


def _diag_tls(data_dir):
    """R11: decided by the boot record, not by the file existing. A leftover cert on a panel
    whose TLS is terminated elsewhere is never a warning; a TLS start that failed at boot is."""
    tls, err = _boot_tls()
    if tls is False and err:
        return "fail", ("The panel should serve HTTPS, but TLS FAILED to start at boot (%s) and "
                        "it is serving plain HTTP." % _cls_token(err))
    cert_path = os.path.join(data_dir, "ssl", "cert.pem")
    if not os.path.exists(cert_path):
        return None
    if tls is False:
        return "ok", ("Not in use (TLS is terminated by Tailscale Serve or a proxy, or the panel "
                      "serves plain HTTP); a leftover cert.pem is present.")
    try:
        days = _cert_days(cert_path)
    except Exception:  # noqa: BLE001
        return "warn", "Present but couldn't be parsed."
    return _cert_verdict(days, tls)


_UNIT_TOKEN_RE = re.compile(r"^[a-z-]{1,24}\Z")
_USER_UNIT = "~/.config/systemd/user/linuxgsm-panel.service"
_SYSTEM_UNIT = "/etc/systemd/system/linuxgsm-panel.service"


def _unit_token(value):
    return value if isinstance(value, str) and _UNIT_TOKEN_RE.match(value) else "other"


def _linger_on():
    """Whether systemd keeps this account's user manager running without a login; None if the
    account cannot be named. The name is used for the path test only and never printed."""
    try:
        import pwd
        name = pwd.getpwuid(os.geteuid()).pw_name
        return os.path.exists(os.path.join("/var/lib/systemd/linger", name))
    except Exception:  # noqa: BLE001
        return None


def _same_dir(a, b):
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except Exception:  # noqa: BLE001
        return False


def _service_problems(scope, props):
    """The problems a unit's `systemctl show` properties reveal, as fixed sentences."""
    out = []
    if props.get("UnitFileState") not in ("enabled", "enabled-runtime"):
        out.append("the unit is %s, so it does not start at boot"
                   % _unit_token(props.get("UnitFileState")))
    if scope == "user" and props.get("UnitFileState") == "enabled" and _linger_on() is False:
        out.append("linger is OFF, so the panel stops at logout and does not start at boot")
    if str(props.get("MainPID") or "") != str(os.getpid()):
        out.append("the unit's MainPID is not this process")
    wd = props.get("WorkingDirectory")
    if wd and not _same_dir(wd, PANEL_DIR):
        out.append("the unit's WorkingDirectory is not this checkout")
    return out


def _is_this_process(props):
    return str(props.get("MainPID") or "") == str(os.getpid())


def _service_summary(scope, props):
    """One line of fixed tokens: scope, enablement, state, whether MainPID is us, linger."""
    linger = ({True: "on", False: "OFF"}.get(_linger_on(), "unknown") if scope == "user"
              else "n/a")
    return "%s unit · %s · %s (%s) · MainPID is this process: %s · linger %s." % (
        scope, _unit_token(props.get("UnitFileState")), _unit_token(props.get("ActiveState")),
        _unit_token(props.get("SubState")), "yes" if _is_this_process(props) else "no", linger)


def _both_units_note():
    both = os.path.exists(os.path.expanduser(_USER_UNIT)) and os.path.exists(_SYSTEM_UNIT)
    return " BOTH a system unit and a per-user unit exist (two installs?)." if both else ""


def _unit_or_read(unit):
    """`unit` as given, or the shared `systemctl show` read now; {} for nothing at all."""
    if unit is None:
        from panel.ops.debug_report import _src_systemd
        unit = _src_systemd.unit_show()
    return unit or {}


def _diag_service(unit):
    """R8: the ONE `systemctl show` the report shares (debug_report._src_systemd), not a file
    existing. Paths are printed as yes/no, never the home directory or the account."""
    both_note = _both_units_note()
    unit = _unit_or_read(unit)
    props = unit.get("props") or {}
    if unit.get("error") or not props:
        return "warn", "systemd state unreadable (%s).%s" % (
            _unit_token(unit.get("error") or "no-answer"), both_note)
    scope = "user" if unit.get("scope") == "user" else "system"
    problems = _service_problems(scope, props)
    detail = _service_summary(scope, props)
    if problems:
        detail += " " + "; ".join(problems) + "."
    return ("warn" if problems or both_note else "ok"), detail + both_note


def _diag_auto_updates():
    # Hardening — a warn, not a fault: the panel runs fine either way, but for an unattended box
    # you want the OS patching itself.
    try:
        au = unattended_upgrades_status()
        return ("ok" if au["enabled"] else "warn"), au["detail"]
    except Exception:  # noqa: BLE001
        return "warn", "Couldn't determine the update status."


def _diag_guarded(fn):
    """fn()'s (level, detail), with a check that raised reported as a warning by class."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - one check's failure must not take the others
        return "warn", "Could not be checked (%s)." % type(exc).__name__


def panel_diagnostics(db_check=None, unit=None):
    """A fast, local self-check of the panel's own health: file integrity, data dir, database,
    encryption keys and host credentials, the privileged helper, config, disk space, TLS cert and
    service unit. No SSH/network. Returns {checks:[{name,level,detail}], summary, counts}.

    `db_check` is debug_report._src_db.integrity()'s result and `unit` _src_systemd.unit_show()'s,
    when the caller (the debug report) already has them: one integrity check and one
    `systemctl show` per report. Without them this reads both itself, the integrity check off the
    hub. Every detail is safe for the public report: no absolute path, account or host."""
    from panel.core import config as _cfg
    data_dir, dbp = str(_cfg.DATA_DIR), str(_cfg.DB_PATH)
    plan = (("File integrity", _diag_file_integrity),
            ("Data directory", lambda: _diag_data_dir(data_dir)),
            ("Database", lambda: _diag_database(dbp)),
            ("Database integrity", lambda: _diag_db_integrity(db_check, dbp)),
            ("Encryption keys", _diag_encryption_keys),
            ("Host credentials", _diag_host_credentials),
            ("Privileged helper", _diag_privileged_helper),
            ("Configuration", _diag_configuration),
            ("Disk space", _diag_disk_space),
            ("TLS certificate", lambda: _diag_tls(data_dir)),
            ("Service", lambda: _diag_service(unit)),
            ("Automatic security updates", _diag_auto_updates))
    checks = []
    for name, fn in plan:
        res = _diag_guarded(fn)
        if res is not None:
            checks.append({"name": name, "level": res[0], "detail": res[1]})
    levels = [c["level"] for c in checks]
    summary = "fail" if "fail" in levels else ("warn" if "warn" in levels else "ok")
    return {"checks": checks, "summary": summary,
            "ok": levels.count("ok"), "warn": levels.count("warn"),
            "fail": levels.count("fail")}


# ─── Root-owned pieces vs the commit they belong to (R9, R27) ──────────
# install.sh installs these three ROOT-OWNED, outside the checkout, and only install.sh run as
# root refreshes them. Compared by git blob id, computed here in Python (the files are read, never
# executed), against one `git ls-tree HEAD`.
_ROOT_PIECES = (("panel-helper", "tools/panel-helper"), ("install.sh", "install.sh"),
                ("db_maintenance.py", "db_maintenance.py"))
_ROOT_PIECE_MAX = 16 * 1024 * 1024
_root_pieces_cache = {"at": 0.0, "res": None}
_ROOT_PIECES_TTL = 60


def _root_dir():
    return os.path.dirname(_priv.HELPER_PATH)


def _git_blob_id(path):
    """git's blob id for the file at `path` (sha1 over 'blob <size>\\0' + content).

    sha1 because that is git's object id, compared with git's own; not a security decision."""
    import hashlib
    with open(path, "rb") as fh:
        data = fh.read(_ROOT_PIECE_MAX + 1)
    if len(data) > _ROOT_PIECE_MAX:
        raise OSError("too large to compare")
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()  # nosec B324


def _installed_blob(path):
    """('ok', blob) | ('missing', None) | ('unreadable', None) for one root-owned file."""
    try:
        return "ok", _git_blob_id(path)
    except FileNotFoundError:
        return "missing", None
    except OSError:
        return "unreadable", None


def _head_blobs():
    """{repo path: blob id} at HEAD for the three pieces, from ONE `git ls-tree`; None if it failed."""
    out, _, rc = _git(["ls-tree", "HEAD", "--"] + [rel for _n, rel in _ROOT_PIECES], timeout=5)
    if rc != 0:
        return None
    blobs = {}
    for line in (out or "").splitlines():
        meta, _, rel = line.partition("\t")
        parts = meta.split()
        if len(parts) == 3 and parts[1] == "blob":
            blobs[rel] = parts[2]
    return blobs


def _piece_state(installed, head_blob):
    kind, blob = installed
    if kind != "ok":
        return kind
    if head_blob is None:
        return "unknown"
    return "same" if blob == head_blob else "differs"


def root_piece_state(force=False):
    """{name: {"state": same|differs|missing|unreadable|unknown, "blob", "head_blob", "rel"}}.

    'unreadable' is a file the panel account may not read: never reported as 'differs'. Cached
    for _ROOT_PIECES_TTL so the Diagnostics check and the report's Install section share one
    read."""
    now = time.time()
    if not force and _root_pieces_cache["res"] is not None and \
            (now - _root_pieces_cache["at"]) < _ROOT_PIECES_TTL:
        return _root_pieces_cache["res"]
    head = _head_blobs()
    res = {}
    for name, rel in _ROOT_PIECES:
        installed = _installed_blob(os.path.join(_root_dir(), name))
        head_blob = (head or {}).get(rel)
        res[name] = {"state": _piece_state(installed, head_blob), "blob": installed[1],
                     "head_blob": head_blob, "rel": rel}
    _root_pieces_cache.update(at=now, res=res)
    return res


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


# An address: a run of [\w.+-] (the local part), "@", a [\w-] label, ".", then [\w.-] to its end.
_EMAIL_LOCAL_RE = re.compile(r"[\w.+-]+")
_EMAIL_DOMAIN_RE = re.compile(r"@[\w-]+\.[\w.-]+")


def _redact_emails(text):
    r"""`text` with every email address replaced by [email], in one pass.

    Exactly what re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "[email]", text) returns. That sub tried
    a match at every character of a run with no "@" after it, and read the run to its end from
    each one: a 20,000-character token — a base64 blob in the log tail — took 1.2s, and one twice
    as long four times that. A match can only begin where the search resumes or at the start of a
    run, since every character of a run reaches the same "@", so taking each run whole and
    looking at what follows it finds the same addresses at the same places."""
    out, done, pos = [], 0, 0
    while True:
        run = _EMAIL_LOCAL_RE.search(text, pos)
        if run is None:
            break
        dom = _EMAIL_DOMAIN_RE.match(text, run.end())
        if dom is None:
            pos = run.end()
            continue
        out.append(text[done:run.start()])
        out.append("[email]")
        done = pos = dom.end()
    out.append(text[done:])
    return "".join(out)


def _redact(text):
    """Best-effort scrub of anything secret-looking from free text (a log tail). The
    report is whitelist-built so this is defence-in-depth: emails, long token/key/hash
    strings, and key=value secrets get masked before an admin reviews + shares it."""
    text = _redact_emails(text)
    # key=value / key: value where the key name contains a secret-ish word (incl.
    # prefixed forms like auth_token, access_key) — redact the value, keep the key.
    text = re.sub(r"(?i)\b([\w-]*(?:password|passwd|secret|token|api[_-]?key|auth[_-]?key|"
                  r"cred(?:ential)?|cookie|bearer)[\w-]*)(\s*[=:]\s*)\S+", r"\1\2[redacted]", text)
    text = re.sub(r"\b[A-Za-z0-9+/_-]{28,}={0,2}\b", "[redacted]", text)
    return text


# A journal line's syslog 'time host proc[pid]:' prefix. `\S+\s[^:]+:` where this had
# `\S+\s+[^:]+:`: the two match the same prefixes — `[^:]` takes blanks too, so "one or more
# blanks, then one or more non-colons" is just "a blank, then one or more non-colons" — but with
# `\s+` beside `[^:]+`, a line with no colon after a long run of blanks was re-split at every
# blank of the run before it could fail.
_JOURNAL_PREFIX_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+\S+\s[^:]+:\s?")


def _dedupe_log_tracebacks(text):
    """Collapse repeated identical Python tracebacks in a journal tail so one recurring
    error (e.g. an internet scanner tripping the panel's self-signed TLS cert) doesn't
    crowd out everything else in a debug report. The FIRST full occurrence of each
    distinct traceback is kept; later identical ones are replaced with a one-line note.
    The dedup signature ignores the syslog 'time host proc[pid]:' prefix, so the same
    traceback logged at different times still matches."""

    def body(ln):
        return _JOURNAL_PREFIX_RE.sub("", ln)

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
        # (?::\d+)? as in _repo_slug: ssh://git@ssh.github.com:443/o/r linked to github.com/443/o.
        m = (re.search(r"github\.com(?::\d+)?[:/]([^/\s]+/[^/\s.]+)", out.strip())
             if rc == 0 else None)
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
        elif upd.get("outcome") == "failed":
            # Stopped with an error and no health-check rollback: before the panel was stopped
            # (the source unreachable, a pin that cannot be verified), or inside the stopped
            # window, whose handler puts the old code back. Either used to read "unknown (in
            # progress…)" for good. The reason is log text, so it is redacted like the log tail.
            u_outcome = _redact("FAILED — the installer stopped (exit %s): %s" % (
                upd.get("exit_code"), upd.get("reason") or "see the log below"))
        elif upd.get("outcome") == "held":
            u_outcome = _redact("NOT UPDATED — %s" % upd.get("reason"))
        elif upd.get("outcome") == "current":
            u_outcome = _redact("nothing to install — %s" % upd.get("reason"))
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
