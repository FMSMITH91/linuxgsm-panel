"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import re
import subprocess  # nosec B404 - every call site below passes an argv LIST, never a shell string
from panel.core import terminal
import time
from panel.security import privileged as _priv
from panel.ops.ssh_manager import (_core, files)  # noqa: E402,F401  (module objects: the
# reference resolves at CALL time, which is what keeps a stub on the definition site
# visible to every caller — see the package docstring.





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

# Said when the runner could not be written, so nothing was scheduled. Worded to state both halves
# — what failed AND that the crontab is untouched — because the old behaviour said "Added" and the
# operator's next move was to wait for a job that could never fire.
_RUNNER_FAILED = ("Couldn't install the job recorder on the host — nothing was scheduled. "
                  "Check that the host is reachable and that ~/.lgsm-cron isn't a file.")


def _cron_job_id(command):
    import hashlib
    return hashlib.sha256((command or "").encode("utf-8", "replace")).hexdigest()[:12]


def _install_cron_runner(server, user):
    """Install the per-user cron wrapper script (idempotent). Runs AS THE GAME USER (like the
    file manager) — never as root — so it can only ever touch that user's own home. Writing
    the runner as root could be redirected through a symlink a compromised game process
    planted in ~/.lgsm-cron; dropping to the user removes that escalation.

    Returns the rc. It used to be discarded, and that rc is the only thing that says whether the
    script the crontab line is about to point at actually exists: if ~/.lgsm-cron is already a
    regular file the `mkdir -p` fails and the `&&` chain writes nothing, and the tailscale/local
    transports answer a timeout with ("", "…", -1) rather than raising. Either way the crontab
    was then rewritten to call a script that is not there, the panel said "Added", and the job
    never ran — indistinguishable in the card from one that simply has not fired yet, because
    Last run reads the .status file the missing runner never writes."""
    import base64
    b64 = base64.b64encode(_CRON_RUNNER_SCRIPT.encode()).decode()
    # Absolute path (not ~) — `sudo -u` doesn't reliably set $HOME, and the game user's home
    # is /home/<user> by construction (useradd -m). Cron itself sets $HOME correctly when it
    # later runs the script, so the runner's own $HOME use resolves to the same dir.
    d = "/home/%s/.lgsm-cron" % user
    inner = ('mkdir -p {d} && chmod 700 {d} && '
             'printf %s {b} | base64 -d > {d}/run && chmod 700 {d}/run'
             ).format(d=_core._quote(d), b=_core._quote(b64))
    _out, _err, rc = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(inner)}",
                                       timeout=15, sudo=False)
    return rc


def _escape_cron_percent(cmd):
    r"""`\%` for every unescaped `%`. cron reads a bare `%` as "end of command, stdin follows"."""
    return re.sub(r"(?<!\\)%", r"\\%", cmd or "")


def _unescape_cron_percent(cmd):
    """The inverse, for DISPLAY: what cron will actually deliver to the shell."""
    return (cmd or "").replace("\\%", "%")


# A plain command — a path plus simple args, with no shell operators, quotes, or cron-special `%`. Such
# a command is safe to keep VISIBLE via the inline recorder, so the Autostart detection (which greps
# the raw crontab for `<base> monitor`) still finds it after the admin reschedules it here.
_SIMPLE_CMD_RE = re.compile(r"^[\w./ @:+=,-]+\Z")


def _wrap_cron_command(server, user, command):
    """Return the crontab command that records `command`'s runs. Toggle-backed and plain commands are
    kept VISIBLE (inline recorder) so the Autostart / daily-restart detection still works after a
    reschedule; anything with `%`, quotes, or shell operators uses the base64 runner (robust, no
    escaping needed).

    Returns None when the base64 runner could not be installed on the host — the caller must
    refuse rather than schedule a line pointing at a script that is not there. The two visible
    forms need nothing installed, so they can never fail here."""
    cmd = (command or "").strip()
    # ORDER MATTERS, and it was the other way round. The panel's OWN daily-restart line is
    # `touch /home/<u>/.restart-pending` — a plain command, which set_daily_restart writes WRAPPED
    # via the inline recorder. list_cron_jobs unwraps it for display, and rescheduling it in the
    # generic editor sent that display form back through here, where the .restart-pending branch
    # returned it bare: the panel's own line silently stopped reporting last-run and success after
    # any edit. Checked second, the branch now only catches a command the recorder cannot take.
    if _SIMPLE_CMD_RE.match(cmd):
        return _record_managed_cmd(user, cmd)   # plain command (incl. `<base> monitor`): visible + tracked
    if ".restart-pending" in cmd:
        # Kept VERBATIM because the daily-restart detection greps the raw crontab for this, and
        # wrapping a compound command in the inline recorder would move its redirect and its exit
        # status onto only the last statement. But verbatim is not the same as unescaped: this
        # branch ran BEFORE the base64 runner, which is the thing that makes `%` safe, and
        # _validate_cron permits `%`. cron truncates a line at the first unescaped `%` and feeds
        # the remainder in as stdin, so `… restart >> ~/log/r-%Y.log` quietly became
        # `… restart >> ~/log/r-` while the panel's editor showed the whole thing back.
        return _escape_cron_percent(cmd)
    import base64
    if _install_cron_runner(server, user) != 0:
        return None
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
        return _unescape_cron_percent(m2.group(1).strip()), m2.group(2)
    # Unwrapped: a legacy line, or one this module wrote verbatim. `\%` in a crontab IS an escaped
    # percent, so showing it as `%` is showing what cron will hand the shell — and it is what has
    # to come back from the editor for a round-trip through _escape_cron_percent to be a no-op.
    return _unescape_cron_percent(command), None


# Rendering a failed job's captured output into ONE readable line. LinuxGSM paints its console
# with ANSI colour and appends its verdict as a separate " ... FAIL" line, so a blind last-N-lines
# tail shows escape soup whose informative line ("curl: (22) ... 404") may not even be in it.
# A line that is ONLY a verdict token: no information once the panel already knows the job failed.
_CRON_VERDICT_RE = re.compile(r"^[.\s]*(OK|FAIL|ERROR|SKIP|UPDATE|WARNING|INFO|CANCELED)[.\s]*$", re.I)
_CRON_WHY_RE = re.compile(r"fail|error|cannot|can't|denied|refus|timed? ?out|no such|not found|"
                          r"missing|unable|invalid|permission|traceback|curl: \(|wget:", re.I)


def _cron_log_text(b64):
    """Decode the base64 log tail the reader ships. Base64 is what keeps the tab-delimited wire
    format intact: a game log is arbitrary bytes, and LinuxGSM's `\\r` repaints alone would end a
    record early — the text=True transports fold `\\r` into `\\n`, and str.splitlines() splits on it
    — taking the failure reason with them. Lenient at both steps: whatever the game server printed
    is not necessarily valid UTF-8, and a log we cannot decode must not cost us the other jobs."""
    import base64 as _b64
    import binascii
    try:
        return _b64.b64decode(b64 or "", validate=False).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return ""


def _clean_cron_error(raw, limit=240):
    """One-line summary of WHY a job failed, from its decoded log tail. Strips ANSI, honours `\\r`
    redraws (only a line's final repaint is what a terminal shows), drops bare " ... FAIL" verdict
    lines, then keeps the last few DISTINCT lines that say something — the fatal one comes last, and
    LinuxGSM's fetch retry prints the SAME reason once per mirror, which would otherwise spend the
    whole budget on one sentence. Fills from the newest line back in whole lines, never mid-word."""
    lines = []
    for chunk in (raw or "").split("\n"):
        seg = " ".join(terminal.render_line(chunk).split())
        if seg and not _CRON_VERDICT_RE.match(seg):
            lines.append(seg)
    why = [ln for ln in lines if _CRON_WHY_RE.search(ln)] or lines
    keep = []                                    # last 3 DISTINCT lines, chronological
    for ln in reversed(why):
        if ln not in keep:
            keep.insert(0, ln)
        if len(keep) == 3:
            break
    out = ""
    for ln in reversed(keep):                    # newest first, so it always makes the cut
        nxt = ln if not out else ln + " " + out
        if len(nxt) > limit:
            break
        out = nxt
    return out or (keep[-1][:limit] if keep else "")


def _read_cron_status(server, user):
    """{job_id: {last_run(epoch), ok(bool), error(str), rc(int)}} from the recorder's status
    files for `user`. Runs AS THE GAME USER so reading a job's log can't be redirected through
    a symlink to a root-only file (info leak) — it only ever reads that user's own files. One
    shell round-trip; best-effort (empty on any error)."""
    d = "/home/%s/.lgsm-cron" % user
    # The log tail is base64'd so NOTHING in it can break the tab-delimited protocol — a game log
    # carries \r repaints, stray control bytes and invalid UTF-8, any of which would otherwise end
    # the record early (or fail the transport's strict decode) and cost us the failure reason. Cap
    # the bytes BEFORE encoding so the reply stays bounded; single line per job, so split on \n.
    inner = (f'cd {_core._quote(d)} 2>/dev/null || exit 0; '
             'for s in *.status; do [ -e "$s" ] || continue; id="${s%.status}"; '
             'read rc st en < "$s" 2>/dev/null; err=""; '
             '[ "$rc" != "0" ] && err="$(tail -n 40 "$id.log" 2>/dev/null | tail -c 3000 '
             '| base64 | tr -d "\\n")"; '
             'printf "%s\\t%s\\t%s\\t%s\\t%s\\n" "$id" "$rc" "$st" "$en" "$err"; done')
    out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(inner)}", timeout=12, sudo=False)
    status = {}
    for line in (out or "").split("\n"):
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        jid, rc, en = parts[0], parts[1], parts[3]
        err = parts[4] if len(parts) > 4 else ""
        try:
            status[jid] = {"last_run": int(en), "ok": rc == "0", "rc": int(rc),
                           "error": _clean_cron_error(_cron_log_text(err))}
        except ValueError:
            continue
    return status


def _read_cron_run_times(server, user):
    """{command_string: last_run_epoch} from cron's OWN execution log (journald), so that
    panel-managed and legacy entries — which the recorder doesn't wrap — still show WHEN they
    last ran. Cron logs the command it ran but not its exit status, so this is time-only.
    Best-effort (empty if cron logging is off/unavailable)."""
    # Was `journalctl _COMM=cron … | grep -F '(<user>) CMD ' | tail -n 800` — the user name went
    # into a grep pattern running as root. The verb reads the window; the filtering is here.
    out, _, _ = _core.run_privileged(server, "journal-cron", [], timeout=12, merge_stderr=False)
    marker = "(%s) CMD " % user
    # Over-long lines are skipped before anything else looks at them. The journal is the remote's
    # to write, and this runs on the request greenlet: the regex that used to pull the command out
    # (`\)\s+CMD\s+\((.*)\)\s*$`) is quadratic on a line of repeated ") CMD (" fragments with
    # no closing parenthesis, so one hostile line froze the whole panel — every user and host —
    # until it finished. A crontab command is a few hundred bytes; nothing real is lost.
    out = "\n".join([ln for ln in (out or "").splitlines()
                     if marker in ln and len(ln) <= _MAX_CRON_LOG_LINE][-800:])
    times = {}
    for line in (out or "").splitlines():
        cmd = _cron_log_command(line, marker)
        if cmd is None:
            continue
        try:
            epoch = int(float(line.split(None, 1)[0]))
        except (ValueError, IndexError):
            continue
        times[cmd] = epoch   # chronological log → last occurrence wins
    return times


# A cron command line is a few hundred bytes; a journal line longer than this is not one.
_MAX_CRON_LOG_LINE = 4096


def _cron_log_command(line, marker):
    """The command in a cron journal line `<epoch> ... (<user>) CMD (<command>)`, or None.

    Plain string search, not a regex: find the marker, expect "(", and take everything up to the
    line's final ")". Linear in the line's length whatever the line contains."""
    i = line.find(marker)
    if i < 0:
        return None
    rest = line[i + len(marker):].strip()
    if len(rest) < 2 or rest[0] != "(" or rest[-1] != ")":
        return None
    return rest[1:-1].strip()


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
    out, _, _ = _core.run_privileged(server, "crontab-list", [user], timeout=10, merge_stderr=False)
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
    ok, _ = _core._rewrite_crontab(server, user, "-vE '^'", new_lines)
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


# What `crontab -u X -l` says, measured on a live host:
#
#   rc 0                                          the crontab was read (empty or not)
#   rc 1  stderr "no crontab for X"               the account genuinely has none
#   rc 1  stderr "crontab:  user `X\' unknown"     no such account
#   rc -1                                         the transport failed — an unreachable host
#                                                 answers ("", "...", -1), it does not raise
#
# Only the first two are ANSWERS. The message match is the one locale-dependent part, and it
# fails in the SAFE direction: a host whose cron speaks another language reports "couldn't read"
# for an account with no crontab, which is a worse page and not a wrong write.
_NO_CRONTAB_RE = re.compile(r"no crontab for", re.I)


def list_cron_jobs(server, user, selfname=None):
    """Read the game user's crontab as a list of jobs, or None if it could not be READ.

    Comment/blank lines are skipped. Each job: {raw, schedule, command, managed, last_run, ok,
    error}. `raw` is the exact line (identity for edit/delete); `command` is the un-wrapped,
    human-readable form. Run history comes from the recorder for user-added jobs (time + ok/error)
    and from cron's own log for managed/legacy jobs (time only — ok stays None, cron doesn't log
    exit status).

    None, NOT []. The rc was discarded here, so a host that did not answer produced "" and parsed
    to an empty list — indistinguishable from a user with no jobs. Two things acted on that:
    the page said "No scheduled tasks yet.", and _sync_toggles_from_cron treats the crontab as the
    source of truth for the Autostart and Daily-restart switches, so it saw both lines "gone" and
    turned both columns OFF. Merely OPENING Files & Config for a server whose host was briefly
    unreachable silently disabled its autostart — verified in a rendered panel: seeded with
    autostart=1, one page load, column 0, crontab on the host untouched. Nothing turns it back on,
    because the reconcile only ever mirrors what it read."""
    selfname = selfname or user
    out, err, rc = _core.run_privileged(server, "crontab-list", [user], timeout=10, merge_stderr=False)
    if rc != 0 and not _NO_CRONTAB_RE.search("%s\n%s" % (err or "", out or "")):
        return None
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
    out, err, rc = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(inner)}",
                                     timeout=15, sudo=False)
    # The job itself is DETACHED, so this rc says nothing about how the job ends — that lands in
    # the .status file and shows up under Last run. What it DOES say is whether the launch
    # happened at all. Discarding it meant an unreachable host, a refused sudo or a missing
    # directory all answered "Started — the result will appear under Last run shortly", with an
    # audit row recording success, for a job that was never started and whose Last run therefore
    # never changes. run_command does not raise for those, so the route's except never saw it.
    if rc != 0:
        return False, ((err or out or "Couldn't start the job on the host").replace("\n", " ")[:200])
    return True, "Started — the result will appear under Last run shortly."


def add_cron_job(server, user, schedule, command, selfname=None):
    """Append a new cron entry to the game user's crontab (keeps all existing lines). The
    command is wrapped through the recorder so its runs are tracked."""
    ok, msg, _line = _validate_cron(schedule, command)
    if not ok:
        return False, msg
    schedule = " ".join(schedule.split())
    wrapped = _wrap_cron_command(server, user, command)
    # The runner write is what makes this line runnable; scheduling it anyway produced a crontab
    # entry that mails "No such file or directory" to a mailbox nobody reads, while the panel
    # reported "Added" with a success audit row. Refuse instead — nothing has been written yet.
    if wrapped is None:
        return False, _RUNNER_FAILED
    return _core._rewrite_crontab(server, user, "", [f"{schedule} {wrapped}"])


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
    # Same as add_cron_job: refuse BEFORE the rewrite, which here also protects the existing line
    # — the old entry would otherwise be dropped and replaced by one that cannot run.
    if wrapped is None:
        return False, _RUNNER_FAILED
    # -vxF: drop the line that exactly (whole-line, fixed-string) matches old_raw,
    # keep everything else, then append the rewritten (recorder-wrapped) entry.
    return _core._rewrite_crontab(server, user, "", [f"{schedule} {wrapped}"],
                                  drop_line=old_raw)


def delete_cron_job(server, user, old_raw, selfname=None):
    """Remove a user cron entry (matched exactly by `old_raw`). Refuses to remove a
    panel-managed line."""
    selfname = selfname or user
    old_raw = old_raw or ""
    if _cron_line_managed(old_raw, user, selfname):
        return False, "That entry is managed by the panel — use its own toggle to change it."
    return _core._rewrite_crontab(server, user, "", [], drop_line=old_raw)


# Printed LAST by the backup listing, so an answer that was cut short is not read as "none".
_BACKUP_LIST_DONE = "__LGSMP_BK_DONE__"


def list_game_backups(server, user):
    """A game server's LinuxGSM backups (~/lgsm/backup/*.tar.*): [{name, size, created}],
    newest first. Read as the game user; best-effort (empty on error). LinuxGSM compresses with
    zstd when available (.tar.zst), else gzip (.tar.gz) — match all archive types like LinuxGSM's
    own tooling does, not just .tar.gz.

    Returns None if the host could not be READ, which is not the same as a server with no backups.
    Both used to come back as [], and the Backups card said "No backups yet." about a directory it
    had never reached. Every caller has to choose: the two that size a new backup treat unknown as
    "no estimate" (they already did), and the one that DELETES to make room must not act on it."""
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
           '2>/dev/null | head -1; printf "%%s\\n" ' + _BACKUP_LIST_DONE) % (bdir, user)
    out, _, rc = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(cmd)}", timeout=20, sudo=False)
    # A host that did not answer prints nothing, and so does a server with no backups yet.
    # rc is what tells them apart, and it was discarded. The SENTINEL is the other half, the
    # same shape _looks_installed uses: `cmd` ends in a pipeline through `head`, which exits 0
    # whatever happened before it, so rc alone cannot see a run that was cut short.
    if rc != 0 or _BACKUP_LIST_DONE not in (out or ""):
        return None
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
    _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(cmd)}", timeout=30, sudo=False)


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
    out, _, _ = _core.run_command(server, "df -PB1 %s" % _core._quote("/home/%s" % user), timeout=15, sudo=False)
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
_GAME_BACKUP_NAME = re.compile(r"^[A-Za-z0-9._-]+\.tar\.[A-Za-z0-9.]+\Z")


def delete_game_backup(server, user, name):
    """Delete one game backup by file name from ~/lgsm/backup/, as the game user. Returns True on
    success. `name` is shape-validated here; the caller validates it against the actual listing."""
    if not _GAME_BACKUP_NAME.match(name or ""):
        return False
    path = "/home/%s/lgsm/backup/%s" % (user, name)
    _, _, rc = _core.run_command(server, f"sudo -u {user} rm -f -- {_core._quote(path)}", timeout=30, sudo=False)
    return rc == 0


def _as_user_argv(user, *args):
    """`sudo -u <user> <args…>` — the pre-helper fallback for reading a game user's own files.

    ONE call site on purpose. The unit suite counts direct ["sudo", …] argv sites as the measure of
    how far /etc/sudoers.d/linuxgsm-panel is from narrowing to the helper alone, and that count is a
    ratchet that may fall and never rise. The backup download and both download shapes of the file
    browser want the same escalation, so they share this rather than each growing another site.

    Only reached where `helper_present()` is False, which is also where the grant is still
    NOPASSWD:ALL — so this permits nothing the host does not already permit.
    """
    return ["sudo", "-u", user] + list(args)


def stream_game_backup(server, user, name, chunk=262144):
    """Yield the bytes of ~/lgsm/backup/<name> as the game user, for a browser download. Works for
    local, paramiko and Tailscale-CLI remotes. `name` MUST already be validated by the caller
    (checked against the real backup list); we also re-check its shape here. Uses the (green,
    eventlet-patched) subprocess/paramiko IO so a multi-GB download doesn't block the event hub."""
    if not _GAME_BACKUP_NAME.match(name or ""):
        return
    path = "/home/%s/lgsm/backup/%s" % (user, name)

    if _core.is_local_server(server) or getattr(server, "auth_method", "") == "tailscale":
        if _core.is_local_server(server):
            # Was `sudo -u <user> cat <path>`. The verb keeps the property that mattered — the read
            # happens AS THE GAME USER, so a symlink planted at that path reaches only what that
            # user could already read. The helper drops supplementary groups, gid then uid before
            # opening; reading as root would have turned this into "hand me any file on the box".
            argv = (_priv.helper_argv("game-backup-read", [user, name])
                    if _core.helper_present() else _as_user_argv(user, "cat", path))
        else:
            host = _core._resolve_ts_host(server)
            argv = ["ssh", "-T", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
                    "-p", str(server.port or 22), f"{server.username}@{host}",
                    f"sudo -u {user} cat {_core._quote(path)}"]
        p = subprocess.Popen(argv, stdout=subprocess.PIPE)  # nosec B603  # nosemgrep - argv list, no shell; the remote path is _quote()d above
        try:
            while True:
                b = p.stdout.read(chunk)
                if not b:
                    break
                yield b
        finally:
            try:
                p.stdout.close()
            except Exception:  # nosec B110 - the pipe is already closed when the child exited
                pass           # first; closing it twice is the normal path, not a failure.
            p.wait()
        return

    # paramiko remote
    client = _core.get_connection(server)
    _in, out, _err = client.exec_command(f"sudo -u {user} cat {_core._quote(path)}")
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
        backups = list_game_backups(server, user)   # newest first, or None if unreadable
        if backups is None:
            # This function DELETES backups. A listing that could not be read tells us
            # nothing about what is on the host, and "nothing to prune" is the only safe
            # reading — the same stance the `total > 0` disk check below takes, for the
            # same reason, and that one was a bug here once already.
            return ""
        if not backups:
            return ""   # first backup — nothing to prune; let LinuxGSM/disk decide
        # Estimate the next backup from the LARGEST existing one (worst case), ignoring 0-byte
        # failed archives — the newest can be tiny or empty and badly underestimate the need.
        est = max((b.get("size", 0) for b in backups), default=0)
        _disk = backup_disk_info(server, user)
        free, total = _disk.get("free", 0), _disk.get("total", 0)
        # `total` is the sentinel, exactly as run_game_backup's pre-flight check uses it: a failed
        # `df` reads as 0/0, and free=0 is always below any threshold — so a transport hiccup sent
        # this straight into the delete loop and removed backups to make room it never measured.
        # Measured on the test host: with df working, nothing was deleted; with the df read timed
        # out, two of four backups were deleted and the run reported "freed space first".
        #
        # The sibling 100 lines away already says the rule out loud — "Only enforce when we
        # actually read the disk (total > 0); a failed df reads as 0/0" — but it guards the path
        # that BLOCKS a backup. This is the path that DELETES them, which is the worse of the two
        # to get wrong, and it is the one that was missing the check.
        if not est or not total or free >= int(est * 1.15):
            return ""   # plenty of room, or we could not measure — keep full safety
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
            _core._log.info("freed disk before backing up %s: removed %d old backup(s)", user, deleted)
            return "freed space first (removed %d old backup%s)" % (deleted, "" if deleted == 1 else "s")
    except Exception:
        _core._log.debug("backup headroom check failed", exc_info=True)
    return ""


def _gamedig_type(game_type, query_type=None):
    """The gamedig `--type` to use for a server: an explicit per-server override when set (the
    panel's GAMEDIG_TYPE map is only a default and can be wrong/missing, e.g. cod), else the map.
    The override is sanitised to a safe charset here too, so it can never break out of the query
    command regardless of upstream validation. Returns '' when the game isn't queryable."""
    qt = re.sub(r"[^a-z0-9_-]", "", (query_type or "").strip().lower())[:40]
    return qt or _core.GAMEDIG_TYPE.get(game_type or "", "")


def player_count(server, user, game_type=None, port=None, query_type=None):
    """Best-effort CURRENT player count for a running instance, via gamedig (the same
    tool the empty-only daily restart uses). Returns an int, or None when the game
    isn't queryable (no gamedig type / no port) or the query fails — callers treat
    None as 'unknown' and don't block on it. gamedig is a bare command on PATH exactly
    as the restart cron invokes it (installed globally via npm at setup)."""
    gdtype = _gamedig_type(game_type, query_type)
    if not gdtype or not port:
        return None
    # `{c, ok}`, not a bare `.players|length` — and `ok` is the whole point. gamedig writes its
    # FAILURE as a JSON object on stdout ({"error":"Failed all 1 attempts"}), `.players` is then
    # null, and **jq reports the length of null as 0**. So the old filter turned every failed
    # query into a confident "0 players", which is the one answer this function must never invent:
    # mod_restart_decision, _host_idle_state and the reboot-when-empty poller all read 0 as
    # "nobody is on, it is safe to act", and a stopped, firewalled or GSLT-less server produces it
    # just as readily as an empty one.
    #
    # player_slots twenty lines below has carried this guard from the start, and its comment says
    # exactly this ("a FAILED query reads as '0 players'"). This function simply never got it.
    jqf = '{c:(.players|length), ok:(.players|type=="array")}'
    cmd = (f"gamedig --type {gdtype} {_core._gamedig_host(server)}:{int(port)} 2>/dev/null "
           f"| jq -c {_core._quote(jqf)} 2>/dev/null")
    try:
        out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(cmd)}", timeout=25, sudo=False)
    except Exception:
        return None
    line = (out or "").strip().splitlines()[-1].strip() if (out or "").strip() else ""
    if not line:
        return None
    try:
        import json as _json
        d = _json.loads(line)
    except (ValueError, TypeError):
        return None
    if not (isinstance(d, dict) and d.get("ok")):
        return None      # gamedig could not read the server — unknown, NOT zero
    return d.get("c") if isinstance(d.get("c"), int) else None


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
    cmd = (f"gamedig --type {gdtype} {_core._gamedig_host(server)}:{int(port)} 2>/dev/null "
           f"| jq -c {_core._quote(jqf)} 2>/dev/null")
    try:
        out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(cmd)}", timeout=25, sudo=False)
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


_game_map_cache = _core.register_remote_cache({})   # {(remote_id, port): (expiry, mapname)}
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
    cmd = (f"gamedig --type {gdtype} {_core._gamedig_host(server)}:{int(port)} 2>/dev/null "
           f"| jq -r '.map // \"\"' 2>/dev/null")
    val = ""
    try:
        out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(cmd)}", timeout=25, sudo=False)
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
        vals = files.lgsm_get_values(server, user, selfname, ["querymode", "querytype", "queryport", "port"])
    except Exception:
        return None
    if vals is None:
        return None      # the config could not be read — unknown, and unknown is not "0 players"
    if (vals.get("querymode") or "").strip() != "2":   # only the gamedig querymode is handled here
        return None
    qtype = re.sub(r"[^A-Za-z0-9_-]", "", (vals.get("querytype") or "").strip())[:40]
    qport = ((vals.get("queryport") or "").strip() or (vals.get("port") or "").strip()
             or str(fallback_port or "").strip())
    if not qtype or not qport.isdecimal():
        return None
    # The `ok` key, for the third time in this file. gamedig writes its FAILURE to stdout as a JSON
    # object -- {"error":"Failed all 1 attempts"} -- so `.players` is null, and jq reports the
    # length of null as 0. A bare `.players|length` therefore turns every dropped query into a
    # confident "0 players": measured, `echo '{"error":"..."}' | jq -r '.players|length'` prints 0
    # with rc 0. That is the one answer this function must never invent, and its own docstring
    # promises it does not ("or the query fails. None => 'unknown', which the reboot poller treats
    # as 'don't reboot'"). player_slots has carried this guard from the start and player_count
    # gained it later; this one never got it.
    jqf = '{c:(.players|length), ok:(.players|type=="array")}'
    cmd = ("gamedig --type %s %s:%d 2>/dev/null | jq -c %s 2>/dev/null"
           % (qtype, _core._gamedig_host(server), int(qport), _core._quote(jqf)))
    try:
        out, _, _ = _core.run_command(server, "sudo -u %s bash -c %s" % (user, _core._quote(cmd)), timeout=25, sudo=False)
    except Exception:
        return None
    line = (out or "").strip().splitlines()[-1].strip() if (out or "").strip() else ""
    if not line:
        return None
    try:
        import json as _json
        d = _json.loads(line)
    except (ValueError, TypeError):
        return None
    if not (isinstance(d, dict) and d.get("ok")):
        return None      # gamedig could not read the server — unknown, NOT zero
    return d.get("c") if isinstance(d.get("c"), int) else None
