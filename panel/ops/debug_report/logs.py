"""Debug-report sections: journal_digest (R71) and recent_log (R68, R69, R70, R73).

Owner: builder B1. Both read the report's ONE journal read (_src_journal, up to 5000 lines): the
digest summarises all of it, the recent log prints the newest 400 lines within a budget. That read
is the panel's own output where journald can filter it (the sudo/pam lines every privileged call
writes are left out BEFORE the line limit, so the window is not spent on them); the sudo lines come
from a read of their own, which the digest counts — once — by fixed labels.

Privacy: the recent log's lines go through privacy.scrub_lines BEFORE anything is selected or
budgeted; the digest normalises first (syslog prefix stripped, digits folded) and scrubs only the
lines it prints. When the privacy pass fails, the text is withheld, never printed pattern-free.
"""
import os
import re
import threading
import time

from panel.ops.debug_report import _src_journal, privacy
from panel.ops.debug_report._base import Result, cut_words

DIGEST_LINES = 5000
TAIL_LINES = 400
LOG_BUDGET = 30000          # characters of log body the recent log may print
_QUOTE_MAX = 100

_PREFIX_RE = re.compile(r"^([A-Z][a-z]{2}[ \t]+\d{1,2}[ \t]+[\d:]{5,8})[ \t]+\S+[ \t][^:\n]{1,200}:[ \t]?")
_PID_RE = re.compile(r"^[A-Z][a-z]{2}[ \t]+\d{1,2}[ \t]+[\d:]{5,8}[ \t]+\S+[ \t][^:\[\n]{1,100}\[(\d{1,10})\]:")
_DIGITS_RE = re.compile(r"\d+")
_EXC_RE = re.compile(r"([A-Za-z_][\w.]{0,120})(?::|$)")
_LEVEL_RE = re.compile(r"^(CRITICAL|ERROR|WARNING) ")
_START_MARK = "LinuxGSM Panel starting on"
_PRIORITY_RE = re.compile(r"Traceback|Error|ERROR|WARNING|CRITICAL|Exception|[Ff]ailed|"
                          r"Main process exited|oom-kill|Out of memory|" + _START_MARK)
# The panel's own privileged calls. On a system install every helper call writes three journal
# lines -- sudo's COMMAND line and pam_unix's session opened/closed -- about three calls a minute,
# so the 400-line tail was nothing else: on the test VPS, 1,666 calls in a 5,000-line read, and
# every "most repeated" line was one of them. They are counted by helper verb and left out of the
# log and the digest's repeats. A REFUSED sudo is the opposite of noise and stays in both.
_PAM_SESSION_RE = re.compile(r"^pam_unix\((?:sudo|sudo-i|runuser|runuser-l|su|su-l):session\): "
                             r"session (?:opened|closed) for user ")
# Spacing differs by implementation: sudo-rs writes 'user :  PWD=...' (two blanks after the
# colon, and a trailing blank); sudo.ws ' user : PWD=...'. sudo-rs logs no line for a refusal.
# Groups: the target account (USER=), the program, and the rest of the command line (first line
# only: classic sudo continues a long one on '(command continued)' lines of its own).
_SUDO_CMD_RE = re.compile(r" :[ \t]{1,4}(?:TTY=[^;\n]{1,64};[ \t]{1,4})?PWD=[^;\n]{0,512};[ \t]{1,4}"
                          r"USER=([^;\n]{1,64});[ \t]{1,4}COMMAND=(\S{1,512})(?: ([^\n]{0,2048}))?")
_SUDO_CONTINUED_RE = re.compile(r"^[ \t]*\S{1,64} :[ \t]{1,4}\(command continued\) ")
# Programs the panel itself runs through sudo as root, named by their basename. Anything else —
# a script an operator ran with sudo in the panel's terminal, which lives in the same unit — is
# 'other program': its name is the operator's, not something to print.
_ROOT_PROGRAMS = frozenset((
    "true", "env", "su", "runuser", "crontab", "rm", "cat", "tee", "ls", "test", "python3",
    "journalctl", "renice", "ufw", "fail2ban-client", "apt-get", "apt", "dpkg", "tailscale",
    "sysctl", "timedatectl", "systemctl", "systemd-run", "install", "chown", "chmod", "mkdir",
    "mv", "cp", "useradd", "userdel", "usermod", "gpasswd", "visudo", "reboot", "git"))
_SHELLS = frozenset(("bash", "sh", "dash"))
# What the panel runs AS a game account, by a fixed fingerprint of the command: (label, tokens that
# must all appear). First match wins. Only these labels are ever printed, never the command.
# The console's tmux bodies come first. Each opens with the panel's own socket lookup
# (ssh_manager._core._tmux_live_socket_sh), and a console send ends with what was typed, which can
# hold any later entry's tokens ("say gamedig jq -r"), so the fixed text has to decide. The send
# was counted as "other": the VPS proof of #393 found 42 of them so.
_TMUX_SOCK = "tmux-$(id -u)"
_GAME_READS = (
    ("console send", (_TMUX_SOCK, " send-keys ")),
    ("console snapshot", (_TMUX_SOCK, " capture-pane ")),
    ("console session check", (_TMUX_SOCK, "echo __LIVE__")),
    ("gamedig map", ("gamedig", "jq -r")),
    ("gamedig player list", ("gamedig", "[.players[]")),
    ("gamedig players", ("gamedig", "players|length")),
    ("gamedig", ("gamedig",)),
    ("console poll", ("S=$(stat -c", "tail -c +")),
    ("console stat", ("stat -c",)),
    ("console read", ("printf B", "tail -c +")),
    ("console window", ("printf B", "tail -")),
    # Three bodies that would otherwise fall to "other" or to "LinuxGSM action" (the version read
    # opens with `cd` and holds `&&`): the backup prune (cron.prune_game_backups), the stale-lock
    # sweep before a backup (game._stale_backup_lock_sweep) and the installed-build read
    # (game._steam_build).
    ("backup prune", ("find -H ", "xargs -0 -r rm -f --")),
    ("backup lock sweep", ("-x tar", "backup.lock")),
    ("installed version", ("appmanifest_", "version_history.json")),
    ("LinuxGSM config", ("cat ", ".cfg")),
    ("LinuxGSM action", ("cd ", "&& ")),
)
_SUDO_REFUSED_RE = re.compile(r"a password is required|NOT in sudoers|not allowed to (?:run|execute)"
                              r"|incorrect password|authentication failure|command not allowed",
                              re.IGNORECASE)
# What systemd logs when it stops the panel's unit and processes inside it do not stop with it:
# another account's processes a user manager may not signal (EPERM), then left behind and found
# again at the next start. On the live host that was every self-update trying to kill game servers
# the panel had started — printed only among the "most repeated lines", with At a glance saying
# one problem. It catches only the case where they SURVIVED: on a system install, or as the
# panel's own account, the kill succeeds and the journal says nothing at all. The Panel process
# section's cgroup listing is the measurement; this is the history.
_CGROUP_KILL_RE = re.compile(r"Failed to kill control group|remains running after unit stopped|"
                             r"Found left-over process")
_SOURCE_LABEL = {"user-journal": "user journal (journalctl --user)",
                 "user-unit": "system journal, this account's user unit",
                 "helper": "system journal via the privileged helper",
                 "root": "system journal (the panel runs as root)"}


def _journal(ctx):
    """The report's one journal read, shared by both sections (a second caller waits for it)."""
    lock = ctx.memo("journal_lock", threading.Lock)
    if not lock.acquire(timeout=max(0.1, ctx.remaining())):
        raise TimeoutError("journal read still running")
    try:
        return ctx.memo("journal", lambda: _src_journal.read(
            DIGEST_LINES, timeout=min(10.0, max(0.5, ctx.remaining()))))
    finally:
        lock.release()


def _body(line):
    """A journal line without its 'time host proc[pid]:' prefix."""
    return _PREFIX_RE.sub("", line, count=1)


def _stamp(line):
    m = _PREFIX_RE.match(line)
    return m.group(1) if m else None


def _norm(text):
    return _DIGITS_RE.sub("#", text).strip()


def _zone():
    return time.strftime("UTC%z")


def _span(lines):
    """'<first> → <last> host time (UTC+0000)', or a note that the lines carry no timestamps."""
    stamps = [s for s in (_stamp(ln) for ln in (lines[0], lines[-1])) if s]
    if len(stamps) < 2:
        return "no timestamps in the lines read"
    return "%s → %s host time (%s)" % (stamps[0], stamps[1], _zone())


def _quote(ctx, text):
    """`text` scrubbed and cut to _QUOTE_MAX characters, safe inside a code span."""
    out = privacy.scrub_lines(ctx, [text])
    if out is None:
        return "(withheld)"
    # Cut at a word: the Tailscale names are added to the map only after every section (finish),
    # so the assembler's final pass must see whole words to match them.
    return cut_words(out[0].replace("`", "'").strip(), _QUOTE_MAX)


# ── Errors in the journal (R71) ─────────────────────────────────────────────────────────────────
def _tracebacks(bodies, stamps):
    """{normalised exception line: [count, last stamp, raw exception line]} for every traceback."""
    found, i, n = {}, 0, len(bodies)
    while i < n:
        if not bodies[i].startswith("Traceback (most recent call last):"):
            i += 1
            continue
        j = i + 1
        while j < n and bodies[j].startswith((" ", "\t")):
            j += 1
        if j < n:
            exc = bodies[j].strip()
            slot = found.setdefault(_norm(exc)[:200], [0, None, exc])
            slot[0] += 1
            slot[1] = stamps[j] or slot[1]
        i = j + 1
    return found


def _repeated(bodies):
    """The most repeated non-traceback lines: [(count, raw line)], three or more times only."""
    seen = {}
    for b in bodies:
        if not b.strip() or b.startswith((" ", "\t", "Traceback")):
            continue
        slot = seen.setdefault(_norm(b)[:200], [0, b])
        slot[0] += 1
    top = sorted(seen.values(), key=lambda v: -v[0])[:5]
    return [(c, raw) for c, raw in top if c >= 3]


def _level_counts(bodies):
    counts = {}
    for b in bodies:
        m = _LEVEL_RE.match(b)
        if m:
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return counts


def _levels_line(bodies):
    levels = _level_counts(bodies)
    if not levels:
        return "- **Logged at WARNING or above**: no level-tagged lines (warnings may reach the " \
               "journal without a level)"
    return "- **Logged at WARNING or above**: %s" % ", ".join(
        "%d %s" % (levels[k], k) for k in ("CRITICAL", "ERROR", "WARNING") if k in levels)


def _repeated_lines(ctx, bodies):
    rep = _repeated(bodies)
    out = ["- **Most repeated lines**:%s" % ("" if rep else " none repeated 3 or more times")]
    out += ["  - ×%d `%s`" % (count, _quote(ctx, raw)) for count, raw in rep]
    return out


def _traceback_lines(ctx, tbs):
    total = sum(v[0] for v in tbs.values())
    if not total:
        return ["- **Tracebacks**: none in this window"]
    top = sorted(tbs.values(), key=lambda v: -v[0])
    out = ["- **Tracebacks**: %d, %d distinct:" % (total, len(tbs))]
    for count, last, exc in top[:8]:
        m = _EXC_RE.match(exc)
        out.append("  - %s ×%d%s: `%s`" % (m.group(1) if m else "?", count,
                                           " (last %s)" % last if last else "", _quote(ctx, exc)))
    if len(top) > 8:
        out.append("  - … and %d more distinct" % (len(top) - 8))
    return out


GAME_ACCOUNT = "as a game account"
# The panel's own account (the service account, or the login account of a per-user install): the
# installer runs its snapshot and config steps as it ('sudo -u <panel> env -C / tar …', 'python3 -I
# - …/config.json'), and those were counted as game-account work.
PANEL_ACCOUNT = "as the panel's own account"


def _panel_accounts():
    """The names of the panel's own account: this process's, and the installer's service account.

    Asked once per count, of the own uid only (getpwuid), as the privacy pass does. The service
    account is named too, for a report generated as root, where this process's account is root.
    """
    import pwd
    from panel.ops.debug_report.install import SERVICE_ACCOUNT
    names = {SERVICE_ACCOUNT}
    try:
        names.add(pwd.getpwuid(os.geteuid()).pw_name)
    except (KeyError, OSError):
        pass                       # no passwd entry: the service account's name still counts
    names.discard("root")
    return frozenset(names)


def _game_read(rest):
    """The fixed label for what a command run as a game account was, from its fingerprint."""
    for label, tokens in _GAME_READS:
        if all(t in rest for t in tokens):
            return label
    return "other"


def _priv_verb(command, rest, user="root", own=frozenset()):
    """The label a sudo line is counted under: (label, sub-label or None). Fixed words only.

    The helper's own lines are its verb ('other verb' for one the table does not know). Anything
    run as the panel's own account (`own`, from _panel_accounts) is PANEL_ACCOUNT, by program,
    unless it is a shell body with a game fingerprint (_own_account_label). Anything run as another
    account (USER= not root) is the panel's game-account work — gamedig, the console reads and
    sends, LinuxGSM configs, and every argv-form read — counted together under GAME_ACCOUNT with a
    fixed fingerprint of what it was (_GAME_READS). Anything else is root: a program the panel
    itself runs is named, '<program> as root'; a shell is 'shell as root'; anything else 'other
    program as root'. Never an argument, never a path, never the account: for su the argument is
    an account, and USER= is one.
    """
    from panel.security import privileged as _priv
    rest = rest or ""
    if command.endswith("/" + os.path.basename(_priv.HELPER_PATH)):
        words = rest.split()
        return (words[0] if words and words[0] in set(_priv.verbs()) else "other verb"), None
    prog = os.path.basename(command)
    user = (user or "").strip()
    if user in own:
        return _own_account_label(prog, rest)
    if user != "root":
        return GAME_ACCOUNT, _game_label(prog, rest)
    return _root_label(prog), None


def _own_account_label(prog, rest):
    """(label, sub-label) for a call run as the panel's own account.

    A shell body with a game fingerprint is game work whichever account ran it: a game server may
    run under the panel's login account (game_idents_ok refuses only root), and its gamedig and
    console calls are then sudo'd to that account. Everything else is PANEL_ACCOUNT, by program:
    an argv-form call (cat, rm) carries no fingerprint, so its account decides, and its sub-label
    is the program under either label.
    """
    read = _game_read(rest) if prog in _SHELLS else "other"
    if read != "other":
        return GAME_ACCOUNT, read
    return PANEL_ACCOUNT, _program_label(prog)


def _program_label(prog):
    """A program's name when the panel itself runs it, 'shell' for a shell, else 'other'."""
    if prog in _SHELLS:
        return "shell"
    return prog if prog in _ROOT_PROGRAMS else "other"


def _game_label(prog, rest):
    """What a command run as a game account was: a shell body's fingerprint, else its program."""
    if prog in _SHELLS:
        return _game_read(rest)
    return _program_label(prog)


def _root_label(prog):
    """'<program> as root' for a program the panel runs, else a fixed word."""
    if prog in _SHELLS:
        return "shell as root"
    return "%s as root" % prog if prog in _ROOT_PROGRAMS else "other program as root"


def _split_priv(lines):
    """(lines without the panel's own successful sudo/runuser/su lines, {label: calls}, sessions).

    A label counted for game-account work is a dict {sub-label: calls}; every other is an int.
    """
    kept, verbs, sessions = [], {}, 0
    own = _panel_accounts()
    for ln in lines:
        body = _body(ln)
        if _SUDO_REFUSED_RE.search(body):
            kept.append(ln)
        elif _PAM_SESSION_RE.match(body):
            sessions += 1
        elif _SUDO_CONTINUED_RE.match(body):
            continue
        else:
            m = _SUDO_CMD_RE.search(body)
            if m is None:
                kept.append(ln)
                continue
            _count_priv(verbs, *_priv_verb(m.group(2), m.group(3), m.group(1), own))
    return kept, verbs, sessions


def _count_priv(verbs, label, sub):
    if sub is None:
        verbs[label] = verbs.get(label, 0) + 1
        return
    slot = verbs.setdefault(label, {})
    slot[sub] = slot.get(sub, 0) + 1


def _priv_total(n):
    return sum(n.values()) if isinstance(n, dict) else n


def _priv_entry(label, n):
    if not isinstance(n, dict):
        return "%s ×%d" % (label, n)
    subs = sorted(n.items(), key=lambda kv: (-kv[1], kv[0]))
    return "%s ×%d [%s]" % (label, _priv_total(n), ", ".join("%s ×%d" % kv for kv in subs))


def _priv_line(verbs, sessions, span_of, title="Privileged calls (left out below)"):
    """'- **Privileged calls (left out below)**: N sudo calls ... (verb ×n, ...) · M session lines'.

    The game-account work is ONE entry with its kinds nested, so a thousand gamedig runs cannot
    push the helper's verbs out of the six shown.
    """
    if not verbs and not sessions:
        return None
    total = sum(_priv_total(n) for n in verbs.values())
    top = sorted(verbs.items(), key=lambda kv: (-_priv_total(kv[1]), kv[0]))
    shown = ", ".join(_priv_entry(k, v) for k, v in top[:6]) + (", …" if len(top) > 6 else "")
    return ("- **%s**: %d successful sudo call%s in %s%s · %d pam session line%s"
            % (title, total, "" if total == 1 else "s", span_of, " (%s)" % shown if shown else "",
               sessions, "" if sessions == 1 else "s"))


def _priv_summary(j):
    """The privileged-call line for this report, from the separate sudo read when there was one."""
    if j.get("sudo"):
        _kept, verbs, sessions = _split_priv(j["sudo"])
        return _priv_line(verbs, sessions, "the %d sudo lines of the panel's unit from %s, %s"
                          % (len(j["sudo"]), _src_journal.window_words("panel-sudo"),
                             _span(j["sudo"])), title="Privileged calls")
    if j.get("filtered"):
        return "- **Privileged calls**: not counted (%s)" % (j.get("sudo_why") or "no sudo lines read")
    _kept, verbs, sessions = _split_priv(j["lines"])
    return _priv_line(verbs, sessions, "this window")


def _cut_words(j):
    """What a CUT read holds: the window had more than the read keeps, and these are its OLDEST."""
    return ("the oldest %d entries of the panel's own output from %s (cut off: the window held "
            "more, and its newest lines were not read)"
            % (_src_journal.entry_count(j["lines"]), _src_journal.window_words("panel-own")))


def section_journal_digest(ctx):
    """Tracebacks, log levels and the most repeated lines over the whole journal read."""
    j = _journal(ctx)
    res = Result()
    if not j["lines"]:
        return res.add("_(digest unavailable: %s)_" % (j["why"] or "no journal read"))
    lines, _verbs, _sessions = _split_priv(j["lines"])
    bodies = [_body(ln) for ln in lines]
    if j.get("cut"):
        res.add("- **Window**: %s, its sudo lines read apart, %s" % (_cut_words(j), _span(j["lines"])))
    elif j.get("filtered"):
        res.add("- **Window**: %d lines of the panel's own output from %s (its sudo lines read "
                "apart), %s" % (len(j["lines"]), _src_journal.window_words("panel-own"),
                                _span(j["lines"])))
    else:
        res.add("- **Window**: the last %d lines, %s" % (len(j["lines"]), _span(j["lines"])))
    priv = _priv_summary(j)
    if priv:
        res.add(priv)
    tbs = _tracebacks(bodies, [_stamp(ln) for ln in lines])
    res.lines.extend(_traceback_lines(ctx, tbs))
    res.add(_levels_line(bodies))
    res.lines.extend(_repeated_lines(ctx, bodies))
    _cgroup_kill_lines(res, bodies)
    if tbs:
        res.find("warn", "Journal", "%d traceback(s) in the journal window"
                 % sum(v[0] for v in tbs.values()))
    return res


def _cgroup_kill_lines(res, bodies):
    """The digest's line, and a warning, for systemd's 'could not stop it with the unit' lines."""
    n = sum(1 for b in bodies if _CGROUP_KILL_RE.search(b))
    if not n:
        return
    res.add("- **Processes systemd could not stop with the panel**: %d line%s ('Failed to kill "
            "control group', 'remains running after unit stopped', 'left-over process'): another "
            "account's processes — game servers started from the panel — were inside its unit "
            "when it stopped. Panel process lists what is in it now." % (n, "" if n == 1 else "s"))
    res.find("warn", "Journal", "systemd could not stop processes inside the panel's unit with it "
             "(%d journal line%s): game servers started from the panel" % (n, "" if n == 1 else "s"))


# ── Recent log (R68, R69, R70, R73) ─────────────────────────────────────────────────────────────
def _window_events(lines):
    """(start pids in order, crash count, OOM count) in the lines."""
    starts, crashes, ooms = [], 0, 0
    for ln in lines:
        if _START_MARK in ln:
            m = _PID_RE.match(ln)
            starts.append(m.group(1) if m else "?")
        if "Main process exited" in ln and "status=0/SUCCESS" not in ln:
            crashes += 1
        if "oom-kill" in ln or "Out of memory" in ln:
            ooms += 1
    return starts, crashes, ooms


def _events_line(lines):
    starts, crashes, ooms = _window_events(lines)
    if not starts:
        head = "no start line (the window is shorter than the uptime)"
    else:
        head = "%d start%s (pid%s %s)" % (len(starts), "" if len(starts) == 1 else "s",
                                         "" if len(starts) == 1 else "s", " → ".join(starts))
    return "- **In this window**: %s, %d crash%s (systemd 'Main process exited' with a failure), " \
           "%d OOM kill%s" % (head, crashes, "" if crashes == 1 else "es", ooms,
                              "" if ooms == 1 else "s")


def _collapse(lines):
    """Consecutive repeats (prefix stripped, digits folded) folded into one note; -> (lines, n)."""
    out, folded, i = [], 0, 0
    while i < len(lines):
        key, j = _norm(_body(lines[i])), i + 1
        while j < len(lines) and key and _norm(_body(lines[j])) == key:
            j += 1
        out.append(lines[i])
        if j - i > 1:
            folded += j - i - 1
            until = _stamp(lines[j - 1])
            out.append("    ↳ (same line repeated %d× more%s)" % (j - i - 1,
                                                                  " until %s" % until if until else ""))
        i = j
    return out, folded


def _mark_starts(lines):
    out = []
    for ln in lines:
        if _START_MARK in ln:
            m = _PID_RE.match(ln)
            out.append("—— panel (re)started: pid %s ——" % (m.group(1) if m else "?"))
        out.append(ln.replace("```", "'''"))
    return out


def _priority(lines):
    """Indices to keep first: whole traceback blocks, error/warning lines, restart lines."""
    keep, in_tb = set(), False
    for i, ln in enumerate(lines):
        body = _body(ln)
        if body.startswith("Traceback (most recent call last):"):
            in_tb = True
        if in_tb or _PRIORITY_RE.search(body) or ln.startswith("——"):
            keep.add(i)
        if in_tb and not body.startswith((" ", "\t", "Traceback")):
            in_tb = False
    return keep


def _take(lines, order, chosen, used, limit):
    """Add indices from `order` to `chosen` until `limit` characters; -> (used, how many added)."""
    added = 0
    for i in order:
        if i in chosen:
            continue
        if used + len(lines[i]) + 1 > limit:
            break
        chosen.add(i)
        used += len(lines[i]) + 1
        added += 1
    return used, added


def _budget(lines):
    """Lines that fit LOG_BUDGET, in order, elided spans marked; -> (lines, kept priority, newest)."""
    if sum(len(ln) + 1 for ln in lines) <= LOG_BUDGET:
        return lines, None, None
    chosen = set()
    used, n_priority = _take(lines, sorted(_priority(lines)), chosen, 0, LOG_BUDGET // 2)
    newest = _take(lines, range(len(lines) - 1, -1, -1), chosen, used, LOG_BUDGET)[1]
    return _render_kept(lines, chosen), n_priority, newest


def _render_kept(lines, chosen):
    out, gap = [], 0
    for i, ln in enumerate(lines):
        if i in chosen:
            if gap:
                out.append("    … (%d line%s elided) …" % (gap, "" if gap == 1 else "s"))
                gap = 0
            out.append(ln)
        else:
            gap += 1
    return out


def section_recent_log(ctx):
    """The newest journal lines: source, span, zone, starts and crashes, then a budgeted body."""
    from panel.ops import system_ops as so
    j = _journal(ctx)
    res = Result()
    if not j["lines"]:
        return (res.add("- **Source**: none (%s)" % (j["why"] or "no journal read"))
                .add("```").add("(no journal available)").add("```")
                .find("unread", "Recent log", "no journal readable"))
    kept, verbs, sessions = _split_priv(j["lines"])
    tail = kept[-TAIL_LINES:]
    scrubbed = privacy.scrub_lines(ctx, tail)
    res.add("- **Source**: %s · %d lines · %s · report generated %s UTC" % (
        _SOURCE_LABEL.get(j["source"], "journal"), len(tail), _span(tail),
        time.strftime("%H:%M:%S", time.gmtime())))
    if j.get("cut"):
        # The block below ends at the newest of what was read, which is not the newest there is.
        res.add("- **Read**: %s" % _cut_words(j))
    # Counted ONCE, in Errors in the journal; this only says the lines are not in the block below.
    if verbs or sessions or j.get("filtered"):
        res.add("- **Privileged calls**: left out below; counted under Errors in the journal")
    if scrubbed is None:
        return res.add("_(withheld: pseudonymisation unavailable)_").find(
            "warn", "Recent log", "withheld: pseudonymisation unavailable")
    res.add(_events_line(scrubbed))
    deduped = so._dedupe_log_tracebacks("\n".join(scrubbed)).split("\n")
    collapsed, folded = _collapse(deduped)
    body, n_priority, newest = _budget(_mark_starts(collapsed))
    if n_priority is not None:
        res.add("- **Kept**: %d traceback, warning, error and restart lines, then the newest %d "
                "lines; %d repeated lines collapsed" % (n_priority, newest, folded))
    elif folded:
        res.add("- **Kept**: every line; %d repeated lines collapsed" % folded)
    return res.add("```").add("\n".join(body)).add("```")
