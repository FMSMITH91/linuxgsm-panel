"""Debug-report sections: journal_digest (R71) and recent_log (R68, R69, R70, R73).

Owner: builder B1. Both read the report's ONE journal read (_src_journal, up to 5000 lines): the
digest summarises all of it, the recent log prints the newest 400 lines within a budget.

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
_SUDO_CMD_RE = re.compile(r" :[ \t]{1,4}(?:TTY=[^;\n]{1,64};[ \t]{1,4})?PWD=[^;\n]{0,512};[ \t]{1,4}"
                          r"USER=[^;\n]{1,64};[ \t]{1,4}COMMAND=(\S{1,512})(?: (\S{1,64}))?")
_SUDO_REFUSED_RE = re.compile(r"a password is required|NOT in sudoers|not allowed to (?:run|execute)"
                              r"|incorrect password|authentication failure|command not allowed",
                              re.IGNORECASE)
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


def _priv_verb(command, arg):
    """The helper verb a sudo COMMAND ran ('other verb' for one the table does not know), or
    'other command' for anything but the helper: never an argument, which can be an account."""
    from panel.security import privileged as _priv
    if not command.endswith("/" + os.path.basename(_priv.HELPER_PATH)):
        return "other command"
    return arg if arg in set(_priv.verbs()) else "other verb"


def _split_priv(lines):
    """(lines without the panel's own successful sudo/runuser/su lines, {verb: calls}, sessions)."""
    kept, verbs, sessions = [], {}, 0
    for ln in lines:
        body = _body(ln)
        if _SUDO_REFUSED_RE.search(body):
            kept.append(ln)
        elif _PAM_SESSION_RE.match(body):
            sessions += 1
        else:
            m = _SUDO_CMD_RE.search(body)
            if m is None:
                kept.append(ln)
                continue
            verb = _priv_verb(m.group(1), m.group(2))
            verbs[verb] = verbs.get(verb, 0) + 1
    return kept, verbs, sessions


def _priv_line(verbs, sessions, span_of):
    """'- **Privileged calls (left out below)**: N sudo calls ... (verb ×n, ...) · M session lines'."""
    if not verbs and not sessions:
        return None
    top = sorted(verbs.items(), key=lambda kv: (-kv[1], kv[0]))
    shown = ", ".join("%s ×%d" % kv for kv in top[:6]) + (", …" if len(top) > 6 else "")
    return ("- **Privileged calls (left out below)**: %d successful sudo call%s in %s%s · %d pam "
            "session line%s" % (sum(verbs.values()), "" if sum(verbs.values()) == 1 else "s",
                                span_of, " (%s)" % shown if shown else "", sessions,
                                "" if sessions == 1 else "s"))


def section_journal_digest(ctx):
    """Tracebacks, log levels and the most repeated lines over the whole journal read."""
    j = _journal(ctx)
    res = Result()
    if not j["lines"]:
        return res.add("_(digest unavailable: %s)_" % (j["why"] or "no journal read"))
    lines, verbs, sessions = _split_priv(j["lines"])
    bodies = [_body(ln) for ln in lines]
    res.add("- **Window**: the last %d lines, %s" % (len(j["lines"]), _span(j["lines"])))
    priv = _priv_line(verbs, sessions, "this window")
    if priv:
        res.add(priv)
    tbs = _tracebacks(bodies, [_stamp(ln) for ln in lines])
    res.lines.extend(_traceback_lines(ctx, tbs))
    res.add(_levels_line(bodies))
    res.lines.extend(_repeated_lines(ctx, bodies))
    if tbs:
        res.find("warn", "Journal", "%d traceback(s) in the journal window"
                 % sum(v[0] for v in tbs.values()))
    return res


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
    priv = _priv_line(verbs, sessions, "the %d-line journal read" % len(j["lines"]))
    if priv:
        res.add(priv)
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
