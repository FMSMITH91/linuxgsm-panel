"""The ONE journal read per report (R68, R69, R71's source). Owner: builder B1.

read(max_lines=5000, timeout=10) -> dict
    {"source": "user-journal"|"user-unit"|"helper"|"root"|None, "lines": [str, ...],
     "why": fixed reason or None, "filtered": bool, "sudo": [str, ...] or None, "sudo_why": ...}

    1. A per-user install's own journal: `journalctl --user` with the matches `-u linuxgsm-panel`
       would add, minus the sudo noise (see below). Falling back to `--user -u linuxgsm-panel`
       itself when that read failed or came back empty.
    2. When that is empty, and only when the root-owned helper is installed or this process is
       root: the privileged `journal` verb, the system unit's journal — its `panel-own` source, the
       same filtered read for the system unit, then its plain `panel` source (`journalctl -u
       linuxgsm-panel`) when the helper is older than that source or answers nothing. Never
       otherwise: without the helper, _run_verb falls back to a plain `sudo`, which can prompt and
       counts toward pam_faillock.
    3. Otherwise: `journalctl _SYSTEMD_USER_UNIT=linuxgsm-panel.service _UID=<uid> -q`, filtered
       the same way, which an adm or systemd-journal member can read unprivileged. _UID keeps out
       another account's same-named user unit (a second install on the same machine).

    WHY FILTERED. Every privileged call the panel makes writes three lines into its own unit's
    journal (sudo's COMMAND line, pam_unix's session opened and closed). On the live host that was
    4964 of the 5000 lines read: the window covered under three hours and the recent log printed 36
    lines. So the main read asks journald, by INDEXED FIELD matches, for the panel's own output
    (_TRANSPORT stdout/journal), the unit's syslog lines at warning or worse (a REFUSED sudo stays,
    and so does anything else that complains), and the messages systemd and coredump write about
    the unit — the terms systemd's add_matches_for_unit / add_matches_for_user_unit use, with the
    service's own term narrowed. NOT `--grep`: on systemd 254+ `-n` with `--grep` walks the whole
    journal backwards and returns newest-first (24-39 s on the test VPS, past the 10 s cap), and
    on 249 it filters the same last N lines without widening anything.

    WHY A WINDOW, NOT `-n`. These matches are an AND of two dense terms (the unit's entries, most
    of them sudo lines; every service's stdout) whose intersection is sparse, and sd-journal steps
    through that one of the unit's entries at a time. `-n N` walks back from the end until N match,
    so when the whole retained journal holds fewer than N it walks ALL of it: on the test VPS
    (1.9 GB, 1683 matches) it was still running at 315 s, the 10 s budget went on it, and the
    report showed no journal at all. So each filtered read is `--since=<window> --lines=+N`: it
    seeks to the window's start and walks forward (bounded by the window, whatever the journal's
    size), keeping the OLDEST N lines of it (privileged.JOURNAL_SINCE has the windows and the
    versions). A read that comes back with all N has more than that in its window, so its newest
    lines are missing: the plain read is used instead, which reads the newest N. And a filtered
    read gets at most _FILTERED_SHARE of the time left, so the plain read after it always has the
    rest — the filtered read spending the whole budget is how the VPS report ended up with none.

    "sudo" is a second, separate read of the unit's sudo lines (SYSLOG_IDENTIFIER=sudo) over the
    last hour, which the digest counts by helper verb; None when the main read was not filtered
    (its own lines then carry them, as before) or when it could not be read ("sudo_why").

    journalctl prints '-- No entries --' to stdout with rc 0 when nothing matches, and an older
    helper's verb has no -q: output that is only such marker lines (or journalctl's "No journal
    files were found.") is EMPTY, never content.
    Every read is an argv with stdin DEVNULL and a timeout, through system_ops' capped reader.
    "why" is fixed vocabulary built from return codes and matched strings, never stderr itself.
    Never raises.
"""
import re
import time

from panel.security import privileged as _priv

_UNIT = "linuxgsm-panel"
_SERVICE = _UNIT + ".service"
_MARKER_RE = re.compile(r"^(?:-- (?:No entries|Boot |Reboot|Logs begin|Journal begins|Journal ends)"
                        r"|No journal files were found)")
# Syslog lines kept from the unit: emerg..warning. sudo logs a successful command at notice (5) and
# pam its sessions at info (6); a refusal is alert (1), pam's auth failures err/crit.
_LOUD = ["PRIORITY=%d" % p for p in range(5)]
# The share of the time left that a FILTERED read may spend, so the plain read after it always has
# the rest (see WHY A WINDOW).
_FILTERED_SHARE = 0.5


def user_unit_matches(uid):
    """The filtered matches for this account's USER unit (`--user -u`'s terms, sudo noise out)."""
    me, unit = "_UID=%d" % uid, _SERVICE
    return (["_SYSTEMD_USER_UNIT=" + unit, me, "_TRANSPORT=stdout", "_TRANSPORT=journal", "+",
             "_SYSTEMD_USER_UNIT=" + unit, me, "_TRANSPORT=syslog"] + _LOUD
            + ["+", "USER_UNIT=" + unit, me,
               "+", "COREDUMP_USER_UNIT=" + unit, me, "_UID=0",
               "+", "OBJECT_SYSTEMD_USER_UNIT=" + unit, me, "_UID=0"])


def user_unit_sudo_matches(uid):
    """The sudo lines of this account's user unit: the calls the digest counts."""
    return ["_SYSTEMD_USER_UNIT=" + _SERVICE, "_UID=%d" % uid, "SYSLOG_IDENTIFIER=sudo"]


def window_words(name):
    """'the last 24 hours' for a privileged.JOURNAL_SINCE window ('-24h')."""
    hours = int(_priv.JOURNAL_SINCE[name].strip("-h"))
    return "the last hour" if hours == 1 else "the last %d hours" % hours


def content_lines(out):
    """The lines of journalctl output that are not its '-- ... --' markers or blank."""
    return [ln for ln in (out or "").split("\n") if ln.strip() and not _MARKER_RE.match(ln.strip())]


def _state(out, err, rc):
    """A fixed description of a read that produced no content."""
    err = err or ""
    if rc == -1 and "timed out" in err:
        return "timed out"
    if rc == -1 or rc == 127:
        return "journalctl could not be started"
    if "No journal files were found" in (out or "") + err:
        return "no journal files, rc %d" % rc
    if "ermission" in err or "insufficient" in err.lower():
        return "not permitted, rc %d" % rc
    return "no entries, rc %d" % rc


def _privileged_allowed(so):
    """Whether the journal verb may run: the helper is installed, or we are root already."""
    if so._helper_present():
        return True
    return hasattr(so.os, "geteuid") and so.os.geteuid() == 0


def _first_lines(reads, n):
    """Run the (filtered, read) pairs in order until one has content: (lines, filtered, state).

    A filtered read that came back FULL -- `n` lines, the oldest n of its window, so its newest
    lines are past them -- gives way to the plain read after it, which reads the newest n. The
    full read is the answer only when that one has nothing.
    """
    state, full = "not read", None
    for filtered, run in reads:
        out, err, rc = run()
        lines = content_lines(out)
        if filtered and len(lines) >= n:
            full = full or lines
            continue
        if lines:
            return lines, filtered, None
        state = _state(out, err, rc)
    if full:
        return full, True, None
    return [], False, state


def _sudo_lines(run):
    """(the unit's sudo lines, None) or (None, why) from one read."""
    out, err, rc = run()
    lines = content_lines(out)
    return (lines, None) if lines else (None, _state(out, err, rc))


def _found(source, lines, filtered, sudo_run):
    """read()'s answer for a source that had content, with its sudo read when it was filtered."""
    sudo, sudo_why = (_sudo_lines(sudo_run) if filtered else (None, None))
    return {"source": source, "lines": lines, "why": None, "filtered": filtered,
            "sudo": sudo, "sudo_why": sudo_why}


def read(max_lines=5000, timeout=10):
    """The panel's recent journal lines and where they came from (see the module docstring)."""
    from panel.ops import system_ops as so
    n = str(max(1, min(int(max_lines), 20000)))
    end = time.monotonic() + max(0.5, min(float(timeout), 10.0))
    uid = so.os.getuid() if hasattr(so.os, "getuid") else -1

    def left():
        return max(0.5, end - time.monotonic())

    def share():
        return max(0.5, left() * _FILTERED_SHARE)

    def jctl(pre, matches=(), window=None):
        # The options BEFORE the matches: journalctl reads a stray option after them as a match
        # when POSIXLY_CORRECT is set. The unit reads keep the argv they always had. A filtered
        # read (`window`, a privileged.JOURNAL_SINCE name) is bounded by its window and its share.
        limit = (["--since=" + _priv.JOURNAL_SINCE[window], "--lines=+" + n] if window
                 else ["-n", n])
        return lambda: so._debug_run(["journalctl"] + list(pre) + ["-q"] + limit + ["--no-pager"]
                                     + list(matches),
                                     timeout=share() if window == "panel-own" else left())

    lines, filtered, state = _first_lines(
        [(True, jctl(["--user"], user_unit_matches(uid), "panel-own")),
         (False, jctl(["--user", "-u", _UNIT]))], int(n))
    if lines:
        return _found("user-journal", lines, filtered,
                      jctl(["--user"], user_unit_sudo_matches(uid), "panel-sudo"))
    tried = ["user journal: " + state]
    if _privileged_allowed(so):
        source = "helper" if so._helper_present() else "root"

        def verb(src, budget=left):
            return lambda: so._run_verb("journal", [src, n], timeout=budget(), merge_stderr=False)
        lines, filtered, state = _first_lines(
            [(True, verb("panel-own", share)), (False, verb("panel"))], int(n))
        if lines:
            return _found(source, lines, filtered, verb("panel-sudo"))
        tried.append("system journal via %s: %s" % (source, state))
    else:
        lines, filtered, state = _first_lines(
            [(True, jctl([], user_unit_matches(uid), "panel-own")),
             (False, jctl(["_SYSTEMD_USER_UNIT=%s" % _SERVICE, "_UID=%d" % uid]))], int(n))
        if lines:
            return _found("user-unit", lines, filtered,
                          jctl([], user_unit_sudo_matches(uid), "panel-sudo"))
        tried.append("system journal for this account's unit: " + state)
        tried.append("no journal readable without sudo")
    return {"source": None, "lines": [], "why": "; ".join(tried), "filtered": False,
            "sudo": None, "sudo_why": None}
