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
    service's own term narrowed. -n then counts only those lines, so the window reaches back as far
    as the panel's own output does. NOT `--grep`: on systemd 254+ `-n` with `--grep` walks the
    whole journal backwards and returns newest-first (24-39 s on the test VPS, past the 10 s cap),
    and on 249 it filters the same last N lines without widening anything.

    "sudo" is a second, separate read of the unit's sudo lines (SYSLOG_IDENTIFIER=sudo), which the
    digest counts by helper verb; None when the main read was not filtered (its own lines then
    carry them, as before) or when it could not be read ("sudo_why").

    journalctl prints '-- No entries --' to stdout with rc 0 when nothing matches, and an older
    helper's verb has no -q: output that is only such marker lines (or journalctl's "No journal
    files were found.") is EMPTY, never content.
    Every read is an argv with stdin DEVNULL and a timeout, through system_ops' capped reader.
    "why" is fixed vocabulary built from return codes and matched strings, never stderr itself.
    Never raises.
"""
import re
import time

_UNIT = "linuxgsm-panel"
_SERVICE = _UNIT + ".service"
_MARKER_RE = re.compile(r"^(?:-- (?:No entries|Boot |Reboot|Logs begin|Journal begins|Journal ends)"
                        r"|No journal files were found)")
# Syslog lines kept from the unit: emerg..warning. sudo logs a successful command at notice (5) and
# pam its sessions at info (6); a refusal is alert (1), pam's auth failures err/crit.
_LOUD = ["PRIORITY=%d" % p for p in range(5)]


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


def _first_lines(reads):
    """Run the (filtered, read) pairs in order until one has content: (lines, filtered, state)."""
    state = "not read"
    for filtered, run in reads:
        out, err, rc = run()
        lines = content_lines(out)
        if lines:
            return lines, filtered, None
        state = _state(out, err, rc)
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

    def jctl(pre, matches=()):
        # The options BEFORE the matches: journalctl reads a stray option after them as a match
        # when POSIXLY_CORRECT is set. The unit reads keep the argv they always had.
        return lambda: so._debug_run(["journalctl"] + list(pre) + ["-q", "-n", n, "--no-pager"]
                                     + list(matches), timeout=left())

    lines, filtered, state = _first_lines(
        [(True, jctl(["--user"], user_unit_matches(uid))), (False, jctl(["--user", "-u", _UNIT]))])
    if lines:
        return _found("user-journal", lines, filtered,
                      jctl(["--user"], user_unit_sudo_matches(uid)))
    tried = ["user journal: " + state]
    if _privileged_allowed(so):
        source = "helper" if so._helper_present() else "root"

        def verb(src):
            return lambda: so._run_verb("journal", [src, n], timeout=left(), merge_stderr=False)
        lines, filtered, state = _first_lines([(True, verb("panel-own")), (False, verb("panel"))])
        if lines:
            return _found(source, lines, filtered, verb("panel-sudo"))
        tried.append("system journal via %s: %s" % (source, state))
    else:
        lines, filtered, state = _first_lines(
            [(True, jctl([], user_unit_matches(uid))),
             (False, jctl(["_SYSTEMD_USER_UNIT=%s" % _SERVICE, "_UID=%d" % uid]))])
        if lines:
            return _found("user-unit", lines, filtered, jctl([], user_unit_sudo_matches(uid)))
        tried.append("system journal for this account's unit: " + state)
        tried.append("no journal readable without sudo")
    return {"source": None, "lines": [], "why": "; ".join(tried), "filtered": False,
            "sudo": None, "sudo_why": None}
