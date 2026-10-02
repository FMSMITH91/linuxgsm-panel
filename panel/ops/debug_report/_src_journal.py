"""The ONE journal read per report (R68, R69, R71's source). Owner: builder B1.

read(max_lines=5000, timeout=10) -> dict
    {"source": "user-journal"|"user-unit"|"helper"|"root"|None, "lines": [str, ...],
     "why": fixed reason or None}

    1. `journalctl --user -u linuxgsm-panel -q -n N --no-pager`: a per-user install's own journal.
    2. When that is empty, and only when the root-owned helper is installed or this process is
       root: the privileged `journal` verb (`journalctl -u linuxgsm-panel`), the system unit's
       journal. Never otherwise: without the helper, _run_verb falls back to a plain `sudo`, which
       can prompt and counts toward pam_faillock.
    3. Otherwise: `journalctl _SYSTEMD_USER_UNIT=linuxgsm-panel.service _UID=<uid> -q`, which an
       adm or systemd-journal member can read unprivileged. _UID keeps out another account's
       same-named user unit (a second install on the same machine).

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
_MARKER_RE = re.compile(r"^(?:-- (?:No entries|Boot |Reboot|Logs begin|Journal begins|Journal ends)"
                        r"|No journal files were found)")


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


def read(max_lines=5000, timeout=10):
    """The panel's recent journal lines and where they came from (see the module docstring)."""
    from panel.ops import system_ops as so
    n = str(max(1, min(int(max_lines), 20000)))
    end = time.monotonic() + max(0.5, min(float(timeout), 10.0))

    def left():
        return max(0.5, end - time.monotonic())

    out, err, rc = so._debug_run(["journalctl", "--user", "-u", _UNIT, "-q", "-n", n, "--no-pager"],
                                 timeout=left())
    lines = content_lines(out)
    if lines:
        return {"source": "user-journal", "lines": lines, "why": None}
    tried = ["user journal: " + _state(out, err, rc)]
    if _privileged_allowed(so):
        source = "helper" if so._helper_present() else "root"
        out, err, rc = so._run_verb("journal", ["panel", n], timeout=left(), merge_stderr=False)
        lines = content_lines(out)
        if lines:
            return {"source": source, "lines": lines, "why": None}
        tried.append("system journal via %s: %s" % (source, _state(out, err, rc)))
    else:
        uid = so.os.getuid() if hasattr(so.os, "getuid") else -1
        out, err, rc = so._debug_run(["journalctl", "_SYSTEMD_USER_UNIT=%s.service" % _UNIT,
                                      "_UID=%d" % uid, "-q", "-n", n, "--no-pager"], timeout=left())
        lines = content_lines(out)
        if lines:
            return {"source": "user-unit", "lines": lines, "why": None}
        tried.append("system journal for this account's unit: " + _state(out, err, rc))
        tried.append("no journal readable without sudo")
    return {"source": None, "lines": [], "why": "; ".join(tried)}
