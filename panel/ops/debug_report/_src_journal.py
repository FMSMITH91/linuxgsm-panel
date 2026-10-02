"""The ONE journal read per report (R68, R69, R71's source). Owner: builder B1.

read(max_lines=5000, timeout=10) -> dict
    {"source": "user-journal"|"helper"|"root"|None, "lines": [str, ...], "why": fixed reason or None}
    Unprivileged first: `journalctl --user -u linuxgsm-panel -q` / `_SYSTEMD_USER_UNIT=...` with -q,
    --no-pager, stdin DEVNULL; output that is only '-- No entries --' / '-- Boot ...' markers is
    EMPTY. The privileged journal verb only when the helper is present or euid is 0 -- never a sudo
    without -n. Never raises.
"""


def read(max_lines=5000, timeout=10):
    """Not implemented yet."""
    return {"source": None, "lines": [], "why": "not implemented"}
