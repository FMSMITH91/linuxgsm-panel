"""The ONE `systemctl [--user] show linuxgsm-panel` per report.

Shared by R8 (Diagnostics' Service check), R15 (Panel process) and R21 (unit drift). Owner: builder B3.

unit_show(timeout=5) -> dict
    {"scope": "user"|"system"|None, "props": {Name: value, ...}, "error": None|"<fixed reason>"}
    props includes at least: ActiveState, SubState, UnitFileState, MainPID, NRestarts, Result,
    NeedDaemonReload, MemoryCurrent, MemoryPeak, TasksCurrent, ActiveEnterTimestamp, DropInPaths,
    FragmentPath, WorkingDirectory. Argv, stdin DEVNULL, --no-pager, timeout <= 5 s. Never raises:
    a missing bus or binary is error="unreadable" (or another fixed token), props {}.

    Also: "rc" (int or None) and "why" (a fixed token for the failure's class: "no-bus",
    "no-systemctl", "timeout", "no-unit-file", "not-loaded", "error"). A property an older systemd
    does not know (MemoryPeak before 255) is simply absent from props: the caller prints "n/a".
    Values carry paths (FragmentPath, DropInPaths, WorkingDirectory): callers compare them, and never
    print them.

Sections read it through shared(ctx), the report's memo under MEMO_KEY, so the three share one call.
"""
import os
import subprocess  # nosec B404 - one fixed argv (systemctl show), no shell

from panel.ops import system_ops as so

UNIT = "linuxgsm-panel.service"
USER_UNIT_FILE = "~/.config/systemd/user/linuxgsm-panel.service"
SYSTEM_UNIT_FILE = "/etc/systemd/system/linuxgsm-panel.service"
PROPS = ("ActiveState", "SubState", "UnitFileState", "MainPID", "NRestarts", "Result",
         "NeedDaemonReload", "MemoryCurrent", "MemoryPeak", "TasksCurrent", "ActiveEnterTimestamp",
         "ActiveEnterTimestampMonotonic", "DropInPaths", "FragmentPath", "WorkingDirectory",
         "KillMode", "LoadState")
MAX_TIMEOUT = 5


def scope():
    """'system', 'user' or None: which unit file this install has, as system_ops decides it."""
    if so._is_system_service():
        return "system"
    if os.path.exists(os.path.expanduser(USER_UNIT_FILE)):
        return "user"
    return None


def argv(which):
    """The systemctl argv for `which` scope ('system' or 'user')."""
    cmd = ["systemctl"]
    if which == "user":
        cmd.append("--user")
    return cmd + ["show", UNIT, "--no-pager", "-p", ",".join(PROPS)]


def run(cmd, timeout):
    """(stdout, stderr, rc) of `cmd`: stdin /dev/null, no shell, a hard timeout.

    Raises OSError or subprocess.TimeoutExpired. A module function, so the tests can stand in for it.
    """
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True,  # nosec B603
                       timeout=timeout, check=False, env=dict(os.environ, LC_ALL="C"))
    return r.stdout or "", r.stderr or "", r.returncode


def parse(text):
    """`Name=value` lines as a dict; a property printed empty is left out (the caller says n/a)."""
    props = {}
    for line in (text or "").splitlines():
        name, sep, value = line.partition("=")
        if sep and name in PROPS and value.strip() and value.strip() != "[not set]":
            props[name] = value.strip()
    return props


def _why(err):
    """A fixed token for a failed `systemctl show`'s stderr: the text itself is never kept."""
    low = (err or "").lower()
    if "bus" in low:
        return "no-bus"
    return "error"


def unit_show(timeout=5):
    """The unit's properties, read once. Never raises."""
    which = scope()
    res = {"scope": which, "props": {}, "error": None, "rc": None, "why": None}
    if which is None:
        res["error"], res["why"] = "unreadable", "no-unit-file"
        return res
    try:
        out, err, rc = run(argv(which), min(float(timeout), MAX_TIMEOUT))
    except subprocess.TimeoutExpired:
        res["error"], res["why"] = "unreadable", "timeout"
        return res
    except OSError:
        res["error"], res["why"] = "unreadable", "no-systemctl"
        return res
    res["rc"] = rc
    if rc != 0:
        res["error"], res["why"] = "unreadable", _why(err)
        return res
    res["props"] = parse(out)
    if res["props"].get("LoadState") == "not-found" or not res["props"]:
        res["error"], res["why"] = "unreadable", "not-loaded"
    return res


# The one memo key for the report's `systemctl show` (Diagnostics' R8, Panel process R15/R21).
MEMO_KEY = "systemd.unit_show"


def shared(ctx):
    """unit_show(), once per report."""
    return ctx.memo(MEMO_KEY, lambda: unit_show())  # pylint: disable=unnecessary-lambda
