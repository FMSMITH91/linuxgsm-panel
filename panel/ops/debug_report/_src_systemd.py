"""The ONE `systemctl [--user] show linuxgsm-panel` per report, shared by R8 (Diagnostics' Service
check), R15 (Panel process) and R21 (unit drift). Owner: builder B3.

unit_show(timeout=5) -> dict
    {"scope": "user"|"system"|None, "props": {Name: value, ...}, "error": None|"<fixed reason>"}
    props includes at least: ActiveState, SubState, UnitFileState, MainPID, NRestarts, Result,
    NeedDaemonReload, MemoryCurrent, MemoryPeak, TasksCurrent, ActiveEnterTimestamp, DropInPaths,
    FragmentPath, WorkingDirectory. Argv, stdin DEVNULL, --no-pager, timeout <= 5 s. Never raises:
    a missing bus or binary is error="unreadable" (or another fixed token), props {}.
"""


def unit_show(timeout=5):
    """Not implemented yet."""
    return {"scope": None, "props": {}, "error": "not implemented"}
