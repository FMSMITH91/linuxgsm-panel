"""Debug-report section(s): servers, console

Owner: builder B4. servers: per game server DB vs monitor vs port scan vs players, install jobs, LinuxGSM data (R52, R54, R55). console: console feed state per watched server (R56).
"""
from panel.ops.debug_report._base import Result


def section_servers(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'servers', "not implemented")

def section_console(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'console', "not implemented")
