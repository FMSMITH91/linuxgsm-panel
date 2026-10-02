"""Debug-report section(s): workers

Owner: builder B4. heartbeats and respawns from runtime_stats (R22).
"""
from panel.ops.debug_report._base import Result


def section_workers(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'workers', "not implemented")
