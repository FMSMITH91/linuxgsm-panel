"""Debug-report section(s): errors_since_start

Owner: builder B3. The swallowed-error counter fed by the logging handler app.py attaches (R23, R24),
read from runtime_stats.
"""
from panel.ops.debug_report._base import Result


def section_errors_since_start(ctx):
    """Not implemented yet."""
    return Result().find("unread", "errors_since_start", "not implemented")
