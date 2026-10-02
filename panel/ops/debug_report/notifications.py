"""Debug-report section(s): notifications

Owner: builder B3. channels as booleans, delivery counters, command-bot polling (R63).
"""
from panel.ops.debug_report._base import Result


def section_notifications(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'notifications', "not implemented")
