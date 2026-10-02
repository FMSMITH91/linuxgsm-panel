"""Debug-report section(s): config

Owner: builder B1. whitelisted and classified config, file vs running, never defaults when unreadable (R65, R66, R67, plus R37/R39's running values).
"""
from panel.ops.debug_report._base import Result


def section_config(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'config', "not implemented")
