"""Debug-report section(s): root_pieces

Owner: builder B2. helper fresh check + privileged-call counters (R25), root-owned pieces vs the commit
they belong to (R27), origin category (R28), host prerequisites (R29).
"""
from panel.ops.debug_report._base import Result


def section_root_pieces(ctx):
    """Not implemented yet."""
    return Result().find("unread", "root_pieces", "not implemented")
