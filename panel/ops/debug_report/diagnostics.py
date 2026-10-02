"""Debug-report section(s): diagnostics

Owner: builder B2. panel_diagnostics(), rendered sorted fail/warn/ok, with the R8-R14 fixes; its lines also go in the public summary (summary_lines).
"""
from panel.ops.debug_report._base import Result


def section_diagnostics(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'diagnostics', "not implemented")
