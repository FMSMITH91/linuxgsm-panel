"""Debug-report header lines and the Dependencies section.

Owner: builder B1. header_lines(ctx): generated time and build time (R3), panel version, the commit
this PROCESS runs vs the checkout's HEAD with RESTART PENDING and the tracked branch (R4, R32's one
header token), OS / kernel / Python, host clock zone + NTP + locale (R5).
section_dependencies: requirements.txt pins vs installed vs loaded (R64).
"""
from panel.ops.debug_report._base import Result


def header_lines(ctx):
    """Not implemented yet: the assembler falls back to a minimal header."""
    raise NotImplementedError


def section_dependencies(ctx):
    """Not implemented yet."""
    return Result().find("unread", "dependencies", "not implemented")
