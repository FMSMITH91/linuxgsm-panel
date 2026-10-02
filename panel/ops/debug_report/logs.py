"""Debug-report section(s): journal_digest, recent_log

Owner: builder B1. ONE journal read via _src_journal (R68, R69); journal_digest (R71); recent_log with source/span/zone header and budget (R70, R73).
"""
from panel.ops.debug_report._base import Result


def section_journal_digest(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'journal_digest', "not implemented")

def section_recent_log(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'recent_log', "not implemented")
