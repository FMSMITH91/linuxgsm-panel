"""Debug-report section(s): database, backups

Owner: builder B2. database: one integrity check off-hub, not-checked vs damaged, pragmas/backup/moved-aside/schema, table census and retention, audit digest (R57-R61). backups: panel backups and update snapshots (R62).
"""
from panel.ops.debug_report._base import Result


def section_database(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'database', "not implemented")

def section_backups(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'backups', "not implemented")
