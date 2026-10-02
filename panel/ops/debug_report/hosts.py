"""Debug-report section(s): hosts_brief, hosts

Owner: builder B4. hosts_brief: the compact public block (R6, R53 conflicts). hosts: per-host transport/address class/flags, reachability, last probe error, tailscale peer, cached OS/specs, SSH internals (R46-R51).
"""
from panel.ops.debug_report._base import Result


def section_hosts_brief(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'hosts_brief', "not implemented")

def section_hosts(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'hosts', "not implemented")
