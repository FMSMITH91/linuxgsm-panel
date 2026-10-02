"""The ONE Tailscale read per report, shared by R36, R49 and R72's name list. Owner: builder B3.

info() -> dict or None
    From panel.ops.tailscale_integration.get_tailscale_info() WITHOUT force_refresh (its 15 s
    cache), plus the fields R36/R49 need from the same status/prefs JSON. No second CLI call, no
    ping. Never raises: None when tailscale is absent or unreadable.
"""


def info():
    """Not implemented yet."""
    return None
