"""Debug-report section(s): network, access

Owner: builder B3. network: Tailscale/Serve/Funnel (R36), proxy trust (R37), this request (R38), cookies (R39), UFW (R40), fail2ban (R41). access: sign-ins/auth.log (R43), throttle and ban gate (R44), accounts/2FA counts (R45).
"""
from panel.ops.debug_report._base import Result


def section_network(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'network', "not implemented")

def section_access(ctx):
    """Not implemented yet."""
    return Result().find("unread", 'access', "not implemented")
