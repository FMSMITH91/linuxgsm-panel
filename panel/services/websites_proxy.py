"""The web proxy's configuration, rendered from the database (scaffold).

Builder W2 fills this in. render is a pure function of the enabled sites and the host's WebsiteProxy
row (exposure mode, allow list, origin TLS), unit-tested as text, and the helper applies its output.
allow_list returns the networks a 'restricted' host opens ports 80/443 to and trusts a client-address
header from: the row's own CIDRs plus the ranges of its presets from the signed catalog.
"""
# pylint: disable=unused-argument  # scaffold signatures; the builder that fills them in removes this


def render(sites, proxy=None):
    """The proxy configuration text for `sites` (enabled, with verified domains) under `proxy`'s settings."""
    raise NotImplementedError("websites_proxy.render is not built yet")


def allow_list(proxy):
    """The canonical networks `proxy` admits in 'restricted' mode: its CIDRs plus its presets' ranges."""
    raise NotImplementedError("websites_proxy.allow_list is not built yet")


def rules_problems(rules):
    """What is wrong with a site's custom rules (a list of dicts), as a list of sentences (empty: none)."""
    raise NotImplementedError("websites_proxy.rules_problems is not built yet")
