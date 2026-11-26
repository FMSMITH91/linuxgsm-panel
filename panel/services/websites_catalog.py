"""The websites' pinned images, proxy binary and allow-list presets, from the signed catalog (scaffold).

Builder W2 fills this in, reading the catalog's `sites` section through addons_catalog's accessor (no
second signature or store). pins(kind) is what installs and updates use; preset_ranges(name) is what
a 'restricted' host's allow list takes for a preset such as "cloudflare".
"""
# pylint: disable=unused-argument  # scaffold signatures; the builder that fills them in removes this


def pins(kind):
    """The pins for `kind` (a site kind, "caddy" or "tunnel") as a dict: image digest, or url/sha256/version."""
    raise NotImplementedError("websites_catalog.pins is not built yet")


def preset_ranges(name):
    """The networks of allow-list preset `name` ("cloudflare"), IPv4 and IPv6, as canonical strings."""
    raise NotImplementedError("websites_catalog.preset_ranges is not built yet")


def runtimes():
    """The runtimes the catalog offers: {name: {versions: {version: image}, build, start, port}}."""
    raise NotImplementedError("websites_catalog.runtimes is not built yet")


def recipes():
    """The one-click app recipes the catalog offers: {name: {kind, runtime, version, url, sha256, steps}}."""
    raise NotImplementedError("websites_catalog.recipes is not built yet")
