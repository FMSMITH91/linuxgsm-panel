#!/usr/bin/env python3
"""Keep the catalog's CDN allow-list presets current: fetch each CDN's published list, check it, update the catalog.

The panel's 'restricted' exposure mode opens ports 80/443 only to the networks of an allow list; each
preset's networks live in panel/addon_images/catalog.json (sites.presets.<cdn>), so panels get them
through the signed catalog and never fetch them themselves. This script reads each CDN's official list
from the fixed URLs in PROVIDERS (https only, no redirect followed, size capped) and accepts a CDN's
list only when every entry is a canonical, public network (no host bits, no private, loopback,
link-local or reserved range, a prefix no wider than /8 or /16) and both families are there. A CDN
whose list is refused keeps the catalog's networks it had; the others are still updated. Run by
.github/workflows/cdn-ranges.yml, which opens one pull request when the catalog changed.

    cloudflare  https://www.cloudflare.com/ips-v4 and /ips-v6, a network per line
    fastly      https://api.fastly.com/public-ip-list, JSON {"addresses": [...], "ipv6_addresses": [...]}

    cdn_ranges.py check     print "changed=true|false" (the catalog is rewritten when true) and, when a
                            CDN's list was refused, "refused=<names>"; exit 1 when one was refused
"""
import ipaddress
import json
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CATALOG = os.path.join(ROOT, "panel", "addon_images", "catalog.json")
PROVIDERS = {
    "cloudflare": ("lines", ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")),
    "fastly": ("fastly", ("https://api.fastly.com/public-ip-list",)),
}
URLS = tuple(u for _fmt, urls in PROVIDERS.values() for u in urls)
MAX_BYTES = 16384
MAX_NETS = 200
# Named, since Cloudflare's list host answers urllib's default user agent with 403 Forbidden.
USER_AGENT = "linuxgsm-panel-cdn-ranges"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("a redirect is not followed (%s)" % code)


def fetch(url, opener=None):
    """The text at `url` (https, no redirect, at most MAX_BYTES)."""
    if url not in URLS:
        raise ValueError("not one of the fixed CDN URLs")
    opener = opener or urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with opener.open(req, timeout=30) as resp:   # nosec B310 - one of the fixed https URLs above
        body = resp.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("the list is larger than expected")
    return body.decode("ascii")


def networks(entries):
    """`entries` (strings) when each is a canonical public network; ValueError on anything else."""
    out = []
    for item in entries:
        if not isinstance(item, str):
            raise ValueError("not a network: %r" % (item,))
        net = ipaddress.ip_network(item, strict=True)
        if str(net) != item or not net.is_global or net.prefixlen < (8 if net.version == 4 else 16):
            raise ValueError("not a canonical public network: %r" % item[:60])
        out.append(item)
    if not out or len(out) > MAX_NETS:
        raise ValueError("an empty or oversized list")
    return out


def entries(fmt, text):
    """The list's entries, as strings, out of one fetched body of format `fmt`."""
    if fmt == "lines":
        return text.split()
    doc = json.loads(text)
    if not isinstance(doc, dict) or not all(isinstance(doc.get(k), list) for k in ("addresses", "ipv6_addresses")):
        raise ValueError("not Fastly's {addresses, ipv6_addresses}")
    return doc["addresses"] + doc["ipv6_addresses"]


def provider_networks(name, fetcher=fetch):
    """CDN `name`'s published networks, every one checked, both families there; ValueError otherwise."""
    fmt, urls = PROVIDERS[name]
    nets = []
    for url in urls:
        nets += networks(entries(fmt, fetcher(url)))
    if {ipaddress.ip_network(n).version for n in nets} != {4, 6}:
        raise ValueError("both IPv4 and IPv6 networks are needed")
    if len(nets) > MAX_NETS:
        raise ValueError("an oversized list")
    return nets


def updated(catalog_text, found):
    """(new catalog text, changed) with sites.presets.<name> set to found[name] for each name of `found`."""
    doc = json.loads(catalog_text)
    presets = doc["sites"]["presets"]
    if all(presets.get(name) == nets for name, nets in found.items()):
        return catalog_text, False
    presets.update(found)
    return json.dumps(doc, indent=2, sort_keys=True) + "\n", True


def main(argv, fetcher=fetch, catalog=CATALOG):
    """Run `check`; the exit status."""
    if argv[1:] != ["check"]:
        sys.stderr.write(__doc__)
        return 2
    found, refused = {}, []
    for name in sorted(PROVIDERS):
        try:
            found[name] = provider_networks(name, fetcher)
        except (OSError, ValueError, KeyError, UnicodeDecodeError) as exc:
            sys.stderr.write("cdn_ranges: %s refused: %s\n" % (name, exc))
            refused.append(name)
    try:
        with open(catalog, encoding="utf-8") as fh:
            text, changed = updated(fh.read(), found)
    except (OSError, ValueError, KeyError) as exc:
        sys.stderr.write("cdn_ranges: the catalog could not be read: %s\n" % exc)
        return 1
    if changed:
        with open(catalog, "w", encoding="utf-8") as fh:
            fh.write(text)
    sys.stdout.write("changed=%s\n" % ("true" if changed else "false"))
    if refused:
        sys.stdout.write("refused=%s\n" % ",".join(refused))
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
