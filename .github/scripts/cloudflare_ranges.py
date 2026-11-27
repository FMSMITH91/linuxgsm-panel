#!/usr/bin/env python3
"""Keep the catalog's Cloudflare ranges current: fetch Cloudflare's published lists, check them, update the catalog.

The panel's 'restricted' exposure mode opens ports 80/443 only to the networks of an allow-list preset;
the Cloudflare preset's networks live in panel/addon_images/catalog.json (sites.presets.cloudflare), so
panels get them through the signed catalog and never fetch them themselves. This script reads
https://www.cloudflare.com/ips-v4 and /ips-v6 (fixed URLs, https only, no redirect followed, size
capped), and accepts them only when every line is a canonical, public network (no host bits, no private,
loopback, link-local or reserved range, a prefix no wider than /8 or /16) and both families are there,
before anything is written. Run by .github/workflows/cloudflare-ranges.yml, which opens a pull request
when the catalog changed.

    cloudflare_ranges.py check     exit 0 and print "changed=true|false"; the catalog is rewritten when true
"""
import ipaddress
import json
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CATALOG = os.path.join(ROOT, "panel", "addon_images", "catalog.json")
URLS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
MAX_BYTES = 16384
MAX_NETS = 200


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("a redirect is not followed (%s)" % code)


def fetch(url, opener=None):
    """The text at `url` (https, no redirect, at most MAX_BYTES)."""
    if url not in URLS:
        raise ValueError("not one of the fixed Cloudflare URLs")
    opener = opener or urllib.request.build_opener(_NoRedirect)
    with opener.open(url, timeout=30) as resp:   # nosec B310 - one of the fixed https URLs above
        body = resp.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("the list is larger than expected")
    return body.decode("ascii")


def networks(text):
    """The canonical public networks of one list (a line each); ValueError on anything else."""
    out = []
    for line in text.split():
        net = ipaddress.ip_network(line, strict=True)
        if str(net) != line or not net.is_global or net.prefixlen < (8 if net.version == 4 else 16):
            raise ValueError("not a canonical public network: %r" % line[:60])
        out.append(line)
    if not out or len(out) > MAX_NETS:
        raise ValueError("an empty or oversized list")
    return out


def updated(catalog_text, v4, v6):
    """(new catalog text, changed) with sites.presets.cloudflare set to `v4` + `v6`."""
    doc = json.loads(catalog_text)
    nets = v4 + v6
    if {ipaddress.ip_network(n).version for n in nets} != {4, 6}:
        raise ValueError("both IPv4 and IPv6 networks are needed")
    if doc["sites"]["presets"]["cloudflare"] == nets:
        return catalog_text, False
    doc["sites"]["presets"]["cloudflare"] = nets
    return json.dumps(doc, indent=2, sort_keys=True) + "\n", True


def main(argv, fetcher=fetch, catalog=CATALOG):
    """Run `check`; the exit status."""
    if argv[1:] != ["check"]:
        sys.stderr.write(__doc__)
        return 2
    try:
        v4, v6 = (networks(fetcher(u)) for u in URLS)
        with open(catalog, encoding="utf-8") as fh:
            text, changed = updated(fh.read(), v4, v6)
    except (OSError, ValueError, KeyError, UnicodeDecodeError) as exc:
        sys.stderr.write("cloudflare_ranges: refused: %s\n" % exc)
        return 1
    if changed:
        with open(catalog, "w", encoding="utf-8") as fh:
            fh.write(text)
    sys.stdout.write("changed=%s\n" % ("true" if changed else "false"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
