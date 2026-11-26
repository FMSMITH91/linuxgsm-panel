"""Part 299 of the unit suite: the websites' runtime (builder W2).

1. The signed catalog's `sites` section: the floor's pins are whole and checked, a signed catalog's
   section is used only when it passes and only under the add-on rule (issued after this panel), a
   refused one leaves the floor's, and the signing tool refuses a catalog without a valid section.
2. The web proxy's configuration (websites_proxy.render) as text: the catch-all abort, the admin API
   off, HTTP/3 off, headers, timeouts, body limits, the per-site token, the three exposure modes and
   the forwarded-header trust they allow, the page cache and the custom rules.
3. The containers (websites.py): Quadlet units, the in-container server configs that refuse a request
   without the proxy's token, php.ini with the forced hardening, the app runtime, the object cache and
   the tunnel connector, and the shell the panel runs as a site's account.
4. The helper verbs and their remote forms: accounts, the proxy, the egress guard, quotas and the
   ws<id>_ database names.
5. The SSH layer and the firewall label; 6. the recipe engine.

HOW IT RUNS. Pure functions and the helper's own validators; no host is reached and nothing is
installed. Section 4 loads tools/panel-helper by path, as part05 does.
"""
import json as _json299
import os
import re as _re299

from unit.part01 import eq, _root
from panel.services import addons_catalog as _cat299
from panel.services import websites_catalog as _wc299

_FLOOR_PATH299 = os.path.join(_root, "panel", "addon_images", "catalog.json")
with open(_FLOOR_PATH299, encoding="utf-8") as _fh299:
    _FLOOR_DOC299 = _json299.load(_fh299)
_SITES299 = _FLOOR_DOC299["sites"]


def _copy299(value):
    return _json299.loads(_json299.dumps(value))


# ── 1. the catalog's sites section ──────────────────────────────────────────────────────────────
def _s299_floor():
    digests = [_SITES299["static"]["image"], _SITES299["wpcli"]["image"], _SITES299["object_cache"]["image"],
               _SITES299["tunnel"]["cloudflare"]["image"]]
    digests += [e["image"] for e in _SITES299["php"].values()]
    digests += [e["image"] for e in _SITES299["wordpress"]["php"].values()]
    digests += [e["image"] for r in _SITES299["runtimes"].values() for e in r["versions"].values()]
    eq("sites catalog: the floor's section passes the panel's own check, every image is pinned by a full sha256 "
       "digest, and it is what addons_catalog carries as the floor's section",
       (_wc299.sites_problems(_SITES299), all(_re299.fullmatch(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}", d) for d in digests),
        _cat299.FLOOR_SECTIONS.get("sites") == _SITES299, len(digests) >= 12),
       ([], True, True, True))
    eq("sites catalog: the shipped recipes are WordPress, phpBB, Drupal and MyBB, each release downloaded "
       "from an allowed https host with its sha256 (WordPress comes in its pinned image)",
       (sorted(_SITES299["recipes"]),
        [bool(_re299.fullmatch(r"[0-9a-f]{64}", r.get("sha256", ""))) for k, r in sorted(_SITES299["recipes"].items())
         if k != "wordpress"]),
       (["drupal", "mybb", "phpbb", "wordpress"], [True, True, True]))
    eq("sites catalog: the panel's digest shape is the add-on catalog's (one rule for both)",
       _wc299._DIGEST, _cat299._DIGEST)


def _bad299(path, value):
    """The floor's section with the field at `path` (a tuple of keys) set to `value`."""
    doc = _copy299(_SITES299)
    node = doc
    for key in path[:-1]:
        node = node[key]
    if value is KeyError:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return doc


_ZERO299 = "0" * 64


def _s299_refusals():
    caddy_url = _SITES299["caddy"]["assets"]["amd64"]["url"]
    cases = {
        "image by tag": _bad299(("static", "image"), "docker.io/nginxinc/nginx-unprivileged:stable"),
        "caddy from another host": _bad299(("caddy", "assets", "amd64", "url"),
                                           caddy_url.replace("github.com", "example.com")),
        "caddy asset of another version": _bad299(("caddy", "assets", "amd64", "url"),
                                                  caddy_url.replace("2.11.9", "2.11.8")),
        "short sha256": _bad299(("caddy", "assets", "amd64", "sha256"), "abc"),
        "php without eol": _bad299(("php", "8.4", "eol"), KeyError),
        "preset with a private net": _bad299(("presets", "cloudflare"), ["10.0.0.0/8", "2606:4700::/32"]),
        "preset IPv4 only": _bad299(("presets", "cloudflare"), ["173.245.48.0/20"]),
        "preset not canonical": _bad299(("presets", "cloudflare"), ["173.245.48.1/20", "2606:4700::/32"]),
        "recipe url with a query": _bad299(("recipes", "phpbb", "url"), _SITES299["recipes"]["phpbb"]["url"] + "?x=1"),
        "recipe url on a port": _bad299(("recipes", "mybb", "url"), "https://github.com:8443/mybb/x.zip"),
        "recipe step of an unknown type": _bad299(("recipes", "phpbb", "steps", 0), {"type": "run-shell"}),
        "secret on a command line": _bad299(("recipes", "wordpress", "steps", 3, "argv", 5),
                                            "--admin_password={admin_password}"),
        "config written outside the site": _bad299(("recipes", "phpbb", "steps", 2, "dest"), "../../.bashrc"),
        "unknown placeholder": _bad299(("recipes", "drupal", "steps", 3, "template"), "{panel_secret_key}"),
        "egress to any host": _bad299(("recipes", "wordpress", "egress"), ["example.com"]),
        "database step without database": _bad299(("recipes", "mybb", "database"), False),
        "no recipes": _bad299(("recipes",), KeyError),
    }
    let = sorted(k for k, doc in cases.items() if not _wc299.sites_problems(doc))
    eq("sites catalog: a tag instead of a digest, a proxy binary from another host or version, a short hash, a "
       "PHP version without its end of support, a private or one-family preset, a download URL with a query or "
       "port, an unknown step type, a secret on a command line, a path outside the site, an unknown value, egress "
       "to an unlisted host, a database mismatch and a missing key are each refused", let, [])


def _with_stored299(sites, issued="2099-01-01T00:00:00Z", floor_time=1):
    """websites_catalog.section() with a stored catalog holding `sites`; the module state put back after."""
    saved = dict(_cat299._state)
    stored = {"schema": 1, "seq": 7, "issued": issued, "expires": "2099-02-01T00:00:00Z",
              "addons": _copy299(_cat299.FLOOR)}
    if sites is not None:
        stored["sites"] = sites
    _cat299._state.update(loaded=True, stored=stored, floor_time=floor_time)
    try:
        return _wc299.section(), _wc299.pins("static"), _wc299.preset_ranges("cloudflare")
    finally:
        _cat299._state.clear()
        _cat299._state.update(saved)


def _s299_stored():
    newer = _copy299(_SITES299)
    newer["static"]["image"] = "docker.io/nginxinc/nginx-unprivileged@sha256:" + "1" * 64
    newer["presets"]["cloudflare"] = ["198.41.128.0/17", "2606:4700::/32"]
    (sites, src), static, preset = _with_stored299(newer)
    eq("sites catalog (pins, through section()): a signed catalog's valid section issued after this panel is the "
       "one installs and the allow list use, with its source",
       (static["image"], preset, src.get("kind"), src.get("seq"), sites is not None),
       (newer["static"]["image"], ["198.41.128.0/17", "2606:4700::/32"], "catalog", 7, True))
    broken = _bad299(("static", "image"), "docker.io/nginxinc/nginx-unprivileged:latest")
    (_sites, src), static, _p = _with_stored299(broken)
    eq("sites catalog (pins): a signed catalog whose section is refused changes nothing: the floor's pins stay",
       (static["image"], src), (_SITES299["static"]["image"], {"kind": "floor"}))
    (_sites, src), static, _p = _with_stored299(newer, floor_time=4102444800)
    eq("sites catalog (pins): a catalog issued before this panel's own commit is not used (the floor is newer)",
       (static["image"], src), (_SITES299["static"]["image"], {"kind": "floor"}))
    (_sites, src), static, _p = _with_stored299(None)
    eq("sites catalog (pins): a catalog signed before the section existed leaves the floor's (control)",
       (static["image"], src), (_SITES299["static"]["image"], {"kind": "floor"}))


def _s299_versions():
    from datetime import date as _date299
    eq("sites catalog: a PHP version past its upstream security support is not offered; today's supported ones are",
       (_wc299.php_versions(_date299(2026, 11, 26)), _wc299.php_versions(_date299(2028, 1, 1)),
        _wc299.php_image("php", "8.3", _date299(2028, 1, 1)), _wc299.php_image("wordpress", "8.4", _date299(2026, 11, 26))),
       (["8.3", "8.4", "8.5"], ["8.4", "8.5"], None, _SITES299["wordpress"]["php"]["8.4"]["image"]))
    rt = _wc299.runtimes(_date299(2027, 6, 1))
    eq("sites catalog: Node's versions are offered only while supported upstream, with the runtime's defaults",
       (sorted(rt["node"]["versions"]), rt["node"]["port"], rt["node"]["start"], rt["node"]["egress"]),
       (["24", "26"], 3000, "npm start", ["registry.npmjs.org"]))


def _s299_generator():
    import importlib.util as _ilu299
    spec = _ilu299.spec_from_file_location("addon_catalog_p299", os.path.join(_root, "tools", "addon_catalog.py"))
    gen = _ilu299.module_from_spec(spec)
    spec.loader.exec_module(gen)
    src = _copy299(_FLOOR_DOC299)
    no_sites = {k: v for k, v in src.items() if k != "sites"}
    bad_sites = dict(src, sites=_bad299(("php", "8.4", "image"), "docker.io/library/php:8.4-apache"))
    got = [gen.build(_json299.dumps(o), "", 1800000000, "auto")[0] for o in (no_sites, bad_sites, src)]
    old_published = dict(no_sites, seq=3, issued="2026-11-01T00:00:00Z", expires="2026-12-01T00:00:00Z")
    rc, out, _msg = gen.build(_json299.dumps(src), _json299.dumps(old_published), 1800000000, "auto")
    eq("sites catalog (signing tool): a catalog without `sites` or with a refused one is not signed; today's builds, "
       "and builds on a published catalog from before the section, carrying the section into the next seq",
       (got, rc, _json299.loads(out).get("seq") if out else None, "sites" in (_json299.loads(out) if out else {})),
       ([1, 1, 0], 0, 4, True))


for _step299 in (_s299_floor, _s299_refusals, _s299_stored, _s299_versions, _s299_generator):
    _step299()
