"""Part 314 of the unit suite: new app and image versions reach the websites' catalog by themselves.

1. Renovate's websites managers (.github/renovate.json, read as Renovate reads them: each matchString over the
   catalog's text, a recursive one layer by layer with the outer layers' groups kept, the tag from
   currentValueTemplate) match every image pin in the catalog's `sites` section once, by the tag the image really
   has, and npm's exact version; a digest update applied as Renovate applies it changes that pin alone and leaves a
   catalog the panel accepts; the package rules keep each image on its tag (cloudflared's tag, its release date,
   moves) and npm on its major, and check every websites pin daily.
2. The catalog's site recipes and images are whole: each download recipe has a version, an https url on the
   allowed hosts that names it and a 64-hex sha256, WordPress's recipe has the version of its image, and every
   image in `sites` is pinned by digest.

HOW IT RUNS. Pure functions over the catalog's text and copies of it. No network, no git.
"""
import copy as _copy314
import hashlib as _hash314
import json as _json314
import os
import re as _re314
import shutil as _sh314
import tempfile as _tf314

from unit.part01 import _root, eq
from panel.services import websites_catalog as _wc314

_TMP314 = _tf314.mkdtemp(prefix="p314-")
_CATALOG314 = os.path.join(_root, "panel", "addon_images", "catalog.json")
with open(_CATALOG314, encoding="utf-8") as _fh314:
    _TEXT314 = _fh314.read()
with open(os.path.join(_root, ".github", "renovate.json"), encoding="utf-8") as _fh314:
    _RN314 = _json314.load(_fh314)
_PIN314 = _re314.compile(r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}")


def _site_mgrs314(cfg=None):
    return [m for m in (cfg or _RN314).get("customManagers") or [] if m.get("description", "").startswith("Websites:")]


# ── 1. Renovate ─────────────────────────────────────────────────────────────────────────────────
def _py_re314(pattern):
    """A Renovate (RE2, JavaScript-style) regex as Python's: `(?<name>` is `(?P<name>`."""
    return _re314.compile(_re314.sub(r"\(\?<(?=[A-Za-z])", "(?P<", pattern))


def _render314(template, groups):
    """A currentValueTemplate or depNameTemplate with its {{{group}}} names filled (the only syntax used here)."""
    out = _re314.sub(r"\{\{\{(\w+)\}\}\}", lambda x: groups[x.group(1)], template)
    if "{{" in out:
        raise ValueError("a template construct this reader does not take: %r" % template)
    return out


def _matches314(mgr, text):
    """[(groups, replaceString)] one regex manager finds in `text`.

    "any" runs each matchString over the whole text; "recursive" narrows layer by layer, each layer's groups kept
    for the next, the last layer's match being the string Renovate replaces.
    """
    pats = [_py_re314(p) for p in mgr["matchStrings"]]
    if mgr.get("matchStringsStrategy") != "recursive":
        return [(x.groupdict(), x.group(0)) for p in pats for x in p.finditer(text)]
    out = []

    def layer(sub, i, groups):
        for x in pats[i].finditer(sub):
            g = dict(groups, **{k: v for k, v in x.groupdict().items() if v is not None})
            if i == len(pats) - 1:
                out.append((g, x.group(0)))
            else:
                layer(x.group(0), i + 1, g)
    layer(text, 0, {})
    return out


def _deps314(mgrs, text):
    """[{depName, currentValue, currentDigest, datasource, replaceString, valueCaptured}] the managers extract."""
    deps = []
    for m in mgrs:
        for g, rs in _matches314(m, text):
            deps.append({"depName": g.get("depName") or _render314(m.get("depNameTemplate", ""), g),
                         "currentValue": g.get("currentValue") or _render314(m.get("currentValueTemplate", ""), g),
                         "currentDigest": g.get("currentDigest"), "datasource": m.get("datasourceTemplate"),
                         "replaceString": rs, "valueCaptured": "currentValue" in g})
    return deps


def _walk314(node, path=()):
    """(path, value) of every string in a JSON tree."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk314(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk314(v, path + (i,))
    elif isinstance(node, str):
        yield path, node


def _want314(sites):
    """({(depName, tag, digest)} each websites pin must be extracted as, [paths of pins no rule here covers]).

    The tag is the one the image has (read off Docker Hub on 2026-11-27: every digest in the catalog was the digest
    of exactly this tag), built from the catalog's own keys and versions. A pin no rule covers is a new image the
    managers must learn.
    """
    want, unknown = set(), []
    wp, cache = sites["wordpress"]["version"], sites["caddy_cache"]["caddy"]
    rules = {("php", None, "image"): lambda p: p[1] + "-apache",
             ("runtimes", "node", "versions", None, "image"): lambda p: p[3] + "-bookworm-slim",
             ("wordpress", "php", None, "image"): lambda p: "%s-php%s-apache" % (wp, p[2]),
             ("wpcli", "image"): lambda p: "cli-%s-php8.4" % sites["wpcli"]["version"],
             ("object_cache", "image"): lambda p: sites["object_cache"]["version"] + "-alpine",
             ("static", "image"): lambda p: sites["static"]["version"] + "-alpine-slim",
             ("tunnel", "cloudflare", "image"): lambda p: sites["tunnel"]["cloudflare"]["version"],
             ("tunnel", "cloudflare", "certs"): lambda p: "trixie-slim",
             ("caddy_cache", "base"): lambda p: cache, ("caddy_cache", "builder"): lambda p: cache + "-builder"}
    for path, value in _walk314(sites):
        if not _PIN314.fullmatch(value):
            continue
        rule = [f for shape, f in rules.items() if len(shape) == len(path)
                and all(s is None or s == q for s, q in zip(shape, path))]
        if rule:
            name, digest = value.split("@")
            want.add((name, rule[0](path), digest))
        else:
            unknown.append(".".join(map(str, path)))
    want.add(("npm", sites["runtimes"]["node"]["npm"], None))
    return want, unknown


def _got314(mgrs, text):
    return sorted((d["depName"], d["currentValue"], d["currentDigest"]) for d in _deps314(mgrs, text))


def _coverage314(mgrs, text):
    """(extracted, wanted, unknown pins) for a catalog text: the gate's three answers."""
    want, unknown = _want314(_json314.loads(text)["sites"])
    return _got314(mgrs, text), sorted(want, key=repr), unknown


def _s314_renovate_pins():
    got, want, unknown = _coverage314(_site_mgrs314(), _TEXT314)
    eq("renovate (websites): every image pin in the catalog's sites section is extracted once, by the tag the image "
       "has (php:<series>-apache, node:<version>-bookworm-slim, wordpress:<version>-php<series>-apache, "
       "wordpress:cli-<version>-php8.4, valkey:<major>-alpine, nginx-unprivileged:<x.y>-alpine-slim, cloudflared's "
       "release, debian:trixie-slim, caddy:<version> and its builder), and npm's exact version; no pin is left over",
       (sorted(got, key=repr), unknown, len(got)), (want, [], 17))
    addon = [m for m in _RN314["customManagers"] if m not in _site_mgrs314()
             and any("addon_images" in f for f in m.get("managerFilePatterns") or [])]
    sites_digests = {v.split("@")[1] for _p, v in _walk314(_json314.loads(_TEXT314)["sites"]) if _PIN314.fullmatch(v)}
    eq("renovate (websites): the add-ons' managers take no websites pin, and every websites manager reads the catalog "
       "alone",
       ([d for d in _deps314(addon, _TEXT314) if d["currentDigest"] in sites_digests],
        [m["managerFilePatterns"] for m in _site_mgrs314() if m["managerFilePatterns"] != ["/^panel/addon_images/catalog\\.json$/"]]),
       ([], []))
    # Controls: a fourth PHP series is extracted with its own tag; without the PHP manager its pins are left over.
    doc = _json314.loads(_TEXT314)
    doc["sites"]["php"]["8.6"] = dict(doc["sites"]["php"]["8.5"], image="docker.io/library/php@sha256:" + "6" * 64)
    wider = _json314.dumps(doc, indent=2, sort_keys=True) + "\n"
    got6, want6, _u6 = _coverage314(_site_mgrs314(), wider)
    no_php = [m for m in _site_mgrs314() if "library/php" not in "".join(m["matchStrings"])]
    got_np, want_np, _u = _coverage314(no_php, _TEXT314)
    eq("renovate (websites): (control) a fourth PHP series in the catalog is extracted as php:8.6-apache with no "
       "change to the config; without the PHP manager the three PHP pins are what is missing",
       (sorted(got6, key=repr) == want6, ("docker.io/library/php", "8.6-apache", "sha256:" + "6" * 64) in got6,
        sorted(set(want_np) - set(got_np))),
       (True, True, sorted(w for w in want_np if w[0] == "docker.io/library/php")))


def _apply314(text, dep, new_value, new_digest):
    """`text` after one update applied as Renovate's auto-replace does.

    In the dependency's replaceString the digest becomes the new digest and, only when the manager captured the
    tag, the tag becomes the new tag.
    """
    new = dep["replaceString"]
    if dep["valueCaptured"]:
        new = new.replace(dep["currentValue"], new_value, 1)
    if dep["currentDigest"]:
        new = new.replace(dep["currentDigest"], new_digest, 1)
    assert text.count(dep["replaceString"]) == 1, dep["replaceString"]
    return text.replace(dep["replaceString"], new, 1)


def _changed314(a, b):
    """The paths whose strings differ between two JSON trees."""
    pa, pb = dict(_walk314(a)), dict(_walk314(b))
    return sorted(".".join(map(str, p)) for p in set(pa) | set(pb) if pa.get(p) != pb.get(p))


def _s314_renovate_updates():
    base = _json314.loads(_TEXT314)
    bad = []
    for dep in _deps314(_site_mgrs314(), _TEXT314):
        new_value = "2026.12.0" if dep["depName"].endswith("/cloudflared") else "11.99.0" if dep["depName"] == "npm" \
            else dep["currentValue"]
        new_digest = "sha256:" + _hash314.sha256(dep["replaceString"].encode()).hexdigest() if dep["currentDigest"] else None
        doc = _json314.loads(_apply314(_TEXT314, dep, new_value, new_digest))
        changed, problems = _changed314(base, doc), _wc314.sites_problems(doc["sites"])
        want = 2 if dep["depName"].endswith("/cloudflared") else 1
        if len(changed) != want or problems or not all(p.startswith("sites.") for p in changed):
            bad.append((dep["depName"], dep["currentValue"], changed, problems[:2]))
    eq("renovate (websites): each update applied as Renovate applies it (the digest, and cloudflared's version with "
       "it) changes that one pin alone, and the catalog still passes the panel's check",
       bad, [])


def _rule_on314(rules, datasource, dep, update):
    """Whether Renovate raises an update of `update` type for `dep`.

    The package rules in order, the last that matches deciding (the rules here match by datasource, dep name and
    update type only).
    """
    on = True
    for r in rules:
        if (datasource in r.get("matchDatasources", [datasource]) and dep in r.get("matchDepNames", [dep])
                and update in r.get("matchUpdateTypes", [update]) and "enabled" in r
                and not set(r) - {"description", "matchDatasources", "matchDepNames", "matchUpdateTypes", "enabled"}):
            on = r["enabled"]
    return on


def _s314_rules():
    rules = _RN314["packageRules"]
    cases = [("docker", "docker.io/library/php", "minor"), ("docker", "docker.io/library/php", "digest"),
             ("docker", "docker.io/library/node", "major"), ("docker", "docker.io/library/wordpress", "patch"),
             ("docker", "docker.io/library/wordpress", "digest"), ("docker", "docker.io/cloudflare/cloudflared", "minor"),
             ("docker", "docker.io/cloudflare/cloudflared", "major"), ("npm", "npm", "major"), ("npm", "npm", "minor")]
    want = [False, True, False, False, True, True, True, False, True]
    without = [r for r in rules if "cloudflared" not in "".join(r.get("matchDepNames") or [])]
    eq("renovate (websites): an image keeps its tag (a digest update only: no other PHP, Node.js or WordPress), "
       "cloudflared's release tag moves (a new year included), npm stays on its major; (control) without the "
       "cloudflared rule its new release would not be raised",
       ([_rule_on314(rules, *c) for c in cases], _rule_on314(without, *cases[5])), (want, False))
    daily = [r for r in rules if r.get("schedule") == ["* 0-5 * * *"] and r.get("description", "").startswith("Websites:")]
    deps = sorted({d["depName"] for d in _deps314(_site_mgrs314(), _TEXT314)})
    eq("renovate (websites): every websites dependency is checked daily, like the add-ons' pins",
       [sorted(r.get("matchDepNames") or []) for r in daily], [deps])


# ── 2. the catalog's recipes and images are whole ───────────────────────────────────────────────
def _shape_bad314(sites):
    """What a catalog's sites section lacks for a new install to use its newest releases and images."""
    bad = []
    for name, r in sorted(sites["recipes"].items()):
        downloads = any(s.get("type") == "download-verify-unpack" for s in r.get("steps", []))
        if r.get("kind") == "wordpress":
            if r.get("version") != sites["wordpress"]["version"] or "url" in r or "sha256" in r:
                bad.append("%s: WordPress's code is its image's: the recipe's version is sites.wordpress's" % name)
            continue
        url = r.get("url") if isinstance(r.get("url"), str) else ""
        host = url[len("https://"):].split("/")[0] if url.startswith("https://") else ""
        if not downloads or not _re314.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", str(r.get("version"))):
            bad.append("%s: a download step and a version" % name)
        elif host not in _wc314.ALLOWED_HOSTS or r["version"] not in url.replace(r["version"].replace(".", ""),
                                                                                  r["version"]):
            bad.append("%s: an https url on an allowed host that names its version" % name)
        if not _re314.fullmatch(r"[0-9a-f]{64}", str(r.get("sha256"))):
            bad.append("%s: a 64-hex sha256" % name)
    for path, value in _walk314({k: v for k, v in sites.items() if k not in ("recipes", "origin_pull", "presets")}):
        if path[-1] in ("image", "base", "builder", "certs") and not _PIN314.fullmatch(value):
            bad.append("%s: not pinned by digest" % ".".join(map(str, path)))
    return bad


def _s314_shape():
    eq("catalog: every site recipe that downloads has a version, an https url on the allowed hosts naming it and a "
       "64-hex sha256; WordPress's recipe has its image's version; every site image is pinned by digest",
       _shape_bad314(_json314.loads(_TEXT314)["sites"]), [])
    s = _copy314.deepcopy(_json314.loads(_TEXT314)["sites"])
    s["recipes"]["phpbb"]["url"] = s["recipes"]["phpbb"]["url"].replace("https://", "http://")
    del s["recipes"]["smf"]["sha256"]
    s["recipes"]["mybb"]["url"] = "https://example.org/mybb_1841.zip"
    s["recipes"]["drupal"]["url"] = s["recipes"]["drupal"]["url"].replace(s["recipes"]["drupal"]["version"], "11.0.0")
    s["static"]["image"] = "docker.io/nginx/nginx-unprivileged:1.30-alpine-slim"
    s["recipes"]["wordpress"]["version"] = "1.0"
    eq("catalog: (control) an http url, a missing sha256, a host off the list, a url naming another version, an image "
       "by tag and a WordPress recipe off its image's version are each named",
       _shape_bad314(s),
       ["drupal: an https url on an allowed host that names its version",
        "mybb: an https url on an allowed host that names its version",
        "phpbb: an https url on an allowed host that names its version", "smf: a 64-hex sha256",
        "wordpress: WordPress's code is its image's: the recipe's version is sites.wordpress's",
        "static.image: not pinned by digest"])


for _step314 in (_s314_renovate_pins, _s314_renovate_updates, _s314_rules, _s314_shape):
    _step314()
_sh314.rmtree(_TMP314, ignore_errors=True)
