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
3. .github/scripts/site_app_versions.py against stand-in upstreams: a newer stable release whose publisher's
   checksum matches is written (version, url, sha256 and a strip folder that names the version, nothing else);
   a mismatched checksum, a missing folder, another branch or an older release is not; WordPress moves with its
   image's digests; nothing is written by `plan`; its fetch follows a redirect only to an allowed host.
4. .github/workflows/site-app-versions.yml: daily, blocked egress to exactly the script's hosts, the job token's
   two write scopes, one pull request at a time, a refused release fails the run.

HOW IT RUNS. Pure functions over copies of the catalog in this part's scratch directory; the script's own `fetch`
runs a stand-in curl (a Python script first on PATH). No network, no git, nothing outside the scratch directory.
"""
import copy as _copy314
import hashlib as _hash314
import importlib.util as _ilu314
import io as _io314
import json as _json314
import os
import re as _re314
import shutil as _sh314
import sys as _sys314
import tarfile as _tar314
import tempfile as _tf314
import zipfile as _zip314

from unit.part01 import _root, eq
from unit.part29 import _code29, _job29, _name29, _steps29, _wf29
from unit.part223 import _egress223
from panel.services import websites_catalog as _wc314

_TMP314 = _tf314.mkdtemp(prefix="p314-")
_CATALOG314 = os.path.join(_root, "panel", "addon_images", "catalog.json")
with open(_CATALOG314, encoding="utf-8") as _fh314:
    _TEXT314 = _fh314.read()
with open(os.path.join(_root, ".github", "renovate.json"), encoding="utf-8") as _fh314:
    _RN314 = _json314.load(_fh314)
_SPEC314 = _ilu314.spec_from_file_location("site_app_versions_p314",
                                           os.path.join(_root, ".github", "scripts", "site_app_versions.py"))
_SAV314 = _ilu314.module_from_spec(_SPEC314)
_SPEC314.loader.exec_module(_SAV314)
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
    bad, deps = [], _deps314(_site_mgrs314(), _TEXT314)
    for dep in deps:
        new_value = "2026.12.0" if dep["depName"].endswith("/cloudflared") else "11.99.0" if dep["depName"] == "npm" \
            else dep["currentValue"]
        new_digest = "sha256:" + _hash314.sha256(dep["replaceString"].encode()).hexdigest() if dep["currentDigest"] else None
        doc = _json314.loads(_apply314(_TEXT314, dep, new_value, new_digest))
        changed, problems = _changed314(base, doc), _wc314.sites_problems(doc["sites"])
        want = 2 if dep["depName"].endswith("/cloudflared") else 1
        if len(changed) != want or problems or not all(p.startswith("sites.") for p in changed):
            bad.append((dep["depName"], dep["currentValue"], changed, problems[:2]))
    eq("renovate (websites): each update applied as Renovate applies it (the digest, and cloudflared's version with "
       "it) changes that one pin alone, and the catalog still passes the panel's check (all 17 tried)",
       (bad, len(deps)), ([], 17))


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


# ── 3. the script, against stand-in upstreams ───────────────────────────────────────────────────
def _zipped314(files):
    buf = _io314.BytesIO()
    with _zip314.ZipFile(buf, "w") as zf:
        for name in files:
            zf.writestr(name, "x")
    return buf.getvalue()


def _tarred314(files):
    buf = _io314.BytesIO()
    with _tar314.open(fileobj=buf, mode="w:gz") as tf:
        for name in files:
            info = _tar314.TarInfo(name)
            info.size = 1
            tf.addfile(info, _io314.BytesIO(b"x"))
    return buf.getvalue()


def _sha314(data):
    return _hash314.sha256(data).hexdigest()


def _upstream314(**over):
    """{url: body or (body, headers)}: one newer release of every app, and WordPress's image on every PHP series.

    Each release carries its publisher's checksum; `over` replaces entries (None: the url answers 404).
    """
    phpbb, drupal = _zipped314(["phpBB3/index.php"]), _tarred314(["drupal-11.4.15/index.php"])
    mybb, smf = _zipped314(["Upload/index.php", "Documentation/readme.html"]), _tarred314(["SMF-2.1.9/index.php"])
    d_url = "https://ftp.drupal.org/files/projects/drupal-11.4.15.tar.gz"
    rel = ("<release><name>drupal {v}</name><version>{v}</version><status>published</status><release_link>"
           "https://www.drupal.org/project/drupal/releases/{v}</release_link><files><file><url>"
           "https://ftp.drupal.org/files/projects/drupal-{v}.tar.gz</url><archive_type>tar.gz</archive_type>"
           "<md5>{md5}</md5><size>{size}</size></file></files><terms><term><name>Release type</name><value>{t}</value>"
           "</term></terms><security covered=\"1\">Covered</security></release>")
    history = ("<project><supported_branches>10.6.,11.4.,11.5.,12.0.</supported_branches><releases>"
               + rel.format(v="12.0.1", md5="0" * 32, size=1, t="Bug fixes")
               + rel.format(v="11.5.0-beta1", md5="0" * 32, size=1, t="New features")
               + rel.format(v="11.4.15", md5=_hash314.md5(drupal, usedforsecurity=False).hexdigest(), size=len(drupal),
                            t="Security update")
               + rel.format(v="11.4.14", md5="0" * 32, size=1, t="Insecure") + "</releases></project>")
    page = ('<a href="%s" class="download">Download tar.gz</a><div class="views-field-field-release-file-sha256">'
            '<span class="views-label views-label-field-release-file-sha256">SHA-256: </span><span class="field-'
            'content hash">%s</span></div>' % (d_url, _sha314(drupal)))
    gh_asset = {"name": "mybb_1842.zip", "digest": "sha256:" + _sha314(mybb),
                "browser_download_url": "https://github.com/mybb/mybb/releases/download/mybb_1842/mybb_1842.zip"}
    wp = {"https://registry-1.docker.io/v2/library/wordpress/manifests/7.1.6-php%s-apache" % s:
          (b"", {"docker-content-digest": "sha256:" + _sha314(s.encode())}) for s in ("8.3", "8.4", "8.5")}
    up = {"https://version.phpbb.com/phpbb/versions.json": _json314.dumps({"stable": {"3.3": {
              "current": "3.3.20", "announcement": "https://www.phpbb.com/community/viewtopic.php?t=1"}}}).encode(),
          "https://download.phpbb.com/pub/release/3.3/3.3.20/phpBB-3.3.20.zip": phpbb,
          "https://download.phpbb.com/pub/release/3.3/3.3.20/phpBB-3.3.20.zip.sha256":
              ("%s  phpBB-3.3.20.zip\n" % _sha314(phpbb)).encode(),
          _SAV314.DRUPAL_HISTORY: history.encode(), d_url: drupal,
          "https://www.drupal.org/project/drupal/releases/11.4.15": page.encode(),
          "https://mybb.com/version_check.php": b"<mybb><latest_version>1.8.42</latest_version>"
                                                b"<version_code>1842</version_code></mybb>",
          "https://api.github.com/repos/mybb/mybb/releases/tags/mybb_1842": _json314.dumps({
              "draft": False, "prerelease": False, "assets": [gh_asset],
              "html_url": "https://github.com/mybb/mybb/releases/tag/mybb_1842"}).encode(),
          gh_asset["browser_download_url"]: mybb,
          "https://api.github.com/repos/SimpleMachines/SMF/releases?per_page=50": _json314.dumps([
              {"tag_name": "v3.0.0", "prerelease": True}, {"tag_name": "v2.1.9"}, {"tag_name": "v2.1.8"}]).encode(),
          "https://github.com/SimpleMachines/SMF/archive/refs/tags/v2.1.9.tar.gz": smf,
          _SAV314.WP_CHECK: _json314.dumps({"offers": [{"response": "upgrade", "current": "7.1.6"}]}).encode(),
          _SAV314.WP_TOKEN: _json314.dumps({"token": "t" * 40}).encode()}
    up.update(wp)
    up.update(over)
    return up


def _getter314(up, seen=None):
    """A stand-in for the script's fetch over `up`: an unknown url is an error, None answers 404."""
    def get(url, limit=_SAV314.META_MAX, headers=None, method="GET"):
        if seen is not None:
            seen.append(url)
        _SAV314.allowed(url)
        if url not in up:
            raise OSError("no stand-in for %s" % url)
        got = up[url]
        if got is None:
            return None, {}
        body, hdrs = got if isinstance(got, tuple) else (got, {})
        if len(body) > limit and method != "HEAD":
            raise _SAV314.Refused("larger than expected")
        return body, hdrs
    return get


def _run314(argv_tail, up, catalog_text=None):
    """(exit status, stdout, the catalog after, the body file's text or None) of main() over a scratch catalog."""
    d = _tf314.mkdtemp(prefix="run-", dir=_TMP314)
    path, body = os.path.join(d, "catalog.json"), os.path.join(d, "body.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(catalog_text or _TEXT314)
    argv = ["site_app_versions.py"] + [body if a == "BODY" else a for a in argv_tail]
    out, saved = _io314.StringIO(), (_sys314.stdout, _sys314.stderr)
    _sys314.stdout, _sys314.stderr = out, _io314.StringIO()
    try:
        rc = _SAV314.main(argv, get=_getter314(up), catalog=path)
    finally:
        _sys314.stdout, _sys314.stderr = saved
    with open(path, encoding="utf-8") as fh:
        after = fh.read()
    text = open(body, encoding="utf-8").read() if os.path.exists(body) else None
    return rc, out.getvalue(), after, text


def _s314_script_writes():
    rc, out, after, body = _run314(["check", "BODY"], _upstream314())
    old, new = _json314.loads(_TEXT314), _json314.loads(after)
    r = new["sites"]["recipes"]
    eq("site app versions (main, check): a newer stable release of every app whose publisher's checksum matches is "
       "written as version, url and sha256 (and the strip folder that names the version: Drupal's, SMF's), "
       "WordPress's version with its image on each PHP series; nothing else changes and the panel accepts it",
       (rc, out, _changed314(old, new), _wc314.sites_problems(new["sites"]),
        [(a, r[a]["version"], r[a]["url"]) for a in ("drupal", "mybb", "phpbb", "smf")], after.endswith("}\n")),
       (0, "changed=true\nrefused=\n", sorted(
           ["sites.recipes.%s.%s" % (a, k) for a in ("drupal", "mybb", "phpbb", "smf") for k in ("version", "url", "sha256")]
           + ["sites.recipes.drupal.steps.1.strip", "sites.recipes.smf.steps.1.strip", "sites.recipes.wordpress.version",
              "sites.wordpress.version"] + ["sites.wordpress.php.%s.image" % s for s in ("8.3", "8.4", "8.5")]),
        [], [("drupal", "11.4.15", "https://ftp.drupal.org/files/projects/drupal-11.4.15.tar.gz"),
             ("mybb", "1.8.42", "https://github.com/mybb/mybb/releases/download/mybb_1842/mybb_1842.zip"),
             ("phpbb", "3.3.20", "https://download.phpbb.com/pub/release/3.3/3.3.20/phpBB-3.3.20.zip"),
             ("smf", "2.1.9", "https://github.com/SimpleMachines/SMF/archive/refs/tags/v2.1.9.tar.gz")], True))
    up = _upstream314()
    eq("site app versions: the sha256 written is the archive's own, and the pull request names each old and new "
       "version with its release notes and how it was checked",
       ([r["phpbb"]["sha256"] == _sha314(up["https://download.phpbb.com/pub/release/3.3/3.3.20/phpBB-3.3.20.zip"]),
         r["drupal"]["steps"][1]["strip"], r["smf"]["steps"][1]["strip"]],
        [ln[:ln.index(":")] for ln in (body or "").splitlines() if ln.startswith("- ")],
        "https://www.drupal.org/project/drupal/releases/11.4.15" in (body or ""),
        "An existing site is not changed" in (body or "") and "Approve workflows to run" in (body or "")),
       ([True, "drupal-11.4.15", "SMF-2.1.9"],
        ["- **Drupal** 11.4.14 -> 11.4.15", "- **MyBB** 1.8.41 -> 1.8.42", "- **phpBB** 3.3.19 -> 3.3.20",
         "- **SMF** 2.1.8 -> 2.1.9", "- **WordPress** 7.1.5 -> 7.1.6"], True, True))


def _s314_script_refuses():
    up = _upstream314()
    tampered = _upstream314(**{
        "https://download.phpbb.com/pub/release/3.3/3.3.20/phpBB-3.3.20.zip.sha256": ("%s  phpBB-3.3.20.zip\n" % ("0" * 64)).encode(),
        "https://www.drupal.org/project/drupal/releases/11.4.15":
            up["https://www.drupal.org/project/drupal/releases/11.4.15"].replace(
                _sha314(up["https://ftp.drupal.org/files/projects/drupal-11.4.15.tar.gz"]).encode(), b"1" * 64),
        "https://api.github.com/repos/mybb/mybb/releases/tags/mybb_1842":
            up["https://api.github.com/repos/mybb/mybb/releases/tags/mybb_1842"].replace(
                _sha314(up["https://github.com/mybb/mybb/releases/download/mybb_1842/mybb_1842.zip"]).encode(), b"2" * 64),
        "https://github.com/SimpleMachines/SMF/archive/refs/tags/v2.1.9.tar.gz": _tarred314(["SMF-other/index.php"])})
    rc, out, after, body = _run314(["check", "BODY"], tampered)
    new = _json314.loads(after)["sites"]
    eq("site app versions (main, check): an archive that does not match its publisher's SHA-256 (phpBB's .sha256 file, "
       "Drupal's release page, MyBB's GitHub asset) or lacks the recipe's folder (SMF) is refused and its recipe left "
       "as it was; WordPress, which passed, is still written",
       (rc, out, [new["recipes"][a]["version"] for a in ("drupal", "mybb", "phpbb", "smf", "wordpress")],
        [ln[:ln.index(" ->")] for ln in (body or "").splitlines() if ln.startswith("- ")]),
       (0, "changed=true\nrefused=drupal,mybb,phpbb,smf\n", ["11.4.14", "1.8.41", "3.3.19", "2.1.8", "7.1.6"],
        ["- **WordPress** 7.1.5"]))
    d_url = "https://ftp.drupal.org/files/projects/drupal-11.4.15.tar.gz"
    real_md5 = _hash314.md5(up[d_url], usedforsecurity=False).hexdigest().encode()
    cases = {"md5": {_SAV314.DRUPAL_HISTORY: up[_SAV314.DRUPAL_HISTORY].replace(real_md5, b"3" * 32)},
             "size": {d_url: up[d_url] + b"\0"}}
    said = {k: [ln for ln in _run314(["plan"], _upstream314(**v))[1].splitlines() if ln.startswith("drupal:")]
            for k, v in cases.items()}
    eq("site app versions (main, plan): a Drupal archive unlike the one its release history describes (its MD5, its "
       "size) is refused",
       said, {"md5": ["drupal: refused: %s does not match its published MD5" % d_url],
              "size": ["drupal: refused: %s is %d bytes, not the published %d" % (d_url, len(up[d_url]) + 1, len(up[d_url]))]})


def _s314_script_skips():
    older = _upstream314(**{
        "https://version.phpbb.com/phpbb/versions.json": _json314.dumps({"stable": {"3.3": {"current": "4.0.0"}}}).encode(),
        _SAV314.DRUPAL_HISTORY: b"<project><supported_branches>11.4.,12.0.</supported_branches><releases><release>"
                                b"<version>12.0.1</version><status>published</status></release></releases></project>",
        "https://mybb.com/version_check.php": b"<mybb><latest_version>1.8.41</latest_version>"
                                              b"<version_code>1841</version_code></mybb>",
        "https://api.github.com/repos/mybb/mybb/releases/tags/mybb_1841": _json314.dumps({"assets": [{
            "name": "mybb_1841.zip", "digest": "sha256:" + "4" * 64,
            "browser_download_url": "https://github.com/mybb/mybb/releases/download/mybb_1841/mybb_1841.zip"}]}).encode(),
        "https://api.github.com/repos/SimpleMachines/SMF/releases?per_page=50":
            _json314.dumps([{"tag_name": "v2.1.7"}, {"tag_name": "v3.0.1"}]).encode(),
        "https://registry-1.docker.io/v2/library/wordpress/manifests/7.1.6-php8.5-apache": None})
    rc, out, after, body = _run314(["check", "BODY"], older)
    eq("site app versions (main, check): a release on another branch (phpBB 4, Drupal 12) is refused, one not newer "
       "than the catalog's (MyBB's same, SMF's older 2.1, never its 3.0) is not written, and WordPress waits while "
       "its image for one PHP series is not published: nothing changes and no pull request text is written",
       (rc, out, after == _TEXT314, body), (0, "changed=false\nrefused=drupal,phpbb\n", True, None))
    rc3, plan_out, after3, body3 = _run314(["plan"], _upstream314())
    eq("site app versions (main, plan): finds and checks every newer release but writes nothing",
       (rc3, after3 == _TEXT314, sorted(ln.split(":")[0] for ln in plan_out.splitlines()), body3),
       (0, True, ["drupal", "mybb", "phpbb", "smf", "wordpress"], None))
    saved_problems = _SAV314._site_problems
    _SAV314._site_problems = lambda sites: ["a stand-in refusal"]
    try:
        rc4, out4, after4, body4 = _run314(["check", "BODY"], _upstream314())
    finally:
        _SAV314._site_problems = saved_problems
    eq("site app versions (main, check): a new catalog the panel's own check refuses is not written at all",
       (rc4, out4, after4 == _TEXT314, body4), (0, "changed=false\nrefused=drupal,mybb,phpbb,smf,wordpress\n", True, None))


_FAKE_CURL314 = r'''
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
url = args[args.index("--") + 1]
hin = args[args.index("--header") + 1][1:]
with open(os.path.join(here, "log.jsonl"), "a") as fh:
    fh.write(json.dumps([url, open(hin).read()]) + "\n")
status, headers, body = json.load(open(os.path.join(here, "responses.json"))).get(url, [404, {}, ""])
with open(args[args.index("--dump-header") + 1], "w") as fh:
    fh.write("HTTP/2 %d\r\n" % status + "".join("%s: %s\r\n" % kv for kv in headers.items()) + "\r\n")
with open(args[args.index("--output") + 1], "w") as fh:
    fh.write(body)
sys.stdout.write(str(status))
'''


def _curl_run314(responses, url, headers=None, limit=_SAV314.META_MAX):
    """(result or the refusal's text, [(url, request headers)] the stand-in curl saw) of the script's fetch."""
    d = _tf314.mkdtemp(prefix="curl-", dir=_TMP314)
    with open(os.path.join(d, "curl"), "w", encoding="utf-8") as fh:
        fh.write("#!%s -I\n%s" % (_sys314.executable, _FAKE_CURL314))
    os.chmod(os.path.join(d, "curl"), 0o700)
    with open(os.path.join(d, "responses.json"), "w", encoding="utf-8") as fh:
        _json314.dump(responses, fh)
    old = os.environ.get("PATH", "")
    os.environ["PATH"] = d + os.pathsep + old
    try:
        got = _SAV314.fetch(url, limit, headers)
    except _SAV314.Refused as exc:
        got = "refused: " + str(exc)
    finally:
        os.environ["PATH"] = old
    log = os.path.join(d, "log.jsonl")
    seen = [tuple(_json314.loads(ln)) for ln in open(log, encoding="utf-8")] if os.path.exists(log) else []
    return got, seen


def _s314_fetch():
    a, b = "https://github.com/o/r/releases/download/t/f.zip", "https://release-assets.githubusercontent.com/f?sig=1"
    ok, seen = _curl_run314({a: [302, {"location": b}, ""], b: [200, {"x-k": "v"}, "data"]}, a, {"Authorization": "Bearer x"})
    eq("site app versions (fetch): a redirect to another allowed host is followed by curl without the request's own "
       "headers, and the body comes back",
       (ok, seen), ((b"data", {"x-k": "v"}), [(a, "Authorization: Bearer x\n"), (b, "")]))
    evil, seen2 = _curl_run314({a: [302, {"location": "https://evil.example/f"}, ""]}, a)
    plain, seen3 = _curl_run314({}, "http://github.com/o/r")
    other = [_curl_run314({}, u)[0][:9] for u in ("https://example.org/x", "https://github.com:8443/x",
                                                  "https://user@github.com/x")]
    missing, _s4 = _curl_run314({}, "https://github.com/o/r/none")
    big, _s5 = _curl_run314({a: [200, {}, "x" * 20]}, a, limit=10)
    eq("site app versions (fetch): a redirect off the allowed hosts is refused and never requested, as is a plain "
       "http URL, another host, a port or a user part; a 404 is (None, {}); a body over the cap is refused",
       (evil[:9], [u for u, _h in seen2], plain[:9], seen3, other, missing, big[:9]),
       ("refused: ", [a], "refused: ", [], ["refused: "] * 3, (None, {}), "refused: "))


# ── 4. the workflow ─────────────────────────────────────────────────────────────────────────────
def _s314_workflow():
    text = _wf29("site-app-versions.yml")
    code, job = _code29(text), _job29(text, "versions")
    steps = _steps29(job)
    mode, hosts = _egress223(job)
    on = code[code.find("\non:"):code.find("\nconcurrency:")]
    check_step = [s for s in steps if _name29(s) == "Find, download and check the newest releases"]
    pr_step = [s for s in steps if _name29(s) == "Open a pull request with the new releases"]
    fail_step = [s for s in steps if _name29(s) == "Fail when a release source or archive was refused"]
    eq("site app versions (workflow): daily and on demand only, no top-level grant, the job token may write contents "
       "and pull requests and nothing else, Harden-Runner first in block mode with exactly the script's hosts, a "
       "checkout that keeps no credentials, and no secret but the job token",
       (_re314.findall(r"^  ([a-z_]+):", on, _re314.M), "permissions: {}" in code,
        _re314.findall(r"^      ([a-z-]+): write", job, _re314.M), _name29(steps[0]) if steps else None, mode,
        sorted(hosts), "persist-credentials: false" in steps[1] if len(steps) > 1 else False,
        sorted(set(_re314.findall(r"secrets\.[A-Za-z0-9_]+", code)))),
       (["schedule", "workflow_dispatch"], True, ["contents", "pull-requests"], "Harden Runner", "block",
        sorted(h + ":443" for h in _SAV314.HOSTS), True, []))
    eq("site app versions (workflow): the check step runs the script isolated into the step's outputs, a pull request "
       "is opened only when the catalog changed and no other from this workflow is open, with the script's text, and "
       "a refused release fails the run",
       (len(check_step) == 1 and 'python3 -I .github/scripts/site_app_versions.py check "${RUNNER_TEMP}/site-app-versions.md"'
        ' >> "$GITHUB_OUTPUT"' in check_step[0],
        len(pr_step) == 1 and "if: steps.check.outputs.changed == 'true'" in pr_step[0]
        and 'startswith("site-app-versions/")' in pr_step[0] and '--body-file "${RUNNER_TEMP}/site-app-versions.md"' in pr_step[0]
        and pr_step[0].count("exit 0") == 1,
        len(fail_step) == 1 and "if: steps.check.outputs.refused != ''" in fail_step[0] and "exit 1" in fail_step[0]),
       (True, True, True))
    scan = _code29(_wf29("addon-images.yml"))
    with open(os.path.join(_root, ".github", "required-checks.txt"), encoding="utf-8") as fh:
        required = fh.read()
    eq("site app versions (gate): the image scan, a required check, builds and scans the images of a pull request that "
       "changes the catalog",
       ("github-actions | Add-on images (Trivy, hadolint)" in required.splitlines(), "    name: Add-on images (Trivy, hadolint)"
        in scan, "              'panel/addon_images/**'" in scan), (True, True, True))
    cf = [s for s in _steps29(_job29(_wf29("cloudflare-ranges.yml"), "ranges")) if "gh pr create" in s]
    eq("cloudflare ranges (workflow): its pull request says to approve the checks GitHub holds for a pull request a "
       "workflow's own token opened, before merging",
       [("press Approve workflows to run in the merge box to run the required checks before merging" in s) for s in cf],
       [True])


for _step314 in (_s314_renovate_pins, _s314_renovate_updates, _s314_rules, _s314_shape, _s314_script_writes,
                 _s314_script_refuses, _s314_script_skips, _s314_fetch, _s314_workflow):
    _step314()
_sh314.rmtree(_TMP314, ignore_errors=True)
