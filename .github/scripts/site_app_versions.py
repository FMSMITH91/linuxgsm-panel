#!/usr/bin/env python3
"""Keep the catalog's one-click app releases current: find, download, check and pin each app's newest release.

A new website install takes its app from panel/addon_images/catalog.json (sites.recipes.<app>: version,
url and sha256), which tools/sign-catalog.sh signs and panels fetch daily, so a new release reaches the
next install with no panel update. For each app this script reads the project's own release source for
the newest stable release on the branch the recipe supports (phpBB 3.3, Drupal 11, MyBB 1.8, SMF 2.1),
downloads the official archive over https, checks it against the checksum the publisher itself publishes
(where one is), checks that it still unpacks into the folder the recipe strips, and writes version, url
and sha256 (and the strip folder, where it names the version: Drupal's and SMF's). WordPress's code comes
from the official WordPress image, so its version moves with that image: the newest release WordPress's
own version check names, and the digest of the official image's tag for it on each PHP series.

Only the fixed https hosts in HOSTS are reached, and a redirect is followed only to another of them (OWASP
SSRF Prevention Cheat Sheet, application layer allow-list). No XML parser is used: the two XML sources are
read field by field from a size-capped text, and one carrying a DTD is refused (OWASP XXE Prevention Cheat
Sheet). A release that is not newer than the catalog's is never written, an app whose check fails is left
as it is and named in `refused`, and the new catalog must pass the panel's own check (websites_catalog's
sites_problems) before anything is written.

    site_app_versions.py plan          print what would change; write nothing
    site_app_versions.py check BODY    when a release passed, write the catalog and the pull request's text
                                       to BODY (a path inside the folder it runs in: the workspace);
                                       print "changed=true|false" and "refused=<apps>"

Run daily by .github/workflows/site-app-versions.yml, which opens one pull request when the catalog changed.
"""
import collections
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import shutil
import subprocess  # nosec B404 - curl, with a fixed argument list
import tarfile
import tempfile
import urllib.parse
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CATALOG = os.path.join(ROOT, "panel", "addon_images", "catalog.json")
# Every host this script may reach: the release sources, the archives' hosts and where GitHub sends a
# download (codeload for a tag's archive, the release-asset hosts for an attached file), and Docker
# Hub's registry for the WordPress image's digests.
HOSTS = frozenset({
    "api.github.com", "github.com", "codeload.github.com", "release-assets.githubusercontent.com",
    "objects.githubusercontent.com", "api.wordpress.org", "auth.docker.io", "registry-1.docker.io",
    "version.phpbb.com", "download.phpbb.com", "updates.drupal.org", "www.drupal.org", "ftp.drupal.org",
    "mybb.com"})
META_MAX = 4 * 1024 * 1024
ARCHIVE_MAX = 96 * 1024 * 1024
MEMBERS_MAX = 100000
USER_AGENT = "linuxgsm-panel-site-app-versions"
WP_CHECK = "https://api.wordpress.org/core/version-check/1.7/"
WP_REGISTRY_AUTH_URL = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/wordpress:pull"
WP_MANIFEST = "https://registry-1.docker.io/v2/library/wordpress/manifests/%s"
WP_INDEX = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json"
DRUPAL_HISTORY = "https://updates.drupal.org/release-history/drupal/current"

# What the pull request says about each app's check (the publisher's checksum, or why there is none).
HOW = {
    "phpbb": "checked against the .sha256 file download.phpbb.com publishes beside the archive",
    "drupal": "checked against the SHA-256 on the release's drupal.org page and the MD5 and size in "
              "Drupal's release history",
    "mybb": "checked against the SHA-256 GitHub records for the asset of MyBB's own release, which "
            "mybb.com's version check names",
    "smf": "SMF publishes no checksum for its release archive: the SHA-256 pins what GitHub served for the "
           "release's tag",
    "wordpress": "the official WordPress image's digest for this version on each PHP series, read from Docker "
                 "Hub (the image's build checks the archive against the SHA-1 wordpress.org publishes)",
}

Release = collections.namedtuple("Release", "version url checks note")


class Refused(Exception):
    """A release source or archive that did not pass; the app is left as it is."""


def allowed(url):
    """`url` when it is https on one of HOSTS with no port, user or fragment; Refused otherwise."""
    parts = urllib.parse.urlsplit(url)
    if (parts.scheme != "https" or parts.hostname not in HOSTS or parts.port is not None or parts.username
            or parts.password or parts.fragment):
        raise Refused("not an allowed https URL: %s" % url[:120])
    return url


def _request_headers(path, headers):
    """Write `headers` for curl's --header @file, readable by this user alone."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("".join("%s: %s\n" % kv for kv in (headers or {}).items()))


def _response_headers(path):
    """{name: value} of the last response curl's --dump-header wrote to `path`."""
    with open(path, encoding="latin-1") as fh:
        lines = fh.read().splitlines()
    starts = [i for i, ln in enumerate(lines) if ln.startswith("HTTP/")] or [0]
    pairs = (ln.partition(":") for ln in lines[starts[-1] + 1:])
    return {k.strip().lower(): v.strip() for k, sep, v in pairs if sep}


def _curl(curl, url, limit, headers, method, tmp):
    """(status, {header: value}, body path) of one request, no redirect followed.

    The request headers go to curl in a file, never on its command line (the registry's token is one).
    """
    hin, hout, out = (os.path.join(tmp, n) for n in ("request-headers", "response-headers", "body"))
    _request_headers(hin, headers)
    # A HEAD's Content-Length is the size of what a GET would send, so its size cap is the caller's own check.
    size = ["--head"] if method == "HEAD" else ["--max-filesize", str(max(limit, 1))]
    argv = [curl, "--silent", "--show-error", "--proto", "=https", "--max-redirs", "0", "--max-time", "300",
            "--header", "@" + hin, "--dump-header", hout, "--output", out, "--write-out", "%{http_code}"] + size + ["--", url]
    run = subprocess.run(argv, capture_output=True, text=True, timeout=330, check=False)  # nosec B603 - fixed argv, allowed() URL
    if run.returncode != 0 or not run.stdout.isdigit():
        raise Refused("%s: curl failed (%s)" % (url[:120], run.stderr.strip()[:200]))
    return int(run.stdout), _response_headers(hout), out


def fetch(url, limit=META_MAX, headers=None, method="GET"):
    """(body, {header: value}) of `url`, at most `limit` bytes; a 404 gives (None, {}).

    Fetched by curl (a server that turns away other clients serves it), https only, with each redirect
    followed only to another allowed URL and the request's own headers dropped when the host changes.
    """
    curl = shutil.which("curl")
    if curl is None:
        raise Refused("curl is not installed")
    with tempfile.TemporaryDirectory(prefix="site-app-versions-") as tmp:
        for _hop in range(6):
            status, got, out = _curl(curl, allowed(url), limit, headers, method, tmp)
            nxt = urllib.parse.urljoin(url, got.get("location", "")) if status in (301, 302, 303, 307, 308) else ""
            if not nxt:
                break
            if urllib.parse.urlsplit(nxt).hostname != urllib.parse.urlsplit(url).hostname:
                headers = None
            url = nxt
        else:
            raise Refused("too many redirects: %s" % url[:120])
        if status == 404:
            return None, {}
        if status != 200:
            raise Refused("%s answered %s" % (url[:120], status))
        body = b""
        if method != "HEAD":
            with open(out, "rb") as fh:
                body = fh.read(limit + 1)
    if len(body) > limit:
        raise Refused("larger than expected: %s" % url[:120])
    return body, got


def _body(get, url, limit=META_MAX):
    body = get(url, limit)[0]
    if body is None:
        raise Refused("not found: %s" % url[:120])
    return body


def _json(get, url):
    return json.loads(_body(get, url).decode("utf-8"))


def _text(get, url):
    text = _body(get, url).decode("utf-8", "replace")
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise Refused("a DTD in %s" % url[:120])
    return text


def _tag(text, name):
    """The text of the first <name>...</name> in `text`, or ""."""
    m = re.search(r"<%s>([^<]{0,400})</%s>" % (name, name), text)
    return m.group(1).strip() if m else ""


def _version(value, shape):
    if not isinstance(value, str) or re.fullmatch(shape, value) is None:
        raise Refused("not a release version of the supported branch: %r" % str(value)[:40])
    return value


def key(version):
    """A version as a tuple of numbers, for comparing."""
    return tuple(int(p) for p in version.split("."))


def _note(url, host, fallback):
    """`url` when it is a plain https link on `host`, else `fallback` (the pull request links it)."""
    pat = r"https://%s/[A-Za-z0-9._~/?=&%%+-]{0,200}" % re.escape(host)
    return url if isinstance(url, str) and re.fullmatch(pat, url) else fallback


# ── the release sources ─────────────────────────────────────────────────────────────────────────
def phpbb(get):
    """The newest phpBB 3.3: the version phpBB's own update check offers, with the .sha256 file beside the archive."""
    entry = _json(get, "https://version.phpbb.com/phpbb/versions.json")["stable"]["3.3"]
    v = _version(entry.get("current"), r"3\.3\.[0-9]{1,3}")
    url = "https://download.phpbb.com/pub/release/3.3/%s/phpBB-%s.zip" % (v, v)
    words = _body(get, url + ".sha256").decode("ascii").split()
    if len(words) != 2 or words[1] != "phpBB-%s.zip" % v or not re.fullmatch(r"[0-9a-f]{64}", words[0]):
        raise Refused("phpBB's .sha256 file does not name the archive")
    note = _note(entry.get("announcement"), "www.phpbb.com", "https://www.phpbb.com/downloads/")
    return Release(v, url, {"sha256": words[0]}, note)


def _drupal_release(block, branches):
    """The Release of one <release> of Drupal's history when it is a covered 11.x.y release, else None."""
    v = _tag(block, "version")
    if (re.fullmatch(r"11\.[0-9]{1,3}\.[0-9]{1,3}", v) is None or _tag(block, "status") != "published"
            or not any(b and v.startswith(b) for b in branches)):
        return None
    if '<security covered="1">' not in block or "<value>Insecure</value>" in block:
        return None
    url = "https://ftp.drupal.org/files/projects/drupal-%s.tar.gz" % v
    m = re.search(r"<file><url>%s</url><archive_type>tar\.gz</archive_type><md5>([0-9a-f]{32})</md5>"
                  r"<size>([0-9]{1,10})</size>" % re.escape(url), block)
    page = "https://www.drupal.org/project/drupal/releases/%s" % v
    if m is None or _tag(block, "release_link") != page:
        return None
    return Release(v, url, {"md5": m.group(1), "size": int(m.group(2))}, page)


def drupal(get):
    """Drupal 11: the newest release on a supported 11.x branch that Drupal's security advisories cover."""
    text = _text(get, DRUPAL_HISTORY)
    branches = [b.strip() for b in _tag(text, "supported_branches").split(",")]
    found = [r for r in (_drupal_release(b, branches) for b in re.findall(r"<release>(.*?)</release>", text, re.S))
             if r is not None]
    if not found:
        raise Refused("no covered Drupal 11 release in the release history")
    best = max(found, key=lambda r: key(r.version))
    page = _body(get, best.note).decode("utf-8", "replace")
    at = page.find('href="%s"' % best.url)
    m = re.search(r'release-file-sha256">.{0,300}?class="field-content hash">([0-9a-f]{64})<',
                  page[at:at + 4000], re.S) if at >= 0 else None
    if m is None:
        raise Refused("no SHA-256 for %s on its release page" % best.url)
    return best._replace(checks=dict(best.checks, sha256=m.group(1)))


def mybb(get):
    """The newest MyBB 1.8: the version mybb.com's version check names, and the asset of that GitHub release."""
    text = _text(get, "https://mybb.com/version_check.php")
    v = _version(_tag(text, "latest_version"), r"1\.8\.[0-9]{1,2}")
    code = "18%02d" % int(v.split(".")[2])
    if _tag(text, "version_code") != code:
        raise Refused("mybb.com's version code %r is not %s's" % (_tag(text, "version_code")[:10], v))
    rel = _json(get, "https://api.github.com/repos/mybb/mybb/releases/tags/mybb_%s" % code)
    name = "mybb_%s.zip" % code
    url = "https://github.com/mybb/mybb/releases/download/mybb_%s/%s" % (code, name)
    assets = [a for a in rel.get("assets") or [] if a.get("name") == name and a.get("browser_download_url") == url]
    digest = str(assets[0].get("digest")) if len(assets) == 1 else ""
    if rel.get("draft") or rel.get("prerelease") or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise Refused("MyBB's release mybb_%s has no published asset %s with its sha256" % (code, name))
    note = _note(rel.get("html_url"), "github.com", "https://github.com/mybb/mybb/releases/tag/mybb_%s" % code)
    return Release(v, url, {"sha256": digest[len("sha256:"):]}, note)


def smf(get):
    """SMF 2.1: the newest published (not pre-release) v2.1.x release of SimpleMachines/SMF."""
    rels = _json(get, "https://api.github.com/repos/SimpleMachines/SMF/releases?per_page=50")
    found = [str(r.get("tag_name"))[1:] for r in rels if isinstance(r, dict) and not r.get("draft")
             and not r.get("prerelease") and re.fullmatch(r"v2\.1\.[0-9]{1,3}", str(r.get("tag_name")))]
    if not found:
        raise Refused("no published SMF 2.1 release")
    v = max(found, key=key)
    return Release(v, "https://github.com/SimpleMachines/SMF/archive/refs/tags/v%s.tar.gz" % v, {},
                   "https://github.com/SimpleMachines/SMF/releases/tag/v%s" % v)


FINDERS = (("drupal", "Drupal", drupal), ("mybb", "MyBB", mybb), ("phpbb", "phpBB", phpbb), ("smf", "SMF", smf))


# ── checking an archive ─────────────────────────────────────────────────────────────────────────
def _names(body, url):
    """The member names of the zip or tar.gz archive `body` (nothing is unpacked)."""
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            names = zf.namelist()
    else:
        names = []
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tf:
            for member in tf:
                names.append(member.name)
                if len(names) > MEMBERS_MAX:
                    break
    if len(names) > MEMBERS_MAX:
        raise Refused("too many files in %s" % url[:120])
    return names


def _strip(recipe, version):
    """The recipe's download step's strip folder for `version` (the catalog's own, with its version moved)."""
    steps = [s for s in recipe["steps"] if s.get("type") == "download-verify-unpack"]
    if len(steps) != 1 or not steps[0].get("strip"):
        raise Refused("the recipe has no one download step with a strip folder")
    return steps[0]["strip"].replace(recipe["version"], version)


def verified(get, rel, strip):
    """The sha256 of `rel`'s archive, once its size, every published checksum and its folder `strip` match."""
    body = _body(get, rel.url, ARCHIVE_MAX)
    if "size" in rel.checks and len(body) != rel.checks["size"]:
        raise Refused("%s is %d bytes, not the published %d" % (rel.url, len(body), rel.checks["size"]))
    if "md5" in rel.checks and hashlib.md5(body, usedforsecurity=False).hexdigest() != rel.checks["md5"]:
        raise Refused("%s does not match its published MD5" % rel.url)
    sha = hashlib.sha256(body).hexdigest()
    if "sha256" in rel.checks and sha != rel.checks["sha256"]:
        raise Refused("%s does not match its published SHA-256" % rel.url)
    try:
        names = _names(body, rel.url)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
        raise Refused("%s is not a readable archive (%s)" % (rel.url, exc)) from None
    if not any(n.startswith(strip + "/") for n in names):
        raise Refused("%s has no %s/ folder for the recipe to unpack" % (rel.url, strip))
    return sha


# ── WordPress: its version moves with the official image ────────────────────────────────────────
def wordpress(get, wp):
    """(version, {series: image}, note) for WordPress's newest release, or None while an image is not out yet.

    `wp` is the catalog's sites.wordpress. Every PHP series it has needs the official image's tag
    <version>-php<series>-apache, by digest, read from Docker Hub's registry (a HEAD, which no pull counts).
    """
    offer = (_json(get, WP_CHECK).get("offers") or [{}])[0]
    if offer.get("response") not in ("upgrade", "latest"):
        raise Refused("WordPress's version check offers no release")
    v = _version(offer.get("current"), r"[0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,3})?")
    token = _json(get, WP_REGISTRY_AUTH_URL).get("token")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._-]{20,8192}", token):
        raise Refused("Docker Hub gave no pull token")
    images = {}
    for series in sorted(wp["php"]):
        found, hdrs = get(WP_MANIFEST % ("%s-php%s-apache" % (v, series)), 0,
                          {"Authorization": "Bearer " + token, "Accept": WP_INDEX}, "HEAD")
        digest = hdrs.get("docker-content-digest", "")
        if found is None and not digest:
            return None
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise Refused("Docker Hub gave no digest for WordPress %s on PHP %s" % (v, series))
        images[series] = "docker.io/library/wordpress@" + digest
    return v, images, "https://wordpress.org/documentation/wordpress-version/version-%s/" % v.replace(".", "-")


# ── the plan ────────────────────────────────────────────────────────────────────────────────────
def _app_change(sites, app, finder, get):
    """(app, old, new, note) after writing a newer verified release into `sites`, or None when there is none."""
    recipe = sites["recipes"][app]
    rel = finder(get)
    if key(rel.version) <= key(recipe["version"]):
        return None
    allowed(rel.url)
    strip = _strip(recipe, rel.version)
    sha = verified(get, rel, strip)
    old = recipe["version"]
    for step in recipe["steps"]:
        if step.get("type") == "download-verify-unpack":
            step["strip"] = strip
    recipe.update(version=rel.version, url=rel.url, sha256=sha)
    return app, old, rel.version, rel.note


def _wordpress_change(sites, get):
    found = wordpress(get, sites["wordpress"])
    if found is None:
        sys.stderr.write("site_app_versions: wordpress: the official image is not published yet\n")
        return None
    v, images, note = found
    old = sites["wordpress"]["version"]
    if key(v) <= key(old) or key(v) <= key(sites["recipes"]["wordpress"]["version"]):
        return None
    sites["wordpress"]["version"] = sites["recipes"]["wordpress"]["version"] = v
    for series, image in images.items():
        sites["wordpress"]["php"][series]["image"] = image
    return "wordpress", old, v, note


def _site_problems(sites):
    """The panel's own check of a `sites` section (panel/services/websites_catalog.py, loaded by path)."""
    spec = importlib.util.spec_from_file_location(
        "websites_catalog_for_site_app_versions", os.path.join(ROOT, "panel", "services", "websites_catalog.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.sites_problems(sites)


def plan(doc, get):
    """([(app, old, new, note)], [(app, why)]): the newer releases written into `doc`, and the refused apps."""
    sites, changes, refused = doc["sites"], [], []
    steps = [(app, lambda a=app, f=finder: _app_change(sites, a, f, get)) for app, _n, finder in FINDERS]
    for app, step in steps + [("wordpress", lambda: _wordpress_change(sites, get))]:
        try:
            change = step()
        except (Refused, OSError, ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
            refused.append((app, str(exc)[:300] or type(exc).__name__))
            continue
        if change:
            changes.append(change)
    problems = _site_problems(sites) if changes else []
    if problems:
        return [], refused + [(c[0], "the new catalog fails the panel's check: %s" % problems[:3]) for c in changes]
    return changes, refused


def pr_text(changes):
    """The pull request's text: each app's old and new version, its release notes and how it was checked."""
    names = dict([(app, name) for app, name, _f in FINDERS], wordpress="WordPress")
    head = ("New app releases for new website installs (sites.recipes in the add-on catalog), found and checked "
            "by .github/scripts/site_app_versions.py:")
    tail = ("An existing site is not changed: a new install uses these releases once panels have the next "
            "signed catalog. GitHub holds the checks of a pull request a workflow's own token opened until "
            "someone with write access approves them: press Approve workflows to run in the merge box to run "
            "the required checks (the add-on image scan and the unit suite's catalog checks) before merging.")
    items = ["- **%s** %s -> %s: [release notes](%s). %s." % (names[app], old, new, note, HOW[app][:1].upper() + HOW[app][1:])
             for app, old, new, note in changes]
    return "\n".join([head, ""] + items + ["", tail]) + "\n"


def main(argv, get=fetch, catalog=CATALOG):
    """Run `plan` or `check BODY`; the exit status (0 when it ran, whatever it found)."""
    if not (argv[1:] == ["plan"] or (len(argv) == 3 and argv[1] == "check")):
        sys.stderr.write(__doc__)
        return 2
    try:
        body = inside(argv[2]) if argv[1] == "check" else None
    except Refused as e:
        sys.stderr.write("site_app_versions: %s\n" % e)
        return 2
    with open(catalog, encoding="utf-8") as fh:
        text = fh.read()
    doc = json.loads(text)
    if json.dumps(doc, indent=2, sort_keys=True) + "\n" != text:
        sys.stderr.write("site_app_versions: the catalog is not in its written form (indent 2, sorted keys)\n")
        return 1
    changes, refused = plan(doc, get)
    _say(changes, refused, sys.stdout if argv[1] == "plan" else sys.stderr)
    if argv[1] == "check":
        _write(doc, changes, refused, catalog, body)
    return 0


def inside(path):
    """`path` resolved (links and `..` followed) when it is inside the folder the script runs in; Refused when not.

    The pull request's text is written to the path named on the command line, so it may not leave that folder (CI
    runs the script in the workspace): OWASP Path Traversal Prevention Cheat Sheet, "Validate the Resolved Path":
    resolve it, compare its components with the base's, then use the path checked.
    """
    resolved, base = os.path.realpath(path), os.path.realpath(os.getcwd())
    if resolved == base or os.path.commonpath([resolved, base]) != base:
        raise Refused("%s is outside the folder site_app_versions.py runs in (%s)" % (path, base))
    return resolved


def _say(changes, refused, out):
    """One line per changed or refused app, on `out`."""
    for app, old, new, note in changes:
        out.write("%s: %s -> %s (%s)\n" % (app, old, new, note))
    for app, why in refused:
        out.write("%s: refused: %s\n" % (app, why))


def _write(doc, changes, refused, catalog, body_path):
    """`check`'s writes: the catalog and the pull request's text when something changed, and the step's outputs."""
    if changes:
        with open(catalog, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        with open(body_path, "w", encoding="utf-8") as fh:
            fh.write(pr_text(changes))
    sys.stdout.write("changed=%s\nrefused=%s\n" % ("true" if changes else "false", ",".join(a for a, _w in refused)))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
