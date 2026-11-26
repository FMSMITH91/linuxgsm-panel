"""The websites' pinned images, proxy binary, allow-list presets, runtimes and app recipes.

WHERE THEY COME FROM
    The `sites` section of the add-on catalog: the floor (panel/addon_images/catalog.json, shipped with
    the panel) and the signed catalog, read through addons_catalog.section(): one signature, one
    store, one rollback and freeze rule. A signed catalog's section is used only when every part of
    it passes sites_problems(); otherwise the floor's is used and the refusal is logged once. So a
    refused section changes nothing, and nothing here installs anything: a person presses Update.

WHAT IS CHECKED (OWASP Input Validation Cheat Sheet: allow-list, fullmatch; Docker Security Cheat
Sheet rule 13: images pinned by digest; SSRF Prevention Cheat Sheet, application layer: downloads
only from an allow-list of fixed https hosts, with no query, port or user part)
    Every image is pinned by a full sha256 digest; every downloaded file (the proxy binary, an app
    release) carries an https URL on ALLOWED_HOSTS and its sha256; the proxy's URL is exactly the
    upstream release asset for its version and architecture. PHP and Node versions carry the date
    their upstream security support ends, and a version past it is not offered. Recipes use only the
    step types the panel implements (STEP_TYPES), with fields of fixed shapes; a placeholder in a
    command line may only name a value that is not a secret (secrets go on stdin or in the
    environment, never on argv).

This module needs nothing but the standard library at import, so tools/addon_catalog.py (which signs
catalogs) can load it by path and refuse a catalog the panels would refuse.
"""
import ipaddress
import json
import logging
import re
from datetime import date

_log = logging.getLogger("panel.websites.catalog")

# The same digest shape addons_catalog._DIGEST holds (a unit check keeps them equal).
_DIGEST = r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}"
_SHA = r"[0-9a-f]{64}"
_DATE = r"20[0-9]{2}-[01][0-9]-[0-3][0-9]"
_VERSION = r"[0-9A-Za-z][0-9A-Za-z.+-]{0,31}"
_PHP = r"[0-9]\.[0-9]{1,2}"
_RUNTIME_VERSION = r"[0-9]{1,3}"
_NAME = r"[a-z][a-z0-9-]{0,31}"
_HOST = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
ARCHES = ("amd64", "arm64")
# The only hosts a site file is ever downloaded from (the SSRF cheat sheet's allow-list).
ALLOWED_HOSTS = ("github.com", "download.phpbb.com", "ftp.drupal.org", "downloads.wordpress.org",
                 "download.simplemachines.org")
_URL_PATH = r"/[A-Za-z0-9._~/+-]{1,200}"
_CADDY_URL = "https://github.com/caddyserver/caddy/releases/download/v{v}/caddy_{v}_linux_{a}.tar.gz"
# The hosts a site may reach while it builds or runs (WordPress's updates, npm's registry): relayed
# one by one, never a route to the internet.
EGRESS_HOSTS = ("api.wordpress.org", "downloads.wordpress.org", "registry.npmjs.org")
SITE_KEYS = ("caddy", "static", "php", "wordpress", "wpcli", "tunnel", "object_cache", "runtimes", "presets",
             "origin_pull", "recipes")
OPTIONAL_KEYS = ("caddy_cache",)
TUNNEL_PROVIDERS = ("cloudflare",)
PRESETS = ("cloudflare",)
# A CDN's client certificate authority for authenticated origin pulls (public; PEM).
_PEM = r"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]{100,8000}-----END CERTIFICATE-----\n"

# ── recipes ─────────────────────────────────────────────────────────────────────────────────────
STEP_TYPES = ("download-verify-unpack", "create-database", "render-config", "run-in-container",
              "set-permissions", "drive-web-installer")
RECIPE_KINDS = ("php", "wordpress", "app")
# Values a recipe may name in braces. SECRETS are never put on a command line or in a URL.
PLACEHOLDERS = ("db_name", "db_user", "db_password", "db_host", "db_host_name", "db_port", "site_name",
                "site_url", "domain", "admin_user", "admin_email", "admin_password", "salt", "trusted_hosts")
SECRETS = ("db_password", "admin_password", "salt")
_PH_RE = re.compile(r"\{([a-z_]{1,24})\}")
_REL = r"(?:[A-Za-z0-9_][A-Za-z0-9_.-]{0,63})(?:/[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}){0,5}"
_ENV_NAME = r"[A-Z][A-Z0-9_]{0,31}"
_FIELD = r"[A-Za-z0-9_\[\]]{1,64}"
_ARGV_WORD = r"[^\x00-\x1f\x7f]{1,2000}"
TEMPLATE_MAX = 16384
PAGES_MAX = 20
ARGV_MAX = 24


def _full(rx, value):
    return isinstance(value, str) and re.fullmatch(rx, value) is not None


def _whole(value):
    """Whether `value` is an int and not a bool (True and False are ints in Python)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _obj(value, keys, optional=()):
    """Whether `value` is a dict holding every key of `keys` and nothing outside `keys` + `optional`."""
    return isinstance(value, dict) and set(keys) <= set(value) <= set(keys) | set(optional)


def _url_ok(url):
    """Whether `url` is https on ALLOWED_HOSTS with a plain path (no port, user, query or fragment)."""
    if not isinstance(url, str) or not url.startswith("https://"):
        return False
    host, _sep, path = url[len("https://"):].partition("/")
    return host in ALLOWED_HOSTS and _full(_URL_PATH, "/" + path) and ".." not in path


def _file_ok(entry):
    return _obj(entry, ("url", "sha256")) and _url_ok(entry["url"]) and _full(_SHA, entry["sha256"])


def _caddy_problems(entry, key):
    if not _obj(entry, ("version", "assets")) or not _full(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", entry["version"]):
        return ["%s: needs a version x.y.z and its assets" % key]
    assets = entry["assets"]
    if not _obj(assets, ("amd64",), ARCHES):
        return ["%s: needs an amd64 asset (and at most %s)" % (key, ", ".join(ARCHES))]
    out = []
    for arch, a in sorted(assets.items()):
        if not _file_ok(a):
            out.append("%s.%s: needs an https url on an allowed host and its sha256" % (key, arch))
        elif key == "caddy" and a["url"] != _CADDY_URL.format(v=entry["version"], a=arch):
            out.append("%s.%s: the url is not the upstream release asset for %s" % (key, arch, entry["version"]))
    return out


def _image_problems(entry, key, extra=("version",)):
    if not _obj(entry, ("image",), extra) or not _full(_DIGEST, entry["image"]):
        return ["%s: an image pinned by a full sha256 digest" % key]
    if "version" in entry and not _full(_VERSION, entry["version"]):
        return ["%s: a version of letters, digits and dots" % key]
    if "eol" in entry and not _date_ok(entry["eol"]):
        return ["%s: eol is a date YYYY-MM-DD" % key]
    return []


def _date_ok(text):
    if not _full(_DATE, text):
        return False
    try:
        date.fromisoformat(text)
    except ValueError:
        return False
    return True


def _versions_problems(entries, key, shape, need_eol):
    if not isinstance(entries, dict) or not entries:
        return ["%s: at least one version" % key]
    out = []
    for ver, entry in sorted(entries.items()):
        if not _full(shape, ver):
            out.append("%s: %r is not a version" % (key, ver))
            continue
        extra = ("eol",) if need_eol else ()
        out += _image_problems(entry, "%s.%s" % (key, ver), extra)
        if need_eol and not (isinstance(entry, dict) and "eol" in entry):
            out.append("%s.%s: needs the date its security support ends (eol)" % (key, ver))
    return out


def _wordpress_problems(entry):
    if not _obj(entry, ("version", "php")) or not _full(_VERSION, entry["version"]):
        return ["wordpress: needs a version and its images per PHP version"]
    return _versions_problems(entry["php"], "wordpress.php", _PHP, False)


def _tunnel_problems(entry):
    if not isinstance(entry, dict) or not entry or not set(entry) <= set(TUNNEL_PROVIDERS):
        return ["tunnel: one entry per provider of %s" % ", ".join(TUNNEL_PROVIDERS)]
    out = []
    for name, e in sorted(entry.items()):
        out += _image_problems(e, "tunnel.%s" % name)
    return out


def _runtime_problems(name, entry):
    key = "runtimes.%s" % name
    if not _full(r"[a-z][a-z0-9]{0,15}", name):
        return ["%s: not a runtime name" % key]
    if not _obj(entry, ("versions", "build", "start", "port"), ("egress",)):
        return ["%s: needs versions, build, start and port" % key]
    out = _versions_problems(entry["versions"], key + ".versions", _RUNTIME_VERSION, True)
    for cmd in ("build", "start"):
        if not (isinstance(entry[cmd], str) and 0 < len(entry[cmd]) <= 1000 and _full(_ARGV_WORD, entry[cmd])):
            out.append("%s.%s: one line of at most 1000 characters" % (key, cmd))
    if not (_whole(entry["port"]) and 1024 <= entry["port"] <= 65535):
        out.append("%s.port: 1024-65535" % key)
    out += _egress_problems(entry.get("egress", []), key)
    return out


def _egress_problems(hosts, key):
    if not isinstance(hosts, list) or any(h not in EGRESS_HOSTS for h in hosts):
        return ["%s.egress: only hosts of %s" % (key, ", ".join(EGRESS_HOSTS))]
    return []


def _presets_problems(entry):
    if not _obj(entry, PRESETS):
        return ["presets: exactly %s" % ", ".join(PRESETS)]
    out = []
    for name, nets in sorted(entry.items()):
        if not isinstance(nets, list) or not nets or len(nets) > 200:
            out.append("presets.%s: a list of 1-200 networks" % name)
            continue
        canon = [_canonical_net(n) for n in nets]
        if any(c is None or c != n for c, n in zip(canon, nets)):
            out.append("presets.%s: every network canonical (host bits clear), public" % name)
        elif {ipaddress.ip_network(n).version for n in nets} != {4, 6}:
            out.append("presets.%s: both IPv4 and IPv6 networks" % name)
    return out


def _canonical_net(text):
    try:
        net = ipaddress.ip_network(text, strict=True)
    except (TypeError, ValueError):
        return None
    if not net.is_global or net.prefixlen < (8 if net.version == 4 else 16):
        return None
    return str(net)


# ── recipe steps ────────────────────────────────────────────────────────────────────────────────
def _placeholders(text):
    return set(_PH_RE.findall(text))


def _unknown_placeholders(text):
    return sorted(_placeholders(text) - set(PLACEHOLDERS))


def _step_download(step, recipe):
    if not _obj(step, ("type",), ("strip",)) or ("strip" in step and not _full(_REL, step["strip"])):
        return ["a download step names at most a folder to strip"]
    return [] if "url" in recipe else ["a download step needs the recipe's url and sha256"]


def _step_render(step, _recipe):
    if not _obj(step, ("type", "dest", "escape", "template"), ("append",)):
        return ["a config step has dest, escape, template (and append)"]
    out = []
    if not _full(_REL, step["dest"]) or ".." in step["dest"]:
        out.append("dest %r is not a path inside the site" % step["dest"])
    if step["escape"] not in ("php", "yaml"):
        out.append("escape is php or yaml")
    tpl = step["template"]
    if not isinstance(tpl, str) or not tpl or len(tpl) > TEMPLATE_MAX or "\x00" in tpl:
        out.append("template is text of at most %d characters" % TEMPLATE_MAX)
    elif _unknown_placeholders(tpl):
        out.append("template names unknown values %s" % _unknown_placeholders(tpl))
    if "append" in step and not isinstance(step["append"], bool):
        out.append("append is true or false")
    return out


def _step_run(step, _recipe):
    if not _obj(step, ("type", "image", "argv"), ("stdin", "env")):
        return ["a run step has image and argv (and stdin, env)"]
    out = []
    if step["image"] not in ("site", "wpcli"):
        out.append("image is site or wpcli")
    argv = step["argv"]
    if not isinstance(argv, list) or not 0 < len(argv) <= ARGV_MAX or not all(_full(_ARGV_WORD, w) for w in argv):
        return out + ["argv is 1-%d words without control characters" % ARGV_MAX]
    named = set().union(*(_placeholders(w) for w in argv))
    if named & set(SECRETS) or named - set(PLACEHOLDERS) - {"trusted_hosts"}:
        out.append("argv may name only values that are not secrets")
    if "stdin" in step and step["stdin"] not in PLACEHOLDERS:
        out.append("stdin names one value")
    env = step.get("env", {})
    if not isinstance(env, dict) or len(env) > 16 or any(
            not _full(_ENV_NAME, k) or v not in PLACEHOLDERS for k, v in env.items()):
        out.append("env maps NAMES to values")
    return out


def _step_permissions(step, _recipe):
    if not _obj(step, ("type",), ("readonly", "remove")):
        return ["a permissions step has readonly and remove lists"]
    out = []
    for key in ("readonly", "remove"):
        paths = step.get(key, [])
        if not isinstance(paths, list) or len(paths) > 16 or not all(_full(_REL, p) and ".." not in p for p in paths):
            out.append("%s is a list of paths inside the site" % key)
    return out


def _step_installer(step, _recipe):
    if not _obj(step, ("type", "pages")):
        return ["a web installer step has pages"]
    pages = step["pages"]
    if not isinstance(pages, list) or not 0 < len(pages) <= PAGES_MAX:
        return ["pages is a list of 1-%d pages" % PAGES_MAX]
    out = []
    for i, page in enumerate(pages):
        out += ["page %d: %s" % (i + 1, p) for p in _page_problems(page)]
    return out


def _page_problems(page):
    if not _obj(page, ("path", "method", "form", "expect")):
        return ["has path, method, form and expect"]
    out = []
    if not _full(r"/[A-Za-z0-9_./-]{0,120}(?:\?[A-Za-z0-9_=&.-]{1,120})?", page["path"]) or ".." in page["path"]:
        out.append("path is a local path on the site")
    if page["method"] not in ("GET", "POST"):
        out.append("method is GET or POST")
    form = page["form"]
    if not isinstance(form, dict) or len(form) > 32 or any(
            not _full(_FIELD, k) or not isinstance(v, str) or len(v) > 200 or "\x00" in v or _unknown_placeholders(v)
            for k, v in form.items()):
        out.append("form maps field names to short values")
    if not (isinstance(page["expect"], str) and 0 < len(page["expect"]) <= 120 and _full(_ARGV_WORD, page["expect"])):
        out.append("expect is the text the page must show")
    return out


_STEP_CHECKS = {"download-verify-unpack": _step_download, "create-database": lambda s, r: (
    [] if _obj(s, ("type",)) else ["a database step has no fields"]),
    "render-config": _step_render, "run-in-container": _step_run, "set-permissions": _step_permissions,
    "drive-web-installer": _step_installer}


def recipe_problems(name, recipe):
    """Why `recipe` (catalog entry `name`) is not one the panel runs; [] when it is."""
    key = "recipes.%s" % name
    if not _full(_NAME, name):
        return ["%s: not a recipe name" % key]
    if not _obj(recipe, ("name", "kind", "version", "php", "database", "steps", "admin_path"),
                ("url", "sha256", "installer_path", "egress", "runtime")):
        return ["%s: has name, kind, version, php, database, steps and admin_path" % key]
    out = _recipe_head_problems(key, recipe)
    steps = recipe["steps"]
    if not isinstance(steps, list) or not 0 < len(steps) <= 12:
        return out + ["%s.steps: 1-12 steps" % key]
    for i, step in enumerate(steps):
        kind = step.get("type") if isinstance(step, dict) else None
        if kind not in STEP_TYPES:
            out.append("%s.steps[%d]: a type of %s" % (key, i, ", ".join(STEP_TYPES)))
            continue
        out += ["%s.steps[%d]: %s" % (key, i, p) for p in _STEP_CHECKS[kind](step, recipe)]
    if recipe["database"] != any(s.get("type") == "create-database" for s in steps if isinstance(s, dict)):
        out.append("%s: needs a database step exactly when database is true" % key)
    return out


def _recipe_head_problems(key, recipe):
    out = []
    if not (isinstance(recipe["name"], str) and 0 < len(recipe["name"]) <= 40 and _full(_ARGV_WORD, recipe["name"])):
        out.append("%s.name: a short display name" % key)
    if recipe["kind"] not in RECIPE_KINDS or not _full(_VERSION, recipe["version"]):
        out.append("%s: kind of %s and a version" % (key, ", ".join(RECIPE_KINDS)))
    if not isinstance(recipe["php"], list) or not all(_full(_PHP, v) for v in recipe["php"]):
        out.append("%s.php: a list of PHP versions" % key)
    if not isinstance(recipe["database"], bool):
        out.append("%s.database: true or false" % key)
    if ("url" in recipe) != ("sha256" in recipe) or ("url" in recipe and not _file_ok(
            {"url": recipe["url"], "sha256": recipe["sha256"]})):
        out.append("%s: a release url on an allowed host with its sha256, or neither" % key)
    for path_key in ("admin_path", "installer_path"):
        if path_key in recipe and not _full(r"/[A-Za-z0-9_./-]{0,80}", recipe[path_key]):
            out.append("%s.%s: a local path" % (key, path_key))
    out += _egress_problems(recipe.get("egress", []), key)
    return out


# ── the whole section ───────────────────────────────────────────────────────────────────────────
def sites_problems(obj):
    """Why `obj` is not a `sites` section this panel uses; [] when it is."""
    if not _obj(obj, SITE_KEYS, OPTIONAL_KEYS):
        return ["sites: exactly %s (and optionally %s)" % (", ".join(SITE_KEYS), ", ".join(OPTIONAL_KEYS))]
    out = _caddy_problems(obj["caddy"], "caddy")
    if "caddy_cache" in obj:
        out += _caddy_problems(obj["caddy_cache"], "caddy_cache")
    out += _image_problems(obj["static"], "static")
    out += _versions_problems(obj["php"], "php", _PHP, True)
    out += _wordpress_problems(obj["wordpress"])
    out += _image_problems(obj["wpcli"], "wpcli")
    out += _tunnel_problems(obj["tunnel"])
    out += _image_problems(obj["object_cache"], "object_cache")
    runtimes = obj["runtimes"]
    if not isinstance(runtimes, dict) or not runtimes:
        out.append("runtimes: at least one runtime")
    else:
        for name, entry in sorted(runtimes.items()):
            out += _runtime_problems(name, entry)
    out += _presets_problems(obj["presets"])
    if not _obj(obj["origin_pull"], PRESETS) or not all(_full(_PEM, v) for v in obj["origin_pull"].values()):
        out.append("origin_pull: one PEM certificate per preset")
    recipes = obj["recipes"]
    if not isinstance(recipes, dict):
        out.append("recipes: an object of recipes")
    else:
        for name, recipe in sorted(recipes.items()):
            out += recipe_problems(name, recipe)
    return out


_REFUSED_SEEN = set()


def section():
    """(the `sites` section in use, its source): the signed catalog's when it passes, else the floor's."""
    from panel.services import addons_catalog as _cat   # imported here: tools/addon_catalog.py loads this file alone
    floor, stored, source = _cat.section("sites")
    if stored is not None:
        bad = sites_problems(stored)
        if not bad:
            return stored, source
        mark = (source.get("seq"), len(bad))
        if mark not in _REFUSED_SEEN:
            _REFUSED_SEEN.add(mark)
            _log.warning("signed catalog #%s: its sites section is refused (%d problem(s), first: %s); "
                         "the built-in one is used", source.get("seq"), len(bad), bad[0])
    return floor, {"kind": "floor"}


def _copy(value):
    return json.loads(json.dumps(value))


def pins(kind):
    """The pins for `kind`, a copy: "static", "php", "wordpress", "wpcli", "caddy", "caddy_cache", "tunnel" or "object_cache".

    {} for "caddy_cache" while the catalog has no cache-enabled proxy build. KeyError for anything else.
    """
    sites, _source = section()
    if kind == "caddy_cache":
        return _copy(sites.get("caddy_cache") or {})
    if kind not in ("static", "php", "wordpress", "wpcli", "caddy", "tunnel", "object_cache"):
        raise KeyError(kind)
    return _copy(sites[kind])


def supported(versions, today=None):
    """The keys of `versions` ({version: {..., "eol": date}}) whose security support has not ended, sorted."""
    today = today or date.today()
    return sorted((v for v, e in versions.items() if date.fromisoformat(e["eol"]) >= today),
                  key=lambda v: tuple(int(n) for n in v.split(".")))


def php_versions(today=None):
    """The PHP versions a site may choose today (security-supported upstream), oldest first."""
    return supported(pins("php"), today)


def php_image(kind, version, today=None):
    """The image of a PHP-based `kind` ("php" or "wordpress") at PHP `version`, or None when not offered today."""
    if version not in php_versions(today):
        return None
    if kind == "wordpress":
        return pins("wordpress")["php"].get(version, {}).get("image")
    return pins("php")[version]["image"]


def static_image():
    """The static kind's image (nginx, unprivileged)."""
    return pins("static")["image"]


def caddy_asset(arch):
    """{url, sha256, version} of the proxy binary for `arch` ("amd64" or "arm64"), or None when not pinned."""
    caddy = pins("caddy")
    asset = caddy["assets"].get(arch)
    return dict(asset, version=caddy["version"]) if asset else None


def preset_ranges(name):
    """The networks of allow-list preset `name` ("cloudflare"), IPv4 and IPv6, as canonical strings."""
    sites, _source = section()
    if name not in PRESETS:
        raise KeyError(name)
    return list(sites["presets"][name])


def origin_pull_ca(name):
    """The PEM certificate a CDN (`name`, "cloudflare") presents for authenticated origin pulls."""
    sites, _source = section()
    if name not in PRESETS:
        raise KeyError(name)
    return sites["origin_pull"][name]


def runtimes(today=None):
    """The runtimes the catalog offers: {name: {versions: {version: image}, build, start, port, egress}}.

    Only versions still supported upstream today are listed.
    """
    sites, _source = section()
    out = {}
    for name, entry in sites["runtimes"].items():
        live = supported(entry["versions"], today)
        out[name] = {"versions": {v: entry["versions"][v]["image"] for v in live}, "build": entry["build"],
                     "start": entry["start"], "port": entry["port"], "egress": list(entry.get("egress", []))}
    return out


def recipes():
    """The one-click app recipes the catalog offers: {name: {kind, runtime, version, url, sha256, steps, ...}} (copies)."""
    sites, _source = section()
    return _copy(sites["recipes"])


def recipe(name):
    """The recipe `name` (a copy), or None when the catalog has none of that name."""
    return recipes().get(name)
