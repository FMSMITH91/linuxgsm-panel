"""Modrinth (https://api.modrinth.com/v2) for a PaperMC server's plugins and a Java server's datapacks.

Search, and one verified download. Two kinds of project (KINDS): a "plugin" (Paper, Spigot or
Bukkit builds, a .jar) and a "datapack" (Modrinth's datapack project type, whose builds list the
"datapack" loader and ship a .zip; checked against the API on 2026-11-14: Terralith's 1.21 builds are
loaders ["datapack"] with one primary .zip on cdn.modrinth.com and a sha512).

The PANEL HOST is the only thing that talks to Modrinth; the browser never does, and the game
server never downloads anything. What the panel fetches is held to:

* https only, to api.modrinth.com for the API and cdn.modrinth.com for a file, with redirects
  refused (a redirect could name any host);
* a file URL taken from the API's own answer, never from the caller;
* a size cap on every body (the API's and the file's), and a timeout on every request;
* a file whose sha512 equals the one the API gave for it: a body that does not match is dropped
  before anything reaches the game server.

Ids are checked by Modrinth's documented format (an eight-character base62 id) before they go
into a URL, and a search query is capped and must be printable. The one place this module touches
the network is _mdr_http_get, so the tests replace it.
"""
import hashlib
import json
import re
import urllib.parse
import urllib.request

API = "https://api.modrinth.com/v2"
_MDR_API_HOST = "api.modrinth.com"
_MDR_CDN_HOSTS = frozenset({"cdn.modrinth.com"})
_MDR_TIMEOUT = 15
_MDR_FILE_TIMEOUT = 60
_MDR_API_CAP = 2 * 1024 * 1024
# The file browser's upload limit: a plugin is put on the server as an uploaded jar would be.
FILE_CAP = 50 * 1024 * 1024
_MDR_UA = "linuxgsm-panel (plugin browser)"
# The loaders a PaperMC server runs: Paper's own builds, and the Spigot and Bukkit builds it loads.
LOADERS = ("paper", "spigot", "bukkit")
SEARCH_LIMIT = 20
QUERY_MAX = 80
_MDR_ID = re.compile(r"[0-9A-Za-z]{8}")
_MDR_SHA512 = re.compile(r"[0-9a-f]{128}")
_MDR_MC_VERSION = re.compile(r"\d{1,2}\.\d{1,3}(?:\.\d{1,3})?")
_MDR_PAPER_MC = re.compile(r"\(MC: (\d{1,2}\.\d{1,3}(?:\.\d{1,3})?)\)")
_MDR_TEXT_MAX = 300

BAD_ID = "That is not a Modrinth project id."
BAD_QUERY = "A search is at most 80 characters, on one line, with no control characters."
UNAVAILABLE = "Modrinth could not be reached, or gave an answer that could not be read. Try again later."
NO_VERSION = "Modrinth lists no build of this plugin for Paper, Spigot or Bukkit on this Minecraft version."
NO_FILE = "This plugin's build on Modrinth has no file the panel can install (it must be a .jar file)."
TOO_LARGE = "This plugin's file is larger than the 50 MB the panel will install."
BAD_HASH = "The downloaded file did not match the checksum Modrinth gave for it, so it was not installed."
DP_NO_VERSION = "Modrinth lists no datapack build of this project for this Minecraft version."
DP_NO_FILE = "This datapack's build on Modrinth has no file the panel can install (it must be a .zip file)."
DP_TOO_LARGE = "This datapack's file is larger than the 50 MB the panel will install."
# Per kind: the search facets, the loaders a build must list, the file extension, and its refusals.
KINDS = {
    "plugin": {"facets": [["project_type:plugin"], ["categories:" + x for x in LOADERS]], "loaders": LOADERS,
               "ext": ".jar", "no_version": NO_VERSION, "no_file": NO_FILE, "too_large": TOO_LARGE},
    "datapack": {"facets": [["project_type:datapack"]], "loaders": ("datapack",), "ext": ".zip",
                 "no_version": DP_NO_VERSION, "no_file": DP_NO_FILE, "too_large": DP_TOO_LARGE},
}


class _MdrNoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the allowlist is the URL asked for, not wherever it points next."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return None, which makes urllib raise the 3xx as an HTTPError."""
        return None


def _mdr_allowed(url, hosts):
    """Whether `url` is https on one of `hosts`, on the default port, with no credentials."""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return (p.scheme == "https" and p.hostname in hosts and p.port in (None, 443)
            and not p.username and not p.password)


def _mdr_http_get(url, cap, hosts, timeout=_MDR_TIMEOUT):
    """GET `url`: (body bytes, None) or (None, why). Never raises; refuses a URL off `hosts`."""
    if not _mdr_allowed(url, hosts):
        return None, "not an allowed URL"
    opener = urllib.request.build_opener(_MdrNoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": _MDR_UA, "Accept": "*/*"})
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with opener.open(req, timeout=timeout) as resp:  # nosec B310 - https Modrinth hosts only, checked above
            if getattr(resp, "status", 200) != 200:
                return None, "HTTP %s" % resp.status
            body = resp.read(cap + 1)
    except Exception as e:  # noqa: BLE001 - every failure is "Modrinth could not be reached"
        return None, e.__class__.__name__
    if len(body) > cap:
        return None, "too large"
    return body, None


def _mdr_api(path, params=None):
    """The API's JSON answer for `path` (already made of checked parts), or None."""
    url = API + path + ("?" + urllib.parse.urlencode(params) if params else "")
    body, _why = _mdr_http_get(url, _MDR_API_CAP, frozenset({_MDR_API_HOST}))
    if body is None:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def valid_id(value):
    """Whether `value` is a Modrinth project or version id: eight base62 characters."""
    return isinstance(value, str) and bool(_MDR_ID.fullmatch(value))


def valid_mc_version(value):
    """Whether `value` reads as a Minecraft release number such as 1.21 or 1.21.4."""
    return isinstance(value, str) and bool(_MDR_MC_VERSION.fullmatch(value))


def query_problem(query):
    """Why a search text is refused, else None."""
    if not isinstance(query, str) or len(query) > QUERY_MAX or not query.isprintable():
        return BAD_QUERY
    return None


def paper_mc_version(text):
    """The Minecraft version from Paper's serverfiles/version_history.json text, or None.

    Paper writes the build it runs there, as {"currentVersion": "1.21.4-212-abc (MC: 1.21.4)"}.
    """
    try:
        data = json.loads(text or "")
    except ValueError:
        return None
    current = data.get("currentVersion") if isinstance(data, dict) else None
    m = _MDR_PAPER_MC.search(current) if isinstance(current, str) else None
    return m.group(1) if m else None


def _mdr_text(value, limit=_MDR_TEXT_MAX):
    """A text field from Modrinth's answer, capped; anything that is not text is ''."""
    return value[:limit] if isinstance(value, str) else ""


def _mdr_count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _mdr_hit(hit):
    """The fields the card shows for one search hit, or None for one without a valid project id."""
    if not isinstance(hit, dict) or not valid_id(hit.get("project_id")):
        return None
    return {"project_id": hit["project_id"], "title": _mdr_text(hit.get("title"), 100),
            "description": _mdr_text(hit.get("description")), "author": _mdr_text(hit.get("author"), 64),
            "downloads": _mdr_count(hit.get("downloads"))}


def search(query, mc_version=None, kind="plugin"):
    """(hits, None) for a checked query, or (None, why). With no version, every version is searched."""
    why = query_problem(query)
    if why:
        return None, why
    facets = [list(f) for f in KINDS[kind]["facets"]]
    if mc_version:
        facets.append(["versions:" + mc_version])
    params = {"query": query, "facets": json.dumps(facets), "limit": SEARCH_LIMIT,
              "index": "relevance" if query else "downloads"}
    data = _mdr_api("/search", params)
    hits = data.get("hits") if isinstance(data, dict) else None
    if not isinstance(hits, list):
        return None, UNAVAILABLE
    return [h for h in (_mdr_hit(x) for x in hits) if h is not None], None


def safe_filename(name, ext=".jar"):
    """A file name from the API's: basename only, [A-Za-z0-9._+-], ending `ext` (.jar, .zip); else None."""
    if not isinstance(name, str):
        return None
    base = re.split(r"[/\\]", name)[-1]
    base = re.sub(r"[^A-Za-z0-9._+-]", "_", base).lstrip(".")[:128]
    if not base.lower().endswith(ext) or len(base) <= len(ext):
        return None
    return base[:-len(ext)] + ext


def _mdr_primary(files):
    """The version's primary file (the first when none is marked), or None."""
    if not isinstance(files, list) or not files:
        return None
    marked = [f for f in files if isinstance(f, dict) and f.get("primary") is True]
    first = marked[0] if marked else files[0]
    return first if isinstance(first, dict) else None


def _mdr_pick(versions, project_id):
    """The newest release (else the newest build) of `project_id` from the API's list, or None."""
    ok = [v for v in versions if isinstance(v, dict) and v.get("project_id") == project_id
          and valid_id(v.get("id"))] if isinstance(versions, list) else []
    releases = [v for v in ok if v.get("version_type") == "release"]
    return (releases or ok or [None])[0]


def _mdr_file_ok(url, sha):
    """Whether a file's URL is https on Modrinth's CDN and its sha512 is 128 lowercase hex digits."""
    return (isinstance(url, str) and _mdr_allowed(url, _MDR_CDN_HOSTS)
            and isinstance(sha, str) and bool(_MDR_SHA512.fullmatch(sha)))


def file_plan(version, kind="plugin"):
    """(plan, None) for the version's primary file, or (None, why).

    plan = {"url", "filename", "sha512", "size"}: a URL on Modrinth's CDN over https, a sanitized
    .jar (a plugin) or .zip (a datapack) name, a 128-hex sha512, and a size within FILE_CAP.
    """
    k = KINDS[kind]
    f = _mdr_primary(version.get("files"))
    if f is None:
        return None, k["no_file"]
    hashes = f.get("hashes") if isinstance(f.get("hashes"), dict) else {}
    url, sha = f.get("url"), hashes.get("sha512")
    name = safe_filename(f.get("filename"), k["ext"])
    if name is None or not _mdr_file_ok(url, sha):
        return None, k["no_file"]
    size = f.get("size")
    if isinstance(size, int) and size > FILE_CAP:
        return None, k["too_large"]
    return {"url": url, "filename": name, "sha512": sha, "size": size if isinstance(size, int) else None}, None


def resolve(project_id, mc_version=None, kind="plugin"):
    """(info, None) for the build to install, or (None, why).

    info = {"title", "version_id", "version_number", "plan"}: the newest release of the project for
    the kind's loaders (Paper, Spigot or Bukkit; or "datapack"), on `mc_version` when it is known,
    and its primary file's plan.
    """
    if not valid_id(project_id):
        return None, BAD_ID
    params = {"loaders": json.dumps(list(KINDS[kind]["loaders"])), "include_changelog": "false"}
    if mc_version:
        params["game_versions"] = json.dumps([mc_version])
    # Already held to valid_id (8 base62 characters); quoted as well, so the path segment can never be
    # anything but one segment whatever the check above it allows.
    seg = urllib.parse.quote(project_id, safe="")
    project = _mdr_api("/project/" + seg)
    versions = _mdr_api("/project/%s/version" % seg, params)
    if not isinstance(project, dict) or not isinstance(versions, list):
        return None, UNAVAILABLE
    version = _mdr_pick(versions, project_id)
    if version is None:
        return None, KINDS[kind]["no_version"]
    plan, why = file_plan(version, kind)
    if why:
        return None, why
    return {"title": _mdr_text(project.get("title"), 100) or project_id, "version_id": version["id"],
            "version_number": _mdr_text(version.get("version_number"), 64), "plan": plan}, None


def download(plan, kind="plugin"):
    """(bytes, None) for the plan's file once its sha512 matches, or (None, why). Nothing is kept else."""
    body, _why = _mdr_http_get(plan["url"], FILE_CAP, _MDR_CDN_HOSTS, timeout=_MDR_FILE_TIMEOUT)
    if body is None:
        return None, KINDS[kind]["too_large"] if _why == "too large" else UNAVAILABLE
    if hashlib.sha512(body).hexdigest() != plan["sha512"]:
        return None, BAD_HASH
    return body, None
