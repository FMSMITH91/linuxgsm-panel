"""Game icons for the install page, fetched by the PANEL from linuxgsm.com and served from its origin.

LinuxGSM's own site shows a small icon per game on https://linuxgsm.com/servers/ — an
`<img class="games">` inside the link to `/servers/<script>/`, pointing at an upload under
`/wp-content/uploads/` whose file name follows no pattern a script name could predict. So the
index page is read once (and again weekly) to map each script name to its icon, and each icon is
fetched the first time a browser asks the panel for it.

The browser never talks to linuxgsm.com: the page's CSP is `img-src 'self' data:` and stays so.
What the panel fetches is held to:

* https only, to the one host linuxgsm.com, with redirects refused (a redirect could name any host);
* an icon URL under /wp-content/uploads/ on that host, read out of the index — never a caller's text;
* a size cap on every body, and a timeout on every request;
* an image that IS a PNG, JPEG or WEBP by its first bytes (and says so in Content-Type). SVG is
  never accepted: it is a document that can carry script, and nothing here needs a vector icon.

The route asks for an icon by script name, and that name must be one LinuxGSM's serverlist knows
(lgsm_data), so it can never address a path: the cache file name is that name plus a fixed suffix.
A game with no icon (or a fetch that failed) is answered "none" and the page draws its initials.
A failure is remembered for a while, so a page full of tiles cannot make the panel hammer the site.
"""
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from panel import REPO_ROOT as _ROOT

_log = logging.getLogger(__name__)

INDEX_URL = "https://linuxgsm.com/servers/"
_HOST = "linuxgsm.com"
_UPLOADS = "/wp-content/uploads/"
_TIMEOUT = 8
_INDEX_CAP = 3 * 1024 * 1024
ICON_CAP = 256 * 1024
_INDEX_MAX_AGE = 7 * 24 * 3600
_ICON_MAX_AGE = 30 * 24 * 3600
_FAIL_BACKOFF = 6 * 3600
_INDEX_FAIL_BACKOFF = 3600

# A LinuxGSM script name: the serverlist's `gameservername`, which is `<shortname>server`.
SCRIPT_RE = re.compile(r"[a-z0-9]{1,24}server")
# One tile on the index: the link to the game's page, then its small icon.
_TILE_RE = re.compile(r'<a href="https://linuxgsm\.com/servers/([a-z0-9]{1,24}server)/"><img '
                      r'[^>]{0,300}?class="games"[^>]{0,300}?src="([^"<>\s]{1,300})"')
_TYPES = (("image/png", b"\x89PNG\r\n\x1a\n", "png"), ("image/jpeg", b"\xff\xd8\xff", "jpg"))

_CACHE_DIR = _ROOT / "data" / "game_icons"
_lock = threading.Lock()
_state = {"index": None, "index_at": 0.0, "index_failed_until": 0.0}
_failed = {}          # script -> monotonic-free epoch until which a failed icon is not retried


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the allowlist is the URL asked for, not wherever it points next."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return None, which makes urllib raise the 3xx as an HTTPError."""
        return None


def _cmpd_allowed_url(url, uploads_only=False):
    """Whether `url` is https on linuxgsm.com (and, for an icon, under /wp-content/uploads/)."""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if p.scheme != "https" or p.hostname != _HOST or p.port not in (None, 443) or p.username:
        return False
    if uploads_only and (not p.path.startswith(_UPLOADS) or ".." in p.path or p.query):
        return False
    return True


def _cmpd_http_get(url, cap):
    """GET `url` (allowlisted by the caller): (body, content_type, None) or (None, None, why).

    Never raises. The one place this module touches the network, so tests replace it.
    """
    if not _cmpd_allowed_url(url):
        return None, None, "not an allowed URL"
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "linuxgsm-panel"})
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with opener.open(req, timeout=_TIMEOUT) as resp:  # nosec B310 - https linuxgsm.com only, checked above
            if getattr(resp, "status", 200) != 200:
                return None, None, "HTTP %s" % resp.status
            body = resp.read(cap + 1)
            ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    except Exception as e:  # noqa: BLE001 - every failure is "no icon", never a raise to the page
        return None, None, e.__class__.__name__
    if len(body) > cap:
        return None, None, "too large"
    return body, ctype, None


def sniff(data):
    """("image/png" | "image/jpeg" | "image/webp", ext) by the first bytes, else None."""
    if not data:
        return None
    for mime, magic, ext in _TYPES:
        if data.startswith(magic):
            return mime, ext
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp", "webp"
    return None


def parse_index(html):
    """{script: icon URL} from the servers page, keeping only allowlisted icon URLs (first wins)."""
    out = {}
    for script, src in _TILE_RE.findall(html or ""):
        if script not in out and _cmpd_allowed_url(src, uploads_only=True):
            out[script] = src
    return out


def _index_file():
    return _CACHE_DIR / "index.json"


def _cmpd_saved_index():
    """(icons, saved-at epoch) from the cached index file, each entry re-checked; None when unreadable."""
    try:
        saved = json.loads(_index_file().read_text(encoding="utf-8"))
        icons, at = saved["icons"], float(saved.get("at") or 0)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None
    if not isinstance(icons, dict):
        return None
    return {k: v for k, v in icons.items() if _cmpd_index_entry_ok(k, v)}, at


def _cmpd_index_entry_ok(script, url):
    """Whether one saved index entry is a script name and an allowlisted icon URL."""
    return (isinstance(script, str) and bool(SCRIPT_RE.fullmatch(script)) and isinstance(url, str)
            and _cmpd_allowed_url(url, uploads_only=True))


def _cmpd_load_index():
    """The {script: url} map: memory, else the cached file, else a fetch. {} when none is had."""
    now = time.time()
    if _state["index"] is not None and now - _state["index_at"] < _INDEX_MAX_AGE:
        return _state["index"]
    saved = _cmpd_saved_index()
    if saved is not None:
        _state.update(index=saved[0], index_at=saved[1])
        if now - saved[1] < _INDEX_MAX_AGE:
            return saved[0]
    if now < _state["index_failed_until"]:
        return _state["index"] or {}
    return _cmpd_fetch_index(now)


def _cmpd_fetch_index(now):
    """Fetch and parse the servers page; on nothing usable, back off and keep what is known."""
    body, _ctype, why = _cmpd_http_get(INDEX_URL, _INDEX_CAP)
    icons = parse_index(body.decode("utf-8", errors="replace")) if body else {}
    if not icons:
        _log.info("game icons: the LinuxGSM servers page gave no icons (%s)", why or "none found")
        _state["index_failed_until"] = now + _INDEX_FAIL_BACKOFF
        return _state["index"] or {}
    _state.update(index=icons, index_at=now)
    _cmpd_write(_index_file(), json.dumps({"at": now, "icons": icons}).encode("utf-8"))
    return icons


def _cmpd_write(path, data):
    """Write `path` atomically (a reader never sees half a file): True once written. Logged, never raised."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name("%s.%d.%d.tmp" % (path.name, os.getpid(), threading.get_ident()))
        tmp.write_bytes(data)
        os.replace(tmp, path)
        return True
    except OSError:
        _log.warning("game icons: could not write the cache under data/", exc_info=True)
        return False


def _cmpd_cached(script):
    """(bytes, mime, age seconds) of the cached icon, re-sniffed, or None."""
    for _mime, _magic, ext in _TYPES + (("image/webp", b"", "webp"),):
        path = _CACHE_DIR / ("%s.%s" % (script, ext))
        try:
            data = path.read_bytes()
            age = time.time() - path.stat().st_mtime
        except OSError:
            continue
        kind = sniff(data)
        if kind is not None and kind[1] == ext and len(data) <= ICON_CAP:
            return data, kind[0], age
    return None


def _cmpd_fetch_icon(script):
    """Fetch, check and cache `script`'s icon: (bytes, mime) or None."""
    url = _cmpd_load_index().get(script)
    if not url:
        return None
    body, ctype, why = _cmpd_http_get(url, ICON_CAP)
    kind = sniff(body)
    if kind is None or ctype not in ("image/png", "image/jpeg", "image/webp"):
        _log.info("game icons: %s refused (%s)", script, why or "not a PNG/JPEG/WEBP image")
        return None
    if _cmpd_write(_CACHE_DIR / ("%s.%s" % (script, kind[1])), body):
        _r37b_drop_other_formats(script, kind[1])
    return body, kind[0]


def _r37b_drop_other_formats(script, kept):
    """Remove `script`'s cached icon in every format but `kept`, once the new one is written.

    An icon whose format changed upstream (a png re-uploaded as webp) was written beside the old
    file, and _cmpd_cached, which looks in a fixed order, kept finding the old one, stale, so every
    request for it fetched again under the module-wide lock. Only after a write that worked: a
    failed write leaves the old copy as the only one there is.
    """
    for _mime, _magic, ext in _TYPES + (("image/webp", b"", "webp"),):
        if ext != kept:
            try:
                (_CACHE_DIR / ("%s.%s" % (script, ext))).unlink(missing_ok=True)
            except OSError:
                _log.warning("game icons: could not remove an old cached icon", exc_info=True)


def _cmpd_listed_name(script, known):
    """Return LinuxGSM's own copy of `script` from `known`, or None.

    From here on (cache file names, the log) the name is that copy, never the caller's text.
    """
    if not isinstance(script, str) or not SCRIPT_RE.fullmatch(script):
        return None
    return {k: k for k in known}.get(script)


def icon(script, known):
    """(bytes, mime) for `script`'s icon, or None. `known` is the set of LinuxGSM script names.

    A name that is not one of LinuxGSM's scripts is refused before anything reads a file or the
    network. A cached icon is served at once; a missing or month-old one is fetched (one fetch at a
    time), and a failure is not retried for _FAIL_BACKOFF, the stale copy serving meanwhile.
    """
    script = _cmpd_listed_name(script, known)
    if script is None:
        return None
    hit = _cmpd_cached(script)
    if hit is not None and hit[2] < _ICON_MAX_AGE:
        return hit[0], hit[1]
    if time.time() < _failed.get(script, 0):
        return (hit[0], hit[1]) if hit else None
    with _lock:
        fresh = _cmpd_fetch_icon(script)
    if fresh is None:
        _failed[script] = time.time() + _FAIL_BACKOFF
        return (hit[0], hit[1]) if hit else None
    _failed.pop(script, None)
    return fresh
