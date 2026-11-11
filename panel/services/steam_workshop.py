"""Steam Workshop ids and titles for a server's Workshop card (panel/routes/workshop.py).

The PANEL HOST asks Steam's public Web API for the titles of the Workshop items and collections a
server's config lists; the browser never does, and nothing is downloaded here (LinuxGSM's
workshop-update, or the game itself, does that on the game server). What the panel fetches is held to:

* POST to https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/ and
  GetCollectionDetails/v1/ only (both need no key), with redirects refused;
* at most 100 ids per request (_WSC_BATCH, LinuxGSM's own workshopapimax), each 1 to 20 digits;
* a size cap on every answer, a timeout on every request;
* a short in-process cache, so a card opened again does not ask Steam again.

When Steam does not answer, the caller shows the bare ids and says titles are unavailable: editing a
list never depends on Steam. The one place this module touches the network is _wsc_http_post, so the
tests replace it.
"""
import json
import re
import threading
import time
import urllib.parse
import urllib.request

_WSC_BASE = "https://api.steampowered.com/ISteamRemoteStorage/"
_WSC_METHODS = ("GetPublishedFileDetails", "GetCollectionDetails")
_WSC_TIMEOUT = 10
_WSC_CAP = 2 * 1024 * 1024
_WSC_BATCH = 100
_WSC_TTL = 600
_WSC_CACHE_MAX = 4000
_WSC_TITLE_MAX = 200
_WSC_UA = "linuxgsm-panel (workshop titles)"

# A Workshop id as LinuxGSM and the games read one: digits only. 20 digits holds any 64-bit id.
_WSC_ID = re.compile(r"[0-9]{1,20}")
# A Workshop page URL: only its `id` query parameter is read, and the URL is never fetched.
_WSC_URL_HOSTS = frozenset({"steamcommunity.com", "www.steamcommunity.com"})
MAX_IDS = 200

BAD_ID = ("A Workshop id is 1 to 20 digits, or a steamcommunity.com Workshop link that has one "
          "(…?id=123456789).")
TOO_MANY = "A list holds at most 200 Workshop ids."
DUPLICATE = "Each Workshop id can be in the list once."

_wsc_cache = {}
_wsc_lock = threading.Lock()


class _WscNoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the allowlist is the URL asked for, not wherever it points next."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return None, which makes urllib raise the 3xx as an HTTPError."""
        return None


def valid_id(value):
    """Whether `value` is a Workshop id: a string of 1 to 20 digits."""
    return isinstance(value, str) and bool(_WSC_ID.fullmatch(value))


def normalize_id(value):
    """The Workshop id in `value` (digits, or a steamcommunity.com link's `id=`), or None.

    The link is only taken apart, never fetched: https on steamcommunity.com, and its `id`
    parameter must be digits.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if valid_id(text):
        return text
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        return None
    if parts.scheme not in ("https", "http") or (parts.hostname or "") not in _WSC_URL_HOSTS:
        return None
    found = urllib.parse.parse_qs(parts.query).get("id") or []
    return found[0] if len(found) == 1 and valid_id(found[0]) else None


def check_ids(values):
    """(ids, None) for a list of ids or links, in order, or (None, why)."""
    if not isinstance(values, list):
        return None, BAD_ID
    if len(values) > MAX_IDS:
        return None, TOO_MANY
    ids = []
    for v in values:
        wid = normalize_id(v)
        if wid is None:
            return None, BAD_ID
        if wid in ids:
            return None, DUPLICATE
        ids.append(wid)
    return ids, None


def split_ids(text):
    """The ids in a workshopmods value, in order, as LinuxGSM reads them, and the tokens it ignores.

    LinuxGSM's fn_workshop_config_ids splits on blanks, commas and semicolons and skips (with a
    warning) anything that is not digits. Returns (ids, ignored).
    """
    ids, ignored = [], []
    for token in re.split(r"[\s,;]+", text or ""):
        if not token:
            continue
        (ids if valid_id(token) else ignored).append(token)
    return ids, ignored


def _wsc_http_post(method, form):
    """POST `form` to one ISteamRemoteStorage method: (body bytes, None) or (None, why). Never raises."""
    if method not in _WSC_METHODS:
        return None, "not an allowed method"
    url = _WSC_BASE + method + "/v1/"
    data = urllib.parse.urlencode(form).encode("ascii")
    opener = urllib.request.build_opener(_WscNoRedirect)
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"User-Agent": _WSC_UA, "Accept": "application/json",
                                          "Content-Type": "application/x-www-form-urlencoded"})
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with opener.open(req, timeout=_WSC_TIMEOUT) as resp:  # nosec B310 - a fixed https Steam URL
            if getattr(resp, "status", 200) != 200:
                return None, "HTTP %s" % resp.status
            body = resp.read(_WSC_CAP + 1)
    except Exception as e:  # noqa: BLE001 - every failure is "Steam could not be reached"
        return None, e.__class__.__name__
    if len(body) > _WSC_CAP:
        return None, "too large"
    return body, None


def _wsc_ask(method, ids, list_key):
    """Steam's rows under response.<list_key> for `ids` (at most _WSC_BATCH), or None."""
    count = "collectioncount" if method == "GetCollectionDetails" else "itemcount"
    form = {count: str(len(ids))}
    for i, wid in enumerate(ids):
        form["publishedfileids[%d]" % i] = wid
    body, _why = _wsc_http_post(method, form)
    if body is None:
        return None
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    resp = data.get("response") if isinstance(data, dict) else None
    rows = resp.get(list_key) if isinstance(resp, dict) else None
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else None


def _wsc_entry(detail, collection):
    """The card's fields for one id from Steam's two answers."""
    title = detail.get("title") if detail.get("result") == 1 else None
    children = collection.get("children") if collection.get("result") == 1 else None
    items = len(children) if isinstance(children, list) and children else 0
    return {"title": title[:_WSC_TITLE_MAX] if isinstance(title, str) else "",
            "found": detail.get("result") == 1, "collection": items > 0, "items": items}


def _wsc_fetch(ids):
    """{id: entry} for one batch, or None when Steam did not answer both questions."""
    details = _wsc_ask("GetPublishedFileDetails", ids, "publishedfiledetails")
    colls = _wsc_ask("GetCollectionDetails", ids, "collectiondetails")
    if details is None or colls is None:
        return None
    by_d = {str(r.get("publishedfileid")): r for r in details}
    by_c = {str(r.get("publishedfileid")): r for r in colls}
    return {wid: _wsc_entry(by_d.get(wid, {}), by_c.get(wid, {})) for wid in ids}


def _wsc_wanted(ids):
    """The valid ids in `ids`, each once, in order, at most MAX_IDS."""
    wanted = []
    for wid in ids or []:
        if valid_id(wid) and wid not in wanted:
            wanted.append(wid)
    return wanted[:MAX_IDS]


def _wsc_cached(wanted, now):
    """({id: entry} still fresh in the cache, [ids to ask Steam for])."""
    out, missing = {}, []
    with _wsc_lock:
        for wid in wanted:
            hit = _wsc_cache.get(wid)
            if hit and now - hit[0] < _WSC_TTL:
                out[wid] = hit[1]
            else:
                missing.append(wid)
    return out, missing


def _wsc_store(got, now):
    """Keep Steam's answers in the cache (emptied first when it has grown past its cap)."""
    with _wsc_lock:
        if len(_wsc_cache) > _WSC_CACHE_MAX:
            _wsc_cache.clear()
        for wid, entry in got.items():
            _wsc_cache[wid] = (now, entry)


def details(ids):
    """({id: {"title", "found", "collection", "items"}}, True) for the valid ids given.

    The second value is False when Steam did not answer for some of them: those ids are left out,
    and the card shows them bare. Invalid ids are dropped before anything is asked.
    """
    now = time.monotonic()
    out, missing = _wsc_cached(_wsc_wanted(ids), now)
    complete = True
    for start in range(0, len(missing), _WSC_BATCH):
        got = _wsc_fetch(missing[start:start + _WSC_BATCH])
        if got is None:
            complete = False
            continue
        _wsc_store(got, now)
        out.update(got)
    return out, complete
