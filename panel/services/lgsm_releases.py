"""LinuxGSM's release notes, for the server page's "What's new" before and after update-lgsm.

The notes come from LinuxGSM's GitHub releases (api.github.com/repos/GameServerManagers/LinuxGSM/
releases), the page every LinuxGSM release is published on. They are read in the background, at
most once a day (and again within the hour after a failed read, or when the newest release the
panel knows of is not among them yet), and every page is served from that copy: opening the notes
never makes a request to GitHub, and a page is never held up by one.

The notes are Markdown written by a third party. They reach the page as plain text only: each one
is cut into blocks (a heading, a list item or a paragraph) whose text has its markup, HTML tags and
link targets removed, and the page puts that text in with textContent. The only link the page
draws is the release's own page, built here from a validated tag, never taken from the answer.
"""
import json
import logging
import re
import threading
import time
import urllib.request

from panel.services import lgsm_data

_log = logging.getLogger(__name__)

RELEASES_PAGE = "https://github.com/GameServerManagers/LinuxGSM/releases"
_API_URL = "https://api.github.com/repos/GameServerManagers/LinuxGSM/releases?per_page=20"
_TIMEOUT = 10
_MAX_BYTES = 2 * 1024 * 1024
_FRESH_SECONDS = 86400
_RETRY_SECONDS = 3600
# What one release may show: past this the page says the notes go on and links the release page.
_NOTE_CHARS = 2500
_NOTE_BLOCKS = 30
# How many releases one answer may hold (an account many releases behind sees the newest ten).
_MAX_RELEASES = 10
# The long per-pull-request list GitHub generates under the written notes: left to the release page.
_STOP_RE = re.compile(r"^#{1,6}\s*(what'?s changed|new contributors)\b", re.I)
_FULL_CHANGELOG = "**full changelog**"
_HEAD_RE = re.compile(r"^#{1,6}\s+")
_ITEM_RE = re.compile(r"^(?:[-*+]|\d{1,3}[.)])\s+")
# A link target may hold one level of parentheses ("(https://x/a_(b))"): taken whole, not cut at ")".
_TARGET = r"\((?:[^()]|\([^()]*\))*\)"
_IMAGE_RE = re.compile(r"!\[[^\]]*\]" + _TARGET)
_LINK_RE = re.compile(r"\[([^\]]*)\]" + _TARGET)
_TAG_RE = re.compile(r"<[^>]*>")
_MARK_RE = re.compile(r"\*\*|__|`")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SPACE_RE = re.compile(r"\s+")

_lock = threading.Lock()
_cache = {"releases": None, "until": 0.0, "read": 0.0, "running": False}


def _key(tag):
    """A release tag ('v26.6.0') as a tuple to order by."""
    return tuple(int(p) for p in tag[1:].split("."))


def plain(text):
    """One line of Markdown as plain text: links keep their words, markup and HTML tags are dropped."""
    text = _IMAGE_RE.sub("", text)
    text = _LINK_RE.sub(r"\1", text)
    text = _TAG_RE.sub("", text)
    text = _MARK_RE.sub("", text)
    return _SPACE_RE.sub(" ", _CTRL_RE.sub(" ", text)).strip()


def _block(line):
    """A {"k", "t"} block for one non-empty line: "h" a heading, "li" a list item, "p" the rest."""
    if _HEAD_RE.match(line):
        return {"k": "h", "t": plain(_HEAD_RE.sub("", line))}
    if _ITEM_RE.match(line):
        return {"k": "li", "t": plain(_ITEM_RE.sub("", line))}
    return {"k": "p", "t": plain(line)}


def blocks(body):
    """The written part of one release's notes as blocks, and whether anything was left out.

    Stops at GitHub's generated "What's Changed" list and the "Full Changelog" line, and at
    _NOTE_CHARS / _NOTE_BLOCKS. -> (blocks, cut).
    """
    out, size = [], 0
    for raw in (body or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if _STOP_RE.match(line) or line.lower().startswith(_FULL_CHANGELOG):
            return out, True
        block = _block(line)
        if not block["t"]:
            continue
        if len(out) >= _NOTE_BLOCKS or size + len(block["t"]) > _NOTE_CHARS:
            return out, True
        size += len(block["t"])
        out.append(block)
    return out, False


def _release(item):
    """One release from GitHub's answer as the page gets it, or None for a draft, prerelease or odd item."""
    if not isinstance(item, dict) or item.get("draft") or item.get("prerelease"):
        return None
    tag = lgsm_data.release_tag(item.get("tag_name"))
    body = item.get("body")
    if tag is None or not isinstance(body, (str, type(None))):
        return None
    published = item.get("published_at")
    notes, cut = blocks(body)
    return {"tag": tag, "date": published[:10] if isinstance(published, str) else "",
            "blocks": notes, "cut": cut, "url": RELEASES_PAGE + "/tag/" + tag}


def parse(answer):
    """GitHub's releases answer (decoded JSON) as releases, newest first; None when it is not that shape."""
    if not isinstance(answer, list):
        return None
    found = [r for r in (_release(i) for i in answer) if r]
    return sorted(found, key=lambda r: _key(r["tag"]), reverse=True)


def _open(req):
    """GET `req` (the fixed _API_URL): the body, at most _MAX_BYTES. Raises on any failure."""
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- a fixed https://api.github.com URL
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # nosec B310 - fixed https host
        return resp.read(_MAX_BYTES)


def _fetch():
    """Read LinuxGSM's releases from GitHub: the parsed list, or None. Never raises."""
    req = urllib.request.Request(_API_URL, headers={"Accept": "application/vnd.github+json",
                                                    "User-Agent": "linuxgsm-panel"})
    try:
        answer = json.loads(_open(req).decode("utf-8", errors="replace"))
    except Exception as e:
        _log.debug("LinuxGSM's release notes could not be read: %s", e.__class__.__name__)
        return None
    return parse(answer)


def _refresh():
    found = _fetch()
    with _lock:
        if found:
            _cache["releases"] = found
        _cache["read"] = time.time()
        _cache["until"] = _cache["read"] + (_FRESH_SECONDS if found else _RETRY_SECONDS)
        _cache["running"] = False


def _due(newest):
    """Whether a background read should start now (called under _lock)."""
    if _cache["running"]:
        return False
    if time.time() >= _cache["until"]:
        return True
    # A newer release than the copy holds: read again, but no more often than the retry interval.
    known = {r["tag"] for r in _cache["releases"] or ()}
    return bool(newest and newest not in known and time.time() >= _cache["read"] + _RETRY_SECONDS)


def releases(newest=None):
    """Every release the panel has read, newest first ([] before the first read). Never waits on GitHub.

    `newest`: the latest release the panel knows of (lgsm_data.latest_release); a copy without it
    starts a re-read, at most once an hour.
    """
    with _lock:
        held, due = _cache["releases"], _due(newest)
        if due:
            _cache["running"] = True
    if due:
        try:
            threading.Thread(target=_refresh, daemon=True, name="lgsm-releases").start()
        except Exception:
            with _lock:
                _cache["running"] = False
    return list(held or ())


def between(since, until):
    """The releases after `since` up to and including `until`, newest first, at most _MAX_RELEASES.

    `since` None (not read): `until` alone. An invalid `until` gives []. Never waits on GitHub.
    """
    if lgsm_data.release_tag(until) is None:
        return []
    held = releases(until)
    if lgsm_data.release_tag(since) is None:
        return [r for r in held if r["tag"] == until]
    low, high = _key(since), _key(until)
    return [r for r in held if low < _key(r["tag"]) <= high][:_MAX_RELEASES]
