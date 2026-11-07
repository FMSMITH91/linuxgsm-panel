"""The "What's new" card: which CHANGELOG entries a user has not seen yet.

The changelog has no per-release sections to diff — the panel's version is the date of a commit,
and every change lands as a bullet under `## [Unreleased]`. So "what changed since you last
looked" is answered by CONTENT, not by version: each top-level bullet is keyed by a short hash of
its bold title, and a user row remembers the keys that were in the file the last time they
dismissed the card (User.whats_new_seen). An entry whose key is not in that set is new to them.

That also survives the file being reorganised: a bullet moved from [Unreleased] into a dated
section keeps its title, so it keeps its key and is not shown twice. A bullet whose TITLE is
reworded reads as new, which is the one case where showing it again is arguably right.

The stored value is "<stamp>:<key>,<key>,…", where the stamp is a hash of every key. A page view
compares only the stamp, so the common case — nothing changed since they last looked — never
splits the list. No database code here: the caller owns the row.

The file's text is shown as plain text (autoescaped by Jinja) — never as HTML from the file.
"""
import hashlib
import os
import re
import threading

_CHANGELOG = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                          "docs", "CHANGELOG.md")

# How many entries the card renders at most. Someone who skipped a month of updates would
# otherwise get hundreds; the rest are counted, and the full changelog is one link away.
SHOW_MAX = 40

_HEADING_RE = re.compile(r"^###\s+(\S[^\n]*)\Z")
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_SPACE_RE = re.compile(r"\s+")

_lock = threading.Lock()
_cache = {"sig": None, "entries": []}


def _cmpb_plain(text):
    """Markdown inline markup reduced to the words a reader sees: no **, backticks or link URLs."""
    text = _LINK_RE.sub(r"\1", text)
    text = text.replace("**", "").replace("`", "")
    return _SPACE_RE.sub(" ", text).strip()


def _cmpb_key(title):
    """The 8-hex key of an entry: its title, whitespace- and case-folded, hashed."""
    norm = _SPACE_RE.sub(" ", title).strip().lower()
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:8]


def _cmpb_entry(category, lines):
    """One parsed bullet: its category heading, title, body and key."""
    raw = " ".join(s.strip() for s in lines)[2:].strip()       # drop the leading "- "
    m = _BOLD_RE.search(raw)
    if m and m.start() == 0:
        title = _cmpb_plain(m.group(1))
        body = _cmpb_plain(raw[m.end():])
    else:
        # No bold lead: the first sentence stands as the title.
        plain = _cmpb_plain(raw)
        cut = plain.find(". ")
        title, body = (plain[:cut + 1], plain[cut + 2:]) if 0 < cut < 160 else (plain, "")
    return {"category": category, "title": title, "body": body, "key": _cmpb_key(title)}


def _cmpb_add(entries, seen, category, cur):
    """Append the bullet whose lines are `cur` (if any), unless its key was already taken."""
    if cur is None:
        return
    e = _cmpb_entry(category, cur)
    if e["title"] and e["key"] not in seen:
        seen.add(e["key"])
        entries.append(e)


def _cmpb_heading(line):
    """The category a "### <category>" line opens; None for any other heading."""
    m = _HEADING_RE.match(line)
    return m.group(1).rstrip() if m else None


def parse(text):
    """Every top-level bullet in a CHANGELOG's text, in file order.

    A bullet is a line starting "- " at column 0 under a "### <category>" heading; indented lines
    that follow (wrapped text, nested lists) belong to it. Anything before the first category
    heading (the preamble) is not an entry. Duplicate keys keep the first.
    """
    entries, seen = [], set()
    category, cur = None, None
    for line in (text or "").splitlines():
        if line.startswith("#"):
            _cmpb_add(entries, seen, category, cur)
            cur, category = None, _cmpb_heading(line)
        elif line.startswith("- ") and category:
            _cmpb_add(entries, seen, category, cur)
            cur = [line]
        elif cur is not None and not line[:1].strip():
            # Indented (wrapped text, a nested point) or blank: still this bullet.
            if line.strip():
                cur.append(line)
        else:
            _cmpb_add(entries, seen, category, cur)
            cur = None
    _cmpb_add(entries, seen, category, cur)
    return entries


def current_entries(path=None):
    """The entries of the panel's own CHANGELOG, re-read only when the file changes.

    [] when it cannot be read (a copy without docs/): the card then never shows and nothing is
    recorded, rather than every entry reading as new.
    """
    path = path or _CHANGELOG
    try:
        st = os.stat(path)
    except OSError:
        return []
    sig = (path, st.st_mtime_ns, st.st_size)
    with _lock:
        if _cache["sig"] == sig:
            return _cache["entries"]
    try:
        with open(path, encoding="utf-8") as f:
            entries = parse(f.read())
    except (OSError, UnicodeDecodeError):
        return []
    with _lock:
        _cache["sig"], _cache["entries"] = sig, entries
    return entries


def stamp(entries):
    """The value a user row stores once it has seen `entries`. "" for no entries."""
    if not entries:
        return ""
    keys = ",".join(e["key"] for e in entries)
    return hashlib.sha256(keys.encode("ascii")).hexdigest()[:12] + ":" + keys


def current_stamp():
    """stamp() of the panel's own CHANGELOG — the column default for a brand-new account."""
    return stamp(current_entries()) or None


def unseen(stored, entries):
    """The entries `stored` (a user's whats_new_seen) has not seen, in file order.

    Nothing for a row that has never recorded anything (None or ""): a new account, or one the
    upgrade could not stamp, starts from what is there now instead of from the whole history.
    """
    if not stored or not entries:
        return []
    if stored.partition(":")[0] == stamp(entries).partition(":")[0]:
        return []
    known = set(stored.partition(":")[2].split(","))
    return [e for e in entries if e["key"] not in known]
