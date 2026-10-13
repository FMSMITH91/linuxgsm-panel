"""Lightweight UI translations shared by Jinja templates and client-side JS.

Strings are keyed by their English source text (gettext-style), so anything not yet translated
falls back to English automatically — pages never break, they just show English until a phrase is
added to a language file. Each non-English catalog is a FOLDER of section files
(translations/<lang>/*.json), each a flat {"English": "Translated"} map, merged into one catalog.
A single flat translations/<lang>.json is legacy and merged LAST if present — so following the old
layout would silently override every section file. The merged catalog is also handed to the browser
(window.I18N) so the panel's JavaScript can translate the strings it renders too.

ONE KEY, ONE FILE. The merge below is last-write-wins in sorted FILENAME order, which is not a
decision anybody made — it is alphabetical accident. Three dashboard tile labels had drifted into
two files each, two of them with DIFFERENT translations, so which Spanish string a user saw was
decided by "servers.json sorts after common.json". A key living in exactly one section file is what
makes the merge order stop mattering, and tests/unit_test.py enforces it.
"""
import json
import re
import threading

from flask import has_request_context, session
from flask_login import current_user

from panel import REPO_ROOT as _ROOT   # translations/ is at the checkout root, not beside this file
_DIR = _ROOT / "translations"

# Supported languages: code -> native name (shown in the switcher).
LANGUAGES = {"en": "English", "es": "Español", "fr": "Français"}
DEFAULT_LANG = "en"
# Each non-English language is a FOLDER of section files (translations/<lang>/*.json) that are all
# merged into one catalog — so translations can be organised per page/section and grown file by
# file. The code -> folder map is fixed (constant literals), so the directory we list below is
# never built from request input. A legacy single translations/<lang>.json is still merged if it
# happens to exist.
_LANG_DIRS = {code: code for code in LANGUAGES if code != DEFAULT_LANG}
_LEGACY_FILES = {code: code + ".json" for code in LANGUAGES if code != DEFAULT_LANG}

_cache = {}
_lock = threading.Lock()


def normalize_lang(lang):
    """Coerce a raw language value (may be None, 'es-ES', 'FR', …) to a supported code."""
    lang = (lang or "").split("-")[0].strip().lower()
    return lang if lang in LANGUAGES else DEFAULT_LANG


def catalog(lang):
    """The {english: translated} map for a language ({} for English or an unknown/missing file)."""
    lang = normalize_lang(lang)
    dname = _LANG_DIRS.get(lang)   # constant literal (e.g. "es") or None for en/unknown
    if not dname:
        return {}
    with _lock:
        if lang not in _cache:
            merged = {}

            def _merge(path):
                # OSError: file vanished/unreadable. ValueError: malformed JSON
                # (json.JSONDecodeError subclasses it). Either way the section just
                # contributes nothing — the catalog degrades gracefully.
                try:
                    loaded = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    return
                if isinstance(loaded, dict):
                    for k, v in loaded.items():
                        if isinstance(v, str) and v:
                            merged[k] = v

            # Every section file in translations/<lang>/ (paths come from the directory
            # listing, not from request input), then the legacy single file if present.
            # OSError => no translations dir for this language yet; fall through.
            try:
                section_files = sorted((_DIR / dname).glob("*.json"))
            except OSError:
                section_files = []
            for p in section_files:
                _merge(p)
            legacy = _DIR / _LEGACY_FILES[lang]
            if legacy.is_file():
                _merge(legacy)
            _cache[lang] = merged
        return _cache[lang]


def translate(lang, s):
    """Translate one English string, falling back to the original when there's no translation."""
    if not s:
        return s
    return catalog(lang).get(s, s)


# ── Sentences the server builds for the viewer (flash messages, JSON "message"/"error") ─────────
# A message with a value in it ("Group 'x' created.") was built with an f-string or %, so what
# reached the page was one finished English sentence no catalog key could ever match: the
# browser's auto-translator only swaps EXACT catalog text, and es/fr users read English. The
# sentence is now translated WHOLE, with named slots, and the values go in afterwards — the same
# convention as the browser's window.tf ("{name}"), so a translation may move a value anywhere in
# its sentence. Values are never translated, and they are put in as plain text: escaping stays
# where it always was (Jinja's autoescape for a flash, the page's esc()/textContent for JSON).
# Filled by a regex, not str.format, so a catalog value can never reach an attribute
# ("{name.__class__}") or raise on a stray brace, and a value containing braces is not re-read.
_SLOT = re.compile(r"\{(\w+)\}")


def _said(value):
    """A slot's value as text: a list or tuple is its items joined by ", "."""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def fill(s, **vals):
    """Put each {slot}'s value into s; an unknown slot is left as written."""
    return _SLOT.sub(lambda m: _said(vals[m.group(1)]) if m.group(1) in vals else m.group(0), s)


def request_lang():
    """The viewer's UI language: their saved preference, else the session's choice, else English.

    Outside a request (a background worker) there is no viewer, so English.
    """
    if not has_request_context():
        return DEFAULT_LANG
    lang = None
    try:
        if getattr(current_user, "is_authenticated", False):
            lang = getattr(current_user, "language", None)
    except Exception:
        lang = None
    if not lang:
        try:
            lang = session.get("lang")
        except Exception:
            lang = None
    return normalize_lang(lang)


class Sentence(str):
    """An English sentence that remembers how it was built, for text that is ALSO kept in English.

    A refusal a helper words once is often both recorded (an audit row, a log line — read by admins,
    in English, and compared by tests) and shown to the viewer. As a str it is that English sentence,
    so every recorder keeps working unchanged; tr() reads the template and values it was built from
    and shows the viewer the whole sentence in their language.
    """

    __slots__ = ("template", "vals")

    def __new__(cls, template, **vals):
        obj = super().__new__(cls, fill(template, **vals))
        obj.template = template
        obj.vals = vals
        return obj


class Sentences(str):
    """Whole sentences said one after another: English joined by a space, each translated alone.

    For a service answer that is a sentence plus notes (a firewall rule kept, a Funnel left on).
    The notes were clauses appended to the sentence's English, so nothing matched a key; each part
    here is a Sentence (or a fixed literal) of its own. Empty parts are dropped. `sep` joins them
    (a space by default); any other separator ("; and ") is itself translated.
    """

    __slots__ = ("parts", "sep")

    def __new__(cls, *parts, sep=" "):
        parts = [p for p in parts if p]
        obj = super().__new__(cls, sep.join(str(p) for p in parts))
        obj.parts, obj.sep = parts, sep
        return obj


def tr(s, **vals):
    """One whole sentence in the viewer's language, with its {slot} values put in.

    `s` may be a Sentence (its own template and values are used) and a value may be one too — a
    panel-worded label or clause, translated whole in its turn — or a list of them, each translated
    and then joined. Any other value is put in as written.
    """
    if isinstance(s, Sentences):
        return (tr(s.sep) if s.sep.strip() else s.sep).join(tr(p) for p in s.parts)
    if isinstance(s, Sentence):
        s, vals = s.template, dict(s.vals, **vals)
    lang = request_lang()
    vals = {k: [_tr_value(x) for x in v] if isinstance(v, (list, tuple)) else _tr_value(v)
            for k, v in vals.items()}
    return fill(translate(lang, s), **vals)


def _tr_value(value):
    """One slot value for tr(): a Sentence translated, anything else as it is."""
    return tr(value) if isinstance(value, (Sentence, Sentences)) else value


# ── A Sentence kept in the database, translated when it is shown ─────────────────────────────────
# A worker thread has no viewer, so what it records for later (a failed install's reason on its
# row) was stored as finished English and every es/fr viewer read English. Storing how the sentence
# was built instead — its template and values, as JSON — lets the page translate it for whoever
# looks, while the English column beside it stays what admins, logs and the debug report read.
# A value that is not a Sentence (a host's own words) is kept as written and never translated.
_RECORD_DEPTH = 6        # deeper than any sentence the panel builds; a hand-made record past it is refused
_RECORD_TEXT_MAX = 2000  # a host's raw tail is already cut to 300; anything longer is cut, not refused


def sentence_record(s, _depth=0):
    """`s` (a Sentence, Sentences, list or plain value) as plain JSON-able data for sentence_restored."""
    if _depth > _RECORD_DEPTH:
        return str(s)[:_RECORD_TEXT_MAX]
    if isinstance(s, Sentences):
        return {"parts": [sentence_record(p, _depth + 1) for p in s.parts], "sep": s.sep}
    if isinstance(s, Sentence):
        return {"t": s.template, "v": {k: sentence_record(v, _depth + 1) for k, v in s.vals.items()}}
    if isinstance(s, (list, tuple)):
        return [sentence_record(x, _depth + 1) for x in s]
    if isinstance(s, (int, float)) and not isinstance(s, bool):
        return s
    return str(s)[:_RECORD_TEXT_MAX]


def _restored_all(items, depth):
    """sentence_restored() of each of `items`, or None when any one of them could not be restored."""
    out = [sentence_restored(x, depth) for x in items]
    return None if any(x is None for x in out) else out


def _restored_parts(data, depth):
    """The Sentences a {"parts", "sep"} record holds, or None."""
    if not (isinstance(data["parts"], list) and isinstance(data["sep"], str)):
        return None
    parts = _restored_all(data["parts"], depth)
    return None if parts is None else Sentences(*parts, sep=data["sep"])


def _restored_sentence(data, depth):
    """The Sentence a {"t", "v"} record holds, or None."""
    if not (isinstance(data["t"], str) and isinstance(data["v"], dict)):
        return None
    # A slot name is a keyword to Sentence(), so it must be one — and not one of __new__'s own.
    if not all(isinstance(k, str) and k.isidentifier() and k not in ("cls", "template") for k in data["v"]):
        return None
    vals = dict(zip(data["v"], _restored_all(data["v"].values(), depth) or ()))
    return None if len(vals) != len(data["v"]) else Sentence(data["t"], **vals)


def sentence_restored(data, _depth=0):
    """The Sentence sentence_record() wrote, or None for anything it could not have written.

    Read from a database column, so it is checked rather than trusted: a restored or hand-edited
    panel.db can hold anything, and the caller then shows its English column instead.
    """
    if _depth > _RECORD_DEPTH:
        return None
    if isinstance(data, str) or (isinstance(data, (int, float)) and not isinstance(data, bool)):
        return data
    if isinstance(data, list):
        return _restored_all(data, _depth + 1)
    if isinstance(data, dict) and set(data) == {"parts", "sep"}:
        return _restored_parts(data, _depth + 1)
    if isinstance(data, dict) and set(data) == {"t", "v"}:
        return _restored_sentence(data, _depth + 1)
    return None
