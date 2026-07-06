"""Lightweight UI translations shared by Jinja templates and client-side JS.

Strings are keyed by their English source text (gettext-style), so anything not yet translated
falls back to English automatically — pages never break, they just show English until a phrase is
added to a language file. Per-language catalogs live in translations/<lang>.json as a flat
{"English": "Translated"} map. The same catalog is handed to the browser (window.I18N) so the
panel's JavaScript can translate the strings it renders too.
"""
import json
import threading
from pathlib import Path

_DIR = Path(__file__).resolve().parent / "translations"

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
