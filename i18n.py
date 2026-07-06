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

_cache = {}
_lock = threading.Lock()


def normalize_lang(lang):
    """Coerce a raw language value (may be None, 'es-ES', 'FR', …) to a supported code."""
    lang = (lang or "").split("-")[0].strip().lower()
    return lang if lang in LANGUAGES else DEFAULT_LANG


def catalog(lang):
    """The {english: translated} map for a language ({} for English or an unknown/missing file)."""
    lang = normalize_lang(lang)
    if lang == DEFAULT_LANG:
        return {}
    with _lock:
        if lang not in _cache:
            data = {}
            try:
                loaded = json.loads((_DIR / (lang + ".json")).read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = {k: v for k, v in loaded.items() if isinstance(v, str) and v}
            except Exception:
                data = {}
            _cache[lang] = data
        return _cache[lang]


def translate(lang, s):
    """Translate one English string, falling back to the original when there's no translation."""
    if not s:
        return s
    return catalog(lang).get(s, s)
