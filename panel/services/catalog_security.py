"""The signed catalog's optional `security` section: which of its pins are security updates.

A catalog that moves a pin for a security fix says so here, and the panel then marks that update as a
security update on the Updates page and installs it in the next nightly window even where automatic
updates are off for that item (services/updates_auto.py):

    "security": {"addons": ["b3"], "sites": ["php", "wordpress"], "note": "OpenSSL fix in the base image"}

`addons` names add-ons (the catalog's add-on ids), `sites` names parts of the `sites` section whose images
websites run (static, php, wordpress, runtimes), `note` is one plain line shown beside those updates. Every
key is optional; anything else is refused (OWASP Input Validation Cheat Sheet: allow-list, fullmatch), and a
refused section marks nothing.

This module needs nothing but the standard library at import, so tools/addon_catalog.py (which signs
catalogs) loads it by path and refuses a catalog the panels would refuse.
"""
import re

KEYS = ("addons", "sites", "note")
# The parts of the `sites` section a website's image comes from (services/websites.image_for).
SITE_PARTS = ("static", "php", "wordpress", "runtimes")
_ADDON_RE = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_NOTE_MAX = 200
_LIST_MAX = 32


def _list_problems(name, value, ok):
    """Why the list `value` of section key `name` is refused ([] when it passes): `ok(item)` checks one item."""
    if not isinstance(value, list) or len(value) > _LIST_MAX:
        return ["security.%s must be a list of at most %d names" % (name, _LIST_MAX)]
    bad = [v for v in value if not (isinstance(v, str) and ok(v))]
    return ["security.%s holds names it may not: %s" % (name, ", ".join(repr(b) for b in bad[:5]))] if bad else []


def _note_problems(note):
    if isinstance(note, str) and len(note) <= _NOTE_MAX and note.isprintable():
        return []
    return ["security.note must be one line of plain text of at most %d characters" % _NOTE_MAX]


def security_problems(sec):
    """Why a catalog's `security` section is refused; [] when it passes."""
    if not isinstance(sec, dict) or not set(sec) <= set(KEYS):
        return ["security must be an object holding only %s" % ", ".join(KEYS)]
    out = _list_problems("addons", sec.get("addons", []), lambda v: bool(_ADDON_RE.match(v)))
    out += _list_problems("sites", sec.get("sites", []), lambda v: v in SITE_PARTS)
    return out + (_note_problems(sec["note"]) if "note" in sec else [])


def parsed(sec):
    """{"addons": frozenset, "sites": frozenset, "note": str} from a section that passed; all empty otherwise."""
    if sec is None or security_problems(sec):
        return {"addons": frozenset(), "sites": frozenset(), "note": ""}
    return {"addons": frozenset(sec.get("addons", ())), "sites": frozenset(sec.get("sites", ())),
            "note": sec.get("note", "")}
