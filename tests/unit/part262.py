"""Part 262 of the unit suite: the docs that list every outside service name each one the panel has.

docs/configuration.md says what the Settings card's Outside services switches cover, and the threat
model's TB5 "I" row lists what an outside service learns. Both are hand-written lists, and both left
out the DB-IP switch when it was added. Each switch in panel/core/outside_services.py SERVICES is
mapped here to the words each document uses for it, so a new switch fails until both name it.

HOW IT RUNS. Reads the two documents and the SERVICES table. Nothing reaches a host or data/.
"""
import os

from unit.part01 import check, eq
from unit.part05 import _root
from panel.core import outside_services as _os262

# switch key -> (its words in configuration.md's sentence, its words in THREAT-MODEL.md's TB5 "I" row)
_NAMED262 = {
    _os262.UPDATE_CHECK: ("the update check", "update checks"),
    _os262.BREACH_CHECK: ("Have I Been Pwned", "the breached-password check"),
    _os262.LGSM_GITHUB: ("LinuxGSM's game list and release notes", "LinuxGSM's files"),
    _os262.GAME_ICONS: ("game icons", "game icons"),
    _os262.STEAM_WORKSHOP: ("Steam Workshop titles", "Workshop titles"),
    _os262.MODRINTH: ("Modrinth", "Modrinth"),
    _os262.PUBLIC_IP: ("the public address lookup", "the public address"),
    _os262.DBIP: ("DB-IP's country database for B3", "DB-IP's country database for B3"),
}


def _read262(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _list_in262(text, start):
    """The parenthesised list that follows `start` in `text` ("" when `start` is not there)."""
    at = text.find(start)
    if at < 0:
        return ""
    open_at = text.find("(", at)
    return text[open_at:text.find(")", open_at) + 1] if open_at >= 0 else ""


def _missing262(cfg_list, tm_list):
    """{switch key: [the document(s) whose list does not name it]}."""
    out = {}
    for key, (cfg_words, tm_words) in _NAMED262.items():
        miss = [doc for doc, words, lst in (("configuration.md", cfg_words, cfg_list),
                                            ("THREAT-MODEL.md", tm_words, tm_list)) if words not in lst]
        if miss:
            out[key] = miss
    return out


_cfg_list262 = _list_in262(_read262("docs", "configuration.md"), "one switch for each service the panel calls by itself")
_tm_list262 = _list_in262(_read262("docs", "THREAT-MODEL.md"), "| I | An outside service learns")
eq("docs: every Outside services switch has its words here (a switch added to SERVICES fails until both "
   "documents name it)", sorted(_NAMED262), sorted(_os262.KEYS))
check("docs: configuration.md's Outside services sentence and the threat model's TB5 'I' row name every switch, "
      "the DB-IP country database among them",
      bool(_cfg_list262) and bool(_tm_list262) and not _missing262(_cfg_list262, _tm_list262),
      repr((_missing262(_cfg_list262, _tm_list262), _cfg_list262[:80], _tm_list262[:80])))
eq("docs: ...a list that leaves a switch out is named, by switch and by document (control)",
   _missing262(_cfg_list262.replace("Modrinth", "x"), _tm_list262), {_os262.MODRINTH: ["configuration.md"]})
