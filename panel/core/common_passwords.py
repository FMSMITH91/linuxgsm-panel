"""Refuse a common, breached or easily guessed password, offline.

OWASP Authentication Cheat Sheet, "Implement Proper Password Strength Controls" > "Block common and
previously breached passwords" (read 2026-11-15). The panel makes no network call for this: the
screen is a bundled list of the roots most breach-list entries are built from
(common_passwords.txt, ~350 lines, under 4 KB) plus the shapes those lists are full of — one
character repeated, a run (12345678, abcdefgh), a keyboard walk (qwertyuiop, 1qaz2wsx), a root with
leetspeak and digits or symbols around it (P@ssw0rd2026!), a root said twice (dragondragon) or two
roots run together (sunshinefootball). A long phrase of ordinary words passes.
"""
import os
import re
import threading

_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common_passwords.txt")
_LOCK = threading.Lock()
_LISTS = {}
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
                       "@": "a", "$": "s", "!": "i", "|": "l", "+": "t"})
_KEYBOARD_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm", "abcdefghijklmnopqrstuvwxyz",
                  "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p", "qazwsxedcrfvtgbyhnujmikolp",
                  "1q2w3e4r5t6y7u8i9o0p", "q1w2e3r4t5y6u7i8o9p0")
_EDGE = re.compile(r"\A[\d\W_]+|[\d\W_]+\Z")
_TRAILING = re.compile(r"[\d\W_]+\Z")


def _load():
    """(roots, literals) from common_passwords.txt, read once."""
    with _LOCK:
        if not _LISTS:
            roots, literals, into = set(), set(), None
            with open(_FILE, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip().casefold()
                    if not line or line.startswith("#"):
                        continue
                    if line == "[literal]":
                        into = literals
                        continue
                    (literals if into is literals else roots).add(line)
            _LISTS["roots"], _LISTS["literals"] = roots, literals
    return _LISTS["roots"], _LISTS["literals"]


def _is_walk(s):
    """Whether `s` is a stretch of one keyboard row or run, either way round, or one repeated."""
    if len(s) < 4:
        return False
    for row in _KEYBOARD_ROWS:
        for line in (row, row[::-1]):
            if s in line * (len(s) // len(line) + 2):
                return True
    return False


def _unit(s):
    """The shortest piece `s` is a repeat of (abcabc -> abc), or `s` itself."""
    for n in range(1, len(s) // 2 + 1):
        if len(s) % n == 0 and s[:n] * (len(s) // n) == s:
            return s[:n]
    return s


def _cores(s):
    """The roots a password may hide: its letters with leetspeak read back and the edges set aside."""
    return {c for c in (_EDGE.sub("", s), _EDGE.sub("", s).translate(_LEET),
                        _TRAILING.sub("", s).translate(_LEET), _EDGE.sub("", s.translate(_LEET)))
            if c}


def _two_roots(core, roots):
    """Whether `core` is two listed roots run together."""
    return any(core[:i] in roots and core[i:] in roots for i in range(3, len(core) - 2))


def is_common(password):
    """True when `password` is a common, breached or easily guessed one (see the module note)."""
    roots, literals = _load()
    s = re.sub(r"\s+", "", (password or "").casefold())
    if not s or s in literals or _EDGE.sub("", s) in literals or len(set(s)) <= 2:
        return True
    unit = _unit(s)
    if len(unit) <= 3 or _is_walk(s) or _is_walk(unit):
        return True
    for core in _cores(s) | _cores(unit):
        cunit = _unit(core)
        if core in roots or cunit in roots or core in literals or _is_walk(core) or _two_roots(core, roots):
            return True
    return False
