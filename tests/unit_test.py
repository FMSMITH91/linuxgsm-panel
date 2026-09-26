#!/usr/bin/env python3
"""Fast unit tests for the pure-logic helpers — no network, no SSH, no live DB.

This file is the RUNNER. The checks live in tests/unit/part01..part06, imported here in order;
each part is ordinary module-level code that records results as it is imported, exactly as it did
when this was one 6,966-line file. No check and no ordering changed: the parts were cut at
top-level statement boundaries, and the chunks were proved to reconstruct the original
byte-for-byte before anything moved.

WHY THE PARTS IMPORT FROM EACH OTHER. The suite is a narrative — earlier sections build fixtures
later ones use (`check` and `results` themselves, the scanned module lists, the privileged helper).
Each part imports what it needs from the parts before it, nothing imports backwards, so the import
order below IS the execution order, and it is the order the single file had.

WHY THE TALLY IS HERE AND NOT IN A PART. `passed` must be counted after every part has run. Left
in the last part it would have counted only the checks recorded up to that point — a smaller total,
still exiting 0. A suite quietly reporting fewer checks than it has is the exact failure this suite
exists to catch, so it is not allowed to be the shape of the suite itself.

    python tests/unit_test.py      # exits 0 if all pass, 1 otherwise
"""
import functools
import glob
import os
import sys

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _root)
# tests/ on the path too, so `unit.partNN` resolves whichever directory this is run from.
sys.path.insert(0, os.path.join(_root, "tests"))

# ── nothing in this suite may read or write the machine's own config.json (or its keys) ─────────
# DATA_DIR is a fixed path inside the checkout, so a unit check that reached panel.core.config
# without redirecting it first read — or wrote — the data/ of whatever panel runs from this
# checkout. The gate that was meant to stop that read each part's TEXT: it counted only direct
# load_config()/save_config() calls and exempted a whole file that mentioned `CONFIG_FILE =`
# anywhere, so part01 rewrote data/config.json seven times BEFORE its redirect and was exempt
# because of it, and 26 other lines read it through panel helpers (_ssh_connect_timeout,
# create_backup, the PrefixMiddleware...) with no direct call at all. Green, the whole time, on a
# suite whose answers depended on the machine it ran on.
#
# So both halves are done at RUNTIME, here, before any part or panel module is imported:
#   1. the three paths are pointed at a throwaway dir for the whole run — every indirect read now
#      sees a fresh install's absent config, the same on a dev box as in CI; and
#   2. every entry point is wrapped (a module that does `from panel.core.config import
#      load_config` then holds the wrapper too), and a call made while a path resolves to the
#      checkout's own file — a check that pointed it back, or a runner that lost step 1 — is
#      recorded with the test line that led to it, and fails the run below.
import shutil  # noqa: E402
import tempfile  # noqa: E402

import unit as _unit_pkg  # noqa: E402
from panel.core import config as _cfg_live  # noqa: E402

_WATCHED = {"CONFIG_FILE": ("load_config", "save_config", "update_config", "config_unreadable"),
            "SECRET_FILE": ("get_secret_key",),
            "CRED_KEY_FILE": ("_cred_fernet",)}
# The checkout's own paths, for the one part01 check that asserts where they resolve.
_unit_pkg.LIVE_PATHS = {_n: getattr(_cfg_live, _n) for _n in _WATCHED}
_LIVE_REAL = {_n: os.path.realpath(str(_p)) for _n, _p in _unit_pkg.LIVE_PATHS.items()}
_RUN_DATA = tempfile.mkdtemp(prefix="lgsm-unit-data-")
for _n, _p in _unit_pkg.LIVE_PATHS.items():
    setattr(_cfg_live, _n, type(_p)(_RUN_DATA) / _p.name)
_TESTS_DIR = os.path.join(_root, "tests") + os.sep
_config_touches = []


def _watch(attr, fn):
    @functools.wraps(fn)
    def _watched(*a, **k):
        if os.path.realpath(str(getattr(_cfg_live, attr))) == _LIVE_REAL[attr]:
            f = sys._getframe(1)
            while f is not None and not f.f_code.co_filename.startswith(_TESTS_DIR):
                f = f.f_back
            _config_touches.append("%s from %s" % (
                fn.__name__, "%s:%d" % (os.path.relpath(f.f_code.co_filename, _root), f.f_lineno)
                if f is not None else "outside tests/"))
        return fn(*a, **k)
    return _watched


for _attr, _fns in _WATCHED.items():
    for _fn in _fns:
        setattr(_cfg_live, _fn, _watch(_attr, getattr(_cfg_live, _fn)))

from unit import part01, part02, part03, part04, part05, part06, part07  # noqa: F401,E402
from unit.part01 import check, results  # noqa: E402

check("suites: no unit check reads or writes the machine's own config.json or keys",
      not _config_touches,
      "%d call(s): %s" % (len(_config_touches), "; ".join(sorted(set(_config_touches)))))

# Every part file ran. Checked HERE, after the imports, because a gate inside a part cannot see
# that part being dropped: the old one lived in part06 and matched part names as substrings of this
# file's text (the docstring says "part01..part06"), so removing `part06` from the import line took
# its ~5,000 checks — and the gate — with it, and the tally still exited 0.
_parts_on_disk = sorted(os.path.basename(p)[:-3]
                        for p in glob.glob(os.path.join(_root, "tests", "unit", "part*.py")))
check("unit suite: every tests/unit/part*.py was imported and ran",
      bool(_parts_on_disk) and all("unit." + p in sys.modules for p in _parts_on_disk),
      "never ran: %s" % [p for p in _parts_on_disk if "unit." + p not in sys.modules])


# ok is True (pass), False (fail) or None (skipped — the check did not run; see part01.skip).
passed = sum(1 for ok, _, _ in results if ok is True)
failed = sum(1 for ok, _, _ in results if ok is False)
skipped = [(name, detail) for ok, name, detail in results if ok is None]
for ok, name, detail in results:
    line = ("PASS" if ok is True else "FAIL" if ok is False else "SKIP") + "  " + name
    if detail and ok is not True:
        line += "   [%s]" % (detail,)   # (detail,) not detail: a multi-element TUPLE detail made
        #     THIS line raise ('not all arguments converted'), so a
        #     FAILING check printed a traceback instead of its name
        #     and killed the tally and cleanup. Lists and ints are fine
        #     here; the concat-style printer elsewhere breaks on those.
    print(line)
print("\n%d / %d checks passed" % (passed, len(results) - len(skipped)))
# Loud, and after the tally, because a skip is a hole in the run rather than a result in it. It
# does not fail the suite (the environment is not the code's fault) but it must never be mistaken
# for a pass — the whole point of counting it apart.
if skipped:
    print("\n%d CHECK(S) DID NOT RUN:" % len(skipped))
    for name, detail in skipped:
        print("  SKIP  %s   [%s]" % (name, detail))
shutil.rmtree(_RUN_DATA, ignore_errors=True)
sys.exit(0 if results and failed == 0 else 1)
