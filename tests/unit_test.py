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
import os
import sys

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _root)
# tests/ on the path too, so `unit.partNN` resolves whichever directory this is run from.
sys.path.insert(0, os.path.join(_root, "tests"))

from unit import part01, part02, part03, part04, part05, part06  # noqa: F401,E402
from unit.part01 import results  # noqa: E402


passed = sum(1 for ok, _, _ in results if ok)
for ok, name, detail in results:
    line = ("PASS" if ok else "FAIL") + "  " + name
    if detail and not ok:
        line += "   [%s]" % detail
    print(line)
print("\n%d / %d checks passed" % (passed, len(results)))
sys.exit(0 if results and passed == len(results) else 1)
