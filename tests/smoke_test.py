"""Smoke test: boots the app on a THROWAWAY database and asserts no page or route returns a 5xx.

It exercises the main pages plus the group create/edit routes and much else. This catches the class of bug a syntax/compile check can't see: a route that
500s at runtime (wrong model assigned to a relationship, unguarded int() on
form input, a template that errors, etc.). It needs no configured install and
no network, so it runs in CI on every push.

SAFETY: it refuses to run if a real database already exists, and it removes any
data files it created, so it never touches a live install's data.

    python tests/smoke_test.py     # exits 0 if all checks pass, 1 otherwise

This file is the RUNNER. The checks live in tests/smoke/part*.py, imported in _PARTS order; each
part is ordinary module-level code that records results as it is imported, exactly as it did when
this was one 16,000-line file. It was split because CodeQL could not read it: its Python
extractor took 24 minutes on that one 1 MB module, so .github/codeql/codeql-config.yml left it
out of the analysis altogether.

HOW IT WAS CUT, AND WHY NOTHING CHANGED. part01 is the old preamble (the refusal to run over a real
database, the app, `check`, `results`, `client_as`, `cleanup`), still run outside the try. The
old try's body was cut at top-level statements, at section headers, into part02 onwards, with
only its 4-space indent removed; each part's statements parse to the same syntax tree as the lines
they came from (strings untouched), and the same checks print in the same order. Each part
imports from the parts before it the names it reads before binding them itself; nothing imports
backwards, so this import order IS the execution order, and it is the order the single file had.
The few functions that read a global a LATER part rebinds are all called before that rebinding,
so an imported name holds the value the single file would have read. A check that found the repo
from __file__ reads part01's _SUITE_FILE (this file's path), so its paths are unchanged.

WHY THE TALLY IS HERE AND NOT IN A PART. `passed` must be counted after every part has run, and a
crash in any part must still be a recorded FAILURE followed by the tally and the cleanup, as it
was when the whole body sat inside this try. The unit suite checks that every
tests/smoke/part*.py is named in _PARTS (a part left off the list would drop its checks while the
tally still read N / N).
"""
import importlib
import os
import sys

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _root)
# tests/ on the path too, so `smoke.partNN` resolves however this is run (tools/nosudo_runner.py
# runs it with runpy, which does not put the script's own directory on the path).
sys.path.insert(0, os.path.join(_root, "tests"))

# Named, never globbed: a part's checks run only if it is on this list, which is what the unit
# suite's gate compares against the files on disk.
_PARTS = ("part02", "part03", "part04", "part05", "part06")

# part01 runs outside the try, as the preamble always did; it exits 0 with "SKIP:" over a real DB.
from smoke.part01 import cleanup, results  # noqa: E402

try:
    for _part in _PARTS:
        importlib.import_module("smoke." + _part)
except Exception:
    # A crash part-way through otherwise just prints fewer checks and still reads as green-ish.
    # That has hidden three separate mistakes while writing these; a crash is a FAILURE.
    import traceback as _tb
    _tb.print_exc()
    results.append((False, "suite crashed before finishing — see the traceback above", ""))
finally:
    passed = sum(1 for ok, _, _ in results if ok)
    for ok, name, detail in results:
        line = ("PASS" if ok else "FAIL") + "  " + name
        if detail and not ok:
            line += "   [%s]" % (detail,)   # (detail,) not detail: a multi-element TUPLE detail made
            #     THIS line raise ('not all arguments converted'), so a
            #     FAILING check printed a traceback instead of its name
            #     and killed the tally and cleanup. Lists and ints are fine
            #     here; the concat-style printer elsewhere breaks on those.
        print(line)
    print("\n%d / %d checks passed" % (passed, len(results)))
    cleanup()

sys.exit(0 if results and passed == len(results) else 1)
