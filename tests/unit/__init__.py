"""Sections of the unit suite. See tests/unit_test.py for why these are separate files.

REPO_ROOT lives here because several parts derive paths from __file__, and every one of them
assumed this code sat at tests/<file>.py. The split moved it to tests/unit/<file>.py, so each
`parent.parent` quietly resolved to tests/ and those gates began reading files that do not exist
(`tests/app.py`). Anchoring on a file only the root has removes the assumption rather than moving
it one level along, where the next reorganisation would break it again.
"""
import os

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(REPO_ROOT, "app.py")):
    _parent = os.path.dirname(REPO_ROOT)
    if _parent == REPO_ROOT:
        raise RuntimeError("could not find the repo root (no app.py above %s)" % __file__)
    REPO_ROOT = _parent
