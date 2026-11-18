"""Part 251 of the unit suite: the installer's git in the checkout never leaves gc running behind it.

A git command that leaves many loose objects starts `git gc --auto`, which forks into the background
by default and keeps deleting loose objects after git has returned. install.sh's next step after the
fetch, _chown_panel_tree, walks the whole checkout (.git/objects included) with find -execdir chown;
on the 9b455f4b deploy (2026-11-18) gc removed objects find had listed, find exited non-zero and the
update rolled back. _gitc runs git with gc.autoDetach=false, so any gc finishes before it returns.
"""
import os
import re as _re251

from unit.part01 import check
from unit.part05 import _root

_INSTALL251 = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
_FN251 = _re251.search(r"(?ms)^_gitc\(\) \{\n.*?^\}\n", _INSTALL251)
_BODY251 = _FN251.group(0) if _FN251 else ""
_GIT_CALLS251 = _re251.findall(r"\bgit (?:-c \S+ )*-C \"\$\{PANEL_DIR\}\"", _BODY251)

check("install.sh _gitc: both of its git calls (as the checkout's owner, and as itself) run with "
      "gc.autoDetach=false and maintenance.autoDetach=false, so a background gc never deletes objects under the chown that follows",
      len(_GIT_CALLS251) == 2 and all("-c gc.autoDetach=false" in c and "-c maintenance.autoDetach=false" in c
                                      for c in _GIT_CALLS251),
      repr(_GIT_CALLS251))

