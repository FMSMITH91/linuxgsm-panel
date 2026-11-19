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
# r31: _gitc builds git's command once, in the `gitv` array, and every run (as itself, as the tree's
# owner through sudo, as root through the no-follow helper) is "${gitv[@]}"; no other `git` word is run.
_GITV251 = _re251.search(r"local -a gitv=\(([^)]*)\)", _BODY251)
_RUNS251 = _re251.findall(r'"\$\{gitv\[@\]\}"', _BODY251)
_BARE251 = [ln for ln in _BODY251.splitlines()
            if _re251.search(r"(^|[\s;(])git\s", ln.split("#")[0]) and "gitv=(" not in ln]

check("install.sh _gitc: every one of its git runs (as itself, as the checkout's owner, and as root) uses the one "
      "command with gc.autoDetach=false and maintenance.autoDetach=false, so a background gc never deletes objects "
      "under the chown that follows",
      bool(_GITV251) and "-c gc.autoDetach=false" in _GITV251.group(1)
      and "-c maintenance.autoDetach=false" in _GITV251.group(1) and len(_RUNS251) == 3 and not _BARE251,
      "gitv=%r runs=%d bare=%r" % (_GITV251 and _GITV251.group(1), len(_RUNS251), _BARE251))
