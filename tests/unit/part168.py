"""Required stops: an update does not skip a release the next one depends on.

Release 2 of the root clean-up moved the files the installed updater reads, and only an updater that
had taken release 1 knew where. A panel that skipped release 1 had every update fail and roll back.
panel/install/update-stops lists such releases. install.sh (_apply_update_stop) moves a checkout that
is behind one to it first, and the Update card (system_ops._update_stop) offers that same commit, so
the card and the installer agree. Each check runs the real code against a scratch history.
"""
import os
import re as _re168
import shlex as _shlex168
import subprocess as _sp168  # nosec B404 - git and bash on this part's own fixture repositories
import tempfile as _tf168

from unit.part01 import _root, check, eq
from unit.part06 import _inst, _inst_shfn

_SB168 = _tf168.mkdtemp(prefix="p168-")
_GENV168 = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t",
                GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t",
                GIT_COMMITTER_EMAIL="t@example.invalid")


def _git168(*args):
    # git on this part's own fixture repositories, with no global or system config
    return _sp168.run(["git", *args], capture_output=True, text=True, env=_GENV168,  # nosec B603 B607
                      check=False).stdout.strip()


def _commit168(repo, msg, stops=None):
    """One commit on `repo`'s branch; `stops` (a list of lines) writes panel/install/update-stops."""
    if stops is not None:
        os.makedirs(os.path.join(repo, "panel", "install"), exist_ok=True)
        with open(os.path.join(repo, "panel", "install", "update-stops"), "w", encoding="utf-8") as fh:
            fh.write("# required stops\n" + "".join(s + "\n" for s in stops))
        _git168("-C", repo, "add", "-A")
    _git168("-C", repo, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", msg)
    return _git168("-C", repo, "rev-parse", "HEAD")


# main: A - S1 - B - S2 - C - M - D, where M merges a side branch X that starts at S2: X is reachable
# from D and comes after S2, but was never main's tip.
# D lists S2, S1, X, an id that is not a commit, a short id and a comment, in no particular order.
_UP168 = os.path.join(_SB168, "up")
_git168("init", "-q", "-b", "main", _UP168)
_C168 = {n: _commit168(_UP168, n) for n in ("A", "S1", "B", "S2", "C")}
_git168("-C", _UP168, "checkout", "-q", "-b", "side", _C168["S2"])
_C168["X"] = _commit168(_UP168, "X")
_git168("-C", _UP168, "checkout", "-q", "main")
_git168("-C", _UP168, "-c", "commit.gpgsign=false", "merge", "-q", "--no-ff", "-m", "merge side", "side")
_C168["M"] = _git168("-C", _UP168, "rev-parse", "HEAD")
_C168["D"] = _commit168(_UP168, "D", stops=[_C168["S2"] + "  second stop", _C168["S1"] + "  first stop",
                                            _C168["X"] + "  a side-branch commit", "f" * 40 + "  not a commit",
                                            _C168["B"][:12] + "  too short", "# " + _C168["C"]])
_CO168 = os.path.join(_SB168, "co")
_git168("clone", "-q", _UP168, _CO168)

# ── install.sh: _choose_update_target with the stop applied ────────────────────────────────────
_FN168 = ('warn() { echo "WARN $*" >&2; }\n'
          + "".join(_inst_shfn(n) for n in ("_gitc", "_ref_exists", "_choose_update_target"))
          + "_hold_unless_signed() { :; }\n")   # the signature gate is part142's; stubbed to pass


def _target168(head, pin=""):
    """(UPD_TARGET, UPD_STOP, UPD_FINAL) for a checkout at `head`, with PANEL_UPDATE_REF=`pin`."""
    _git168("-C", _CO168, "reset", "-q", "--hard", head)
    # bash over install.sh's own functions, on this part's fixture clone
    r = _sp168.run(["bash", "-c", "PANEL_DIR=%s\nDEFAULT_BRANCH=main\nPANEL_UPDATE_REF=%s\n%s"
                    '_choose_update_target; echo "T=${UPD_TARGET} S=${UPD_STOP} F=${UPD_FINAL}"'
                    % (_shlex168.quote(_CO168), _shlex168.quote(pin), _FN168)],  # nosec B603 B607
                   capture_output=True, text=True, timeout=60, env=_GENV168, check=False)
    m = _re168.search(r"T=(\S*) S=(\S*) F=(\S*)", r.stdout)
    return m.groups() if m else ("rc=%d %s" % (r.returncode, r.stderr[-300:]), "", "")


_N168 = {v: k for k, v in _C168.items()}


def _named168(t):
    return tuple(_N168.get(x, x) for x in t)


eq("install.sh: a checkout behind two stops goes to the OLDER one first, whatever order the list names "
   "them in, and remembers the release it was headed for", _named168(_target168(_C168["A"])), ("S1", "S1", "D"))
eq("install.sh: ...then to the next stop", _named168(_target168(_C168["S1"])), ("S2", "S2", "D"))
# From S2 the only listed commit ahead is X, which is off the first-parent line.
eq("install.sh: ...and from the last stop to the newest release (a listed commit that is not on main's "
   "first-parent line is not a stop)", _named168(_target168(_C168["S2"])), ("D", "", ""))
eq("install.sh: a checkout past every stop goes straight to the newest release", _named168(_target168(_C168["C"])),
   ("D", "", ""))
eq("install.sh: a pin to the newest release stops at the stop too (the panel pins every update)",
   _named168(_target168(_C168["B"], _C168["D"])), ("S2", "S2", "D"))
eq("install.sh: a pin whose own commit lists no stops goes to the pin (the list is read from the target)",
   _named168(_target168(_C168["A"], _C168["C"])), ("C", "", ""))
check("install.sh: fetch_code says the release was required and which comes next, and the update's "
      "result line asks for one more update",
      '[[ -z "${UPD_STOP:-}" ]] || echo "  ${UPD_STOP:0:10} is a release no update may skip' in _inst
      and 'Update once more to install the newest release (${UPD_FINAL:0:10})' in _inst, "")

# ── the panel: the Update card offers the same commit ──────────────────────────────────────────
from panel.ops import system_ops as _so168  # noqa: E402

_saved168 = (_so168.PANEL_DIR, _so168._remote_ci_state)
_REF168 = "refs/remotes/origin/main"
try:
    _so168.PANEL_DIR = _CO168
    _card168 = {}
    for _h168 in ("A", "S1", "S2", "C", "X"):
        _git168("-C", _CO168, "reset", "-q", "--hard", _C168[_h168])
        _card168[_h168] = _N168.get(_so168._update_stop(_C168["D"], _REF168))
    eq("system_ops._update_stop: the card's stop is the installer's, from every starting point",
       _card168, {"A": "S1", "S1": "S2", "S2": None, "C": None, "X": None})
    _git168("-C", _CO168, "reset", "-q", "--hard", _C168["A"])
    _ci168 = {}
    _so168._remote_ci_state = lambda sha: _ci168.get(sha, "passing")
    _take168 = _so168._take_update_stop(_C168["D"], "passing", _REF168, lambda sha: True)
    eq("system_ops._take_update_stop: a signed stop whose checks passed replaces the target, and the "
       "commits behind are counted to it", (_N168.get(_take168[0]), _take168[1], _take168[2]), ("S1", "passing", 1))
    eq("system_ops._take_update_stop: ...an unsigned stop offers nothing (the installer would hold)",
       _so168._take_update_stop(_C168["D"], "passing", _REF168, lambda sha: sha != _C168["S1"])[0], None)
    _ci168[_C168["S1"]] = "pending"
    eq("system_ops._take_update_stop: ...nor does one whose checks have not passed",
       _so168._take_update_stop(_C168["D"], "passing", _REF168, lambda sha: True)[:2], (None, "pending"))
    _git168("-C", _CO168, "reset", "-q", "--hard", _C168["C"])
    eq("system_ops._take_update_stop: with no stop ahead, the target and its state are kept",
       _so168._take_update_stop(_C168["D"], "passing", _REF168, lambda sha: True), (_C168["D"], "passing", None))
finally:
    _so168.PANEL_DIR, _so168._remote_ci_state = _saved168

# ── the list in this repository, and the README's fix for a panel that predates it ──────────────
with open(os.path.join(_root, "panel", "install", "update-stops"), encoding="utf-8") as _fh168:
    _ids168 = [ln.split()[0] for ln in _fh168 if ln.strip() and not ln.startswith("#")]
check("update-stops: every line is a full commit id followed by why", all(_re168.fullmatch(r"[0-9a-f]{40}", i)
                                                                         for i in _ids168) and _ids168, repr(_ids168))
with open(os.path.join(_root, "docs", "README.md"), encoding="utf-8") as _fh168:
    _readme168 = _fh168.read()
eq("README: the command for a panel stuck before the root clean-up pins release 1, the first required stop",
   sorted(set(_re168.findall(r"PANEL_UPDATE_REF=([0-9a-f]{40})", _readme168))), _ids168[:1])
