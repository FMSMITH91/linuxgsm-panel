"""Part 15 of the unit suite: the panel's version is the date of the commit it runs.

The rule, in panel/ops/system_ops.py (version_for_commit, panel_version) and again in install.sh
(panel_version): the commit's committer time, as a UTC date written YYYY.M.D with no leading zeros.
Without a .git the VERSION file answers, which git's export-subst fills with the commit's epoch
when it builds an archive.

Everything is run against REAL git repositories made here, with committer times set to known
instants. A stub cannot tell a committer date from an author date, or UTC from local time. The
local timezone is moved far east and far west of UTC while the checks run, and a control check
proves each move took effect: a timezone that silently did not apply would pass the very bug these
checks are for.
"""
import os
import shutil
import subprocess as _sp15
import tarfile as _tar15
import tempfile
import time as _time15

from unit.part01 import SO, check
from unit.part05 import _root
from unit.part06 import _inst_shfn

# Known instants, and the committer offsets they were "made" in (the offset must not matter).
_CV_LATE = 1790467170     # 2026-09-26 23:59:30 UTC: the 27th anywhere east of UTC+0:00:30
_CV_FIRST = 1798761605    # 2027-01-01 00:00:05 UTC: still 2026 anywhere west of UTC
_CV_OLD_AUTHOR = 1000000000   # 2001-09-09: LATE's AUTHOR date, so reading %at instead shows 2001
# POSIX TZ strings need no tzdata, so they apply in a bare CI container too. The sign is POSIX's:
# XST-14 is fourteen hours EAST of UTC.
_CV_EAST, _CV_WEST = "XST-14", "YST+12"

_CV_SB = tempfile.mkdtemp(prefix="calver-")
_CV_ENV_KEYS = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_CEILING_DIRECTORIES", "TZ")
_CV_ENV_SAVED = {k: os.environ.get(k) for k in _CV_ENV_KEYS}
_CV_PANEL_DIR = SO.PANEL_DIR
_CV_GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
# install.sh's own functions, whole, run as the installer runs them. _gitc is the real one: it is
# how install.sh asks git as the checkout's owner.
_CV_SH = "set -euo pipefail\n" + "".join(
    _inst_shfn(n) for n in ("_gitc", "_epoch_version", "_version_file", "panel_version"))


def _cv_git(repo, *args, **env):
    """Run git in `repo` with no user or system config; returns stdout, stripped."""
    r = _sp15.run(["git", "-C", repo, *args], capture_output=True, text=True, check=False,
                  env=dict(os.environ, **_CV_GIT_ENV, **env))
    return r.stdout.strip()


def _cv_commit(repo, msg, committed, author=None, files=None):
    """Commit `files` (or an empty commit) with a fixed committer time; returns the full sha."""
    for name, body in (files or {}).items():
        with open(os.path.join(repo, name), "w", encoding="utf-8") as fh:
            fh.write(body)
        _cv_git(repo, "add", name)
    _cv_git(repo, "commit", "-q", "--allow-empty", "-m", msg,
            GIT_COMMITTER_DATE=committed, GIT_AUTHOR_DATE=author or committed)
    return _cv_git(repo, "rev-parse", "HEAD")


def _cv_set_tz(tz):
    """Point this process's local time (and every git and bash it starts) at `tz`."""
    os.environ["TZ"] = tz
    _time15.tzset()


def _cv_ymd(tm):
    """A struct_time's date, written the way the panel writes a version."""
    return "%d.%d.%d" % tuple(tm[:3])


def _cv_dir(name, version=None):
    """A copy of the panel with NO .git: just a VERSION file holding `version` (None: no file)."""
    path = os.path.join(_CV_SB, name)
    os.makedirs(path)
    if version is not None:
        with open(os.path.join(path, "VERSION"), "w", encoding="utf-8") as fh:
            fh.write(version)
    return path


def _cv_version_at(path):
    """The panel's version (system_ops.panel_version) for a panel installed at `path`."""
    SO.PANEL_DIR = path
    return SO.panel_version()


def _cv_sh(path, call="panel_version"):
    """What install.sh's `call` prints for a panel at `path`: (stdout, returncode)."""
    r = _sp15.run(["bash", "-c", _CV_SH + call + "\n"], capture_output=True, text=True,
                  check=False, timeout=60, env=dict(os.environ, PANEL_DIR=path))
    return r.stdout.strip(), r.returncode


# The rules for a copy with no .git, which both implementations must apply alike:
# what VERSION holds (None: no file) -> what the version reads as.
_CV_RULES = {
    "an epoch (what an archive holds) is its UTC date": ("%d\n" % _CV_LATE, "2026.9.26"),
    "the placeholder git did not fill in is unknown": ("$Format:%ct$\n", "unknown"),
    "an old hand-kept version is shown as it is": ("0.10.0-alpha\n", "0.10.0-alpha"),
    "an empty file is unknown": ("\n", "unknown"),
    "an epoch past 12 digits is unknown, not a date": ("9" * 13 + "\n", "unknown"),
    "no VERSION file at all is unknown": (None, "unknown"),
}


try:
    os.environ["GIT_CONFIG_GLOBAL"], os.environ["GIT_CONFIG_NOSYSTEM"] = os.devnull, "1"
    # git never looks above a fixture for a repository: a .git it cannot read must fall back to
    # VERSION, not find whatever repository the temp dir happens to sit inside.
    os.environ["GIT_CEILING_DIRECTORIES"] = _CV_SB
    _cv_repo = os.path.join(_CV_SB, "repo")
    _sp15.run(["git", "init", "-q", "-b", "main", _cv_repo], capture_output=True, check=False)
    _cv_late = _cv_commit(_cv_repo, "late", "@%d +1400" % _CV_LATE,
                          author="@%d +0000" % _CV_OLD_AUTHOR,
                          files={"VERSION": "$Format:%ct$\n", ".gitattributes": "VERSION export-subst\n"})
    _cv_first = _cv_commit(_cv_repo, "first of the year", "@%d -1200" % _CV_FIRST)
    # A second checkout whose HEAD is the late commit, for the installer (which only asks HEAD).
    _cv_repo_late = os.path.join(_CV_SB, "repo-late")
    _sp15.run(["git", "clone", "-q", "--no-checkout", _cv_repo, _cv_repo_late],
              capture_output=True, check=False)
    _cv_git(_cv_repo_late, "checkout", "-q", "--detach", _cv_late)
    SO.PANEL_DIR = _cv_repo

    # ── version_for_commit: the committer date, in UTC, whatever the local zone ─────────────────
    _cv_set_tz(_CV_EAST)
    _cv_east_moved = _cv_ymd(_time15.localtime(_CV_LATE)) == "2026.9.27"
    check("calver: (control) the east timezone really moved 23:59 UTC on the 26th to the 27th",
          _cv_east_moved, "local %s — the checks below would prove nothing about UTC"
          % _cv_ymd(_time15.localtime(_CV_LATE)))
    _cv_v = SO.version_for_commit(_cv_late)
    check("calver: a commit at 23:59 UTC is dated in UTC, not the local day (east of UTC)",
          _cv_v == "2026.9.26", repr(_cv_v))
    check("calver: ...by its COMMITTER date, not the 2001 author date",
          not _cv_v.startswith("2001."), repr(_cv_v))

    _cv_set_tz(_CV_WEST)
    _cv_west_moved = _cv_ymd(_time15.localtime(_CV_FIRST)) == "2026.12.31"
    check("calver: (control) the west timezone really moved 00:00 UTC on 1 January back a day",
          _cv_west_moved, "local %s" % _cv_ymd(_time15.localtime(_CV_FIRST)))
    _cv_v = SO.version_for_commit(_cv_first)
    check("calver: the 1st of a month is YYYY.M.D with no leading zeros, in UTC (west of UTC)",
          _cv_v == "2027.1.1", repr(_cv_v))
    check("calver: with no commit named it is HEAD's",
          SO.version_for_commit() == "2027.1.1", repr(SO.version_for_commit()))
    check("calver: a commit git does not know, or one that looks like an option, has no version",
          SO.version_for_commit("0" * 40) == "" and SO.version_for_commit("--all") == ""
          and SO.version_for_commit("") == "",
          repr((SO.version_for_commit("0" * 40), SO.version_for_commit("--all"))))
    # VERSION is a FILE in the checkout and no revision: git would otherwise answer with the last
    # commit that touched it.
    check("calver: a file's name is not a revision, so it has no version",
          SO.version_for_commit("VERSION") == "", repr(SO.version_for_commit("VERSION")))
    _cv_bad = {t: SO._version_from_epoch(t) for t in ("", "12a", "-5", "1.5", "１２",
                                                        "9" * 13, " %d " % _CV_FIRST)}
    check("calver: only a plain run of ASCII digits is an epoch (surrounding space is trimmed)",
          all(v == "" for t, v in _cv_bad.items() if t != " %d " % _CV_FIRST)
          and _cv_bad[" %d " % _CV_FIRST] == "2027.1.1", repr(_cv_bad))

    # ── panel_version: git first, then VERSION ───────────────────────────────────────────────────
    _cv_set_tz(_CV_EAST)
    with open(os.path.join(_cv_repo, "VERSION"), "w", encoding="utf-8") as _cv_fh:
        _cv_fh.write("%d\n" % _CV_OLD_AUTHOR)     # a checkout's VERSION is not what it reads
    check("calver: a git checkout's version is HEAD's date, whatever its VERSION file says",
          _cv_version_at(_cv_repo) == "2027.1.1", repr(_cv_version_at(_cv_repo)))
    _cv_nogit = _cv_dir("broken-git", "%d\n" % _CV_LATE)
    os.makedirs(os.path.join(_cv_nogit, ".git"))
    check("calver: a .git that git cannot read falls back to VERSION rather than 'unknown'",
          _cv_version_at(_cv_nogit) == "2026.9.26", repr(_cv_version_at(_cv_nogit)))
    _cv_nogit_dirs = {}
    for _cv_i, (_cv_what, (_cv_body, _cv_want)) in enumerate(sorted(_CV_RULES.items())):
        _cv_nogit_dirs[_cv_what] = _cv_dir("nogit-%d" % _cv_i, _cv_body)
        _cv_got = _cv_version_at(_cv_nogit_dirs[_cv_what])
        check("calver: without a .git, %s" % _cv_what, _cv_got == _cv_want,
              "VERSION %r read as %r, want %r" % (_cv_body, _cv_got, _cv_want))

    # ── the repository's own VERSION + .gitattributes, through a real `git archive` ─────────────
    # What a GitHub "Download ZIP" is built with. Committed from THIS checkout's two files, so a
    # placeholder or attribute that stopped matching fails here.
    _cv_arc_repo = os.path.join(_CV_SB, "arc-repo")
    _sp15.run(["git", "init", "-q", "-b", "main", _cv_arc_repo], capture_output=True, check=False)
    for _cv_name in ("VERSION", ".gitattributes"):
        shutil.copyfile(os.path.join(_root, _cv_name), os.path.join(_cv_arc_repo, _cv_name))
        _cv_git(_cv_arc_repo, "add", _cv_name)
    _cv_arc_sha = _cv_commit(_cv_arc_repo, "archived", "@%d +0000" % _CV_LATE)
    _cv_tar = os.path.join(_CV_SB, "arc.tar")
    _cv_git(_cv_arc_repo, "archive", "-o", _cv_tar, _cv_arc_sha, "VERSION")
    try:
        with _tar15.open(_cv_tar) as _cv_tf:
            _cv_arc_text = _cv_tf.extractfile("VERSION").read().decode("utf-8")
    except (OSError, KeyError, AttributeError, _tar15.TarError) as _cv_e:
        _cv_arc_text = "(no archive: %r)" % (_cv_e,)
    check("calver: git archive fills the repository's VERSION with the commit's epoch",
          _cv_arc_text.strip() == str(_CV_LATE),
          "archived VERSION is %r — check VERSION's placeholder and `VERSION export-subst` in "
          ".gitattributes" % _cv_arc_text)
    _cv_out = _cv_dir("arc-out", _cv_arc_text)
    check("calver: ...which a copy with no .git reads as that commit's date",
          _cv_version_at(_cv_out) == "2026.9.26", repr(_cv_version_at(_cv_out)))

    # ── install.sh's panel_version: the same rule, in bash ───────────────────────────────────────
    _cv_date_east = _sp15.run(["bash", "-c", "date -d @%d +%%d" % _CV_LATE], capture_output=True,
                              text=True, check=False).stdout.strip()
    check("calver: (control) bash's own date sees the east timezone too",
          _cv_date_east == "27", "date printed %r for 23:59 UTC on the 26th" % _cv_date_east)
    _cv_short_late = _cv_git(_cv_repo_late, "rev-parse", "--short", "HEAD")
    _cv_sh_late = _cv_sh(_cv_repo_late)
    check("install.sh: a checkout's version is its commit's UTC COMMITTER date, beside the commit",
          _cv_sh_late == ("2026.9.26 · %s" % _cv_short_late, 0), repr(_cv_sh_late))
    _cv_set_tz(_CV_WEST)
    _cv_short_first = _cv_git(_cv_repo, "rev-parse", "--short", "HEAD")
    _cv_sh_first = _cv_sh(_cv_repo)
    check("install.sh: ...with no leading zeros, and in UTC west of it too (1 January)",
          _cv_sh_first == ("2027.1.1 · %s" % _cv_short_first, 0), repr(_cv_sh_first))
    _cv_sh_ep = {e: _cv_sh(_CV_SB, "_epoch_version %s" % e)[0]
                 for e in ("1788264000", "08", "12a", "9" * 13)}
    check("install.sh: _epoch_version writes 1 September as 2026.9.1 (09 is not octal), and "
          "refuses what the panel refuses",
          _cv_sh_ep == {"1788264000": "2026.9.1", "08": "1970.1.1", "12a": "", "9" * 13: ""},
          repr(_cv_sh_ep))
    check("install.sh: a .git that git cannot read falls back to VERSION, as the panel does",
          _cv_sh(_cv_nogit) == ("2026.9.26", 0), repr(_cv_sh(_cv_nogit)))
    for _cv_what, (_cv_body, _cv_want) in sorted(_CV_RULES.items()):
        _cv_got = _cv_sh(_cv_nogit_dirs[_cv_what])
        check("install.sh: without a .git, %s" % _cv_what, _cv_got == (_cv_want, 0),
              "VERSION %r read as %r, want %r" % (_cv_body, _cv_got, _cv_want))
    check("install.sh: ...and a GitHub ZIP's VERSION reads as its commit's date",
          _cv_sh(_cv_out) == ("2026.9.26", 0), repr(_cv_sh(_cv_out)))
finally:
    SO.PANEL_DIR = _CV_PANEL_DIR
    for _cv_k, _cv_val in _CV_ENV_SAVED.items():
        if _cv_val is None:
            os.environ.pop(_cv_k, None)
        else:
            os.environ[_cv_k] = _cv_val
    _time15.tzset()
    shutil.rmtree(_CV_SB, ignore_errors=True)
