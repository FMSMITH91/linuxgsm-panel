"""GitHub Releases from tools/sign-release.sh.

* tools/release_notes.py lists only the CHANGELOG entries a release added (by the "What's new" key),
  grouped by category, and says how to check the signature.
* sign-release.sh's release_tag names a release by its commit's UTC date, YYYY.M.D, and .2, .3 for a
  later release the same day; the same commit keeps its tag.
* The whole script, on a local bare repository with a stand-in GitHub CLI: signing main publishes a
  release of that commit with those notes and the signature attached, a second run leaves it alone,
  and SIGN_RELEASE_NO_RELEASE / SIGN_RELEASE_NO_DEPLOY publish none.
"""
import os
import re as _re217
import shlex as _shlex217
import shutil as _shutil217
import tempfile as _tf217

from unit.part01 import check, eq, skip
from unit.part05 import _root
from unit.part142 import _ENV142, _run142

_SB217 = _tf217.mkdtemp(prefix="p217-")
_NOTES217 = os.path.join(_root, "tools", "release_notes.py")
_TOOL217 = os.path.join(_root, "tools", "sign-release.sh")
_HAVE217 = bool(_shutil217.which("ssh-keygen")) and bool(_shutil217.which("git"))

_BEFORE217 = """# Changelog

## [Since 0.10.0-alpha]

### Added

- **Old feature.** Already released.

### Fixed

- **Old fix.** Also released.
"""
_AFTER217 = """# Changelog

## [Since 0.10.0-alpha]

### Added

- **New feature.** Just added
  across two lines.
- **Old feature.** Already released.

### Fixed

- **Old fix.** Also released.

### Security

- **New hardening.** Shipped in this one.
"""


def _write217(name, text):
    path = os.path.join(_SB217, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def _git217(*a, **kw):
    return _run142(["git", *a], env=kw.pop("env", _ENV142), **kw).stdout.strip()


# ── 1. the notes ───────────────────────────────────────────────────────────────────────────────
_b217, _a217 = _write217("before.md", _BEFORE217), _write217("after.md", _AFTER217)
_n217 = _run142(["python3", _NOTES217, _b217, _a217, "a" * 40, "2026.3.5"]).stdout
check("release notes: only the entries the release added, grouped by category, with their text",
      "### Added\n\n- **New feature.** Just added across two lines." in _n217
      and "### Security\n\n- **New hardening.** Shipped in this one." in _n217
      and "Old feature" not in _n217 and "Old fix" not in _n217, _n217[:400])
check("release notes: ...and how to check the attached signature against the release key",
      "linuxgsm-panel-2026.3.5.sig" in _n217 and "commit %s" % ("a" * 40) in _n217
      and "-n linuxgsm-panel-release" in _n217, _n217[-400:])
_same217 = _run142(["python3", _NOTES217, _a217, _a217, "b" * 40, "2026.3.6"]).stdout
_first217 = _run142(["python3", _NOTES217, os.path.join(_SB217, "missing.md"), _a217, "c" * 40, "2026.3.7"]).stdout
eq("release notes: a release that added no entry says so; the first release points at the changelog "
   "instead of listing all of history",
   ("No user-facing change" in _same217, "first release published here" in _first217,
    "New feature" in _first217), (True, True, False))

# ── 2. the tag ─────────────────────────────────────────────────────────────────────────────────
_sign217 = open(_TOOL217, encoding="utf-8").read()
_tagfn217 = _re217.search(r"^release_tag\(\) \{.*?^\}\n", _sign217, _re217.M | _re217.S)


def _tag217(repo, sha, remote):
    """Run sign-release.sh's own release_tag on a fixture repository."""
    script = (_tagfn217.group(0) if _tagfn217 else "") + "cd %s && release_tag %s %s" % (
        _shlex217.quote(repo), sha, _shlex217.quote(remote))
    # A local zone where that commit falls on another date (the 4th, not the 5th), so a name taken from
    # local time instead of UTC shows on any machine, CI (which runs in UTC) included.
    return _run142(["bash", "-c", script], env=dict(_ENV142, TZ="America/Los_Angeles")).stdout.strip()


if _HAVE217:
    _bare217 = os.path.join(_SB217, "tag.git")
    _dev217 = os.path.join(_SB217, "tagdev")
    _git217("init", "-q", "--bare", "-b", "main", _bare217)
    _git217("clone", "-q", _bare217, _dev217)
    # 23:30 on the 4th in UTC-5 is the 5th in UTC: the name is the UTC date.
    _late217 = dict(_ENV142, GIT_COMMITTER_DATE="2026-03-04T23:30:00-05:00", GIT_AUTHOR_DATE="2026-03-04T23:30:00-05:00")
    _git217("-C", _dev217, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "one", env=_late217)
    _c1 = _git217("-C", _dev217, "rev-parse", "HEAD")
    _git217("-C", _dev217, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "two", env=_late217)
    _c2 = _git217("-C", _dev217, "rev-parse", "HEAD")
    _git217("-C", _dev217, "push", "-q", "origin", "main")
    _t_none = _tag217(_dev217, _c1, "origin")
    _git217("-C", _dev217, "tag", "2026.3.5", _c1)
    _git217("-C", _dev217, "push", "-q", "origin", "refs/tags/2026.3.5")
    _t_other, _t_same = _tag217(_dev217, _c2, "origin"), _tag217(_dev217, _c1, "origin")
    eq("release tag: the commit's UTC date; .2 when that date's tag is another commit; the same commit keeps it",
       (_t_none, _t_other, _t_same), ("2026.3.5", "2026.3.5.2", "2026.3.5"))
else:
    skip("release tag: named by date", "git or ssh-keygen is not installed")

# ── 3. the whole script, with a stand-in GitHub CLI ────────────────────────────────────────────
_FAKEGH217 = r"""
log="$FAKEGH_LOG"
printf '%s\n' "$*" >> "$log"
if [ "$1" = release ] && [ "$2" = view ]; then exit "${FAKEGH_VIEW_RC:-1}"; fi
if [ "$1" = release ] && [ "$2" = create ]; then
    prev=""
    for a in "$@"; do
        if [ "$prev" = --notes-file ]; then echo "NOTES:"; cat "$a"; fi
        case "$a" in *.sig) echo "ASSET: $(basename "$a") $(head -c 29 "$a")";; esac
        prev="$a"
    done >> "$log"
fi
exit 0
"""


def _signed_run217(dev, sha, log, **extra):
    """sign-release.sh --yes <sha> in `dev`, the GitHub CLI replaced by the stand-in logging to `log`."""
    env = dict(_ENV142, SIGN_RELEASE_KEY=_KEY217, FAKEGH_LOG=log,
               SIGN_RELEASE_GH="bash %s" % _shlex217.quote(_gh217), **extra)
    return _run142(["bash", _TOOL217, "--yes", sha], cwd=dev, env=env, input="")


if _HAVE217:
    _gh217 = _write217("fakegh.sh", _FAKEGH217)
    _KEY217 = os.path.join(_SB217, "relkey")
    _run142(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", _KEY217])
    with open(_KEY217 + ".pub", encoding="utf-8") as _fh217:
        _pub217 = "release " + " ".join(_fh217.read().split()[:2]) + "\n"
    _rb217 = os.path.join(_SB217, "rel.git")
    _rd217 = os.path.join(_SB217, "reldev")
    _git217("init", "-q", "--bare", "-b", "main", _rb217)
    _git217("clone", "-q", _rb217, _rd217)
    os.makedirs(os.path.join(_rd217, "panel", "install"))
    os.makedirs(os.path.join(_rd217, "docs"))
    with open(os.path.join(_rd217, "panel", "install", "release-signers"), "w", encoding="utf-8") as _fh217:
        _fh217.write(_pub217)
    with open(os.path.join(_rd217, "docs", "CHANGELOG.md"), "w", encoding="utf-8") as _fh217:
        _fh217.write(_BEFORE217)
    _git217("-C", _rd217, "config", "gpg.format", "ssh")
    _git217("-C", _rd217, "config", "user.signingkey", _KEY217 + ".pub")
    _git217("-C", _rd217, "add", ".")
    _git217("-C", _rd217, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "first")
    _git217("-C", _rd217, "push", "-q", "origin", "main")
    _ra217 = _git217("-C", _rd217, "rev-parse", "HEAD")
    _log0 = os.path.join(_SB217, "gh0.log")
    _r0 = _signed_run217(_rd217, _ra217, _log0, SIGN_RELEASE_NO_RELEASE="1")
    with open(os.path.join(_rd217, "docs", "CHANGELOG.md"), "w", encoding="utf-8") as _fh217:
        _fh217.write(_AFTER217)
    # A code change too: a commit of documentation alone starts no deploy (ci_ignored_only).
    with open(os.path.join(_rd217, "panel", "x.py"), "w", encoding="utf-8") as _fh217:
        _fh217.write("X = 1\n")
    _git217("-C", _rd217, "add", ".")
    _git217("-C", _rd217, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "second")
    _git217("-C", _rd217, "push", "-q", "origin", "main")
    _rs217 = _git217("-C", _rd217, "rev-parse", "HEAD")
    _log1 = os.path.join(_SB217, "gh1.log")
    _r1 = _signed_run217(_rd217, _rs217, _log1)
    _gh1 = open(_log1, encoding="utf-8").read() if os.path.exists(_log1) else ""
    _gh0 = open(_log0, encoding="utf-8").read() if os.path.exists(_log0) else ""
    _tag1 = _tag217(_rd217, _rs217, "origin")
    check("sign-release.sh: signing main publishes a GitHub release of that commit, named by its date, "
          "with the entries it added as the notes and the signature attached",
          _r1.returncode == 0 and ("release create %s --target %s" % (_tag1, _rs217)) in _gh1
          and "- **New feature.**" in _gh1 and "Old feature" not in _gh1
          and ("ASSET: linuxgsm-panel-%s.sig -----BEGIN SSH SIGNATURE" % _tag1) in _gh1
          and "workflow run deploy.yml" in _gh1 and "published GitHub release" in _r1.stdout,
          "rc=%s %s | %s | %s" % (_r1.returncode, _r1.stderr[-300:], _r1.stdout[-200:], _gh1[-600:]))
    check("sign-release.sh: SIGN_RELEASE_NO_RELEASE signs and deploys but publishes no release",
          _r0.returncode == 0 and "release create" not in _gh0 and "workflow run deploy.yml" in _gh0,
          "rc=%s %s" % (_r0.returncode, _gh0[-300:]))
    _log2 = os.path.join(_SB217, "gh2.log")
    _r2 = _signed_run217(_rd217, _rs217, _log2, FAKEGH_VIEW_RC="0")
    _gh2 = open(_log2, encoding="utf-8").read() if os.path.exists(_log2) else ""
    _log3 = os.path.join(_SB217, "gh3.log")
    _r3 = _signed_run217(_rd217, _rs217, _log3, SIGN_RELEASE_NO_DEPLOY="1")
    _gh3 = open(_log3, encoding="utf-8").read() if os.path.exists(_log3) else ""
    check("sign-release.sh: a release that already exists is left alone, and SIGN_RELEASE_NO_DEPLOY "
          "publishes nothing at all",
          _r2.returncode == 0 and "release create" not in _gh2 and "already exists" in _r2.stdout
          and _r3.returncode == 0 and _gh3 == "",
          "%s | %s | %s" % (_r2.stdout[-200:], _gh2[-200:], _gh3[-200:]))
else:
    skip("sign-release.sh: GitHub release", "git or ssh-keygen is not installed")

_shutil217.rmtree(_SB217, ignore_errors=True)
