"""Part 327 of the unit suite: Lighthouse CI from a committed, hash-locked npm tree.

The lighthouse workflow ran Lighthouse CI through a third-party action whose newest release resolved
@lhci/cli 0.15.1, which carries sixteen published advisories (thirteen high) that 0.16.1 fixes. The job
now installs .github/lhci with `npm ci --ignore-scripts` from a lockfile that pins every package by
sha512, and runs collect and assert itself. These checks hold:
1. the tree: exact top-level pins that the lockfile's root repeats, every package from npm's registry
   with a sha512, none with an install script, and an .npmrc that turns install scripts off;
2. the workflow: the install (npm ci from that folder, its flags, Node pinned by SHA and new enough for
   the tree's engines), no other way in (no npm install, no npx, no third-party action), and the run
   step itself: collect then assert with CI's config and the runner's Chrome, a failed assertion or
   collect failing the step, and no browser failing it by name;
3. its updates: a Dependabot npm entry for the folder with the week's cooldown, grouped.

HOW IT RUNS. The workflow is read as text with part29's helpers; the run step runs in bash, as the
runner runs it, in a scratch folder with a stand-in lhci and browser on PATH.
"""
import json as _json327
import os
import re as _re327
import shutil as _shutil327
import subprocess as _sp327  # nosec B404 - bash over this part's own stand-ins
import tempfile as _tf327

from unit.part01 import _root, check, eq
from unit.part29 import _code29, _job29, _name29, _runbody29, _steps29, _wf29

_DIR327 = os.path.join(_root, ".github", "lhci")


def _read327(*parts):
    with open(os.path.join(_DIR327, *parts), encoding="utf-8") as fh:
        return fh.read()


# ── 1. the tree ─────────────────────────────────────────────────────────────────────────────────
_pkg327 = _json327.loads(_read327("package.json"))
_lock327 = _json327.loads(_read327("package-lock.json"))
_deps327 = _pkg327.get("dependencies") or {}
check("lhci tree: package.json pins @lhci/cli 0.16.1 or later and puppeteer-core (the sign-in script drives it) "
      "exactly, with no ranges, scripts or dev tools",
      "@lhci/cli" in _deps327 and "puppeteer-core" in _deps327
      and all(_re327.fullmatch(r"\d+\.\d+\.\d+", v) for v in _deps327.values())
      and tuple(int(x) for x in _deps327["@lhci/cli"].split(".")) >= (0, 16, 1)
      and not _pkg327.get("scripts") and not _pkg327.get("devDependencies") and _pkg327.get("private") is True,
      repr(_pkg327))


def _entry_bad327(path, meta):
    """What is wrong with one package entry of a lockfile: its source, its sha512, an install script."""
    return ["%s: %s" % (path, why) for bad, why in (
        (not str(meta.get("resolved", "")).startswith("https://registry.npmjs.org/"), "not from npm's registry"),
        (not str(meta.get("integrity", "")).startswith("sha512-"), "no sha512"),
        (bool(meta.get("hasInstallScript")), "has an install script"),
    ) if bad]


def _root_bad327(lock, deps):
    """What is wrong with a lockfile's version and root against package.json's dependencies."""
    pkgs = lock.get("packages") or {}
    bad = [] if lock.get("lockfileVersion", 0) >= 3 else ["lockfileVersion %r" % lock.get("lockfileVersion")]
    if (pkgs.get("") or {}).get("dependencies") != deps:
        bad.append("the root's dependencies are not package.json's")
    return bad + ["%s is not locked at %s" % (name, ver) for name, ver in deps.items()
                  if (pkgs.get("node_modules/" + name) or {}).get("version") != ver]


def _lock_bad327(lock, deps):
    """What is wrong with a package-lock.json against package.json's dependencies ([] when nothing)."""
    entries = [why for path, meta in (lock.get("packages") or {}).items() if path for why in _entry_bad327(path, meta)]
    return _root_bad327(lock, deps) + entries


eq("lhci tree: the lockfile repeats those pins, and every package in it comes from npm's registry with a sha512 "
   "and no install script", _lock_bad327(_lock327, _deps327), [])
_ctl_lock327 = _json327.loads(_json327.dumps(_lock327))
_ctl_first327 = next(p for p in _ctl_lock327["packages"] if p)
_ctl_lock327["packages"][_ctl_first327].pop("integrity", None)
_ctl_lock327["packages"][_ctl_first327]["hasInstallScript"] = True
eq("lhci tree: ...and a package with no sha512 or with an install script is named (control)",
   _lock_bad327(_ctl_lock327, _ctl_lock327["packages"][""].get("dependencies") or {}),
   ["%s: no sha512" % _ctl_first327, "%s: has an install script" % _ctl_first327])
check("lhci tree: the folder's .npmrc turns install scripts off for anyone running npm there",
      "ignore-scripts=true" in [ln.strip() for ln in _read327(".npmrc").splitlines()], _read327(".npmrc"))

# ── 2. the workflow ─────────────────────────────────────────────────────────────────────────────
_LH327 = _job29(_wf29("lighthouse.yml"), "lighthouse")
_steps327 = _steps29(_LH327)
_names327 = [_name29(s) for s in _steps327]
_uses327 = sorted(set(_re327.findall(r"^\s*-? *uses: ([^@\s]+)@[0-9a-f]{40} ", _code29(_LH327), _re327.M)))
_uses_all327 = _re327.findall(r"^\s*-? *uses: (\S+)", _code29(_LH327), _re327.M)
eq("lighthouse job: its only actions are Harden-Runner, checkout, setup-python and setup-node, each pinned by "
   "full SHA (no third-party Lighthouse action)",
   (_uses327, len(_uses_all327)),
   (["actions/checkout", "actions/setup-node", "actions/setup-python", "step-security/harden-runner"], 4))
_inst327 = next((s for s in _steps327 if _name29(s) == "Install Lighthouse CI from its lockfile"), "")
_node327 = next((s for s in _steps327 if "uses: actions/setup-node@" in s), "")
_run_i327 = _names327.index("Run Lighthouse CI") if "Run Lighthouse CI" in _names327 else -1
check("lighthouse job: Lighthouse CI is installed by npm ci from .github/lhci, install scripts off, after Node "
      "is set up and before the run step",
      _re327.search(r"^ {8}working-directory: \.github/lhci$", _inst327, _re327.M) is not None
      and _re327.search(r"^ {8}run: npm ci --ignore-scripts --no-audit --no-fund$", _inst327, _re327.M) is not None
      and _node327 in _steps327 and _inst327 in _steps327
      and _steps327.index(_node327) < _steps327.index(_inst327) < _run_i327, repr(_inst327))
_engine327 = _re327.fullmatch(r">=(\d+)\.(\d+)(?:\.\d+)?", (_pkg327.get("engines") or {}).get("node", ""))
_nodever327 = _re327.search(r'node-version: "(\d+)"', _node327)
check("lighthouse job: ...on a Node major the tree's engines accept",
      _engine327 is not None and _nodever327 is not None
      and (int(_nodever327.group(1)),) > (int(_engine327.group(1)),), repr((_engine327, _nodever327)))
check("lighthouse job: nothing else installs or fetches a package (no npm install, npm i, npx or npm exec)",
      not _re327.search(r"\bnpm (?:install|i|exec|x)\b|\bnpx\b|\bpnpm\b|\byarn\b", _code29(_LH327)),
      _code29(_LH327)[-300:])

_RUN327 = _runbody29(_steps327[_run_i327]) if _run_i327 >= 0 else ""
_BASH327 = _shutil327.which("bash") or "/bin/bash"
_LHCI_STUB327 = """#!%s
echo "$* CHROME_PATH=${CHROME_PATH:-}" >> "$P327_LOG"
case "$1" in "$P327_FAIL") exit 1 ;; esac
exit 0
""" % _BASH327


def _run327(browsers, fail=""):
    """Run the workflow's run step in a scratch folder; return (rc, stdout, the lhci calls)."""
    sb = _tf327.mkdtemp(prefix="lgsm-unit-p327-")
    try:
        lhci = os.path.join(sb, ".github", "lhci", "node_modules", ".bin", "lhci")
        os.makedirs(os.path.dirname(lhci))
        bindir = os.path.join(sb, "bin")
        os.makedirs(bindir)
        for path, text in [(lhci, _LHCI_STUB327)] + [(os.path.join(bindir, b), "#!%s\nexit 0\n" % _BASH327)
                                                     for b in browsers]:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in this part runs itself
            os.chmod(path, 0o700)
        log = os.path.join(sb, "calls")
        open(log, "w", encoding="utf-8").close()
        # PATH is the stand-ins' folder alone: the runner image's own Chrome must not answer for a missing one.
        p = _sp327.run([_BASH327, "--noprofile", "--norc", "-eo", "pipefail", "-c", _RUN327],  # nosec B603 - the workflow's own step
                       cwd=sb, capture_output=True, text=True, timeout=60, check=False,
                       env={"PATH": bindir, "P327_LOG": log, "P327_FAIL": fail, "HOME": sb})
        with open(log, encoding="utf-8") as fh:
            calls = [ln.replace(sb, "<sb>") for ln in fh.read().splitlines()]
        return p.returncode, p.stdout + p.stderr, calls
    finally:
        _shutil327.rmtree(sb, ignore_errors=True)


_CFG327 = "--config=.github/lighthouserc.json CHROME_PATH=<sb>/bin/"
_ok327 = _run327(["google-chrome"])
eq("lighthouse run step: collect, then assert, both with CI's config and the runner's Chrome as CHROME_PATH "
   "(what Lighthouse and puppeteer launch)",
   (_ok327[0], _ok327[2]), (0, ["collect " + _CFG327 + "google-chrome", "assert " + _CFG327 + "google-chrome"]))
_cr327 = _run327(["chromium"])
eq("lighthouse run step: ...Chromium when the image has no Google Chrome",
   (_cr327[0], _cr327[2]), (0, ["collect " + _CFG327 + "chromium", "assert " + _CFG327 + "chromium"]))
_fa327 = _run327(["google-chrome"], fail="assert")
check("lighthouse run step: a failed assertion fails the step (assert's exit status is the step's)",
      _fa327[0] != 0 and [c.split()[0] for c in _fa327[2]] == ["collect", "assert"], repr(_fa327))
_fc327 = _run327(["google-chrome"], fail="collect")
check("lighthouse run step: ...and a failed collect fails it before any assertion is judged",
      _fc327[0] != 0 and [c.split()[0] for c in _fc327[2]] == ["collect"], repr(_fc327))
_nb327 = _run327([])
check("lighthouse run step: no browser on the image fails the step by name, and Lighthouse never runs",
      _nb327[0] != 0 and "::error::no Chrome on this runner image" in _nb327[1] and _nb327[2] == [], repr(_nb327))

# ── 3. its updates ──────────────────────────────────────────────────────────────────────────────
with open(os.path.join(_root, ".github", "dependabot.yml"), encoding="utf-8") as _fh327:
    _dep327 = _fh327.read()
_dep_blk327 = next((b for b in _re327.split(r"\n(?=  - package-ecosystem: )", _dep327)
                    if 'directory: "/.github/lhci"' in b), "")
check("dependabot: an npm entry moves .github/lhci, with the week's cooldown, its bumps grouped in one pull request",
      _dep_blk327.startswith('  - package-ecosystem: "npm"\n    directory: "/.github/lhci"\n')
      and _re327.search(r"^    cooldown:\n      default-days: 7$", _dep_blk327, _re327.M) is not None
      and _re327.search(r'^    groups:\n      [a-z-]+:\n        patterns: \["\*"\]$', _dep_blk327, _re327.M) is not None,
      _dep_blk327)
