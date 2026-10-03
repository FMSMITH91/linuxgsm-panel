"""Part 27 of the unit suite: the dependency and secret scanners judge what they claim to.

An audit of every CI config against its vendor's documentation (2026-10-03) found scanners that
passed while reading less than they said. Each block here pins one fix, and every check fails on
the tree before it:

- the dependency audit (security-code.yml) gained osv-scanner over every lockfile, gamedig's npm
  tree included, with a count that fails a lockfile read as empty; its one exemption is reasoned and
  expiring (tools/gamedig/osv-scanner.toml), and Dependency Review's allow-ghsas is held to it;
- pip-audit reads the pins as written (--disable-pip), fails a pin it cannot audit (--strict), and
  must have audited every pin: requirements-bootstrap.txt had been audited as zero packages;
- Dependency Review fails at any severity; every Dependabot entry has Renovate's release-age cooldown;
- the Semgrep job installs one lockfile with pip's dependency check on (no --no-deps);
- gitleaks runs its `git` command against an `[[allowlists]]` config, not the deprecated forms.

HOW IT RUNS. The workflows are read as text (PyYAML is not installed in CI's test environment), and
the two audit steps' run blocks are taken out of the workflow and run with bash -e, as the runner
runs them, with the scanner replaced by a stub that records its arguments and answers as told.
"""
import json as _json27
import os
import re as _re27
import shutil as _shutil27
import subprocess as _sp27  # nosec B404 - runs bash on the workflow's own step, with stub scanners
import sys
import tempfile as _tf27

from unit.part01 import _root, check
from unit.part06 import _ci_installs, _wf_run_block

_WF27 = os.path.join(_root, ".github", "workflows")


def _read27(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _job27(text, job_id):
    """One job's text: from `  <id>:` to the next job at the same indent."""
    _m = _re27.search(r"^  %s:\n(?:(?:    .*|\s*)\n)*" % _re27.escape(job_id), text + "\n", _re27.M)
    return _m.group(0) if _m else ""


def _stub27(directory, name, body):
    """An executable Python stub called `name` in `directory`."""
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!%s\n%s" % (sys.executable, body))
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
    os.chmod(path, 0o700)
    return path


def _run_step27(script, env):
    """A workflow run block, run as the runner runs one: `bash -e`, from the repository root."""
    _p = _sp27.run(["bash", "-e", "-c", script], cwd=_root, env=env, capture_output=True,  # nosec B603 B607 - bash on the workflow's own step
                   text=True, timeout=120, check=False)
    return _p.returncode, _p.stdout + _p.stderr


_SC27 = _read27(".github", "workflows", "security-code.yml")
_DA27 = _job27(_SC27, "dependency-audit")
check("dependency audit: the job was found, under its required name",
      "name: Dependency vulnerabilities (pip-audit)" in _DA27, _DA27[:200])


# ── pip-audit: the pins as written, every one of them, and a pin it cannot audit fails ────────────
# pip-audit 2.10.1 without --disable-pip resolves the file with `pip install --dry-run` in a venv
# whose pip it first upgrades to the newest. requirements-bootstrap.txt pins pip, the newest, so pip
# was "already installed" and the file was audited as ZERO packages, exit 0. Measured in
# python:3.11-slim before the fix: --no-deps and --strict --require-hashes both audited 0 of its 1;
# --disable-pip audited 1. --strict turns a pin PyPI cannot answer for from "skipped" into a failure.
_PA_STUB27 = r'''
import json, os, re, sys
args = sys.argv[1:]
with open(os.environ["P27_LOG"], "a") as fh:
    fh.write(json.dumps(args) + "\n")
mode = os.environ.get("P27_MODE", "all")
req = args[args.index("-r") + 1]
out = args[args.index("-o") + 1]
pins = re.findall(r"^([A-Za-z0-9._-]+)==(\S+)", open(req).read(), re.M)
if mode == "strict":
    sys.stderr.write("ERROR:pip_audit._cli:x: Dependency not found on PyPI and could not be audited\n")
    sys.exit(1)
deps = [{"name": n, "version": v, "vulns": []} for n, v in pins]
rc = 0
if mode == "drop1" and req == "requirements.txt":
    deps = deps[1:]
if mode == "skip1" and req == "requirements.txt":
    deps[0] = {"name": deps[0]["name"], "skip_reason": "not on PyPI"}
if mode == "vuln" and req == "requirements.txt":
    deps[0]["vulns"] = [{"id": "GHSA-p27a-fixd", "fix_versions": ["9.9"]},
                        {"id": "GHSA-p27b-nofx", "fix_versions": []}]
    rc = 1
json.dump({"dependencies": deps, "fixes": []}, open(out, "w"))
sys.exit(rc)
'''
_pa_tmp27 = _tf27.mkdtemp(prefix="lgsm-unit-p27-pa-")
try:
    _pa_run27 = ""
    try:
        _pa_run27 = _wf_run_block(_SC27, "Audit the panel's pins (pip-audit)")
    except StopIteration:
        pass
    check("pip-audit: the audit is one step, in the dependency-audit job",
          bool(_pa_run27) and "- name: Audit the panel's pins (pip-audit)" in _DA27)
    _stub27(_pa_tmp27, "pip-audit", _PA_STUB27)
    _pa_have_jq27 = _shutil27.which("jq") is not None
    check("pip-audit: jq is on PATH (the step reads pip-audit's JSON with it, as the runner does)",
          _pa_have_jq27)
    _pa_pins27 = {_f: len(_re27.findall(r"^[A-Za-z0-9._-]+==", _read27(_f), _re27.M))
                  for _f in ("requirements.txt", "requirements-bootstrap.txt")}

    def _pa27(mode):
        _log = os.path.join(_pa_tmp27, "argv-%s.log" % mode)
        _env = dict(os.environ, PATH=_pa_tmp27 + ":" + os.environ.get("PATH", ""),
                    RUNNER_TEMP=_pa_tmp27, P27_LOG=_log, P27_MODE=mode)
        _rc, _out = _run_step27(_pa_run27, _env) if _pa_run27 else (None, "")
        _argv = ([_json27.loads(_l) for _l in open(_log, encoding="utf-8")]
                 if os.path.exists(_log) else [])
        return _rc, _out, _argv

    _rc, _out, _argv = _pa27("all")
    check("pip-audit: both lockfiles are audited with --strict --require-hashes --disable-pip, and "
          "nothing else is passed",
          [(_a[_a.index("-r") + 1], sorted(_t for _t in _a if _t.startswith("--")))
           for _a in _argv if "-r" in _a]
          == [(_f, ["--disable-pip", "--require-hashes", "--strict"])
              for _f in ("requirements.txt", "requirements-bootstrap.txt")], repr(_argv))
    check("pip-audit: a clean audit of every pin passes, and says how many it read",
          _rc == 0 and all("%s: audited %d of its %d pinned packages" % (_f, _n, _n) in _out
                           for _f, _n in _pa_pins27.items()) and min(_pa_pins27.values()) >= 1,
          "rc=%r pins=%r out=%r" % (_rc, _pa_pins27, _out[-600:]))
    _rc, _out, _ = _pa27("drop1")
    check("pip-audit: ...a pin the audit did not read fails the step, by file and count",
          _rc not in (0, None) and ("audited %d of the %d packages pinned in requirements.txt"
                                    % (_pa_pins27["requirements.txt"] - 1,
                                       _pa_pins27["requirements.txt"])) in _out, _out[-400:])
    _rc, _out, _ = _pa27("skip1")
    check("pip-audit: ...a pin reported as skipped counts as not read", _rc not in (0, None)
          and "NOT checked" in _out, _out[-400:])
    _rc, _out, _ = _pa27("vuln")
    check("pip-audit: a finding fails the step and is named with its fix, or the lack of one",
          _rc not in (0, None) and "GHSA-p27a-fixd (fixed in 9.9)" in _out
          and "GHSA-p27b-nofx (no fix yet)" in _out and "::error::" in _out, _out[-600:])
    _rc, _out, _ = _pa27("strict")
    check("pip-audit: a pin it could not audit (--strict's exit) fails the step", _rc not in (0, None)
          and "pip-audit failed on requirements.txt" in _out, _out[-400:])
finally:
    _shutil27.rmtree(_pa_tmp27, ignore_errors=True)
check("pip-audit: no step anywhere still runs pip-audit --no-deps (it does not stop the resolution)",
      "pip-audit --no-deps" not in _SC27 and "pip-audit" in _SC27)


# ── osv-scanner: every lockfile in the repository, each read, at any severity ───────────────────
# What is a lockfile here: every package-lock.json, and every pip-compile output (its header says
# so), wherever it lives. A new one that the step does not pass to osv-scanner fails this.
_LOCK_SKIP27 = {".git", ".claude", ".venv", "venv", "node_modules", "data", "__pycache__"}
_locks27 = set()
for _dp, _dns, _fns in os.walk(_root):
    _dns[:] = [_d for _d in _dns if _d not in _LOCK_SKIP27]
    for _fn in _fns:
        _rel = os.path.relpath(os.path.join(_dp, _fn), _root)
        if _fn == "package-lock.json":
            _locks27.add(_rel)
        elif _fn.endswith(".txt"):
            with open(os.path.join(_dp, _fn), encoding="utf-8", errors="replace") as _fh27:
                if "autogenerated by pip-compile" in _fh27.read(4096):
                    _locks27.add(_rel)
check("osv-scanner: the repository's lockfiles were found (gamedig's, the panel's two, the CI "
      "tools')",
      {"tools/gamedig/package-lock.json", "requirements.txt", "requirements-bootstrap.txt",
       ".github/ci-requirements/pip-audit.txt"} <= _locks27, repr(sorted(_locks27)))

_OSV_STUB27 = r'''
import json, os, sys
args = sys.argv[1:]
with open(os.environ["P27_LOG"], "a") as fh:
    fh.write(json.dumps(args) + "\n")
mode = os.environ.get("P27_MODE", "")
for i, a in enumerate(args):
    if a != "--lockfile":
        continue
    v = args[i + 1]
    path = v.split(":", 1)[1] if v.startswith("requirements.txt:") else v
    if mode == "omit:" + path:
        continue
    n = 0 if mode == "zero:" + path else 3
    print("Scanned %s file and found %d package%s" % (os.path.join(os.getcwd(), path), n,
                                                       "" if n == 1 else "s"))
sys.exit(1 if mode == "rc1" else 0)
'''
_osv_tmp27 = _tf27.mkdtemp(prefix="lgsm-unit-p27-osv-")
try:
    _osv_run27 = ""
    try:
        _osv_run27 = _wf_run_block(_SC27, "Audit every lockfile (osv-scanner)")
    except StopIteration:
        pass
    _stub27(_osv_tmp27, "osv-scanner", _OSV_STUB27)

    def _osv27(mode):
        _log = os.path.join(_osv_tmp27, "argv-%d.log" % len(os.listdir(_osv_tmp27)))
        _env = dict(os.environ, RUNNER_TEMP=_osv_tmp27, P27_LOG=_log, P27_MODE=mode)
        _rc, _out = _run_step27(_osv_run27, _env) if _osv_run27 else (None, "")
        _argv = ([_json27.loads(_l) for _l in open(_log, encoding="utf-8")]
                 if os.path.exists(_log) else [])
        return _rc, _out, (_argv[0] if _argv else [])

    _rc, _out, _argv = _osv27("")
    _osv_vals27 = [_argv[_i + 1] for _i, _a in enumerate(_argv[:-1]) if _a == "--lockfile"]
    _osv_paths27 = {(_v.split(":", 1)[1] if _v.startswith("requirements.txt:") else _v)
                    for _v in _osv_vals27}
    check("osv-scanner: the step scans every lockfile in the repository",
          _argv[:2] == ["scan", "source"] and _osv_paths27 == _locks27
          and len(_osv_vals27) == len(_locks27),
          "missing=%r extra=%r argv=%r" % (sorted(_locks27 - _osv_paths27),
                                           sorted(_osv_paths27 - _locks27), _argv[:6]))
    check("osv-scanner: ...each pip lockfile with the requirements.txt: parse-as prefix (it picks a "
          "parser by file name), the npm one by its own name",
          bool(_osv_vals27) and all(_v.startswith("requirements.txt:") != _v.endswith(".json")
                                    for _v in _osv_vals27), repr(_osv_vals27))
    check("osv-scanner: ...and with every lockfile read, a clean scan passes and says so",
          _rc == 0 and "osv-scanner read %d of %d lockfiles." % (len(_locks27), len(_locks27)) in _out,
          "rc=%r %s" % (_rc, _out[-400:]))
    _rc, _out, _ = _osv27("zero:.github/ci-requirements/pip-audit.txt")
    check("osv-scanner: a lockfile read as no packages fails the step, by name",
          _rc not in (0, None) and "read no packages from: .github/ci-requirements/pip-audit.txt" in _out,
          _out[-400:])
    _rc, _out, _ = _osv27("omit:tools/gamedig/package-lock.json")
    check("osv-scanner: ...and so does one it never reported reading",
          _rc not in (0, None) and "read no packages from: tools/gamedig/package-lock.json" in _out,
          _out[-400:])
    _rc, _out, _ = _osv27("rc1")
    check("osv-scanner: a finding (its exit 1) fails the step, after the count is printed",
          _rc == 1 and "osv-scanner read" in _out, "rc=%r %s" % (_rc, _out[-300:]))
finally:
    _shutil27.rmtree(_osv_tmp27, ignore_errors=True)

# Pinned and checksummed (part19's Renovate gate covers the marker); both osv steps run even when
# pip-audit failed, so a Python finding never hides an npm one.
_osv_inst27 = _DA27[_DA27.find("- name: Install osv-scanner"):_DA27.find("- name: Audit every lockfile")]
check("osv-scanner: installed from the release tag and checked against its sha256 before it runs",
      _re27.search(r"OSV_SCANNER_VERSION: 'v[0-9.]+'\n\s+OSV_SCANNER_SHA256: '[0-9a-f]{64}'",
                   _osv_inst27) is not None
      and "releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" in _osv_inst27
      and _osv_inst27.find("sha256sum -c -") < _osv_inst27.find('chmod +x "${RUNNER_TEMP}/osv-scanner"'),
      _osv_inst27[-500:])
_osv_steps27 = [_b for _b in _DA27.split("\n      - ") if "osv-scanner" in _b.split("\n")[0]]
check("osv-scanner: both its steps run even when pip-audit failed (if: !cancelled())",
      len(_osv_steps27) == 2
      and all("\n        if: ${{ !cancelled() }}\n" in "\n" + _b for _b in _osv_steps27),
      repr([_b[:80] for _b in _osv_steps27]))
check("dependency audit: the workflow runs it on every pull request, on main and weekly",
      _re27.search(r"^  pull_request:\n    branches: \[ main \]\n(?!    paths)", _SC27, _re27.M)
      is not None and "\n  schedule:\n    - cron:" in _SC27 and "\n  push:\n" in _SC27)


# ── the exemptions: reasoned, expiring, and the same list in Dependency Review ──────────────────
# osv-scanner reads osv-scanner.toml from the scanned file's own directory only (docs, v2.6.0). Read
# as text: the 3.10 CI leg has no tomllib.
def _ignored27(text):
    """[[IgnoredVulns]] entries as dicts of their id, ignoreUntil and reason (raw text)."""
    _out = []
    for _blk in _re27.split(r"^\[\[IgnoredVulns\]\]\s*$", text, flags=_re27.M)[1:]:
        _blk = _re27.split(r"^\[", _blk, flags=_re27.M)[0]
        _id = _re27.search(r'^id = "([^"]+)"\s*$', _blk, _re27.M)
        _until = _re27.search(r"^ignoreUntil = (\d{4}-\d{2}-\d{2})\s*$", _blk, _re27.M)
        _reason = _re27.search(r'^reason = (?:"""(.*?)"""|"([^"\n]*)")', _blk, _re27.M | _re27.S)
        _out.append({"id": _id and _id.group(1), "until": _until and _until.group(1),
                     "reason": _reason and (_reason.group(1) or _reason.group(2) or "").strip()})
    return _out


_osv_cfgs27 = {}
for _lk in sorted(_locks27):
    _cfg = os.path.join(_root, os.path.dirname(_lk), "osv-scanner.toml")
    if os.path.exists(_cfg):
        with open(_cfg, encoding="utf-8") as _fh27:
            _osv_cfgs27[os.path.relpath(_cfg, _root)] = _ignored27(_fh27.read())
_osv_ign27 = [_e for _es in _osv_cfgs27.values() for _e in _es]
check("osv-scanner.toml: gamedig's sits beside its lockfile and carries the reviewed advisory",
      "tools/gamedig/osv-scanner.toml" in _osv_cfgs27
      and "GHSA-ch52-4w7c-c8xp" in [_e["id"] for _e in _osv_ign27], repr(_osv_cfgs27))
_osv_bad27 = [_e for _e in _osv_ign27
              if not _e["id"] or not _e["until"] or len(_e["reason"] or "") < 80]
check("osv-scanner.toml: every exemption has an id, an ignoreUntil date and a written reason",
      _osv_ign27 and not _osv_bad27, repr(_osv_bad27))
check("osv-scanner.toml: ...and an entry with no date, or no reason, is caught (control)",
      [_e["id"] for _e in _ignored27('[[IgnoredVulns]]\nid = "GHSA-x"\nreason = "%s"\n\n'
                                     '[[IgnoredVulns]]\nid = "GHSA-y"\nignoreUntil = 2027-01-01\n'
                                     % ("r" * 90))
       if not _e["until"] or len(_e["reason"] or "") < 80] == ["GHSA-x", "GHSA-y"])

_DR27 = _read27(".github", "workflows", "dependency-review.yml")
_dr_sev27 = _re27.findall(r"^\s+fail-on-severity: (\S+)\s*$", _DR27, _re27.M)
check("dependency review: fails a pull request that adds an advisory of any severity "
      "(fail-on-severity: low, the action's default)", _dr_sev27 == ["low"], repr(_dr_sev27))
_dr_allow27 = _re27.findall(r"^\s+allow-ghsas: (.+?)\s*$", _DR27, _re27.M)
_dr_ids27 = [_i.strip() for _i in ",".join(_dr_allow27).split(",") if _i.strip()]


def _dr_unreviewed27(ids, entries):
    return [_i for _i in ids if _i not in {_e["id"] for _e in entries if _e["until"]}]


check("dependency review: every allow-ghsas id is a dated osv-scanner exemption (one triage)",
      _dr_ids27 == ["GHSA-ch52-4w7c-c8xp"] and not _dr_unreviewed27(_dr_ids27, _osv_ign27),
      repr((_dr_ids27, _dr_unreviewed27(_dr_ids27, _osv_ign27))))
check("dependency review: ...and an id with no osv-scanner entry is caught (control)",
      _dr_unreviewed27(["GHSA-ch52-4w7c-c8xp", "GHSA-p27z-none"], _osv_ign27) == ["GHSA-p27z-none"])


# ── Dependabot: every entry waits out Renovate's release-age floor ──────────────────────────────
# Only the npm entry had a cooldown; the panel's pip set, the CI tools' and the Actions had none.
# Read per entry, with comment lines dropped: the npm entry's COMMENT says "cooldown:", and a scan
# of raw text read the entry before it as covered.
def _db_uncooled27(text, days):
    _src = "\n".join(_l for _l in text.splitlines() if not _l.lstrip().startswith("#"))
    _bad = []
    for _blk in _re27.split(r"\n(?=  - package-ecosystem: )", _src)[1:]:
        _m = _re27.search(r"\n    cooldown:\n      default-days: (\d+)\n", _blk + "\n")
        if not _m or int(_m.group(1)) != days:
            _bad.append(" ".join(_blk.split()[:5]))
    return _bad


with open(os.path.join(_root, ".github", "renovate.json"), encoding="utf-8") as _fh27:
    _rn_age27 = _re27.fullmatch(r"(\d+) days", _json27.load(_fh27).get("minimumReleaseAge") or "")
_DB27 = _read27(".github", "dependabot.yml")
_db_n27 = len(_re27.findall(r"^  - package-ecosystem: ", _DB27, _re27.M))
check("dependabot: every entry has a cooldown of Renovate's minimumReleaseAge",
      _rn_age27 is not None and _db_n27 >= 5
      and not _db_uncooled27(_DB27, int(_rn_age27.group(1))),
      repr((_rn_age27 and _rn_age27.group(0), _db_n27,
            _rn_age27 and _db_uncooled27(_DB27, int(_rn_age27.group(1))))))
check("dependabot: ...and an entry whose only cooldown is in a comment is caught (control)",
      _db_uncooled27('updates:\n  - package-ecosystem: "pip"\n    directory: "/"\n'
                     '    #   cooldown:\n    #     default-days: 7\n', 7)
      == ['- package-ecosystem: "pip" directory: "/"'])


# ── Semgrep: one lockfile, installed whole ──────────────────────────────────────────────────────
# semgrep 1.178 pinned a vulnerable PyJWT, so PyJWT was compiled out and installed from a second
# file with --no-deps. semgrep 1.179 allows a safe one: one closure, and pip checks it is complete.
_SG27 = _job27(_SC27, "sast-semgrep")
_sg_inst27 = [_t for _w, _t in _ci_installs if _w == "security-code.yml"
              and any(_x.startswith(".github/ci-requirements/semgrep") for _x in _t)]
_sg_txt27 = _read27(".github", "ci-requirements", "semgrep.txt")
check("semgrep: the job installs semgrep.txt alone, hash-checked, with pip's dependency check on",
      len(_sg_inst27) == 1
      and [_sg_inst27[0][_i + 1] for _i, _t in enumerate(_sg_inst27[0]) if _t == "-r"]
      == [".github/ci-requirements/semgrep.txt"]
      and "--require-hashes" in _sg_inst27[0] and "--no-deps" not in _sg_inst27[0]
      and "-r .github/ci-requirements/semgrep.txt" in " ".join(_SG27.split()),
      repr(_sg_inst27))
check("semgrep: ...and its lockfile is the whole closure: PyJWT pinned in it, nothing compiled out",
      _re27.search(r"^pyjwt==\d", _sg_txt27, _re27.M) is not None
      and "--unsafe-package" not in _sg_txt27 and "were not pinned" not in _sg_txt27
      and not os.path.exists(os.path.join(_root, ".github", "ci-requirements", "semgrep-pyjwt.txt")))
check("workflows: no pip install anywhere uses --no-deps", _ci_installs
      and not [_w for _w, _t in _ci_installs if "--no-deps" in _t])


# ── gitleaks: the `git` command, and the `[[allowlists]]` table ─────────────────────────────────
# v8.19.0 deprecated `detect` (hidden, still there), v8.25.0 replaced `[allowlist]`. A release that
# removed either would turn the required secret scan red, or worse, ignore the placeholders' table.
_GL27 = _read27(".github", "workflows", "security.yml")
_GL_BIN27 = "/tmp/gitleaks"  # nosec B108 - the path security.yml installs to; read as text, never written
_gl_src27 = _re27.sub(r"\\\n\s*", " ", "\n".join(_l for _l in _GL27.splitlines()
                                                  if not _l.lstrip().startswith("#")))
_gl_calls27 = [" ".join(_l.split()) for _l in _gl_src27.splitlines() if _GL_BIN27 + " " in _l]
check("gitleaks: both scans run `gitleaks git` on the checkout, with the config, redacted, failing "
      "on a finding; the PR one over the PR's range",
      len(_gl_calls27) == 2
      and all(_c.startswith(_GL_BIN27 + " git --config .github/gitleaks.toml ")
              and _c.endswith(" --redact --verbose --exit-code 1 .") for _c in _gl_calls27)
      and sum('--log-opts "${BASE_SHA}..${HEAD_SHA}"' in _c for _c in _gl_calls27) == 1,
      repr(_gl_calls27))
check("gitleaks: no deprecated command (detect, protect) is run",
      not _re27.search(_re27.escape(_GL_BIN27) + r" (detect|protect)\b", _gl_src27))
_GLT27 = "\n".join(_l for _l in _read27(".github", "gitleaks.toml").splitlines()
                   if not _l.lstrip().startswith("#"))
check("gitleaks: the config's allowlist is an [[allowlists]] table, not the deprecated [allowlist]",
      _re27.findall(r"^[ \t]*(\[\[?allowlists?\]\]?)[ \t]*$", _GLT27, _re27.M) == ["[[allowlists]]"],
      repr(_re27.findall(r"^[ \t]*(\[\[?allowlists?\]\]?)[ \t]*$", _GLT27, _re27.M)))
