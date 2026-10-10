"""Part 42 of the unit suite: zizmor and Harden-Runner, the CI scanners added together.

* zizmor (docs.zizmor.sh) audits the workflows themselves. zizmor.yml runs it on every pull
  request, on pushes to main and weekly, at the pedantic persona, and uploads its SARIF to code
  scanning under the category `zizmor`, which both alert gates wait for. The scan job holds a
  read-only token; only the upload job may write, and it runs nothing but GitHub's own actions.
* Harden-Runner (step-security/harden-runner) records each job's outbound connections and root
  processes, from the first step of every job. Audit mode: no allow-list, though it still routes
  the job's DNS through its proxy and blocks StepSecurity's global blocklist.

Held here: Harden-Runner is the first step of every job, pinned, in audit mode; zizmor's triggers,
permissions, install and upload; its scan step, cut out of the workflow and run by bash against a
stand-in zizmor (a run that read fewer workflow files than exist, or could not run, fails); the
three lists the alert gates keep (the categories, the workflows codeql-alerts.yml is triggered by,
and the workflows it waits for) agree; and every finding accepted with `# zizmor: ignore[...]` is
named here with its workflow, with a reason beside it, and no zizmor config file exists.

HOW IT RUNS. The workflows are read as TEXT with part29's helpers (no YAML parser where CI runs
this suite). Nothing touches the network or the checkout's data/.
"""
import glob as _glob42
import importlib.util as _ilu42
import json as _json42
import os
import re as _re42
import shutil as _shutil42
import subprocess as _sp42  # nosec B404 - runs bash on a workflow step and this part's own stand-in
import tempfile as _tf42

from unit.part01 import check
from unit.part03 import _cls_files as _cls_files42
from unit.part05 import _root
from unit.part06 import _wf_run_block
from unit.part29 import _code29, _job29, _jobs29, _wf29
from unit.part30 import _block30

_WF42 = os.path.join(_root, ".github", "workflows")

# ── Harden-Runner: the first step of every job, pinned, in audit mode ─────────────────────────────
# The step every job carries, by its SHAPE: the pin is a full commit SHA with its version comment,
# and `with:` holds `egress-policy: audit` and nothing else. The SHA itself is read from the
# workflows, not written here: Dependabot's weekly github-actions PR moves every copy and its comment
# together, and that PR must pass. What fails is a job that differs: another pin than the others,
# block mode, a later position, or one more input. An input is never harmless here:
# `disable-sudo-and-containers` breaks ci.yml's root step and the docker jobs, and `policy` or
# `use-policy-store` lets StepSecurity's policy store replace the egress policy (block) for a job
# that holds id-token: write (the action's policy-utils.ts mergeConfigs).
_HR_STEP42 = _re42.compile(r"      - name: Harden Runner\n"
                           r"        uses: step-security/harden-runner@([0-9a-f]{40}) # (v\d+\.\d+\.\d+)\n"
                           r"        with:\n"
                           r"          egress-policy: audit\n")
# Jobs Harden-Runner cannot run in, each with why. A reusable-workflow call site (`uses:` on the job)
# has no steps of its own and is exempt by its shape; a job in a container must be listed here (the
# agent needs the runner VM, not a container: the action's docs/limitations.md).
_HR_EXCEPT42 = {
    ("deploy.yml", "deploy"): "it holds the tailnet identity that reaches the live panel as a "
                              "root-capable account; StepSecurity's runtime blocklist and flags "
                              "must not shape a deploy, and its log must not list root commands",
}


def _first_step42(job_text):
    """A job's text from its first step on; the comment and blank lines above that step dropped."""
    at = job_text.find("\n    steps:\n")
    if at < 0:
        return ""
    lines = job_text[at + len("\n    steps:\n"):].splitlines(True)
    while lines and (not lines[0].strip() or lines[0].lstrip().startswith("#")):
        lines.pop(0)                   # a comment above the step is the step's own business
    return "".join(lines)


def _hr_more42(rest):
    """The first line after the Harden-Runner block that still belongs to its step, or None.

    The step ends where the next line of code is indented less than its keys (8): the next `- `
    step, or the job's next key. Blank and comment lines between say nothing (a blank line inside
    `with:` does not end it in YAML).
    """
    for ln in rest.splitlines():
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        return ln.strip() if len(ln) - len(ln.lstrip(" ")) >= 8 else None
    return None


def _hr_job_bad42(name, job, job_text):
    """(what is wrong with one job's first step or None, the (sha, version) it is pinned to)."""
    if (name, job) in _HR_EXCEPT42:
        return None, None
    if _re42.search(r"^    container:", job_text, _re42.M):
        return "%s/%s: runs in a container; list it in _HR_EXCEPT42 with why" % (name, job), None
    first = _first_step42(job_text)
    m = _HR_STEP42.match(first)
    if not m:
        return "%s/%s: first step is %r" % (name, job, first.split("\n", 1)[0].strip()), None
    more = _hr_more42(first[m.end():])
    if more:
        return "%s/%s: Harden-Runner carries more than egress-policy: audit: %r" % (name, job, more), None
    return None, m.groups()


def _hr_bad42(name, text):
    """(jobs read, what is wrong, {(sha, version): [jobs]}) for one workflow's text."""
    bad, jobs, pins = [], [], {}
    for job in _jobs29(text):
        jt = _job29(text, job)
        if _re42.search(r"^    uses: ", jt, _re42.M):
            continue                       # a reusable-workflow call: no steps of its own
        jobs.append((name, job))
        why, pin = _hr_job_bad42(name, job, jt)
        bad.append(why)
        if pin:
            pins.setdefault(pin, []).append("%s/%s" % (name, job))
    bad = [b for b in bad if b]
    uses = len(_re42.findall(r"^\s*(?:- )?uses: step-security/harden-runner@", _code29(text), _re42.M))
    want = len([j for j in jobs if j not in _HR_EXCEPT42])
    if uses != want:
        bad.append("%s: %d Harden-Runner steps for %d jobs" % (name, uses, want))
    return jobs, bad, pins


def _hr_scan42(files):
    """(jobs read, what is wrong, pins) over [(name, text)]: each job, and every job on ONE pin."""
    jobs, bad, pins = [], [], {}
    for name, text in files:
        j, b, p = _hr_bad42(name, text)
        jobs += j
        bad += b
        for pin, where in p.items():
            pins.setdefault(pin, []).extend(where)
    if len(pins) > 1:
        bad.append("Harden-Runner is pinned %d ways: %s" % (len(pins), "; ".join(
            "%s %s in %s" % (s[:12], v, ", ".join(w[:3])) for (s, v), w in sorted(pins.items()))))
    return jobs, bad, pins


_hr_files42 = sorted(_glob42.glob(os.path.join(_WF42, "*.yml"))
                     + _glob42.glob(os.path.join(_WF42, "*.yaml")))
_hr_jobs42, _hr_bad_all42, _hr_pins42 = _hr_scan42(
    [(os.path.basename(_p42), open(_p42, encoding="utf-8").read()) for _p42 in _hr_files42])
check("harden-runner: every job of every workflow but deploy begins with the Harden-Runner step, "
      "SHA-pinned with its version comment, in audit mode with no other input, once, and every job "
      "on the same pin",
      not _hr_bad_all42 and len(_hr_pins42) == 1 and len(_hr_files42) >= 22 and len(_hr_jobs42) >= 30
      and set(_HR_EXCEPT42) == {("deploy.yml", "deploy")}
      and sum(len(w) for w in _hr_pins42.values())
      == len([j for j in _hr_jobs42 if j not in _HR_EXCEPT42])
      and {("deploy.yml", "deploy"), ("ci.yml", "checks"), ("zizmor.yml", "upload"),
           ("cflite_build.yml", "build"), ("scorecard.yml", "analysis"),
           ("codeql-alerts.yml", "open-alerts")} <= set(_hr_jobs42),
      repr((_hr_bad_all42[:6], sorted(_hr_pins42), len(_hr_files42), len(_hr_jobs42))))

# ...and the reader catches each way a job can get it wrong, and passes what is allowed. The pins
# below are made up: what is held is the shape, and that every job shares one.
_HR_A42, _HR_B42 = ("a" * 40, "v2.21.1"), ("b" * 40, "v2.22.0")


def _hr_step_text42(pin=_HR_A42, policy="audit"):
    """The Harden-Runner step as every job writes it, on `pin`."""
    return ("      - name: Harden Runner\n"
            "        uses: step-security/harden-runner@%s # %s\n"
            "        with:\n"
            "          egress-policy: %s\n" % (pin[0], pin[1], policy))


_HR_JOB42 = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n%s      - run: true\n"
_HR42 = _hr_step_text42()
_hr_cases42 = {
    "first": [_HR_JOB42 % _HR42],
    "comment above": [_HR_JOB42 % ("      # why it is here\n" + _HR42)],
    "a blank line after": [_HR_JOB42 % (_HR42 + "\n")],
    "missing": [_HR_JOB42 % "      - uses: actions/checkout@x\n"],
    "second": [_HR_JOB42 % ("      - uses: actions/checkout@x\n" + _HR42)],
    "block mode": [_HR_JOB42 % _hr_step_text42(policy="block")],
    "by tag": [_HR_JOB42 % _HR42.replace("@%s # %s" % _HR_A42, "@v2")],
    "no version comment": [_HR_JOB42 % _HR42.replace(" # %s" % _HR_A42[1], "")],
    "twice": [_HR_JOB42 % (_HR42 + _HR42)],
    "extra input": [_HR_JOB42 % (_HR42 + "          disable-sudo-and-containers: true\n")],
    "policy input": [_HR_JOB42 % (_HR42 + "          policy: ci-policy\n")],
    "input after a blank line": [_HR_JOB42 % (_HR42 + "\n          use-policy-store: true\n")],
    "another step key": [_HR_JOB42 % (_HR42 + "        continue-on-error: true\n")],
    "every job bumped together": [_HR_JOB42 % _hr_step_text42(_HR_B42),
                                  _HR_JOB42 % _hr_step_text42(_HR_B42)],
    "one job on another SHA": [_HR_JOB42 % _HR42, _HR_JOB42 % _hr_step_text42(_HR_B42)],
    "container": ["on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    container: ubuntu:24.04\n"
                  "    steps:\n      - run: true\n"],
    "reusable call": ["on: push\njobs:\n  a:\n    uses: ./.github/workflows/x.yml\n"],
}
_hr_seen42 = {k: bool(_hr_scan42([("t%d.yml" % i, t) for i, t in enumerate(v)])[1])
              for k, v in _hr_cases42.items()}
check("harden-runner: ...the check fails a job without it, with it later, twice, in block mode, by "
      "tag, with no version comment, with any other input or key, on a pin the other jobs do not "
      "share, or in a container, and passes a comment above it, every job bumped together, and a "
      "reusable-workflow call",
      _hr_seen42 == {"first": False, "comment above": False, "a blank line after": False,
                     "missing": True, "second": True, "block mode": True, "by tag": True,
                     "no version comment": True, "twice": True, "extra input": True,
                     "policy input": True, "input after a blank line": True,
                     "another step key": True, "every job bumped together": False,
                     "one job on another SHA": True, "container": True, "reusable call": False},
      repr(_hr_seen42))

# Dependabot proposes each Harden-Runner bump: its github-actions entry reads every workflow ("/").
_dep42 = open(os.path.join(_root, ".github", "dependabot.yml"), encoding="utf-8").read()
check("harden-runner: Dependabot's github-actions updates cover the workflows it is pinned in",
      _re42.search(r'^  - package-ecosystem: "github-actions"\n    directory: "/"\n', _dep42, _re42.M)
      is not None, "")

# What the copy says audit mode does. It is not passive (agent v0.16.3, agent.go and dnsconfig.go):
# it swaps the job's DNS for its own proxy, enforces StepSecurity's global blocklist, fetched at
# run time, and its post step prints the agent's log (each endpoint, each root command line) into
# the public job log. The first copy said it "blocks nothing", the stated reason the deploy job, which
# holds a tailnet identity, needed no thought; each place that describes it now says all three.
_dpl42 = _wf29("deploy.yml")
# deploy carries no Harden-Runner (_HR_EXCEPT42); its note, the comment block that opens its
# steps, says why in the same terms.
_dpl_hr42 = _re42.search(r"^    steps:\n((?:      #.*\n)+)", _dpl42, _re42.M)
_dpl_note42 = " ".join(ln.strip().strip("# ") for ln in _dpl_hr42.group(1).splitlines()) if _dpl_hr42 else ""
_dpl_note42 = _dpl_note42 if _dpl_note42.startswith("No Harden-Runner here") else ""
_cl42 = open(os.path.join(_root, "docs", "CHANGELOG.md"), encoding="utf-8").read()
_cl_hr42 = _re42.search(r"^  - \*Harden-Runner\*.*\n(?:    .*\n)*", _cl42, _re42.M)
_cl_hr42 = " ".join(_cl_hr42.group(0).split()) if _cl_hr42 else ""
_rd_hr42 = [ln for ln in open(os.path.join(_root, "README.md"), encoding="utf-8").read().splitlines()
            if "Harden-Runner" in ln]
_hr_copy42 = {"deploy.yml": _dpl_note42, "CHANGELOG": _cl_hr42, "README": " ".join(_rd_hr42)}
_hr_copy_bad42 = sorted(k for k, v in _hr_copy42.items()
                        if not v or _re42.search(r"blocks? (?:none|nothing)|nothing is blocked", v, _re42.I)
                        or not all(w in v for w in ("blocklist", "DNS", "public")))
check("harden-runner: the deploy job's note (why it has none), the CHANGELOG and the README say what "
      "audit mode does (the DNS proxy, StepSecurity's blocklist, the public log), and none says it "
      "blocks nothing",
      not _hr_copy_bad42, repr((_hr_copy_bad42, {k: v[:160] for k, v in _hr_copy42.items()})))

# ── zizmor: what it runs on ─────────────────────────────────────────────────────────────────────
_zz42 = _wf29("zizmor.yml")
_zz_on42 = _code29(_zz42[_zz42.find("\non:\n"):_zz42.find("\nconcurrency:")])
_zz_pr42 = _re42.search(r"^  pull_request:\n((?:    .*\n)*)", _zz_on42 + "\n", _re42.M)
_sec_on42 = _code29(_wf29("security-code.yml"))
_pi42 = {f: _re42.findall(r"    paths-ignore:\n((?:      - .*\n)+)", t)
         for f, t in (("zizmor.yml", _zz_on42), ("security-code.yml", _sec_on42))}
check("zizmor: runs on every pull request (no path filter), on pushes to main with security-code.yml's "
      "paths-ignore list, and weekly",
      _zz_pr42 is not None and not _re42.search(r"paths", _zz_pr42.group(1))
      and _re42.search(r"^  push:\n    branches: \[ main \]\n    paths-ignore:\n", _zz_on42, _re42.M)
      and _re42.search(r"^  schedule:\n    - cron: \"[0-9]+ [0-9]+ \* \* [0-6]\"", _zz_on42, _re42.M)
      and len(_pi42["zizmor.yml"]) == 1 and _pi42["zizmor.yml"] == _pi42["security-code.yml"],
      repr((_zz_on42, _pi42)))

# ── zizmor: the scan holds a read-only token; only the upload may write, and runs no tool ──────────
_zz_scan42 = _job29(_zz42, "zizmor")
_zz_up42 = _job29(_zz42, "upload")
_zz_up_uses42 = sorted({_re42.sub(r"@.*", "", u) for u in
                        _re42.findall(r"^\s+(?:- )?uses: (\S+)", _code29(_zz_up42), _re42.M)})
check("zizmor: the scan job holds only contents: read (and pull-requests: read, for its scope step) and "
      "hands zizmor that token; the upload job alone writes security events, after the scan, with "
      "GitHub's own actions and no run: step",
      _block30(_zz_scan42, "permissions", 4) == {"contents": "read", "pull-requests": "read"}
      and "GH_TOKEN: ${{ github.token }}" in _zz_scan42 and "security-events" not in _code29(_zz_scan42)
      and _block30(_zz_up42, "permissions", 4) == {"contents": "read", "security-events": "write"}
      and _re42.search(r"^    needs: zizmor$", _zz_up42, _re42.M) is not None
      and "run:" not in _code29(_zz_up42)
      and _zz_up_uses42 == ["actions/checkout", "actions/download-artifact",
                            "github/codeql-action/upload-sarif", "step-security/harden-runner"]
      and _block30(_zz42, "permissions", 0) == {"contents": "read"},
      repr((_block30(_zz_scan42, "permissions", 4), _block30(_zz_up42, "permissions", 4),
            _zz_up_uses42)))

# ── zizmor: its SARIF reaches code scanning under its own category, from the scan's artifact ──────
_sc42 = _wf29("security-code.yml")
_zz_up_cat42 = _re42.search(r"uses: github/codeql-action/upload-sarif@([0-9a-f]{40}) # \S+\n"
                            r"\s+with:\n\s+sarif_file: \$\{\{ runner\.temp \}\}/zizmor/zizmor\.sarif\n"
                            r"\s+category: zizmor\n", _zz_up42)
_zz_art42 = (_re42.findall(r"uses: actions/upload-artifact@[0-9a-f]{40} # \S+\n\s+with:\n"
                           r"\s+name: (\S+)\n\s+path: zizmor\.sarif\n", _zz_scan42),
             _re42.findall(r"uses: actions/download-artifact@[0-9a-f]{40} # \S+\n\s+with:\n"
                           r"\s+name: (\S+)\n\s+path: \$\{\{ runner\.temp \}\}/zizmor\n", _zz_up42))
check("zizmor: the upload sends the scan's own SARIF artifact to code scanning as category zizmor, "
      "with the upload-sarif commit security-code.yml pins",
      _zz_up_cat42 is not None and _zz_art42 == (["zizmor-sarif"], ["zizmor-sarif"])
      and {_zz_up_cat42.group(1)} == set(_re42.findall(r"github/codeql-action/upload-sarif@([0-9a-f]{40})",
                                                         _sc42)),
      repr((_zz_up_cat42 and _zz_up_cat42.group(0), _zz_art42)))

# ── zizmor: installed from its hash lockfile, on the Python that lockfile was compiled for ──────────
_zz_lock42 = open(os.path.join(_root, ".github", "ci-requirements", "zizmor.txt"), encoding="utf-8").read()
_zz_lock_py42 = _re42.search(r"^# This file is autogenerated by pip-compile with [pP]ython (\d+\.\d+)$",
                             _zz_lock42, _re42.M)
_zz_py42 = _re42.search(r"python-version:\s*[\x22']?([0-9.]+)", _zz_scan42)
_zz_pip42 = " ".join(" ".join(_re42.findall(r"pip install[^\n]*(?:\n\s+(?!- )\S[^\n]*)*",
                                            _code29(_zz_scan42))).split())
check("zizmor: the scan installs zizmor.txt alone (one pinned zizmor, hash-checked, wheels only), on "
      "the Python its pip-compile header names",
      _re42.search(r"^zizmor==\d+\.\d+\.\d+ \\\n(    --hash=sha256:[0-9a-f]{64}( \\)?\n)+\Z",
                   _code29(_zz_lock42).strip("\n") + "\n") is not None
      and _zz_lock_py42 is not None and _zz_py42 is not None
      and _zz_lock_py42.group(1) == _zz_py42.group(1)
      and _zz_pip42 == "pip install --quiet --require-hashes --only-binary :all: "
                       "-r .github/ci-requirements/zizmor.txt",
      repr((_zz_pip42, _zz_py42 and _zz_py42.group(1), _zz_lock_py42 and _zz_lock_py42.group(1))))

# ── zizmor: the scan step, run ────────────────────────────────────────────────────────────────────
# A stand-in zizmor records its argv, prints the log lines and SARIF it is given, and exits as told;
# the step runs in a tree holding two workflow files.
_ZZ_STEP42 = "zizmor (SARIF)"
_zz_run42 = _wf_run_block(_zz42, _ZZ_STEP42) if "- name: " + _ZZ_STEP42 in _zz42 else ""
_ZZ_STUB42 = """#!/bin/bash
[ "$1" = --version ] && { echo "zizmor 0.0.0-stand-in"; exit 0; }
printf '%s\\n' "$@" > "$ZZ_ARGV"
printf '%b' "$ZZ_LOG" >&2
printf '%s' "$ZZ_SARIF"
exit "${ZZ_RC:-0}"
"""
_SARIF42 = _json42.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "zizmor"}},
                                                         "results": []}]})
_SARIF1_42 = _json42.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "zizmor"}},
                                                          "results": [{"ruleId": "zizmor/x", "locations": [
                                                              {"physicalLocation": {"artifactLocation": {
                                                                  "uri": ".github/workflows/a.yml"},
                                                                  "region": {"startLine": 3}}}]}]}]})
_LOG2_42 = (" INFO audit: zizmor: \U0001f308 completed ./.github/workflows/a.yml\\n"
            " INFO audit: zizmor: \U0001f308 completed ./.github/workflows/b.yml\\n"
            " INFO audit: zizmor: \U0001f308 completed ./.github/dependabot.yml\\n")
_sb42 = _tf42.mkdtemp(prefix="lgsm-unit-p42-")
try:
    os.makedirs(os.path.join(_sb42, "tree", ".github", "workflows"))
    os.makedirs(os.path.join(_sb42, "bin"))
    for _n42 in ("a.yml", "b.yml"):
        with open(os.path.join(_sb42, "tree", ".github", "workflows", _n42), "w") as _fh42:
            _fh42.write("on: push\n")
    with open(os.path.join(_sb42, "bin", "zizmor"), "w") as _fh42:
        _fh42.write(_ZZ_STUB42)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in this part runs itself
    os.chmod(os.path.join(_sb42, "bin", "zizmor"), 0o700)

    def _zz_step42(log, sarif, rc=0):
        """(rc, stdout+stderr, summary, argv) of the step run with the stand-in."""
        if not _zz_run42.strip():
            return 99, "no such step", "", []
        paths = {k: os.path.join(_sb42, k) for k in ("summary", "argv")}
        for _pp in paths.values():
            open(_pp, "w").close()
        p = _sp42.run(["bash", "-c", _zz_run42], capture_output=True, text=True,  # nosec B603 B607 - the workflow's own step
                      cwd=os.path.join(_sb42, "tree"), timeout=60,
                      env=dict(os.environ, PATH=os.path.join(_sb42, "bin") + os.pathsep + os.environ["PATH"],
                               GITHUB_STEP_SUMMARY=paths["summary"], ZZ_ARGV=paths["argv"],
                               ZZ_LOG=log, ZZ_SARIF=sarif, ZZ_RC=str(rc)))
        return (p.returncode, p.stdout + p.stderr, open(paths["summary"]).read(),
                open(paths["argv"]).read().split())

    _zr42 = {
        "clean": _zz_step42(_LOG2_42, _SARIF42),
        "finding": _zz_step42(_LOG2_42, _SARIF1_42),
        "one unread": _zz_step42(_LOG2_42.split("\\n", 1)[1], _SARIF42),
        "no run": _zz_step42(_LOG2_42, _json42.dumps({"version": "2.1.0", "runs": []})),
        "failed": _zz_step42(_LOG2_42, "", rc=1),
    }
    check("zizmor: the scan runs pedantic, strict, configless SARIF over the checkout, and passes when it "
          "audited every workflow file (a finding passes too: code scanning gates it)",
          _zr42["clean"][0] == 0 and _zr42["finding"][0] == 0
          and "audited 2 of 2 workflow files; 0 finding(s)" in _zr42["clean"][1]
          and "`zizmor/x` .github/workflows/a.yml:3" in _zr42["finding"][2]
          and _zr42["clean"][3] == ["--persona=pedantic", "--strict-collection", "--no-config",
                                    "--color=never", "--format=sarif", "."],
          repr({k: (v[0], v[1][-300:], v[3]) for k, v in _zr42.items() if k in ("clean", "finding")}))
    check("zizmor: ...and FAILS when it audited fewer workflow files than exist, wrote no run, or "
          "could not run",
          _zr42["one unread"][0] == 1 and "audited 1 of the 2 workflow files" in _zr42["one unread"][1]
          and _zr42["no run"][0] == 1 and _zr42["failed"][0] == 1
          and "zizmor did not complete" in _zr42["failed"][1],
          repr({k: (v[0], v[1][-300:]) for k, v in _zr42.items()}))
finally:
    _shutil42.rmtree(_sb42, ignore_errors=True)

# ── the alert gates know every uploader: three lists, one set of workflows ──────────────────────────
_CSA42_PATH = os.path.join(_root, ".github", "scripts", "code_scanning_analyses.py")
_spec42 = _ilu42.spec_from_file_location("code_scanning_analyses_p42", _CSA42_PATH)
_CSA42 = _ilu42.module_from_spec(_spec42)
_spec42.loader.exec_module(_CSA42)
_cqa42 = _wf29("codeql-alerts.yml")
_cqa_trig42 = _re42.search(r"^    workflows: \[ (.*) \]$", _cqa42, _re42.M)
_cqa_trig42 = sorted(_re42.findall(r'"([^"]+)"', _cqa_trig42.group(1))) if _cqa_trig42 else []
_cqa_wait42 = _re42.search(r"^\s+for wf in ([^;]+); do$", _cqa42, _re42.M)
_cqa_wait42 = sorted(_cqa_wait42.group(1).split()) if _cqa_wait42 else []
_up_files42 = sorted(set(_CSA42.CATEGORIES.values()))
_up_names42 = sorted(_re42.search(r"^name: (.+)$", _wf29(f), _re42.M).group(1).strip()
                     for f in _up_files42)
check("code-scanning gates: the categories' workflows are exactly the ones codeql-alerts.yml is "
      "triggered by and waits for, zizmor's included",
      _CSA42.CATEGORIES.get("zizmor") == "zizmor.yml"
      and _up_files42 == ["codeql.yml", "security-code.yml", "zizmor.yml"]
      and _cqa_wait42 == _up_files42 and _cqa_trig42 == _up_names42,
      repr((_up_files42, _cqa_wait42, _up_names42, _cqa_trig42)))

# ── every accepted zizmor finding, named here, with its reason beside it ─────────────────────────
# zizmor runs with --no-config, so an inline `# zizmor: ignore[<rule>] <reason>` is the only way to
# accept a finding. Each is listed here, so a new one shows in review as a change to this test.
# zizmor reads more than the workflows (its --collect: action.yml anywhere, .github/dependabot.yml,
# the pre-commit files) and honours an ignore in each, so every YAML file in the repository is read:
# the tree part03 walks, which on a checkout is `git ls-files`.
_WFP42 = ".github/workflows/"
_ZZ_IGNORES42 = {
    (_WFP42 + "codacy-coverage.yml", "dangerous-triggers"),   # main's copy runs; the report is untrusted data
    (_WFP42 + "codeql-alerts.yml", "dangerous-triggers"),     # judges main only; runs nothing of the trigger's
    (_WFP42 + "deploy.yml", "dangerous-triggers"),            # a push to main, proved on main's first parents
    (_WFP42 + "cflite_build.yml", "concurrency-limits"),      # a cancelled build on main's head is a failure
    (_WFP42 + "cflite_batch.yml", "concurrency-limits"),      # its check lands on main's head
    (_WFP42 + "cflite_cron.yml", "concurrency-limits"),       # its check lands on main's head
    (_WFP42 + "cflite_cleanup.yml", "concurrency-limits"),    # its check lands on main's head
    (_WFP42 + "sonar-main-issues.yml", "concurrency-limits"),  # its check lands on main's head
}
_zz_yaml42 = sorted(_f for _f in _cls_files42 if _f.endswith((".yml", ".yaml")))
_zz_ign42, _zz_ign_bad42 = set(), []
for _f42 in _zz_yaml42:
    for _ln42 in open(os.path.join(_root, _f42), encoding="utf-8").read().splitlines():
        # Rule names only: the workflows' prose writes the form as `ignore[<rule>]`, which is not one.
        _m42 = _re42.search(r"#\s*zizmor\s*:\s*ignore\[([a-z0-9][a-z0-9, -]*)\](.*)$", _ln42)
        if not _m42:
            continue
        if len(_m42.group(2).strip()) < 25:
            _zz_ign_bad42.append("%s: no reason: %s" % (_f42, _ln42.strip()))
        _zz_ign42 |= {(_f42, _r.strip()) for _r in _m42.group(1).split(",")}
_zz_cfg42 = [c for c in (".github/zizmor.yml", ".github/zizmor.yaml", "zizmor.yml", "zizmor.yaml")
             if os.path.exists(os.path.join(_root, c))]
_zz_wf_read42 = [os.path.relpath(_p, _root).replace(os.sep, "/") for _p in _hr_files42]
check("zizmor: every accepted finding, in any file zizmor reads (the workflows, dependabot.yml, any "
      "action.yml), is an inline ignore named here, with a reason, and no zizmor config file exists "
      "to switch a rule off",
      _zz_ign42 == _ZZ_IGNORES42 and not _zz_ign_bad42 and not _zz_cfg42
      and ".github/dependabot.yml" in _zz_yaml42 and set(_zz_wf_read42) <= set(_zz_yaml42),
      repr((sorted(_zz_ign42 ^ _ZZ_IGNORES42), _zz_ign_bad42, _zz_cfg42, len(_zz_yaml42))))
