"""Part 50 of the unit suite: a documentation-only pull request skips the heavy checks.

Every Actions check a pull request must pass runs on every pull request, unfiltered (a required
check whose workflow did not run holds the pull request forever), so a README edit ran the whole
matrix, coverage, CodeQL, Bandit, Semgrep, pip-audit, Lighthouse and the rest. Each of those jobs
now runs .github/scripts/pr_scope.py right after its checkout and skips its later STEPS when the
pull request changes only documentation; the job still concludes success under its own name.

Held here:
* the script: what counts as documentation (the push paths-ignore list, held equal to the
  workflows' and to the panel's update gate), and that it FAILS OPEN — not a pull request, a list
  it cannot read or that is not the whole list, a head that moved, an empty list, bad input: all
  "not docs-only". Run as a program against a stand-in gh, as the jobs run it.
* the wiring: in every scoped job the scope step follows the checkout, every later step is gated
  on `docs_only != 'true'` (so a missing or garbled answer runs it), nothing is gated at job level,
  and the job may read the pull request's files. Every workflow a pull request runs is either
  scoped or named as always running in full.
* what still runs: Gitleaks and Dependency Review untouched; the unit suite on one CI leg (it reads
  README.md, SECURITY.md, the CHANGELOG and VERSIONS.md); the PR alert gate passes a docs-only pull
  request by a step that says so and reads no alert, while its wait and its judgement stay gated.

HOW IT RUNS. The workflows are read as TEXT with part29's helpers (CI has no YAML parser). The
script runs in a subprocess with a stand-in `gh` first on PATH; nothing touches the network.
"""
import importlib.util as _ilu50
import json as _json50
import os
import re as _re50
import shutil as _shutil50
import subprocess as _sp50  # nosec B404 - runs this repository's own script against a stand-in gh
import sys
import tempfile as _tf50

from unit.part01 import check
from unit.part05 import _root
from unit.part29 import _code29, _job29, _name29, _steps29, _wf29
from panel.ops import system_ops as _so50  # noqa: E402

_PS50_PATH = os.path.join(_root, ".github", "scripts", "pr_scope.py")
_spec50 = _ilu50.spec_from_file_location("pr_scope_p50", _PS50_PATH)
PS = _ilu50.module_from_spec(_spec50)
_spec50.loader.exec_module(PS)

# ── 1. what counts as documentation: one list, three places ─────────────────────────────────────
_ci50 = _wf29("ci.yml")
_push_ign50 = _re50.search(r"^  push:\n    branches: \[ main \]\n    paths-ignore:\n((?:      - .*\n)+)",
                           _code29(_ci50) + "\n", _re50.M)
_push_list50 = _re50.findall(r"^      - '([^']+)'$", _push_ign50.group(1), _re50.M) if _push_ign50 else []
check("docs-only: the script's list is ci.yml's push paths-ignore list (which part14 holds equal to "
      "codeql.yml's, security-code.yml's and zizmor.yml's)",
      bool(_push_list50) and sorted(PS.DOCS_ONLY_PATTERNS) == sorted(_push_list50),
      repr((PS.DOCS_ONLY_PATTERNS, _push_list50)))
_samples50 = ["README.md", "a/b/c.md", ".github/SECURITY.md", "docs/x.png", "docs/sub/y.py", "LICENSE",
              ".gitignore", ".gitattributes", ".editorconfig", "app.py", "docsx/y.py", "LICENSE.txt",
              "sub/LICENSE", "sub/.gitignore", ".github/workflows/ci.yml", "README.MD", "README.md.py",
              "tools/panel-helper", "requirements.txt", "static/vendor/VERSIONS.md", "doc/x.md", "docs"]
_disagree50 = [p for p in _samples50 if PS.is_doc(p) != _so50._ci_path_ignored(p)]
check("docs-only: ...and the files in it, and what it matches path by path, are the panel update "
      "gate's (system_ops._ci_path_ignored)",
      PS.DOCS_ONLY_FILES == frozenset(_so50._CI_PATHS_IGNORED_FILES) and not _disagree50
      and PS.is_doc("README.md") and not PS.is_doc("app.py"), repr(_disagree50))
check("docs-only: every path must be documentation, and no paths is not documentation",
      PS.docs_only(["README.md", "docs/a.png", "LICENSE"]) and not PS.docs_only([])
      and not PS.docs_only(["README.md", "app.py"]) and not PS.docs_only(["", "README.md"])
      and not PS.docs_only([None]), "")

# ── 2. the script, run as the jobs run it, against a stand-in gh ────────────────────────────────
_H50 = "a" * 40
_sb50 = _tf50.mkdtemp(prefix="prscope50-")
try:
    _bin50 = os.path.join(_sb50, "bin")
    os.makedirs(_bin50)
    with os.fdopen(os.open(os.path.join(_bin50, "gh"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700),
                   "w") as _fh:
        # Logs each call; answers the pull request (head, changed_files) and its file list from the
        # environment; fails either on request.
        _fh.write('#!/bin/bash\necho "$*" >> "$GH_LOG"\n'
                  'case "$*" in\n'
                  '  *"/files"*) [ -n "${FILES_FAIL:-}" ] && { echo boom >&2; exit 1; }\n'
                  '              printf "%s" "$FILES" ;;\n'
                  '  *) [ -n "${META_FAIL:-}" ] && { echo boom >&2; exit 1; }\n'
                  '     printf \'{"head": {"sha": "%s"}, "changed_files": %s}\' "$HEAD" "$COUNT" ;;\n'
                  'esac\n')

    def _rows50(*pairs):
        return "".join(_json50.dumps([n, o]) + "\n" for n, o in pairs)

    def _ps50(files="", count=None, head=_H50, event="pull_request", pr="7", sha=_H50, **extra):
        """Run the script; return (docs_only output lines, stdout, gh calls)."""
        _d = _tf50.mkdtemp(dir=_sb50)
        _out, _log = os.path.join(_d, "out"), os.path.join(_d, "log")
        _n = count if count is not None else sum(1 for ln in files.splitlines() if ln.strip())
        _env = dict(os.environ, PATH=_bin50 + os.pathsep + os.environ.get("PATH", ""),
                    GITHUB_OUTPUT=_out, GH_LOG=_log, FILES=files, COUNT=str(_n), HEAD=head)
        _env.update(extra)
        _p = _sp50.run([sys.executable, _PS50_PATH, "--event", event, "--repo", "o/r", "--pr", pr,  # nosec B603 - fixed argv
                        "--head-sha", sha], capture_output=True, text=True, timeout=60, env=_env,
                       check=False)
        _read = (lambda f: open(f).read() if os.path.exists(f) else "")
        return (_p.returncode, _read(_out).splitlines(), _p.stdout + _p.stderr, _read(_log))

    _docs50 = _rows50(("README.md", None), ("docs/a.png", None), ("LICENSE", None))
    _r = _ps50(_docs50)
    check("pr_scope: a pull request changing only README.md, docs/ and LICENSE is docs-only, said "
          "as a notice (positive control)",
          _r[0] == 0 and _r[1] == ["docs_only=true"] and "::notice::DOCS-ONLY" in _r[2]
          and "repos/o/r/pulls/7/files?per_page=100" in _r[3] and "--paginate" in _r[3]
          and "repos/o/r/pulls/7\n" in _r[3], repr(_r))
    _cases50 = {
        "a code file too": _ps50(_rows50(("README.md", None), ("app.py", None))),
        "code renamed to docs": _ps50(_rows50(("README.md", None), ("docs/old.md", "panel/old.py"))),
        "file list unreadable": _ps50(_docs50, FILES_FAIL="1"),
        "pull request unreadable": _ps50(_docs50, META_FAIL="1"),
        "not the whole list": _ps50(_docs50, count=4),
        "head moved on": _ps50(_docs50, head="b" * 40),
        "no files": _ps50(""),
        "list garbled": _ps50("README.md\n", count=1),
    }
    check("pr_scope: a code file, a code file renamed into docs/, an unreadable or partial list, a "
          "head that moved on, no files, or a garbled list is NOT docs-only (everything runs)",
          all(_v[0] == 0 and _v[1] == ["docs_only=false"] and "everything runs" in _v[2]
              for _v in _cases50.values())
          and "app.py" in _cases50["a code file too"][2]
          and "panel/old.py" in _cases50["code renamed to docs"][2]
          and "read 3 files of the 4" in _cases50["not the whole list"][2]
          and "not this run's" in _cases50["head moved on"][2],
          repr({_k: _v[1:3] for _k, _v in _cases50.items()}))
    _quiet50 = {"push": _ps50(_docs50, event="push"), "schedule": _ps50(_docs50, event="schedule"),
                "manual": _ps50(_docs50, event="workflow_dispatch"),
                "bad number": _ps50(_docs50, pr="7; true"), "no number": _ps50(_docs50, pr=""),
                "short sha": _ps50(_docs50, sha="abc")}
    check("pr_scope: anything but a pull request, or one named with a bad number or commit, runs "
          "everything without asking gh",
          all(_v[0] == 0 and _v[1] == ["docs_only=false"] and _v[3] == "" for _v in _quiet50.values()),
          repr({_k: _v[1:] for _k, _v in _quiet50.items()}))
    check("pr_scope: it reads the pull request's WHOLE file list at its head, never a commit's (a "
          "docs-only first commit followed by a code commit is a code change)",
          "/commits" not in open(_PS50_PATH, encoding="utf-8").read()
          and _cases50["a code file too"][3].count("/files") == 1, "")
finally:
    _shutil50.rmtree(_sb50, ignore_errors=True)

# SonarCloud's pythonsecurity:S8705 (command argument injection) does not take a regex match as a
# sanitiser: the slug gh is handed is rebuilt character by character from a constant table, and the
# number through int(), so no text from the command line reaches gh's argv. gh's flags come before
# `--`, the path after it.
_slug_in50 = "".join(["Own", "er/re", "po.x"])
_rp50 = open(_PS50_PATH, encoding="utf-8").read()
_rp50 = _rp50[_rp50.index("def read_paths("):_rp50.index("\ndef ", _rp50.index("def read_paths(") + 1)]
check("pr_scope: the slug gh is given is REBUILT, not the argument's own text, and anything that is not "
      "an owner/name slug is refused",
      PS.safe_slug(_slug_in50) == _slug_in50 and PS.safe_slug(_slug_in50) is not _slug_in50
      and all(PS.safe_slug(_b) is None for _b in ("o/r;x", "a b/c", "", None, "o/r\n", "-o/r", "o/r/x"))
      and '% (slug, number)' in _rp50 and "% (repo" not in _rp50
      and 0 <= _rp50.find('"--jq"') < _rp50.find('"--",', _rp50.find('"--jq"'))
      < _rp50.find('"repos/%s/pulls/%d/files'),
      repr(PS.safe_slug(_slug_in50)))

# ── 3. the wiring: every scoped job ─────────────────────────────────────────────────────────────
_SCOPED50 = {
    "ci.yml": ("checks", "coverage", "js-coverage", "gamedig-lockfile"),
    "codeql.yml": ("analyze", "pr-alerts"),
    "security-code.yml": ("dependency-audit", "sast-bandit", "sast-semgrep"),
    "lighthouse.yml": ("lighthouse",),
    "complexity.yml": ("complexity",),
    "sonar-new-issues.yml": ("sonar-new-issues",),
    "actionlint.yml": ("actionlint",),
    "zizmor.yml": ("zizmor",),
}
# Run in full on every pull request: a secret can be pasted into a README (Gitleaks); Dependency
# Review takes seconds; the fuzzers have their own allowlists, which no documentation path is in.
_ALWAYS50 = {"security.yml", "dependency-review.yml", "fuzz.yml", "cflite_pr.yml"}
_RUN50 = "steps.scope.outputs.docs_only != 'true'"
_DOCS50 = "steps.scope.outputs.docs_only == 'true'"
_SCOPE_CMD50 = ('python3 .github/scripts/pr_scope.py --event "$EVENT" --repo "$GITHUB_REPOSITORY" '
                '--pr "$PR" --head-sha "$HEAD_SHA"')
_SCOPE_ENV50 = ("EVENT: ${{ github.event_name }}", "PR: ${{ github.event.pull_request.number }}",
                "HEAD_SHA: ${{ github.event.pull_request.head.sha }}", "GH_TOKEN: ${{ github.token }}")
# The steps that run ONLY on a docs-only pull request, and the ones a docs-only pull request runs
# anyway, by (workflow, job, step): each with the reason it is not gated like the rest.
_DOCS_STEPS50 = {
    ("ci.yml", "checks", "Documentation-only pull request, so the unit suite alone (it reads the docs)"),
    ("ci.yml", "coverage", "Record that a documentation-only pull request measured nothing"),
    ("codeql.yml", "pr-alerts",
     "Documentation-only pull request, so nothing was analysed and there is nothing to judge"),
}
_UNGATED50 = {
    # Uploads coverage.xml or, on a docs-only pull request, docs-only.txt (codacy-coverage.yml).
    ("ci.yml", "coverage", "Upload the report"): None,
    # Its `if` needs the analyze step's success, which a docs-only pull request skips.
    ("codeql.yml", "analyze", "Upload the results to code scanning"): "steps.analyze.outcome == 'success'",
}


def _name50(step):
    """A step's name, or the action it uses (without the pin) when it has none."""
    m = _re50.search(r"uses: ([^@\s]+)", step)
    return _name29(step) or (m.group(1) if m else "")


def _if50(step):
    """The step's `if:` expression, with any ${{ }} wrapper removed ("" when it has none)."""
    m = _re50.search(r"^(?:- | {8})if: (.*)$", step, _re50.M)
    e = m.group(1).strip() if m else ""
    return e[3:-2].strip() if e.startswith("${{") and e.endswith("}}") else e


def _head_bad50(text):
    """What is wrong with a job's own keys: gated at job level, or unable to list the files."""
    head = text[:text.find("\n    steps:\n")]
    bad = []
    if "docs_only" in head.replace("docs_only: ${{ steps.scope.outputs.docs_only }}", ""):
        bad.append("gated at job level (a skipped job reports under the wrong name)")
    if not _re50.search(r"^    permissions:\n(?:      .*\n)*?      pull-requests: read", head + "\n",
                        _re50.M):
        bad.append("cannot read the pull request's files")
    if "docs_only == 'false'" in text or "docs_only != 'false'" in text:
        bad.append("compares with 'false': a missing answer would skip the checks")
    return bad


def _scope_at50(steps, names):
    """The scope step's index when it directly follows the checkout (Harden Runner first), else None."""
    sc = next((i for i, s in enumerate(steps) if _re50.search(r"^ {8}id: scope$", s, _re50.M)), None)
    co = next((i for i, s in enumerate(steps) if "uses: actions/checkout@" in s), None)
    ok = sc is not None and co is not None and sc == co + 1 and names[:1] == ["Harden Runner"]
    return sc if ok else None


def _step_bad50(key, cond):
    """What is wrong with one step after the scope step, given its `if:`; "" when nothing is."""
    if key in _DOCS_STEPS50:
        return "" if _DOCS50 in cond else "not gated to docs-only pull requests"
    if key in _UNGATED50:
        want = _UNGATED50[key]
        ok = not cond if want is None else want in cond
        return "" if ok else "its exemption's reason no longer holds (%r)" % cond
    gated = _RUN50 in [c.strip() for c in _re50.split(r"&&|\|\|", cond)]
    if not gated or ("||" in cond and cond != _RUN50 + " || matrix.docs"):
        return "not skipped on a docs-only pull request (if: %r)" % cond
    return ""


def _wiring50(wf, job):
    """What is wrong with one scoped job's wiring, as a list of reasons."""
    text = _code29(_job29(_wf29(wf), job))
    if not text:
        return ["no such job"]
    bad = _head_bad50(text)
    steps = _steps29(text)
    names = [_name50(s) for s in steps]
    sc = _scope_at50(steps, names)
    if sc is None:
        return bad + ["the scope step does not directly follow the checkout: %r" % names]
    one = " ".join(steps[sc].split())
    if _SCOPE_CMD50 not in one or not all(e in steps[sc] for e in _SCOPE_ENV50) or _if50(steps[sc]):
        bad.append("the scope step is not the script, run with this run's pull request and head")
    for step, name in zip(steps[sc + 1:], names[sc + 1:]):
        why = _step_bad50((wf, job, name), _if50(step))
        if why:
            bad.append("%s: %s" % (name, why))
    return bad


_wiring_bad50 = {"%s:%s" % (wf, j): _wiring50(wf, j) for wf, jobs in _SCOPED50.items() for j in jobs}
check("docs-only wiring: in every scoped job the scope step follows the checkout, runs the script for "
      "this run's pull request and head, and every later step is skipped only on `docs_only != "
      "'true'` (a missing answer runs it), never at job level",
      not any(_wiring_bad50.values()), repr({k: v for k, v in _wiring_bad50.items() if v}))
_zz50 = _code29(_job29(_wf29("zizmor.yml"), "upload"))
_zz_steps50 = _steps29(_zz50)
check("docs-only wiring: zizmor's upload job takes the scan job's answer, and skips every step after "
      "Harden Runner on it (it never looks for a SARIF that was not made)",
      "docs_only: ${{ steps.scope.outputs.docs_only }}" in _code29(_job29(_wf29("zizmor.yml"), "zizmor"))
      and len(_zz_steps50) == 4 and not _if50(_zz_steps50[0])
      and all(_if50(s) == "needs.zizmor.outputs.docs_only != 'true'" for s in _zz_steps50[1:]),
      repr([_if50(s) for s in _zz_steps50]))
_pr_wfs50 = sorted(os.path.basename(f) for f in os.listdir(os.path.join(_root, ".github", "workflows"))
                   if _re50.search(r"^  pull_request:", _code29(_wf29(f)).split("\njobs:")[0], _re50.M))
_wf_calls50 = {f: "pr_scope.py" in _wf29(f) for f in _pr_wfs50}
check("docs-only wiring: every workflow a pull request runs is scoped here or named as always running "
      "in full, and those named never call the script",
      set(_pr_wfs50) == set(_SCOPED50) | _ALWAYS50
      and all(_wf_calls50[f] for f in _SCOPED50) and not any(_wf_calls50[f] for f in _ALWAYS50),
      repr(_wf_calls50))

# ── 4. what a docs-only pull request still runs ─────────────────────────────────────────────────
_gl50 = _code29(_job29(_wf29("security.yml"), "secret-scan"))
_gl_on50 = _code29(_wf29("security.yml")).split("\njobs:")[0]
check("docs-only: Gitleaks scans every pull request in full (no path filter, no step gated), since a "
      "secret pasted into a README is still a secret",
      "docs_only" not in _wf29("security.yml") and _gl50 and "Secret scanning (Gitleaks)" in _gl50
      and not _re50.search(r"^ {4,8}if:", _gl50, _re50.M)
      and _re50.search(r"^  pull_request:\n    branches: \[ main \]\n(?!    paths)", _gl_on50 + "\n",
                       _re50.M) is not None, _gl50[:200])
check("docs-only: Dependency Review is not scoped either (it takes seconds)",
      "docs_only" not in _wf29("dependency-review.yml"), "")
_checks50 = _code29(_job29(_ci50, "checks"))
_cs50 = {_name50(s): _if50(s) for s in _steps29(_checks50)}
_docs_rows50 = _re50.findall(r"^ {12}docs: true\b", _checks50, _re50.M)
_unit50 = next((s for s in _steps29(_checks50) if _name29(s).startswith("Documentation-only")), "")
check("docs-only: one CI leg still runs the unit suite on a docs-only pull request, set up as usual "
      "(its checks read README.md, SECURITY.md, the CHANGELOG and VERSIONS.md)",
      len(_docs_rows50) == 1
      and _if50(_unit50) == _DOCS50 + " && matrix.docs" and "run: python tests/unit_test.py" in _unit50
      and _cs50.get("Install dependencies") == _RUN50 + " || matrix.docs"
      and sum(1 for k, v in _cs50.items() if v == _RUN50 + " || matrix.docs") == 2,
      repr(_cs50))
_unit_reads50 = [f for f in ("part06.py", "part37.py", "part42.py")
                 if "README.md" in open(os.path.join(_root, "tests", "unit", f), encoding="utf-8").read()
                 or "VERSIONS.md" in open(os.path.join(_root, "tests", "unit", f), encoding="utf-8").read()]
check("docs-only: ...which is needed, because the unit suite does read the documentation",
      len(_unit_reads50) >= 2, repr(_unit_reads50))
_cov50 = _code29(_job29(_ci50, "coverage"))
_cov_up50 = next((s for s in _steps29(_cov50) if _name29(s) == "Upload the report"), "")
_cc50 = _wf29("codacy-coverage.yml")
check("docs-only: the coverage job leaves docs-only.txt in its artifact instead of a report, which is "
      "the file codacy-coverage.yml reads as the reason there is none",
      'echo "documentation-only pull request, so nothing was measured" > docs-only.txt' in _cov50
      and "            docs-only.txt\n" in _cov_up50 + "\n" and 'REPORT_DIR}/docs-only.txt' in _cc50
      and '[ "${WR_EVENT}" = "pull_request" ]' in _cc50, _cov_up50[-200:])
_pa50 = _code29(_job29(_wf29("codeql.yml"), "pr-alerts"))
_pa_steps50 = {_name29(s): s for s in _steps29(_pa50)}
_pa_docs50 = _pa_steps50.get(
    "Documentation-only pull request, so nothing was analysed and there is nothing to judge", "")
check("docs-only: the PR alert gate passes a docs-only pull request by a step that says so and reads "
      "nothing, and waits and judges on any other",
      _pa_docs50 and "gh " not in _pa_docs50 and "code-scanning/" not in _pa_docs50
      and "code_scanning_analyses" not in _pa_docs50
      and "GITHUB_STEP_SUMMARY" in _pa_docs50 and "::notice::documentation-only" in _pa_docs50
      and _if50(_pa_steps50.get("Wait for this merge commit's analysis in every category", "")) == _RUN50
      and _if50(_pa_steps50.get("Judge refs/pull/<n>/merge", "")) == _RUN50,
      repr({k: _if50(v) for k, v in _pa_steps50.items()}))
