"""CI: coverage, js coverage and Lighthouse skip a pull request that changes nothing they measure.

.github/scripts/pr_scope.py decided only "documentation-only". With --job it also decides, for one job,
whether every path a pull request changes is on that job's list of paths that cannot change what it
measures (JOB_IRRELEVANT): a workflow-only or CI-tool-only pull request ran all three, about forty
runner-minutes, for nothing. The job still runs under its own name and passes, as a required check
must. Anything not on a list runs the job (fail open). These checks hold the lists, the fail-open
cases and the wiring in the workflows.
"""
import importlib.util as _ilu169
import os
import re as _re169
import tempfile as _tf169

from unit.part01 import _root, check, eq

_spec169 = _ilu169.spec_from_file_location("pr_scope169", os.path.join(_root, ".github", "scripts", "pr_scope.py"))
_ps169 = _ilu169.module_from_spec(_spec169)
_spec169.loader.exec_module(_ps169)

# ── the lists: what each job skips for, and what it never skips for ─────────────────────────────
_CASES169 = [
    # (path, coverage skips, js coverage skips, lighthouse skips)
    ("README.md", True, True, True),
    ("docs/CHANGELOG.md", True, True, True),
    (".github/workflows/zizmor.yml", True, True, True),
    (".github/workflows/ci.yml", False, False, True),            # its own workflow runs the job
    (".github/workflows/lighthouse.yml", True, True, False),
    (".github/ci-requirements/zizmor.txt", True, True, True),
    (".github/ci-requirements/coverage.txt", False, True, True),  # coverage installs it
    (".github/ci-requirements-checks/checks.txt", True, True, True),
    (".github/dependabot.yml", True, True, True),
    (".semgrepignore", True, True, True),
    ("tools/gamedig/package-lock.json", True, True, True),
    ("panel/install/requirements.in", True, True, True),
    ("panel/install/requirements.txt", False, False, False),     # what the panel installs
    ("tests/unit/part01.py", False, True, True),                  # coverage runs the suites
    ("tools/js_coverage/run.py", False, False, True),
    ("tools/nosudo_runner.py", False, False, True),               # js coverage serves the panel under it
    ("tools/lhci_serve.py", False, True, False),
    ("tools/lhci-login.js", False, True, False),
    (".github/lighthouserc.json", True, True, False),            # Lighthouse's own config
    ("install.sh", False, True, True),
    ("panel/install/recover.sh", False, True, True),
    ("panel/static/js/panel.js", False, False, False),
    ("panel/templates/base.html", False, False, False),
    ("panel/ops/system_ops.py", False, False, False),
    (".github/scripts/pr_scope.py", False, False, False),          # decides what the job does
    (".github/scripts/reuse_pr_result.py", False, False, False),
    (".github/scripts/sonar_new_issues.py", False, True, True),
    ("a-new-kind-of-file.xyz", False, False, False),               # fails open
    ("new/dir/thing.py", False, False, False),
]
_JOBS169 = ("coverage", "js coverage", "lighthouse")
_wrong169 = [(p, j, want) for p, *wants in _CASES169 for j, want in zip(_JOBS169, wants)
             if _ps169.job_skips(j, [p]) is not want]
eq("pr_scope --job: each path skips exactly the jobs it cannot change, and runs the others", _wrong169, [])
check("pr_scope --job: a pull request skips a job only when EVERY path it changes is on that job's list",
      _ps169.job_skips("coverage", ["README.md", ".github/workflows/zizmor.yml"])
      and not _ps169.job_skips("coverage", ["README.md", "panel/ops/system_ops.py"])
      and not _ps169.job_skips("coverage", []), "")
check("pr_scope --job: a job with no list, or an unreadable file list, runs",
      _ps169.decide_job("checks", ["README.md"])[0] is False and _ps169.decide_job("coverage", None)[0] is False
      and _ps169.decide_job("coverage", [".github/workflows/zizmor.yml"])[0] is True, "")
eq("pr_scope: a glob's `*` stays within one name and `**` crosses directories",
   [_ps169._matches(p, ("panel/install/requirements*.in",)) for p in
    ("panel/install/requirements.in", "panel/install/requirements-bootstrap.in", "panel/install/requirements.txt",
     "panel/install/x/requirements.in")]
   + [_ps169._matches(p, ("panel/install/*.sh",)) for p in ("panel/install/recover.sh", "panel/install/sub/x.sh")]
   + [_ps169._matches(p, ("tools/**",)) for p in ("tools/a/b/c.py", "toolsx/a.py")],
   [True, True, False, False, True, False, True, False])

# ── main(): the outputs the workflows read ──────────────────────────────────────────────────────
_out169 = os.path.join(_tf169.mkdtemp(prefix="p169-"), "out")
_saved_env169 = os.environ.get("GITHUB_OUTPUT")
try:
    os.environ["GITHUB_OUTPUT"] = _out169
    _ps169.main(["--event", "push", "--job", "coverage"])
    _ps169.main(["--event", "push"])
finally:
    if _saved_env169 is None:
        os.environ.pop("GITHUB_OUTPUT", None)
    else:
        os.environ["GITHUB_OUTPUT"] = _saved_env169
with open(_out169, encoding="utf-8") as _fh169:
    _lines169 = _fh169.read().splitlines()
eq("pr_scope: with --job it writes skip as well as docs_only, and anything but a pull request runs "
   "(skip=false); without --job only docs_only", _lines169, ["docs_only=false", "skip=false", "docs_only=false"])

# ── the workflows: each listed job passes its own name and gates every step on skip ────────────
def _job169(path, job_id):
    with open(os.path.join(_root, ".github", "workflows", path), encoding="utf-8") as fh:
        text = fh.read()
    m = _re169.search(r"^  %s:\n((?:    .*\n|\s*\n)+)" % _re169.escape(job_id), text, _re169.M)
    return m.group(1) if m else ""


# `coverage` and `js coverage` are their verdict jobs' names: the jobs `coverage` and `js-coverage` run
# in parts (ci.yml), and each part asks the same question under the same name, below. The number is how
# many steps at least gate on the answer (js-coverage-verdict has three after its scope step).
_WIRING169 = {"coverage": ("ci.yml", "coverage-verdict", 5), "js coverage": ("ci.yml", "js-coverage-verdict", 3),
              "lighthouse": ("lighthouse.yml", "lighthouse", 5)}
_bad169 = []
for _name169, (_wf169, _id169, _min169) in _WIRING169.items():
    _b169 = _job169(_wf169, _id169)
    if "    name: %s\n" % _name169 not in _b169:
        _bad169.append("%s: job %s is not named %r" % (_wf169, _id169, _name169))
    if '--job "%s"' % _name169 not in _b169:
        _bad169.append("%s %s: the scope step does not pass --job %r" % (_wf169, _id169, _name169))
    if "outputs.docs_only" in _b169:
        _bad169.append("%s %s: a step still gates on docs_only" % (_wf169, _id169))
    if _b169.count("steps.scope.outputs.skip") < _min169:
        _bad169.append("%s %s: fewer than %d steps gate on skip" % (_wf169, _id169, _min169))
    if _ps169.JOB_WORKFLOW.get(_name169) != ".github/workflows/" + _wf169:
        _bad169.append("pr_scope.JOB_WORKFLOW[%r] is not %s" % (_name169, _wf169))
for _pj169, _pn169 in (("coverage", "coverage"), ("js-coverage", "js coverage")):
    _parts169 = _job169("ci.yml", _pj169)
    if '--job "%s"' % _pn169 not in _parts169 or "outputs.docs_only" in _parts169 \
            or _parts169.count("steps.scope.outputs.skip") < 5:
        _bad169.append("ci.yml %s: its parts do not ask pr_scope --job %r and gate their steps on skip" % (_pj169, _pn169))
eq("workflows: coverage, js coverage and Lighthouse each pass their own name to pr_scope --job and gate "
   "their steps on its skip; pr_scope knows each one's workflow", _bad169, [])
eq("pr_scope: every job with a list is wired in a workflow, and none other",
   sorted(_ps169.JOB_IRRELEVANT), sorted(_WIRING169))
_missing169 = [p for keep in _ps169._JOB_KEEP.values() for p in keep
               if "*" not in p and not os.path.exists(os.path.join(_root, p))]
_missing169 += [p for p in _ps169._ALWAYS_RUN if not os.path.exists(os.path.join(_root, p))]
eq("pr_scope: every file a job keeps (it installs or runs it) exists, so a rename cannot drop it from the job",
   _missing169, [])


def _installs169(block):
    """List the requirements files a job block installs (-r, --requirement, --requirement=)."""
    return sorted(set(_re169.findall(r"(?:-r|--requirement)[ =]+([\w./-]+\.(?:txt|in))", block)))


def _skipped_installs169(name, block):
    """List the files a job installs that its own --job list says cannot change what it measures."""
    return [f for f in _installs169(block) if _ps169.irrelevant_to(name, f)]


# A job that skips for a path it installs would pass a pull request that bumps only that file without ever
# installing it: each --job job's installs are read from its own block (and its parts', for a job in
# parts) and held against its list.
_PARTS_OF169 = {"coverage": "coverage", "js coverage": "js-coverage"}
_blocks169 = {n: _job169(w, j) + (_job169(w, _PARTS_OF169[n]) if n in _PARTS_OF169 else "")
              for n, (w, j, _m) in _WIRING169.items()}
_inst169 = {n: _installs169(b) for n, b in _blocks169.items()}
eq("pr_scope --job: no job skips for a requirements file it installs (read from its own workflow block)",
   {n: _skipped_installs169(n, b) for n, b in _blocks169.items()},
   {n: [] for n in _WIRING169})
check("pr_scope --job: ...the coverage job's installs were read, its coverage.txt among them (floor)",
      ".github/ci-requirements/coverage.txt" in _inst169["coverage"], repr(_inst169))
eq("pr_scope --job: (control) a file a job installs from a directory its list skips is reported",
   _skipped_installs169("coverage", "        run: pip install -r .github/ci-requirements/foo.txt "
                                    "--requirement=.github/ci-requirements/coverage.txt\n"),
   [".github/ci-requirements/foo.txt"])
