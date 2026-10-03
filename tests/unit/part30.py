"""Part 30 of the unit suite: the CI review's fixes to the fuzz workflows and the CodeQL triggers.

The adversarial review of the vendor-documentation audit found these on the integrated branch:
* E3: ClusterFuzzLite logs a failed upload and goes on, so a build, batch, prune or coverage job
  could pass having stored nothing. Each producer now ends by listing its own run's artifacts.
* E4: cflite_build.yml's concurrency group cancelled a build on main when the next merge landed,
  and "cancelled" on main's head reads as a failure to the panel's update gate and deploy.yml.
* E5: codeql.yml's and security-code.yml's concurrency groups were workflow+ref, so the Monday
  scheduled run cancelled an in-progress push run on main. The event is part of the group now.
* SEC1: the fuzz-artifact guard runs again directly before the fuzzing step reads the corpus.
* SEC2: cflite_cleanup.yml deletes foreign cifuzz-* artifacts on a schedule; it must never fail,
  because its check lands on main's head.

HOW IT RUNS. The workflows are read as TEXT, with part29's helpers: no CI job that runs this suite
installs a YAML parser (this part first imported one and was red on CI while green here, where the
dev venv has PyYAML). The last check holds every unit part to that: a third-party import must be a
package the suite's CI jobs install. Nothing runs.
"""
import ast as _ast30
import importlib.metadata as _md30
import inspect as _inspect30
import os
import re as _re30
import sys as _sys30

from unit.part01 import check
from unit.part05 import _root
from unit.part29 import _code29, _job29, _name29, _runbody29, _steps29, _wf29


def _steps30(job_text):
    return [(_name29(st), st) for st in _steps29(job_text)]


def _block30(text, key, indent):
    """The `key:` mapping at `indent` spaces in text, as {child: value}; comments dropped."""
    m = _re30.search(r"^%s%s:\n((?:%s .*\n)*)" % (" " * indent, _re30.escape(key), " " * indent),
                     text + "\n", _re30.M)
    if m is None:
        return None
    pad = " " * (indent + 2)
    return {ln[len(pad):].split(":", 1)[0]: ln.split(":", 1)[1].split("#", 1)[0].strip()
            for ln in m.group(1).splitlines()
            if ln.startswith(pad) and not ln[len(pad):].startswith((" ", "#"))}


def _if30(job_text):
    m = _re30.search(r"^    if: (.*)$", job_text, _re30.M)
    return m.group(1) if m else ""


_STORE30 = "This run stored the fuzz artifacts it made"
_GUARD30 = "Every stored fuzz artifact was made on main here"

# ── E3: every producer ends by checking its own run stored what it made ─────────────────────────
_producers30 = [("cflite_build.yml", "build"), ("cflite_batch.yml", "batch"),
                ("cflite_cron.yml", "prune"), ("cflite_cron.yml", "coverage")]
_store_bodies30, _store_bad30 = [], []
for _f30, _j30 in _producers30:
    _jt30 = _job29(_wf29(_f30), _j30)
    _st30 = _steps30(_jt30)
    _names30 = [n for n, _s in _st30]
    if not _names30 or _names30[-1] != _STORE30:
        _store_bad30.append("%s/%s: last step is %r" % (_f30, _j30, _names30[-1:] or None))
        continue
    _body30 = _runbody29(_st30[-1][1])
    _store_bodies30.append(_body30)
    if "actions/runs/${GITHUB_RUN_ID}/artifacts" not in _body30 or "exit 1" not in _body30:
        _store_bad30.append("%s/%s: the step does not list this run's artifacts and fail" % (_f30, _j30))
    if (_block30(_jt30, "permissions", 4) or {}).get("actions") != "read":
        _store_bad30.append("%s/%s: no actions: read to list them" % (_f30, _j30))
check("cflite: every producer (build, batch, prune, coverage) ends by checking its own run stored "
      "the artifacts it made, with one body for all (ClusterFuzzLite logs a failed upload and goes on)",
      not _store_bad30 and len(_store_bodies30) == 4 and len(set(_store_bodies30)) == 1,
      repr(_store_bad30 or [len(set(_store_bodies30))]))

# ── E4: the build on main is never cancelled by the next merge ──────────────────────────────────
_bcode30 = _code29(_wf29("cflite_build.yml"))
check("cflite: the continuous build on main has no concurrency group (a cancelled build on main's "
      "head is a failure to the update gate and deploy)",
      _re30.search(r"^ *concurrency:", _bcode30, _re30.M) is None,
      repr(_re30.findall(r"^ *concurrency:.*", _bcode30, _re30.M)))

# ── E5: a scheduled CodeQL or security-code run never cancels the push run of the same ref ───────
_conc30 = {f: (_block30(_wf29(f), "concurrency", 0) or {}).get("group", "")
           for f in ("codeql.yml", "security-code.yml")}
check("CodeQL and security-code: the concurrency group includes the event, so the Monday schedule "
      "does not cancel an in-progress push run on main",
      all("${{ github.event_name }}" in g and "${{ github.ref }}" in g for g in _conc30.values()),
      repr(_conc30))

# ── SEC1: the guard runs before the build, directly before fuzzing, and after it ────────────────
_pr30 = _steps30(_job29(_wf29("cflite_pr.yml"), "code-change"))
_pr_names30 = [n for n, _s in _pr30]
_fuzz_i30 = next((i for i, n in enumerate(_pr_names30) if n.startswith("Fuzz the changed code")), -1)
_guards30 = [i for i, n in enumerate(_pr_names30) if n.startswith(_GUARD30)]
_gbodies30 = {_runbody29(_pr30[i][1]) for i in _guards30}
check("cflite PR: the foreign-artifact guard runs three times (before the build, directly before "
      "fuzzing, after it), with one body",
      len(_guards30) == 3 and _fuzz_i30 > 0 and _guards30[1] == _fuzz_i30 - 1
      and _guards30[0] < _fuzz_i30 < _guards30[2] and len(_gbodies30) == 1,
      repr((_guards30, _fuzz_i30, len(_gbodies30))))

# ── SEC2: the cleanup is scheduled on main only, may only touch artifacts, and never fails ──────
_cl30 = _wf29("cflite_cleanup.yml")
_cl_on30 = _block30(_cl30, "on", 0) or {}
_cl_job30 = _job29(_cl30, "cleanup")
_cl_perm30 = _block30(_cl_job30, "permissions", 4)
_cl_run30 = "\n".join(_runbody29(st) for st in _steps29(_cl_job30))
check("cflite cleanup: schedule and manual runs only, on this repository's main, with actions: write "
      "and nothing else, and it never fails (its check lands on main's head)",
      set(_cl_on30) == {"schedule", "workflow_dispatch"}
      and _cl_perm30 == {"actions": "write"}
      and "refs/heads/main" in _if30(_cl_job30)
      and "exit 1" not in _cl_run30 and "set -euo" not in _cl_run30 and "::error::" not in _cl_run30
      and "::warning::" in _cl_run30, repr((sorted(_cl_on30), _cl_perm30)))

# ── Every third-party import in the unit suite is a package its CI jobs install ─────────────────
# This part first read the workflows with PyYAML: green here (the dev venv has it), red on CI
# (neither the checks job nor coverage installs it). The base every job that runs the suite
# installs is requirements.txt plus requirements-bootstrap.txt. An import inside a `try` whose
# handler takes ImportError is optional and exempt; a first-party module (a file or package at the
# root, in tests/ or in tools/) is not a dependency.


def _pins30(name):
    with open(os.path.join(_root, name), encoding="utf-8") as fh:
        return {_re30.sub(r"[-_.]+", "-", m.group(1)).lower()
                for m in _re30.finditer(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==", fh.read(), _re30.M)}


def _guarded30(tree):
    """Return the ids of the import nodes inside a try that handles ImportError (or a parent of it)."""
    out = set()
    for node in _ast30.walk(tree):
        if not isinstance(node, _ast30.Try):
            continue
        caught = set()
        for h in node.handlers:
            types = h.type.elts if isinstance(h.type, _ast30.Tuple) else [h.type]
            caught |= {getattr(t, "id", None) for t in types}
        if caught & {"ImportError", "ModuleNotFoundError", "Exception", None}:
            out |= {id(n) for stmt in node.body for n in _ast30.walk(stmt)}
    return out


def _dist_tops30():
    """Return {top-level import name: {normalised distribution names}} for what is installed.

    Not importlib.metadata.packages_distributions(): on Python 3.10, the oldest the panel supports
    and a CI leg, it reads only top_level.txt, which flit and hatch wheels (Flask, Werkzeug, Jinja2,
    pyotp...) do not ship, so it maps almost nothing. 3.11 also infers the names from the RECORD;
    this does that on every version.
    """
    out = {}
    for dist in _md30.distributions():
        name = _re30.sub(r"[-_.]+", "-", dist.metadata["Name"] or "").lower()
        for top in _tops30(dist):
            out.setdefault(top, set()).add(name)
    return out


def _tops30(dist):
    """Return the top-level import names one distribution declares or installs."""
    tops = set((dist.read_text("top_level.txt") or "").split())
    for f in dist.files or ():
        first = f.parts[0]
        tops.add(first if len(f.parts) > 1 else (_inspect30.getmodulename(first) or first))
    return {t for t in tops if "." not in t}


def _first_party30(top):
    return any(os.path.exists(os.path.join(_root, d, top + ext))
               for d in ("", "tests", "tools") for ext in (".py", os.sep + "__init__.py"))


_base30 = _pins30("requirements.txt") | _pins30("requirements-bootstrap.txt")
_dists30 = _dist_tops30()
_unit_dir30 = os.path.join(_root, "tests", "unit")
_unknown30 = set()
for _fn30 in sorted(os.listdir(_unit_dir30)) + [os.path.join("..", "unit_test.py")]:
    if not _fn30.endswith(".py"):
        continue
    with open(os.path.join(_unit_dir30, _fn30), encoding="utf-8") as _fh30:
        _tree30 = _ast30.parse(_fh30.read())
    _opt30 = _guarded30(_tree30)
    for _n30 in _ast30.walk(_tree30):
        if id(_n30) in _opt30:
            continue
        if isinstance(_n30, _ast30.Import):
            _mods30 = [a.name for a in _n30.names]
        elif isinstance(_n30, _ast30.ImportFrom) and not _n30.level and _n30.module:
            _mods30 = [_n30.module]
        else:
            continue
        for _top30 in {m.split(".", 1)[0] for m in _mods30}:
            if _top30 in _sys30.stdlib_module_names or _first_party30(_top30):
                continue
            _have30 = _dists30.get(_top30, set())
            if not _have30 & _base30:
                _unknown30.add("%s: %s (%s)" % (os.path.basename(_fn30), _top30,
                                                   ", ".join(sorted(_have30)) or "not installed"))
check("unit suite: every third-party module a part imports unguarded is a package CI installs for it "
      "(requirements.txt or requirements-bootstrap.txt), not just something the dev venv has",
      not _unknown30 and len(_base30) > 20 and {"flask", "werkzeug"} <= set(_dists30)
      and "flask" in _dists30["flask"], repr(sorted(_unknown30) or (len(_base30), _dists30.get("flask"))))
