"""Part 325 of the unit suite: shorter waits for the unit suite, without a part going untested on main.

1. The per-part clock (tests/unit/timing.py, UNIT_PART_TIMES): silent and writing nothing when unset; set, it
   records every part the runner imports and prints one summary block. The runner wraps each part's import in
   it, and CI's two unit runs set it. shard_weights.json measures every part in _PARTS, and the plan's four
   shards come out within 15% of each other.
2. Test impact selection (tests/unit/impact.py): a change to one panel module selects the parts the map says
   ran it (and the parts that ran a module importing it), the setup, part15 and the parts that walk the tree,
   and not the rest; a change to the runner, a shared test module, a workflow, the requirements, install.sh or
   tools/, a file the map never saw, and a missing, old or malformed map each run everything. A shard cut to a
   selection keeps its setup, part15, the selected parts it owns and their imports.
3. .github/scripts/unit_select.py runs everything for any event but a pull request, for the `full-tests`
   label, and for a map that did not come from a push to main; ci.yml gives the selection to both unit runs
   only on a pull request, never lets main reuse a selected pass, builds the map on main only, and the root
   step passes a selection with no root check only when both runs say the same selection.

HOW IT RUNS. The modules on made-up maps and the runner's real _PARTS and import graph; the recorder and the
root step's own Python in child interpreters; ci.yml read as text.
"""
import contextlib as _ctx325
import datetime as _dt325
import importlib.util as _ilu325
import io as _io325
import json as _json325
import os
import re as _re325
import subprocess as _sp325  # nosec B404 - python with fixed argvs over this part's own inputs
import sys as _sys325
import tempfile as _tf325
import zipfile as _zip325

from unit.part01 import _root, check, eq
from unit.part06 import _wf_run_block
from unit import impact as _im325, shard as _sh325, timing as _tm325

with open(os.path.join(_root, "tests", "unit_test.py"), encoding="utf-8") as _fh325:
    _RUNNER325 = _fh325.read()
_at325 = _RUNNER325.index("\n_PARTS = (")
_PARTS325 = tuple(_re325.findall(r'"(part\d+)"', _RUNNER325[_at325:_RUNNER325.index(")", _at325)]))
_GRAPH325 = _sh325.import_graph(_PARTS325, _root)
with open(os.path.join(_root, ".github", "workflows", "ci.yml"), encoding="utf-8") as _fh325:
    _CI325 = _fh325.read()
_NOW325 = _dt325.datetime(2026, 11, 28, 12, 0, tzinfo=_dt325.timezone.utc)


def _py325(code, *args, env=None, timeout=120):
    """A child Python running `code`; (exit code, stdout + stderr)."""
    p = _sp325.run([_sys325.executable, "-c", code] + list(args), capture_output=True, text=True,  # nosec B603
                   timeout=timeout, env=env, check=False)
    return p.returncode, p.stdout + p.stderr


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The per-part clock
# ════════════════════════════════════════════════════════════════════════════════════════════════
with _tf325.TemporaryDirectory() as _td325:
    _off325, _out325 = _tm325.PartClock({}), _io325.StringIO()
    _off325.start("part01")
    _off325.stop()
    _gone325 = _off325.report(_out325)
    _file325 = os.path.join(_td325, "t.json")
    _on325, _said325 = _tm325.PartClock({"UNIT_PART_TIMES": _file325}), _io325.StringIO()
    for _p325 in ("part01", "part02"):
        _on325.start(_p325)
        sum(range(20000))
        _on325.stop()
    _on325.report(_said325)
    with open(_file325, encoding="utf-8") as _fh325:
        _times325 = _json325.load(_fh325)
check("part clock: unset, it records, writes and prints nothing; set, it writes every part's wall and CPU time, "
      "memory, processes started and load, and prints one summary block",
      _gone325 is None and _out325.getvalue() == "" and not _off325.rows
      and sorted(_times325["ms"]) == ["part01", "part02"] and set(_times325) == {"ms", "cpu_ms", "rss_mb", "procs", "load1"}
      and _said325.getvalue().count(_tm325.SUMMARY_HEAD) == 1 and "2 parts" in _said325.getvalue(),
      repr((_out325.getvalue(), _times325, _said325.getvalue()))[:600])

# The runner times every part: the clock starts right before each part's import and stops right after it,
# and reports once, after the loop.
_loop325 = _RUNNER325[_RUNNER325.index("\nfor _part in _RUN_PARTS:"):]
_loop325 = _loop325[:_loop325.index("\n_r29d_last_left")]
_body325 = [ln.strip() for ln in _loop325.splitlines()]
_imp325 = _body325.index('importlib.import_module("unit." + _part)')
check("runner: each part's import is timed (the clock starts just before it and stops just after it), and the "
      "times are reported once, after the last part",
      "_clock.start(_part)" in _body325[_imp325 - 2:_imp325] and "_clock.stop()" in _body325[_imp325 + 1:_imp325 + 3]
      and _body325.count("_clock.report()") == 1 and _body325.index("_clock.report()") > _imp325
      and "\n_clock.report()\n" in _loop325, repr(_body325[_imp325 - 3:_imp325 + 4]))

_run_step325 = _wf_run_block(_CI325, "Run all checks (compile, lint, unit, smoke, shellcheck)")
_root_step325 = _wf_run_block(_CI325, "Run the root-only unit checks, as root")
check("ci.yml: both unit runs of a shard time their parts (UNIT_PART_TIMES), and the root step prints the root "
      "run's block, as the run as the runner prints its own",
      'UNIT_PART_TIMES="${RUNNER_TEMP}/unit-times-user.json"' in _run_step325
      and 'UNIT_PART_TIMES="${RUNNER_TEMP}/unit-times-root.json"' in _run_step325
      and "/^unit part times /" in _root_step325 and _tm325.SUMMARY_HEAD.startswith("unit part times "),
      _root_step325[:300])

_W325 = _sh325.load_weights()
_owned325 = _sh325.plan(_PARTS325, _GRAPH325, _W325, 4)
_sums325 = [sum(_W325.get(p, _sh325.FALLBACK_MS) for p in _sh325.run_list(_PARTS325, _GRAPH325, o)) for o in _owned325]
check("shard weights: every part in _PARTS has a measured time (none counts the fallback), and the four shards "
      "the plan makes from them are within 15% of each other",
      not [p for p in _PARTS325 if p not in _W325] and max(_sums325) <= 1.15 * min(_sums325),
      "unmeasured: %s; shard sums (ms): %s" % ([p for p in _PARTS325 if p not in _W325][:8], _sums325))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Selection
# ════════════════════════════════════════════════════════════════════════════════════════════════
_A325, _B325, _C325, _WK325, _LS325 = "part94", "part190", "part272", "part66", "part67"


_FULL325 = [("tests/unit_test.py", None), ("tests/unit/shard.py", None), ("tests/unit/impact.py", None),
            ("tests/unit/reboot41_a.py", None), ("tests/suite_deadline.py", None), (".github/workflows/ci.yml", None),
            (".github/scripts/unit_select.py", None), ("panel/install/requirements.txt", None), ("install.sh", None),
            ("tools/panel-helper", None), ("tools/run-tests.sh", None),
            ("panel/ops/never_seen.py", None), ("panel/static/js/new.js", None)]

def _map325(**kw):
    """A made-up map, with `kw` over its keys.

    _A325 ran panel/ops/backup.py, _B325 ran panel/routes/api.py, _C325 read a template, _WK325 listed
    the top directory (it walks the tree), _LS325 listed panel/routes, and every part read one file, so
    every part has a record.
    """
    m = {"version": _im325.VERSION, "made": "2026-11-27T12:00:00+00:00", "commit": "0" * 40,
         "run": {"panel/ops/backup.py": [_A325], "panel/routes/api.py": [_B325], "panel/app.py": [_B325]},
         "read": {"panel/templates/x.html": [_C325], "docs/every-part.txt": list(_PARTS325)},
         "listed": {".": [_WK325], "panel/routes": [_LS325]}}
    for path, _ in _FULL325[:-2]:   # each path that runs everything was read too: the map alone would select
        m["read"].setdefault(path, [_C325])
    m.update(kw)
    return m


def _sel325(changes, imap=None, users=None, since=None):
    return _im325.select(changes, _PARTS325, _GRAPH325, _map325() if imap is None else imap, _NOW325, users, since)


_base325 = set(_PARTS325[:12]) | {"part15", _WK325}
_one325 = _sel325([("M", "panel/ops/backup.py", None)])
eq("select: a change to one panel module runs the parts the map says ran it, with the setup, part15 and the "
   "parts that walk the tree, and nothing else",
   (sorted(_one325[0] or ()), _one325[1].endswith("parts touch what changed")),
   (sorted(_base325 | {_A325}), True))
_users325 = {"panel/ops/backup.py": {"panel/routes/api.py"}}
_imp325s = [_sel325([("M", "panel/ops/backup.py", None)], users=_users325, since=_s)[0]
            for _s in ({"panel/routes/api.py"}, set(), None)]
check("select: ...and the parts that ran a module importing it (read from the tree under test) when main changed "
      "that importer after the map was made, or when what main changed since is not known",
      _imp325s == [_base325 | {_A325, _B325}, _base325 | {_A325}, _base325 | {_A325, _B325}], repr(_imp325s))
_new325 = _map325()
_new325["read"]["docs/every-part.txt"] = [p for p in _PARTS325 if p != "part200"]
_since325 = _sel325([("M", "panel/ops/backup.py", None)], _new325, since={"tests/unit/part201.py"})
check("select: a part the map has no record of (added after it), and a part main changed since the map, always run",
      _since325[0] == _base325 | {_A325, "part200", "part201"}, repr(sorted(_since325[0] or ())[-6:]))
_tpl325 = _sel325([("M", "panel/templates/x.html", None)])
_add325 = _sel325([("A", "panel/routes/new.py", None)])
_gone325s = _sel325([("D", "panel/ops/backup.py", None)])
check("select: a file a part reads selects that part; a file added where a part lists the directory selects the "
      "lister; a deleted file selects what ran it",
      _tpl325[0] == _base325 | {_C325} and _add325[0] == _base325 | {_LS325} and _gone325s[0] == _base325 | {_A325},
      repr((_tpl325, _add325, _gone325s)))
_users47_325 = {p for p, deps in _GRAPH325.items() if "part47" in deps}
_edit325 = _sel325([("M", "tests/unit/part47.py", None)])
check("select: editing a part runs it and every part that imports it",
      _edit325[0] is not None and {"part47"} | _users47_325 <= _edit325[0] and _users47_325,
      repr(sorted(_users47_325)[:6]))

_full325 = {p: _sel325([("M" if p != "panel/static/js/new.js" else "A", p, None)])[0] for p, _ in _FULL325}
check("select: a change to the runner, a shared test module, a workflow or CI script, the requirements, "
      "install.sh, tools/, a file no part touched, or a file added where no part lists runs every part",
      all(v is None for v in _full325.values()), repr({k: v is None for k, v in _full325.items()}))
_ren325 = _sel325([("R", "panel/ops/backup2.py", "tools/old.py")])
_none325 = _sel325([])
_old325 = _sel325([("M", "panel/ops/backup.py", None)], _map325(made="2026-11-19T12:00:00+00:00"))
_ver325 = _sel325([("M", "panel/ops/backup.py", None)], _map325(version=99))
_naive325 = _sel325([("M", "panel/ops/backup.py", None)], _map325(made="2026-11-27T12:00:00"))
_bad325 = _sel325([("M", "panel/ops/backup.py", None)], {"version": _im325.VERSION})
_fresh325 = _sel325([("M", "panel/ops/backup.py", None)], _map325(made="2026-11-22T12:00:00+00:00"))
check("select: a rename from a path that runs everything, no change listed, a map older than 7 days, of another "
      "version, without a zone or without its tables all run every part; a 6-day-old map is used",
      [x[0] for x in (_ren325, _none325, _old325, _ver325, _naive325, _bad325)] == [None] * 6
      and _fresh325[0] == _base325 | {_A325}, repr([x[1] for x in (_ren325, _none325, _old325, _ver325, _naive325, _bad325)]))

# A shard cut to a selection: its setup and part15 always, the selected parts IT owns with their imports,
# and none of its other parts; another shard's selected part is not run here.
def _case325():
    """(shard index, its run list, an owned part, a part it runs only as another owned part's import)."""
    for i, own in enumerate(_owned325):
        run = _sh325.run_list(_PARTS325, _GRAPH325, own)
        base = set()
        for q in list(run[:12]) + ["part15"]:
            base |= _sh325._closure(q, _GRAPH325)
        for other in (p for p in run if p not in own and p not in base):
            for pick in own:
                if other not in _sh325._closure(pick, _GRAPH325):
                    return i, run, pick, other
    return None


_i325, _run325, _pick325, _other325 = _case325() or (0, [], "", "")   # none: the check below fails
_cut325 = _im325.narrow(_run325, {_pick325, _other325}, _GRAPH325, set(_owned325[_i325]))
_need325 = set(_run325[:12]) | {"part15", _pick325}
_todo325 = sorted(_need325)   # what the setup, part15 and the picked part import, all the way down
while _todo325:
    for _q325 in _GRAPH325.get(_todo325.pop(), ()):
        if _q325 not in _need325:
            _need325.add(_q325)
            _todo325.append(_q325)
check("shard + selection: a shard keeps its setup, part15, the selected parts it owns and what they import, in "
      "_PARTS order, and runs no part another shard owns or it was not asked for",
      _cut325 == [p for p in _run325 if p in _need325] and _other325 in _run325 and _other325 not in _cut325
      and _cut325[-1] == "part15",
      repr((_pick325, _other325, _cut325[:20])))

_bad_env325 = []
for _v325 in ("part9999", "part01 rm", "../x"):
    try:
        _im325.parse_env(_v325, _PARTS325)
    except ValueError as _e325:
        _bad_env325.append(str(_e325)[:60])
eq("UNIT_SELECT: unset or empty selects nothing (every part runs), 'auto' asks the map, names are taken; a name "
   "not in _PARTS is refused",
   (_im325.parse_env(None, _PARTS325), _im325.parse_env(" ", _PARTS325), _im325.parse_env("auto", _PARTS325),
    _im325.parse_env("part94, part190", _PARTS325), len(_bad_env325)),
   (None, None, "auto", ("part94", "part190"), 3))

# The recorder, in a child interpreter (its audit hook cannot be removed again): what a part runs, reads
# and lists inside the checkout is recorded under that part, and nothing outside a part or outside the tree.
_REC325 = r'''
import json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
import impact
root = tempfile.mkdtemp()
os.makedirs(os.path.join(root, "pkg"))
with open(os.path.join(root, "pkg", "mod.py"), "w") as fh:
    fh.write("def f():\n    return 7\n")
with open(os.path.join(root, "data.txt"), "w") as fh:
    fh.write("x")
sys.path.insert(0, os.path.join(root, "pkg"))
out = os.path.join(root, "rec.json")
try:
    rec = impact.Recorder({"UNIT_IMPACT_RECORD": out}, root)
except SystemExit as e:
    print("REFUSED", e)
    raise SystemExit(0)
import mod
open(os.path.join(root, "data.txt")).read()   # outside any part: not recorded
rec.start("partA"); mod.f(); open(os.path.join(root, "data.txt")).read(); rec.stop()
rec.start("partB"); mod.f(); os.listdir(os.path.join(root, "pkg")); open("/etc/hostname" if os.path.exists("/etc/hostname") else __file__); rec.stop()
rec.save()
print(json.dumps(json.load(open(out))))
'''
_rc325, _rec_out325 = _py325(_REC325, os.path.join(_root, "tests", "unit"))
if _sys325.version_info >= (3, 12):
    try:
        _rec325 = _json325.loads(_rec_out325.strip().splitlines()[-1])
    except (ValueError, IndexError):
        _rec325 = {}
    _ok325 = (_rec325.get("partA") == {"run": ["pkg/mod.py"], "read": ["data.txt"], "listed": []}
              and _rec325.get("partB") == {"run": ["pkg/mod.py"], "read": [], "listed": ["pkg"]})
else:
    _ok325 = "REFUSED" in _rec_out325 and "3.12" in _rec_out325
check("recorder: each part's own record holds what it ran (a function already called by an earlier part too), "
      "read and listed inside the checkout, and nothing outside a part or the tree (before 3.12 it refuses to start)",
      _rc325 == 0 and _ok325, _rec_out325[-600:])

_built325 = _im325.build_map([{"part2": {"run": ["a.py"], "read": [], "listed": []}},
                              {"part10": {"run": ["a.py"], "read": ["b"], "listed": ["d"]}}], "2026-11-28T00:00:00+00:00", "c")
eq("impact map: the shards' records merge into {path: parts}, the parts in _PARTS order",
   (_built325["run"], _built325["read"], _built325["listed"], _built325["version"]),
   ({"a.py": ["part2", "part10"]}, {"b": ["part10"]}, {"d": ["part10"]}, _im325.VERSION))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. CI: who selects, and what main reads
# ════════════════════════════════════════════════════════════════════════════════════════════════
_spec325 = _ilu325.spec_from_file_location("unit_select_p325", os.path.join(_root, ".github", "scripts", "unit_select.py"))
_us325 = _ilu325.module_from_spec(_spec325)
_spec325.loader.exec_module(_us325)
_HEAD325 = "a" * 40


def _zip_map325(imap):
    buf = _io325.BytesIO()
    with _zip325.ZipFile(buf, "w") as zf:
        zf.writestr(_us325.MAP_FILE, _json325.dumps(imap))
    return buf.getvalue()


def _decide325(labels=(), event="push", head_branch="main", files=None, imap=None):
    """unit_select.decide on a stand-in GitHub: one pull request, one map artifact from run 7."""
    files = files if files is not None else [["modified", "panel/ops/backup.py", None]]
    answers = {
        "repos/o/r/pulls/5": {"head": {"sha": _HEAD325}, "changed_files": len(files), "base": {"sha": "b" * 40},
                              "labels": [{"name": n} for n in labels]},
        "repos/o/r/compare/%s...%s" % ("0" * 40, "b" * 40): {"status": "identical", "files": []},
        "repos/o/r/actions/artifacts?name=unit-impact-map&per_page=20": {"artifacts": [
            {"id": 3, "name": "unit-impact-map", "expired": False, "size_in_bytes": 100,
             "created_at": "2026-11-27T12:00:00Z", "workflow_run": {"id": 7}}]},
        "repos/o/r/actions/runs/7": {"event": event, "head_branch": head_branch, "path": ".github/workflows/ci.yml",
                                     "head_repository": {"full_name": "o/r"}, "repository": {"full_name": "o/r"}},
    }

    def gh(args):
        path = args[-1]
        if path.startswith("repos/o/r/pulls/5/files"):
            return "\n".join(_json325.dumps(f) for f in files)
        return _json325.dumps(answers[path]) if path in answers else None
    was = (_us325._PR_SCOPE._gh, _us325._gh_bytes)
    _us325._PR_SCOPE._gh, _us325._gh_bytes = gh, lambda args: _zip_map325(imap or _map325())
    try:
        return _us325.decide("pull_request", "o/r", "5", _HEAD325, now=_NOW325)
    finally:
        _us325._PR_SCOPE._gh, _us325._gh_bytes = was


_ok_d325 = _decide325()
_lab325 = _decide325(labels=("full-tests",))
_pr_run325 = _decide325(event="pull_request")
_branch325 = _decide325(head_branch="feature")
_nonpr325 = _us325.decide("push", "o/r", "", "", now=_NOW325)
check("unit_select: a pull request with a map from main's own push is selected; the full-tests label, a map "
      "artifact from a pull request's run or another branch, and any event but a pull request run every part",
      _ok_d325[0] == _base325 | {_A325} and _lab325[0] is None and _pr_run325[0] is None and _branch325[0] is None
      and _nonpr325[0] is None, repr([x[1] for x in (_ok_d325, _lab325, _pr_run325, _branch325, _nonpr325)]))


def _step325(name):
    """The text of the step named `name` in ci.yml, from its `- name:` line to the next step."""
    i = _CI325.index("      - name: " + name + "\n")
    j = _CI325.find("\n      - ", i + 1)
    return _CI325[i:j]


_sel_step325 = _step325("Which unit parts can this pull request's change affect?")
_mark325 = _step325("Every unit part ran here, none left out by a selection")
_reuse325 = _step325("Did the merged pull request pass this job on the same tree?")
_build325 = _step325("Build the unit impact map")
_upload325 = _step325("Upload the unit impact map")
check("ci.yml: the selection runs only on a pull request's unit shards and goes to both unit runs; a push to main "
      "reuses a pass only when its marker step ran, which a selection skips; the map is built and uploaded on a "
      "push to main only, from records the coverage run makes",
      "github.event_name == 'pull_request'" in _sel_step325 and "startsWith(matrix.part, 'unit ')" in _sel_step325
      and "unit_select.py" in _sel_step325 and 'export UNIT_SELECT="${SELECTED}"' in _run_step325
      and 'UNIT_SELECT="${UNIT_SELECT}"' in _run_step325
      and "steps.select.outputs.parts == ''" in _mark325
      and '--work-step "Every unit part ran here, none left out by a selection"' in _reuse325
      and all("github.event_name == 'push' && github.ref == 'refs/heads/main'" in t for t in (_build325, _upload325))
      and 'export UNIT_IMPACT_RECORD="${RUNNER_TEMP}/impact.json"' in _CI325 and ".impact.${{ matrix.id }}.json" in _CI325,
      _sel_step325[:300])

# The root step's own Python on made-up logs: a selection with no root check passes when both runs say it; a
# root run of another selection, and an unselected run with no root check, still fail.
_judge325 = _root_step325[_root_step325.find("<<'EOF'\n") + 8:_root_step325.rfind("\nEOF")]
_SEL325 = "unit selection: 14 of 315 parts (UNIT_SELECT names them)\n"
_U325 = _SEL325 + "PASS  a\n\nunit shard 2/4: 13 of 315 parts: x\n\n1 / 1 checks passed\n"
_R325 = _SEL325 + "PASS  a\n\nunit shard 2/4: 13 of 315 parts: x\n\n1 / 1 checks passed\n"


def _judge_rc325(user, root):
    with _tf325.TemporaryDirectory() as tmp:
        u, r = os.path.join(tmp, "u.txt"), os.path.join(tmp, "r.txt")
        for path, text in ((u, user), (r, root)):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        p = _sp325.run([_sys325.executable, "-", u, r], input=_judge325, capture_output=True, text=True,  # nosec B603
                       timeout=60, check=False)
    return p.returncode


eq("ci.yml: the root step passes a selection with no root check only when both runs say that selection; another "
   "selection, or no selection, with no root check fails",
   [_judge_rc325(_U325, _R325), _judge_rc325(_U325, _R325.replace("14 of", "15 of")),
    _judge_rc325(_U325.replace(_SEL325, ""), _R325.replace(_SEL325, ""))],
   [0, 1, 1])

# The end-of-run gate of an unsplit run cut to a selection, as the runner calls it (shard.end_gates): it
# passes when the run imported exactly its run list, and fails when a listed part never ran.
_said_gate325 = []


def _gate_check325(name, ok, detail=""):
    _said_gate325.append((name, bool(ok), detail))


_was_sel325 = _sh325.SELECTED
try:
    _sh325.SELECTED = frozenset(_PARTS325[:12])
    _ran325 = tuple(_sh325._imported_parts())
    _disk325 = sorted(_PARTS325)
    with _ctx325.redirect_stdout(_io325.StringIO()):   # its "unit selection:" line is the runner's to print
        _sh325.end_gates(_gate_check325, _gate_check325, ["w%d" % _i325 for _i325 in range(8)], None, (_PARTS325, _ran325, _disk325), _root, None)
        _sh325.end_gates(_gate_check325, _gate_check325, ["w%d" % _i325 for _i325 in range(8)], None, (_PARTS325, _ran325 + ("part15",), _disk325),
                         _root, None)
finally:
    _sh325.SELECTED = _was_sel325
check("runner: a selected unsplit run's end gate passes when it imported exactly its run list, fails when a listed "
      "part never ran, and the whole-suite gates are still counted",
      [ok for name, ok, _ in _said_gate325 if "selection's run list" in name] == [True, False]
      and [ok for name, ok, _ in _said_gate325 if "whole-suite gates ran here" in name] == [True, True],
      repr(_said_gate325)[:600])
