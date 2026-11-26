"""Part 294 of the unit suite: the unit suite split into shards that run side by side, and CI's verdict on them.

1. tests/unit/shard.py: UNIT_SHARD=i/n is read strictly (anything else is refused), the shards own every part but
   the setup (part01-part12) and part15 exactly once, each shard lists every part its parts import, in _PARTS
   order, with the setup first and part15 last, and the plan is the same in every process, whatever
   PYTHONHASHSEED (each shard computes it on its own).
2. The runner (tests/unit_test.py) refuses a malformed UNIT_SHARD before it runs anything, and the gates that read
   the whole suite run in exactly one shard.
3. tools/run-tests.sh refuses a RUN_TESTS_UNIT it does not know, and without the unit lane still holds the lanes
   to every other suite once.
4. ci.yml: the checks legs and the coverage run are split into the same four unit shards and one part for the
   rest; the checks each leg reported, and `coverage`, come from verdict jobs that run whatever happened
   (`always()`) and pass only when every part passed; coverage combines every part's data; the root step refuses
   two runs of different shards.

HOW IT RUNS. The shard module on the runner's real _PARTS (read from tests/unit_test.py), child Pythons for the
hash seeds and for the runner's refusal, bash for run-tests.sh's refusal and for the verdict steps' own scripts cut
out of ci.yml, and the root step's own Python on made-up logs.
"""
import json as _json294
import os
import re as _re294
import signal as _signal294
import subprocess as _sp294  # nosec B404 - python and bash with fixed argvs over this part's own inputs
import sys as _sys294
import tempfile as _tf294

from unit.part01 import _root, check, eq
from unit.part06 import _wf_run_block
from unit.part29 import _job29, _name29, _steps29, _wf29
from unit import shard as _sh294


def _run294(argv, timeout=120, **kw):
    """The finished process; one still running at `timeout` is killed and answers -9 with what it printed.

    The class of the timeout raised depends on whose subprocess this is (eventlet's green one raises its
    own TimeoutExpired), so it is told by name.
    """
    inp = kw.pop("input", None)
    with _sp294.Popen(argv, stdin=_sp294.PIPE if inp is not None else _sp294.DEVNULL, stdout=_sp294.PIPE,
                      stderr=_sp294.PIPE, text=True, start_new_session=True, **kw) as proc:  # nosec B603 - fixed argvs
        try:
            out, err = proc.communicate(inp, timeout=timeout)
        except Exception as e:  # noqa: BLE001 - re-raised unless it is the timeout
            if type(e).__name__ != "TimeoutExpired":
                raise
            try:
                os.killpg(proc.pid, _signal294.SIGKILL)   # the child and all it started
            except OSError:
                proc.kill()
            out, err = proc.communicate()
            return _sp294.CompletedProcess(argv, -9, out or "", err or "")
    return _sp294.CompletedProcess(argv, proc.returncode, out, err)


with open(os.path.join(_root, "tests", "unit_test.py"), encoding="utf-8") as _fh294:
    _runner294 = _fh294.read()
_at294 = _runner294.index("\n_PARTS = (")
_PARTS294 = tuple(_re294.findall(r'"(part\d+)"', _runner294[_at294:_runner294.index(")", _at294)]))
_graph294 = _sh294.import_graph(_PARTS294, _root)
_weights294 = _sh294.load_weights()
_always294 = set(_PARTS294[:_sh294.SETUP]) | set(_sh294.TAIL)


# ── 1. the split ──────────────────────────────────────────────────────────────────────────────────
def _parse294(value):
    try:
        return _sh294.parse(value)
    except ValueError:
        return "refused"


eq("unit shards: UNIT_SHARD reads i/n, and unset or empty runs the whole suite",
   [_parse294(v) for v in (None, "", "1/4", "4/4", "1/1", "32/32")], [None, None, (1, 4), (4, 4), (1, 1), (32, 32)])
eq("unit shards: ...and anything else is refused, never read as the whole suite or as no shard",
   [_parse294(v) for v in ("0/4", "5/4", "1/0", "a/b", " 1/4", "1/4 ", "01/4", "1/33", "1/4/2", "1", "-1/4", "1/4\n")],
   ["refused"] * 12)


def _split_bad294(n):
    """What is wrong with the split into n shards ([] when nothing)."""
    owned = _sh294.plan(_PARTS294, _graph294, _weights294, n)
    bad = ["%d shards, not %d" % (len(owned), n)] if len(owned) != n else []
    bad += _owned_bad294([p for o in owned for p in o])
    for i, own in enumerate(owned, 1):
        bad += _list_bad294(i, own, _sh294.run_list(_PARTS294, _graph294, own))
    return bad


def _owned_bad294(flat):
    """A part no shard owns, one owned twice, or the setup or part15 owned at all."""
    bad = ["lost: %s" % p for p in _PARTS294 if p not in _always294 and p not in flat]
    bad += ["owned twice: %s" % p for p in sorted(set(flat)) if flat.count(p) > 1]
    return bad + ["setup or part15 owned: %s" % p for p in flat if p in _always294]


def _list_bad294(i, own, lst):
    """What is wrong with shard i's run list `lst` for the parts it owns."""
    bad = ["shard %d: %s imports %s, not listed" % (i, p, q) for p in lst for q in _graph294[p] if q not in lst]
    bad += ["shard %d: an owned part missing" % i for p in own if p not in lst]
    bad += ["shard %d: not in _PARTS order" % i] * (lst != [p for p in _PARTS294 if p in lst])
    return bad + ["shard %d: not the setup first and part15 last" % i] * (
        lst[:_sh294.SETUP] != list(_PARTS294[:_sh294.SETUP]) or lst[-1:] != list(_sh294.TAIL))


_splits294 = {n: _split_bad294(n) for n in range(1, 9)}
check("unit shards: split 1 to 8 ways, every part but the setup and part15 is owned by exactly one shard, and each "
      "shard lists every part its parts import (through shared modules too), in _PARTS order, setup first, part15 last",
      len(_PARTS294) > 250 and not any(_splits294.values()), repr({n: b[:4] for n, b in _splits294.items() if b}))
_loads294 = [sum(_weights294.get(p, _sh294.FALLBACK_MS) for p in _sh294.run_list(_PARTS294, _graph294, o))
             for o in _sh294.plan(_PARTS294, _graph294, _weights294, 4)]
check("unit shards: ...and four shards come out even by the measured times (the slowest within 10% of the fastest), "
      "each well under the whole suite's time", max(_loads294) <= 1.1 * min(_loads294)
      and max(_loads294) < 0.6 * sum(_weights294.get(p, _sh294.FALLBACK_MS) for p in _PARTS294), repr(_loads294))
# A part that imports another drags it in; one with no measurement still gets a shard.
_toy294 = ("a01", "a02", "b1", "b2", "b3", "b4", "part15")
_toygraph294 = {"b3": ["b1"], "b4": []}
_toyplan294 = _sh294.plan(_toy294, _toygraph294, {"b1": 5000, "b2": 4000, "b3": 1000}, 2, setup=2)
_toylists294 = [_sh294.run_list(_toy294, _toygraph294, o, setup=2) for o in _toyplan294]
eq("unit shards: (control) on a made-up suite the heaviest part and what imports it share a shard, a part with no "
   "measurement counts the fallback, and a dragged-in part is listed but owned once",
   (_toyplan294, _toylists294),
   ([["b1", "b3"], ["b2", "b4"]], [["a01", "a02", "b1", "b3", "part15"], ["a01", "a02", "b2", "b4", "part15"]]))

# The same plan in every process: each shard computes it alone, and a part owned by two shards (or by none)
# is what a plan that depended on set order or float rounding would give.
_child294 = ("import json, sys\nsys.path.insert(0, sys.argv[1])\nfrom unit import shard\n"
             "parts = tuple(sys.argv[2].split())\n"
             "print(json.dumps(shard.plan(parts, shard.import_graph(parts, sys.argv[3]), shard.load_weights(), 4)))\n")
_mine294 = _sh294.plan(_PARTS294, _graph294, _weights294, 4)
_seeds294 = {}
for _seed294 in ("1", "2", "3"):
    _p294 = _run294([_sys294.executable, "-c", _child294, os.path.join(_root, "tests"), " ".join(_PARTS294), _root],
                    env=dict(os.environ, PYTHONHASHSEED=_seed294))
    _seeds294[_seed294] = _json294.loads(_p294.stdout) if _p294.returncode == 0 else _p294.stderr[-300:]
check("unit shards: the plan is the same in a child Python under three hash seeds as in this run",
      all(v == _mine294 for v in _seeds294.values()), repr({k: v if isinstance(v, str) else "differs"
                                                           for k, v in _seeds294.items() if v != _mine294}))


# ── 2. the runner ─────────────────────────────────────────────────────────────────────────────────
_bad_env294 = dict(os.environ, UNIT_SHARD="5/4")
_refused294 = _run294([_sys294.executable, os.path.join(_root, "tests", "unit_test.py")], env=_bad_env294, timeout=60)
check("unit runner: UNIT_SHARD=5/4 stops the run at once, naming the value, before any part runs",
      _refused294.returncode == 1 and "UNIT_SHARD='5/4'" in _refused294.stderr and "PASS" not in _refused294.stdout
      and "checks passed" not in _refused294.stdout, repr((_refused294.returncode, _refused294.stderr[-300:])))
eq("unit runner: the whole-suite gates run in the unsplit run and in exactly one shard of any split",
   [_sh294.runs_whole_suite_gates(None)] + [[_sh294.runs_whole_suite_gates((i, n)) for i in range(1, n + 1)].count(True)
                                            for n in range(1, 9)],
   [True] + [1] * 8)
with open(os.path.join(_root, "tests", "unit", "shard.py"), encoding="utf-8") as _fh294:
    _shardsrc294 = _fh294.read()
_wholes294 = _re294.findall(r"^ *_?whole_check\(\"([^\"]+)\"", _runner294 + _shardsrc294, _re294.M)
_plain294 = [n for n in ("unit suite: every ordering note that lists a part's imports lists exactly them",
                         "unit suite: no part imports a part that runs at or after it in _PARTS")
             if ('\ncheck("%s"' % n) in _runner294]
check("unit runner: the gates that read the whole suite (the ordering notes, the import order, the split itself) "
      "are recorded through _whole_check, and the run counts them",
      len(_wholes294) == 9 and not _plain294 and "want = 8 if shard is None else 9 if shard[0] == 1 else 0" in _shardsrc294
      and "_whole_check, _whole_ran = _shard.whole_gate(check, _SHARD)" in _runner294, repr((_wholes294, _plain294)))


# ── 3. run-tests.sh ───────────────────────────────────────────────────────────────────────────────
_rt294 = _run294(["bash", os.path.join(_root, "tools", "run-tests.sh")], env=dict(os.environ, RUN_TESTS_UNIT="unti"),
                 timeout=60)
check("run-tests.sh: RUN_TESTS_UNIT it does not know (a misspelt `unit`) stops the run, before any check",
      _rt294.returncode == 2 and "RUN_TESTS_UNIT=unti" in _rt294.stderr and "==" not in _rt294.stdout,
      repr((_rt294.returncode, _rt294.stdout[-200:], _rt294.stderr[-200:])))
with open(os.path.join(_root, "tools", "run-tests.sh"), encoding="utf-8") as _fh294:
    _rts294 = _fh294.read()
check("run-tests.sh: without the unit lane, the lanes are still held to every other suite exactly once",
      "mapfile -t suites < <(printf '%s\\n' \"${ALL_SUITES[@]}\" | grep -vx unit_suite)" in _rts294
      and 'want="$(printf \'%s\\n\' "${suites[@]}" | sort)"' in _rts294
      and 'if [[ "$got" != "$want" ]]; then' in _rts294, "run_lanes' check")


# ── 4. ci.yml ─────────────────────────────────────────────────────────────────────────────────────
_ci294 = _wf29("ci.yml")
_UNITS294 = ["unit %d/4" % i for i in range(1, 5)]


def _parts294(job):
    text = _job29(_ci294, job)
    m = _re294.search(r"^        part: \[ (.*) \]$", text, _re294.M)
    return [v.strip() for v in m.group(1).split(",")] if m else _re294.findall(r"^          - part: (.*)$", text, _re294.M)


eq("ci.yml: each checks leg and the coverage run are the four unit shards and one part for the rest",
   (_parts294("checks"), _parts294("coverage")), (_UNITS294 + ["suites"], _UNITS294 + ["suites"]))
_ids294 = _re294.findall(r"^            id: (\w+)$", _job29(_ci294, "coverage"), _re294.M)
_comb294 = _wf_run_block(_job29(_ci294, "coverage-verdict"), "Combine the parts' data into one report")
check("ci.yml: coverage-verdict combines the data of every coverage part, and fails on any part's missing",
      _ids294 == ["unit1", "unit2", "unit3", "unit4", "suites"]
      and "for id in %s; do" % " ".join(_ids294) in _comb294 and 'exit 1' in _comb294, repr((_ids294, _comb294[:300])))


def _verdict_bad294(job, needs, name, step):
    """What is wrong with one verdict job's wiring ([] when nothing)."""
    text = _job29(_ci294, job)
    return [why for bad, why in (
        ("    name: %s\n" % name not in text, "not named %r" % name),
        ("    needs: %s\n" % needs not in text, "does not need %s" % needs),
        ("    if: ${{ always() }}\n" not in text, "not always()"),
        ("RESULT: ${{ needs.%s.result }}\n" % needs not in text, "does not read the parts' result"),
        (step not in [_name29(s) for s in _steps29(text)], "no step %r" % step),
    ) if bad]


_vbad294 = {j: _verdict_bad294(j, n, nm, st) for j, n, nm, st in (
    ("checks-verdict", "checks", "checks (${{ matrix.os }} · py${{ matrix.python }})", "Every part of every leg passed"),
    ("coverage-verdict", "coverage", "coverage", "Every part of the coverage run passed"))}
check("ci.yml: the checks each leg reports, and coverage, come from verdict jobs that run whatever happened "
      "(always()) and read every part's result, under the names the ruleset requires",
      not any(_vbad294.values()), repr(_vbad294))


def _verdicts294(step, tmp):
    """{RESULT: exit status} of a verdict step's own script, cut out of ci.yml, run by bash."""
    path = os.path.join(tmp, "verdict.sh")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_wf_run_block(_ci294, step))
    return {r: _run294(["bash", "-e", path], env=dict(os.environ, RESULT=r)).returncode
            for r in ("success", "failure", "cancelled", "skipped", "")}


with _tf294.TemporaryDirectory() as _tmp294:
    _vr294 = {s: _verdicts294(s, _tmp294) for s in ("Every part of every leg passed",
                                                    "Every part of the coverage run passed")}
check("ci.yml: a verdict passes only when every part passed: failed, cancelled, skipped or no result fails it",
      all(v == {"success": 0, "failure": 1, "cancelled": 1, "skipped": 1, "": 1} for v in _vr294.values()),
      repr(_vr294))

# The root step's own Python, on made-up logs of two runs: the same shard is judged; two shards are refused.
_judge_src294 = _wf_run_block(_ci294, "Run the root-only unit checks, as root")
_judge294 = _judge_src294[_judge_src294.find("<<'EOF'\n") + 8:_judge_src294.rfind("\nEOF")]
_USER294 = ("PASS  a\nSKIP  root gate   [skipped: needs root]\n\nunit shard 2/4: 3 of 9 parts: x\n\n1 / 1 checks passed\n")
_ROOT294 = "PASS  a\nPASS  root gate\nPASS  r1\n\nunit shard 2/4: 3 of 9 parts: x\n\n3 / 3 checks passed\n"


def _judge_rc294(user, root, tmp):
    u, r = os.path.join(tmp, "u.txt"), os.path.join(tmp, "r.txt")
    for path, text in ((u, user), (r, root)):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    p = _run294([_sys294.executable, "-", u, r], input=_judge294)
    return p.returncode, "not the same part" in p.stdout


with _tf294.TemporaryDirectory() as _tmp294:
    _jr294 = [_judge_rc294(_USER294, _ROOT294, _tmp294),
              _judge_rc294(_USER294, _ROOT294.replace("shard 2/4", "shard 3/4"), _tmp294),
              _judge_rc294(_USER294, _ROOT294.replace("\nunit shard 2/4: 3 of 9 parts: x\n", ""), _tmp294)]
eq("ci.yml: the root step judges a root run of the same shard, and refuses one of another shard or of the whole suite",
   _jr294, [(0, False), (1, True), (1, True)])


# A shared module that runs checks or pushes a context when first imported belongs to the one part that
# imports it: imported by a second part, it runs inside whichever of the two comes first in a shard, out
# of its place (part124 importing reboot41_a for a list of names ran part41's fixtures, and left the
# request context only part41 pops for every part after it).
def _side_effect_mods294():
    """{unit.<module>} of tests/unit's shared modules that record checks or push a context at import."""
    import ast as _ast294
    out = set()
    for name in sorted(os.listdir(os.path.join(_root, "tests", "unit"))):
        if not name.endswith(".py") or _re294.fullmatch(r"part\d+\.py|__init__\.py", name):
            continue
        with open(os.path.join(_root, "tests", "unit", name), encoding="utf-8") as fh:
            if _side_effect294(_ast294.parse(fh.read())):
                out.add("unit." + name[:-3])
    return out


def _side_effect294(tree):
    """Whether a module records a check at its top level, or pushes a context anywhere."""
    import ast as _ast294
    top = [n.value.func for n in tree.body if isinstance(n, _ast294.Expr) and isinstance(n.value, _ast294.Call)]
    if any(isinstance(n, _ast294.Attribute) and n.attr == "push" for n in _ast294.walk(tree)):
        return True
    return any(isinstance(f, _ast294.Name) and f.id in ("check", "eq", "skip") for f in top)


def _mods_reached294(part):
    """The shared unit.* modules `part` imports, directly or through other shared modules."""
    seen, todo = set(), sorted(_sh294._module_imports("unit." + part, _root))
    while todo:
        mod = todo.pop()
        if mod in seen or _re294.fullmatch(r"unit\.part\d+", mod):
            continue
        seen.add(mod)
        todo.extend(sorted(_sh294._module_imports(mod, _root)))
    return seen


_side294 = _side_effect_mods294()
_reach294 = {p: _mods_reached294(p) for p in _PARTS294}
_shared294 = {m: sorted(p for p in _PARTS294 if m in _reach294[p]) for m in sorted(_side294)}
check("unit shards: a shared module that runs checks or pushes a context at import is imported by one part only "
      "(reboot41_fixtures, through every reboot41 module: part41)",
      "unit.reboot41_fixtures" in _side294 and _shared294.get("unit.reboot41_fixtures") == ["part41"]
      and all(len(v) <= 1 for v in _shared294.values()), repr({m: v for m, v in _shared294.items() if len(v) != 1}))
