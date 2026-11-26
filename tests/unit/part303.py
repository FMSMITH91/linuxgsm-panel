"""Part 303 of the unit suite: the unit suite split into shards that run side by side, and CI's verdict on them.

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
import json as _json303
import os
import re as _re303
import signal as _signal303
import subprocess as _sp303  # nosec B404 - python and bash with fixed argvs over this part's own inputs
import sys as _sys303
import tempfile as _tf303

from unit.part01 import _root, check, eq
from unit.part06 import _wf_run_block
from unit.part29 import _job29, _name29, _steps29, _wf29
from unit import shard as _sh303


def _run303(argv, timeout=120, **kw):
    """The finished process; one still running at `timeout` is killed and answers -9 with what it printed.

    The class of the timeout raised depends on whose subprocess this is (eventlet's green one raises its
    own TimeoutExpired), so it is told by name.
    """
    inp = kw.pop("input", None)
    with _sp303.Popen(argv, stdin=_sp303.PIPE if inp is not None else _sp303.DEVNULL, stdout=_sp303.PIPE,
                      stderr=_sp303.PIPE, text=True, start_new_session=True, **kw) as proc:  # nosec B603 - fixed argvs
        try:
            out, err = proc.communicate(inp, timeout=timeout)
        except Exception as e:  # noqa: BLE001 - re-raised unless it is the timeout
            if type(e).__name__ != "TimeoutExpired":
                raise
            try:
                os.killpg(proc.pid, _signal303.SIGKILL)   # the child and all it started
            except OSError:
                proc.kill()
            out, err = proc.communicate()
            return _sp303.CompletedProcess(argv, -9, out or "", err or "")
    return _sp303.CompletedProcess(argv, proc.returncode, out, err)


with open(os.path.join(_root, "tests", "unit_test.py"), encoding="utf-8") as _fh303:
    _runner303 = _fh303.read()
_at303 = _runner303.index("\n_PARTS = (")
_PARTS303 = tuple(_re303.findall(r'"(part\d+)"', _runner303[_at303:_runner303.index(")", _at303)]))
_graph303 = _sh303.import_graph(_PARTS303, _root)
_weights303 = _sh303.load_weights()
_always303 = set(_PARTS303[:_sh303.SETUP]) | set(_sh303.TAIL)


# ── 1. the split ──────────────────────────────────────────────────────────────────────────────────
def _parse303(value):
    try:
        return _sh303.parse(value)
    except ValueError:
        return "refused"


eq("unit shards: UNIT_SHARD reads i/n, and unset or empty runs the whole suite",
   [_parse303(v) for v in (None, "", "1/4", "4/4", "1/1", "32/32")], [None, None, (1, 4), (4, 4), (1, 1), (32, 32)])
eq("unit shards: ...and anything else is refused, never read as the whole suite or as no shard",
   [_parse303(v) for v in ("0/4", "5/4", "1/0", "a/b", " 1/4", "1/4 ", "01/4", "1/33", "1/4/2", "1", "-1/4", "1/4\n")],
   ["refused"] * 12)


def _split_bad303(n):
    """What is wrong with the split into n shards ([] when nothing)."""
    owned = _sh303.plan(_PARTS303, _graph303, _weights303, n)
    bad = ["%d shards, not %d" % (len(owned), n)] if len(owned) != n else []
    bad += _owned_bad303([p for o in owned for p in o])
    for i, own in enumerate(owned, 1):
        bad += _list_bad303(i, own, _sh303.run_list(_PARTS303, _graph303, own))
    return bad


def _owned_bad303(flat):
    """A part no shard owns, one owned twice, or the setup or part15 owned at all."""
    bad = ["lost: %s" % p for p in _PARTS303 if p not in _always303 and p not in flat]
    bad += ["owned twice: %s" % p for p in sorted(set(flat)) if flat.count(p) > 1]
    return bad + ["setup or part15 owned: %s" % p for p in flat if p in _always303]


def _list_bad303(i, own, lst):
    """What is wrong with shard i's run list `lst` for the parts it owns."""
    bad = ["shard %d: %s imports %s, not listed" % (i, p, q) for p in lst for q in _graph303[p] if q not in lst]
    bad += ["shard %d: an owned part missing" % i for p in own if p not in lst]
    bad += ["shard %d: not in _PARTS order" % i] * (lst != [p for p in _PARTS303 if p in lst])
    return bad + ["shard %d: not the setup first and part15 last" % i] * (
        lst[:_sh303.SETUP] != list(_PARTS303[:_sh303.SETUP]) or lst[-1:] != list(_sh303.TAIL))


_splits303 = {n: _split_bad303(n) for n in range(1, 9)}
check("unit shards: split 1 to 8 ways, every part but the setup and part15 is owned by exactly one shard, and each "
      "shard lists every part its parts import (through shared modules too), in _PARTS order, setup first, part15 last",
      len(_PARTS303) > 250 and not any(_splits303.values()), repr({n: b[:4] for n, b in _splits303.items() if b}))
_loads303 = [sum(_weights303.get(p, _sh303.FALLBACK_MS) for p in _sh303.run_list(_PARTS303, _graph303, o))
             for o in _sh303.plan(_PARTS303, _graph303, _weights303, 4)]
check("unit shards: ...and four shards come out even by the measured times (the slowest within 10% of the fastest), "
      "each well under the whole suite's time", max(_loads303) <= 1.1 * min(_loads303)
      and max(_loads303) < 0.6 * sum(_weights303.get(p, _sh303.FALLBACK_MS) for p in _PARTS303), repr(_loads303))
# A part that imports another drags it in; one with no measurement still gets a shard.
_toy303 = ("a01", "a02", "b1", "b2", "b3", "b4", "part15")
_toygraph303 = {"b3": ["b1"], "b4": []}
_toyplan303 = _sh303.plan(_toy303, _toygraph303, {"b1": 5000, "b2": 4000, "b3": 1000}, 2, setup=2)
_toylists303 = [_sh303.run_list(_toy303, _toygraph303, o, setup=2) for o in _toyplan303]
eq("unit shards: (control) on a made-up suite the heaviest part and what imports it share a shard, a part with no "
   "measurement counts the fallback, and a dragged-in part is listed but owned once",
   (_toyplan303, _toylists303),
   ([["b1", "b3"], ["b2", "b4"]], [["a01", "a02", "b1", "b3", "part15"], ["a01", "a02", "b2", "b4", "part15"]]))

# The same plan in every process: each shard computes it alone, and a part owned by two shards (or by none)
# is what a plan that depended on set order or float rounding would give.
_child303 = ("import json, sys\nsys.path.insert(0, sys.argv[1])\nfrom unit import shard\n"
             "parts = tuple(sys.argv[2].split())\n"
             "print(json.dumps(shard.plan(parts, shard.import_graph(parts, sys.argv[3]), shard.load_weights(), 4)))\n")
_mine303 = _sh303.plan(_PARTS303, _graph303, _weights303, 4)
_seeds303 = {}
for _seed303 in ("1", "2", "3"):
    _p303 = _run303([_sys303.executable, "-c", _child303, os.path.join(_root, "tests"), " ".join(_PARTS303), _root],
                    env=dict(os.environ, PYTHONHASHSEED=_seed303))
    _seeds303[_seed303] = _json303.loads(_p303.stdout) if _p303.returncode == 0 else _p303.stderr[-300:]
check("unit shards: the plan is the same in a child Python under three hash seeds as in this run",
      all(v == _mine303 for v in _seeds303.values()), repr({k: v if isinstance(v, str) else "differs"
                                                           for k, v in _seeds303.items() if v != _mine303}))


# ── 2. the runner ─────────────────────────────────────────────────────────────────────────────────
_bad_env303 = dict(os.environ, UNIT_SHARD="5/4")
_refused303 = _run303([_sys303.executable, os.path.join(_root, "tests", "unit_test.py")], env=_bad_env303, timeout=60)
check("unit runner: UNIT_SHARD=5/4 stops the run at once, naming the value, before any part runs",
      _refused303.returncode == 1 and "UNIT_SHARD='5/4'" in _refused303.stderr and "PASS" not in _refused303.stdout
      and "checks passed" not in _refused303.stdout, repr((_refused303.returncode, _refused303.stderr[-300:])))
eq("unit runner: the whole-suite gates run in the unsplit run and in exactly one shard of any split",
   [_sh303.runs_whole_suite_gates(None)] + [[_sh303.runs_whole_suite_gates((i, n)) for i in range(1, n + 1)].count(True)
                                            for n in range(1, 9)],
   [True] + [1] * 8)
with open(os.path.join(_root, "tests", "unit", "shard.py"), encoding="utf-8") as _fh303:
    _shardsrc303 = _fh303.read()
_wholes303 = _re303.findall(r"^ *_?whole_check\(\"([^\"]+)\"", _runner303 + _shardsrc303, _re303.M)
_plain303 = [n for n in ("unit suite: every ordering note that lists a part's imports lists exactly them",
                         "unit suite: no part imports a part that runs at or after it in _PARTS")
             if ('\ncheck("%s"' % n) in _runner303]
check("unit runner: the gates that read the whole suite (the ordering notes, the import order, the split itself) "
      "are recorded through _whole_check, and the run counts them",
      len(_wholes303) == 9 and not _plain303 and "want = 8 if shard is None else 9 if shard[0] == 1 else 0" in _shardsrc303
      and "_whole_check, _whole_ran = _shard.whole_gate(check, _SHARD)" in _runner303, repr((_wholes303, _plain303)))


# ── 3. run-tests.sh ───────────────────────────────────────────────────────────────────────────────
_rt303 = _run303(["bash", os.path.join(_root, "tools", "run-tests.sh")], env=dict(os.environ, RUN_TESTS_UNIT="unti"),
                 timeout=60)
check("run-tests.sh: RUN_TESTS_UNIT it does not know (a misspelt `unit`) stops the run, before any check",
      _rt303.returncode == 2 and "RUN_TESTS_UNIT=unti" in _rt303.stderr and "==" not in _rt303.stdout,
      repr((_rt303.returncode, _rt303.stdout[-200:], _rt303.stderr[-200:])))
with open(os.path.join(_root, "tools", "run-tests.sh"), encoding="utf-8") as _fh303:
    _rts303 = _fh303.read()
check("run-tests.sh: without the unit lane, the lanes are still held to every other suite exactly once",
      "mapfile -t suites < <(printf '%s\\n' \"${ALL_SUITES[@]}\" | grep -vx unit_suite)" in _rts303
      and 'want="$(printf \'%s\\n\' "${suites[@]}" | sort)"' in _rts303
      and 'if [[ "$got" != "$want" ]]; then' in _rts303, "run_lanes' check")


# ── 4. ci.yml ─────────────────────────────────────────────────────────────────────────────────────
_ci303 = _wf29("ci.yml")
_UNITS303 = ["unit %d/4" % i for i in range(1, 5)]


def _parts303(job):
    text = _job29(_ci303, job)
    m = _re303.search(r"^        part: \[ (.*) \]$", text, _re303.M)
    return [v.strip() for v in m.group(1).split(",")] if m else _re303.findall(r"^          - part: (.*)$", text, _re303.M)


eq("ci.yml: each checks leg and the coverage run are the four unit shards and one part for the rest",
   (_parts303("checks"), _parts303("coverage")), (_UNITS303 + ["suites"], _UNITS303 + ["suites"]))
_ids303 = _re303.findall(r"^            id: (\w+)$", _job29(_ci303, "coverage"), _re303.M)
_comb303 = _wf_run_block(_job29(_ci303, "coverage-verdict"), "Combine the parts' data into one report")
check("ci.yml: coverage-verdict combines the data of every coverage part, and fails on any part's missing",
      _ids303 == ["unit1", "unit2", "unit3", "unit4", "suites"]
      and "for id in %s; do" % " ".join(_ids303) in _comb303 and 'exit 1' in _comb303, repr((_ids303, _comb303[:300])))


def _verdict_bad303(job, needs, name, step):
    """What is wrong with one verdict job's wiring ([] when nothing)."""
    text = _job29(_ci303, job)
    return [why for bad, why in (
        ("    name: %s\n" % name not in text, "not named %r" % name),
        ("    needs: %s\n" % needs not in text, "does not need %s" % needs),
        ("    if: ${{ always() }}\n" not in text, "not always()"),
        ("RESULT: ${{ needs.%s.result }}\n" % needs not in text, "does not read the parts' result"),
        (step not in [_name29(s) for s in _steps29(text)], "no step %r" % step),
    ) if bad]


_vbad303 = {j: _verdict_bad303(j, n, nm, st) for j, n, nm, st in (
    ("checks-verdict", "checks", "checks (${{ matrix.os }} · py${{ matrix.python }})", "Every part of every leg passed"),
    ("coverage-verdict", "coverage", "coverage", "Every part of the coverage run passed"))}
check("ci.yml: the checks each leg reports, and coverage, come from verdict jobs that run whatever happened "
      "(always()) and read every part's result, under the names the ruleset requires",
      not any(_vbad303.values()), repr(_vbad303))


def _verdicts303(step, tmp):
    """{RESULT: exit status} of a verdict step's own script, cut out of ci.yml, run by bash."""
    path = os.path.join(tmp, "verdict.sh")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_wf_run_block(_ci303, step))
    return {r: _run303(["bash", "-e", path], env=dict(os.environ, RESULT=r)).returncode
            for r in ("success", "failure", "cancelled", "skipped", "")}


with _tf303.TemporaryDirectory() as _tmp303:
    _vr303 = {s: _verdicts303(s, _tmp303) for s in ("Every part of every leg passed",
                                                    "Every part of the coverage run passed")}
check("ci.yml: a verdict passes only when every part passed: failed, cancelled, skipped or no result fails it",
      all(v == {"success": 0, "failure": 1, "cancelled": 1, "skipped": 1, "": 1} for v in _vr303.values()),
      repr(_vr303))

# The root step's own Python, on made-up logs of two runs: the same shard is judged; two shards are refused.
_judge_src303 = _wf_run_block(_ci303, "Run the root-only unit checks, as root")
_judge303 = _judge_src303[_judge_src303.find("<<'EOF'\n") + 8:_judge_src303.rfind("\nEOF")]
_USER303 = ("PASS  a\nSKIP  root gate   [skipped: needs root]\n\nunit shard 2/4: 3 of 9 parts: x\n\n1 / 1 checks passed\n")
_ROOT303 = "PASS  a\nPASS  root gate\nPASS  r1\n\nunit shard 2/4: 3 of 9 parts: x\n\n3 / 3 checks passed\n"


def _judge_rc303(user, root, tmp):
    u, r = os.path.join(tmp, "u.txt"), os.path.join(tmp, "r.txt")
    for path, text in ((u, user), (r, root)):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    p = _run303([_sys303.executable, "-", u, r], input=_judge303)
    return p.returncode, "not the same part" in p.stdout


with _tf303.TemporaryDirectory() as _tmp303:
    _jr303 = [_judge_rc303(_USER303, _ROOT303, _tmp303),
              _judge_rc303(_USER303, _ROOT303.replace("shard 2/4", "shard 3/4"), _tmp303),
              _judge_rc303(_USER303, _ROOT303.replace("\nunit shard 2/4: 3 of 9 parts: x\n", ""), _tmp303)]
eq("ci.yml: the root step judges a root run of the same shard, and refuses one of another shard or of the whole suite",
   _jr303, [(0, False), (1, True), (1, True)])


# A shared module that runs checks or pushes a context when first imported belongs to the one part that
# imports it: imported by a second part, it runs inside whichever of the two comes first in a shard, out
# of its place (part124 importing reboot41_a for a list of names ran part41's fixtures, and left the
# request context only part41 pops for every part after it).
def _side_effect_mods303():
    """{unit.<module>} of tests/unit's shared modules that record checks or push a context at import."""
    import ast as _ast303
    out = set()
    for name in sorted(os.listdir(os.path.join(_root, "tests", "unit"))):
        if not name.endswith(".py") or _re303.fullmatch(r"part\d+\.py|__init__\.py", name):
            continue
        with open(os.path.join(_root, "tests", "unit", name), encoding="utf-8") as fh:
            if _side_effect303(_ast303.parse(fh.read())):
                out.add("unit." + name[:-3])
    return out


def _side_effect303(tree):
    """Whether a module records a check at its top level, or pushes a context anywhere."""
    import ast as _ast303
    top = [n.value.func for n in tree.body if isinstance(n, _ast303.Expr) and isinstance(n.value, _ast303.Call)]
    if any(isinstance(n, _ast303.Attribute) and n.attr == "push" for n in _ast303.walk(tree)):
        return True
    return any(isinstance(f, _ast303.Name) and f.id in ("check", "eq", "skip") for f in top)


def _mods_reached303(part):
    """The shared unit.* modules `part` imports, directly or through other shared modules."""
    seen, todo = set(), sorted(_sh303._module_imports("unit." + part, _root))
    while todo:
        mod = todo.pop()
        if mod in seen or _re303.fullmatch(r"unit\.part\d+", mod):
            continue
        seen.add(mod)
        todo.extend(sorted(_sh303._module_imports(mod, _root)))
    return seen


_side303 = _side_effect_mods303()
_reach303 = {p: _mods_reached303(p) for p in _PARTS303}
_shared303 = {m: sorted(p for p in _PARTS303 if m in _reach303[p]) for m in sorted(_side303)}
check("unit shards: a shared module that runs checks or pushes a context at import is imported by one part only "
      "(reboot41_fixtures, through every reboot41 module: part41)",
      "unit.reboot41_fixtures" in _side303 and _shared303.get("unit.reboot41_fixtures") == ["part41"]
      and all(len(v) <= 1 for v in _shared303.values()), repr({m: v for m, v in _shared303.items() if len(v) != 1}))
