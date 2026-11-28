"""Part 325 of the unit suite: shorter waits for the unit suite, without a part going untested on main.

1. The per-part clock (tests/unit/timing.py, UNIT_PART_TIMES): silent and writing nothing when unset; set, it
   records every part the runner imports and prints one summary block. The runner wraps each part's import in
   it, and CI's two unit runs set it. shard_weights.json measures every part in _PARTS, and the plan's four
   shards come out within 15% of each other.

HOW IT RUNS. The clock on its own, the runner's and ci.yml's text, and the shard plan on the runner's real _PARTS.
"""
import datetime as _dt325
import io as _io325
import json as _json325
import os
import re as _re325
import subprocess as _sp325  # nosec B404 - python with fixed argvs over this part's own inputs
import sys as _sys325
import tempfile as _tf325

from unit.part01 import _root, check
from unit.part06 import _wf_run_block
from unit import shard as _sh325, timing as _tm325

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
