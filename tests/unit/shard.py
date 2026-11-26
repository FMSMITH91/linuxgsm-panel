"""Which parts of the unit suite one shard runs, when the suite is split to run side by side.

UNIT_SHARD=i/n (1 <= i <= n) runs shard i of n; unset or empty, the runner runs every part as it
always has. Every shard runs part01-part12 first (the shared setup every later part builds on) and
part15 last (it judges the run-wide records of the parts its own process ran). Each other part is
OWNED by exactly one shard. A shard also runs, at its own place in _PARTS, every part an owned part
imports, directly or through a shared module: a part imported but not listed would run inside the
importing part's import, out of order, so the shard lists it. Such a part's checks then run in each
shard that needs it, which costs time but never loses a check.

The owners are chosen to even out the shards' time, from the measured seconds per part in
shard_weights.json (milliseconds, whole numbers: the plan is computed separately in every shard's
process, so it must not depend on float rounding or on set order, which PYTHONHASHSEED changes).
A part with no measurement counts FALLBACK_MS. Nothing here imports the panel or eventlet.
"""
import ast
import json
import os
import re
import sys

SETUP = 12                 # part01-part12, in _PARTS order, first in every shard
TAIL = ("part15",)         # last in every shard
FALLBACK_MS = 2000         # a part shard_weights.json has not measured yet
MAX_SHARDS = 32
_HERE = os.path.dirname(os.path.abspath(__file__))
_SPEC = re.compile(r"([1-9][0-9]*)/([1-9][0-9]*)")


def parse(value):
    """(i, n) for 'i/n'; None for unset or empty; ValueError for anything else."""
    if value is None or value == "":
        return None
    m = _SPEC.fullmatch(value)
    if m is None or not int(m.group(1)) <= int(m.group(2)) <= MAX_SHARDS:
        raise ValueError("UNIT_SHARD=%r: expected i/n with 1 <= i <= n <= %d" % (value, MAX_SHARDS))
    return int(m.group(1)), int(m.group(2))


def from_env(environ):
    """The shard UNIT_SHARD names, or None; a malformed value ends the run at once (exit 1), naming it."""
    try:
        return parse(environ.get("UNIT_SHARD"))
    except ValueError as e:
        raise SystemExit(str(e)) from None


def runs_whole_suite_gates(shard):
    """Whether this run holds the gates that read the whole suite: the unsplit run, or shard 1."""
    return shard is None or shard[0] == 1


def _module_imports(module, root):
    """The unit.* modules `module` (unit.<name>) imports, in any spelling; none when it has no file."""
    path = os.path.join(root, "tests", *module.split(".")) + ".py"
    if not os.path.isfile(path):
        return set()
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    return {m for node in ast.walk(tree) for m in _named(node) if m.startswith("unit.")}


def _named(node):
    """The modules one import statement names (none for any other node)."""
    if isinstance(node, ast.Import):
        return [a.name for a in node.names]
    if not isinstance(node, ast.ImportFrom):
        return []
    mod = ("unit" + ("." + node.module if node.module else "")) if node.level == 1 else node.module
    if not mod:
        return []
    return [mod] + (["unit." + a.name for a in node.names] if mod == "unit" else [])


def parts_reached(part, root, seen=None):
    """{partNN} `part` imports, directly or through non-part unit modules."""
    seen = set() if seen is None else seen
    out = set()
    for mod in sorted(_module_imports("unit." + part, root)):
        name = mod[len("unit."):]
        if re.fullmatch(r"part\d+", name):
            out.add(name)
        elif mod not in seen:
            seen.add(mod)
            out |= parts_reached(name, root, seen)
    return out


def import_graph(parts, root):
    """{part: sorted list of the parts it reaches}, for every part of `parts`."""
    return {p: sorted(parts_reached(p, root)) for p in parts}


def load_weights(path=None):
    """{part: milliseconds} from shard_weights.json."""
    with open(path or os.path.join(_HERE, "shard_weights.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    return {k: int(v) for k, v in data["ms"].items()}


def _closure(part, graph):
    """`part` and every part it reaches, through the parts it reaches too."""
    out, todo = set(), [part]
    while todo:
        p = todo.pop()
        if p not in out:
            out.add(p)
            todo.extend(graph.get(p, ()))
    return out


def plan(parts, graph, weights, n, setup=SETUP):
    """[owned parts of shard 1, ..., of shard n], each in _PARTS order."""
    always = set(parts[:setup]) | set(TAIL)
    order = {p: i for i, p in enumerate(parts)}

    def cost(names):
        return sum(weights.get(p, FALLBACK_MS) for p in sorted(names))

    base = set()
    for p in always:
        base |= _closure(p, graph)
    runs = [set(base) for _ in range(n)]
    owned = [[] for _ in range(n)]
    rest = [p for p in parts if p not in always]
    # Heaviest first (with what it drags in); a tie keeps _PARTS order. Each goes where the slowest
    # shard ends up least slow, then where it adds the least work (a shard already running it as an
    # import costs nothing more), then to the lower shard.
    for p in sorted(rest, key=lambda q: (-cost(_closure(q, graph) - base), order[q])):
        need = _closure(p, graph)
        loads = [cost(r) for r in runs]
        top = max(loads)
        i = min(range(n), key=lambda k: (max(top, cost(runs[k] | need)), cost(runs[k] | need) - loads[k], k))
        runs[i] |= need
        owned[i].append(p)
    return [sorted(o, key=order.get) for o in owned]


def run_list(parts, graph, owned, setup=SETUP):
    """The parts one shard runs, in _PARTS order: the setup, what it owns with all they import, part15 last."""
    keep = set(parts[:setup]) | set(TAIL)
    for p in list(keep) + list(owned):
        keep |= _closure(p, graph)
    head = [p for p in parts if p in keep and p not in TAIL]
    return head + [p for p in parts if p in TAIL]


def shard_parts(shard, parts, root):
    """The run list for `shard` (i, n) over the runner's _PARTS."""
    graph = import_graph(parts, root)
    owned = plan(parts, graph, load_weights(), shard[1])
    return run_list(parts, graph, owned[shard[0] - 1])


def whole_gate(check, shard):
    """(a check() that records only where this run holds the whole-suite gates, the names it recorded)."""
    ran = []

    def whole_check(name, cond, detail=""):
        if runs_whole_suite_gates(shard):
            ran.append(name)
            check(name, cond, detail)
    return whole_check, ran


def _split_problems(parts, n, root, reached):
    """What is wrong with the split of `parts` into n shards ([] when nothing), and the run lists."""
    graph = import_graph(parts, root)
    owned = plan(parts, graph, load_weights(), n)
    lists = [run_list(parts, graph, o) for o in owned]
    flat = [p for o in owned for p in o]
    bad = sorted((set(parts[SETUP:]) - set(TAIL)) ^ set(flat)) + sorted({p for p in flat if flat.count(p) > 1})
    return bad + _lists_problems(parts, graph, lists) + _reader_problems(parts, graph, reached), lists


def _lists_problems(parts, graph, lists):
    """A run list missing a part one of its parts imports, or out of _PARTS order."""
    bad = ["%s: %s not listed" % (p, q) for lst in lists for p in lst for q in graph[p] if q not in lst]
    return bad + ["a list leaves _PARTS order" for lst in lists if lst != [p for p in parts if p in lst]]


def _reader_problems(parts, graph, reached):
    """Each part whose imports this module reads otherwise than the runner's order gate does."""
    return ["%s: the readers differ" % p for p in parts if set(graph[p]) != {"part" + d for d in reached("unit." + p)}]


def end_gates(check, whole_check, whole_ran, shard, lists, root, reached):
    """The runner's end-of-run gates on which parts ran, for the unsplit run or for one shard.

    `lists` is (_PARTS, the parts this run imported, every tests/unit/part*.py), and `reached` the order
    gate's import reader (_r16d_parts_reached), which the split's own reader must agree with.
    """
    parts, run, on_disk = lists
    if shard is None:
        _unsplit_gate(check, parts, on_disk)
    else:
        _shard_gates(check, whole_check, shard, lists, root, reached)
    # The whole-suite gates ran once each, here, exactly when this run holds them (the unsplit run, or shard 1).
    # Counted from the shard itself, not through runs_whole_suite_gates, which this is the check on.
    want = 8 if shard is None else 9 if shard[0] == 1 else 0
    check("unit suite: the whole-suite gates ran here exactly when this run holds them, each once",
          len(set(whole_ran)) == len(whole_ran) == want, "shard %r: %d ran" % (shard, len(whole_ran)))


def _unsplit_gate(check, parts, on_disk):
    """The unsplit run imported every part file, each from its own place in _PARTS."""
    modules = sys.modules
    check("unit suite: every tests/unit/part*.py was imported and ran, each from its own place in _PARTS",
          bool(on_disk) and all("unit." + p in modules for p in on_disk) and set(on_disk) == set(parts),
          "never ran: %s; not in _PARTS: %s" % ([p for p in on_disk if "unit." + p not in modules],
                                                sorted(set(on_disk) ^ set(parts))))


def _shard_gates(check, whole_check, shard, lists, root, reached):
    """A shard ran exactly its run list; once (shard 1), the split itself holds; and the run says which shard."""
    parts, run, on_disk = lists
    # Every part of the run list ran, and no part outside it was imported (one would have run inside
    # another part's import, out of order).
    ran = sorted(m[len("unit."):] for m in sys.modules if re.fullmatch(r"unit\.part\d+", m))
    check("unit suite: this shard imported every part of its run list, each from its own place in _PARTS, and no other part",
          bool(ran) and ran == sorted(run), "shard %d/%d; never ran: %s; ran, not listed: %s" % (
              shard + (sorted(set(run) - set(ran)), sorted(set(ran) - set(run)))))
    # The split: every part file is in _PARTS, each part but the setup and part15 is owned by exactly one
    # shard, every shard's list holds what its parts import and keeps _PARTS order, and the split's import
    # reader agrees with the order gate's.
    bad, shard_lists = _split_problems(parts, shard[1], root, reached)
    whole_check("unit suite: every tests/unit/part*.py is in _PARTS, and the shards own each part but the setup "
                "and part15 exactly once, each shard listing every part its parts import, in _PARTS order",
                not bad and set(on_disk) == set(parts) and bool(on_disk) and shard_lists[shard[0] - 1] == list(run),
                "not in _PARTS: %s; %s" % (sorted(set(on_disk) ^ set(parts)), bad[:6]))
    # Which shard this was: CI's root step refuses two runs of different shards.
    print("\nunit shard %d/%d: %d of %d parts: %s" % (shard + (len(run), len(parts), " ".join(run))))
