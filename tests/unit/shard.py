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
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mod = ("unit" + ("." + node.module if node.module else "")) if node.level == 1 else node.module
            if mod:
                out.add(mod)
                if mod == "unit":
                    out.update("unit." + a.name for a in node.names)
    return {m for m in out if m.startswith("unit.")}


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
        i = min(range(n), key=lambda k: (max(max(loads), cost(runs[k] | need)), cost(runs[k] | need) - loads[k], k))
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
