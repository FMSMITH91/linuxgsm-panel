"""Which unit parts a change can affect: the map of what each part touches, and the selection made from it.

RECORDING (UNIT_IMPACT_RECORD=<file>, set by CI's coverage job, which runs every part on every push to
main). While each part runs, the runner's recorder notes, under that part's name, every file of the
checkout the part EXECUTES (a sys.monitoring tool: the first call of each code object in each part,
re-armed between parts), READS (the "open" audit event), LISTS (os.listdir, os.scandir, glob) or
names on a command line it starts (subprocess.Popen). `impact.py build` merges the shards' records
into one map: {path: [parts]} for each of the three, plus when and from which commit it was made.

SELECTING (`select`, used by CI on a pull request through .github/scripts/unit_select.py, and by the
runner for UNIT_SELECT=auto). The parts run are:
  - the setup (part01-part12) and part15, which every run holds (tests/unit/shard.py);
  - every part that walks the tree (it listed a directory of the checkout while it ran): the census,
    i18n, What's-new, route-list and workflow-text gates read whatever is there, so they always run;
  - every part the change edits, and every part that imports one of those;
  - every part the map says executed, read or named a changed file (a deleted or renamed one's old
    path included), and every part that listed the directory a file was added to or removed from.
Everything runs instead (the answer is None, with the reason) when the change touches the runner, a
shared test module, the requirements, a workflow, install.sh or tools/; when a changed file is one
the map has no record of; and when the map is missing, unreadable, of another version, or older than
MAX_AGE_DAYS. Any doubt runs everything: a part not selected is a part the map PROVES never touched
what changed, in a full run made from a commit at most MAX_AGE_DAYS old.

Nothing here imports the panel or eventlet; the recorder needs Python 3.12+ (sys.monitoring).
"""
import ast
import datetime
import fnmatch
import json
import os
import re
import subprocess  # nosec B404 - git with a fixed argv, no shell
import sys

VERSION = 1
MAX_AGE_DAYS = 7
SETUP = 12
TAIL = ("part15",)
_PART = re.compile(r"part\d+\Z")
_PART_FILE = re.compile(r"tests/unit/(part\d+)\.py\Z")
# A change to any of these can change what every part does, or how the suite is run: everything runs.
FULL_PATTERNS = (
    "tests/unit_test.py", "tests/suite_deadline.py", "tests/unit/*.py", "tests/unit/shard_weights.json",
    "requirements*.txt", "panel/install/requirements*", ".github/workflows/*", ".github/scripts/*",
    ".github/ci-requirements-checks/*", ".github/coveragerc", "install.sh", "tools/*", "tools/**",
)


def full_reason(paths):
    """The first path among `paths` that makes everything run, with why; None when none does."""
    for p in paths:
        if _PART_FILE.match(p):
            continue
        for pat in FULL_PATTERNS:
            if fnmatch.fnmatchcase(p, pat):
                return "%s changed (matches %s): the whole suite runs" % (p, pat)
    return None


def _closure_users(changed_parts, graph):
    """The changed parts and every part that imports one of them, directly or through another part."""
    users = {p: {q for q, deps in graph.items() if p in deps} for p in graph}
    out, todo = set(), list(changed_parts)
    while todo:
        p = todo.pop()
        if p not in out:
            out.add(p)
            todo.extend(users.get(p, ()))
    return out


def map_problem(imap, now):
    """Why `imap` cannot be used (None when it can): its shape, version and age."""
    if not isinstance(imap, dict) or imap.get("version") != VERSION:
        return "the map is missing or of another version"
    if not all(isinstance(imap.get(k), dict) for k in ("run", "read", "listed")):
        return "the map is not in the expected shape"
    try:
        made = datetime.datetime.fromisoformat(imap["made"])
    except (KeyError, TypeError, ValueError):
        return "the map does not say when it was made"
    if made.tzinfo is None:
        return "the map's time has no zone"
    age = now - made
    if age < datetime.timedelta(minutes=-10) or age > datetime.timedelta(days=MAX_AGE_DAYS):
        return "the map was made %s, more than %d days from now" % (imap["made"], MAX_AGE_DAYS)
    return None


def _module_of(path):
    """The dotted module name of a .py path ("panel/ops/x.py" -> "panel.ops.x"; a package's __init__ is the package)."""
    parts = path[:-3].split("/")
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _from_base(node, module, is_pkg):
    """The module a `from ... import` names, its relative dots resolved against `module`."""
    base = node.module or ""
    if not node.level:
        return base
    pkg = module.split(".") if is_pkg else module.split(".")[:-1]
    pkg = pkg[:len(pkg) - node.level + 1]
    return ".".join(pkg + ([base] if base else []))


def _imported_names(tree, module, is_pkg):
    """Every module name an ast `tree` of `module` imports, a `from x import y` giving both x and x.y."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _from_base(node, module, is_pkg)
            out.add(base)
            out.update(base + "." + a.name for a in node.names if base)
    return out


_SKIP = ("tests/", "tools/", ".venv/", "venv/", "node_modules/")


def _code_files(root, skip=_SKIP):
    """{module name: path} for every .py file of the checkout's code (not tests, tools or a virtualenv)."""
    files = {}
    for dirpath, dirnames, names in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        dirnames[:] = [d for d in dirnames
                       if not d.startswith(".") and not os.path.normpath(os.path.join(rel_dir, d)).startswith(skip)
                       and (os.path.normpath(os.path.join(rel_dir, d)) + "/") not in skip]
        for rel in (os.path.normpath(os.path.join(rel_dir, n)) for n in names if n.endswith(".py")):
            if not rel.startswith(skip):
                files[_module_of(rel)] = rel
    return files


def _parsed(root, rel):
    """The ast of the checkout's file `rel`, or None when it cannot be read or parsed."""
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            return ast.parse(fh.read())
    except (OSError, SyntaxError, ValueError):
        return None


def importers(root):
    """{path: {paths of the checkout's .py files that import it}} for the code tree.

    Read from the tree under test, not the map, so an import added after the map was made still
    selects the parts that ran the importing module. One level: the parts that ran a module through
    a longer chain ran the modules on it, which the map already holds.
    """
    files = _code_files(root)
    direct = {}
    for mod, rel in files.items():
        tree = _parsed(root, rel)
        names = _imported_names(tree, mod, rel.endswith("__init__.py")) if tree is not None else ()
        for target in {files.get(n) for n in names} - {None, rel}:
            direct.setdefault(target, set()).add(rel)
    return direct


def walkers(imap):
    """Every part that listed the checkout's own top directory while it ran: the gates that walk the whole tree.

    A part that lists one directory (the templates, the scripts) is selected through that directory
    when a file is added to or removed from it, and through each file it reads when one changes.
    """
    return set(imap["listed"].get(".", ()))


def recorded(imap):
    """Every part the map holds any record for."""
    return {p for kind in ("run", "read", "listed") for parts in imap[kind].values() for p in parts}


def _always(parts, imap, since_map):
    """The parts every selection runs.

    They are the setup, part15, the tree walkers, the parts the map has no record of, and the parts main
    changed after the map was made.
    """
    keep = set(parts[:SETUP]) | set(TAIL) | (walkers(imap) & set(parts)) | (set(parts) - recorded(imap))
    return keep | {m.group(1) for m in map(_PART_FILE.match, since_map or ()) if m}


def _file_hits(path, gone, imap, users, since_map):
    """The parts the map ties to the changed file `path` (None: none, everything must run).

    `gone`: the path was added, removed or renamed, so the parts that listed its directory count too.
    """
    hit = set(imap["run"].get(path, ())) | set(imap["read"].get(path, ()))
    if gone:
        hit |= set(imap["listed"].get(os.path.dirname(path) or ".", ()))
    if not hit:
        return None
    for user in users.get(path, ()):
        if since_map is None or user in since_map:
            hit |= set(imap["run"].get(user, ()))
    return hit


def _path_parts(path, gone, parts, imap, users, since_map):
    """(whether `path` is a part's own file, the parts it selects, why everything runs instead or "")."""
    m = _PART_FILE.match(path)
    if m:
        return True, {m.group(1)}, ("" if m.group(1) in parts else "%s is not in _PARTS" % path)
    hit = _file_hits(path, gone, imap, users, since_map)
    return False, hit or set(), ("" if hit else "%s is a file no part was recorded touching" % path)


def _touched(changes):
    """(path, gone) for every path `changes` names: each new path, and each renamed file's old one."""
    for status, path, old in changes:
        if path:
            yield path, status[:1] in "ADR"
        if old:
            yield old, True


def select(changes, parts, graph, imap, now, users=None, since_map=None):
    """(set of parts to run, why) for `changes`; (None, why) when everything must run.

    `changes` is [(status, path, old_path or None)] with git's status letter (A, M, D, R...),
    `parts` the runner's _PARTS, `graph` {part: [parts it imports]} (shard.import_graph).

    What changed on main after the map was made can make the map miss a part: `since_map` is the set
    of paths main changed between the map's commit and the tree under test (None: not known). A part
    the map has no record of (added since), and a part main changed since, always run. A changed module
    also selects every part that ran a module importing it (`users`, {path: paths importing it}, read
    from the tree under test by importers()), when that importer changed since the map, so a call
    added after the map is followed; when `since_map` is not known, every importer counts.
    """
    if not changes:
        return None, "no changed file was listed"
    why = full_reason([p for p, _ in _touched(changes)]) or map_problem(imap, now)
    if why:
        return None, why
    keep, edited = _always(parts, imap, since_map), set()
    for path, gone in _touched(changes):
        part, hit, why = _path_parts(path, gone, parts, imap, users or {}, since_map)
        if why:
            return None, why
        (edited if part else keep).update(hit)
    keep = (keep | _closure_users(edited, graph)) & set(parts)
    return keep, "%d of %d parts touch what changed" % (len(keep), len(parts))


def build_map(records, made, commit):
    """One map from the shards' records ({part: {"run": [...], "read": [...], "listed": [...]}} each)."""
    out = {"version": VERSION, "made": made, "commit": commit, "run": {}, "read": {}, "listed": {}}
    for rec in records:
        for part, kinds in rec.items():
            for kind in ("run", "read", "listed"):
                for path in kinds.get(kind, ()):
                    out[kind].setdefault(path, set()).add(part)
    for kind in ("run", "read", "listed"):
        out[kind] = {p: sorted(s, key=lambda q: int(q[4:])) for p, s in sorted(out[kind].items())}
    return out


def git_changes(root, base):
    """[(status, path, old_path)] between the merge base of `base` and the working tree, untracked files added."""
    def git(*args):
        return subprocess.run(["git", "-C", root] + list(args), capture_output=True, text=True,  # nosec B603
                              check=True).stdout
    mb = git("merge-base", base, "HEAD").strip()
    out = []
    for row in git("diff", "--name-status", "-M", mb).splitlines():
        cols = row.split("\t")
        out.append((cols[0], cols[-1], cols[1] if cols[0][:1] in "RC" else None))
    out += [("A", p, None) for p in git("ls-files", "--others", "--exclude-standard").splitlines()]
    return out


def changed_since(root, commit, base):
    """The paths changed between `commit` and the merge base of `base` and HEAD; None when git cannot say."""
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        return None
    try:
        mb = subprocess.run(["git", "-C", root, "merge-base", base, "HEAD"], capture_output=True, text=True,  # nosec B603
                            check=True).stdout.strip()
        out = subprocess.run(["git", "-C", root, "diff", "--name-only", commit, mb], capture_output=True,  # nosec B603
                             text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return set(out.split())


def parse_env(value, parts):
    """UNIT_SELECT: None (everything), "auto", or a tuple of part names; ValueError for anything else."""
    if value is None or not value.strip():
        return None
    if value.strip() == "auto":
        return "auto"
    names = tuple(re.split(r"[\s,]+", value.strip()))
    bad = [n for n in names if not _PART.match(n) or n not in parts]
    if bad:
        raise ValueError("UNIT_SELECT names parts not in _PARTS: %s" % " ".join(bad[:6]))
    return names


def from_env(environ, parts, graph, root, now=None):
    """(selected part names or None, why) for the runner, from UNIT_SELECT; exit 1 on a malformed value."""
    try:
        want = parse_env(environ.get("UNIT_SELECT"), parts)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    if want is None:
        return None, "UNIT_SELECT is not set"
    if want != "auto":
        return set(want) | set(parts[:SETUP]) | set(TAIL), "UNIT_SELECT names them"
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        with open(environ.get("UNIT_IMPACT_MAP") or "", encoding="utf-8") as fh:
            imap = json.load(fh)
        base = environ.get("UNIT_SELECT_BASE") or "origin/main"
        changes = git_changes(root, base)
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        return None, "auto: %s: %s" % (type(e).__name__, str(e)[:200])
    return select(changes, parts, graph, imap, now, importers(root), changed_since(root, imap.get("commit"), base))


def _closure_of(seeds, graph):
    """`seeds` and every part they import, all the way down."""
    keep, todo = set(), list(seeds)
    while todo:
        p = todo.pop()
        if p not in keep:
            keep.add(p)
            todo.extend(graph.get(p, ()))
    return keep


def narrow(run, selected, graph, owned=None):
    """`run` (a run list, in _PARTS order) cut to its setup, part15, the selected parts it owns and what they import.

    `owned` is the shard's own parts (tests/unit/shard.py's plan); None for the unsplit run, which owns them all.
    A selected part that is in `run` only because an owned part imports it is kept through that import.
    """
    mine = set(run) if owned is None else set(owned)
    seeds = set(run[:SETUP]) | (set(run) & set(TAIL)) | (set(run) & set(selected) & mine)
    keep = _closure_of(seeds, graph)
    return [p for p in run if p in keep]


class Recorder:
    """What each part executes, reads, lists and names on a command line, when UNIT_IMPACT_RECORD names a file."""

    def __init__(self, environ, root):
        """Start recording when UNIT_IMPACT_RECORD is set; otherwise every method does nothing."""
        self.path = environ.get("UNIT_IMPACT_RECORD") or None
        self.part = None
        self.data = {}
        if not self.path:
            return
        mon = getattr(sys, "monitoring", None)
        if mon is None:
            raise SystemExit("UNIT_IMPACT_RECORD needs Python 3.12 or later (sys.monitoring)")
        self.root = os.path.abspath(root)
        self._mon = mon
        self._tool = next(t for t in (3, 4) if mon.get_tool(t) is None)
        mon.use_tool_id(self._tool, "unit-impact")
        mon.register_callback(self._tool, mon.events.PY_START, self._started)
        mon.set_events(self._tool, mon.events.PY_START)
        sys.addaudithook(self._audit)

    def _rel(self, path):
        """`path` relative to the checkout, or None when it is outside it."""
        try:
            p = os.path.abspath(os.fsdecode(path))
        except (TypeError, ValueError):
            return None
        if p == self.root:
            return "."
        return p[len(self.root) + 1:] if p.startswith(self.root + os.sep) else None

    def _add(self, kind, path):
        if self.part is not None:
            rel = self._rel(path)
            if rel is not None:
                self.data[self.part][kind].add(rel)

    def _started(self, code, _offset):
        self._add("run", code.co_filename)
        return self._mon.DISABLE

    def _audit(self, event, args):
        if self.part is None:
            return
        if event == "open" and isinstance(args[0], (str, bytes)):
            self._add("read", args[0])
        elif event in ("os.listdir", "os.scandir") and isinstance(args[0], (str, bytes)):
            self._add("listed", args[0])
        elif event == "glob.glob" and isinstance(args[0], str):
            self._add("listed", os.path.dirname(args[0].split("*", 1)[0]) or ".")
        elif event == "subprocess.Popen":
            self._argv(args[1], args[2])

    def _argv(self, argv, cwd):
        """Every checkout path an argument names, alone or inside a shell script."""
        argv = [argv] if isinstance(argv, (str, bytes)) else list(argv or ())
        here = os.fsdecode(cwd) if cwd else os.getcwd()
        for a in (os.fsdecode(a) for a in argv if isinstance(a, (str, bytes))):
            self._arg(a, here)

    def _arg(self, a, here):
        """The checkout paths one argument names: inside it anywhere, or as a whole relative path."""
        for m in re.finditer(re.escape(self.root) + r"/[^\s'\"`;|&)]+", a):
            self._add("read", m.group(0))
        if "/" in a and "\n" not in a and len(a) < 400 and os.path.exists(os.path.join(here, a)):
            self._add("read", os.path.join(here, a))

    def start(self, part):
        """Record what follows under `part`, re-arming the per-code-object call event."""
        if self.path:
            self.data.setdefault(part, {"run": set(), "read": set(), "listed": set()})
            self.part = part
            self._mon.restart_events()

    def stop(self):
        """Stop recording under the current part."""
        self.part = None

    def save(self):
        """Write this run's record: {part: {"run": [...], "read": [...], "listed": [...]}}."""
        if self.path:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump({p: {k: sorted(v) for k, v in kinds.items()} for p, kinds in self.data.items()}, fh)


def main(argv):
    """`build <out> <commit> <record>...` merges records into a map; `select <map> [base]` prints a local selection."""
    if len(argv) >= 5 and argv[1] == "build":
        records = []
        for path in argv[4:]:
            with open(path, encoding="utf-8") as fh:
                records.append(json.load(fh))
        made = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        imap = build_map(records, made, argv[3])
        with open(argv[2], "w", encoding="utf-8") as fh:
            json.dump(imap, fh)
        print("impact map: %d parts, %d files run, %d read, %d directories listed"
              % (len({p for k in ("run", "read", "listed") for v in imap[k].values() for p in v}),
                 len(imap["run"]), len(imap["read"]), len(imap["listed"])))
        return 0
    print("usage: impact.py build <out.json> <commit> <record.json>...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
