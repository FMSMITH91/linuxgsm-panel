"""Which functions write an audit row, with every call resolved to the function it really reaches.

tests/rbac_test.py uses this for its gate "every mutating endpoint writes an audit entry". That gate
used to follow callees by BARE NAME: a view that called any function named `_run` counted as audited
when some function named `_run`, anywhere, called log_action. The setup wizard's three Tailscale
routes passed that way while writing no row at all: they reach system_ops._run, and the `_run`s that
log are two unrelated workers.

So each call is resolved statically, the way Python would resolve it:

  * a bare name through the function's own scope, then the enclosing functions', then the module's
    globals — never a class body's, which a method does not see — so a parameter, a local, or a
    `for` / `with ... as` / `except ... as` name that shadows a global is not the global;
  * `import x as y`, `from x import y` and `from .x import y` followed to the module that defines
    the name, through re-exports, star imports (the names __all__ lists, else the public ones), and
    a package's PEP 562 __getattr__ over the modules in its _MODULES tuple (panel.ops.ssh_manager),
    first one first, as at run time; `y = x.fn` makes `y` an alias of what `x.fn` is;
  * `mod.fn` and `mod.sub.fn` on a resolved module, `self.fn` / `cls.fn` inside a method, and
    `Class.fn`, including a base class the walk can resolve; calling a class runs its __init__;
  * only the calls in a function's own body: a nested def's calls are that def's, reached only
    when something calls it;
  * a function PASSED to a call (threading.Thread(target=fn), start_background_task(fn),
    functools.partial(fn)) counts as reached by the caller, because that is how a route hands its
    work to a worker thread.

Anything else (a call on an object the walk cannot type, getattr(), a dict of functions) resolves to
nothing and so never counts as logging. That is the conservative direction: a route that logs only
through such a call fails the gate, and has to be read and listed, instead of passing by a name
that happens to match.
"""
import ast
import collections
import pathlib

LOG_MODULE, LOG_NAME = "panel.security.auth", "log_action"
_SKIP = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_BLOCKS = ("body", "orelse", "finalbody", "handlers")
# What `name = <value>` binds `name` to: an alias of a name or attribute, or a sequence (read only
# for a package's _MODULES). Any other value leaves the name opaque.
_ASSIGN_KINDS = {ast.Name: "expr", ast.Attribute: "expr", ast.Tuple: "seq", ast.List: "seq"}


class _Scope:
    """The names one module, function or class body binds: name -> binding (None = unreadable)."""

    __slots__ = ("names", "parent", "mod", "kind", "cls", "self_name", "stars")

    def __init__(self, mod, kind="module", parent=None):
        """Start an empty `kind` scope in module `mod`; a lookup that misses goes on to `parent`."""
        self.names, self.parent, self.mod, self.kind = {}, parent, mod, kind
        self.cls, self.self_name, self.stars = None, None, []


def module_name(root, path):
    """The dotted module name of `path` under `root` (a package's __init__.py is the package)."""
    parts = list(pathlib.Path(path).relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


class CallGraph:
    """Resolved call edges between the functions of a set of modules, and which reach log_action."""

    def __init__(self, sources):
        """Build from {module name: (source text, is_package)}."""
        self._mods, self._pkg, self._fns, self._cls = {}, {}, {}, {}
        for name, (text, is_pkg) in sources.items():
            self._pkg[name] = name if is_pkg else name.rpartition(".")[0]
            scope = _Scope(name)
            self._mods[name] = scope
            self._bind_block(ast.parse(text).body, scope, name)
        self._edges = {key: self._callees(node, scope) for key, (node, scope) in self._fns.items()}
        self._to_log = self._reaching(self._log_key())

    @classmethod
    def from_tree(cls, root, paths):
        """Build from the files `paths` of a checkout at `root`."""
        return cls({module_name(root, p): (pathlib.Path(p).read_text(encoding="utf-8"),
                                           pathlib.Path(p).name == "__init__.py") for p in paths})

    # ── binding: what each scope's names refer to ───────────────────────────────────────────────
    def _bind_block(self, stmts, scope, qual):
        for st in stmts:
            self._bind_stmt(st, scope, qual)

    def _bind_stmt(self, st, scope, qual):
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._bind_def(st, scope, qual)
        elif isinstance(st, ast.ClassDef):
            self._bind_class(st, scope, qual)
        elif isinstance(st, ast.Import):
            for al in st.names:
                bound = al.asname or al.name.partition(".")[0]
                scope.names[bound] = ("mod", al.name if al.asname else bound)
        elif isinstance(st, ast.ImportFrom):
            self._bind_from(st, scope)
        elif isinstance(st, ast.Assign):
            self._bind_assign(st, scope)
        else:
            self._bind_other(st, scope, qual)

    def _bind_other(self, st, scope, qual):
        """Blocks (if/try/with/for/while) bind in the enclosing scope; any other store is opaque."""
        if isinstance(st, (ast.Global, ast.Nonlocal)):
            return
        for field in _BLOCKS:
            for sub in getattr(st, field, None) or ():
                self._bind_nested(sub, scope, qual)
        for node in ast.walk(st) if not getattr(st, "body", None) else self._heads(st):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                self._opaque(node.id, scope)

    def _bind_nested(self, sub, scope, qual):
        """One statement of a block, or an except clause (whose `as` name is opaque)."""
        if isinstance(sub, ast.ExceptHandler):
            self._opaque(sub.name, scope)
            self._bind_block(sub.body, scope, qual)
        else:
            self._bind_stmt(sub, scope, qual)

    @staticmethod
    def _heads(st):
        """The parts of a block statement that are not its nested statements (targets, items)."""
        for field, value in ast.iter_fields(st):
            if field not in _BLOCKS:
                for v in value if isinstance(value, list) else [value]:
                    if isinstance(v, ast.AST):
                        yield from ast.walk(v)

    @staticmethod
    def _opaque(name, scope):
        if name:
            scope.names[name] = None

    def _bind_def(self, node, scope, qual):
        name = node.name
        fq = self._qual(qual, scope, name)
        key = (scope.mod, fq, node.lineno)
        inner = _Scope(scope.mod, "function", scope.parent if scope.kind == "class" else scope)
        self._bind_args(node, inner, scope)
        self._bind_block(node.body, inner, fq)
        for st in ast.walk(node):
            if isinstance(st, ast.Global):
                for n in st.names:
                    inner.names.pop(n, None)
        self._fns[key] = (node, inner)
        scope.names[name] = ("fn", key)

    @staticmethod
    def _bind_args(node, inner, scope):
        """Parameters are opaque; a method's first one is its class (not in a staticmethod)."""
        args = node.args
        positional = args.posonlyargs + args.args
        for a in positional + args.kwonlyargs + [args.vararg, args.kwarg]:
            if a is not None:
                inner.names[a.arg] = None
        static = any(getattr(d, "id", None) == "staticmethod" for d in node.decorator_list)
        if scope.kind == "class" and positional and not static:
            inner.cls, inner.self_name = scope.cls, positional[0].arg

    def _bind_class(self, node, scope, qual):
        fq = self._qual(qual, scope, node.name)
        key = (scope.mod, fq, node.lineno)
        body = _Scope(scope.mod, "class", scope)
        body.cls = key
        self._cls[key] = (node, body, scope)
        self._bind_block(node.body, body, fq)
        scope.names[node.name] = ("cls", key)

    @staticmethod
    def _qual(qual, scope, name):
        """The __qualname__ Python gives `name` defined in `scope`, whose own qualname is `qual`."""
        if scope.kind == "module":
            return name
        return "%s.%s" % (qual, name) if scope.kind == "class" else "%s.<locals>.%s" % (qual, name)

    def _bind_from(self, st, scope):
        base = st.module or ""
        if st.level:
            pkg = self._pkg[scope.mod].split(".")
            pkg = pkg[:len(pkg) - (st.level - 1)]
            base = ".".join(pkg + ([st.module] if st.module else []))
        for al in st.names:
            if al.name == "*":
                scope.stars.append(base)
            else:
                scope.names[al.asname or al.name] = ("from", base, al.name)

    @staticmethod
    def _bind_assign(st, scope):
        """`x = y` and `x = mod.y` are aliases, `_MODULES = (a, b)` is a sequence; else opaque."""
        kind = None
        if len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            kind = _ASSIGN_KINDS.get(type(st.value))
        for node in (n for tgt in st.targets for n in ast.walk(tgt)):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                scope.names[node.id] = (kind, st.value, scope) if kind else None

    # ── resolution: what an expression refers to ─────────────────────────────────────────────────
    def resolve(self, expr, scope, depth=0):
        """The binding an expression (a Name or an attribute chain) resolves to, or None."""
        if depth > 40:
            return None
        if isinstance(expr, ast.Name):
            return self._lookup(expr.id, scope, depth)
        if isinstance(expr, ast.Attribute):
            return self._member(self.resolve(expr.value, scope, depth + 1), expr.attr, depth + 1)
        return None

    def _lookup(self, name, scope, depth):
        while scope is not None:
            if scope.self_name == name:
                return ("cls", scope.cls)
            if name in scope.names:
                return self._settle(scope.names[name], depth)
            if scope.parent is None:
                return self._star(scope, name, depth)
            scope = scope.parent
        return None

    def _star(self, scope, name, depth):
        for base in scope.stars:
            if not self._exports(base, name):
                continue
            found = self._member(("mod", base), name, depth + 1)
            if found is not None:
                return found
        return None

    def _exports(self, base, name):
        """Does `from base import *` bind `name`?

        The names its __all__ lists when it has one, else every name not starting with an
        underscore — as Python does, so `_run` is never one.
        """
        listed = self._mods.get(base, _Scope("")).names.get("__all__")
        if listed and listed[0] == "seq":
            return name in {getattr(e, "value", None) for e in getattr(listed[1], "elts", ())}
        return not name.startswith("_")

    def _settle(self, binding, depth):
        """Follow a lazy binding (an import, an alias) to a module, function or class."""
        if binding is None or depth > 40:
            return None
        kind = binding[0]
        if kind == "from":
            _, base, attr = binding
            sub = "%s.%s" % (base, attr) if base else attr
            if sub in self._mods:
                return ("mod", sub)
            return self._member(("mod", base), attr, depth + 1)
        if kind == "expr":
            return self.resolve(binding[1], binding[2], depth + 1)
        return None if kind == "seq" else binding

    def _member(self, base, attr, depth):
        if base is None or depth > 40:
            return None
        if base[0] == "cls":
            return self._method(base[1], attr, depth)
        if base[0] != "mod" or base[1] not in self._mods:
            return None
        scope = self._mods[base[1]]
        if attr in scope.names:
            return self._settle(scope.names[attr], depth + 1)
        sub = "%s.%s" % (base[1], attr)
        if sub in self._mods:
            return ("mod", sub)
        return self._star(scope, attr, depth) or self._pep562(scope, attr, depth)

    def _pep562(self, scope, attr, depth):
        """A package whose __getattr__ searches the modules of its _MODULES tuple, in order."""
        listed = scope.names.get("_MODULES")
        if "__getattr__" not in scope.names or not listed or listed[0] != "seq":
            return None
        for elt in getattr(listed[1], "elts", ()):
            mod = self.resolve(elt, scope, depth + 1)
            if mod and mod[0] == "mod" and attr in self._mods.get(mod[1], _Scope("")).names:
                return self._member(mod, attr, depth + 1)
        return None

    def _method(self, key, attr, depth):
        if depth > 40:
            return None
        node, body, outer = self._cls[key]
        if attr in body.names:
            return self._settle(body.names[attr], depth + 1)
        for base in node.bases:
            found = self.resolve(base, outer, depth + 1)
            if found and found[0] == "cls":
                hit = self._method(found[1], attr, depth + 1)
                if hit is not None:
                    return hit
        return None

    # ── edges and reachability ───────────────────────────────────────────────────────────────────
    def _body_nodes(self, node):
        """Every node in a function's body, not descending into a nested def or class."""
        todo = list(node.body)
        while todo:
            cur = todo.pop()
            yield cur
            if not isinstance(cur, _SKIP):
                todo.extend(ast.iter_child_nodes(cur))

    def _callees(self, node, scope):
        out = set()
        for cur in self._body_nodes(node):
            if not isinstance(cur, ast.Call):
                continue
            out.update(self._fn_keys(self.resolve(cur.func, scope), call=True))
            for arg in list(cur.args) + [kw.value for kw in cur.keywords]:
                out.update(self._fn_keys(self.resolve(arg, scope), call=False))
        return out

    def _fn_keys(self, binding, call):
        """The functions a call, or a function value passed on, reaches (a class runs __init__)."""
        if binding is None:
            return ()
        if binding[0] == "fn":
            return (binding[1],)
        if binding[0] == "cls" and call:
            init = self._method(binding[1], "__init__", 0)
            return (init[1],) if init and init[0] == "fn" else ()
        return ()

    def _log_key(self):
        found = self._member(("mod", LOG_MODULE), LOG_NAME, 0)
        if not found or found[0] != "fn":
            raise LookupError("%s.%s is not a function this walk can find" % (LOG_MODULE, LOG_NAME))
        return found[1]

    def _reaching(self, target):
        """{function key: the callee it reaches log_action through}, walked back from log_action."""
        callers = collections.defaultdict(set)
        for src, dsts in self._edges.items():
            for dst in dsts:
                callers[dst].add(src)
        via, todo = {}, collections.deque([target])
        while todo:
            cur = todo.popleft()
            for src in sorted(callers[cur]):
                if src not in via:
                    via[src] = cur
                    todo.append(src)
        return via

    # ── queries ──────────────────────────────────────────────────────────────────────────────────
    def function_key(self, mod, qualname, firstlineno=None):
        """The key of the function `qualname` in `mod`, matched by its first line when given."""
        hits = [k for k in self._fns if k[0] == mod and k[1] == qualname
                and firstlineno in (None, self._first_line(k))]
        return hits[-1] if hits else None

    def _first_line(self, key):
        node = self._fns[key][0]
        return node.decorator_list[0].lineno if node.decorator_list else node.lineno

    def logs(self, key):
        """Does the function `key` reach log_action through calls this walk can resolve?"""
        return key in self._to_log

    def chain(self, key):
        """The path from `key` to log_action, as 'module.qualname' strings."""
        out = []
        while key in self._to_log and len(out) < 50:
            out.append("%s.%s" % key[:2])
            key = self._to_log[key]
        return out + ["%s.%s" % (LOG_MODULE, LOG_NAME)] if out else []

    def callees(self, key):
        """The functions `key` reaches directly, as keys."""
        return set(self._edges.get(key, ()))
