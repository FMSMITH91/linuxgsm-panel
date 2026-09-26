"""Part 7 of the unit suite: GHSA-hh39-76g3-wxcx, the gates. Imported for its side effects."""
# GHSA-hh39-76g3-wxcx: a game server's account (short_name) and LinuxGSM script name (lgsm_name)
# went into `sudo -u <account> bash -c '<body>'` unquoted and unchecked from twenty-five builders,
# while the model's @validates hook checks them only on ASSIGNMENT — never on a row loaded from the
# database, a restored backup, or a hand edit. Every such command is now built by one choke point
# (_core.game_user_cmd / game_user_exec_cmd), which refuses an unsafe name. Three parts hold that:
#
#   1. GATES over panel/**/*.py (AST, so comments and docstrings are not code): no `sudo -u` built
#      with an unquoted interpolation; no `sudo -u` built anywhere BUT the two builders, which must
#      validate first; and every helper call whose body names the LinuxGSM script passes it along
#      (or the function checks it). Each gate has a CONTROL that proves it can fail. THIS part.
#   2. BEHAVIOUR, per converted function: every unsafe name is refused, nothing reaches the
#      transport, and the refusal reads as the function's own "could not run" — never as an empty,
#      healthy answer. A plain name still sends its command, spelled exactly as the old builders
#      spelled it. tests/unit/part08.py.
#   3. DATA LAYER: a backup whose database carries such a row is refused before anything is
#      touched, and a clean one still restores; a row LOADED with one is flagged, not fatal.
#      tests/unit/part09.py.
import ast as _gh_ast

from unit.part01 import check, os, re  # noqa: E402
from unit import REPO_ROOT as _gh_root  # noqa: E402

# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 1. GATES
# ═══════════════════════════════════════════════════════════════════════════════════════════════
# Text that ends in `sudo [-flags] -u ` (or --user=): whatever is interpolated next is the account.
_GH_TAIL = re.compile(r"\bsudo(?:\s+-{1,2}[A-Za-z][\w-]*)*\s+(?:-u\s*|--user[=\s]\s*)\Z")
_GH_FORMAT_TAIL = re.compile(r"\bsudo(?:\s+-{1,2}[A-Za-z][\w-]*)*\s+(?:-u\s*|--user[=\s]\s*)\{")
_GH_PCT = re.compile(r"%(?:\(([^)]*)\))?[#0\- +]*(?:\*|\d+)?(?:\.(?:\*|\d+))?([diouxXeEfFgGcrsa%])")
_GH_QUOTERS = {"_quote", "quote"}
_GH_BUILDERS = {"game_user_cmd", "game_user_exec_cmd"}
_GH_BUILDER_FILE = os.path.join("panel", "ops", "ssh_manager", "_core.py")
_GH_VALIDATORS = {"_require_game_idents", "game_idents_ok", "_idents_ok"}
_GH_HELPER_CALLS = {"game_user_cmd", "game_user_exec_cmd", "shell_as_game_user"}
_GH_SELF_NAMES = {"selfname", "lgsm_name"}
# ...and where a script name comes from WITHOUT one of those names: a GameServer's own attributes.
# console_log is `/home/<account>/log/console/<lgsm_name>-console.log`, lgsm_name is
# `<game_type>server`, and all of it is loaded from the database. The first version of this gate
# keyed on the two local NAMES only, so `log_path = gs.console_log` handed to read_as_game_user
# with no selfname= was invisible to it — the console poller ran game_type unchecked (review F1).
_GH_SELF_ATTRS = {"lgsm_name", "game_type", "console_log", "server_script"}
# Every helper that runs panel-built TEXT as a game account, and so must be told the script name
# when the text carries one. read_as_game_user was missing from the first version.
_GH_TEXT_RUNNERS = {"shell_as_game_user", "read_as_game_user", "game_user_cmd", "game_user_exec_cmd"}


def _gh_callee(call):
    f = call.func
    return f.attr if isinstance(f, _gh_ast.Attribute) else (f.id if isinstance(f, _gh_ast.Name) else "")


def _gh_quoted(v):
    return isinstance(v, _gh_ast.Call) and _gh_callee(v) in _GH_QUOTERS


def _gh_trailing_text(node):
    """The literal text a string expression ENDS with, or None when it ends in a value."""
    if isinstance(node, _gh_ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, _gh_ast.JoinedStr) and node.values:
        last = node.values[-1]
        return last.value if isinstance(last, _gh_ast.Constant) else None
    if isinstance(node, _gh_ast.BinOp) and isinstance(node.op, _gh_ast.Add):
        return _gh_trailing_text(node.right)
    return None


def _gh_fstring_sites(n):
    """(line, value, "fstring") for each value f-string `n` interpolates right after `sudo -u`."""
    out, prev = [], ""
    for v in n.values:
        if isinstance(v, _gh_ast.Constant) and isinstance(v.value, str):
            prev = v.value
        elif isinstance(v, _gh_ast.FormattedValue):
            if _GH_TAIL.search(prev):
                out.append((n.lineno, v.value, "fstring"))
            prev = ""
    return out


def _gh_is_str_percent(n):
    """Is `n` a `"literal text" % args` expression?"""
    return (isinstance(n, _gh_ast.BinOp) and isinstance(n.op, _gh_ast.Mod)
            and isinstance(n.left, _gh_ast.Constant) and isinstance(n.left.value, str))


def _gh_pct_named(right, key):
    """The value a `%(key)s` conversion takes from `right` when that is a dict literal, else None."""
    val = None
    if isinstance(right, _gh_ast.Dict):
        for k, dv in zip(right.keys, right.values):
            if isinstance(k, _gh_ast.Constant) and k.value == key:
                val = dv
    return val


def _gh_percent_sites(n):
    """(line, value or None, "percent") for each conversion of `n` whose text ends in `sudo -u`."""
    fmt = n.left.value
    args = n.right.elts if isinstance(n.right, _gh_ast.Tuple) else [n.right]
    out, i = [], 0
    for m in _GH_PCT.finditer(fmt):
        if m.group(2) == "%":
            continue
        if m.group(1) is not None:
            val = _gh_pct_named(n.right, m.group(1))
        else:
            val = args[i] if i < len(args) else None
            i += 1
        if _GH_TAIL.search(fmt[:m.start()]):
            out.append((n.lineno, val, "percent"))
    return out


def _gh_concat_sites(n):
    """[(line, value, "concat")] when the `+` in `n` appends a value to text ending in `sudo -u`."""
    t = _gh_trailing_text(n.left)
    if t is None or not _GH_TAIL.search(t):
        return []
    r = n.right
    if isinstance(r, _gh_ast.JoinedStr) and r.values and isinstance(r.values[0], _gh_ast.FormattedValue):
        return [(n.lineno, r.values[0].value, "concat")]
    if not isinstance(r, (_gh_ast.Constant, _gh_ast.JoinedStr)):
        return [(n.lineno, r, "concat")]
    return []


def _gh_is_str_format(n):
    """Is `n` a `"literal text".format(...)` call?"""
    return (isinstance(n, _gh_ast.Call) and isinstance(n.func, _gh_ast.Attribute)
            and n.func.attr == "format" and isinstance(n.func.value, _gh_ast.Constant))


def _gh_argv_sites(n):
    """(line, value, "argv") for each value list/tuple literal `n` puts after "sudo" ... "-u"."""
    out, elts, seen_sudo = [], n.elts, False
    for j, e in enumerate(elts):
        if isinstance(e, _gh_ast.Constant) and e.value == "sudo":
            seen_sudo = True
        elif (seen_sudo and isinstance(e, _gh_ast.Constant) and e.value in ("-u", "--user")
              and j + 1 < len(elts) and not isinstance(elts[j + 1], _gh_ast.Constant)):
            out.append((n.lineno, elts[j + 1], "argv"))
    return out


def _gh_node_sites(n):
    """The `sudo -u` sites AST node `n` itself builds, as _gh_sites lists them."""
    if isinstance(n, _gh_ast.JoinedStr):
        return _gh_fstring_sites(n)
    if _gh_is_str_percent(n):
        return _gh_percent_sites(n)
    if isinstance(n, _gh_ast.BinOp) and isinstance(n.op, _gh_ast.Add):
        return _gh_concat_sites(n)
    if _gh_is_str_format(n) and isinstance(n.func.value.value, str):
        return [(n.lineno, None, "format")] if _GH_FORMAT_TAIL.search(n.func.value.value) else []
    if isinstance(n, (_gh_ast.List, _gh_ast.Tuple)):
        return _gh_argv_sites(n)
    return []


def _gh_sites(tree):
    """Every [(line, value node or None, kind)] where a command puts a value after `sudo -u`."""
    # kind is how the COMMAND STRING is built — "fstring", "percent", "concat" or "format" — or
    # "argv" for a list-form argv.
    return [site for n in _gh_ast.walk(tree) for site in _gh_node_sites(n)]


def _gh_functions(tree):
    return [n for n in _gh_ast.walk(tree) if isinstance(n, (_gh_ast.FunctionDef, _gh_ast.AsyncFunctionDef))]


def _gh_enclosing(funcs, line):
    best = None
    for f in funcs:
        if f.lineno <= line <= f.end_lineno and (best is None or f.lineno > best.lineno):
            best = f
    return best


def _gh_names_script(node, tainted):
    """Does expression `node` carry a script name: a tainted local, or a GameServer attribute?"""
    return any((isinstance(x, _gh_ast.Name) and x.id in tainted)
               or (isinstance(x, _gh_ast.Attribute) and x.attr in _GH_SELF_ATTRS)
               for x in _gh_ast.walk(node))


# Calls whose RESULT is still the text they were handed. Any other call makes a new value:
# `vals = lgsm_get_values(server, user, selfname, …)` is config values, not the script name.
_GH_TEXT_CALLS = {"str", "strip", "lstrip", "rstrip", "lower", "upper", "replace", "format", "join",
                  "_quote", "quote"}


def _gh_carries(node, tainted):
    """Does the VALUE of expression `node` carry the script name as text?"""
    if isinstance(node, _gh_ast.Name):
        return node.id in tainted
    if isinstance(node, _gh_ast.Attribute):
        return node.attr in _GH_SELF_ATTRS or _gh_carries(node.value, tainted)
    if isinstance(node, _gh_ast.Call):
        if _gh_carries(node.func, tainted):            # a method of a value that carries it
            return True
        return _gh_callee(node) in _GH_TEXT_CALLS and any(
            _gh_carries(a, tainted) for a in list(node.args) + [k.value for k in node.keywords])
    return any(_gh_carries(c, tainted) for c in _gh_ast.iter_child_nodes(node))


def _gh_assignment(n):
    """(targets, value) when statement or expression `n` assigns (=, :=, +=, x: T = v), else None."""
    if isinstance(n, _gh_ast.Assign):
        return n.targets, n.value
    if isinstance(n, (_gh_ast.AnnAssign, _gh_ast.AugAssign, _gh_ast.NamedExpr)):
        return [n.target], n.value
    return None


def _gh_taint_step(func, tainted):
    """Add to `tainted` each name `func` assigns from a value carrying one; True if any was new."""
    grew = False
    for n in _gh_ast.walk(func):
        assigned = _gh_assignment(n)
        if assigned is None or assigned[1] is None or not _gh_carries(assigned[1], tainted):
            continue
        for t in assigned[0]:
            for x in _gh_ast.walk(t):
                if isinstance(x, _gh_ast.Name) and x.id not in tainted:
                    tainted.add(x.id)
                    grew = True
    return grew


def _gh_tainted(func):
    """The local names in `func` that carry the script name, to a fixed point."""
    # selfname / lgsm_name, and every name assigned from an expression whose value does
    # (`log_path = gs.console_log`).
    tainted, grew = set(_GH_SELF_NAMES), True
    while grew:
        grew = _gh_taint_step(func, tainted)
    return tainted


def _gh_validates_before(func, line, names=None):
    """True when `func` calls a validator at or before `line` — on one of `names`, when given."""
    # "On one of `names`": one of those names, or a GameServer script attribute, is among the
    # validator's arguments.
    for n in _gh_ast.walk(func):
        if isinstance(n, _gh_ast.Call) and _gh_callee(n) in _GH_VALIDATORS and n.lineno <= line:
            if names is None:
                return True
            if any(_gh_names_script(a, names) for a in n.args):
                return True
    return False


def _gh_text_holders(n):
    """The expressions AST node `n` puts into TEXT: f-string, % or +, .format(), tmux socket."""
    if isinstance(n, _gh_ast.FormattedValue):
        return [n.value]
    if isinstance(n, _gh_ast.BinOp) and isinstance(n.op, (_gh_ast.Mod, _gh_ast.Add)):
        return [n.left, n.right]
    if isinstance(n, _gh_ast.Call) and _gh_callee(n) == "_tmux_live_socket_sh":
        return list(n.args)
    if _gh_is_str_format(n):
        return list(n.args) + [k.value for k in n.keywords]
    return []


def _gh_interpolates_self(func, tainted=None):
    """Does `func` put the LinuxGSM script name into TEXT (anywhere _gh_text_holders looks)?"""
    tainted = _gh_tainted(func) if tainted is None else tainted
    return any(_gh_names_script(h, tainted) for n in _gh_ast.walk(func) for h in _gh_text_holders(n))


def _gh_in_builder(fn, rel):
    """Is `fn` (a function node, or None) one of the two checked builders, in their own file?"""
    return fn is not None and fn.name in _GH_BUILDERS and rel == _GH_BUILDER_FILE


def _gh_checks_account_before(fn, line):
    """Does `fn` call _require_game_idents at or before `line`?"""
    return any(isinstance(n, _gh_ast.Call) and _gh_callee(n) == "_require_game_idents"
               and n.lineno <= line for n in _gh_ast.walk(fn))


def _gh_site_problems(rel, fn, site):
    """The G1/G2 problems of one `sudo -u` site (line, value, kind) of `rel`, inside `fn` or None."""
    line, val, kind = site
    where = "%s:%d %s()" % (rel, line, fn.name if fn else "<module>")
    if kind == "argv":
        # An argv has no shell to escape — but sudo still RESOLVES the name ("#0" is uid 0).
        if fn is None or not _gh_validates_before(fn, line):
            return ["G2 %s: a `sudo -u` argv with no account check before it" % where]
        return []
    out = []
    if kind == "format" or not _gh_quoted(val):
        out.append("G1 %s: `sudo -u` built with an unquoted %s interpolation" % (where, kind))
    if not _gh_in_builder(fn, rel):
        out.append("G2 %s: `sudo -u` built outside _core.game_user_cmd/game_user_exec_cmd" % where)
    elif not _gh_checks_account_before(fn, line):
        out.append("G2 %s: the builder does not check the account before building" % where)
    return out


def _gh_runner_calls(tree, funcs):
    """[(call, its function)] for each text-runner or _rewrite_crontab call outside the builders."""
    out = []
    for n in _gh_ast.walk(tree):
        if not (isinstance(n, _gh_ast.Call) and _gh_callee(n) in (_GH_TEXT_RUNNERS | {"_rewrite_crontab"})):
            continue
        fn = _gh_enclosing(funcs, n.lineno)
        if fn is None or fn.name in _GH_BUILDERS or fn.name == "shell_as_game_user":
            continue
        out.append((n, fn))
    return out


def _gh_call_problem(rel, n, fn):
    """The G3 problem of runner call `n` in `fn`, or None: its body names the script, unpassed."""
    tainted = _gh_tainted(fn)
    if not _gh_interpolates_self(fn, tainted):
        return None
    passes_self = _gh_callee(n) in _GH_TEXT_RUNNERS and any(k.arg == "selfname" for k in n.keywords)
    if passes_self or _gh_validates_before(fn, n.lineno, tainted):
        return None
    return ("G3 %s:%d %s(): its body names the LinuxGSM script, and %s() is neither "
            "given selfname= nor preceded by a check of it" % (rel, n.lineno, fn.name, _gh_callee(n)))


def _gh_scan(src, rel):
    """(problems, sites, helper_calls) for one module's source. `rel` is its repo-relative path."""
    tree = _gh_ast.parse(src)
    funcs = _gh_functions(tree)
    sites = _gh_sites(tree)
    problems = [p for s in sites for p in _gh_site_problems(rel, _gh_enclosing(funcs, s[0]), s)]
    calls = _gh_runner_calls(tree, funcs)
    helper_calls = len([n for n, _fn in calls if _gh_callee(n) in _GH_HELPER_CALLS])
    problems += [p for p in (_gh_call_problem(rel, n, fn) for n, fn in calls) if p]
    return problems, sites, helper_calls


def _gh_panel_modules():
    """[(repo-relative path, source)] of every panel/**/*.py."""
    out = []
    for dp, dns, fns in os.walk(os.path.join(_gh_root, "panel")):
        dns[:] = [d for d in dns if d != "__pycache__"]
        for fn in sorted(fns):
            if fn.endswith(".py"):
                path = os.path.join(dp, fn)
                with open(path, encoding="utf-8") as f:
                    out.append((os.path.relpath(path, _gh_root), f.read()))
    return out


_gh_modules = _gh_panel_modules()
_gh_problems, _gh_all_sites, _gh_helper_calls, _gh_files = [], [], 0, 0
for _gh_rel, _gh_src in _gh_modules:
    _gh_p, _gh_s, _gh_h = _gh_scan(_gh_src, _gh_rel)
    _gh_files += 1
    _gh_problems += _gh_p
    _gh_all_sites += [(_gh_rel,) + s for s in _gh_s]
    _gh_helper_calls += _gh_h

check("GHSA-hh39 gate: the scan read the panel's modules (not an empty walk)",
      _gh_files >= 50, "%d files" % _gh_files)
check("GHSA-hh39 gate G1/G2/G3: every `sudo -u` is built by the checked builder, quoted, with the "
      "script name passed along",
      not _gh_problems, "; ".join(_gh_problems[:6]))
# The anchor, matched ONCE each: the gate above passes vacuously if the scanner cannot see the
# builders, so the scanner must find exactly the three sites that are allowed to exist.
_gh_where = sorted((r, ln, k) for r, ln, _v, k in _gh_all_sites)
check("GHSA-hh39 gate: the scanner finds exactly the two string builders and the one argv site",
      [(r, k) for r, _ln, k in _gh_where] == [
          (_GH_BUILDER_FILE, "fstring"),
          (_GH_BUILDER_FILE, "fstring"),
          (os.path.join("panel", "ops", "ssh_manager", "cron.py"), "argv")],
      repr(_gh_where))
check("GHSA-hh39 gate: ...and the command sites it checks for selfname actually exist",
      _gh_helper_calls >= 40, "%d helper calls" % _gh_helper_calls)

# ── CONTROLS: each gate, fed a planted bad snippet, must fail — and a good one must not ────────
_GH_BUILDER_REL = _GH_BUILDER_FILE


def _gh_plant(src, rel="panel/planted.py"):
    return _gh_scan(src, rel)[0]


_gh_ctl = {
    "G1 f-string": _gh_plant('def f(user):\n    return f"sudo -u {user} bash -c x"\n'),
    "G1 percent": _gh_plant('def f(user, x):\n    return "sudo -u %s bash -c %s" % (user, _quote(x))\n'),
    "G1 concat": _gh_plant('def f(user):\n    return "sudo -n -u " + user\n'),
    "G1 .format": _gh_plant('def f(user):\n    return "sudo -u {} bash".format(user)\n'),
    "G2 quoted but outside the builder": _gh_plant(
        'def f(user):\n    return f"sudo -u {_quote(user)} bash -c x"\n'),
    "G2 the builder without its check": _gh_plant(
        'def game_user_cmd(user, inner, selfname=None):\n'
        '    return f"sudo -u {_quote(user)} bash -c {_quote(inner)}"\n', _GH_BUILDER_REL),
    "G2 an argv with no check": _gh_plant('def f(user):\n    return ["sudo", "-u", user, "cat"]\n'),
    "G3 script name dropped": _gh_plant(
        'def f(server, user, selfname):\n'
        '    return _core.shell_as_game_user(server, user, f"./{selfname} details")\n'),
    "G3 crontab line names an unchecked script": _gh_plant(
        'def f(server, user, selfname):\n'
        '    return _rewrite_crontab(server, user, "", [f"* * * * * /home/{user}/{selfname}"])\n'),
    # The review's F1, as it was written in server_files._console_tick: no local is NAMED selfname
    # or lgsm_name, the script name arrives through a GameServer attribute and a local.
    "G3 console path from a GameServer attribute, via a local, to read_as_game_user": _gh_plant(
        'def f(gs):\n'
        '    log_path = gs.console_log\n'
        '    return _sm.read_as_game_user(gs.remote, gs.short_name, f"tail -5 {log_path}")\n'),
    "G3 game_type straight into the text": _gh_plant(
        'def f(gs):\n'
        '    return _core.shell_as_game_user(gs.remote, gs.short_name, "./%sserver x" % gs.game_type)\n'),
    "G3 through a string method and .format()": _gh_plant(
        'def f(server, user, gs):\n'
        '    name = (gs.lgsm_name or "").strip()\n'
        '    return _core.shell_as_game_user(server, user, "./{} details".format(name))\n'),
}
check("GHSA-hh39 gate CONTROL: every planted bad shape is caught, by the gate it belongs to",
      all(any(p.startswith(k.split()[0] + " ") for p in v) for k, v in _gh_ctl.items()),
      {k: v for k, v in _gh_ctl.items() if not any(p.startswith(k.split()[0] + " ") for p in v)})
_gh_good = {
    "the builder, checked": _gh_plant(
        'def game_user_cmd(user, inner, selfname=None):\n'
        '    _require_game_idents(user, selfname)\n'
        '    return f"sudo -u {_quote(user)} bash -c {_quote(inner)}"\n', _GH_BUILDER_REL),
    "an argv, checked": _gh_plant(
        'def f(user):\n    _core._require_game_idents(user)\n    return ["sudo", "-u", user]\n'),
    "script name passed": _gh_plant(
        'def f(server, user, selfname):\n'
        '    return _core.shell_as_game_user(server, user, f"./{selfname} x", selfname=selfname)\n'),
    "script name checked first": _gh_plant(
        'def f(server, user, selfname):\n'
        '    if not _core.game_idents_ok(user, selfname):\n        return None\n'
        '    return _rewrite_crontab(server, user, "", [f"/home/{user}/{selfname}"])\n'),
    "a comment or docstring mentioning it": _gh_plant(
        'def f(user):\n    """`sudo -u {user} bash -c` used to be spelled here."""\n'
        '    # f"sudo -u {user}"\n    return 1\n'),
    "the console path WITH the script name passed": _gh_plant(
        'def f(gs):\n'
        '    log_path = gs.console_log\n'
        '    return _sm.read_as_game_user(gs.remote, gs.short_name, f"tail -5 {log_path}",\n'
        '                                 selfname=gs.lgsm_name)\n'),
    "a game_type attribute checked first": _gh_plant(
        'def f(gs):\n'
        '    if not _core.game_idents_ok(gs.short_name, gs.lgsm_name):\n        return None\n'
        '    return _core.shell_as_game_user(gs.remote, gs.short_name, f"./{gs.lgsm_name} x")\n'),
    # A call's RESULT is not the name it was handed: this is player_count_via_lgsm_query's shape,
    # and a taint that flowed through every call argument called it a script name.
    "config values READ with the script name are not the script name": _gh_plant(
        'def f(server, user, selfname):\n'
        '    vals = files.lgsm_get_values(server, user, selfname, ["port"])\n'
        '    q = vals.get("port").strip()\n'
        '    return _core.shell_as_game_user(server, user, "gamedig %s" % q)\n'),
}
check("GHSA-hh39 gate CONTROL: ...and the correct shapes pass (the gate is not a blanket no)",
      not any(_gh_good.values()), {k: v for k, v in _gh_good.items() if v})


# ── G4: every system-ssh argv takes its destination from ssh_destination, after `--` ─────────
# Review F4: four argvs handed `<username>@<host>` from a LOADED row to ssh, which reads a leading
# dash as an option. Every list literal that begins with "ssh" must put SSH_DEST_SEP immediately
# before an ssh_destination(...) call — so a fifth ssh argv cannot be added the old way.
def _gh_is_ssh_list(n):
    """Is `n` a list literal whose first element is the string "ssh"?"""
    return (isinstance(n, _gh_ast.List) and n.elts and isinstance(n.elts[0], _gh_ast.Constant)
            and n.elts[0].value == "ssh")


def _gh_whole_argv(n, parent):
    """The elements of every list in the `+` chain that list `n` is part of: one command line."""
    # `["ssh", …] + _ssh_mux_opts() + ["-p", …, dest]` is one argv.
    top = n
    while isinstance(parent.get(top), _gh_ast.BinOp) and isinstance(parent[top].op, _gh_ast.Add):
        top = parent[top]
    return [e for part in _gh_ast.walk(top) if isinstance(part, _gh_ast.List) for e in part.elts]


def _gh_has_option(elts):
    """Does the argv `elts` pass a literal option — is it a command line at all?"""
    return any(isinstance(e, _gh_ast.Constant) and isinstance(e.value, str) and e.value.startswith("-")
               for e in elts)


def _gh_dest_after_sep(elts):
    """Does the argv `elts` put SSH_DEST_SEP immediately before an ssh_destination(...) call?"""
    for a, b in zip(elts, elts[1:]):
        sep = (isinstance(a, (_gh_ast.Name, _gh_ast.Attribute))
               and (getattr(a, "id", None) or getattr(a, "attr", None)) == "SSH_DEST_SEP")
        if sep and isinstance(b, _gh_ast.Call) and _gh_callee(b) == "ssh_destination":
            return True
    return False


def _gh_ssh_argv_problems(src, rel):
    """The G4 problems of `src` (at `rel`): ssh argvs whose destination skips the checked pair."""
    out, tree = [], _gh_ast.parse(src)
    parent = {c: p for p in _gh_ast.walk(tree) for c in _gh_ast.iter_child_nodes(p)}
    for n in _gh_ast.walk(tree):
        if not _gh_is_ssh_list(n):
            continue
        elts = _gh_whole_argv(n, parent)
        if not _gh_has_option(elts):
            continue    # ["ssh"] naming the service, ["ssh", n] naming its journal: not a command line
        if not _gh_dest_after_sep(elts):
            out.append("G4 %s:%d: an ssh argv whose destination is not SSH_DEST_SEP, "
                       "ssh_destination(...)" % (rel, n.lineno))
    return out


_gh_ssh_found, _gh_ssh_bad = 0, []
for _gh_rel, _gh_src in _gh_modules:
    _gh_ssh_bad += _gh_ssh_argv_problems(_gh_src, _gh_rel)
    # Counted by the SAME definition, with the destination rule made unsatisfiable.
    _gh_ssh_found += len(_gh_ssh_argv_problems(_gh_src.replace("ssh_destination(", "ssh_dest_off("), "x"))
check("GHSA-hh39 gate G4: every system-ssh argv takes its destination from ssh_destination, after `--`",
      not _gh_ssh_bad, "; ".join(_gh_ssh_bad[:4]))
check("GHSA-hh39 gate G4: ...and it found the four ssh argvs there are (the Tailscale transport, two "
      "downloads, the terminal)", _gh_ssh_found == 4, "%d found" % _gh_ssh_found)
check("GHSA-hh39 gate G4 CONTROL: the old spelling fails it, and the new one passes",
      _gh_ssh_argv_problems('a = ["ssh", "-p", "22", f"{s.username}@{h}", cmd]\n', "x.py")
      and _gh_ssh_argv_problems('a = ["ssh", "-p", "22", _core.ssh_destination(u, h), cmd]\n', "x.py")
      and not _gh_ssh_argv_problems('a = ["ssh", "-p", "22", _core.SSH_DEST_SEP, '
                                    '_core.ssh_destination(u, h), cmd]\n', "x.py"))
