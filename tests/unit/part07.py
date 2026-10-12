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
import string as _gh_string

from unit.part01 import check, os, re  # noqa: E402
from unit import REPO_ROOT as _gh_root  # noqa: E402

# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 1. GATES
# ═══════════════════════════════════════════════════════════════════════════════════════════════
# Text that ends in `sudo [options] -u ` (or --user=): whatever is interpolated next is the account.
# The last flag may be a COMBINED one ending in u (`sudo -nu `, `sudo -Hu `): `-u` as its own token
# only, the gate never saw `f"sudo -nu {user} ..."` outside the builder. The options before it may
# take a VALUE — sudo's -C -D -g -h -p -R -r -T -t -U do, as `--opt=value` does — and that value
# may itself be interpolated (_GH_HOLE stands for it): with value-less flags only, `sudo -g {grp}
# -u {user}`, `sudo -C 3 -u` and `sudo --preserve-env=PATH -u` all read as clean. A bare word
# (`sudo journalctl -u`) is a command, and ends the options.
_GH_HOLE = "\x00"
_GH_OPTS = (r"\bsudo(?:\s+(?:-[A-Za-z]*[CDghpRrTtU]\s+\S+|--?[A-Za-z][\w-]*(?:=\S*)?|"
            + _GH_HOLE + r"))*\s+(?:-[A-Za-z]*u\s*|--user[=\s]\s*)")
# An opening quote may sit between the flag and the account (`sudo -u '{user}'`): hand-typed
# quotes are no quoting at all against a name holding `'` (GHSA-hh39's own payload class), and
# without the `['"]?` such a site was not seen as a site, by G1 or G2.
_GH_TAIL = re.compile(_GH_OPTS + r"['\"]?\Z")
_GH_FORMAT_TAIL = re.compile(_GH_OPTS + r"['\"]?\{")
# An argv ELEMENT that carries the flag and the account together (`"--user=" + user`, f"-u{user}").
_GH_ARGV_JOINED = re.compile(r"(?:-[A-Za-z]*u|--user=)['\"]?" + _GH_HOLE)
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


def _gh_hole(value):
    """The text an interpolated `value` stands for: the word sudo when it names sudo, else a hole."""
    # `f"{sudo} -u {user}"` / `f"{self._sudo} -u ..."`: the command word itself interpolated.
    return "sudo" if "sudo" in _gh_ast.unparse(value).lower() else _GH_HOLE


def _gh_text(node):
    """The WHOLE text a string expression builds, each interpolated value replaced by _gh_hole."""
    # The whole chain, not its last literal: `"sudo " + "-u " + user` keeps `sudo` and `-u` in two
    # literals, and an f-string's `sudo` and `-u` can sit either side of an interpolated flag.
    if isinstance(node, _gh_ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, _gh_ast.JoinedStr):
        return "".join(v.value if isinstance(v, _gh_ast.Constant) else _gh_hole(v.value)
                       for v in node.values)
    if isinstance(node, _gh_ast.BinOp) and isinstance(node.op, _gh_ast.Add):
        return _gh_text(node.left) + _gh_text(node.right)
    formatted = _gh_formatted_text(node)
    return _gh_hole(node) if formatted is None else formatted


def _gh_formatted_text(node):
    """`"-u%s" % user` / `"--user={}".format(user)` as the literal with each conversion a hole.

    Read as one hole, the flag in the literal was lost and a joined argv element was no site
    (review 1011d). None for any other node.
    """
    if _gh_is_str_percent(node):
        return _GH_PCT.sub(lambda m: "%" if m.group(2) == "%" else _GH_HOLE, node.left.value)
    if _gh_is_str_format(node) and isinstance(node.func.value.value, str):
        return re.sub(r"\{[^{}]*\}", _GH_HOLE,
                      node.func.value.value.replace("{{", "(").replace("}}", ")"))
    return None


def _gh_trailing_text(node):
    """The text a string expression ENDS with, or None when it ends in a value."""
    if isinstance(node, _gh_ast.JoinedStr) and node.values and not isinstance(
            node.values[-1], _gh_ast.Constant):
        return None
    if isinstance(node, (_gh_ast.Constant, _gh_ast.JoinedStr)) or (
            isinstance(node, _gh_ast.BinOp) and isinstance(node.op, _gh_ast.Add)
            and _gh_trailing_text(node.right) is not None):
        text = _gh_text(node)
        return text if isinstance(text, str) else None
    return None


def _gh_fstring_sites(n, prefix=""):
    """(line, value, "fstring") for each value f-string `n` interpolates right after `sudo -u`.

    `prefix` is the text a `+` chain put before the f-string.
    """
    out, text = [], prefix
    for v in n.values:
        if isinstance(v, _gh_ast.Constant) and isinstance(v.value, str):
            text += v.value
        elif isinstance(v, _gh_ast.FormattedValue):
            if _GH_TAIL.search(text):
                out.append((n.lineno, v.value, "fstring"))
            text += _gh_hole(v.value)
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
    # The text before each conversion has the EARLIER ones filled with _gh_hole(their value), as
    # the f-string path does: matched against the raw `"%s -u %s" % (sudo, user)` it had no "sudo"
    # in it, and the sudo word interpolated by % was no site at all (review 1011e).
    fmt = n.left.value
    args = n.right.elts if isinstance(n.right, _gh_ast.Tuple) else [n.right]
    out, i, text, pos = [], 0, "", 0
    for m in _GH_PCT.finditer(fmt):
        text += fmt[pos:m.start()]
        pos = m.end()
        if m.group(2) == "%":
            text += "%"
            continue
        if m.group(1) is not None:
            val = _gh_pct_named(n.right, m.group(1))
        else:
            val = args[i] if i < len(args) else None
            i += 1
        if _GH_TAIL.search(text):
            out.append((n.lineno, val, "percent"))
        text += _GH_HOLE if val is None else _gh_hole(val)
    return out


def _gh_format_arg(n, key, auto):
    """The argument `.format()` call `n` fills field `key` with (auto-numbered at `auto`), or None."""
    args = list(n.args)
    if key == "":
        return args[auto] if auto < len(args) else None
    if key.isdecimal():
        return args[int(key)] if int(key) < len(args) else None
    return {k.arg: k.value for k in n.keywords if k.arg}.get(key)


def _gh_format_sites(n):
    """(line, None, "format") for each `.format()` field whose text ends in `sudo -u`.

    Earlier fields are filled with _gh_hole(their argument), as for % above.
    """
    fmt = n.func.value.value
    try:
        fields = list(_gh_string.Formatter().parse(fmt))
    except ValueError:
        return [(n.lineno, None, "format")] if _GH_FORMAT_TAIL.search(fmt) else []
    out, text, auto = [], "", 0
    for literal, field, _spec, _conv in fields:
        text += literal
        if field is None:
            continue
        if _GH_TAIL.search(text):
            out.append((n.lineno, None, "format"))
        key = field.split(".")[0].split("[")[0]
        val = _gh_format_arg(n, key, auto)
        auto += key == ""
        text += _GH_HOLE if val is None else _gh_hole(val)
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


def _gh_concat_fstring_sites(n):
    """The sites of an f-string on the right of `+`, read with the text the left put before it."""
    # `"sudo " + f"-u {user}"`: alone, the f-string has no `sudo` in it. Its own sites (when it
    # does) are found again here, so _gh_sites drops the duplicates.
    if isinstance(n.right, _gh_ast.JoinedStr):
        left = _gh_trailing_text(n.left)
        if left is not None:
            return [(ln, v, "concat") for ln, v, _k in _gh_fstring_sites(n.right, left)]
    return []


def _gh_is_str_format(n):
    """Is `n` a `"literal text".format(...)` call?"""
    return (isinstance(n, _gh_ast.Call) and isinstance(n.func, _gh_ast.Attribute)
            and n.func.attr == "format" and isinstance(n.func.value, _gh_ast.Constant))


def _gh_is_user_flag(e):
    """Is `e` sudo's user option as a literal: `--user`, `-u`, or a short-flag cluster ending in u?"""
    return (isinstance(e, _gh_ast.Constant) and isinstance(e.value, str)
            and (e.value == "--user" or re.fullmatch(r"-[A-Za-z]*u", e.value)) is not None)


_GH_SUDO_BASENAMES = {"sudo", "sudo.ws", "sudo-rs"}


def _gh_is_sudo_word(e):
    """Is argv element `e` sudo?

    By name or path (`/usr/bin/sudo`, `sudo.ws`, `sudo-rs`), or a name that holds it (`SUDO_WS`,
    `self._sudo`).
    """
    # sudo.ws is classic sudo on 26.04 (debug_report/install.py holds SUDO_WS = "/usr/bin/sudo.ws"),
    # and an argv spelling sudo through a constant was no site at all (review 1011e).
    if isinstance(e, _gh_ast.Constant) and isinstance(e.value, str):
        return e.value.rsplit("/", 1)[-1] in _GH_SUDO_BASENAMES
    if isinstance(e, (_gh_ast.Name, _gh_ast.Attribute)):
        return "sudo" in (getattr(e, "id", None) or e.attr).lower()
    # A call that hands back the prefix (`sudo_prefix() + ["-u", user]`), judged by its name too.
    if isinstance(e, _gh_ast.Call) and isinstance(e.func, (_gh_ast.Name, _gh_ast.Attribute)):
        return _gh_is_sudo_word(e.func)
    return False


def _gh_argv_sites(n, elts=None):
    """(line, value, "argv") for each value list/tuple literal `n` puts after "sudo" ... "-u".

    `elts` is the whole command line `n` is part of when that is more than `n` (a `+` chain, a list
    grown by `+=` or .extend()), so the "sudo" and the "-u" may sit in different literals.
    """
    out, elts, seen_sudo = [], (n.elts if elts is None else elts), False
    for j, e in enumerate(elts):
        if _gh_is_sudo_word(e):
            seen_sudo = True
        elif (seen_sudo and _gh_is_user_flag(e)
              and j + 1 < len(elts) and not isinstance(elts[j + 1], _gh_ast.Constant)):
            out.append((n.lineno, elts[j + 1], "argv"))
        elif seen_sudo and _gh_is_joined_user(e):
            out.append((n.lineno, e, "argv"))
    return out


def _gh_is_joined_user(e):
    """Is argv element `e` the user flag and an interpolated account in one (`"--user=" + user`)?"""
    return not isinstance(e, _gh_ast.Constant) and _GH_ARGV_JOINED.match(_gh_text(e)) is not None


def _gh_node_sites(n):
    """The `sudo -u` sites AST node `n` itself builds, as _gh_sites lists them."""
    if isinstance(n, _gh_ast.JoinedStr):
        return _gh_fstring_sites(n)
    if _gh_is_str_percent(n):
        return _gh_percent_sites(n)
    if isinstance(n, _gh_ast.BinOp) and isinstance(n.op, _gh_ast.Add):
        return _gh_concat_sites(n) + _gh_concat_fstring_sites(n)
    if _gh_is_str_format(n) and isinstance(n.func.value.value, str):
        return _gh_format_sites(n)
    if isinstance(n, (_gh_ast.List, _gh_ast.Tuple)):
        return _gh_argv_sites(n)
    return []


def _gh_enclosing_fn(node, parent):
    """The function node `node` sits in, or None at module level."""
    fn = parent.get(node)
    while fn is not None and not isinstance(fn, (_gh_ast.FunctionDef, _gh_ast.AsyncFunctionDef)):
        fn = parent.get(fn)
    return fn


def _gh_named_list(grown, fn, name):
    """The elements list name `name` was given in `fn`, else at module level (`BASE = [...]`)."""
    return grown.get((fn, name)) or grown.get((None, name)) or []


def _gh_splice(elts, fn, grown):
    """`elts` with each `*x` replaced by the elements x was given, or by x itself when unknown."""
    out = []
    for e in elts:
        if isinstance(e, _gh_ast.Starred):
            out += _gh_flatten(e.value, fn, grown)
        else:
            out.append(e)
    return out


def _gh_flatten(node, fn, grown):
    """The argv elements expression `node` builds.

    Lists, tuples, a `+` chain of them, a name the function (or the module) gave a list, and
    `*name` spliced in.
    """
    if isinstance(node, _gh_ast.BinOp) and isinstance(node.op, _gh_ast.Add):
        return _gh_flatten(node.left, fn, grown) + _gh_flatten(node.right, fn, grown)
    # A name, attribute or call with no list recorded for it (one imported, `self._sudo`,
    # `sudo_prefix()`) stays ONE element, so the sudo-word rule can judge it by its name: turned
    # into [] it vanished from the line, and `SUDO_ARGV + ["-u", user]` was no site (review 1012a).
    if isinstance(node, _gh_ast.Name):
        return list(_gh_named_list(grown, fn, node.id)) or [node]
    if isinstance(node, (_gh_ast.List, _gh_ast.Tuple)):
        return _gh_splice(node.elts, fn, grown)
    return _gh_flatten_other(node, fn, grown)


def _gh_flatten_other(node, fn, grown):
    """_gh_flatten for a call or attribute: `list(BASE)`'s elements, any literal inside, or itself."""
    if (isinstance(node, _gh_ast.Call) and getattr(node.func, "id", "") in ("list", "tuple")
            and len(node.args) == 1):
        return _gh_flatten(node.args[0], fn, grown)     # `list(BASE)`: BASE's elements
    inner = [e for part in _gh_ast.walk(node) if isinstance(part, (_gh_ast.List, _gh_ast.Tuple))
             for e in part.elts]
    return inner or ([node] if isinstance(node, (_gh_ast.Attribute, _gh_ast.Call)) else [])


def _gh_argv_line(n, parent, grown):
    """The elements of the whole command line list literal `n` is part of (see _gh_argv_sites).

    A `+` chain of lists is one argv (`["sudo", "-n"] + ["-u", user]`, this codebase's own
    style), read as G4 reads an ssh one; a list added to a name with `+=` or .extend() follows the
    lists that name was given earlier in the same function (`grown`: {name: [elements]}). A NAME
    in the chain (`a + ["-u", user]`, `BASE + [...]`) or a `*a` splice is followed the same way:
    only list literals were read before, so each of those was no site (review 1011e).
    """
    top = n
    while isinstance(parent.get(top), _gh_ast.BinOp) and isinstance(parent[top].op, _gh_ast.Add):
        top = parent[top]
    fn = _gh_enclosing_fn(top, parent)
    elts = _gh_flatten(top, fn, grown)
    name = _gh_grown_name(parent.get(top))
    if name is not None:
        elts = _gh_named_list(grown, fn, name) + elts
    return elts


def _gh_grown_name(up):
    """The list name `up` grows (`name += [...]`, `name.extend([...])`), or None."""
    if isinstance(up, _gh_ast.Call) and isinstance(up.func, _gh_ast.Attribute) \
            and up.func.attr == "extend" and isinstance(up.func.value, _gh_ast.Name):
        return up.func.value.id
    if isinstance(up, _gh_ast.AugAssign) and isinstance(up.target, _gh_ast.Name):
        return up.target.id
    return None


class _GhGrown(dict):
    """_gh_grown_lists' answer, with `at`: {(function or None, name): the line it last grew on}."""

    def __init__(self):
        super().__init__()
        self.at = {}


def _gh_grown_lists(tree):
    """{(function or None, name): every element a list name is given there, in source order}.

    `name = [...]`, `name = name + [...]` / `other + [...]`, `name += [...]` and
    `name.extend([...])` all count (review 1011e: only `name = [...]` did, so `a = []; a +=
    ["sudo"]; a += ["-u", user]` and `a = a + ["-u", user]` were no site); None is module level.
    So do `name.append(x)`, `name.insert(0, x)`, `name = list(other)` and `name = other`
    (review 1012a).
    """
    grown = _GhGrown()
    parent = {c: p for p in _gh_ast.walk(tree) for c in _gh_ast.iter_child_nodes(p)}
    nodes = sorted((n for n in _gh_ast.walk(tree) if isinstance(n, (_gh_ast.Assign, _gh_ast.AugAssign,
                                                                     _gh_ast.Call))),
                   key=lambda n: (n.lineno, n.col_offset))
    for n in nodes:
        fn = _gh_enclosing_fn(n, parent)
        if isinstance(n, _gh_ast.Assign):
            _gh_grow_assign(n, fn, grown)
        else:
            _gh_grow_added(n, fn, grown)
    return grown


def _gh_grow_assign(n, fn, grown):
    """Record what `name = [...]`, `name = a + [...]`, `name = list(a)` or `name = a` gives each name."""
    _copy = isinstance(n.value, _gh_ast.Name) or (
        isinstance(n.value, _gh_ast.Call) and getattr(n.value.func, "id", "") in ("list", "tuple"))
    if not (_copy or isinstance(n.value, (_gh_ast.List, _gh_ast.Tuple, _gh_ast.BinOp))):
        return
    elts = _gh_flatten(n.value, fn, grown)
    for t in (t for t in n.targets if isinstance(t, _gh_ast.Name)):
        grown.at[(fn, t.id)] = n.lineno
        if isinstance(n.value, _gh_ast.BinOp) or _copy:
            grown[(fn, t.id)] = list(elts)   # `a = a + [...]` already holds a's old list
        else:
            grown.setdefault((fn, t.id), []).extend(elts)


def _gh_grow_added(n, fn, grown):
    """Record what `name += [...]`, `name.extend([...])`, `.append(x)` or `.insert(i, x)` adds."""
    name = _gh_grown_name(n)
    added = n.value if isinstance(n, _gh_ast.AugAssign) else (n.args[0] if getattr(n, "args", None) else None)
    if name is not None and added is not None:
        grown.setdefault((fn, name), []).extend(_gh_flatten(added, fn, grown))
        grown.at[(fn, name)] = n.lineno
        return
    _gh_grow_appended(n, fn, grown)


def _gh_grow_appended(n, fn, grown):
    """Record what `name.append(x)` or `name.insert(i, x)` adds to a list the file gave elements."""
    _f = getattr(n, "func", None)
    if not (isinstance(_f, _gh_ast.Attribute) and isinstance(_f.value, _gh_ast.Name)
            and (_f.attr, len(n.args)) in (("append", 1), ("insert", 2))):
        return
    _key = (fn, _f.value.id)
    if _key not in grown:
        return          # a list this file never gave elements is not an argv being built
    if _f.attr == "append":
        grown[_key].append(n.args[0])
    elif isinstance(n.args[0], _gh_ast.Constant) and n.args[0].value == 0:
        grown[_key].insert(0, n.args[1])
    else:
        grown[_key].append(n.args[1])
    grown.at[_key] = n.lineno


def _gh_sites(tree):
    """Every [(line, value node or None, kind)] where a command puts a value after `sudo -u`."""
    # kind is how the COMMAND STRING is built — "fstring", "percent", "concat" or "format" — or
    # "argv" for a list-form argv.
    out, seen = [], set()
    parent = {c: p for p in _gh_ast.walk(tree) for c in _gh_ast.iter_child_nodes(p)}
    grown = _gh_grown_lists(tree)
    for n in _gh_ast.walk(tree):
        node_sites = (_gh_argv_sites(n, _gh_argv_line(n, parent, grown))
                      if isinstance(n, (_gh_ast.List, _gh_ast.Tuple)) else _gh_node_sites(n))
        for site in node_sites:
            if site[1] is None or id(site[1]) not in seen:
                seen.add(id(site[1]))
                out.append(site)
    return out + _gh_grown_sites(grown, seen)


def _gh_grown_sites(grown, seen):
    """Each named list's sites as it ends up, filed at the line it last grew on.

    One grown by .append()/.insert() has no literal holding its "-u", so no literal's line ever
    read it whole.
    """
    out = []
    for _key, _elts in grown.items():
        for site in _gh_argv_sites(_GhAt(grown.at.get(_key, 0)), _elts):
            if id(site[1]) not in seen:
                seen.add(id(site[1]))
                out.append(site)
    return out


class _GhAt:
    """A stand-in node for _gh_argv_sites: only its line is read."""

    def __init__(self, lineno):
        self.lineno = lineno


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
    # ...or the runner's own text argument names it anywhere inside, through a helper call too
    # (review 1011d): `_protected_resolved(user, ap, selfname, inner)` writes the name into the
    # command, and a call reads as "a new value" to _gh_carries, so delete/rename/create-path
    # ran a loaded row's lgsm_name unchecked with this gate green.
    _first_text = 1 if _gh_callee(n) in ("game_user_cmd", "game_user_exec_cmd") else 2
    in_arg = any(_gh_names_script(a, tainted) for a in n.args[_first_text:])
    if not (in_arg or _gh_interpolates_self(fn, tainted)):
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
    "G1 combined flag": _gh_plant('def f(user):\n    return f"sudo -nu {user} bash -c x"\n'),
    "G1 combined flag, .format": _gh_plant('def f(user):\n    return "sudo -Hu {} bash".format(user)\n'),
    "G1 .format": _gh_plant('def f(user):\n    return "sudo -u {} bash".format(user)\n'),
    # Options that take a value, before the -u (review 1011b): each read as clean before.
    "G1 a -g value before -u": _gh_plant('def f(grp, user):\n    return f"sudo -g {grp} -u {user} bash -c x"\n'),
    "G1 a -C value before -u": _gh_plant('def f(user):\n    return f"sudo -C 3 -u {user} bash"\n'),
    "G1 an --opt=value before -u": _gh_plant(
        'def f(user):\n    return f"sudo --preserve-env=PATH -u {user} bash"\n'),
    "G1 the sudo word interpolated": _gh_plant('def f(sudo, user):\n    return f"{sudo} -u {user} bash"\n'),
    "G1 sudo and -u in separate literals": _gh_plant('def f(user):\n    return "sudo " + "-u " + user\n'),
    "G1 -u in an f-string after a sudo literal": _gh_plant(
        'def f(user):\n    return "sudo " + f"-u {user} bash"\n'),
    "G1 the sudo word interpolated, %": _gh_plant(
        'def f(self, user):\n    return "%s -u %s bash" % (self._sudo, user)\n'),
    "G1 the sudo word interpolated, .format": _gh_plant(
        'def f(sudo, user):\n    return "{} -u {} bash".format(sudo, user)\n'),
    "G1 a -g value in a % format": _gh_plant(
        'def f(g, user):\n    return "sudo -g %s -u %s bash" % (g, user)\n'),
    # The account in hand-typed quotes (review 1011c): no site at all before, so no gate fired.
    "G1 hand-quoted, f-string": _gh_plant('def f(user):\n    return f"sudo -u \'{user}\' bash -c x"\n'),
    "G1 hand-double-quoted, f-string": _gh_plant("def f(user):\n    return f'sudo -u \"{user}\" bash'\n"),
    "G1 hand-quoted, %": _gh_plant('def f(user):\n    return "sudo -u \'%s\' bash" % user\n'),
    "G1 hand-quoted, .format": _gh_plant('def f(user):\n    return "sudo -u \'{}\' bash".format(user)\n'),
    "G1 hand-quoted, concat": _gh_plant('def f(user):\n    return "sudo -u \'" + user + "\' bash"\n'),
    "G2 an argv with --user= joined to the account": _gh_plant(
        'def f(user):\n    return ["sudo", "--user=" + user, "cat"]\n'),
    "G2 an argv with -u joined to the account": _gh_plant(
        'def f(user):\n    return ["sudo", f"-u{user}", "cat"]\n'),
    # Review 1011d: each of these was no site at all, so G2 never fired.
    "G2 an argv with -u joined by %": _gh_plant('def f(user):\n    return ["sudo", "-u%s" % user, "cat"]\n'),
    "G2 an argv with --user= joined by .format()": _gh_plant(
        'def f(user):\n    return ["sudo", "--user={}".format(user), "cat"]\n'),
    "G2 an argv split by +": _gh_plant('def f(user):\n    return ["sudo", "-n"] + ["-u", user, "cat"]\n'),
    "G2 a tuple argv split by +": _gh_plant('def f(user):\n    return ("sudo", "-n") + ("-u", user)\n'),
    "G2 an argv grown by +=": _gh_plant(
        'def f(user):\n    a = ["sudo"]\n    a += ["-u", user]\n    return a\n'),
    "G2 an argv grown by .extend()": _gh_plant(
        'def f(user):\n    a = ["sudo"]\n    a.extend(["-u", user])\n    return a\n'),
    # Review 1011e: each of these was no site at all.
    "G2 a named list in the + chain": _gh_plant(
        'def f(user):\n    a = ["sudo", "-n"]\n    return a + ["-u", user, "cat"]\n'),
    "G2 a module-level list in the + chain": _gh_plant(
        'BASE = ["sudo", "-n"]\ndef f(user):\n    return BASE + ["-u", user]\n'),
    "G2 a starred list": _gh_plant('def f(user):\n    a = ["sudo"]\n    return [*a, "-u", user]\n'),
    "G2 an argv grown by += only": _gh_plant(
        'def f(user):\n    a = []\n    a += ["sudo"]\n    a += ["-u", user]\n    return a\n'),
    "G2 an argv rebuilt as a = a + [...]": _gh_plant(
        'def f(user):\n    a = ["sudo"]\n    a = a + ["-u", user]\n    return a\n'),
    # Review 1012a: each of these was still no site at all.
    "G2 an argv grown by .append()": _gh_plant(
        'def f(user):\n    a = ["sudo", "-n"]\n    a.append("-u")\n    a.append(user)\n    return a\n'),
    "G2 an argv grown by .insert(0, sudo)": _gh_plant(
        'def f(user):\n    a = ["-u", user]\n    a.insert(0, "sudo")\n    return a\n'),
    "G2 an imported prefix in the + chain": _gh_plant(
        'from x import SUDO_ARGV\ndef f(user):\n    return SUDO_ARGV + ["-u", user]\n'),
    "G2 an imported prefix spliced": _gh_plant(
        'from x import SUDO_ARGV\ndef f(user):\n    return [*SUDO_ARGV, "-u", user]\n'),
    "G2 an attribute prefix spliced": _gh_plant(
        'def f(self, user):\n    return [*self._sudo, "-u", user]\n'),
    "G2 a prefix from a call": _gh_plant('def f(user):\n    return sudo_prefix() + ["-u", user]\n'),
    "G2 a list(copy) grown by +=": _gh_plant(
        'BASE = ["sudo"]\ndef f(user):\n    cmd = list(BASE)\n    cmd += ["-u", user]\n    return cmd\n'),
    "G2 a copy of a name grown by +=": _gh_plant(
        'def f(user):\n    a = ["sudo"]\n    b = a\n    b += ["-u", user]\n    return b\n'),
    "G2 an argv naming sudo.ws": _gh_plant('def f(user):\n    return ["sudo.ws", "-u", user]\n'),
    "G2 an argv naming sudo through a constant": _gh_plant(
        'SUDO_WS = "/usr/bin/sudo.ws"\ndef f(user):\n    return [SUDO_WS, "-u", user]\n'),
    "G2 an argv naming sudo by path": _gh_plant(
        'def f(user):\n    return ["/usr/bin/sudo", "-u", user, "cat"]\n'),
    "G2 quoted but outside the builder": _gh_plant(
        'def f(user):\n    return f"sudo -u {_quote(user)} bash -c x"\n'),
    "G2 the builder without its check": _gh_plant(
        'def game_user_cmd(user, inner, selfname=None):\n'
        '    return f"sudo -u {_quote(user)} bash -c {_quote(inner)}"\n', _GH_BUILDER_REL),
    "G2 an argv with no check": _gh_plant('def f(user):\n    return ["sudo", "-u", user, "cat"]\n'),
    "G2 an argv with a combined flag and no check": _gh_plant(
        'def f(user):\n    return ["sudo", "-nu", user, "cat"]\n'),
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
    "G3 the name handed to a helper that builds the runner's text": _gh_plant(
        'def f(server, user, selfname, ap, inner):\n'
        '    return _core.shell_as_game_user(server, user, _protected_resolved(user, ap, selfname, inner))\n'),
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
    "a command of sudo's whose own -u is not sudo's": _gh_plant(
        'def f(unit):\n    return f"sudo journalctl -u {_quote(unit)} -n 5"\n'),
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


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# CHAT BOTS, THE DISCORD GATEWAY, AND ALERT DEBOUNCE / FAN-OUT
# ═══════════════════════════════════════════════════════════════════════════════════════════════
import contextlib as _bf_ctx  # noqa: E402
import logging as _bf_logging  # noqa: E402
import sys as _bf_sys  # noqa: E402
import threading as _bf_threading  # noqa: E402
import time as _bf_time  # noqa: E402
from types import SimpleNamespace as _BfNS  # noqa: E402

from panel.services import notifications as _bf_n  # noqa: E402
from panel.services import monitoring as _bf_mon  # noqa: E402
from panel.services.bots import commands as _bf_cmd  # noqa: E402
from panel.services.bots import discord as _bf_dc  # noqa: E402
from panel.services.bots import telegram as _bf_tg  # noqa: E402


class _BfLogCap(_bf_logging.Handler):
    """Collects (level, message) from one logger while attached."""

    def __init__(self):
        super().__init__(_bf_logging.DEBUG)
        self.recs = []

    def emit(self, record):
        self.recs.append((record.levelno, record.getMessage()))


@_bf_ctx.contextmanager
def _bf_patched(obj, **attrs):
    """Set attributes on `obj` for the duration of the block, then put the originals back."""
    saved = {k: getattr(obj, k) for k in attrs}
    try:
        for k, v in attrs.items():
            setattr(obj, k, v)
        yield
    finally:
        for k, v in saved.items():
            setattr(obj, k, v)


# ── 1. Who may run what: the allowed-user list and the command classification ─────────────────
# The bots authorised by CHAT only, so every member of the Telegram group, or anyone who could
# post in the Discord channel, could /stop a server or /update (self-update and restart) the panel.
_bf_ok, _bf_bad = _bf_n.parse_command_users("123, 456 789;abc 0123\n123  -5 123456789012345678901")
check("bot users: ids are parsed from commas, spaces, semicolons and new lines, without repeats",
      _bf_ok == ["123", "456", "789"], repr(_bf_ok))
check("bot users: a non-numeric, zero-led, signed or over-long entry is REJECTED and reported",
      _bf_bad == ["abc", "0123", "-5", "123456789012345678901"], repr(_bf_bad))
_bf_ok, _bf_bad = _bf_n.parse_command_users(" ".join(str(10 ** 6 + i) for i in range(60)))
check("bot users: the list is capped, and the cap is reported rather than silent",
      len(_bf_ok) == _bf_n._COMMAND_USERS_MAX and _bf_bad and "more than" in _bf_bad[-1],
      "%d kept, rejected=%r" % (len(_bf_ok), _bf_bad[-1:]))
check("bot users: the STORED list is re-validated on read (hand-edited config), junk dropped",
      _bf_n.command_users({"command_users": ["12", "x", 5, "0"]}) == frozenset({"12", "5"})
      and _bf_n.command_users({"command_users": "12"}) == frozenset()
      and _bf_n.command_users({}) == frozenset() and _bf_n.command_users(None) == frozenset(), "")

_bf_store = {}
with _bf_patched(_bf_n, _cfg=lambda: {"telegram": {"command_users": ["77"]},
                                      "discord": {"command_users": ["88"]}},
                 update_config=lambda fn: fn(_bf_store)):
    _bf_n.save_settings(telegram={"command_users": "11, 22, nope"}, discord={}, events={})
check("bot users: save stores the validated ids, and a caller that omits the field keeps the list",
      _bf_store["notifications"]["telegram"]["command_users"] == ["11", "22"]
      and _bf_store["notifications"]["discord"]["command_users"] == ["88"],
      repr({k: _bf_store["notifications"][k].get("command_users") for k in ("telegram", "discord")}))

# The classification is DEFAULT-DENY: only the read-only database answers are open.
_bf_open = {c for c, _d in _bf_n.TG_COMMANDS if _bf_cmd.is_open_command(c, "x")}
check("bot commands: exactly status/servers/hosts/connect/help are open to anyone in the chat",
      _bf_open == {"status", "servers", "hosts", "connect", "help"}, repr(sorted(_bf_open)))
check("bot commands: every state-changing or server-reaching command needs an allowed user",
      not any(_bf_cmd.is_open_command(c, "srv") for c in
              ("start", "stop", "restart", "backup", "update", "upgrade", "console", "say",
               "players", "frobnicate")), "")
check("bot commands: a bare /start (Telegram's 'open the chat') and an empty word stay open",
      _bf_cmd.is_open_command("start", "") and _bf_cmd.is_open_command("", ""), "")

_bf_ref_none = _bf_cmd.command_refusal("telegram", "stop", "cs", {"id": 7}, frozenset())
_bf_ref_other = _bf_cmd.command_refusal("discord", "update", "", {"id": "8"}, frozenset({"7"}))
check("bot refusal: with no allowed users, /stop is refused, naming the sender's id and the setting",
      _bf_ref_none and "/stop" in _bf_ref_none and "Your user ID is 7" in _bf_ref_none
      and "Users who may run commands" in _bf_ref_none and "none have been allowed" in _bf_ref_none,
      repr(_bf_ref_none))
check("bot refusal: a sender not on a non-empty list is refused, and the list is not disclosed",
      _bf_ref_other and "!update" in _bf_ref_other and "not one of them" in _bf_ref_other
      and "7" not in _bf_ref_other.replace("Your user ID is 8", ""), repr(_bf_ref_other))
check("bot refusal: a sender ON the list is let through; /status is open even with no list",
      _bf_cmd.command_refusal("telegram", "stop", "cs", {"id": 7}, frozenset({"7"})) is None
      and _bf_cmd.command_refusal("telegram", "status", "", {"id": 9}, frozenset()) is None, "")
check("bot refusal: the USERNAME is never an identity — a sender named like an allowed id is refused",
      _bf_cmd.command_refusal("discord", "stop", "cs", {"id": "9", "username": "7"},
                              frozenset({"7"})) is not None
      and _bf_cmd.command_refusal("discord", "stop", "cs", None, frozenset({"7"})) is not None, "")
check("bot refusal: a command word that is not a plain word is not echoed back",
      "**" not in (_bf_cmd.command_refusal("discord", "**x**", "", {"id": 1}, frozenset()) or ""), "")

# The audit actor: the numeric id FIRST (what the list matches, what an admin revokes), the
# username only as a reader's hint and cut to its charset.
check("bot audit: the origin records the numeric sender id, then a sanitised username",
      _bf_cmd._bot_origin("telegram", {"id": 123456789, "username": "bob\nforged"})
      == "telegram:123456789 (bobforged)"
      and _bf_cmd._bot_origin("discord", {"username": "someone"}) == "discord:unknown (someone)"
      and _bf_cmd._bot_origin("discord", None) == "discord:unknown",
      repr(_bf_cmd._bot_origin("telegram", {"id": 123456789, "username": "bob\nforged"})))


# ── 2. The Telegram router applies it, per SENDER, before anything is queued or acked ─────────
def _bf_tg_route(text, sender_id, allowed):
    """Route one update from the authorised chat; returns (dispatched texts, replies)."""
    ran, said = [], []
    with _bf_patched(_bf_tg, _tg_dispatch=lambda app, tok, chat, t, sender=None: ran.append(t),
                     _tg_reply=lambda tok, chat, t: said.append(t),
                     _tg_command_users=lambda: frozenset(allowed)):
        _bf_tg._tg_route_update(None, "1:tok", "42", "PanelBot",
                                {"update_id": 1, "message": {"text": text, "chat": {"id": 42},
                                                             "from": {"id": sender_id}}})
    return ran, said


_bf_r = _bf_tg_route("/update", 7, ())
check("telegram: a group member not on the list cannot self-update the panel with /update",
      _bf_r[0] == [] and _bf_r[1] and "Your user ID is 7" in _bf_r[1][0], repr(_bf_r))
_bf_r = _bf_tg_route("/stop codserver", 8, ("7",))
check("telegram: ...nor /stop a server when the list names someone else", _bf_r[0] == [], repr(_bf_r))
_bf_r = _bf_tg_route("/console codserver", 8, ("7",))
check("telegram: ...nor read the live console", _bf_r[0] == [], repr(_bf_r))
_bf_r = _bf_tg_route("/stop codserver", 7, ("7",))
check("telegram: an allowed user's /stop is dispatched, with no refusal",
      _bf_r == (["/stop codserver"], []), repr(_bf_r))
_bf_r = _bf_tg_route("/status", 8, ())
check("telegram: /status still works for anyone in the chat, with no list at all",
      _bf_r == (["/status"], []), repr(_bf_r))
# The /update audit row: the panel's self-update from chat used to leave no audit row at all.
_bf_audits = []
with _bf_patched(_bf_tg, bot_update_status=lambda: {"git": True, "update_available": True},
                 spend_update_check=lambda: True, _set_tg_pending_update=lambda *a: None,
                 _tg_reply=lambda *a: None, _panel_ver_label=lambda: "v",
                 audit_bot_action=lambda app, origin, action, target, **k: _bf_audits.append(
                     (origin, action, k.get("success"))),
                 so=_BfNS(panel_self_update=lambda: (True, "started"), panel_commit=lambda: "abc")):
    _bf_tg._telegram_do_update(None, "1:tok", "42", {"id": 7, "username": "op"})
check("telegram: a panel /update from chat is audited as panel_self_update under the sender's id",
      _bf_audits == [("telegram:7 (op)", "panel_self_update", True)], repr(_bf_audits))

# /say is audited under the sender too (the web page's Say logs moderate_say; the bot logged nothing).
_bf_audits = []
with _bf_patched(_bf_cmd, _find_server=lambda a: (_BfNS(name="CS", short_name="cs", game_type="csgo",
                                                        lgsm_name="csgoserver", remote=None), None),
                 _sm=_BfNS(moderate=lambda *a, **k: (True, "said")),
                 audit_bot_action=lambda app, origin, action, target, **k: _bf_audits.append(
                     (origin, action, target, k.get("detail")))):
    _bf_cmd._say_text(_BfNS(app_context=_bf_ctx.nullcontext), "cs hello all", origin="discord:9 (op)")
check("bots: /say is audited as moderate_say, with the sender and the message",
      _bf_audits == [("discord:9 (op)", "moderate_say", "CS", "hello all")], repr(_bf_audits))

# audit_bot_action itself: best-effort, under a request context, never raising into the command.
_bf_logged = []
with _bf_patched(_bf_cmd, log_action=lambda user, action, **k: _bf_logged.append((action, k["actor"]))):
    _bf_cmd.audit_bot_action(_BfNS(test_request_context=_bf_ctx.nullcontext), "telegram:1",
                             "panel_self_update", "Panel Server")
    _bf_raised = None
    try:
        _bf_cmd.audit_bot_action(_BfNS(), "telegram:1", "x", "y")      # no request context at all
    except Exception as _bf_e:   # noqa: BLE001
        _bf_raised = _bf_e
check("bots: audit_bot_action writes the row as the bot origin and swallows its own failure",
      _bf_logged == [("panel_self_update", "telegram:1")] and _bf_raised is None,
      repr((_bf_logged, _bf_raised)))


# ── 3. The Discord router, driven through the real watch loop ─────────────────────────────────
class _BfStop(BaseException):
    """Ends a watch loop from its own sleep — a BaseException so its `except Exception` passes it."""


def _bf_dc_messages(msgs, allowed):
    """Run one Gateway session delivering `msgs` [(author, text)]; returns (dispatched, replies)."""
    cfg = {"discord": {"enabled": True, "accept_commands": True, "bot_token": "enc",  # nosec B105 - a fixture token
                       "channel_id": "999", "command_users": list(allowed)}}
    ran, said = [], []

    def gateway(_tok, on_message, **_k):
        for author, text in msgs:
            on_message("999", False, text, author)
        return None

    def sleep(_s):
        raise _BfStop()

    with _bf_patched(_bf_n, _cfg=lambda: cfg, discord_gateway_run=gateway), \
            _bf_patched(_bf_dc, decrypt_secret=lambda s: "A" * 50, time=_BfNS(sleep=sleep),
                        _dc_dispatch=lambda app, tok, chan, text, sender=None: ran.append(text),
                        _dc_reply=lambda tok, chan, text: said.append(text)):
        try:
            _bf_dc._discord_command_watch(None)
        except _BfStop:
            pass  # the stub ends the watch loop by raising this
    return ran, said


_bf_r = _bf_dc_messages([({"id": "9", "username": "op"}, "!stop cs"),
                         ({"id": "10", "username": "9"}, "!restart cs"),
                         (None, "!update"),
                         ({"id": "10"}, "!status")], ("9",))
check("discord: an allowed author's !stop runs; the same command from anyone else in the channel "
      "does not, whatever their username", _bf_r[0] == ["!stop cs", "!status"], repr(_bf_r[0]))
check("discord: each refused command is answered with the way to be allowed",
      len(_bf_r[1]) == 2 and all("Users who may run commands" in _t for _t in _bf_r[1]),
      repr(_bf_r[1]))


# ── 4. The Discord Gateway: fatal close codes stop the bot; everything else backs off ─────────
class _BfGwWS:
    """A websocket-client-shaped socket: recv_data() hands out (opcode, bytes) frames in order."""

    def __init__(self, frames):
        self.frames, self.sent = list(frames), []

    def recv_data(self):
        if self.frames:
            return self.frames.pop(0)
        raise OSError("socket closed")

    def send(self, s):
        self.sent.append(s)

    def settimeout(self, _t):
        pass

    def close(self):
        pass


_bf_hello = (0x1, b'{"op": 10, "d": {"heartbeat_interval": 50}}')   # 50 ms: its thread exits at once
_bf_code = _bf_n.discord_gateway_run(
    "b" * 50, lambda *a: None,
    _connect=lambda: _BfGwWS([_bf_hello, (0x8, b"\x0f\xaeDisallowed intent(s).")]))
check("discord gateway: the close code Discord ended the session with is returned (4014)",
      _bf_code == 4014, repr(_bf_code))
_bf_seen = []
_bf_code = _bf_n.discord_gateway_run(
    "b" * 50, lambda *a: _bf_seen.append(a[2]),
    _connect=lambda: _BfGwWS([_bf_hello, (0x1, b'{"op": 0, "s": 1, "t": "MESSAGE_CREATE", '
                                                b'"d": {"channel_id": "5", "content": "!status", '
                                                b'"author": {"id": "1"}}}')]))
check("discord gateway: frames read through recv_data still reach the handler; a dropped socket "
      "has no close code", _bf_seen == ["!status"] and _bf_code is None, repr((_bf_seen, _bf_code)))


def _bf_watch(codes, hours=24.0, lasted=0.0, on_sleep=None):
    """Run the Discord watcher over simulated time, the Gateway answering from `codes`.

    The last code repeats. Returns (session start times, sleeps, warnings logged).
    """
    now = [0.0]
    cfg = {"discord": {"enabled": True, "accept_commands": True, "bot_token": "enc",  # nosec B105 - a fixture token
                       "channel_id": "999"}}
    calls, sleeps, script = [], [], list(codes)

    def gateway(_tok, _on_message, **_k):
        calls.append(now[0])
        now[0] += lasted
        return script.pop(0) if len(script) > 1 else script[0]

    def sleep(s):
        sleeps.append(s)
        now[0] += s
        if on_sleep:
            on_sleep(len(sleeps), cfg)
        if now[0] >= hours * 3600:
            raise _BfStop()

    cap = _BfLogCap()
    _bf_dc._log.addHandler(cap)
    _lvl = _bf_dc._log.level
    _bf_dc._log.setLevel(_bf_logging.DEBUG)
    try:
        with _bf_patched(_bf_n, _cfg=lambda: cfg, discord_gateway_run=gateway), \
                _bf_patched(_bf_dc, decrypt_secret=lambda s: s, time=_BfNS(sleep=sleep),
                            _clock=lambda: now[0]):
            try:
                _bf_dc._discord_command_watch(None)
            except _BfStop:
                pass  # the stub ends the watch loop by raising this
    finally:
        _bf_dc._log.removeHandler(cap)
        _bf_dc._log.setLevel(_lvl)
        _bf_n.set_discord_gateway_problem("")
    return calls, sleeps, [m for lv, m in cap.recs if lv >= _bf_logging.WARNING]


# 4014 and 4004 never become IDENTIFY storms. Before the fix this was one IDENTIFY every ~16 s:
# about 5,400 a day against Discord's 1,000, which gets the bot's token reset.
_bf_calls, _bf_sleeps, _bf_warn = _bf_watch([4014])
check("discord watch: a 4014 (disallowed intents) is NOT retried every 15 s — a handful of "
      # 5, the design's number (a 6 h hold: 24/6 + the first). Not computed from _DC_FATAL_RETRY:
      # a bound that moves with the constant passed it lowered to 15 s, the storm this names.
      "IDENTIFYs a day at most", 1 <= len(_bf_calls) <= 5,
      "%d sessions in 24h (hold %ss)" % (len(_bf_calls), _bf_dc._DC_FATAL_RETRY))
check("discord watch: ...and says why ONCE per attempt, at WARNING, naming the Message Content intent",
      len(_bf_warn) == len(_bf_calls) and "Message Content" in _bf_warn[0], repr(_bf_warn[:2]))
_bf_problem = []
_bf_calls, _, _ = _bf_watch([4004], hours=0.1,
                            on_sleep=lambda n, c: _bf_problem.append(_bf_n.discord_gateway_problem()))
check("discord watch: a 4004 (bad token) is shown on the settings page while it holds",
      _bf_problem and "4004" in _bf_problem[-1] and len(_bf_calls) == 1, repr(_bf_problem[-1:]))


def _bf_toggle(n, cfg):
    """Untick "Accept commands" on the 3rd sleep and tick it again on the 4th."""
    if n == 3:
        cfg["discord"]["accept_commands"] = False
    elif n == 4:
        cfg["discord"]["accept_commands"] = True


_bf_calls, _, _ = _bf_watch([4014], hours=0.2, on_sleep=_bf_toggle)
check("discord watch: unticking and re-ticking Accept commands retries a fatal close at once",
      len(_bf_calls) == 2, "%d sessions" % len(_bf_calls))


def _bf_new_token(n, cfg):
    """Save a different bot token on the 3rd sleep."""
    if n == 3:
        cfg["discord"]["bot_token"] = "enc2"  # nosec B105 - a fixture token, the one the save put in


_bf_calls, _, _ = _bf_watch([4004], hours=0.2, on_sleep=_bf_new_token)
check("discord watch: saving a new bot token retries a fatal close at once",
      len(_bf_calls) == 2, "%d sessions" % len(_bf_calls))

# Any other end backs off exponentially, with a cap; a long-lived session resets it.
_bf_calls, _bf_sleeps, _ = _bf_watch([None], hours=4)
check("discord watch: sessions that die young back off 30, 60, 120… up to the cap",
      _bf_sleeps[:7] == [30, 60, 120, 240, 480, 900, 900]
      and max(_bf_sleeps) == _bf_dc._DC_BACKOFF_MAX, repr(_bf_sleeps[:8]))
_bf_calls, _, _ = _bf_watch([None], hours=24)
check("discord watch: ...so a socket that keeps dropping stays far under 1,000 IDENTIFYs a day",
      len(_bf_calls) < 150, "%d sessions in 24h" % len(_bf_calls))
_bf_calls, _bf_sleeps, _ = _bf_watch([1000], hours=1, lasted=_bf_dc._DC_SESSION_HEALTHY)
check("discord watch: a session that lived a while reconnects promptly, as before",
      set(_bf_sleeps) == {_bf_dc._DC_CMD_BACKOFF}, repr(sorted(set(_bf_sleeps))))
with _bf_patched(_bf_n, _cfg=lambda: {}):
    _bf_n.set_discord_gateway_problem("close code 4014")
    _bf_form = _bf_n.settings_for_form()["discord"]
    _bf_n.set_discord_gateway_problem("")
check("notify form: why the Gateway stopped reaches the Discord card",
      _bf_form.get("gateway_problem") == "close code 4014", repr(_bf_form))


# ── 5. Alerts: a failed probe is not an outage until it is confirmed ──────────────────────────
_bf_ps = _bf_sys.modules["panel.core.panel_state"]
_bf_alerts = []
_bf_host = _BfNS(id=424242, display_name="edge", is_online=True)
_bf_saved_state = {k: dict(v) for k, v in _bf_ps._monitor_state.items()}


def _bf_hosts(seq):
    """Feed reachability readings for one host; returns the alert keys fired."""
    del _bf_alerts[:]
    for r in seq:
        _bf_mon._record_host_reachability(_bf_host, r)
    return list(_bf_alerts)


try:
    with _bf_patched(_bf_mon.notifications, notify=lambda k, t, b="": _bf_alerts.append(k)):
        _bf_hosts([True])                                           # baseline
        _bf_one = _bf_hosts([False])
        check("monitor: ONE failed probe of a host is not an alert (it used to page at once)",
              _bf_one == [] and _bf_ps._monitor_state["remotes"][_bf_host.id] is True,
              repr(_bf_one))
        check("monitor: ...though the is_online column still says what the probe saw",
              _bf_host.is_online is False, repr(_bf_host.is_online))
        _bf_back = _bf_hosts([True])
        check("monitor: a blip that clears announces nothing — no phantom 'back online'",
              _bf_back == [], repr(_bf_back))
        _bf_flap = _bf_hosts([False, True] * 10)
        check("monitor: a host flapping every sweep no longer alerts every sweep",
              _bf_flap == [], repr(_bf_flap))
        _bf_down = _bf_hosts([False] * _bf_mon._DOWN_CONFIRM_SWEEPS + [False] * 3)
        check("monitor: consecutive failures ARE declared, once, and not repeated",
              _bf_down == ["remote_unreachable"], repr(_bf_down))
        check("monitor: ...and recovery after a real outage is announced",
              _bf_hosts([True]) == ["remote_recovered"], "")

        # Servers: the same rule, and the maintenance probe (an SSH round trip) waits for it.
        _bf_probed = []
        _bf_gs = _BfNS(id=434343, name="cs", short_name="cs")
        with _bf_patched(_bf_mon, _lgsm_maintenance_running=lambda r, gs: _bf_probed.append(gs.id) or False):
            _bf_ps._expected_offline.pop(_bf_gs.id, None)

            def _bf_srv(seq, prev=True):
                """Feed port readings for one server; returns (recorded state, alert keys)."""
                del _bf_alerts[:]
                for up in seq:
                    prev = _bf_mon._server_transition(_bf_host, _bf_gs, up, prev, False)
                return prev, list(_bf_alerts)

            _bf_rec, _bf_a = _bf_srv([False])
            check("monitor: one sweep with a server's port shut is not 'went offline', and costs "
                  "no maintenance probe", _bf_rec is True and _bf_a == [] and _bf_probed == [],
                  repr((_bf_rec, _bf_a, _bf_probed)))
            _bf_rec, _bf_a = _bf_srv([True, False, True, False, True], prev=_bf_rec)
            check("monitor: a server whose scan misses it now and then does not alert at all",
                  _bf_a == [], repr(_bf_a))
            _bf_rec, _bf_a = _bf_srv([False] * _bf_mon._DOWN_CONFIRM_SWEEPS, prev=True)
            check("monitor: a server down for consecutive sweeps alerts once",
                  _bf_rec is False and _bf_a == ["server_down"], repr((_bf_rec, _bf_a)))
            _bf_rec, _bf_a = _bf_srv([True], prev=_bf_rec)
            check("monitor: ...and its recovery is announced", _bf_a == ["server_up"], repr(_bf_a))
finally:
    for _bf_k, _bf_v in _bf_saved_state.items():
        _bf_ps._monitor_state[_bf_k].clear()
        _bf_ps._monitor_state[_bf_k].update(_bf_v)


# ── 6. notify(): bounded, one sender, bursts folded into one message ──────────────────────────
_bf_sent = []
_bf_gate = _bf_threading.Event()


def _bf_slow_tg(tok, chat, text):
    """A Telegram send held until the burst has queued up behind it."""
    _bf_gate.wait(2)
    _bf_sent.append(text)
    return True, ""


def _bf_wait_idle(timeout=5.0):
    """Wait for the sender thread to empty the queue and stand down."""
    end = _bf_time.monotonic() + timeout
    while _bf_time.monotonic() < end:
        if not _bf_n._alert_sender[0] and _bf_n._alert_queue.empty():
            return True
        _bf_time.sleep(0.01)
    return False


_bf_cfg = {"telegram": {"enabled": True, "chat_id": "1", "token": ""}, "events": {"server_up": True}}  # nosec B105 - an empty fixture token
with _bf_patched(_bf_n, _cfg=lambda: _bf_cfg, send_telegram=_bf_slow_tg,
                 send_discord=lambda *a: (True, ""), send_ntfy=lambda *a: (True, "")):
    _bf_threads0 = _bf_threading.active_count()
    for _bf_i in range(50):
        _bf_n.notify("server_up", "Server back online", "srv%02d on edge is back online." % _bf_i)
    _bf_peak = _bf_threading.active_count() - _bf_threads0
    _bf_gate.set()
    _bf_idle = _bf_wait_idle()
_bf_all = "\n".join(_bf_sent)
check("notify(): fifty alerts in one sweep start ONE sender thread, not fifty",
      _bf_peak <= 1, "%d extra threads" % _bf_peak)
check("notify(): ...and are folded into a few messages, not fifty sends into Telegram's rate limit",
      _bf_idle and 1 <= len(_bf_sent) <= 5, "%d sends" % len(_bf_sent))
check("notify(): ...with every alert in them, and each message under the providers' caps",
      all("srv%02d" % _bf_i in _bf_all for _bf_i in range(50))
      and all(len(_t) <= _bf_n._ALERT_TEXT_MAX for _t in _bf_sent),
      repr([len(_t) for _t in _bf_sent]))
check("notify(): a lone alert reads exactly as before",
      _bf_n._alert_text([("k", "Server offline", "gmod went down")])
      == "🎮 LinuxGSM Panel — Server offline\ngmod went down", "")

# A full queue drops (with a WARNING) rather than blocking the monitor or growing without bound.
_bf_cap = _BfLogCap()
_bf_n._log.addHandler(_bf_cap)
_bf_small_q = _bf_n.queue.Queue(maxsize=2)
with _bf_patched(_bf_n, _cfg=lambda: _bf_cfg, _alert_queue=_bf_small_q):
    _bf_n._alert_sender[0] = True           # a sender "is running", so nothing drains meanwhile
    try:
        _bf_t0 = _bf_time.monotonic()
        for _ in range(5):
            _bf_n.notify("server_up", "x", "y")
        _bf_took = _bf_time.monotonic() - _bf_t0
    finally:
        _bf_n._alert_sender[0] = False
        _bf_n._log.removeHandler(_bf_cap)
check("notify(): a full queue drops the alert with a WARNING instead of blocking",
      _bf_small_q.qsize() == 2 and _bf_took < 1
      and any(lv >= _bf_logging.WARNING and "queue is full" in m for lv, m in _bf_cap.recs),
      repr((_bf_small_q.qsize(), _bf_cap.recs[-1:])))

# One channel whose sender raises no longer stops the others.
_bf_got = []
_bf_cfg2 = {"telegram": {"enabled": True, "chat_id": "1"}, "ntfy": {"enabled": True, "topic": "t"},
            "events": {"server_down": True}}


def _bf_boom(*_a):
    raise ValueError("bug in a sender")


with _bf_patched(_bf_n, _cfg=lambda: _bf_cfg2, send_telegram=_bf_boom,
                 send_ntfy=lambda *a: (_bf_got.append("nt"), (True, ""))[1]):
    _bf_n.notify("server_down", "t")
    _bf_wait_idle()
check("notify(): a channel whose sender raises does not stop the next channel",
      _bf_got == ["nt"] and not _bf_n._alert_sender[0], repr(_bf_got))
