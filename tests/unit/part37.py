"""Part 37 of the unit suite: scanner coverage, vendored code and secret detection (build ws7).

What it holds, one section each:
* F5: py/partial-ssrf is excluded repo-wide on the strength of a justification that had gone stale
  (it said notifications._post was the only outbound-HTTP sink). The justification now lists every
  outbound-HTTP call site, and this part lists them too: a new one fails until it is reviewed.
* F6: the CodeQL model pack in .github/codeql/extensions makes Flask-SocketIO handler parameters
  remote sources, and the command text entering run_command, shell_as_game_user, read_as_game_user
  and game_user_cmd command-injection sinks, with shlex.quote a barrier. The own-host shell has no
  row: the canary probe (#394) proved the eventlet Popen row inert, so it was removed.
  Whether CodeQL honours it is proved by the probe PR's canary; this part holds the pack's shape and
  the code shapes its rows assume, so a refactor cannot leave a model quietly matching nothing. A
  barrier cannot be scoped, so every place a whole script is quoted for a second shell (where the
  quote would hide what is inside) is listed here and must sit behind an entry-point sink.
* V2: static/vendor/ is described to scanners by package.json + package-lock.json, and every file in
  it is tied to that manifest by sha256 and by the version its own banner states; a package a
  bundle names in a banner inside it is locked and pinned at that version. The Socket.IO client must
  carry socket.io-parser's two advisory fixes. Templates load the files by a content-hashed URL, and
  the two manifests are noise to the update card.
* V3: gitleaks' keyword-free Telegram rule, emulated here on planted tokens built at run time (a
  literal would itself be the thing the scanners flag), and part05's fixture-shape pattern. A pull
  request is scanned with the base's allowlists, never with ones it brings itself.
* V11: every entry in gitleaks' global allowlist says why it is there (the two that did not were
  dead, and are gone).
* V4: SECURITY.md tells an operator of an install set up before the setup token what to check.
* V5: the CHANGELOG may not describe a PyJWT split that the CI lockfiles no longer have (and need not
  describe PyJWT at all).
* F7: a test module imports `app` one way; a cleanup that cannot delete a file says so; and a suite
  that sys.exit()s in its finally records a BaseException as a crash instead of exiting green.

HOW IT RUNS. Everything is read as TEXT or parsed with ast: the workflows and YAML with no YAML
parser (CI installs none), TOML with no TOML parser (3.10 has no tomllib). Nothing touches the
network, the checkout's data/, or runs a scanner; the real gitleaks and CodeQL runs that prove the
rules are in the build report.
"""
import ast as _ast37
import glob as _glob37
import hashlib as _hl37
import json as _json37
import os
import re as _re37
import secrets as _secrets37
import string as _string37

from panel.ops import system_ops as _so37
from unit.part01 import check
from unit.part05 import _fixture_shapes, _root
from unit.part06 import _wf_run_block
from unit.part29 import _read29


def _rel37(path):
    return os.path.relpath(path, _root).replace(os.sep, "/")


def _shipped_py37():
    """Every Python file a panel runs: what install.sh installs from .github/update-paths.txt."""
    files = [os.path.join(_root, f) for f in ("app.py", "manage.py", "db_maintenance.py")]
    files += sorted(_glob37.glob(os.path.join(_root, "panel", "**", "*.py"), recursive=True))
    files.append(os.path.join(_root, "tools", "panel-helper"))
    return [f for f in files if os.path.isfile(f)]


# ── F5: every outbound-HTTP call site, reviewed ─────────────────────────────────────────────────
# Third-party HTTP and WebSocket clients: importing one is a call site in the making.
_HTTP_LIBS37 = ("requests", "httpx", "aiohttp", "urllib3", "pycurl", "websocket", "websockets")
_HTTP_REVIEWED37 = {
    ("panel/services/notifications.py", "<module>", "build_opener"),
    ("panel/services/notifications.py", "_post", "_OPENER.open"),
    ("panel/services/notifications.py", "telegram_get_updates", "_OPENER.open"),
    ("panel/services/notifications.py", "telegram_get_me", "_OPENER.open"),
    ("panel/services/notifications.py", "_gateway_connector", "import websocket"),
    ("panel/services/notifications.py", "_connect", "websocket.create_connection"),
    ("panel/ops/system_ops.py", "_ci_fetch_page", "urlopen"),
    ("panel/services/lgsm_data.py", "_download", "urlopen"),
}


def _callee37(node):
    """`a.b.c` for a call's func, or '' when it is not a dotted name."""
    parts = []
    while isinstance(node, _ast37.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, _ast37.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _urlopen_aliases37(tree):
    """{local name: urlopen or build_opener} for `from urllib.request import ... as ...`."""
    froms = [n for n in _ast37.walk(tree)
             if isinstance(n, _ast37.ImportFrom) and n.module == "urllib.request"]
    return {a.asname or a.name: a.name for n in froms for a in n.names
            if a.name in ("urlopen", "build_opener")}


def _opener_names37(tree):
    """Names bound to the result of a build_opener(...) call: objects whose .open() is a request."""
    calls = [n for n in _ast37.walk(tree)
             if isinstance(n, _ast37.Assign) and isinstance(n.value, _ast37.Call)]
    return {t.id for n in calls if _callee37(n.value.func).split(".")[-1] == "build_opener"
            for t in n.targets if isinstance(t, _ast37.Name)}


def _http_kind37(call, aliases, openers):
    """What outbound-HTTP thing a call does ('urlopen', '<opener>.open', ...), or None."""
    name = _callee37(call.func)
    last = name.split(".")[-1]
    if last in ("urlopen", "build_opener", "install_opener"):
        return last
    if name in aliases:
        return aliases[name]
    if last == "open" and name.split(".")[0] in openers:
        return name
    if last in ("HTTPConnection", "HTTPSConnection"):
        return last
    if name.endswith("websocket.create_connection"):
        return "websocket.create_connection"
    return None


def _node_kinds37(node, aliases, openers):
    """The outbound-HTTP kinds one AST node is: a request call, or a client library's import."""
    if isinstance(node, _ast37.Call):
        kind = _http_kind37(node, aliases, openers)
        return [kind] if kind else []
    if isinstance(node, _ast37.Import):
        mods = [a.name for a in node.names]
    elif isinstance(node, _ast37.ImportFrom):
        mods = [node.module or ""]
    else:
        return []
    return ["import " + m for m in mods if m.split(".")[0] in _HTTP_LIBS37]


def _http_sites37(source, rel):
    """(rel, enclosing function, kind) for every outbound-HTTP call or client import in source."""
    tree = _ast37.parse(source)
    aliases, openers = _urlopen_aliases37(tree), _opener_names37(tree)
    sites = set()
    todo = [(tree, "<module>")]
    while todo:
        node, func = todo.pop()
        for child in _ast37.iter_child_nodes(node):
            sites.update((rel, func, k) for k in _node_kinds37(child, aliases, openers))
            is_def = isinstance(child, (_ast37.FunctionDef, _ast37.AsyncFunctionDef))
            todo.append((child, child.name if is_def else func))
    return sites


def _f5_tripwire():
    """The shipped code's outbound-HTTP call sites are exactly the reviewed ones."""
    files = _shipped_py37()
    found = set()
    for f in files:
        found |= _http_sites37(open(f, encoding="utf-8").read(), _rel37(f))
    check("outbound HTTP: the scan read the shipped Python and found the reviewed request sites",
          len(files) >= 90 and _HTTP_REVIEWED37 <= found,
          "%d files; not found: %r" % (len(files), sorted(_HTTP_REVIEWED37 - found)))
    check("outbound HTTP: no call site outside the ones codeql-config.yml reviews (a new one fails "
          "until it is reviewed and listed there and here)", found == _HTTP_REVIEWED37,
          "new: %r gone: %r" % (sorted(found - _HTTP_REVIEWED37), sorted(_HTTP_REVIEWED37 - found)))


def _f5_controls():
    """The scanner finds each way a request can be made (so an empty result means none)."""
    probes = {
        "urlopen": "import urllib.request\ndef f(u):\n    return urllib.request.urlopen(u)\n",
        "aliased": "from urllib.request import urlopen as fetch\ndef g(u):\n    return fetch(u)\n",
        "opener": "import urllib.request\nO = urllib.request.build_opener()\ndef h(r):\n    return O.open(r)\n",
        "client": "import http.client\ndef k(h):\n    return http.client.HTTPSConnection(h)\n",
        "library": "def m(u):\n    import requests\n    return requests.get(u)\n",
        "socket": "import websocket\ndef w(u):\n    return websocket.create_connection(u)\n",
    }
    got = {k: _http_sites37(v, "probe.py") for k, v in probes.items()}
    want = {"urlopen": {("probe.py", "f", "urlopen")},
            "aliased": {("probe.py", "g", "urlopen")},
            "opener": {("probe.py", "<module>", "build_opener"), ("probe.py", "h", "O.open")},
            "client": {("probe.py", "k", "HTTPSConnection")},
            "library": {("probe.py", "m", "import requests")},
            "socket": {("probe.py", "<module>", "import websocket"),
                       ("probe.py", "w", "websocket.create_connection")}}
    check("outbound HTTP: (control) the scanner finds urlopen, an alias of it, an opener's open, "
          "http.client, a third-party client and a WebSocket", got == want, repr(got))


def _f5_justification():
    """codeql-config.yml's py/partial-ssrf justification names every reviewed site."""
    text = _read29(".github", "codeql", "codeql-config.yml")
    head = text[:text.find("query-filters:")] if "query-filters:" in text else ""
    comment = "\n".join(ln for ln in head.splitlines() if ln.lstrip().startswith("#"))
    named = ("notifications._post", "notifications.telegram_get_updates",
             "notifications.telegram_get_me", "notifications._gateway_connector",
             "system_ops._ci_fetch_page", "lgsm_data._download")
    missing = [n for n in named if n not in comment]
    check("outbound HTTP: the partial-ssrf exclusion's justification names every call site it "
          "rests on, and no longer says _post is the only one",
          bool(comment) and not missing and "ONLY outbound-HTTP sink" not in comment
          and "py/partial-ssrf" in text and "tests/unit/part37.py" in comment,
          "missing %r" % missing)


# ── F6: the CodeQL model pack ────────────────────────────────────────────────────────────────────
_PACK37 = os.path.join(_root, ".github", "codeql", "extensions", "linuxgsm-panel-python")
_SIO_ROWS37 = [
    ["flask_socketio.SocketIO", "Member[on].ReturnValue.Argument[0].Parameter[0..9]", "remote"],
    ["flask_socketio.SocketIO", "Member[on_event].Argument[1,handler:].Parameter[0..9]", "remote"],
    ["flask_socketio.SocketIO", "Member[event].Argument[0].Parameter[0..9]", "remote"],
]
_BARRIER_ROW37 = ["shlex", "Member[quote].ReturnValue", "command-injection"]


def _model_rows37():
    """{extensible: [row, ...]} over every model file in the pack, read as text."""
    rows = {}
    for f in sorted(_glob37.glob(os.path.join(_PACK37, "models", "**", "*.yml"), recursive=True)):
        current = None
        for ln in open(f, encoding="utf-8").read().splitlines():
            m = _re37.match(r"^\s*extensible:\s*(\w+)\s*$", ln)
            if m:
                current = m.group(1)
            elif current and _re37.match(r"^\s*- \[.*\]\s*$", ln):
                rows.setdefault(current, []).append(_json37.loads(ln.strip()[2:]))
    return rows


def _f6_pack():
    """The pack is a library pack on codeql/python-all whose glob reaches its model files."""
    path = os.path.join(_PACK37, "codeql-pack.yml")
    text = open(path, encoding="utf-8").read() if os.path.isfile(path) else ""
    code = "\n".join(ln.split("#", 1)[0].rstrip() for ln in text.splitlines())
    models = _glob37.glob(os.path.join(_PACK37, "models", "*.model.yml"))
    check("codeql model pack: .github/codeql/extensions holds a library pack extending "
          "codeql/python-all, and its dataExtensions glob reaches its model files",
          _re37.search(r"^library: true$", code, _re37.M) is not None
          and _re37.search(r"^extensionTargets:\n  codeql/python-all: \"\*\"$", code, _re37.M) is not None
          and _re37.search(r"^dataExtensions:\n  - models/\*\*/\*\.yml$", code, _re37.M) is not None
          and len(models) >= 2, "%s, %d model files" % ("read" if text else "missing", len(models)))
    rows = _model_rows37()
    check("codeql model pack: Flask-SocketIO handler parameters are remote sources "
          "(the on() decorator, on_event, the bare event decorator)",
          all(r in rows.get("sourceModel", []) for r in _SIO_ROWS37), repr(rows.get("sourceModel")))
    _f6_barrier(rows)
    return rows


def _f6_barrier(rows):
    """shlex.quote is the barrier, and the row the canary probe proved inert stays out."""
    inert = [r for r in rows.get("sinkModel", []) if r[0] == "eventlet"]
    check("codeql model pack: shlex.quote is a command-injection barrier (CodeQL's stdlib model passes "
          "taint through it), and no sink row sits on eventlet's original Popen, which the canary "
          "probe (#394) proved matches nothing",
          _BARRIER_ROW37 in rows.get("barrierModel", []) and not inert,
          repr((rows.get("sinkModel"), rows.get("barrierModel"))))


def _sio_forms37():
    """How panel/ registers Socket.IO handlers: {'on', 'on_event', 'event'} as used, and a count."""
    forms, count = set(), 0
    for f in _glob37.glob(os.path.join(_root, "panel", "**", "*.py"), recursive=True):
        for node in _ast37.walk(_ast37.parse(open(f, encoding="utf-8").read())):
            if isinstance(node, (_ast37.FunctionDef, _ast37.AsyncFunctionDef)):
                for d in node.decorator_list:
                    name = _callee37(d.func if isinstance(d, _ast37.Call) else d)
                    if name.startswith("socketio.") and name.split(".")[-1] in ("on", "event"):
                        forms.add(name.split(".")[-1])
                        count += 1
            elif isinstance(node, _ast37.Call) and _callee37(node.func).endswith("socketio.on_event"):
                forms.add("on_event")
                count += 1
    return forms, count


def _f6_shapes(rows):
    """The code shapes the rows assume are the code's shapes."""
    forms, count = _sio_forms37()
    covered = {_re37.match(r"Member\[(\w+)\]", r[1]).group(1) for r in rows.get("sourceModel", [])
               if r[0] == "flask_socketio.SocketIO"}
    check("codeql model pack: every way panel/ registers a Socket.IO handler is a form a source row "
          "covers", count >= 8 and forms and forms <= covered,
          "%d handlers, forms %r, covered %r" % (count, sorted(forms), sorted(covered)))
    sf = open(os.path.join(_root, "panel", "routes", "server_files.py"), encoding="utf-8").read()
    check("codeql model pack: the app's one SocketIO is flask_socketio.SocketIO, constructed "
          "(the instance the source rows start from)",
          _re37.search(r"^from flask_socketio import \(?[^)]*\bSocketIO\b", sf, _re37.M) is not None
          and _re37.search(r"^\s+socketio = SocketIO\(app\b", sf, _re37.M) is not None)


# ── F6: the command-text entry points, and every script quoted for a second shell ───────────────
# shlex.quote is a barrier, and a barrier cannot be scoped to some sinks: where the panel quotes a
# WHOLE script for a second shell (`sudo bash -c <quote(cmd)>`), every flow inside that script is cut,
# a value left unquoted in it included. The first model put its only sink below those quotes, so it
# saw no game-account script (game_user_cmd's only way to the shell is quoted) and no remote command,
# and an own-host sudo=True command only through a branch CodeQL happens not to prune. The sinks are
# now the entry points the text goes in by, and each place a whole script is quoted is listed here
# with the entry point in front.
_CORE37 = "panel/ops/ssh_manager/_core.py"
_ENTRY37 = (("run_command", "command"), ("shell_as_game_user", "sh"),
            ("read_as_game_user", "sh"), ("game_user_cmd", "inner"))
# The module paths the panel calls them by: routes and services as `_sm.<fn>` (ssh_manager), the
# package's own submodules as `_core.<fn>`. A row needs the undotted top-level type: Python's MaD
# reads a dotted type as an INSTANCE of it (ApiGraphModelsSpecific.qll getExtraNodeFromType).
_ENTRY_MODS37 = ("Member[ops].Member[ssh_manager]", "Member[ops].Member[ssh_manager].Member[_core]")
# Each place a whole script is quoted for a second shell, and what stands in front of it: the
# entry-point sink its text arrives through, or None for a script that is a constant.
_DOUBLE_SHELL37 = {
    (_CORE37, "_run_local"): "run_command",
    (_CORE37, "_run_via_ssh_cli"): "run_command",
    (_CORE37, "_run_via_paramiko"): "run_command",
    (_CORE37, "game_user_cmd"): "game_user_cmd",
    ("panel/security/privileged.py", "<module>[os-update-run]"): None,
}
# The helpers that wrap run_command's text for a second shell. A caller outside _core.py would reach
# one past every entry-point row, so outside it they may only be handed a constant command.
_WRAPPERS37 = {"_run_local": 0, "_run_via_ssh_cli": 1, "_run_via_paramiko": 1, "_exec_local_shell": 0}
# The text before the quote ends in a SHELL's -c: `bash -c `, `sh -lc `, `su - x -c `. A flag that is
# only spelled -c (`jq -c`, `tail -c`, `ls -c`) takes a word, and a quoted word is what the barrier is for.
_DASH_C37 = _re37.compile(r"(?:\b(?:ba|da|k|z)?sh(?:\s+-[a-z]+)*|\b(?:su|runuser)\b[^;&|]*)\s+-[a-z]*c\s+$")


def _entry_rows37(core):
    """The sink rows the entry points need, from _core's own signatures, and what is missing there."""
    params = {n.name: [a.arg for a in n.args.args] for n in core.body
              if isinstance(n, _ast37.FunctionDef)}
    rows, missing = [], []
    for fn, param in _ENTRY37:
        if param not in params.get(fn, []):
            missing.append("%s(%s)" % (fn, param))
            continue
        pos = params[fn].index(param)
        rows += [["panel", "%s.Member[%s].Argument[%d,%s:]" % (mod, fn, pos, param), "command-injection"]
                 for mod in _ENTRY_MODS37]
    return rows, missing


def _f6_entry_points(rows):
    """Every command-text entry point is a sink, at its signature's position, as the panel imports it."""
    core = _ast37.parse(_read29(*_CORE37.split("/")))
    want, missing = _entry_rows37(core)
    sinks = rows.get("sinkModel", [])
    dotted = [r[0] for r in sinks if "." in r[0]]
    check("codeql model pack: each command-text entry point (run_command, shell_as_game_user, "
          "read_as_game_user, game_user_cmd) is a command-injection sink at the position and keyword "
          "_core's signature gives, by both paths the panel calls it (ssh_manager and its _core)",
          not missing and len(want) == 8 and all(r in sinks for r in want) and not dotted,
          "signature missing %r; rows missing %r; dotted types %r"
          % (missing, [r[1] for r in want if r not in sinks], dotted))


def _is_quote37(node):
    return isinstance(node, _ast37.Call) and _callee37(node.func).split(".")[-1] in ("quote", "_quote")


def _fstring_doubles37(node):
    """How many `... -c {quote(x)}` an f-string holds."""
    n, prev = 0, ""
    for v in node.values:
        if isinstance(v, _ast37.Constant):
            prev = str(v.value)
            continue
        n += bool(_DASH_C37.search(prev) and _is_quote37(v.value))
        prev = ""
    return n


def _percent_doubles37(node):
    """How many `"... -c %s" % (quote(x), ...)` a %-format holds."""
    if not (isinstance(node.op, _ast37.Mod) and isinstance(node.left, _ast37.Constant)
            and isinstance(node.left.value, str)):
        return 0
    args = node.right.elts if isinstance(node.right, _ast37.Tuple) else [node.right]
    holes = [m for m in _re37.finditer(r"%[-#0 +]*\d*(?:\.\d+)?[a-z%]", node.left.value)
             if m.group() != "%%"]
    n, start = 0, 0
    for i, m in enumerate(holes):
        before = node.left.value[start:m.start()]
        n += bool(i < len(args) and _DASH_C37.search(before) and _is_quote37(args[i]))
        start = m.end()
    return n


def _concat_doubles37(node):
    """How many `"... -c " + quote(x)` a concatenation chain holds (counted at its top node only)."""
    if not isinstance(node.op, _ast37.Add):
        return 0
    parts, todo = [], [node]
    while todo:
        x = todo.pop()
        if isinstance(x, _ast37.BinOp) and isinstance(x.op, _ast37.Add):
            todo += [x.right, x.left]
        else:
            parts.append(x)
    return sum(1 for a, b in zip(parts, parts[1:]) if isinstance(a, _ast37.Constant)
               and isinstance(a.value, str) and _DASH_C37.search(a.value) and _is_quote37(b))


def _node_doubles37(node, parent):
    """Script-for-a-second-shell quotes in one node (a chained `+` is counted once, at its top)."""
    if isinstance(node, _ast37.JoinedStr):
        return _fstring_doubles37(node)
    if not isinstance(node, _ast37.BinOp):
        return 0
    if isinstance(node.op, _ast37.Add) and isinstance(parent, _ast37.BinOp) and isinstance(parent.op, _ast37.Add):
        return 0
    return _percent_doubles37(node) + _concat_doubles37(node)


def _child_scope37(child, scope):
    """The label a child node's own sites carry: its function's name, or `<scope>[key]` for a table."""
    if isinstance(child, (_ast37.FunctionDef, _ast37.AsyncFunctionDef)):
        return [(child, child.name)]
    if isinstance(child, _ast37.Dict):
        return [(v, "%s[%s]" % (scope, k.value) if isinstance(k, _ast37.Constant) else scope)
                for k, v in zip(child.keys, child.values)] + [(k, scope) for k in child.keys if k]
    return [(child, scope)]


def _double_shell_sites37(source, rel):
    """{(rel, scope): count} of every place source quotes a whole script for a second shell."""
    sites, todo = {}, [(_ast37.parse(source), "<module>", None)]
    while todo:
        node, scope, parent = todo.pop()
        n = _node_doubles37(node, parent)
        if n:
            sites[(rel, scope)] = sites.get((rel, scope), 0) + n
        for child in _ast37.iter_child_nodes(node):
            todo += [(c, s, node) for c, s in _child_scope37(child, scope)]
    return sites


def _f6_double_shell():
    """Every script the shipped code quotes for a second shell is a reviewed one."""
    found = {}
    for f in _shipped_py37():
        found.update(_double_shell_sites37(open(f, encoding="utf-8").read(), _rel37(f)))
    want = {k: 1 for k in _DOUBLE_SHELL37}
    entries = {fn for fn, _p in _ENTRY37}
    check("codeql model pack: every place the shipped code quotes a whole script for a second shell "
          "(`-c <quote(...)>`, where shlex.quote's barrier hides the script) is a reviewed one, behind an "
          "entry-point sink or quoting a constant; a new one fails until it is reviewed",
          found == want and all(v is None or v in entries for v in _DOUBLE_SHELL37.values()),
          "new or changed: %r; gone: %r" % (sorted(set(found.items()) - set(want.items())),
                                             sorted(set(want) - set(found))))
    probes = {
        "f": 'def a(c):\n    return f"sudo bash -c {_quote(c)}"\n',
        "pct": 'import shlex\nT = {"v": lambda a: "setsid sh -c %s & echo %s" % (shlex.quote(a), 1)}\n',
        "add": 'import shlex\ndef b(c):\n    return "su - x -c " + shlex.quote(c) + " && true"\n',
        "word": 'def d(p, f):\n    return f"ls -c {_quote(p)} | jq -c {_quote(f)}" + "tail -c %s" % _quote(p)\n',
    }
    got = {k: _double_shell_sites37(v, "p.py") for k, v in probes.items()}
    check("codeql model pack: (control) the scan finds a script quoted for `bash -c`, `sh -c` and "
          "`su -c` in an f-string, a %-format inside a table and a concatenation, and not a quoted word "
          "after another program's -c (jq, tail, ls)",
          got == {"f": {("p.py", "a"): 1}, "pct": {("p.py", "<module>[v]"): 1},
                  "add": {("p.py", "b"): 1}, "word": {}}, repr(got))


def _wrapper_refs37(tree):
    """(references to a wrapper helper, those that are a call handed a constant command)."""
    refs, ok = 0, 0
    for n in _ast37.walk(tree):
        if isinstance(n, _ast37.Name) and n.id in _WRAPPERS37:
            refs += 1
        elif isinstance(n, _ast37.Attribute) and n.attr in _WRAPPERS37:
            refs += 1
        if isinstance(n, _ast37.Call):
            name = _callee37(n.func).split(".")[-1]
            pos = _WRAPPERS37.get(name)
            arg = n.args[pos] if pos is not None and len(n.args) > pos else None
            ok += isinstance(arg, _ast37.Constant) and isinstance(arg.value, str)
    return refs, ok


# The own-host shell has no sink row (#394 proved the only form tried inert), so what reaches it
# without passing an entry row is held here instead: exactly these functions call _run_local or
# _exec_local_shell. run_command is the entry row's own body; the three privileged builders pass
# text privileged.py builds from validated arguments. A new caller fails until it is reviewed.
_LOCAL_SHELL_CALLERS37 = {("_run_local", "_exec_local_shell"), ("run_command", "_run_local"),
                          ("_run_privileged", "_run_local"), ("write_content_cron", "_run_local"),
                          ("write_root_file", "_run_local")}


def _local_shell_callers37():
    """{(innermost enclosing function, callee)} for every call of _run_local/_exec_local_shell."""
    found = set()

    def visit(node, owner):
        for child in _ast37.iter_child_nodes(node):
            inner = child.name if isinstance(child, (_ast37.FunctionDef, _ast37.AsyncFunctionDef)) else owner
            if isinstance(child, _ast37.Call):
                name = _callee37(child.func).split(".")[-1]
                if name in ("_run_local", "_exec_local_shell"):
                    found.add((owner, name))
            visit(child, inner)

    for f in _glob37.glob(os.path.join(_root, "panel", "**", "*.py"), recursive=True) + [
            os.path.join(_root, "app.py")]:
        visit(_ast37.parse(open(f, encoding="utf-8").read()), "<module>")
    return found


def _f6_local_shell():
    """No sink row covers the own-host shell, so its callers are a reviewed list."""
    got = _local_shell_callers37()
    check("codeql model pack: exactly the reviewed functions call _run_local/_exec_local_shell "
          "(the own-host shell has no sink row; a new caller is reviewed here)",
          got == _LOCAL_SHELL_CALLERS37, repr(sorted(got ^ _LOCAL_SHELL_CALLERS37)))

def _f6_reach():
    """Nothing reaches a second-shell wrapper past the entry-point rows.

    Outside _core.py the wrappers are only handed constants, and nothing imports relatively (an API
    graph does not follow a relative import).
    """
    bad, relative = [], []
    for f in _shipped_py37():
        rel = _rel37(f)
        tree = _ast37.parse(open(f, encoding="utf-8").read())
        relative += ["%s:%d" % (rel, n.lineno) for n in _ast37.walk(tree)
                     if isinstance(n, _ast37.ImportFrom) and n.level]
        if rel != _CORE37:
            refs, ok = _wrapper_refs37(tree)
            bad += ["%s (%d of %d)" % (rel, refs - ok, refs)] if refs != ok else []
    check("codeql model pack: outside _core.py the helpers that wrap run_command's text for a second "
          "shell are only called with a constant command, and no shipped module imports relatively "
          "(either would reach a shell past the entry-point rows)",
          not bad and not relative, "wrapper uses %r; relative imports %r" % (bad, relative))


# ── V2: static/vendor/, its two manifests, and the files ────────────────────────────────────────
_VENDOR37 = os.path.join(_root, "static", "vendor")
_VENDOR_META37 = {"VERSIONS.md", "package.json", "package-lock.json"}


def _vendor_files37():
    """Every file under static/vendor/ except the manifests, relative to it."""
    out = set()
    for dp, _dns, fns in os.walk(_VENDOR37):
        for fn in fns:
            rel = os.path.relpath(os.path.join(dp, fn), _VENDOR37).replace(os.sep, "/")
            if rel not in _VENDOR_META37:
                out.add(rel)
    return out


def _vendor_json37(name):
    """static/vendor/<name> as a dict; {} when it is missing or not JSON."""
    try:
        with open(os.path.join(_VENDOR37, name), encoding="utf-8") as fh:
            return _json37.load(fh)
    except (OSError, ValueError):
        return {}


def _banner37(rel):
    """(version, npm package, path) a vendored file's banner states about ITSELF.

    jsDelivr's banner names the original (`Original file: /npm/<pkg>@<ver>/<path>`), and the first
    version-looking string in it can be its minifier's (`clean-css v5.3.3`); a library's own banner
    says `<Name> v<ver>`.
    """
    with open(os.path.join(_VENDOR37, rel), encoding="utf-8", errors="replace") as fh:
        head = fh.read(600)
    m = _re37.search(r"Original file: /npm/((?:@[^/@\s]+/)?[^/@\s]+)@(\d+\.\d+\.\d+)/(\S+)", head)
    if m:
        return m.group(2), m.group(1), m.group(3)
    m = _re37.search(r"\bv(\d+\.\d+\.\d+)\b", head)
    return (m.group(1) if m else None), None, None


def _v2_files(pj):
    """Every file is listed, and is the bytes its entry records."""
    vend = pj.get("vendored") or {}
    on_disk = _vendor_files37()
    check("vendor: every file under static/vendor/ has a `vendored` entry in its package.json, and "
          "every entry is a file there", len(on_disk) >= 9 and set(vend) == on_disk,
          "unlisted %r, missing %r" % (sorted(on_disk - set(vend)), sorted(set(vend) - on_disk)))
    bad = []
    for rel, ent in sorted(vend.items()):
        if rel in on_disk:
            with open(os.path.join(_VENDOR37, rel), "rb") as fh:
                got = _hl37.sha256(fh.read()).hexdigest()
            if got != ent.get("sha256"):
                bad.append("%s is %s..., the manifest says %s..." % (rel, got[:12], str(ent.get("sha256"))[:12]))
    check("vendor: every vendored file is byte-for-byte the one its manifest entry records (sha256)",
          bool(vend) and not bad, "; ".join(bad))


def _version_bad37(rel, ent, deps, pkgs):
    """What is wrong with one file's version: its pin, the lockfile's version, its banner."""
    name, bad = ent.get("package"), []
    want = deps.get(name) or ""
    if not _re37.fullmatch(r"\d+\.\d+\.\d+", want):
        return ["%s: %s is not pinned to one version (%r)" % (rel, name, want)]
    locked = (pkgs.get("node_modules/%s" % name) or {}).get("version")
    if locked != want:
        bad.append("%s: the lockfile has %s@%s, package.json %s" % (rel, name, locked, want))
    if rel.endswith((".js", ".css")):
        ver, pkg, path = _banner37(rel)
        if ver != want:
            bad.append("%s: its banner says %s, package.json %s" % (rel, ver, want))
        if pkg is not None and (pkg, path) != (name, ent.get("from")):
            bad.append("%s: its banner names %s/%s, the manifest %s/%s" % (rel, pkg, path, name, ent.get("from")))
    return bad


def _v2_versions(pj, lock):
    """Banner, pin, lockfile and VERSIONS.md agree on every file's version."""
    deps, pkgs = pj.get("dependencies") or {}, lock.get("packages") or {}
    vend = pj.get("vendored") or {}
    bad = []
    for rel, ent in sorted(vend.items()):
        bad += _version_bad37(rel, ent, deps, pkgs)
    check("vendor: each file's banner states exactly the version its package is pinned at, and the "
          "lockfile scanners read resolves that version", bool(vend) and not bad, "; ".join(bad))
    root = (pkgs.get("") or {}).get("dependencies")
    check("vendor: the lockfile was written for this package.json (its root lists the same pins)",
          root == deps and lock.get("lockfileVersion") == 3, repr(root))
    _v2_versions_md(deps, vend)


def _v2_versions_md(deps, vend):
    """VERSIONS.md's table agrees with package.json, row by row."""
    rows = _re37.findall(r"^\|\s*([^|]+?)\s*\|\s*([0-9][0-9.]*)\s*\|\s*`([^`]+)`\s*\|",
                         _read29("static", "vendor", "VERSIONS.md"), _re37.M)
    pinned = {f: deps.get(ent.get("package")) for f, ent in vend.items()}
    off = ["%s: VERSIONS.md %s, package.json %s" % (f, v, pinned.get(f))
           for _n, v, f in rows if v != pinned.get(f)]
    check("vendor: VERSIONS.md, the manifest for people, records the same version for every library",
          len(rows) >= 7 and not off, "; ".join(off))


def _v2_socketio(pj, lock):
    """The Socket.IO bundle carries socket.io-parser's two advisory fixes, and says so to scanners."""
    path = os.path.join(_VENDOR37, "socketio", "socket.io.min.js")
    src = open(path, encoding="utf-8", errors="replace").read() if os.path.isfile(path) else ""
    fix_426 = "too many attachments" in src and "maxAttachments" in src
    fix_427 = _re37.search(r"\|\|\s*\w+\s*<\s*1\s*\)\s*throw new Error\(\"Illegal attachments\"\)", src)
    check("vendor: the Socket.IO client carries socket.io-parser's attachment limit (4.2.6, "
          "GHSA-677m-j7p3-52f9) and its at-least-one-attachment check (4.2.7, GHSA-2m8v-j782-fhvr)",
          fix_426 and fix_427 is not None, "4.2.6 fix %s, 4.2.7 fix %s" % (fix_426, fix_427 is not None))
    parser = ((lock.get("packages") or {}).get("node_modules/socket.io-parser") or {}).get("version", "")
    pinned = (pj.get("overrides") or {}).get("socket.io-parser")
    newer = bool(_re37.fullmatch(r"\d+\.\d+\.\d+", parser)) and tuple(map(int, parser.split("."))) >= (4, 2, 7)
    check("vendor: ...and the lockfile records the parser the bundle carries (an override, not npm's "
          "newest), at 4.2.7 or later", newer and pinned == parser, "lock %r, override %r" % (parser, pinned))


# A banner line inside a comment: `<npm name> v<x.y.z>` (Chart.js's bundle keeps `@kurkle/color v0.3.2`).
_BANNER_LINE37 = _re37.compile(r"^\s*\*?\s*(@?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?)\s+v(\d+\.\d+\.\d+)\b",
                               _re37.M)


def _embedded37(text, own, locked):
    """{npm name: version} for each package a bundle names in a banner other than its own.

    A name counts when the lockfile knows it, or when it is scoped (@x/y), which only an npm package is.
    """
    out = {}
    for m in _re37.finditer(r"/\*[!*](.*?)\*/", text, _re37.S):
        for name, ver in _BANNER_LINE37.findall(m.group(1)):
            key = name.lower()
            if key != own and (key in locked or key.startswith("@")):
                out[key] = ver
    return out


def _embedded_bad37(pj, locked):
    """({name: version} the bundles carry, [what the lockfile or the overrides get wrong])."""
    overrides, found, bad = pj.get("overrides") or {}, {}, []
    for rel, ent in sorted((pj.get("vendored") or {}).items()):
        if not rel.endswith((".js", ".css")):
            continue
        with open(os.path.join(_VENDOR37, rel), encoding="utf-8", errors="replace") as fh:
            carried = _embedded37(fh.read(), ent.get("package"), locked)
        found.update(carried)
        bad += ["%s carries %s %s; the lockfile has %s, the override %s"
                % (rel, n, v, locked.get(n), overrides.get(n)) for n, v in sorted(carried.items())
                if locked.get(n) != v or overrides.get(n) != v]
    return found, bad


def _v2_embedded(pj, lock):
    """A package a bundle names in a banner of its own is locked, and pinned, at that version."""
    locked = {k.split("node_modules/", 1)[1]: (v or {}).get("version")
              for k, v in (lock.get("packages") or {}).items() if k.startswith("node_modules/")}
    found, bad = _embedded_bad37(pj, locked)
    probe = _embedded37("/*!\n * Lib v1.0.0\n */x;/*!\n * @scope/inner v0.3.2\n * (c) x\n */y;"
                        "/*! plain-dep v2.0.1 */z;/** Other Lib v9.9.9 */", "lib", {"plain-dep": "2.0.0"})
    check("vendor: every package a bundle names in a banner of its own (Chart.js carries @kurkle/color) "
          "is locked, and pinned by an override, at the version the bundle states, not npm's newest",
          "@kurkle/color" in found and not bad
          and probe == {"@scope/inner": "0.3.2", "plain-dep": "2.0.1"}, "%s; probe %r" % ("; ".join(bad), probe))


def _v2_asset_urls():
    """Templates load static/vendor's scripts and stylesheets by a URL that changes with the bytes."""
    bare, hashed = [], set()
    for tpl in sorted(_glob37.glob(os.path.join(_root, "templates", "**", "*.html"), recursive=True)):
        src = open(tpl, encoding="utf-8").read()
        bare += ["%s: %s" % (os.path.basename(tpl), m) for m in _re37.findall(
            r"url_for\(\s*['\"]static['\"]\s*,\s*filename\s*=\s*['\"](vendor/[^'\"]+\.(?:js|css))['\"]", src)]
        hashed |= set(_re37.findall(r"asset_url\(\s*['\"](vendor/[^'\"]+\.(?:js|css))['\"]\s*\)", src))
    files = {"vendor/" + r for r in _vendor_files37() if r.endswith((".js", ".css"))}
    check("vendor: templates load every vendored script and stylesheet through asset_url, whose URL "
          "changes with the file's bytes (/static is cached for a week, so a fixed URL kept browsers on "
          "the replaced Socket.IO client for up to a week after the update)",
          len(files) >= 7 and not bare and hashed == files,
          "bare url_for: %r; never loaded by asset_url: %r" % (bare, sorted(files - hashed)))


def _v2_update_paths():
    """The two scanner manifests are noise to the update card; the files they describe are runtime."""
    rules = _so37._parse_update_paths(_read29(".github", "update-paths.txt")) or {}
    want = {"static/vendor/package.json": False, "static/vendor/package-lock.json": False}
    want.update({"static/vendor/" + r: True for r in _vendor_files37()})
    got = {p: _so37._is_runtime_path(p, rules) for p in want}
    check("vendor: .github/update-paths.txt makes static/vendor's two scanner manifests noise (a "
          "lockfile-only bump offers no panel an update) and keeps every vendored file runtime",
          bool(rules) and len(want) >= 11 and got == want,
          "runtime?: %r" % {p: v for p, v in got.items() if v != want[p]})


# ── V3: gitleaks' Telegram rule, and part05's fixture shape ──────────────────────────────────────
_TG_RULE_ID37 = "telegram-bot-token-any-context"
_TG_PLACES37 = {
    "the panel's config.json shape": '{"telegram": {"token": "%s", "chat_id": "42"}}',
    "a bare assignment": 'token = "%s"',
    "a function argument": 'bot = Bot("%s")',
    "the Bot API URL": "curl https://api.telegram.org/bot%s/getMe",
    "prose": "My bot token is %s, keep it safe.",
    "an env file": "TELEGRAM_TOKEN=%s",
    "a YAML key": "telegram_bot_token: %s",
    "a whole line": "%s",
}


def _tg_token37(last=""):
    """A fresh bot token in the real shape (ten digits : AA + 33), built here, never written out."""
    alpha = _string37.ascii_letters + _string37.digits + "_-"
    tail = "".join(_secrets37.choice(alpha) for _ in range(33 - len(last))) + last
    return str(1000000000 + _secrets37.randbelow(9000000000)) + ":AA" + tail


def _toml_blocks37(text):
    """[(header, body)] for each table of a TOML file, comment lines dropped."""
    blocks = []
    for ln in text.splitlines():
        if ln.lstrip().startswith("#"):
            continue
        if _re37.match(r"^\[\[?[^\]]+\]\]?\s*$", ln):
            blocks.append([ln.strip(), []])
        elif blocks:
            blocks[-1][1].append(ln)
    return [(h, "\n".join(b)) for h, b in blocks]


def _tg_rule37():
    """The Telegram rule's {regex, group, keywords, target, allow} from .github/gitleaks.toml."""
    blocks = _toml_blocks37(_read29(".github", "gitleaks.toml"))
    at = [i for i, (h, b) in enumerate(blocks) if h == "[[rules]]" and 'id = "%s"' % _TG_RULE_ID37 in b]
    if not at:
        return {"regex": None, "group": 0, "keywords": False, "target": "secret", "allow": []}
    body = blocks[at[0]][1]
    allows = []
    for h, b in blocks[at[0] + 1:]:
        if h != "[[rules.allowlists]]":
            break
        allows.append(b)
    rx = _re37.search(r"^regex = '''(.*)'''$", body, _re37.M)
    grp = _re37.search(r"^secretGroup = (\d+)$", body, _re37.M)
    allow = "\n".join(allows)
    target = _re37.search(r'^regexTarget = "(\w+)"$', allow, _re37.M)
    return {"regex": rx.group(1) if rx else None, "group": int(grp.group(1)) if grp else 0,
            "keywords": _re37.search(r"^keywords\s*=", body, _re37.M) is not None,
            "target": target.group(1) if target else "secret",
            "allow": _re37.findall(r"'''(.*?)'''", allow)}


def _tg_found37(rule, text):
    """The secrets the rule reports in `text`, after its allowlist, as gitleaks would ([] with no rule)."""
    out = []
    for m in _re37.finditer(rule.get("regex") or r"(?!)", text):
        secret = m.group(rule["group"])
        if not any(_re37.search(a, secret if rule["target"] == "secret" else m.group(0))
                   for a in rule["allow"]):
            out.append(secret)
    return out


def _tg_missed37(rule):
    """Each planted token the rule does not report as exactly itself, by placement."""
    missed = []
    for label, fmt in sorted(_TG_PLACES37.items()):
        for tok in (_tg_token37(), _tg_token37(last="-"), _tg_token37(last="_")):
            got = _tg_found37(rule, "a line before\n" + fmt % tok + "\nand one after")
            if got != [tok]:
                missed.append("%s (ends %s): %r" % (label, tok[-1], got))
    return missed


def _v3_rule():
    """The keyword-free rule finds a fresh token everywhere, and nothing it should not."""
    rule = _tg_rule37()
    has = bool(rule.get("regex"))
    check("gitleaks: a keyword-free Telegram rule is configured, reporting capture group 1",
          has and rule["group"] == 1 and not rule["keywords"], repr(rule))
    missed = _tg_missed37(rule)
    check("gitleaks: the Telegram rule finds a fresh token in every placement, as exactly that "
          "token (config.json, an assignment, an argument, the Bot API URL, prose, env, YAML)",
          has and not missed, "; ".join(missed[:4]) or "no rule")
    near = {"gitleaks' own documented false positive": "clm12345:AgencyIdentificationCodeContentType",
            "a 34-character tail": _tg_token37()[:-1],
            "the TESTONLY fixtures": 'T = "12345:TESTONLYnotarealtoken00"; U = "67890:TESTONLYfixturevalue0"',
            "gitleaks' own `:A` shape, not `:AA`": _tg_token37().replace(":AA", ":AB", 1)}
    hits = {k: v for k, v in ((k, _tg_found37(rule, t)) for k, t in near.items()) if v}
    check("gitleaks: ...and finds nothing in gitleaks' own XSD false positive, a 34-character tail, "
          "the panel's TESTONLY fixtures, or a `:A` that is not `:AA`",
          has and not hits, repr(hits) if has else "no rule")


def _v3_allowlist():
    """The rule's allowlist clears the #72 synthetic value and nothing else."""
    rule = _tg_rule37()
    hist = "123456789:" + "AAtoken" * 5      # the #72 fixture (74d11e8d), built, not written out
    same_id = "123456789:AA" + _tg_token37()[-33:]
    matched = bool(rule.get("regex")) and _re37.search(rule["regex"], "t=" + hist + "\n") is not None
    anchored = bool(rule.get("allow")) and all(a.startswith("^") and a.endswith("$") for a in rule["allow"])
    check("gitleaks: the Telegram rule's allowlist clears the #72 synthetic value (the rule does "
          "match it), anchored, on the secret",
          matched and _tg_found37(rule, hist) == [] and rule["target"] == "secret" and anchored,
          repr(rule.get("allow")))
    check("gitleaks: ...and nothing else: the same bot id with another secret, and the value with "
          "its last character changed, still fire", _tg_found37(rule, same_id) == [same_id]
          and _tg_found37(rule, hist[:-1] + "x") == [hist[:-1] + "x"], repr(rule.get("allow")))
    check("gitleaks: the config does not carry the #72 value as a literal (that is the token-shaped "
          "text GitHub's secret scanning alerted on)", hist not in _read29(".github", "gitleaks.toml"))


def _v3_fixture_shape():
    """part05's Telegram fixture shape catches what its word-boundary version let through."""
    pat = dict(_fixture_shapes).get("Telegram bot token", "^$")
    probes = {"a token ending in '-'": _tg_token37(last="-"),
              "the Bot API URL form": "https://api.telegram.org/bot%s/getMe" % _tg_token37(),
              "the #72 value": "123456789:" + "AAtoken" * 5,
              "an ordinary token": 'tok = "%s"' % _tg_token37(last="x")}
    missed = [k for k, v in probes.items() if not _re37.search(pat, v)]
    check("fixtures: part05's Telegram shape catches a token ending in '-', the Bot API URL form, "
          "the #72 value and an ordinary token", not missed, "missed %r" % missed)
    check("fixtures: ...and still passes the TESTONLY fixtures",
          not _re37.search(pat, 'A = "12345:TESTONLYnotarealtoken00"; B = "67890:TESTONLYfixturevalue0"'))


def _gl_branches37():
    """The Gitleaks step's (pull-request branch, other branch), as commands.

    Comment lines are dropped, each continued line is joined to its command, whitespace collapsed.
    """
    body = _wf_run_block(_read29(".github", "workflows", "security.yml"), "Gitleaks")
    code = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    lines = [" ".join(ln.split()) for ln in _re37.sub(r"\\\n\s*", " ", code).splitlines() if ln.strip()]
    start = next((i for i, ln in enumerate(lines) if ln.startswith('if [ -n "${BASE_SHA:-}" ]')), None)
    if start is None or "else" not in lines[start:] or "fi" not in lines[start:]:
        return [], []
    els = lines.index("else", start)
    return lines[start + 1:els], lines[els + 1:lines.index("fi", els)]


def _first_capture37(pattern, commands):
    """The first group of the first command `pattern` matches in full, or None."""
    for c in commands:
        m = _re37.fullmatch(pattern, c)
        if m:
            return m.group(1)
    return None


def _gl_pr_facts37(pr):
    """Where the pull-request branch puts the base's config and ignore file, and the order it runs.

    (the base config's copy, the base ignore file's dir, where the tree's own is removed, where the
    first scan is); None or -1 for what is not there.
    """
    cfg = _first_capture37(r'git show "\$\{BASE_SHA\}:\.github/gitleaks\.toml" > "([^"]+)"', pr)
    ign = _first_capture37(r'git show "\$\{BASE_SHA\}:\.gitleaksignore" > "([^"]+)/\.gitleaksignore".*', pr)
    rm = [i for i, c in enumerate(pr) if c == "rm -rf -- ./.gitleaksignore"]
    first = [i for i, c in enumerate(pr) if c in _gl_scans37(pr)]
    return cfg, ign, (rm or [None])[0], (first or [-1])[0]


def _gl_scans37(commands):
    return [c for c in commands if "gitleaks git " in c]


def _gl_pr_bad37(pr, other):
    """What lets a pull request bring its own allowlist: [] when nothing does."""
    scans, pr_scans = _gl_scans37(pr + other), _gl_scans37(pr)
    cfg, ign, rm_at, first = _gl_pr_facts37(pr)
    tests = [
        (cfg, "no copy of the base's config"),
        (ign, "no copy of the base's .gitleaksignore"),
        (-1 < (-1 if rm_at is None else rm_at) < first, "the tree's own .gitleaksignore is not removed first"),
        (any('--config "%s"' % cfg in c for c in pr_scans), "no scan uses the base's config"),
        (all('--gitleaks-ignore-path "%s"' % ign in c for c in pr_scans), "a scan reads another ignore file"),
        (all("--ignore-gitleaks-allow" in c for c in scans), "a scan honours gitleaks:allow"),
        (len(scans) == 3, "%d scans, not 3" % len(scans)),
    ]
    return [msg for ok, msg in tests if not ok]


def _v3_pr_allowlists():
    """A pull request is scanned by the base's allowlists, never by ones it brings itself."""
    bad = _gl_pr_bad37(*_gl_branches37())
    check("gitleaks: a pull request is scanned with the BASE commit's config and .gitleaksignore, its "
          "own .gitleaksignore deleted first and every `gitleaks:allow` ignored, so it cannot allowlist "
          "its own finding in the same diff", not bad, "; ".join(bad))


def _v11_allowlist_reasons():
    """Every entry in gitleaks' global allowlist says why it is there."""
    text = _read29(".github", "gitleaks.toml")
    m = _re37.search(r"^\[\[allowlists\]\]\n.*?^regexes = \[\n(.*?)^\]", text, _re37.M | _re37.S)
    lines = m.group(1).splitlines() if m else []
    entries, bare = 0, []
    for i, ln in enumerate(lines):
        if not _re37.match(r"^\s*'''", ln):
            continue
        entries += 1
        inline = "#" in ln.split("'''")[-1]
        above = i > 0 and lines[i - 1].lstrip().startswith("#")
        if not (inline or above):
            bare.append(ln.strip())
    check("gitleaks: every global allowlist entry says why it exists (an inline comment, or a "
          "comment block directly above it); two that did not were dead",
          entries >= 8 and not bare, "%d entries; no reason: %r" % (entries, bare))


# ── V5: the CHANGELOG describes Semgrep's PyJWT as CI installs it ───────────────────────────────
# ── V4: what an install set up before the setup token should check ──────────────────────────────
def _v4_prefix_doc():
    """SECURITY.md gives an operator of a pre-fix install the checks the advisory left out."""
    sec = _read29(".github", "SECURITY.md")
    parts = sec.split("#### Checking an install set up before the fix (GHSA-cwmq-pvg9-jjfx)\n", 1)
    body = parts[1].split("\n## ", 1)[0].split("\n#### ", 1)[0] if len(parts) == 2 else ""
    need = ("`aad46a4`", "sudo linuxgsm-panel-recover list-users", "manage.py list-users", "[superadmin]",
            "tailscale status --json | jq -r .CurrentTailnet.Name", "tailscale serve status", "`login`",
            "not an all-clear")
    missing = [n for n in need if n not in body]
    manage = _read29("manage.py")
    recover = "\n".join(ln for ln in _read29("recover.sh").splitlines() if not ln.lstrip().startswith("#"))
    real = ('sub.add_parser("list-users"' in manage and '["superadmin"] if u.is_superadmin' in manage
            and '"${PANEL_DIR}/manage.py" "$@"' in recover)
    check("docs: SECURITY.md tells an operator whose install was set up before the setup token what to "
          "check (superadmins, the tailnet, sign-ins), by commands that exist and print what it says",
          bool(body) and not missing and real, "missing %r; commands real: %s" % (missing, real))


def _v5_verdict(text, gone, pinned):
    """(ok, stale entries) for a CHANGELOG: no [Unreleased] entry may describe the removed split.

    The gate rejects the stale description and nothing else. It used to need a PyJWT entry to EXIST
    as well, so dropping or rewording that bullet, or cutting [Unreleased] into a release, would
    have failed main over a prose edit with nothing stale in it.
    """
    unreleased = text.split("\n## [Unreleased]", 1)[-1].split("\n## [", 1)[0]
    entries = [e for e in _re37.split(r"\n(?=- )", unreleased) if "PyJWT" in e]
    stale = [e.strip()[:70] for e in entries if _re37.search(r"pinned apart|--no-deps|semgrep-pyjwt", e)]
    return gone and pinned and not stale, stale


def _v5_changelog():
    """No [Unreleased] entry describes the PyJWT split #391 removed."""
    gone = not os.path.exists(os.path.join(_root, ".github", "ci-requirements", "semgrep-pyjwt.txt"))
    pinned = "\npyjwt==" in _read29(".github", "ci-requirements", "semgrep.txt").lower()
    ok, stale = _v5_verdict(_read29("docs", "CHANGELOG.md"), gone, pinned)
    check("changelog: [Unreleased] describes Semgrep's PyJWT as CI installs it now (one hash "
          "lockfile, no split), not the split #391 removed", ok, "stale: %r" % stale)
    head = "# Changelog\n\n## [Unreleased]\n\n### Security\n\n"
    probes = {
        "no entry": head + "- **Other.** Text.\n\n## [2026.9.1]\n\n- PyJWT is now pinned apart.\n",
        "a current entry": head + "- **PyJWT 2.15.** One hash lockfile.\n",
        "the stale entry": head + "- **PyJWT.** PyJWT is now pinned apart from semgrep's lockfile, "
                                  "and both install with `--no-deps`.\n",
    }
    got = {k: _v5_verdict(v, True, True)[0] for k, v in probes.items()}
    check("changelog: (control) the PyJWT gate passes an [Unreleased] with no PyJWT entry (one in an "
          "older release does not count) or a current one, and fails the stale text",
          got == {"no entry": True, "a current entry": True, "the stale entry": False}, repr(got))


# ── F7: test modules import app one way; a cleanup that cannot delete a file says so ────────────
def _test_files37():
    return sorted(_glob37.glob(os.path.join(_root, "tests", "**", "*.py"), recursive=True))


def _app_imports37(tree):
    """(lines of `import app`, lines of `from app import`) in one module."""
    plain, frm = [], []
    for n in _ast37.walk(tree):
        if isinstance(n, _ast37.Import) and "app" in {a.name for a in n.names}:
            plain.append(n.lineno)
        elif isinstance(n, _ast37.ImportFrom) and n.module == "app" and not n.level:
            frm.append(n.lineno)
    return plain, frm


def _f7_imports():
    """No test module imports app with both `import app` and `from app import`."""
    both = []
    files = _test_files37()
    for f in files:
        plain, frm = _app_imports37(_ast37.parse(open(f, encoding="utf-8").read()))
        if plain and frm:
            both.append("%s: import at %s, from-import at %s" % (_rel37(f), plain[:3], frm[:3]))
    check("tests: no test module imports app both ways (`import app as X` beside `from app import`; "
          "CodeQL's py/import-and-import-from, held here before CodeQL read tests/ too)",
          len(files) >= 40 and not both, "; ".join(both))


def _is_removal_try37(node):
    """Is node `try: <x>.unlink()` or `try: os.remove(...)`, alone in its body?"""
    if not (isinstance(node, _ast37.Try) and len(node.body) == 1):
        return False
    call = getattr(node.body[0], "value", None)
    return isinstance(call, _ast37.Call) and _callee37(call.func).endswith((".unlink", ".remove"))


def _silent_oserror37(handler):
    """Does this handler catch OSError (or a tuple naming it) and do nothing but `pass`?"""
    if handler.type is None or "OSError" not in _ast37.unparse(handler.type):
        return False
    return all(isinstance(b, _ast37.Pass) for b in handler.body)


def _swallowed_removals37(tree):
    """Lines of `try: <x>.unlink() / os.remove(...)` whose OSError handler is only `pass`."""
    return [n.lineno for n in _ast37.walk(tree) if _is_removal_try37(n)
            and any(_silent_oserror37(h) for h in n.handlers)]


def _f7_cleanups():
    """No test cleanup swallows a failed delete."""
    bad = []
    for f in _test_files37():
        lines = _swallowed_removals37(_ast37.parse(open(f, encoding="utf-8").read()))
        bad += ["%s:%d" % (_rel37(f), ln) for ln in lines]
    probe = "try:\n    p.unlink()\nexcept OSError:\n    pass\n"
    check("tests: no cleanup swallows a failed delete (a panel.db it leaves makes the next run of "
          "every DB-owning suite SKIP and exit 0, with nothing said)",
          not bad and _swallowed_removals37(_ast37.parse(probe)) == [1], "; ".join(bad))


def _exits_in_finally37(node):
    """Is node a module-level try whose finally calls sys.exit()?"""
    if not (isinstance(node, _ast37.Try) and node.finalbody):
        return False
    fin = _ast37.Module(body=node.finalbody, type_ignores=[])
    return any(_callee37(c.func) == "sys.exit" for c in _ast37.walk(fin) if isinstance(c, _ast37.Call))


def _catches_base37(node):
    """Does the try have a handler for BaseException (or a bare except)?"""
    return any(h.type is None or _ast37.unparse(h.type) == "BaseException" for h in node.handlers)


def _f7_crash_handlers():
    """A suite whose module-level finally calls sys.exit() records a BaseException as a crash."""
    tries = []
    for f in sorted(_glob37.glob(os.path.join(_root, "tests", "*.py"))):
        body = _ast37.parse(open(f, encoding="utf-8").read()).body
        tries += [(f, n) for n in body if _exits_in_finally37(n)]
    bad = ["%s:%d" % (_rel37(f), n.lineno) for f, n in tries if not _catches_base37(n)]
    check("tests: a suite whose finally calls sys.exit() records a BaseException as a crash (the "
          "exit replaces it, so an eventlet Timeout ended setup_wizard_test early, green)",
          len(tries) >= 3 and not bad, "%d such suites; Exception-only at %s" % (len(tries), bad))


_f5_tripwire()
_f5_controls()
_f5_justification()
_ROWS37 = _f6_pack()
_f6_shapes(_ROWS37)
_f6_entry_points(_ROWS37)
_f6_double_shell()
_f6_local_shell()
_f6_reach()
_PJ37, _LOCK37 = _vendor_json37("package.json"), _vendor_json37("package-lock.json")
_v2_files(_PJ37)
_v2_versions(_PJ37, _LOCK37)
_v2_socketio(_PJ37, _LOCK37)
_v2_embedded(_PJ37, _LOCK37)
_v2_asset_urls()
_v2_update_paths()
_v3_rule()
_v3_allowlist()
_v3_fixture_shape()
_v3_pr_allowlists()
_v11_allowlist_reasons()
_v4_prefix_doc()
_v5_changelog()
_f7_imports()
_f7_cleanups()
_f7_crash_handlers()
