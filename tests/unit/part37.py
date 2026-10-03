"""Part 37 of the unit suite: scanner coverage, vendored code and secret detection (build ws7).

What it holds, one section each:
* F5: py/partial-ssrf is excluded repo-wide on the strength of a justification that had gone stale
  (it said notifications._post was the only outbound-HTTP sink). The justification now lists every
  outbound-HTTP call site, and this part lists them too: a new one fails until it is reviewed.
* F6: the CodeQL model pack in .github/codeql/extensions makes Flask-SocketIO handler parameters
  remote sources and the panel's own-host shell a command-injection sink. Whether CodeQL honours it
  is proved by the probe PR's canary; this part holds the pack's shape and the code shapes its rows
  assume, so a refactor cannot leave a model quietly matching nothing.
* V2: static/vendor/ is described to scanners by package.json + package-lock.json, and every file in
  it is tied to that manifest by sha256 and by the version its own banner states. The Socket.IO
  client must carry socket.io-parser's two advisory fixes.
* V3: gitleaks' keyword-free Telegram rule, emulated here on planted tokens built at run time (a
  literal would itself be the thing the scanners flag), and part05's fixture-shape pattern.
* V11: every entry in gitleaks' global allowlist says why it is there (the two that did not were
  dead, and are gone).
* V5: the CHANGELOG may not describe a PyJWT split that the CI lockfiles no longer have.
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

from unit.part01 import check
from unit.part05 import _fixture_shapes, _root
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
_SINK_ROW37 = ["eventlet", "Member[patcher].Member[original].ReturnValue.Member[Popen]"
               ".Argument[0,args:].ListElement", "command-injection"]
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
    check("codeql model pack: the own-host shell is a command-injection sink, with shlex.quote a "
          "barrier (CodeQL's stdlib model passes taint through it)",
          _SINK_ROW37 in rows.get("sinkModel", []) and _BARRIER_ROW37 in rows.get("barrierModel", []),
          repr((rows.get("sinkModel"), rows.get("barrierModel"))))
    return rows


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
    core = _ast37.parse(open(os.path.join(_root, "panel", "ops", "ssh_manager", "_core.py"),
                             encoding="utf-8").read())
    check("codeql model pack: _core's local shell is eventlet's original subprocess, Popen'd with a "
          "[\"/bin/bash\", \"-c\", cmd] list literal (what the sink row matches)", _shell_shape37(core))


def _names_imported37(tree, module, name):
    """The local names `from <module> import <name> [as x]` binds in tree."""
    out = set()
    for n in _ast37.walk(tree):
        if isinstance(n, _ast37.ImportFrom) and n.module == module:
            out |= {a.asname or a.name for a in n.names if a.name == name}
    return out


def _assigned_from37(tree, target):
    """The callees of every `<target> = <callee>(...)` assignment in tree."""
    out = set()
    for n in _ast37.walk(tree):
        if not (isinstance(n, _ast37.Assign) and isinstance(n.value, _ast37.Call)):
            continue
        if target in {getattr(t, "id", "") for t in n.targets}:
            out.add(_callee37(n.value.func))
    return out


def _popen_list_heads37(fn):
    """The first two elements of each list literal fn hands to _real_subprocess.Popen."""
    heads = []
    for c in _ast37.walk(fn):
        if not (isinstance(c, _ast37.Call) and _callee37(c.func) == "_real_subprocess.Popen"):
            continue
        if c.args and isinstance(c.args[0], _ast37.List):
            heads.append([getattr(e, "value", None) for e in c.args[0].elts[:2]])
    return heads


def _shell_shape37(tree):
    """Is _real_subprocess = original("subprocess"), and _exec_local_shell's Popen a bash -c list?"""
    original = _names_imported37(tree, "eventlet.patcher", "original")
    bound = bool(original & _assigned_from37(tree, "_real_subprocess"))
    fn = [n for n in tree.body if isinstance(n, _ast37.FunctionDef) and n.name == "_exec_local_shell"]
    return bound and bool(fn) and _popen_list_heads37(fn[0]) == [["/bin/bash", "-c"]]


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


def _v3_rule():
    """The keyword-free rule finds a fresh token everywhere, and nothing it should not."""
    rule = _tg_rule37()
    has = bool(rule.get("regex"))
    check("gitleaks: a keyword-free Telegram rule is configured, reporting capture group 1",
          has and rule["group"] == 1 and not rule["keywords"], repr(rule))
    missed = []
    for label, fmt in sorted(_TG_PLACES37.items()):
        for tok in (_tg_token37(), _tg_token37(last="-"), _tg_token37(last="_")):
            got = _tg_found37(rule, "a line before\n" + fmt % tok + "\nand one after")
            if got != [tok]:
                missed.append("%s%s: %r" % (label, " (ends %s)" % tok[-1], got))
    check("gitleaks: the Telegram rule finds a fresh token in every placement, as exactly that "
          "token (config.json, an assignment, an argument, the Bot API URL, prose, env, YAML)",
          has and not missed, "; ".join(missed[:4]) or "no rule")
    near = {"gitleaks' own documented false positive": "clm12345:AgencyIdentificationCodeContentType",
            "a 34-character tail": _tg_token37()[:-1],
            "the TESTONLY fixtures": 'T = "12345:TESTONLYnotarealtoken00"; U = "67890:TESTONLYfixturevalue0"',
            "gitleaks' own `:A` shape, not `:AA`": _tg_token37().replace(":AA", ":AB", 1)}
    hits = {k: _tg_found37(rule, v) for k, v in near.items()}
    check("gitleaks: ...and finds nothing in gitleaks' own XSD false positive, a 34-character tail, "
          "the panel's TESTONLY fixtures, or a `:A` that is not `:AA`",
          has and not any(hits.values()), repr({k: v for k, v in hits.items() if v}) if has else "no rule")


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
def _v5_changelog():
    """No [Unreleased] entry describes the PyJWT split #391 removed."""
    text = _read29("docs", "CHANGELOG.md")
    unreleased = text.split("\n## [Unreleased]", 1)[-1].split("\n## [", 1)[0]
    entries = [e for e in _re37.split(r"\n(?=- )", unreleased) if "PyJWT" in e]
    gone = not os.path.exists(os.path.join(_root, ".github", "ci-requirements", "semgrep-pyjwt.txt"))
    pinned = "\npyjwt==" in _read29(".github", "ci-requirements", "semgrep.txt").lower()
    stale = [e.strip()[:70] for e in entries if _re37.search(r"pinned apart|--no-deps|semgrep-pyjwt", e)]
    check("changelog: [Unreleased] describes Semgrep's PyJWT as CI installs it now (one hash "
          "lockfile, no split), not the split #391 removed",
          gone and pinned and entries and not stale, "stale: %r" % stale)


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
          "CodeQL's py/import-and-import-from, which does not read tests/)",
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
_f6_shapes(_f6_pack())
_PJ37, _LOCK37 = _vendor_json37("package.json"), _vendor_json37("package-lock.json")
_v2_files(_PJ37)
_v2_versions(_PJ37, _LOCK37)
_v2_socketio(_PJ37, _LOCK37)
_v3_rule()
_v3_allowlist()
_v3_fixture_shape()
_v11_allowlist_reasons()
_v5_changelog()
_f7_imports()
_f7_cleanups()
_f7_crash_handlers()
