"""Part 261 of the unit suite: the browser side of review pass 31.

1. Every step-up route a page calls with fetch() asks for the password in place first. A gate over
   all of panel/static/js: each string that builds the URL of a step-up gated route (a
   step_up_required view, or one asking step_up_needed() itself) for a changing request sits inside
   a step-up helper's callback (window.stepUpThen, or a page's _xxStepUp wrapper), or in a function
   that is only ever called from one. A bare call is sent to the confirm page by panel.js and loses
   what was typed. The callers fixed here are then driven in node with stepUpThen stubbed.

Nothing reaches a host.
"""
import inspect as _inspect261
import os
import re as _re261
import time as _time261
from types import SimpleNamespace as _NS261

from unit.part01 import check, eq, skip
from unit.part05 import _root
from unit.part12 import P9_ADMIN, P9_GS, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch, _p9_patch_sm, \
    _p9_restore_all, _p9_new_server, _p9_delete_server, _p9_flashes
from unit.part221 import _JS_EXTRA221, _JS_STUBS221, _node221
from unit.part226 import _db_setup226, _db_teardown226
from unit.part249 import _DOM249, _SETTLE249, _cut249, _js249, _resp249, _run249

_TRIP261 = len(_P9_TRIPPED)
_TYPED261 = "typed-pw"          # what the node tests type into the database server form
_JS261 = os.path.join(_root, "panel", "static", "js")
_TPL261 = os.path.join(_root, "panel", "templates")
_STEP_UP_NAME261 = _re261.compile(r"step_?up", _re261.I)
_HOLE261 = "\x00"


def _read261(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The gate: no step-up route is fetched outside a step-up helper
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _asks_itself261(fn):
    """Whether a view asks step_up_needed() in its own body (the routes that ask only for some actions)."""
    try:
        src = _inspect261.getsource(_inspect261.unwrap(fn))
    except (OSError, TypeError):
        return False
    return "step_up_needed()" in src


def _step_up_rules261():
    """(pattern, endpoint) for every step-up gated rule that takes a changing method."""
    out = []
    for rule in _p9.url_map.iter_rules():
        fn = _p9.view_functions.get(rule.endpoint)
        if fn is None or not (getattr(fn, "_step_up", False) or _asks_itself261(fn)):
            continue
        if not (set(rule.methods or ()) - {"GET", "HEAD", "OPTIONS"}):
            continue
        out.append((rule.rule, rule.endpoint))
    return out


def _sample261(rule):
    """The rule with each <converter> replaced by one marker character."""
    return _re261.sub(r"<[^>]+>", "\x01", rule)


def _matches261(pieces, sample):
    """Whether a JS URL (its literal text, a hole for each computed part) can be the rule `sample`."""
    # A leading hole is the mount point or a base-URL helper; any other one is an id, one path segment.
    pat = "".join((".*?" if not i else "[^/]*") if p == _HOLE261 else _re261.escape(p) for i, p in enumerate(pieces))
    return _re261.fullmatch(pat, sample, _re261.S) is not None


def _to_dict261(node):
    return node.toDict() if hasattr(node, "toDict") else node


def _walk261(node, parents, visit):
    """Call visit(node, parents) for every AST dict below `node` (parents: innermost last)."""
    if isinstance(node, list):
        for item in node:
            _walk261(item, parents, visit)
        return
    if not isinstance(node, dict) or "type" not in node:
        return
    visit(node, parents)
    parents.append(node)
    for key, val in node.items():
        if key not in ("range", "loc") and isinstance(val, (dict, list)):
            _walk261(val, parents, visit)
    parents.pop()


def _template_pieces261(node):
    """A template literal's text, a hole for each ${...}."""
    out = []
    for i, q in enumerate(node["quasis"]):
        out.append(q["value"]["cooked"])
        if i < len(node["expressions"]):
            out.append(_HOLE261)
    return out


def _concat261(node):
    """The pieces of a '+' chain of strings (a hole per computed part), or None if no literal is in it."""
    kind = node.get("type")
    if kind == "Literal":
        return [node["value"]] if isinstance(node.get("value"), str) else None
    if kind == "TemplateLiteral":
        return _template_pieces261(node)
    if kind != "BinaryExpression" or node.get("operator") != "+":
        return None
    left, right = _concat261(node["left"]), _concat261(node["right"])
    return (left or [_HOLE261]) + (right or [_HOLE261]) if (left or right) else None


def _before_query261(pieces):
    """The pieces up to the query string, neighbouring holes merged into one."""
    out = []
    for p in pieces:
        if p != _HOLE261 and "?" in p:
            out.append(p.split("?", 1)[0])
            break
        if not (p == _HOLE261 and out and out[-1] == _HOLE261):
            out.append(p)
    return out


def _url_pieces261(pieces):
    """The pieces of a URL path ending in literal text, or None (a helper's `base + path` names no route)."""
    out = _before_query261(pieces)
    text = "".join(p for p in out if p != _HOLE261)
    if not out or out[-1] == _HOLE261 or out[-1].endswith("/") or text.count("/") < 2:
        return None
    return out


def _callee_name261(call):
    callee = call.get("callee") or {}
    if callee.get("type") == "Identifier":
        return callee["name"]
    if callee.get("type") == "MemberExpression" and not callee.get("computed"):
        return (callee.get("property") or {}).get("name", "")
    return ""


def _init_method261(init):
    """The method a fetch() init object names: 'GET' without one, None when it cannot be read."""
    if init is None:
        return "GET"
    if init.get("type") != "ObjectExpression":
        return None
    for prop in init.get("properties") or []:
        key = prop.get("key") or {}
        if (key.get("name") or key.get("value")) == "method":
            val = prop.get("value") or {}
            return str(val.get("value")).upper() if val.get("type") == "Literal" else None
    return "GET"


def _fetch_method261(node, parents):
    """The method of the fetch() whose first argument is `node`, None when it is not one."""
    call = parents[-1] if parents else {}
    if call.get("type") != "CallExpression" or _callee_name261(call) != "fetch" or call["arguments"][:1] != [node]:
        return None
    return _init_method261(call["arguments"][1] if len(call["arguments"]) > 1 else None)


_FN_TYPES261 = ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression")
_DECLS261 = {}


def _declared261(node, names):
    """Add to `names` what `node` declares in the function around it (a nested function's body is its own)."""
    if node["type"] == "VariableDeclarator" and node["id"].get("type") == "Identifier":
        names.add(node["id"]["name"])
    if node["type"] == "FunctionDeclaration" and node.get("id"):
        names.add(node["id"]["name"])
    return node["type"] not in _FN_TYPES261


def _own_walk261(node, visit):
    """Call visit(node) for every AST dict below `node`, not entering a node for which it answers False."""
    if isinstance(node, list):
        for item in node:
            _own_walk261(item, visit)
    elif isinstance(node, dict) and "type" in node and visit(node):
        for key, val in node.items():
            if key not in ("range", "loc"):
                _own_walk261(val, visit)


def _decls261(fn):
    """(params, names declared in `fn`'s own body): var/let/const and function declarations, not nested ones."""
    if id(fn) not in _DECLS261:
        names = set()
        _own_walk261(fn.get("body"), lambda n: _declared261(n, names))
        _DECLS261[id(fn)] = ({p.get("name") for p in fn.get("params", [])}, names)
    return _DECLS261[id(fn)]


def _key261(name, parents):
    """Which `name` a use inside `parents` means: a local of an enclosing function, the global, or None (a parameter)."""
    for k in range(len(parents) - 1, -1, -1):
        if parents[k]["type"] in _FN_TYPES261:
            params, names = _decls261(parents[k])
            if name in params:
                return None
            if name in names:
                return "%d:%s" % (id(parents[k]), name)
    return name


def _fn_key261(fn, parent, outer):
    """The key a function is reached by (declaration, var x = function, x = / window.x = function), or None."""
    if fn["type"] == "FunctionDeclaration" and fn.get("id"):
        return _key261(fn["id"]["name"], outer)
    if parent.get("type") == "VariableDeclarator" and parent.get("init") is fn:
        return _key261(parent["id"].get("name"), outer)
    if parent.get("type") != "AssignmentExpression" or parent.get("right") is not fn:
        return None
    left = parent["left"]
    if left.get("type") == "Identifier":
        return _key261(left["name"], outer)
    return left["property"].get("name") if left.get("type") == "MemberExpression" and not left.get("computed") else None


def _names261(node):
    """Every identifier and property name under `node`."""
    out = set()
    _walk261(node, [], lambda n, p: out.add(n["name"]) if n["type"] == "Identifier" else None)
    return out


def _fallback261(parents, k):
    """Whether parents[k] is the else of `if (window.stepUpThen) ...` (the page without step_up_form.js)."""
    up = parents[k - 1] if k else {}
    return (up.get("type") in ("IfStatement", "ConditionalExpression") and up.get("alternate") is parents[k]
            and "stepUpThen" in _names261(up["test"]))


def _helper_arg261(node, up):
    """Whether `node` is handed straight to a step-up helper (stepUpThen, _xxStepUp)."""
    return (up.get("type") == "CallExpression" and any(node is a for a in up.get("arguments", []))
            and bool(_STEP_UP_NAME261.search(_callee_name261(up))))


def _scope261(parents):
    """('helper', None) inside a step-up helper's callback, ('fn', name) in a named function, ('top', None)."""
    for k in range(len(parents) - 1, -1, -1):
        fn = parents[k]
        if _fallback261(parents, k):
            return ("helper", None)
        if fn["type"] not in _FN_TYPES261:
            continue
        up = parents[k - 1] if k else {}
        if _helper_arg261(fn, up):
            return ("helper", None)
        name = _fn_key261(fn, up, parents[:k])
        if name:
            return ("fn", name)
    return ("top", None)


def _not_a_use261(node, up, parents):
    """Whether this identifier names something rather than using it (a declaration, a key, an assignment target)."""
    t = up.get("type")
    own_prop = t == "MemberExpression" and up.get("property") is node and not up.get("computed")
    called = len(parents) > 1 and parents[-2].get("type") == "CallExpression" and parents[-2].get("callee") is up
    return (t in _FN_TYPES261 or (own_prop and not called)
            or (t in ("VariableDeclarator", "Property", "AssignmentExpression")
                and any(node is up.get(k) for k in ("id", "key", "left"))))


def _use_kind261(node, up, parents):
    """The scope a use of a function runs in: a helper's, its caller's, or an entry point's ('top')."""
    if _helper_arg261(node, up):
        return ("helper", None)
    if (up.get("type") == "CallExpression" and up.get("callee") is node) or up.get("type") == "MemberExpression":
        return _scope261(parents)
    return ("top", None)            # handed to a listener, a timer or a data-action: an entry point


def _form_action261(up):
    """Whether a URL is set as a form's action (the form carries data-step-up itself: part249's gate)."""
    return ((up.get("type") == "AssignmentExpression" and (up["left"].get("property") or {}).get("name") == "action")
            or (up.get("type") == "CallExpression" and _callee_name261(up) == "setAttribute"))


class _Js261:
    """Every JS file parsed once: the URL sites, and each name's references with their scope."""

    def __init__(self, esprima):
        self.sites, self.refs, self.strings = [], {}, set()
        self.failed, self.calls, self.url_fns, self.trees = [], [], {}, []
        self.prefix_fns, self.arg_sites = {}, []
        tpl = "".join(_read261(os.path.join(_TPL261, t)) for t in sorted(os.listdir(_TPL261)) if t.endswith(".html"))
        self.actions = set(_re261.findall(r'data-action="([\w$.]+)"', tpl))
        for name in sorted(n for n in os.listdir(_JS261) if n.endswith(".js")):
            self._parse(esprima, name)
        self._resolve()

    def _parse(self, esprima, name):
        try:
            tree = _to_dict261(esprima.parseScript(_read261(os.path.join(_JS261, name)), {"loc": True}))
        except Exception as e:  # noqa: BLE001 - a file that does not parse is reported by name
            self.failed.append("%s: %s" % (name, e))
            return
        self.trees.append(tree)         # kept: the local names are keyed by their function's id()
        _walk261(tree, [], lambda n, p, f=name: self._visit(f, n, p))

    def _resolve(self):
        """Calls of a URL-returning helper are that route's sites; a base helper's argument joins its base."""
        for f, line, callee, method, scope in self.calls:
            if callee in self.url_fns:
                self.sites.append((f, line, self.url_fns[callee], method, scope))
        for f, line, callee, pieces, method, scope in self.arg_sites:
            url = _url_pieces261(self.prefix_fns[callee] + pieces) if callee in self.prefix_fns else None
            if url:
                self.sites.append((f, line, url, method, scope))

    def _visit(self, f, node, parents):
        up = parents[-1] if parents else {}
        kind = node["type"]
        if kind in ("Literal", "TemplateLiteral", "BinaryExpression") and _concat261(up) is None:
            self._site(f, node, parents, _concat261(node))
        if kind == "Literal" and isinstance(node.get("value"), str):
            self.strings.add(node["value"])
            self.actions.update(_re261.findall(r'data-action="([\w$.]+)"', node["value"]))
        if kind == "Identifier" and not _not_a_use261(node, up, parents):
            own = up.get("type") == "MemberExpression" and up.get("property") is node
            key = node["name"] if own else _key261(node["name"], parents)
            if key:
                self.refs.setdefault(key, []).append(_use_kind261(node, up, parents))
        if kind == "CallExpression" and (node.get("callee") or {}).get("type") == "Identifier":
            self.calls.append((f, node["loc"]["start"]["line"], _key261(node["callee"]["name"], parents),
                               _fetch_method261(node, parents), _scope261(parents)))

    def _helpers(self, f, node, parents, pieces):
        """Note a base-plus-argument call (`api('/x')`) and a function returning a base plus its argument."""
        up = parents[-1] if parents else {}
        if up.get("type") == "CallExpression" and up["arguments"][:1] == [node] \
                and up["callee"].get("type") == "Identifier":
            self.arg_sites.append((f, node["loc"]["start"]["line"], _key261(up["callee"]["name"], parents),
                                   pieces, _fetch_method261(up, parents[:-1]), _scope261(parents)))
        name = _scope261(parents)[1] if up.get("type") == "ReturnStatement" else None
        if name and pieces[-1] == _HOLE261 and len(pieces) > 1:
            self.prefix_fns[name] = pieces[:-1]
        return up, name

    def _site(self, f, node, parents, pieces):
        if not pieces:
            return
        up, returned_by = self._helpers(f, node, parents, pieces)
        url = _url_pieces261(pieces)
        if not url or _form_action261(up):
            return
        if returned_by:
            self.url_fns[returned_by] = url
            return
        self.sites.append((f, node["loc"]["start"]["line"], url, _fetch_method261(node, parents), _scope261(parents)))

    def guarded(self, scope, seen=None):
        """Whether code in `scope` runs only after a step-up helper said go."""
        kind, name = scope
        if kind != "fn":
            return kind == "helper"
        seen = set() if seen is None else seen
        if name in self.actions or name in self.strings:
            return False
        if name in seen:
            return True                     # a function calling itself again: its entry is elsewhere
        seen.add(name)
        uses = self.refs.get(name, [])
        return bool(uses) and all(self.guarded(u, seen) for u in uses)


def _gate261():
    """Every changing fetch of a step-up route goes through a step-up helper."""
    try:
        import esprima as _esprima261
    except ImportError:
        skip("step-up gate: every step-up route is fetched inside a step-up helper", "esprima is not installed")
        return None
    js = _Js261(_esprima261)
    rules = _step_up_rules261()
    bare, seen_rules = [], set()
    for f, line, url, method, scope in js.sites:
        hit = [r for r, ep in rules if _matches261(url, _sample261(r))]
        if not hit or method == "GET":
            continue
        seen_rules.update(hit)
        if not js.guarded(scope):
            bare.append("%s:%d %s (%s)" % (f, line, hit[0], scope[1] or scope[0]))
    return js, rules, bare, seen_rules


_G261 = _gate261()
if _G261 is not None:
    _js261, _rules261, _bare261, _seen261 = _G261
    eq("step-up gate: every JS file parses", _js261.failed, [])
    check("step-up gate: no step-up route is fetched outside a step-up helper (a stale sign-in is sent to the "
          "confirm page and loses what was typed)", not _bare261, "; ".join(_bare261))
    # The gate can fail: it reads the routes this pass fixed, and the ones that were already wrapped.
    check("step-up gate: it finds the step-up routes' callers (the Tailscale finalize, Sync ports, the backup "
          "restore, the database server choice, the orphan delete, the add-ons) and the rules behind them",
          {"/api/remote/<int:remote_id>/tailscale-finalize", "/api/server/<int:server_id>/sync-ports",
           "/api/panel/backup/restore", "/api/remote/<int:remote_id>/databases/endpoint",
           "/api/remote/<int:remote_id>/databases/<int:db_id>/delete",
           "/api/server/<int:server_id>/addons/<addon_id>/install"} <= _seen261 and len(_rules261) > 40,
          repr((len(_rules261), sorted(_seen261)[:6])))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The callers fixed here, in node: nothing is sent until stepUpThen runs them
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _top_level261():
    """The Tailscale finalize, Sync ports and the three backup restore paths only ask stepUpThen while it holds."""
    src = "\n".join(_cut249(_js249(f), "function %s(" % n) for f, names in (
        ("manage_remotes.js", ("_mrStepUp", "_tsFinalize", "_tsFinalizeNow")),
        ("remote_firewall.js", ("_fwStepUp", "syncPorts", "_syncPortsNow")),
        ("remote_manage_backups.js", ("_bkStepUp", "restoreBackup", "_bkRestore", "_bkAskSkipSafety", "_bkAskPassphrase")))
        for n in names)
    act = r"""
var els = {}; document.getElementById = function(id){ return els[id] = els[id] || el(); };
_da = function(name){ return ' data-action="' + name + '"'; }; function bkMsg(){}
function act(){
  _tsFinalize(7, '100.64.0.1'); syncPorts(9, el()); restoreBackup('a.tar', false, el());
  _bkAskSkipSafety('a.tar', null, el(), false, 'why'); _bkAskPassphrase('a.tar', el());
}
act(); var held = calls.slice(), line = els['ts-wait-7'].innerHTML; calls = []; gate.run = true; act();
console.log(JSON.stringify({held: held, line: line, after: els['ts-wait-7'].innerHTML,
                            ran: calls.filter(function(c){ return c[0] === 'fetch'; }).map(function(c){ return c[1] + ' ' + c[2]; })}));
"""
    got = _node221("step-up js (pass 31)", _JS_STUBS221 + _JS_EXTRA221 + src + "\n" + act)
    if got is None:
        return
    eq("step-up (node): the Tailscale finalize, Sync ports and the panel backup's restore (first try, without a "
       "safety copy, with a passphrase) only ask stepUpThen while it holds, then send once it runs them",
       (got.get("held"), got.get("ran")),
       ([["stepUp", True]] * 5, ["/api/remote/7/tailscale-finalize POST", "/api/server/9/sync-ports POST"]
        + ["/api/panel/backup/restore POST"] * 3))
    check("step-up (node): while the password dialog is open (or was cancelled) the Tailscale line keeps a Finish "
          "setup button that asks again; once the finalize is sent the button is gone",
          'data-action="_tsFinalize"' in got.get("line", "") and "Finish setup" in got.get("line", "")
          and "_tsFinalize" not in got.get("after", "x"), repr(got))


_DBJS261 = r"""
const posts = [], asked = []; let pass = false;
window.stepUpThen = (go, totp) => { asked.push(totp); if (pass) go(); };
window.STEP_UP_TOTP = false; window.MOUNT = ''; global.MOUNT = ''; global.serverId = 5; global.REMOTE_ID = 4;
global.location = {hash: '', reload(){}}; window.addEventListener = () => {}; window.tf = (s) => s; window.t = (s) => s;
window.toast = () => {};
window.confirmDialog = o => o.onConfirm('typed');
window.fetch = function(url, init){ init = init || {};
  if ((init.method || 'GET') === 'POST') { let b = null; try { b = JSON.parse(init.body); } catch (e) { b = null; } posts.push([url, b]); }
  if (/\/upload$/.test(url)) return Promise.resolve(answer({success: true, id: 'ab', chunk: 4}));
  if (/offset=/.test(url)) return Promise.resolve(answer({success: true, received: 6}));
  return Promise.resolve(answer({success: true, message: 'ok', databases: []})); };
"""


def _databases261():
    """The Databases tab, the manager and the host page's orphan delete wait for stepUpThen."""
    prog = (_SETTLE249 + _DOM249 + _resp249() + _DBJS261 + _js249("server_databases.js") + "\n"
            + _js249("databases_manager.js") + "\n" + _js249("host_databases.js") + "\n" + r"""
(async () => {
  await settle(); posts.length = 0;
  const c = window.dbTabCtx;
  c.st.d = {remote_id: 4, databases: [{id: 3, name: 'gs5_lp'}]};
  const put = (id, v) => { document.getElementById(id).value = v; };
  put('db-remote-kind', 'new'); put('db-remote-addr', '192.0.2.7'); put('db-remote-port', '3306');
  put('db-remote-user', 'root'); put('db-remote-pw', 'typed-pw');
  dbmOpen(5, 7, 'gs5_db', '127.0.0.1', 3306);
  const dump = {name: 'd.sql', size: 6, slice: (a, b) => 'x'.repeat(b - a)};
  document.getElementById('dbm-upload-file').files = [dump];
  const acts = [() => dbRemoteSave(null), () => dbRemoteClear(), () => dbReset(3), () => dbDelete(3), () => dbRestore(3),
                () => dbmUpload(), () => dbmReset(), () => dbmRestoreFiles(), () => dbmDelete(), () => hostDbDelete(9, 'gs1_old')];
  for (const a of acts) { a(); await settle(); c.st.busy = false; dbmCtx.st.busy = false; }
  const held = posts.splice(0), heldAsked = asked.splice(0), kept = ids['db-remote-pw'].value;
  pass = true;
  for (const a of acts) { a(); await settle(); c.st.busy = false; dbmCtx.st.busy = false; }
  console.log(JSON.stringify({held, heldAsked, kept, ran: posts.map(p => p[0]), save: (posts[0] || [])[1]}));
})();
""")
    return _run249("step-up (node): the database pages", prog)


_TOP261 = _top_level261()
_DB261 = _databases261()
if _DB261 is not None:
    eq("step-up (node): the database server choice (Save, Clear), the Databases tab's reset, delete and restore, the "
       "manager's upload, reset, restore and delete, and the host page's orphan delete send nothing while the "
       "password is asked, and what was typed stays in the form",
       (_DB261.get("held"), _DB261.get("heldAsked"), _DB261.get("kept")), ([], [False] * 10, _TYPED261))
    eq("step-up (node): ...and each is sent to its route once stepUpThen runs it",
       [u for u in _DB261.get("ran") or [] if "offset=" not in u and not u.endswith("/finish")],
       ["/api/remote/4/databases/endpoint", "/api/remote/4/databases/endpoint",
        "/api/server/5/databases/3/reset-password", "/api/server/5/databases/3/delete",
        "/api/server/5/databases/3/restore", "/api/server/5/databases/7/upload",
        "/api/server/5/databases/7/reset-password", "/api/server/5/databases/7/restore",
        "/api/server/5/databases/7/delete", "/api/remote/4/databases/9/delete"])
    eq("step-up (node): ...the database server Save sends the typed address and admin login",
       _DB261.get("save"), dict(kind="external", address="192.0.2.7", port=3306, user="root", password=_TYPED261))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A piece whose answer was lost is sent again before the upload is given up (backups, database dumps)
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Each case: what the piece at offset 4 answers, try by try ('drop' = no answer at all), the rest succeed.
_UPCASES261 = r"""
const cases = {
  lostThenAppended: ['drop', {status: 409, body: {success: false, received: 8, resume: true}}],
  proxyPage: [{status: 502, body: null}, {status: 200, body: {success: true, received: 8}}],
  busy: [{status: 409, body: {success: false, busy: true}}, {status: 200, body: {success: true, received: 8}}],
  hostError: Array(5).fill({status: 200, body: {success: false, message: 'host said no'}}),
  gone: [{status: 404, body: {success: false, message: 'No such upload.'}}],
  neverAnswers: Array(5).fill('drop'),
};
"""
_BKUP261 = (_SETTLE249 + _UPCASES261 + r"""
global.window = global; global.setTimeout = (f) => setImmediate(f);
let sent = [], plan = [];
function reply(status, body){ return Promise.resolve({ok: status < 400, status,
  json: () => body === null ? Promise.reject(new SyntaxError('not JSON')) : Promise.resolve(body)}); }
window.fetch = function(url){
  sent.push(String(url));
  if (/cancel$/.test(url)) return reply(200, {success: true});
  if (/finish$/.test(url)) return reply(200, {success: true, name: 'a.tar.gz'});
  const m = /offset=(\d+)/.exec(url);
  if (m && Number(m[1]) === 4 && plan.length) { const p = plan.shift();
    return p === 'drop' ? Promise.reject(new TypeError('Failed to fetch')) : reply(p.status, p.body); }
  if (m) return reply(200, {success: true, received: Math.min(Number(m[1]) + 4, 10)});
  return reply(200, {success: true, id: 'u1', chunk: 4});
};
""" + _cut249(_js249("panel.js"), "window.backupUpload = function(") + r"""
const file = {size: 10, slice: (a, b) => 'x'.repeat(b - a)};
(async () => {
  const out = {};
  for (const k of Object.keys(cases)) {
    sent = []; plan = cases[k].slice(); let res = null, err = null;
    try { res = await window.backupUpload(file, '/x/upload', null); } catch (e) { err = String(e.message || e); }
    out[k] = {ok: !!(res && res.success), msg: res && res.message || null, err,
              at4: sent.filter(u => /offset=4$/.test(u)).length, cancel: sent.some(u => /cancel$/.test(u))};
  }
  console.log(JSON.stringify(out));
})();
""")
_bk261 = _run249("backup upload (node): lost pieces", _BKUP261)
if _bk261 is not None:
    eq("backup upload (node): a piece whose answer was lost is sent again at the same offset, and when the host "
       "had appended it (409 with where it is) the upload goes on and finishes — it was cancelled at once",
       _bk261.get("lostThenAppended"), {"ok": True, "msg": None, "err": None, "at4": 2, "cancel": False})
    eq("backup upload (node): ...so is one answered by a proxy's error page (a 502 that is not JSON)",
       _bk261.get("proxyPage"), {"ok": True, "msg": None, "err": None, "at4": 2, "cancel": False})
    eq("backup upload (node): ...and one the server is still writing (409 busy)",
       _bk261.get("busy"), {"ok": True, "msg": None, "err": None, "at4": 2, "cancel": False})
    eq("backup upload (node): a host error that persists is sent five times in all, then the upload is cancelled "
       "and the host's refusal shown", _bk261.get("hostError"),
       {"ok": False, "msg": "host said no", "err": None, "at4": 5, "cancel": True})
    eq("backup upload (node): a refusal that cannot change (404, no such upload) is not sent again (control)",
       _bk261.get("gone"), {"ok": False, "msg": "No such upload.", "err": None, "at4": 1, "cancel": True})
    eq("backup upload (node): a piece that never answers is tried five times, then the upload is cancelled and "
       "the failure rethrown", _bk261.get("neverAnswers"),
       {"ok": False, "msg": None, "err": "Failed to fetch", "at4": 5, "cancel": True})

_DBUP261 = (_SETTLE249 + _DOM249 + _UPCASES261 + r"""
global.setTimeout = (f) => setImmediate(f); window.MOUNT = '';
let sent = [], plan = [];
function reply(status, body){ return Promise.resolve({ok: status < 400, status,
  json: () => body === null ? Promise.reject(new SyntaxError('not JSON')) : Promise.resolve(body)}); }
window.confirmDialog = o => o.onConfirm();
window.fetch = function(url, init){
  sent.push(String(url));
  if (/cancel$/.test(url)) return reply(200, {success: true});
  if (/finish$/.test(url)) return reply(200, {success: true, message: 'restored'});
  const m = /offset=(\d+)/.exec(url);
  if (m && Number(m[1]) === 4 && plan.length) { const p = plan.shift();
    return p === 'drop' ? Promise.reject(new TypeError('Failed to fetch')) : reply(p.status, p.body); }
  if (m) return reply(200, {success: true, received: Math.min(Number(m[1]) + 4, 10)});
  if (/\/upload$/.test(url)) return reply(200, {success: true, id: 'ab', chunk: 4});
  return reply(200, {success: true});
};
""" + _js249("databases_manager.js") + r"""
(async () => {
  const out = {};
  for (const k of ['lostThenAppended', 'proxyPage', 'busy', 'hostError', 'gone', 'neverAnswers']) {
    sent = []; plan = cases[k].slice(); dbmCtx.st.busy = false;
    dbmOpen(5, 7, 'gs5_db', '127.0.0.1', 3306);
    document.getElementById('dbm-upload-file').files = [{name: 'd.sql', size: 10, slice: (a, b) => 'x'.repeat(b - a)}];
    dbmUpload(); await settle(); await settle();
    out[k] = {at4: sent.filter(u => /offset=4$/.test(u)).length, finish: sent.some(u => /finish$/.test(u)),
              cancel: sent.some(u => /cancel$/.test(u))};
  }
  console.log(JSON.stringify(out));
})();
""")
_dbup261 = _run249("database dump upload (node): lost pieces", _DBUP261)
if _dbup261 is not None:
    eq("database dump upload (node): a lost piece, a proxy's error page and a busy answer are each sent again and the "
       "restore goes on; a lasting host error is tried five times and a 404 once before the upload is cancelled",
       _dbup261, {"lostThenAppended": {"at4": 2, "finish": True, "cancel": False},
                  "proxyPage": {"at4": 2, "finish": True, "cancel": False},
                  "busy": {"at4": 2, "finish": True, "cancel": False},
                  "hostError": {"at4": 5, "finish": False, "cancel": True},
                  "gone": {"at4": 1, "finish": False, "cancel": True},
                  "neverAnswers": {"at4": 5, "finish": False, "cancel": True}})


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The upload routes refuse a piece while another request on the same upload is still running
# ════════════════════════════════════════════════════════════════════════════════════════════════
_UID261 = "b" * 32


def _piece261(table, entry, url, busy):
    """POST one 4-byte piece with the upload planted `busy` or not: (status, busy flag, host commands, busy after)."""
    table.clear()
    entry = dict(entry, busy=busy, ts=_time261.time())
    table[_UID261] = entry
    r = _p9_client(P9_ADMIN).post(url, data=b"abcd", content_type="application/octet-stream")
    return r.status_code, _p9_json_or261(r).get("busy"), entry.get("busy")


def _p9_json_or261(r):
    try:
        return r.get_json(silent=True) or {}
    except ValueError:
        return {}


def _uploads261():
    """Each upload kind's piece, with its upload already busy and not: what came back and what ran on the host."""
    from panel.ops import backup as _bk261
    from panel.routes import _shared as _shr261, backup_upload as _bu261, databases_files as _df261
    from panel.services import game_restore as _grs261
    ran = []

    def _run(*a, **k):
        ran.append("game")
        return _grs261._M["UPSIZE"] + " 4", "", 0
    _p9_patch(_bu261, "_sm", _NS261(game_user_cmd=lambda user, inner: inner, _fmt_size=str, run_command=_run))
    _p9_patch(_shr261, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_bu261, "bk", _NS261(UPLOAD_MAX=_bk261.UPLOAD_MAX, UPLOAD_CHUNK=_bk261.UPLOAD_CHUNK,
                                   upload_append=lambda uid, off, data: ran.append("panel") or (True, 4)))
    game = {"uid": _UID261, "kind": "game", "sid": P9_GS, "user": P9_ADMIN, "size": 10, "got": 0}
    panel = dict(game, kind="panel", sid=0)
    out = {}
    for name, entry, url in (("game", game, "/api/panel/backup/game/%d/upload/%s?offset=0" % (P9_GS, _UID261)),
                             ("panel", panel, "/api/panel/backup/upload/%s?offset=0" % _UID261)):
        for busy in (1, 0):
            del ran[:]
            out[(name, busy)] = _piece261(_bu261._uploads, entry, url, busy) + (list(ran),)
    _bu261._uploads.clear()
    sid, api, _name = _db_setup226()
    try:
        _p9_patch_sm("run_command", lambda server, cmd, timeout=30, sudo=True, **kw:
                     ran.append("db") or (_df261._M["SIZE"] + " 4", "", 0))
        _p9_patch(_df261, "game_account_write_refusal", lambda remote, user, **k: None)
        dbid = int(api.rsplit("/", 1)[1])
        entry = {"uid": _UID261, "db": dbid, "user": P9_ADMIN, "size": 10}
        for busy in (1, 0):
            del ran[:]
            out[("db", busy)] = _piece261(_df261._UPLOADS, entry, api + "/upload/%s?offset=0" % _UID261, busy) \
                + (list(ran),)
    finally:
        _df261._UPLOADS.clear()
        _db_teardown226(sid)
    return out


_p9_arm(who="part261")
try:
    _up261 = _uploads261()
finally:
    _p9_restore_all()
for _kind261 in ("game", "panel", "db"):
    eq("%s upload: a piece sent while another request on the same upload is still running answers 409 busy "
       "(the page waits and sends it again) and runs nothing on the host — two would append the same staged "
       "piece side by side" % _kind261, _up261.get((_kind261, 1)), (409, True, 1, []))
    eq("%s upload: ...a piece with nothing else running is appended, and the upload is not left busy (control)"
       % _kind261, _up261.get((_kind261, 0)), (200, None, 0, [_kind261]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Manage add-ons alone opens Files & Config, where the Add-ons tab is
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _addons_member261():
    """A member with View servers and Manage add-ons on a CoD4 server's host: (status, page text, flashes)."""
    from werkzeug.security import generate_password_hash
    from panel.db import models as _m261
    from panel.routes import server_files as _sf261
    from panel.security import auth as _auth261
    _p9_patch(_sf261, "_host_timezone_cached", lambda remote, app=None: "UTC")     # the page's host reads:
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: ("", "", 0))               # its clock, its command list,
    from panel.routes import _shared as _shr261                                      # read here, not left running
    _p9_patch(_shr261, "threading", _NS261(Thread=lambda target, daemon=None: _NS261(start=target)))
    sid = _p9_new_server(P9_HOST, "cod4p261", "cod4", 28961, name="p261-cod4")
    try:
        with _p9.app_context():
            grp = _m261.Group(name="p261_addons", description="", is_default=False)
            grp.set_permissions([_auth261.VIEW_SERVERS, _auth261.MANAGE_ADDONS])
            grp.servers.append(_m261.db.session.get(_m261.RemoteServer, P9_HOST))
            u = _m261.User(username="p261_addons", password_hash=generate_password_hash(os.urandom(12).hex()),
                           display_name="p261", is_superadmin=False, is_active=True)
            u.groups.append(grp)
            _m261.db.session.add_all([grp, u])
            _m261.db.session.commit()
            uid, gid = u.id, grp.id
        try:
            c = _p9_client(uid)
            r = c.get("/server/%d/files" % sid)
            return r.status_code, r.get_data(as_text=True), _p9_flashes(c)
        finally:
            with _p9.app_context():
                _m261.User.query.filter_by(id=uid).delete()
                _m261.Group.query.filter_by(id=gid).delete()
                _m261.db.session.commit()
    finally:
        _p9_delete_server(sid)


_p9_arm(who="part261")
try:
    _am261 = _addons_member261()
finally:
    _p9_restore_all()
check("files page: a member granted Manage add-ons (and View servers) opens a CoD4 server's Files & Config page and "
      "gets its Add-ons tab — the page refused them with a red error, so the permission reached nothing",
      _am261[0] == 200 and 'data-sfsub-btn="addons"' in _am261[1] and "server_addons.js" in _am261[1],
      repr((_am261[0], _am261[2])))
check("files page: ...and gets no Config, Files or Backups tab, which their permissions do not give (control)",
      'data-sfsub-btn="config"' not in _am261[1] and 'data-sfsub-btn="files"' not in _am261[1]
      and 'data-sfsub-btn="backups"' not in _am261[1], "")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. SFTP settings save while the saved Tailscale address is down
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cats261(client):
    """The categories of the flashed messages waiting in this client's session."""
    with client.session_transaction() as sess:
        return [cat for cat, _m in sess.pop("_flashes", [])]


def _sftp261():
    """Save the SFTP card, Tailscale down, with each form: (status, saved config, flash categories)."""
    from panel.core import config as _cfg261
    from panel.services import sftp_broker as _sb261, sftp_common as _sc261
    _p9_patch(_sb261, "tailscale_ips", lambda: [])
    _p9_patch(_sb261, "restart", lambda: None)
    _p9_patch(_sb261, "f2b_follow", lambda app: None)
    _p9_patch(_sb261, "status", lambda: {"state": "off", "error": ""})
    base = {"sftp_port": "2022", "sftp_max_upload_mb": "1024", "sftp_idle_minutes": "15", "sftp_absolute_hours": "8"}
    out = {}
    for case, saved, form in (
            ("off, saved tailscale", "tailscale", dict(base, sftp_bind="tailscale")),
            ("on, saved tailscale", "tailscale", dict(base, sftp_bind="tailscale", sftp_enabled="on")),
            ("on, new tailscale", "loopback", dict(base, sftp_bind="tailscale", sftp_enabled="on"))):
        _cfg261.update_config(lambda cfg, b=saved: cfg.update({_sc261.BIND_KEY: b, _sc261.ENABLED_KEY: True,
                                                               _sc261.PORT_KEY: 2222}))
        c = _p9_client(P9_ADMIN)
        r = c.post("/settings/sftp", data=form)
        cfg = _cfg261.load_config()
        out[case] = (r.status_code, cfg.get(_sc261.ENABLED_KEY), cfg.get(_sc261.BIND_KEY), cfg.get(_sc261.PORT_KEY),
                     _cats261(c))
    _cfg261.update_config(lambda cfg: cfg.update({_sc261.BIND_KEY: "tailscale"}))
    page = _p9_client(P9_ADMIN).get("/settings").get_data(as_text=True)
    _cfg261.update_config(lambda cfg: [cfg.pop(k, None) for k in (_sc261.BIND_KEY, _sc261.ENABLED_KEY, _sc261.PORT_KEY,
                                                                  _sc261.CAP_KEY, _sc261.IDLE_KEY, _sc261.ABSOLUTE_KEY,
                                                                  _sc261.KBD_SIGNIN_KEY, _sc261.HOST_KEY_KEY)])
    return out, page


_p9_arm(who="part261")
try:
    _sf261, _sfpage261 = _sftp261()
finally:
    _p9_restore_all()
eq("SFTP settings: with the saved address on Tailscale and Tailscale down, turning the service off saves (it was "
   "refused \"Choose where the SFTP service listens\", so the service could not be turned off)",
   _sf261.get("off, saved tailscale"), (302, False, "tailscale", 2022, ["success"]))
eq("SFTP settings: ...and so does changing the port with the service left on (it waits for Tailscale, as before)",
   _sf261.get("on, saved tailscale"), (302, True, "tailscale", 2022, ["success"]))
eq("SFTP settings: ...but choosing Tailscale anew while it is down is still refused (control)",
   _sf261.get("on, new tailscale"), (302, True, "loopback", 2222, ["danger"]))
_tsradio261 = _re261.search(r'<input[^>]*id="sftp-bind-ts"[^>]*>', _sfpage261)
check("SFTP settings: the saved Tailscale choice is drawn checked and NOT disabled while Tailscale is down, so the "
      "form posts it (a disabled radio is not sent)",
      _tsradio261 is not None and "checked" in _tsradio261.group(0) and "disabled" not in _tsradio261.group(0),
      _tsradio261.group(0) if _tsradio261 else "no radio")

eq("part261: no check reached a real transport", _P9_TRIPPED[_TRIP261:], [])
