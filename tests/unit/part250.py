"""Part 250 of the unit suite: checks that can fail, for what the suites themselves promise.

* A server page rendered by a part starts no background host lookup (timezone, public IP): each part
  stubs the name the page looks up. part12 records any such thread instead of starting it.
* A part that ends on "nothing reached a real transport" sent no request with part12's tripwire off.
* The run-wide config/key watch (tests/unit_test.py) wraps every config.py function that names the
  config file, the secret key or the credential key.
* Every monitoring alert names the row that decides who gets the push: a server event its `server=`,
  a host event its `remote=`.
* The JS i18n gate knows every wrapper of window.t / window.tf a script defines under its own name.

HOW IT RUNS. Reads what part12 recorded over the whole run, the panel's source as text, and drives the
panel's own resolver once against a stand-in row. Nothing reaches a host or data/.
"""
import ast as _ast250
import glob as _glob250
import os
import re as _re250
import sys as _sys250
from types import SimpleNamespace as _NS250

from unit.part01 import check, eq
from unit.part05 import _root
from unit.part12 import (P9_RESOLVER_THREADS, P9_UNARMED_REQUESTS, _p9, _p9_arm, _p9_client, _p9_restore_all,
                         _p9_sh)
from panel.core import config as _cfg250
from panel.services import push_alerts as _pa250


def _read250(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ── 1. no part's page render started a background host lookup ─────────────────────────────────────
_threads250 = list(P9_RESOLVER_THREADS)
_p9_sh._host_timezone_cached(_NS250(id=-250, timezone=""), _p9)
_control250 = P9_RESOLVER_THREADS[len(_threads250):]
del P9_RESOLVER_THREADS[len(_threads250):]
eq("page renders: no part rendered a server page with the timezone or public-IP lookup unstubbed (each "
   "started a thread that read the fixture host after the part's stubs were gone)", _threads250, [])
eq("page renders: ...a render that misses its stub is recorded, named by its part, not started (control)",
   _control250, [("part250", "_maybe_resolve_host_timezone")])


# ── 2. no request ran unarmed in a part that checks the tripwire ────────────────────────────────────
def _tripwire_parts250():
    """The parts (but part12, which owns it) that end on a _P9_TRIPPED check."""
    out = set()
    for path in _glob250.glob(os.path.join(_root, "tests", "unit", "part*.py")):
        name = os.path.basename(path)[:-3]
        if name not in ("part12", "part250") and "_P9_TRIPPED" in _read250("tests", "unit", name + ".py"):
            out.add(name)
    return out


_twparts250 = _tripwire_parts250()
_unarmed250 = sorted({(p, path) for p, path in P9_UNARMED_REQUESTS if p in _twparts250})
_p9_client(-1).get("/p250-unarmed")
_p9_arm(who="part250")
try:
    _p9_client(-1).get("/p250-armed")
finally:
    _p9_restore_all()
_ctl_unarmed250 = [r for r in P9_UNARMED_REQUESTS if r[0] == "part250"]
check("tripwire: every part that ends on \"nothing reached a real transport\" drove part12's app only with the "
      "tripwire armed (a request after a bare _p9_restore_all() records no trip whatever it reaches)",
      len(_twparts250) >= 30 and not _unarmed250,
      repr({p: [r for q, r in _unarmed250 if q == p][:3] for p in sorted({q for q, _r in _unarmed250})}))
eq("tripwire: ...a request is noted only when the tripwire is off (control)",
   _ctl_unarmed250, [("part250", "/p250-unarmed")])


# ── 3. the run-wide watch covers every config.py reader of the three paths ────────────────────────
_WATCHED_PATHS250 = ("CONFIG_FILE", "SECRET_FILE", "CRED_KEY_FILE")


def _path_readers250(source):
    """{function name: [paths]} for config.py's top-level functions that name one of the three paths."""
    out = {}
    for node in _ast250.parse(source).body:
        if isinstance(node, _ast250.FunctionDef):
            named = sorted({n.id for n in _ast250.walk(node) if isinstance(n, _ast250.Name)} & set(_WATCHED_PATHS250))
            if named:
                out[node.name] = named
    return out


_readers250 = _path_readers250(_read250("panel", "core", "config.py"))
_unwatched250 = sorted(n for n in _readers250 if not hasattr(getattr(_cfg250, n, None), "__wrapped__"))
check("config watch: every config.py function that names config.json, the secret key or the credential key "
      "is wrapped by the runner's watch (config_value's reader and cred_key_lock were not)",
      {"_cfg_current", "cred_key_lock", "get_secret_key"} <= set(_readers250) and not _unwatched250,
      repr((_unwatched250, sorted(_readers250))))


# ── 4. every alert names the row that routes it ───────────────────────────────────────────────────
_ROW250 = dict([(k, "server") for k in _pa250.SERVER_EVENTS] + [(k, "remote") for k in _pa250.HOST_EVENTS])


def _alert_key250(n):
    """The event key of a notify("<event>", …) call node for a server or host event, else None."""
    if not (isinstance(n, _ast250.Call) and getattr(n.func, "attr", getattr(n.func, "id", None)) == "notify" and n.args):
        return None
    key = getattr(n.args[0], "value", None) if isinstance(n.args[0], _ast250.Constant) else None
    return key if key in _ROW250 else None


def _alert_routes250(source):
    """[(line, key, the keyword it should pass, passed?)] for each notify("<event>", …) call in `source`."""
    out = []
    for n in _ast250.walk(_ast250.parse(source)):
        key = _alert_key250(n)
        if key is not None:
            given = {k.arg: k.value for k in n.keywords}.get(_ROW250[key])
            none = isinstance(given, _ast250.Constant) and given.value is None
            out.append((n.lineno, key, _ROW250[key], given is not None and not none))
    return out


_routes250 = []
for _p250 in sorted(_glob250.glob(os.path.join(_root, "panel", "**", "*.py"), recursive=True)):
    _routes250 += [(os.path.relpath(_p250, _root),) + r for r in _alert_routes250(_read250(_p250))]
_unrouted250 = [r for r in _routes250 if not r[4]]
check("alerts: every server event passes server= and every host event remote= (push_alerts sends an alert "
      "only to those who can see that row; without it nobody gets the push)",
      {r[2] for r in _routes250} == set(_pa250.SERVER_EVENTS) | set(_pa250.HOST_EVENTS) and not _unrouted250,
      repr((_unrouted250, sorted({r[2] for r in _routes250}))))
eq("alerts: ...the scan names a call without its row, or with None for it, and passes one with it (control)",
   [r for r in _alert_routes250("n.notify('server_down', 'x', 'y')\nnotify('disk_low', 'x', remote=None)\n"
                                     "n.notify('server_up', 'x', server=gs)\nn.notify('admin_login', 'x')\n")],
   [(1, "server_down", "server", False), (2, "disk_low", "remote", False), (3, "server_up", "server", True)])


# ── 5. the i18n gate knows every translation wrapper a script defines ─────────────────────────────
if os.path.join(_root, "tools") not in _sys250.path:
    _sys250.path.append(os.path.join(_root, "tools"))
import i18n_scan as _scan250  # noqa: E402

_WRAP250 = _re250.compile(
    r"(?:\bfunction\s+([A-Za-z_$][\w$]*)|\b([A-Za-z_$][\w$]*)\s*=\s*function)\s*\(\s*\w+(?:\s*,\s*\w+)?\s*\)\s*\{\s*"
    r"return\s+window\.(?:t|tf)\s*\?")


def _t_wrappers250(sources):
    """Names a script gives window.t / window.tf, directly or as another such name (`var T = dbmT`)."""
    names = {a or b for src in sources for a, b in _WRAP250.findall(src)}
    grew = True
    while grew:
        more = {m for src in sources for m in _re250.findall(
            r"\b([A-Za-z_$][\w$]*)\s*=\s*(%s)\s*[,;\n]" % "|".join(map(_re250.escape, sorted(names))), src)}
        more = {m[0] for m in more} - names
        names |= more
        grew = bool(more)
    return names


_jsdir250 = os.path.join(_root, "panel", "static", "js")
_wrappers250 = _t_wrappers250([_read250("panel", "static", "js", f) for f in sorted(os.listdir(_jsdir250))
                               if f.endswith(".js")])
eq("i18n gate: every wrapper of window.t / window.tf a script defines is one tools/i18n_scan.py reads as t()",
   sorted(_wrappers250 - set(_scan250.JS_T_ALIASES)), [])
eq("i18n gate: ...the wrapper scan finds a function, a function expression and a name given another (control)",
   sorted(_t_wrappers250(["function aT(s) { return window.t ? window.t(s) : s; }\n",
                          "var bTF = function (s, v) { return window.tf ? window.tf(s, v) : s; };\nvar cT = aT;\n"])),
   ["aT", "bTF", "cT"])
eq("i18n gate: ...and a one-word label handed to each of them is gated as a t() argument (control)",
   [_scan250.is_js_t_arg("Column", "node('th', null, %s(" % a) for a in _scan250.JS_T_ALIASES],
   [True] * len(_scan250.JS_T_ALIASES))
