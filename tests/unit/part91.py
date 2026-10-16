"""Part 91 of the unit suite: Tailscale on the panel's own host goes through the helper.

The owner's decision of 2026-10-16 (option 2). An account that is the tailscaled "operator" writes to tailscaled with no sudo and no helper: it
can log the host out, join it to another tailnet with an auth key, and turn Tailscale SSH on, which
admits root logins by THAT tailnet's rules. The panel made its own account the operator, so the
narrow sudo grant did not hold for Tailscale. Held here:

* no verb, in the helper's table or the panel's, can make any account the operator; the one verb
  left takes the role back, and only from the account that asks and only when it holds it.
* every Tailscale write the panel makes on its host (Serve, Serve's `off`, Tailscale SSH on/off) is
  a helper verb, never the panel's own account: by source and by driving each flow.
* the helper refuses the unsafe shapes: a key join of a node that has already joined a tailnet
  (an `up` with a key re-homes it), an `up` on a node already in a tailnet, a Serve `off` with no
  mount (it clears the whole listener), a Tailscale SSH value other than on/off.
* existing hosts switch: install.sh (fresh install and both update branches) and the panel's own
  boot take the role back from the panel's account, and leave anyone else's.
* an older Tailscale that answers `serve status` only to root is read through the helper, and only
  where there is one (a host without it would send a failing sudo per page load).
* a per-user uninstall removes the panel's Serve route with sudo (its account is not the operator).

HOW IT RUNS. The helper and the panel's modules with stand-ins, undone in a finally; install.sh's
and uninstall.sh's own text run under bash in a throwaway directory with a stand-in `tailscale`.
Nothing reaches this machine's tailscale, sudo, or the checkout's data/.
"""
import ast as _ast91
import atexit as _atexit91
import io as _io91
import json as _json91
import os
import re as _re91
import shutil as _shutil91
import subprocess as _sp91  # nosec B404 - bash over the repo's own scripts, in a throwaway dir
import sys
import tempfile as _tf91
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _VERB_SAMPLES, _helper as _helper91, _root
from panel.ops import system_ops as _so91
from panel.ops import tailscale_integration as _ts91
from panel.routes import route_helpers as _rh91
from panel.security import privileged as _priv91
import app as _app91

_TMP91 = _tf91.mkdtemp(prefix="p91-")
_atexit91.register(_shutil91.rmtree, _TMP91, True)


def _read91(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ════════════════════════════════════════════════════════════════════════════════════════════
# 1. No verb can make an account the Tailscale operator
# ════════════════════════════════════════════════════════════════════════════════════════════
def _r24t_sample_argv(build, verb):
    """`build(verb, part05's sample)`, or [] when the sample does not fit it."""
    try:
        return build(verb, list(_VERB_SAMPLES.get(verb, ())))
    except Exception:  # noqa: BLE001 - a verb its sample does not fit names nothing here
        return []


def _r24t_operator_grants(build, table):
    """The verbs in `table` whose argv, built from part05's sample, NAMES an operator."""
    return [verb for verb in sorted(table)
            if any(_re91.fullmatch(r"--operator=.+", str(a)) for a in _r24t_sample_argv(build, verb))]


def _helper_argv91(verb, args):
    return _helper91.VERBS[verb][1](_helper91.validate(verb, args))


_grants91 = (_r24t_operator_grants(_helper_argv91, _helper91.VERBS)
             + _r24t_operator_grants(_priv91.tool_argv, _priv91._ARGV))
check("Tailscale operator: no verb in the helper's table or the panel's builds a command naming an "
      "operator, and tailscale-set-operator is gone from both (an operator joins the host to any "
      "tailnet and turns Tailscale SSH on with no helper)",
      _grants91 == [] and "tailscale-set-operator" not in _helper91.VERBS
      and "tailscale-set-operator" not in _priv91._ARGV, repr(_grants91))


class _HelperRun91:
    """subprocess for the helper: answers `status --json` / `debug prefs` from `state`, records the rest."""

    TimeoutExpired = _sp91.TimeoutExpired
    DEVNULL = _sp91.DEVNULL
    STDOUT = _sp91.STDOUT

    def __init__(self, status=None, prefs=None):
        self.status, self.prefs, self.ran, self.popen = status, prefs, [], []

    def run(self, argv, **_kw):
        sub = list(argv[1:])
        if sub in (["status", "--json"], ["debug", "prefs"]):
            data = self.status if sub[0] == "status" else self.prefs
            if data is None:
                return _sp91.CompletedProcess(argv, 1, "", "unreadable")
            return _sp91.CompletedProcess(argv, 0, _json91.dumps(data), "")
        self.ran.append(sub)
        return _sp91.CompletedProcess(argv, 0, "", "")

    def Popen(self, argv, **_kw):  # noqa: N802 - subprocess's own name
        self.popen.append(list(argv[1:]))
        return NS(pid=1)


def _in_helper91(fake, argv, stdin=""):
    """(rc, stdout, stderr) of the helper's main(argv) with `fake` as its subprocess."""
    saved = (_helper91.subprocess, _helper91.resolve, sys.stdin, sys.stdout, sys.stderr,
             _helper91.panel_conf)
    # As root directly (no SUDO_UID): tailscale-release-operator then takes the name it is given,
    # whoever runs the suite.
    sudo_uid = os.environ.pop("SUDO_UID", None)
    _helper91.subprocess, _helper91.resolve = fake, (lambda n: "/usr/bin/" + n)
    # The owner chose Tailscale SSH at install: these checks are about the joined-node rules, and
    # part93 holds the opt-in itself.
    _helper91.panel_conf = lambda: {"tailscale_ssh": "yes"}
    sys.stdin, sys.stdout, sys.stderr = _io91.StringIO(stdin), _io91.StringIO(), _io91.StringIO()
    try:
        rc = _helper91.main(["panel-helper"] + list(argv))
        return rc, sys.stdout.getvalue(), sys.stderr.getvalue()
    finally:
        (_helper91.subprocess, _helper91.resolve, sys.stdin, sys.stdout, sys.stderr,
         _helper91.panel_conf) = saved
        if sudo_uid is not None:
            os.environ["SUDO_UID"] = sudo_uid


_me91 = "p91panel"      # no such account here: v_managed_user lets an unknown name through
_rel91 = {}
for _label91, _prefs91 in (("held by the caller", {"OperatorUser": _me91}),
                           ("held by someone else", {"OperatorUser": "alice"}),
                           ("held by nobody", {"OperatorUser": ""}),
                           ("unreadable", None)):
    _f91 = _HelperRun91(prefs=_prefs91)
    _rel91[_label91] = (_in_helper91(_f91, ["tailscale-release-operator", _me91])[:2], _f91.ran)
check("panel-helper: tailscale-release-operator clears the operator (`tailscale set --operator=`, "
      "EMPTY) only when the asking account holds it, and touches nothing otherwise",
      _rel91 == {"held by the caller": ((0, "released"), [["set", "--operator="]]),
                 "held by someone else": ((0, "not-operator"), []),
                 "held by nobody": ((0, "not-operator"), []),
                 "unreadable": ((1, "unread"), [])}, repr(_rel91))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 2. The helper refuses an `up` that would move a node already in a tailnet
# ════════════════════════════════════════════════════════════════════════════════════════════
_key91 = "tskey-auth-" + "p91" + "Zq7Kx2"
_upkey91 = {}
for _label91, _st91 in (("Running", {"BackendState": "Running", "HaveNodeKey": True}),
                        ("Starting", {"BackendState": "Starting"}),
                        ("logged out with its node key (Stopped)", {"BackendState": "Stopped",
                                                                     "HaveNodeKey": True}),
                        ("expired key (NeedsLogin, node key held)", {"BackendState": "NeedsLogin",
                                                                      "HaveNodeKey": True}),
                        ("unreadable", None),
                        ("never joined", {"BackendState": "NeedsLogin", "HaveNodeKey": False})):
    _f91 = _HelperRun91(status=_st91)
    _r91 = _in_helper91(_f91, ["tailscale-up-key", "yes", "-", "-"], _key91 + "\n")
    _upkey91[_label91] = (_r91[0], [c[0] for c in _f91.ran])
check("panel-helper: tailscale-up-key on a node that has joined a tailnet (Running, Starting, or "
      "holding a node key) or whose state cannot be read is refused and runs no `up` (an `up` with "
      "a key re-homes the node into the key's tailnet)",
      all(_upkey91[k] == (1, []) for k in _upkey91 if k != "never joined"), repr(_upkey91))
check("panel-helper: ...and a node that has never joined is still joined with the key (control)",
      _upkey91["never joined"] == (0, ["up"]), repr(_upkey91["never joined"]))

_uplog_saved91 = (_helper91.TS_UP_LOG, _helper91.TS_UP_POLL_SECONDS)
_uplogin91 = {}
try:
    _helper91.TS_UP_LOG, _helper91.TS_UP_POLL_SECONDS = os.path.join(_TMP91, "tsup.log"), 0
    for _label91, _st91 in (("Running", {"BackendState": "Running"}),
                            ("Starting", {"BackendState": "Starting"}),
                            ("NeedsLogin", {"BackendState": "NeedsLogin"}),
                            ("expired key", {"BackendState": "NeedsLogin", "HaveNodeKey": True}),
                            ("down with its key", {"BackendState": "Stopped", "HaveNodeKey": True}),
                            ("unreadable", None)):
        _f91 = _HelperRun91(status=_st91)
        _r91 = _in_helper91(_f91, ["tailscale-up-login", "yes", "-"])
        _uplogin91[_label91] = (_r91[0], _r91[1], [c[0] for c in _f91.popen])
finally:
    _helper91.TS_UP_LOG, _helper91.TS_UP_POLL_SECONDS = _uplog_saved91
check("panel-helper: tailscale-up-login on a node already in a tailnet answers ALREADY_CONNECTED "
      "and starts no `up` (there it could only change prefs, --ssh among them)",
      _uplogin91["Running"] == (0, "ALREADY_CONNECTED", [])
      and _uplogin91["Starting"] == (0, "ALREADY_CONNECTED", []), repr(_uplogin91))
check("panel-helper: ...while a node that needs a login gets `up` started for its URL (control)",
      _uplogin91["NeedsLogin"][2] == ["up"], repr(_uplogin91["NeedsLogin"]))
check("panel-helper: tailscale-up-login on a node that holds a node key but is not up (expired "
      "key, or down) is refused and starts no `up`: its login URL lets whoever opens it pick "
      "another tailnet, the same rule tailscale-up-key's _r24t_joined applies",
      _uplogin91["expired key"] == (1, "", []) and _uplogin91["down with its key"] == (1, "", []),
      repr(_uplogin91))
check("panel-helper: ...while a status it cannot read still starts `up` (first Connect while "
      "tailscaled is still starting; the key join refuses it instead)",
      _uplogin91["unreadable"][2] == ["up"], repr(_uplogin91["unreadable"]))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 3. The new verbs: narrow arguments, the same on both sides
# ════════════════════════════════════════════════════════════════════════════════════════════
def _both91(verb, args):
    """(helper's argv or "refused", panel's argv or "refused") for `verb args`."""
    def _h():
        try:
            return _helper_argv91(verb, args)
        except ValueError:
            return "refused"

    def _p():
        try:
            return _priv91.tool_argv(verb, args)
        except _priv91.VerbError:
            return "refused"
    return _h(), _p()


_ssh91 = {v: _both91("tailscale-ssh", [v]) for v in ("on", "off", "yes", "true", "--operator=x",
                                                     "on --reset", "")}
check("tailscale-ssh: on/off become `tailscale set --ssh=true|false` and nothing else, on both sides; "
      "every other value is refused",
      _ssh91["on"] == (["tailscale", "set", "--ssh=true"],) * 2
      and _ssh91["off"] == (["tailscale", "set", "--ssh=false"],) * 2
      and all(_ssh91[v] == ("refused", "refused") for v in _ssh91 if v not in ("on", "off")),
      repr(_ssh91))

_off91 = {m: _both91("tailscale-serve-off", ["https", "443", m])
          for m in ("/", "/lgsm", "/lgsm/", "//", "", "-x", "/a//", "/x y", "/../etc", "/a/b/c/d")}
check("tailscale-serve-off: always names one mount (\"/\", \"/x\" or the \"/x/\" twin) on both sides; "
      "no mount, \"//\" and every option- or path-shaped value are refused (an `off` with no mount "
      "removes every app on the listener)",
      _off91["/"][0] == _off91["/"][1] == ["tailscale", "serve", "--https=443", "--set-path=/", "off"]
      and _off91["/lgsm/"][0] == _off91["/lgsm/"][1]
      == ["tailscale", "serve", "--https=443", "--set-path=/lgsm/", "off"]
      and _off91["/lgsm"][0] == _off91["/lgsm"][1]
      and all(_off91[m] == ("refused", "refused")
              for m in ("//", "", "-x", "/a//", "/x y", "/../etc", "/a/b/c/d")), repr(_off91))
_offl91 = {k: _both91("tailscale-serve-off", list(a)) for k, a in (
    ("tcp listener", ("tcp", "443", "/")), ("port 0", ("https", "0", "/")),
    ("port as option", ("https", "-1", "/")), ("http 8080", ("http", "8080", "/x")))}
check("tailscale-serve-off: ...the listener is https|http on a real port, or refused",
      _offl91["http 8080"][0] == ["tailscale", "serve", "--http=8080", "--set-path=/x", "off"]
      and all(_offl91[k] == ("refused", "refused") for k in ("tcp listener", "port 0",
                                                            "port as option")), repr(_offl91))
_new91 = ("tailscale-release-operator", "tailscale-ssh", "tailscale-serve-off", "tailscale-serve-status")
check("the panel-host Tailscale verbs are in both tables with the same arity, and LOCAL_ONLY (a "
      "remote's Tailscale is the remote flow's, unchanged)",
      all(len(_helper91.VERBS[v][0]) == len(_priv91._ARGV[v][0]) for v in _new91)
      and set(_new91) <= _priv91.LOCAL_ONLY_VERBS
      and _both91("tailscale-serve-status", []) == (["tailscale", "serve", "status"],) * 2,
      repr([(v, v in _helper91.VERBS, v in _priv91._ARGV) for v in _new91]))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 4. The panel: every Tailscale write on its host is a helper verb
# ════════════════════════════════════════════════════════════════════════════════════════════
# Source: _run_ts (the panel's own account) is only ever handed a READ, and system_ops runs no
# `tailscale` command but reads. The panel's account no longer being the operator means a write as
# it fails; this keeps one from being written back in.
_TS_SRC91 = _read91("panel", "ops", "tailscale_integration.py")
_SO_SRC91 = _read91("panel", "ops", "system_ops.py")
# ...and the one write that only takes power away: the operator clearing ITSELF (release_operator,
# on a host with no helper or a helper too old for the verb; install.sh does the same).
# Read by AST, not by a line pattern (review 1016b: a call whose argument list started on the next
# line, and system_ops' `_run('tailscale …')` in single quotes or an f-string, were never collected).
_READS91 = {("version",), ("--version",), ("status",), ("debug", "prefs"), ("serve", "status"),
            ("set", "--operator=")}


def _r25d_call_name91(node):
    _f = node.func
    return _f.id if isinstance(_f, _ast91.Name) else getattr(_f, "attr", None)


def _r25d_ts_arg_is_read91(node, in_run_ts_json=False):
    """Is the first argument of a `_run_ts(...)` call one of the reads (or _run_ts_json's own `args + ['--json']`)?

    That one only inside _run_ts_json itself, whose own calls are judged by their arguments (review
    1016c: the same text at any other call site passed as a read, whatever `args` held).
    """
    if not node.args:
        return False
    try:
        return tuple(_ast91.literal_eval(node.args[0])) in _READS91
    except (ValueError, TypeError, SyntaxError):
        return in_run_ts_json and _ast91.unparse(node.args[0]) == "args + ['--json']"


def _r25d_so_ts_command91(node):
    """The `tailscale` command a system_ops `_run(...)` call runs ("" for none, its source when not a constant)."""
    if _r25d_call_name91(node) != "_run" or not node.args:
        return ""
    _a = node.args[0]
    if isinstance(_a, _ast91.Constant) and isinstance(_a.value, str):
        return _a.value if _re91.search(r"(?:^|[;&|(]\s*|\bsudo\s+(?:-\S+\s+)*)tailscale\b", _a.value) else ""
    _txt = _ast91.unparse(_a)
    return _txt if "tailscale" in _txt else ""


def _r25d_calls91(src):
    """Every call in source `src`."""
    return [_n for _n in _ast91.walk(_ast91.parse(src)) if isinstance(_n, _ast91.Call)]


def _r25d_so_write91(command):
    """Is system_ops' tailscale command `command` (from _r25d_so_ts_command91) a write?"""
    return bool(command) and not _re91.match(r"tailscale (status|debug prefs)\b", command)


def _r26d_inside91(tree, name):
    """The ids of every node inside the function(s) `name` in `tree`."""
    return {id(_n) for _f in _ast91.walk(tree) if getattr(_f, "name", None) == name for _n in _ast91.walk(_f)}


def _r26d_calls_in91(tree):
    """Every call in `tree`."""
    return [_n for _n in _ast91.walk(tree) if isinstance(_n, _ast91.Call)]


def _r25d_ts_writes91(ts_src, so_src):
    """(the _run_ts calls in `ts_src`, the ones that are not reads, system_ops' tailscale commands that are not)."""
    _tree = _ast91.parse(ts_src)
    _in_json = _r26d_inside91(_tree, "_run_ts_json")
    _calls = [_n for _n in _r26d_calls_in91(_tree) if _r25d_call_name91(_n) in ("_run_ts", "_run_ts_json")]
    _writes = [_ast91.unparse(_n) for _n in _calls if not _r25d_ts_arg_is_read91(_n, id(_n) in _in_json)]
    _so = [_r25d_so_ts_command91(_n) for _n in _r25d_calls91(so_src)]
    return _calls, _writes, [_c for _c in _so if _r25d_so_write91(_c)]


_ts_calls91, _ts_writes91, _so_writes91 = _r25d_ts_writes91(_TS_SRC91, _SO_SRC91)
# The gate against planted writes (control): one per spelling the line pattern could not see.
_r25d_planted91 = _r25d_ts_writes91(
    "_run_ts(\n    ['set', '--ssh=true'], timeout=10)\nx._run_ts(['serve', '--bg', '5000'])\n"
    "_run_ts_json(['status'])\ndef _run_ts_json(args):\n    return _run_ts(args + ['--json'])\n"
    "def elsewhere(args):\n    return _run_ts(args + ['--json'])\n",
    "_run(\n    'tailscale set --ssh 2>&1')\n_run(f'tailscale serve {port}')\n"
    "_run('sudo -n tailscale up')\n_run('ip -o link show | grep -i tailscale')\n_run('tailscale status')\n")
check("panel source: (control) a write in a call split over lines, by an attribute, in single quotes, "
      "an f-string or behind sudo is caught, as is `args + ['--json']` outside _run_ts_json, and reads, "
      "a grep for the name and _run_ts_json's own call are not",
      (len(_r25d_planted91[0]), len(_r25d_planted91[1]), len(_r25d_planted91[2])) == (5, 3, 3),
      repr(_r25d_planted91[1:]))
_names91 = [p for p in ("ensure_operator(", "tailscale-set-operator\"", "--operator=%s")
            for src in (_TS_SRC91, _SO_SRC91, _read91("app.py"),
                        _read91("panel", "routes", "tailscale.py"),
                        _read91("panel", "routes", "route_helpers.py")) if p in src]
check("panel source: the panel's own account only READS tailscaled (every _run_ts call and every "
      "`tailscale` shell command in system_ops is a read, but for the operator clearing itself), "
      "and nothing makes it the operator",
      (_ts_writes91, _so_writes91, _names91) == ([], [], []) and len(_ts_calls91) >= 5,
      repr((_ts_writes91, _so_writes91, _names91)))

_saved91 = []


def _p91(owner, name, value):
    _saved91.append((owner, name, getattr(owner, name)))
    setattr(owner, name, value)


def _undo91():
    while _saved91:
        owner, name, value = _saved91.pop()
        setattr(owner, name, value)


_P91 = "http://127.0.0.1:5000"
_OTHER91 = "http://127.0.0.1:3000"


def _info91(routes, unreadable=False):
    return _ts91.TailscaleInfo(
        installed=True, running=True, backend_state="Running", dns_name="h91.tail0.ts.net",
        serve_unreadable=unreadable,
        serve_config={} if unreadable else {"services": [
            {"url": "https://h91.tail0.ts.net", "funnel": False,
             "routes": [{"mount": m, "target": t} for m, t in routes]}]})


_flows91 = {}
_cli91, _verbs91 = [], []
try:
    _p91(_ts91, "_run_ts", lambda args, timeout=5: (_cli91.append(list(args)), ("", "denied", 1))[1])
    _p91(_ts91._so, "_run_verb",
         lambda verb, args=(), **kw: (_verbs91.append((verb, list(args))), ("", "", 0))[1])
    _p91(_ts91, "allow_tailscale_ufw", lambda: (True, ""))
    _p91(_ts91, "get_tailscale_info", lambda force_refresh=False: _info91(
        [("/lgsm", _P91), ("/old", _P91), ("/", _OTHER91)]))
    _flows91["Enable"] = (_ts91.setup_tailscale_serve(5000, mount="/lgsm")[0], list(_verbs91))
    del _verbs91[:]
    _flows91["Remove a leftover"] = (_ts91.remove_stale_panel_routes(5000, "/lgsm")[0], list(_verbs91))
    del _verbs91[:]
    _flows91["Disable"] = (_ts91.disable_tailscale_serve("/lgsm", 5000)[0], list(_verbs91))
    del _verbs91[:]
    _flows91["SSH on"] = (_so91.tailscale_ssh_enable()[0], list(_verbs91))
    del _verbs91[:]
    _flows91["SSH off"] = (_so91.tailscale_ssh_disable()[0], list(_verbs91))
    del _verbs91[:]
    _p91(_ts91._so, "_run_verb",
         lambda verb, args=(), **kw: (_verbs91.append((verb, list(args))), ("ALREADY_CONNECTED", "", 0))[1])
    _flows91["Connect (already joined)"] = (_ts91.tailscale_up_local()[1], list(_verbs91))
finally:
    _undo91()
check("panel flows: Enable, a leftover's removal, Disable, Tailscale SSH on and off and Connect each "
      "go through the helper's verbs, and none makes the panel's account the Tailscale operator",
      _flows91 == {
          "Enable": (True, [("tailscale-serve", ["serve", "modern", "/lgsm", "http", "5000"])]),
          "Remove a leftover": ("removed", [("tailscale-serve-off", ["https", "443", "/old"])]),
          "Disable": (True, [("tailscale-serve-off", ["https", "443", "/lgsm"]),
                             ("tailscale-serve-off", ["https", "443", "/old"])]),
          "SSH on": (True, [("tailscale-ssh", ["on"])]),
          "SSH off": (True, [("tailscale-ssh", ["off"])]),
          "Connect (already joined)": ("ALREADY_CONNECTED", [("tailscale-up-login", ["yes", "-"])])},
      repr(_flows91))
check("panel flows: ...and in all of them the panel's own account wrote nothing to tailscaled",
      [c for c in _cli91 if c[:1] in (["set"], ["up"], ["down"], ["logout"], ["funnel"])
       or (c[:1] == ["serve"] and c[1:2] != ["status"])] == [], repr(_cli91))

# The setup wizard read an unreadable Serve config, made the panel the operator, and read again.
_wiz91 = []
try:
    _p91(_ts91, "get_tailscale_info", lambda force_refresh=False: _info91([], unreadable=True))
    _p91(_ts91._so, "_run_verb",
         lambda verb, args=(), **kw: (_wiz91.append(verb), ("", "", 0))[1])
    _wizr91 = _rh91._wizard_serve_mount({"tailscale_mount": "/"}, 5000)
finally:
    _undo91()
check("setup wizard: an unreadable Serve config is answered as one, and the panel's account is not "
      "made the Tailscale operator to read it again",
      _wizr91[0] is None and "Couldn't read" in str(_wizr91[1]) and _wiz91 == [], repr((_wizr91, _wiz91)))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 5. release_operator, and the boot that calls it
# ════════════════════════════════════════════════════════════════════════════════════════════
def _release91(user, operator, helper=True, verb_answer=("released", "", 0), system=True,
               self_rc=0):
    """(release_operator's answer, the verbs it ran, what it ran as its own account, its warnings)."""
    seen, own, warned = [], [], []
    try:
        _p91(_ts91, "_current_os_user", lambda: user)
        _p91(_ts91, "_read_prefs_json", lambda: None if operator is None else {"OperatorUser": operator})
        _p91(_ts91._so, "_helper_present", lambda: helper)
        _p91(_ts91._so, "_is_system_service", lambda: system)
        _p91(_ts91._so, "_run_verb", lambda verb, args=(), **kw: (seen.append((verb, list(args))),
                                                                  verb_answer)[1])
        _p91(_ts91, "_run_ts", lambda args, timeout=5: (own.append(list(args)), ("", "", self_rc))[1])
        _p91(_ts91._log, "warning", lambda msg, *a, **k: warned.append(msg % a if a else msg))
        return _ts91.release_operator(), seen, own, warned
    finally:
        _undo91()


_STALE91 = ("", "panel-helper: unknown verb 'tailscale-release-operator'", 2)
_rel_panel91 = {
    "the operator": _release91("lgsmpanel", "lgsmpanel"),
    "someone else's": _release91("lgsmpanel", "alice"),
    "no operator": _release91("lgsmpanel", ""),
    "prefs unread": _release91("lgsmpanel", None),
    "root": _release91("root", "root"),
    "no helper": _release91("lgsmpanel", "lgsmpanel", helper=False),
    "helper refused": _release91("lgsmpanel", "lgsmpanel", verb_answer=("", "denied", 1)),
    "stale helper": _release91("lgsmpanel", "lgsmpanel", verb_answer=_STALE91),
    "no helper, set failed": _release91("lgsmpanel", "lgsmpanel", helper=False, self_rc=1)}
_bare91 = {k: v[:3] for k, v in _rel_panel91.items()}
_SELF91 = [["set", "--operator="]]
check("release_operator: the panel takes the operator role back from its own account wherever "
      "that account holds it (one rule with install.sh): through the helper's verb, and with no "
      "helper as the operator clearing itself",
      _bare91 == {
          "the operator": ("released", [("tailscale-release-operator", ["lgsmpanel"])], []),
          "someone else's": ("not-operator", [], []), "no operator": ("not-operator", [], []),
          "prefs unread": ("not-operator", [], []), "root": ("root", [], []),
          "no helper": ("released", [], _SELF91),
          # A refused helper falls back to the self-clear (review 1016b, part93).
          "helper refused": ("released", [("tailscale-release-operator", ["lgsmpanel"])], _SELF91),
          "stale helper": ("released", [("tailscale-release-operator", ["lgsmpanel"])], _SELF91),
          "no helper, set failed": ("failed", [], _SELF91)}, repr(_bare91))
check("release_operator: a helper too old for the verb is logged as such, telling the operator to "
      "re-run install.sh (not as a plain failure), and a refusal is not",
      any("re-run install.sh" in w for w in _rel_panel91["stale helper"][3])
      and not any("re-run install.sh" in w for w in _rel_panel91["helper refused"][3]),
      repr((_rel_panel91["stale helper"][3], _rel_panel91["helper refused"][3])))
_peruser91 = _release91("lgsmpanel", "lgsmpanel", system=False)
check("release_operator: on a per-user install (the panel's account is the owner's own login) a "
      "release logs that their own `tailscale serve`/`set` now need sudo; a system one does not",
      any("per-user install" in w and "need sudo" in w for w in _peruser91[3])
      and not any("per-user install" in w for w in _rel_panel91["the operator"][3]),
      repr((_peruser91[3], _rel_panel91["the operator"][3])))

_boot91 = []
try:
    _p91(_app91.ts, "release_operator", lambda: _boot91.append("release") or "released")
    _p91(_app91.ts, "setup_tailscale_serve", lambda **kw: _boot91.append("serve") or (True, ""))
    _bootapp91 = NS(config={})
    _app91._boot_serve(_bootapp91, {}, 5000)
finally:
    _undo91()
check("boot: every start takes the operator role back (an update run by an older install.sh "
      "switches on the panel's first start), with Serve not set up as well",
      _boot91 == ["release"] and _bootapp91.config.get("BOOT_SERVE") == "not attempted", repr(_boot91))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 6. An older Tailscale's `serve status` is read through the helper, only where there is one
# ════════════════════════════════════════════════════════════════════════════════════════════
def _serve_read91(helper, err="Access denied: serve config denied", running=False):
    seen = []
    try:
        _p91(_ts91, "_run_ts", lambda args, timeout=5: ("", err, 1))
        _p91(_ts91._so, "_helper_present", lambda: helper)
        _p91(_ts91._so, "_run_verb", lambda verb, args=(), **kw: (
            seen.append(verb), ("https://h91.tail0.ts.net (tailnet only)\n|-- /lgsm proxy %s\n" % _P91,
                                "", 0))[1])
        info = _ts91.TailscaleInfo(running=running)
        _ts91._read_serve_status(info)
        return info.serve_unreadable, [r["mount"] for s in info.serve_config.get("services", [])
                                       for r in s["routes"]], seen
    finally:
        _undo91()


_DOWN91 = "failed to connect to local tailscaled; it doesn't appear to be running"
_sr91 = {"helper": _serve_read91(True), "no helper": _serve_read91(False),
         "tailscaled down": _serve_read91(True, _DOWN91),
         "running, other error": _serve_read91(True, _DOWN91, running=True)}
check("serve status: refused to the panel's account (an older Tailscale), it is read through the "
      "helper's read verb; with no helper it stays unread and no privileged read is tried",
      _sr91["helper"] == (False, ["/lgsm"], ["tailscale-serve-status"])
      and _sr91["no helper"] == (True, [], []), repr(_sr91))
check("serve status: ...but a read that failed for another reason with tailscaled not up (stopped "
      "or hung, which root cannot read either) tries no sudo; with tailscaled up it still does",
      _sr91["tailscaled down"] == (True, [], [])
      and _sr91["running, other error"] == (False, ["/lgsm"], ["tailscale-serve-status"]),
      repr(_sr91))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 7. install.sh takes the role back on a fresh install and on every update
# ════════════════════════════════════════════════════════════════════════════════════════════
_INS91 = _read91("install.sh")


def _fn91(src, name):
    """The text of shell function `name` in `src`, from its `name() {` line to its closing `}`."""
    i = src.find("\n%s() {" % name)
    if i < 0:
        return "%s() { exit 97; }\n" % name
    return src[i + 1:src.index("\n}\n", i) + 3]


def _stand91(d, prefs_json):
    """A stand-in `tailscale` in `d`: `debug prefs` answers `prefs_json`, every call is logged."""
    log = os.path.join(d, "calls")
    stand = os.path.join(d, "tailscale")
    with open(stand, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\necho \"$*\" >> '%s'\n"
                 "if [ \"$1 $2\" = \"debug prefs\" ]; then printf '%%s' '%s'; fi\nexit 0\n"
                 % (log, prefs_json))
    os.chmod(stand, 0o700)  # nosemgrep: insecure-file-permissions - a stand-in this part runs
    return log


def _install_release91(operator, panel_user="lgsmpanel", as_root=1, out=None):
    d = _tf91.mkdtemp(dir=_TMP91)
    log = _stand91(d, _json91.dumps({"OperatorUser": operator, "RunSSH": False}))
    script = ("set -euo pipefail\nok() { echo \"OK $*\"; }\nwarn() { echo \"WARN $*\"; }\n"
              "PANEL_USER=%s\nRUN_AS_ROOT=%d\n%s\nrelease_tailscale_operator\necho REACHED\n"
              % (panel_user, as_root, _fn91(_INS91, "release_tailscale_operator")))
    env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
    r = _sp91.run(["bash", "-c", script], cwd=d, capture_output=True, text=True,  # nosec B603 B607
                  timeout=60, env=env)
    calls = open(log, encoding="utf-8").read().split("\n") if os.path.exists(log) else []
    if out is not None:
        out.append(r.stdout)
    return r.returncode, "REACHED" in r.stdout, [c for c in calls if c.startswith("set")]


_ins_rel91 = {"the panel's account": _install_release91("lgsmpanel"),
              "someone else's": _install_release91("alice"),
              "no operator": _install_release91("")}
check("install.sh: release_tailscale_operator clears the operator (`tailscale set --operator=`) when "
      "it is the panel's account, leaves anyone else's, and never stops the install",
      _ins_rel91 == {"the panel's account": (0, True, ["set --operator="]),
                     "someone else's": (0, True, []), "no operator": (0, True, [])},
      repr(_ins_rel91))
_insout91 = {"per-user": [], "system": [], "per-user, not ours": []}
_install_release91("lgsmpanel", as_root=0, out=_insout91["per-user"])
_install_release91("lgsmpanel", as_root=1, out=_insout91["system"])
_install_release91("alice", as_root=0, out=_insout91["per-user, not ours"])
check("install.sh: on a per-user install (the panel's account is the owner's own login) taking the "
      "operator role back says, then, that their own `tailscale serve`/`set` now need sudo; a "
      "system install, and a release that did not happen, say nothing of it",
      "WARN This is a per-user install" in _insout91["per-user"][0]
      and "need sudo" in _insout91["per-user"][0]
      and "per-user install" not in _insout91["system"][0]
      and "per-user install" not in _insout91["per-user, not ours"][0], repr(_insout91))


def _calls_after91(src, anchor):
    """Whether release_tailscale_operator runs within the six lines after `anchor` in `src`."""
    i = src.find(anchor)
    return i >= 0 and "release_tailscale_operator" in "\n".join(src[i:].split("\n")[:6])


_sites91 = {
    "update, code already current": _calls_after91(
        _INS91, '        [[ "${ORIGIN_TRUSTED}" -eq 1 ]] && write_sudoers_grant\n        write_terminal'),
    "update, new code": _calls_after91(
        _INS91, '    [[ "${ORIGIN_TRUSTED}" -eq 1 ]] && write_sudoers_grant\n    write_terminal'),
    "fresh install (both kinds)": _calls_after91(_INS91, "install_recovery_command\nfi\n")}
check("install.sh: the release runs on a fresh install and in both update branches (install/update "
      "parity: an existing host switches on its next update)", all(_sites91.values()), repr(_sites91))


# ════════════════════════════════════════════════════════════════════════════════════════════
# 8. A per-user uninstall removes the panel's Serve route with sudo
# ════════════════════════════════════════════════════════════════════════════════════════════
def _uninstall_off91(u_sudo):
    """The `off` lines a stand-in sudo saw from uninstall.sh's _ts_remove_routes, and the rc."""
    d = _tf91.mkdtemp(dir=_TMP91)
    _stand91(d, "{}")
    sudo_log = os.path.join(d, "sudo-calls")
    sudo = os.path.join(d, "fakesudo")
    with open(sudo, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\necho \"$*\" >> '%s'\nexec \"$@\"\n" % sudo_log)
    os.chmod(sudo, 0o700)  # nosemgrep: insecure-file-permissions - a stand-in this part runs
    un = _read91("uninstall.sh")
    fn = _fn91(un, "_ts_remove_routes")
    # _ts_panel_routes re-reads Serve before each `off`: answer with the route still there.
    script = ("set -euo pipefail\nok() { echo \"OK $*\"; }\nwarn() { echo \"WARN $*\"; }\n"
              "sudo_note() { :; }\nPANEL_PORT=5000\nU_SUDO=%s\n"
              "_ts_panel_routes() { echo '--https=443 /lgsm 0'; }\n%s\n"
              "_ts_remove_routes '--https=443 /lgsm 0'\n" % (u_sudo, fn))
    env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
    r = _sp91.run(["bash", "-c", script], cwd=d, capture_output=True, text=True,  # nosec B603 B607
                  timeout=60, env=env)
    seen = open(sudo_log, encoding="utf-8").read().split("\n") if os.path.exists(sudo_log) else []
    return r.returncode, [s for s in seen if s.endswith(" off")]


_un91 = {"per-user": _uninstall_off91(os.path.join("$PWD", "fakesudo")), "system": _uninstall_off91("")}
check("uninstall.sh: a per-user uninstall runs the Serve route's `off` under sudo (the panel's "
      "account is no longer the operator), and a system one (already root) without",
      _un91 == {"per-user": (0, ["timeout 15 tailscale serve --https=443 --set-path=/lgsm off"]),
                "system": (0, [])}, repr(_un91))


def _uninstall_read91(u_sudo):
    """(rc, stdout) of uninstall.sh's _ts_panel_routes when the plain read is refused, root's not."""
    d = _tf91.mkdtemp(dir=_TMP91)
    js = _json91.dumps({"TCP": {"443": {"HTTPS": True}}, "Web": {"h91.ts.net:443": {"Handlers": {
        "/lgsm": {"Proxy": "http://127.0.0.1:5000"}}}}})
    with open(os.path.join(d, "tailscale"), "w", encoding="utf-8") as fh:
        # Refused unless run through the stand-in sudo: an older Tailscale, answering root only.
        fh.write("#!/bin/sh\n[ -n \"$P91_ROOT\" ] || { echo 'Access denied' >&2; exit 1; }\n"
                 "printf '%%s' '%s'\n" % js)
    with open(os.path.join(d, "fakesudo"), "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\nP91_ROOT=1 exec \"$@\"\n")
    for name in ("tailscale", "fakesudo"):
        os.chmod(os.path.join(d, name), 0o700)  # nosemgrep: insecure-file-permissions - stand-ins
    un = _read91("uninstall.sh")
    script = ("set -euo pipefail\nsudo_note() { :; }\nU_SUDO=%s\n%s\n%s\n"
              "_ts_panel_routes 5000 routes\n"
              % (u_sudo, un[un.index("_TS_ROUTES_PY='"):un.index("\n'\n", un.index("_TS_ROUTES_PY='")) + 2],
                 _fn91(un, "_ts_panel_routes")))
    env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
    r = _sp91.run(["bash", "-c", script], cwd=d, capture_output=True, text=True,  # nosec B603 B607
                  timeout=60, env=env)
    return r.returncode, r.stdout.strip()


_unr91 = {"per-user": _uninstall_read91(os.path.join("$PWD", "fakesudo")), "system": _uninstall_read91("")}
check("uninstall.sh: a per-user uninstall whose plain `serve status` read is refused (an older "
      "Tailscale, the panel's account no longer the operator) reads it under sudo and finds the "
      "panel's route; a system one (already root) has no second read to make",
      _unr91 == {"per-user": (0, "--https=443 /lgsm 0"), "system": (1, "")}, repr(_unr91))


_tsenv91 = []
try:
    _p91(_ts91, "subprocess", NS(run=lambda argv, **kw: (
        _tsenv91.append(kw.get("env") or {}), NS(stdout="", stderr="", returncode=0))[1]))
    _ts91._run_ts(["serve", "status"])
finally:
    _undo91()
check("serve status: the panel's tailscale reads run in the C locale (the refusal is recognised by "
      "its words, \"Access denied\")",
      [(e.get("LC_ALL"), e.get("LANGUAGE")) for e in _tsenv91] == [("C.UTF-8", "")], repr(
          [(e.get("LC_ALL"), e.get("LANGUAGE")) for e in _tsenv91]))
