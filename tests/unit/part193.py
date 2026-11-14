"""Part 193 of the unit suite: name lookups without dnspython.

Held here:
* Every entry point that can import eventlet sets EVENTLET_NO_GREENDNS=yes first, or imports the
  panel package (whose __init__ sets it) before eventlet: eventlet reads it once, at its first
  import, and with it unset loads greendns, which needs dnspython, which the panel does not install.
  A source gate over the repository's scripts, harnesses and tools, with controls.
* app.py's own preamble, run in a fresh interpreter with the variable unset and `import dns`
  refused: it imports eventlet with greendns off and leaves the four lookups routed; panel/__init__
  alone does the same for a tool that imports a panel module first.
* panel/core/green_dns, as app.py installed it in this process: a lookup whose resolver blocks for a
  second (a real sleep) runs on a worker thread while another greenlet keeps ticking; results and
  socket.gaierror come back unchanged; green create_connection uses it; a lookup from a tpool worker,
  from another native thread and from the hub greenlet itself runs inline instead of deadlocking.
* install.sh's install_deps (cut out and run under bash with a recording pip): a lockfile that
  leaves dnspython out is installed --no-deps, dnspython is uninstalled from the venv (an update's
  venv had it), and pip check may report only eventlet's dnspython requirement; anything else fails,
  named. An older lockfile (a pinned update, the rollback) installs as before. All of it as the
  panel user on a root run.
* CI: every workflow step installing panel/install/requirements.txt does it --no-deps and then runs
  .github/scripts/panel_pip_check.sh, which runs install.sh's own check and refuses an importable
  dnspython; the fuzz image installs --no-deps and bundles no dns.

HOW IT RUNS. In the suite's own (monkey-patched) process for the resolver, with
eventlet.patcher.original("socket")'s functions stubbed and restored in a finally; subprocesses for
the preamble and the shell. Nothing resolves a real name or reaches the network.
"""
import os as _os193
import re as _re193
import subprocess as _sp193  # nosec B404 - python and bash over the repo's own files, fixed argv
import sys as _sys193
import tempfile as _tf193
import shutil as _sh193

from unit.part01 import check
from unit import REPO_ROOT as _root

import eventlet as _ev193
from eventlet import hubs as _hubs193, patcher as _patcher193, tpool as _tpool193
from eventlet.green import socket as _gsock193
import socket as _sock193

from panel.core import green_dns as _gd193

_ENV_RX193 = _re193.compile(r"""^os\.environ\[["']EVENTLET_NO_GREENDNS["']\]\s*=\s*["']yes["']""", _re193.M)
_EVENTLET_RX193 = _re193.compile(r"""^\s*(?:import|from)\s+eventlet\b|["']eventlet[."']""")
_PANEL_RX193 = _re193.compile(r"""^(?:import|from)\s+(?:panel|app)\b""")
_TMP193 = _tf193.mkdtemp(prefix="lgsm-unit-p193-")


def _read193(*parts):
    with open(_os193.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ── 1. the source gate ──────────────────────────────────────────────────────────────────────────
def _first_eventlet_unguarded(text):
    """The first line importing eventlet with neither the variable set nor a panel import above it.

    None when the file is safe: no eventlet at all, the variable set first, or a panel/app import
    first (panel/__init__.py and app.py set it themselves). Only an unindented assignment or import
    counts as first: one inside a function runs when it is called, which may be after a function
    defined below it (tools/nosudo_runner.py imports eventlet in _greenify_first, called before
    _install, whose panel import sits higher in the file).
    """
    for ln in text.splitlines():
        code = ln.split("#", 1)[0]
        if not code.strip():
            continue
        if _ENV_RX193.match(code):
            return None
        if _PANEL_RX193.search(code):
            return None
        if _EVENTLET_RX193.search(code):
            return ln.strip()
    return None


_ENTRY_RX193 = _re193.compile(r"^(?:tools/|panel/install/|tests/fuzz/fuzz_|tests/[^/]+_test\.py$)")


def _entry_point193(rel, text):
    """True for a file that starts a process: a script, a harness, a fuzz target, a tool."""
    # The panel package's modules are imported, never run, and panel/__init__ covers them. The
    # suites' parts run inside their harness (tests/*_test.py, checked here), which imports the
    # panel package before it loads any of them.
    if rel.startswith(("tests/unit/", "tests/smoke/")) or (rel.startswith("panel/") and not rel.startswith("panel/install/")):
        return False
    return bool(text.startswith("#!") or _re193.search(r"__name__ == [\"']__main__[\"']", text)
                or _ENTRY_RX193.match(rel))


_SKIP_DIRS193 = {".git", ".claude", "node_modules", "venv", ".venv", "data", "__pycache__"}
_seen193, _bad193 = [], []
for _dp, _dns, _fns in _os193.walk(_root):
    _dns[:] = [d for d in _dns if d not in _SKIP_DIRS193 and not d.startswith(".venv")]
    for _fn in _fns:
        _rel = _os193.path.relpath(_os193.path.join(_dp, _fn), _root).replace(_os193.sep, "/")
        if not (_fn.endswith(".py") or _rel == "tools/panel-helper"):
            continue
        try:
            with open(_os193.path.join(_dp, _fn), encoding="utf-8") as _fh:
                _txt = _fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        if not _entry_point193(_rel, _txt):
            continue
        _seen193.append(_rel)
        _hit = _first_eventlet_unguarded(_txt)
        if _hit:
            _bad193.append("%s: %s" % (_rel, _hit))
check("greendns off: every entry point sets EVENTLET_NO_GREENDNS=yes, or imports the panel package, "
      "before its first eventlet import (a string in an import_module list included)",
      not _bad193 and len(_seen193) >= 20 and "panel/install/app.py" in _seen193
      and "tools/perf_bench.py" in _seen193 and "tests/fuzz/fuzz_cron.py" in _seen193,
      "%d read; %r" % (len(_seen193), _bad193))
check("greendns off: ...and the gate names eventlet imported first, plainly or by string, and passes the "
      "variable set first or a panel import first (control)",
      _first_eventlet_unguarded("import os\nimport eventlet\n") == "import eventlet"
      and _first_eventlet_unguarded('for d in ("paramiko", "eventlet.tpool"):\n    pass\n') is not None
      and _first_eventlet_unguarded('os.environ["EVENTLET_NO_GREENDNS"] = "yes"\nimport eventlet\n') is None
      and _first_eventlet_unguarded("from panel.core import config\nimport eventlet\n") is None
      and _first_eventlet_unguarded("# import eventlet\nx = 1\n") is None
      and _first_eventlet_unguarded("def a():\n    from panel.ops import x\ndef b():\n    import eventlet\n")
      == "import eventlet")
_init193 = _read193("panel", "__init__.py")
check("greendns off: panel/__init__.py sets the variable at import, before anything else of the panel runs",
      _ENV_RX193.search(_init193) is not None)
_app193 = _read193("panel", "install", "app.py")
check("greendns off: app.py sets it before `import eventlet` and installs green_dns straight after the "
      "patch",
      _ENV_RX193.search(_app193) is not None
      and _ENV_RX193.search(_app193).start() < _app193.index("    import eventlet\n")
      and _app193.index("eventlet.monkey_patch()") < _app193.index("\ngreen_dns.install()"))

# ── 2. app.py's preamble and panel/__init__ in a fresh interpreter, with dns refused ─────────────
_BLOCK_DNS193 = r'''
import sys, os
os.environ.pop("EVENTLET_NO_GREENDNS", None)
class _NoDns:
    def find_spec(self, name, path=None, target=None):
        if name == "dns" or name.startswith("dns."):
            raise ImportError("dnspython is not installed (part193)")
        return None
sys.meta_path.insert(0, _NoDns())
'''
_PROBE193 = _BLOCK_DNS193 + r'''
import warnings
warnings.simplefilter("ignore")
path = sys.argv[1]
src = open(path, encoding="utf-8").read()
# app.py up to and including its green_dns.install() line: the patch and what follows it at once.
src = src[:src.index("\n", src.index("\ngreen_dns.install()") + 1) + 1]
exec(compile(src, path, "exec"), {"__file__": path, "__name__": "lgsm_p193_app_head"})
import socket
from eventlet.green import socket as gs
print("ROUTED" if getattr(socket.getaddrinfo, "lgsm_green_dns", False)
      and getattr(gs.getaddrinfo, "lgsm_green_dns", False) else "NOT-ROUTED")
print("GREENDNS" if "eventlet.support.greendns" in sys.modules else "NO-GREENDNS")
'''
_INIT_PROBE193 = _BLOCK_DNS193 + r'''
sys.path.insert(0, sys.argv[1])
import panel.core.clock
import eventlet
print("NO-GREENDNS" if "eventlet.support.greendns" not in sys.modules else "GREENDNS")
'''
_env193 = {k: v for k, v in _os193.environ.items() if k != "EVENTLET_NO_GREENDNS"}
# Compiled under app.py's own path, so its sys.path arithmetic (three dirnames up) finds this checkout.
_r193 = _sp193.run([_sys193.executable, "-c", _PROBE193, _os193.path.join(_root, "panel", "install", "app.py")],  # nosec B603
                   capture_output=True, text=True, timeout=120, env=_env193, cwd=_TMP193, stdin=_sp193.DEVNULL)
check("app.py preamble, fresh interpreter, variable unset, `import dns` refused: eventlet imports with "
      "greendns off and the lookups are routed through green_dns",
      _r193.returncode == 0 and _r193.stdout.split() == ["ROUTED", "NO-GREENDNS"],
      "rc=%r out=%r err=%r" % (_r193.returncode, _r193.stdout, _r193.stderr[-600:]))
_ri193 = _sp193.run([_sys193.executable, "-c", _INIT_PROBE193, _root], capture_output=True, text=True,  # nosec B603
                    timeout=120, env=_env193, cwd=_TMP193, stdin=_sp193.DEVNULL)
check("panel/__init__: a tool importing a panel module before eventlet gets greendns off too (dns refused)",
      _ri193.returncode == 0 and _ri193.stdout.split() == ["NO-GREENDNS"],
      "rc=%r out=%r err=%r" % (_ri193.returncode, _ri193.stdout, _ri193.stderr[-600:]))
_rc193 = _sp193.run([_sys193.executable, "-c", _BLOCK_DNS193 + "import eventlet\n"], capture_output=True,  # nosec B603
                    text=True, timeout=120, env=_env193, cwd=_TMP193, stdin=_sp193.DEVNULL)
check("greendns off: ...without the variable, eventlet itself fails to import once dns is refused, which "
      "is what the two above would do with it missing (control)",
      _rc193.returncode != 0 and "dnspython is not installed (part193)" in _rc193.stderr,
      "rc=%r err=%r" % (_rc193.returncode, _rc193.stderr[-300:]))

# ── 3. the resolver, as app.py installed it in this process ─────────────────────────────────────
_real193 = _patcher193.original("socket")
_rthreading193 = _patcher193.original("threading")
_rtime193 = _patcher193.original("time")
_saved193 = {n: getattr(_real193, n) for n in _gd193.NAMES}
_calls193 = []


def _slow193(host, port, *args, **kwargs):
    _calls193.append(("slow", _rthreading193.get_ident()))
    _rtime193.sleep(1.0)
    return [("p193", host, port)]


def _fails193(host, *args, **kwargs):
    _calls193.append(("fail", _rthreading193.get_ident()))
    raise _sock193.gaierror(-2, "Name or service not known (part193 %s)" % host)


def _quick193(host, port, *args, **kwargs):
    _calls193.append(("quick", _rthreading193.get_ident()))
    return [("quick", host, port)]


_main_ident193 = _rthreading193.get_ident()
check("green_dns: app.py installed it here: socket's and eventlet.green.socket's four lookups are routed",
      all(getattr(getattr(_m, _n), "lgsm_green_dns", False) for _m in (_sock193, _gsock193)
          for _n in _gd193.NAMES) and _gd193.install() is True)
try:
    _real193.getaddrinfo = _slow193
    _ticks193 = []

    def _ticker193():
        for _ in range(40):
            _ticks193.append(1)
            _ev193.sleep(0.02)

    _tk193 = _ev193.spawn(_ticker193)
    _res193 = None
    with _ev193.Timeout(10, False):
        _res193 = _ev193.spawn(_sock193.getaddrinfo, "stub.invalid", 443).wait()
    _tk193.kill()
    _slow_threads193 = [t for k, t in _calls193 if k == "slow"]
    check("green_dns: a lookup that blocks for a second runs on a worker thread while another greenlet "
          "keeps ticking, and its result comes back unchanged",
          _res193 == [("p193", "stub.invalid", 443)] and len(_ticks193) >= 20
          and _slow_threads193 and _slow_threads193[0] != _main_ident193,
          "ticks=%d result=%r threads=%r main=%r" % (len(_ticks193), _res193, _slow_threads193, _main_ident193))

    _real193.getaddrinfo = _fails193
    _err193 = None
    try:
        _sock193.getaddrinfo("nx.invalid", 80)
    except _sock193.gaierror as _e:
        _err193 = _e
    check("green_dns: ...and socket.gaierror comes back as the resolver raised it",
          _err193 is not None and _err193.errno == -2 and "part193 nx.invalid" in str(_err193), repr(_err193))
    _cc_err193 = None
    try:
        _sock193.create_connection(("cc.invalid", 80), timeout=2)
    except _sock193.gaierror as _e:
        _cc_err193 = _e
    check("green_dns: ...green create_connection (what http.client, urllib3 and smtplib call) resolves "
          "through it too", _cc_err193 is not None and "part193 cc.invalid" in str(_cc_err193)
          and _calls193[-1][0] == "fail" and _calls193[-1][1] != _main_ident193, repr((_cc_err193, _calls193[-1:])))

    _real193.getaddrinfo = _quick193
    del _calls193[:]

    def _nested193():
        return _rthreading193.get_ident(), _sock193.getaddrinfo("nested.invalid", 1)

    _nest193 = None
    with _ev193.Timeout(10, False):
        _nest193 = _tpool193.execute(_nested193)
    check("green_dns: a lookup made ON a tpool worker runs inline there (no second hop, no deadlock)",
          bool(_nest193) and _nest193[1] == [("quick", "nested.invalid", 1)]
          and _calls193 == [("quick", _nest193[0])], repr((_nest193, _calls193)))

    del _calls193[:]
    _native_out193 = []

    def _native193():
        _native_out193.append((_rthreading193.get_ident(), _sock193.getaddrinfo("native.invalid", 2)))

    _nt193 = _rthreading193.Thread(target=_native193, daemon=True)
    _nt193.start()
    _nt193.join(10)
    check("green_dns: ...and one from another native thread (no hub there to wake) runs inline too",
          len(_native_out193) == 1 and _native_out193[0][1] == [("quick", "native.invalid", 2)]
          and _calls193 == [("quick", _native_out193[0][0])], repr((_native_out193, _calls193)))

    del _calls193[:]
    _hub_out193 = []

    def _on_hub193():
        try:
            _hub_out193.append(_sock193.getaddrinfo("hub.invalid", 3))
        except BaseException as _e:  # noqa: B036 - recorded and reported by the check below
            _hub_out193.append(repr(_e))

    _hubs193.get_hub().schedule_call_global(0, _on_hub193)
    for _ in range(50):
        if _hub_out193:
            break
        _ev193.sleep(0.02)
    check("green_dns: ...and one from the hub greenlet itself (a timer callback) runs inline rather than "
          "waiting on a reply only the hub could deliver",
          _hub_out193 == [[("quick", "hub.invalid", 3)]] and _calls193 == [("quick", _main_ident193)],
          repr((_hub_out193, _calls193)))
finally:
    for _n193, _f193 in _saved193.items():
        setattr(_real193, _n193, _f193)

# ── 4. install.sh: install_deps and _pip_check_deps under bash with a recording pip ─────────────
_INS193 = _read193("install.sh")


def _fn193(src, name):
    """The text of shell function `name` in `src`, from its `name() {` line to its closing `}`."""
    i = src.find("\n%s() {" % name)
    if i < 0:
        return "%s() { exit 97; }\n" % name
    return src[i + 1:src.index("\n}\n", i) + 3]


_STUBS193 = r"""
id() { if [ "$#" -eq 1 ] && [ "$1" = -u ]; then echo 0; else command id "$@"; fi; }
_r42i_tree_owner() { echo lgsmpanel; }
_venv_stale() { return 1; }
panel_file() { echo "${PANEL_DIR}/$1"; }
sudo() { echo "AS $2" >> "$P193_LOG"; shift 2; "$@"; }
python3() { return 0; }
ok() { :; }; info() { :; }; warn() { echo "WARN $*" >> "$P193_LOG"; }; die() { exit 9; }
"""
_PIP193 = r"""#!/bin/sh
echo "PIP $*" >> "$P193_LOG"
case "$1" in
  check) [ -n "${P193_CHECK:-}" ] && printf '%s\n' "$P193_CHECK"; exit "${P193_CHECK_RC:-0}" ;;
  uninstall) exit "${P193_UNINSTALL_RC:-0}" ;;
esac
exit 0
"""
_TOLERATED193 = "eventlet 0.41.3 requires dnspython, which is not installed."


def _deps193(tag, req_text, **extra):
    """Run install_deps over a throwaway PANEL_DIR; (rc, log lines, stderr)."""
    pd = _os193.path.join(_TMP193, tag)
    _os193.makedirs(_os193.path.join(pd, "venv", "bin"))
    log = _os193.path.join(_TMP193, tag + ".log")
    with open(_os193.path.join(pd, "requirements.txt"), "w", encoding="utf-8") as fh:
        fh.write(req_text)
    pip = _os193.path.join(pd, "venv", "bin", "pip")
    with open(pip, "w", encoding="utf-8") as fh:
        fh.write(_PIP193)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
    _os193.chmod(pip, 0o700)  # nosec B103
    env = dict(_os193.environ, PANEL_DIR=pd, PANEL_USER="lgsmpanel", P193_LOG=log, **extra)
    script = ("set -euo pipefail\n" + _STUBS193 + _fn193(_INS193, "install_deps")
              + _fn193(_INS193, "_pip_check_deps") + "install_deps\n")
    r = _sp193.run(["bash", "-c", script], capture_output=True, text=True, timeout=60, env=env,  # nosec B603 B607
                   cwd=_TMP193, stdin=_sp193.DEVNULL)
    try:
        with open(log, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        lines = []
    return r.returncode, [ln.replace(pd, "PD") for ln in lines], r.stderr


_NEW193 = ("#    pip-compile --generate-hashes --no-annotate --output-file=requirements.txt --strip-extras "
           "--unsafe-package=dnspython requirements.in\nflask==3.1.3 \\\n    --hash=sha256:aa\n")
_OLD193 = "dnspython==2.8.0 \\\n    --hash=sha256:bb\nflask==3.1.3 \\\n    --hash=sha256:aa\n"
_rc, _log, _err = _deps193("new", _NEW193, P193_CHECK=_TOLERATED193, P193_CHECK_RC="1")
_pips193 = [ln for ln in _log if ln.startswith("PIP ")]
check("install.sh install_deps: a lockfile leaving dnspython out installs --no-deps, uninstalls dnspython "
      "from the venv, and passes pip check reporting only eventlet's dnspython requirement",
      _rc == 0 and _pips193 == ["PIP install --quiet --no-deps -r PD/requirements.txt",
                                "PIP uninstall --quiet --yes dnspython", "PIP check"],
      "rc=%r log=%r err=%r" % (_rc, _log, _err[-300:]))
check("install.sh install_deps: ...each pip run as the panel user on a root run (the venv is theirs)",
      _rc == 0 and [ln for ln in _log if ln.startswith("AS ")] == ["AS lgsmpanel"] * 4, repr(_log))
_rc, _log, _err = _deps193("clean", _NEW193, P193_CHECK="No broken requirements found.")
check("install.sh install_deps: ...and passes a pip check with nothing to report",
      _rc == 0 and "PIP check" in _log, "rc=%r log=%r" % (_rc, _log))
_rc, _log, _err = _deps193("broken", _NEW193, P193_CHECK=_TOLERATED193 + "\nflask 3.1.3 requires werkzeug, "
                           "which is not installed.", P193_CHECK_RC="1")
check("install.sh install_deps: ...any other pip check report fails it, named on stderr",
      _rc != 0 and "flask 3.1.3 requires werkzeug, which is not installed." in _err
      and "eventlet 0.41.3" not in _err, "rc=%r err=%r" % (_rc, _err[-300:]))
_rc, _log, _err = _deps193("dnsother", _NEW193, P193_CHECK="flask 3.1.3 requires dnspython, which is not "
                           "installed.", P193_CHECK_RC="1")
check("install.sh install_deps: ...including dnspython wanted by anything but eventlet",
      _rc != 0 and "flask 3.1.3 requires dnspython" in _err, "rc=%r err=%r" % (_rc, _err[-300:]))
_rc, _log, _err = _deps193("unin", _NEW193, P193_UNINSTALL_RC="1")
check("install.sh install_deps: ...a failed uninstall is a warning, not a failed install",
      _rc == 0 and any(ln.startswith("WARN Could not remove dnspython") for ln in _log)
      and "PIP check" in _log, "rc=%r log=%r" % (_rc, _log))
_rc, _log, _err = _deps193("old", _OLD193)
check("install.sh install_deps: an older lockfile (a pinned update, the rollback) installs as before: "
      "with its dependencies, no uninstall and no check, since its app.py still needs greendns",
      _rc == 0 and [ln for ln in _log if ln.startswith("PIP ")] == ["PIP install --quiet -r PD/requirements.txt"],
      "rc=%r log=%r" % (_rc, _log))
_real_req193 = _read193("panel", "install", "requirements.txt")
check("install.sh install_deps: ...and the real lockfile takes the new path",
      "--unsafe-package=dnspython" in "\n".join(_l for _l in _real_req193.splitlines() if _l.startswith("#")))

# ── 5. CI: --no-deps everywhere requirements.txt is installed, then install.sh's check ───────────
_wf_dir193 = _os193.path.join(_root, ".github", "workflows")
_wf_bad193, _wf_hits193 = [], 0
for _wf in sorted(_os193.listdir(_wf_dir193)):
    if not _wf.endswith((".yml", ".yaml")):
        continue
    _wtxt = _read193(".github", "workflows", _wf)
    _wl = _wtxt.splitlines()
    for _i, _ln in enumerate(_wl):
        _code = _ln.split("#", 1)[0]
        if "pip install" not in _code or "-r panel/install/requirements.txt" not in _code:
            continue
        _wf_hits193 += 1
        if "--no-deps" not in _code:
            _wf_bad193.append("%s:%d installs requirements.txt without --no-deps" % (_wf, _i + 1))
        # The rest of this job: up to the next job key (two spaces in) or the end of the file.
        _rest = []
        for _l2 in _wl[_i + 1:]:
            if _re193.match(r"  [A-Za-z0-9_-]+:\s*$", _l2):
                break
            _rest.append(_l2.split("#", 1)[0].strip())
        if "run: bash .github/scripts/panel_pip_check.sh" not in _rest:
            _wf_bad193.append("%s:%d: no later step of its job runs panel_pip_check.sh" % (_wf, _i + 1))
check("CI: every step installing panel/install/requirements.txt does it --no-deps, and a later step of "
      "the same job runs panel_pip_check.sh", _wf_hits193 >= 5 and not _wf_bad193,
      "%d found; %r" % (_wf_hits193, _wf_bad193))
_df193 = _read193(".clusterfuzzlite", "Dockerfile")
_bs193 = _read193(".clusterfuzzlite", "build.sh")
check("fuzz image: installs requirements.txt --no-deps and bundles no dns",
      _re193.search(r"(?m)^RUN pip3 install [^\n]*--no-deps [^\n]*requirements\.txt", _df193) is not None
      and "--collect-submodules dns" not in _bs193)

# panel_pip_check.sh with a stand-in python: pip check's output and whether `import dns` works.
_PY193 = r"""#!/bin/sh
if [ "$1" = -m ] && [ "$2" = pip ] && [ "$3" = check ]; then
  [ -n "${P193_CHECK:-}" ] && printf '%s\n' "$P193_CHECK"; exit "${P193_CHECK_RC:-0}"
fi
if [ "$1" = -c ]; then exit "${P193_DNS_RC:-1}"; fi
exit 3
"""
_py193 = _os193.path.join(_TMP193, "python193")
with open(_py193, "w", encoding="utf-8") as _fh193:
    _fh193.write(_PY193)
# nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
_os193.chmod(_py193, 0o700)  # nosec B103


def _ppc193(root=_root, **extra):
    env = dict(_os193.environ, PYTHON=_py193, **extra)
    r = _sp193.run(["bash", _os193.path.join(root, ".github", "scripts", "panel_pip_check.sh")],  # nosec B603 B607
                   capture_output=True, text=True, timeout=60, env=env, cwd=_TMP193, stdin=_sp193.DEVNULL)
    return r.returncode, r.stdout + r.stderr


_rc, _out = _ppc193(P193_CHECK=_TOLERATED193, P193_CHECK_RC="1")
check("panel_pip_check.sh: install.sh's check passes eventlet's dnspython line, with dnspython absent",
      _rc == 0 and "dnspython is not installed" in _out, "rc=%r %s" % (_rc, _out[-300:]))
_rc, _out = _ppc193(P193_CHECK="paramiko 4.0.0 requires bcrypt, which is not installed.", P193_CHECK_RC="1")
check("panel_pip_check.sh: ...fails on any other report, named", _rc != 0
      and "paramiko 4.0.0 requires bcrypt" in _out and "::error::" in _out, "rc=%r %s" % (_rc, _out[-300:]))
_rc, _out = _ppc193(P193_CHECK=_TOLERATED193, P193_CHECK_RC="1", P193_DNS_RC="0")
check("panel_pip_check.sh: ...and fails when dnspython is importable", _rc != 0
      and "dnspython is installed" in _out, "rc=%r %s" % (_rc, _out[-300:]))
_fake193 = _os193.path.join(_TMP193, "fakeroot")
_os193.makedirs(_os193.path.join(_fake193, ".github", "scripts"))
_sh193.copy(_os193.path.join(_root, ".github", "scripts", "panel_pip_check.sh"),
            _os193.path.join(_fake193, ".github", "scripts", "panel_pip_check.sh"))
with open(_os193.path.join(_fake193, "install.sh"), "w", encoding="utf-8") as _fh193:
    _fh193.write("#!/bin/bash\n_other() {\n    :\n}\n")
_rc, _out = _ppc193(root=_fake193)
check("panel_pip_check.sh: ...and fails, saying so, when install.sh no longer has the function it runs",
      _rc != 0 and "install.sh has no _pip_check_deps" in _out, "rc=%r %s" % (_rc, _out[-300:]))
_sh193.rmtree(_TMP193, ignore_errors=True)
