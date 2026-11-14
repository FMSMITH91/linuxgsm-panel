"""Part 196 of the unit suite: the packages requirements.txt leaves out, and the panel without them.

Held here:
* install.sh's _lock_left_out: the names a lockfile's header leaves out (--unsafe-package), read
  from comment lines only and only in the characters a package name has; on the real lockfile, the
  six requirements.in explains (dnspython, h11, invoke, pycparser, simple-websocket, wsproto).
* install.sh's install_deps (cut out and run under bash with a recording pip): every name the
  lockfile leaves out is uninstalled from the venv in one pip run, as the panel user.
* install.sh's _pip_check_deps: the reports it lets through are exactly the requirements the
  pinned packages' own metadata makes on what the lockfile leaves out (read from the installed
  metadata, so a new one, or a tolerance nothing needs any more, is named), and the same package
  wanted by any other requirer fails.
* .github/scripts/panel_pip_check.sh, run with a stand-in pip and this interpreter: it reads the
  names from the lockfile's header and fails, naming it, when one is installed; it passes when none
  is, and fails when the header leaves nothing out.
* The panel without them: app.py run by path in a fresh interpreter, with the five (and dns)
  refused at import, serves /healthz with Socket.IO in eventlet mode, and paramiko there completes
  an SSH session (ed25519 host key, key exchange, publickey login, a command) over a socket pair.

HOW IT RUNS. The shell functions are cut out of install.sh and run under bash with stand-ins; the
boot runs in a subprocess over a copy of panel/ with its own data/. Nothing reaches the network.
"""
import importlib.metadata as _md196
import os as _os196
import re as _re196
import shutil as _sh196
import subprocess as _sp196  # nosec B404 - bash and python over the repo's own files, fixed argv
import sys as _sys196
import tempfile as _tf196

from unit.part01 import check
from unit import REPO_ROOT as _root

try:
    from packaging.requirements import Requirement as _Req196
except ImportError:  # pragma: no cover - pip's own copy, as part06 falls back to
    from pip._vendor.packaging.requirements import Requirement as _Req196

_TMP196 = _tf196.mkdtemp(prefix="lgsm-unit-p196-")
_LEFT196 = ["dnspython", "h11", "invoke", "pycparser", "simple-websocket", "wsproto"]


def _read196(*parts):
    with open(_os196.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _fn196(src, name):
    """The text of shell function `name` in `src`, from its `name() {` line to its closing `}`."""
    i = src.find("\n%s() {" % name)
    if i < 0:
        return "%s() { exit 97; }\n" % name
    return src[i + 1:src.index("\n}\n", i) + 3]


def _bash196(script, env=None):
    r = _sp196.run(["bash", "-c", "set -euo pipefail\n" + script], capture_output=True, text=True,  # nosec B603 B607
                   timeout=60, env=dict(_os196.environ, **(env or {})), cwd=_TMP196, stdin=_sp196.DEVNULL)
    return r.returncode, r.stdout, r.stderr


def _write196(path, text, mode=None):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    if mode:
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
        _os196.chmod(path, 0o700)  # nosec B103


_INS196 = _read196("install.sh")
_REQ196 = _read196("panel", "install", "requirements.txt")
_LLO196 = _fn196(_INS196, "_lock_left_out")
_PCD196 = _fn196(_INS196, "_pip_check_deps")

# ── 1. _lock_left_out ────────────────────────────────────────────────────────────────────────────
_real_txt196 = _os196.path.join(_TMP196, "real.txt")
_write196(_real_txt196, _REQ196)
_rc, _out, _err = _bash196(_LLO196 + '_lock_left_out "%s"\n' % _real_txt196)
check("_lock_left_out: the real lockfile leaves out exactly dnspython, h11, invoke, pycparser, "
      "simple-websocket and wsproto", _rc == 0 and _out.split() == _LEFT196, "rc=%r out=%r err=%r" % (_rc, _out, _err))
_odd_txt196 = _os196.path.join(_TMP196, "odd.txt")
_write196(_odd_txt196, "#    pip-compile --unsafe-package=foo;touch${IFS}x --unsafe-package bar requirements.in\n"
                       "baz==1 \\\n    --hash=sha256:aa  # --unsafe-package=notacomment\n")
_rc, _out, _err = _bash196(_LLO196 + '_lock_left_out "%s"\n' % _odd_txt196)
check("_lock_left_out: ...reads comment lines only, and only a package name's characters (nothing else "
      "reaches pip's argv)", _rc == 0 and _out.split() == ["bar", "foo"], "rc=%r out=%r" % (_rc, _out))
_rc, _out, _err = _bash196(_LLO196 + '_lock_left_out "%s"; echo "rc=$?"\n'
                           % _os196.path.join(_TMP196, "missing.txt"))
check("_lock_left_out: ...and a missing file is no names, not a failure (install_deps runs under set -e)",
      _rc == 0 and _out.split() == ["rc=0"], "rc=%r out=%r err=%r" % (_rc, _out, _err))

# ── 2. install_deps: one uninstall of every name the lockfile leaves out ─────────────────────────
_STUBS196 = r"""
id() { if [ "$#" -eq 1 ] && [ "$1" = -u ]; then echo 0; else command id "$@"; fi; }
_r42i_tree_owner() { echo lgsmpanel; }
_venv_stale() { return 1; }
panel_file() { echo "${PANEL_DIR}/$1"; }
sudo() { echo "AS $2" >> "$P196_LOG"; shift 2; "$@"; }
python3() { return 0; }
ok() { :; }; info() { :; }; warn() { echo "WARN $*" >> "$P196_LOG"; }; die() { exit 9; }
"""
_PIP196 = r"""#!/bin/sh
echo "PIP $*" >> "$P196_LOG"
case "$1" in
  check) [ -n "${P196_CHECK:-}" ] && printf '%s\n' "$P196_CHECK"; exit "${P196_CHECK_RC:-0}" ;;
esac
exit 0
"""


def _deps196(tag, req_text, check_out=""):
    """Run install_deps over a throwaway PANEL_DIR; (rc, log lines, stderr)."""
    pd = _os196.path.join(_TMP196, tag)
    _os196.makedirs(_os196.path.join(pd, "venv", "bin"))
    log = _os196.path.join(_TMP196, tag + ".log")
    _write196(_os196.path.join(pd, "requirements.txt"), req_text)
    _write196(_os196.path.join(pd, "venv", "bin", "pip"), _PIP196, mode=True)
    rc, _o, err = _bash196(_STUBS196 + _fn196(_INS196, "install_deps") + _PCD196 + _LLO196 + "install_deps\n",
                           env={"PANEL_DIR": pd, "PANEL_USER": "lgsmpanel", "P196_LOG": log,
                                "P196_CHECK": check_out, "P196_CHECK_RC": "1" if check_out else "0"})
    try:
        with open(log, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        lines = []
    return rc, [ln.replace(pd, "PD") for ln in lines], err


_TOLERATED196 = ["eventlet 0.41.3 requires dnspython, which is not installed.",
                 "paramiko 5.1.0 requires invoke, which is not installed.",
                 "python-engineio 4.15.1 requires simple-websocket, which is not installed.",
                 "cffi 2.1.1 requires pycparser, which is not installed."]
_rc, _log, _err = _deps196("six", _REQ196, "\n".join(_TOLERATED196))
check("install.sh install_deps: the real lockfile installs --no-deps, uninstalls all six it leaves out in "
      "one pip run, and passes a pip check reporting the four requirements on them",
      _rc == 0 and [ln for ln in _log if ln.startswith("PIP ")]
      == ["PIP install --quiet --no-deps -r PD/requirements.txt",
          "PIP uninstall --quiet --yes " + " ".join(_LEFT196), "PIP check"],
      "rc=%r log=%r err=%r" % (_rc, _log, _err[-300:]))
check("install.sh install_deps: ...each pip run as the panel user on a root run (the venv is theirs)",
      _rc == 0 and [ln for ln in _log if ln.startswith("AS ")] == ["AS lgsmpanel"] * 4, repr(_log))

# ── 3. _pip_check_deps: the tolerated reports are exactly what the pinned metadata makes ─────────
_pins196 = dict(_re196.findall(r"(?m)^([a-z0-9][a-z0-9._-]*)==(\S+)", _REQ196))


def _expected_reports196():
    """`pip check`'s report for each requirement a pinned, installed package makes on a left-out one."""
    out = []
    for name in sorted(_pins196):
        try:
            dist = _md196.distribution(name)
        except _md196.PackageNotFoundError:
            continue
        for rd in dist.requires or []:
            req = _Req196(rd)
            dep = _re196.sub(r"[-_.]+", "-", req.name).lower()
            if dep in _LEFT196 and (req.marker is None or req.marker.evaluate({"extra": ""})):
                out.append("%s %s requires %s, which is not installed." % (dist.metadata["Name"].lower(),
                                                                        dist.version, dep))
    return out


_meta196 = _expected_reports196()


def _pcd196(report):
    return _bash196(_PCD196 + '_pip_check_deps "$P196_PIP"\n',
                    env={"P196_PIP": _os196.path.join(_TMP196, "six", "venv", "bin", "pip"),
                         "P196_LOG": _os196.path.join(_TMP196, "pcd.log"), "P196_CHECK": report,
                         "P196_CHECK_RC": "1"})


_rc, _out, _err = _pcd196("\n".join(_meta196))
check("_pip_check_deps: the reports the pinned packages' own metadata makes on what the lockfile leaves "
      "out are exactly the four it tolerates, and it passes them",
      _rc == 0 and sorted(_meta196) == sorted(_TOLERATED196), "rc=%r metadata=%r err=%r" % (_rc, _meta196, _err[-300:]))
_cross196 = ["flask 3.1.3 requires invoke, which is not installed.",
             "eventlet 0.41.3 requires simple-websocket, which is not installed.",
             "python-engineio 4.15.1 requires dnspython, which is not installed.",
             "werkzeug 3.1.9 requires pycparser, which is not installed.",
             "flask-socketio 5.7.2 requires wsproto, which is not installed.",
             "jinja2 3.1.6 requires h11, which is not installed.",
             "xparamiko 5.1.0 requires invoke, which is not installed."]
_cross_bad196 = []
for _line196 in _cross196:
    _rc, _out, _err = _pcd196(_TOLERATED196[0] + "\n" + _line196)
    if _rc == 0 or _line196 not in _err:
        _cross_bad196.append(_line196)
check("_pip_check_deps: ...and the same packages wanted by any other requirer fail it, named",
      not _cross_bad196, "let through: %r" % _cross_bad196)

# ── 4. panel_pip_check.sh: the header's names, with this interpreter ─────────────────────────────
_PY196 = r"""#!/bin/sh
if [ "$1" = -m ] && [ "$2" = pip ] && [ "$3" = check ]; then echo "No broken requirements found."; exit 0; fi
exec "$P196_PY" "$@"
"""
_py196 = _os196.path.join(_TMP196, "python196")
_write196(_py196, _PY196, mode=True)
_fake196 = _os196.path.join(_TMP196, "fakeroot")
_os196.makedirs(_os196.path.join(_fake196, ".github", "scripts"))
_os196.makedirs(_os196.path.join(_fake196, "panel", "install"))
_sh196.copy(_os196.path.join(_root, ".github", "scripts", "panel_pip_check.sh"),
            _os196.path.join(_fake196, ".github", "scripts", "panel_pip_check.sh"))
_sh196.copy(_os196.path.join(_root, "install.sh"), _os196.path.join(_fake196, "install.sh"))


_shadow196 = _os196.path.join(_TMP196, "shadow")
_os196.makedirs(_shadow196)
_write196(_os196.path.join(_shadow196, "p196_shadow.py"), "")


def _ppc196(header):
    _write196(_os196.path.join(_fake196, "panel", "install", "requirements.txt"),
              "#    pip-compile %s requirements.in\nflask==3.1.3 \\\n    --hash=sha256:aa\n" % header)
    r = _sp196.run(["bash", _os196.path.join(_fake196, ".github", "scripts", "panel_pip_check.sh")],  # nosec B603 B607
                   capture_output=True, text=True, timeout=60, cwd=_TMP196, stdin=_sp196.DEVNULL,
                   env=dict(_os196.environ, PYTHON=_py196, P196_PY=_sys196.executable, PYTHONPATH=_shadow196))
    return r.returncode, r.stdout + r.stderr


_rc, _out = _ppc196("--unsafe-package=no-such-dist-p196 --unsafe-package=pip")
check("panel_pip_check.sh: a package the lockfile's header leaves out that is installed here (pip) fails "
      "the job, named", _rc != 0 and "::error::pip is installed in this job's Python" in _out,
      "rc=%r %s" % (_rc, _out[-300:]))
_rc, _out = _ppc196("--unsafe-package=no-such-dist-p196 --unsafe-package=no-such-dist-p196b")
check("panel_pip_check.sh: ...and with none of them installed or importable it passes, naming them",
      _rc == 0 and "none of no-such-dist-p196 no-such-dist-p196b is installed" in _out, "rc=%r %s" % (_rc, _out[-300:]))
_rc, _out = _ppc196("--unsafe-package=no-such-dist-p196 --unsafe-package=p196-shadow")
check("panel_pip_check.sh: ...and one importable with no distribution behind it (a bare module on the "
      "path, named as the package with - as _) fails it too, named",
      _rc != 0 and "::error::p196-shadow is installed" in _out, "rc=%r %s" % (_rc, _out[-300:]))
_rc, _out = _ppc196("--generate-hashes")
check("panel_pip_check.sh: ...and a lockfile that leaves nothing out fails it (the names went missing)",
      _rc != 0 and "leaves nothing out" in _out, "rc=%r %s" % (_rc, _out[-300:]))

# ── 5. the panel without them: app.py by path, /healthz, Socket.IO mode, an SSH session ──────────
_BOOT196 = _os196.path.join(_TMP196, "boot")
_sh196.copytree(_os196.path.join(_root, "panel"), _os196.path.join(_BOOT196, "panel"),
                ignore=_sh196.ignore_patterns("__pycache__", "data"))
_APP_BOOT196 = r'''
import sys, os, runpy
GONE = ("dns", "invoke", "simple_websocket", "wsproto", "h11", "pycparser")
class _Gone:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in GONE:
            raise ImportError("%s is not installed (part196)" % name)
        return None
sys.meta_path.insert(0, _Gone())
tree = sys.argv[1]
os.chdir(tree)
os.environ["LGSM_PANEL_NO_WORKERS"] = "1"
sys.path.insert(0, os.path.join(tree, "panel", "install"))
g = runpy.run_path(os.path.join(tree, "panel", "install", "app.py"), run_name="lgsm_p196_unit")
app = g["create_app"]()
r = app.test_client().get("/healthz")
print("HEALTHZ", r.status_code, app.extensions["socketio"].server.eio.async_mode)
sys.stdout.flush()
import io, socket, threading, paramiko
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization as ser
def key():
    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(ser.Encoding.PEM, ser.PrivateFormat.OpenSSH,
                                                             ser.NoEncryption()).decode()
    return paramiko.Ed25519Key.from_private_key(io.StringIO(pem))
host, user = key(), key()
class Srv(paramiko.ServerInterface):
    def get_allowed_auths(self, u):
        return "publickey"
    def check_auth_publickey(self, u, k):
        return paramiko.AUTH_SUCCESSFUL if k.get_base64() == user.get_base64() else paramiko.AUTH_FAILED
    def check_channel_request(self, kind, cid):
        return paramiko.OPEN_SUCCEEDED
    def check_channel_exec_request(self, ch, cmd):
        def reply():
            ch.sendall(b"ran " + cmd)
            ch.send_exit_status(0)
            ch.close()
        threading.Timer(0.05, reply).start()
        return True
a, b = socket.socketpair()
st = paramiko.Transport(a)
st.add_server_key(host)
st.start_server(event=threading.Event(), server=Srv())
c = paramiko.SSHClient()
c.get_host_keys().add("h.invalid", host.get_name(), host)
c.connect("h.invalid", sock=b, username="u", pkey=user, allow_agent=False, look_for_keys=False, timeout=20)
_i, o, _e = c.exec_command("uptime", timeout=20)
print("SSH", o.read().decode(), o.channel.recv_exit_status(), c.get_transport().host_key_type)
gone = sorted(m for m in sys.modules if m.split(".")[0] in GONE)
print("LOADED", gone or "none")
sys.stdout.flush()
os._exit(0)
'''
_env196 = dict(_os196.environ, EVENTLET_NO_GREENDNS="yes")
_rb196 = _sp196.run([_sys196.executable, "-W", "ignore", "-c", _APP_BOOT196, _BOOT196],  # nosec B603
                    capture_output=True, text=True, timeout=180, env=_env196, cwd=_TMP196, stdin=_sp196.DEVNULL)
check("without dnspython, h11, invoke, pycparser, simple-websocket or wsproto: app.py run by path serves "
      "/healthz with Socket.IO in eventlet mode",
      "HEALTHZ 200 eventlet" in _rb196.stdout,
      "rc=%r out=%r err=%r" % (_rb196.returncode, _rb196.stdout[-300:], _rb196.stderr[-900:]))
check("without them: ...and paramiko completes an SSH session (ed25519 host key, key exchange, publickey "
      "login, a command), loading none of the six",
      "SSH ran uptime 0 ssh-ed25519" in _rb196.stdout and "LOADED none" in _rb196.stdout,
      "rc=%r out=%r err=%r" % (_rb196.returncode, _rb196.stdout[-300:], _rb196.stderr[-900:]))
_sh196.rmtree(_TMP196, ignore_errors=True)
