"""Root clean-up, release 2: the installer-read files live in panel/install/.

app.py, manage.py, db_maintenance.py, VERSION, release-signers, the requirements files, recover.sh,
uninstall.sh and osv-scanner.toml moved out of the repository root. Release 1 (part166) taught the
installer, recover.sh and the helper to look in panel/install/ first. This part holds what moving
them needed besides: the entry points find the panel package two levels up however they are
started, and every reader of an older commit (the release key at root's floor, sign-release.sh's
parent) still finds a file that commit keeps at the root.
"""
import os
import re as _re167
import shlex as _shlex167
import subprocess as _sp167  # nosec B404 - the repo's own entry points and scripts, on fixture trees
import sys as _sys167
import tempfile as _tf167

from unit.part01 import _root, check, eq
from unit.part166 import _key_repo166

_INSTALL167 = os.path.join(_root, "panel", "install")
_MOVED167 = ("app.py", "manage.py", "db_maintenance.py", "VERSION", "release-signers", "requirements.txt",
             "requirements.in", "requirements-bootstrap.txt", "requirements-bootstrap.in", "recover.sh",
             "uninstall.sh", "osv-scanner.toml")
_SB167 = _tf167.mkdtemp(prefix="p167-")


def _py167(argv, cwd="/"):
    # this interpreter over the repo's own entry points, isolated (-I: no script dir, no cwd, no env)
    return _sp167.run([_sys167.executable, "-I"] + argv, capture_output=True, text=True,  # nosec B603
                      timeout=120, cwd=cwd, check=False)


eq("layout: the moved files are in panel/install/ and none is left at the repository root",
   ([n for n in _MOVED167 if not os.path.isfile(os.path.join(_INSTALL167, n))],
    [n for n in _MOVED167 if os.path.lexists(os.path.join(_root, n))]), ([], []))

# ── the entry points put the checkout on sys.path themselves ────────────────────────────────────
_mg167 = _py167([os.path.join(_INSTALL167, "manage.py"), "--help"])
check("manage.py: run by path from /, isolated, it imports app.py beside it and the panel package above it",
      _mg167.returncode == 0 and "reset-password" in _mg167.stdout,
      repr((_mg167.returncode, _mg167.stdout[-200:], _mg167.stderr[-400:])))
_ap167 = _py167(["-c", "import sys; sys.path.insert(0, %r); import app, panel; print(app._CHECKOUT); "
                 "print(panel.__file__)" % _INSTALL167])
eq("app.py: imported with only panel/install/ on the path, it names the checkout and loads the panel "
   "package from it", _ap167.stdout.split()[:2] if _ap167.returncode == 0 else _ap167.stderr[-400:],
   [_root, os.path.join(_root, "panel", "__init__.py")])
check("app.py: the Flask app is rooted at the checkout, so its UI folders resolve there and not in "
      "panel/install/",
      _re167.search(r"Flask\(__name__, root_path=_CHECKOUT, template_folder=\"panel/templates\", "
                    r"static_folder=\"panel/static\"\)",
                    open(os.path.join(_INSTALL167, "app.py"), encoding="utf-8").read()) is not None, "")

# db_maintenance.py: the checkout copy reaches panel.core.config; the root-owned copy (its grandparent
# is /usr/local) must not put that grandparent on the path. Run as a copy in a tree with no panel/ above it.
_dbm_code167 = ("import sys; sys.path.insert(0, sys.argv[1]); import db_maintenance as d\n"
                "try:\n    print(d._paths()[0])\nexcept ModuleNotFoundError as e:\n"
                "    print('NOMOD', e.name, sys.argv[2] in sys.path)\n")
_dbm_ck167 = _py167(["-c", _dbm_code167, _INSTALL167, _root])
eq("db_maintenance.py: the checkout's copy, with no panel.conf beside it, reads the checkout's database path",
   _dbm_ck167.stdout.strip() or _dbm_ck167.stderr[-400:], os.path.join(_root, "data", "panel.db"))
_dbm_lib167 = os.path.join(_SB167, "usr", "local", "lib", "linuxgsm-panel")
os.makedirs(_dbm_lib167)
with open(os.path.join(_INSTALL167, "db_maintenance.py"), encoding="utf-8") as _fh167, \
        open(os.path.join(_dbm_lib167, "db_maintenance.py"), "w", encoding="utf-8") as _out167:
    _out167.write(_fh167.read())
_dbm_rt167 = _py167(["-c", _dbm_code167, _dbm_lib167, os.path.join(_SB167, "usr", "local")])
eq("db_maintenance.py: ...a copy outside a checkout adds nothing to the path, and fails as before without "
   "panel.conf (control)", _dbm_rt167.stdout.strip() or _dbm_rt167.stderr[-400:], "NOMOD panel False")

# ── readers of an older commit find the release key at either place ────────────────────────────
from panel.ops import system_ops as _so167  # noqa: E402

_saved167 = _so167.PANEL_DIR
try:
    _keys167 = []
    for _tag167, _path167 in (("so-new", "panel/install/release-signers"), ("so-old", "release-signers"),
                              ("so-none", "README")):
        _so167.PANEL_DIR = _key_repo166("p167-" + _tag167, _path167)
        _keys167.append(_so167._release_key_at("HEAD"))
finally:
    _so167.PANEL_DIR = _saved167
eq("system_ops._release_key_at: a commit's key from panel/install/, from the root in a commit that predates "
   "the move (root's floor can), and none when it has neither",
   _keys167, ["ssh-ed25519 KEY-AT-panel/install/release-signers", "ssh-ed25519 KEY-AT-release-signers", ""])

_sign167 = open(os.path.join(_root, "tools", "sign-release.sh"), encoding="utf-8").read()
_sat167 = _re167.search(r"^signers_at\(\) \{.*?^\}\n", _sign167, _re167.M | _re167.S)
_sat_out167 = []
for _tag167, _path167 in (("sr-new", "panel/install/release-signers"), ("sr-old", "release-signers"),
                          ("sr-none", "README")):
    _d167 = _key_repo166("p167-" + _tag167, _path167)
    # bash over sign-release.sh's own function, on this part's fixture repo
    _r167 = _sp167.run(["bash", "-c", (_sat167.group(0) if _sat167 else "") + 'cd %s && signers_at HEAD; echo "rc=$?"'
                        % _shlex167.quote(_d167)], capture_output=True, text=True,  # nosec B603 B607
                       timeout=30, check=False, env=dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull,
                                                         GIT_CONFIG_NOSYSTEM="1"))
    # git's own status for a missing file (128) is any failure here: the caller only tests it.
    _sat_out167.append(_re167.sub(r"rc=[1-9][0-9]*$", "rc=failed", _r167.stdout.strip()))
eq("sign-release.sh signers_at: the key the parent commit carries, from panel/install/ or the root, and a "
   "failure when it has neither", _sat_out167,
   ["ssh-ed25519 KEY-AT-panel/install/release-signers\nrc=0", "ssh-ed25519 KEY-AT-release-signers\nrc=0", "rc=failed"])

# ── the root-owned pieces are compared with files that exist ──────────────────────────────────
eq("root pieces: each root-owned copy is compared with a file this commit has",
   [rel for _n, rel in _so167._ROOT_PIECES if not os.path.isfile(os.path.join(_root, rel))], [])
try:
    _so167.PANEL_DIR = "/x"
    _idir167 = _so167.install_dir()
finally:
    _so167.PANEL_DIR = _saved167
eq("system_ops.install_dir: follows PANEL_DIR when a caller points it elsewhere", _idir167, "/x/panel/install")


# ── recover.sh run as the checkout's own copy, every other way of finding the install missing ───
# Its last fallback is its own directory. That is <checkout>/panel/install now, which holds manage.py
# but no venv/: taken first, it ran manage.py under the system python3, without the panel's packages.
def _rec_self167():
    ck = os.path.join(_SB167, "rec-self", "ck")
    os.makedirs(os.path.join(ck, "panel", "install"))
    os.makedirs(os.path.join(ck, "venv", "bin"))
    with open(os.path.join(_INSTALL167, "recover.sh"), encoding="utf-8") as fh, \
            open(os.path.join(ck, "panel", "install", "recover.sh"), "w", encoding="utf-8") as out:
        out.write(fh.read())
    open(os.path.join(ck, "panel", "install", "manage.py"), "w").close()
    py = os.path.join(ck, "venv", "bin", "python")
    with open(py, "w", encoding="utf-8") as fh:
        fh.write('#!/bin/sh\necho "RAN $0 $*"\n')
    os.chmod(py, 0o700)  # nosec B103 - an owner-only stand-in interpreter in this part's temp tree  # nosemgrep
    empty = os.path.join(_SB167, "rec-self", "nothing")
    os.makedirs(empty)
    env = {k: v for k, v in os.environ.items() if k != "PANEL_DIR"}
    env.update(HOME=empty, PANEL_RECOVER_SYSTEM_UNIT=os.path.join(empty, "unit"),
               PANEL_RECOVER_USER_UNIT=os.path.join(empty, "user-unit"), PANEL_RECOVER_HOMES=empty,
               PANEL_RECOVER_PANEL_CONF=os.path.join(empty, "panel.conf"))
    # bash over the repo's own recover.sh, copied into this part's fixture tree
    r = _sp167.run(["bash", os.path.join(ck, "panel", "install", "recover.sh"), "list-users"],  # nosec B603 B607
                   capture_output=True, text=True, timeout=60, env=env, stdin=_sp167.DEVNULL, check=False)
    return ck, r.returncode, r.stdout.strip().splitlines()[-1:] or r.stderr.strip().splitlines()[-1:]


_rs_ck167, _rs_rc167, _rs_out167 = _rec_self167()
eq("recover.sh: run as the checkout's own copy with nothing else to go on, it takes the checkout (its venv's "
   "python, panel/install/manage.py), not panel/install/ itself",
   (_rs_rc167, _rs_out167), (0, ["RAN %s %s list-users" % (os.path.join(_rs_ck167, "venv", "bin", "python"),
                                                           os.path.join(_rs_ck167, "panel", "install", "manage.py"))]))
