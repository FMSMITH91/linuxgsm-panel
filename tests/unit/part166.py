"""Root clean-up, release 1: readers find a moved root file in panel/install/, else at the root.

Every reader of a root file the next release moves into panel/install/ looks there first.

An installed panel's update runs the installer it already has, root-owned. That copy reads
requirements.txt, app.py, release-signers, recover.sh, uninstall.sh and db_maintenance.py at fixed
paths in the commit it moves to, so a commit without them at the root fails its update and rolls back
(measured on the test VPS, 2026-11-10). This release moves nothing. It teaches install.sh, the
root-owned recover.sh and the helper the new place, so a host that has run it can take the release
that moves the files. Each check runs the real script text against both layouts.
"""
import importlib.machinery as _ilm166
import importlib.util as _ilu166
import os
import re as _re166
import shlex as _shlex166
import subprocess as _sp166  # nosec B404 - the repo's own scripts, run on fixture trees
import tempfile as _tf166

from unit.part01 import _root, check, eq
from unit.part06 import _inst, _inst_placement, _inst_shfn

_MOVED166 = ("app.py", "manage.py", "db_maintenance.py", "VERSION", "release-signers", "requirements.txt",
             "requirements-bootstrap.txt", "recover.sh", "uninstall.sh")
_SB166 = _tf166.mkdtemp(prefix="p166-")


def _bash166(script, env=None, cwd=None):
    # bash over this part's own fixture script
    return _sp166.run(["bash", "-c", script], capture_output=True, text=True,  # nosec B603 B607
                      timeout=60, cwd=cwd,
                      env=dict(os.environ, **(env or {})), check=False)


def _tree166(tag, root=(), moved=()):
    """A panel tree with `root` files at its root and `moved` ones in panel/install/."""
    d = os.path.join(_SB166, tag)
    os.makedirs(os.path.join(d, "panel", "install"), exist_ok=True)
    for n in root:
        with open(os.path.join(d, n), "w", encoding="utf-8") as fh:
            fh.write("root " + n + "\n")
    for n in moved:
        with open(os.path.join(d, "panel", "install", n), "w", encoding="utf-8") as fh:
            fh.write("moved " + n + "\n")
    return d


# ── install.sh panel_file: panel/install/<name> first, the root second ─────────────────────────
_old166 = _tree166("old", root=_MOVED166)
_new166 = _tree166("new", moved=_MOVED166)
_both166 = _tree166("both", root=("app.py",), moved=("app.py",))
_pf166 = {d: _bash166(_inst_placement() + "PANEL_DIR=%s\nfor n in %s; do panel_file \"$n\"; done\n"
                      % (_shlex166.quote(d), " ".join(_MOVED166))).stdout.split()
          for d in (_old166, _new166)}
eq("install.sh panel_file: a tree with the files at its root (every install today) reads them there",
   _pf166[_old166], [os.path.join(_old166, n) for n in _MOVED166])
eq("install.sh panel_file: ...and a tree that has moved them reads panel/install/<name>",
   _pf166[_new166], [os.path.join(_new166, "panel", "install", n) for n in _MOVED166])
eq("install.sh panel_file: where both exist the moved copy wins (the release that moves them is the newer)",
   _bash166(_inst_placement() + "PANEL_DIR=%s\npanel_file app.py\n" % _shlex166.quote(_both166)).stdout.strip(),
   os.path.join(_both166, "panel", "install", "app.py"))

# ── stage_panel_file: root stages from the commit at panel/install/<name>, else at <name> ──────
_stub166 = ('stage_root_source() { echo "TRY $1" >&2; [[ " ${HAVE} " == *" $1 "* ]] '
            '&& echo "/stage/$2"; }\n')
_spf166 = _inst_shfn("stage_panel_file")


def _stage166(have):
    r = _bash166(_inst_placement() + _stub166 + _spf166 + 'out="$(stage_panel_file recover.sh recover.sh)"; '
                 'echo "RC=$? OUT=${out}"\n', env={"HAVE": have})
    return r.stdout.strip(), [ln for ln in r.stderr.splitlines() if ln.startswith("TRY ")]


eq("stage_panel_file: a commit with panel/install/recover.sh is staged from there, and the root is not asked",
   _stage166("panel/install/recover.sh"), ("RC=0 OUT=/stage/recover.sh", ["TRY panel/install/recover.sh"]))
eq("stage_panel_file: ...one with recover.sh at the root (every release so far) still stages it",
   _stage166("recover.sh"), ("RC=0 OUT=/stage/recover.sh", ["TRY panel/install/recover.sh", "TRY recover.sh"]))
eq("stage_panel_file: ...and a commit with neither fails, so the caller keeps the root-owned copy in place",
   _stage166(""), ("RC=1 OUT=", ["TRY panel/install/recover.sh", "TRY recover.sh"]))
check("install.sh: recover.sh, uninstall.sh, release-signers and db_maintenance.py are all staged through "
      "stage_panel_file, and none through stage_root_source at the root alone",
      all(('stage_panel_file %s %s' % (n, n)) in _inst
          for n in ("recover.sh", "uninstall.sh", '"${RELEASE_SIGNERS}"', "db_maintenance.py"))
      and not _re166.search(r'stage_root_source\s+"?(recover\.sh|uninstall\.sh|db_maintenance\.py|\$\{RELEASE_SIGNERS\})',
                            _inst), "")


# ...and as ROOT installing from the operator's own tree, through the real stage_root_source: the
# tree's own copy is staged, and root's verified clone (root_source_commit) is never asked for a
# file the tree lacks at the moved path (review of #503: today's layout went down that branch).
_opstub166 = ('id() { if [ "$#" -eq 1 ] && [ "$1" = -u ]; then echo 0; else command id "$@"; fi; }\n'
              "_checkout_is_roots() { return 1; }\n_operator_src() { printf '%s\\n' \"${OPSRC}\"; }\n"
              "_operator_file() { [[ -f \"$1/$2\" ]] && printf '%s\\n' \"$1/$2\"; }\n"
              'root_source_commit() { echo ROOT-GIT >&2; return 1; }\nchown() { :; }\nH_SUDO=""\n')


def _opstage166(tree):
    hd = _tf166.mkdtemp(dir=_SB166, prefix="helper-")
    r = _bash166(_inst_placement() + _opstub166 + "HELPER_DIR=%s\nPANEL_DIR=%s\n" % (
        _shlex166.quote(hd), _shlex166.quote(os.path.join(_SB166, "nopanel")))
        + _inst_shfn("stage_root_source") + 'out="$(stage_panel_file recover.sh recover.sh)" && cat "${out}"\n',
        env={"OPSRC": tree})
    return r.stdout.strip(), "ROOT-GIT" in r.stderr


eq("stage_panel_file (root, operator's tree): today's layout stages the tree's root copy without asking "
   "root's verified clone", _opstage166(_tree166("op-old", root=("recover.sh",))), ("root recover.sh", False))
eq("stage_panel_file (root, operator's tree): ...and a moved layout stages panel/install/recover.sh",
   _opstage166(_tree166("op-new", moved=("recover.sh",))), ("moved recover.sh", False))


# ── _release_key_file: the installed commit's key, at either place ─────────────────────────────
def _key_repo166(tag, path):
    d = os.path.join(_SB166, tag)
    env = dict(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t",
               GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
    os.makedirs(os.path.join(d, os.path.dirname(path)) if os.path.dirname(path) else d, exist_ok=True)
    with open(os.path.join(d, path), "w", encoding="utf-8") as fh:
        fh.write("ssh-ed25519 KEY-AT-%s\n" % path)
    for argv in (["init", "-q"], ["add", "-A"], ["-c", "commit.gpgsign=false", "commit", "-q", "-m", "k"]):
        # git over this part's own temp repo
        _sp166.run(["git", "-C", d] + argv, capture_output=True,  # nosec B603 B607
                   env=dict(os.environ, **env), check=True)
    return d


def _key166(d):
    os.makedirs(os.path.join(d, ".k"), exist_ok=True)
    r = _bash166("set -uo pipefail\n" + _inst_placement() + "id() { echo 1000; }\n"
                 '_gitc() { git -C "${PANEL_DIR}" "$@"; }\nPANEL_DIR=%s\nRELEASE_SIGNERS=release-signers\n'
                 % _shlex166.quote(d) + _inst_shfn("_release_key_file")
                 + 'k="$(_release_key_file %s)" && cat "${k}"\n' % _shlex166.quote(os.path.join(d, ".k")),
                 env={"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
    return r.stdout.strip()


eq("install.sh _release_key_file: a per-user install whose commit keeps release-signers in panel/install/ "
   "checks updates with that key", _key166(_key_repo166("key-new", "panel/install/release-signers")),
   "ssh-ed25519 KEY-AT-panel/install/release-signers")
eq("install.sh _release_key_file: ...and one that keeps it at the root (every release so far) still does",
   _key166(_key_repo166("key-old", "release-signers")), "ssh-ed25519 KEY-AT-release-signers")
check("install.sh _release_key_file: root's floor commit is read at both places too",
      '_rootgit cat-file blob "${floor}:${MOVED_DIR}/${RELEASE_SIGNERS}"' in _inst_shfn("_release_key_file")
      and '_rootgit cat-file blob "${floor}:${RELEASE_SIGNERS}"' in _inst_shfn("_release_key_file"), "")


def _rootkey166(d):
    hd = _tf166.mkdtemp(dir=_SB166, prefix="nokey-")
    floor = os.path.join(hd, "floor")
    with open(floor, "w", encoding="utf-8") as fh:
        fh.write("x\n")
    os.makedirs(os.path.join(d, ".k"), exist_ok=True)
    r = _bash166("set -uo pipefail\n" + _inst_placement()
                 + 'id() { if [ "$#" -eq 1 ] && [ "$1" = -u ]; then echo 0; else command id "$@"; fi; }\n'
                 + '_rootgit() { git -C "${REPO}" "$@"; }\n_source_floor() { git -C "${REPO}" rev-parse HEAD; }\n'
                 + "HELPER_DIR=%s\nROOT_SRC_FLOOR_FILE=%s\nRELEASE_SIGNERS=release-signers\n"
                 % (_shlex166.quote(hd), _shlex166.quote(floor)) + _inst_shfn("_release_key_file")
                 + 'k="$(_release_key_file %s)" && cat "${k}"\n' % _shlex166.quote(os.path.join(d, ".k")),
                 env={"REPO": d, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
    return r.stdout.strip()


eq("install.sh _release_key_file (root, no key placed yet): the key at root's floor commit is read from "
   "panel/install/ there, and from the root in a floor that predates the move",
   [_rootkey166(_key_repo166("rkey-new", "panel/install/release-signers")),
    _rootkey166(_key_repo166("rkey-old", "release-signers"))],
   ["ssh-ed25519 KEY-AT-panel/install/release-signers", "ssh-ed25519 KEY-AT-release-signers"])


# ── The service unit starts the app.py the tree has, and the debug report expects the same ─────
def _unit166(d, as_root):
    r = _bash166(_inst_placement() + "PANEL_DIR=%s\nPANEL_USER=svc\nRUN_AS_ROOT=%d\n" % (_shlex166.quote(d), as_root)
                 + _inst_shfn("render_service_unit") + "render_service_unit\n")
    return [ln for ln in r.stdout.splitlines() if ln.startswith("ExecStart=")]


_py166 = "ExecStart=%s/venv/bin/python %s"
eq("install.sh render_service_unit: both units start panel/install/app.py in a tree that has moved it",
   [_unit166(_new166, 1), _unit166(_new166, 0)],
   [[_py166 % (_new166, os.path.join(_new166, "panel", "install", "app.py"))]] * 2)
eq("install.sh render_service_unit: ...and the root app.py in one that has not (the unit is unchanged today)",
   _unit166(_old166, 1), [_py166 % (_old166, os.path.join(_old166, "app.py"))])
check("install.sh: the unit is refreshed after the new code is fetched, so it names the fetched tree's app.py",
      _inst.index("\n    fetch_code\n    _CODE_FETCHED=1") < _inst.index("\n    ensure_service_unit "), "")
from panel.ops.debug_report import process as _proc166  # noqa: E402
_rend166 = {d: [ln for ln in _proc166.render_unit("system", "svc", d).splitlines() if ln.startswith("ExecStart=")]
            for d in (_old166, _new166)}
eq("debug report: the unit it expects names the same app.py install.sh's unit does, in both layouts",
   _rend166, {_old166: _unit166(_old166, 1), _new166: _unit166(_new166, 1)})

# ── recover.sh: the root-owned copy finds manage.py in either layout ───────────────────────────
# A copy outside the repository, as the root-owned one in /usr/local/lib/linuxgsm-panel is: run from
# the checkout, recover.sh's last fallback (its own directory) finds the repository's manage.py.
_REC166 = os.path.join(_tf166.mkdtemp(dir=_SB166, prefix="helperdir-"), "recover.sh")
with open(os.path.join(_root, "panel", "install", "recover.sh"), encoding="utf-8") as _fh166, \
        open(_REC166, "w", encoding="utf-8") as _out166:
    _out166.write(_fh166.read())
_HOME166 = _tf166.mkdtemp(dir=_SB166, prefix="home-")


def _recover166(d):
    os.makedirs(os.path.join(d, "venv", "bin"), exist_ok=True)
    py = os.path.join(d, "venv", "bin", "python")
    with open(py, "w", encoding="utf-8") as fh:
        fh.write('#!/bin/sh\necho "RAN $*"\n')
    os.chmod(py, 0o700)  # nosec B103 - an owner-only stand-in interpreter in this part's temp tree  # nosemgrep
    r = _sp166.run(["bash", _REC166, "list-users"], capture_output=True, text=True, timeout=60,  # nosec B603 B607
                   env=dict(os.environ, PANEL_DIR=d, HOME=_HOME166), stdin=_sp166.DEVNULL, check=False)
    return r.returncode, r.stdout.strip() or (r.stderr.strip().splitlines() or [""])[-1]


eq("recover.sh: an install that has moved manage.py into panel/install/ is recovered with that manage.py",
   _recover166(_tree166("rec-new", moved=("manage.py",))),
   (0, "RAN %s list-users" % os.path.join(_SB166, "rec-new", "panel", "install", "manage.py")))
eq("recover.sh: ...and one with manage.py at its root (every install today) still is",
   _recover166(_tree166("rec-old", root=("manage.py",))),
   (0, "RAN %s list-users" % os.path.join(_SB166, "rec-old", "manage.py")))
eq("recover.sh: ...while a directory with neither is not taken for an install",
   _recover166(_tree166("rec-none")),
   (1, "Couldn't find a LinuxGSM Panel install on this host — run this ON the panel server."))

# ── the helper: a home holding either layout is a panel account (never user-deleted) ───────────
_hspec166 = _ilu166.spec_from_loader("p166_helper", _ilm166.SourceFileLoader(
    "p166_helper", os.path.join(_root, "tools", "panel-helper")))
_helper166 = _ilu166.module_from_spec(_hspec166)
_hspec166.loader.exec_module(_helper166)


def _holds166(layout):
    home = os.path.join(_SB166, "home-" + layout)
    inst = os.path.join(home, "linuxgsm-panel")
    os.makedirs(os.path.join(inst, "panel", "install"), exist_ok=True)
    os.makedirs(os.path.join(inst, "data"), exist_ok=True)
    if layout == "old":
        open(os.path.join(inst, "app.py"), "w").close()
    elif layout == "new":
        open(os.path.join(inst, "panel", "install", "app.py"), "w").close()
    saved = _helper166.home_of
    _helper166.home_of = lambda _n: home
    try:
        return _helper166._home_holds_a_panel("someone")
    finally:
        _helper166.home_of = saved


eq("panel-helper: a home whose install keeps app.py in panel/install/ is a panel account, as one with it at "
   "the root is, and one with neither is not", [_holds166("new"), _holds166("old"), _holds166("none")],
   [True, True, False])

# ── no installer reads a moved file at the root alone ──────────────────────────────────────────
_code166 = "\n".join(ln for ln in _inst.splitlines() if not ln.lstrip().startswith("#"))
_direct166 = [m.group(0) for m in _re166.finditer(
    r"\$\{?(?:PANEL_DIR|SRC)\}?/(?:app\.py|manage\.py|db_maintenance\.py|VERSION|release-signers"
    r"|requirements[a-z-]*\.txt|recover\.sh|uninstall\.sh)\b", _code166)]
# The two that stay: the link an OLD installer made into the checkout's recover.sh, removed by name.
eq("install.sh: no line reads a file the next release moves at the root alone (only the old recovery "
   "link's own path is named, to remove it)", _direct166, ["${PANEL_DIR}/recover.sh"] * 2)
with open(_REC166, encoding="utf-8") as _fh166:
    _rcode166 = "\n".join(ln for ln in _fh166.read().splitlines() if not ln.lstrip().startswith("#"))
eq("recover.sh: every manage.py it looks for or runs goes through manage_of",
   _re166.findall(r'\$\{\w+\}/manage\.py', _rcode166), [])
