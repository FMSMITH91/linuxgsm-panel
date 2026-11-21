"""Part 287 of the unit suite: the installer's file modes.

1. Update snapshots (data/.backups/<stamp>/code.tgz, data.tgz) are written owner-only: the folder
   0700 and each archive 0600, under umask 077 inside the owner's own shell (sudo's PAM session
   gives an account with its own group umask 0002). ensure_tree_modes takes group and world write
   off everything in the tree and every permission but the owner's off the snapshots, as the tree's
   owner and only on what that account owns, on a fresh install, an update, an up-to-date run and
   both rollbacks.

HOW IT RUNS. install.sh's own text, cut out and run under bash over this part's scratch trees (a
stand-in cron spool among them); `id` and `sudo` are stand-ins where a check needs a root run. The
core-dump probe is a fresh interpreter that points panel.core.config's key files at scratch paths.
The scan script is loaded from .github/scripts and planned over scratch fixtures; nothing runs docker.
Nothing here runs as another account, or reads or writes /etc, the real cron spool, or data/.
"""
import atexit as _atexit287
import os
import shutil as _sh287
import subprocess as _sp287  # nosec B404 - bash over the repo's own install.sh text, in a scratch dir
import tempfile as _tf287
from shlex import quote as _q287

from unit.part01 import check
from unit.part06 import _inst, _inst_shfn

_TMP287 = _tf287.mkdtemp(prefix="p287-")
_atexit287.register(_sh287.rmtree, _TMP287, True)


def _bash287(script, timeout=60):
    """Run `script` under bash; its stdout and stderr together."""
    p = _sp287.run(["bash", "-c", script], capture_output=True, text=True, timeout=timeout,  # nosec B603 B607
                   check=False)
    return p.stdout + p.stderr


def _mode287(path):
    """The permission bits of `path` (not following a link) as an octal string, or "gone"."""
    try:
        return oct(os.lstat(path).st_mode & 0o777)
    except OSError:
        return "gone"


def _write287(path, text, mode):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, mode)


def _loose_tree287():
    """A panel tree as a umask-0002 update leaves it: (panel dir, a file outside it a link names)."""
    top = _tf287.mkdtemp(prefix="tree-", dir=_TMP287)
    pd = os.path.join(top, "linuxgsm-panel")
    _write287(os.path.join(pd, "panel", "app.py"), "# app\n", 0o664)
    _write287(os.path.join(pd, "install.sh"), "#!/bin/sh\n", 0o775)
    _write287(os.path.join(pd, "data", "config.json"), "{}", 0o600)
    _write287(os.path.join(pd, "data", ".backups", "20260101-000000", "data.tgz"), "k", 0o664)
    _write287(os.path.join(pd, "data", ".backups", "20260101-000000", "code.tgz"), "c", 0o664)
    outside = os.path.join(top, "outside.txt")
    _write287(outside, "o", 0o666)
    os.symlink(outside, os.path.join(pd, "panel", "link"))
    for d in (pd, os.path.join(pd, "panel"), os.path.join(pd, "data", ".backups"),
              os.path.join(pd, "data", ".backups", "20260101-000000")):
        os.chmod(d, 0o775)  # nosec B103 - the loose modes under test, in this part's scratch dir
    return pd, outside


# `id` answers as a non-root account, so the run is the same whoever runs the suite (CI runs it as root).
_NOT_ROOT287 = 'id() { case "${1:-}" in -u) echo 4242 ;; *) command id "$@" ;; esac; }\n'


def _tree_modes_run287(pd, prelude=""):
    script = ("set -euo pipefail\nwarn() { echo \"WARN $*\"; }\nPANEL_DIR=%s\n" % _q287(pd) + prelude
              + _inst_shfn("ensure_tree_modes") + "ensure_tree_modes; echo RC=$?\n")
    return _bash287(script)


def _s287_tree_modes():
    pd, outside = _loose_tree287()
    out = _tree_modes_run287(pd, _NOT_ROOT287)
    stamp = os.path.join(pd, "data", ".backups", "20260101-000000")
    got = {rel: _mode287(os.path.join(pd, rel)) for rel in (
        "", "panel", "panel/app.py", "install.sh", "data/config.json", "data/.backups",
        "data/.backups/20260101-000000", "data/.backups/20260101-000000/data.tgz")}
    check("install.sh: ensure_tree_modes takes group and world write off the code tree (files 644, folders 755)",
          got[""] == got["panel"] == "0o755" and got["panel/app.py"] == "0o644" and "RC=0" in out,
          repr((got, out)))
    check("install.sh: ...and leaves every permission but the owner's off the update snapshots (0700, 0600)",
          got["data/.backups"] == got["data/.backups/20260101-000000"] == "0o700"
          and got["data/.backups/20260101-000000/data.tgz"] == _mode287(os.path.join(stamp, "code.tgz")) == "0o600",
          repr(got))
    # Controls: the owner keeps what it had, and a file a link in the tree names is not touched.
    check("install.sh: ...the owner keeps its own bits (a script stays executable, a 0600 file stays 0600)",
          os.stat(os.path.join(pd, "install.sh")).st_mode & 0o700 == 0o700 and got["data/config.json"] == "0o600",
          repr(got))
    check("install.sh: ...and a link in the tree is not followed (the file it names keeps its mode)",
          _mode287(outside) == "0o666" and "WARN" not in out, repr((_mode287(outside), out)))


def _s287_tree_modes_owner():
    """A root run changes modes AS the tree's owner (sudo -u), never as root; a root-owned tree, as root."""
    log = os.path.join(_TMP287, "sudo.log")
    stub = ('id() { case "${1:-}" in -u) echo 0 ;; *) command id "$@" ;; esac; }\n'
            'sudo() { echo "AS $2" >> %s; shift 2; "$@"; }\n' % _q287(log))
    pd, _ = _loose_tree287()
    _tree_modes_run287(pd, stub + "_r42i_tree_owner() { echo nobody; }\n")
    try:
        with open(log, encoding="utf-8") as fh:
            as_owner = fh.read().split("\n")
        os.unlink(log)
    except OSError:
        as_owner = []
    pd2, _ = _loose_tree287()
    out = _tree_modes_run287(pd2, stub + "_r42i_tree_owner() { echo root; }\n")
    check("install.sh: ensure_tree_modes, run as root over the panel user's tree, works as that account",
          as_owner.count("AS nobody") == 2, repr(as_owner))
    check("install.sh: ...and over a tree root owns (a fresh install before the chown), as root itself",
          not os.path.exists(log) and "RC=0" in out, out)


def _snapshot_lines287():
    """install.sh's [1/6] folder line and both archive lines, cut from install.sh as written."""
    lines = _inst.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith('    info "[1/6] Snapshotting'))
    mk = []
    for ln in lines[start + 1:]:
        if ln.strip().startswith("# Compressor"):
            break
        mk.append(ln)
    code = [ln for ln in lines if "--exclude=./venv --exclude=./data -cf - ." in ln and "TREE_SUDO" in ln]
    data = [ln for ln in lines if "--exclude=./.backups" in ln and "TREE_SUDO" in ln and "tar -C" in ln]
    return "\n".join(mk), (code or ["exit 97"])[0], (data or ["exit 97"])[0]


def _s287_snapshot_modes():
    pd, _ = _loose_tree287()
    backup = os.path.join(pd, "data", ".backups", "20991231-235959")
    _sh287.rmtree(os.path.join(pd, "data", ".backups"))
    mk, code, data = _snapshot_lines287()
    script = "\n".join(["set -euo pipefail", "umask 0002", "TREE_SUDO=''", "SNAP_GZ='gzip -1'",
                        "info() { :; }", "PANEL_DIR=%s" % _q287(pd), "BACKUP=%s" % _q287(backup),
                        mk, code, data, "echo SNAPPED"])
    out = _bash287(script)
    got = (_mode287(os.path.dirname(backup)), _mode287(backup), _mode287(os.path.join(backup, "code.tgz")),
           _mode287(os.path.join(backup, "data.tgz")))
    check("install.sh: [1/6] makes data/.backups and the snapshot's folder 0700, under a 0002 umask",
          got[:2] == ("0o700", "0o700") and "SNAPPED" in out, repr((got, out)))
    check("install.sh: ...and writes code.tgz and data.tgz 0600 (they hold the database and its key)",
          got[2:] == ("0o600", "0o600") and os.path.getsize(os.path.join(backup, "data.tgz")) > 0, repr((got, out)))


def _section287(start, end):
    i = _inst.find(start)
    j = _inst.find(end, i) if i >= 0 else -1
    return _inst[i:j] if j >= 0 else ""


def _code_lines287(text):
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def _s287_tree_modes_callers():
    fresh = _code_lines287(_section287('info "[3/4] Registering the service', 'info "[4/4] Verifying'))
    full = _code_lines287(_section287('    info "[4/6] Installing dependencies', '    info "[5/6] Starting'))
    noop = _code_lines287(_section287("        install_gamedig\n        # The breached-password list",
                                      "        update_noop_line\n        exit 0"))
    abort = _code_lines287(_section287("    _update_window_abort() {", "\n    }\n"))
    rollback = _code_lines287(_section287("Rolling back to ${FROM_VER}", "if health_check; then"))
    after_chown = [part.split("_chown_panel_tree", 1)[-1] for part in (fresh, full, abort, rollback)]
    check("install.sh: ensure_tree_modes runs on a fresh install, an update, an up-to-date run and both rollbacks",
          all("ensure_tree_modes" in part for part in (fresh, full, noop, abort, rollback)),
          repr([("ensure_tree_modes" in p) for p in (fresh, full, noop, abort, rollback)]))
    check("install.sh: ...each time after the chown (an account's modes are changed once the tree is its own)",
          all("ensure_tree_modes" in part for part in after_chown), repr([("ensure_tree_modes" in p) for p in after_chown]))


for _fn287 in (_s287_tree_modes, _s287_tree_modes_owner, _s287_snapshot_modes, _s287_tree_modes_callers):
    try:
        _fn287()
    except Exception as _e287:  # a crash names its section instead of taking the suite down
        check("part287: %s ran to the end" % _fn287.__name__, False, repr(_e287))
