"""Part 294 of the unit suite: review pass 36's runtime fixes.

1. The backup disk check measures the filesystem that holds ~/lgsm/backup (a symlink to another disk is
   how backups are moved), falling back to the home while the folder does not exist: the headroom prune
   and the pre-flight refusal no longer act on the home's free space.

HOW IT RUNS. Stand-in transports answer every host call; shell text the panel builds is run by bash over
this part's scratch directory, with stand-ins for the host tools it calls. Nothing reaches a host, /etc
or data/.
"""
import os
import shutil as _sh294
import subprocess as _sp294  # nosec B404 - bash over this part's own scratch files
import tempfile as _tf294

from unit.part01 import check
from unit.part12 import _p9_patch, _p9_restore_all
from panel.ops.ssh_manager import _core as _core294, cron as _cron294, game as _game294

_TMP294 = _tf294.mkdtemp(prefix="p294-")


def _bash294(script, env=None):
    """(stdout, stderr, rc) of `script` run by bash in this part's scratch directory."""
    # nosec B603 B607 - fixed argv: bash over a script this part wrote, in its own scratch directory
    p = _sp294.run(["bash", "-c", script], capture_output=True, text=True, timeout=60, cwd=_TMP294,  # nosec B603 B607
                   env=dict(os.environ, **(env or {})), check=False)
    return p.stdout, p.stderr, p.returncode


# ── 1. The backup disk check reads the backup folder's filesystem ─────────────────────────────────
_GB294 = 1024 ** 3
_HOME294 = os.path.join(_TMP294, "home")
# df stand-in: the home's filesystem has 3 GB free, the disk ~/lgsm/backup links to has 900 GB.
_DF294 = (r'df() { local p="${@: -1}" f; p=$(readlink -f -- "$p");'
          r' case "$p" in "$BIGDISK294"*) f=966367641600;; *) f=3221225472;; esac;'
          r' printf "Filesystem 1B-blocks Used Available Capacity Mounted on\n/dev/x 1099511627776 0 %s 1%% /\n" "$f"; }; ')
_BK_LIST294 = "".join("F\tgsu294-2026-11-2%d-010000.tar.zst\t%d\t17000%d0000\n" % (d, 5 * _GB294, d)
                      for d in range(4)) + _cron294._BACKUP_LIST_DONE + "\n"


def _host294(_server, cmd, *_a, **_k):
    """Answer the listing; run any df command through bash with the home moved under scratch."""
    if _cron294._BACKUP_LIST_DONE in cmd:
        return _BK_LIST294, "", 0
    if "df -PB1" not in cmd:
        return "", "unexpected", 1
    return _bash294(_DF294 + cmd.replace("/home/", _HOME294 + "/"),
                    env={"BIGDISK294": os.path.join(_TMP294, "bigdisk")})


def _disk_case294(linked):
    """(refusal, deleted names, card disk) for gsu294 with ~/lgsm/backup linked to the big disk or absent."""
    _sh294.rmtree(_HOME294, ignore_errors=True)
    os.makedirs(os.path.join(_HOME294, "gsu294", "lgsm"))
    os.makedirs(os.path.join(_TMP294, "bigdisk"), exist_ok=True)
    if linked:
        os.symlink(os.path.join(_TMP294, "bigdisk"), os.path.join(_HOME294, "gsu294", "lgsm", "backup"))
    deleted = []
    try:
        _p9_patch(_core294, "run_command", _host294)
        _p9_patch(_core294, "shell_as_game_user", lambda s, u, sh, **k: _host294(s, sh))
        _p9_patch(_cron294, "delete_game_backup", lambda s, u, name: deleted.append(name) or True)
        note = _cron294._ensure_backup_headroom(object(), "gsu294", 3)
        refusal = _game294._backup_space_refusal(object(), "gsu294", note)
        return refusal, deleted, _cron294.backup_disk_info(object(), "gsu294")
    finally:
        _p9_restore_all()


_ref294, _del294, _disk294 = _disk_case294(linked=True)
check("backup disk: a ~/lgsm/backup linked to a big disk is measured there (900 GB free, not the home's 3 GB)",
      _disk294.get("free") == 966367641600, _disk294)
check("backup disk: with the backup folder on a big disk, the headroom prune deletes nothing", _del294 == [], _del294)
check("backup disk: with the backup folder on a big disk, the pre-flight check does not refuse the backup",
      _ref294 is None, _ref294)
_ref294, _del294, _disk294 = _disk_case294(linked=False)
check("backup disk (control): no backup folder yet reads the home's filesystem", _disk294.get("free") == 3221225472, _disk294)
check("backup disk (control): a tight home with no backup folder still refuses the backup",
      bool(_ref294) and "Not enough disk space" in _ref294, _ref294)
_sent294 = []
try:
    _p9_patch(_core294, "run_command", lambda *a, **k: _sent294.append(a) or ("", "", 1))
    _p9_patch(_core294, "shell_as_game_user", lambda *a, **k: _sent294.append(a) or ("", "", 1))
    _disk294 = _cron294.backup_disk_info(object(), "root")
finally:
    _p9_restore_all()
check("backup disk: an unsafe account name sends nothing and reads zeros",
      _disk294 == {"free": 0, "total": 0} and not _sent294, (_disk294, _sent294))
