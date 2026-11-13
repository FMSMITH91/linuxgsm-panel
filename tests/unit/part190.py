"""Part 190 of the unit suite: restoring a game server from one of its own LinuxGSM backups.

Held here:
* The permission: restore_backup is grantable, listed after the other two backup permissions on the
  Groups page, says it is the most destructive one, in Spanish and French too.
* The host commands, RUN for real by bash on a stand-in home (services/game_restore's own text with
  /home/<account> pointed at a temp dir; tar, python3 and coreutils as on a host): a LinuxGSM backup
  made with LinuxGSM's own tar command is restored file for file, the KEEP paths (backup, lock and
  tmp dirs, ~/.ssh, the panel's cron folder) are left as they are, a symlinked folder stays a link,
  and the archive comes back under its own name and time; held aside, LinuxGSM's own retention
  prunes (by name and by age) cannot reach it; every refusal changes nothing (a member outside
  the folder, a pipe, a symbolic link, a hard link to nothing vetted, no LinuxGSM script, a cut-short
  archive, a symlinked folder outside the home or into the backup dir, too little space, a LinuxGSM
  lock, a process still in serverfiles); an extraction that fails after the clear says so.
* The route, through the app: RESTORE_BACKUP on its own starts it (typed name, the archive from the
  server's own listing), the others do not; a wrong name, an archive not listed, a bad shape are
  refused before any work starts.
* The run (the route's background worker) with every host call stubbed: the order (checks, stop,
  backup kept from pruning anything listed, the restore, start), and what a failure at each step
  does (nothing restored, the archive put back, the server started again or left stopped, the undo
  archive named), audited and alerted.
* While it runs, the server is held: the server page's actions are refused in its own words, and
  a backup of it waits.

HOW IT RUNS. The scripts by bash in temp dirs (cleaned up whatever happens); the routes on part12's
app with its transport tripwire armed and every host call stubbed. Nothing reaches a host or data/.
"""
import gzip as _gz190
import hashlib as _hl190
import io as _io190
import os as _os190
import re as _re190
import shutil as _sh190
import subprocess as _sp190
import tarfile as _tf190
import tempfile as _tmp190
import time as _time190

from unit.part01 import check, eq, skip
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, _p9, _p9_arm, _p9_audit, _p9_audit_count, _p9_client,
                         _p9_patch, _p9_restore_all)
from panel.core import i18n as _i18n190
from panel.core.panel_state import r36j_route_job as _job190
from panel.routes import (_shared as _shr190, game_restore as _gr190, panel_backup as _pb190,
                          server_detail as _sd190)
from panel.security import auth as _auth190
from panel.services import game_restore as _grs190

# ── 1. the permission ───────────────────────────────────────────────────────────────────────────
_keys190 = list(_auth190.ALL_PERMISSIONS)
eq("permission: restore_backup is grantable, listed right after download_backup and delete_backup",
   _keys190[_keys190.index(_auth190.DELETE_BACKUP) + 1], _auth190.RESTORE_BACKUP)
check("permission: its description says it replaces the server's files and is the most destructive",
      "replaces its current files" in _auth190.ALL_PERMISSIONS[_auth190.RESTORE_BACKUP]
      and "most destructive" in _auth190.ALL_PERMISSIONS[_auth190.RESTORE_BACKUP], "")
eq("permission: its description reads in Spanish and French",
   [_i18n190.translate(_l, _auth190.ALL_PERMISSIONS[_auth190.RESTORE_BACKUP]) ==
    _auth190.ALL_PERMISSIONS[_auth190.RESTORE_BACKUP] for _l in ("es", "fr")], [False, False])

# ── 2. the host commands, run by bash on a stand-in home ────────────────────────────────────────
_U190 = "grsu"
_NAME190 = "grsu-2026-11-01-120000.tar.gz"
_UNDO190 = "grsu-2026-11-13-000000.tar.gz"
_T0190 = 1761998400          # the archive's mtime: a year old, so LinuxGSM's age prune would take it
_TOOLS190 = ("bash", "tar", "gzip", "python3", "find", "du", "df", "stat", "readlink", "touch", "mv")
_missing190 = [_t for _t in _TOOLS190 if not _sh190.which(_t)]
_KEEP_PRUNE190 = [_a for _k in _grs190.KEEP for _a in ("-path", "./" + _k, "-prune", "-o")]


class _Sb190:
    """A stand-in host: <root>/home/grsu laid out as LinuxGSM lays out an instance in the account's home."""

    def __init__(self, layout="mc"):
        """Build the home, back it up with LinuxGSM's own tar command, then change it as play would.

        LinuxGSM's own ~/log/server link is ABSOLUTE and points into serverfiles: at serverfiles/logs for
        Minecraft ("mc"), at serverfiles itself for Factorio ("fctr"), so `tar -h` stores those files
        twice, the second name as a hard link. Two older archives sit in the backup dir beside it.
        """
        self.root = _tmp190.mkdtemp(prefix="p190-")
        self.home = _os190.path.join(self.root, "home", _U190)
        self.bdir = _os190.path.join(self.home, "lgsm", "backup")
        h = self.home
        for d in ("lgsm/backup", "lgsm/lock", "lgsm/tmp", "lgsm/config-lgsm/grsu", "serverfiles/world/region",
                  ".ssh", ".steam/steamcmd/linux64", ".steam/sdk64", "log/console", ".lgsm-cron",
                  "serverfiles/logs", "lgsm/node_modules/.bin"):
            _os190.makedirs(_os190.path.join(h, d))
        self.put("serverfiles/logs/latest.log", "server log 1")
        self.put("serverfiles/factorio", "binary")
        self.put("lgsm/node_modules/gamedig.js", "js")
        _os190.symlink(h + ("/serverfiles/logs" if layout == "mc" else "/serverfiles"), _os190.path.join(h, "log/server"))
        _os190.symlink("../gamedig.js", _os190.path.join(h, "lgsm/node_modules/.bin/gamedig"))
        self.older = {"grsu-2026-10-01-000000.tar.gz": 1759276800.25, "grsu-2026-10-02-000000.tar.gz": 1759363200.5}
        for _n, _t in self.older.items():
            with open(_os190.path.join(self.bdir, _n), "wb") as f:
                f.write(b"older archive")
            _os190.utime(_os190.path.join(self.bdir, _n), (_t, _t))
        self.put("grsu", "#!/bin/bash\necho lgsm\n")
        self.put("serverfiles/world/region/r.0.mca", "world v1")
        self.put("lgsm/config-lgsm/grsu/grsu.cfg", "cfg v1")
        self.put(".ssh/authorized_keys", "key 1")
        self.put(".steam/steamcmd/linux64/steamclient.so", "so")
        self.put("log/console/c.log", "log 1")
        self.put(".lgsm-cron/run", "wrapper 1")
        _os190.symlink("steamcmd", _os190.path.join(h, ".steam/root"))            # a symlinked folder
        _os190.symlink("../steamcmd/linux64/steamclient.so", _os190.path.join(h, ".steam/sdk64/steamclient.so"))
        self.archive = _os190.path.join(self.bdir, _NAME190)
        # LinuxGSM's own command (command_backup.sh, master 2026-11), gzip as fn_select_compression picks it.
        _sp190.run(["tar", "--gzip", "-hcf", self.archive, "--exclude", "lgsm/backup", "--exclude",
                    h + "/lgsm/lock", "--exclude", h + "/lgsm/tmp", "--exclude", "./lgsm/backup", "-C", h, "./."],
                   check=True, capture_output=True, timeout=60)
        _os190.utime(self.archive, (_T0190, _T0190))
        self.before = self.tree()
        # Play went on: the world changed, a new region file, the key rotated, the cron wrapper changed.
        self.put("serverfiles/world/region/r.0.mca", "world v2")
        self.put("serverfiles/world/region/r.1.mca", "new")
        self.put(".ssh/authorized_keys", "key 2")
        self.put(".lgsm-cron/run", "wrapper 2")

    def put(self, rel, text):
        """Write `text` to <home>/<rel>."""
        with open(_os190.path.join(self.home, rel), "w") as f:
            f.write(text)

    def read(self, rel):
        """<home>/<rel>'s text, or None."""
        try:
            with open(_os190.path.join(self.home, rel)) as f:
                return f.read()
        except OSError:
            return None

    def tree(self):
        """{path: sha256 of what it holds} for every file outside KEEP, read through symlinks."""
        out = _sp190.run(["find", "."] + _KEEP_PRUNE190 + ["(", "-type", "f", "-o", "-type", "l", ")", "-print0"],
                         cwd=self.home, capture_output=True, timeout=60).stdout
        res = {}
        for rel in filter(None, out.split(b"\0")):
            p = _os190.path.join(self.home, rel.decode())
            if _os190.path.islink(p):
                res[rel.decode()] = "link to " + _os190.readlink(p)
                continue
            try:
                with open(p, "rb") as f:
                    res[rel.decode()] = _hl190.sha256(f.read()).hexdigest()
            except OSError:
                res[rel.decode()] = "unreadable"
        return res

    def run(self, script):
        """Run a panel-built command, its /home/grsu moved into this sandbox: (output, exit status)."""
        text = script.replace("/home/" + _U190, self.home)
        p = _sp190.run(["bash", "-c", text], capture_output=True, text=True, timeout=180, cwd="/")
        return p.stdout + p.stderr, p.returncode

    def vet(self, name=_NAME190, undo_estimate=0):
        """vet_script's output and vet_outcome's reading of it."""
        out, _rc = self.run(_grs190.vet_script(_U190, _U190, name, undo_estimate))
        return out, _grs190.vet_outcome(out)

    def backups(self):
        """The backup dir's entries."""
        return sorted(_os190.listdir(self.bdir))

    def gone(self):
        """Remove the sandbox, whatever state the run left it in."""
        for d, dirs, _files in _os190.walk(self.root):
            for x in dirs:
                try:
                    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                    _os190.chmod(_os190.path.join(d, x), 0o700)  # nosec B103
                except OSError:
                    pass
        _sh190.rmtree(self.root, ignore_errors=True)


def _restore190(sb, ready, undo=_UNDO190, busy_polls=1):
    """Take the stand-in undo backup, then run restore_script: (output, restore_outcome)."""
    held = [_f for _f in sb.backups() if _f.startswith(_NAME190.split(".tar.")[0] + _grs190.HOLD_INFIX)]
    if held and not _os190.path.exists(_os190.path.join(sb.bdir, undo)):
        _sh190.copyfile(_os190.path.join(sb.bdir, held[0]), _os190.path.join(sb.bdir, undo))
    out, rc = sb.run(_grs190.restore_script(_U190, _U190, _NAME190, ready["t0"], ready["need"], undo,
                                            busy_polls=busy_polls, members=ready["members"]))
    return out, _grs190.restore_outcome(out, rc)


def _lgsm_prune190(bdir):
    """LinuxGSM's two retention prunes (fn_backup_prune, master 2026-11), past any maxbackups and maxbackupdays."""
    _sp190.run(["bash", "-c", 'find "$1"/ -type f -name "*.tar.*" -printf "%T@ %p\\n" | sort -rn | tail -100 | '
                'cut -f2- -d" " | xargs -r rm; find "$1"/ -type f -mtime +0 -exec rm -f {} \\;', "_", bdir],
               capture_output=True, timeout=60)


def _crafted190(sb, members, name="grsu-2026-11-02-120000.tar.gz"):
    """An archive in the backup dir holding `members` [(name, type, linkname)] beside the LinuxGSM script."""
    buf = _io190.BytesIO()
    with _tf190.open(fileobj=buf, mode="w", format=_tf190.GNU_FORMAT) as t:
        for mname, mtype, link in [("././", _tf190.DIRTYPE, ""), ("././grsu", _tf190.REGTYPE, "")] + members:
            ti = _tf190.TarInfo(mname)
            ti.type, ti.linkname, ti.mode = mtype, link, 0o755
            t.addfile(ti, _io190.BytesIO(b"") if mtype == _tf190.REGTYPE else None)
    with open(_os190.path.join(sb.bdir, name), "wb") as f:
        f.write(_gz190.compress(buf.getvalue()))
    return name


_r190 = {}
if _missing190:
    skip("restore commands: run on a stand-in home", "missing here: %s" % ", ".join(_missing190))
else:
    # The whole restore, as the run does it.
    _sb = _Sb190()
    try:
        _out, (_state, _ready) = _sb.vet()
        _r190["vet"] = (_state, sorted(_ready) if isinstance(_ready, dict) else str(_ready), _out[-300:])
        _r190["held"] = _sb.backups()
        _r190["held_mtime"] = [int(_os190.stat(_os190.path.join(_sb.bdir, _f)).st_mtime) for _f in _sb.backups()]
        _lgsm_prune190(_sb.bdir)          # LinuxGSM's retention, as the undo backup runs it
        _r190["after_prune"] = _sb.backups()
        if _state == "ready":
            _out, _res = _restore190(_sb, _ready)
            _r190["restore"] = (_res[0], _out[-300:])
        _r190["tree"] = (_sb.tree() == _sb.before, sorted(set(_sb.tree()) ^ set(_sb.before)))
        _r190["keep"] = (_sb.read(".ssh/authorized_keys"), _sb.read(".lgsm-cron/run"))
        _r190["link"] = _os190.path.islink(_os190.path.join(_sb.home, ".steam/root"))
        _a = _os190.path.join(_sb.bdir, _NAME190)
        _r190["putback"] = (_os190.path.isfile(_a) and int(_os190.stat(_a).st_mtime),
                            [_f for _f in _sb.backups() if _grs190.HOLD_INFIX in _f])
        _r190["older"] = {_n: _os190.stat(_os190.path.join(_sb.bdir, _n)).st_mtime
                          for _n in _sb.older if _os190.path.isfile(_os190.path.join(_sb.bdir, _n))}
        _r190["links"] = tuple(_os190.readlink(_q) if _os190.path.islink(_q) else "not a link"
                               for _q in (_os190.path.join(_sb.home, "log/server"),
                                          _os190.path.join(_sb.home, "lgsm/node_modules/.bin/gamedig")))
    finally:
        _sb.gone()

    # Factorio's layout: ~/log/server points at serverfiles itself, so every game file is in the archive twice.
    _sb = _Sb190("fctr")
    try:
        _out, (_state, _ready) = _sb.vet()
        _lgsm_prune190(_sb.bdir)
        _res = _restore190(_sb, _ready) if _state == "ready" else (_out, ("not ready", ""))
        _r190["fctr"] = (_res[1][0], _sb.tree() == _sb.before, sorted(set(_sb.tree()) ^ set(_sb.before)),
                         _os190.path.islink(_os190.path.join(_sb.home, "log/server")) and
                         _os190.readlink(_os190.path.join(_sb.home, "log/server")).endswith("/home/grsu/serverfiles"),
                         sorted(_f for _f in _sb.backups() if _f in _sb.older))
    finally:
        _sb.gone()

    # Each refusal: nothing changed (the home as it was, the archive under its own name, nothing held).
    def _refused190(prep, name=None, undo_estimate=0):
        sb = _Sb190()
        try:
            nm = prep(sb) or name or _NAME190
            tree, listing = sb.tree(), sb.backups()
            out, (state, why) = sb.vet(nm, undo_estimate)
            return (state, str(why) if state != "ready" else "READY", sb.tree() == tree and sb.backups() == listing,
                    out[-200:])
        finally:
            sb.gone()

    def _outside190(sb):
        _os190.makedirs(_os190.path.join(sb.root, "elsewhere"))
        _os190.symlink(_os190.path.join(sb.root, "elsewhere"), _os190.path.join(sb.home, "serverfiles/maps"))

    def _cut190(sb):
        with open(sb.archive, "rb") as f:
            data = f.read()
        with open(sb.archive, "wb") as f:
            f.write(data[:len(data) // 2])
        _os190.utime(sb.archive, (_T0190, _T0190))

    def _lock190(sb):
        sb.put("lgsm/lock/backup.lock", str(int(_time190.time())))

    def _sshlink190(sb):          # ~/.ssh a link to a folder the clear would otherwise empty
        _os190.rename(_os190.path.join(sb.home, ".ssh"), _os190.path.join(sb.home, "dotssh"))
        _os190.symlink("dotssh", _os190.path.join(sb.home, ".ssh"))

    def _bklink190(sb):           # ~/lgsm/backup a link to ~/backups: every archive would be cleared
        _os190.rename(sb.bdir, _os190.path.join(sb.home, "backups"))
        _os190.symlink("../backups", sb.bdir)

    _ref = {
        "dotdot": lambda sb: _crafted190(sb, [("././../evil", _tf190.REGTYPE, "")]),
        "absolute": lambda sb: _crafted190(sb, [("/etc/evil", _tf190.REGTYPE, "")]),
        "outside": lambda sb: _crafted190(sb, [("home/other/x", _tf190.REGTYPE, "")]),
        "fifo": lambda sb: _crafted190(sb, [("././serverfiles/p", _tf190.FIFOTYPE, "")]),
        "symlink": lambda sb: _crafted190(sb, [("././serverfiles/l", _tf190.SYMTYPE, "/etc")]),
        "device": lambda sb: _crafted190(sb, [("././serverfiles/d", _tf190.CHRTYPE, "")]),
        "hardlink": lambda sb: _crafted190(sb, [("././serverfiles/h", _tf190.LNKTYPE, "././nothere")]),
        "hardlink_kept": lambda sb: _crafted190(sb, [("././lgsm/tmp/x", _tf190.REGTYPE, ""),
                                                     ("././serverfiles/h", _tf190.LNKTYPE, "././lgsm/tmp/x")]),
        "linkout": _outside190,
        "linkbackup": lambda sb: _os190.symlink(sb.bdir, _os190.path.join(sb.home, "serverfiles/bk")),
        "cut": _cut190,
        "plaintext": lambda sb: _os190.replace(_os190.path.join(sb.home, "grsu"), sb.archive) or None,
        "locked": _lock190,
        "keeplink_ssh": _sshlink190,
        "keeplink_backup": _bklink190,
    }
    for _k, _prep in _ref.items():
        _r190["ref_" + _k] = _refused190(_prep)

    def _noscript190(sb):
        buf = _io190.BytesIO()
        with _tf190.open(fileobj=buf, mode="w") as t:
            ti = _tf190.TarInfo("././serverfiles/x")
            t.addfile(ti, _io190.BytesIO(b""))
        with open(_os190.path.join(sb.bdir, "grsu-2026-11-03-120000.tar.gz"), "wb") as f:
            f.write(_gz190.compress(buf.getvalue()))
        return "grsu-2026-11-03-120000.tar.gz"
    _r190["ref_noscript"] = _refused190(_noscript190)
    _r190["ref_space"] = _refused190(lambda sb: None, undo_estimate=10 ** 18)

    # More files and folders than free inodes (the margin raised past any filesystem): refused, nothing changed.
    _saved_margin = _grs190.INODE_MARGIN
    try:
        _grs190.INODE_MARGIN = 10 ** 15
        if _os190.statvfs(_tmp190.gettempdir()).f_files:
            _r190["ref_inodes"] = _refused190(lambda sb: None)
        else:
            skip("restore commands: the inode bound", "this filesystem does not count inodes")
    finally:
        _grs190.INODE_MARGIN = _saved_margin

    # A heartbeat while a long step runs (here a pause put after it starts), and none left behind.
    _saved_hb = _grs190.HEARTBEAT
    _sb = _Sb190()
    try:
        _grs190.HEARTBEAT = 1
        _vs = _grs190.vet_script(_U190, _U190, _NAME190, 0)
        _vs = _vs.replace("kill $hb 2>/dev/null' EXIT\n", "kill $hb 2>/dev/null' EXIT\nsleep 2.5\n", 1)
        _t = _time190.time()
        _out, _rc = _sb.run(_vs)
        _r190["heartbeat"] = (_out.count("__GRS_ALIVE__") >= 2, _grs190.vet_outcome(_out)[0], _time190.time() - _t < 30)
        _rs = _grs190.restore_script(_U190, _U190, _NAME190, _grs190.vet_outcome(_out)[1]["t0"], 1, _UNDO190,
                                     busy_polls=1)
        _rs = _re190.sub(r"(\n[^\n]*' EXIT\n)", r"\1sleep 2.5\n", _rs, count=1)
        _out, _rc = _sb.run(_rs)
        _r190["heartbeat_restore"] = _out.count("__GRS_ALIVE__") >= 2
    finally:
        _grs190.HEARTBEAT = _saved_hb
        _sb.gone()

    # The heartbeat ends with its script: nothing holds the output (and the panel) after the last line.
    _t = _time190.time()
    _sp190.run(["bash", "-c", "\n".join(_grs190._grs_heartbeat()) + "\nsleep 1\n"], capture_output=True,
               timeout=120, cwd="/")
    _r190["heartbeat_ends"] = _time190.time() - _t < _grs190.HEARTBEAT / 2

    # The checks' last line cannot reach a panel that has gone: the archive is put back, not left held.
    _sb = _Sb190()
    try:
        _vs = _grs190.vet_script(_U190, _U190, _NAME190, 0).replace("/home/" + _U190, _sb.home)
        _sp190.run(["bash", "-c", 'bash -c "$1" | true', "_", _vs], capture_output=True, timeout=180, cwd="/")
        _r190["undelivered"] = (_os190.path.isfile(_sb.archive), [_f for _f in _sb.backups() if _grs190.HOLD_INFIX in _f])
    finally:
        _sb.gone()

    # A process of the account still in serverfiles: the restore waits, then refuses with nothing cleared.
    _sb = _Sb190()
    try:
        _out, (_state, _ready) = _sb.vet()
        _sleeper = _sp190.Popen(["sleep", "60"], cwd=_os190.path.join(_sb.home, "serverfiles"))
        try:
            _tree = _sb.tree()
            _out, _res = _restore190(_sb, _ready)
            _r190["busy"] = (_res[0], str(_res[1]), _sb.tree() == _tree, _os190.path.isfile(_sb.archive))
        finally:
            _sleeper.kill()
            _sleeper.wait()
    finally:
        _sb.gone()

    # The archive damaged after the checks: the staging extraction fails, before anything is cleared.
    _sb = _Sb190()
    try:
        _out, (_state, _ready) = _sb.vet()
        _tree_x = _sb.tree()
        _held = [_f for _f in _sb.backups() if _f.startswith(_NAME190.split(".tar.")[0] + _grs190.HOLD_INFIX)]
        _sh190.copyfile(_os190.path.join(_sb.bdir, _held[0]), _os190.path.join(_sb.bdir, _UNDO190))
        with open(_os190.path.join(_sb.bdir, _held[0]), "wb") as _f:
            _f.write(b"not a gzip stream")
        _out, _res = _restore190(_sb, _ready)
        _r190["xfail"] = (_res[0], str(_res[1]).startswith("the archive could not be unpacked into a staging folder"),
                          _os190.path.isfile(_sb.archive), _sb.tree() == _tree_x,
                          _os190.path.exists(_os190.path.join(_sb.home, "lgsm", "tmp", "panel-restore-%d" % _ready["t0"])))
    finally:
        _sb.gone()

    # Damaged so that tar fails while every entry still appears (the last member cut short), and an
    # archive that unpacks cleanly to far fewer entries than were counted: both refused at the staging.
    def _staged190(damage):
        sb = _Sb190()
        try:
            out, (state, ready) = sb.vet()
            tree = sb.tree()
            held = [_f for _f in sb.backups() if _f.startswith(_NAME190.split(".tar.")[0] + _grs190.HOLD_INFIX)][0]
            hp = _os190.path.join(sb.bdir, held)
            _sh190.copyfile(hp, _os190.path.join(sb.bdir, _UNDO190))
            with open(hp, "rb") as f:
                raw = _gz190.decompress(f.read())
            with open(hp, "wb") as f:
                f.write(_gz190.compress(damage(raw)))
            out, res = _restore190(sb, ready)
            return res[0], str(res[1]), sb.tree() == tree
        finally:
            sb.gone()

    def _cut_last190(raw):
        end = len(raw.rstrip(b"\0"))
        end += (-end) % 512
        ti = _tf190.TarInfo("././zz-last")
        ti.size = 4096
        return raw[:end] + ti.tobuf(format=_tf190.GNU_FORMAT) + b"z" * 100

    def _fewer190(raw):
        buf = _io190.BytesIO()
        with _tf190.open(fileobj=buf, mode="w", format=_tf190.GNU_FORMAT) as t:
            for mname, data in (("././", None), ("././" + _U190, b"#!/bin/bash\n")):
                ti = _tf190.TarInfo(mname)
                ti.type = _tf190.DIRTYPE if data is None else _tf190.REGTYPE
                ti.size, ti.mode = len(data or b""), 0o755
                t.addfile(ti, _io190.BytesIO(data) if data else None)
        return buf.getvalue()
    _r190["stage_rc"] = _staged190(_cut_last190)
    _r190["stage_count"] = _staged190(_fewer190)

    # An interrupted restore left the archive held: the next restore's checks put it back first.
    _sb = _Sb190()
    try:
        _sb.vet(undo_estimate=0)
        _held = sorted(_sb.backups())
        _lv = _sb.vet("grsu-2026-11-09-000000.tar.gz")[1]     # any other archive: not there
        _a = _sb.archive
        _r190["leftover"] = (_lv[0], _os190.path.isfile(_a) and int(_os190.stat(_a).st_mtime),
                             [_f for _f in _sb.backups() if _grs190.HOLD_INFIX in _f], _held)
    finally:
        _sb.gone()

if "vet" in _r190:
    eq("restore commands: the checks pass on a LinuxGSM backup made by LinuxGSM's own tar command",
       _r190["vet"][:2], ("ready", ["members", "need", "t0", "up"]))
    eq("restore commands: ...and hold every archive in the backup dir aside under a name with no '.tar.', "
       "freshly dated (the one restored, and the two older ones LinuxGSM's retention would prune)",
       (len(_r190["held"]), all(_grs190.HOLD_INFIX in _f and ".tar." not in _f for _f in _r190["held"]),
        "grsu-2026-11-01-120000.restore-source-%d_000000000.gz" % _T0190 in _r190["held"],
        min(_r190["held_mtime"]) > _T0190), (3, True, True, True))
    eq("restore commands: LinuxGSM's own retention (by name past maxbackups, by age past maxbackupdays) "
       "cannot prune the held archive", _r190["after_prune"], _r190["held"])
    eq("restore commands: the restore runs to its end", (_r190.get("restore") or ("missing",))[0], "done")
    eq("restore commands: every file outside KEEP is what the archive held (a file added since is gone)",
       _r190["tree"], (True, []))
    eq("restore commands: ~/.ssh and the panel's cron folder are left as they are now",
       _r190["keep"], ("key 2", "wrapper 2"))
    check("restore commands: a symlinked folder is still a symlink", _r190["link"], "")
    eq("restore commands: the archive is back under its own name and time, nothing left held",
       _r190["putback"], (_T0190, []))
    eq("restore commands: the operator's other archives are all there, under their names and exact times",
       _r190["older"], {"grsu-2026-10-01-000000.tar.gz": 1759276800.25, "grsu-2026-10-02-000000.tar.gz": 1759363200.5})
    check("restore commands: LinuxGSM's absolute ~/log/server link and a symlinked file are links again, with "
          "their own text", _r190["links"][0].endswith("/home/grsu/serverfiles/logs") and _r190["links"][1] == "../gamedig.js",
          repr(_r190["links"]))
    _bad190 = {
        "dotdot": "not under the server's folder", "absolute": "not under the server's folder",
        "outside": "not under the server's folder", "fifo": "device, pipe or symbolic link",
        "symlink": "device, pipe or symbolic link", "device": "member list could not be read",
        "hardlink": "hard link", "hardlink_kept": "hard link", "linkout": "symbolic link in the game account",
        "linkbackup": "symbolic link in the game account", "cut": "could not be read to its end",
        "locked": "LinuxGSM backup or update", "noscript": "does not hold the server's LinuxGSM script",
        "plaintext": "could not be read to its end",
        "space": "not enough free space",
        "keeplink_ssh": "is a symbolic link, so the restore could not keep it apart",
        "keeplink_backup": "is a symbolic link, so the restore could not keep it apart",
    }
    eq("restore commands: each refusal says why and changes nothing (home, archive name, nothing held)",
       {_k: (_r190["ref_" + _k][0], _w in _r190["ref_" + _k][1], _r190["ref_" + _k][2]) for _k, _w in _bad190.items()},
       {_k: ("refused", True, True) for _k in _bad190})
    eq("restore commands: Factorio's layout (~/log/server -> serverfiles, absolute) restores file for file, the link "
       "kept, the older archives kept", _r190["fctr"],
       ("done", True, [], True, ["grsu-2026-10-01-000000.tar.gz", "grsu-2026-10-02-000000.tar.gz"]))
    if "ref_inodes" in _r190:
        eq("restore commands: an archive with more files and folders than free inodes is refused, nothing changed",
           (_r190["ref_inodes"][0], "not enough free inodes" in _r190["ref_inodes"][1], _r190["ref_inodes"][2]),
           ("refused", True, True))
    eq("restore commands: the checks print a heartbeat while they run (a silence timeout never fires on them), "
       "still end READY, and leave nothing running", _r190["heartbeat"], (True, "ready", True))
    check("restore commands: the clear and extraction print a heartbeat too", _r190["heartbeat_restore"], "")
    check("restore commands: a script with a heartbeat ends when it ends (no sleep left holding its output for up "
          "to the heartbeat's interval)", _r190["heartbeat_ends"], "")
    eq("restore commands: when the checks' last line cannot be delivered, the archive is put back (not left "
       "held for a panel that never heard)", _r190["undelivered"], (True, []))
    eq("restore commands: a process of the account still in serverfiles refuses after the wait, nothing "
       "cleared, the archive put back", _r190["busy"][:1] + _r190["busy"][2:], ("refused", True, True))
    eq("restore commands: an archive that does not unpack fully is caught in the staging folder, before anything "
       "is cleared: refused, the home unchanged, the archive put back, the staging folder gone",
       _r190["xfail"], ("refused", True, True, True, False))
    eq("restore commands: a tar that fails although every entry appeared (the last member cut short) refuses at the "
       "staging, the home unchanged", (_r190["stage_rc"][0], "(tar exit 2)" in _r190["stage_rc"][1], _r190["stage_rc"][2]),
       ("refused", True, True))
    eq("restore commands: an archive that unpacks to fewer entries than the checks counted refuses at the staging, "
       "the home unchanged", (_r190["stage_count"][0], "unpacked 2 of" in _r190["stage_count"][1], _r190["stage_count"][2]),
       ("refused", True, True))
    eq("restore commands: an archive an interrupted restore left held is put back by the next checks",
       _r190["leftover"][:3], ("refused", _T0190, []))

# ── 3. the route, through the app ───────────────────────────────────────────────────────────────
_NO_LOGIN190 = "!"
_uids190 = {}
with _p9.app_context():
    from panel.db.models import (GameServer as _PGS190, Group as _PG190, RemoteServer as _PRS190,
                                 User as _PU190, db as _pdb190)
    for _suffix, _perms in (("rs", [_auth190.RESTORE_BACKUP]),
                            ("rsedit", [_auth190.RESTORE_BACKUP, _auth190.EDIT_FILES]),
                            ("dlrm", [_auth190.DOWNLOAD_BACKUP, _auth190.DELETE_BACKUP])):
        _g = _PG190(name="p190_" + _suffix, description="", is_default=False)
        _g.set_permissions([_auth190.VIEW_SERVERS] + _perms)
        _g.servers.append(_pdb190.session.get(_PRS190, P9_HOST))
        _pdb190.session.add(_g)
        _pdb190.session.flush()
        _u = _PU190(username="p190_" + _suffix, password_hash=_NO_LOGIN190, display_name=_suffix,
                    is_superadmin=False, is_active=True)
        _u.groups.append(_g)
        _pdb190.session.add(_u)
        _pdb190.session.commit()
        _uids190[_suffix] = _u.id
    _gs_name190 = _pdb190.session.get(_PGS190, P9_GS).name

_LIST190 = [{"name": "p190-2026-11-01-120000.tar.zst", "size": 1000, "created": 1},
            {"name": "p190-2026-11-02-120000.tar.zst", "size": 2000, "created": 2}]
_started190 = []
_rt190 = {}
try:
    _p9_arm(who="part190")
    _p9_patch(_gr190, "list_game_backups", lambda *a, **k: list(_LIST190))
    _p9_patch(_gr190, "_grs_worker", lambda *a, **k: _started190.append(a[4]))
    _p9_patch(_gr190, "_grs_other_work", lambda gs: None)
    _p9_patch(_shr190, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_pb190, "list_game_backups", lambda *a, **k: list(_LIST190))
    _p9_patch(_pb190, "backup_disk_info", lambda *a, **k: {"free": 1, "total": 2})
    _url190 = "/api/panel/backup/game/%d/restore" % P9_GS
    _C190 = {_k: _p9_client(_v) for _k, _v in _uids190.items()}
    _C190["admin"] = _p9_client(P9_ADMIN)

    def _post190(who, body):
        del _started190[:]
        _gr190._grs_status.pop(P9_GS, None)
        r = _C190[who].post(_url190, json=body)
        return r.status_code, list(_started190)

    _ok190 = {"name": _LIST190[0]["name"], "confirm": _gs_name190}
    _rt190["rs"] = _post190("rs", _ok190)
    _rt190["dlrm"] = _post190("dlrm", _ok190)
    _rt190["admin"] = _post190("admin", _ok190)
    _rt190["wrong_name"] = _post190("rs", dict(_ok190, confirm=_gs_name190 + "x"))
    _rt190["not_listed"] = _post190("rs", dict(_ok190, name="p190-2026-11-09-120000.tar.zst"))
    _rt190["shape"] = _post190("rs", dict(_ok190, name="../../etc/passwd.tar.gz"))
    _rt190["running"] = (_gr190._grs_status.update({P9_GS: {"running": True}}) or
                         _C190["rs"].post(_url190, json=_ok190).status_code)
    _gr190._grs_status.pop(P9_GS, None)
    # The account can become root on its host: refused before anything (the guard every write passes).
    _p9_patch(_shr190, "game_account_write_refusal", lambda *a, **k: _i18n190.Sentence("p190 root-capable"))
    _rt190["rootcap"] = _post190("rs", _ok190)
    _p9_patch(_shr190, "game_account_write_refusal", lambda *a, **k: None)
    _rt190["info"] = _C190["rs"].get("/api/panel/backup/game/%d/info" % P9_GS).status_code
    _rt190["take"] = _C190["rs"].post("/api/panel/backup/game/%d" % P9_GS, json={"force": False}).status_code
    _rt190["page"] = _C190["rs"].get("/server/%d/files" % P9_GS).get_data(as_text=True)
    _rt190["page_dl"] = _C190["dlrm"].get("/server/%d/files" % P9_GS).get_data(as_text=True)
finally:
    _p9_restore_all()
    _gr190._grs_status.pop(P9_GS, None)

eq("route: RESTORE_BACKUP on its own starts the restore of a listed archive (typed name matching)",
   _rt190["rs"], (200, [_LIST190[0]["name"]]))
eq("route: download and delete without RESTORE_BACKUP cannot (refused before any work)", _rt190["dlrm"], (403, []))
eq("route: a superadmin can (control)", _rt190["admin"], (200, [_LIST190[0]["name"]]))
eq("route: a typed name that is not the server's, an archive not in its listing, and a name of the wrong "
   "shape are refused, nothing started",
   [_rt190[_k] for _k in ("wrong_name", "not_listed", "shape")], [(400, []), (404, []), (400, [])])
eq("route: a second restore while one runs is refused", _rt190["running"], 409)
eq("route: an account that can become root on its host is refused before any work (game_account_write_refusal)",
   _rt190["rootcap"], (409, []))
eq("route: RESTORE_BACKUP opens the backup listing; taking a backup stays superadmin-only",
   (_rt190["info"], _rt190["take"]), (200, 403))
check("page: a restore-only viewer sees the Backups tab with Restore, without download or delete",
      'data-sfsub-btn="backups"' in _rt190["page"] and "data-fpm-nors" not in _rt190["page"]
      and "data-fpm-nodl" in _rt190["page"] and "data-fpm-nodel" in _rt190["page"], "")
check("page: without RESTORE_BACKUP the Restore buttons are hidden (data-fpm-nors)",
      "data-fpm-nors" in _rt190["page_dl"], "")


# ── 4. the run, every host call stubbed ─────────────────────────────────────────────────────────
class _Host190:
    """What the stubbed host answers, and every call the run made, in order."""

    def __init__(self, vet="__GRS_READY__ 1 %d 5000 9000" % _T0190, stop=("", "", 0), backup=True,
                 restore="__GRS_CLEARING__\n__GRS_RESTORED__"):
        """Answers per step; the undo backup appears in the listing when `backup` succeeds."""
        self.calls, self.vet_out, self.stop, self.ok, self.restore_out = [], vet, stop, backup, restore
        self.keep, self.alerts = None, []
        self.listing = list(_LIST190)

    def shell(self, server, user, sh, timeout=30, selfname=None):
        if "tar --zstd -tv" in sh:
            self.calls.append("vet")
            return self.vet_out, "", 0
        if "__GRS_CLEARING__" in sh:
            self.calls.append("restore")
            return self.restore_out, "", 0
        self.calls.append("putback")
        return "", "", 0

    def lgsm(self, server, user, action, **k):
        self.calls.append(action)
        return self.stop if action == "stop" else ("", "", 0)

    def marked(self, sid, server, user, selfname, keep, made=None, **k):
        self.calls.append("backup")
        self.keep = keep
        self.held_seen = dict(_held190)
        if self.ok:
            # An upload finished while the backup ran: newer than the undo, and never taken for it.
            self.listing = [{"name": "p190-2026-11-14-000000.tar.zst", "size": 10, "created": 4},
                            {"name": "p190-2026-11-13-000000.tar.zst", "size": 3000, "created": 3}] + self.listing
            if made is not None:
                made.append("p190-2026-11-13-000000.tar.zst")
            return True, "", False
        return False, "LinuxGSM backup failed", False

    def listed(self, *a, **k):
        return list(self.listing)


_held190 = {}       # config.json["restores_held"], in memory for these checks


def _held_cfg190():
    return {"restores_held": _held190}


def _held_update190(mut):
    cfg = {"restores_held": dict(_held190)}
    mut(cfg)
    _held190.clear()
    _held190.update(cfg["restores_held"])


def _run190(host, refusal=None):
    """One _GrsRun through its steps against `host`: (calls, keep, ok, message, audit detail, alerts)."""
    from types import SimpleNamespace as _NS
    try:
        _p9_arm(who="part190")
        _p9_patch(_gr190, "load_config", _held_cfg190)
        _p9_patch(_gr190, "update_config", _held_update190)
        _p9_patch(_shr190, "game_account_write_refusal", lambda *a, **k: refusal)
        _p9_patch(_gr190, "shell_as_game_user", host.shell)
        _p9_patch(_gr190, "list_game_backups", host.listed)
        _p9_patch(_gr190, "_sm", _NS(run_as_game_user=host.lgsm))
        _p9_patch(_gr190, "_lgp", _NS(allowance_seconds=lambda *a, **k: 0,
                                      outcome_of=_gr190._lgp.outcome_of))
        _p9_patch(_gr190, "bk", _NS(game_prune_keep=lambda sid: (2, True)))
        _p9_patch(_gr190, "_grs_other_work", lambda gs: None)
        _p9_patch(_gr190, "_mark_expected_offline", lambda *a, **k: None)
        _p9_patch(_gr190, "_end_offline_window", lambda *a, **k: None)
        _p9_patch(_shr190, "_marked_backup", host.marked)
        _p9_patch(_shr190, "_alert_backup", lambda app, gs, title, body: host.alerts.append(title))
        with _p9.app_context():
            gs = _pdb190.session.get(_PGS190, P9_GS)
            run = _gr190._GrsRun(_p9, gs, P9_ADMIN, _LIST190[0]["name"], list(_LIST190))
            with _job190(P9_GS, _shr190.GRS_KIND):
                run.go()
            st = _gr190._grs_status.get(P9_GS) or {}
            row = _p9_audit("game_backup_restore")
            return host.calls, host.keep, st.get("ok"), st.get("msg", ""), row.detail, host.alerts
    finally:
        _p9_restore_all()
        _gr190._grs_status.pop(P9_GS, None)


_n_audit190 = _p9_audit_count("game_backup_restore")
_h = _Host190()
_w190 = {"ok": _run190(_h)}
_w190["vet_refused"] = _run190(_Host190(vet="__GRS_BAD__ name"))
_w190["backup_failed"] = _run190(_Host190(backup=False))
_w190["late_fail"] = _run190(_Host190(restore="__GRS_CLEARING__\n__GRS_XFAIL__ 2 tar: unexpected EOF"))
_w190["late_refused"] = _run190(_Host190(restore="__GRS_BUSY__"))
_w190["players"] = _run190(_Host190(stop=("[ INFO ] Stopping grsu: 2 players are on the server: stop prevented\n", "", 0)))
_w190["was_down"] = _run190(_Host190(vet="__GRS_READY__ 0 %d 5000 9000" % _T0190))
_w190["rootcap"] = _run190(_Host190(), refusal=_i18n190.Sentence("p190 root-capable"))
_w190["stage_fail"] = _run190(_Host190(restore="__GRS_STAGING__\n__GRS_STAGEFAIL__ 2 tar: Unexpected EOF in archive"))
_held_mid190 = dict(_h.held_seen) if hasattr(_h, "held_seen") else {}

eq("run: checks, stop, the undo backup, the restore, then start (it was running)",
   _w190["ok"][0], ["vet", "stop", "backup", "restore", "start"])
eq("run: the undo backup keeps every archive listed plus itself (nothing listed is pruned)", _w190["ok"][1], 3)
check("run: success is recorded, naming the archive and the undo archive",
      _w190["ok"][2] is True and "Restored from p190-2026-11-01-120000.tar.zst" in _w190["ok"][3]
      and "restore p190-2026-11-13-000000.tar.zst" in _w190["ok"][3]
      and "pre-restore backup: p190-2026-11-13-000000.tar.zst" in _w190["ok"][4], repr(_w190["ok"][2:5]))
eq("run: refused by its checks, nothing else happens (no stop, no backup), and it is alerted",
   (_w190["vet_refused"][0], _w190["vet_refused"][2], bool(_w190["vet_refused"][5])), (["vet"], False, True))
eq("run: a failed undo backup restores nothing: the archive is put back and the server started again",
   _w190["backup_failed"][0], ["vet", "stop", "backup", "putback", "start"])
check("run: ...and says nothing was changed", "Not restored: nothing was changed." in _w190["backup_failed"][3],
      _w190["backup_failed"][3])
eq("run: an extraction that failed after the clear leaves the server stopped (no start)",
   _w190["late_fail"][0], ["vet", "stop", "backup", "restore"])
check("run: ...and names the pre-restore archive to go back to",
      "partly replaced" in _w190["late_fail"][3] and "restore p190-2026-11-13-000000.tar.zst" in _w190["late_fail"][3]
      and _w190["late_fail"][2] is False, _w190["late_fail"][3])
eq("run: refused by the last command's checks (nothing cleared), the server is started again",
   _w190["late_refused"][0], ["vet", "stop", "backup", "restore", "start"])
eq("run: LinuxGSM refusing the stop for players restores nothing and puts the archive back (no start: it "
   "kept running)", _w190["players"][0], ["vet", "stop", "putback"])
eq("run: a server that reads as stopped still gets LinuxGSM's stop (it drops the monitoring lock LinuxGSM's monitor "
   "restarts a crashed server by), is restored and left stopped", _w190["was_down"][0],
   ["vet", "stop", "backup", "restore"])
eq("run: an account that can become root is refused in the run too, before the checks reach the host",
   (_w190["rootcap"][0], _w190["rootcap"][2]), ([], False))
check("run: the undo is the archive the backup path names, not a newer upload in the listing",
      "restore p190-2026-11-13-000000.tar.zst" in _w190["ok"][3] and "11-14" not in _w190["ok"][3], _w190["ok"][3])
check("run: while the archive is held, config.json names it (and none is left once the run ends)",
      (_held_mid190.get(str(P9_GS)) or {}).get("name") == _LIST190[0]["name"] and not _held190,
      repr((_held_mid190, _held190)))
eq("run: an archive that would not unpack into the staging folder restores nothing and starts the server again",
   (_w190["stage_fail"][0], "Not restored: nothing was changed." in _w190["stage_fail"][3],
    "could not be unpacked into a staging folder" in _w190["stage_fail"][3]),
   (["vet", "stop", "backup", "restore", "start"], True, True))
eq("run: every outcome writes an audit row", _p9_audit_count("game_backup_restore") - _n_audit190, 9)

# ── 5. while it runs, the server is held ────────────────────────────────────────────────────────
with _job190(P9_GS, _shr190.GRS_KIND):
    _hold190 = (str(_sd190._r39a_wipe_refusal(P9_GS, "p190", "restart") or ""), _shr190._r39a_backup_held(P9_GS),
                _shr190._r39a_backup_held(P9_GS, wipe_ok=True))
check("held: the server page's actions are refused in the restore's own words",
      "is being restored from a backup" in _hold190[0] and "'restart' was not run" in _hold190[0], _hold190[0])
eq("held: a backup of the server waits, except the restore's own undo backup", _hold190[1:], (True, False))

# ── 6. uploading a game server's backup, through the app, onto a stand-in host ──────────────────
def _tar190(members, compress="gz"):
    """A tar of `members` [(name, bytes)] ("./" names), compressed as asked ("gz", "plain")."""
    buf = _io190.BytesIO()
    with _tf190.open(fileobj=buf, mode="w", format=_tf190.GNU_FORMAT) as t:
        for mname, data in members:
            ti = _tf190.TarInfo(mname)
            ti.size, ti.mode = len(data), 0o644
            t.addfile(ti, _io190.BytesIO(data))
    raw = buf.getvalue()
    return _gz190.compress(raw) if compress == "gz" else raw


def _bomb190(prefix="./", size=10 * 1024 ** 3):
    """A gzip'd tar whose one header declares `size` bytes: its data is never there (a bomb's shape)."""
    ti = _tf190.TarInfo(prefix + "huge")
    ti.size = size
    return _gz190.compress(ti.tobuf(format=_tf190.GNU_FORMAT) + b"\0" * 1024)


_up190 = {}
with _p9.app_context():
    _gsrow190 = _pdb190.session.get(_PGS190, P9_GS)
    _short190, _self190 = _gsrow190.short_name, _gsrow190.lgsm_name or _gsrow190.short_name
    _rid190 = _gsrow190.remote_id
_root190 = _tmp190.mkdtemp(prefix="p190-up-")
_uhome190 = _os190.path.join(_root190, "home", _short190)
_os190.makedirs(_uhome190)
_ubdir190 = _os190.path.join(_uhome190, "lgsm", "backup")


_blank190 = []          # a finish whose answer is lost once: its command is not run, nothing comes back
_chunks190 = []         # the largest stdin chunk each piece's command was handed


def _fake_run190(server, cmd, timeout=30, sudo=None, stdin_text=None):
    """run_command for the upload routes: the panel-built script, run by bash on the stand-in home."""
    if _blank190 and "__GRS_UPSTORED__" in cmd:
        _blank190.pop()
        return "", "", -1
    if stdin_text is not None and not isinstance(stdin_text, str):
        _parts = [bytes(c) for c in stdin_text]
        _chunks190.append(max(len(c) for c in _parts))
        stdin_text = b"".join(_parts).decode("ascii")
    p = _sp190.run(["bash", "-c", cmd.replace("/home/" + _short190, _uhome190)], input=stdin_text,
                   capture_output=True, text=True, timeout=120, cwd="/")
    return p.stdout, p.stderr, p.returncode


def _upload190(client, data, chunk=None, start_extra=None):
    """Start, send every piece, finish: [(status, json) per request]."""
    base = "/api/panel/backup/game/%d/upload" % P9_GS
    r = client.post(base, json=dict({"size": len(data)}, **(start_extra or {})))
    out = [(r.status_code, r.get_json(silent=True) or {})]
    uid = out[0][1].get("id")
    if not uid:
        return out
    step = chunk or len(data)
    for at in range(0, len(data), step):
        r = client.post("%s/%s?offset=%d" % (base, uid, at), data=data[at:at + step],
                        content_type="application/octet-stream")
        out.append((r.status_code, r.get_json(silent=True) or {}))
    r = client.post("%s/%s/finish" % (base, uid), json={})
    out.append((r.status_code, r.get_json(silent=True) or {}))
    return out


try:
    if _missing190:
        raise RuntimeError("tools missing")
    from types import SimpleNamespace as _NSU
    from panel.routes import backup_upload as _bu190
    from panel.ops import ssh_manager as _sm190
    _p9_arm(who="part190")
    _p9_patch(_bu190, "_sm", _NSU(game_user_cmd=lambda user, inner: inner, run_command=_fake_run190,
                                  _fmt_size=_sm190._fmt_size))
    _p9_patch(_shr190, "game_account_write_refusal", lambda *a, **k: None)
    _CU190 = {_k: _p9_client(_v) for _k, _v in _uids190.items()}
    _good190 = _tar190([("././", b""), ("././" + _self190, b"#!/bin/bash\n"), ("././serverfiles/a", b"a" * 9000)])
    _n_up190 = _p9_audit_count("game_backup_upload")
    _res = _upload190(_CU190["rsedit"], _good190, chunk=4096, start_extra={"name": "../../../etc/cron.d/x.tar.gz"})
    _up190["ok"] = ([_c for _c, _j in _res], _res[-1][1].get("name", ""), sorted(_os190.listdir(_ubdir190)))
    _up190["ok_audit"] = _p9_audit_count("game_backup_upload") - _n_up190
    _plain = _tar190([("./", b""), ("./" + _self190, b"#!/bin/bash\n")], compress="plain")
    _up190["plain"] = _upload190(_CU190["rsedit"], _plain)[-1][1].get("name", "")
    _up190["dlrm"] = _upload190(_CU190["dlrm"], _good190)[0][0]
    _up190["rs_only"] = _upload190(_CU190["rs"], _good190)[0][0]
    _p9_patch(_shr190, "game_account_write_refusal", lambda *a, **k: _i18n190.Sentence("p190 root-capable"))
    _parts0 = sorted(_os190.listdir(_ubdir190))
    _up190["rootcap"] = (_upload190(_CU190["rsedit"], _good190)[0][0], sorted(_os190.listdir(_ubdir190)) == _parts0)
    _p9_patch(_shr190, "game_account_write_refusal", lambda *a, **k: None)
    # A plain tar when the disk has no room for its gzip copy (the margin raised for the finish only).
    _before_gz = sorted(_os190.listdir(_ubdir190))
    _saved_m = _grs190.MARGIN
    _base0 = "/api/panel/backup/game/%d/upload" % P9_GS
    _uid0 = _CU190["rsedit"].post(_base0, json={"size": len(_plain)}).get_json()["id"]
    _CU190["rsedit"].post("%s/%s?offset=0" % (_base0, _uid0), data=_plain, content_type="application/octet-stream")
    try:
        _grs190.MARGIN = 10 ** 18
        _fin = _CU190["rsedit"].post("%s/%s/finish" % (_base0, _uid0), json={}).get_json() or {}
    finally:
        _grs190.MARGIN = _saved_m
    _up190["gz_space"] = (_fin.get("success"), "not enough free space" in _fin.get("message", ""),
                          sorted(_os190.listdir(_ubdir190)) == _before_gz)
    # A finish whose answer was lost keeps the upload: asked again, it is stored.
    _blank190.append(1)
    _r = _upload190(_CU190["rsedit"], _good190)
    _again = _CU190["rsedit"].post("/api/panel/backup/game/%d/upload/%s/finish" % (P9_GS, _r[0][1]["id"]), json={})
    _up190["retry"] = (_r[-1][1].get("retry"), (_again.get_json() or {}).get("success"))
    # Cancelled: its part file is gone, and another upload may start at once.
    _uid1 = _CU190["rsedit"].post(_base0, json={"size": 8192}).get_json()["id"]
    _CU190["rsedit"].post("%s/%s?offset=0" % (_base0, _uid1), data=b"x" * 4096, content_type="application/octet-stream")
    _parts = [_f for _f in _os190.listdir(_ubdir190) if _f.startswith(".panel-upload-")]
    _cx = _CU190["rsedit"].post("%s/%s/cancel" % (_base0, _uid1), json={})
    _again = _CU190["rsedit"].post(_base0, json={"size": 10})
    _up190["cancel"] = (bool(_parts), _cx.status_code,
                        [_f for _f in _os190.listdir(_ubdir190) if _f.startswith(".panel-upload-") and _uid1 in _f],
                        _again.status_code)
    _CU190["rsedit"].post("%s/%s/cancel" % (_base0, (_again.get_json() or {}).get("id", "x")), json={})
    _up190["oversize"] = _CU190["rsedit"].post("/api/panel/backup/game/%d/upload" % P9_GS,
                                           json={"size": _grs190.UPLOAD_MAX + 1}).status_code
    _before = sorted(_os190.listdir(_ubdir190))
    for _k, _data in (("format", b"this is not an archive at all" * 50),
                      ("bomb", _bomb190("././")),
                      ("escape", _tar190([("././", b""), ("././" + _self190, b"x"), ("././../../evil", b"x")])),
                      ("noscript", _tar190([("././", b""), ("././serverfiles/a", b"a")]))):
        _r = _upload190(_CU190["rsedit"], _data)
        _up190[_k] = (_r[-1][0], _r[-1][1].get("success"), _r[-1][1].get("message", ""),
                      sorted(_os190.listdir(_ubdir190)) == _before)
    # A piece sent twice (its answer lost): the second is not appended, and the page is told where to go on.
    _base = "/api/panel/backup/game/%d/upload" % P9_GS
    _uid = _CU190["rsedit"].post(_base, json={"size": 8192}).get_json()["id"]
    _a = _CU190["rsedit"].post("%s/%s?offset=0" % (_base, _uid), data=b"x" * 4096, content_type="application/octet-stream")
    _b = _CU190["rsedit"].post("%s/%s?offset=0" % (_base, _uid), data=b"x" * 4096, content_type="application/octet-stream")
    _up190["resume"] = (_a.status_code, _b.status_code, (_b.get_json() or {}).get("received"))
    # A piece larger than one 64 KB chunk of base64: still handed over in chunks.
    del _chunks190[:]
    _uidb = _CU190["rsedit"].post(_base, json={"size": 200000}).get_json()["id"]
    _CU190["rsedit"].post("%s/%s?offset=0" % (_base, _uidb), data=_os190.urandom(200000),
                          content_type="application/octet-stream")
    _CU190["rsedit"].post("%s/%s/cancel" % (_base, _uidb), json={})
    _up190["big_chunks"] = list(_chunks190)
    # Finished before every byte arrived: refused, and its part file removed.
    _fin = _CU190["rsedit"].post("%s/%s/finish" % (_base, _uid), json={}).get_json() or {}
    _up190["early"] = (_fin.get("success"), [_f for _f in _os190.listdir(_ubdir190) if _uid in _f])
    _uid = _CU190["rsedit"].post(_base, json={"size": 8192}).get_json()["id"]
    _up190["traversal_id"] = _CU190["rsedit"].post(_base + "/..%2F..%2Fetc%2Fpasswd?offset=0", data=b"x",
                                               content_type="application/octet-stream").status_code
    _up190["big_piece"] = _CU190["rsedit"].post("%s/%s?offset=4096" % (_base, _uid), data=b"x" * (_grs190.UPLOAD_CHUNK + 1),
                                            content_type="application/octet-stream").status_code
except RuntimeError as _e:
    skip("game backup upload: driven onto a stand-in host", str(_e))
finally:
    _p9_restore_all()
    _sh190.rmtree(_root190, ignore_errors=True)
    __import__("panel.routes.backup_upload", fromlist=["_uploads"])._uploads.clear()

if "ok" in _up190:
    _pat190 = r"%s-\d{4}-\d{2}-\d{2}-\d{6}\.tar\.gz\Z" % _self190
    check("upload: RESTORE_BACKUP uploads in pieces; the archive is stored under a LinuxGSM backup's name "
          "(the browser's name and path ignored), and nothing else is left in the backup dir",
          set(_c for _c in _up190["ok"][0]) == {200} and _re190.match(_pat190, _up190["ok"][1])
          and _up190["ok"][2] == [_up190["ok"][1]], repr(_up190["ok"]))
    eq("upload: ...and it is audited", _up190["ok_audit"], 1)
    check("upload: a plain tar is accepted and stored compressed (.tar.gz)",
          bool(_re190.match(_pat190, _up190["plain"])), _up190["plain"])
    eq("upload: download and delete without RESTORE_BACKUP cannot start one", _up190["dlrm"], 403)
    eq("upload: RESTORE_BACKUP without EDIT_FILES cannot either (an uploaded archive is any file, the scripts the "
       "server runs included)", _up190["rs_only"], 403)
    eq("upload: an account that can become root on its host is refused before anything is written",
       _up190["rootcap"], (409, True))
    eq("upload: a plain tar is refused when there is no room for its gzip copy, and nothing is left behind",
       _up190["gz_space"], (False, True, True))
    eq("upload: a finish whose answer was lost says so (retry) and keeps the upload, which a second finish stores",
       _up190["retry"], (True, True))
    eq("upload: a cancelled upload's part file is removed and another upload may start at once",
       _up190["cancel"], (True, 200, [], 200))
    eq("upload: a size over the cap is refused before the host", _up190["oversize"], 400)
    _uwhy190 = {"format": "not a tar archive", "bomb": "far more than any game server",
                "escape": "not under the server's folder", "noscript": "LinuxGSM script"}
    eq("upload: not a tar, a decompression bomb's shape, a member escaping its folder, and an archive of "
       "another server are refused with their reason, and nothing is listed",
       {_k: (_up190[_k][1], _w in _up190[_k][2], _up190[_k][3]) for _k, _w in _uwhy190.items()},
       {_k: (False, True, True) for _k in _uwhy190})
    eq("upload: a piece sent twice is not appended twice; the page is told how much the host holds",
       _up190["resume"], (200, 409, 4096))
    eq("upload: finished before every byte arrived, it is refused and its part file removed", _up190["early"], (False, []))
    check("upload: a piece goes to the host as base64 in chunks of at most 64 KB, never as one string (a 200 KB "
          "piece included)", _up190["big_chunks"] and max(_up190["big_chunks"]) <= 65536 and max(_chunks190) <= 65536,
          repr((_up190["big_chunks"], _chunks190[:5])))
    eq("upload: an upload id that is a path, and a piece over 4 MB, are refused",
       (_up190["traversal_id"], _up190["big_piece"]), (404, 413))


# ── 7. uploading a panel backup (superadmin), into a throwaway backup dir ────────────────────────
from panel.ops import backup as _bk190
_pbdir190 = _tmp190.mkdtemp(prefix="p190-pb-")
_pup190 = {}


def _pupload190(client, data):
    base = "/api/panel/backup/upload"
    r = client.post(base, json={"size": len(data)})
    j = r.get_json(silent=True) or {}
    if not j.get("id"):
        return r.status_code, j
    client.post("%s/%s?offset=0" % (base, j["id"]), data=data, content_type="application/octet-stream")
    r = client.post("%s/%s/finish" % (base, j["id"]), json={})
    return r.status_code, r.get_json(silent=True) or {}


try:
    _p9_arm(who="part190")
    _p9_patch(_bk190, "BACKUP_DIR", __import__("pathlib").Path(_pbdir190))
    _CA190 = _p9_client(P9_ADMIN)
    _CR190 = _p9_client(_uids190["rs"])
    _cfg = b'{"backup": {}}'
    _n_pb190 = _p9_audit_count("panel_backup_upload")
    _pup190["plain"] = _pupload190(_CA190, _tar190([("config.json", _cfg)]))
    _pup190["plain_audit"] = _p9_audit_count("panel_backup_upload") - _n_pb190
    _enc_head = (b"LGSMBK1\n" + b'{"kdf": "scrypt", "salt": "c2FsdHNhbHQ=", "n": 32768, "r": 8, "p": 1}\n'
                 + b"gAAAAABtokentokentoken")
    _pup190["enc"] = _pupload190(_CA190, _enc_head)
    _listed = sorted(_os190.listdir(_pbdir190))
    for _k, _data in (("format", b"plain text, not a backup" * 20),
                      ("enc_params", _enc_head.replace(b'"n": 32768', b'"n": 1048576')),
                      ("bomb", _bomb190("")),
                      ("escape", _tar190([("../config.json", _cfg)])),
                      ("extra", _tar190([("config.json", _cfg), ("evil.sh", b"x")]))):
        _pup190[_k] = _pupload190(_CA190, _data) + (sorted(_os190.listdir(_pbdir190)) == _listed,)
    _pup190["not_su"] = _CR190.post("/api/panel/backup/upload", json={"size": 10}).status_code
    _pup190["oversize"] = _CA190.post("/api/panel/backup/upload", json={"size": _bk190.UPLOAD_MAX + 1}).status_code
    _pup190["traversal_id"] = _CA190.post("/api/panel/backup/upload/..%2F..%2Fpanel.db?offset=0", data=b"x",
                                          content_type="application/octet-stream").status_code
finally:
    _p9_restore_all()
    _sh190.rmtree(_pbdir190, ignore_errors=True)

_pname190 = r"panel-backup-\d{8}-\d{6}-upload\.tar\.gz"
check("panel upload: a superadmin's panel backup is checked and listed under a generated name",
      _pup190["plain"][1].get("success") is True and bool(_re190.match(_pname190 + r"\Z", _pup190["plain"][1].get("name", ""))),
      repr(_pup190["plain"]))
eq("panel upload: ...audited", _pup190["plain_audit"], 1)
check("panel upload: an encrypted one is taken on its header and listed as encrypted (.enc)",
      bool(_re190.match(_pname190 + r"\.enc\Z", _pup190["enc"][1].get("name", ""))), repr(_pup190["enc"]))
_pwhy190 = {"format": "Could not read the backup archive", "enc_params": "parameters this panel will not use", "bomb": "far more than a panel backup",
            "escape": "invalid", "extra": "invalid"}
eq("panel upload: not a backup, an encrypted header asking for costly parameters, a decompression bomb's shape, "
   "a member escaping the archive and a member restore does not know are refused, nothing listed",
   {_k: (_pup190[_k][1].get("success"), _w in _pup190[_k][1].get("message", ""), _pup190[_k][2])
    for _k, _w in _pwhy190.items()}, {_k: (False, True, True) for _k in _pwhy190})
eq("panel upload: not a superadmin, a size over the cap and an upload id that is a path are refused",
   (_pup190["not_su"], _pup190["oversize"], _pup190["traversal_id"]), (403, 400, 404))

# ── 8. a restore a panel restart cut off; no panel restart under a running restore ─────────────────
_rec190 = {"shell": [], "alerts": []}
try:
    _p9_arm(who="part190")
    _p9_patch(_gr190, "load_config", _held_cfg190)
    _p9_patch(_gr190, "update_config", _held_update190)
    _p9_patch(_gr190, "shell_as_game_user", lambda srv, user, sh, **k: (_rec190["shell"].append(sh) or ("", "", 0)))
    _p9_patch(_shr190, "_alert_backup", lambda app, gs, title, body: _rec190["alerts"].append(body))
    _held190.clear()
    _held190[str(P9_GS)] = {"name": _LIST190[0]["name"], "t0": _T0190, "undo": "p190-2026-11-13-000000.tar.zst",
                            "actor": P9_ADMIN, "short_name": _short190, "remote_id": _rid190, "at": 1}
    # A restore of that server still running in this process is left alone...
    _gr190._grs_status[P9_GS] = {"running": True}
    _gr190._grs_recover_pass(_p9)
    _rec190["while_running"] = (len(_rec190["shell"]), bool(_held190))
    # ...and with no run holding it, it is recovered.
    _gr190._grs_status.pop(P9_GS, None)
    _n_rec190 = _p9_audit_count("game_backup_restore")
    _gr190._grs_recover_pass(_p9)
    _rec190["audit"] = _p9_audit_count("game_backup_restore") - _n_rec190
    _rec190["row"] = _p9_audit("game_backup_restore").detail
    _rec190["status"] = (_gr190._grs_status.get(P9_GS) or {}).get("msg", "")
    _rec190["left"] = dict(_held190)
    # While a restore runs, the panel does not restart itself (the update route, and every route behind
    # panel_host_busy: branch switch, repair, panel restore, binding change, the bots' update).
    from panel.ops import system_ops as _so190
    _upd190 = []
    _p9_patch(_so190, "panel_self_update", lambda *a, **k: (_upd190.append(1) or (True, "ok")))
    _gr190._grs_status[P9_GS] = {"running": True}
    _r = _p9_client(P9_ADMIN).post("/api/panel/update", json={})
    _rec190["update"] = (_r.status_code, list(_upd190))
    _gr190._grs_status.pop(P9_GS, None)
finally:
    _p9_restore_all()
    _gr190._grs_status.pop(P9_GS, None)
    _held190.clear()

eq("recovery: a recorded restore that a run of this process still holds is left alone",
   _rec190["while_running"], (0, True))
check("recovery: with no run holding it, the archive is put back under its own name and time",
      len(_rec190["shell"]) == 1 and '"$B"/*.restore-source-*' in _rec190["shell"][0]
      and 'touch -m -d "@${t/_/.}"' in _rec190["shell"][0], repr(_rec190["shell"]))
check("recovery: ...recorded as interrupted (audit, alert, the card), naming the pre-restore archive, and forgotten",
      _rec190["audit"] == 1 and "interrupted" in _rec190["row"] and "p190-2026-11-13-000000.tar.zst" in _rec190["row"]
      and _rec190["alerts"] and "restore p190-2026-11-13-000000.tar.zst" in _rec190["status"] and not _rec190["left"],
      repr(_rec190))
eq("restart: the panel's self-update is refused while a game server is being restored (nothing launched)",
   _rec190["update"], (409, []))

# ── 8b. a command's stdin is written in slices, never whole (the panel's memory) ─────────────────
from panel.ops.ssh_manager import _core as _core190
_big190 = bytes(range(256)) * 1000
_sl190 = [bytes(_p) for _p in _core190._stdin_pieces(_big190)]
_ch190 = _core190.StdinChunks([b"a" * 10, b"b" * 20])
eq("stdin: bytes are written in slices of at most 64 KB that join to the whole; chunks are written as given",
   (max(len(_p) for _p in _sl190) <= 65536, b"".join(_sl190) == _big190, len(_sl190) > 1,
    [bytes(_p) for _p in _core190._stdin_pieces(_ch190)], _core190._stdin_bytes("é")),
   (True, True, True, [b"a" * 10, b"b" * 20], "é".encode("utf-8")))

# ── 9. the panel's Backups page offers Restore on each game backup; the card stacks on a phone ────────
from unit.part47 import _SETTLE47 as _SET190, _cut47 as _cut190, _node47 as _node190
with open(_os190.path.join(_os190.path.dirname(_auth190.__file__), "..", "static", "js", "remote_manage_backups.js"),
          encoding="utf-8") as _f190:
    _RMB190 = _f190.read()
_ui190 = _node190(_SET190 + (
    "global.window = global; global.MOUNT = ''; global.escapeHtml = s => String(s); global.bkFmtBytes = b => b + ' B';\n"
    "global.bkAgo = () => ''; global._da = (f) => ' data-action=\"' + f + '\"'; global.tf = s => s;\n"
    "global.bkMsg = () => {}; global.loadBackups = () => {}; let posted = [], need = null;\n"
    "global.confirmDialog = o => { need = o.requireText; o.onConfirm(); };\n"
    "global.fetch = (u, o) => { posted.push([u, JSON.parse(o.body)]); return Promise.resolve({json: () => ({success: true})}); };\n"
    + _cut190(_RMB190, "function bkGameRows(") + "\n" + _cut190(_RMB190, "function restoreGameBackup(") + "\n"
    "const html = bkGameRows({id: 7, name: 'My Server', backups: [{name: 'ms-2026-11-01-000000.tar.gz', size: 1, created: 0}]});\n"
    "const at = {'data-name': 'ms-2026-11-01-000000.tar.gz', 'data-gid': '7', 'data-server': 'My Server'};\n"
    "restoreGameBackup({getAttribute: k => at[k]});\n"
    "(async () => { await settle(); console.log(JSON.stringify({button: html.includes('data-action=\"restoreGameBackup\"')\n"
    "  && html.includes('data-server=\"My Server\"'), need, posted})); })();\n"))
if _ui190 is None:
    skip("panel Backups page: Restore on a game backup", "node is not installed here")
else:
    eq("panel Backups page: each game backup has a Restore that asks for the server's name and posts the "
       "restore route with it", _ui190, {"button": True, "need": "My Server", "posted": [
           ["/api/panel/backup/game/7/restore", {"name": "ms-2026-11-01-000000.tar.gz", "confirm": "My Server"}]]})
with open(_os190.path.join(_os190.path.dirname(_auth190.__file__), "..", "static", "css", "panel.css"),
          encoding="utf-8") as _f190:
    _css190 = _f190.read()
_mob190 = _css190[_css190.find("@media (max-width: 575.98px) {\n  #backup-card thead"):]
check("Backups card on a phone: rows wrap (name on its own line, the buttons below it) with 40px buttons",
      "#backup-card #bk-rows tr { display: flex; flex-wrap: wrap;" in _mob190
      and "#backup-card #bk-rows td:first-child { flex: 0 0 100%; }" in _mob190
      and "min-width: 40px; min-height: 40px;" in _mob190, "")

with _p9.app_context():
    for _u in _PU190.query.filter(_PU190.username.like("p190_%")).all():
        _pdb190.session.delete(_u)
    for _g in _PG190.query.filter(_PG190.name.like("p190_%")).all():
        _pdb190.session.delete(_g)
    _pdb190.session.commit()
