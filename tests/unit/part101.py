"""Part 101 of the unit suite: the sixteenth review's fixes by builder A (review 1016e).

The helper's link checks, install and uninstall, and the monitor. Held here, each against the code
path the finding named:

* the helper's offline DB repair resolves data/ ITSELF as restore and self-update resolve theirs: a
  root-made data/ link whose target goes through a link the panel user made is refused, and the
  account the repair runs as is read by descriptor from the resolved directory, not through the
  link's chain; the reclaim opens that directory one component at a time.
* a link counts as root's only under its one name: a hard link to a root-owned symlink (which the
  panel user can make with fs.protected_hardlinks=0) is refused by the helper's walk and by
  install.sh's snapshot prune.
* install.sh's port picker refuses a config.json that does not read as an object instead of
  replacing every setting in it with {"port": N}.
* uninstall.sh reads config.json's port by install.sh's rule (a port the panel would not bind is
  5000, what it binds), not with a raw int().
* the monitor's maintenance probe asks again without sudo when the row's sudo answered nothing, so
  a LinuxGSM cron update on a remote whose sudo needs a password is not paged as an outage.

HOW IT RUNS. The helper on stand-ins, undone in a finally; install.sh's and uninstall.sh's own text
under bash in throwaway directories; the monitor with its transport stubbed. Nothing reaches this
machine's sudo, tailscale or the checkout's data/.
"""
import atexit as _atexit101
import contextlib as _ctx101
import io as _io101
import json as _json101
import os
import pwd as _pwd101
import shlex as _shlex101
import shutil as _shutil101
import subprocess as _sp101  # nosec B404 - bash over the repo's own install.sh/uninstall.sh text
import tempfile as _tf101
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper as _helper101, _root

_TMP101 = _tf101.mkdtemp(prefix="p101-")
_atexit101.register(_shutil101.rmtree, _TMP101, True)


def _read101(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _fn101(src, name):
    """The text of shell function `name` in `src`, from its `name() {` line to its closing `}`."""
    i = src.find("\n%s() {" % name)
    if i < 0:
        return "%s() { exit 101; }\n" % name
    return src[i + 1:src.index("\n}\n", i) + 3]


def _bash101(script, env=None):
    """Run `script` under bash; the CompletedProcess."""
    return _sp101.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,  # nosec B603 B607
                      env=dict(os.environ, **(env or {})))


_INS101 = _read101("install.sh")
_UNI101 = _read101("uninstall.sh")
_ME101 = _pwd101.getpwuid(os.getuid())


class _Os101:
    """The helper's `os`, whose lstat reports the paths in `root` as root's (uid 0), nlink as is."""

    def __init__(self, real, root):
        self._real = real
        self._root = root

    def lstat(self, path, *a, **k):
        st = self._real.lstat(path, *a, **k)
        if path not in self._root:
            return st
        f = list(st[:10])
        f[4] = 0
        return self._real.stat_result(f)

    def __getattr__(self, name):
        return getattr(self._real, name)


def _repair101(db_path, root_made=(), lstat_root=()):
    """(_db_repair_target(), _db_repair_account(db_path)) with panel.conf's db_path `db_path`.

    `root_made`: links _r26a_link_root_made answers "root made it" for (a root-made link cannot be
    made here without root). `lstat_root`: paths the helper's lstat reports as root's instead, so
    the real _r26a_link_root_made judges them.
    """
    dbm = os.path.join(_TMP101, "db_maintenance.py")
    open(dbm, "w").close()
    saved = {k: getattr(_helper101, k) for k in ("panel_conf", "DBM_PATH", "_r26a_link_root_made",
                                                 "os")}
    real_root_made = _helper101._r26a_link_root_made
    try:
        _helper101.panel_conf = lambda: {"db_path": db_path}
        _helper101.DBM_PATH = dbm
        if root_made:
            _helper101._r26a_link_root_made = lambda p: p in root_made or real_root_made(p)
        if lstat_root:
            _helper101.os = _Os101(os, set(lstat_root))
        with _ctx101.redirect_stderr(_io101.StringIO()):
            return _helper101._db_repair_target(), _helper101._db_repair_account(db_path)
    finally:
        for k, v in saved.items():
            setattr(_helper101, k, v)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The helper's offline DB repair walks data/ itself, as restore and self-update do
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The operator moved data/ to a disk: panel/data is root's link to <disk>/data. <disk> is the panel
# user's, which swapped <disk>/data for its own link to <other>/data, another account's directory
# holding a panel.db. Only the directory ABOVE data/ was checked, and data/'s owner was read with
# os.stat through the whole chain: the repair ran on, and as the owner of, <other>/data.
_b101 = _tf101.mkdtemp(dir=_TMP101)
os.makedirs(os.path.join(_b101, "other", "data"))
open(os.path.join(_b101, "other", "data", "panel.db"), "wb").close()
os.makedirs(os.path.join(_b101, "disk"))
os.symlink(os.path.join(_b101, "other", "data"), os.path.join(_b101, "disk", "data"))
os.makedirs(os.path.join(_b101, "panel"))
os.symlink(os.path.join(_b101, "disk", "data"), os.path.join(_b101, "panel", "data"))
_beyond101 = _repair101(os.path.join(_b101, "panel", "data", "panel.db"),
                        root_made={os.path.join(_b101, "panel", "data")})
check("panel-helper: the DB repair refuses a root-made data/ link whose target goes through a link "
      "the panel user made (only the directory above data/ was walked, so the chain was followed)",
      _beyond101[0] is None, repr(_beyond101))
check("panel-helper: ...and decides no account through it (data/'s owner was read with os.stat "
      "through the whole chain, so the panel user chose whom the repair ran as)",
      _beyond101[1] is None, repr(_beyond101))

# The control: the same root-made link straight to <disk>/data is followed, and the job is handed
# the RESOLVED path, so its account, reclaim and repair name the directory that was checked.
_c101 = _tf101.mkdtemp(dir=_TMP101)
os.makedirs(os.path.join(_c101, "disk", "data"))
open(os.path.join(_c101, "disk", "data", "panel.db"), "wb").close()
os.makedirs(os.path.join(_c101, "panel"))
os.symlink(os.path.join(_c101, "disk", "data"), os.path.join(_c101, "panel", "data"))
_ctl101 = _repair101(os.path.join(_c101, "panel", "data", "panel.db"),
                     root_made={os.path.join(_c101, "panel", "data")})
_ctlreal101 = os.path.join(os.path.realpath(_c101), "disk", "data", "panel.db")
check("panel-helper: ...while a root-made data/ link straight to the real directory is repaired, "
      "at the resolved path, as that directory's owner (control)",
      _ctl101[0] == _ctlreal101 and getattr(_ctl101[1], "pw_uid", None) == _ME101.pw_uid,
      repr((_ctl101, _ctlreal101)))

# The reclaim, root's last step before the drop, opens the directory one component at a time: a
# link swapped into the resolved path after the checks is refused, not followed to the files of
# whatever it names. (It opened the directory by path, which follows every link in it.)
_r101 = _tf101.mkdtemp(dir=_TMP101)
os.makedirs(os.path.join(_r101, "real"))
open(os.path.join(_r101, "real", "panel.db"), "wb").close()
os.symlink(os.path.join(_r101, "real"), os.path.join(_r101, "swapped"))
_chowned101 = []
_saved_os101 = _helper101.os


class _OsReclaim101(_Os101):
    """fstat reports regular files as root's (an earlier root-run repair's); fchown records."""

    def fstat(self, fd):
        st = self._real.fstat(fd)
        if not (st.st_mode & 0o170000) == 0o100000:
            return st
        f = list(st[:10])
        f[4] = 0
        return self._real.stat_result(f)

    def fchown(self, fd, uid, gid):
        _chowned101.append(self._real.fstat(fd).st_ino)


try:
    _helper101.os = _OsReclaim101(os, set())
    _helper101._db_repair_reclaim(os.path.join(_r101, "swapped", "panel.db"), _ME101)
    _via_link101 = list(_chowned101)
    del _chowned101[:]
    _helper101._db_repair_reclaim(os.path.join(_r101, "real", "panel.db"), _ME101)
    _direct101 = list(_chowned101)
finally:
    _helper101.os = _saved_os101
check("panel-helper: the repair's reclaim hands nothing over through a link swapped into the "
      "checked path; through the real directory it does (control)",
      _via_link101 == [] and len(_direct101) == 1, repr((_via_link101, _direct101)))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A hard link to a root-owned symlink is not "a link root made"
# ════════════════════════════════════════════════════════════════════════════════════════════════
# With fs.protected_hardlinks=0 the panel user may hard-link any root-owned symlink on the same
# filesystem into its own tree. The copy is a symlink entry with root as its owner, and st_uid == 0
# alone read it as an operator's link. Here this account makes both links, and the helper's lstat
# reports them as root's: the copy shares the inode, so it (and its original) have two names.
_h101 = _tf101.mkdtemp(dir=_TMP101)
os.makedirs(os.path.join(_h101, "elsewhere"))
open(os.path.join(_h101, "elsewhere", "panel.db"), "wb").close()
os.symlink(os.path.join(_h101, "elsewhere"), os.path.join(_h101, "rootlink"))
os.makedirs(os.path.join(_h101, "panel"))
os.link(os.path.join(_h101, "rootlink"), os.path.join(_h101, "panel", "data"), follow_symlinks=False)
os.makedirs(os.path.join(_h101, "panel2"))
os.symlink(os.path.join(_h101, "elsewhere"), os.path.join(_h101, "panel2", "data"))
_hl101 = os.path.join(_h101, "panel", "data")
_one101 = os.path.join(_h101, "panel2", "data")
_premise101 = os.lstat(_hl101)
check("panel-helper (premise): a hard link to a symlink is itself a symlink entry with two names",
      (_premise101.st_mode & 0o170000) == 0o120000 and _premise101.st_nlink == 2, repr(_premise101))
_saved_os101 = _helper101.os
try:
    _helper101.os = _Os101(os, {_hl101, _one101})
    _made101 = (_helper101._r26a_link_root_made(_hl101), _helper101._r26a_link_root_made(_one101))
finally:
    _helper101.os = _saved_os101
check("panel-helper: a root-owned link with a second name (a hard-linked copy) is not root-made; "
      "one with its only name is (control)", _made101 == (False, True), repr(_made101))
_hard101 = _repair101(os.path.join(_hl101, "panel.db"), lstat_root={_hl101})
_single101 = _repair101(os.path.join(_one101, "panel.db"), lstat_root={_one101})
check("panel-helper: the DB repair refuses a data/ that is a hard-linked copy of a root-owned "
      "symlink, and decides no account through it",
      _hard101 == (None, None), repr(_hard101))
check("panel-helper: ...and follows the same root-owned link under its only name (control)",
      _single101[0] == os.path.join(os.path.realpath(_h101), "elsewhere", "panel.db")
      and _single101[1] is not None, repr(_single101))

# install.sh's snapshot prune trusts PANEL_DIR's link by the same rule. `stat` here reports root
# as the owner of everything and the real link count.
_trust101 = _fn101(_INS101, "_r26a_link_trusted")
_as_root101 = "stat() { command stat \"$@\" | sed 's/^[0-9]*/0/'; }\n"
_lt101 = {}
for _k101, _p101, _who101, _hook101 in (("hard, root", _hl101, "0", _as_root101),
                                        ("single, root", _one101, "0", _as_root101),
                                        ("hard, own", _hl101, str(os.getuid()), "")):
    _lt101[_k101] = _bash101("%s%s_r26a_link_trusted %s %s; echo \"RC=$?\"\n"
                             % (_hook101, _trust101, _p101, _who101)).stdout.strip()
check("install.sh: the snapshot prune does not trust a root-owned link with a second name (a "
      "hard-linked copy the panel user made); one with its only name it does (control)",
      _lt101["hard, root"] == "RC=1" and _lt101["single, root"] == "RC=0", repr(_lt101))
check("install.sh: ...and a per-user run still trusts the running account's own link, whatever its "
      "link count (control)", _lt101["hard, own"] == "RC=0", repr(_lt101))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. install.sh's port picker keeps a config.json it cannot read
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The fresh path (which the panel user can force by deleting its own app.py) read an unparseable
# config.json as {} and replaced it with {"port": N}: setup_complete, the Tailscale keys and every
# other setting gone, where the panel itself keeps the file for a one-character fix. A valid
# non-object died in a traceback.
_pick101 = _fn101(_INS101, "choose_and_record_port")


def _pick_run101(content):
    """(output, config.json afterwards) for one port pick over a config.json holding `content`."""
    d = _tf101.mkdtemp(dir=_TMP101)
    os.makedirs(os.path.join(d, "data"))
    cfg = os.path.join(d, "data", "config.json")
    with open(cfg, "w", encoding="utf-8") as fh:
        fh.write(content)
    r = _bash101("PANEL_DIR=%s\n%schoose_and_record_port 47210\necho \"RC=$?\"\n" % (d, _pick101))
    with open(cfg, encoding="utf-8") as fh:
        return r.stdout + r.stderr, fh.read()


_broken101 = '{"setup_complete": true, "tailscale_mount": "/x",}'
_pb101 = _pick_run101(_broken101)
_pl101 = _pick_run101("[]")
_pg101 = _pick_run101('{"setup_complete": true}')
check("install.sh: the port picker refuses a config.json that does not parse, and leaves it as it "
      "was (it was replaced by {\"port\": N}, every setting in it gone)",
      "RC=4" in _pb101[0] and _pb101[1] == _broken101 and "Refusing to record the port" in _pb101[0],
      repr(_pb101))
check("install.sh: ...and one that parses to something other than an object, without a traceback",
      "RC=4" in _pl101[0] and _pl101[1] == "[]" and "Traceback" not in _pl101[0], repr(_pl101))
_pgj101 = _json101.loads(_pg101[1]) if _pg101[1].startswith("{") else {}
check("install.sh: ...while a readable config.json keeps its settings and gains the port (control)",
      "RC=0" in _pg101[0] and _pgj101.get("setup_complete") is True
      and isinstance(_pgj101.get("port"), int), repr(_pg101))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. uninstall.sh reads the port the panel binds
# ════════════════════════════════════════════════════════════════════════════════════════════════
# int() of the raw value: `true` read as 1, 0 as 0 and 70000 as 70000, none of which the panel
# binds (it binds 5000), so the installer's rule for 5000 was left open and port 1's removed.
_ui101 = _UNI101.find('    PANEL_PORT="$(printf')
_uend101 = '|| echo "")"\n'
_uline101 = _UNI101[_ui101:_UNI101.index(_uend101, _ui101) + len(_uend101)] if _ui101 >= 0 else ""


def _uport101(conf):
    r = _bash101('CONF_JSON=%s\n%secho "PORT=${PANEL_PORT}"\n' % (_shlex101.quote(conf), _uline101))
    return r.stdout.strip()


_uports101 = {c: _uport101(c) for c in ('{"port": true}', '{"port": 0}', '{"port": 70000}',
                                        '{"port": "8443"}', '{"port": 5001}', '{}', '{"port": null}',
                                        '[]', 'not json')}
check("uninstall.sh: a config.json port the panel would not bind (true, 0, 70000) reads as 5000, "
      "the port it binds",
      [_uports101[c] for c in ('{"port": true}', '{"port": 0}', '{"port": 70000}')]
      == ["PORT=5000"] * 3, repr(_uports101))
check("uninstall.sh: ...a port it binds reads as itself, a missing one as 5000 (control)",
      [_uports101[c] for c in ('{"port": "8443"}', '{"port": 5001}', '{}', '{"port": null}')]
      == ["PORT=8443", "PORT=5001", "PORT=5000", "PORT=5000"], repr(_uports101))
check("uninstall.sh: ...and a config.json that is not an object, or not JSON, still reads as "
      "nothing (warned, no rule removed)",
      _uports101["[]"] == "PORT=" and _uports101["not json"] == "PORT=", repr(_uports101))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The monitor's maintenance probe on a remote whose sudo asks for a password
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Since the reachability probe stopped needing sudo, such a remote reaches the per-server checks.
# The maintenance probe still ran under the row's sudo, answered nothing, and read as "not in
# maintenance": every LinuxGSM cron update paged "went offline unexpectedly". Stubbed at the
# transport (Tailscale SSH's, which returns rather than raises), so run_command's own sudo default
# is the one judged.
from unit.part12 import _p9_patch, _p9_restore_all  # noqa: E402
from panel.ops.ssh_manager import _core as _smc101  # noqa: E402
from panel.services import monitoring as _mon101  # noqa: E402

_sent101 = []
_cmds101 = []


def _ts_cli101(server, command, timeout=30, sudo=None, stdin_text=None):
    """Tailscale SSH to a remote whose sudo needs a password; a cron update is running."""
    use_sudo = sudo if sudo is not None else server.sudo_enabled
    _cmds101.append(bool(use_sudo))
    if use_sudo:
        return "", "sudo: a terminal is required to read the password", 1
    return ("BUSY\n" if "pgrep" in command else ""), "", 0


_srv101 = NS(id=-10101, name="p101", display_name="p101", host="p101.example.invalid", port=22,
             is_local=False, auth_method="tailscale", sudo_enabled=True, username="admin")
_gs101 = NS(id=-10102, name="p101 gmod", short_name="p101gmod", game_type="gmod",
            lgsm_name="gmodserver")
_maint101, _downs101 = None, None
try:
    _p9_patch(_smc101, "_run_via_ssh_cli", _ts_cli101)
    _p9_patch(_mon101, "notifications", NS(notify=lambda *a, **k: _sent101.append(a[0])))
    _maint101 = _mon101._lgsm_maintenance_running(_srv101, _gs101)
    _downs101 = [_mon101._mon_server_went_down(_srv101, _gs101, False, True, False) for _ in range(2)]
except Exception as _e101:  # noqa: BLE001 - recorded: a raise fails the checks below by name
    _maint101 = "raised %s: %s" % (type(_e101).__name__, _e101)
finally:
    _p9_restore_all()
    _mon101._monitor_state["server_misses"].pop(_gs101.id, None)
check("monitoring: on a remote whose sudo needs a password, the maintenance probe asks again "
      "without sudo and sees the running LinuxGSM update (it read the refusal as 'not in maintenance')",
      _maint101 is True and _cmds101[:2] == [True, False], repr((_maint101, _cmds101)))
check("monitoring: ...so a cron update holding its port shut two sweeps running pages nothing",
      _sent101 == [] and isinstance(_downs101, list)
      and _downs101[-1] is _mon101._IN_MAINTENANCE, repr((_sent101, _downs101)))
