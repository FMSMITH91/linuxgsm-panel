"""Part 104 of the unit suite: the seventeenth review's fixes by builder A (review 1016f).

The helper, the installer and the app core. Held here, each against the code path the finding
named:

* discovery reads ~/lgsm/mods/installed-mods.txt as it reads the .cfg files, on the panel host
  (the helper) and on a remote (the shell scan): a regular file only, never through a link or into
  a fifo, bounded. A link to /dev/zero grew one line until memory ran out, and a fifo blocked the
  scan for every account on the host.
* the helper, as root, reports nothing for a /home entry with no account (or uid 0's) instead of
  reading it in-process AS ROOT, following links the directory's owner made.
* the remote form of gmod-mount-read answers a failed read with a non-zero rc, as the helper does;
  `|| true` made it "mounts nothing", and the remove path then dropped every other mount.
* a hand-edited `"security_whitelist": "203.0.113.5"` is one entry, not eleven characters none of
  which is an address.
* install-gamedig.sh runs the installed tree's check as nobody, never as root.
* install.sh hands apt-get its non-interactive settings through sudo on the OS upgrade and the
  unattended-upgrades install.
* the legacy OS-update routes start the detached os-update-run job instead of a foreground apt
  with a 600 s kill.

HOW IT RUNS. The helper and the scan script in their own processes over a throwaway home (part43's
bounded runner, so a fifo cannot hang the suite), with a memory ceiling; shell text under bash with
stand-ins first on PATH; config.json in a temp directory. Nothing reaches this machine's sudo,
runuser, apt or the checkout's data/.
"""
import atexit as _atexit104
import os
import shutil as _shutil104
import subprocess as _sp104  # nosec B404 - bash over the repo's own scripts and stand-ins
import sys as _sys104
import tempfile as _tf104
from pathlib import Path as _Path104

from unit.part01 import check
from unit.part05 import _helper as _helper104, _root
from unit.part12 import _p9_app
from unit.part43 import _run_bounded43
from panel.core import config as _cfg104
from panel.ops import system_ops as _so104
from panel.ops.ssh_manager import _core as _smc104
from panel.security import privileged as _priv104

_TMP104 = _tf104.mkdtemp(prefix="p104-")
_atexit104.register(_shutil104.rmtree, _TMP104, True)


def _read104(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _stand_in104(path, body):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- a stand-in program in this test's temp dir
    os.chmod(path, 0o700)  # nosec B103 - a stand-in program in this test's temp dir


def _bash104(script, env=None, cwd=None):
    """Run `script` under bash; the CompletedProcess."""
    return _sp104.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,  # nosec B603 B607
                      env=dict(os.environ, **(env or {})), cwd=cwd)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Discovery reads installed-mods.txt as it reads the .cfg files, on both forms
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Four accounts, each with one real instance. Their installed-mods.txt is: two lines (the control);
# a fifo; a link to /dev/zero; a link to a five-line file outside the account (a line-count oracle
# over whatever the link names). Only the first is a mods list the scan may count.
_HOME104 = os.path.realpath(_tf104.mkdtemp(dir=_TMP104, prefix="home-"))
_OUTSIDE104 = os.path.join(_TMP104, "outside.txt")
with open(_OUTSIDE104, "w", encoding="utf-8") as _fh104:
    _fh104.write("a\nb\nc\nd\ne\n")


def _account104(user, mods):
    inst = user
    cfg = os.path.join(_HOME104, user, "lgsm", "config-lgsm", inst)
    os.makedirs(cfg)
    os.makedirs(os.path.join(_HOME104, user, "lgsm", "mods"))
    _stand_in104(os.path.join(_HOME104, user, inst), "#!/bin/sh\n")
    target = os.path.join(_HOME104, user, "lgsm", "mods", "installed-mods.txt")
    if mods == "fifo":
        os.mkfifo(target)
    elif mods.startswith("/"):
        os.symlink(mods, target)
    else:
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(mods)


for _u104, _m104 in (("aserver", "metamod\nsourcemod\n"), ("bserver", "fifo"),
                     ("cserver", "/dev/zero"), ("dserver", _OUTSIDE104)):
    _account104(_u104, _m104)
_MODS_WANT104 = {"aserver": 2, "bserver": 0, "cserver": 0, "dserver": 0}

# The ceiling keeps the old code's /dev/zero read from taking this machine's memory with it: it
# fails by name (MemoryError, or grep killed) instead.
_ULIMIT104 = "ulimit -v 1048576; "
_HELPER_RUN104 = ("import importlib.machinery as m, importlib.util as u, sys\n"
                  "ld = m.SourceFileLoader('panel_helper_p104', sys.argv[1])\n"
                  "h = u.module_from_spec(u.spec_from_loader(ld.name, ld))\n"
                  "ld.exec_module(h)\n"
                  "h.HOME_ROOT = sys.argv[2]\n"
                  "h.do_lgsm_discover([], None)\n")


def _mods104(out):
    got = {}
    for line in (out or "").splitlines():
        f = line.split("|")
        if len(f) == 8 and f[0] == "FOUND":
            got[f[1]] = int(f[5]) if f[5].isdigit() else f[5]
    return got


_hout104, _herr104, _hrc104 = _run_bounded43(
    ["bash", "-c", _ULIMIT104 + 'exec "$0" -I -c "$1" "$2" "$3"', _sys104.executable, _HELPER_RUN104,
     os.path.join(_root, "tools", "panel-helper"), _HOME104])
check("discover helper: a fifo and a /dev/zero link at installed-mods.txt do not stop the scan, and "
      "every account is still found (a fifo blocked open() until the panel's timeout ended the scan "
      "for every account; /dev/zero grew one line until memory ran out)",
      _hrc104 == 0 and sorted(_mods104(_hout104)) == sorted(_MODS_WANT104),
      "rc %r %r: %s" % (_hrc104, _mods104(_hout104), _herr104[-300:]))
check("discover helper: ...and only a regular installed-mods.txt is counted: the fifo, the "
      "/dev/zero link and a link to a five-line file outside the account count 0",
      _mods104(_hout104) == _MODS_WANT104, repr(_mods104(_hout104)))

_SCAN104 = _smc104._discover_scan_script(_HOME104)
for _sh104 in ("sh", "bash"):
    _sout104, _serr104, _src104 = _run_bounded43(["bash", "-c", _ULIMIT104 + 'exec "$0" -c "$1"',
                                                  _sh104, _SCAN104])
    check("discover scan (%s): a fifo or a /dev/zero link at installed-mods.txt does not stop root's "
          "scan, and every account is still found" % _sh104,
          _src104 == 0 and sorted(_mods104(_sout104)) == sorted(_MODS_WANT104),
          "rc %r %r: %s" % (_src104, _mods104(_sout104), _serr104[-300:]))
    check("discover scan (%s): ...and only a regular installed-mods.txt is counted, never one "
          "through a link (root's grep answered any root-readable file's line count)" % _sh104,
          _mods104(_sout104) == _MODS_WANT104, repr(_mods104(_sout104)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. As root, a /home entry with no account (or uid 0's) is not read in-process
# ════════════════════════════════════════════════════════════════════════════════════════════════
# This process is not root, so the helper's `os` here answers getuid() 0. A real account would then
# fork and drop, which cannot work unprivileged; the two names below must never get that far.
class _Os104:
    """The helper's `os`, as root; every listdir recorded, so a read shows."""

    def __init__(self, real):
        self._real = real
        self.listed = []

    def getuid(self):
        return 0

    def listdir(self, path):
        self.listed.append(path)
        return self._real.listdir(path)

    def __getattr__(self, name):
        return getattr(self._real, name)


_NOACCT104 = "p104noacct"
_HOME2_104 = os.path.realpath(_tf104.mkdtemp(dir=_TMP104, prefix="home2-"))
for _u104 in (_NOACCT104, "root"):
    os.makedirs(os.path.join(_HOME2_104, _u104, "lgsm", "config-lgsm", "xserver"))
    _stand_in104(os.path.join(_HOME2_104, _u104, "xserver"), "#!/bin/sh\n")


class _Cap104:
    def __init__(self):
        self.text = []

    def write(self, t):
        self.text.append(t)

    def flush(self):
        pass  # nothing buffered


def _as_root104(fake_root):
    saved = (_helper104.HOME_ROOT, _helper104.sys.stdout, _helper104.os)
    cap, fake = _Cap104(), _Os104(os)
    try:
        _helper104.HOME_ROOT = _HOME2_104
        _helper104.sys.stdout = cap
        if fake_root:
            _helper104.os = fake
        for user in (_NOACCT104, "root"):
            _helper104._discover_user(user, os.path.join(_HOME2_104, user, "lgsm", "config-lgsm"),
                                      [], 0)
    finally:
        _helper104.HOME_ROOT, _helper104.sys.stdout, _helper104.os = saved
    return "".join(cap.text), fake.listed


try:
    _entry_noacct104 = __import__("pwd").getpwnam(_NOACCT104)
except KeyError:
    _entry_noacct104 = None
_rootout104, _rootlisted104 = _as_root104(True)
check("panel-helper: as root, discovery reads nothing of a /home entry with no account, nor of "
      "uid 0's: it read them in-process AS ROOT, following links the directory's owner made",
      _entry_noacct104 is None and _rootout104 == "" and _rootlisted104 == [],
      repr((_rootout104, _rootlisted104)))
_userout104, _ = _as_root104(False)
check("panel-helper: ...while unprivileged (a per-user install, nothing to drop from) the same "
      "entries are still read in-process (control)",
      _userout104.count("FOUND|") == 2, repr(_userout104))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The remote gmod-mount-read keeps a failed read's rc
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The rendering, with the home rewritten into a throwaway directory and runuser a stand-in that
# runs the command as this account. A directory at mount.cfg's name makes cat fail whoever runs it.
_GM104 = os.path.join(_TMP104, "gmhome")
_STUB104 = os.path.join(_TMP104, "stub")
os.makedirs(_STUB104)
_stand_in104(os.path.join(_STUB104, "runuser"),
             '#!/bin/bash\n[ "$1" = -u ] && [ "$3" = -- ] || exit 125\nshift 3\nexec "$@"\n')
_MOUNT104 = _priv104.remote_command("gmod-mount-read", ["gm"])
_MCFG104 = os.path.join(_GM104, "serverfiles", "garrysmod", "cfg", "mount.cfg")


def _mount_read104(state):
    _shutil104.rmtree(_GM104, ignore_errors=True)
    os.makedirs(os.path.dirname(_MCFG104))
    if state == "file":
        with open(_MCFG104, "w", encoding="utf-8") as fh:
            fh.write('"mountcfg"\n{\n\t"cstrike"\t"/home/cu/cstrike"\n}\n')
    elif state == "dir":
        os.makedirs(_MCFG104)
    elif state == "dangling":
        os.symlink(os.path.join(_GM104, "nowhere"), _MCFG104)
    r = _bash104(_MOUNT104.replace("/home/gm", _GM104),
                 env={"PATH": _STUB104 + ":" + os.environ.get("PATH", "/usr/bin:/bin")})
    return r.returncode, r.stdout


_mr104 = {s: _mount_read104(s) for s in ("absent", "file", "dir", "dangling")}
check("privileged: the remote mount.cfg read answers a read that FAILED with a non-zero rc (a "
      "directory at the name, a dangling link): `|| true` made it rc 0, which gmod_current_mounts "
      "reads as 'mounts nothing', and the remove path then dropped every other mount",
      _mr104["dir"][0] != 0 and _mr104["dangling"][0] != 0, repr(_mr104))
check("privileged: ...while an absent mount.cfg is still rc 0 and empty (no mounts IS a reading), "
      "and a present one is read whole, rc 0",
      _mr104["absent"] == (0, "") and _mr104["file"][0] == 0 and '"cstrike"' in _mr104["file"][1],
      repr(_mr104))
check("privileged: ...and the file is still read as the game account (runuser first)",
      _MOUNT104.startswith("runuser -u gm -- timeout 8 cat /home/gm/serverfiles/garrysmod/cfg/mount.cfg"),
      _MOUNT104)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. A hand-edited security_whitelist string is one entry
# ════════════════════════════════════════════════════════════════════════════════════════════════
_cfgfile_saved104 = _cfg104.CONFIG_FILE
_cfgtmp104 = _Path104(_tf104.mkdtemp(dir=_TMP104)) / "config.json"
_wl104 = {}
try:
    _cfg104.CONFIG_FILE = _cfgtmp104
    for _label104, _body104 in (("string", '{"security_whitelist": "203.0.113.5"}'),
                                ("blank", '{"security_whitelist": "  "}'),
                                ("object", '{"security_whitelist": {"203.0.113.5": 1}}'),
                                ("number", '{"security_whitelist": 5}'),
                                ("mixed", '{"security_whitelist": ["203.0.113.5", 7, null]}'),
                                ("list", '{"security_whitelist": ["203.0.113.5", "198.51.100.0/24"]}')):
        _cfgtmp104.write_text(_body104, encoding="utf-8")
        _cfg104._cfg_cache["key"] = None
        try:
            _wl104[_label104] = _p9_app._security_whitelist()
        except Exception as _e104:  # noqa: BLE001 - a raise is a named failure here, never a crash
            _wl104[_label104] = repr(_e104)
    _cfgtmp104.write_text('{"security_whitelist": "203.0.113.5"}', encoding="utf-8")
    _cfg104._cfg_cache["key"] = None
    _ign104 = _so104._f2b_ignoreip_line(_p9_app._security_whitelist())
finally:
    _cfg104.CONFIG_FILE = _cfgfile_saved104
    _cfg104._cfg_cache["key"] = None
check("config: a hand-edited security_whitelist string is ONE entry (it read as its characters, "
      "none an address, so fail2ban, every remote's jail and the auto-block dropped the operator's "
      "own address), and it reaches the jail's ignoreip",
      _wl104.get("string") == ["203.0.113.5"] and "203.0.113.5" in _ign104.split(),
      repr((_wl104.get("string"), _ign104)))
check("config: ...a blank string, an object or a number is no entry, a non-string item in a list "
      "is dropped, and a real list is kept as it is (control)",
      _wl104.get("blank") == [] and _wl104.get("object") == [] and _wl104.get("number") == []
      and _wl104.get("mixed") == ["203.0.113.5"]
      and _wl104.get("list") == ["203.0.113.5", "198.51.100.0/24"], repr(_wl104))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. install-gamedig.sh runs the new tree's check as nobody
# ════════════════════════════════════════════════════════════════════════════════════════════════
# `works` runs the installed package, whose import-time code `--ignore-scripts` keeps from ever
# running as root. Its text, with bash's read-only EUID answered as root's 0, a runuser stand-in
# that records its arguments, and a gamedig stand-in that answers as gamedig does.
_GDS104 = _read104("tools", "gamedig", "install-gamedig.sh")
_wi104 = _GDS104.find("\nworks() {")
_works104 = (_GDS104[_wi104 + 1:_GDS104.index("\n}\n", _wi104) + 3] if _wi104 >= 0
             else "works() { return 9; }\n")
_GDB104 = os.path.join(_TMP104, "gd")
os.makedirs(_GDB104)
_stand_in104(os.path.join(_GDB104, "runuser"),
             '#!/bin/bash\necho "RUNUSER $*" >> "$P104LOG"\n[ "$1" = -u ] && [ "$3" = -- ] || exit 125\n'
             'shift 3\nexec "$@"\n')
_stand_in104(os.path.join(_GDB104, "gamedig"), '#!/bin/sh\necho \'{"error":"Failed all 1 attempts"}\'\n')
_GDLOG104 = os.path.join(_GDB104, "calls")


def _works_run104(as_root):
    if os.path.exists(_GDLOG104):
        os.remove(_GDLOG104)
    # Either way by the id the script is handed, not this run's own (review 1022c lead: the control kept
    # "${EUID}", which is 0 on CI's root leg, and passed there whatever it found).
    body = _works104.replace('"${EUID}"', "0" if as_root else "1000")
    # runuser is looked up on PATH plus /usr/sbin:/sbin: the weekly cron's PATH has no sbin.
    body = body.replace(":/usr/sbin:/sbin", "")
    r = _bash104(body + 'works %s; echo "RC $?"\n' % os.path.join(_GDB104, "gamedig"),
                 env={"PATH": _GDB104 + ":" + os.environ.get("PATH", "/usr/bin:/bin"),
                      "P104LOG": _GDLOG104})
    try:
        with open(_GDLOG104, encoding="utf-8") as fh:
            calls = fh.read().splitlines()
    except OSError:
        calls = []
    return r.stdout.strip(), calls


_gdroot104 = _works_run104(True)
check("install-gamedig.sh: as root, the installed tree's check runs as nobody (runuser -u nobody), "
      "never as root: it ran the package's code as root on every host, weekly",
      _gdroot104[0] == "RC 0" and len(_gdroot104[1]) == 1
      and _gdroot104[1][0].startswith("RUNUSER -u nobody -- timeout 60 %s --type minecraft"
                                      % os.path.join(_GDB104, "gamedig")), repr(_gdroot104))
check("install-gamedig.sh: ...and runuser is found from the weekly cron too, whose PATH "
      "(/usr/bin:/bin) has no sbin directory, where runuser lives",
      'PATH="${PATH}:/usr/sbin:/sbin" command -v runuser' in _works104, _works104[:400])
_gduser104 = _works_run104(False)
check("install-gamedig.sh: ...and with no root to drop from it runs the check as it is (control)",
      _gduser104 == ("RC 0", []), repr(_gduser104))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. install.sh's OS upgrade and unattended-upgrades are non-interactive through sudo
# ════════════════════════════════════════════════════════════════════════════════════════════════
# A per-user install's `sudo` drops an exported DEBIAN_FRONTEND/NEEDRESTART_MODE (env_reset), so
# the upgrade could stop at a debconf, ucf or needrestart dialog. The fresh install's two blocks run
# here under bash with sudo, id and apt-get as stand-ins (functions), as a per-user install.
_INS104 = _read104("install.sh")


def _block104(start, end="\nfi\n"):
    i = _INS104.find(start)
    return _INS104[i:_INS104.index(end, i) + len(end)] if i >= 0 else "false\n"


_apt_ni104 = _block104("APT_NI_ENV=(", "\n}\n")   # the settings and _r30a_apt_ni, which uses them
_fresh104 = _block104('if [[ "${PANEL_NO_UPGRADE:-0}" != "1" ]] && command -v apt-get >/dev/null 2>&1; then\n'
                      '    UPG_SUDO=""')
_au104 = _block104("if command -v apt-get >/dev/null 2>&1; then\n    AU_SUDO=")
# sudo writes to a file of its own: two of the calls send their output to /dev/null.
_SUDOLOG104 = os.path.join(_TMP104, "sudo.log")
_shim104 = ("info() { :; }\nok() { :; }\nwarn() { :; }\nid() { echo 1000; }\n"
            "sudo() { echo \"SUDO $*\" >> \"$P104SUDO\"; }\ndpkg() { return 1; }\n"
            "command() { [ \"$2\" = apt-get ]; }\n")
_bash104(_shim104 + _apt_ni104 + _fresh104 + _au104, env={"P104SUDO": _SUDOLOG104})
try:
    with open(_SUDOLOG104, encoding="utf-8") as _fh104:
        _r104 = _fh104.read().splitlines()
except OSError:
    _r104 = []
_ni104 = "SUDO env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get "
check("install.sh: a per-user install's OS upgrade hands apt-get its non-interactive settings "
      "THROUGH sudo (an export is dropped by env_reset): update, full-upgrade and autoremove",
      [ln for ln in _r104 if "full-upgrade" in ln or " update" in ln or "autoremove" in ln]
      == [_ni104 + "update -qq", _ni104 + "-y -o Dpkg::Options::=--force-confold full-upgrade",
          _ni104 + "-y autoremove --purge"], repr(_r104))
check("install.sh: ...and so does the unattended-upgrades install",
      _ni104 + "install -y unattended-upgrades" in _r104, repr(_r104))
# The update path's upgrade is nested in the update flow; every apt-get in install.sh behind
# UPG_SUDO or AU_SUDO goes through APT_NI, but the read-only simulation.
_bare104 = [ln.strip() for ln in _INS104.splitlines()
            if ("${UPG_SUDO} apt-get" in ln or "${AU_SUDO} apt-get" in ln) and " -s " not in ln]
check("install.sh: ...and no apt-get behind UPG_SUDO/AU_SUDO (the update path's included) is run "
      "without APT_NI, but the simulation",
      _bare104 == [] and _INS104.count('_r30a_apt_ni "${UPG_SUDO}"') == 6, repr(_bare104))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. The legacy OS-update route starts the detached job
# ════════════════════════════════════════════════════════════════════════════════════════════════
# POST /api/server-management/os-update-run ran the helper's foreground `apt upgrade` from a thread
# of the panel with a 600 s kill: an upgrade past 600 s, or any panel restart, killed apt mid-dpkg.
_ou_calls104 = []


def _verb104(answers):
    def _run(verb, args=(), **k):
        _ou_calls104.append(verb)
        return answers.get(verb, ("", "", 0))
    return _run


_ou_saved104 = (_so104._run_verb, _so104._can_escalate, _so104.threading)


class _NoThread104:
    @staticmethod
    def Thread(*a, **k):
        raise AssertionError("os_run_update started a thread of the panel")

    def __getattr__(self, name):
        return getattr(_ou_saved104[2], name)


_ou104 = {}
try:
    _so104._can_escalate = lambda: True
    _so104.threading = _NoThread104()
    for _k104, _ans104 in (
            ("start", {"apt-upgrade-running": ("", "", 1),
                       "os-update-run": ("launching\n" + _priv104.OS_UPDATE_STARTED, "", 0)}),
            ("running", {"apt-upgrade-running": ("", "", 0), "os-update-own-running": ("", "", 0)}),
            ("refused", {"apt-upgrade-running": ("", "", 1),
                         "os-update-run": ("", "sudo: a password is required", 1)})):
        del _ou_calls104[:]
        _so104._run_verb = _verb104(_ans104)
        try:
            _ou104[_k104] = (_so104.os_run_update(), list(_ou_calls104))
        except AssertionError as _e104:
            _ou104[_k104] = (repr(_e104), list(_ou_calls104))
finally:
    _so104._run_verb, _so104._can_escalate, _so104.threading = _ou_saved104
check("system_ops: the panel host's legacy OS update starts the helper's DETACHED os-update-run job, "
      "never the foreground apt-upgrade verb from a thread of the panel",
      _ou104["start"] == ((True, "OS update started in background. This may take several minutes."),
                          ["apt-upgrade-running", "os-update-run"]), repr(_ou104))
check("system_ops: ...an update already running is watched, not started again, and a job that did "
      "not start is answered as not started",
      _ou104["running"] == ((True, "An update is already running — watching it."),
                            ["apt-upgrade-running", "os-update-own-running"])
      and _ou104["refused"][0] == (False, "Couldn't start the update."), repr(_ou104))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 8. The database repair is refused beside a self-update or a restore
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Each of the three replaces panel.db, the update and the restore already refuse each other, and
# the repair (stop the panel, rewrite or replace panel.db offline) asked neither.
from panel.ops import backup as _bk104  # noqa: E402

_rp_dir104 = _tf104.mkdtemp(dir=_TMP104)
os.makedirs(os.path.join(_rp_dir104, "venv", "bin"))
for _f104 in (os.path.join("venv", "bin", "python3"), "db_maintenance.py"):
    open(os.path.join(_rp_dir104, _f104), "w").close()
_rp_saved104 = (_so104.PANEL_DIR, _so104._update_in_progress, _bk104.restore_pending,
                _so104._is_system_service, _so104._helper_present, _so104._run_verb)
# The repair's own "launched" record too, which the "neither" case sets (review 1022c lead: left set).
_rp_launched104 = dict(_so104._r30a_repair_launched)
_rp104 = {}
try:
    _so104.PANEL_DIR = _rp_dir104
    _so104._is_system_service = lambda: True
    _so104._helper_present = lambda: True
    for _k104, (_upd104, _rst104) in (("update", (True, False)), ("restore", (False, True)),
                                      ("neither", (False, False))):
        del _ou_calls104[:]
        _so104._update_in_progress = (lambda v: (lambda: v))(_upd104)
        _bk104.restore_pending = (lambda v: (lambda: v))(_rst104)
        _so104._run_verb = _verb104({})
        _rp104[_k104] = (_so104.panel_repair_database(), list(_ou_calls104))
finally:
    (_so104.PANEL_DIR, _so104._update_in_progress, _bk104.restore_pending,
     _so104._is_system_service, _so104._helper_present, _so104._run_verb) = _rp_saved104
    _so104._r30a_repair_launched.clear()
    _so104._r30a_repair_launched.update(_rp_launched104)
check("db repair: refused while a panel update is being installed, or a backup restore is in "
      "flight (each replaces panel.db, as the repair does), and no repair job is started",
      _rp104["update"][0][0] is False and _rp104["restore"][0][0] is False
      and _rp104["update"][1] == [] and _rp104["restore"][1] == [], repr(_rp104))
check("db repair: ...and with neither it starts the helper's repair job (control)",
      _rp104["neither"][0][0] is True and _rp104["neither"][1] == ["panel-db-repair"], repr(_rp104))
