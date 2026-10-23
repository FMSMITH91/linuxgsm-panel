"""Part 97 of the unit suite: the fifteenth review's fixes by builder A (review 1016c).

Install, the helper, the boot's port and the monitor. Held here, each against the code path the
finding named:

* install.sh's snapshot prune follows a link the running account made on a per-user install (it
  never pruned there again), and on a root run follows a root-made link only to a target the panel
  user can never make lead anywhere else.
* the helper's restore and self-update follow a root-made data/ link without following a link of
  the panel user's beyond it, and open the resolved directory one component at a time, so a
  directory above it swapped for a link after the check is refused.
* the helper rewrites panel.conf under an exclusive lock, so two records at once keep both keys.
* every reader of the panel's port reads what the boot binds: load_config corrects a hand-edited
  port as the boot does, so do the firewall guard's last-parsed read and install.sh's reader, and
  install.sh no longer records its "could not read config.json" fallback as config.json's port.
* the monitor's reachability probe runs without sudo, so a remote whose sudo asks for a password is
  up (its disk, load and ports read), and a reboot there is refused for its sudo, not as silent.
* the debug report withholds every body once its pattern pass has failed, as its footer says.

HOW IT RUNS. install.sh's own functions under bash in a throwaway directory, the helper and the
panel's modules with stand-ins, undone in a finally; part12's app for the reboot request. Nothing
reaches this machine's sudo, tailscale or the checkout's data/.
"""
import atexit as _atexit97
import fcntl as _fcntl97
import os
import select as _select97
import shutil as _shutil97
import subprocess as _sp97  # nosec B404 - bash over the repo's own install.sh, in a throwaway dir
import sys
import tempfile as _tf97
import time as _time97
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper as _helper97, _root

_TMP97 = _tf97.mkdtemp(prefix="p97-")
_atexit97.register(_shutil97.rmtree, _TMP97, True)


def _read97(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _fn97(src, name):
    """The text of shell function `name` in `src`, from its `name() {` line to its closing `}`."""
    i = src.find("\n%s() {" % name)
    if i < 0:
        return "%s() { exit 97; }\n" % name
    return src[i + 1:src.index("\n}\n", i) + 3]


_INS97 = _read97("install.sh")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. install.sh: the snapshot prune and a PANEL_DIR that is a link the operator made
# ════════════════════════════════════════════════════════════════════════════════════════════════
_STAMPS97 = ["20260101-00000%d" % i for i in range(5)]
# The stand-ins. `id -u` answers 0 where P97_ROOT asks for a root run (any other `id` is the real
# one). `stat` answers 0 (root) for PANEL_DIR where P97_ROOTLINK asks for a link root made. The
# panel user can write anything under $P97/home and nothing else ($P97/srv stands in for a disk the
# operator mounted). P97_SWAP swaps the target <home>/panel-real for the panel user's link to
# <other> before the prune starts, which is what readlink -f then resolved.
_HOOKS97 = r'''
id() { if [ -n "$P97_ROOT" ] && [ "$*" = "-u" ]; then echo 0; else command id "$@"; fi; }
stat() { if [ -n "$P97_ROOTLINK" ] && [ "${!#}" = "$PANEL_DIR" ]; then echo 0 1;
         else command stat "$@"; fi; }
_panel_ids() { _PR_UID=4242; }
_panel_cannot_write() { case "$1" in "$P97"/home|"$P97"/home/*) return 1 ;; *) return 0 ;; esac; }
'''


def _r26a_prune(where, root=False, rootlink=False, swap=False, nested=False):
    """(rc, stamps left at the link's target, stamps left in <other>, output) for one prune.

    PANEL_DIR is $base/home/linuxgsm-panel, a link to `where` ("home": $base/home/panel-real, or
    "srv": $base/srv/panel); `nested` puts the panel user's link $base/srv/hop in the way.
    """
    base = _tf97.mkdtemp(dir=_TMP97)
    target = os.path.join(base, "home", "panel-real") if where == "home" else \
        os.path.join(base, "srv", "panel")
    other = os.path.join(base, "other")
    for t in (target, other):
        for s in _STAMPS97:
            os.makedirs(os.path.join(t, "data", ".backups", s))
    os.makedirs(os.path.join(base, "home"), exist_ok=True)
    panel = os.path.join(base, "home", "linuxgsm-panel")
    link_to = target
    if nested:
        os.symlink(os.path.dirname(target), os.path.join(base, "srv", "hop"))
        link_to = os.path.join(base, "srv", "hop", os.path.basename(target))
    os.symlink(link_to, panel)
    if swap:
        os.rename(target, target + ".moved")
        os.symlink(other, target)
        target += ".moved"
    script = ("set -euo pipefail\nwarn() { echo \"WARN $*\"; }\nKEEP_BACKUPS=3\nP97=%s\n"
              "P97_ROOT=%s\nP97_ROOTLINK=%s\nPANEL_DIR=%s\n%s\n%s%s%s_r22a_prune_snapshots\n"
              % (base, "1" if root else "", "1" if rootlink else "", panel, _HOOKS97,
                 _fn97(_INS97, "_r26a_link_trusted"), _fn97(_INS97, "_r26a_fixed_target"),
                 _fn97(_INS97, "_r22a_prune_snapshots")))
    r = _sp97.run(["bash", "-c", script], cwd=base, capture_output=True, text=True,  # nosec B603 B607
                  timeout=60)

    def left(t):
        p = os.path.join(t, "data", ".backups")
        return sorted(os.listdir(p)) if os.path.isdir(p) else None
    return r.returncode, left(target), left(other), r.stdout + r.stderr


_pr97 = {"per-user, own link": _r26a_prune("home"),
         "root, root link to srv": _r26a_prune("srv", root=True, rootlink=True),
         "root, root link into home": _r26a_prune("home", root=True, rootlink=True),
         "root, root link into home, swapped":
             _r26a_prune("home", root=True, rootlink=True, swap=True),
         "root, root link through a panel link":
             _r26a_prune("srv", root=True, rootlink=True, nested=True),
         "root, panel user's link": _r26a_prune("srv", root=True)}
check("install.sh: on a per-user install a PANEL_DIR that is the running account's own link is "
      "pruned to KEEP_BACKUPS (it was refused as 'a link', and every update's database snapshot was "
      "kept forever)",
      _pr97["per-user, own link"][0] == 0 and _pr97["per-user, own link"][1] == _STAMPS97[2:],
      repr(_pr97["per-user, own link"]))
check("install.sh: on a root run a link the panel user made is still refused (control)",
      _pr97["root, panel user's link"][1] == _STAMPS97 and "WARN" in _pr97["root, panel user's link"][3],
      repr(_pr97["root, panel user's link"]))
check("install.sh: on a root run a root-made link to a target beyond the panel user's reach is "
      "still pruned (control)",
      _pr97["root, root link to srv"][0] == 0 and _pr97["root, root link to srv"][1] == _STAMPS97[2:],
      repr(_pr97["root, root link to srv"]))
check("install.sh: a root-made link whose target the panel user swapped for a link to <other> before "
      "the prune prunes nothing in <other> (readlink -f resolved both sides there)",
      _pr97["root, root link into home, swapped"][2] == _STAMPS97
      and "WARN" in _pr97["root, root link into home, swapped"][3],
      repr(_pr97["root, root link into home, swapped"]))
check("install.sh: ...and a root-made link into a directory the panel user can write, or through a "
      "link of its own, is refused before anything is pruned",
      _pr97["root, root link into home"][1] == _STAMPS97
      and "WARN" in _pr97["root, root link into home"][3]
      and _pr97["root, root link through a panel link"][1] == _STAMPS97
      and "WARN" in _pr97["root, root link through a panel link"][3],
      repr((_pr97["root, root link into home"], _pr97["root, root link through a panel link"])))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The helper's restore and self-update: a root-made data/ link, and what lies beyond it
# ════════════════════════════════════════════════════════════════════════════════════════════════
_STAGED97 = (("config.json", "{\"restored\": true}"), ("secret_key", "k"))


def _r26a_data(at):
    """A data/ directory at `at` with a restore staged in it and a live config.json."""
    stage = os.path.join(at, _helper97.RESTORE_STAGE)
    os.makedirs(stage)
    for name, text in _STAGED97:
        with open(os.path.join(stage, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    with open(os.path.join(at, "config.json"), "w", encoding="utf-8") as fh:
        fh.write("{}")


def _r26a_helper_run(data, panel, root_made, swap=None):
    """(restore target, self-update target) for panel.conf's data_dir `data`; each job run.

    `root_made`: the links _r26a_link_root_made answers "root made it" for (a root-made link cannot
    be made here without root). `swap(target)` runs after the targets are read and before the job
    bodies, as the panel user would between the two.
    """
    base = os.path.dirname(panel)
    installer = os.path.join(base, "install.sh")
    with open(installer, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n")
    saved = {k: getattr(_helper97, k) for k in ("panel_conf", "INSTALLER_PATH", "resolve",
                                                "subprocess", "_r26a_link_root_made")}
    real_root_made = _helper97._r26a_link_root_made
    try:
        _helper97.panel_conf = lambda: {"data_dir": data, "panel_dir": panel}
        _helper97.INSTALLER_PATH = installer
        _helper97.resolve = lambda name: "/bin/true"
        _helper97.subprocess = NS(run=lambda *a, **k: NS(returncode=0), STDOUT=_sp97.STDOUT,
                                  TimeoutExpired=_sp97.TimeoutExpired)
        _helper97._r26a_link_root_made = lambda p: p in root_made or real_root_made(p)
        target = _helper97._restore_target()
        su = _helper97._self_update_target()
        if swap is not None:
            swap(target)
        if target is not None:
            _helper97._restore_run(target)
        if su is not None:
            _helper97._self_update_run(su[0], su[1], "-", "-")
    finally:
        for k, v in saved.items():
            setattr(_helper97, k, v)
    return target, su and su[1]


def _r26a_untouched(d):
    """Was nothing restored or logged in data directory `d`?"""
    with open(os.path.join(d, "config.json"), encoding="utf-8") as fh:
        return (fh.read() == "{}" and os.path.isdir(os.path.join(d, _helper97.RESTORE_STAGE))
                and not os.path.exists(os.path.join(d, _helper97.SELF_UPDATE_LOG)))


# A root-made data/ link to <disk>/hop/data, where <disk>/hop is the PANEL USER'S link to <other>:
# realpath followed both, and the re-check walked a path with no links left in it.
_b97 = _tf97.mkdtemp(dir=_TMP97)
_r26a_data(os.path.join(_b97, "other", "data"))
os.makedirs(os.path.join(_b97, "disk"))
os.symlink(os.path.join(_b97, "other"), os.path.join(_b97, "disk", "hop"))
os.makedirs(os.path.join(_b97, "panel"))
os.symlink(os.path.join(_b97, "disk", "hop", "data"), os.path.join(_b97, "panel", "data"))
_beyond97 = _r26a_helper_run(os.path.join(_b97, "panel", "data"), os.path.join(_b97, "panel"),
                             {os.path.join(_b97, "panel", "data")})
check("panel-helper: a root-made data/ link whose target goes through a link the panel user made is "
      "refused by restore and self-update, and nothing is restored or logged where it leads (realpath "
      "followed it, and the re-check walked a path with no links left)",
      _beyond97 == (None, None) and _r26a_untouched(os.path.join(_b97, "other", "data")),
      repr(_beyond97))

# The control: the same root-made link straight to <disk>/data still restores and logs there.
_c97 = _tf97.mkdtemp(dir=_TMP97)
_r26a_data(os.path.join(_c97, "disk", "data"))
os.makedirs(os.path.join(_c97, "panel"))
os.symlink(os.path.join(_c97, "disk", "data"), os.path.join(_c97, "panel", "data"))
_ctl97 = _r26a_helper_run(os.path.join(_c97, "panel", "data"), os.path.join(_c97, "panel"),
                          {os.path.join(_c97, "panel", "data")})
_ctlreal97 = os.path.join(os.path.realpath(_c97), "disk", "data")
with open(os.path.join(_ctlreal97, "config.json"), encoding="utf-8") as _fh97:
    _ctlcfg97 = _fh97.read()
check("panel-helper: ...while a root-made data/ link straight to the real directory is still restored "
      "into and logged in (control)",
      _ctl97 == (_ctlreal97, _ctlreal97) and _ctlcfg97 == "{\"restored\": true}"
      and os.path.isfile(os.path.join(_ctlreal97, _helper97.SELF_UPDATE_LOG)), repr(_ctl97))


# The checkout (a directory the panel user owns, above a real data/) swapped for its link to
# <other> after the targets were read: the job bodies opened data/ by path, O_NOFOLLOW only at its
# last component, and followed the swapped directory above it.
def _r26a_swap_checkout(base):
    def swap(_target):
        os.rename(os.path.join(base, "panel"), os.path.join(base, "panel.moved"))
        os.symlink(os.path.join(base, "other"), os.path.join(base, "panel"))
    return swap


_s97 = _tf97.mkdtemp(dir=_TMP97)
_r26a_data(os.path.join(_s97, "panel", "data"))
_r26a_data(os.path.join(_s97, "other", "data"))
_swap97 = _r26a_helper_run(os.path.join(_s97, "panel", "data"), os.path.join(_s97, "panel"), set(),
                           swap=_r26a_swap_checkout(_s97))
check("panel-helper: a checkout swapped for the panel user's link after restore and self-update read "
      "their target has root restore nothing into, and write no log in, the data/ it leads to",
      _swap97[0] is not None and _r26a_untouched(os.path.join(_s97, "other", "data")),
      repr(_swap97))
_pin97 = {}
for _l97, _p97 in (("real", os.path.join(_s97, "panel.moved", "data")),
                   ("link above", os.path.join(_s97, "panel", "data")),
                   ("dotdot", os.path.join(_s97, "panel.moved", "..", "other", "data"))):
    try:
        os.close(_helper97._r26a_open_pinned_dir(_p97))
        _pin97[_l97] = "opened"
    except OSError:
        _pin97[_l97] = "refused"
check("panel-helper: the pinned open refuses a link at any depth and a `..`, and opens a real "
      "directory (control)",
      _pin97 == {"real": "opened", "link above": "refused", "dotdot": "refused"}, repr(_pin97))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The helper's panel.conf rewrite holds a lock from its read to its replace
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The test holds the lock (the directory that holds panel.conf) as a second record would, and runs
# one record in a child process: it must wait, leaving the file as it was, and finish once the lock
# is let go. Unlocked, it wrote straight away, which is the window in which two records each wrote
# back the file they had read and the later one dropped the other's key.
_cd97 = _tf97.mkdtemp(dir=_TMP97)
_conf97 = os.path.join(_cd97, "panel.conf")
with open(_conf97, "w", encoding="utf-8") as _fh97:
    _fh97.write("panel_dir=/x\npanel_port=5000\n")
_CHILD97 = ("import importlib.machinery as m, importlib.util as u, sys\n"
            "s = u.spec_from_loader('h', m.SourceFileLoader('h', sys.argv[1]))\n"
            "h = u.module_from_spec(s)\ns.loader.exec_module(h)\nh.PANEL_CONF = sys.argv[2]\n"
            "print('READY', flush=True)\n"
            "print(repr(h._r25j_conf_set({'panel_port': '8443'})))\n")
_lk97 = os.open(_cd97, os.O_RDONLY | os.O_DIRECTORY)
_child97 = None
try:
    _fcntl97.flock(_lk97, _fcntl97.LOCK_EX)
    _child97 = _sp97.Popen([sys.executable, "-I", "-c", _CHILD97,  # nosec B603 - the repo's helper
                            os.path.join(_root, "tools", "panel-helper"), _conf97],
                           stdout=_sp97.PIPE, stderr=_sp97.PIPE, text=True)
    # "Still waiting" is read only once the child is at the call (review 1017a: after a fixed
    # sleep, a child still starting Python read as waiting, so the check held with no lock at all).
    _ready97 = (_select97.select([_child97.stdout], [], [], 30)[0] != []
                and _child97.stdout.readline().strip() == "READY")
    # Then given time to write, watched rather than slept (review 1022a lead: one fixed second on a
    # loaded machine could read an UNLOCKED child that had not yet written as one still waiting).
    _end97 = _time97.monotonic() + 2.0
    while _ready97 and _child97.poll() is None and _time97.monotonic() < _end97:
        with open(_conf97, encoding="utf-8") as _fh97:
            if _fh97.read() != "panel_dir=/x\npanel_port=5000\n":
                break
        _time97.sleep(0.05)
    _waited97 = _ready97 and _child97.poll() is None
    with open(_conf97, encoding="utf-8") as _fh97:
        _held97 = _fh97.read()
finally:
    os.close(_lk97)                 # lets the child go
try:
    _out97 = _child97.communicate(timeout=30)[0].strip() if _child97 is not None else None
except _sp97.TimeoutExpired:
    _child97.kill()                 # not left running past the part (review 1022c lead); fails below
    _out97 = "timed out: %r" % (_child97.communicate()[0],)
with open(_conf97, encoding="utf-8") as _fh97:
    _after97 = _fh97.read()
check("panel-helper: panel.conf's read-change-replace waits for the lock another record holds, "
      "instead of writing back the file it read and dropping that record's key",
      _waited97 and _held97 == "panel_dir=/x\npanel_port=5000\n" and _out97 == "''"
      and _after97 == "panel_dir=/x\npanel_port=8443\n" and os.listdir(_cd97) == ["panel.conf"],
      repr((_waited97, _held97, _out97, _after97, os.listdir(_cd97))))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. One reading of the panel's port: what the boot binds
# ════════════════════════════════════════════════════════════════════════════════════════════════
import json as _json97  # noqa: E402 - only this section reads config.json
from pathlib import Path as _Path97  # noqa: E402
from panel.core import config as _cfg97  # noqa: E402
from panel.core import validation as _val97  # noqa: E402
from panel.ops.ssh_manager import firewall as _fw97  # noqa: E402
from unit.part12 import _p9_patch, _p9_patch_sm, _p9_restore_all  # noqa: E402

_PORTS97 = (0, 70000, -1, True, "5001", 5001, 5000.7, None)


def _r26a_load(raw):
    """(load_config's port, the firewall guard's port, its last-parsed port) for config.json `raw`."""
    d = _tf97.mkdtemp(dir=_TMP97)
    f = os.path.join(d, "config.json")
    with open(f, "w", encoding="utf-8") as fh:
        _json97.dump({} if raw is None else {"port": raw}, fh)
    saved_cache = dict(_cfg97._cfg_cache)
    try:
        # Through the suite's patcher, undone below: a module attribute reassigned in a function is
        # CodeQL's py/import-of-mutable-attribute at every `from panel.core.config import CONFIG_FILE`.
        _p9_patch(_cfg97, "CONFIG_FILE", _Path97(f))
        _cfg97._cfg_cache.update(key=None, data=None)
        port = _cfg97.load_config().get("port")
        fw = _fw97._panel_web_port(NS(is_local=True), ts_running=False)
        last = _fw97._last_parsed_panel_port()
    finally:
        _p9_restore_all()
        _cfg97._cfg_cache.clear()
        _cfg97._cfg_cache.update(saved_cache)
    return port, fw, last


_ld97 = {repr(v): _r26a_load(v) for v in _PORTS97}
_boot97 = {repr(v): _val97._port_or(v if v is not None else 5000, 5000) for v in _PORTS97}
check("config: load_config reads a hand-edited port (0, 70000, -1, true) as the port the boot binds, "
      "5000, so fail2ban's jail, the firewall guard and the Tailscale steps agree with the listener; "
      "a quoted one and a good one still read as given",
      {k: v[0] for k, v in _ld97.items()} == _boot97
      and _boot97 == {"0": 5000, "70000": 5000, "-1": 5000, "True": 5000, "'5001'": 5001,
                      "5001": 5001, "5000.7": 5000, "None": 5000}, repr((_ld97, _boot97)))
check("firewall: the guard protects the rule for the port the boot bound, from load_config and from "
      "the last-parsed config.json alike (the raw cache read 0 or 70000)",
      all(v[1] == _boot97[k] and v[2] == _boot97[k] for k, v in _ld97.items()), repr(_ld97))

# install.sh's reader: the same rule, and nothing when config.json could not be read.
_RD97 = _fn97(_INS97, "_owner_read") + _fn97(_INS97, "_r26a_cfg_port") + _fn97(_INS97, "panel_port")


def _r26a_install_port(text, fn="panel_port", extra=""):
    d = _tf97.mkdtemp(dir=_TMP97)
    os.makedirs(os.path.join(d, "data"))
    if text is not None:
        with open(os.path.join(d, "data", "config.json"), "w", encoding="utf-8") as fh:
            fh.write(text)
    r = _sp97.run(["bash", "-c", "set -euo pipefail\nPANEL_DIR=%s\n%s%s%s\n" % (d, _RD97, extra, fn)],
                  capture_output=True, text=True, timeout=60)  # nosec B603 B607
    return r.stdout.strip()


_ins97 = {repr(v): _r26a_install_port(_json97.dumps({} if v is None else {"port": v}))
          for v in _PORTS97}
check("install.sh: panel_port reads config.json's port as the panel does (a hand-edited 0, 70000, "
      "-1 or true opened, printed and recorded a port the panel never listened on)",
      _ins97 == {k: str(v) for k, v in _boot97.items()}, repr(_ins97))
_unread97 = {"unparseable": _r26a_install_port("{not json", "_r26a_cfg_port"),
             "not an object": _r26a_install_port("[1]", "_r26a_cfg_port"),
             "absent": _r26a_install_port(None, "_r26a_cfg_port"),
             "unparseable, panel_port": _r26a_install_port("{not json")}
check("install.sh: a config.json that cannot be read gives no port to record (its 5000 fallback was "
      "recorded over the real port), while panel_port still says 5000 and an absent one is 5000",
      _unread97 == {"unparseable": "", "not an object": "", "absent": "5000",
                    "unparseable, panel_port": "5000"}, repr(_unread97))
_REC97 = "".join(_fn97(_INS97, n) for n in ("_r25j_panel_port_to_record", "_r25j_is_panel_port"))
_rc97 = _tf97.mkdtemp(dir=_TMP97)
with open(os.path.join(_rc97, "panel.conf"), "w", encoding="utf-8") as _fh97:
    _fh97.write("panel_port=8443\n")
_kept97 = _r26a_install_port("{not json", "_r25j_panel_port_to_record %s/panel.conf" % _rc97,
                             _REC97 + "_R25J_CHOSEN_PORT=\n_r25j_port_held_by_other() { return 1; }\n")
check("install.sh: ...so an update keeps the recorded port when config.json cannot be read",
      _kept97 == "8443", repr(_kept97))

# The fresh install's port probe near the top of the range: 65535 held here, so the probe's next
# candidate is past the last port, where bind() raises OverflowError rather than OSError.
import socket as _socket97  # noqa: E402
_hold97 = _socket97.socket(_socket97.AF_INET, _socket97.SOCK_STREAM)
try:
    try:
        _hold97.bind(("127.0.0.1", 65535))  # held on loopback: install.sh's all-address probe of it then fails too
        _hold97.listen(1)
    except OSError:
        pass                                # held by something else already: busy either way
    _cp97 = _tf97.mkdtemp(dir=_TMP97)
    _top97 = _sp97.run(["bash", "-c", "set -euo pipefail\nPANEL_DIR=%s\n%schoose_and_record_port 65535\n"
                        % (_cp97, _fn97(_INS97, "choose_and_record_port"))],
                       capture_output=True, text=True, timeout=60)  # nosec B603 B607
finally:
    _hold97.close()
check("install.sh: the fresh install's port probe stops at 65535 and answers 'none free' (it tried "
      "65536, where bind raises OverflowError, and died with a traceback)",
      _top97.stdout.strip() == "" and "OverflowError" not in _top97.stderr
      and _top97.returncode == 0, repr((_top97.returncode, _top97.stdout, _top97.stderr[-300:])))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The monitor's reachability probe runs without sudo
# ════════════════════════════════════════════════════════════════════════════════════════════════
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm  # noqa: E402
from panel.services import host_reboot as _hr97  # noqa: E402
from panel.services import monitoring as _mon97  # noqa: E402


def _r26a_rc(server, cmd, timeout=30, sudo=None, stdin_text=None):
    """A remote whose sudo asks for a password: any command under sudo is refused.

    Under sudo means an explicit sudo=True, or the row's sudo_enabled when sudo is not passed, as
    run_command reads it.
    """
    if (server.sudo_enabled if sudo is None else sudo):
        return "", "sudo: a terminal is required to read the password", 1
    return ("ok\n" if cmd == "echo ok" else ""), "", 0


_srv97 = NS(id=-9701, name="p97", host="p97.example.invalid", port=22, is_local=False,
            auth_method="key", sudo_enabled=True, username="admin")
_read97 = []
_probe97, _reboot97 = None, None
# Armed first, so a path that grows a call past the stubs below is recorded, not run (review 1016f lead).
_trip97 = len(_P9_TRIPPED)
try:
    _p9_arm(patch=_p9_patch, who="part97")
    _p9_patch(_mon97, "run_command", _r26a_rc)
    _p9_patch_sm("run_command", _r26a_rc)
    _p9_patch_sm("run_privileged", lambda *a, **k: ("", "", 1))
    _p9_patch(_mon97, "_remote_listening_ports", lambda r: set())
    _p9_patch(_mon97, "_host_restart_flags", lambda r: None)
    _p9_patch(_mon97, "_host_disk_pct", lambda r: _read97.append("disk") or 12)
    _p9_patch(_mon97, "_host_load_mem", lambda r: _read97.append("load") or (5, 40))
    _probe97 = _mon97._probe_host(_srv97)
    with _p9.app_context():
        _reboot97 = _hr97.request_reboot(_srv97, "now", "p97-admin", "test")
except Exception as _e97:  # noqa: BLE001 - recorded: a raise fails the checks below by name
    _reboot97 = "raised %s: %s" % (type(_e97).__name__, _e97)
finally:
    _p9_restore_all()
    _mon97._probe_record.pop(_srv97.id, None)
check("monitoring: the reachability probe and the reboot request reach no real transport",
      len(_P9_TRIPPED) == _trip97, repr(_P9_TRIPPED[_trip97:][:4]))
check("monitoring: a sudo-enabled remote whose sudo asks for a password answers the reachability "
      "probe (it ran `echo ok` under sudo: 'Host unreachable', marked offline, and its disk, load "
      "and port checks never ran)",
      isinstance(_probe97, tuple) and _probe97[1].get("reachable") is True
      and _read97 == ["disk", "load"], repr((_probe97, _read97)))
_rbmsg97 = str(_reboot97[1].get("message")) if isinstance(_reboot97, tuple) else ""
check("reboot: ...and a reboot of it is refused for its sudo by the preflight, not as a host that "
      "is not answering",
      isinstance(_reboot97, tuple) and _reboot97[0] == 409 and _reboot97[1].get("error") == "preflight"
      and "sudo is refused" in _rbmsg97, repr(_reboot97))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. The debug report: a pattern pass that failed once withholds every body after it
# ════════════════════════════════════════════════════════════════════════════════════════════════
from panel.ops.debug_report import privacy as _priv97  # noqa: E402


class _Ctx97:
    """The one thing privacy.prepare asks of a report's context: memo(key, build)."""

    def __init__(self):
        self.memos = {}

    def memo(self, key, build):
        if key not in self.memos:
            self.memos[key] = build()
        return self.memos[key]


_pc97 = _Ctx97()
_pc97.memos["privacy"] = _priv97._State()
_pc97.memos["privacy"].pattern_error = "RecursionError"     # as an earlier section's scrub left it
_pw97 = _priv97.scrub(_pc97, "## Verdicts\nbody line one\nbody line two")
_pc97.memos["privacy"].pattern_error = None
_pok97 = _priv97.scrub(_pc97, "## Verdicts\nbody line one")
check("debug report: once the pattern pass has failed, the final pass withholds every body too (it "
      "ran again, and printed the bodies scrubbed before the failure under 'every section body was "
      "withheld'); a pass that has not failed prints them (control)",
      "body line" not in _pw97 and "## Verdicts" in _pw97 and "body line one" in _pok97,
      repr((_pw97, _pok97)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. The Tailscale routes read the port the boot binds (the integrator's leftover, review 1016c)
# ════════════════════════════════════════════════════════════════════════════════════════════════
# B's A09 lead named panel/routes/tailscale.py's `cfg.get("port", 5000)` reads as raw. Each one is
# a load_config read, so section 4's reader is theirs too; this drives the routes themselves with a
# hand-edited port, so a route that went back to reading config.json raw fails here by name.
from unit.part12 import P9_ADMIN, _p9_client  # noqa: E402
from panel.ops import tailscale_integration as _tsi97  # noqa: E402
from panel.routes import tailscale as _tsr97  # noqa: E402


def _r26j_ts_ports():
    """[(where, port)] the Serve enable and the status JSON's suggestion were handed, config.json port 0."""
    seen = []
    d = _tf97.mkdtemp(dir=_TMP97)
    f = os.path.join(d, "config.json")
    with open(f, "w", encoding="utf-8") as fh:
        _json97.dump({"port": 0}, fh)
    saved_cache = dict(_cfg97._cfg_cache)
    info = _tsi97.TailscaleInfo(installed=True, running=True, backend_state="Running")
    try:
        _p9_arm(patch=_p9_patch, who="part97")
        _p9_patch(_cfg97, "CONFIG_FILE", _Path97(f))     # restored by _p9_restore_all, as in _r26a_load
        _cfg97._cfg_cache.update(key=None, data=None)
        _p9_patch(_tsr97, "_serve_enable",
                  lambda port, mount, funnel, page: (seen.append(("serve", port)), ("", 204))[1])
        _p9_patch(_tsi97, "suggest_best_bind", lambda port, **k: seen.append(("suggest", port)) or {})
        _p9_patch(_tsi97, "get_tailscale_info", lambda force_refresh=False: info)
        c = _p9_client(P9_ADMIN)
        codes = (c.post("/api/tailscale/serve", json={"action": "enable", "mount": "/",
                                                      "funnel": False}).status_code,
                 c.get("/api/tailscale").status_code)
    finally:
        _p9_restore_all()
        _cfg97._cfg_cache.clear()
        _cfg97._cfg_cache.update(saved_cache)
    return codes, seen


_tsp97 = _r26j_ts_ports()
check("tailscale routes: with a hand-edited port 0 in config.json, Serve's enable and the status "
      "page's bind suggestion are handed 5000, the port the boot binds (never 0)",
      _tsp97 == ((204, 200), [("serve", 5000), ("suggest", 5000)]), repr(_tsp97))
check("part97: ...nor did the Serve and status routes it drove since (every host call was stubbed)",
      len(_P9_TRIPPED) == _trip97, repr(_P9_TRIPPED[_trip97:][:6]))
