"""Part 51 of the unit suite: review 1011's core, system_ops, ssh-core and reboot findings.

* The recovery CLI (manage.py) starts none of the service's background workers.
* (further sections are added below, one per finding)

HOW IT RUNS. Every outside call is a stand-in (patched with part20's _patch / _patched, undone at
the end of each block); nothing touches the network, sudo, a real host or the checkout's data/.
"""
import os
import tempfile as _tf51
import types as _types51

from unit.part01 import SO, check
from unit.part05 import _root
from unit.part20 import _patch, _patched

import app as _app51  # noqa: E402

NS = _types51.SimpleNamespace

# ── A01: the recovery CLI starts no background workers ──────────────────────────────────────────


class _RecThread51:
    """A threading.Thread stand-in that records what was made and never runs it."""
    made = []

    def __init__(self, target=None, name=None, daemon=None, args=()):
        self.target, self.name = target, name
        _RecThread51.made.append(self)

    def start(self):
        """Never started."""


def _workers_started51(env_on):
    """[thread names] a supervisor and the hub-lag watch would start, with the CLI's flag on/off."""
    _RecThread51.made = []
    spawned = []
    saved = os.environ.pop(_app51.NO_WORKERS_ENV, None)
    try:
        if env_on:
            os.environ[_app51.NO_WORKERS_ENV] = "1"
        with _patched():
            _patch(_app51, "threading", NS(Thread=_RecThread51))
            _patch(_app51._dr_process, "start_hub_lag_watch",
                   lambda spawn=None: spawned.append("hub-lag-watch"))
            _app51._make_supervisor(NS(logger=NS(error=lambda *a, **k: None)))("p51-worker",
                                                                                lambda: None)
            _app51._start_hub_lag_watch()
    finally:
        os.environ.pop(_app51.NO_WORKERS_ENV, None)
        if saved is not None:
            os.environ[_app51.NO_WORKERS_ENV] = saved
    return [t.name for t in _RecThread51.made] + spawned


_w51_on = _workers_started51(True)
_w51_off = _workers_started51(False)
check("recovery CLI: with manage.py's flag set, neither a supervised ticker nor the hub-lag watch "
      "is started (and without it both still are)",
      _w51_on == [] and _w51_off == ["supervise-p51-worker", "hub-lag-watch"],
      repr((_w51_on, _w51_off)))
with open(os.path.join(_root, "manage.py"), encoding="utf-8") as _f51:
    _msrc51 = _f51.read()
check("recovery CLI: manage.py sets the no-workers flag BEFORE it builds the app",
      "os.environ[NO_WORKERS_ENV] = \"1\"" in _msrc51
      and _msrc51.index("os.environ[NO_WORKERS_ENV]") < _msrc51.index("app = create_app()"))

# ── A01: allocating a port refuses when a valve sibling's config could not be read ──────────────


class _Q51:
    def __init__(self, rows):
        self._rows = rows

    def filter_by(self, **_kw):
        return self

    def all(self):
        return list(self._rows)


def _alloc51(read):
    """resolve_free_port's answer (or the exception it raised) over five stopped csgo siblings."""
    sibs = [NS(game_type="csgo", port=27015 + i, short_name="csgo%d" % i, lgsm_name="csgoserver")
            for i in range(5)]
    with _patched():
        _patch(_app51, "_remote_listening_ports", lambda remote: set())
        _patch(_app51, "GameServer", NS(query=_Q51(sibs)))
        _patch(_app51, "sm_game_engine", lambda gt: "valve")
        _patch(_app51, "lgsm_get_values", read)
        try:
            return _app51.resolve_free_port(NS(name="h51"), 1, 27015, "csgo")
        except Exception as e:  # noqa: BLE001 - the answer under test
            return e


def _first_unread51(remote, user, selfname, keys):
    """The first sibling's read did not complete (a tailscale timeout); the rest answer."""
    return None if user == "csgo0" else {"clientport": "", "sourcetvport": ""}


def _first_raises51(remote, user, selfname, keys):
    if user == "csgo0":
        raise OSError("the host did not answer")
    return {"clientport": "", "sourcetvport": ""}


_a51_none = _alloc51(_first_unread51)
_a51_raise = _alloc51(_first_raises51)
_a51_ok = _alloc51(lambda remote, user, selfname, keys: {
    "clientport": "", "sourcetvport": "27020" if user == "csgo0" else ""})
check("free-port: a valve sibling whose config could not be read (None, or a raise) refuses with "
      "PortScanUnreadable instead of handing out a port it may own",
      type(_a51_none).__name__ == "PortScanUnreadable"
      and type(_a51_raise).__name__ == "PortScanUnreadable"
      and "csgo0" in str(_a51_none), repr((_a51_none, _a51_raise)))
check("free-port: ...while a sibling read that answered still steers past its SourceTV port",
      _a51_ok == (27021, True), repr(_a51_ok))
with _patched():
    _patch(_app51, "_remote_listening_ports", lambda remote: set())
    _patch(_app51, "GameServer", NS(query=_Q51([NS(game_type="csgo", port=27015, short_name="csgo0",
                                                   lgsm_name="csgoserver")])))
    _patch(_app51, "sm_game_engine", lambda gt: "valve")
    _patch(_app51, "lgsm_get_values", lambda remote, user, selfname, keys:
           {"clientport": "27005", "sourcetvport": "27020"} if user == "new" else None)
    try:
        _aux51 = _app51._resolve_source_aux_ports(NS(name="h51"), 1, "new", "csgoserver", 27016)
    except Exception as _e51:  # noqa: BLE001 - the answer under test
        _aux51 = _e51
check("aux ports: the post-install move stays best-effort -- an unreadable sibling is skipped, "
      "not raised", _aux51 == {}, repr(_aux51))

# ── A01 lead: a hand-edited socketio_cors_origins that is not a list or a string ────────────────
_so51 = []
for _v51 in (5, 2.5, True, {"a": 1}):
    try:
        _so51.append(_app51._explicit_socket_origins(_v51))
    except Exception as _e51:  # noqa: BLE001 - the answer under test
        _so51.append(_e51)
check("socket origins: a number (or any non-list) in socketio_cors_origins lists no origin instead "
      "of raising inside every handshake; a list and a string still work",
      _so51 == [[], [], [], []]
      and _app51._explicit_socket_origins(["https://a.example", "*"]) == ["https://a.example"]
      and _app51._explicit_socket_origins("https://a.example") == ["https://a.example"],
      repr(_so51))

# ── A02: the branch list's fetch is serialised with the status fetch and the installer ──────────
_bl51 = {"fetched": [], "updating": False}


def _fetch_rec51():
    _bl51["fetched"].append(SO._update_lock.locked())


with _patched():
    _patch(SO, "_is_git_checkout", lambda: True)
    _patch(SO, "_tracked_branch", lambda: "main")
    _patch(SO, "_fetch_all_branches", _fetch_rec51)
    _patch(SO, "_update_in_progress", lambda: _bl51["updating"])
    _patch(SO, "_git", lambda args, timeout=45: ("refs/remotes/origin/main\nrefs/remotes/origin/dev\n",
                                                 "", 0))
    _bl51_ts0 = SO._update_cache["ts"]
    SO._update_cache["ts"] = 12345.0
    try:
        _bl51_idle = SO.list_panel_branches()
        _bl51_ts = SO._update_cache["ts"]
        _bl51["updating"] = True
        _bl51_busy = SO.list_panel_branches()
    finally:
        SO._update_cache["ts"] = _bl51_ts0
check("branch list: its fetch runs under _update_lock (the status check's single-flight lock), and "
      "a status cached before the ref moved is recomputed next time",
      _bl51["fetched"][:1] == [True] and _bl51_ts == 0.0 and _bl51_idle == (["main", "dev"], "main"),
      repr((_bl51, _bl51_ts, _bl51_idle)))
check("branch list: ...and while an update runs it fetches nothing, listing the refs already here",
      len(_bl51["fetched"]) == 1 and _bl51_busy == (["main", "dev"], "main"),
      repr((_bl51, _bl51_busy)))

# ── A02: no branch switch is launched over a running update, and its log is never removed ───────
_sw51 = {"writes": [], "launch": []}
with _patched():
    from panel.core import config as _cfg51
    _patch(SO, "_is_git_checkout", lambda: True)
    _patch(SO, "_update_in_progress", lambda: True)
    _patch(SO, "_git", lambda args, timeout=45: ("0123abc\trefs/heads/dev\n", "", 0))
    _patch(SO, "_launch_installer", lambda **k: (_sw51["launch"].append(k), (False, "refused"))[1])
    _patch(_cfg51, "load_config", lambda: {})
    _patch(_cfg51, "update_config", lambda fn: _sw51["writes"].append(fn))
    _sw51_dev = SO.panel_switch_branch("dev")
check("branch switch: to a branch other than main is refused too while an update runs, before the "
      "config is written or the launcher reached",
      _sw51_dev[0] is False and "being installed right now" in _sw51_dev[1]
      and _sw51["writes"] == [] and _sw51["launch"] == [], repr((_sw51_dev, _sw51)))

_li51_dir = _tf51.mkdtemp(prefix="lgsm-p51-launch-")
os.makedirs(os.path.join(_li51_dir, "data"))
with open(os.path.join(_li51_dir, "install.sh"), "w", encoding="utf-8") as _fh51:
    _fh51.write("#!/bin/bash\n")
_li51_log = os.path.join(_li51_dir, "data", "self-update.log")
_li51_seen = []


def _li51_run(*_a, **_k):
    _li51_seen.append(os.path.exists(_li51_log))
    return NS(returncode=1, stderr="Unit panel-selfupdate.service already exists.", stdout="")


with _patched():
    _patch(SO, "PANEL_DIR", _li51_dir)
    _patch(SO, "_is_system_service", lambda: False)
    _patch(SO, "_helper_present", lambda: False)
    _patch(SO, "_update_in_progress", lambda: True)
    _patch(SO, "subprocess", NS(run=_li51_run, DEVNULL=-3, PIPE=-1))
    with open(_li51_log, "w", encoding="utf-8") as _fh51:
        _fh51.write("=== panel self-update ===\n[ OK ] step 3\n")
    _li51 = SO._launch_installer(target_ref="", branch="dev")
check("self-update launcher: while a run is in progress it leaves that run's log in place (the "
      "launch it then makes is refused)",
      _li51[0] is False and _li51_seen == [True] and os.path.exists(_li51_log),
      repr((_li51, _li51_seen)))

# ── A02: a disconnect hook (and a ban-change listener) is keyed by module AND qualified name ───
from panel.ops import socket_hooks as _sh51  # noqa: E402
from panel.security import banlist as _bl51mod  # noqa: E402


def _same_site51(module, heard, tag):
    """A `lambda sid: ...` as register() in `module` would build it."""
    fn = (lambda *a: heard.append(tag))  # noqa: E731 - it is the lambda shape under test
    fn.__qualname__, fn.__module__ = "register.<locals>.<lambda>", module
    return fn


_heard51 = []
_saved_hooks51, _saved_ls51 = dict(_sh51._hooks), dict(_bl51mod._listeners)
try:
    _sh51._hooks.clear()
    _sh51.add_disconnect_hook(_same_site51("panel.routes.host_terminal", _heard51, "terminal"))
    _sh51.add_disconnect_hook(_same_site51("panel.routes.p51_other", _heard51, "other"))
    _sh51.add_disconnect_hook(_same_site51("panel.routes.p51_other", _heard51, "other again"))
    _sh51.run_disconnect_hooks("sid51")
    _bl51mod._listeners.clear()
    _bl51mod.on_change(_same_site51("panel.routes.server_files", _heard51, "ban sweep"))
    _bl51mod.on_change(_same_site51("panel.routes.p51_other", _heard51, "ban other"))
    _bl51_n = len(_bl51mod._listeners)
finally:
    _sh51._hooks.clear()
    _sh51._hooks.update(_saved_hooks51)
    _bl51mod._listeners.clear()
    _bl51mod._listeners.update(_saved_ls51)
check("socket hooks: two modules' register.<locals>.<lambda> hooks both run (a second module's no "
      "longer replaces the terminal's cleanup), while one re-registered from the same site replaces "
      "itself", sorted(_heard51) == ["other again", "terminal"], repr(_heard51))
check("ban listeners: ...and the same for banlist.on_change", _bl51_n == 2, repr(_bl51_n))

# ── A02 lead: a backup restore and a self-update exclude each other ─────────────────────────────
from panel.ops import backup as _bk51  # noqa: E402

_rx51 = []
with _patched():
    _patch(SO, "_update_in_progress", lambda: True)
    _patch(_bk51, "_restore_backup_locked", lambda *a, **k: (_rx51.append(a), (True, "restored"))[1])
    _rx51_r = _bk51.restore_backup("x.tar.gz")
check("restore: refused while a self-update is in progress (its rollback could put the pre-update "
      "database back over the restored one), and the restore lock is released",
      _rx51_r[0] is False and "update is being installed" in _rx51_r[1] and _rx51 == []
      and not _bk51._restore_lock.locked(), repr((_rx51_r, _rx51)))
_rx51_dir = _tf51.mkdtemp(prefix="lgsm-p51-rx-")
with open(os.path.join(_rx51_dir, "install.sh"), "w", encoding="utf-8") as _fh51:
    _fh51.write("#!/bin/bash\n")
_rx51_run = []
with _patched():
    _patch(SO, "PANEL_DIR", _rx51_dir)
    _patch(SO, "_is_system_service", lambda: False)
    _patch(SO, "_helper_present", lambda: False)
    _patch(SO, "subprocess", NS(run=lambda *a, **k: (_rx51_run.append(a), NS(returncode=0, stderr=""))[1],
                                DEVNULL=-3, PIPE=-1))
    _bk51._restore_lock.acquire()
    try:
        _rx51_u = SO._launch_installer(target_ref="", branch="main")
    finally:
        _bk51._restore_lock.release()
check("self-update: not launched while a backup restore holds the restore lock",
      _rx51_u[0] is False and "restore is in progress" in _rx51_u[1] and _rx51_run == []
      and not os.path.exists(os.path.join(_rx51_dir, "data", "self-update.sh")),
      repr((_rx51_u, _rx51_run)))

# ── A02 lead: repair restores a renamed file's original and skips a new one ─────────────────────
_rp51 = []


def _rp51_git(args, timeout=45):
    a = list(args)
    if a[:1] == ["checkout"]:
        # git refuses the WHOLE command when any path is not in HEAD.
        _rp51.append(a)
        return ("", "", 1 if {"new.py", "renamed.py"} & set(a) else 0)
    if a == ["rev-parse", "--short", "HEAD"]:
        return ("abc1234\n", "", 0)
    if a[:3] == ["diff", "--name-status", "HEAD"]:
        return ("M\tapp.py\nA\tnew.py\nR100\told.py\trenamed.py\n", "", 0)
    return ("", "", 0)


with _patched():
    _patch(SO, "_git", _rp51_git)
    _patch(SO, "_is_git_checkout", lambda: True)
    _patch(SO, "_update_in_progress", lambda: False)
    _rp51_all = SO.panel_repair(None)
    _rp51_new = SO.panel_repair(["new.py"])
    SO._integrity_cache["data"] = None
check("repair: with a staged add and a rename present, 'restore all' checks out only paths HEAD "
      "has (the rename's original), so git does not refuse the whole command",
      _rp51_all[0] is True and _rp51_all[2] == ["app.py", "old.py"]
      and _rp51[:1] == [["checkout", "HEAD", "--", "app.py", "old.py"]], repr((_rp51_all, _rp51)))
check("repair: ...and a selection of only a NEW file says there is nothing to restore it to",
      _rp51_new[0] is False and "new" in _rp51_new[1] and len(_rp51) == 1, repr((_rp51_new, _rp51)))
