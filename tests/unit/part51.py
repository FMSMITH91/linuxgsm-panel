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

# ── A01: a valve sibling whose config could not be read is SAID, not silently "no aux ports" ────


class _Q51:
    def __init__(self, rows):
        self._rows = rows

    def filter_by(self, **_kw):
        return self

    def all(self):
        return list(self._rows)


def _alloc51(read):
    """(resolve_free_port's answer or exception, warnings logged) over five stopped csgo siblings."""
    sibs = [NS(game_type="csgo", port=27015 + i, short_name="csgo%d" % i, lgsm_name="csgoserver")
            for i in range(5)]
    warned = []
    with _patched():
        _patch(_app51, "_remote_listening_ports", lambda remote: set())
        _patch(_app51, "GameServer", NS(query=_Q51(sibs)))
        _patch(_app51, "sm_game_engine", lambda gt: "valve")
        _patch(_app51, "lgsm_get_values", read)
        _patch(_app51, "_log", NS(warning=lambda msg, *a, **k: warned.append(msg % a),
                                  debug=lambda *a, **k: None))
        try:
            got = _app51.resolve_free_port(NS(name="h51"), 1, 27015, "csgo")
        except Exception as e:  # noqa: BLE001 - the answer under test
            got = e
    return got, warned


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
check("free-port: a valve sibling whose config could not be read (None, or a raise) is logged as a "
      "warning naming it -- the later 'Port N was unavailable' has a recorded reason -- and does not "
      "block the install (an orphaned row would block every install on the host)",
      _a51_none[0] == (27020, True) and _a51_raise[0] == (27020, True)
      and any("csgo0" in w and "not reserved" in w for w in _a51_none[1])
      and any("csgo0" in w for w in _a51_raise[1]), repr((_a51_none, _a51_raise)))
check("free-port: ...while a sibling read that answered still steers past its SourceTV port, "
      "with no warning", _a51_ok == ((27021, True), []), repr(_a51_ok))
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


def _git51(args, timeout=45):
    """for-each-ref's two branches; rev-parse names a tip that moves with every fetch."""
    if args[:1] == ["rev-parse"]:
        return ("tip%d\n" % len(_bl51["fetched"]), "", 0)
    return ("refs/remotes/origin/main\nrefs/remotes/origin/dev\n", "", 0)


with _patched():
    _patch(SO, "_is_git_checkout", lambda: True)
    _patch(SO, "_tracked_branch", lambda: "main")
    _patch(SO, "_fetch_all_branches", _fetch_rec51)
    _patch(SO, "_update_in_progress", lambda: _bl51["updating"])
    _patch(SO, "_git", _git51)
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
    _patch(_cfg51, "update_config", _sw51["writes"].append)
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

# ── A02 lead: a terminal keystroke payload that is not a string is ignored ──────────────────────
from panel.ops import terminal_session as _tsess51  # noqa: E402

_tw51 = []
for _d51 in (123, ["x"], {"a": 1}, "ls\r"):
    _s51 = NS(_closed=False, last_input=0.0, _chan=None, _fd=None, label="p51")
    try:
        _tsess51.Session.write(_s51, _d51)
        _tw51.append(_s51.last_input > 0)
    except Exception as _e51:  # noqa: BLE001 - the answer under test
        _tw51.append(type(_e51).__name__)
check("terminal: term_input data that is not a string is dropped, not an AttributeError in the "
      "socket handler (a string still counts as input)",
      _tw51 == [False, False, False, True], repr(_tw51))

# ── A03: a tailnet rule counts as a way in only where UFW, first match wins, lets sshd through ──
from unit.part02 import protect as _protect51  # noqa: E402


def _fw51(rules):
    g = _protect51(NS(port=22), rules, tailscale=(True, False), sshd_ports=(22,))
    return {(x["port_label"], x["action"], x.get("iface", "")): x for x in g}


_fw51_port = _fw51(["22/tcp ALLOW IN Anywhere", "5000/tcp on tailscale0 ALLOW IN Anywhere"])
_fw51_deny = _fw51(["22/tcp ALLOW IN Anywhere", "Anywhere on tailscale0 DENY IN Anywhere",
                    "Anywhere on tailscale0 ALLOW IN Anywhere"])
_fw51_ok = _fw51(["22/tcp ALLOW IN Anywhere", "Anywhere on tailscale0 ALLOW IN Anywhere"])
_fw51_ssh = _fw51(["22/tcp ALLOW IN Anywhere", "22 on tailscale0 ALLOW IN Anywhere"])
_fw51_k = ("22/tcp", "ALLOW", "")


def _fw51_state(gp):
    return {k: (v["is_access"], v["protected"], v["warn"]) for k, v in gp.items()}


check("firewall: a port-scoped tailnet rule (5000/tcp on tailscale0) is not a way in, so the only "
      "public SSH rule stays protected",
      _fw51_port[_fw51_k]["protected"] and not _fw51_port[("5000/tcp", "ALLOW", "tailscale0")]["is_access"],
      repr(_fw51_state(_fw51_port)))
check("firewall: ...nor is a tailscale0 allow below a tailscale0 DENY (UFW takes the first match)",
      _fw51_deny[_fw51_k]["protected"], repr(_fw51_state(_fw51_deny)))
check("firewall: ...while a whole-interface allow, or an SSH-port allow on tailscale0, is still the "
      "second way in that makes the public rule only warn",
      _fw51_ok[_fw51_k]["warn"] and not _fw51_ok[_fw51_k]["protected"]
      and _fw51_ssh[_fw51_k]["warn"] and not _fw51_ssh[_fw51_k]["protected"],
      repr((_fw51_state(_fw51_ok), _fw51_state(_fw51_ssh))))

# ── A03: the bootstrap reads the exit codes of its UFW, timezone, swap and fail2ban steps ───────
from panel.ops.ssh_manager import _core as _smc51  # noqa: E402
from panel.ops.ssh_manager import hosts as _smh51  # noqa: E402

_BS51_EFF = ("port 22\nclientaliveinterval 300\nclientalivecountmax 2\n"
             "permitrootlogin without-password\npasswordauthentication no\n")


def _bootstrap51(fail):
    """remote_bootstrap_vps on a stubbed host where the verbs named in `fail` exit 1."""
    calls = []

    def _priv(server, verb, args=None, **_k):
        calls.append((verb, tuple(args or ())))
        if verb == "sshd-effective-config":
            return (_BS51_EFF, "", 0)
        if verb in fail or (verb, tuple(args or ())) in fail:
            return ("", "ERROR: %s failed on p51" % verb, 1)
        return ("", "", 0)

    def _run(server, cmd, **_k):
        if "swapon" in cmd:
            return ("0\n", "", 0)
        return ("", "", 0)

    with _patched():
        _patch(_smc51, "is_local_server", lambda s: True)   # no reboot step
        _patch(_smc51, "_wait_for_dpkg_lock", lambda *a, **k: True)
        _patch(_smc51, "run_privileged", _priv)
        _patch(_smc51, "run_command", _run)
        _patch(_smc51, "write_root_file", lambda s, target, content, **k: (
            calls.append(("write", (target,))),
            ("", "disk full", 1) if ("write", target) in fail else ("", "", 0))[1])
        _patch(_smc51, "_restart_sshd", lambda *a, **k: ("", "", 0))
        _patch(_smh51, "_bootstrap_node", lambda s: [])
        _patch(_smh51, "install_gamedig", lambda s, timeout=600: ("", 0))
        _patch(_smh51, "_write_node_tools_cron", lambda s: True)
        _patch(_smh51, "_bootstrap_ssh_ports", lambda s: ["22"])
        ok, msg, log = _smh51.remote_bootstrap_vps(
            NS(id=9151, host="203.0.113.51", auth_method="key"), set_timezone="America/Chicago",
            enable_ufw=True, install_lgsm_deps=False, username="", install_fail2ban=True,
            do_reboot=False)
    return ok, msg, log, calls


_bs51_ok = _bootstrap51(())
check("bootstrap (control): with every step succeeding the job is 'complete'",
      _bs51_ok[0] is True and "VPS bootstrap complete" in _bs51_ok[1] and "NOT DONE" not in _bs51_ok[2],
      repr(_bs51_ok[:2]))
_bs51_ufw = _bootstrap51({"ufw-enable"})
check("bootstrap: a `ufw enable` that failed is 'finished, but the firewall was NOT enabled', never "
      "'complete'",
      _bs51_ufw[0] is False and "firewall was NOT enabled" in _bs51_ufw[1]
      and "ufw enable" in _bs51_ufw[1] and "NOT DONE" in _bs51_ufw[2], repr(_bs51_ufw[:2]))
_bs51_dd = _bootstrap51({("ufw-default", ("deny", "incoming"))})
check("bootstrap: ...and so is a `ufw default deny incoming` that failed",
      _bs51_dd[0] is False and "ufw default deny incoming" in _bs51_dd[1], repr(_bs51_dd[:2]))
_bs51_tz = _bootstrap51({"set-timezone"})
_bs51_sw = _bootstrap51({"create-swapfile"})
_bs51_f2 = _bootstrap51({"service-enable-now"})
_bs51_jw = _bootstrap51({("write", "fail2ban-jail-local")})
check("bootstrap: a failed timezone, swap file or fail2ban step is named in a 'finished, but' "
      "answer and logged NOT DONE, not reported as done",
      _bs51_tz[0] is False and "timezone was not set to America/Chicago" in _bs51_tz[1]
      and _bs51_sw[0] is False and "swap file was not created" in _bs51_sw[1]
      and "2G swap file created" not in _bs51_sw[2]
      and _bs51_f2[0] is False and "fail2ban is not protecting SSH" in _bs51_f2[1]
      and _bs51_jw[0] is False and "jail could not be written" in _bs51_jw[1]
      and not any(c[0] == "service-enable-now" and c[1] == ("fail2ban",) for c in _bs51_jw[3]),
      repr([r[1] for r in (_bs51_tz, _bs51_sw, _bs51_f2, _bs51_jw)]))

# ── A03 lead: "tailscale0 is allowed" is not a way in when sshd listens only on the public address ──
_TS51_HDR = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n"


def _tailnet51(listing, ports="port 22\n"):
    """_tailnet_ssh_state on a host with Tailscale up, SSH off, tailscale0 allowed in UFW."""
    def _rc(server, cmd, **_k):
        if "status --json" in cmd:
            return ('{"BackendState":"Running"}', "", 0)
        if "debug prefs" in cmd:
            return ('{"RunSSH": false}', "", 0)
        if "/sys/class/net" in cmd:
            return ("eth0\nlo\ntailscale0\n", "", 0)
        return ("", "", 0)

    def _rp(server, verb, args=(), **_k):
        if verb == "ufw-status":
            return (_TS51_HDR + "Anywhere on tailscale0     ALLOW IN    Anywhere\n", "", 0)
        if verb == "sshd-effective-config":
            return (ports, "", 0)
        if verb == "listening-sockets":
            return listing
        return ("", "", 0)

    with _patched():
        _patch(_smc51, "run_command", _rc)
        _patch(_smc51, "run_privileged", _rp)
        return _smh51._tailnet_ssh_state(NS(id=9152, host="203.0.113.52", auth_method="key"))


def _ss51(*addrs):
    return ("State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
            + "".join("LISTEN 0      128    %s 0.0.0.0:*\n" % a for a in addrs), "", 0)


_tn51_public = _tailnet51(_ss51("203.0.113.52:22", "127.0.0.1:631"))
_tn51_both = _tailnet51(_ss51("203.0.113.52:22", "127.0.0.1:22"))
check("tailnet ssh state: sshd seen listening only on the public address is NOT a tailnet way in, "
      "though tailscale0 is allowed",
      _tn51_public == (True, False, False) and _tn51_both == (True, False, False),
      repr((_tn51_public, _tn51_both)))
_tn51_ok = [_tailnet51(_ss51(a)) for a in ("0.0.0.0:22", "[::]:22", "*:22", "100.101.102.103:22",
                                           "[fd7a:115c:a1e0::5]:22")]
_tn51_unread = [_tailnet51(("", "timed out", -1)), _tailnet51(_ss51("203.0.113.52:22"), ports=""),
                _tailnet51(_ss51("203.0.113.52:2222"))]
check("tailnet ssh state: ...while a wildcard or a Tailscale address still is, and an unread or "
      "empty listing changes nothing (the firewall test decides, as before)",
      all(t == (True, False, True) for t in _tn51_ok + _tn51_unread), repr((_tn51_ok, _tn51_unread)))

# ── A05: a count the stop phase cannot read is read the census's way, and does not loop silently ──
from panel.services import host_reboot as _hr51  # noqa: E402
from panel.services import notifications as _notif51  # noqa: E402


class _JobLike51:
    """The _Job methods under test, on an object holding only what they read."""

    _back_to_waiting = _hr51._Job._back_to_waiting
    _wait_back = _hr51._Job._wait_back
    _waiting_again = _hr51._Job._waiting_again
    _stop_group = _hr51._Job._stop_group
    _bounce_for = _hr51._Job._bounce_for
    _still_empty = _hr51._Job._still_empty
    _past_deadline = _hr51._Job._past_deadline
    _bounced = _hr51._Job._bounced

    def __init__(self, rid):
        self.remote_id, self.by, self.fired, self.wait_info = rid, "p51", False, None
        self.remote = NS(id=rid, name="p51-host", display_name="p51-host")
        self.job = {"mode": "when_empty", "boot": "b51"}
        self.bounce = self.bounce_joined = False
        self.bounce_unread = ""
        self.deadline = None
        self.entries, self.stopped = [], []

    def _cancelled(self):
        return False

    def _stop_one(self, e):
        self.stopped.append(e["id"])
        e["stop"] = "stopped"


_RID51 = 951051
_sent51 = []
with _patched():
    _patch(_notif51, "notify", lambda key, title, body, **k: _sent51.append((key, title, body)))
    _j51 = _JobLike51(_RID51)
    try:
        for _ in range(_hr51.BOUNCE_NOTIFY_AT + 1):
            _j51._back_to_waiting(None, bounce=False, reason="a player count could not be read",
                                  backoff=True, unread="fctr")
            with _hr51._rwe_lock:
                _j51.wait_info = _hr51._reboot_when_empty.pop(_RID51, None)   # the next fire's
    finally:
        with _hr51._rwe_lock:
            _hr51._reboot_when_empty.pop(_RID51, None)
_unread51 = [b for _k, t, b in _sent51 if t == "Host reboot cannot read a player count"]
check("reboot when empty: a count unread just before the stop, again and again, sends ONE notice "
      "naming the server at the bounce threshold (it was silent for the whole wait), and is still "
      "not counted as a player joining",
      len(_unread51) == 1 and "fctr" in _unread51[0]
      and not any("Players keep joining" in b for _k, _t, b in _sent51)
      and not (_j51.wait_info or {}).get("bounces")
      and (_j51.wait_info or {}).get("unread_bounces") == _hr51.BOUNCE_NOTIFY_AT + 1,
      repr((_sent51, _j51.wait_info)))


def _stop_group51(per_server, batched):
    """_stop_group over one server whose own read answers `per_server`, the host batch `batched`."""
    j = _JobLike51(_RID51)
    gs = NS(id=5101, name="fctr", short_name="fctrserver")
    other = NS(id=5102, name="gmod", short_name="gmodserver")
    e = {"id": 5101, "name": "fctr"}
    seen = []
    with _patched():
        _patch(_hr51._mon, "_server_slots", lambda g, allow_console=False, primary=None: per_server)
        _patch(_hr51._mon, "_batched_slots",
               lambda servers: (seen.append(sorted(s.id for s in servers)), batched)[1])
        j._stop_group([e], {5101: gs, 5102: other})
    return j, seen


_sg51_batch, _sg51_seen = _stop_group51((None, None, None), {5101: (0, 16, None)})
_sg51_none, _ = _stop_group51((None, None, None), {})
_sg51_own, _sg51_own_seen = _stop_group51((0, 16, None), {5101: (3, 16, None)})
check("reboot when empty: a server its own account cannot read is read by the host's batched "
      "query (the census's path) before its stop, and stopped when that reads it empty",
      _sg51_batch.stopped == [5101] and not _sg51_batch.bounce and _sg51_seen == [[5101, 5102]],
      repr((_sg51_batch.stopped, _sg51_batch.bounce, _sg51_seen)))
check("reboot when empty: ...one neither read can see still stops the reboot, recorded by name; "
      "and a server its own account reads is not asked twice",
      _sg51_none.stopped == [] and _sg51_none.bounce and not _sg51_none.bounce_joined
      and _sg51_none.bounce_unread == "fctr"
      and _sg51_own.stopped == [5101] and _sg51_own_seen == [],
      repr((_sg51_none.__dict__, _sg51_own.stopped, _sg51_own_seen)))

_jb51 = _JobLike51(_RID51)
_jb51.bounce, _jb51.bounce_unread = True, "fctr"
with _patched():
    _patch(_hr51, "rollback", lambda *a, **k: None)
    _patch(_notif51, "notify", lambda *a, **k: None)
    try:
        _jb51._bounced()
        with _hr51._rwe_lock:
            _jb51_info = dict(_hr51._reboot_when_empty.get(_RID51) or {})
    finally:
        with _hr51._rwe_lock:
            _hr51._reboot_when_empty.pop(_RID51, None)
check("reboot when empty: ...and the stop phase's own bounce (_bounced) is what counts it",
      _jb51_info.get("unread_bounces") == 1 and not _jb51_info.get("bounces"), repr(_jb51_info))

# ── A05: a reboot whose every planned server the operator took over is not "no server running" ──
def _bare51(servers):
    with _patched():
        _patch(_hr51, "_rbhold_remark_unplanned", lambda rid: None)
        try:
            now = _hr51.time.time()
            return _hr51._bare_answered(NS(id=_RID51, display_name="p51-host"),
                                        {"boot": "b-old", "sent": now - 90, "servers": servers},
                                        {"boot": "b-new", "uptime": 30}, now, now - 90)
        finally:
            _hr51._reboot_awaiting.pop(_RID51, None)


_bare51_taken = _bare51([{"name": "fctr", "owner": "p51", "stop": "stopped"},
                         {"name": "gmod", "owner": "p51", "stop": "stopped"}])
_bare51_plain = _bare51([])
check("reboot: a job whose two stopped servers the operator took over during the reboot says so, "
      "not 'no running game server was found' (a truly empty plan still does)",
      _bare51_taken[1] is True and "took over the 2 game servers it stopped" in _bare51_taken[0]
      and "no running game server" not in _bare51_taken[0]
      and "no running game server was found before it" in _bare51_plain[0],
      repr((_bare51_taken, _bare51_plain)))

# ── A05 lead: the maintenance probe's pattern is anchored to the script name ────────────────────
import re as _re51  # noqa: E402
import shlex as _shlex51  # noqa: E402

from panel.services import monitoring as _mon51  # noqa: E402

_mp51 = []
with _patched():
    _patch(_mon51, "run_command", lambda remote, cmd, timeout=30: (_mp51.append(cmd), ("IDLE\n", "", 0))[1])
    _mon51._lgsm_maintenance_running(NS(id=95153, host="192.0.2.53"),
                                     NS(short_name="rust1", lgsm_name="rustserver", game_type="rust",
                                        name="Rust"))
_mp51_argv = _shlex51.split(_mp51[0]) if _mp51 else []
_mp51_pat = _mp51_argv[_mp51_argv.index("-f") + 1] if "-f" in _mp51_argv[:-1] else ""
_mp51_hits = {c: bool(_re51.search(_mp51_pat, c)) for c in (
    "/bin/bash ./rustserver update", "/home/rust1/rustserver force-update", "bash ./rustserver backup",
    "/bin/bash ./myrustserver update", "/bin/bash ./rustserver updater-notes",
    "/bin/bash ./rustserver monitor")} if _mp51_pat else {}
check("maintenance probe: the pgrep pattern matches only this script's own maintenance commands "
      "(not another script whose name ends in it, nor a longer command word)",
      _mp51_hits == {"/bin/bash ./rustserver update": True, "/home/rust1/rustserver force-update": True,
                     "bash ./rustserver backup": True, "/bin/bash ./myrustserver update": False,
                     "/bin/bash ./rustserver updater-notes": False,
                     "/bin/bash ./rustserver monitor": False},
      repr((_mp51, _mp51_pat, _mp51_hits)))
