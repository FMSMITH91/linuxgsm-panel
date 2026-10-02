"""Part 23 of the unit suite: the debug report's hosts, game servers, console and workers (B4).

What is checked here, in order:
  1. the instrumentation the report reads, driven in the loops that write it: the monitor's probe
     classifier (R48), the console poller's per-server counters (R56), the loops' heartbeats and
     the supervisor's respawn count and thread names (R22), and the gates that keep the loops'
     names and the report's list of workers the same list;
  2. the sections themselves (R6, R46-R56), against a throwaway SQLite database and caches filled
     by hand: what each prints, that a read that fails says so rather than reading as "none" or 0,
     and that no host, address, account name, server name or free text reaches the output.

HOW IT RUNS. Its own Flask app on a temp SQLite file (not part12's, so nothing here depends on
what an earlier part left in its database). Every module attribute it replaces, every process-wide
map it writes and every runtime_stats group is restored in the finally at the bottom. Nothing here
starts a thread, opens a socket or runs a command: the loops are driven one pass at a time with a
`time.sleep` that raises, and every host read is a stub.
"""
import ast as _ast23
import os
import re as _re23
import shutil as _shutil23
import tempfile as _tf23
import time as _time23
from pathlib import Path as _Path23
from types import SimpleNamespace as NS

from cryptography.fernet import Fernet as _Fernet23
from flask import Flask as _Flask23

from unit.part01 import check
import app as _app23mod
from panel.core import config as _cfg23
from panel.core import panel_state as _ps23
from panel.core import runtime_stats as _rs23
from panel.core.clock import utcnow as _utcnow23
from panel.db.models import UnreadableSecret as _Unreadable23
from panel.db.models import GameServer, HostSample, RemoteServer, db
from panel.ops import tailscale_integration as _tsi23
from panel.ops.debug_report import _src_tailscale as _srcts23
from panel.ops.debug_report import hosts as _h23
from panel.ops.debug_report import servers as _s23
from panel.ops.debug_report import workers as _w23
from panel.ops.debug_report._base import Ctx as _Ctx23
from panel.ops.ssh_manager import _core as _core23
from panel.ops.ssh_manager import firewall as _fw23
from panel.ops.ssh_manager import hosts as _smh23
from panel.ops.ssh_manager import portscan as _pscan23
from panel.routes import os_updates as _osu23  # noqa: F401 - imported so its ticker is defined
from panel.routes import server_files as _sf23
from panel.services import lgsm_data as _lgsm23
from panel.services import monitoring as _mon23
from panel.services import notifications as _notif23

_REPO23 = _Path23(__file__).resolve().parents[2]
_TMP23 = _tf23.mkdtemp(prefix="lgsm-unit-p23-")
_app23 = _Flask23("p23")
_app23.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_TMP23, "p23.db"),
                     SQLALCHEMY_TRACK_MODIFICATIONS=False)
db.init_app(_app23)

# Everything this part changes, put back in the finally.
_patched23 = []
_maps23 = [(m, dict(m)) for _e in _ps23.keyed_state_with_locks() for m, _lk in _e]
_monstate23 = {k: dict(v) for k, v in _ps23._monitor_state.items()}
_caches23 = [(c, dict(c)) for c in (_core23._host_metrics_cache, _pscan23._port_scan_cache,
                                    _fw23._specs_cache, _smh23._OS_SLUG_CACHE, _tsi23._cache,
                                    _sf23._console_viewers)]
_groups23 = {g: dict(v) for g, v in _rs23._GROUPS.items()}

# The values no output may contain: every one is a host, an address, an account, a name or free
# text that the fixtures plant where the sections read.
_SECRETS23 = ("p23-SECRET", "p23tsbox", "p23keybox", "p23localuser", "p23gameuser", "203.0.113",
              "tail-p23", "100.64.0.23", "p23-INGAME", "p23secretpath")


class _Stop23(Exception):
    """Raised by a fake sleep to end a loop after the pass under test."""


def _patch23(owner, name, value):
    _patched23.append((owner, name, getattr(owner, name)))
    setattr(owner, name, value)


def _restore23():
    while _patched23:
        owner, name, value = _patched23.pop()
        setattr(owner, name, value)


def _sleeper23(stop_on):
    """A time stand-in whose sleep() raises _Stop23 on its `stop_on`-th call."""
    calls = {"n": 0}

    def _sleep(_s):
        calls["n"] += 1
        if calls["n"] >= stop_on:
            raise _Stop23()
    return NS(time=_time23.time, monotonic=_time23.monotonic, sleep=_sleep)


def _hb23(name):
    return _rs23.snapshot("heartbeat").get(name) or {}


def _text23(res):
    return "\n".join(res.lines)


def _leaks23(text):
    return [s for s in _SECRETS23 if s in text]


# ── 1a. R48: the monitor's probe keeps its bool and records WHY, as a fixed token ─────────────

def _probe23():
    ts_host = NS(id=-2301, auth_method="tailscale", is_local=False)
    _patch23(_mon23, "run_command", lambda r, cmd, timeout=None: ("", "SSH command timed out", -1))
    first = _mon23._host_reachable(ts_host)
    rec1 = dict(_mon23._probe_record.get(-2301) or {})
    _time23.sleep(0.01)
    second = _mon23._host_reachable(ts_host)
    rec2 = dict(_mon23._probe_record.get(-2301) or {})
    check("probe record: a timed-out tailscale probe is still False, recorded as 'timeout' rc -1",
          first is False and rec1.get("token") == "timeout" and rec1.get("rc") == -1
          and rec1.get("streak") == 1 and rec1.get("ok") is False, repr(rec1))
    check("probe record: a second failure extends the streak and keeps when the failing began",
          second is False and rec2.get("streak") == 2
          and rec2.get("fail_since") == rec1.get("fail_since") and rec2.get("at") > rec1.get("at"),
          repr((rec1, rec2)))
    _patch23(_mon23, "run_command", lambda r, cmd, timeout=None: ("ok\n", "", 0))
    third = _mon23._host_reachable(ts_host)
    rec3 = dict(_mon23._probe_record.get(-2301) or {})
    check("probe record: an answer is True, resets the streak and stamps the last OK",
          third is True and rec3.get("streak") == 0 and rec3.get("ok_at") and rec3.get("token") is None
          and rec3.get("fail_since") is None, repr(rec3))
    cases = {
        "host_key_changed": _core23.HostKeyMismatch("The SSH host key for 203.0.113.9 has CHANGED"),
        "host_key_unreadable": _core23.HostKeyMismatch(
            "The stored SSH host key for x cannot be decrypted on this host"),
        "auth_failed": ConnectionError("SSH authentication failed. Check credentials."),
        "timeout": ConnectionError("Connection to 203.0.113.9:22 timed out."),
        "dns": ConnectionError("Cannot resolve hostname: p23keybox"),
        "credential_unreadable": ConnectionError("No usable SSH password is stored for 203.0.113.9."),
        "other:ValueError": ValueError("203.0.113.9 said no"),
    }
    got = {}
    for want, exc in cases.items():
        def _raise(r, cmd, timeout=None, _e=exc):
            raise _e
        _patch23(_mon23, "run_command", _raise)
        ok = _mon23._host_reachable(NS(id=-2302, auth_method="key", is_local=False))
        got[want] = (ok, (_mon23._probe_record.get(-2302) or {}).get("token"))
    check("probe record: a raised probe is False and classified by its fixed wording",
          all(v == (False, k) for k, v in got.items()), repr(got))
    check("probe record: no message or address is stored, only the token and rc",
          not _leaks23(repr(_mon23._probe_record.get(-2302))), repr(_mon23._probe_record.get(-2302)))
    replies = {"sudo_password_required": ("", "sudo: a password is required", 1),
               "ssh_cli_rc255": ("", "", 255), "empty_output_rc0": ("", "", 0),
               "host_key_changed": ("", "Host key verification failed.", 255),
               "refused": ("", "ssh: connect to host p23keybox port 22: Connection refused", 255)}
    rgot = {}
    for want, reply in replies.items():
        _patch23(_mon23, "run_command", lambda r, cmd, timeout=None, _rep=reply: _rep)
        _mon23._host_reachable(NS(id=-2303, auth_method="tailscale", is_local=False))
        rgot[want] = (_mon23._probe_record.get(-2303) or {}).get("token")
    check("probe record: a non-raising transport's reply is classified from stderr and rc",
          all(rgot[k] == k for k in replies), repr(rgot))
    _patch23(_mon23, "run_command", lambda r, cmd, timeout=None: ("", "", 7))
    _mon23._host_reachable(NS(id=-2304, auth_method=None, is_local=True))
    check("probe record: the panel host's own failure names its transport (local_rc7)",
          (_mon23._probe_record.get(-2304) or {}).get("token") == "local_rc7",
          repr(_mon23._probe_record.get(-2304)))
    _patch23(_mon23, "run_command", lambda r, cmd, timeout=None: ("ok", "", 0))
    check("probe record: a host object with no id is answered as before and records nothing",
          _mon23._host_reachable(NS()) is True and None not in _mon23._probe_record)
    _ps23.forget_rows(remote_ids=[-2301])
    check("probe record: registered, so a deleted host's id is forgotten with its other state",
          -2301 not in _mon23._probe_record
          and any(m is _mon23._probe_record for m in _ps23.remote_keyed_state()))


# ── 1b. R56: the console poller's per-server counters ─────────────────────────────────────────

class _Log23:
    """A console log on a fake host, answering the two reads _console_tick makes."""

    def __init__(self):
        self.ino, self.data, self.stat_ok, self.fail_chunk = 900, "", True, False

    def read(self, _server, _user, sh, timeout=30, selfname=None):
        if sh.startswith("stat -c"):
            return ("%d %d" % (self.ino, len(self.data)) if self.stat_ok else ""), "", 0
        if self.fail_chunk:
            return "", "SSH command timed out", -1
        a, n = sh.split("tail -c +", 1)[1].split(" ", 1)[0], sh.split("head -c ", 1)[1].split(";")[0]
        return ("B" + self.data[int(a) - 1:int(a) - 1 + int(n)] + "E"), "", 0


def _console23():
    sid = -2310
    log, pushed = _Log23(), []
    sio = NS(emit=lambda ev, payload, room=None, **k: pushed.append(payload.get("data")))
    gs = NS(console_log="/home/p23gameuser/p23secretpath/console.log", remote=NS(timezone=""),
            short_name="p23gameuser", lgsm_name="p23gameuser")
    _patch23(_core23, "read_as_game_user", log.read)
    _patch23(_sf23, "_host_timezone_cached", lambda *a, **k: "")

    def tick():
        _sf23._console_tick(_app23, sio, gs, sid)
        return dict(_sf23._console_feed.get(sid) or {})

    log.stat_ok = False
    f1 = tick()
    check("console feed: an unparseable stat is a failed tick with a fixed token",
          f1.get("streak") == 1 and f1.get("fails") == 1 and f1.get("last_fail") == "stat-unparseable",
          repr(f1))
    log.stat_ok, log.data = True, "old line\n"
    f2 = tick()
    check("console feed: first sight is a good tick (it reads nothing) and ends the streak",
          f2.get("streak") == 0 and f2.get("ticks") == 2 and not f2.get("pushed_at"), repr(f2))
    log.data += "new line\n"
    f3 = tick()
    check("console feed: a pushed chunk stamps pushed_at, and the push itself is unchanged",
          f3.get("pushed_at") and f3.get("streak") == 0 and pushed == ["new line"], repr((f3, pushed)))
    log.data += "more\n"
    log.fail_chunk = True
    f4 = tick()
    check("console feed: a read that never ran is 'read-failed', and the offset does not move",
          f4.get("last_fail") == "read-failed" and f4.get("streak") == 1
          and _ps23._console_offsets[sid]["pos"] == len("old line\nnew line\n"), repr(f4))
    log.fail_chunk, log.ino, log.data = False, 901, "boot\n"
    f5 = tick()
    check("console feed: a rotated log is counted, and its first chunk still pushed",
          f5.get("rotations") == 1 and pushed[-1] == "boot" and f5.get("streak") == 0, repr(f5))
    check("console feed: the counters hold no path, line or account (fixed tokens and numbers)",
          not _leaks23(repr(f5)) and "boot" not in repr(f5), repr(f5))
    check("console feed: registered, so a deleted server's counters are forgotten",
          any(m is _sf23._console_feed for m in _ps23.server_keyed_state()))


def _poller23():
    got = {}
    _sf23._start_console_poller(_app23, NS(emit=lambda *a, **k: None),
                                lambda name, target: got.__setitem__(name, target))
    poller = got.get("console-poller")
    sid = -2311

    def _drain_raises(app, remote, server_id):
        raise ConnectionError("tail of /home/p23secretpath failed")

    _patch23(_sf23, "_console_to_poll", lambda app, sio, server_id: NS(remote=None))
    _patch23(_sf23, "_drain_action_output", _drain_raises)
    _patch23(_sf23, "time", _sleeper23(1))
    _sf23._console_viewers.clear()
    _sf23._console_viewers[sid] = {"sock-p23": 1}
    before = _hb23("console-poller").get("passes", 0)
    try:
        poller()
    except _Stop23:
        pass
    feed = _sf23._console_feed.get(sid) or {}
    check("console poller: a console whose read raises is counted by exception CLASS, not message",
          feed.get("last_fail") == "raised:ConnectionError" and feed.get("streak") == 1, repr(feed))
    check("console poller: a pass with a failing console still completes, and beats",
          _hb23("console-poller").get("passes", 0) == before + 1
          and _hb23("console-poller").get("cadence") == 2
          and (_rs23.snapshot("console").get("poller|watched") or (0, None))[1] == 1,
          repr((_hb23("console-poller"), _rs23.snapshot("console"))))
    _sf23._console_viewers.clear()


# ── 1c. R22: heartbeats, failures, the supervisor's respawns and thread names ─────────────────

def _one_pass23(fn, stop_on):
    try:
        fn()
    except _Stop23:
        return True
    return False


def _loops23():
    _patch23(_app23mod, "_monitor_pass", lambda: None)
    _patch23(_app23mod, "time", _sleeper23(2))
    b = _hb23("monitor").get("passes", 0)
    _one_pass23(lambda: _app23mod._monitor_watch(_app23), 2)
    check("heartbeat: the monitor loop beats once per completed pass, with its cadence",
          _hb23("monitor").get("passes", 0) == b + 1 and _hb23("monitor").get("cadence") == 60,
          repr(_hb23("monitor")))

    def _boom():
        raise RuntimeError("pass failed")
    _patch23(_app23mod, "_monitor_pass", _boom)
    _patch23(_app23mod, "time", _sleeper23(2))
    f = _rs23.snapshot("loopfail").get("monitor", 0)
    _one_pass23(lambda: _app23mod._monitor_watch(_app23), 2)
    check("heartbeat: a failed monitor pass is counted and does NOT beat",
          _rs23.snapshot("loopfail").get("monitor", 0) == f + 1
          and _hb23("monitor").get("passes", 0) == b + 1, repr(_rs23.snapshot("loopfail")))
    for loop, name, stubs in (
            (_app23mod._player_count_watch, "player-counts", {"_refresh_player_counts": None}),
            (_app23mod._metrics_history_watch, "metrics-history",
             {"_record_metric_samples": None, "_prune_metric_samples": None}),
            (_app23mod._node_tools_cron_watch, "node-tools", {"_node_tools_cron_pass": None})):
        for attr in stubs:
            _patch23(_app23mod, attr, lambda *a, **k: None)
        _patch23(_app23mod, "time", _sleeper23(1))
        b = _hb23(name).get("passes", 0)
        _one_pass23(lambda: loop(_app23), 1)
        check("heartbeat: the %s loop beats on a completed pass" % name,
              _hb23(name).get("passes", 0) == b + 1, repr(_hb23(name)))
    _patch23(_app23mod, "_autoblock_hosts", lambda: set())
    _patch23(_app23mod, "time", _sleeper23(2))
    b = _hb23("autoblock").get("passes", 0)
    _one_pass23(lambda: _app23mod._autoblock_watch(_app23), 2)
    check("heartbeat: the autoblock loop beats even on a tick with no host opted in",
          _hb23("autoblock").get("passes", 0) == b + 1, repr(_hb23("autoblock")))
    _patch23(_mon23, "time", _sleeper23(2))
    b = _hb23("reboot-when-empty").get("passes", 0)
    _one_pass23(lambda: _mon23._reboot_when_empty_watch(_app23), 2)
    check("heartbeat: the reboot-when-empty loop beats on a tick with nothing queued",
          _hb23("reboot-when-empty").get("passes", 0) == b + 1, repr(_hb23("reboot-when-empty")))


def _supervisor23():
    made = []

    class _RecThread:
        def __init__(self, target=None, name=None, daemon=None, args=(), kwargs=None):
            self.target, self.name = target, name
            made.append(self)

        def start(self):
            return None

        def join(self, timeout=None):
            return None

    _patch23(_app23mod, "threading", NS(Thread=_RecThread))
    _patch23(_app23mod, "time", _sleeper23(1))
    fake_app = NS(logger=NS(error=lambda *a, **k: None))
    sup = _app23mod._make_supervisor(fake_app)
    sup("p23-worker", lambda: None)
    runner = made[0].target if made else None
    before = _rs23.snapshot("respawn").get("p23-worker", 0)
    _one_pass23(runner, 1)
    check("supervisor: the runner and the worker threads are named (the report finds them by name)",
          [m.name for m in made] == ["supervise-p23-worker", "p23-worker"], repr([m.name for m in made]))
    check("supervisor: a worker that exits is counted as a respawn under its name",
          _rs23.snapshot("respawn").get("p23-worker", 0) == before + 1, repr(_rs23.snapshot("respawn")))


def _calls23(path, attr):
    """[(first string argument, call node)] of every `<x>.<attr>(...)` / `<attr>(...)` call."""
    tree = _ast23.parse((_REPO23 / path).read_text(encoding="utf-8"))
    out = []
    for n in _ast23.walk(tree):
        if not isinstance(n, _ast23.Call):
            continue
        fname = getattr(n.func, "attr", None) or getattr(n.func, "id", None)
        if fname == attr:
            first = n.args[0] if n.args else None
            out.append((first.value if isinstance(first, _ast23.Constant) else None, n))
    return out


_LOOP_FILES23 = ("app.py", "panel/services/monitoring.py", "panel/routes/server_files.py",
                 "panel/routes/os_updates.py", "panel/routes/host_terminal.py",
                 "panel/ops/terminal_session.py")


def _gates23():
    beats = {name for f in _LOOP_FILES23 for name, _n in _calls23(f, "beat")}
    timed = {n for n, cadence in _w23.WORKERS if cadence is not None}
    check("workers: every worker the report lists with a cadence has a loop that beats under that "
          "name", timed <= beats, "no beat for %r" % sorted(timed - beats))
    known = {n for n, _c in _w23.WORKERS}
    supervised = {name for f in _LOOP_FILES23 for attr in ("supervise", "_supervise")
                  for name, _n in _calls23(f, attr) if name}
    check("workers: every supervised loop is in the report's list of workers",
          supervised and supervised <= known, "missing %r" % sorted(supervised - known))
    threads = _calls23("app.py", "Thread")
    unnamed = [n.lineno for _name, n in threads
               if not any(k.arg == "name" for k in n.keywords)]
    check("workers: every thread app.py starts is named (threading.enumerate() can tell them apart)",
          threads and not unnamed, "unnamed at app.py lines %r" % unnamed)
    named = {k.value.value for _name, n in threads for k in n.keywords
             if k.arg == "name" and isinstance(k.value, _ast23.Constant)}
    check("workers: every long-running thread app.py names is a worker the report lists",
          {"monitor", "player-counts", "metrics-history", "node-tools", "reboot-when-empty",
           "autoblock", "ban-watch", "telegram-bot", "discord-bot"} <= named <= known
          | {"f2b-autostart", "bot-update-report", "autoblock-now"}, repr(sorted(named)))


# ── 2. the sections, against a throwaway database ─────────────────────────────────────────────

def _fixtures23():
    """The hosts and servers every section check below reads. Returns their ids."""
    bad_cred = "enc:v1:" + _Fernet23(_Fernet23.generate_key()).encrypt(b"x").decode()
    panel_port = _cfg23.load_config().get("port", 5000)
    with _app23.app_context():
        db.create_all()
        hosts = {
            "local": RemoteServer(name="p23-SECRET-local", host="127.0.0.1", port=22,
                                  username="p23localuser", auth_method="local", is_local=True),
            "ts": RemoteServer(name="p23-SECRET-ts", host="p23tsbox", port=22, username="root",
                               auth_method="tailscale", sudo_enabled=True),
            "key": RemoteServer(name="p23-SECRET-key", host="p23keybox", port=2222,
                                username="p23gameuser", auth_method="key",
                                host_key="ssh-ed25519 AAAAp23"),
            "pw": RemoteServer(name="p23-SECRET-pw", host="203.0.113.77", port=22, username="root",
                               auth_method="password", auth_credential=bad_cred),
        }
        db.session.add_all(hosts.values())
        db.session.commit()
        ids = {k: h.id for k, h in hosts.items()}
        k = ids["key"]
        servers = {
            "a": GameServer(remote_id=k, name="p23-SECRET-a", short_name="p23gameuser",
                            game_type="gmod", port=27015, status="online", installed=True,
                            commands='[{"cmd": "start"}]'),
            "b": GameServer(remote_id=k, name="p23-SECRET-b", short_name="p23gameuserb",
                            game_type="cs", port=27015, status="offline", installed=True),
            "c": GameServer(remote_id=k, name="p23-SECRET-c", short_name="p23gameuserc",
                            game_type="mc", port=2222, status="failed", installed=False,
                            install_retryable=False,
                            install_error="Please delete some /tmp/dumps* directories p23-SECRET"),
            "d": GameServer(remote_id=k, name="p23-SECRET-d", short_name="p23gameuserd",
                            game_type="rust", port=28015, status="installing"),
            "e": GameServer(remote_id=k, name="p23-SECRET-e", short_name="p23gameusere",
                            game_type="ark", port=7777, status="installing"),
            "f": GameServer(remote_id=ids["local"], name="p23-SECRET-f", short_name="p23gameuserf",
                            game_type="vh", port=panel_port, status="offline", installed=True),
        }
        db.session.add_all(servers.values())
        db.session.commit()
        ids.update({n: g.id for n, g in servers.items()})
        utc = _utcnow23()
        db.session.add_all([HostSample(remote_id=k, ts=utc, cpu=1, ram_pct=2, disk_pct=3),
                            HostSample(remote_id=k, ts=utc, cpu=1, ram_pct=2, disk_pct=3)])
        db.session.commit()
    return ids


_NOW23 = [_time23.time()]


def _state23(ids):
    """Fill the monitor's maps and the caches the sections read; freeze the sections' clock."""
    now = _NOW23[0] = _time23.time()
    clock = NS(time=lambda: _NOW23[0], sleep=_time23.sleep, monotonic=_time23.monotonic)
    _patch23(_h23, "time", clock)
    _patch23(_s23, "time", clock)
    _ps23._monitor_state["remotes"].update({ids["local"]: True, ids["ts"]: False,
                                            ids["key"]: True})
    _ps23._monitor_state["remote_misses"][ids["key"]] = 1
    _ps23._monitor_state["servers"].update({ids["a"]: True, ids["b"]: True})
    _ps23._monitor_state["server_misses"][ids["b"]] = 1
    _ps23._player_counts[ids["a"]] = {"count": 3, "max": 10, "name": "p23-INGAME", "ts": now - 20}
    _ps23._expected_offline[ids["b"]] = now - 40
    _mon23._probe_record[ids["ts"]] = {"ok": False, "token": "timeout", "rc": -1, "at": now - 41,
                                       "ok_at": now - 11520, "fail_since": now - 11520,
                                       "streak": 187}
    _core23._host_metrics_cache[ids["local"]] = (now + 2 - 6, {"host": {"disk_percent": 41,
                                                                       "ram_percent": 63}})
    _pscan23._port_scan_cache[ids["key"]] = (now + _pscan23._PORT_SCAN_TTL - 4, {27015, 2222})
    _fw23._specs_cache[ids["key"]] = {"os": "Ubuntu 26.04 LTS", "arch": "x86_64", "cores": "4",
                                      "ram": "7.8 GB", "virt": "kvm", "cpu": "AMD EPYC 7763",
                                      "hostname": "p23-SECRET-hostname", "kernel": "6.8.0"}
    _smh23._OS_SLUG_CACHE[ids["key"]] = "ubuntu-26.04"
    with _ps23._install_lock:
        _ps23._install_jobs.clear()
        _ps23._install_jobs[ids["e"]] = {
            "status": "running", "step": 4, "total": 8,
            "step_name": "Downloading game server files (this can take a while)",
            "message": "p23-SECRET-message", "log": ["p23-SECRET-log"], "started": now - 3120,
            "updated": now - 2820, "name": "p23-SECRET-jobname", "born": None}
    _tsi23._cache.update({"ts": now, "info": NS(
        installed=True, backend_state="Running", magic_dns_enabled=True,
        peers=[{"hostname": "p23tsbox", "dns_name": "p23tsbox.tail-p23.ts.net",
                "ips": ["100.64.0.23"], "os": "linux", "online": False,
                "last_seen": "2026-10-01T10:00:00Z"}])})


def _brief23(ids):
    with _app23.app_context():
        res = _h23.section_hosts_brief(_Ctx23(app=_app23))
    text = _text23(res)
    check("hosts brief: three lines, and the same three go in the public summary",
          len(res.lines) == 3 and res.summary_lines == res.lines, repr(res.lines))
    check("hosts brief: the panel's own host is counted apart from the remotes, by transport",
          "**Hosts**: 4 (panel host 1 · tailscale 1 · key 1 · password 1)" in text, text)
    check("hosts brief: the monitor's view, with the down host's id, R48 token and how long",
          "Monitor: 2 up, 1 DOWN (host %d: timeout, 3 h 12 m), 1 not yet probed" % ids["ts"] in text,
          text)
    check("hosts brief: game servers by status, with the install stranded without a job",
          "**Game servers**: 6. Online 1 · offline 2 · failed 1 · installing 2 (stranded 1)" in text,
          text)
    check("hosts brief: port conflicts -- a shared port, a remote's SSH port, the panel's own port",
          "**Port conflicts**: 3." in text
          and "host %d: port 27015 → gs %d (gmod), gs %d (cs)" % (ids["key"], ids["a"], ids["b"])
          in text and "port 2222 is the host's SSH port → gs %d (mc)" % ids["c"] in text
          and "is the panel's own port → gs %d (vh)" % ids["f"] in text, text)
    levels = sorted((f["level"], f["text"]) for f in res.findings)
    check("hosts brief: the down host, the conflicts and the stranded install are findings",
          ("warn", "host %d is down (timeout)" % ids["ts"]) in levels
          and any("port conflict" in t for _l, t in levels) and any("stranded" in t for _l, t in levels),
          repr(levels))
    check("hosts brief: no host, address, account or server name in it", not _leaks23(text),
          repr(_leaks23(text)))

    def _broken():
        raise RuntimeError("db gone")
    _patch23(_h23, "_read_gs_cols", _broken)
    with _app23.app_context():
        res2 = _h23.section_hosts_brief(_Ctx23(app=_app23))
    _restore_one23(_h23, "_read_gs_cols")
    t2 = _text23(res2)
    check("hosts brief: an unreadable table says so, by class, and never reads as 0 or 'none'",
          "**Game servers**: could not be read (RuntimeError)" in t2
          and "**Port conflicts**: could not be read (RuntimeError)" in t2
          and "**Hosts**: 4" in t2 and "none" not in t2.split("**Port conflicts**")[1]
          and any(f["level"] == "unread" for f in res2.findings), t2)


def _restore_one23(owner, name):
    for i in range(len(_patched23) - 1, -1, -1):
        o, n, v = _patched23[i]
        if o is owner and n == name:
            setattr(o, n, v)
            del _patched23[i]
            return


def _hosts23(ids):
    with _app23.app_context():
        res = _h23.section_hosts(_Ctx23(app=_app23))
    text = _text23(res)
    check("hosts: each host's transport as run_command decides it, with classes, never values",
          ("- host %d · tailscale (system ssh, multiplexing" % ids["ts"]) in text
          and ("- host %d · key (paramiko, pooled) · port custom · sudo no · address bare name "
               "(no dot) · login non-root · host key pinned" % ids["key"]) in text
          and ("- host %d · local (panel host)" % ids["local"]) in text, text)
    check("hosts: a bare name on a key host is flagged; on a tailscale host it is not",
          "FLAG: a bare name on a key host" in text and text.count("FLAG:") == 1, text)
    check("hosts: a password that does not decrypt under this cred_key is named, not printed",
          ("- host %d · password (paramiko, pooled) · port 22 · sudo no · address private IPv4"
           % ids["pw"]) in text and "credential UNREADABLE under this cred_key" in text, text)
    check("hosts: reachability -- monitor, DB column, last good read, scan and 24 h samples",
          "monitor DOWN (declared) · DB is_online no" in text
          and "last good metrics read 6 s ago · disk 41% ram 63%" in text
          and "monitor up, 1/2 misses pending" in text and "24 h: 2/1440" in text
          and "port scan 4 s ago (2 listening)" in text, text)
    check("hosts: a host with no installed game is 'never sampled', not down",
          "no installed games, so never sampled (absence is not downtime)" in text, text)
    check("hosts: the last probe, by its R48 token and rc, with the last OK and the streak",
          "last probe: FAILED 41 s ago: timeout (rc -1) · last OK 3 h 12 m ago · streak 187" in text,
          text)
    check("hosts: the tailscale peer -- online, last seen, OS -- matched in memory only",
          "tailscale peer: online NO · last seen" in text and "· linux" in text
          and "**Tailscale (this node)**: BackendState Running · MagicDNS on" in text
          and any("tailnet peer is offline" in f["text"] for f in res.findings), text)
    check("hosts: cached specs from an allowlist (never the hostname field); none read says so",
          "specs: Ubuntu 26.04 LTS · 6.8.0 · x86_64 · AMD EPYC 7763 · 4 · 7.8 GB · kvm · deps list "
          "ubuntu-26.04" in text and "(specs not read since panel start)" in text, text)
    check("hosts: the SSH transport line (pool and multiplexing)",
          "- **SSH transport**: paramiko pool " in text and "tailscale ssh multiplexing" in text, text)
    check("hosts: no host, address, account, peer name or display name in it", not _leaks23(text),
          repr(_leaks23(text)))
    _patch23(_h23, "probe_records", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    with _app23.app_context():
        t3 = _text23(_h23.section_hosts(_Ctx23(app=_app23)))
    _restore_one23(_h23, "probe_records")
    check("hosts: an unreadable probe record says so on every host, never 'none recorded'",
          "last probe: could not be read" in t3 and "none recorded" not in t3, t3)


def _no_key23(ids):
    calls = []
    real_key = _cfg23.CRED_KEY_FILE
    absent = _Path23(_TMP23) / "no-such-cred-key"
    _patch23(_cfg23, "CRED_KEY_FILE", absent)
    _patch23(_cfg23, "_cred_fernet", lambda: calls.append(1) or (_ for _ in ()).throw(
        RuntimeError("decrypted without the key")))
    with _app23.app_context():
        db.session.expire_all()
        text = _text23(_h23.section_hosts(_Ctx23(app=_app23)))
        brief = _text23(_h23.section_hosts_brief(_Ctx23(app=_app23)))
    _restore_one23(_cfg23, "_cred_fernet")
    _restore_one23(_cfg23, "CRED_KEY_FILE")
    check("hosts: with cred_key missing nothing is decrypted (a decrypt would mint a new key)",
          calls == [] and not absent.exists() and _cfg23.CRED_KEY_FILE == real_key, repr(calls))
    check("hosts: ...and the sections say what was not read, and still print the rest",
          "address/login: not read (credential key missing)" in text
          and "**Hosts**: 4" in brief and "monitor DOWN" in text, text)


def _tailscale23(ids):
    calls = []
    info = {"installed": True, "backend_state": "NeedsLogin",
            "peers": [{"hostname": "p23tsbox", "online": True, "direct": False, "os": "linux"}]}
    _patch23(_srcts23, "info", lambda: calls.append(1) or info)
    _tsi23._cache.update({"ts": _time23.time() - 3600})
    ctx = _Ctx23(app=_app23)
    with _app23.app_context():
        text = _text23(_h23.section_hosts(ctx))
        _h23.ts_info(ctx)
    check("tailscale: a stale cache falls back to the report's one shared read, once per report",
          calls == [1], repr(calls))
    check("tailscale: NeedsLogin is named as what breaks every tailscale host; relayed is said",
          "BackendState NeedsLogin · MagicDNS unknown · every tailscale host will fail" in text
          and "tailscale peer: online yes · DERP-relayed" in text, text)
    check("tailscale: matching is by name, MagicDNS or IP, case-insensitively",
          _h23.match_peer("P23TSBOX.tail-p23.ts.net.", [{"dns_name": "p23tsbox.tail-p23.ts.net"}])
          and _h23.match_peer("100.64.0.23", [{"ips": ["100.64.0.23"]}])
          and _h23.match_peer("other", [{"hostname": "p23tsbox"}]) is None)


def _classes23():
    unread = _Unreadable23()
    got = {h: _h23.addr_class(h) for h in ("100.101.102.103", "box.tail1234.ts.net", "gamebox",
                                           "example.org", "::1", "10.1.2.3", "1.1.1.1", "",
                                           "fd7a:115c:a1e0::5")}
    got["<unreadable>"] = _h23.addr_class(unread)
    check("address classes: by ipaddress and name shape only, never resolved",
          got == {"100.101.102.103": "tailnet IPv4", "box.tail1234.ts.net": "MagicDNS name",
                  "gamebox": "bare name (no dot)", "example.org": "DNS name", "::1": "loopback",
                  "10.1.2.3": "private IPv4", "1.1.1.1": "public IPv4", "": "empty",
                  "fd7a:115c:a1e0::5": "tailnet IPv6", "<unreadable>": "unreadable"}, repr(got))


def _mux23():
    base = _tf23.mkdtemp(prefix="lgsm-unit-p23-cm-")
    path = os.path.join(base, "cm")
    _patch23(_core23, "_SSH_CM_DIR", path)
    absent = _h23.mux_state()
    os.mkdir(path, 0o755)
    os.chmod(path, 0o755)
    shared = _h23.mux_state()
    os.chmod(path, 0o700)
    private = _h23.mux_state()
    _restore_one23(_core23, "_SSH_CM_DIR")
    os.rmdir(path)
    os.rmdir(base)
    check("ssh multiplexing: absent, open to group/other, and private are three answers",
          absent[0] is None and shared == (False, "OFF: control dir is open to group/other")
          and private == (True, "on"), repr((absent, shared, private)))

    class _Cl:
        def __init__(self, active):
            self.active = active

        def get_transport(self):
            return NS(is_active=lambda: self.active) if self.active is not None else None

    _patch23(_core23, "_connections", {"root@p23keybox:22": _Cl(True), "x@y:1": _Cl(False),
                                       "z@w:2": _Cl(None)})
    check("ssh pool: clients and active transports are counted from is_active() alone",
          _h23._pool_counts() == (3, 1), repr(_h23._pool_counts()))
    _restore_one23(_core23, "_connections")


def _servers23(ids):
    _patch23(_notif23, "alerts_muted", lambda gs: gs.id == ids["b"])
    _patch23(_lgsm23, "status", lambda: {
        "have_serverlist": True, "cached": {"serverlist.csv": 259200, "ubuntu-24.04.csv": None},
        "errors": {"serverlist.csv": "HTTP 404 from https://p23-SECRET.example/serverlist.csv"},
        "reason": "x"})
    with _app23.app_context():
        res = _s23.section_servers(_Ctx23(app=_app23))
    text = _text23(res)
    check("game servers: LinuxGSM data ages and the failed fetch by category, never its message",
          "- **LinuxGSM data**: serverlist.csv 3 d old · ubuntu-24.04.csv never fetched · last "
          "fetch error: serverlist.csv (fetch failed)" in text, text)
    check("game servers: DB status beside the monitor, the port scan and the player poll",
          ("- gs %d · gmod · host %d · port 27015 · DB online · monitor up · port listening (scan "
           "4 s ago) · players 3 (polled 20 s ago) · cmds 1" % (ids["a"], ids["key"])) in text, text)
    check("game servers: misses pending, a panel stop, an empty command list, alerts muted",
          ("- gs %d · cs" % ids["b"]) in text and "monitor up (1/2 misses pending)" in text
          and "expected offline (panel stop 40 s ago)" in text
          and "cmds 0 (command list never fetched → Start/Stop/Update may be hidden)" in text
          and "alerts muted" in text, text)
    check("game servers: a failed install by its classifier's CODE, never the raw error",
          "DB failed" in text and "retryable no · install_error classified: steam_dumps" in text,
          text)
    check("install jobs: a running job by step number and FIXED step name; stranded is named",
          "**Install jobs**: 1 running, 0 finished since panel start" in text
          and ("- gs %d · ark · host %d · install RUNNING step 4/8 'Downloading game server files' "
               "· started 52 m ago · last progress 47 m ago" % (ids["e"], ids["key"])) in text
          and ("- gs %d · rust · host %d · status installing but NO live job → stranded"
               % (ids["d"], ids["key"])) in text
          and any("stranded" in f["text"] for f in res.findings), text)
    check("game servers: port conflicts in full", text.count("  - host ") == 3, text)
    check("game servers: no server name, job text, tag, in-game name or address in it",
          not _leaks23(text), repr(_leaks23(text)))
    _ps23._install_lock.acquire()
    try:
        with _app23.app_context():
            busy = _text23(_s23.section_servers(_Ctx23(app=_app23)))
    finally:
        _ps23._install_lock.release()
    check("install jobs: a lock that stays busy is 'not read', never '0 running'",
          "**Install jobs**: not read (the install lock was busy for 1 s)" in busy
          and "0 running" not in busy, busy)
    _patch23(_lgsm23, "status", lambda: (_ for _ in ()).throw(OSError("/p23secretpath")))
    with _app23.app_context():
        bad = _s23.section_servers(_Ctx23(app=_app23))
    check("game servers: a part that cannot be read says so by class; the rest still prints",
          "**LinuxGSM data**: could not be read (OSError)" in _text23(bad)
          and ("- gs %d · gmod" % ids["a"]) in _text23(bad) and not _leaks23(_text23(bad)),
          _text23(bad))


def _console_section23(ids):
    _restore_one23(_s23, "time")      # the poller's heartbeat is stamped with the real clock
    a, b = ids["a"], ids["b"]
    _sf23._console_viewers.clear()
    _sf23._console_viewers.update({a: {"s1": 1, "s2": 2}, b: {"s3": 3}})
    _sf23._console_feed[a] = {"ticks": 50, "fails": 0, "streak": 0, "pushed_at": _time23.time() - 3,
                              "rotations": 1}
    _sf23._console_feed[b] = {"ticks": 20, "fails": 14, "streak": 14, "last_fail": "stat-unparseable"}
    _ps23._console_partial[a] = "p23-SECRET half line"
    _ps23._console_backlog[a] = ["p23-SECRET"] * 37
    _ps23._action_output[a] = {"action": "update", "path": "/home/p23secretpath/x.log",
                               "user": "p23gameuser", "pos": 0}
    _rs23.beat("console-poller", 2, 0.3)
    with _app23.app_context():
        res = _s23.section_console(_Ctx23(app=_app23))
    text = _text23(res)
    check("console: viewers, last push, rotations, partial line, backlog and the running action",
          ("- gs %d gmod (host %d): 2 viewers · last chunk pushed 3 s ago · ticks 50, failed 0 · "
           "log rotated 1× · partial line 20 chars · backlog 37/600 · action output: update "
           "running" % (a, ids["key"])) in text, text)
    check("console: a console whose reads keep failing says how many and the last kind",
          "14 consecutive failed ticks (last: stat-unparseable) ← console frozen" in text
          and any(f["level"] == "warn" and "gs %d" % b in f["text"] for f in res.findings), text)
    check("console: the poller's own last pass beside its cadence",
          "- **Poller**: last pass 0 s ago / every 2 s · took 0.3 s · respawned" in text, text)
    check("console: no path, console text or account in it", not _leaks23(text), repr(_leaks23(text)))
    _sf23._console_viewers.clear()
    with _app23.app_context():
        idle = _text23(_s23.section_console(_Ctx23(app=_app23)))
    check("console: nobody watching is said as such", "- no consoles open (poller idle)" in idle,
          idle)


def _workers23(ids):
    names = [n for n, _c in _w23.WORKERS]
    _rs23._GROUPS.pop("heartbeat", None)
    _rs23._GROUPS.pop("loopfail", None)
    _rs23._GROUPS.pop("respawn", None)
    _rs23.beat("monitor", 60, 4.1)
    _rs23.bump("respawn", "console-poller")
    _rs23.bump("loopfail", "node-tools")
    _rs23.bump("loopfail", "node-tools")
    alive = {n: True for n in names}
    alive["reboot-when-empty"] = False
    del alive["autoblock"]
    _patch23(_w23, "threads_by_name", lambda: dict(alive))
    with _app23.app_context():
        res = _w23.section_workers(_Ctx23(app=_app23))
    text = _text23(res)
    found = [f["text"] for f in res.findings]
    check("workers: a beating loop's last pass beside its cadence, how long it took, passes",
          "- monitor: last pass 0 s ago / every 60 s · took 4.1 s · passes 1 · thread alive" in text,
          text)
    check("workers: never completed a pass, not instrumented, failed passes: three answers",
          "- player-counts: never completed a pass since start (" in text
          and "- telegram-bot: not instrumented · thread alive" in text
          and "- node-tools: never completed a pass since start" in text
          and "failed passes 2" in text, text)
    check("workers: a dead or missing thread, a respawn, and all-failing passes are findings",
          "reboot-when-empty: thread not alive" in found and "autoblock: thread not alive" in found
          and "console-poller respawned 1×" in found
          and "node-tools: every pass since start has failed (2)" in found, repr(found))
    check("workers: the verdict names the dead workers and counts respawns",
          res.verdict == "**Background workers**: 2 NOT alive (reboot-when-empty, autoblock) · 1 "
                         "respawn", repr(res.verdict))
    check("workers: newest player poll and samples beside the heartbeats",
          _re23.search(r"- player counts: newest poll \d+ s ago", text)
          and _re23.search(r"newest host sample \d+ s ago", text)
          and "newest game sample none in the table" in text, text)
    _patch23(_w23, "threads_by_name", lambda: {"MainThread": True})
    with _app23.app_context():
        res2 = _w23.section_workers(_Ctx23(app=_app23))
    check("workers: when no worker's thread is visible at all, none is called dead",
          not any("not alive" in f["text"] for f in res2.findings)
          and "thread state not visible" in res2.verdict, repr((res2.verdict, res2.findings)))


try:
    _probe23()
    _console23()
    _poller23()
    _loops23()
    _supervisor23()
    _gates23()
    _classes23()
    _mux23()
    _ids23 = _fixtures23()
    _state23(_ids23)
    _brief23(_ids23)
    _hosts23(_ids23)
    _no_key23(_ids23)
    _tailscale23(_ids23)
    _servers23(_ids23)
    _console_section23(_ids23)
    _workers23(_ids23)
finally:
    _restore23()
    for _m, _snap in _maps23:
        _m.clear()
        _m.update(_snap)
    for _k, _v in _monstate23.items():
        _ps23._monitor_state[_k].clear()
        _ps23._monitor_state[_k].update(_v)
    for _c, _snap in _caches23:
        _c.clear()
        _c.update(_snap)
    _rs23._GROUPS.clear()
    _rs23._GROUPS.update(_groups23)
    _shutil23.rmtree(_TMP23, ignore_errors=True)
