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


_TIMEOUT23 = "timeout"   # a probe token (named apart: Bandit reads a "token" literal as a secret)


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



def _has23(d, **want):
    """The keys of `want` whose value in `d` is different: [] when every one matches."""
    d = d or {}
    return [k for k, v in want.items() if d.get(k) != v]


def _missing23(text, *needles):
    """The needles not found in `text`: [] when every one is there."""
    return [n for n in needles if n not in text]


def _restore_one23(owner, name):
    """Undo the most recent _patch23 of owner.name, ahead of the finally."""
    for i in range(len(_patched23) - 1, -1, -1):
        o, n, v = _patched23[i]
        if o is owner and n == name:
            setattr(o, n, v)
            del _patched23[i]
            return


def _one_pass23(fn):
    """Run a loop until its fake sleep raises _Stop23."""
    try:
        fn()
    except _Stop23:
        return True
    return False


# ── 1a. R48: the monitor's probe keeps its bool and records WHY, as a fixed token ─────────────

def _rec23(rid):
    return dict(_mon23._probe_record.get(rid) or {})


def _probe_streak23():
    ts_host = NS(id=-2301, auth_method="tailscale", is_local=False)
    _patch23(_mon23, "run_command", lambda r, cmd, timeout=None: ("", "SSH command timed out", -1))
    first = _mon23._host_reachable(ts_host)
    rec1 = _rec23(-2301)
    _time23.sleep(0.01)
    second = _mon23._host_reachable(ts_host)
    rec2 = _rec23(-2301)
    check("probe record: a timed-out tailscale probe is still False, recorded as 'timeout' rc -1",
          first is False and not _has23(rec1, token=_TIMEOUT23, rc=-1, streak=1, ok=False), repr(rec1))
    check("probe record: a second failure extends the streak and keeps when the failing began",
          all((second is False, rec2.get("streak") == 2, rec2.get("at", 0) > rec1.get("at", 0),
               rec2.get("fail_since") == rec1.get("fail_since"))), repr((rec1, rec2)))
    _patch23(_mon23, "run_command", lambda r, cmd, timeout=None: ("ok\n", "", 0))
    third = _mon23._host_reachable(ts_host)
    rec3 = _rec23(-2301)
    check("probe record: an answer is True, resets the streak and stamps the last OK",
          all((third is True, rec3.get("ok_at"),
               not _has23(rec3, streak=0, token=None, fail_since=None))), repr(rec3))


_PROBE_RAISES23 = {
    "host_key_changed": _core23.HostKeyMismatch("The SSH host key for 203.0.113.9 has CHANGED"),
    "host_key_unreadable": _core23.HostKeyMismatch(
        "The stored SSH host key for x cannot be decrypted on this host"),
    "auth_failed": ConnectionError("SSH authentication failed. Check credentials."),
    "timeout": ConnectionError("Connection to 203.0.113.9:22 timed out."),
    "dns": ConnectionError("Cannot resolve hostname: p23keybox"),
    "credential_unreadable": ConnectionError("No usable SSH password is stored for 203.0.113.9."),
    "other:ValueError": ValueError("203.0.113.9 said no"),
}
_PROBE_REPLIES23 = {
    "sudo_password_required": ("", "sudo: a password is required", 1),
    "ssh_cli_rc255": ("", "", 255), "empty_output_rc0": ("", "", 0),
    "host_key_changed": ("", "Host key verification failed.", 255),
    "refused": ("", "ssh: connect to host p23keybox port 22: Connection refused", 255),
}


def _raiser23(exc):
    def _raise(r, cmd, timeout=None):
        raise exc
    return _raise


def _probe_tokens23():
    got = {}
    for want, exc in _PROBE_RAISES23.items():
        _patch23(_mon23, "run_command", _raiser23(exc))
        ok = _mon23._host_reachable(NS(id=-2302, auth_method="key", is_local=False))
        got[want] = (ok, _rec23(-2302).get("token"))
    check("probe record: a raised probe is False and classified by its fixed wording",
          all(v == (False, k) for k, v in got.items()), repr(got))
    check("probe record: no message or address is stored, only the token and rc",
          not _leaks23(repr(_rec23(-2302))), repr(_rec23(-2302)))
    rgot = {}
    for want, reply in _PROBE_REPLIES23.items():
        _patch23(_mon23, "run_command", lambda r, cmd, timeout=None, _rep=reply: _rep)
        _mon23._host_reachable(NS(id=-2303, auth_method="tailscale", is_local=False))
        rgot[want] = _rec23(-2303).get("token")
    check("probe record: a non-raising transport's reply is classified from stderr and rc",
          all(rgot[k] == k for k in _PROBE_REPLIES23), repr(rgot))
    _patch23(_mon23, "run_command", lambda r, cmd, timeout=None: ("", "", 7))
    _mon23._host_reachable(NS(id=-2304, auth_method=None, is_local=True))
    check("probe record: the panel host's own failure names its transport (local_rc7)",
          _rec23(-2304).get("token") == "local_rc7", repr(_rec23(-2304)))


def _probe_contract23():
    _patch23(_mon23, "run_command", lambda r, cmd, timeout=None: ("ok", "", 0))
    check("probe record: a host object with no id is answered as before and records nothing",
          _mon23._host_reachable(NS()) is True and None not in _mon23._probe_record)
    _ps23.forget_rows(remote_ids=[-2301])
    check("probe record: registered, so a deleted host's id is forgotten with its other state",
          all((-2301 not in _mon23._probe_record,
               any(m is _mon23._probe_record for m in _ps23.remote_keyed_state()))))


# ── 1b. R56: the console poller's per-server counters ─────────────────────────────────────────

class _Log23:
    """A console log on a fake host, answering the two reads _console_tick makes."""

    def __init__(self):
        self.ino, self.data, self.stat_ok, self.fail_chunk = 900, "", True, False
        self.unframed = False

    def read(self, _server, _user, sh, timeout=30, selfname=None):
        if sh.startswith("stat -c"):
            return ("%d %d" % (self.ino, len(self.data)) if self.stat_ok else ""), "", 0
        # The tick's one command (server_files._console_poll_cmd): stat, the start the host picks
        # from the inode and offset it is handed, and the framed bytes from there.
        m = _re23.search(r'= (\d+) \] && \[ "\$2" -ge (\d+) \].*-gt (\d+) \]; then D=', sh)
        if not self.stat_ok or m is None:
            return "", "", 0
        if self.fail_chunk:
            return "", "SSH command timed out", -1
        return self._poll_reply(*(int(g) for g in m.groups())), "", 0

    def _poll_reply(self, ino, pos, cap):
        """What the host prints for the poll: the start it chose, then the framed bytes."""
        size = len(self.data)
        a = pos if (ino == self.ino and size >= pos) else 0
        n = min(size - a, cap)
        head = "%d %d %d %d" % (self.ino, size, a, n)
        if not n:
            return head
        return head + ("\na reply with no frame" if self.unframed else "\nB" + self.data[a:a + n] + "E")


_CSID23 = -2310


def _console_rig23():
    """(log, pushed, tick): a fake host log, what reached the room, and one tick of the poller."""
    log, pushed = _Log23(), []
    sio = NS(emit=lambda ev, payload, room=None, **k: pushed.append(payload.get("data")))
    gs = NS(console_log="/home/p23gameuser/p23secretpath/console.log", remote=NS(timezone=""),
            short_name="p23gameuser", lgsm_name="p23gameuser")
    _patch23(_core23, "read_as_game_user", log.read)
    _patch23(_sf23, "_host_timezone_cached", lambda *a, **k: "")

    def tick():
        _sf23._console_tick(_app23, sio, gs, _CSID23)
        return dict(_sf23._console_feed.get(_CSID23) or {})
    return log, pushed, tick


def _console23():
    log, pushed, tick = _console_rig23()
    log.stat_ok = False
    f1 = tick()
    check("console feed: an unparseable stat is a failed tick with a fixed token",
          not _has23(f1, streak=1, fails=1, last_fail="stat-unparseable"), repr(f1))
    log.stat_ok, log.data = True, "old line\n"
    f2 = tick()
    check("console feed: first sight is a good tick (it reads nothing) and ends the streak",
          not _has23(f2, streak=0, ticks=2, pushed_at=None), repr(f2))
    log.data += "new line\n"
    f3 = tick()
    check("console feed: a pushed chunk stamps pushed_at, and the push itself is unchanged",
          all((f3.get("pushed_at"), f3.get("streak") == 0, pushed == ["new line"])),
          repr((f3, pushed)))
    log.data += "more\n"
    log.fail_chunk = True
    f4 = tick()
    check("console feed: a read that never ran is 'read-failed', and the offset does not move",
          all((not _has23(f4, last_fail="read-failed", streak=1),
               _ps23._console_offsets[_CSID23]["pos"] == len("old line\nnew line\n"))), repr(f4))
    log.fail_chunk, log.unframed = False, True
    f4b = tick()
    check("console feed: a reply that ran but came back unframed is 'read-unframed'",
          not _has23(f4b, last_fail="read-unframed", streak=2), repr(f4b))
    log.unframed, log.ino, log.data = False, 901, "boot\n"
    f5 = tick()
    check("console feed: a rotated log is counted, and its first chunk still pushed",
          all((not _has23(f5, rotations=1, streak=0), pushed[-1:] == ["boot"])), repr(f5))
    check("console feed: the counters hold no path, line or account (fixed tokens and numbers)",
          not _leaks23(repr(f5)) and "boot" not in repr(f5), repr(f5))
    check("console feed: registered, so a deleted server's counters are forgotten",
          any(m is _sf23._console_feed for m in _ps23.server_keyed_state()))


def _drain_raises23(app, remote, server_id):
    raise ConnectionError("tail of /home/p23secretpath failed")


def _poller23():
    got = {}
    _sf23._start_console_poller(_app23, NS(emit=lambda *a, **k: None), got.__setitem__)
    sid = -2311
    _patch23(_sf23, "_console_to_poll", lambda app, sio, server_id: NS(remote=None))
    _patch23(_sf23, "_drain_action_output", _drain_raises23)
    _patch23(_sf23, "time", _sleeper23(1))
    _sf23._console_viewers.clear()
    _sf23._console_viewers[sid] = {"sock-p23": 1}
    before = _hb23("console-poller").get("passes", 0)
    _one_pass23(got.get("console-poller"))
    feed = _sf23._console_feed.get(sid)
    check("console poller: a console whose read raises is counted by exception CLASS, not message",
          not _has23(feed, last_fail="raised:ConnectionError", streak=1), repr(feed))
    watched = _rs23.snapshot("console").get("poller|watched") or (0, None)
    check("console poller: a pass with a failing console still completes, and beats",
          all((not _has23(_hb23("console-poller"), passes=before + 1, cadence=2),
               watched[1] == 1)), repr((_hb23("console-poller"), watched)))
    _sf23._console_viewers.clear()


# ── 1c. R22: heartbeats, failures, the supervisor's respawns and thread names ─────────────────

def _boom23():
    raise RuntimeError("pass failed")


def _monitor_loop23():
    _patch23(_app23mod, "_monitor_pass", lambda: None)
    _patch23(_app23mod, "time", _sleeper23(2))
    b = _hb23("monitor").get("passes", 0)
    _one_pass23(lambda: _app23mod._monitor_watch(_app23))
    check("heartbeat: the monitor loop beats once per completed pass, with its cadence",
          not _has23(_hb23("monitor"), passes=b + 1, cadence=60), repr(_hb23("monitor")))
    _patch23(_app23mod, "_monitor_pass", _boom23)
    _patch23(_app23mod, "time", _sleeper23(2))
    f = _rs23.snapshot("loopfail").get("monitor", 0)
    _one_pass23(lambda: _app23mod._monitor_watch(_app23))
    check("heartbeat: a failed monitor pass is counted and does NOT beat",
          all((_rs23.snapshot("loopfail").get("monitor", 0) == f + 1,
               _hb23("monitor").get("passes", 0) == b + 1)), repr(_rs23.snapshot("loopfail")))


_LOOPS23 = (("_player_count_watch", "player-counts", ("_refresh_player_counts",), 1),
            ("_metrics_history_watch", "metrics-history",
             ("_record_metric_samples", "_prune_metric_samples"), 1),
            ("_node_tools_cron_watch", "node-tools", ("_node_tools_cron_pass",), 1),
            ("_autoblock_watch", "autoblock", ("_autoblock_hosts",), 2))


def _other_loops23():
    for loop, name, stubs, stop_on in _LOOPS23:
        for attr in stubs:
            _patch23(_app23mod, attr, lambda *a, **k: set())
        _patch23(_app23mod, "time", _sleeper23(stop_on))
        b = _hb23(name).get("passes", 0)
        _one_pass23(lambda _loop=getattr(_app23mod, loop): _loop(_app23))
        check("heartbeat: the %s loop beats on a completed pass" % name,
              _hb23(name).get("passes", 0) == b + 1, repr(_hb23(name)))
    from panel.services import host_reboot as _hr23
    _patch23(_hr23, "time", _sleeper23(2))
    b = _hb23("reboot-when-empty").get("passes", 0)
    _one_pass23(lambda: _hr23.reboot_when_empty_watch(_app23))
    check("heartbeat: the reboot-when-empty loop beats on a tick with nothing queued",
          _hb23("reboot-when-empty").get("passes", 0) == b + 1, repr(_hb23("reboot-when-empty")))
    _patch23(_hr23, "run_restore_pass", lambda app, now=None: 60)
    _patch23(_hr23, "time", _sleeper23(2))
    b = _hb23("host-reboot").get("passes", 0)
    _one_pass23(lambda: _hr23.host_reboot_worker(_app23))
    check("heartbeat: the host-reboot loop beats on a completed pass",
          _hb23("host-reboot").get("passes", 0) == b + 1, repr(_hb23("host-reboot")))


class _RecThread23:
    """A Thread that records how it was made, and never runs."""

    made = []

    def __init__(self, target=None, name=None, daemon=None, args=(), kwargs=None):
        self.target, self.name = target, name
        _RecThread23.made.append(self)

    def start(self):
        """Never started."""

    def join(self, timeout=None):
        """Nothing to wait for."""


def _supervisor23():
    _RecThread23.made = []
    _patch23(_app23mod, "threading", NS(Thread=_RecThread23))
    _patch23(_app23mod, "time", _sleeper23(1))
    sup = _app23mod._make_supervisor(NS(logger=NS(error=lambda *a, **k: None)))
    sup("p23-worker", lambda: None)
    made = _RecThread23.made
    before = _rs23.snapshot("respawn").get("p23-worker", 0)
    _one_pass23(made[0].target if made else (lambda: None))
    names = [m.name for m in made]
    check("supervisor: the runner and the worker threads are named (the report finds them by name)",
          names == ["supervise-p23-worker", "p23-worker"], repr(names))
    check("supervisor: a worker that exits is counted as a respawn under its name",
          _rs23.snapshot("respawn").get("p23-worker", 0) == before + 1,
          repr(_rs23.snapshot("respawn")))


def _calls23(path, attr):
    """[(first string argument, call node)] of every `<x>.<attr>(...)` / `<attr>(...)` call."""
    tree = _ast23.parse((_REPO23 / path).read_text(encoding="utf-8"))
    calls = [n for n in _ast23.walk(tree) if isinstance(n, _ast23.Call)]
    out = []
    for n in calls:
        if (getattr(n.func, "attr", None) or getattr(n.func, "id", None)) == attr:
            first = n.args[0] if n.args else None
            out.append((first.value if isinstance(first, _ast23.Constant) else None, n))
    return out


# panel/routes/_shared.py: the backup-ticker's pass (_backup_ticker_pass) beats there, so that a
# pass whose daily backup raised can still run the game sweeps and be counted as failed.
_LOOP_FILES23 = ("app.py", "panel/services/monitoring.py", "panel/services/host_reboot.py",
                 "panel/routes/server_files.py",
                 "panel/routes/os_updates.py", "panel/routes/host_terminal.py",
                 "panel/ops/terminal_session.py", "panel/ops/debug_report/process.py",
                 "panel/routes/_shared.py")


def _names_gates23():
    beats = {name for f in _LOOP_FILES23 for name, _n in _calls23(f, "beat")}
    timed = {n for n, cadence in _w23.WORKERS if cadence is not None}
    check("workers: every worker the report lists with a cadence has a loop that beats under that "
          "name", timed <= beats, "no beat for %r" % sorted(timed - beats))
    known = {n for n, _c in _w23.WORKERS}
    supervised = {name for f in _LOOP_FILES23 for attr in ("supervise", "_supervise")
                  for name, _n in _calls23(f, attr)} - {None}
    check("workers: every supervised loop is in the report's list of workers",
          bool(supervised) and supervised <= known, "missing %r" % sorted(supervised - known))


def _thread_gates23():
    known = {n for n, _c in _w23.WORKERS}
    threads = [n for _name, n in _calls23("app.py", "Thread")]
    kws = [{k.arg: k.value for k in n.keywords} for n in threads]
    unnamed = [n.lineno for n, kw in zip(threads, kws) if "name" not in kw]
    check("workers: every thread app.py starts is named (threading.enumerate() can tell them apart)",
          bool(threads) and not unnamed, "unnamed at app.py lines %r" % unnamed)
    named = {kw["name"].value for kw in kws if isinstance(kw.get("name"), _ast23.Constant)}
    loops = {"monitor", "player-counts", "metrics-history", "node-tools",
             "autoblock", "ban-watch", "telegram-bot", "discord-bot"}
    check("workers: every long-running thread app.py names is a worker the report lists",
          loops <= named <= known | {"f2b-autostart", "bot-update-report", "autoblock-now",
                                     "cgroup-adopt"},   # one-shots: they run once and end
          repr(sorted(named)))


# ── 2. the sections, against a throwaway database ─────────────────────────────────────────────

def _bad_cred23():
    """A credential that IS ciphertext, under a key this install does not hold."""
    return "enc:v1:" + _Fernet23(_Fernet23.generate_key()).encrypt(b"x").decode()


def _host_rows23():
    return {
        "local": RemoteServer(name="p23-SECRET-local", host="127.0.0.1", port=22,
                              username="p23localuser", auth_method="local", is_local=True),
        "ts": RemoteServer(name="p23-SECRET-ts", host="p23tsbox", port=22, username="root",
                           auth_method="tailscale", sudo_enabled=True),
        "key": RemoteServer(name="p23-SECRET-key", host="p23keybox", port=2222,
                            username="p23gameuser", auth_method="key",
                            host_key="ssh-ed25519 AAAAp23"),
        "pw": RemoteServer(name="p23-SECRET-pw", host="203.0.113.77", port=22, username="root",
                           auth_method="password", auth_credential=_bad_cred23()),
    }


def _server_rows23(k, local, panel_port):
    def gs(tag, game, port, status, **kw):
        return GameServer(remote_id=kw.pop("rid", k), name="p23-SECRET-" + tag,
                          short_name="p23gameuser" + tag, game_type=game, port=port,
                          status=status, **kw)
    return {
        "a": gs("a", "gmod", 27015, "online", installed=True, commands='[{"cmd": "start"}]'),
        "b": gs("b", "cs", 27015, "offline", installed=True),
        "c": gs("c", "mc", 2222, "failed", installed=False, install_retryable=False,
                install_error="Please delete some /tmp/dumps* directories p23-SECRET"),
        "d": gs("d", "rust", 28015, "installing"),
        "e": gs("e", "ark", 7777, "installing"),
        "f": gs("f", "vh", panel_port, "offline", installed=True, rid=local),
    }


def _fixtures23():
    """The hosts and servers every section check below reads. Returns their ids."""
    panel_port = _cfg23.load_config().get("port", 5000)
    with _app23.app_context():
        db.create_all()
        hosts = _host_rows23()
        db.session.add_all(hosts.values())
        db.session.commit()
        ids = {k: h.id for k, h in hosts.items()}
        servers = _server_rows23(ids["key"], ids["local"], panel_port)
        db.session.add_all(servers.values())
        db.session.commit()
        ids.update({n: g.id for n, g in servers.items()})
        utc = _utcnow23()
        db.session.add_all([HostSample(remote_id=ids["key"], ts=utc, cpu=1, ram_pct=2, disk_pct=3)
                            for _i in range(2)])
        db.session.commit()
    return ids


_NOW23 = [_time23.time()]


def _state_monitor23(ids, now):
    _ps23._monitor_state["remotes"].update({ids["local"]: True, ids["ts"]: False,
                                            ids["key"]: True})
    _ps23._monitor_state["remote_misses"][ids["key"]] = 1
    _ps23._monitor_state["servers"].update({ids["a"]: True, ids["b"]: True})
    _ps23._monitor_state["server_misses"][ids["b"]] = 1
    _ps23._player_counts[ids["a"]] = {"count": 3, "max": 10, "name": "p23-INGAME", "ts": now - 20}
    _ps23._expected_offline[ids["b"]] = now - 40
    _mon23._probe_record[ids["ts"]] = {"ok": False, "token": _TIMEOUT23, "rc": -1, "at": now - 41,
                                       "ok_at": now - 11520, "fail_since": now - 11520,
                                       "streak": 187}


def _state_caches23(ids, now):
    _core23._host_metrics_cache[ids["local"]] = (now + 2 - 6, {"host": {"disk_percent": 41,
                                                                       "ram_percent": 63}})
    _pscan23._port_scan_cache[ids["key"]] = (now + _pscan23._PORT_SCAN_TTL - 4, {27015, 2222})
    _fw23._specs_cache[ids["key"]] = {"os": "Ubuntu 26.04 LTS", "arch": "x86_64", "cores": "4",
                                      "ram": "7.8 GB", "virt": "kvm", "cpu": "AMD EPYC 7763",
                                      "hostname": "p23-SECRET-hostname", "kernel": "6.8.0"}
    _smh23._OS_SLUG_CACHE[ids["key"]] = "ubuntu-26.04"
    _tsi23._cache.update({"ts": now, "info": NS(
        installed=True, backend_state="Running", magic_dns_enabled=True,
        peers=[{"hostname": "p23tsbox", "dns_name": "p23tsbox.tail-p23.ts.net",
                "ips": ["100.64.0.23"], "os": "linux", "online": False,
                "last_seen": "2026-10-01T10:00:00Z"}])})


def _state23(ids):
    """Fill the monitor's maps and the caches the sections read; freeze the sections' clock."""
    now = _NOW23[0] = _time23.time()
    clock = NS(time=lambda: _NOW23[0], sleep=_time23.sleep, monotonic=_time23.monotonic)
    _patch23(_h23, "time", clock)
    _patch23(_s23, "time", clock)
    _state_monitor23(ids, now)
    _state_caches23(ids, now)
    with _ps23._install_lock:
        _ps23._install_jobs.clear()
        _ps23._install_jobs[ids["e"]] = {
            "status": "running", "step": 4, "total": 8,
            "step_name": "Downloading game server files (this can take a while)",
            "message": "p23-SECRET-message", "log": ["p23-SECRET-log"], "started": now - 3120,
            "updated": now - 2820, "name": "p23-SECRET-jobname", "born": None}


def _section23(fn, ctx=None):
    with _app23.app_context():
        return fn(ctx or _Ctx23(app=_app23))


def _brief23(ids):
    res = _section23(_h23.section_hosts_brief)
    text = _text23(res)
    check("hosts brief: three lines, and the same three go in the public summary",
          len(res.lines) == 3 and res.summary_lines == res.lines, repr(res.lines))
    miss = _missing23(
        text, "**Hosts**: 4 (panel host 1 · tailscale 1 · key 1 · password 1)",
        "Monitor: 2 up, 1 DOWN (host %d: timeout, 3 h 12 m), 1 not yet probed" % ids["ts"])
    check("hosts brief: the panel's own host apart from the remotes; the monitor's view with the "
          "down host's id, R48 token and how long", not miss, "%r in %s" % (miss, text))
    check("hosts brief: game servers by status, with the install stranded without a job",
          not _missing23(text, "**Game servers**: 6. Online 1 · offline 2 · failed 1 · "
                               "installing 2 (stranded 1)"), text)
    miss = _missing23(
        text, "**Port conflicts**: 3.",
        "host %d: port 27015 → gs %d (gmod), gs %d (cs)" % (ids["key"], ids["a"], ids["b"]),
        "port 2222 is the host's SSH port → gs %d (mc)" % ids["c"],
        "is the panel's own port → gs %d (vh)" % ids["f"])
    check("hosts brief: port conflicts -- a shared port, a remote's SSH port, the panel's own port",
          not miss, "%r in %s" % (miss, text))
    found = " | ".join(f["level"] + ":" + f["text"] for f in res.findings)
    check("hosts brief: the down host, the conflicts and the stranded install are findings",
          not _missing23(found, "warn:host %d is down (timeout)" % ids["ts"], "port conflict",
                         "stranded"), found)
    check("hosts brief: no host, address, account or server name in it", not _leaks23(text),
          repr(_leaks23(text)))


def _brief_unread23():
    _patch23(_h23, "_read_gs_cols", _boom23)
    res = _section23(_h23.section_hosts_brief)
    _restore_one23(_h23, "_read_gs_cols")
    text = _text23(res)
    check("hosts brief: an unreadable table says so, by class, and never reads as 0 or 'none'",
          all((not _missing23(text, "**Game servers**: could not be read (RuntimeError)",
                              "**Port conflicts**: could not be read (RuntimeError)", "**Hosts**: 4"),
               "none" not in text.split("**Port conflicts**")[1],
               any(f["level"] == "unread" for f in res.findings))), text)


def _hosts23(ids):
    res = _section23(_h23.section_hosts)
    text = _text23(res)
    miss = _missing23(
        text, "- host %d · tailscale (system ssh, multiplexing" % ids["ts"],
        "- host %d · key (paramiko, pooled) · port custom · sudo no · address bare name (no dot) · "
        "login non-root · host key pinned" % ids["key"],
        "- host %d · local (panel host)" % ids["local"])
    check("hosts: each host's transport as run_command decides it, with classes, never values",
          not miss, "%r in %s" % (miss, text))
    check("hosts: a bare name on a key host is flagged; on a tailscale host it is not",
          "FLAG: a bare name on a key host" in text and text.count("FLAG:") == 1, text)
    check("hosts: a password that does not decrypt under this cred_key is named, not printed",
          not _missing23(text, "- host %d · password (paramiko, pooled) · port 22 · sudo no · "
                               "address private IPv4" % ids["pw"],
                         "credential UNREADABLE under this cred_key"), text)
    miss = _missing23(text, "monitor DOWN (declared) · DB is_online no",
                      "last good metrics read 6 s ago · disk 41% ram 63%",
                      "monitor up, 1/2 misses pending", "24 h: 2/1440",
                      "port scan 4 s ago (2 listening)",
                      "no installed games, so never sampled (absence is not downtime)")
    check("hosts: reachability -- monitor, DB column, last good read, scan, 24 h samples, and a "
          "host with no game that is 'never sampled', not down", not miss, "%r in %s" % (miss, text))
    check("hosts: the last probe, by its R48 token and rc, with the last OK and the streak",
          not _missing23(text, "last probe: FAILED 41 s ago: timeout (rc -1) · last OK 3 h 12 m "
                               "ago · streak 187"), text)
    _hosts_more23(res, text)


def _hosts_more23(res, text):
    found = " | ".join(f["text"] for f in res.findings)
    miss = _missing23(text + found, "tailscale peer: online NO · last seen", "· linux",
                      "**Tailscale (this node)**: BackendState Running · MagicDNS on",
                      "tailnet peer is offline")
    check("hosts: the tailscale peer -- online, last seen, OS -- matched in memory only",
          not miss, "%r in %s" % (miss, text))
    check("hosts: cached specs from an allowlist (never the hostname field); none read says so",
          not _missing23(text, "specs: Ubuntu 26.04 LTS · 6.8.0 · x86_64 · AMD EPYC 7763 · 4 · "
                               "7.8 GB · kvm · deps list ubuntu-26.04",
                         "(specs not read since panel start)"), text)
    check("hosts: the SSH transport line (pool and multiplexing)",
          not _missing23(text, "- **SSH transport**: paramiko pool ", "tailscale ssh multiplexing"),
          text)
    check("hosts: no host, address, account, peer name or display name in it", not _leaks23(text),
          repr(_leaks23(text)))
    _patch23(_h23, "probe_records", _boom23)
    t3 = _text23(_section23(_h23.section_hosts))
    _restore_one23(_h23, "probe_records")
    check("hosts: an unreadable probe record says so on every host, never 'none recorded'",
          "last probe: could not be read" in t3 and "none recorded" not in t3, t3)


def _no_key23():
    calls = []
    real_key = _cfg23.CRED_KEY_FILE
    absent = _Path23(_TMP23) / "no-such-cred-key"
    _patch23(_cfg23, "CRED_KEY_FILE", absent)
    _patch23(_cfg23, "_cred_fernet", lambda: calls.append(1) or _boom23())
    text = _text23(_section23(_h23.section_hosts))
    brief = _text23(_section23(_h23.section_hosts_brief))
    _restore_one23(_cfg23, "_cred_fernet")
    _restore_one23(_cfg23, "CRED_KEY_FILE")
    check("hosts: with cred_key missing nothing is decrypted (a decrypt would mint a new key)",
          all((calls == [], not absent.exists(), _cfg23.CRED_KEY_FILE == real_key)), repr(calls))
    check("hosts: ...and the sections say what was not read, and still print the rest",
          not _missing23(text + brief, "address/login: not read (credential key missing)",
                         "**Hosts**: 4", "monitor DOWN"), text)


def _tailscale23():
    calls = []
    info = {"installed": True, "backend_state": "NeedsLogin",
            "peers": [{"hostname": "p23tsbox", "online": True, "direct": False, "os": "linux"}]}
    _patch23(_srcts23, "read", lambda: calls.append(1) or ("ok", info))
    _tsi23._cache.update({"ts": _time23.time() - 3600})
    ctx = _Ctx23(app=_app23)
    text = _text23(_section23(_h23.section_hosts, ctx))
    _h23.ts_info(ctx)
    check("tailscale: a stale cache falls back to the report's one shared read, once per report",
          calls == [1], repr(calls))
    check("tailscale: NeedsLogin is named as what breaks every tailscale host; relayed is said",
          not _missing23(text, "BackendState NeedsLogin · MagicDNS unknown · every tailscale host "
                               "will fail", "tailscale peer: online yes · DERP-relayed"), text)
    hits = (_h23.match_peer("P23TSBOX.tail-p23.ts.net.", [{"dns_name": "p23tsbox.tail-p23.ts.net"}]),
            _h23.match_peer("100.64.0.23", [{"ips": ["100.64.0.23"]}]),
            _h23.match_peer("other", [{"hostname": "p23tsbox"}]))
    check("tailscale: matching is by name, MagicDNS or IP, case-insensitively",
          all((hits[0], hits[1], hits[2] is None)), repr(hits))


_ADDR23 = {"100.101.102.103": "tailnet IPv4", "box.tail1234.ts.net": "MagicDNS name",
           "gamebox": "bare name (no dot)", "example.org": "DNS name", "::1": "loopback",
           "10.1.2.3": "private IPv4", "1.1.1.1": "public IPv4", "": "empty",
           "fd7a:115c:a1e0::5": "tailnet IPv6"}


def _classes23():
    got = {h: _h23.addr_class(h) for h in _ADDR23}
    check("address classes: by ipaddress and name shape only, never resolved",
          got == _ADDR23 and _h23.addr_class(_Unreadable23()) == "unreadable", repr(got))


class _Client23:
    """A pooled paramiko client whose transport is up, down, or gone."""

    def __init__(self, active):
        self.active = active

    def get_transport(self):
        return NS(is_active=lambda: self.active) if self.active is not None else None


def _mux23():
    base = _tf23.mkdtemp(prefix="lgsm-unit-p23-cm-")
    path = os.path.join(base, "cm")
    _patch23(_core23, "_SSH_CM_DIR", path)
    absent = _h23.mux_state()
    os.mkdir(path, 0o700)
    # A control dir the group can read: the fixture the "not private" branch must catch.
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(path, 0o740)
    shared = _h23.mux_state()
    # Back to owner-only, the private case.
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(path, 0o700)
    private = _h23.mux_state()
    _restore_one23(_core23, "_SSH_CM_DIR")
    _shutil23.rmtree(base, ignore_errors=True)
    check("ssh multiplexing: absent, open to group/other, and private are three answers",
          all((absent[0] is None, shared == (False, "OFF: control dir is open to group/other"),
               private == (True, "on"))), repr((absent, shared, private)))
    _patch23(_core23, "_connections", {"root@p23keybox:22": _Client23(True),
                                       "x@y:1": _Client23(False), "z@w:2": _Client23(None)})
    check("ssh pool: clients and active transports are counted from is_active() alone",
          _h23._pool_counts() == (3, 1), repr(_h23._pool_counts()))
    _restore_one23(_core23, "_connections")


def _lgsm_status23():
    return {"have_serverlist": True, "cached": {"serverlist.csv": 259200, "ubuntu-24.04.csv": None},
            "errors": {"serverlist.csv": "HTTP 404 from https://p23-SECRET.example/serverlist.csv"},
            "reason": "x"}


def _servers23(ids):
    _patch23(_notif23, "alerts_muted", lambda gs: gs.id == ids["b"])
    _patch23(_lgsm23, "status", _lgsm_status23)
    res = _section23(_s23.section_servers)
    text = _text23(res)
    check("game servers: LinuxGSM data ages and the failed fetch by category, never its message",
          not _missing23(text, "- **LinuxGSM data**: serverlist.csv 3 d old · ubuntu-24.04.csv "
                               "never fetched · last fetch error: serverlist.csv (fetch failed)"),
          text)
    check("game servers: DB status beside the monitor, the port scan and the player poll",
          not _missing23(text, "- gs %d · gmod · host %d · port 27015 · DB online · monitor up · "
                               "port listening (scan 4 s ago) · players 3 (polled 20 s ago) · "
                               "cmds 1" % (ids["a"], ids["key"])), text)
    miss = _missing23(text, "- gs %d · cs" % ids["b"], "monitor up (1/2 misses pending)",
                      "expected offline (panel stop 40 s ago)", "alerts muted",
                      "cmds 0 (command list never fetched → Start/Stop/Update may be hidden)")
    check("game servers: misses pending, a panel stop, an empty command list, alerts muted",
          not miss, "%r in %s" % (miss, text))
    check("game servers: a failed install by its classifier's CODE, never the raw error",
          not _missing23(text, "DB failed", "retryable no · install_error classified: steam_dumps"),
          text)
    check("game servers: port conflicts in full", text.count("  - host ") == 3, text)
    check("game servers: no server name, job text, tag, in-game name or address in it",
          not _leaks23(text), repr(_leaks23(text)))
    _jobs23(ids, res, text)


def _oserror23():
    raise OSError("/p23secretpath")


def _jobs23(ids, res, text):
    miss = _missing23(
        text + " | ".join(f["text"] for f in res.findings),
        "**Install jobs**: 1 running, 0 finished since panel start",
        "- gs %d · ark · host %d · install RUNNING step 4/8 'Downloading game server files' · "
        "started 52 m ago · last progress 47 m ago" % (ids["e"], ids["key"]),
        "- gs %d · rust · host %d · status installing but NO live job → stranded"
        % (ids["d"], ids["key"]), "gs %d: stranded in installing" % ids["d"])
    check("install jobs: a running job by step number and FIXED step name; stranded is named",
          not miss, "%r in %s" % (miss, text))
    _ps23._install_lock.acquire()
    try:
        busy = _text23(_section23(_s23.section_servers))
        busy_brief = _text23(_section23(_h23.section_hosts_brief))
    finally:
        _ps23._install_lock.release()
    check("install jobs: a lock that stays busy is 'not read', never '0 running'",
          "**Install jobs**: not read (the install lock was busy for 1 s)" in busy
          and "0 running" not in busy, busy)
    check("hosts brief: ...and the stranded count says it was not checked, never 'stranded 0'",
          "(stranded: not checked (install lock busy))" in busy_brief
          and "stranded 0" not in busy_brief, busy_brief)
    _patch23(_lgsm23, "status", _oserror23)
    bad = _text23(_section23(_s23.section_servers))
    check("game servers: a part that cannot be read says so by class; the rest still prints",
          all((not _missing23(bad, "**LinuxGSM data**: could not be read (OSError)",
                              "- gs %d · gmod" % ids["a"]), not _leaks23(bad))), bad)


def _console_state23(a, b):
    _sf23._console_viewers.clear()
    _sf23._console_viewers.update({a: {"s1": 1, "s2": 2}, b: {"s3": 3}})
    _sf23._console_feed[a] = {"ticks": 50, "fails": 0, "streak": 0,
                              "pushed_at": _time23.time() - 3, "rotations": 1}
    _sf23._console_feed[b] = {"ticks": 20, "fails": 14, "streak": 14,
                              "last_fail": "stat-unparseable"}
    _ps23._console_partial[a] = "p23-SECRET half line"
    _ps23._console_backlog[a] = ["p23-SECRET"] * 37
    _ps23._action_output[a] = {"action": "update", "path": "/home/p23secretpath/x.log",
                               "user": "p23gameuser", "pos": 0}
    _rs23.beat("console-poller", 2, 0.3)


def _console_section23(ids):
    _restore_one23(_s23, "time")      # the poller's heartbeat is stamped with the real clock
    a, b = ids["a"], ids["b"]
    _console_state23(a, b)
    _rs23.put("console", "poller|watched", 2)
    res = _section23(_s23.section_console)
    text = _text23(res)
    check("console: viewers, last push, rotations, partial line, backlog and the running action",
          not _missing23(text, "- gs %d gmod (host %d): 2 viewers · last chunk pushed 3 s ago · "
                               "ticks 50, failed 0 · log rotated 1× · partial line 20 chars · "
                               "backlog 37/600 · action output: update running" % (a, ids["key"])),
          text)
    found = " | ".join(f["level"] + ":" + f["text"] for f in res.findings)
    check("console: a console whose reads keep failing says how many and the last kind",
          not _missing23(text + found, "14 consecutive failed ticks (last: stat-unparseable) ← "
                                       "console frozen", "warn:gs %d:" % b), text + found)
    check("console: the poller's own last pass beside its cadence, and how many it watches",
          not _missing23(text, "- **Poller**: last pass 0 s ago / every 2 s · took 0.3 s · "
                               "watching 2 servers · respawned"), text)
    check("console: no path, console text or account in it", not _leaks23(text),
          repr(_leaks23(text)))
    _sf23._console_viewers.clear()
    idle = _text23(_section23(_s23.section_console))
    check("console: nobody watching is said as such", "- no consoles open (poller idle)" in idle,
          idle)


def _worker_state23():
    for g in ("heartbeat", "loopfail", "respawn"):
        _rs23._GROUPS.pop(g, None)
    _rs23.beat("monitor", 60, 4.1)
    _rs23.bump("respawn", "console-poller")
    _rs23.bump("loopfail", "node-tools")
    _rs23.bump("loopfail", "node-tools")
    alive = {n: True for n, _c in _w23.WORKERS}
    alive["reboot-when-empty"] = False
    del alive["autoblock"]
    _patch23(_w23, "threads_by_name", lambda: dict(alive))


def _workers23():
    _worker_state23()
    res = _section23(_w23.section_workers)
    text = _text23(res)
    found = " | ".join(f["text"] for f in res.findings)
    check("workers: a beating loop's last pass beside its cadence, how long it took, passes",
          not _missing23(text, "- monitor: last pass 0 s ago / every 60 s · took 4.1 s · passes 1 "
                               "· thread alive"), text)
    miss = _missing23(text, "- player-counts: never completed a pass since start (",
                      "- telegram-bot: not instrumented · thread alive",
                      "- node-tools: never completed a pass since start", "failed passes 2")
    check("workers: never completed a pass, not instrumented, failed passes: three answers",
          not miss, "%r in %s" % (miss, text))
    miss = _missing23(found, "reboot-when-empty: thread not alive", "autoblock: thread not alive",
                      "console-poller respawned 1×",
                      "node-tools: every pass since start has failed (2)")
    check("workers: a dead or missing thread, a respawn, and all-failing passes are findings",
          not miss, "%r in %s" % (miss, found))
    dead_lines = [ln for ln in res.lines if ln.startswith(("- autoblock:", "- reboot-when-empty:"))]
    check("workers: a dead thread and a thread that is missing altogether both read NOT alive",
          len(dead_lines) == 2 and all(ln.endswith("thread NOT alive") for ln in dead_lines),
          repr(dead_lines))
    check("workers: the verdict names the dead workers and counts respawns",
          res.verdict == "**Background workers**: 2 NOT alive (reboot-when-empty, autoblock) · 1 "
                         "respawn", repr(res.verdict))
    check("workers: newest player poll and samples beside the heartbeats",
          all((_re23.search(r"- player counts: newest poll \d+ s ago", text),
               _re23.search(r"newest host sample \d+ s ago", text),
               "newest game sample none in the table" in text)), text)
    _patch23(_w23, "threads_by_name", lambda: {"MainThread": True})
    res2 = _section23(_w23.section_workers)
    check("workers: when no worker's thread is visible at all, none is called dead",
          all((not any("not alive" in f["text"] for f in res2.findings),
               "thread state not visible" in (res2.verdict or ""))),
          repr((res2.verdict, res2.findings)))


def _instrumentation23():
    _probe_streak23()
    _probe_tokens23()
    _probe_contract23()
    _console23()
    _poller23()
    _monitor_loop23()
    _other_loops23()
    _supervisor23()
    _names_gates23()
    _thread_gates23()


def _sections23():
    _classes23()
    _mux23()
    ids = _fixtures23()
    _state23(ids)
    _brief23(ids)
    _brief_unread23()
    _hosts23(ids)
    _no_key23()
    _tailscale23()
    _servers23(ids)
    _console_section23(ids)
    _workers23()


def _cleanup23():
    _restore23()
    for m, snap in _maps23:
        m.clear()
        m.update(snap)
    for k, v in _monstate23.items():
        _ps23._monitor_state[k].clear()
        _ps23._monitor_state[k].update(v)
    for c, snap in _caches23:
        c.clear()
        c.update(snap)
    _rs23._GROUPS.clear()
    _rs23._GROUPS.update(_groups23)
    _shutil23.rmtree(_TMP23, ignore_errors=True)


try:
    _instrumentation23()
    _sections23()
finally:
    _cleanup23()
