"""Part 244 of the unit suite: the panel's polls and samples, cheaper with the same figures.

1. The player-count poll: every 45 s while a page shows the counts or a player alert could fire, else
   every 90 s. The routes that show the counts and the "notify when empty" switch keep it quick; an
   idle wait passes within one step of a page opening; the heartbeat says which cadence it is on.
2. The host sample: memory, load, cores, uptime and traffic come from the awk it already runs (read
   against /proc here), with no free, nproc, sort or tail; its `ss` and the port scan share one answer,
   so a dashboard's metrics poll and its status poll run one `ss` between them.
3. A remote host page's live read diffs /proc/stat against the previous poll's, with no 0.25 s window,
   and takes the two-read window on a cold start, a long gap or a second caller within 0.5 s.
4. /api/server/<id>/stats: one sample per poll period answers every viewer, while one viewer still gets
   a fresh sample each poll; the power actions' running check keeps the 2 s cache.
5. The host page's live bars poll only while the card or the header badge is on screen (in node).

HOW IT RUNS. Routes on part12's app with its transport tripwire armed and run_command replaced by a
recorder; the loop runs on a clock of its own; the host sample's awk runs under bash on this machine's
own /proc. Nothing reaches a host or data/.
"""
import os
import subprocess as _sp244  # nosec B404 - bash over the panel's own sample command, read-only /proc
import sys
import threading as _threading244
import time as _time244
from types import SimpleNamespace as NS

from unit.part01 import check, eq
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GM, P9_GS, P9_HOST, P9_VIEWER, _P9_TRIPPED, _p9, _p9_arm, _p9_client,
                         _p9_patch, _p9_restore_all, _p9_set)
from unit.part47 import _node47
from panel.db.models import GameServer as _GS244, User as _U244, db as _db244
from panel.ops.ssh_manager import _core as _core244
from panel.ops.ssh_manager import portscan as _ps244
from panel.services import monitoring as _mon244
from panel.services import push_alerts as _push244

_app244 = sys.modules["app"]
_TRIP244 = len(_P9_TRIPPED)


class _Stop244(Exception):
    """Raised by the loop's clock to end the `while True` after the passes under test."""


class _Clock244:
    """The player loop's `time`: time() is the test's, sleep() moves it on and may stop the loop."""

    def __init__(self, now, passes, stop_after, on_sleep=None):
        self.now, self.passes, self.stop_after, self.on_sleep, self.slept = now, passes, stop_after, on_sleep, []

    def time(self):
        return self.now

    def sleep(self, s):
        self.slept.append(s)
        self.now += s
        if self.on_sleep:
            self.on_sleep(self)
        if len(self.passes) >= self.stop_after:
            raise _Stop244()


def _reset_poll244(viewed=0.0):
    _mon244._player_poll_state.update(viewed=viewed, armed_at=None, armed=True)


def _loop244(stop_after=3, on_sleep=None, t0=10_000.0):
    """Run _player_count_watch on its own clock; return (times of each pass, the clock)."""
    passes = []
    clock = _Clock244(t0, passes, stop_after, on_sleep)
    _p9_patch(_app244, "_refresh_player_counts", lambda app: passes.append(clock.now))
    _p9_patch(_app244, "time", clock)
    try:
        _app244._player_count_watch(_p9)
    except _Stop244:
        pass                # the stand-in clock ends the loop this way once it has run enough passes
    finally:
        _p9_restore_all()
    return [round(p - t0, 1) for p in passes], clock


def _cfg244(events):
    """A config with the given notification events switched on."""
    return lambda: {"notifications": {"events": {k: True for k in events}}}


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The player-count poll
# ════════════════════════════════════════════════════════════════════════════════════════════════
with _p9.app_context():
    _armed_rows244 = _GS244.query.filter_by(notify_when_empty=True).count()
    _chose244 = [u.username for u in _U244.query.filter_by(is_active=True).all()
                 if {"server_full", "server_peak"} & _push244.chosen_events(u)]
eq("player poll: (control) part12's servers start with no 'notify when empty' armed, and no account "
   "chose a player alert for its devices", (_armed_rows244, _chose244), (0, []))

_p9_patch(_mon244, "load_config", _cfg244(()))
_reset_poll244()
_idle244, _idle_clock244 = _loop244()
eq("player poll: with no page showing the counts and no player alert, a pass every 90 s (it was 45 s)",
   _idle244, [0.0, 90.0, 180.0])
eq("player poll: the idle wait sleeps to the 45 s mark, then looks again every 5 s",
   _idle_clock244.slept[:4], [45.0, 5, 5, 5])

_reset_poll244()
_p9_patch(_mon244, "load_config", _cfg244(()))


_opened244, _ = _loop244(stop_after=2, on_sleep=lambda c: (c.now - 10_000.0 == 60
                                                         and _mon244.want_fresh_player_counts(c.now)))
eq("player poll: a page that shows the counts 60 s into an idle wait gets its pass then, not at 90 s",
   _opened244, [0.0, 60.0])

_reset_poll244(viewed=10_000.0)
_p9_patch(_mon244, "load_config", _cfg244(()))
_viewed244, _ = _loop244()
eq("player poll: while a page keeps asking for the counts, a pass every 45 s",
   _viewed244[:2], [0.0, 45.0])

# Each player alert keeps the 45 s cadence on its own.
_p9_set(P9_GS, notify_when_empty=True)
_reset_poll244()
_p9_patch(_mon244, "load_config", _cfg244(()))
_nwe244, _ = _loop244(stop_after=2)
_p9_set(P9_GS, notify_when_empty=False)
eq("player poll: a server with 'notify when empty' armed keeps the 45 s cadence", _nwe244, [0.0, 45.0])
for _ev244 in ("server_full", "server_peak"):
    _reset_poll244()
    _p9_patch(_mon244, "load_config", _cfg244((_ev244,)))
    _on244, _ = _loop244(stop_after=2)
    eq("player poll: the %s alert switched on for the channels keeps the 45 s cadence" % _ev244,
       _on244, [0.0, 45.0])
with _p9.app_context():
    _u244 = _db244.session.get(_U244, P9_VIEWER)
    _u244.set_ui_pref("push_events", ["server_full"])
    _db244.session.commit()
_reset_poll244()
_p9_patch(_mon244, "load_config", _cfg244(()))
_pushed244, _ = _loop244(stop_after=2)
with _p9.app_context():
    _u244 = _db244.session.get(_U244, P9_VIEWER)
    _u244.set_ui_pref("push_events", None)
    _db244.session.commit()
eq("player poll: an account that chose 'server full' for its own devices keeps the 45 s cadence",
   _pushed244, [0.0, 45.0])

_reset_poll244()
_p9_patch(_mon244, "load_config", lambda: (_ for _ in ()).throw(OSError("unreadable")))
eq("player poll: when the alert settings cannot be read, the quick cadence (never a missed alert)",
   _mon244._player_poll_cadence(_p9, 10_000.0), 45)
_p9_restore_all()

# The heartbeat tells the Schedules card and the debug report which cadence the loop is on.
from panel.core import runtime_stats as _rs244  # noqa: E402
_reset_poll244()
_p9_patch(_mon244, "load_config", _cfg244(()))
_loop244(stop_after=1)
_beat_idle244 = (_rs244.snapshot("heartbeat").get("player-counts") or {}).get("cadence")
_reset_poll244(viewed=10_000.0)
_p9_patch(_mon244, "load_config", _cfg244(()))
_loop244(stop_after=1)
_beat_quick244 = (_rs244.snapshot("heartbeat").get("player-counts") or {}).get("cadence")
eq("player poll: the heartbeat records 90 s at rest and 45 s while a page shows the counts",
   (_beat_idle244, _beat_quick244), (90, 45))

# The routes that show the counts, and the switch that arms "notify when empty", keep it quick.
_p9_arm()
_p9_patch(_core244, "run_command", lambda *a, **k: ("", "no host in this check", 1))
_A244 = _p9_client(P9_ADMIN)
_marks244 = {}
for _what244, _go244 in (("dashboard", lambda: _A244.get("/")),
                         ("Game Servers poll", lambda: _A244.get("/api/servers")),
                         ("server status", lambda: _A244.get("/api/server/%d" % P9_GS)),
                         ("notify when empty", lambda: _A244.post("/api/server/%d/notify-empty" % P9_GS,
                                                                  json={"enabled": True}))):
    _reset_poll244()
    _t244 = _time244.time()
    _code244 = _go244().status_code
    _marks244[_what244] = (_code244, _mon244._player_poll_state["viewed"] >= _t244)
_reset_poll244()
_A244.post("/api/server/%d/notify-empty" % P9_GS, json={"enabled": False})
_marks244["notify off"] = (200, _mon244._player_poll_state["viewed"] > 0)
_p9_restore_all()
_p9_set(P9_GS, notify_when_empty=False)
eq("player poll: the dashboard, the Game Servers poll, a server's status and arming 'notify when empty' "
   "each keep the 45 s cadence; switching the alert off does not",
   _marks244, {"dashboard": (200, True), "Game Servers poll": (200, True), "server status": (200, True),
               "notify when empty": (200, True), "notify off": (200, False)})
_reset_poll244()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The host sample
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _read244(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


_cmd244 = _core244._host_sample_cmd()
eq("host sample: one ps and one awk for every /proc figure, df and ss once each through an awk, and no "
   "free, nproc, sort, tail, echo or awk of its own on a /proc file",
   [_cmd244.count(x) for x in ("ps -eo", "| awk", "df -B1", "ss -H", "free", "nproc", "sort", "tail", "echo",
                               "' /proc/")], [1, 3, 1, 1, 0, 0, 0, 0, 0, 0])
check("host sample: without the ports, the command leaves out the `ss`",
      "ss -H" not in _core244._host_sample_cmd(with_ports=False) and "ss -H" in _cmd244, "")

_load_before244 = _read244("/proc/loadavg").split()[:3]
_run244 = _sp244.run(["bash", "-c", _cmd244], capture_output=True, text=True, timeout=30,  # nosec B603 B607
                     check=False)
_load_after244 = _read244("/proc/loadavg").split()[:3]
_host244, _acc244 = _core244._parse_host_sample(_run244.stdout)
_mem244 = {ln.split(":")[0]: int(ln.split()[1]) for ln in _read244("/proc/meminfo").splitlines()
           if ln.split(":")[0] in ("MemTotal", "MemAvailable")}
_cores244 = sum(1 for ln in _read244("/proc/stat").splitlines() if ln[:3] == "cpu" and ln[3:4].isdigit())
_up244 = int(float(_read244("/proc/uptime").split()[0]))
check("host sample: RAM is MemTotal and MemTotal - MemAvailable from /proc/meminfo, in bytes",
      _host244["ram_total"] == _mem244["MemTotal"] * 1024
      and abs(_host244["ram_used"] - (_mem244["MemTotal"] - _mem244["MemAvailable"]) * 1024) < 256 * 2 ** 20,
      repr((_host244["ram_total"], _host244["ram_used"], _mem244, _run244.stderr[-300:])))
check("host sample: the load averages are /proc/loadavg's, the cores its online CPUs and the uptime "
      "/proc/uptime's whole seconds",
      [str(x) for x in _host244["load"]] in ([str(float(x)) for x in _load_before244],
                                              [str(float(x)) for x in _load_after244])
      and _host244["cores"] == _cores244 and abs(_host244["uptime_secs"] - _up244) <= 2,
      repr((_host244["load"], _load_before244, _host244["cores"], _cores244, _host244["uptime_secs"], _up244)))
_nets244 = [ln.split() for ln in _run244.stdout.splitlines() if ln.startswith("NETIF ")]
_dev244 = [ln.replace(":", " ", 1).split() for ln in _read244("/proc/net/dev").splitlines()[2:]]
eq("host sample: one NETIF line per /proc/net/dev interface, its received and sent bytes",
   [n[1] for n in _nets244], [d[0] for d in _dev244])
check("host sample: the disk line is df's figures for /, and an answered ss says so (PORTS)",
      _host244["disk_total"] > 0 and _acc244["ports_read"] is (bool(_acc244["ports"])), repr(_acc244["ports_read"]))

# Shared both ways with the port scan.
_sent244, _sent_ids244 = [], []


def _rc244(out):
    def _run(server, cmd, timeout=None, sudo=None):
        _sent244.append(cmd)
        _sent_ids244.append(getattr(server, "id", None))
        return out(cmd) if callable(out) else out, "", 0
    return _run


_SAMPLE244 = ("cpu  100 0 100 800 0 0 0\nGJA csgoserver 10\ncpu  150 0 150 900 0 0 0\nGJB csgoserver 20\n"
              "GAMERAM csgoserver 2048 3\nGUP csgoserver 60\nMEM 8000000000 2000000000\nLOAD 0.1 0.2 0.3\n"
              "CORES 4\nUPTIME 99\nDISK 1000 500\n")
_p9_patch(_core244, "run_command", _rc244(lambda c: _SAMPLE244 + ("PORT 27015\nPORT 22\nPORTS 2\n" if "ss -H" in c else "")))
_ps244._port_scan_cache.pop(244001, None)
_core244._host_metrics_cache.pop(244001, None)
_s1_244 = _core244.host_live_metrics(NS(id=244001), force=True)
_n1_244 = len(_sent244)
_scan244 = _ps244._remote_listening_ports(NS(id=244001))
_n2_244 = len(_sent244)
_s2_244 = _core244.host_live_metrics(NS(id=244001), force=True)
eq("host sample: its answered ss is the port scan's answer for 5 s (the scan runs no command), and a "
   "sample within those 5 s takes the scan's ports and runs no ss",
   (_s1_244["ports"], _scan244, _n2_244 - _n1_244, "ss -H" in _sent244[-1], _s2_244["ports"]),
   ({27015, 22}, {27015, 22}, 0, False, {27015, 22}))
_empty_ss244 = _sp244.run(["bash", "-c", _core244._HOST_SS.replace("ss -H -ltnu 2>/dev/null", "true", 1)],  # nosec B603 B607
                          capture_output=True, text=True, timeout=10, check=False).stdout
_unshared244 = []
for _out244 in ("PORT 27015\n", "PORTS 0\n", _empty_ss244):
    _p9_patch(_core244, "run_command", _rc244(_SAMPLE244 + _out244))
    _ps244._port_scan_cache.pop(244002, None)
    _core244.host_live_metrics(NS(id=244002), force=True)
    _unshared244.append(244002 in _ps244._port_scan_cache)
check("host sample: an ss that printed nothing says so (no PORTS line), and is not shared as 'no ports "
      "listening', nor is a PORTS 0", _unshared244 == [False, False, False] and _empty_ss244 == "",
      repr((_unshared244, _empty_ss244)))
_p9_restore_all()
_ps244._port_scan_cache.pop(244001, None)

# The callers: an open dashboard's metrics poll, then its status poll, run ONE ss between them.
_p9_arm()
_sent244.clear()
_sent_ids244.clear()
_p9_patch(_core244, "run_command", _rc244(lambda c: (_SAMPLE244 + "PORT 27015\nPORTS 1\n") if "ps -eo" in c else ""))
for _c244 in (_core244._host_metrics_cache, _ps244._port_scan_cache):
    _c244.pop(P9_HOST, None)
_r1_244 = _A244.get("/api/dashboard/metrics")
_r2_244 = _A244.get("/api/servers")
_ss244 = [c for c, i in zip(_sent244, _sent_ids244) if "ss -H" in c and i == P9_HOST]
_rows244 = {r["id"]: r["status"] for r in (_r2_244.get_json() or []) if isinstance(r, dict)}
_p9_restore_all()
for _c244 in (_core244._host_metrics_cache, _ps244._port_scan_cache):
    _c244.pop(P9_HOST, None)
eq("host sample: the dashboard's metrics poll and its status poll run one ss between them, and the "
   "status poll reads the server listening on its port as online from it",
   (_r1_244.status_code, _r2_244.status_code, len(_ss244), _rows244.get(P9_GS), _rows244.get(P9_GM)),
   (200, 200, 1, "online", "offline"))
_p9_set(P9_GM, status="offline")
_p9_set(P9_GS, status="online")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A remote host page's live read
# ════════════════════════════════════════════════════════════════════════════════════════════════
_T244 = [50_000.0]
_fake_time244 = NS(time=lambda: _T244[0], sleep=lambda s: None, monotonic=_time244.monotonic)
_B244 = [100]


def _live244(cmd):
    """/proc/stat, meminfo and df as a host answers them; each read moves the counters on."""
    def stat():
        _B244[0] += 100
        b = _B244[0]
        return "cpu  %d 0 %d %d 0 0 0\ncpu0 %d 0 %d %d 0 0 0\n" % (b, b, 8 * b, b, b, 8 * b)
    out = ""
    if "===A" in cmd:
        out += "===A\n" + stat()
    out += "===B\n" + stat()
    return out + "===MEM\nMemTotal: 1000 kB\nMemAvailable: 500 kB\n===DISK\nFs 1B-blocks Used A U% M\n/dev/x 100 50 50 50% /\n"


_sent244.clear()
_p9_patch(_core244, "run_command", _rc244(_live244))
_p9_patch(_core244, "time", _fake_time244)
_core244._remote_cpu_prev.pop(244003, None)
_rv244 = NS(id=244003, is_local=False, auth_method="key", host="192.0.2.99", name="p244")
_seq244 = []
for _at244 in (0, 2, 2.2, 2.6, 4, 40):
    _T244[0] = 50_000.0 + _at244
    _m244 = _core244.remote_live_metrics(_rv244)
    _seq244.append(("sleep 0.25" in _sent244[-1], _m244["cpu_overall"], _m244["read_ok"]))
_p9_restore_all()
eq("remote live read: a cold start takes the 0.25 s window; a poll 2 s later diffs against the last "
   "read with no window; a second caller 0.2 s after takes the window and is not kept (0.6 s after the "
   "kept read is still a steady poll); a 36 s gap takes it again",
   _seq244, [(True, 20.0, True), (False, 20.0, True), (True, 20.0, True), (False, 20.0, True),
             (False, 20.0, True), (True, 20.0, True)])

# Through the host page's route.
_p9_arm()
_sent244.clear()
_p9_patch(_core244, "run_command", _rc244(_live244))
_p9_patch(_core244, "time", _fake_time244)
_core244._remote_cpu_prev.pop(P9_HOST, None)
_route244 = []
for _at244 in (0, 2):
    _T244[0] = 60_000.0 + _at244
    _rr244 = _A244.get("/api/remote/%d/live" % P9_HOST)
    _route244.append((_rr244.status_code, "sleep 0.25" in _sent244[-1], (_rr244.get_json() or {}).get("cpu_overall")))
_T244[0] = 60_004.0
_p9_patch(_core244, "run_command", lambda *a, **k: ("", "timed out", -1))
_failed244 = _A244.get("/api/remote/%d/live" % P9_HOST).get_json() or {}
_p9_restore_all()
check("remote live read: the host page's /live polls take one read each once warm, with the CPU from "
      "the delta; a failed read is still reported as unreachable",
      _route244 == [(200, True, 20.0), (200, False, 20.0)] and _failed244.get("unreachable") is True,
      repr((_route244, _failed244)))
_core244._remote_cpu_prev.pop(P9_HOST, None)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. /stats: one sample per poll period
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _game244(cmd):
    port = "1" if "csgoserver" in cmd else "0"
    return ("cpu  100 0 100 800 0 0 0\nGJA 10\ncpu  150 0 150 900 0 0 0\nGJB 20\nGAMERAM 2048 3\nGUP 60\n"
            "MEM 8000000000 2000000000\nLOAD 0.1 0.2 0.3\nDISK 1000 500\nCORES 4\nUPTIME 99\nPORT %s\n" % port)


def _stats_runs244(sid, offsets):
    """Commands run when /stats of `sid` is asked at each offset (seconds) after the first."""
    out = []
    for at in offsets:
        _T244[0] = 70_000.0 + at
        _A244.get("/api/server/%d/stats" % sid)
        out.append(len([c for c in _sent244 if "ps -u" in c]))
    return out


_p9_arm()
_sent244.clear()
_p9_patch(_core244, "run_command", _rc244(_game244))
_p9_patch(_core244, "time", _fake_time244)
_core244._live_metrics_cache.clear()
_online244 = _stats_runs244(P9_GS, (0, 3, 6.9, 7.5, 15.5))
_sent244.clear()
_core244._live_metrics_cache.clear()
_offline244 = _stats_runs244(P9_GM, (0, 10, 18.9, 20))
_sent244.clear()
_T244[0] = 80_000.0
_A244.get("/api/server/%d/stats" % P9_GS)
_T244[0] = 80_005.0
with _p9.app_context():
    _gs244 = _db244.session.get(_GS244, P9_GS)
    _running244 = _app244._live_run_state(_gs244, _gs244.remote)
_p9_restore_all()
_core244._live_metrics_cache.clear()
eq("/stats: an online server's viewers share one sample for 7 s, and one viewer polling every 8 s gets "
   "a fresh sample on each poll, also when its request arrives half a second early",
   _online244, [1, 1, 1, 2, 3])
eq("/stats: a stopped server's viewers share one sample for 19 s (its page polls every 20 s)",
   _offline244, [1, 1, 1, 2])
check("/stats: the running check that refuses a power action still reads a sample at most 2 s old",
      len([c for c in _sent244 if "ps -u" in c]) == 2 and _running244 is True, repr((_sent244[-1:], _running244)))
_p9_set(P9_GM, status="offline")
_p9_set(P9_GS, status="online")

# Two viewers whose polls arrive together share the one sample (the second waits for the first).
_sent244.clear()


def _slow_game244(server, cmd, timeout=None, sudo=None):
    _sent244.append(cmd)
    _time244.sleep(0.3)
    return _game244(cmd), "", 0


_p9_patch(_core244, "run_command", _slow_game244)
_core244._live_metrics_cache.pop((244005, "csgoserver", 27015), None)
_got244 = []
_ths244 = [_threading244.Thread(target=lambda: _got244.append(_core244.server_live_metrics(
    NS(id=244005), "csgoserver", 27015, max_age=7)["port_open"])) for _ in range(2)]
for _th244 in _ths244:
    _th244.start()
for _th244 in _ths244:
    _th244.join(10)
_p9_restore_all()
_core244._live_metrics_cache.pop((244005, "csgoserver", 27015), None)
eq("/stats: two viewers whose polls arrive together run one sample between them, and both get it",
   (len(_sent244), _got244), (1, [True, True]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The host page's live bars poll only while on screen (in node)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_JS244 = _read244(os.path.join(_root, "panel", "static", "js", "remote_manage_backups.js"))
_HEAD244 = "var _liveOnScreen"
_at244 = _JS244.find(_HEAD244)
_end244 = _JS244.find("pollWhenVisible(", max(_at244, 0))
_block244 = _JS244[_at244:_JS244.find("\n", _end244)] if _at244 >= 0 and _end244 >= 0 else ""
_prog244 = """
var polls = 0, tick = null, now = 0, obs = null;
function pollLive(){ polls++; }
function pollWhenVisible(fn, ms){ tick = fn; }
Date.now = function(){ return now; };
function IntersectionObserver(cb){ this.cb = cb; this.els = []; obs = this; }
IntersectionObserver.prototype.observe = function(e){ this.els.push(e); };
var window = {IntersectionObserver: IntersectionObserver};
var card = {n: 'card'}, badge = {n: 'badge'};
var document = {hidden: false, querySelector: function(s){
  return s === '.live-res' ? card : (s === '#remote-status' ? badge : null); }};
""" + _block244 + """
var seen = [polls, obs.els.length];
obs.cb([{target: card, isIntersecting: true}, {target: badge, isIntersecting: true}]); seen.push(polls);
now = 2000; tick(); seen.push(polls);
obs.cb([{target: card, isIntersecting: false}]); now = 4000; tick(); seen.push(polls);
obs.cb([{target: badge, isIntersecting: false}]); now = 6000; tick(); now = 8000; tick(); seen.push(polls);
now = 9000; obs.cb([{target: card, isIntersecting: true}]); seen.push(polls);
now = 9500; obs.cb([{target: badge, isIntersecting: true}]); seen.push(polls);
document.hidden = true; obs.cb([{target: card, isIntersecting: false}]); now = 20000;
obs.cb([{target: card, isIntersecting: true}]); seen.push(polls);
console.log(JSON.stringify(seen));
"""
_seen244 = _node47(_prog244)
eq("host page live bars: one read at load; a 2 s read while the card or the badge is on screen; none "
   "while both are off screen; a read at once when one comes back a poll after the last; none on a "
   "hidden tab", _seen244, [1, 2, 1, 2, 3, 3, 4, 4, 4])
check("host page live bars: (control) the block cut from the page script is the one it runs, and the "
      "page has no other 2 s live poll",
      _JS244.count("pollWhenVisible(function(){ if(_liveSeen()) _livePoll(); }, 2000);") == 1
      and "pollWhenVisible(pollLive" not in _JS244, "")
eq("part244: no check reached a real transport", _P9_TRIPPED[_TRIP244:], [])
