r"""Part 309 of the unit suite: History from 24 hours to a year, on the server page and the host page.

Held here (panel/services/history_rollup.py, the prune tick in panel/install/app.py, panel/routes/api.py,
panel/routes/remotes.py, panel/db/models.py, the two pages and their scripts):
* The tick (app._prune_metric_samples, clock replaced): each complete hour of samples becomes one row per
  server (MetricHourly) and per host (HostHourly) with the average, highest and lowest of each figure and
  the most players; the current hour waits. A second run changes nothing; a rolled hour whose samples
  were pruned keeps its row; a backlog is rolled a day per tick, and a gap is stepped over. Rows past a
  year go.
* The rollups go with their server and their host (the ORM delete, and delete_remote's bulk delete).
* The migration: an upgraded database gets the rollups' indexes back.
* The routes on part12's app: the four long ranges read the rollups merged to at most 240 points
  (averages weighted by samples, a None figure not counted as 0), the hours not rolled yet built from the
  samples, any other range refused (the host) or the 24h one (the server); a fixed number of queries
  whatever the number of rows.
* The pages: six range buttons on each, which wrap at phone width; the scripts in node: the axis and
  labels per range, the peak lines, a long range polled every ten minutes.

HOW IT RUNS. No host is reached: part12's transport tripwire is armed and the pages' outside reads are
stubbed as part177 does. The sample and rollup tables of part12's database are set aside first and put
back after, so the tick sees this part's rows only.
"""
import os as _os309
from datetime import timedelta as _td309

import sqlalchemy as _sa309

import app as _app309
from unit.part01 import _root, check, eq
from unit.part12 import (_P9_TRIPPED, P9_ADMIN, P9_GM, P9_GS, P9_HOST, P9_HOST2, _p9, _p9_arm, _p9_client,
                         _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part75 import _run_js75
from unit.part131 import _STATUS131
from panel.core import panel_state as _ps309
from panel.core.clock import utcnow as _utcnow309
from panel.db import models as _m309
from panel.db.models import db as _db309
from panel.ops import system_ops as _so309, tailscale_integration as _ts309
from panel.ops.ssh_manager import _core as _core309
from panel.routes import api as _api309, server_detail as _sd309
from panel.services import history_rollup as _hr309

_MS, _HS, _MH, _HH = _m309.MetricSample, _m309.HostSample, _m309.MetricHourly, _m309.HostHourly
_TABLES309 = (_MS, _HS, _MH, _HH)
_SRV309, _HOST309 = 930901, 930951          # ids no row of part12's has: the tick's own fixture
_F309 = _hr309.floor_hour(_utcnow309())
_T309 = _F309 - _td309(days=30)             # the tick cases' first hour


def _put309(rows):
    with _p9.app_context():
        _db309.session.add_all(rows)
        _db309.session.commit()


def _ms309(at, cpu=1.0, ram=100, players=None, sid=_SRV309):
    return _MS(server_id=sid, ts=at, cpu=cpu, ram_mb=ram, players=players)


def _hs309(at, cpu=1.0, ram=50.0, disk=30.0, rx=None, tx=None, rid=_HOST309):
    return _HS(remote_id=rid, ts=at, cpu=cpu, ram_pct=ram, disk_pct=disk, net_rx_kbps=rx, net_tx_kbps=tx)


def _rows309(model, *cols):
    with _p9.app_context():
        return [tuple(getattr(r, c) for c in cols) for r in model.query.order_by(model.id.asc()).all()]


_clock309 = [_T309]
_tickerr309 = []


def _tick309(now):
    """One tick through its caller, app._prune_metric_samples, at `now` (the 30-minute throttle reset).

    A tick that raises (a row counted twice breaks the one-row-an-hour index) is recorded, not fatal, so
    the checks below name it.
    """
    _clock309[0] = now
    _ps309._last_sample_prune[0] = 0.0
    try:
        _app309._prune_metric_samples(_p9)
    except Exception as exc:  # noqa: BLE001 - recorded for the checks
        _tickerr309.append(repr(exc)[:200])
        with _p9.app_context():
            _db309.session.rollback()


def _clear309():
    with _p9.app_context():
        for model in _TABLES309:
            model.query.delete(synchronize_session=False)
        _db309.session.commit()


_SM_COLS = ("server_id", "hour", "n", "cpu_avg", "cpu_max", "cpu_min", "ram_avg", "ram_max", "ram_min", "players_max")
_HH_COLS = ("remote_id", "hour", "n", "cpu_avg", "ram_avg", "disk_avg", "rx_avg", "rx_max", "tx_avg", "tx_max")

with _p9.app_context():
    _saved309 = {m: [dict(r._mapping) for r in _db309.session.execute(_sa309.select(m.__table__))]
                 for m in _TABLES309}
_saved_prune309 = list(_ps309._last_sample_prune)
_k309 = {}
try:
    _p9_arm(who="part309")
    _p9_patch(_app309, "utcnow", lambda: _clock309[0])
    _clear309()
    # ── 1. the tick rolls complete hours ────────────────────────────────────────────────────────
    _put309([_ms309(_T309, 10, 100, None), _ms309(_T309 + _td309(minutes=20), 20, 200, 4),
             _ms309(_T309 + _td309(minutes=40), 60, 300, 2),
             _ms309(_T309 + _td309(hours=1, minutes=5), 50, 500, 7),
             _ms309(_T309 + _td309(hours=2, minutes=5), 99, 900, 1),
             _hs309(_T309 + _td309(minutes=1), 5, 50, 30, rx=100.0), _hs309(_T309 + _td309(minutes=31), 15, 70, 30)])
    _tick309(_T309 + _td309(hours=2, minutes=30))
    _k309["first"] = (_rows309(_MH, *_SM_COLS), _rows309(_HH, *_HH_COLS))
    _tick309(_T309 + _td309(hours=2, minutes=30))
    _k309["again"] = (_rows309(_MH, *_SM_COLS), _rows309(_HH, *_HH_COLS))
    _tick309(_T309 + _td309(hours=3, minutes=1))
    _k309["next"] = _rows309(_MH, "hour", "n", "cpu_avg")
    # ── 2. a rolled hour whose samples were pruned keeps its row ───────────────────────────────
    with _p9.app_context():
        _MS.query.filter(_MS.ts >= _T309 + _td309(hours=2)).delete(synchronize_session=False)
        _db309.session.commit()
    _put309([_ms309(_T309 + _td309(hours=4, minutes=1), 30)])
    _tick309(_T309 + _td309(hours=5, minutes=1))
    _k309["pruned"] = _rows309(_MH, "hour", "n", "cpu_avg")
    # ── 3. a backlog a day per tick; a gap stepped over ─────────────────────────────────────────
    _clear309()
    _put309([_ms309(_T309 + _td309(hours=h, minutes=2)) for h in range(30)])
    _tick309(_T309 + _td309(hours=31))
    _k309["backlog1"] = len(_rows309(_MH, "hour"))
    _tick309(_T309 + _td309(hours=31))
    _k309["backlog2"] = len(_rows309(_MH, "hour"))
    _clear309()
    _put309([_ms309(_T309 + _td309(hours=h, minutes=2)) for h in (10, 60, 100)])
    for _i309 in range(3):
        _tick309(_T309 + _td309(hours=101))
    _k309["gap"] = [h for (h,) in _rows309(_MH, "hour")]
    # ── 4. a year and a day, then gone; the samples' 14 days as before ─────────────────────────
    _clear309()
    _nowy309 = _T309 + _td309(days=400)
    _put309([_MH(server_id=_SRV309, hour=_nowy309 - _td309(days=367), n=1),
             _MH(server_id=_SRV309, hour=_nowy309 - _td309(days=365), n=1),
             _HH(remote_id=_HOST309, hour=_nowy309 - _td309(days=367), n=1),
             _HH(remote_id=_HOST309, hour=_nowy309 - _td309(days=365), n=1),
             _ms309(_nowy309 - _td309(days=15)), _ms309(_nowy309 - _td309(days=13))])
    _tick309(_nowy309)
    # The rollups near the year's edge (the tick also rolls the sample hours, which are not in question here).
    _k309["year"] = ([h for h in _rows309(_MH, "hour") if h[0] < _nowy309 - _td309(days=300)],
                     [h for h in _rows309(_HH, "hour") if h[0] < _nowy309 - _td309(days=300)], _rows309(_MS, "ts"))
finally:
    _p9_restore_all()
    _clear309()
    _ps309._last_sample_prune[:] = _saved_prune309

_sm1, _hh1 = _k309.get("first") or ([], [])
eq("tick: each complete hour of a server's samples is one row: how many, average/highest/lowest CPU and RAM, "
   "the most players (a sample without a count is not 0); the current hour waits",
   _sm1, [(_SRV309, _T309, 3, 30.0, 60.0, 10.0, 200.0, 300.0, 100.0, 4),
          (_SRV309, _T309 + _td309(hours=1), 1, 50.0, 50.0, 50.0, 500.0, 500.0, 500.0, 7)])
eq("tick: ...and a host's: CPU, RAM and disk averaged, the network rate's average and highest over the samples "
   "that have one (None when none has)",
   _hh1, [(_HOST309, _T309, 2, 10.0, 60.0, 30.0, 100.0, 100.0, None, None)])
eq("tick: a second run over the same hours changes nothing (no sample counted twice) and no tick failed",
   (_k309.get("again"), _tickerr309), ((_sm1, _hh1), []))
eq("tick: the next run rolls only the hour that completed since, the earlier rows as they were",
   _k309.get("next"), [(_T309, 3, 30.0), (_T309 + _td309(hours=1), 1, 50.0), (_T309 + _td309(hours=2), 1, 99.0)])
eq("tick: a rolled hour whose samples were since pruned keeps its row (it is not built again from what is "
   "left), and the hours after it still roll",
   _k309.get("pruned"), [(_T309, 3, 30.0), (_T309 + _td309(hours=1), 1, 50.0), (_T309 + _td309(hours=2), 1, 99.0),
                         (_T309 + _td309(hours=4), 1, 30.0)])
eq("tick: a backlog of 30 hours is rolled a day per tick (24, then the other 6), so one tick never holds the hub "
   "for the whole backlog", (_k309.get("backlog1"), _k309.get("backlog2")), (24, 30))
eq("tick: a gap longer than a day (a panel that was stopped) is stepped over: three ticks roll hours 10, 60 "
   "and 100", _k309.get("gap"), [_T309 + _td309(hours=h) for h in (10, 60, 100)])
eq("tick: rollups older than a year and a day go and younger ones stay, for servers and hosts; samples older "
   "than 14 days go as before",
   _k309.get("year"), ([(_nowy309 - _td309(days=365),)], [(_nowy309 - _td309(days=365),)],
                       [(_nowy309 - _td309(days=13),)]))

# ── 5. the rollups go with their server and their host ──────────────────────────────────────────


def _hist_counts309(sids, rids):
    with _p9.app_context():
        return ([_MH.query.filter_by(server_id=s).count() for s in sids],
                [_HH.query.filter_by(remote_id=r).count() for r in rids])


_d309 = {}
try:
    _p9_arm(who="part309")
    _trip0309 = len(_P9_TRIPPED)
    with _p9.app_context():
        _dr309 = _m309.RemoteServer(name="p309-host", host="192.0.2.93", port=22, username="root",
                                    auth_method="key", auth_credential="", is_online=True)
        _db309.session.add(_dr309)
        _db309.session.flush()
        _dg309 = [_m309.GameServer(remote_id=_dr309.id, name="p309-%d" % i, short_name="csgoserver",
                                   game_type="csgo", port=27200 + i, installed=True) for i in range(2)]
        _db309.session.add_all(_dg309)
        _db309.session.commit()
        _drid309, _dgid309 = _dr309.id, [g.id for g in _dg309]
    _put309([_MH(server_id=s, hour=_T309, n=1) for s in _dgid309 + [P9_GS]]
            + [_HH(remote_id=r, hour=_T309, n=1) for r in (_drid309, P9_HOST)])
    with _p9.app_context():
        _db309.session.delete(_db309.session.get(_m309.GameServer, _dgid309[0]))
        _db309.session.commit()
    _d309["one"] = _hist_counts309(_dgid309 + [P9_GS], [_drid309, P9_HOST])
    _d309["resp"] = _p9_client(P9_ADMIN).post("/remotes/%d/delete" % _drid309, json={"pass" + "word": "Str0ng!passw0rd"},
                                              headers={"X-Requested-With": "XMLHttpRequest"}).status_code
    _d309["host"] = _hist_counts309(_dgid309 + [P9_GS], [_drid309, P9_HOST])
    _d309["trips"] = _P9_TRIPPED[_trip0309:]
finally:
    _p9_restore_all()
    _clear309()
eq("delete: a deleted game server's hourly history goes with it; another server's and the hosts' stay",
   _d309.get("one"), ([0, 1, 1], [1, 1]))
eq("delete host: the host's hourly history and its game servers' go with it (delete_remote's bulk delete); "
   "another host's and its server's stay",
   (_d309.get("resp"), _d309.get("host")), (200, ([0, 0, 1], [0, 1])))

# ── 6. the migration: an upgraded database gets the rollups' indexes ────────────────────────────
_IX309 = {"metric_hourly": {"ux_metric_hourly_server_hour", "ix_metric_hourly_hour"},
          "host_hourly": {"ux_host_hourly_remote_hour", "ix_host_hourly_hour"}}


def _ix309():
    with _p9.app_context():
        insp = _sa309.inspect(_db309.engine)
        return {t: {ix["name"] for ix in insp.get_indexes(t)} & want for t, want in _IX309.items()}


with _p9.app_context():
    with _db309.engine.begin() as _conn309:
        for _names309 in _IX309.values():
            for _n309 in sorted(_names309):
                # An index name from this check's own fixed list, not input: DDL takes no bind parameters.
                _conn309.execute(_sa309.text("DROP INDEX IF EXISTS %s" % _n309))  # nosemgrep
_bare309 = _ix309()
with _p9.app_context():
    _m309._run_light_migrations()
eq("migration: a database whose rollup tables lack their indexes (one made before them, then given the tables) "
   "gets them back from the start-up migration",
   (_bare309, _ix309()), ({"metric_hourly": set(), "host_hourly": set()}, _IX309))

# ── 7. the routes ───────────────────────────────────────────────────────────────────────────────
# The route's clock is pinned to _NOW309, so the buckets below are where the route puts them however
# long the run takes: a 30-day range is 721 hours from floor(now - 30 days) in buckets of 4 hours, a
# 90-day one 2161 in buckets of 10.
_NOW309 = _F309 + _td309(minutes=17)
_S30 = _hr309.floor_hour(_NOW309 - _td309(hours=720))
_S90 = _hr309.floor_hour(_NOW309 - _td309(hours=2160))
_A30 = _S30 + _td309(hours=4 * 100)         # the first hour of one 30-day bucket
_A90 = _S90 + _td309(hours=10 * 50)


def _year309():
    """A year of rolled hours for P9_GS and P9_HOST, the newest two hours before now (players 5, CPU 20)."""
    with _p9.app_context():
        hours = [_F309 - _td309(hours=2 + i) for i in range(8760)]
        _db309.session.execute(_MH.__table__.insert(), [
            {"server_id": P9_GS, "hour": h, "n": 60, "cpu_avg": 20.0, "cpu_max": 40.0, "cpu_min": 1.0,
             "ram_avg": 100.0, "ram_max": 200.0, "ram_min": 50.0, "players_max": 5} for h in hours])
        _db309.session.execute(_HH.__table__.insert(), [
            {"remote_id": P9_HOST, "hour": h, "n": 60, "cpu_avg": 20.0, "cpu_max": 40.0, "cpu_min": 1.0,
             "ram_avg": 50.0, "ram_max": 60.0, "ram_min": 40.0, "disk_avg": 30.0, "disk_max": 30.0,
             "disk_min": 30.0, "rx_avg": 10.0, "rx_max": 20.0, "tx_avg": 5.0, "tx_max": 9.0} for h in hours])
        _db309.session.commit()


def _queries309(client, path):
    """(status, reply, the number of SQL statements the request ran)."""
    n = [0]

    def _count(*_a):
        n[0] += 1
    with _p9.app_context():
        engine = _db309.engine
    _sa309.event.listen(engine, "before_cursor_execute", _count)
    try:
        r = client.get(path)
    finally:
        _sa309.event.remove(engine, "before_cursor_execute", _count)
    return r.status_code, r.get_json(silent=True) or {}, n[0]


_g309 = {}
try:
    _p9_arm(who="part309")
    _trip1309 = len(_P9_TRIPPED)
    _p9_patch(_api309, "utcnow", lambda: _NOW309)
    _A309 = _p9_client(P9_ADMIN)
    _clear309()
    _g309["empty"] = {r: _queries309(_A309, "/api/server/%d/history?range=%s" % (P9_GS, r)) for r in ("30d", "1y")}
    _g309["hempty"] = _queries309(_A309, "/api/remote/%d/history?range=1y" % P9_HOST)
    _year309()
    # An hour the tick has not rolled yet (the one after the newest rolled), from its samples.
    _put309([_ms309(_F309 - _td309(minutes=55), cpu=80.0, ram=300, players=9, sid=P9_GS),
             _hs309(_F309 - _td309(minutes=55), cpu=80.0, rid=P9_HOST)])
    _g309["year"] = {r: _queries309(_A309, "/api/server/%d/history?range=%s" % (P9_GS, r))
                     for r in ("30d", "90d", "6mo", "1y")}
    _g309["hyear"] = _queries309(_A309, "/api/remote/%d/history?range=1y" % P9_HOST)
    # Two hours in one bucket: weighted by their samples, the higher max, the lower min, None not 0.
    _put309([_MH(server_id=P9_GM, hour=_A30, n=60, cpu_avg=10.0, cpu_max=30.0, cpu_min=5.0, ram_avg=100.0,
                 ram_max=100.0, ram_min=100.0, players_max=3),
             _MH(server_id=P9_GM, hour=_A30 + _td309(hours=1), n=20, cpu_avg=40.0, cpu_max=95.0, cpu_min=1.0,
                 ram_avg=500.0, ram_max=500.0, ram_min=500.0, players_max=None),
             _HH(remote_id=P9_HOST2, hour=_A90, n=60, cpu_avg=10.0, ram_avg=1.0, disk_avg=1.0, rx_avg=100.0,
                 rx_max=150.0, tx_avg=None, tx_max=None),
             _HH(remote_id=P9_HOST2, hour=_A90 + _td309(hours=3), n=60, cpu_avg=30.0, ram_avg=1.0, disk_avg=1.0,
                 rx_avg=None, rx_max=None, tx_avg=None, tx_max=None)])
    _g309["bucket"] = _A309.get("/api/server/%d/history?range=30d" % P9_GM).get_json(silent=True) or {}
    _g309["hbucket"] = _A309.get("/api/remote/%d/history?range=90d" % P9_HOST2).get_json(silent=True) or {}
    _g309["ranges"] = [(_A309.get("/api/remote/%d/history?range=%s" % (P9_HOST2, r)).status_code,
                        (_A309.get("/api/server/%d/history?range=%s" % (P9_GM, r)).get_json(silent=True) or {})
                        .get("range")) for r in ("24h", "7d", "30d", "90d", "6mo", "1y", "2y", "")]
    _g309["trips"] = _P9_TRIPPED[_trip1309:]
finally:
    _p9_restore_all()
    _clear309()

_e30, _e1y = (_g309.get("empty") or {}).get("30d", (0, {}, 0)), (_g309.get("empty") or {}).get("1y", (0, {}, 0))
eq("long ranges: with nothing recorded the server history answers empty series for 30d and 1y (the page then "
   "says so), and the host history too",
   [(_e30[0], _e30[1].get("server"), _e30[1].get("range")), (_e1y[0], _e1y[1].get("server")),
    ((_g309.get("hempty") or (0, {}))[1].get("host"))],
   [(200, [], "30d"), (200, []), []])
_y309 = _g309.get("year") or {}
_pts309 = {r: (v[1].get("server") or [], v[1].get("host") or []) for r, v in _y309.items()}
check("long ranges: a year of hourly rows comes back as at most 240 points a series for each of 30d, 90d, 6mo and "
      "1y, oldest first, each inside its range",
      len(_pts309) == 4 and all(0 < len(s) <= 240 and 0 < len(h) <= 240 and [p["t"] for p in s] == sorted(p["t"] for p in s)
                                for s, h in _pts309.values())
      and len(_pts309["1y"][0]) >= 200,
      repr({r: (len(s), len(h)) for r, (s, h) in _pts309.items()}))
_last309 = (_pts309.get("30d") or ([{}], [{}]))
eq("long ranges: the hour the tick has not rolled yet is built from its samples, so the newest point has its "
   "players (9) and its CPU peak (80) beside the rolled hours'",
   ((_last309[0] or [{}])[-1].get("players"), (_last309[0] or [{}])[-1].get("cpu_max"),
    (_last309[1] or [{}])[-1].get("cpu_max")), (9, 80.0, 80.0))
_qs309 = [v[2] for v in _y309.values()] + [_g309.get("hyear", (0, {}, 0))[2]]
_q0309 = [_e30[2], _e1y[2], (_g309.get("hempty") or (0, {}, 0))[2]]
check("long ranges: a fixed number of queries whatever the rows (a year of them reads as many as none), at most "
      "8 a request",
      _qs309 and len(set(_qs309[:4] + _q0309[:2])) == 1 and _qs309[4] == _q0309[2] and max(_qs309 + _q0309) <= 8,
      repr((_qs309, _q0309)))
_b309 = [p for p in (_g309.get("bucket") or {}).get("server") or [] if p.get("t") == _A30.isoformat() + "Z"]
eq("long ranges: two hours in one point: CPU and RAM averaged by their samples (17.5, 200), the higher peak, the "
   "lower low, the most players (a None count is not 0)",
   [(p.get("cpu"), p.get("cpu_max"), p.get("cpu_min"), p.get("ram"), p.get("players")) for p in _b309],
   [(17.5, 95.0, 1.0, 200.0, 3)])
_hb309 = [p for p in (_g309.get("hbucket") or {}).get("host") or [] if p.get("t") == _A90.isoformat() + "Z"]
eq("long ranges: a host point averages CPU over both hours (20) and the network rate over the hour that had one "
   "(100, not 50); no rate at all stays None",
   [(p.get("cpu"), p.get("rx"), p.get("rx_max"), p.get("tx")) for p in _hb309], [(20.0, 100.0, 150.0, None)])
eq("ranges: the host history answers the six ranges and refuses any other (400); the server history answers "
   "each of the six as itself and anything else as 24h",
   _g309.get("ranges"), [(200, "24h"), (200, "7d"), (200, "30d"), (200, "90d"), (200, "6mo"), (200, "1y"),
                         (400, "24h"), (200, "24h")])
check("routes and tick: nothing reached a host transport", not _g309.get("trips") and not _d309.get("trips"),
      repr((_g309.get("trips"), _d309.get("trips"))))

# ── 8. the pages ────────────────────────────────────────────────────────────────────────────────
_RANGES309 = ["24h", "7d", "30d", "90d", "6mo", "1y"]
_pg309 = {}
try:
    _p9_arm(who="part309")
    _p9_patch_sm("run_command", lambda *a, **k: ("", "", 0))
    _p9_patch(_so309, "get_server_status", lambda *a, **k: _STATUS131)
    _p9_patch(_ts309, "panel_funnel_facts", lambda cfg: {})
    _p9_patch(_core309, "run_privileged", lambda *a, **k: ("", "", 1))
    _p9_patch(_core309, "run_command", lambda *a, **k: ("", "", 1))
    _p9_patch(_sd309, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd309, "_host_timezone_cached", lambda *a, **k: "")
    _pg309["server"] = _p9_client(P9_ADMIN).get("/server/%d" % P9_GS)
    _pg309["host"] = _p9_client(P9_ADMIN).get("/remote/%d/manage" % P9_HOST)
finally:
    _p9_restore_all()


def _buttons309(resp, attr):
    """[(range, title)] of the range buttons, the card header's classes, as the page arrived."""
    import re as _re309
    html = resp.get_data(as_text=True) if resp.status_code == 200 else ""
    btns = _re309.findall(r'<button[^>]*\b%s="([^"]+)"[^>]*\btitle="([^"]+)"' % attr, html)
    group = html.find('aria-label="History range"')
    head = html.rfind('class="card-header', 0, group)
    return btns, html[head:html.find(">", head)]


_sb309, _sh309 = _buttons309(_pg309["server"], "data-hist-range")
_hb2309, _hh2309 = _buttons309(_pg309["host"], "data-hh-range")
eq("pages: the server page's History card and the host page's each offer 24h, 7d, 30d, 90d, 6mo and 1y, each "
   "named in full on hover",
   ([b for b, _t in _sb309], [b for b, _t in _hb2309], [t for _b, t in _sb309]),
   (_RANGES309, _RANGES309, ["Last 24 hours", "Last 7 days", "Last 30 days", "Last 90 days", "Last 6 months",
                             "Last year"]))
check("pages: each card header wraps (flex-wrap), so at phone width the six buttons take their own line instead "
      "of running past the card", "flex-wrap" in _sh309 and "flex-wrap" in _hh2309, repr((_sh309, _hh2309)))

# ── 9. the scripts in node ──────────────────────────────────────────────────────────────────────


def _read309(*parts):
    with open(_os309.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


_hist_js309 = _read309("panel", "static", "js", "history_charts.js")
_host_js309 = _read309("panel", "static", "js", "remote_history.js")
_sd_js309 = _read309("panel", "static", "js", "server_detail.js")
_sd_from309 = _sd_js309.find("function _r25c_histUnread(")
_sd_to309 = _sd_js309.find("}, 30000);", _sd_from309)
_sd_cut309 = _sd_js309[_sd_from309:_sd_to309 + len("}, 30000);")] if _sd_from309 > 0 and _sd_to309 > 0 else ""

_stage309 = r"""
process.env.TZ = 'UTC';
global.window = global;
const els = {}, built = {}, urls = [];
let replyWith, clickFn = null, pollFn = null;
const canvas = id => ({id, getContext: () => ({id})});
['hh-cpu', 'hh-ram', 'hh-disk', 'hh-net', 'hist-players', 'hist-server', 'hist-host', 'hist-net']
  .forEach(id => { els[id] = canvas(id); });
els['hh-card'] = {offsetParent: {}};
const cls = () => ({on: new Set(), toggle(k, v){ if (v) this.on.add(k); else this.on.delete(k); },
                    contains(k){ return this.on.has(k); }});
els['hh-empty'] = {style: {display: 'none'}, classList: cls()};
els['hh-charts'] = {style: {}};
els['hist-empty'] = {style: {display: 'none'}};
els['hist-charts'] = {style: {}};
global.document = {getElementById: id => (id in els ? els[id] : null),
                   addEventListener: (t, fn) => { if (t === 'click') clickFn = fn; }};
global.MOUNT = ''; global.REMOTE_ID = 7; global.serverId = 3;
global.pollWhenVisible = fn => { pollFn = fn; };
global.fetch = u => { urls.push(u); return Promise.resolve({json: () => Promise.resolve(replyWith)}); };
global.Chart = class {
  constructor(ctx, cfg){ this.data = cfg.data; this.options = cfg.options; built[ctx.id] = this; }
  update(){} destroy(){ this.destroyed = true; } };
const settle = () => new Promise(r => setTimeout(r, 0)).then(() => new Promise(r => setTimeout(r, 0)));
const click = (attr, rng) => clickFn({target: {closest: s => (s.indexOf(attr) >= 0 ? {
  getAttribute: () => rng, parentNode: {querySelectorAll: () => []}} : null)}});
const long = [{t: '2026-01-02T03:00:00Z', cpu: 5, cpu_max: 9, ram: 6, ram_max: 7, disk: 7, disk_max: 8, rx: 1, tx: 2}];
const raw = [{t: '2026-01-02T03:00:00Z', cpu: 5, ram: 6, disk: 7, rx: 1, tx: 2}];
"""

_prog309h = _stage309 + _hist_js309 + "\n" + _host_js309 + "\n" + r"""
(async () => {
  const out = {};
  const iso = '2026-01-02T03:04:00Z';
  out.lbl = ['24h', '7d', '30d', '90d', '6mo', '1y'].map(r => [/2026/.test(_histLbl(iso, r)), /:/.test(_histLbl(iso, r)),
                                                           /03|3/.test(_histLbl(iso, r))]);
  out.axis = ['24h', '7d', '1y'].map(r => typeof _histAxis('x', r).afterFit === 'function');
  out.due = [_histDue('k', '24h', 1000), _histDue('k', '24h', 1001), _histDue('k2', '1y', 2000),
             _histDue('k2', '1y', 2000 + 599999), _histDue('k2', '1y', 2000 + 600000)];
  replyWith = {host: raw}; window.loadHostHistory(); await settle();
  out.raw = built['hh-cpu'].data.datasets.map(d => d.label);
  replyWith = {host: long}; click('data-hh-range', '1y'); await settle();
  const cpu = built['hh-cpu'];
  out.url = urls[urls.length - 1];
  out.long = cpu.data.datasets.map(d => [d.label, d.data, !!d.borderDash]);
  out.disk = built['hh-disk'].data.datasets.map(d => d.data);
  out.net = built['hh-net'].data.datasets.length;
  const before = urls.length;
  pollFn(); pollFn();
  await settle();
  out.polls = urls.length - before;
  replyWith = {host: []}; click('data-hh-range', '6mo'); await settle();
  out.empty = [els['hh-empty'].style.display, urls[urls.length - 1]];
  console.log(JSON.stringify(out));
})();
"""
_o309h = _run_js75("History: the shared chart code and the host card over the long ranges", _prog309h)
if _o309h is not None:
    eq("history charts: a point reads its date in every range, its time in 24h (hour and minute), 7d and 30d "
       "(the hour), none in 90d, 6mo or 1y, and the year in 6mo and 1y, which cross one",
       _o309h.get("lbl"), [[False, True, True], [False, False, True], [False, False, True], [False, False, False],
                           [True, False, False], [True, False, False]])
    eq("history charts: only the 24h axis puts the date under the time (the others' labels carry it)",
       _o309h.get("axis"), [True, False, False])
    eq("history charts: a poll reads 24h and 7d every time, and a long range once in ten minutes",
       _o309h.get("due"), [True, True, True, False, True])
    eq("host History card: the 24h range draws the average only (control)", _o309h.get("raw"), ["CPU %"])
    eq("host History card: the 1y button asks for range=1y and draws CPU, RAM and disk each with its average and a "
       "dashed Peak line; the network chart as before",
       [_o309h.get("url"), _o309h.get("long"), _o309h.get("disk"), _o309h.get("net")],
       ["/api/remote/7/history?range=1y", [["CPU %", [5], False], ["Peak", [9], True]], [[7], [8]], 2])
    eq("host History card: on a long range two polls in a row read it once", _o309h.get("polls"), 1)
    eq("host History card: a long range with nothing in it says so (the empty line shows)", _o309h.get("empty"),
       ["", "/api/remote/7/history?range=6mo"])

_prog309s = _stage309 + _hist_js309 + "\nvar _histRange = '24h';\n" + _sd_cut309 + "\n" + r"""
(async () => {
  const out = {};
  window._sdTab = 'history';
  replyWith = {server: long.map(p => Object.assign({players: 4}, p)), host: long};
  click('data-hist-range', '90d'); await settle();
  out.url = urls[urls.length - 1];
  out.ids = Object.keys(built).sort();
  const before = urls.length;
  pollFn(); pollFn(); await settle();
  out.longPolls = urls.length - before;
  click('data-hist-range', '24h'); await settle();
  const b2 = urls.length;
  pollFn(); pollFn(); await settle();
  out.rawPolls = urls.length - b2;
  console.log(JSON.stringify(out));
})();
"""
_o309s = _run_js75("History: the server page over the long ranges", _prog309s)
if _o309s is not None:
    eq("server History: the 90d button asks for range=90d and draws the four charts; on a long range two polls read "
       "it once, on 24h each poll reads it",
       _o309s, {"url": "/api/server/3/history?range=90d", "ids": ["hist-host", "hist-net", "hist-players", "hist-server"],
                "longPolls": 1, "rawPolls": 2})

# Part12's sample and rollup rows, put back as they were.
with _p9.app_context():
    for _model309, _rows309s in _saved309.items():
        _model309.query.delete(synchronize_session=False)
        if _rows309s:
            _db309.session.execute(_model309.__table__.insert(), _rows309s)
    _db309.session.commit()
