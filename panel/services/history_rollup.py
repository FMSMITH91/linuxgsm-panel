"""Hourly history: the rollups behind the History ranges from 30 days to a year.

The per-minute samples (MetricSample, HostSample) are kept 14 days. Before they go, each complete
hour is rolled into one row per server (MetricHourly) and per host (HostHourly): average, highest
and lowest of each figure, the network rates' average and highest, the most players seen. Those
rows are kept a year, so the year range reads ~8,760 rows per server instead of half a million.

roll_up() is idempotent: it builds whole hours from the samples, after the newest hour it already
holds, replacing (never adding to) any row in its window, so a re-run never counts a sample twice;
and a missed tick (a panel that was stopped) is caught up on the next one, from the first sample not
yet rolled. Nothing here leaves the host.
"""
import calendar
from datetime import timedelta

from sqlalchemy import Integer, case, func, select, type_coerce

from panel.db.models import HostHourly, HostSample, MetricHourly, MetricSample, db

# A year and a day, so the 1-year range is full at its oldest edge.
ROLLUP_RETENTION_DAYS = 366
# The most points one series in a History reply carries, whatever the range.
MAX_POINTS = 240
# The most hours one tick rolls. A first run after an upgrade has up to 14 days of samples to roll;
# the tick runs on the hub, so it does that a day at a time (~35 ms at 40 servers) instead of in one
# long query; the reads build the hours not rolled yet from the samples meanwhile.
_MAX_HOURS_PER_TICK = 24
# An hour's start in the format SQLAlchemy stores a DateTime in, so a rollup's hour compares with
# a bound datetime as the same text.
_HOUR_FMT = "%Y-%m-%d %H:00:00.000000"


class _Kind:
    """One kind of history: the sample model, its rollup model, the id column, and the aggregates."""

    def __init__(self, raw, hourly, key, aggs):
        self.raw, self.hourly, self.key, self.aggs = raw, hourly, key, aggs


# (rollup column, SQL aggregate, sample column). avg, max and min skip a None, as a sample without a
# player count or a network rate has.
SERVER = _Kind(MetricSample, MetricHourly, "server_id",
               (("cpu_avg", "avg", "cpu"), ("cpu_max", "max", "cpu"), ("cpu_min", "min", "cpu"),
                ("ram_avg", "avg", "ram_mb"), ("ram_max", "max", "ram_mb"), ("ram_min", "min", "ram_mb"),
                ("players_max", "max", "players")))
HOST = _Kind(HostSample, HostHourly, "remote_id",
             (("cpu_avg", "avg", "cpu"), ("cpu_max", "max", "cpu"), ("cpu_min", "min", "cpu"),
              ("ram_avg", "avg", "ram_pct"), ("ram_max", "max", "ram_pct"), ("ram_min", "min", "ram_pct"),
              ("disk_avg", "avg", "disk_pct"), ("disk_max", "max", "disk_pct"), ("disk_min", "min", "disk_pct"),
              ("rx_avg", "avg", "net_rx_kbps"), ("rx_max", "max", "net_rx_kbps"),
              ("tx_avg", "avg", "net_tx_kbps"), ("tx_max", "max", "net_tx_kbps")))
# A point's keys: the averages (and the most players) under the names the raw ranges' points use, so
# the charts draw every range the same way; the highest and lowest under their own.
_POINT_NAMES = {"cpu_avg": "cpu", "ram_avg": "ram", "disk_avg": "disk", "rx_avg": "rx", "tx_avg": "tx",
                "players_max": "players"}


def floor_hour(ts):
    """The start of the hour `ts` falls in."""
    return ts.replace(minute=0, second=0, microsecond=0)


def _hourly_select(kind, start, end=None, key_id=None):
    """The samples from `start` (to before `end`) grouped into one row per id per hour, as the rollup holds them."""
    raw = kind.raw
    hour = type_coerce(func.strftime(_HOUR_FMT, raw.ts), db.DateTime)
    cols = [getattr(raw, kind.key), hour.label("hour"), func.count().label("n")]
    cols += [getattr(func, agg)(getattr(raw, col)).label(name) for name, agg, col in kind.aggs]
    q = select(*cols).where(raw.ts >= start)
    if end is not None:
        q = q.where(raw.ts < end)
    if key_id is not None:
        q = q.where(getattr(raw, kind.key) == key_id)
    return q.group_by(getattr(raw, kind.key), hour)


def _roll_start(kind):
    """The hour the next roll starts at: that of the first sample after the newest hour already rolled.

    None when there is no such sample. A rolled hour is never built again: its samples may since have
    been pruned (a panel stopped for two weeks), and building it from what is left would shrink it or
    delete it. After a gap (the panel was stopped) the roll starts at the first sample after it.
    """
    newest = db.session.scalar(select(func.max(kind.hourly.hour)))
    q = select(func.min(kind.raw.ts))
    if newest is not None:
        q = q.where(kind.raw.ts >= newest + timedelta(hours=1))
    first = db.session.scalar(q)
    return floor_hour(first) if first is not None else None


def roll_up(kind, now):
    """Roll `kind`'s complete hours, up to _MAX_HOURS_PER_TICK of them, into its hourly rows; hours rolled.

    An hour is complete once `now` is past it: the current hour is left for a later tick (the sampler
    and this tick take turns on one thread, so no sample lands in an hour after it is rolled). The
    window starts after the newest rolled hour, and any row already in it is replaced rather than added
    to, so running a window twice gives the same rows. The caller commits.
    """
    start = _roll_start(kind)
    end = floor_hour(now)
    if start is None or start >= end:
        return 0
    end = min(end, start + timedelta(hours=_MAX_HOURS_PER_TICK))
    hourly = kind.hourly
    db.session.execute(hourly.__table__.delete().where(hourly.hour >= start, hourly.hour < end))
    names = [kind.key, "hour", "n"] + [name for name, _agg, _col in kind.aggs]
    db.session.execute(hourly.__table__.insert().from_select(names, _hourly_select(kind, start, end)))
    return int((end - start).total_seconds() // 3600)


def tick(now, raw_retention_days):
    """One pass of the history upkeep: roll the complete hours, then drop samples and rollups past their age.

    The samples are dropped only after their hours are rolled, so nothing is lost between the two. Returns
    {"server": hours rolled, "host": hours rolled}.
    """
    rolled = {"server": roll_up(SERVER, now), "host": roll_up(HOST, now)}
    raw_cutoff = now - timedelta(days=raw_retention_days)
    MetricSample.query.filter(MetricSample.ts < raw_cutoff).delete(synchronize_session=False)
    HostSample.query.filter(HostSample.ts < raw_cutoff).delete(synchronize_session=False)
    year_cutoff = now - timedelta(days=ROLLUP_RETENTION_DAYS)
    MetricHourly.query.filter(MetricHourly.hour < year_cutoff).delete(synchronize_session=False)
    HostHourly.query.filter(HostHourly.hour < year_cutoff).delete(synchronize_session=False)
    db.session.commit()
    return rolled


def newest(kind, key_id):
    """(newest sample's time, newest rolled hour's start) for `key_id`, each None when there is none."""
    raw, hourly = kind.raw, kind.hourly
    return (db.session.scalar(select(func.max(raw.ts)).where(getattr(raw, kind.key) == key_id)),
            db.session.scalar(select(func.max(hourly.hour)).where(getattr(hourly, kind.key) == key_id)))


def _bucketed_select(kind, key_id, start, width):
    """`key_id`'s rolled hours from `start` merged in SQL into buckets of `width` seconds, one row per bucket.

    Averages weighted by each hour's samples, the highest max, the lowest min; `hour` is the bucket's first
    hour and `last` its newest. Done in the query: a year is 8,760 rows, and merging them in Python held the
    hub for ~40 ms a series, where SQLite answers the ~240 merged rows in a few.
    """
    hourly = kind.hourly
    epoch0 = calendar.timegm(start.timetuple())
    # precedence=8, as `*` and `/` have: the subtraction is then bracketed before the integer division.
    bucket = (type_coerce(func.strftime("%s", hourly.hour), Integer) - epoch0).op("/", precedence=8)(width).label("b")
    cols = [bucket, func.min(hourly.hour).label("hour"), func.max(hourly.hour).label("last"),
            func.sum(hourly.n).label("n")]
    for name, agg, _col in kind.aggs:
        col = getattr(hourly, name)
        if agg == "avg":
            expr = func.sum(col * hourly.n) * 1.0 / func.sum(case((col.is_not(None), hourly.n)))
        else:
            expr = getattr(func, agg)(col)
        cols.append(expr.label(name))
    return (select(*cols).where(getattr(hourly, kind.key) == key_id, hourly.hour >= start)
            .group_by(bucket).order_by(bucket))


def series(kind, key_id, since, hours):
    """`key_id`'s history over the `hours` up to now, at most MAX_POINTS points of equal width, oldest first.

    Each point has the averages under the per-minute points' names (cpu, ram, disk, rx, tx; players is the
    most seen) and the highest and lowest under their own (cpu_max, cpu_min, ...). The rolled hours are
    merged in the query; the hours after the newest rolled one (the current hour, and any a tick has not
    reached yet) are built from the samples the way the rollup builds them, so a long range is as current
    as the 24-hour one. Two queries; an empty list when nothing was recorded in the range.
    """
    start = floor_hour(since)
    width = 3600 * -(-(hours + 1) // MAX_POINTS)
    rolled = db.session.execute(_bucketed_select(kind, key_id, start, width)).all()
    live_from = max(since, rolled[-1].last + timedelta(hours=1)) if rolled else since
    live = db.session.execute(_hourly_select(kind, live_from, key_id=key_id)).all()
    buckets = {r.b: [r] for r in rolled}
    for r in live:
        buckets.setdefault(int((r.hour - start).total_seconds()) // width, []).append(r)
    return [_merge(buckets[b], kind) for b in sorted(buckets)]


def _merge(rows, kind):
    """One point from consecutive hourly rows: averages weighted by samples, the highest max, the lowest min."""
    out = {"t": rows[0].hour.isoformat() + "Z"}
    for name, agg, _col in kind.aggs:
        out[_POINT_NAMES.get(name, name)] = _combine(agg, [(getattr(r, name), r.n or 0) for r in rows
                                                           if getattr(r, name) is not None])
    return out


def _combine(agg, vals):
    """One figure from (value, samples) pairs: None for none, else the weighted average, the max or the min."""
    weight = sum(w for _v, w in vals)
    if not vals or (agg == "avg" and not weight):
        return None
    if agg == "avg":
        return round(sum(v * w for v, w in vals) / weight, 1)
    return round((max if agg == "max" else min)(v for v, _w in vals), 1)
