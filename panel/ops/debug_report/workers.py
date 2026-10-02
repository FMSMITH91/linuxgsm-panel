"""Debug-report section(s): workers.

Owner: builder B4. heartbeats and respawns from runtime_stats (R22).

Each background loop calls runtime_stats.beat(name, cadence, took) when a pass COMPLETES, and
bump("loopfail", name) when a pass raises; the supervisor bumps ("respawn", name) when a worker it
runs exits. Every thread is started with name= a fixed identifier, so threading.enumerate() can say
which are alive. Printed: each loop's last completed pass BESIDE its cadence -- no "stale"
threshold is invented here -- plus how long the pass took, failures and respawns.

Three states are kept apart, because they mean different things: "never completed a pass since
start", "not instrumented" (a loop with no heartbeat), and the extra reads that say whether there
was anything to do at all (no samples because no server is installed).
"""
import threading
import time

from panel.ops.debug_report._base import Result, ago, unread_line
from panel.ops.debug_report.hosts import mod, snap, tok

AREA = "Background workers"

# (name -- both the heartbeat key and the thread name, cadence in s, None for an event loop)
WORKERS = (
    ("monitor", 60), ("player-counts", 45), ("metrics-history", 60), ("node-tools", 86400),
    ("reboot-when-empty", 60), ("autoblock", 3600), ("ban-watch", 90),
    ("console-poller", 2), ("backup-ticker", 3600), ("due-actions", 90),
    ("install-reconcile", 600), ("priority-keeper", 120), ("update-check", 1800),
    ("telegram-bot", None), ("discord-bot", None),
    ("terminal-idle-sweeper", None), ("terminal-revocation-sweeper", None),
)
# Loops that only exist on some installs: absent is not dead.
_OPTIONAL = {"ban-watch"}


def threads_by_name():
    """{thread name: alive} from ONE snapshot of threading.enumerate()."""
    return {t.name: t.is_alive() for t in list(threading.enumerate())}


def _thread_word(name, threads, visible):
    if not visible:
        return "thread state not visible from here"
    if name not in threads:
        return "thread not found" if name in _OPTIONAL else "thread NOT alive"
    return "thread alive" if threads[name] else "thread NOT alive"


def _pass_words(name, cadence, hb, uptime, now):
    """'last pass 38 s ago / every 60 s · took 4.1 s · passes 12', or why there is none."""
    every = " / every %s" % ago(cadence) if cadence else ""
    if not isinstance(hb, dict):
        if cadence is None:
            return ["not instrumented"]
        return ["never completed a pass since start (%s)%s" % (ago(uptime), every)]
    words = ["last pass %s ago%s" % (ago(now - hb.get("at", now)),
                                     " / every %s" % ago(hb["cadence"]) if hb.get("cadence")
                                     else every)]
    took = hb.get("took")
    if isinstance(took, (int, float)):
        words.append("took %.1f s" % took)
    words.append("passes %d" % hb.get("passes", 0))
    return words


def _worker_line(name, cadence, stats, threads, visible):
    now = time.time()
    words = _pass_words(name, cadence, stats["hb"].get(name), now - stats["started"], now)
    fails = stats["fail"].get(name, 0)
    if fails:
        words.append("failed passes %d" % fails)
    respawns = stats["respawn"].get(name, 0)
    if respawns:
        words.append("respawned %d×" % respawns)
    words.append(_thread_word(name, threads, visible))
    return "- %s: %s" % (name, " · ".join(words))


def _findings(res, name, stats, threads, visible):
    """Facts only: a thread that is not alive, a respawn, a loop whose every pass has failed."""
    if visible and name not in _OPTIONAL and not threads.get(name, False):
        res.find("warn", AREA, "%s: thread not alive" % name)
    if stats["respawn"].get(name):
        res.find("warn", AREA, "%s respawned %d×" % (name, stats["respawn"][name]))
    if stats["fail"].get(name) and not isinstance(stats["hb"].get(name), dict):
        res.find("warn", AREA, "%s: every pass since start has failed (%d)" % (
            name, stats["fail"][name]))


def _extras(now):
    """What the loops' own state says, beside their heartbeats (no instrumentation needed)."""
    ps = mod("panel.core.panel_state")
    counts = [v.get("ts") for v in snap(ps._player_counts).values()
              if isinstance(v, dict) and v.get("ts")]
    lines = ["- player counts: newest poll %s" % ("%s ago" % ago(now - max(counts)) if counts
                                                  else "none (no installed server polled)")]
    prune = ps._last_sample_prune[0]
    lines.append("- metric samples: %s · last prune %s" % (
        _newest_samples(), "%s ago" % ago(now - prune) if prune else "not yet by this process"))
    return lines


def _newest_samples():
    """'newest game sample 52 s ago, host sample 52 s ago' from two indexed MAX(ts)."""
    models = mod("panel.db.models")
    func = mod("sqlalchemy").func
    utcnow = mod("panel.core.clock").utcnow()
    out = []
    for label, model in (("game", models.MetricSample), ("host", models.HostSample)):
        ts = models.db.session.query(func.max(model.ts)).scalar()
        out.append("newest %s sample %s" % (label, "%s ago" % ago(
            (utcnow - ts).total_seconds()) if ts else "none in the table"))
    return ", ".join(out)


def _stats():
    rs = mod("panel.core.runtime_stats")
    return {"hb": rs.snapshot("heartbeat"), "fail": rs.snapshot("loopfail"),
            "respawn": rs.snapshot("respawn"), "started": rs.started()}


def _dead(threads, visible):
    """The known workers whose thread is not alive (none can be named when none is visible)."""
    if not visible:
        return []
    return [n for n, _c in WORKERS if n not in _OPTIONAL and not threads.get(n, False)]


def _verdict(stats, threads, visible):
    dead = _dead(threads, visible)
    respawns = sum(v for v in stats["respawn"].values() if isinstance(v, int))
    if dead:
        alive = "%d NOT alive (%s)" % (len(dead), ", ".join(dead))
    else:
        alive = "all %d alive" % len(WORKERS) if visible else "thread state not visible"
    return "**Background workers**: %s · %d respawn%s" % (alive, respawns,
                                                          "" if respawns == 1 else "s")


def section_workers(ctx):
    """R22: each loop's last completed pass beside its cadence, failures, respawns, liveness."""
    res = Result()
    stats = _stats()
    threads = threads_by_name()
    # A loop's thread can only be called dead if this process's threads are visible at all:
    # one named worker found proves the names are readable here.
    visible = any(n in threads for n, _c in WORKERS)
    for name, cadence in WORKERS:
        res.add(_worker_line(name, cadence, stats, threads, visible))
        _findings(res, name, stats, threads, visible)
    known = {n for n, _c in WORKERS}
    for name in sorted(k for k in stats["hb"] if k not in known):
        res.add("- %s: last pass %s ago (not in the list of known workers)" % (
            tok(name), ago(time.time() - stats["hb"][name].get("at", 0))))
    try:
        res.lines += _extras(time.time())
    except Exception as exc:  # noqa: BLE001
        res.add(unread_line("loop state", exc))
    res.verdict = _verdict(stats, threads, visible)
    return res
