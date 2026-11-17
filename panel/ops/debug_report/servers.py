"""Debug-report section(s): servers, console.

Owner: builder B4. servers: per game server DB vs monitor vs port scan vs players, install jobs,
LinuxGSM data (R52, R54, R55). console: console feed state per watched server (R56).

Ids, game types (LinuxGSM shortnames), ports, statuses, counts, ages and fixed tokens only. Never
gs.name, short_name, a tag name, a console line or log path, an install's free text, a viewer's
identity or the in-game title. Caches are READ: nothing here scans a port, polls players or SSHes.
"""
import json
import re
import sys
import time

from panel.ops.debug_report._base import Result, ago, unread_line
from panel.ops.debug_report.hosts import (LockBusy, fmt_conflict, game_tok, gs_cols,
                                          install_jobs, mod, port_conflicts, snap, stranded_ids,
                                          tok)

AREA = "Game servers"
_ERRORS_SCANNED = 4096     # bytes of install_error handed to the classifier (R52 cost)
_DATA_NAME_RE = re.compile(r"^[a-z0-9.-]{1,32}\.csv\Z")
_ACTION_RE = re.compile(r"^[a-z-]{1,20}\Z")
# The install steps' fixed names (manage_servers' run.progress / job.p calls). A step name is
# printed only when it starts with one of these, and then as the fixed prefix: a GMod content step
# carries the content labels and a progress callback's own text after it.
_STEP_NAMES = ("Queued", "Preparing user account", "Installing dependencies",
               "Downloading LinuxGSM", "Downloading game server files", "Working around a SteamCMD",
               "Fetching the Linux server binaries", "Configuring server",
               "Detecting ports & opening firewall", "Enabling autostart", "Installing GMod content",
               "Starting server", "Complete")


# ── servers (R52, R53, R54, R55) ──────────────────────────────────────────────────────────────

def _lgsm_line():
    """R55: lgsm_data.status() -- cached files' ages and which fetch failed, by category only."""
    st = mod("panel.services.lgsm_data").status()
    ages = ["%s %s" % (tok(n, _DATA_NAME_RE), "never fetched" if a is None else ago(a) + " old")
            for n, a in sorted((st.get("cached") or {}).items())]
    errs = st.get("errors") or {}
    err = "none" if not errs else ", ".join(
        "%s (%s)" % (tok(n, _DATA_NAME_RE), "cache write failed"
                     if str(m).startswith("could not write") else "fetch failed")
        for n, m in sorted(errs.items()))
    empty = "" if st.get("have_serverlist") else " · game list EMPTY"
    return "- **LinuxGSM data**: %s · last fetch error: %s%s" % (" · ".join(ages), err, empty)


def _step_label(name):
    for fixed in _STEP_NAMES:
        if isinstance(name, str) and name.startswith(fixed):
            return fixed
    return None


def _job_line(sid, job, by_id, now):
    """'- gs 16 · ark · host 4 · install RUNNING step 4/8 'Downloading…' · started 52 m ago …'."""
    row = by_id.get(sid) or {}
    label = _step_label(job.get("step_name"))
    started, updated = job.get("started"), job.get("updated")
    return "- gs %s · %s · host %s · install %s step %s/%s%s · started %s ago · last progress %s ago" % (
        sid, row.get("game_type", "?"), row.get("remote_id", "?"),
        tok(job.get("status"), other="?").upper(), job.get("step", "?"), job.get("total", "?"),
        " '%s'" % label if label else "", ago(now - started) if started else "?",
        ago(now - updated) if updated else "?")


def _jobs_lines(res, rows):
    """R54: live install jobs, then the rows stranded in installing with no job behind them."""
    try:
        jobs = install_jobs()
    except LockBusy:
        return res.add("- **Install jobs**: not read (the install lock was busy for 1 s)")
    by_id = {r["id"]: r for r in rows}
    running = {k: v for k, v in jobs.items() if v.get("status") == "running"}
    res.add("- **Install jobs**: %d running, %d finished since panel start" % (
        len(running), len(jobs) - len(running)))
    now = time.time()
    for sid, job in sorted(running.items()):
        res.add(_job_line(sid, job, by_id, now))
    for sid in stranded_ids(rows, jobs):
        r = by_id[sid]
        res.add("- gs %d · %s · host %s · status %s but NO live job → stranded (the reconciler "
                "runs every 10 min)" % (sid, r["game_type"], r["remote_id"], r["status"]))
        res.find("warn", AREA, "gs %d: stranded in %s with no live install job" % (sid, r["status"]))
    return res


def _load_servers():
    """Every GameServer row, tags eager-loaded (alerts_muted would lazy-load them, N+1)."""
    models = mod("panel.db.models")
    orm = mod("sqlalchemy.orm")
    return (models.GameServer.query.options(orm.joinedload(models.GameServer.tags))
            .order_by(models.GameServer.id).all())


def _state():
    """Copies of every live map a server line reads."""
    ps = mod("panel.core.panel_state")
    ms = ps._monitor_state
    return {"mon": snap(ms["servers"]), "misses": snap(ms["server_misses"]),
            "players": snap(ps._player_counts), "expected": snap(ps._expected_offline),
            "stop": snap(ps._expected_stop),
            "cron_restart": snap(ps._cron_restart_pending),
            "scan": snap(mod("panel.ops.ssh_manager.portscan")._port_scan_cache)}


def _monitor_word(gs_id, st):
    up = st["mon"].get(gs_id)
    word = "monitor up" if up is True else "monitor down" if up is False else "monitor: not checked"
    if st["misses"].get(gs_id):
        word += " (%s/%d misses pending)" % (
            st["misses"][gs_id], mod("panel.services.monitoring")._DOWN_CONFIRM_SWEEPS)
    return word


def _port_word(gs, st, now):
    hit = st["scan"].get(gs.remote_id)
    if not (isinstance(hit, tuple) and len(hit) == 2):
        return "port scan: none since panel start"
    ttl = mod("panel.ops.ssh_manager.portscan")._PORT_SCAN_TTL
    return "port %s (scan %s ago)" % ("listening" if gs.port in (hit[1] or ()) else "NOT listening",
                                     ago(now - (hit[0] - ttl)))


def _players_word(gs_id, st, now):
    entry = st["players"].get(gs_id)
    if not isinstance(entry, dict):
        return "players unknown (never polled)"
    count = entry.get("count")
    when = entry.get("ts")
    return "players %s (polled %s ago)" % (count if isinstance(count, int) else "unknown",
                                           ago(now - when) if when else "?")


def _cmds_word(raw):
    try:
        n = len(json.loads(raw or "[]"))
    except (TypeError, ValueError):
        return "cmds unreadable"
    if n == 0:
        return "cmds 0 (command list never fetched → Start/Stop/Update may be hidden)"
    return "cmds %d" % n


def _flags(gs, st, now, muted):
    """The conditional flags of a server line, each a fixed word."""
    out = []
    since = st["expected"].get(gs.id)
    window = mod("panel.services.monitoring")._EXPECT_OFFLINE_WINDOW
    if since == float("inf"):          # host_reboot: held for as long as its host's reboot plan runs
        out.append("expected offline (host reboot)")
    elif isinstance(since, (int, float)) and now - since <= window:
        # A Stop's down is never paged; any other window (a restart, a reboot's mark, a plan's end)
        # pages a server still down when it ends — the monitor reads the two differently.
        if (st.get("stop") or {}).get(gs.id) == since:
            out.append("expected offline (panel stop %s ago)" % ago(now - since))
        else:
            out.append("expected offline (back expected, %s left)" % ago(since + window - now))
    if gs.restart_pending:
        out.append("restart_pending")
    if st["cron_restart"].get(gs.id):
        out.append("daily-restart flag set on the host")
    if muted:
        out.append("alerts muted")
    return out


def _install_words(gs):
    """For a failed install: retryable, and the classifier's CODE -- never the raw error."""
    if gs.status != "failed" and not gs.install_error:
        return []
    words = ["retryable %s" % ("yes" if gs.install_retryable else "no")]
    if gs.install_error:
        why = mod("panel.ops.ssh_manager.hosts").classify_install_failure(
            gs.install_error[:_ERRORS_SCANNED])
        words.append("install_error classified: %s" % (tok(why[0]) if why else "unclassified"))
    return words


def _server_line(gs, st, now, muted):
    head = ["- gs %d" % gs.id, game_tok(gs.game_type), "host %s" % gs.remote_id,
            "port %s" % gs.port, "DB %s" % tok(gs.status, other="other")]
    if gs.status in ("installing", "configuring"):
        return " · ".join(head + ["(the monitor skips a server mid-install)"])
    body = [_monitor_word(gs.id, st), _port_word(gs, st, now), _players_word(gs.id, st, now),
            _cmds_word(gs.commands)]
    return " · ".join(head + body + _flags(gs, st, now, muted) + _install_words(gs))


def _servers_lines(res):
    """R52: one line per server. Rows load with tags; alerts_muted is asked per row."""
    servers = _load_servers()
    if not servers:
        return res.add("- no game servers in the database")
    st, now = _state(), time.time()
    notify = mod("panel.services.notifications")
    for gs in servers:
        try:
            res.add(_server_line(gs, st, now, notify.alerts_muted(gs)))
        except Exception as exc:  # noqa: BLE001
            res.add(unread_line("gs %d" % gs.id, exc))
    return res


def _conflict_lines(ctx, res):
    """R53, in full."""
    conf = port_conflicts(ctx)
    res.add("- **Port conflicts**: %s" % ("none" if not conf else len(conf)))
    for c in conf:
        res.add("  - " + fmt_conflict(c))


def section_servers(ctx):
    """The Game servers section: data cache, install jobs, port conflicts, then each server."""
    res = Result()
    for what, fn in (("LinuxGSM data", lambda: res.add(_lgsm_line())),
                     ("Install jobs", lambda: _jobs_lines(res, gs_cols(ctx))),
                     ("Port conflicts", lambda: _conflict_lines(ctx, res)),
                     ("Game servers", lambda: _servers_lines(res))):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - one part unread is printed as exactly that
            res.add(unread_line(what, exc))
            res.find("unread", AREA, "%s could not be read" % what)
    return res


# ── console (R56) ─────────────────────────────────────────────────────────────────────────────

def _feed_maps():
    """Copies of the poller's per-server maps, or None when the console module is not loaded."""
    sf = sys.modules.get("panel.routes.server_files")
    if sf is None:
        return None
    ps = mod("panel.core.panel_state")
    if not sf._viewers_lock.acquire(timeout=1):
        raise LockBusy()
    try:
        viewers = {k: len(v) for k, v in list(sf._console_viewers.items())}
    finally:
        sf._viewers_lock.release()
    return {"viewers": viewers, "feed": snap(sf._console_feed),
            "partial": {k: len(v) for k, v in snap(ps._console_partial).items()
                        if isinstance(v, str)},
            "backlog": {k: len(v) for k, v in snap(ps._console_backlog).items()
                        if isinstance(v, list)},
            "action": snap(ps._action_output), "offsets": snap(ps._console_offsets)}


def _feed_words(f, now):
    words = []
    if not isinstance(f, dict):
        return ["counters not recorded yet"]
    pushed = f.get("pushed_at")
    words.append("last chunk pushed %s ago" % ago(now - pushed) if pushed
                 else "nothing pushed since panel start")
    words.append("ticks %d, failed %d" % (f.get("ticks", 0), f.get("fails", 0)))
    if f.get("rotations"):
        words.append("log rotated %d×" % f["rotations"])
    if f.get("streak"):
        words.append("%d consecutive failed ticks (last: %s) ← console frozen" % (
            f["streak"], tok(f.get("last_fail"))))
    return words


def _console_line(sid, maps, by_id, now):
    row = by_id.get(sid) or {}
    n = maps["viewers"].get(sid, 0)
    words = ["- gs %s %s (host %s): %d viewer%s" % (sid, row.get("game_type", "?"),
                                                    row.get("remote_id", "?"), n,
                                                    "" if n == 1 else "s")]
    words += _feed_words(maps["feed"].get(sid), now)
    words.append("partial line %d chars" % maps["partial"].get(sid, 0))
    words.append("backlog %d/%d" % (maps["backlog"].get(sid, 0),
                                    mod("panel.routes._shared")._CONSOLE_BACKLOG_MAX))
    act = maps["action"].get(sid)
    if isinstance(act, dict):
        words.append("action output: %s running" % tok(act.get("action"), _ACTION_RE))
    return " · ".join(words)


def _watched_words(rs):
    """' · watching 2 servers' from the poller's last pass, or '' when it recorded none."""
    rec = rs.snapshot("console").get("poller|watched")
    if not (isinstance(rec, tuple) and len(rec) == 2 and isinstance(rec[1], int)):
        return ""
    return " · watching %d server%s" % (rec[1], "" if rec[1] == 1 else "s")


def _poller_line(now):
    rs = mod("panel.core.runtime_stats")
    hb = rs.snapshot("heartbeat").get("console-poller")
    respawns = rs.snapshot("respawn").get("console-poller", 0)
    if not isinstance(hb, dict):
        return "- **Poller**: no pass recorded since panel start · respawned %d×" % respawns
    took = hb.get("took")
    return "- **Poller**: last pass %s ago / every %s s%s%s · respawned %d×" % (
        ago(now - hb["at"]), hb.get("cadence") or "?",
        " · took %.1f s" % took if isinstance(took, (int, float)) else "", _watched_words(rs),
        respawns)


def section_console(ctx):
    """R56: per watched server, what the console poller has seen. Counts and classes only."""
    res = Result()
    now = time.time()
    res.add(_poller_line(now))
    maps = _feed_maps()
    if maps is None:
        return res.add("- the console module is not loaded in this process")
    ids = sorted(set(maps["viewers"]) | set(maps["feed"]) | set(maps["action"]),
                 key=lambda k: (not isinstance(k, int), str(k)))
    if not maps["viewers"]:
        res.add("- no console is being watched (poller idle)")
    try:
        by_id = {r["id"]: r for r in gs_cols(ctx)}
    except Exception as exc:  # noqa: BLE001 - the lines still print, without game types
        res.add(unread_line("game types", exc))
        by_id = {}
    for sid in ids:
        res.add(_console_line(sid, maps, by_id, now))
        f = maps["feed"].get(sid)
        if maps["viewers"].get(sid) and isinstance(f, dict) and f.get("streak"):
            res.find("warn", "Live console", "gs %s: %d consecutive failed console reads (%s)" % (
                sid, f["streak"], tok(f.get("last_fail"))))
    return res
