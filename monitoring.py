"""The monitor loop and everything that feeds it: player counts, host probes, metric samples,
LinuxGSM maintenance detection, autoblock reconciliation, and the deferred reboot watch.

Lifted out of app.py, where these sat interleaved with route registration and the chat bots across
roughly a thousand lines. Nothing here is per-app: each function takes what it needs as an argument
or reads shared process state from panel_state, which is why the move needed no redesign.

A few of these are also called from route handlers (_cached_player_count, _autoblock_threshold,
_whitelisted, _host_reachable, _metrics_work). app.py imports them back. The dependency direction
is deliberate — routes may reach into monitoring; monitoring never reaches into routes.
"""
import concurrent.futures
import ipaddress
import logging
import re
import shlex
import time

import notifications
import system_ops as so
from auth import log_action
from clock import utcnow
from config import load_config
from models import GameServer, HostSample, MetricSample, RemoteServer, db
from panel_state import (
    _cron_restart_pending, _expected_offline, _max_players_cache, _monitor_state, _os_update_seen,
    _player_counts, _reboot_when_empty, _rwe_lock, _server_full_alerted, _server_peak_notified,
)
from ssh_manager import (
    _remote_listening_ports, game_map, lgsm_get_values, remote_fail2ban_top_ips, remote_reboot,
    remote_ufw_blocked_ips, remote_ufw_deny_ip, remote_ufw_undeny_ip, run_command,
    server_live_metrics, tailnet_exempt_ips,
    console_status as sm_console_status,
    game_engine as sm_game_engine,
    get_server_status as sm_get_server_status,
    player_count_via_lgsm_query as sm_player_count_via_lgsm_query,
    player_slots as sm_player_slots,
)

_log = logging.getLogger("panel.monitoring")

# What app.py imports from here. CodeQL analyses a module in isolation, so the three tuning
# constants below — read only by the ticker loops in app.py — read as unused globals to it.
# Declaring the surface is the idiomatic fix rather than a suppression, and it stays true
# when those loops move next to the code they drive.
__all__ = [
    "_AUTOBLOCK_DEFAULT_THRESHOLD",
    "_METRIC_RETENTION_DAYS",
    "_METRIC_SAMPLE_SECONDS",
    "_MONITOR_HOST_WORKERS",
    "_MONITOR_SECONDS",
    "_PLAYER_POLL_SECONDS",
    "_PLAYER_POLL_WORKERS",
    "_autoblock_reconcile",
    "_autoblock_threshold",
    "_cached_player_count",
    "_host_reachable",
    "_metrics_work",
    "_monitor_pass",
    "_query_server_metrics",
    "_reboot_when_empty_watch",
    "_record_metric_samples",
    "_refresh_player_counts",
    "_whitelisted",
]

def _host_idle_state(remote):
    """'idle' (no players on any game server, confidently), 'busy' (someone is connected), or
    'unknown' (at least one server couldn't be read). The reboot-when-empty poller only acts on
    'idle', so a game the panel can't query is never rebooted out from under its players."""
    unknown = False
    for gs in GameServer.query.filter_by(remote_id=remote.id, installed=True).all():
        pc = _server_players_confident(gs)
        if pc is None:
            unknown = True
        elif pc > 0:
            return "busy"
    return "unknown" if unknown else "idle"


def _host_reachable(remote):
    """Whether a host answers a trivial command right now (run_command runs it locally for the panel
    host). Used to avoid rebooting a host we can't currently confirm is idle."""
    try:
        out, _, _ = run_command(remote, "echo ok", timeout=10)
        return "ok" in (out or "")
    except Exception:
        return False


_PLAYER_POLL_SECONDS = 45


_PEAK_NOTIFY_INTERVAL = 3600  # at most one "new record" alert per server per hour


def _cached_player_count(server_id):
    """Last known player count for a server (int, incl. 0), or None when unknown / not polled yet."""
    entry = _player_counts.get(server_id)
    return entry["count"] if entry else None


_PLAYER_POLL_WORKERS = 8   # cap on concurrent per-server queries (SSH/gamedig) in one poll pass


def _query_server_slots(gs):
    """Worker for the parallel poll: (id, (count, max, name)) for one server.

    Takes the ALREADY-LOADED row rather than an id, and opens no app context of its own. It used to
    do both, which meant it held a database connection for the whole gamedig/SSH round trip — up to
    the query timeout. With 8 workers that pinned 9 of the pool's 15 connections (SQLAlchemy's
    default 5 + 10 overflow) for as long as one slow host took to answer, and every web request in
    that window queued behind them.

    Reads only loaded columns plus the joinedloaded host, so nothing lazy-loads on a pool thread.
    Never raises."""
    try:
        if gs.status == "offline":
            return gs.id, (0, _server_max_config(gs), None)
        return gs.id, tuple(_server_slots(gs))
    except Exception:
        return gs.id, (None, None, None)


def _metrics_work(servers):
    """Freeze what the metrics workers need, read in the CALLER's thread.

    Each worker used to open an app context of its own and re-fetch the server plus lazy-load its
    host — two queries per server on an endpoint the dashboard polls every few seconds, so 500
    servers meant ~1000 queries per poll. The rows are already loaded here (get_user_servers
    joinedloads the host), so read them once and hand the workers plain values."""
    return [(gs.remote, gs.id, gs.short_name, gs.port, gs.game_type, gs.query_type, gs.remote_id)
            for gs in servers if gs.installed]


def _query_server_metrics(work):
    """Worker for the dashboard metrics poll: (sid, metrics_dict|None, remote_id, map) for one
    server. server_live_metrics is one cached SSH round trip that yields BOTH the whole host's
    figures and this game's share. Takes the frozen tuple from _metrics_work rather than an id: it
    runs on a pool thread, where a session of its own costs a query per server and sharing the
    caller's would not be thread-safe. Reads only already-loaded columns. Never raises."""
    remote, sid, short_name, port, game_type, query_type, remote_id = work
    try:
        m = server_live_metrics(remote, short_name, port)
    except Exception:
        return sid, None, remote_id, ""
    mp = ""
    if m.get("game_procs"):     # only query the map for a running server
        try:
            mp = game_map(remote, short_name, game_type, port, query_type)
        except Exception:
            mp = ""
    return sid, m, remote_id, mp


def _refresh_player_counts(app):
    """One pass: re-read the confident (count, max, name) for every installed server into the cache.
    The per-server queries (gamedig / console over SSH — the slow part) run in a small thread pool so
    a pass doesn't grow linearly with the server count; the cache update + notifications then run
    single-threaded here (all DB writes stay in this one context). An offline server is 0 players
    without a query; a running one the panel can't read stays None."""
    with app.app_context():
        from sqlalchemy.orm import joinedload
        # joinedload: the workers read gs.remote, and lazily that is both a query per server AND a
        # lazy load fired from a pool thread against this context's session.
        servers = [gs for gs in GameServer.query.options(joinedload(GameServer.remote))
                   .filter_by(installed=True).all()
                   if gs.status not in ("installing", "configuring")]
        if not servers:
            return
        # Query all servers concurrently (bounded), then apply the results serially below.
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(_PLAYER_POLL_WORKERS, len(servers))) as ex:
            for sid, slots in ex.map(_query_server_slots, servers):
                results[sid] = slots
        for gs in servers:
            count, mx, gname = results.get(gs.id, (None, None, None))
            # Keep the last-known in-game name when this pass didn't get one (e.g. the server is
            # stopped or momentarily unqueryable) rather than blanking it in the UI.
            prev_name = (_player_counts.get(gs.id) or {}).get("name")
            _player_counts[gs.id] = {"count": count, "max": mx,
                                     "name": gname or prev_name, "ts": time.time()}
            # One-shot "notify when empty": fire once on a CONFIRMED 0 (never on an unknown count),
            # then clear the flag so it doesn't ping every time the server empties.
            # A muting tag skips the whole block, flag included: the request stays ARMED, so it
            # fires the next time the server empties after the tag comes off — rather than being
            # silently consumed while nobody could be told.
            if gs.notify_when_empty and count == 0 and not notifications.alerts_muted(gs):
                try:
                    notifications.notify("server_empty", "Server is empty",
                                         "%s on %s now has 0 players — safe to make changes."
                                         % (gs.name, gs.remote.display_name))
                    gs.notify_when_empty = False
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                    _log.debug("notify-when-empty failed for %s", getattr(gs, "short_name", "?"), exc_info=True)
            # Server full — alert on the transition INTO full, re-arm when it drops below the cap.
            if isinstance(count, int) and isinstance(mx, int) and mx > 0:
                if count >= mx and not _server_full_alerted.get(gs.id):
                    if not notifications.alerts_muted(gs):
                        notifications.notify("server_full", "Server full",
                                             "%s on %s is full (%d/%d players)."
                                             % (gs.name, gs.remote.display_name, count, mx))
                    # Marked alerted regardless, so unmuting mid-session doesn't fire retroactively
                    # for a server that has been sitting at its cap the whole time.
                    _server_full_alerted[gs.id] = True
                elif count < mx and _server_full_alerted.get(gs.id):
                    _server_full_alerted[gs.id] = False
            # New player-count record — always track the peak; alert at most once/hour, and never on
            # the first-ever count (0 -> N is a baseline, not a "record").
            if isinstance(count, int) and count > (gs.peak_players or 0):
                prev = gs.peak_players or 0
                try:
                    gs.peak_players = count
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                if (prev > 0 and (time.time() - _server_peak_notified.get(gs.id, 0)) > _PEAK_NOTIFY_INTERVAL
                        and not notifications.alerts_muted(gs)):
                    _server_peak_notified[gs.id] = time.time()
                    notifications.notify("server_peak", "New player record",
                                         "%s on %s just hit %d players — a new record."
                                         % (gs.name, gs.remote.display_name, count))


_METRIC_SAMPLE_SECONDS = 60


_METRIC_RETENTION_DAYS = 14


def _record_metric_samples(app):
    """One pass: snapshot every installed server's game CPU%/RAM (+ the cached player count) and each
    host's whole-VPS CPU%/RAM%/disk% into MetricSample/HostSample for the history charts. Reuses the
    parallel metrics worker; the player count comes from the cache the player poller already keeps."""
    with app.app_context():
        # joinedload: the workers need each server's host, and lazily that is one query per server.
        from sqlalchemy.orm import joinedload
        work = _metrics_work(GameServer.query.options(joinedload(GameServer.remote))
                             .filter_by(installed=True).all())
        if not work:
            return
        now = utcnow()
        rows, hosts_seen = [], set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(_PLAYER_POLL_WORKERS, len(work))) as ex:
            for sid, m, rid, _mp in ex.map(_query_server_metrics, work):
                if not m:
                    continue
                rows.append(MetricSample(server_id=sid, ts=now,
                                         cpu=round(m.get("game_cpu_percent") or 0, 1),
                                         ram_mb=int(m.get("game_ram_mb") or 0),
                                         players=_cached_player_count(sid)))
                if rid is not None and rid not in hosts_seen:
                    hosts_seen.add(rid)
                    rt, dt = m.get("ram_total") or 0, m.get("disk_total") or 0
                    rows.append(HostSample(remote_id=rid, ts=now,
                                           cpu=round(m.get("cpu_percent") or 0, 1),
                                           ram_pct=round(100.0 * (m.get("ram_used") or 0) / rt, 1) if rt else 0,
                                           disk_pct=round(100.0 * (m.get("disk_used") or 0) / dt, 1) if dt else 0))
        if rows:
            db.session.add_all(rows)
            db.session.commit()


_MONITOR_SECONDS = 60


_EXPECT_OFFLINE_WINDOW = 180    # a panel-issued stop/restart suppresses "server down" for this long


# LinuxGSM commands that legitimately take a server down for a while. Every entry widens the window
# in which a REAL crash is swallowed, so a command earns its place here only by actually stopping
# the server: `monitor` (runs every few minutes, would suppress everything) and `update-lgsm` (fetches
# scripts with the server up) are deliberately absent.
_LGSM_MAINTENANCE_CMDS = ("update", "force-update", "validate", "mods-update", "restart", "backup")


def _lgsm_maintenance_running(remote, gs):
    """True if LinuxGSM is mid-maintenance for this server right now.

    _expected_offline only knows about stops the PANEL issued. A server's own LinuxGSM cron —
    `30 4 * * * ./gmodserver force-update` on a stock install — takes it down without telling the
    panel anything, so the monitor read a nightly scheduled update as "went offline unexpectedly"
    and alerted every single night.

    Checked by process, not by parsing crontabs: the maintenance command's own shell process lives
    for the whole stop→update→start cycle, so its presence covers exactly the window during which
    Only runs when a server has just been seen DOWN and the panel did not stop it itself, so it
    costs nothing in the normal case.

    Fails to False on any error — a probe that cannot answer must not hide a real outage."""
    try:
        user = (gs.short_name or "").strip()
        # lgsm_name is derived ("{game_type}server"), so it is falsy only when game_type is — and it
        # degrades to a bare "server", which would match ANY *server maintenance this user is running.
        selfname = (gs.lgsm_name or "").strip() if (gs.game_type or "").strip() else ""
        if not user or not selfname:
            return False
        # pgrep -f takes an ERE. short_name/game_type are pinned to [A-Za-z0-9._-], so "." is the one
        # metacharacter that can reach here; make it literal so it can't match a neighbouring name.
        pattern = "%s (%s)" % (selfname.replace(".", "[.]"), "|".join(_LGSM_MAINTENANCE_CMDS))
        out, _, _ = run_command(
            remote,
            "pgrep -u %s -f %s >/dev/null 2>&1 && echo BUSY || echo IDLE"
            % (shlex.quote(user), shlex.quote(pattern)),
            timeout=10)
        # Exact token, not a substring: the command line itself contains the word BUSY, so anything
        # that echoes it back on stdout would otherwise mute this server's alerts permanently.
        return "BUSY" in (out or "").split()
    except Exception:
        _log.debug("maintenance probe failed for %s", getattr(gs, "name", "?"), exc_info=True)
        return False


def _host_disk_pct(remote):
    """Root-filesystem usage percent for a host (int), or None. Cheap df, best-effort."""
    try:
        out, _, _ = run_command(remote, "df -P / | awk 'NR==2{print $5}'", timeout=10)
        m = re.search(r"(\d+)%", out or "")
        return int(m.group(1)) if m else None
    except Exception:
        return None


def _host_load_mem(remote):
    """(cpu-load-per-core %, memory %) for a host, or (None, None). One cheap command."""
    try:
        out, _, _ = run_command(
            remote,
            "L=$(awk '{print $1}' /proc/loadavg); C=$(nproc); "
            "M=$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{printf \"%d\", t?(t-a)*100/t:0}' /proc/meminfo); "
            "echo \"$L $C $M\"", timeout=10)
        parts = (out or "").split()
        load1, cores, mempct = float(parts[0]), max(1, int(parts[1])), int(parts[2])
        return int(load1 / cores * 100), mempct
    except Exception:
        return None, None


# Hosts probed at once in one monitoring sweep. The sweep used to walk them one at a time, so its
# duration was the SUM of every host's latency and a single unreachable host (an SSH connect timeout)
# delayed the checks for every other host behind it.
_MONITOR_HOST_WORKERS = 8


def _host_restart_flags(remote):
    """The set of game users on `remote` whose ~/.restart-pending flag exists. One cheap ls."""
    try:
        out, _, _ = run_command(
            remote, "ls -1d /home/*/.restart-pending 2>/dev/null || true", timeout=10)
        return {ln.split("/")[2] for ln in (out or "").splitlines() if ln.startswith("/home/")}
    except Exception:
        return set()


def _probe_host(remote):
    """Every network probe for one host, gathered off the database.

    Runs on a pool thread, so it touches no session and reads only already-loaded columns of
    `remote`; a slow host costs latency, never a pooled connection. Returns (remote_id, dict) and
    never raises — each probe already degrades to None/False on its own."""
    try:
        if not _host_reachable(remote):
            return remote.id, {"reachable": False}
        try:
            ports = _remote_listening_ports(remote)
        except Exception:
            ports = None
        return remote.id, {"reachable": True, "disk": _host_disk_pct(remote),
                           "load_mem": _host_load_mem(remote), "ports": ports,
                           "restart_flagged": _host_restart_flags(remote)}
    except Exception:
        _log.debug("host probe failed for %s", getattr(remote, "name", "?"), exc_info=True)
        return remote.id, {"reachable": False}


def _monitor_pass():
    """One monitoring sweep: fire notifications on host-reachability, disk, and server up/down
    transitions vs the previous pass. First pass only records a baseline (so nothing alerts on
    startup). Never raises out.

    The network probes run concurrently; everything that touches the database, the recorded state or
    a notification stays serial in this thread, so ordering and the alert logic are unchanged."""
    remotes = RemoteServer.query.all()
    if not remotes:
        return
    probes = {}
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(_MONITOR_HOST_WORKERS, len(remotes))) as ex:
        for rid, data in ex.map(_probe_host, remotes):
            probes[rid] = data
    _th = notifications.get_thresholds()   # user-configurable disk_pct / load_pct; once per sweep
    status_changed = False
    for remote in remotes:
        probe = probes.get(remote.id) or {"reachable": False}
        reachable = probe["reachable"]
        prev = _monitor_state["remotes"].get(remote.id)
        if prev is True and not reachable:
            notifications.notify("remote_unreachable", "Host unreachable",
                                 "%s stopped responding." % remote.display_name)
        elif prev is False and reachable:
            notifications.notify("remote_recovered", "Host back online",
                                 "%s is responding again." % remote.display_name)
        _monitor_state["remotes"][remote.id] = reachable
        if not reachable:
            continue
        pct = probe["disk"]
        if pct is not None:
            alerted = _monitor_state["disk"].get(remote.id, False)
            if pct >= _th["disk_pct"] and not alerted:
                notifications.notify("disk_low", "Disk running low",
                                     "%s is at %d%% disk usage." % (remote.display_name, pct))
                _monitor_state["disk"][remote.id] = True
            elif pct < _th["disk_pct"] - 5 and alerted:
                _monitor_state["disk"][remote.id] = False
        # High CPU/memory — only when SUSTAINED for the configured window (load_mins), so a brief spike
        # on a small box doesn't page you; re-arm once it drops well below. CPU-load (a per-core loadavg
        # %, which can exceed 100) and memory each have their own threshold.
        loadpct, mempct = probe["load_mem"]
        st = _monitor_state["load"].setdefault(remote.id, {})
        need = max(1, round(_th["load_mins"] * 60 / _MONITOR_SECONDS))   # monitor passes over the line
        for kind, val, thresh, label in (("cpu", loadpct, _th["load_pct"], "CPU load"),
                                         ("mem", mempct, _th["mem_pct"], "memory")):
            if val is None:
                continue
            st[kind + "_hi"] = (st.get(kind + "_hi", 0) + 1) if val >= thresh else 0
            if st[kind + "_hi"] >= need and not st.get(kind + "_alerted"):
                notifications.notify("high_load", "Host under load",
                                     "%s is at %d%% %s (sustained %d+ min)."
                                     % (remote.display_name, val, label, _th["load_mins"]))
                st[kind + "_alerted"] = True
            elif val < thresh - 10 and st.get(kind + "_alerted"):
                st[kind + "_alerted"] = False
        ports = probe["ports"]
        if ports is None:
            continue
        for gs in GameServer.query.filter_by(remote_id=remote.id, installed=True).all():
            if gs.status in ("installing", "configuring"):
                continue
            up = gs.port in ports
            # Display-only: does the BOX think a restart is queued for this server?
            _cron_restart_pending[gs.id] = gs.short_name in (probe.get("restart_flagged") or set())
            prev_up = _monitor_state["servers"].get(gs.id)
            # State is tracked either way — only the ALERT is muted by a tag, so a server that goes
            # down while muted still reports "back online" correctly once it is unmuted.
            muted = notifications.alerts_muted(gs)
            if prev_up is True and not up:
                # The panel's own stop/restart is already accounted for locally — check that FIRST so
                # an intentional stop keeps its existing semantics and costs no SSH round trip.
                expected = time.time() - _expected_offline.get(gs.id, 0) <= _EXPECT_OFFLINE_WINDOW
                if not expected and _lgsm_maintenance_running(remote, gs):
                    # A scheduled LinuxGSM update/restart is running: the port is SUPPOSED to be shut.
                    # Leave the recorded state untouched so neither this pass nor the recovery pass
                    # alerts — otherwise suppressing "offline" would just produce "back online".
                    continue
                if not expected and not muted:
                    notifications.notify("server_down", "Server offline",
                                         "%s on %s went offline unexpectedly." % (gs.name, remote.display_name))
            elif prev_up is False and up and not muted:
                notifications.notify("server_up", "Server back online",
                                     "%s on %s is back online." % (gs.name, remote.display_name))
            _monitor_state["servers"][gs.id] = up
            # Persist what this pass just measured. Nothing else writes gs.status for a
            # running/stopped transition except the three browser-polled endpoints (/api/servers,
            # /api/server/<id>, /api/server/<id>/stats), so with nobody on the dashboard the column
            # froze at whatever the last poll saw — while this loop recomputed the truth every 60s
            # and threw it away. Two things read that column and were wrong for as long as it was
            # stale: the chat bots' /servers and /status, and _query_server_slots, which short-
            # circuits a server it believes offline to 0 players WITHOUT querying it — so a server
            # that came back up while nobody was looking reported "offline (0/24)" indefinitely.
            st = "online" if up else "offline"
            if gs.status != st:
                gs.status = st
                status_changed = True
    if status_changed:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            _log.debug("monitor: persisting server status failed", exc_info=True)
    _forget_deleted_rows({r.id for r in remotes},
                         {row[0] for row in db.session.query(GameServer.id).all()})


def _forget_deleted_rows(remote_ids, server_ids):
    """Drop per-row state for hosts/servers that no longer exist.

    Every map below is keyed by a database row id, and SQLite hands a deleted row's id straight to
    the next INSERT (plain INTEGER PRIMARY KEY = rowid, no AUTOINCREMENT). Without this a newly
    added server inherits the deleted one's flags: _server_full_alerted swallows its first "server
    full", _server_peak_notified suppresses its first peak for an hour, _expected_offline hides a
    genuine outage, and _monitor_state["disk"] eats a new host's first disk-low alert. Worse,
    _max_players_cache is not a flag at all — it hands the new server the OLD one's capacity, which
    is the number the "full" logic then compares the live player count against.

    #81 fixed exactly this for the OS-update sweep's own map and pruned only that one; these are
    its siblings. Driven off the live id sets rather than the delete routes on purpose: deleting a
    RemoteServer cascades to its GameServers (delete-orphan), so rows disappear without any
    per-server route running.
    """
    for m in (_monitor_state["remotes"], _monitor_state["disk"], _monitor_state["load"],
              # #85's snapshot prunes itself inside the daily OS-update sweep, which is the right
              # place for the alert state it guards. It is ALSO read on every page load by
              # /api/os-updates/summary, so a deleted host lingers in the login banner for up to a
              # day — under a row id a newly added host may already own, which means its name and
              # package count show to whoever can access the NEW host. Pruning here as well makes
              # that prompt instead of daily; both are idempotent.
              _os_update_seen):
        for gone in [k for k in m if k not in remote_ids]:
            m.pop(gone, None)
    for m in (_monitor_state["servers"], _server_full_alerted, _server_peak_notified,
              _expected_offline, _cron_restart_pending, _max_players_cache, _player_counts):
        for gone in [k for k in m if k not in server_ids]:
            m.pop(gone, None)
    with _rwe_lock:
        for gone in [k for k in _reboot_when_empty if k not in remote_ids]:
            _reboot_when_empty.pop(gone, None)


def _reboot_when_empty_watch(app):
    """Reboot each 'reboot when empty' host once it is reachable AND every game server on it reports
    0 players. Unreachable hosts are skipped (never rebooted on a guess), so a host that can't be
    queried just waits. Runs forever on a 60s tick; the registry is in-memory."""
    while True:
        time.sleep(60)
        with _rwe_lock:
            pending = list(_reboot_when_empty.keys())
        if not pending:
            continue
        with app.test_request_context():   # DB + log_action context for the background thread
            for rid in pending:
                try:
                    remote = RemoteServer.query.get(rid)
                    if not remote:
                        with _rwe_lock:
                            _reboot_when_empty.pop(rid, None)
                        continue
                    if not _host_reachable(remote):
                        continue   # can't reach it — don't reboot a host we can't confirm is idle
                    if _host_idle_state(remote) != "idle":
                        continue   # someone's connected, or a server's count is unknown — wait
                    with _rwe_lock:
                        info = _reboot_when_empty.pop(rid, None)
                    ok, msg = remote_reboot(remote)
                    log_action(None, "reboot_when_empty_fire", target=remote.name,
                               detail="host idle — %s" % msg, success=ok,
                               actor=(info or {}).get("by") or "system")
                    notifications.notify("auto_reboot", "Host auto-rebooted",
                                         "%s was empty of players, so its queued reboot ran." % remote.display_name)
                except Exception:
                    _log.debug("reboot-when-empty tick failed for remote %s", rid, exc_info=True)


_AUTOBLOCK_TAG = "panel-autoblock"


_AUTOBLOCK_DEFAULT_THRESHOLD = 20


def _autoblock_threshold():
    try:
        return max(1, min(int(load_config().get("autoblock_threshold", _AUTOBLOCK_DEFAULT_THRESHOLD)), 100000))
    except (TypeError, ValueError):
        return _AUTOBLOCK_DEFAULT_THRESHOLD


def _whitelist_networks():
    """The whitelist parsed into ip_network objects once (skipping any that no longer parse)."""
    nets = []
    # Reads the config directly rather than calling app.py's _security_whitelist(): that reader is
    # one of a trio with _security_whitelist_add/_remove, and importing it here would be circular
    # (app imports monitoring). Splitting the trio to avoid one line of duplication is the worse
    # trade — the key name is the contract, and it is asserted below.
    for entry in list(load_config().get("security_whitelist", []) or []):
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return nets


def _whitelisted(ip, nets=None):
    """True if `ip` is covered by any whitelist entry (an exact IP or a CIDR that contains it)."""
    import ipaddress
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return any(addr in n for n in (nets if nets is not None else _whitelist_networks()))


def _autoblock_reconcile(remote):
    """Make the host's 'panel-autoblock' UFW rules match the current offenders: block any IP whose
    failed-attempt count over the last 7 days is at/above the threshold and isn't already blocked (by
    us or manually), tailnet-exempt, or whitelisted; and release only our own auto-blocks that have
    since dropped below the threshold (or been whitelisted)."""
    threshold = _autoblock_threshold()
    if remote.is_local:
        top = so.fail2ban_top_ips(100, days=7)
        blocked = so.ufw_blocked_ips()
        def deny(ip):
            return so.ufw_deny_ip(ip, tag=_AUTOBLOCK_TAG)
        undeny = so.ufw_undeny_ip
    else:
        top = remote_fail2ban_top_ips(remote, 100, days=7)
        blocked = remote_ufw_blocked_ips(remote)
        def deny(ip):
            return remote_ufw_deny_ip(remote, ip, tag=_AUTOBLOCK_TAG)
        def undeny(ip):
            return remote_ufw_undeny_ip(remote, ip)
    qualify = {r["ip"] for r in top if r.get("ip") and (r.get("attempts") or 0) >= threshold}
    qualify -= tailnet_exempt_ips(remote, qualify)   # never auto-block your own tailnet (Tailscale up)
    _nets = _whitelist_networks()
    qualify = {ip for ip in qualify if not _whitelisted(ip, _nets)}   # never auto-block a whitelisted IP
    auto = {ip for ip, tag in blocked.items() if tag == _AUTOBLOCK_TAG}
    added = removed = 0
    for ip in qualify - set(blocked.keys()):   # over threshold, not blocked yet → auto-block
        deny(ip)
        added += 1
    for ip in auto - qualify:                   # our auto-block fell below threshold / got whitelisted → release
        undeny(ip)
        removed += 1
    return added, removed


def _server_max_config(gs):
    """Server capacity from the LinuxGSM config (maxplayers, else slots), cached — capacity is
    essentially static, so a successful read is kept for the panel's lifetime and reused. Readable
    even while the server is stopped (it's just a config file). None if unset/unreadable."""
    cached = _max_players_cache.get(gs.id)
    if cached is not None:
        return cached
    mx = None
    try:
        vals = lgsm_get_values(gs.remote, gs.short_name, gs.lgsm_name, ["maxplayers", "slots"])
        for key in ("maxplayers", "slots"):
            v = (vals.get(key) or "").strip()
            if v.isdecimal():
                mx = int(v)
                break
    except Exception:
        _log.debug("max-players: config read failed for %s", getattr(gs, "short_name", "?"), exc_info=True)
    if mx is not None:
        _max_players_cache[gs.id] = mx   # only cache a real value; retry next time on unknown
    return mx


def _server_slots(gs, allow_console=False):
    """(count, max, name) for one game server. The COUNT we can trust — gamedig first (which also
    yields max AND the server's advertised in-game name in the same query), then LinuxGSM's own
    NETWORK query; a stopped server is 0, and None means 'unknown' so the auto-reboot never fires on
    a game it can't see. The game CONSOLE (`status`) is used only when allow_console=True — every
    caller here is a background/timer poll, so this stays False and the panel never types into a
    game's console automatically (set a GSLT so gamedig can read the server instead). MAX is
    gamedig's reported capacity when it has one, otherwise the LinuxGSM config. NAME (the in-game
    hostname players see) only comes from gamedig; None from the other sources. Never raises."""
    # Primary: gamedig gives count, max AND the advertised name in a single query.
    try:
        cur, mx, gname = sm_player_slots(gs.remote, gs.short_name, gs.game_type, gs.port, gs.query_type)
    except Exception:
        cur, mx, gname = None, None, None
    if cur is not None:
        return cur, (mx if mx is not None else _server_max_config(gs)), gname
    try:
        if allow_console and sm_game_engine(gs.game_type):
            # Console backup — ONE `status` gives BOTH the count (a real 0 for a stopped/empty console
            # game) and the advertised name. Only on an explicit, on-demand request — NEVER on a poll.
            players, name = sm_console_status(gs.remote, gs.short_name, gs.game_type, selfname=gs.lgsm_name)
            return len(players or []), _server_max_config(gs), name
    except Exception:
        return None, _server_max_config(gs), None
    # Not in the panel's gamedig map and not a console engine — ask LinuxGSM's OWN query settings
    # (querytype/queryport), which cover games gamedig supports but the panel never mapped.
    try:
        lc = sm_player_count_via_lgsm_query(gs.remote, gs.short_name, gs.lgsm_name, fallback_port=gs.port)
    except Exception:
        lc = None
    if lc is not None:
        return lc, _server_max_config(gs), None
    # No gamedig type, no console engine, and LinuxGSM has no network query: a stopped server is
    # definitely empty; a running one we simply can't read, so report unknown (poller won't reboot).
    try:
        if sm_get_server_status(gs.remote, gs) == "offline":
            return 0, _server_max_config(gs), None
    except Exception:
        _log.debug("reboot-when-empty: status check failed for %s", getattr(gs, "short_name", "?"),
                   exc_info=True)
    return None, _server_max_config(gs), None


def _server_players_confident(gs):
    """The trustworthy player COUNT (int) for one server, or None. Thin wrapper over _server_slots
    for callers (the auto-reboot) that only need the count — behaviour is unchanged."""
    return _server_slots(gs)[0]

