"""The monitor loop and everything that feeds it.

That is: player counts, host probes, metric samples, LinuxGSM maintenance detection and autoblock
reconciliation. The reboot-when-empty wait moved to panel/services/host_reboot.py with the clean
reboot it now starts.

Lifted out of app.py, where these sat interleaved with route registration and the chat bots across
roughly a thousand lines. Nothing here is per-app: each function takes what it needs as an argument
or reads shared process state from panel_state, which is why the move needed no redesign.

A few of these are also called from route handlers (_cached_player_count, _autoblock_threshold,
_whitelisted, _host_reachable, _metrics_work). app.py imports them back. The dependency direction
is deliberate — routes may reach into monitoring; monitoring never reaches into routes.
"""
import concurrent.futures
import contextlib
import functools
import itertools
import logging
import os
import re
import shlex
import time

from panel.services import notifications
from panel.ops import system_ops as so
from panel.core.clock import utcnow
from panel.core.config import load_config
from panel.core.validation import ip_address_or_none, ip_network_or_none, unzoned_ip_or_network
from panel.db.models import (GameServer, HostSample, MetricSample, RemoteServer, db,
    row_label, rows_still_held)
from panel.core.panel_state import (
    _cron_restart_pending, _expected_offline, _host_reboots, _hr_lock, _max_players_cache,
    _monitor_state, _player_counts, _reboot_awaiting, _server_full_alerted, _server_peak_notified,
    forget_rows, keyed_state_with_locks, register_remote_state,
)
from panel.ops.ssh_manager import (
    _gamedig_type, _remote_listening_ports, game_idents_ok, game_map, host_live_metrics,
    is_local_server, lgsm_get_values, metrics_for_game,
    remote_fail2ban_attempt_counts,
    remote_ufw_blocked_ips, remote_ufw_deny_ip, remote_ufw_undeny_ip, run_command,
    run_privileged,
    server_live_metrics, tailnet_exempt_ips, ufw_lock,
    console_status as sm_console_status,
    game_engine as sm_game_engine,
    get_server_status as sm_get_server_status,
    player_count_via_lgsm_query as sm_player_count_via_lgsm_query,
    player_slots as sm_player_slots,
    player_slots_batch as sm_player_slots_batch,
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
    "_record_metric_samples",
    "_refresh_player_counts",
    "_whitelisted",
]


def _host_idle_state(remote):
    """Classify a host as 'idle', 'busy' or 'unknown': host_reboot.host_player_state, folded.

    The census every reboot path asks (panel/services/host_reboot.py) is the one predicate: a host
    mid-install, mid-backup or mid-update, or one that is not answering, folds into 'unknown' here,
    so nothing that reads this ever reboots into work in flight or on a guess.
    """
    from panel.services import host_reboot
    state = host_reboot.host_player_state(remote)["state"]
    return state if state in ("idle", "busy") else "unknown"


def _host_reachable(remote):
    """Whether a host answers a trivial command right now.

    run_command runs it locally for the panel host. Used to avoid rebooting a host we can't
    currently confirm is idle.

    Still a bare bool to every caller. WHY it failed is recorded beside it (_note_probe), for the
    debug report: a host key that changed and a box that is powered off were the same
    "unreachable" here, and so was every other cause.
    """
    try:
        out, err, rc = run_command(remote, "echo ok", timeout=10)
        ok = "ok" in (out or "")
    except Exception as exc:
        _note_probe(remote, False, _probe_exc_token(exc), None)
        return False
    _note_probe(remote, ok, None if ok else _probe_reply_token(remote, err, rc), rc)
    return ok


# ── The last probe of each host, for the debug report (R48) ───────────────────────────────────
# remote id -> {ok, token, rc, at, ok_at, fail_since, streak}. A FIXED-VOCABULARY token and the
# rc only, never the message or stderr: _connect_client's messages carry the host's address, and
# the report is meant for a public issue. Registered, so a deleted host's id is forgotten with its
# other state rather than handed to whatever host takes the id next. Written from the monitor's
# pool threads as one whole-dict assignment: a lost write under a race costs one stale reading.
_probe_record = register_remote_state({})

# stderr markers of the non-raising transports (tailscale's ssh CLI, local); first match wins.
_PROBE_ERR_TOKENS = (
    ("host key verification failed", "host_key_changed"),
    ("remote host identification has changed", "host_key_changed"),
    ("permission denied", "auth_failed"),
    ("could not resolve hostname", "dns"),
    ("name or service not known", "dns"),
    ("temporary failure in name resolution", "dns"),
    ("connection refused", "refused"),
    ("no route to host", "no_route"),
    ("timed out", "timeout"),
    ("invalid ssh login or host", "ssh_destination_refused"),
)
# The messages _connect_client and its helpers raise ConnectionError with, by their fixed wording.
_PROBE_EXC_TOKENS = (
    ("authentication failed", "auth_failed"),
    ("timed out", "timeout"),
    ("cannot resolve hostname", "dns"),
    ("no usable ssh password", "credential_unreadable"),
    ("connection refused", "refused"),
    ("errno 111", "refused"),
    ("no route to host", "no_route"),
)
# sudo refusing for want of a password, classic sudo's and sudo-rs's wording alike.
_SUDO_PROMPT_RE = re.compile(
    r"(?mi)^\s*sudo:\s*(?:a password is required|a terminal is required|no tty present"
    r"|sorry, you must have a tty|interactive authentication is required)")


def _first_marker(text, table):
    """The token of the first marker of `table` found in `text` (case-insensitively), or None."""
    low = (text or "").lower()
    for marker, token in table:
        if marker in low:
            return token
    return None


def _probe_exc_token(exc):
    """A fixed token for a probe that RAISED: 'other:<Class>' for anything unrecognised."""
    try:
        name = type(exc).__name__
        if name == "HostKeyMismatch":
            return ("host_key_unreadable" if "cannot be decrypted" in str(exc)
                    else "host_key_changed")
        if isinstance(exc, TimeoutError):
            return "timeout"
        return _first_marker(str(exc), _PROBE_EXC_TOKENS) or "other:" + name
    except Exception:  # noqa: BLE001 - a classifier must never be what fails the probe
        return "other:unclassified"


def _probe_transport(remote):
    """'local', 'ssh_cli' (tailscale) or 'ssh' (paramiko): run_command's own predicates."""
    if getattr(remote, "is_local", False) or getattr(remote, "auth_method", None) == "local":
        return "local"
    return "ssh_cli" if getattr(remote, "auth_method", None) == "tailscale" else "ssh"


def _probe_reply_token(remote, err, rc):
    """A fixed token for a probe that ANSWERED without 'ok' (how the non-raising transports fail)."""
    try:
        if _SUDO_PROMPT_RE.search(err or ""):
            return "sudo_password_required"
        token = _first_marker(err, _PROBE_ERR_TOKENS)
        if token:
            return token
        if rc == 0:
            return "empty_output_rc0"
        rc_txt = str(rc) if isinstance(rc, int) else "?"
        return "%s_rc%s" % (_probe_transport(remote), rc_txt)
    except Exception:  # noqa: BLE001
        return "other:unclassified"


def _note_probe(remote, ok, token, rc):
    """Record one probe of `remote` in _probe_record. Never raises."""
    try:
        rid = getattr(remote, "id", None)
        if not isinstance(rid, int):
            return
        now = time.time()
        prev = _probe_record.get(rid)
        prev = prev if isinstance(prev, dict) else {}
        _probe_record[rid] = {
            "ok": bool(ok), "token": token, "at": now,
            "rc": rc if isinstance(rc, int) else None,
            "ok_at": now if ok else prev.get("ok_at"),
            "fail_since": None if ok else (prev.get("fail_since") or now),
            "streak": 0 if ok else int(prev.get("streak") or 0) + 1}
    except Exception:  # noqa: BLE001 - instrumentation must never raise into the monitor
        return


_PLAYER_POLL_SECONDS = 45


_PEAK_NOTIFY_INTERVAL = 3600  # at most one "new record" alert per server per hour


def _cached_player_count(server_id):
    """Last known player count for a server (int, incl. 0), or None when unknown / not polled yet."""
    entry = _player_counts.get(server_id)
    return entry["count"] if entry else None


_PLAYER_POLL_WORKERS = 8   # cap on concurrent per-server queries (SSH/gamedig) in one poll pass


def _query_server_slots(gs, primary=None):
    """Worker for the parallel poll: (id, (count, max, name)) for one server.

    Takes the ALREADY-LOADED row rather than an id, and opens no app context of its own. It used to
    do both, which meant it held a database connection for the whole gamedig/SSH round trip — up to
    the query timeout. With 8 workers that pinned 9 of the pool's 15 connections (SQLAlchemy's
    default 5 + 10 overflow) for as long as one slow host took to answer, and every web request in
    that window queued behind them.

    Reads only loaded columns plus the joinedloaded host, so nothing lazy-loads on a pool thread.
    Never raises.

    `primary` is this server's answer from its host's batched gamedig query, when there was one
    (see _batched_slots): the per-server gamedig run is then not repeated, and a target the batch
    could not read goes on down the same fallbacks a failed per-server query takes.
    """
    try:
        if gs.status == "offline":
            return gs.id, (0, _server_max_config(gs), None)
        if primary is None:
            return gs.id, tuple(_server_slots(gs))
        return gs.id, tuple(_server_slots(gs, primary=primary))
    except Exception:
        return gs.id, (None, None, None)


def _panel_identities(remote):
    """Accounts on `remote` that are more than a game account: the panel's own, or its SSH login.

    A batched player query runs every server's gamedig as ONE account, so it must be a game
    account and never one of these: gamedig parses replies anyone can spoof, and the panel's own
    account is root-capable on a per-user install (and the SSH login is the identity the panel
    escalates with on a remote).
    """
    if is_local_server(remote):
        try:
            import pwd
            return {pwd.getpwuid(os.getuid()).pw_name}
        except (ImportError, KeyError, AttributeError):
            return None          # cannot tell which account is ours: batch nothing
    login = (getattr(remote, "username", None) or "").strip()
    return {login, "root"} if login else None


def _batch_account(remote, rows):
    """The game account a host's batched player query runs as, or None to query per server.

    The first of the host's own game accounts (by server id) that is a plain account name and is
    neither the panel's account nor its SSH login. None when there is no such account — the host
    then keeps one query per server, each as its own account, exactly as before.
    """
    avoid = _panel_identities(remote)
    if avoid is None:
        return None
    local = is_local_server(remote)
    for gs in sorted(rows, key=lambda g: g.id):
        if gs.short_name in avoid or not game_idents_ok(gs.short_name):
            continue
        if local and _admin_account(gs.short_name):
            continue
        return gs.short_name
    return None


# The groups that make an account an administrator: sudo (admin on old Ubuntu releases, wheel
# elsewhere), and the groups that are root by another door — lxd/lxc and incus-admin start a
# privileged container with the host's / mounted, docker and libvirt do the same with a container or
# a VM, and disk writes the root filesystem's block device directly.
_ADMIN_GROUPS = frozenset(("admin", "root", "sudo", "wheel", "lxd", "lxc", "incus-admin", "docker",
                           "libvirt", "disk"))


def _admin_account(user):
    """Whether `user` on this host is in an administrator group, or that could not be read.

    An imported server can run as a human's own sudo-capable account. That server's own query
    already runs as it; a batch must not make every other server's query run as it too.
    """
    try:
        import grp
        import pwd
        gid = pwd.getpwnam(user).pw_gid
        names = {grp.getgrgid(g).gr_name for g in os.getgrouplist(user, gid)}
    except (ImportError, KeyError, OSError, AttributeError):
        return True              # cannot tell: do not run anyone else's query as it
    return bool(names & _ADMIN_GROUPS)


def _batchable(gs):
    """Whether one server can join its host's batched gamedig query this pass."""
    return (gs.status != "offline" and gs.remote is not None
            and game_idents_ok(gs.short_name) and bool(gs.port)
            and bool(_gamedig_type(gs.game_type, gs.query_type)))


# A host whose batch did not run (its account refused by sudo, say — an imported server outside the
# panel's game group) is polled per server, as before, for this long before the batch is tried
# again. Without it, every pass there paid a failed batch on top of the per-server queries.
_BATCH_RETRY_SECONDS = 600
_batch_failed_at = register_remote_state({})   # remote_id -> time.time() of the last failed batch


def _query_host_slots(work):
    """Worker: one batched gamedig query for one host's servers: {server id: (count, max, name)}.

    {} when the batch could not run, so every one of them is queried on its own. Never raises.
    """
    remote, rows = work
    rid = getattr(remote, "id", None)
    if time.time() - _batch_failed_at.get(rid, float("-inf")) < _BATCH_RETRY_SECONDS:
        return {}
    try:
        acct = _batch_account(remote, rows)
        if acct is None:
            return {}
        got = sm_player_slots_batch(remote, acct, [(gs.id, gs.game_type, gs.port, gs.query_type)
                                                   for gs in rows])
    except Exception:
        _log.debug("batched player query failed for %s", row_label(remote, "name"), exc_info=True)
        got = None
    if got is None:
        _batch_failed_at[rid] = time.time()
        return {}
    _batch_failed_at.pop(rid, None)
    return got


def _batched_slots(servers):
    """{server id: gamedig's (count, max, name)} from ONE query per host that has two or more.

    Every player poll ran one `sudo -u <account> gamedig` per server — three journal lines each,
    every 45 s, the largest single source of the panel's privileged calls. gamedig reads no file,
    so one game account can query all of a host's games in one command. A host with one server,
    or with no account it may use (_batch_account), is left out and queried per server as before.
    """
    by_host = {}
    for gs in servers:
        if _batchable(gs):
            by_host.setdefault(gs.remote_id, []).append(gs)
    work = [(rows[0].remote, rows) for rows in by_host.values() if len(rows) >= 2]
    if not work:
        return {}
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(_PLAYER_POLL_WORKERS, len(work))) as ex:
        for got in ex.map(_query_host_slots, work):
            out.update(got)
    return out


def _metrics_work(servers):
    """Freeze what the metrics workers need, read in the CALLER's thread.

    Each worker used to open an app context of its own and re-fetch the server plus lazy-load its
    host — two queries per server on an endpoint the dashboard polls every few seconds, so 500
    servers meant ~1000 queries per poll. The rows are already loaded here (get_user_servers
    joinedloads the host), so read them once and hand the workers plain values.
    """
    return [(gs.remote, gs.id, gs.short_name, gs.port, gs.game_type, gs.query_type, gs.remote_id)
            for gs in servers if gs.installed]


def _host_metrics_work(servers):
    """Group the installed servers by HOST: [(remote, [(sid, short_name, port, game_type, query_type)])].

    The rows are read HERE, in the caller's thread, for the same reason _metrics_work does it — a
    worker that touches the ORM needs a session of its own, which costs a query per server on an
    endpoint the dashboard polls.
    """
    by_host = {}
    for gs in servers:
        if not gs.installed or gs.remote is None:
            continue
        by_host.setdefault(gs.remote_id, (gs.remote, []))[1].append(
            (gs.id, gs.short_name, gs.port, gs.game_type, gs.query_type))
    return list(by_host.values())


def _query_host_metrics(work, want_map=True):
    """Worker: sample ONE host once, and slice it per game. [(sid, metrics|None, remote_id, map)].

    One round trip per host instead of one per game. The host figures each game's row carries are
    identical by definition — they describe the machine — so fetching them once per game was work
    the panel did N times to learn the same thing. Measured against an 80ms link this was the whole
    cost of /api/dashboard/metrics: ceil(servers / 8) x latency, 1.05s at 100 servers, every 10
    seconds per open dashboard, with a 2s cache that a 10s poll can never hit. Never raises.

    `want_map=False` leaves every map "" and asks for none. The history sampler passes it: it
    stores no map, and asking cost one `sudo -u <account> gamedig` per running server per minute
    (about 30% of the privileged calls on a three-server host) for an answer it threw away.
    """
    remote, games = work
    try:
        sample = host_live_metrics(remote)
    except Exception:
        return [(sid, None, getattr(remote, "id", None), "") for sid, _s, _p, _g, _q in games]
    # The same ram_total sentinel the sampler below already applies, and for the same reason —
    # this guarded only the RAISING transport. host_live_metrics builds its answer up front
    # ({"cpu_percent": 0.0, "ram_total": 0, ...}), runs one command whose rc it discards, and
    # returns that dict unchanged when the output is empty. Only paramiko raises; the tailscale
    # and local transports return ("", "...timed out", -1), so on the transport the panel steers
    # people towards a failed read arrived here as a fully populated, TRUTHY dict of zeros.
    #
    # /api/dashboard/metrics then passed it through its own `if not m` and wrote
    # reachable/probed/metrics True with cpu 0, ram 0, disk 0 — so a host that was actually
    # unreachable (or at 95% disk) rendered as "Reachable · CPU 0% · RAM 0% · Disk 0%". None is
    # the answer the route already knows how to show, because it is what the raising path gives.
    if not (sample.get("host") or {}).get("ram_total"):
        return [(sid, None, getattr(remote, "id", None), "") for sid, _s, _p, _g, _q in games]
    out = []
    for sid, short_name, port, game_type, query_type in games:
        m = metrics_for_game(sample, short_name, port)
        mp = ""
        if want_map and m.get("game_procs"):     # only query the map for a running server
            try:
                mp = game_map(remote, short_name, game_type, port, query_type)
            except Exception:
                mp = ""
        out.append((sid, m, getattr(remote, "id", None), mp))
    return out


def _query_server_metrics(work):
    """Worker for the dashboard metrics poll: (sid, metrics_dict|None, remote_id, map) for one server.

    server_live_metrics is one cached SSH round trip that yields BOTH the whole host's figures and
    this game's share. Takes the frozen tuple from _metrics_work rather than an id: it runs on a
    pool thread, where a session of its own costs a query per server and sharing the caller's would
    not be thread-safe. Reads only already-loaded columns. Never raises.
    """
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

    The per-server queries (gamedig / console over SSH — the slow part) run in a small thread pool
    so a pass doesn't grow linearly with the server count; the cache update + notifications then run
    single-threaded here (all DB writes stay in this one context). An offline server is 0 players
    without a query; a running one the panel can't read stays None.
    """
    with app.app_context():
        from sqlalchemy.orm import joinedload
        # joinedload: the workers read gs.remote, and lazily that is both a query per server AND a
        # lazy load fired from a pool thread against this context's session.
        servers = [gs for gs in GameServer.query.options(joinedload(GameServer.remote))
                   .filter_by(installed=True).all()
                   if gs.status not in ("installing", "configuring")]
        if not servers:
            return
        # One gamedig query per host first, then every server through its own chain, with the
        # batch's answer standing in for its first step. All concurrent (bounded); the results are
        # applied serially below.
        primaries = _batched_slots(servers)

        def _one(gs):
            if gs.id in primaries:
                return _query_server_slots(gs, primaries[gs.id])
            return _query_server_slots(gs)
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(_PLAYER_POLL_WORKERS, len(servers))) as ex:
            for sid, slots in ex.map(_one, servers):
                results[sid] = slots
        # Only the servers that are still the rows the queries were for: one deleted meanwhile,
        # its id taken, would hand the new server the old one's count and in-game name.
        for gs in rows_still_held(servers):
            count, mx, gname = results.get(gs.id, (None, None, None))
            _apply_player_count(gs, count, mx, gname)


def _apply_player_count(gs, count, mx, gname):
    """Write one server's polled (count, max, name) to the cache and fire its player alerts.

    Runs serially in the poller's app context, in the order the alerts have always run: the
    one-shot "notify when empty", then "server full", then "new player record".
    """
    # Keep the last-known in-game name when this pass didn't get one (e.g. the server is
    # stopped or momentarily unqueryable) rather than blanking it in the UI.
    prev_name = (_player_counts.get(gs.id) or {}).get("name")
    _player_counts[gs.id] = {"count": count, "max": mx,
                             "name": gname or prev_name, "ts": time.time()}
    _notify_if_emptied(gs, count)
    _track_server_full(gs, count, mx)
    _track_player_peak(gs, count)


def _notify_if_emptied(gs, count):
    """Fire a server's one-shot "notify when empty" on a CONFIRMED 0 players, then disarm it."""
    # One-shot "notify when empty": fire once on a CONFIRMED 0 (never on an unknown count),
    # then clear the flag so it doesn't ping every time the server empties.
    # A muting tag skips the whole block, flag included: the request stays ARMED, so it
    # fires the next time the server empties after the tag comes off — rather than being
    # silently consumed while nobody could be told.
    # A server its host's reboot plan stopped reads 0 too, and that is not "the players left": the
    # flag stays armed for the real moment, after the server is back.
    if (gs.notify_when_empty and count == 0 and not gs.reboot_restore
            and not notifications.alerts_muted(gs)):
        # DISARM FIRST, then send — the order the peak block below already uses.
        # notifications.notify never raises (it dispatches on a thread of its own), so the
        # only statement the except could ever catch was the commit; and when it did catch
        # it, the alert had already gone out while the flag stayed armed in the database.
        # This panel writes to one SQLite file from four places at once, so a "database is
        # locked" here is ordinary, and the 45s poller then re-sent the "one-shot" every
        # 45 seconds until a commit landed. Worst case now is one lost alert.
        try:
            gs.notify_when_empty = False
            db.session.commit()
        except Exception:
            db.session.rollback()
            _log.debug("notify-when-empty failed for %s", getattr(gs, "short_name", "?"), exc_info=True)
        else:
            notifications.notify("server_empty", "Server is empty",
                                 "%s on %s now has 0 players — safe to make changes."
                                 % (gs.name, gs.remote.display_name))


def _track_server_full(gs, count, mx):
    """Alert on a server's transition INTO full, and re-arm once it drops below the cap."""
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


def _track_player_peak(gs, count):
    """Record a new player-count peak, and announce it at most once an hour."""
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


def _sample_rows(sampled, now, server_ids, remote_ids):
    """The MetricSample/HostSample rows for one pass's samples, for the rows still in the ids given."""
    rows, hosts_seen = [], set()
    for sid, m, rid, _mp in sampled:
        # ram_total is the sentinel app.py's _live_run_state already uses: `free -b` never
        # fails on a reachable host, so a zero there means the read did not happen. The
        # metrics readers build their dict UP FRONT and return it all-zero when the SSH
        # read produces no output — truthy, so `if not m` passed it through and every blip
        # wrote a 0% CPU / 0 MB sample per game and a 0/0/0 host sample. The trend charts
        # then showed dips that never happened, and a host at 95% disk recorded 0%. Kept
        # after the switch to the batched worker, which applies the same sentinel itself.
        if not m or not m.get("ram_total") or sid not in server_ids:
            continue
        rows.append(_metric_sample_row(sid, now, m))
        if rid is not None and rid in remote_ids and rid not in hosts_seen:
            hosts_seen.add(rid)
            rows.append(_host_sample_row(rid, now, m))
    return rows


def _record_metric_samples(app):
    """One pass: snapshot game and host usage into MetricSample/HostSample for the history charts.

    Every installed server's game CPU%/RAM (+ the cached player count) and each host's whole-VPS
    CPU%/RAM%/disk%. Reuses the parallel metrics worker; the player count comes from the cache the
    player poller already keeps.
    """
    with app.app_context():
        # joinedload: the workers need each server's host, and lazily that is one query per server.
        from sqlalchemy.orm import joinedload
        # Grouped by HOST, like /api/dashboard/metrics already is. This built _metrics_work and
        # mapped _query_server_metrics over it — one SSH round trip PER SERVER, each carrying the
        # 0.25s sampling sleep, every 60s forever, to fetch whole-machine figures that are
        # identical by definition and of which this pass writes exactly one HostSample per host
        # anyway. 100 servers on 5 hosts opened 100 executions where 5 answer the same rows, in
        # background threads competing with the console and the web requests for the same SSH
        # connections. The tuple shape is identical, so the body below is unchanged — and the
        # sampler now shares host_live_metrics' short cache with an open dashboard instead of
        # each keeping its own.
        servers = (GameServer.query.options(joinedload(GameServer.remote))
                   .filter_by(installed=True).all())
        work = _host_metrics_work(servers)
        if not work:
            return
        now = utcnow()
        # want_map=False: MetricSample and HostSample have no map column, so the map lookup the
        # dashboard needs was a sudo'd gamedig run per running server per pass, thrown away.
        sample_host = functools.partial(_query_host_metrics, want_map=False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(_PLAYER_POLL_WORKERS, len(work))) as ex:
            sampled = list(itertools.chain.from_iterable(ex.map(sample_host, work)))
        # A sample is history kept for 14 days under the row's id, so only rows that are still the
        # ones sampled get one: a server or host deleted during the pass, its id taken, would
        # start its successor's charts with the deleted one's figures.
        live = rows_still_held(servers)
        rows = _sample_rows(sampled, now, {gs.id for gs in live},
                            {r.id for r in rows_still_held({gs.remote for gs in live
                                                            if gs.remote is not None})})
        if rows:
            db.session.add_all(rows)
            db.session.commit()


def _metric_sample_row(sid, now, m):
    """The MetricSample for one game server: its CPU%/RAM from `m` plus the cached player count."""
    return MetricSample(server_id=sid, ts=now,
                        cpu=round(m.get("game_cpu_percent") or 0, 1),
                        ram_mb=int(m.get("game_ram_mb") or 0),
                        players=_cached_player_count(sid))


def _host_sample_row(rid, now, m):
    """The HostSample for one host: whole-VPS CPU%/RAM%/disk% from `m` (0 where a total is 0)."""
    rt, dt = m.get("ram_total") or 0, m.get("disk_total") or 0
    return HostSample(remote_id=rid, ts=now,
                      cpu=round(m.get("cpu_percent") or 0, 1),
                      ram_pct=round(100.0 * (m.get("ram_used") or 0) / rt, 1) if rt else 0,
                      disk_pct=round(100.0 * (m.get("disk_used") or 0) / dt, 1) if dt else 0)


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
    the port is legitimately closed.

    Only runs when a server has just been seen DOWN and the panel did not stop it itself, so it
    costs nothing in the normal case.

    Fails to False on any error — a probe that cannot answer must not hide a real outage.
    """
    try:
        user = (gs.short_name or "").strip()
        # lgsm_name is derived ("{game_type}server"), so it is falsy only when game_type is — and it
        # degrades to a bare "server", which would match ANY *server maintenance this user is running.
        selfname = (gs.lgsm_name or "").strip() if (gs.game_type or "").strip() else ""
        # Both names go into a pgrep ERE, and nothing has checked them since they were ASSIGNED: a
        # row loaded from an older database, a hand edit or a restore can carry `x|.*`, which makes
        # every maintenance process on the host this server's — BUSY for ever, so its offline
        # alerts are muted for good. game_idents_ok is the rule every command builder applies.
        if not user or not selfname or not game_idents_ok(user, selfname):
            return False
        # pgrep -f takes an ERE. With the names checked above, "." is the one metacharacter that
        # can reach here; make it literal so it can't match a neighbouring name.
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
        # row_label, not getattr: a server another row took the id of raises from this read too.
        _log.debug("maintenance probe failed for %s", row_label(gs, "name"), exc_info=True)
        return False


_DIGIT_RUN_RE = re.compile(r"\d+")


def _first_percent(text):
    r"""Return the number in front of the first '%' that has digits before it, or None.

    What `re.search(r"(\d+)%", text)` found. That search restarted `\d+` at every digit of a
    run with no '%' after it and walked the rest of the run each time: quadratic in the run. Each
    run is read once here, and the first one a '%' follows is the one the search stopped at.
    """
    text = text or ""
    for run in _DIGIT_RUN_RE.finditer(text):
        if text.startswith("%", run.end()):
            return int(run.group())
    return None


def _host_disk_pct(remote):
    """Root-filesystem usage percent for a host (int), or None. Cheap df, best-effort."""
    try:
        out, _, _ = run_command(remote, "df -P / | awk 'NR==2{print $5}'", timeout=10)
        return _first_percent(out)
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
    """Game users on `remote` with a pending ~/.restart-pending flag, or None if we could not look.

    None matters. This was `ls -1d /home/*/.restart-pending … || true` sent with no `sudo=`, so on
    the panel's own host it went out as `sudo bash -c`, and the narrow grant refuses that. Even
    unprivileged it could not work: the final path component is literal, so the shell STATS each
    candidate, which needs search permission on a 0750 home. Every stat was EACCES, the glob
    matched nothing, `|| true` threw the rc away, and the caller got an empty set — a confident
    "nothing pending" from a read that never happened.

    A verb now, and it reports failure: rc != 0 is None, not set(). See
    tools/panel-helper:do_restart_flags.
    """
    try:
        out, _, rc = run_privileged(remote, "restart-flags", [], timeout=10, merge_stderr=False)
    except Exception:
        _log.debug("restart flags: probe failed", exc_info=True)
        return None
    if rc != 0:
        return None
    names = set()
    for ln in (out or "").splitlines():
        ln = ln.strip()
        if ln.startswith("/home/"):          # the remote rendering prints whole paths
            parts = ln.split("/")
            if len(parts) > 2:
                names.add(parts[2])
        elif ln:                             # the helper prints bare user names
            names.add(ln)
    return names


def _probe_host(remote, read_flags=True):
    """Every network probe for one host, gathered off the database.

    Runs on a pool thread, so it touches no session and reads only already-loaded columns of
    `remote`; a slow host costs latency, never a pooled connection. Returns (remote_id, dict) and
    never raises — each probe already degrades to None/False on its own.

    `read_flags=False` skips the restart-flags read ("restart_flagged": None, which _monitor_server
    reads as "did not look" and leaves the banner as it was); so does a port scan that failed,
    because then no server of the host is judged and the answer was always discarded.
    """
    try:
        if not _host_reachable(remote):
            return remote.id, {"reachable": False}
        try:
            ports = _remote_listening_ports(remote)
        except Exception:
            ports = None
        flags = _host_restart_flags(remote) if read_flags and ports is not None else None
        return remote.id, {"reachable": True, "disk": _host_disk_pct(remote),
                           "load_mem": _host_load_mem(remote), "ports": ports,
                           "restart_flagged": flags}
    except Exception:
        _log.debug("host probe failed for %s", getattr(remote, "name", "?"), exc_info=True)
        return remote.id, {"reachable": False}


# The restart-flags read is a privileged call (a helper verb on the panel's host, `sudo` over SSH on
# a remote) that the monitor made for every host on every 60 s sweep — about 60 an hour per host,
# three journal lines each — to feed one display-only banner. Only a daily-restart cron line writes
# the flag. So a host is read when one of its servers has daily restart on, or still shows the
# banner (so it clears once the flag goes), and otherwise every _RESTART_FLAGS_REFRESH seconds:
# that bounded re-read is what catches a cron the column does not know about (an imported server
# keeps its old crontab with the column False until Scheduled Tasks is opened, and a crontab
# edited in the terminal says nothing to the panel). A host with no installed server is never read:
# its answer had nothing to apply to.
_RESTART_FLAGS_REFRESH = 600
_restart_flags_read_at = register_remote_state({})   # remote_id -> time.time() of the last read


def _restart_flag_hosts(rows):
    """The host ids whose restart flags this sweep reads, from (server id, host id, daily_restart)."""
    by_host = {}
    for sid, rid, daily in rows:
        by_host.setdefault(rid, []).append((sid, daily))
    now = time.time()
    want = set()
    for rid, servers in by_host.items():
        due = now - _restart_flags_read_at.get(rid, float("-inf")) >= _RESTART_FLAGS_REFRESH
        if due or any(daily or _cron_restart_pending.get(sid) for sid, daily in servers):
            want.add(rid)
    return want


def _monitor_pass():
    """One monitoring sweep: fire notifications on host-reachability, disk and server transitions.

    Transitions (host up/down, disk, load, server up/down) are against the previous pass. First
    pass only records a baseline (so nothing alerts on startup). Never raises out.

    The network probes run concurrently; everything that touches the database, the recorded state or
    a notification stays serial in this thread, so ordering and the alert logic are unchanged.
    """
    remotes = RemoteServer.query.all()
    # BEFORE the early return, not after. The prune used to be the last statement in this
    # function, which made it unreachable in the one case where it has the most to forget: delete
    # every host and `remotes` is empty, so the sweep returns here and every registered map keeps
    # its entries for the life of the process. Add a host back — it takes id 1 again, SQLite
    # having no other rows to count from — and it inherits all of them. The prune needs no host to
    # run against; it is driven by the LIVE id sets, and empty ones are a perfectly good answer.
    _forget_deleted_rows({r.id for r in remotes},
                         {row[0] for row in db.session.query(GameServer.id).all()})
    if not remotes:
        return
    # Which hosts' restart flags to read is decided HERE, in this thread: the probes run on pool
    # threads, which must not touch the session.
    flag_hosts = _restart_flag_hosts(
        db.session.query(GameServer.id, GameServer.remote_id, GameServer.daily_restart)
        .filter_by(installed=True).all())
    probes = _probe_hosts(remotes, flag_hosts)
    _stamp_flag_reads(probes, flag_hosts)
    # The probes take seconds per host. A host deleted meanwhile, its id taken, is not judged on
    # the old host's probe: its successor's servers were checked against the OLD machine's port
    # scan and alerted on, and the old host's reachability was recorded as the new one's.
    remotes = rows_still_held(remotes)
    _th = notifications.get_thresholds()   # user-configurable disk_pct / load_pct; once per sweep
    # Every installed server for every host, in ONE query, grouped by host. The per-host fetch used
    # to sit inside the loop below, so the monitor's query count grew with the number of hosts —
    # once a minute, forever. The route budgets in smoke_test cover the PAGES, not this sweep, so
    # nothing was watching it.
    _by_remote = {}
    for _gs in GameServer.query.filter_by(installed=True).all():
        _by_remote.setdefault(_gs.remote_id, []).append(_gs)
    status_changed = False
    for remote in remotes:
        probe = probes.get(remote.id) or {"reachable": False}
        if _monitor_host(remote, probe, _th, _by_remote.get(remote.id, ())):
            status_changed = True
    if status_changed:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            _log.debug("monitor: persisting server status failed", exc_info=True)


def _probe_hosts(remotes, flag_hosts=None):
    """Run _probe_host for every host concurrently (bounded): {remote_id: probe dict}.

    `flag_hosts` is the set of host ids whose restart flags are read this sweep; None reads all.
    """
    def _one(remote):
        if flag_hosts is None:
            return _probe_host(remote)
        return _probe_host(remote, read_flags=remote.id in flag_hosts)
    probes = {}
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(_MONITOR_HOST_WORKERS, len(remotes))) as ex:
        for rid, data in ex.map(_one, remotes):
            probes[rid] = data
    return probes


def _stamp_flag_reads(probes, flag_hosts):
    """Record when each host's restart flags were last READ — a read that failed is not stamped."""
    now = time.time()
    for rid in flag_hosts:
        if (probes.get(rid) or {}).get("restart_flagged") is not None:
            _restart_flags_read_at[rid] = now


def _monitor_host(remote, probe, th, servers):
    """Apply one host's probe: reachability, disk, load, then each of its game servers.

    Returns True when a host or server status column changed and the sweep has to commit.
    """
    reachable = probe["reachable"]
    status_changed = _record_host_reachability(remote, reachable)
    if not reachable:
        return status_changed
    _check_host_disk(remote, probe["disk"], th)
    _check_host_load(remote, probe["load_mem"], th)
    ports = probe["ports"]
    if ports is None:
        return status_changed
    for gs in servers:
        if _monitor_server(remote, gs, probe, ports):
            status_changed = True
    return status_changed


# How many sweeps in a row a host must fail to answer, or a server's port stay shut, before it is
# DECLARED down and alerted on. It was one: a single `echo ok` that timed out — a busy box, a
# dropped packet, sshd reloading — paged "Host unreachable", then "Host back online" a minute
# later; a host whose link flapped alerted on every other sweep; and a game whose port scan
# missed it once reported "went offline unexpectedly" followed by "back online". Two sweeps is a
# minute of real outage before anyone is told, which is the trade a pager should make.
#
# Only the ALERT and the recorded transition state wait. The columns (is_online, gs.status) still
# say what the last probe measured: they are what the dashboard and the bots show, and a probe
# that failed is a fact about right now. What does not happen any more is a transition the
# operator is told about and then told the reverse of a minute later.
_DOWN_CONFIRM_SWEEPS = 2


def _record_host_reachability(remote, reachable):
    """Alert on a host going down or coming back, and record it; True if is_online changed.

    Down is declared only after _DOWN_CONFIRM_SWEEPS failed probes in a row; until then the host
    stays recorded as up, so a blip that clears is neither "unreachable" nor "back online".
    """
    prev = _monitor_state["remotes"].get(remote.id)
    misses = _monitor_state["remote_misses"]
    recorded = reachable
    # A reboot the panel made: the outage is recorded as usual, and the panel's own host_reboot
    # summary says when it is back — so neither page is sent about it.
    muted = _reboot_alerts_muted(remote.id)
    if reachable or prev is not True:
        misses.pop(remote.id, None)
    else:
        misses[remote.id] = misses.get(remote.id, 0) + 1
        if misses[remote.id] < _DOWN_CONFIRM_SWEEPS:
            recorded = True                  # not declared yet: one more sweep to be sure
        else:
            misses.pop(remote.id, None)
            if not muted:
                notifications.notify("remote_unreachable", "Host unreachable",
                                     "%s stopped responding." % remote.display_name)
    if prev is False and reachable and not muted:
        notifications.notify("remote_recovered", "Host back online",
                             "%s is responding again." % remote.display_name)
    _monitor_state["remotes"][remote.id] = recorded
    # ...and to the COLUMN, not just this pass's memory. is_online was written in exactly three
    # places — host creation (hardcoded True), the manual "Test connection" button, and a
    # successful bootstrap — so a host that went down stayed green forever and one whose single
    # manual test failed stayed red forever after it recovered. The dashboard badge, the host
    # cards and the bots' /hosts all branch on this column first (host_probed only separates
    # "not checked yet"), so every one of them repeated the stale answer. This is the same fix
    # the game-server status column already got in _monitor_server, for the same reason.
    if remote.is_online != reachable:
        remote.is_online = reachable
        return True
    return False


# After the panel sees a host it rebooted come back, this long before its reachability alerts are
# its own again: the monitor's sweep that notices it is back runs up to a minute later.
_REBOOT_BACK_GRACE = 300
# A host with no plan rows (nothing was running) is muted this long after the reboot was sent.
_REBOOT_BARE_MUTE = 900


def _reboot_alerts_muted(remote_id, now=None):
    """Whether a host's unreachable/recovered alerts are held because the panel rebooted it."""
    now = time.time() if now is None else now
    ent = _reboot_awaiting.get(remote_id)
    if ent:
        back = ent.get("back")
        return back is None or now - back < _REBOOT_BACK_GRACE
    with _hr_lock:
        job = _host_reboots.get(remote_id)
        sent = job.get("sent") if job else None
    return bool(sent) and now - sent < _REBOOT_BARE_MUTE


def _check_host_disk(remote, pct, th):
    """Alert once when a host's disk crosses the threshold; re-arm 5 points below it."""
    if pct is not None:
        alerted = _monitor_state["disk"].get(remote.id, False)
        if pct >= th["disk_pct"] and not alerted:
            notifications.notify("disk_low", "Disk running low",
                                 "%s is at %d%% disk usage." % (remote.display_name, pct))
            _monitor_state["disk"][remote.id] = True
        elif pct < th["disk_pct"] - 5 and alerted:
            _monitor_state["disk"][remote.id] = False


def _check_host_load(remote, load_mem, th):
    """Alert once on SUSTAINED high CPU load or memory on a host; re-arm 10 points below."""
    # High CPU/memory — only when SUSTAINED for the configured window (load_mins), so a brief spike
    # on a small box doesn't page you; re-arm once it drops well below. CPU-load (a per-core loadavg
    # %, which can exceed 100) and memory each have their own threshold.
    loadpct, mempct = load_mem
    st = _monitor_state["load"].setdefault(remote.id, {})
    need = max(1, round(th["load_mins"] * 60 / _MONITOR_SECONDS))   # monitor passes over the line
    for kind, val, thresh, label in (("cpu", loadpct, th["load_pct"], "CPU load"),
                                     ("mem", mempct, th["mem_pct"], "memory")):
        if val is None:
            continue
        st[kind + "_hi"] = (st.get(kind + "_hi", 0) + 1) if val >= thresh else 0
        if st[kind + "_hi"] >= need and not st.get(kind + "_alerted"):
            notifications.notify("high_load", "Host under load",
                                 "%s is at %d%% %s (sustained %d+ min)."
                                 % (remote.display_name, val, label, th["load_mins"]))
            st[kind + "_alerted"] = True
        elif val < thresh - 10 and st.get(kind + "_alerted"):
            st[kind + "_alerted"] = False


# What _server_transition answers for a server whose LinuxGSM maintenance is running: record
# nothing at all for it this pass (not the transition state, not the status column).
_IN_MAINTENANCE = object()


def _monitor_server(remote, gs, probe, ports):
    """Apply one game server's port check: alerts, transition state, status column.

    True when gs.status changed. A server mid-install, or one whose LinuxGSM maintenance is
    running, is left exactly as it was.
    """
    if gs.status in ("installing", "configuring"):
        return False
    up = gs.port in ports
    # Display-only: does the BOX think a restart is queued for this server?
    # None means "could not look", and that must not be written as "no restart pending"
    # — the badge would simply go out, which is indistinguishable from the cron having
    # run. Leaving the previous value keeps the last thing actually measured.
    _rf = probe.get("restart_flagged")
    if _rf is not None:
        _cron_restart_pending[gs.id] = gs.short_name in _rf
    prev_up = _monitor_state["servers"].get(gs.id)
    # State is tracked either way — only the ALERT is muted by a tag, so a server that goes
    # down while muted still reports "back online" correctly once it is unmuted.
    muted = notifications.alerts_muted(gs)
    recorded = _server_transition(remote, gs, up, prev_up, muted)
    if recorded is _IN_MAINTENANCE:
        return False
    _monitor_state["servers"][gs.id] = recorded
    # Persist what this pass just measured. Nothing else writes gs.status for a
    # running/stopped transition except the three browser-polled endpoints (/api/servers,
    # /api/server/<id>, /api/server/<id>/stats), so with nobody on the dashboard the column
    # froze at whatever the last poll saw — while this loop recomputed the truth every 60s
    # and threw it away. Two things read that column and were wrong for as long as it was
    # stale: the chat bots' /servers and /status, and _query_server_slots, which short-
    # circuits a server it believes offline to 0 players WITHOUT querying it — so a server
    # that came back up while nobody was looking reported "offline (0/24)" indefinitely.
    # _new_status, not `st`: while this sat inline in _monitor_pass, `st` was the host's
    # load-state dict, and rebinding it to a string here was harmless only because that
    # assignment re-ran at the top of each host iteration. Both now live in their own helpers.
    _new_status = "online" if up else "offline"
    if gs.status != _new_status:
        gs.status = _new_status
        return True
    return False


def _offline_expected(server_id):
    """Whether the panel itself has this server down: a panel stop/restart's window, or a reboot plan's hold (inf)."""
    return time.time() - _expected_offline.get(server_id, 0) <= _EXPECT_OFFLINE_WINDOW


def _mon_server_went_down(remote, gs, up, prev_up, muted):
    """The down leg of _server_transition (prev_up True, now down): alert and answer what to record."""
    misses = _monitor_state["server_misses"]
    # The panel's own stop/restart is already accounted for locally — check that FIRST so
    # an intentional stop costs no SSH round trip.
    if _offline_expected(gs.id):
        misses.pop(gs.id, None)
        # Recorded DOWN at once, and nobody is told. It used to keep the previous value (up)
        # for the whole window, so that its return would not page "Server back online" for an
        # outage nobody was told about; but a Stop is MEANT to stay down, so when the window
        # ended the sweeps after it declared the server down and paged "went offline
        # unexpectedly" about every panel Stop, four or five minutes after it. The return is
        # kept quiet by the mark instead (_server_transition), however long after the window.
        _monitor_state["server_unannounced"][gs.id] = True
        return up
    # Not declared down until the port has been shut for _DOWN_CONFIRM_SWEEPS sweeps in a
    # row (see there). Until then the server stays recorded as up, so the sweep that
    # finds it listening again has nothing to announce. Counted BEFORE the maintenance
    # probe, so a single missed scan does not cost that SSH round trip either; once
    # confirmed, the count is kept through maintenance, so a server still down when
    # LinuxGSM's update finishes is reported on the next sweep.
    misses[gs.id] = misses.get(gs.id, 0) + 1
    if misses[gs.id] < _DOWN_CONFIRM_SWEEPS:
        return prev_up
    if _lgsm_maintenance_running(remote, gs):
        # A scheduled LinuxGSM update/restart is running: the port is SUPPOSED to be shut.
        # Leave the recorded state untouched so neither this pass nor the recovery pass
        # alerts — otherwise suppressing "offline" would just produce "back online".
        return _IN_MAINTENANCE
    misses.pop(gs.id, None)          # declared: recorded False from here on
    if not muted:
        notifications.notify("server_down", "Server offline",
                             "%s on %s went offline unexpectedly." % (gs.name, remote.display_name))
    return up


def _server_transition(remote, gs, up, prev_up, muted):
    """Alert on one server's up/down transition and answer what to record for it.

    The answer is usually `up`; the previous value for a down not yet confirmed by
    _DOWN_CONFIRM_SWEEPS sweeps; or _IN_MAINTENANCE when LinuxGSM's own maintenance has the port
    shut. A down the panel expected (_offline_expected) is recorded at once and marked
    unannounced, and the return of a server so marked is not announced either.
    """
    misses = _monitor_state["server_misses"]
    unannounced = _monitor_state["server_unannounced"]
    if up or prev_up is not True:
        misses.pop(gs.id, None)
    if prev_up is True and not up:
        return _mon_server_went_down(remote, gs, up, prev_up, muted)
    if up:
        quiet = unannounced.pop(gs.id, False)
        if prev_up is False and not muted and not quiet:
            notifications.notify("server_up", "Server back online",
                                 "%s on %s is back online." % (gs.name, remote.display_name))
    elif prev_up is None and _offline_expected(gs.id):
        # Never seen by this process: the first sweep after a panel restart. A reboot plan that
        # still holds the server (host_reboot.resume_reboot_state put the hold back before this
        # sweep could run) took it down, and the plan's own summary reports its return.
        unannounced[gs.id] = True
    return up


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

    THE MAPS ARE NOT NAMED HERE ANY MORE. They used to be, and that made every new row-keyed map an
    edit somebody had to remember to make in this function — which is how two of them were missed
    for as long as they existed. _game_backup_status and the GMod content-apply state are both read
    to RENDER a server's page, so a recycled id showed the new server the previous one's backup
    outcome, or a content install frozen at "running". They are registered at their declarations
    now (panel_state.register_server_state / register_remote_state), and this walks the registry.
    The OS-update sweep's arming counts (_os_update_state["hosts"]) are registered too: the sweep
    prunes them itself, but only against ids no row holds, which a recycled id never is.

    #85's snapshot (_os_update_seen) is registered even though the sweep also prunes it: it is read
    on every page load by /api/os-updates/summary, so a deleted host would otherwise linger in the
    login banner for up to a day — under a row id a newly added host may already own, which means
    its name and package count show to whoever can access the NEW host. Both are idempotent.
    """
    server_maps, remote_maps = keyed_state_with_locks()
    gone = []
    for entries, live in ((remote_maps, remote_ids), (server_maps, server_ids)):
        dead = set()
        for m, lock in entries:
            # Under the map's own lock where it has one — _install_jobs and _bootstrap_jobs are
            # written from request handlers and job threads that only ever touch them locked, and
            # this sweep runs on the monitor thread. Each of those locks covers a dict operation
            # and nothing else, so holding it here cannot stall the sweep.
            with lock if lock is not None else contextlib.nullcontext():
                dead.update(k for k in m if k not in live)
        gone.append(dead)
    # The same forgetting the delete routes and every INSERT do, so an action-output entry dropped
    # here is marked `forgotten` too — its worker may still be running, and must not announce its
    # end into whatever server takes the id next.
    forget_rows(remote_ids=gone[0], server_ids=gone[1])


# How long PAST _EXPECT_OFFLINE_WINDOW a host's servers stay expected-offline when the panel reboots
# the host. Only for the servers a clean reboot does NOT hold in its plan (stopped ones, and ones it
# could not read): a planned server is held for as long as its plan runs (host_reboot).
_REBOOT_EXPECT_OFFLINE_EXTRA = 300


def _mark_host_expected_offline(remote_id, extra=_REBOOT_EXPECT_OFFLINE_EXTRA):
    """Mark every game server on a host the panel is about to reboot as expected-offline.

    The same way a panel-issued stop marks one server. Returns the previous marks.
    """
    until = time.time() + extra
    prev = {}
    for (gid,) in db.session.query(GameServer.id).filter_by(remote_id=remote_id).all():
        prev[gid] = _expected_offline.get(gid)
        _expected_offline[gid] = until
    return prev


_AUTOBLOCK_TAG = "panel-autoblock"


_AUTOBLOCK_DEFAULT_THRESHOLD = 20


def _autoblock_threshold():
    try:
        return max(1, min(int(load_config().get("autoblock_threshold", _AUTOBLOCK_DEFAULT_THRESHOLD)), 100000))
    except (TypeError, ValueError):
        return _AUTOBLOCK_DEFAULT_THRESHOLD


def _whitelist_networks():
    """The whitelist parsed into ip_network objects once (skipping any that no longer parse).

    An entry stored with a zone id (only a config from before _security_whitelist_add refused one
    can hold it) is read as the address or network it names, as it was before that refusal: the
    Settings page lists it as active, and skipping it silently let the auto-block ban an address
    an admin believes is whitelisted (validation.unzoned_ip_or_network).
    """
    nets = []
    # Reads the config directly rather than calling app.py's _security_whitelist(): that reader is
    # one of a trio with _security_whitelist_add/_remove, and importing it here would be circular
    # (app imports monitoring). Splitting the trio to avoid one line of duplication is the worse
    # trade — the key name is the contract, and it is asserted below.
    for entry in list(load_config().get("security_whitelist", []) or []):
        net = ip_network_or_none(unzoned_ip_or_network(entry))
        if net is not None:
            nets.append(net)
    return nets


def _whitelisted(ip, nets=None):
    """True if `ip` is covered by any whitelist entry (an exact IP or a CIDR that contains it).

    A zoned `ip` is not an address, and is covered by nothing.
    """
    addr = ip_address_or_none(ip)
    if addr is None:
        return False
    return any(addr in n for n in (nets if nets is not None else _whitelist_networks()))


def _autoblock_reconcile(remote):
    """Make the host's 'panel-autoblock' UFW rules match the current offenders.

    Block any IP whose failed-attempt count over the last 7 days is at/above the threshold and
    isn't already blocked (by us or manually), tailnet-exempt, or whitelisted; and release only our
    own auto-blocks that have since dropped below the threshold (or been whitelisted).

    "Manually" is real now: the blocked-IP readers return every all-ports deny, tagging one the
    panel did not write "" — so it is never re-blocked (which deleted it) and never in `auto`
    (which released it). And the counts are the FULL tally, not the display's top 100: ranked
    below 100 meant never blocked, and falling below 100 meant released while over threshold.
    """
    threshold = _autoblock_threshold()
    counts, blocked, deny, undeny = _autoblock_host_io(remote)
    # A failed read answers None. Releasing on it would unblock every IP the panel has auto-blocked
    # — and they only come back if a LATER successful read still finds them over the threshold
    # inside the 7-day window, so anything that has since aged out is gone for good.
    if counts is None:
        _log.debug("autoblock: skipping %s — the fail2ban read failed", remote.name)
        return 0, 0
    # The SAME reasoning for the firewall read, which was missing it. An unreadable firewall
    # answers None; treating that as "nothing is blocked" made every offender look unblocked and
    # re-issued a delete+add for each of them on every cycle — up to 200 privileged commands a
    # cycle against a host that is not answering.
    if blocked is None:
        _log.debug("autoblock: skipping %s — the firewall read failed", remote.name)
        return 0, 0
    qualify = _autoblock_offenders(remote, counts, threshold)
    auto = {ip for ip, tag in blocked.items() if tag == _AUTOBLOCK_TAG}
    # COUNT WHAT APPLIED, not what was attempted. Both writers return (ok, msg) and both were
    # being called for their side effect only — so the caller's audit row ("+%d blocked, -%d
    # released") reported rules that never landed when ufw was down or the host stopped answering
    # mid-cycle. Same defect as the sync-ports route, in the function whose two READS were already
    # guarded a few lines above: an audit row recording an action that did not happen is worse
    # than no row.
    failed = []
    # over threshold, not blocked yet → auto-block
    added = _autoblock_apply(deny, qualify - set(blocked.keys()), "block %s", failed)
    # our auto-block fell below threshold / got whitelisted → release
    removed = _autoblock_apply(undeny, auto - qualify, "release %s", failed)
    if failed:
        # Not silent: the counts above are now honest, which on their own would make a failing
        # host look like a quiet one.
        _log.warning("autoblock on %s: %d change(s) did not apply (%s)",
                     getattr(remote, "name", "?"), len(failed), ", ".join(failed)[:200])
    return added, removed


def _autoblock_host_io(remote):
    """Read a host's attempt counts and blocked IPs: (counts, blocked, deny, undeny).

    deny/undeny are that host's firewall writers, each taking one IP and answering (ok, msg). The
    two reads happen here, in this order, before the caller looks at either answer.
    """
    if remote.is_local:
        counts = so.fail2ban_attempt_counts(days=7)
        blocked = so.ufw_blocked_ips()

        # The panel host's writers run through system_ops, not ssh_manager.run_privileged, so they
        # take the host's ufw_lock here: a delete-by-number on this host (remote_ufw_delete_rule on
        # the local row) holds it from its check to its delete, and an insert at 1 in between is
        # exactly what it must not see.
        def deny(ip):
            with ufw_lock(remote):
                return so.ufw_deny_ip(ip, tag=_AUTOBLOCK_TAG)

        def undeny(ip):
            with ufw_lock(remote):
                return so.ufw_undeny_ip(ip)
    else:
        counts = remote_fail2ban_attempt_counts(remote, days=7)
        blocked = remote_ufw_blocked_ips(remote)

        def deny(ip):
            return remote_ufw_deny_ip(remote, ip, tag=_AUTOBLOCK_TAG)

        def undeny(ip):
            return remote_ufw_undeny_ip(remote, ip)
    return counts, blocked, deny, undeny


def _autoblock_offenders(remote, counts, threshold):
    """The IPs at/above the threshold, less the host's tailnet-exempt ones and the whitelist."""
    qualify = {ip for ip, n in counts.items() if ip and (n or 0) >= threshold}
    qualify -= tailnet_exempt_ips(remote, qualify)   # never auto-block your own tailnet (Tailscale up)
    _nets = _whitelist_networks()
    return {ip for ip in qualify if not _whitelisted(ip, _nets)}   # never auto-block a whitelisted IP


def _autoblock_apply(write, ips, what, failed):
    """Call write(ip) for each IP; return how many applied, appending `what % ip` for the rest."""
    applied = 0
    for ip in ips:
        ok, _msg = write(ip)
        if ok:
            applied += 1
        else:
            failed.append(what % ip)
    return applied


# A cached capacity is re-read after this long. It used to be kept for the whole process lifetime
# ("capacity is essentially static"), which is not true of a number this panel's OWN settings form
# edits: nothing on the write path clears this map, so raising slots from 16 to 32 left the panel
# answering 16 until it was restarted. That number is not only displayed — it is the `count >= mx`
# the "Server full" alert fires on, so the panel pushed "full (16/16)" with 16 slots free, latched
# _server_full_alerted, and was then silent when the server genuinely filled. An hour is still one
# read per server per hour, and unlike a pop in the write path it also catches an edit made on the
# host (LinuxGSM config, another panel, an admin in vim).
_MAX_PLAYERS_TTL = 3600
# A config that was READ and names no capacity at all is re-read this often instead.
_MAX_PLAYERS_UNSET_TTL = 600


def _server_max_config(gs):
    """Server capacity from the LinuxGSM config (maxplayers, else slots), or None if unset/unreadable.

    Cached for _MAX_PLAYERS_TTL seconds — capacity changes rarely, but it does change. Readable
    even while the server is stopped (it's just a config file).
    """
    cached = _max_players_cache.get(gs.id)
    prev = None
    if cached is not None:
        prev, read_at = cached
        ttl = _MAX_PLAYERS_TTL if prev is not None else _MAX_PLAYERS_UNSET_TTL
        if (time.time() - read_at) < ttl:
            return prev
    read, mx = _read_max_config(gs)
    if mx is not None:
        _max_players_cache[gs.id] = (mx, time.time())
        return mx
    if read and prev is None:
        # READ, and the config names no capacity (Minecraft keeps it in server.properties): that is
        # an answer, so it is kept for _MAX_PLAYERS_UNSET_TTL. Uncached, every 45 s pass re-ran a
        # `sudo -u <account>` config read to learn the same nothing, for as long as it ran.
        _max_players_cache[gs.id] = (None, time.time())
    # The re-read failed (or the key is unset). A failed read is not a measurement: keep serving
    # the last capacity actually read rather than blanking the UI and disarming the full alert,
    # and retry on the next call — which is what an uncached server already does.
    return prev


def _read_max_config(gs):
    """(read, capacity): whether the config was READ at all, and maxplayers/slots from it or None.

    lgsm_get_values answers None for "could not be read" and a dict for a read; the two stay apart
    here, because only a real read may be cached as "no capacity set".
    """
    try:
        vals = lgsm_get_values(gs.remote, gs.short_name, gs.lgsm_name, ["maxplayers", "slots"])
    except Exception:
        _log.debug("max-players: config read failed for %s", getattr(gs, "short_name", "?"), exc_info=True)
        return False, None
    if not isinstance(vals, dict):
        return False, None
    for key in ("maxplayers", "slots"):
        v = (vals.get(key) or "").strip()
        if v.isdecimal():
            return True, int(v)
    return True, None


def _server_slots(gs, allow_console=False, primary=None):
    """(count, max, name) for one game server. Never raises.

    The COUNT we can trust — gamedig first (which also yields max AND the server's advertised
    in-game name in the same query), then LinuxGSM's own NETWORK query; a stopped server is 0, and
    None means 'unknown' so the auto-reboot never fires on a game it can't see. The game CONSOLE
    (`status`) is used only when allow_console=True — every caller here is a background/timer poll,
    so this stays False and the panel never types into a game's console automatically (set a GSLT
    so gamedig can read the server instead). MAX is gamedig's reported capacity when it has one,
    otherwise the LinuxGSM config. NAME (the in-game hostname players see) only comes from gamedig;
    None from the other sources.

    `primary`, when given, is gamedig's answer already read for this server by its host's batched
    query; (None, None, None) there means that query could not read it, and the fallbacks run.
    """
    # Primary: gamedig gives count, max AND the advertised name in a single query.
    cur, mx, gname = primary if primary is not None else _gamedig_slots(gs)
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
    lc = _lgsm_query_count(gs)
    if lc is not None:
        return lc, _server_max_config(gs), None
    return _stopped_or_unknown_slots(gs)


def _gamedig_slots(gs):
    """Gamedig's (count, max, name) for one server, or (None, None, None) when the query raised."""
    try:
        cur, mx, gname = sm_player_slots(gs.remote, gs.short_name, gs.game_type, gs.port, gs.query_type)
    except Exception:
        cur, mx, gname = None, None, None
    return cur, mx, gname


def _lgsm_query_count(gs):
    """The player count from LinuxGSM's own network query settings, or None (never raises)."""
    try:
        # cached=True: querymode/querytype/queryport are static config, and reading them cost a
        # `sudo -u <account>` per pass for every server that gamedig could not read.
        return sm_player_count_via_lgsm_query(gs.remote, gs.short_name, gs.lgsm_name,
                                              fallback_port=gs.port, cached=True)
    except Exception:
        return None


def _stopped_or_unknown_slots(gs):
    """_server_slots' last resort: (0, max, None) for a stopped server, else (None, max, None)."""
    # No gamedig type, no console engine, and LinuxGSM has no network query: a stopped server is
    # definitely empty; a running one we simply can't read, so report unknown (poller won't reboot).
    #
    # A server the monitor found LISTENING (status "online", from its port scan) is not asked:
    # the status check is a LinuxGSM `details` through the helper — several `du` runs over the
    # server's files, 7-15 s on the test VPS — every 45 s, and for a running server it can only
    # say it is running. The answer is unknown either way. The one difference: status lags the
    # port by up to a minute, and in that window `details` could have said "stopped" (0 players)
    # where this says unknown — the cautious direction, which delays a reboot-when-empty or a
    # notify-when-empty by at most one monitor pass rather than acting on a guess.
    if getattr(gs, "status", None) == "online":
        return None, _server_max_config(gs), None
    try:
        if sm_get_server_status(gs.remote, gs) == "offline":
            return 0, _server_max_config(gs), None
    except Exception:
        _log.debug("reboot-when-empty: status check failed for %s", getattr(gs, "short_name", "?"),
                   exc_info=True)
    return None, _server_max_config(gs), None


def _server_players_confident(gs):
    """The trustworthy player COUNT (int) for one server, or None.

    Thin wrapper over _server_slots for callers (the auto-reboot) that only need the count —
    behaviour is unchanged.
    """
    return _server_slots(gs)[0]
