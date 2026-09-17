"""Process-wide caches and locks shared by the monitor loop and the request handlers.

These were module-level in app.py already — app.py's own note explains why they were hoisted out
of register_routes: "every one of these is process-wide anyway, none is per-app". Splitting the
monitor loop into monitoring.py is what forces them into a module of their own, because both sides
genuinely read and write the same objects.

EVERY name here is MUTATED IN PLACE, never rebound. That is what makes `from panel_state import
_player_counts` safe: importers share the one object. Rebinding one of these (`_player_counts = {}`)
would silently give the rebinding module a private copy and strand every other reader on the old
one — clear it with `.clear()` instead.
"""
import threading   # noqa: F401  (locks below are constructed from it)

# This module exists ONLY to hold these; every one is read and written by importers
# (app.py, monitoring.py) and none is used here, which is exactly what CodeQL's
# py/unused-global-variable flags — it analyses a module in isolation and cannot see the
# `from panel_state import ...` on the other side. __all__ is not a suppression: it is the
# idiomatic way to declare an export-only module's surface, and it makes the intent
# explicit for readers too.
__all__ = [
    "_reboot_when_empty",
    "_rwe_lock",
    "_max_players_cache",
    "_os_update_seen",
    "_player_counts",
    "_server_full_alerted",
    "_server_peak_notified",
    "_last_sample_prune",
    "_monitor_state",
    "_expected_offline",
    "_cron_restart_pending",
    "_action_output",
    "_install_jobs",
    "_install_lock",
    "_full_backup_lock",
    "_game_backup_status",
    "_os_update_state",
    "register_server_state",
    "register_remote_state",
    "server_keyed_state",
    "remote_keyed_state",
]


# ── Row-keyed state, registered where it is declared ──────────────────────────────────────────
# Every map registered here is keyed by a database row id, and SQLite hands a deleted row's id
# straight to the next INSERT (plain INTEGER PRIMARY KEY = rowid, no AUTOINCREMENT) — so a newly
# added server or host inherits whatever the deleted one left behind unless the id is forgotten.
# monitoring._forget_deleted_rows is what forgets it.
#
# THE LIST USED TO BE WRITTEN OUT BY HAND in that function, which made every new map an edit
# somebody had to remember to make somewhere else. Two were missed: _game_backup_status and the
# GMod content-apply state, both of which are read to RENDER a server's page, so a recycled id
# showed the new server the PREVIOUS one's backup outcome or a content install stuck at "running".
# Registering at the declaration means the pruner's list and the declarations are the same list,
# and a map that is deliberately not pruned (see _os_update_state) is now visibly not registered
# rather than indistinguishable from one that was forgotten.
_server_keyed_state = []
_remote_keyed_state = []


def register_server_state(mapping):
    """Mark `mapping` as keyed by GameServer.id so the pruner clears deleted ids from it.
    Returns `mapping`, so a declaration can wrap itself: `_x = register_server_state({})`."""
    _server_keyed_state.append(mapping)
    return mapping


def register_remote_state(mapping):
    """Mark `mapping` as keyed by RemoteServer.id. Returns `mapping` — see above."""
    _remote_keyed_state.append(mapping)
    return mapping


def server_keyed_state():
    """Every registered GameServer.id-keyed map. A tuple: the registry is appended to at import
    time and only read afterwards, and handing out the live list invites a caller to mutate it."""
    return tuple(_server_keyed_state)


def remote_keyed_state():
    """Every registered RemoteServer.id-keyed map."""
    return tuple(_remote_keyed_state)

# Hosts the operator asked to "reboot when empty" — reboot once every game server on them is idle.
# remote_id -> {"by": username, "since": epoch}. In-memory on purpose: a panel restart clears any
# pending request, so no surprise reboot ever survives a restart.
_reboot_when_empty = {}

_rwe_lock = threading.Lock()

_max_players_cache = register_server_state({})   # server_id -> int  (capacity is ~static, so read it once and reuse)

# The daily sweep already asks every host what it has waiting; this is that answer, kept so the
# login banner and the OS Updates card can SHOW it without re-running `apt update` on a page load.
# Distinct from the sweep's own arming state (_os_update_state in create_app), which exists only to
# decide whether to send a chat alert and must keep its exact shape.
#
# Written by the sweep AND by every explicit check, so installing updates from the panel clears the
# banner right away instead of leaving it up until tomorrow's sweep.
_os_update_seen = register_remote_state({})   # remote.id -> {name, count, security, packages, at}

# A gamedig query per server is far too slow to run on every dashboard status poll (every 8s), so a
# background poller refreshes the counts on a slower cadence and the request path just reads this
# cache. count is an int, or None when the game genuinely can't be queried ("—" in the UI).
_player_counts = register_server_state({})   # server_id -> {"count": int|None, "ts": float}

_server_full_alerted = register_server_state({})   # server_id -> bool (currently at cap; re-arms when it drops below)

_server_peak_notified = register_server_state({})   # server_id -> ts of the last new-record alert (rate-limit)

_last_sample_prune = [0.0]   # 1-element holder so _prune_metric_samples updates it without `global`

# disk_pct / load_pct thresholds are user-configurable — see notifications.get_thresholds().
_monitor_state = {"remotes": register_remote_state({}), "servers": register_server_state({}),
                  "disk": register_remote_state({}), "load": register_remote_state({})}

_expected_offline = register_server_state({})   # server_id -> ts the panel last stopped/restarted it

# Game users whose ~/.restart-pending flag is set, per host id. The DAILY-RESTART cron sets that
# flag on the box at 05:00 and its hourly partner restarts once the server empties — a mechanism the
# panel writes but then cannot see, because the panel's own "restart when empty" is a DB column and
# nothing connects the two. The banner therefore stayed hidden while a restart really was queued.
# Display only: the column is never written from this, so the panel's own queue is untouched and
# nothing can be restarted twice.
_cron_restart_pending = register_server_state({})

# A long LinuxGSM action (update/validate/backup/…) currently running for this server, and the
# host-side file its output is being written to. The console poller tails that file and pushes
# the new bytes to whoever has the console open — which is what makes "watch the live console for
# progress" true. Without it an update ran entirely out of sight: its output was captured over
# SSH and only ever reached the audit log, so the console the panel told you to watch stayed
# silent for the whole download.
#
# server_id -> {"action": str, "path": str, "user": str, "pos": int}. `pos` is the byte offset
# the poller has already sent, and the POLLER is the only writer of it (one thread, so a plain
# int is enough). Starting at 0 means a console opened mid-update replays from the beginning.
_action_output = register_server_state({})

# ── Background-job state ─────────────────────────────────────────────────────────────────────
# These lived at module level in app.py, which was fine while the only readers were app.py's own
# routes and the workers nested inside register_routes(). Extracting those workers into their own
# module makes app.py the wrong home: a jobs module importing app.py — which imports the jobs
# module — is a cycle. They are process-wide shared state, which is exactly what this module is
# for, so they move here alongside the monitor's own maps and follow the same contract: MUTATED IN
# PLACE, never rebound.

# Live game-server install progress, keyed by GameServer id (same process, so a plain dict + lock
# is fine). Written by the install job runner, read by /api/server/<id>/install-status.
_install_jobs = {}
_install_lock = threading.Lock()

# Only one game-file backup at a time (full OR single-server) — they are slow and space-heavy.
_full_backup_lock = threading.Lock()
# Last on-demand per-server backup outcome, keyed by server id (transient, in-memory).
_game_backup_status = register_server_state({})

# The daily OS-update sweep's ARMING state: when it last ran, and the per-host counts it alerted
# on. Distinct from _os_update_seen above, which is what the login banner and the OS Updates card
# read — this one exists only to decide whether to send a chat alert, and must keep its exact
# shape (see the transition tests in smoke_test.py).
_os_update_state = {"last_run": 0.0, "hosts": {}}   # remote.id -> (count, security_count)
