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

# Hosts the operator asked to "reboot when empty" — reboot once every game server on them is idle.
# remote_id -> {"by": username, "since": epoch}. In-memory on purpose: a panel restart clears any
# pending request, so no surprise reboot ever survives a restart.
_reboot_when_empty = {}

_rwe_lock = threading.Lock()

_max_players_cache = {}   # server_id -> int  (capacity is ~static, so read it once and reuse)

# The daily sweep already asks every host what it has waiting; this is that answer, kept so the
# login banner and the OS Updates card can SHOW it without re-running `apt update` on a page load.
# Distinct from the sweep's own arming state (_os_update_state in create_app), which exists only to
# decide whether to send a chat alert and must keep its exact shape.
#
# Written by the sweep AND by every explicit check, so installing updates from the panel clears the
# banner right away instead of leaving it up until tomorrow's sweep.
_os_update_seen = {}         # remote.id -> {name, count, security, packages, at}

# A gamedig query per server is far too slow to run on every dashboard status poll (every 8s), so a
# background poller refreshes the counts on a slower cadence and the request path just reads this
# cache. count is an int, or None when the game genuinely can't be queried ("—" in the UI).
_player_counts = {}          # server_id -> {"count": int|None, "ts": float}

_server_full_alerted = {}    # server_id -> bool (currently at cap; re-arms when it drops below)

_server_peak_notified = {}   # server_id -> ts of the last new-record alert (rate-limit)

_last_sample_prune = [0.0]   # 1-element holder so _prune_metric_samples updates it without `global`

# disk_pct / load_pct thresholds are user-configurable — see notifications.get_thresholds().
_monitor_state = {"remotes": {}, "servers": {}, "disk": {}, "load": {}}   # id -> last-seen state

_expected_offline = {}          # server_id -> ts the panel last stopped/restarted it

# Game users whose ~/.restart-pending flag is set, per host id. The DAILY-RESTART cron sets that
# flag on the box at 05:00 and its hourly partner restarts once the server empties — a mechanism the
# panel writes but then cannot see, because the panel's own "restart when empty" is a DB column and
# nothing connects the two. The banner therefore stayed hidden while a restart really was queued.
# Display only: the column is never written from this, so the panel's own queue is untouched and
# nothing can be restarted twice.
_cron_restart_pending = {}

