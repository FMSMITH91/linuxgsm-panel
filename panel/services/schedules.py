"""Settings -> Schedules: the panel's own background jobs, and the few whose timing an admin may change.

Every job the panel runs by itself is listed with what it does, how often it runs, and when it last
ran and runs next, read from the loops' own records (runtime_stats' heartbeats and first-pass
records, which the debug report reads too). Three can be changed, because changing them cannot
break anything that depends on them:

- the daily panel backup's time of day (BACKUP_AT), read by ops/backup.daily_backup_tick;
- how often the panel checks for its own updates (UPDATE_EVERY), read by routes/os_updates;
- the daily OS-update check: its time of day (OS_CHECK_AT) and an off switch (OS_CHECK), read by
  routes/os_updates.

Times are stored as "HH:MM" in UTC and compared against the clock in UTC; the form shows and takes
them in the viewer's own zone (schedules.js sends it), converted with clock.convert_wall_time.
Everything else runs on a cadence other code relies on (the console's 2-second poll, the monitor's
minute), so it is shown, not offered. The daily backup's on/off and how long backups are kept stay
on the Backups card, and the update check's on/off in Outside services: one editor per setting.
"""
import time
from datetime import datetime, timedelta, timezone

from panel.core import clock, i18n, runtime_stats
from panel.core.config import config_value

BACKUP_AT = "backup_daily_at"
UPDATE_EVERY = "update_check_minutes"
OS_CHECK_AT = "os_update_check_at"
OS_CHECK = "os_update_check"
UPDATE_CHOICES = (30, 60, 180, 360, 720, 1440)
UPDATE_DEFAULT = 30
OS_CHECK_EVERY = 24 * 3600

# The loops shown, read-only: (heartbeat key, name, what it does). Cadences are the loops' own.
WORKERS = (
    ("monitor", "Monitor", "Checks each game server and host is up, and sends the alerts you set."),
    ("console-poller", "Console", "Reads new console lines for the consoles that are open."),
    ("player-counts", "Player counts", "Asks each running game server how many players are on; every 90 s when no page or alert needs them."),
    ("metrics-history", "Usage history", "Records CPU, memory and disk use for the charts."),
    ("due-actions", "Restart or stop when empty", "Restarts or stops a server you queued, once its players leave."),
    ("backup-ticker", "Backups", "Takes the daily panel backup, scheduled game backups and queued ones."),
    ("wipe-schedule", "Scheduled wipes", "Runs the world wipes and resets you scheduled."),
    ("install-reconcile", "Installs", "Finishes the state of an install the panel lost track of in a restart."),
    ("priority-keeper", "Game priority", "Keeps game processes at their CPU priority."),
    ("autoblock", "Auto-block", "Blocks addresses with too many failed logins, when Auto-block is on."),
    ("ban-watch", "Bans", "Watches fail2ban for new bans to report."),
    ("update-check", "Update checks", "Checks for panel and OS updates, and certificate expiry."),
    ("node-tools", "Node.js tools", "Keeps the tools the panel uses to query games installed."),
    ("host-reboot", "Host reboots", "Carries out a reboot you started, and brings servers back after it."),
    ("reboot-when-empty", "Reboot when empty", "Reboots a host you queued, once its players leave."),
    ("restore-recover", "Game restores", "Finishes a game restore the panel lost track of in a restart."),
)


def _hhmm(value):
    """A stored "HH:MM" as (hour, minute), or None for unset or unreadable."""
    got = clock.parse_hhmm(value, default=None) if value else None
    return got


def backup_at():
    """The daily panel backup's time of day, (hour, minute) UTC, or None for "about every 24 hours"."""
    return _hhmm(config_value(BACKUP_AT, ""))


def os_check_at():
    """The OS-update check's time of day, (hour, minute) UTC, or None for "24 hours after the last"."""
    return _hhmm(config_value(OS_CHECK_AT, ""))


def os_check_on():
    """Whether the daily OS-update check runs (on unless config.json holds exactly false)."""
    return config_value(OS_CHECK, True) is not False


def update_every():
    """Seconds between panel update checks: one of UPDATE_CHOICES (in minutes), else the default."""
    v = config_value(UPDATE_EVERY, UPDATE_DEFAULT)
    return (v if isinstance(v, int) and not isinstance(v, bool) and v in UPDATE_CHOICES else UPDATE_DEFAULT) * 60


def last_slot(at, now=None):
    """Epoch of the latest `at` ((hour, minute) UTC) at or before `now`."""
    now = time.time() if now is None else now
    d = datetime.fromtimestamp(now, timezone.utc)
    slot = d.replace(hour=at[0], minute=at[1], second=0, microsecond=0)
    if slot > d:
        slot -= timedelta(days=1)
    return slot.timestamp()


def due_at_slot(at, last_run, now=None):
    """Whether a job set for `at` is due: the latest slot has passed since it last ran."""
    return last_run < last_slot(at, now)


def _naive(epoch):
    """An epoch as the naive UTC datetime the |datetime filter takes, or None."""
    if not epoch:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).replace(tzinfo=None)


def _next_slot(at, after):
    return last_slot(at, after) + 86400


def _cadences():
    """{loop: its cadence in seconds}, from the debug report's table of the panel's loops."""
    from panel.ops.debug_report import workers as _w   # lazy: the report package is large
    return dict(_w.WORKERS)


def _worker_times(name, cadence):
    """(last, next) epochs of a loop: its last completed pass, and that plus its cadence.

    A loop with no completed pass yet is due at its first pass, from its own start record.
    """
    beat = runtime_stats.snapshot("heartbeat").get(name) or {}
    last = beat.get("at")
    if last:
        every = beat.get("cadence") or cadence
        return last, (last + every if every else None)
    start = runtime_stats.snapshot("loop_start").get(name)
    if isinstance(start, tuple) and len(start) == 2 and isinstance(start[1], (int, float)):
        return None, start[0] + start[1]
    return None, None


def worker_rows():
    """The read-only rows: name, what, every (seconds or None), last and next (naive UTC or None)."""
    cadences = _cadences()
    out = []
    for key, name, what in WORKERS:
        last, nxt = _worker_times(key, cadences.get(key))
        out.append({"key": key, "name": name, "what": what, "every": cadences.get(key),
                    "last": _naive(last), "next": _naive(nxt)})
    return out


def backup_times(newest, enabled, now=None):
    """(last, next) epochs of the daily panel backup: `newest` daily backup's time, and when the next is due."""
    now = time.time() if now is None else now
    if not enabled:
        return newest or None, None
    at = backup_at()
    if at is None:
        return newest or None, max(now, (newest or 0) + 23 * 3600)
    return newest or None, (now if due_at_slot(at, newest or 0, now) else _next_slot(at, now))


def os_check_times(last_run, now=None):
    """(last, next) epochs of the OS-update check."""
    now = time.time() if now is None else now
    if not os_check_on():
        return last_run or None, None
    at = os_check_at()
    if at is None:
        return last_run or None, ((last_run + OS_CHECK_EVERY) if last_run else None)
    return last_run or None, (now if last_run and due_at_slot(at, last_run, now) else _next_slot(at, now))


def every_words(seconds):
    """How often a loop runs, as a Sentence ("Every {n} minutes"), for the read-only rows."""
    seconds = int(seconds or 0)
    if not seconds:
        return i18n.Sentence("Runs continuously")
    if seconds == 86400:
        return i18n.Sentence("Once a day")
    if seconds % 3600 == 0:
        return i18n.Sentence("Every hour") if seconds == 3600 else i18n.Sentence("Every {n} hours", n=seconds // 3600)
    if seconds % 60 == 0:
        return i18n.Sentence("Every minute") if seconds == 60 else i18n.Sentence("Every {n} minutes", n=seconds // 60)
    return i18n.Sentence("Every {n} seconds", n=seconds)


def utc_hhmm(at):
    """(hour, minute) as "HH:MM", or "" for None."""
    return "%02d:%02d" % at if at else ""


def parse_time(raw, viewer_tz):
    """A typed "HH:MM" in the viewer's zone -> the "HH:MM" UTC to store; "" for blank; None if unreadable."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    at = clock.parse_hhmm(raw, default=None)
    if at is None:
        return None
    return utc_hhmm(clock.convert_wall_time(at[0], at[1], clock.valid_timezone(viewer_tz) or "UTC", "UTC"))


def parse_form(form):
    """({config key: value} from the Schedules form, "") or ({}, why in fixed words)."""
    tz = form.get("tz", "")
    backup = parse_time(form.get("backup_at"), tz)
    os_at = parse_time(form.get("os_check_at"), tz)
    if backup is None or os_at is None:
        return {}, "Enter a time as HH:MM, or leave it empty."
    raw = form.get("update_every") or ""
    every = int(raw) if raw.isascii() and raw.isdecimal() and len(raw) <= 5 else 0
    if every not in UPDATE_CHOICES:
        return {}, "Choose how often to check for panel updates from the list."
    return {BACKUP_AT: backup, OS_CHECK_AT: os_at, UPDATE_EVERY: every, OS_CHECK: bool(form.get("os_check"))}, ""


def change_note(cfg, new):
    """The audit row's words for what the Schedules form changed: "key: old -> new" for each."""
    olds = {BACKUP_AT: cfg.get(BACKUP_AT, ""), OS_CHECK_AT: cfg.get(OS_CHECK_AT, ""),
            UPDATE_EVERY: cfg.get(UPDATE_EVERY, UPDATE_DEFAULT), OS_CHECK: cfg.get(OS_CHECK, True) is not False}
    return "; ".join("%s: %s -> %s" % (k, olds[k] if olds[k] != "" else "any", v if v != "" else "any")
                     for k, v in new.items() if olds.get(k) != v)
