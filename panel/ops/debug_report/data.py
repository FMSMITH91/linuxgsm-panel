"""Debug-report section(s): database, backups.

Owner: builder B2. database: one integrity check off-hub, not-checked vs damaged, pragmas/backup/
moved-aside/schema, table census and retention, audit digest (R57-R61). backups: panel backups and
update snapshots (R62).

Every SQL read goes through _src_db.run_ro: ONE read-only connection in a tpool worker, bounded by
the report's deadline. Only counts, MIN()/MAX() timestamps, pragma numbers and action names
(^[a-z0-9_]{1,64}$, enforced here) come back -- never a username, target, detail or address. The
schema comparison uses SQLAlchemy's inspector on the hub (a PRAGMA per table, milliseconds).
"""
import datetime as _dt
import os
import re
import shutil
import time

from panel.ops.debug_report._base import Result, ago

_ACTION_RE = re.compile(r"^[a-z0-9_]{1,64}\Z")
_ASIDE_RE = re.compile(r"\.corrupt-\d+(?:-\d+)?\Z")
_STAMP_RE = re.compile(r"^\d{8}-\d{6}\Z")
_LIST_MAX = 10
_DAY = 86400.0
# Network and security changes worth listing by name (R61).
_NETSEC_ACTIONS = ("panel_change_binding", "panel_restart", "close_panel_port",
                   "tailscale_serve_enable", "tailscale_serve_disable", "tailscale_ssh_enable",
                   "tailscale_ssh_disable", "tailscale_up_local", "tailscale_install_local",
                   "ufw_allow_tailscale", "ufw_block", "ufw_unblock", "whitelist_add",
                   "whitelist_remove", "autoblock_toggle", "autoblock_threshold",
                   "change_ssh_port", "fail2ban_unban", "server_reboot")
# Static SQL (no formatting): one placeholder per _NETSEC_ACTIONS entry -- a unit check holds the
# two to the same length -- and the actor reduced to a category inside SQLite, so no name is read.
_FAILED_SQL = ("SELECT action, COUNT(*), MAX(timestamp) FROM audit_log WHERE success = 0 AND "
               "timestamp >= ? GROUP BY action ORDER BY COUNT(*) DESC LIMIT 15")
_NETSEC_SQL = ("SELECT action, timestamp, success FROM audit_log WHERE action IN (?, ?, ?, ?, ?, "
               "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ORDER BY id DESC LIMIT 10")
_ORIGIN_SQL = ("SELECT CASE WHEN user_id IS NOT NULL THEN 'web' WHEN username LIKE 'telegram:%' OR "
               "username LIKE 'discord:%' THEN 'bot' ELSE 'system or not signed in' END, COUNT(*) "
               "FROM audit_log WHERE timestamp >= ? GROUP BY 1")
_IPS_SQL = ("SELECT COUNT(*) FROM audit_log WHERE timestamp < ? AND ip_address != '' AND "
            "ip_address IS NOT NULL AND ip_address NOT LIKE '%/%'")


def _mb(n):
    return "%.1f MB" % (n / 1048576.0) if n >= 1048576 else "%d KB" % max(0, n // 1024)


def _size(path):
    try:
        return _mb(os.path.getsize(path))
    except FileNotFoundError:
        return "none"
    except OSError:
        return "unreadable"


def _epoch(ts):
    """A naive-UTC SQLite timestamp ('YYYY-MM-DD HH:MM:SS[.ffffff]') as epoch seconds, or None."""
    try:
        return _dt.datetime.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=_dt.timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def _sql_time(seconds_ago):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() - seconds_ago))


def _db_path():
    from panel.core import config as cfg
    return str(cfg.DB_PATH)


def _int_cfg(c, key, default):
    try:
        return int(c.get(key, default) or 0)
    except (TypeError, ValueError):
        return None


# ── R57/R58: health from the report's one integrity check ────────────────────────────────────────
def _health_lines(ctx, res):
    from panel.ops.debug_report import diagnostics
    chk = diagnostics.shared_integrity(ctx)
    took = chk.get("took")
    timing = " _(quick_check %.2f s, off-hub)_" % took if isinstance(took, float) else ""
    state = chk.get("state")
    if state == "ok":
        res.add("- **health**: ok%s" % timing)
        return
    if state == "damaged":
        detail = (chk.get("detail") or chk.get("detail_class") or "")[:160]
        res.add("- **health**: DAMAGED: %s · rolling backup: %s%s" % (
            detail or "quick_check failed", chk.get("backup") or "not checked", timing))
        res.find("fail", "Database", "the database is DAMAGED")
        return
    res.add("- **health**: NOT CHECKED: could not be read (%s)%s" % (
        chk.get("detail_class") or "NoAnswer", timing))
    res.find("warn", "Database", "the integrity check could not run")


# ── R59: file, pragmas, backup, moved-aside copies, schema ───────────────────────────────────────
def _pragma_line(prag, res):
    def one(name):
        v = prag.get(name)
        return v[0][0] if isinstance(v, list) and v and v[0] else None
    page, free, mode = one("page_size"), one("freelist_count"), one("journal_mode")
    if page is None or free is None:
        res.add("- **pragmas**: could not be read (%s)" % next(
            (v.split(":", 1)[-1] for v in prag.values() if isinstance(v, str)), "NoAnswer"))
        return
    res.add("- **file** %s · **WAL** %s · journal_mode %s · freelist %d pages (%s reclaimable)" % (
        _size(_db_path()), _size(_db_path() + "-wal"),
        mode if isinstance(mode, str) and mode.isalpha() else "?", free, _mb(free * page)))


def _backup_line(res):
    path = _db_path() + ".backup"
    try:
        st = os.stat(path)
    except FileNotFoundError:
        res.add("- **rolling backup**: none on disk (a corrupt database would start EMPTY)")
        res.find("warn", "Database", "there is no rolling backup")
        return
    except OSError as exc:
        res.add("- **rolling backup**: could not be read (%s)" % type(exc).__name__)
        return
    res.add("- **rolling backup** %s.backup: %s, refreshed at a start (%s, %s ago)" % (
        os.path.basename(_db_path()), _mb(st.st_size),
        time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(st.st_mtime)),
        ago(time.time() - st.st_mtime)))


def _aside_line(res):
    path = _db_path()
    base = os.path.basename(path)
    try:
        names = sorted(n for n in os.listdir(os.path.dirname(path) or ".")
                       if n.startswith(base + ".corrupt-") and _ASIDE_RE.search(n))
    except OSError as exc:
        res.add("- **moved-aside copies**: could not be listed (%s)" % type(exc).__name__)
        return
    if not names:
        res.add("- **moved-aside copies**: none")
        return
    res.add("- **moved-aside copies**: %d (%s): at each, a start found the database damaged and "
            "the self-heal replaced it" % (len(names), ", ".join(names[-_LIST_MAX:])))
    res.find("warn", "Database", "the self-heal has replaced a damaged database before")


def _table_drift(insp, table):
    """(missing 'table.column's, missing declared index names) of one table that exists."""
    cols = {c["name"] for c in insp.get_columns(table.name)}
    idx = {i["name"] for i in insp.get_indexes(table.name)}
    return (["%s.%s" % (table.name, c.name) for c in table.columns if c.name not in cols],
            [i.name for i in table.indexes if i.name and i.name not in idx])


def _schema_drift():
    """(missing tables, missing columns, missing declared indexes, tables lacking AUTOINCREMENT)."""
    from sqlalchemy import inspect
    from panel.db import id_sequence
    from panel.db import models
    insp = inspect(models.db.engine)
    have_tables = set(insp.get_table_names())
    m_tables = [t.name for t in models.db.metadata.sorted_tables if t.name not in have_tables]
    m_cols, m_idx = [], []
    for t in models.db.metadata.sorted_tables:
        if t.name in have_tables:
            cols, idx = _table_drift(insp, t)
            m_cols += cols
            m_idx += idx
    with models.db.engine.connect() as conn:
        lacking = [m.__tablename__ for m in models._AUTOINCREMENT_MODELS
                   if id_sequence.lacks_autoincrement(conn, m.__tablename__)]
    return m_tables, m_cols, m_idx, lacking


def _schema_line(res):
    try:
        drift = _schema_drift()
    except Exception as exc:  # noqa: BLE001 - its own line says so
        res.add("- **schema**: could not be inspected (%s)" % type(exc).__name__)
        return
    labels = ("missing tables", "missing columns", "missing declared indexes",
              "tables lacking AUTOINCREMENT")
    res.add("- **schema**: " + " · ".join(
        "%s %s" % (lab, ", ".join(vals[:_LIST_MAX]) if vals else "none")
        for lab, vals in zip(labels, drift)))
    if any(drift):
        res.find("warn", "Database", "the schema differs from the models (a migration did not run)")


# ── R60: volume and retention ────────────────────────────────────────────────────────────────────
def _census_queries(ip_days):
    q = {"metric_sample": ("SELECT COUNT(*), MIN(ts) FROM metric_sample", ()),
         "host_sample": ("SELECT COUNT(*), MIN(ts) FROM host_sample", ()),
         "audit_log": ("SELECT COUNT(*), MIN(timestamp) FROM audit_log", ())}
    if ip_days and ip_days > 0:
        q["audit_ips"] = (_IPS_SQL, (_sql_time(ip_days * _DAY),))
    return q


def _count_age(rows):
    """(count, oldest age in days or None) from a COUNT(*), MIN(ts) answer."""
    count, oldest = rows[0]
    t = _epoch(oldest)
    return int(count or 0), (None if t is None else (time.time() - t) / _DAY)


def _sample_line(name, rows, keep_days, res):
    if isinstance(rows, str):
        res.add("- **%s**: could not count (%s)" % (name, rows.split(":", 1)[-1]))
        return
    count, age = _count_age(rows)
    ok = age is None or age <= keep_days + 1
    res.add("- **%s** %s rows · oldest %s (retention %d d %s)" % (
        name, format(count, ","), "n/a" if age is None else "%.1f d" % age, keep_days,
        "✓" if ok else "✗"))
    if not ok:
        res.find("warn", "Database", "%s is older than its retention: the prune has not run" % name)


def _audit_line(rows, ip_rows, conf, res):
    if isinstance(rows, str):
        res.add("- **audit_log**: could not count (%s)" % rows.split(":", 1)[-1])
        return
    from panel.core import runtime_stats as rs
    count, age = _count_age(rows)
    keep, ip_days = conf
    if keep is None:
        ret = "audit_log_retention_days is not a number, so nothing is pruned"
    elif keep <= 0:
        ret = "keep forever (audit_log_retention_days unset)"
    else:
        # Applied once at start: allowed to be as old as the retention plus this process's uptime.
        allowed = keep + (time.time() - rs.started()) / _DAY + 1
        ret = "%d d %s" % (keep, "✓" if age is None or age <= allowed else "✗ (not pruned)")
    ips = "IP reduction off" if not ip_days else "IPs reduced after %d d" % ip_days
    if isinstance(ip_rows, list):
        ips += " (%d older rows not reduced)" % int(ip_rows[0][0] or 0)
    res.add("- **audit_log** %s rows · oldest %s · retention: %s · %s" % (
        format(count, ","), "n/a" if age is None else "%.0f d" % age, ret, ips))


# ── R61: the audit digest ────────────────────────────────────────────────────────────────────────
def _digest_queries():
    since = (_sql_time(7 * _DAY),)
    return {"failed": (_FAILED_SQL, since), "netsec": (_NETSEC_SQL, _NETSEC_ACTIONS),
            "origin": (_ORIGIN_SQL, since)}


def _when(ts):
    t = _epoch(ts)
    return "%s ago" % ago(time.time() - t) if t is not None else "?"


def _failed_text(rows):
    return " · ".join("%s ×%s (last %s)" % (a, format(int(n), ","), _when(t))
                      for a, n, t in rows if _ACTION_RE.match(str(a))) or "none recorded"


def _netsec_text(rows):
    return " · ".join("%s %s %s" % (a, _when(t), "ok" if s else "FAILED")
                      for a, t, s in rows if _ACTION_RE.match(str(a))) or "none recorded"


def _origin_text(rows):
    return " · ".join("%s %s" % (o, format(int(n), ",")) for o, n in rows) or "none"


def _digest_line(label, rows, render):
    """One digest line: the rendered rows, or 'could not be read (Class)' -- never 'none'."""
    if isinstance(rows, str):
        return "  - %s: could not be read (%s)" % (label, rows.split(":", 1)[-1])
    return "  - %s: %s" % (label, render(rows or []))


def _digest_lines(got, res):
    res.add("- **Audit log, last 7 days**:")
    res.add(_digest_line("failed actions", got.get("failed"), _failed_text))
    res.add(_digest_line("network & security changes (newest first)", got.get("netsec"),
                         _netsec_text))
    res.add(_digest_line("rows by origin", got.get("origin"), _origin_text))


def _retention_conf():
    from panel.core import config as cfg
    c = cfg.load_config()
    return (_int_cfg(c, "audit_log_retention_days", 0), _int_cfg(c, "audit_ip_retention_days", 90))


def _volume_lines(got, conf, res):
    from panel.services import monitoring
    keep = monitoring._METRIC_RETENTION_DAYS
    _sample_line("metric_sample", got.get("metric_sample"), keep, res)
    _sample_line("host_sample", got.get("host_sample"), keep, res)
    _audit_line(got.get("audit_log"), got.get("audit_ips"), conf, res)


def _guarded(res, label, fn, *args):
    try:
        fn(*args)
    except Exception as exc:  # noqa: BLE001 - one part's failure is printed as such
        res.add("- **%s**: could not be read (%s)" % (label, type(exc).__name__))
        res.find("unread", "Database", "%s could not be read" % label)


def section_database(ctx):
    """The Database section of the report.

    Health from the shared check, the file and its pragmas, the rolling backup and any moved-aside
    copies, schema drift, volume against retention, and the audit digest.
    """
    from panel.ops.debug_report import _src_db
    res = Result()
    _guarded(res, "health", _health_lines, ctx, res)
    try:
        conf = _retention_conf()
    except Exception:  # noqa: BLE001 - unreadable config: said as such on the audit line
        conf = (None, None)
    queries = {"page_size": ("PRAGMA page_size", ()), "freelist_count": ("PRAGMA freelist_count", ()),
               "journal_mode": ("PRAGMA journal_mode", ())}
    queries.update(_census_queries(conf[1]))
    queries.update(_digest_queries())
    got = _src_db.run_ro(queries, timeout=max(1.0, min(10.0, ctx.remaining() - 1.0)))
    _guarded(res, "pragmas", _pragma_line,
             {k: got.get(k) for k in ("page_size", "freelist_count", "journal_mode")}, res)
    for label, fn in (("rolling backup", _backup_line), ("moved-aside copies", _aside_line),
                      ("schema", _schema_line)):
        _guarded(res, label, fn, res)
    _guarded(res, "data volume", _volume_lines, got, conf, res)
    _guarded(res, "audit digest", _digest_lines, got, res)
    return res


# ── R62: panel backups and update snapshots ──────────────────────────────────────────────────────
def _passphrase_state():
    """(level, words) for the backup passphrase: readable or not, never its value.

    Decrypted only when the key file exists: decrypting without it would CREATE a new cred_key.
    """
    from panel.core import config as cfg
    from panel.ops import backup as bk
    if not bk.get_settings().get("encrypt"):
        return "ok", "encryption off"
    if not cfg.CRED_KEY_FILE.exists():
        return "fail", "encryption on, but cred_key is missing, so the passphrase is unreadable"
    try:
        readable = bool(bk.get_passphrase())
    except bk.PassphraseUnreadable:
        readable = False
    if readable:
        return "ok", "encryption on, passphrase readable"
    return "fail", ("encryption on, but the passphrase CANNOT be decrypted with this cred_key, so "
                    "every backup is being refused")


def _settings_line(res):
    from panel.ops import backup as bk
    s = bk.get_settings()
    level, words = _passphrase_state()
    res.add("- **Daily**: %s · keep %s d · %s" % ("enabled" if s.get("enabled") else "OFF",
                                                  s.get("keep_days"), words))
    if level == "fail":
        res.find("fail", "Backups", "the backup passphrase cannot be read: backups are refused")


def _archive_kind(name):
    from panel.ops import backup as bk
    tail = name.rsplit("-", 1)[-1]
    return tail[:-len(".tar.gz" + (bk.ENC_SUFFIX if bk.is_encrypted_backup(name) else ""))]


def _archives(bdir):
    """[(kind, size, mtime)] of the panel's own archives in `bdir` (a glob: no mkdir, no chmod)."""
    from panel.ops import backup as bk
    out = []
    for p in bdir.glob(bk._GLOB):
        if bk._NAME_RE.match(p.name):
            st = p.lstat()
            out.append((_archive_kind(p.name), st.st_size, st.st_mtime))
    return out


def _archives_line(res):
    from panel.ops import backup as bk
    bdir = bk.BACKUP_DIR
    if not bdir.exists():
        res.add("- **Archives**: none (data/backups does not exist yet)")
        return
    try:
        arch = _archives(bdir)
        free = shutil.disk_usage(str(bdir)).free
    except OSError as exc:
        res.add("- **Archives**: could not list data/backups (%s)" % type(exc).__name__)
        return
    newest = max([mt for kind, _sz, mt in arch if kind == "daily"] or [0])
    res.add("- **Archives**: %d (%s) · %s · disk free %.1f GB · newest daily %s" % (
        len(arch), _kinds_text(arch), _mb(sum(sz for _k, sz, _m in arch)), free / 1073741824.0,
        ("%s ago" % ago(time.time() - newest)) if newest else "never"))
    if bk.get_settings().get("enabled") and time.time() - newest > 2 * _DAY:
        res.find("warn", "Backups", "no daily panel backup in the last two days")


def _kinds_text(arch):
    kinds = {}
    for kind, _sz, _mt in arch:
        kinds[kind] = kinds.get(kind, 0) + 1
    return ", ".join("%d %s" % (n, k) for k, n in sorted(kinds.items())) or "none"


_FULL_COUNTS_RE = re.compile(r"^(\d+) server\(s\) backed up(?:, (\d+) failed)?"
                             r"(?:, (\d+) skipped \(players online\))?")
# The installed servers the scheduled sweep backs up (installed, with a host), and what the
# unattended runs recorded. Static SQL; ids and game types only, never a name.
_SCHED_SERVERS_SQL = ("SELECT id, game_type FROM game_server WHERE installed = 1 AND remote_id IS "
                      "NOT NULL AND remote_id != 0 ORDER BY id")
_SCHED_AUDIT_SQL = ("SELECT action, COUNT(*), SUM(CASE WHEN success THEN 1 ELSE 0 END), "
                    "MAX(timestamp) FROM audit_log WHERE action IN ('scheduled_backup', "
                    "'queued_backup', 'scheduled_backup_overdue', 'queued_backup_waiting') "
                    "AND timestamp >= ? GROUP BY action")
# The backups themselves, and the two reports of a backup players kept waiting
# (_shared._report_overdue_skip / _report_long_queue), which are not backups and have their own
# actions so they are not counted as failed ones.
_SCHED_BACKUP_ACTIONS = (("scheduled_backup", "scheduled"), ("queued_backup", "queued"))
_SCHED_REPORT_ACTIONS = (("scheduled_backup_overdue", "reported overdue"),
                         ("queued_backup_waiting", "reported still queued"))
_SCHED_AUDIT_DAYS = 30


def _manual_line(res):
    """The MANUAL "Back up game servers now" run, from COUNTS parsed off its summary's prefix.

    full_backup_last/summary are that button's alone (record_full_backup has no other caller); the
    automatic schedule keeps a clock per server, read by _schedule_lines. This line used to sit
    under the schedule's settings and read "never run" on every install where nobody had pressed
    the button, however many scheduled backups had run. The summary names game servers and
    carries their error text, so it is never printed.
    """
    from panel.ops import backup as bk
    s = bk.get_full_settings()
    head = "- **Manual 'Back up game servers now'**:"
    if not s.get("last"):
        res.add(head + " never run")
        return
    m = _FULL_COUNTS_RE.match(str(s.get("summary") or ""))
    counts = ("%s backed up, %s failed, %s skipped" % (m.group(1), m.group(2) or 0, m.group(3) or 0)
              if m else "outcome not recorded in counts")
    queued = " · some queued for when empty" if "will back up once empty" in str(s.get("summary")) \
        else ""
    res.add(head + " last run %s ago: %s%s" % (ago(time.time() - s["last"]), counts, queued))
    if m and int(m.group(2) or 0):
        res.find("warn", "Backups", "the last manual full backup had failures")


def _sched_row(sid, gtype, sched, now):
    """One server's automatic schedule as (sort key, line, due_at or None)."""
    from panel.ops.debug_report.hosts import game_tok
    every, last = sched["interval_days"], sched["last"]
    words = ["gs %d" % sid, game_tok(gtype)]
    own = " (its own setting)" if sched.get("interval_set") else ""
    if every <= 0:
        return (3, 0), " · ".join(words + ["off%s" % own]), None
    words.append("every %d d%s" % (every, own))
    if not last:
        return (1, 0), " · ".join(words + ["clock not started"]), None
    due_at = last + every * _DAY
    words.append("last %s ago" % ago(now - last))
    if now >= due_at:
        return (0, due_at), " · ".join(words + ["due since %s" % ago(now - due_at)]), due_at
    return (2, last), " · ".join(words + ["next in %s" % ago(due_at - now)]), None


def _ticker_passed(due_at, now):
    """Whether the backup-ticker STARTED a completed pass after `due_at`, more than a cadence ago.

    Gating the warning on the ticker's own heartbeat keeps out what is not a missed backup: a
    report taken just after a restart (the first pass is 2 min in), a server that fell due while
    the panel was down, a pass still archiving other servers one after another.
    """
    from panel.core import runtime_stats as rs
    from panel.ops.debug_report.workers import WORKERS
    hb = rs.snapshot("heartbeat").get("backup-ticker")
    if not isinstance(hb, dict) or now - due_at <= dict(WORKERS)["backup-ticker"]:
        return False
    return hb.get("at", 0) - (hb.get("took") or 0) > due_at


def _schedule_rows(cfg, servers, now):
    from panel.ops import backup as bk
    defaults = bk.full_settings_from(cfg)
    rows = [_sched_row(int(sid), gtype, bk.game_schedule_from(cfg, sid, defaults), now)
            for sid, gtype in servers]
    return sorted(rows, key=lambda r: r[0])


def _schedule_head(cfg):
    from panel.ops import backup as bk
    d = bk.full_settings_from(cfg)
    default = ("default every %d d, keep %d" % (d["interval_days"], d["keep"])
               if d["interval_days"] > 0 else "default: off, keep %d" % d["keep"])
    return "- **Game-server backups, automatic** (%s; each server can override it)" % default


def _schedule_lines(res, servers):
    """The automatic per-server schedule: each installed server's interval and clock (R62).

    One config read for every server: get_game_schedule reads config.json twice per call, a
    deepcopy of the whole file each time. An unreadable config.json is said as such, because the
    sweeps are skipped while it is (_shared._backups_blocked_by_config) and its defaults would
    print every clock as "not started".
    """
    from panel.ops import backup as bk
    cfg = bk.load_config()   # the backup module's own reader: the one the schedule is read with
    if bk.is_unreadable(cfg):
        res.add("- **Game-server backups, automatic**: config.json could not be read, so the "
                "scheduled and queued sweeps are skipped until it can")
        res.find("warn", "Backups", "config.json is unreadable: scheduled game backups are skipped")
        return
    head = _schedule_head(cfg)
    if isinstance(servers, str):
        res.add(head + ": installed servers could not be read (%s)" % servers.split(":", 1)[-1])
        res.find("unread", "Backups", "the installed game servers could not be read")
        return
    if not servers:
        res.add(head + ": no installed game servers")
        return
    _schedule_body(res, head, _schedule_rows(cfg, servers, time.time()))


def _schedule_body(res, head, rows):
    """The schedule's count line, the first _LIST_MAX servers (most overdue first), the finding."""
    now = time.time()
    counts = [sum(1 for r in rows if r[0][0] == k) for k in range(4)]
    res.add(head + ": %d installed · %d due · %d clock not started · %d on schedule · %d off" % (
        len(rows), counts[0], counts[1], counts[2], counts[3]))
    for _key, line, _due in rows[:_LIST_MAX]:
        res.add("  - " + line)
    if len(rows) > _LIST_MAX:
        res.add("  - … and %d more" % (len(rows) - _LIST_MAX))
    missed = sum(1 for r in rows if r[2] is not None and _ticker_passed(r[2], now))
    if missed:
        res.find("warn", "Backups", "%d game server(s) due for a scheduled backup that the "
                 "backup-ticker has passed since without taking (players online, or failing)"
                 % missed)


def _audit_counts(rows):
    known = {a for a, _l in _SCHED_BACKUP_ACTIONS + _SCHED_REPORT_ACTIONS}
    by = {}
    for action, n, ok, newest in rows:
        if action in known:
            by[action] = (int(n or 0), int(ok or 0), newest)
    return by


def _scheduled_audit_line(res, rows):
    """What the unattended runs recorded in the last 30 days: the clocks alone cannot say.

    A clock also moves when it is first started and when a backup fails, so only these audit rows
    (one per unattended backup, success or not) show that backups actually happened.
    """
    head = "- **Unattended game-server backups, last %d d**" % _SCHED_AUDIT_DAYS
    if isinstance(rows, str):
        res.add(head + ": could not be read (%s)" % rows.split(":", 1)[-1])
        return
    by = _audit_counts(rows or [])
    parts = []
    for action, label in _SCHED_BACKUP_ACTIONS:
        if action not in by:
            parts.append("%s: none" % label)
            continue
        n, ok, newest = by[action]
        parts.append("%s: %d ok, %d failed, newest %s" % (label, ok, n - ok, _when(newest)))
    parts += ["%s: %d, newest %s" % (label, by[action][0], _when(by[action][2]))
              for action, label in _SCHED_REPORT_ACTIONS if action in by]
    res.add(head + ": " + " · ".join(parts))


def _schedule_queries():
    return {"sched_servers": (_SCHED_SERVERS_SQL, ()),
            "sched_audit": (_SCHED_AUDIT_SQL, (_sql_time(_SCHED_AUDIT_DAYS * _DAY),))}


def _snapshot_dirs(root):
    """[(stamp, bytes)] of install.sh's update snapshots: one level, lstat only, no symlinks."""
    out = []
    with os.scandir(root) as it:
        for e in it:
            if _STAMP_RE.match(e.name) and e.is_dir(follow_symlinks=False):
                out.append((e.name, _dir_bytes(e.path)))
    return sorted(out)


def _dir_bytes(path):
    total = 0
    try:
        with os.scandir(path) as it:
            for e in it:
                if e.is_file(follow_symlinks=False):
                    total += e.stat(follow_symlinks=False).st_size
    except OSError:
        return None
    return total


def _snapshots_line(res):
    from panel.ops import system_ops as so
    root = os.path.join(so.PANEL_DIR, "data", ".backups")
    try:
        snaps = _snapshot_dirs(root)
    except FileNotFoundError:
        res.add("- **Update snapshots** (data/.backups): none")
        return
    except OSError as exc:
        res.add("- **Update snapshots** (data/.backups): unreadable (%s)" % type(exc).__name__)
        return
    sizes = [b for _s, b in snaps]
    res.add("- **Update snapshots** (data/.backups): %d%s, %s" % (
        len(snaps), (", newest %s (host time)" % snaps[-1][0]) if snaps else "",
        "unreadable size" if None in sizes else _mb(sum(sizes))))


def section_backups(ctx):
    """Panel backups (settings, passphrase readable, archives), game-server backups, snapshots.

    Game-server backups are three lines because there are three things: the automatic schedule
    (a clock per server), what the unattended runs recorded, and the manual full run.
    """
    from panel.ops.debug_report import _src_db
    res = Result()
    got = _src_db.run_ro(_schedule_queries(), timeout=max(1.0, min(10.0, ctx.remaining() - 1.0)))
    for label, part, args in (
            ("settings", _settings_line, ()), ("archives", _archives_line, ()),
            ("game-server schedule", _schedule_lines, (got.get("sched_servers"),)),
            ("unattended game-server backups", _scheduled_audit_line, (got.get("sched_audit"),)),
            ("manual full backup", _manual_line, ()), ("snapshots", _snapshots_line, ())):
        try:
            part(res, *args)
        except Exception as exc:  # noqa: BLE001 - its own line says so
            res.add("- **%s**: could not be read (%s)" % (label, type(exc).__name__))
            res.find("unread", "Backups", "a part could not be read")
    return res
