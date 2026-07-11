"""Panel backup & restore.

A backup is a single .tar.gz of everything needed to bring the panel back exactly as it was:
the SQLite database (a *consistent* snapshot via the sqlite backup API, safe while the panel
is running), config.json, and the two encryption keys (secret_key + cred_key) — without those
keys a restored DB's stored SSH credentials couldn't be decrypted.

Backups live in data/backups/ (dir 0700, files 0600). They contain secrets, so every route
that touches them is superadmin-only, and names are strictly validated to prevent path
traversal. Restore is destructive, so it first takes an automatic pre-restore safety backup,
then swaps the files and restarts the panel from a detached unit that survives the restart.
"""
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time

from config import (DATA_DIR, DB_PATH, CONFIG_FILE, SECRET_FILE, CRED_KEY_FILE,
                    load_config, update_config)

_log = logging.getLogger("panel.backup")

BACKUP_DIR = DATA_DIR / "backups"
# panel-backup-<YYYYMMDD-HHMMSS>-<kind>.tar.gz
_NAME_RE = re.compile(r"^panel-backup-\d{8}-\d{6}-[a-z]+\.tar\.gz$")
_MEMBERS = ("panel.db", "config.json", "secret_key", "cred_key")

DEFAULT_KEEP_DAYS = 14


def _ensure_dir():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(BACKUP_DIR, 0o700)
    except OSError:
        _log.debug("could not chmod backups dir", exc_info=True)


def _safe_path(name):
    """Return the backup file named `name` from BACKUP_DIR, or None. The returned path is taken
    from the directory LISTING — never built from the request — and `name` must basename-match
    one of our strictly-named backups, so nothing outside data/backups can ever be reached."""
    name = os.path.basename(name or "")
    if not _NAME_RE.match(name):
        return None
    for p in BACKUP_DIR.glob("panel-backup-*.tar.gz"):
        if p.name == name and p.is_file():
            return p
    return None


def _snapshot_db(dest):
    """Write a CONSISTENT copy of panel.db to `dest` using SQLite's online-backup API — safe
    even while the panel is mid-write (WAL), unlike a plain file copy."""
    if not os.path.exists(DB_PATH):
        return
    src = sqlite3.connect(str(DB_PATH))
    try:
        dst = sqlite3.connect(str(dest))
        try:
            with dst:
                src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def create_backup(kind="manual"):
    """Create a new backup archive. `kind` is a short lowercase tag (manual/daily/pre-restore).
    Returns (True, name) or (False, message)."""
    kind = re.sub(r"[^a-z]", "", (kind or "manual").lower()) or "manual"
    _ensure_dir()
    name = "panel-backup-%s-%s.tar.gz" % (time.strftime("%Y%m%d-%H%M%S"), kind)
    dest = BACKUP_DIR / name
    tmp = tempfile.mkdtemp(prefix="lgsm-bk-")
    try:
        _snapshot_db(os.path.join(tmp, "panel.db"))
        for src, member in ((CONFIG_FILE, "config.json"), (SECRET_FILE, "secret_key"),
                            (CRED_KEY_FILE, "cred_key")):
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(tmp, member))
        with tarfile.open(dest, "w:gz") as tar:
            for member in _MEMBERS:
                fp = os.path.join(tmp, member)
                if os.path.exists(fp):
                    tar.add(fp, arcname=member)
        os.chmod(dest, 0o600)
        return True, name
    except Exception:
        _log.exception("backup creation failed")
        try:
            os.remove(dest)
        except OSError:
            _log.debug("could not remove partial backup", exc_info=True)
        return False, "Backup failed — see panel logs."
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def list_backups():
    """All backups, newest first: [{name, size, created(epoch), kind}]."""
    _ensure_dir()
    out = []
    for p in BACKUP_DIR.glob("panel-backup-*.tar.gz"):
        if not _NAME_RE.match(p.name):
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        kind = p.name.rsplit("-", 1)[-1][:-len(".tar.gz")]
        out.append({"name": p.name, "size": st.st_size, "created": int(st.st_mtime), "kind": kind})
    out.sort(key=lambda b: b["created"], reverse=True)
    return out


def delete_backup(name):
    p = _safe_path(name)
    if not p:
        return False, "No such backup."
    try:
        p.unlink()
        return True, "Backup deleted."
    except OSError:
        _log.exception("backup delete failed")
        return False, "Could not delete the backup."


def prune_backups(keep_days=None):
    """Remove daily backups older than keep_days (manual/pre-restore backups are kept — the
    user made those deliberately). Returns the number removed."""
    if keep_days is None:
        try:
            keep_days = int(load_config().get("backup_keep_days", DEFAULT_KEEP_DAYS))
        except (TypeError, ValueError):
            keep_days = DEFAULT_KEEP_DAYS
    cutoff = time.time() - max(1, keep_days) * 86400
    removed = 0
    for b in list_backups():
        if b["kind"] == "daily" and b["created"] < cutoff:
            ok, _ = delete_backup(b["name"])
            removed += 1 if ok else 0
    return removed


def daily_backup_tick():
    """Called periodically by the panel's background thread: if daily backups are enabled and
    the newest daily one is >~24h old (or none exists), make one and prune old dailies. Cheap
    no-op otherwise. Returns True if a backup was taken."""
    cfg = load_config()
    if not cfg.get("backup_enabled", True):
        return False
    dailies = [b for b in list_backups() if b["kind"] == "daily"]
    newest = dailies[0]["created"] if dailies else 0
    if time.time() - newest < 23 * 3600:      # ~daily, with slack so a slightly-early tick is fine
        return False
    ok, _ = create_backup("daily")
    if ok:
        prune_backups()
    return ok


def _service_restart_launcher(script_path):
    """systemd-run argv that runs `script_path` DETACHED (survives the panel stop/restart the
    script performs). Mirrors system_ops' service-model detection: per-user vs system unit."""
    user_unit = os.path.expanduser("~/.config/systemd/user/linuxgsm-panel.service")
    system_unit = "/etc/systemd/system/linuxgsm-panel.service"
    if os.path.exists(user_unit) or not os.path.exists(system_unit):
        return ["systemd-run", "--user", "--collect", "/bin/bash", script_path]
    return ["sudo", "systemd-run", "--collect", "/bin/bash", script_path]


def restore_backup(name):
    """Restore a backup: take an automatic pre-restore safety backup, then swap the DB/config/
    keys into place and restart the panel — all from a DETACHED unit so it survives the panel
    stopping. Destructive; returns (ok, message). The panel goes down for a few seconds."""
    src = _safe_path(name)
    if not src:
        return False, "No such backup."
    # Validate the archive up front (members only, no path escapes) before we touch anything.
    try:
        with tarfile.open(src, "r:gz") as tar:
            names = tar.getnames()
        if not names or any(n not in _MEMBERS for n in names):
            return False, "Backup archive looks invalid."
    except Exception:
        _log.exception("backup archive unreadable")
        return False, "Could not read the backup archive."

    create_backup("prerestore")     # safety net before we overwrite the live data

    stage = tempfile.mkdtemp(prefix="lgsm-restore-")
    try:
        with tarfile.open(src, "r:gz") as tar:
            for m in tar.getmembers():
                if m.name in _MEMBERS and m.isfile():
                    tar.extract(m, stage)   # names already whitelisted above
    except Exception:
        _log.exception("backup extract failed")
        shutil.rmtree(stage, ignore_errors=True)
        return False, "Could not extract the backup."

    # STOP the panel first (releases the SQLite file), swap the files, clear the WAL/SHM
    # sidecars (the restored DB is authoritative), then START it again. No `set -e`: even if a
    # copy fails, we must always try to bring the panel back up rather than leave it stopped.
    ufl = "--user " if os.path.exists(os.path.expanduser("~/.config/systemd/user/linuxgsm-panel.service")) else ""
    lines = ["#!/bin/bash", "sleep 1",
             "systemctl %sstop linuxgsm-panel.service || true" % ufl, "sleep 1"]
    for member, target in (("panel.db", DB_PATH), ("config.json", CONFIG_FILE),
                           ("secret_key", SECRET_FILE), ("cred_key", CRED_KEY_FILE)):
        srcf = os.path.join(stage, member)
        if os.path.exists(srcf):
            lines.append('cp -f %s %s || true' % (_sh(srcf), _sh(str(target))))
    lines += [
        'rm -f %s %s' % (_sh(str(DB_PATH) + "-wal"), _sh(str(DB_PATH) + "-shm")),
        "systemctl %sstart linuxgsm-panel.service || true" % ufl,
    ]
    script = os.path.join(str(DATA_DIR), "restore.sh")
    try:
        with open(script, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(script, 0o700)
        subprocess.Popen(_service_restart_launcher(script),
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=os.environ.copy())
        return True, "Restoring from %s — the panel will restart in a few seconds." % name
    except Exception:
        _log.exception("restore dispatch failed")
        return False, "Could not start the restore."


def _sh(s):
    """Minimal single-quote shell escaping for a filesystem path in the restore script."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def get_settings():
    cfg = load_config()
    try:
        keep = int(cfg.get("backup_keep_days", DEFAULT_KEEP_DAYS))
    except (TypeError, ValueError):
        keep = DEFAULT_KEEP_DAYS
    return {"enabled": bool(cfg.get("backup_enabled", True)), "keep_days": max(1, min(365, keep))}


def set_settings(enabled=None, keep_days=None):
    def _mut(cfg):   # update_config: race-safe read-modify-write under the config lock
        if enabled is not None:
            cfg["backup_enabled"] = bool(enabled)
        if keep_days is not None:
            try:
                cfg["backup_keep_days"] = max(1, min(365, int(keep_days)))
            except (TypeError, ValueError):
                _log.debug("ignored invalid keep_days", exc_info=True)
    update_config(_mut)
    return get_settings()


# ── Full backups (game server files, via LinuxGSM's own backup) ──────────────
# Space-heavy, so they run on their own (longer) interval and keep only a few per server.
DEFAULT_FULL_INTERVAL = 7   # days; 0 = off
DEFAULT_FULL_KEEP = 2       # LinuxGSM backups kept per game server


def get_full_settings():
    cfg = load_config()

    def _int(k, d):
        try:
            return int(cfg.get(k, d))
        except (TypeError, ValueError):
            return d
    return {
        "interval_days": max(0, min(365, _int("full_backup_interval_days", DEFAULT_FULL_INTERVAL))),
        "keep": max(1, min(30, _int("full_backup_keep", DEFAULT_FULL_KEEP))),
        "last": _int("full_backup_last", 0),
        "summary": cfg.get("full_backup_summary", ""),
    }


def set_full_settings(interval_days=None, keep=None):
    def _mut(cfg):
        if interval_days is not None:
            try:
                cfg["full_backup_interval_days"] = max(0, min(365, int(interval_days)))
            except (TypeError, ValueError):
                _log.debug("ignored invalid full interval", exc_info=True)
        if keep is not None:
            try:
                cfg["full_backup_keep"] = max(1, min(30, int(keep)))
            except (TypeError, ValueError):
                _log.debug("ignored invalid full keep", exc_info=True)
    update_config(_mut)
    return get_full_settings()


def record_full_backup(summary):
    """Persist the time + one-line summary of the most recent full backup."""
    ts, note = int(time.time()), str(summary)[:300]   # runs in the backup thread → update_config
    update_config(lambda cfg: cfg.update({"full_backup_last": ts, "full_backup_summary": note}))


def full_backup_due():
    """True if scheduled full backups are on and one is due (interval elapsed since the last)."""
    s = get_full_settings()
    if s["interval_days"] <= 0:
        return False
    return time.time() - s["last"] >= s["interval_days"] * 86400


# ── Per-server schedules ─────────────────────────────────────────────────────
# Each game server can override the global default (interval + keep), or inherit it. Overrides
# live in cfg["game_schedules"] keyed by server id; a server's own last-run is tracked there too,
# so scheduled backups are decided (and staggered) per server.
def get_game_schedule(sid):
    """Effective schedule for one server: its override where set, else the global default.
    Returns {interval_days, keep, last, overridden}."""
    cfg = load_config()
    entry = _game_schedules(cfg).get(str(sid))
    if not isinstance(entry, dict):   # tolerate a corrupted config — treat as no override
        entry = {}
    d = get_full_settings()
    has_iv, has_keep = "interval_days" in entry, "keep" in entry

    def _clamp(v, lo, hi, dflt):
        try:
            return max(lo, min(hi, int(v)))
        except (TypeError, ValueError):
            return dflt
    return {
        "interval_days": _clamp(entry["interval_days"], 0, 365, d["interval_days"]) if has_iv else d["interval_days"],
        "keep": _clamp(entry["keep"], 1, 30, d["keep"]) if has_keep else d["keep"],
        "last": _clamp(entry.get("last", 0), 0, 2 ** 63, 0),
        "overridden": has_iv or has_keep,
        "interval_set": has_iv,   # True → this server overrides the interval (else inherits default)
        "keep_set": has_keep,     # True → this server overrides keep
    }


def _game_schedules(cfg):
    """The game_schedules map from config, tolerant of corruption (returns {} if it isn't a dict)."""
    gs = cfg.get("game_schedules")
    return gs if isinstance(gs, dict) else {}


def set_game_schedule(sid, interval_days, keep):
    """Set/clear a server's schedule override. For each of interval_days/keep: a number sets an
    override, None clears it (inherit the global default). The server's last-run is preserved."""
    def _mut(cfg):
        sched = _game_schedules(cfg)
        cfg["game_schedules"] = sched   # normalise a corrupted value back to a dict
        entry = sched.get(str(sid))
        if not isinstance(entry, dict):
            entry = {}
        if interval_days is None:
            entry.pop("interval_days", None)
        else:
            entry["interval_days"] = max(0, min(365, int(interval_days)))
        if keep is None:
            entry.pop("keep", None)
        else:
            entry["keep"] = max(1, min(30, int(keep)))
        if entry:
            sched[str(sid)] = entry
        else:
            sched.pop(str(sid), None)
    update_config(_mut)
    return get_game_schedule(sid)


def remove_game_schedule(sid):
    """Drop a server's schedule entry entirely — used when it's uninstalled, so no stale override
    or last-run lingers in config (and can't be inherited if SQLite later reuses the row id)."""
    def _mut(cfg):
        gs = cfg.get("game_schedules")
        if isinstance(gs, dict):
            gs.pop(str(sid), None)
    update_config(_mut)


def record_game_backup(sid):
    """Mark a server's scheduled backup as just done (updates only that server's last-run)."""
    def _mut(cfg):   # runs after a scheduled backup (background) → update_config
        sched = _game_schedules(cfg)
        cfg["game_schedules"] = sched
        entry = sched.get(str(sid))
        if not isinstance(entry, dict):
            entry = {}
        entry["last"] = int(time.time())
        sched[str(sid)] = entry
    update_config(_mut)


def game_backup_due(sid):
    """True if this server's schedule is enabled (interval > 0) and a backup is due."""
    s = get_game_schedule(sid)
    if s["interval_days"] <= 0:
        return False
    return time.time() - s["last"] >= s["interval_days"] * 86400
