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

from config import DATA_DIR, DB_PATH, CONFIG_FILE, SECRET_FILE, CRED_KEY_FILE, load_config, save_config

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
    """Resolve `name` to a backup file, or None if it isn't a valid backup name that lives
    directly in BACKUP_DIR (blocks path traversal / arbitrary-file access)."""
    if not name or not _NAME_RE.match(name):
        return None
    p = (BACKUP_DIR / name).resolve()
    if p.parent != BACKUP_DIR.resolve() or not p.is_file():
        return None
    return p


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
    cfg = load_config()
    if enabled is not None:
        cfg["backup_enabled"] = bool(enabled)
    if keep_days is not None:
        try:
            cfg["backup_keep_days"] = max(1, min(365, int(keep_days)))
        except (TypeError, ValueError):
            pass
    save_config(cfg)
    return get_settings()
