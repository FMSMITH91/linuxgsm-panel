#!/usr/bin/env python3
"""Offline SQLite maintenance for the panel database.

Pure stdlib sqlite3 operating directly on the DB *file* — deliberately NO Flask/ORM
import — so two very different callers can share one implementation:

  • install.sh runs `python db_maintenance.py update` with the service STOPPED, as the
    post-snapshot step of an update: health check → repair (only if needed) → optimize →
    health check again. It exits 0 to let the update continue, or 2 to ABORT (the DB
    couldn't be made healthy) so the updater restores the original and stops.
  • the panel imports integrity_check() for its on-demand "check database health" card.

Safety: repair NEVER deletes the original — it copies the flagged file aside first, then
either swaps in a data-preserving rebuild or restores the last-known-good rolling backup.
Every function is best-effort and never raises; each returns a (ok, message) tuple.
"""
import logging
import os
import shutil
import sqlite3
import subprocess  # nosec B404 - only ever invokes the sqlite3 CLI with fixed args
import sys
import time

_log = logging.getLogger("panel.db_maintenance")


def _paths():
    """(db_path, rolling_backup_path) from the panel config. Imported lazily so the module
    stays usable in tests that pass explicit paths without a config on disk."""
    from config import DB_PATH
    p = str(DB_PATH)
    return p, p + ".backup"


def _silent_rm(path):
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        _log.debug("db_maintenance: could not remove %s", path, exc_info=True)


def integrity_check(path):
    """(ok, detail). ok=True when PRAGMA integrity_check reports 'ok'. A missing or empty
    file counts as healthy (a fresh DB will just be created). An unopenable/malformed image
    is NOT healthy. Never raises."""
    try:
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return True, "no database yet"
    except OSError:
        return False, "database file is unreadable"
    try:
        con = sqlite3.connect(path, timeout=15)
        try:
            rows = con.execute("PRAGMA integrity_check").fetchall()
        finally:
            con.close()
    except sqlite3.DatabaseError as e:
        return False, "cannot open database (%s)" % type(e).__name__
    msgs = [str(r[0]) for r in rows] if rows else []
    if msgs == ["ok"]:
        return True, "ok"
    return False, "; ".join(msgs[:10]) or "integrity check failed"


def optimize(path=None):
    """(ok, message) with bytes reclaimed. WAL checkpoint + ANALYZE + VACUUM. Meant to run
    with NO other connection open (the updater stops the service first). VACUUM is atomic —
    a failure leaves the DB exactly as it was. Never raises."""
    if path is None:
        path = _paths()[0]
    try:
        before = os.path.getsize(path)
    except OSError:
        return False, "no database file"

    def _size():
        try:
            return os.path.getsize(path)
        except OSError:
            return before

    try:
        con = sqlite3.connect(path, timeout=60)
        try:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            con.execute("ANALYZE")
            con.execute("VACUUM")
            con.commit()
        finally:
            con.close()
    except sqlite3.DatabaseError as e:
        return False, "optimize failed (%s)" % type(e).__name__
    freed = max(0, before - _size())
    return True, ("reclaimed %s" % _fmt_bytes(freed) if freed else "already compact")


def _fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (int(n), unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024
    return "%d B" % int(n)


def _aside(path):
    """Copy (not move) the flagged DB aside so the original stays in place as the rebuild
    source and as a forensic/recovery copy. Returns the aside path (or '' on failure)."""
    dst = "%s.corrupt-%d" % (path, int(time.time()))
    try:
        shutil.copy2(path, dst)
        return dst
    except OSError:
        return ""


def _rebuild_via_recover(src_path, dst_path):
    """Best salvage: the sqlite3 CLI '.recover' reads the file page-by-page and reconstructs
    what it can — it survives corruption a plain dump can't. Only used when the CLI exists."""
    cli = shutil.which("sqlite3")
    if not cli:
        return False
    # Both calls: fixed `sqlite3` binary (shutil.which), a literal '.recover' subcommand, and
    # config-derived DB paths — no shell, nothing caller/HTTP supplied. Bandit B603 and Semgrep's
    # dangerous-subprocess audit are false positives here (they flag any non-static argv).
    try:
        rec = subprocess.run([cli, src_path, ".recover"], capture_output=True, timeout=600)  # nosec B603  # nosemgrep
        if rec.returncode != 0 or not rec.stdout:
            return False
        load = subprocess.run([cli, dst_path], input=rec.stdout,  # nosec B603  # nosemgrep
                              capture_output=True, timeout=600)
        return load.returncode == 0 and os.path.exists(dst_path) and os.path.getsize(dst_path) > 0
    except (OSError, subprocess.SubprocessError):
        return False


def _rebuild_via_dump(src_path, dst_path):
    """Fallback salvage using Python's iterdump — recovers cleanly readable rows, skipping any
    statement that hits corruption. Handles lighter damage when the CLI isn't installed."""
    try:
        src = sqlite3.connect(src_path, timeout=15)
        dst = sqlite3.connect(dst_path)
        try:
            with dst:
                for line in src.iterdump():
                    try:
                        dst.execute(line)
                    except sqlite3.DatabaseError:
                        # Skip an unrecoverable statement and keep salvaging the rest.
                        _log.debug("db rebuild: skipped an unrecoverable statement", exc_info=True)
        finally:
            src.close()
            dst.close()
        return os.path.exists(dst_path) and os.path.getsize(dst_path) > 0
    except sqlite3.DatabaseError:
        return False


def repair(path=None, backup=None):
    """(ok, message). Data-preserving repair, in order of least data loss:
      1. copy the flagged DB aside (never deleted),
      2. rebuild it (CLI .recover, else iterdump) and, if the rebuilt copy is healthy, swap it in,
      3. else restore the last healthy rolling backup,
      4. else fail (original left in place for manual recovery).
    Never raises."""
    if path is None or backup is None:
        _p, _b = _paths()
        path = path or _p
        backup = backup if backup is not None else _b
    if not os.path.exists(path):
        return False, "no database file to repair"

    aside = _aside(path)
    kept = (" (original kept at %s)" % os.path.basename(aside)) if aside else ""
    tmp = path + ".rebuilt"
    _silent_rm(tmp)
    if _rebuild_via_recover(path, tmp) or _rebuild_via_dump(path, tmp):
        ok, _ = integrity_check(tmp)
        if ok:
            try:
                os.replace(tmp, path)
                for ext in ("-wal", "-shm"):
                    _silent_rm(path + ext)   # stale WAL/SHM must not replay over the rebuilt file
                return True, "rebuilt from recoverable data" + kept
            except OSError:
                _log.debug("db repair: could not swap in the rebuilt DB", exc_info=True)
    _silent_rm(tmp)

    if backup and os.path.exists(backup):
        ok, _ = integrity_check(backup)
        if ok:
            try:
                shutil.copy2(backup, path)
                for ext in ("-wal", "-shm"):
                    _silent_rm(path + ext)
                return True, "restored the last healthy backup" + kept
            except OSError:
                _log.debug("db repair: could not restore the backup", exc_info=True)
    return False, "could not repair — rebuild failed and no healthy backup exists" + kept


def run_update_maintenance():
    """The updater's post-snapshot DB step (service already stopped):
        health check -> repair only if needed -> optimize -> health check again.
    Prints progress for the update log. Returns 0 to CONTINUE the update, 2 to ABORT (the
    database could not be made healthy — the updater then restores the original and stops)."""
    path, backup = _paths()
    try:
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            print("  no database yet — nothing to maintain")
            return 0
    except OSError:
        print("  database file unreadable — aborting to be safe")
        return 2

    ok, detail = integrity_check(path)
    if ok:
        print("  [1/3] health check: ok")
    else:
        print("  [1/3] health check: PROBLEMS FOUND (%s)" % detail)
        print("        repairing (your original is copied aside first)…")
        rok, rmsg = repair(path, backup)
        print("        repair: %s" % rmsg)
        if not rok:
            print("  ABORT: database could not be repaired — leaving your data untouched")
            return 2

    ook, omsg = optimize(path)      # optimize failure is non-fatal — the DB is still healthy
    print("  [2/3] optimize: %s" % omsg)

    fok, fdetail = integrity_check(path)
    if not fok:
        print("  [3/3] health check: STILL UNHEALTHY (%s) — abort" % fdetail)
        return 2
    print("  [3/3] health check: ok")
    return 0


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "check"
    if cmd == "update":
        return run_update_maintenance()
    if cmd == "check":
        ok, detail = integrity_check(_paths()[0])
        print(detail)
        return 0 if ok else 1
    if cmd == "optimize":
        ok, msg = optimize()
        print(msg)
        return 0 if ok else 1
    if cmd == "repair":
        ok, msg = repair()
        print(msg)
        return 0 if ok else 1
    print("usage: db_maintenance.py [update|check|optimize|repair]")
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
