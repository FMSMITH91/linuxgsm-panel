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
    """(db_path, rolling_backup_path).

    panel.conf FIRST, because that is the case this file exists for. install.sh installs a
    root-owned copy of this script at /usr/local/lib/linuxgsm-panel/ and runs it with the SYSTEM
    python — deliberately, so root never executes the panel user's own interpreter or code — and
    writes panel.conf beside it recording `db_path`. Its comment says so: "panel.conf records the
    one path it needs".

    Importing panel.core.config is exactly what CANNOT work there: the panel package is not on the
    system python's path, so every root run raised ModuleNotFoundError. install.sh reported
    "Database maintenance reported a non-fatal issue (rc=1) — continuing" and carried on, which
    means that on the primary (root / system-service) install the pre-update database step never
    ran at all: no integrity check, no refreshed rolling backup, and — the part that matters most —
    the rc=2 branch that ABORTS an update to protect a database it could not repair could never
    fire, because the script died with rc=1 before checking anything. Seen on a real host mid-update.

    The import stays as the fallback for the in-checkout copy (an unprivileged systemd --user
    install runs that one, where panel IS importable and no panel.conf is written)."""
    conf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.conf")
    try:
        with open(conf, encoding="utf-8") as fh:
            for line in fh:
                key, _sep, val = line.partition("=")
                if key.strip() == "db_path" and val.strip():
                    p = val.strip()
                    return p, p + ".backup"
    except OSError:
        pass          # no panel.conf beside us — the checkout copy, handled below
    from panel.core.config import DB_PATH
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
    statement that hits corruption. Handles lighter damage when the CLI isn't installed.

    KEEP WHAT WAS READ. The per-statement guard only wrapped `dst.execute(line)`, and the error a
    corrupt page raises comes from the `src.iterdump()` GENERATOR — so it escaped that guard,
    unwound the `with dst:` (rolling the destination back to empty) and was caught by the outer
    handler as a total failure. Measured on a 169-page database with ONE page corrupted in the
    middle: 1477 statements were readable and zero were kept, the rebuild came out 0 bytes, and
    repair() reported "could not repair".

    That is the case this function exists for. The generator is stepped by hand now, so the
    statements read BEFORE the bad page are committed, and each commit is its own transaction so
    the rollback cannot take them either. It is still only a salvage: the caller runs an integrity
    check on the result and refuses to swap in a rebuild that is not healthy."""
    try:
        src = sqlite3.connect(src_path, timeout=15)
        dst = sqlite3.connect(dst_path)
        kept = 0
        try:
            lines = src.iterdump()
            while True:
                try:
                    line = next(lines)
                except StopIteration:
                    break
                except sqlite3.DatabaseError:
                    # The corrupt page. Everything before it is already committed below.
                    _log.debug("db rebuild: the dump stopped at unreadable data", exc_info=True)
                    break
                try:
                    dst.execute(line)
                    kept += 1
                except sqlite3.DatabaseError:
                    # A statement the destination will not take — skip it and keep salvaging.
                    _log.debug("db rebuild: skipped an unrecoverable statement", exc_info=True)
            dst.commit()
        finally:
            src.close()
            dst.close()
        _log.debug("db rebuild: kept %d statement(s) from the dump", kept)
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
    # NEITHER of these may be a symlink. This function runs as ROOT (panel-helper's
    # panel-db-repair execs it with the system python), and both paths live in the panel's own
    # data/ directory, which the panel user owns. os.path.exists() follows links, shutil.copy2()
    # opens its DESTINATION "wb" and so writes THROUGH one, and `backup` is just
    # `<db_path>.backup` — so pointing panel.db at a root-owned file and putting a valid SQLite
    # database (integrity_check passes; a SQLite file can carry any bytes you like inside a TEXT
    # value) at panel.db.backup made root overwrite that file, and copystat then set its mode.
    # The rebuild branch fails first on a non-database target, which is what routes execution to
    # the copy.
    #
    # lstat, not realpath: the question is whether this exact name is a link, and O_NOFOLLOW is
    # the same question asked by open(). Refusing is right — a symlink here is never something the
    # panel put there.
    for _p, _what in ((path, "database"), (backup, "backup")):
        if _p and os.path.islink(_p):
            return False, "refusing to repair through a symlinked %s path" % _what

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
                # Copy to a temp beside the target and RENAME, rather than copy2 onto the target.
                # os.replace does not follow a symlink at the destination — it replaces the name —
                # so even if the islink check above were ever removed or raced, the write cannot
                # land on whatever the link points at. Same reason the rebuild branch above is
                # safe: it already goes through os.replace.
                _restore_tmp = path + ".restoring"
                _silent_rm(_restore_tmp)
                shutil.copy2(backup, _restore_tmp)
                os.replace(_restore_tmp, path)
                for ext in ("-wal", "-shm"):
                    _silent_rm(path + ext)
                return True, "restored the last healthy backup" + kept
            except OSError:
                _silent_rm(path + ".restoring")
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
        # An explicit DB path makes this runnable WITHOUT importing config — which is what lets the
        # privileged helper run a root-owned copy of this file with the system interpreter, instead
        # of root executing the panel's own checkout. _paths() (and therefore config) is only
        # touched when no path is given, i.e. when a human runs it from the panel directory.
        path = argv[2] if len(argv) > 2 else None
        ok, msg = repair(path, (path + ".backup") if path else None)
        print(msg)
        return 0 if ok else 1
    print("usage: db_maintenance.py [update|check|optimize|repair]")
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
