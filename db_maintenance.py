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
import re
import secrets
import shutil
import sqlite3
import stat
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
    # lexists, not exists: exists() FOLLOWS a symlink, so a dangling one planted at a temp name
    # (aimed at a root path that does not exist yet) read as "nothing there", survived this, and
    # the copy that followed wrote through it. os.remove on a link removes the link itself.
    try:
        if path and os.path.lexists(path):
            os.remove(path)
    except OSError:
        _log.debug("db_maintenance: could not remove %s", path, exc_info=True)


# Create-only, never-follow. O_CREAT|O_EXCL fails on ANY existing name, a symlink included (the
# kernel does not follow a link under O_EXCL), so a name planted in data/ before we get there is a
# refusal rather than a destination.
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NEW_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC


def _claim_new(path):
    """Create `path` empty, as a name nothing else holds. True if this call created it."""
    try:
        os.close(os.open(path, _NEW_FILE_FLAGS, 0o600))
        return True
    except OSError:
        return False


def _copy_to_new_file(src, dst):
    """Copy src's bytes into a file this call CREATES at dst (mode 0600). Raises OSError —
    FileExistsError when anything, a symlink included, already holds the name.

    Replaces shutil.copy2 for every copy repair() makes. copy2 opens its destination with
    open(dst, "wb"), which follows a symlink and writes THROUGH it, and copystat() then gives the
    link's target the source's mode. repair() runs as root over the panel user's own data/
    directory, so every destination name there is one that user can plant first."""
    sfd = os.open(src, os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
    try:
        dfd = os.open(dst, _NEW_FILE_FLAGS, 0o600)
        try:
            while True:
                chunk = os.read(sfd, 1 << 20)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    view = view[os.write(dfd, view):]
            os.fsync(dfd)
        except OSError:
            os.close(dfd)
            _silent_rm(dst)
            raise
        os.close(dfd)
    finally:
        os.close(sfd)


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
    source and as a forensic/recovery copy. Returns the aside path (or '' on failure).

    The copy is CREATED, never opened over something already there. The name was
    `<path>.corrupt-<unix time>` written with shutil.copy2 — a name the panel user could predict
    and plant as a symlink (one per second of the window) in its own data/ directory, and a copy
    that writes through a link. Root ran this unconditionally, straight after the symlink checks
    on path and backup, so a single panel-db-repair call wrote panel.db's bytes (chosen by the
    same user) to any root path — /etc/cron.d included. A planted name is now skipped, and the
    fallback names carry a random part so planting cannot exhaust them either."""
    base = "%s.corrupt-%d" % (path, int(time.time()))
    for attempt in range(8):
        dst = base if attempt == 0 else "%s-%s" % (base, secrets.token_hex(4))
        try:
            _copy_to_new_file(path, dst)
            return dst
        except FileExistsError:
            continue
        except OSError:
            return ""
    return ""


# A table name this panel could have created: a plain SQL identifier. SQLite has no parameter
# binding for identifiers, so counting rows per table means building the statement as text — and
# `_row_census` is pointed at a DAMAGED or restored database file, which is not a source whose
# sqlite_master contents should be trusted on sight. Validating the name first means the value
# interpolated below is known-safe by construction rather than merely escaped.
_SAFE_TABLE_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]{0,62}\Z")


def _row_census(path):
    """Total rows across every ordinary table, or None if the file cannot be counted.

    The one question `PRAGMA integrity_check` does not answer. It says whether a file is a
    well-formed SQLite image; this says whether the data is still in it. repair() needs both,
    because a salvage that recovered the schema and a handful of rows is structurally perfect and
    is still the worse of the two candidates when a complete backup exists.

    None means "could not count" and is deliberately NOT zero — a caller comparing candidates must
    be able to tell an empty database from one it failed to read, which is the same distinction the
    rest of this codebase draws for a failed probe. Never raises."""
    try:
        con = sqlite3.connect(path, timeout=15)
        try:
            names = [r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'").fetchall()]
            total = 0
            for name in names:
                if not _SAFE_TABLE_RE.match(name):
                    # Refuse rather than skip. Skipping would UNDERCOUNT, and an undercount here
                    # is the same defect this whole function exists to prevent — repair() would
                    # compare a too-small number against the backup and could discard the fuller
                    # file. "I could not count this" is the honest answer, and the caller already
                    # treats None as "unknown, do not overrule the rebuild".
                    _log.debug("db repair: unexpected table name in %s; not counting", path)
                    return None
                # Still quoted, as defence in depth — the name is already known to hold no quote.
                # The suppressions sit on the lines the scanners report, and they are suppressions
                # of a FALSE positive, not of a risk being accepted: SQLite has no parameter
                # binding for identifiers, `name` has just been matched against _SAFE_TABLE_RE
                # ([A-Za-z_][A-Za-z0-9_]*), and sqlite3's execute() runs exactly one statement per
                # call, so neither a quote nor a statement separator can reach the query.
                _count_sql = 'SELECT COUNT(*) FROM "%s"' % name  # nosec B608  # nosemgrep - validated identifier
                total += con.execute(_count_sql).fetchone()[0]  # nosec B608  # nosemgrep - validated identifier
            return total
        finally:
            con.close()
    except (sqlite3.DatabaseError, OSError):
        _log.debug("db repair: could not count rows in %s", path, exc_info=True)
        return None


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
    _restored_note = ""     # set when the rebuild was measurably worse than the backup
    _silent_rm(tmp)
    # Split, with a _silent_rm between. These were `A(path, tmp) or B(path, tmp)`, so when the
    # .recover attempt failed AFTER creating tmp, the iterdump attempt opened that same partial
    # file: its CREATE TABLE statements then fail as "table already exists", get skipped by the
    # salvage loop, and the rows that belong to them land nowhere. The same _silent_rm(tmp) already
    # brackets this block on both sides.
    #
    # Each attempt starts from a file THIS call created (_claim_new: O_EXCL|O_NOFOLLOW), not from
    # whatever the name held. sqlite opens its database path following links, so a symlink left at
    # panel.db.rebuilt was a destination for the salvaged output. A name that cannot be claimed is
    # a skipped rebuild, and the backup branch below still runs.
    _rebuilt = _claim_new(tmp) and _rebuild_via_recover(path, tmp)
    if not _rebuilt:
        _silent_rm(tmp)
        _rebuilt = _claim_new(tmp) and _rebuild_via_dump(path, tmp)
    if _rebuilt:
        ok, _ = integrity_check(tmp)
        if ok:
            # "Least data loss" is the docstring's promise, and nothing measured it. Both tests
            # above are STRUCTURAL: _rebuild_via_dump returns on `os.path.getsize(dst) > 0` and
            # integrity_check asks PRAGMA integrity_check — "is this a well-formed SQLite file",
            # not "does it still hold the data". A rebuild that salvaged the schema and almost
            # nothing else passes both, and the backup branch below is only reached when the
            # rebuild fails ENTIRELY, so the healthy rolling backup was never even consulted.
            #
            # Measured, in a temp dir, against a 4000-row table with one early data page
            # overwritten and a complete backup on disk: repair() reported
            # "rebuilt from recoverable data" and swapped in a database holding 17 of 4000 rows,
            # while panel.db.backup still had all 4000. The loss then becomes permanent — the
            # panel restarts straight after a repair, and _ensure_db_healthy refreshes the rolling
            # backup FROM the gutted file on that next boot.
            #
            # So compare them and take the fuller one. A census that cannot be read answers None,
            # and an unknown does not get to overrule the rebuild — that keeps the previous
            # behaviour for every case this can no longer measure.
            _rebuilt_rows = _row_census(tmp)
            _backup_rows = _row_census(backup) if (backup and os.path.exists(backup)) else None
            _prefer_backup = (_rebuilt_rows is not None and _backup_rows is not None
                              and _backup_rows > _rebuilt_rows
                              and integrity_check(backup)[0])
            if _prefer_backup:
                _log.debug("db repair: backup holds %d row(s) vs %d rebuilt — restoring the backup",
                           _backup_rows, _rebuilt_rows)
                _silent_rm(tmp)
                _restored_note = (" (restored the rolling backup: %d row(s), against %d salvaged "
                                  "from the damaged file)" % (_backup_rows, _rebuilt_rows))
            else:
                try:
                    os.replace(tmp, path)
                    for ext in ("-wal", "-shm"):
                        _silent_rm(path + ext)   # stale WAL/SHM must not replay over the rebuild
                    _n = "" if _rebuilt_rows is None else (" (%d row(s) recovered)" % _rebuilt_rows)
                    return True, "rebuilt from recoverable data" + _n + kept
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
                #
                # The temp itself is CREATED (_copy_to_new_file), not copy2'd over: copy2 wrote
                # through a symlink planted at panel.db.restoring, and _silent_rm used to leave a
                # DANGLING one in place because exists() follows it.
                _restore_tmp = path + ".restoring"
                _silent_rm(_restore_tmp)
                _copy_to_new_file(backup, _restore_tmp)
                os.replace(_restore_tmp, path)
                for ext in ("-wal", "-shm"):
                    _silent_rm(path + ext)
                return True, "restored the last healthy backup" + _restored_note + kept
            except OSError:
                _silent_rm(path + ".restoring")
                _log.debug("db repair: could not restore the backup", exc_info=True)
    return False, "could not repair — rebuild failed and no healthy backup exists" + kept


def run_update_maintenance(path=None, backup=None):
    """The updater's post-snapshot DB step (service already stopped):
        health check -> repair only if needed -> optimize -> health check again.
    Prints progress for the update log. Returns 0 to CONTINUE the update, 2 to ABORT (the
    database could not be made healthy — the updater then restores the original and stops)."""
    if path is None:
        path, backup = _paths()
    elif backup is None:
        backup = path + ".backup"
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


def _euid():
    return os.geteuid()


def _become(uid, gid):
    """Drop to uid/gid for good: no supplementary groups, and real, effective and saved ids all
    changed, so nothing later in this process can take root back."""
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def _confine_to_db_dir(path):
    """ROOT ONLY. Pin the database's directory, become the account that owns it, and work from
    inside it. Returns (name, why): `name` is the database's name relative to the new working
    directory, or None with `why` saying why that could not be done safely.

    Every file this module creates or opens sits in the panel's data/ directory, which the panel
    user owns — and this runs as root twice: panel-helper's panel-db-repair, and install.sh's
    update step (which that same user can start through panel-self-update). Refusing a symlink at
    each name cannot make that safe. sqlite itself opens the -wal and -shm companions, and the
    database path, following links, and a name checked a moment ago can be swapped before it is
    used. So root does none of the file work: it becomes the directory's owner, and then every
    create, copy and rename happens with exactly the access that account already had. The
    directory is pinned by descriptor first (O_NOFOLLOW, then fchdir), so renaming it or putting
    a symlink where it was afterwards changes nothing about where this process is working.

    A root-owned directory stays root's, since nothing below root can plant a name in it unless
    its mode lets group or others write — and that is refused."""
    d = os.path.dirname(os.path.abspath(path))
    try:
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW | _CLOEXEC)
    except FileNotFoundError:
        return None, "missing"
    except OSError as e:
        return None, "cannot open the database directory safely (%s)" % type(e).__name__
    try:
        st = os.fstat(fd)
        if st.st_uid == 0:
            if st.st_mode & 0o022:
                return None, "the database directory is writable by accounts other than root"
        else:
            try:
                import pwd
                gid = pwd.getpwuid(st.st_uid).pw_gid
            except (ImportError, KeyError):
                gid = st.st_gid
            _reclaim_db_files(fd, os.path.basename(path), st.st_uid, gid)
            try:
                _become(st.st_uid, gid)
            except OSError as e:
                return None, "could not drop to the database's owner (%s)" % type(e).__name__
        os.fchdir(fd)
    finally:
        os.close(fd)
    return os.path.basename(path), ""


def _reclaim_db_files(dir_fd, name, uid, gid):
    """Give the database's own files back to the directory's owner before dropping to it.

    Earlier versions ran the whole repair as root, and a database it rebuilt or restored came out
    root-owned (sqlite and shutil.copy2 create as the caller) — one the panel service cannot write,
    or, restored from a 0600 backup, cannot even read. Dropping to the owner without this would turn
    that leftover into an update that ABORTS on a database the owner can no longer open.

    Each file is opened by descriptor with O_NOFOLLOW and fchown'd only if it is a regular file with
    ONE link: a symlink is refused at open, and a second link would mean the inode is also some
    other file's, which must not change hands."""
    for member in (name, name + "-wal", name + "-shm", name + ".backup"):
        try:
            mfd = os.open(member, os.O_RDONLY | _NOFOLLOW | _CLOEXEC | getattr(os, "O_NONBLOCK", 0),
                          dir_fd=dir_fd)
        except OSError:
            continue          # absent, a symlink, or unopenable: nothing to reclaim here
        try:
            mst = os.fstat(mfd)
            if stat.S_ISREG(mst.st_mode) and mst.st_nlink == 1 and mst.st_uid != uid:
                os.fchown(mfd, uid, gid)
        except OSError:
            _log.debug("db_maintenance: could not reclaim %s", member, exc_info=True)
        finally:
            os.close(mfd)


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "check"
    if cmd not in ("update", "check", "optimize", "repair"):
        print("usage: db_maintenance.py [update|check|optimize|repair]")
        return 64
    # An explicit DB path makes repair runnable WITHOUT importing config — which is what lets the
    # privileged helper run a root-owned copy of this file with the system interpreter, instead
    # of root executing the panel's own checkout. _paths() (and therefore config) is only
    # touched when no path is given, i.e. when a human runs it from the panel directory.
    if cmd == "repair" and len(argv) > 2:
        path = argv[2]
    else:
        path = _paths()[0]
    if _euid() == 0:
        name, why = _confine_to_db_dir(path)
        if name is None:
            if why == "missing":
                print("no database yet — nothing to maintain")
                return 0 if cmd in ("update", "check") else 1
            print("refusing: %s" % why)
            return 1
        path = name
    backup = path + ".backup"
    if cmd == "update":
        return run_update_maintenance(path, backup)
    if cmd == "check":
        ok, detail = integrity_check(path)
        print(detail)
        return 0 if ok else 1
    if cmd == "optimize":
        ok, msg = optimize(path)
        print(msg)
        return 0 if ok else 1
    ok, msg = repair(path, backup)
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
