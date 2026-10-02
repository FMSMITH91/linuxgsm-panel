"""Part 10 of the unit suite. Imported for its side effects.

The failure paths of the four modules behind the panel's own backup/restore and host maintenance:
db_maintenance.py, panel/ops/backup.py, panel/routes/panel_backup.py and panel/ops/system_ops.py.
Each check asserts what the code RETURNS, WRITES, SENDS or REFUSES — the branches a green run never
reached were overwhelmingly the ones where a read failed or a command answered non-zero, which is
where this codebase's worst bugs have lived (a failed read taken as a measurement).

House rules kept here, because they are what makes a check in this file mean anything:
  * every stub is saved and restored in a `finally`, on the module that DEFINES the name;
  * nothing reaches a network, an SSH host or a real privileged command — _run, _run_verb and
    subprocess are stubbed on the module under test, and every filesystem path is a temp dir;
  * a call under test is wrapped (_p7_call) so a regression is a FAIL naming the check, not an
    exception that takes the rest of the suite down with it.
"""
import base64 as _p7_b64
import contextlib as _p7_ctx
import io as _p7_io
import os
import shutil as _p7_sh
import sqlite3 as _p7_sq
import subprocess as _p7_sp  # nosec B404 - the suite's stubs, and its own fixed argv
import sys
import tempfile as _p7_tf

from unit.part01 import (SO, check, eq, skip)  # noqa: F401,E402

# The failure paths below log what they are built to log (a traceback per refused restore, per
# failed launch...). Silenced for this part so the suite's output stays the checks; the lines that
# log still execute. Put back as found at the end of the file.
import logging as _p7_logging  # noqa: E402
_p7_quiet = {_n: _p7_logging.getLogger(_n).disabled
             for _n in ("panel.backup", "panel.db_maintenance", "panel.system_ops")}
for _n in _p7_quiet:
    _p7_logging.getLogger(_n).disabled = True


class _Over:
    """Stand-in for a MODULE object, with the named attributes replaced.

    Every other attribute is the real module's. Assigned onto the module under test
    (`_dbm7.os = _Over(os, replace=...)`), so only that module sees the override — the
    process-wide `os` is never touched.
    """

    def __init__(self, real, **over):
        self._real = real
        self.__dict__.update(over)

    def __getattr__(self, name):
        return getattr(self._real, name)


def _p7_call(fn, *a, **k):
    """fn(*a, **k), or 'raised <Type>: <msg> at <file>:<line>' if it raised — so a check fails by name.

    The location is the INNERMOST frame, where the exception was raised. Without it, CI on
    Python 3.10 and 3.12 reported only "raised TypeError: can't concat str to bytearray", and
    nothing in that says the error came from inside subprocess.py (a green os.read handed
    back '' where bytes were expected), not from the code under test.
    """
    try:
        return fn(*a, **k)
    except Exception as e:  # noqa: BLE001 - recorded as the failure detail
        tb = e.__traceback__
        while tb.tb_next is not None:
            tb = tb.tb_next
        return "raised %s: %s at %s:%d" % (type(e).__name__, e, tb.tb_frame.f_code.co_filename,
                                           tb.tb_lineno)


def _p7_out(fn, *a, **k):
    """(return value, captured stdout) of fn(*a, **k); an exception is returned as a string."""
    buf = _p7_io.StringIO()
    with _p7_ctx.redirect_stdout(buf):
        rv = _p7_call(fn, *a, **k)
    return rv, buf.getvalue()


def _p7_raise(exc):
    def _r(*a, **k):
        raise exc
    return _r


# ══ db_maintenance.py ════════════════════════════════════════════════════════════════════════════
# The updater's pre-update database step and the root-run repair. Everything here happens in a temp
# dir; _paths() is stubbed wherever a call would otherwise resolve the checkout's own data/panel.db.
import db_maintenance as _dbm7  # noqa: E402
from eventlet import patcher as _p7_patcher  # noqa: E402

_d7 = _p7_tf.mkdtemp(prefix="p7-dbm-")


def _p7_db(path, tables=(("t", 40),)):
    c = _p7_sq.connect(path)
    try:
        for name, rows in tables:
            c.execute("CREATE TABLE %s (id INTEGER PRIMARY KEY, v TEXT)" % name)
            c.executemany("INSERT INTO %s (v) VALUES (?)" % name, [("x" * 80,) for _ in range(rows)])  # nosec B608 - the test's table name
        c.commit()
    finally:
        c.close()
    return path


def _p7_rows(path, table="t"):
    try:
        c = _p7_sq.connect(path)
        try:
            return c.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0]  # nosec B608 - the test's table name
        finally:
            c.close()
    except _p7_sq.DatabaseError:
        return None


def _p7_garbage(path, n=9000):
    with open(path, "wb") as f:
        f.write(b"\x13\x37" * (n // 2))
    return path


_dbm7_saved = {k: getattr(_dbm7, k) for k in (
    "os", "sqlite3", "shutil", "subprocess", "_paths", "_euid", "_become", "repair",
    "integrity_check", "optimize", "run_update_maintenance", "_copy_to_new_file",
    "_reclaim_db_files")}


@_p7_ctx.contextmanager
def _p7_real_os_read():
    """Inside the block, db_maintenance reads through the unpatched os.read (see _aside below)."""
    _dbm7.os = _Over(os, read=_p7_patcher.original("os").read)
    try:
        yield
    finally:
        _dbm7.os = _dbm7_saved["os"]


def _dbm7_fmt_bytes_unit_ladder():
    # ── _fmt_bytes: the unit ladder, and the GB cap (it never falls through to "B")
    eq("dbm/_fmt_bytes: B, KB, MB, and GB is the ceiling",
       [_dbm7._fmt_bytes(n) for n in (0, None, 1023, 1536, 3 * 1024 ** 2, 5 * 1024 ** 4)],
       ["0 B", "0 B", "1023 B", "1.5 KB", "3.0 MB", "5120.0 GB"])


def _dbm7_optimize():
    # ── optimize()
    global _c, _cmp
    _big = _p7_db(os.path.join(_d7, "big.db"), (("t", 3000),))
    _c = _p7_sq.connect(_big)
    _c.execute("DELETE FROM t")
    _c.commit()
    _c.close()
    _big_before = os.path.getsize(_big)
    _opt = _p7_call(_dbm7.optimize, _big)
    check("dbm/optimize: VACUUM after a mass delete reports the bytes it reclaimed",
          isinstance(_opt, tuple) and _opt[0] is True and _opt[1].startswith("reclaimed ")
          and _opt[1].endswith(" KB") and os.path.getsize(_big) < _big_before,
          "%r size %d -> %d" % (_opt, _big_before, os.path.getsize(_big)))
    eq("dbm/optimize: a file that is not a database fails, naming the error class",
       _p7_call(_dbm7.optimize, _p7_garbage(os.path.join(_d7, "junk.db"))),
       (False, "optimize failed (DatabaseError)"))
    eq("dbm/optimize: a missing file is 'no database file', not a success",
       _p7_call(_dbm7.optimize, os.path.join(_d7, "absent.db")), (False, "no database file"))
    # path=None reads _paths(): the same call answers differently depending only on what it names.
    _dbm7._paths = lambda: (os.path.join(_d7, "absent.db"), "")
    _o_none_missing = _p7_call(_dbm7.optimize)
    _dbm7._paths = lambda: (_big, _big + ".backup")
    _o_none_present = _p7_call(_dbm7.optimize)
    _dbm7._paths = _dbm7_saved["_paths"]
    check("dbm/optimize: with no path it optimises the database _paths() names",
          _o_none_missing == (False, "no database file") and isinstance(_o_none_present, tuple)
          and _o_none_present[0] is True, "%r / %r" % (_o_none_missing, _o_none_present))
    # The size read AFTER the vacuum failing must not invent a saving: it falls back to `before`.
    _cmp = _p7_db(os.path.join(_d7, "cmp.db"))
    _gs_calls = {"n": 0}

    def _p7_getsize_once(p):
        _gs_calls["n"] += 1
        if _gs_calls["n"] > 1:
            raise OSError("gone")
        return os.path.getsize(p)
    _dbm7.os = _Over(os, path=_Over(os.path, getsize=_p7_getsize_once))
    try:
        _o_sz = _p7_call(_dbm7.optimize, _cmp)
    finally:
        _dbm7.os = _dbm7_saved["os"]
    eq("dbm/optimize: an unreadable size after VACUUM claims no saving", _o_sz, (True, "already compact"))


def _dbm7_integrity_check_failed_read():
    # ── integrity_check(): a failed read is never "healthy"
    _dbm7.os = _Over(os, path=_Over(os.path, exists=lambda p: True,
                                    getsize=_p7_raise(PermissionError("denied"))))
    try:
        _ic_unread = _p7_call(_dbm7.integrity_check, os.path.join(_d7, "whatever.db"))
    finally:
        _dbm7.os = _dbm7_saved["os"]
    eq("dbm/integrity: a database whose size cannot be read is NOT healthy",
       _ic_unread, (False, "database file is unreadable"))

    class _P7Con:
        def __init__(self, rows):
            self.rows = rows

        def execute(self, _sql):
            return self

        def fetchall(self):
            return self.rows

        def close(self):
            pass

    _dbm7.sqlite3 = _Over(_p7_sq, connect=lambda *a, **k: _P7Con([("err %d" % i,) for i in range(12)]))
    try:
        _ic_many = _p7_call(_dbm7.integrity_check, _cmp)
        _dbm7.sqlite3 = _Over(_p7_sq, connect=lambda *a, **k: _P7Con([]))
        _ic_none = _p7_call(_dbm7.integrity_check, _cmp)
    finally:
        _dbm7.sqlite3 = _dbm7_saved["sqlite3"]
    eq("dbm/integrity: problems are reported, capped at the first ten",
       _ic_many, (False, "; ".join("err %d" % i for i in range(10))))
    eq("dbm/integrity: an EMPTY pragma answer is a failure, not an 'ok'",
       _ic_none, (False, "integrity check failed"))


def _dbm7_aside_forensic_copy():
    # ── _aside(): the forensic copy
    # A source that opens but cannot be READ (a directory) fails mid-copy: nothing may be left at
    # the destination name, or the next repair would find a half-written ".corrupt-" file.
    #
    # Read through the REAL os.read, the one production runs: db_maintenance is its own process
    # (install.sh, panel-helper) and never runs under eventlet, but this suite is monkey-patched,
    # and eventlet's green os.read waits on the hub for any fd that is not a regular file. For a
    # directory, epoll refuses the fd (EPERM) AFTER the hub has filed a read listener for the
    # suite's own greenlet, and the trampoline raises before the `try` that would remove it. So
    # this check left that listener behind; repair()'s own _aside, four checks on, reopened the fd
    # number, which turned it into a pending IOClosed; and the hub threw that into the next thing
    # the suite waited on — the sqlite3 CLI's subprocess in the swap check below, where the green
    # os.read answered '' to Popen's bytearray. TypeError on Python 3.10 and 3.12; on 3.13+ an
    # OSError that silently aborted the .recover rebuild. The real read raises EISDIR.
    _asrc = os.path.join(_d7, "adir")
    os.mkdir(_asrc)
    with _p7_real_os_read():
        _a_res = _p7_call(_dbm7._aside, _asrc)
    _a_left = [n for n in os.listdir(_d7) if n.startswith("adir.corrupt-")]
    check("dbm/aside: a copy that fails mid-way answers '' and leaves no partial file",
          _a_res == "" and not _a_left, "res=%r left=%r" % (_a_res, _a_left))
    # Every candidate name taken: eight attempts, the first the plain name, the rest randomised.
    _a_tried = []

    def _p7_taken(src, dst):
        _a_tried.append(dst)
        raise FileExistsError(dst)
    _dbm7._copy_to_new_file = _p7_taken
    try:
        _a_all = _p7_call(_dbm7._aside, os.path.join(_d7, "x.db"))
    finally:
        _dbm7._copy_to_new_file = _dbm7_saved["_copy_to_new_file"]
    check("dbm/aside: when every name is planted it tries eight distinct names, then gives up",
          _a_all == "" and len(_a_tried) == 8 and len(set(_a_tried)) == 8
          and all(t.startswith(_a_tried[0] + "-") for t in _a_tried[1:]),
          "res=%r tried=%r" % (_a_all, _a_tried[:3]))


def _dbm7_silent_rm_claim_new():
    # ── _silent_rm / _claim_new: a name that cannot be cleared or claimed skips the rebuild
    _sr_dir = os.path.join(_d7, "not-removable")
    os.mkdir(_sr_dir)
    _sr_res = _p7_call(_dbm7._silent_rm, _sr_dir)
    check("dbm/_silent_rm: a name it cannot remove is left, and nothing raises",
          _sr_res is None and os.path.isdir(_sr_dir), repr(_sr_res))
    eq("dbm/_claim_new: an existing name is not claimed", _dbm7._claim_new(_sr_dir), False)
    _plant = _p7_garbage(os.path.join(_d7, "plant.db"))
    _p7_db(_plant + ".backup", (("t", 7),))
    os.mkdir(_plant + ".rebuilt")                  # the rebuild's temp name, unremovable
    _pl_res = _p7_call(_dbm7.repair, _plant, _plant + ".backup")
    check("dbm/repair: an unclaimable .rebuilt name skips the rebuild and restores the backup",
          isinstance(_pl_res, tuple) and _pl_res[0] is True
          and _pl_res[1].startswith("restored the last healthy backup")
          and _p7_rows(_plant) == 7 and os.path.isdir(_plant + ".rebuilt"),
          "%r rows=%r" % (_pl_res, _p7_rows(_plant)))

    eq("dbm/repair: a path with no file is refused",
       _p7_call(_dbm7.repair, os.path.join(_d7, "nothing-here.db"), ""),
       (False, "no database file to repair"))


def _dbm7_repair_swap_itself_fails():
    # ── repair() when the swap itself fails: the original stays, and no temp is left behind
    # The rebuild is forced down the iterdump path (no sqlite3 CLI), as the _rebuild_via_recover
    # checks below stub it: this is about os.replace failing, and must not depend on whether the
    # machine has the CLI, nor run a real subprocess to find out.
    _sw = _p7_db(os.path.join(_d7, "swap.db"), (("t", 30),))
    _p7_db(_sw + ".backup", (("t", 30),))
    _dbm7.os = _Over(os, replace=_p7_raise(OSError("EXDEV")))
    _dbm7.shutil = _Over(_p7_sh, which=lambda n: None)
    try:
        _sw_res = _p7_call(_dbm7.repair, _sw, _sw + ".backup")
    finally:
        _dbm7.os, _dbm7.shutil = _dbm7_saved["os"], _dbm7_saved["shutil"]
    check("dbm/repair: when neither the rebuild nor the backup can be swapped in, it says so",
          isinstance(_sw_res, tuple) and _sw_res[0] is False
          and _sw_res[1].startswith("could not repair"), repr(_sw_res))
    check("dbm/repair: ...the original database is untouched",
          _p7_rows(_sw) == 30 and _dbm7.integrity_check(_sw)[0], "rows=%r" % _p7_rows(_sw))
    check("dbm/repair: ...and neither temp (.rebuilt, .restoring) is left beside it",
          not os.path.lexists(_sw + ".rebuilt") and not os.path.lexists(_sw + ".restoring"),
          repr(sorted(n for n in os.listdir(_d7) if n.startswith("swap.db."))))


def _dbm7_rebuild_via_recover_sqlite3():
    # ── _rebuild_via_recover: the sqlite3 CLI path, driven with a stubbed CLI
    _rv_calls = []

    def _p7_mk_run(rec_rc, rec_out, load_rc, write_dst=True, raise_exc=None):
        def _run(argv, **kw):
            _rv_calls.append((list(argv), kw.get("input")))
            if raise_exc is not None:
                raise raise_exc
            if argv[-1] == ".recover":
                return _p7_sp.CompletedProcess(argv, rec_rc, rec_out, b"")
            if write_dst:
                with open(argv[1], "wb") as f:
                    f.write(b"SQLite format 3\x00" + b"\x00" * 100)
            return _p7_sp.CompletedProcess(argv, load_rc, b"", b"")
        return _run

    _rv_src, _rv_dst = os.path.join(_d7, "rv-src.db"), os.path.join(_d7, "rv-dst.db")
    try:
        _dbm7.shutil = _Over(_p7_sh, which=lambda n: None)
        _dbm7.subprocess = _Over(_dbm7_saved["subprocess"], run=_p7_mk_run(0, b"x", 0))
        _rv_nocli = _p7_call(_dbm7._rebuild_via_recover, _rv_src, _rv_dst)
        check("dbm/recover: without the sqlite3 CLI it declines, and runs nothing",
              _rv_nocli is False and not _rv_calls, "res=%r calls=%r" % (_rv_nocli, _rv_calls))
        _dbm7.shutil = _Over(_p7_sh, which=lambda n: "/opt/p7/sqlite3")
        _rv_ok = _p7_call(_dbm7._rebuild_via_recover, _rv_src, _rv_dst)
        eq("dbm/recover: .recover's output is piped into a load of the destination",
           (_rv_ok, _rv_calls), (True, [(["/opt/p7/sqlite3", _rv_src, ".recover"], None),
                                        (["/opt/p7/sqlite3", _rv_dst], b"x")]))
        os.remove(_rv_dst)
        _dbm7.subprocess = _Over(_dbm7_saved["subprocess"], run=_p7_mk_run(0, b"x", 1))
        eq("dbm/recover: a load that exits non-zero is a failed rebuild, even with a file written",
           _p7_call(_dbm7._rebuild_via_recover, _rv_src, _rv_dst), False)
        os.remove(_rv_dst)
        _dbm7.subprocess = _Over(_dbm7_saved["subprocess"], run=_p7_mk_run(0, b"x", 0, write_dst=False))
        eq("dbm/recover: a load that leaves no database is a failed rebuild",
           _p7_call(_dbm7._rebuild_via_recover, _rv_src, _rv_dst), False)
        _dbm7.subprocess = _Over(_dbm7_saved["subprocess"],
                                 run=_p7_mk_run(0, b"x", 0, raise_exc=_p7_sp.TimeoutExpired("sqlite3", 600)))
        eq("dbm/recover: a CLI that times out is a failed rebuild, not an exception",
           _p7_call(_dbm7._rebuild_via_recover, _rv_src, _rv_dst), False)
    finally:
        _dbm7.shutil, _dbm7.subprocess = _dbm7_saved["shutil"], _dbm7_saved["subprocess"]


def _dbm7_rebuild_via_dump_statement():
    # ── _rebuild_via_dump: a statement the destination refuses is skipped, not fatal
    global _c
    _dp_src = _p7_db(os.path.join(_d7, "dump-src.db"), (("t", 5), ("u", 7)))
    _dp_dst = os.path.join(_d7, "dump-dst.db")
    _c = _p7_sq.connect(_dp_dst)
    _c.execute("CREATE TABLE t (only_one_column TEXT)")    # t's CREATE and INSERTs will be refused
    _c.commit()
    _c.close()
    _dp_res = _p7_call(_dbm7._rebuild_via_dump, _dp_src, _dp_dst)
    check("dbm/dump: statements the destination refuses are skipped and the salvage continues",
          _dp_res is True and _p7_rows(_dp_dst, "u") == 7 and _p7_rows(_dp_dst, "t") == 0,
          "res=%r u=%r t=%r" % (_dp_res, _p7_rows(_dp_dst, "u"), _p7_rows(_dp_dst, "t")))
    _dp_dir = os.path.join(_d7, "dump-into-a-dir")
    os.mkdir(_dp_dir)
    eq("dbm/dump: a destination sqlite cannot open is a failed rebuild, not an exception",
       _p7_call(_dbm7._rebuild_via_dump, _dp_src, _dp_dir), False)


def _dbm7_run_update_maintenance_updater():
    # ── run_update_maintenance: the updater's continue (0) / abort (2) decision
    global _ru_fix, _ru_good, _ru_out, _ru_rc, f
    _ru_good = _p7_db(os.path.join(_d7, "ru-good.db"))
    _ru_rc, _ru_out = _p7_out(_dbm7.run_update_maintenance, _ru_good)
    check("dbm/update: a healthy database continues the update, through all three steps",
          _ru_rc == 0 and "[1/3] health check: ok" in _ru_out and "[2/3] optimize:" in _ru_out
          and "[3/3] health check: ok" in _ru_out, "rc=%r out=%r" % (_ru_rc, _ru_out))
    _dbm7._paths = lambda: (os.path.join(_d7, "ru-absent.db"), os.path.join(_d7, "ru-absent.db.backup"))
    try:
        _ru_rc, _ru_out = _p7_out(_dbm7.run_update_maintenance)
    finally:
        _dbm7._paths = _dbm7_saved["_paths"]
    check("dbm/update: with no path it maintains _paths()'s database — absent, so nothing to do",
          _ru_rc == 0 and "no database yet" in _ru_out, "rc=%r out=%r" % (_ru_rc, _ru_out))
    _ru_empty = os.path.join(_d7, "ru-empty.db")
    open(_ru_empty, "wb").close()
    eq("dbm/update: an empty file is a fresh install, not a corrupt one",
       _p7_out(_dbm7.run_update_maintenance, _ru_empty)[0], 0)
    _dbm7.os = _Over(os, path=_Over(os.path, exists=lambda p: True,
                                    getsize=_p7_raise(PermissionError("denied"))))
    try:
        _ru_rc, _ru_out = _p7_out(_dbm7.run_update_maintenance, _ru_good)
    finally:
        _dbm7.os = _dbm7_saved["os"]
    check("dbm/update: a database whose size cannot be read ABORTS the update",
          _ru_rc == 2 and "aborting" in _ru_out, "rc=%r out=%r" % (_ru_rc, _ru_out))
    _ru_bad = _p7_garbage(os.path.join(_d7, "ru-bad.db"))
    with open(_ru_bad, "rb") as f:
        _ru_bad_bytes = f.read()
    _ru_rc, _ru_out = _p7_out(_dbm7.run_update_maintenance, _ru_bad)
    with open(_ru_bad, "rb") as f:
        _ru_bad_after = f.read()
    check("dbm/update: an unrepairable database ABORTS (2) and leaves the file as it was",
          _ru_rc == 2 and "ABORT" in _ru_out and _ru_bad_after == _ru_bad_bytes,
          "rc=%r out=%r" % (_ru_rc, _ru_out))
    _ru_fix = _p7_garbage(os.path.join(_d7, "ru-fix.db"))
    _p7_db(_ru_fix + ".backup", (("t", 11),))
    _ru_rc, _ru_out = _p7_out(_dbm7.run_update_maintenance, _ru_fix)     # backup defaults to .backup


def _dbm7_run_update_maintenance_updater_2():
    global _ru_out, _ru_rc
    check("dbm/update: a damaged database with a healthy backup is repaired and the update continues",
          _ru_rc == 0 and "PROBLEMS FOUND" in _ru_out and _p7_rows(_ru_fix) == 11,
          "rc=%r rows=%r out=%r" % (_ru_rc, _p7_rows(_ru_fix), _ru_out))
    _ic_seq = [(True, "ok"), (False, "row 9 missing from index")]
    _dbm7.integrity_check = lambda p: _ic_seq.pop(0)
    _dbm7.optimize = lambda p: (True, "already compact")
    try:
        _ru_rc, _ru_out = _p7_out(_dbm7.run_update_maintenance, _ru_good)
    finally:
        _dbm7.integrity_check, _dbm7.optimize = _dbm7_saved["integrity_check"], _dbm7_saved["optimize"]
    check("dbm/update: unhealthy AFTER optimize still aborts, and names the problem",
          _ru_rc == 2 and "STILL UNHEALTHY (row 9 missing from index)" in _ru_out,
          "rc=%r out=%r" % (_ru_rc, _ru_out))


def _dbm7_main_cli_install_sh():
    # ── main(): the CLI install.sh and panel-helper call
    global _mn_bad, _mn_db, _mn_seen
    _mn_db = _p7_db(os.path.join(_d7, "main.db"))
    _mn_bad = _p7_garbage(os.path.join(_d7, "main-bad.db"))
    _dbm7._euid = lambda: 1000
    _mn_seen = []


def _dbm7_main_cli_install_sh_2():
    eq("dbm/main: an unknown command is a usage error (64)",
       _p7_out(_dbm7.main, ["db_maintenance.py", "vacuum"])[0], 64)
    _dbm7._paths = lambda: (_mn_db, _mn_db + ".backup")
    _mn_rc, _mn_out = _p7_out(_dbm7.main, ["db_maintenance.py"])
    check("dbm/main: the default command is 'check' — 0 and 'ok' on a healthy database",
          _mn_rc == 0 and _mn_out.strip() == "ok", "rc=%r out=%r" % (_mn_rc, _mn_out))
    _mn_rc, _mn_out = _p7_out(_dbm7.main, ["db_maintenance.py", "optimize"])
    check("dbm/main: 'optimize' answers 0 with its message",
          _mn_rc == 0 and (_mn_out.strip() == "already compact" or _mn_out.startswith("reclaimed")),
          "rc=%r out=%r" % (_mn_rc, _mn_out))
    _dbm7._paths = lambda: (_mn_bad, _mn_bad + ".backup")
    _mn_chk = _p7_out(_dbm7.main, ["db_maintenance.py", "check"])
    _mn_opt = _p7_out(_dbm7.main, ["db_maintenance.py", "optimize"])
    check("dbm/main: 'check' and 'optimize' answer 1 on a damaged database",
          _mn_chk[0] == 1 and _mn_opt[0] == 1, "check=%r optimize=%r" % (_mn_chk, _mn_opt))
    _dbm7.run_update_maintenance = lambda p, b: (_mn_seen.append(("update", p, b)), 7)[1]
    _dbm7.repair = lambda p, b: (_mn_seen.append(("repair", p, b)), (False, "nope"))[1]
    _mn_upd = _p7_out(_dbm7.main, ["db_maintenance.py", "update"])[0]
    _mn_rep = _p7_out(_dbm7.main, ["db_maintenance.py", "repair"])[0]
    check("dbm/main: 'update' and a path-less 'repair' act on _paths()'s database and its .backup",
          _mn_upd == 7 and _mn_rep == 1
          and _mn_seen == [("update", _mn_bad, _mn_bad + ".backup"),
                           ("repair", _mn_bad, _mn_bad + ".backup")],
          "update=%r repair=%r seen=%r" % (_mn_upd, _mn_rep, _mn_seen))
    # As root, a database directory that does not exist is "nothing to maintain" for the
    # updater's commands and a failure for the ones an operator asked for.
    _dbm7._euid = lambda: 0
    _mn_gone = os.path.join(_d7, "no-such-dir", "panel.db")
    _dbm7._paths = lambda: (_mn_gone, _mn_gone + ".backup")
    _mn_c = _p7_out(_dbm7.main, ["db_maintenance.py", "check"])
    _mn_r = _p7_out(_dbm7.main, ["db_maintenance.py", "repair", _mn_gone])
    check("dbm/main as root: a missing database directory is 0 for check, 1 for repair",
          _mn_c[0] == 0 and "no database yet" in _mn_c[1] and _mn_r[0] == 1,
          "check=%r repair=%r" % (_mn_c, _mn_r))


def _dbm7_main_cli_install_sh_3():
    global _k
    try:
        _dbm7_main_cli_install_sh_2()
    finally:
        for _k in ("_paths", "_euid", "repair", "run_update_maintenance"):
            setattr(_dbm7, _k, _dbm7_saved[_k])


def _dbm7_main_cli_install_sh_4():
    global _cf_cwd, _cf_db, _cf_dir, _pw_became, _pw_saved
    eq("dbm/_euid: the process's effective uid", _dbm7._euid(), os.geteuid())

    # As root, over a directory someone else owns, the drop to that owner FAILING must stop
    # everything: no repair, no chdir. The REAL _become runs; the kernel's refusal is supplied by
    # os.setgroups on the module, so no privilege of this process is ever actually changed.
    _cf_dir = _p7_tf.mkdtemp(prefix="p7-confine-", dir=_d7)
    _cf_db = _p7_garbage(os.path.join(_cf_dir, "panel.db"))
    _cf_cwd = os.getcwd()
    if os.stat(_cf_dir).st_uid != 0:
        _cf_seen = []
        _dbm7._euid = lambda: 0
        _dbm7.repair = lambda p, b: (_cf_seen.append(p), (True, "ran"))[1]
        _dbm7.os = _Over(os, setgroups=_p7_raise(PermissionError(1, "Operation not permitted")))
        try:
            _cf_rc, _cf_out = _p7_out(_dbm7.main, ["db_maintenance.py", "repair", _cf_db])
        finally:
            _dbm7._euid, _dbm7.repair = _dbm7_saved["_euid"], _dbm7_saved["repair"]
            _dbm7.os = _dbm7_saved["os"]
            _cf_moved = os.getcwd()
            os.chdir(_cf_cwd)
        check("dbm/main as root: a drop to the owner that fails refuses, and repairs nothing",
              _cf_rc == 1 and "could not drop to the database's owner" in _cf_out
              and not _cf_seen and _cf_moved == _cf_cwd,
              "rc=%r out=%r ran=%r cwd=%r" % (_cf_rc, _cf_out, _cf_seen, _cf_moved))
    else:
        skip("dbm/main as root: a drop to the owner that fails refuses, and repairs nothing",
             "the temp dir is root-owned here, so no drop is attempted")
    if os.geteuid() != 0:
        # _reclaim_db_files: a chown the kernel refuses is logged, and the file is left as it was.
        _rc_fd = os.open(_cf_dir, os.O_RDONLY | os.O_DIRECTORY)
        _rc_before = os.stat(_cf_db).st_uid
        try:
            _rc_res = _p7_call(_dbm7._reclaim_db_files, _rc_fd, "panel.db", os.getuid() + 4242, os.getgid())
        finally:
            os.close(_rc_fd)
        check("dbm/reclaim: a refused chown is swallowed and the owner is unchanged",
              _rc_res is None and os.stat(_cf_db).st_uid == _rc_before, "res=%r" % (_rc_res,))
    else:
        skip("dbm/reclaim: a refused chown is swallowed and the owner is unchanged",
             "running as root: the chown would succeed")
    # No passwd entry for the directory's owner: the drop uses the directory's own group.
    _pw_became = []
    _pw_saved = sys.modules.get("pwd")

    class _P7NoPw:
        @staticmethod
        def getpwuid(uid):
            raise KeyError(uid)
    sys.modules["pwd"] = _P7NoPw()
    _dbm7._become = lambda uid, gid: _pw_became.append((uid, gid))
    _dbm7._reclaim_db_files = lambda *a: None


def _dbm7_main_cli_install_sh_5():
    global e
    try:
        _pw_res = _p7_call(_dbm7._confine_to_db_dir, _cf_db)
    finally:
        _dbm7._become = _dbm7_saved["_become"]
        _dbm7._reclaim_db_files = _dbm7_saved["_reclaim_db_files"]
        if _pw_saved is not None:
            sys.modules["pwd"] = _pw_saved
        else:
            sys.modules.pop("pwd", None)
        os.chdir(_cf_cwd)
    _cf_st = os.stat(_cf_dir)
    if _cf_st.st_uid != 0:
        check("dbm/confine: an owner with no passwd entry is dropped to with the directory's group",
              _pw_res == ("panel.db", "") and _pw_became == [(_cf_st.st_uid, _cf_st.st_gid)],
              "res=%r became=%r" % (_pw_res, _pw_became))
    else:
        skip("dbm/confine: an owner with no passwd entry is dropped to with the directory's group",
             "the temp dir is root-owned here, so no drop happens")

    # The script entry point itself: `python db_maintenance.py <bad>` exits with main()'s code.
    import runpy as _p7_runpy  # noqa: E402
    _rp_argv = sys.argv
    sys.argv = ["db_maintenance.py", "nonsense"]
    try:
        with _p7_ctx.redirect_stdout(_p7_io.StringIO()):
            _p7_runpy.run_path(_dbm7.__file__, run_name="__main__")
        _rp_code = "did not exit"
    except SystemExit as e:
        _rp_code = e.code
    finally:
        sys.argv = _rp_argv
    eq("dbm/__main__: the script exits with main()'s status", _rp_code, 64)


try:
    _dbm7_fmt_bytes_unit_ladder()
    _dbm7_optimize()
    _dbm7_integrity_check_failed_read()
    _dbm7_aside_forensic_copy()
    _dbm7_silent_rm_claim_new()
    _dbm7_repair_swap_itself_fails()
    _dbm7_rebuild_via_recover_sqlite3()
    _dbm7_rebuild_via_dump_statement()
    _dbm7_run_update_maintenance_updater()
    _dbm7_run_update_maintenance_updater_2()
    _dbm7_main_cli_install_sh()
    _dbm7_main_cli_install_sh_3()
    _dbm7_main_cli_install_sh_4()
    _dbm7_main_cli_install_sh_5()
finally:
    for _k, _v in _dbm7_saved.items():
        setattr(_dbm7, _k, _v)
    _p7_sh.rmtree(_d7, ignore_errors=True)


# ══ panel/ops/backup.py ══════════════════════════════════════════════════════════════════════════
# Every path constant is pointed at a temp dir for this block (part02 already moved them off the
# checkout; they are put back as found), and config is an in-memory dict, so nothing here reads or
# writes a config.json at all.
import pathlib as _p7_pl  # noqa: E402
import tarfile as _p7_tar  # noqa: E402
import time as _p7_time  # noqa: E402
from panel.core import config as _p7_cfgmod  # noqa: E402
from panel.ops import backup as _bk7  # noqa: E402

_bk7_names = ("BACKUP_DIR", "DATA_DIR", "DB_PATH", "CONFIG_FILE", "SECRET_FILE", "CRED_KEY_FILE",
              "load_config", "update_config", "get_passphrase", "_helper_present", "_run_verb",
              "subprocess", "create_backup", "prune_backups", "_derive_key", "_encrypt_archive",
              "_safe_path", "_service_restart_launcher", "os", "tempfile", "decrypt_secret", "time")
_bk7_saved = {k: getattr(_bk7, k) for k in _bk7_names}
_b7 = _p7_pl.Path(_p7_tf.mkdtemp(prefix="p7-bk-"))
_b7_cfg = {}


def _p7_bk_update(mut):
    c = dict(_b7_cfg)
    mut(c)
    _b7_cfg.clear()
    _b7_cfg.update(c)
    return c


def _p7_enc_file(path, plain, passphrase, n=2 ** 12, kdf="scrypt", r=8, p=1):
    """Write an encrypted-archive file in the panel's format, at the cheapest cost it accepts.

    n=2**12, so a check here costs milliseconds rather than scrypt's default tenth of a second.
    """
    import json as _json
    from cryptography.fernet import Fernet
    salt = os.urandom(16)
    key = _bk7_saved["_derive_key"](passphrase, salt, n=n, r=r, p=p)
    head = _json.dumps({"kdf": kdf, "n": n, "r": r, "p": p,
                        "salt": _p7_b64.b64encode(salt).decode()}).encode()
    with open(path, "wb") as f:
        f.write(_bk7._ENC_MAGIC + head + b"\n" + Fernet(key).encrypt(plain))
    return path


def _p7_names_in(d):
    return sorted(p.name for p in d.iterdir())


def _bk7_setup():
    _bk7.BACKUP_DIR = _b7 / "backups"
    _bk7.DATA_DIR = _b7
    _bk7.DB_PATH = _b7 / "panel.db"
    _bk7.CONFIG_FILE = _b7 / "config.json"
    _bk7.SECRET_FILE = _b7 / "secret_key"
    _bk7.CRED_KEY_FILE = _b7 / "cred_key"
    _bk7.load_config = lambda: dict(_b7_cfg)
    _bk7.update_config = _p7_bk_update
    _p7_db(str(_bk7.DB_PATH), (("t", 3),))
    _bk7.CONFIG_FILE.write_text("{}")
    _bk7.SECRET_FILE.write_text("s")
    _bk7.CRED_KEY_FILE.write_text("k")


def _bk7_encrypted_archive_reader_malformed():
    # ── the encrypted-archive reader: every malformed file is a refusal with a reason
    global _plain_bytes, _plain_name
    _plain_ok, _plain_name = _bk7.create_backup("manual", passphrase="")  # nosec B106 - no passphrase
    _plain_path = _bk7.BACKUP_DIR / _plain_name if _plain_ok else None
    _plain_bytes = _plain_path.read_bytes() if _plain_path else b""
    check("backup/_is_readable_tar: a plain archive reads as a tar, noise does not",
          _plain_ok and _bk7._is_readable_tar(_plain_path) is True
          and _bk7._is_readable_tar(_p7_garbage(str(_b7 / "noise.bin"))) is False,
          "create=%r" % ((_plain_ok, _plain_name),))
    _dec_out = str(_b7 / "dec.tar.gz")
    eq("backup/decrypt: an archive that cannot be read is refused, not raised",
       _p7_call(_bk7._decrypt_archive, str(_b7 / "no-such.enc"), _dec_out, "pw"),
       (False, "Could not read the backup archive."))
    # A header that is valid JSON once its last byte is dropped, and no newline after it: the
    # newline test is the only thing that stops the whole file being read as header + ciphertext
    # (a slice at find() == -1 cuts one byte off and parses), which would answer "wrong passphrase".
    _nonl = _b7 / "nonl.enc"
    _nonl.write_bytes(_bk7._ENC_MAGIC + b'{"kdf":"scrypt","n":4096,"r":8,"p":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA=="}X')
    eq("backup/decrypt: a header with no terminating newline is 'damaged'",
       _p7_call(_bk7._decrypt_archive, str(_nonl), _dec_out, "pw"),
       (False, "The encrypted backup's header is damaged."))
    _pbk = _p7_enc_file(str(_b7 / "pbkdf.enc"), b"x", "a passphrase here", kdf="pbkdf2")
    eq("backup/decrypt: an unknown KDF is refused before any key is derived",
       _p7_call(_bk7._decrypt_archive, _pbk, _dec_out, "a passphrase here"),
       (False, "This backup uses an encryption scheme this panel does not know."))
    _good_enc = _p7_enc_file(str(_b7 / "good.enc"), _plain_bytes, "a passphrase here")
    _bk7._derive_key = _p7_raise(MemoryError("scrypt"))
    try:
        _de_err = _p7_call(_bk7._decrypt_archive, _good_enc, _dec_out, "a passphrase here")
    finally:
        _bk7._derive_key = _bk7_saved["_derive_key"]
    eq("backup/decrypt: a derivation that fails for any other reason is a refusal",
       _de_err, (False, "The backup could not be decrypted."))
    _dec_dir = _b7 / "dest-is-a-dir"
    _dec_dir.mkdir()
    eq("backup/decrypt: a destination it cannot write is reported, not raised",
       _p7_call(_bk7._decrypt_archive, _good_enc, str(_dec_dir), "a passphrase here"),
       (False, "Could not write the decrypted archive."))
    _de_ok = _p7_call(_bk7._decrypt_archive, _good_enc, _dec_out, "a passphrase here")
    _de_bytes = open(_dec_out, "rb").read() if os.path.exists(_dec_out) else b""
    check("backup/decrypt: ...and the same archive opens with the right passphrase, byte for byte",
          _de_ok == (True, "") and _plain_bytes and _de_bytes == _plain_bytes, repr(_de_ok))


def _bk7_get_passphrase_create_backup():
    # ── get_passphrase / create_backup: a config it cannot read REFUSES the backup
    _bk7.load_config = _p7_raise(OSError("config.json: I/O error"))
    try:
        _cb_before = _p7_names_in(_bk7.BACKUP_DIR)
        _cb_ref = _p7_call(_bk7.create_backup, "daily")
        _cb_after = _p7_names_in(_bk7.BACKUP_DIR)
    finally:
        _bk7.load_config = lambda: dict(_b7_cfg)
    check("backup/create: a config that raises is a refusal — never a plaintext archive",
          isinstance(_cb_ref, tuple) and _cb_ref[0] is False and _cb_ref[1].startswith("Backup refused")
          and _cb_after == _cb_before,
          "res=%r new=%r" % (_cb_ref, sorted(set(_cb_after) - set(_cb_before))))


def _bk7_regression_two_backups_one():
    # ── REGRESSION (fixed in this change): two backups of one kind within the same second
    # The archive name is the time to the second, and create_backup opened it for writing without
    # asking whether it was taken. A second manual backup in that second (a double-click, two
    # admins, the restore's safety copy racing a manual one) OVERWROTE the first archive — and when
    # the second one then failed, its cleanup os.remove()d the name, deleting the first backup
    # after it had been reported to its caller as taken. The clock is frozen on the module so both
    # calls really do land in one second.
    global _frozen
    _frozen = _p7_time.time()
    _bk7.time = _Over(_p7_time, time=lambda: _frozen,
                      strftime=lambda f, t=None: _p7_time.strftime(
                          f, t if t is not None else _p7_time.localtime(_frozen)))


def _bk7_regression_two_backups_one_2():
    _same_a = _p7_call(_bk7.create_backup, "samesec", passphrase="")  # nosec B106 - no passphrase
    _same_a_bytes = (_bk7.BACKUP_DIR / _same_a[1]).read_bytes() if _same_a[0] else b""
    _bk7.CONFIG_FILE.write_text('{"changed": true}')
    _same_b = _p7_call(_bk7.create_backup, "samesec", passphrase="")  # nosec B106 - no passphrase
    _same_a_after = ((_bk7.BACKUP_DIR / _same_a[1]).read_bytes()
                     if (_bk7.BACKUP_DIR / _same_a[1]).exists() else b"")
    check("backup/create: a second backup in the same second gets its own name, not the first's",
          _same_a[0] and _same_b[0] and _same_a[1] != _same_b[1] and _same_a_after == _same_a_bytes,
          "a=%r b=%r first-intact=%r" % (_same_a, _same_b, _same_a_after == _same_a_bytes))
    _bk7.os = _Over(os, chmod=_p7_raise(PermissionError("read-only")))
    try:
        _same_c = _p7_call(_bk7.create_backup, "samesec", passphrase="")  # nosec B106 - no passphrase
    finally:
        _bk7.os = _bk7_saved["os"]
    _same_left = sorted(n for n in _p7_names_in(_bk7.BACKUP_DIR) if "samesec" in n)
    check("backup/create: a same-second backup that FAILS does not delete the ones already taken",
          _same_c == (False, "Backup failed — see panel logs.")
          and _same_left == sorted([_same_a[1], _same_b[1]]),
          "c=%r left=%r" % (_same_c, _same_left))


def _bk7_regression_two_backups_one_3():
    # Every candidate second taken: a refusal that touches none of them, never an overwrite.
    for _b in range(10):
        (_bk7.BACKUP_DIR / ("panel-backup-%s-samesec.tar.gz" % _p7_time.strftime(
            "%Y%m%d-%H%M%S", _p7_time.localtime(_frozen + _b)))).write_bytes(b"kept")
    _same_d = _p7_call(_bk7.create_backup, "samesec", passphrase="")  # nosec B106 - no passphrase
    _same_kept = [(_bk7.BACKUP_DIR / _n).read_bytes() for _n in _p7_names_in(_bk7.BACKUP_DIR)
                  if "samesec" in _n]
    check("backup/create: with every candidate name taken it refuses and overwrites none",
          _same_d == (False, "Backup failed — see panel logs.") and len(_same_kept) == 10
          and all(b == b"kept" for b in _same_kept), "d=%r n=%d" % (_same_d, len(_same_kept)))
    _bk7.os = _Over(os, open=_p7_raise(PermissionError("EACCES")))
    try:
        _same_e = _p7_call(_bk7.create_backup, "othersec", passphrase="")  # nosec B106 - no passphrase
    finally:
        _bk7.os = _bk7_saved["os"]
    eq("backup/create: a backups dir it cannot create a file in is a failure, not a raise",
       _same_e, (False, "Backup failed — see panel logs."))


def _bk7_regression_two_backups_one_4():
    global _n
    try:
        _bk7_regression_two_backups_one_2()
        _bk7_regression_two_backups_one_3()
    finally:
        _bk7.time = _bk7_saved["time"]
        _bk7.CONFIG_FILE.write_text("{}")
        for _n in _p7_names_in(_bk7.BACKUP_DIR):
            if "samesec" in _n:
                (_bk7.BACKUP_DIR / _n).unlink()


def _bk7_create_backup_failure_after():
    # ── create_backup: a failure after the archive exists leaves no partial archive behind
    global _db_moved, _n
    _bk7.os = _Over(os, chmod=_p7_raise(PermissionError("read-only")))
    try:
        _cp_before = _p7_names_in(_bk7.BACKUP_DIR)
        _cp_res = _p7_call(_bk7.create_backup, "manual", passphrase="")  # nosec B106 - no passphrase
        _cp_after = _p7_names_in(_bk7.BACKUP_DIR)
    finally:
        _bk7.os = _bk7_saved["os"]
    check("backup/create: a failure after writing removes the partial archive and says so",
          _cp_res == (False, "Backup failed — see panel logs.") and _cp_after == _cp_before,
          "res=%r new=%r" % (_cp_res, sorted(set(_cp_after) - set(_cp_before))))
    _bk7._encrypt_archive = _p7_raise(RuntimeError("fernet"))
    try:
        _ce_before = _p7_names_in(_bk7.BACKUP_DIR)
        _ce_res = _p7_call(_bk7.create_backup, "manual", passphrase="a passphrase here")  # nosec B106 - a fixture passphrase
        _ce_after = _p7_names_in(_bk7.BACKUP_DIR)
    finally:
        _bk7._encrypt_archive = _bk7_saved["_encrypt_archive"]
    _bk7.os = _Over(os, chmod=_p7_raise(PermissionError("read-only")), remove=_p7_raise(PermissionError("EPERM")))
    try:
        _cr_res = _p7_call(_bk7.create_backup, "unremovable", passphrase="")  # nosec B106 - no passphrase
    finally:
        _bk7.os = _bk7_saved["os"]
    _cr_left = [n for n in _p7_names_in(_bk7.BACKUP_DIR) if "unremovable" in n]
    check("backup/create: a partial archive it cannot even remove is still reported as a failure",
          _cr_res == (False, "Backup failed — see panel logs.") and len(_cr_left) == 1, "%r %r" % (_cr_res, _cr_left))
    for _n in _cr_left:
        (_bk7.BACKUP_DIR / _n).unlink()
    check("backup/create: a failed ENCRYPT leaves nothing in the backups dir — not even a plaintext stage",
          _ce_res == (False, "Backup failed — see panel logs.") and _ce_after == _ce_before,
          "res=%r new=%r" % (_ce_res, sorted(set(_ce_after) - set(_ce_before))))
    # No panel.db at all (a fresh install): the archive carries the config and keys only.
    _db_moved = _b7 / "panel.db.away"
    os.replace(str(_bk7.DB_PATH), str(_db_moved))


def _bk7_create_backup_failure_after_2():
    global _nd_ok, _t, e
    try:
        _nd_ok, _nd_name = _bk7.create_backup("manual", passphrase="")  # nosec B106 - no passphrase
        with _p7_tar.open(str(_bk7.BACKUP_DIR / _nd_name)) as _t:
            _nd_members = sorted(_t.getnames())
        os.remove(str(_bk7.BACKUP_DIR / _nd_name))
    except Exception as e:  # noqa: BLE001
        _nd_members = "raised %s" % e
    finally:
        os.replace(str(_db_moved), str(_bk7.DB_PATH))
    eq("backup/create: with no database yet the archive holds only config and keys",
       _nd_members, ["config.json", "cred_key", "secret_key"])


def _bk7_listing_safe_path_delete():
    # ── the listing, _safe_path, delete
    (_bk7.BACKUP_DIR / "panel-backup-notadate.tar.gz").write_bytes(b"x")
    os.symlink(str(_b7 / "gone"), str(_bk7.BACKUP_DIR / "panel-backup-20200101-000000-daily.tar.gz"))
    _lb_names = [b["name"] for b in _bk7.list_backups()]
    check("backup/list: a misnamed file and a dangling link are left out of the listing",
          "panel-backup-notadate.tar.gz" not in _lb_names
          and "panel-backup-20200101-000000-daily.tar.gz" not in _lb_names and _plain_name in _lb_names,
          repr(_lb_names))
    eq("backup/_safe_path: a well-formed name with no such file is None",
       _bk7._safe_path("panel-backup-19990101-000000-manual.tar.gz"), None)
    eq("backup/delete: an unknown name is refused",
       _p7_call(_bk7.delete_backup, "panel-backup-19990101-000000-manual.tar.gz"),
       (False, "No such backup."))

    class _P7Unlinkable:
        def unlink(self):
            raise PermissionError("EPERM")
    _bk7._safe_path = lambda n: _P7Unlinkable()
    try:
        _del_res = _p7_call(_bk7.delete_backup, _plain_name)
    finally:
        _bk7._safe_path = _bk7_saved["_safe_path"]
    eq("backup/delete: an unlink the OS refuses is reported as a failure",
       _del_res, (False, "Could not delete the backup."))


def _bk7_prune_backups_configured_retention():
    # ── prune_backups: the configured retention, and a junk value falling back to the default
    global _k
    _pr_names = {"old": "panel-backup-20200102-000000-daily.tar.gz",
                 "mid": "panel-backup-20200103-000000-daily.tar.gz"}
    for _k, _age in (("old", 20), ("mid", 5)):
        _pp = _bk7.BACKUP_DIR / _pr_names[_k]
        _pp.write_bytes(b"x")
        _ts = _p7_time.time() - _age * 86400
        os.utime(str(_pp), (_ts, _ts))
    _b7_cfg["backup_keep_days"] = "fourteen"
    _pr_junk = _p7_call(_bk7.prune_backups)
    _pr_after_junk = {b["name"] for b in _bk7.list_backups()}
    _b7_cfg["backup_keep_days"] = 3
    _pr_three = _p7_call(_bk7.prune_backups)
    _pr_after_three = {b["name"] for b in _bk7.list_backups()}
    _b7_cfg.pop("backup_keep_days")
    check("backup/prune: an unparseable retention falls back to the default (14 days)",
          _pr_junk == 1 and _pr_names["old"] not in _pr_after_junk and _pr_names["mid"] in _pr_after_junk,
          "removed=%r left=%r" % (_pr_junk, sorted(_pr_after_junk)))
    check("backup/prune: ...and a configured 3 days prunes the 5-day-old daily too",
          _pr_three == 1 and _pr_names["mid"] not in _pr_after_three and _plain_name in _pr_after_three,
          "removed=%r left=%r" % (_pr_three, sorted(_pr_after_three)))


def _bk7_daily_backup_tick():
    # ── daily_backup_tick
    _dt_calls = []
    _dt_next = [(True, "n")]
    _bk7.create_backup = lambda kind="manual", **k: (_dt_calls.append(("create", kind)), _dt_next[0])[1]
    _bk7.prune_backups = lambda *a, **k: (_dt_calls.append(("prune",)), 0)[1]
    try:
        _b7_cfg["backup_enabled"] = False
        _dt_off = _p7_call(_bk7.daily_backup_tick)
        _b7_cfg["backup_enabled"] = True
        check("backup/tick: disabled daily backups take nothing",
              _dt_off is False and not _dt_calls, "res=%r calls=%r" % (_dt_off, _dt_calls))
        _dt_on = _p7_call(_bk7.daily_backup_tick)       # no recent daily in the listing now
        check("backup/tick: with no recent daily it takes one and prunes",
              _dt_on is True and _dt_calls == [("create", "daily"), ("prune",)],
              "res=%r calls=%r" % (_dt_on, _dt_calls))
        del _dt_calls[:]
        _dt_next[0] = (False, "disk full")
        _dt_fail = _p7_call(_bk7.daily_backup_tick)
        check("backup/tick: a failed backup is reported False and prunes nothing",
              _dt_fail is False and _dt_calls == [("create", "daily")],
              "res=%r calls=%r" % (_dt_fail, _dt_calls))
        del _dt_calls[:]
        _fresh = _bk7.BACKUP_DIR / ("panel-backup-%s-daily.tar.gz" % _p7_time.strftime("%Y%m%d-%H%M%S"))
        _fresh.write_bytes(b"x")
        _dt_recent = _p7_call(_bk7.daily_backup_tick)
        check("backup/tick: a daily taken within the day means no new one",
              _dt_recent is False and not _dt_calls, "res=%r calls=%r" % (_dt_recent, _dt_calls))
        _fresh.unlink()
    finally:
        _bk7.create_backup, _bk7.prune_backups = _bk7_saved["create_backup"], _bk7_saved["prune_backups"]
        _b7_cfg.pop("backup_enabled", None)


def _bk7_service_restart_launcher_per():
    # ── _service_restart_launcher: per-user unit, system unit, neither
    _units = {"user": False, "system": False}

    def _p7_unit_exists(p):
        if p.endswith("/.config/systemd/user/linuxgsm-panel.service"):
            return _units["user"]
        if p == "/etc/systemd/system/linuxgsm-panel.service":
            return _units["system"]
        return os.path.exists(p)
    _bk7.os = _Over(os, path=_Over(os.path, exists=_p7_unit_exists))
    try:
        _l_none = _bk7._service_restart_launcher("/s.sh")
        _units["system"] = True
        _l_sys = _bk7._service_restart_launcher("/s.sh")
        _units["user"] = True
        _l_both = _bk7._service_restart_launcher("/s.sh")
    finally:
        _bk7.os = _bk7_saved["os"]
    eq("backup/launcher: a system unit is started through sudo; a user unit (or none) is not",
       (_l_none, _l_sys, _l_both),
       (["systemd-run", "--user", "--collect", "/bin/bash", "/s.sh"],
        ["sudo", "systemd-run", "--collect", "/bin/bash", "/s.sh"],
        ["systemd-run", "--user", "--collect", "/bin/bash", "/s.sh"]))


def _bk7_restore_backup_refusal_happens():
    # ── restore_backup: every refusal happens before anything live is touched
    global _p7_archive, _stage
    _stage = os.path.join(str(_b7), ".restore-stage")
    eq("backup/restore: an unknown name is refused",
       _p7_call(_bk7.restore_backup, "panel-backup-19990101-000000-manual.tar.gz"),
       (False, "No such backup."))
    _enc_name = "panel-backup-20240101-000000-manual.tar.gz.enc"
    _p7_enc_file(str(_bk7.BACKUP_DIR / _enc_name), _plain_bytes, "a passphrase here")
    _dec_tmp_root = _p7_tf.mkdtemp(prefix="p7-dec-", dir=str(_b7))
    _bk7.tempfile = _Over(_p7_tf, mkdtemp=lambda prefix="": _p7_tf.mkdtemp(prefix=prefix, dir=_dec_tmp_root))
    _bk7.get_passphrase = _p7_raise(_bk7.PassphraseUnreadable("cred_key rotated"))
    try:
        _ru_res = _p7_call(_bk7.restore_backup, _enc_name)
    finally:
        _bk7.get_passphrase = _bk7_saved["get_passphrase"]
        _bk7.tempfile = _bk7_saved["tempfile"]
    check("backup/restore: an encrypted archive with an undecryptable stored passphrase is refused",
          isinstance(_ru_res, tuple) and _ru_res[0] is False
          and _ru_res[1].startswith("Cannot decrypt this backup") and "cred_key rotated" not in _ru_res[1],
          repr(_ru_res))
    check("backup/restore: ...and its decrypt dir is removed",
          os.listdir(_dec_tmp_root) == [], repr(os.listdir(_dec_tmp_root)))

    def _p7_archive(name, members):
        path = _bk7.BACKUP_DIR / name
        with _p7_tar.open(str(path), "w:gz") as t:
            for m, data in members.items():
                src = _b7 / ("m-" + m.replace("/", "_"))
                src.write_bytes(data)
                t.add(str(src), arcname=m)
        return name
    _foreign = _p7_archive("panel-backup-20240102-000000-manual.tar.gz",
                           {"panel.db": b"x", "../../etc/cron.d/x": b"* * * * * root id"})
    eq("backup/restore: an archive carrying anything but the four members is refused",
       _p7_call(_bk7.restore_backup, _foreign), (False, "Backup archive looks invalid."))
    _nottar = "panel-backup-20240103-000000-manual.tar.gz"
    (_bk7.BACKUP_DIR / _nottar).write_bytes(b"not a gzip at all")
    eq("backup/restore: an archive that does not open is refused",
       _p7_call(_bk7.restore_backup, _nottar), (False, "Could not read the backup archive."))
    check("backup/restore: ...and neither refusal staged anything",
          not os.path.exists(_stage))

    # _restore_validated directly: an archive that cannot be extracted cleans its stage up.
    eq("backup/restore: an extract that fails is reported, and the stage is removed",
       (_p7_call(_bk7._restore_validated, _b7 / "noise.bin", "x", skip_safety_backup=True),
        os.path.exists(_stage)),
       ((False, "Could not extract the backup."), False))

    # The helper answers non-zero: nothing restarts, and the staged keys do not linger.
    _rv_verbs = []
    _bk7._helper_present = lambda: True
    _bk7._run_verb = lambda verb, args=(), **k: (_rv_verbs.append((verb, list(args), k.get("timeout"))),
                                                 ("", "helper: refused", 1))[1]
    try:
        _hv_res = _p7_call(_bk7.restore_backup, _plain_name, skip_safety_backup=True)
    finally:
        _bk7._helper_present, _bk7._run_verb = _bk7_saved["_helper_present"], _bk7_saved["_run_verb"]
    check("backup/restore: a helper that refuses the restore is a failure, and the stage is wiped",
          _hv_res == (False, "Could not start the restore.") and _rv_verbs == [("panel-restore", [], 20)]
          and not os.path.exists(_stage),
          "res=%r verbs=%r staged=%r" % (_hv_res, _rv_verbs, os.path.exists(_stage)))


def _bk7_restore_backup_refusal_happens_2():
    global _lg_script, _lg_text
    _bk7._helper_present = _p7_raise(RuntimeError("stat failed"))
    try:
        _hx_res = _p7_call(_bk7.restore_backup, _plain_name, skip_safety_backup=True)
    finally:
        _bk7._helper_present = _bk7_saved["_helper_present"]
    check("backup/restore: a dispatch that raises is a failure, and the stage is wiped",
          _hx_res == (False, "Could not start the restore.") and not os.path.exists(_stage), repr(_hx_res))

    # The pre-helper fallback: a script that copies exactly the staged members, quoted, then a
    # detached launch of it. Popen is recorded, never run.
    _popen = []
    _bk7._helper_present = lambda: False
    _bk7.subprocess = _Over(_p7_sp, Popen=lambda argv, **k: _popen.append(list(argv)))
    _bk7._service_restart_launcher = lambda script: ["LAUNCH", script]
    try:
        # A REAL database: restore re-reads the archive's panel.db before anything is staged
        # (GHSA-hh39-76g3-wxcx), so bytes that are not SQLite are refused before this path runs.
        _lg_db = _p7_db(str(_b7 / "lg-src.db"), (("t", 2),))
        with open(_lg_db, "rb") as _lg_f:
            _lg_name = _p7_archive("panel-backup-20240104-000000-manual.tar.gz",
                                   {"panel.db": _lg_f.read(), "config.json": b"{}"})
        _lg_res = _p7_call(_bk7.restore_backup, _lg_name, skip_safety_backup=True)
    finally:
        _bk7._helper_present = _bk7_saved["_helper_present"]
        _bk7.subprocess = _bk7_saved["subprocess"]
        _bk7._service_restart_launcher = _bk7_saved["_service_restart_launcher"]
    _lg_script = os.path.join(str(_b7), "restore.sh")
    _lg_text = open(_lg_script).read() if os.path.exists(_lg_script) else ""
    check("backup/restore (pre-helper): launches the written script detached, and says NO safety copy",
          isinstance(_lg_res, tuple) and _lg_res[0] is True and "NO pre-restore safety copy" in _lg_res[1]
          and _popen == [["LAUNCH", _lg_script]], "res=%r popen=%r" % (_lg_res, _popen))


def _bk7_restore_backup_refusal_happens_3():
    check("backup/restore (pre-helper): the script copies only the members the archive had",
          ("cp -f '%s/panel.db' '%s' || true" % (_stage, _bk7.DB_PATH)) in _lg_text
          and ("cp -f '%s/config.json' '%s' || true" % (_stage, _bk7.CONFIG_FILE)) in _lg_text
          and "secret_key" not in _lg_text and "cred_key" not in _lg_text
          and ("rm -rf '%s'" % _stage) in _lg_text, _lg_text)
    check("backup/restore (pre-helper): the script is owner-only",
          os.path.exists(_lg_script) and (os.stat(_lg_script).st_mode & 0o777) == 0o700)
    eq("backup/_sh: a quote in a path cannot end the quoting", _bk7._sh("/a b/it's"), "'/a b/it'\\''s'")
    _p7_sh.rmtree(_stage, ignore_errors=True)


def _bk7_settings_junk_value_ignored():
    # ── settings: every junk value is ignored or clamped, never stored raw
    _b7_cfg.clear()
    _b7_cfg["backup_keep_days"] = "a fortnight"
    eq("backup/settings: an unparseable stored retention reads as the default",
       _bk7.get_settings()["keep_days"], _bk7.DEFAULT_KEEP_DAYS)
    _ss = _p7_call(_bk7.set_settings, enabled=0, keep_days="x")
    check("backup/settings: a junk keep_days is not stored; 'enabled' is stored as a bool",
          _b7_cfg.get("backup_enabled") is False and _b7_cfg.get("backup_keep_days") == "a fortnight"
          and isinstance(_ss, dict) and _ss["keep_days"] == _bk7.DEFAULT_KEEP_DAYS, repr(_b7_cfg))
    _p7_call(_bk7.set_settings, keep_days=99999)
    eq("backup/settings: a huge retention is clamped to the maximum", _b7_cfg.get("backup_keep_days"),
       _bk7.MAX_KEEP_DAYS)
    _b7_cfg.clear()
    _b7_cfg.update({"full_backup_interval_days": "weekly", "full_backup_keep": None, "full_backup_last": "?"})
    _fs = _bk7.get_full_settings()
    eq("backup/full settings: unparseable stored values read as the defaults",
       (_fs["interval_days"], _fs["keep"], _fs["last"]),
       (_bk7.DEFAULT_FULL_INTERVAL, _bk7.DEFAULT_FULL_KEEP, 0))
    _p7_call(_bk7.set_full_settings, interval_days="x", keep=[3])
    check("backup/full settings: junk writes leave the stored values alone",
          _b7_cfg.get("full_backup_interval_days") == "weekly" and _b7_cfg.get("full_backup_keep") is None,
          repr(_b7_cfg))
    _p7_call(_bk7.set_full_settings, interval_days=9999, keep=0)
    eq("backup/full settings: numbers are clamped into range",
       (_b7_cfg.get("full_backup_interval_days"), _b7_cfg.get("full_backup_keep")),
       (_bk7.MAX_INTERVAL_DAYS, _bk7.MIN_FULL_KEEP))


def _bk7_per_server_retention():
    # ── per-server retention
    _b7_cfg.clear()
    _b7_cfg["game_schedules"] = {"41": {"keep": 9}}
    eq("backup/game_prune_keep: a readable config answers the server's own retention",
       _bk7.game_prune_keep(41), (9, True))
    _bk7.load_config = lambda: _p7_cfgmod.UnreadableConfig({"game_schedules": {"41": {"keep": 9}}})
    try:
        eq("backup/game_prune_keep: an unreadable config keeps the MAXIMUM, and says it did not read",
           _bk7.game_prune_keep(41), (_bk7.MAX_FULL_KEEP, False))
    finally:
        _bk7.load_config = lambda: dict(_b7_cfg)
    _b7_cfg["game_schedules"] = {"42": {"interval_days": 3, "keep": 7, "last": 5}}
    _p7_call(_bk7.set_game_schedule, 42, _bk7.UNCHANGED, _bk7.UNCHANGED)
    eq("backup/game schedule: UNCHANGED for both fields changes nothing",
       _b7_cfg["game_schedules"]["42"], {"interval_days": 3, "keep": 7, "last": 5})
    _b7_cfg["game_schedules"] = {"43": {"interval_days": 3}}
    _p7_call(_bk7.set_game_schedule, 43, None, _bk7.UNCHANGED)
    check("backup/game schedule: clearing a server's only override removes its entry entirely",
          "43" not in _b7_cfg["game_schedules"], repr(_b7_cfg["game_schedules"]))


try:
    _bk7_setup()
    _bk7_encrypted_archive_reader_malformed()
    _bk7_get_passphrase_create_backup()
    _bk7_regression_two_backups_one()
    _bk7_regression_two_backups_one_4()
    _bk7_create_backup_failure_after()
    _bk7_create_backup_failure_after_2()
    _bk7_listing_safe_path_delete()
    _bk7_prune_backups_configured_retention()
    _bk7_daily_backup_tick()
    _bk7_service_restart_launcher_per()
    _bk7_restore_backup_refusal_happens()
    _bk7_restore_backup_refusal_happens_2()
    _bk7_restore_backup_refusal_happens_3()
    _bk7_settings_junk_value_ignored()
    _bk7_per_server_retention()
finally:
    for _k in _bk7_names:
        setattr(_bk7, _k, _bk7_saved[_k])
    _p7_sh.rmtree(str(_b7), ignore_errors=True)


# ══ panel/routes/panel_backup.py ═════════════════════════════════════════════════════════════════
# The REAL view functions, on a bare Flask app, with every collaborator stubbed at
# panel.routes.panel_backup (the module whose globals the route closures read). The backup lock and
# status map are this block's own objects, and threads are run synchronously, so a "background"
# run has finished — and can be asserted on — by the time the response arrives. No real lock, no
# database, no SSH, no thread is left behind.
import threading as _p7_threading  # noqa: E402
from types import SimpleNamespace as _P7NS  # noqa: E402
import flask as _p7_flask  # noqa: E402
import panel.routes.panel_backup as _pb7  # noqa: E402
import panel.security.auth as _p7_auth  # noqa: E402

_pb7_names = ("current_user", "log_action", "get_game", "GameServer", "RemoteServer", "db",
              "threading", "_button_backup_running",
              "_marked_backup", "_record_full_clock", "_record_game_clock", "run_game_backup",
              "notifications", "bk", "so", "list_game_backups", "delete_game_backup",
              "stream_game_backup", "backup_disk_info", "_cached_player_count")
_pb7_saved = {k: getattr(_pb7, k) for k in _pb7_names}
_pb7_auth_user = _p7_auth.current_user
_pb7_log = []
_pb7_notes = []
_pb7_thread = {"fail": False}


class _P7SyncThread:
    """A threading.Thread that runs its target inside start().

    The worker has finished when the route returns. `fail` makes start() raise, the way a
    thread-limited host does.
    """

    def __init__(self, target=None, daemon=None, **_k):
        self._target = target

    def start(self):
        if _pb7_thread["fail"]:
            raise RuntimeError("can't start new thread")
        self._target()


class _P7Query:
    def __init__(self, rows):
        self.rows = rows

    def filter_by(self, **kw):
        return _P7Query([r for r in self.rows if all(getattr(r, k) == v for k, v in kw.items())])

    def options(self, *_a):
        return self

    def all(self):
        return list(self.rows)


class _P7GameServer:
    remote = None        # the attribute joinedload() is handed
    query = _P7Query([])


def _p7_gs(sid, name, installed=True, remote_id=7, pending=False):
    return _P7NS(id=sid, name=name, installed=installed, remote_id=remote_id,
                 remote=_P7NS(id=remote_id, name="host", host="h", is_local=False) if remote_id else None,
                 short_name="gs%d" % sid, lgsm_name="gs%dserver" % sid, game_type="gmod",
                 port=27000 + sid, query_type=None, backup_pending=pending)


_pb7_db_commits = []
_pb7_db = _P7NS(session=_P7NS(commit=lambda: _pb7_db_commits.append(1), get=lambda M, i: _pb7_rows.get(i)))
_pb7_rows = {}

_pb7_app = _p7_flask.Flask("p7_panel_backup")
_pb7_app.secret_key = "unit-suite"  # nosec B105 - a stand-in app's key
_pb7_app.config["LOGIN_DISABLED"] = True     # login_required is not what is under test
_pb7_app.logger.disabled = True
_pb7_c = None
try:
    _pb7.register(_pb7_app)
    _pb7_c = _pb7_app.test_client()
    _p7_auth.current_user = _P7NS(is_authenticated=True, is_superadmin=True, id=1, username="p7admin")
    _pb7.current_user = _p7_auth.current_user
    _pb7.log_action = lambda user, action, target="", detail="", success=True, **k: _pb7_log.append(
        (action, str(target), str(detail), success))
    _pb7.db = _pb7_db
    _pb7.GameServer = _P7GameServer
    # The panel's OWN lock and status map, emptied in place, never rebound: a rebinding gives this
    # module a private copy and strands every other reader on the old one (part05's panel_state
    # gate). The map's contents are put back in the `finally`; the lock must be free to begin with.
    check("panel_backup: the full-backup lock is free before the route checks start",
          not _pb7._full_backup_lock.locked())
    _pb7_gbs_snap = dict(_pb7._game_backup_status)
    _pb7._game_backup_status.clear()
    _pb7.threading = _Over(_p7_threading, Thread=_P7SyncThread)
    _pb7.notifications = _Over(_pb7_saved["notifications"],
                               alerts_muted=lambda gs: gs.name == "delta",
                               notify=lambda *a, **k: _pb7_notes.append(a))
    _pb7_clock = []
    _pb7._record_full_clock = lambda app, summary: _pb7_clock.append(summary)
    _pb7._record_game_clock = lambda app, sid, gname: _pb7_clock.append(("game", sid))

    # ── the full backup run: every outcome lands in the summary, the queue and the alert ───────
    _pb7_fleet = [_p7_gs(1, "alpha"), _p7_gs(2, "bravo"), _p7_gs(3, "charlie"), _p7_gs(4, "delta"),
                  _p7_gs(5, "echo", pending=True), _p7_gs(6, "foxtrot", remote_id=None), _p7_gs(7, "kilo")]
    _P7GameServer.query = _P7Query(_pb7_fleet)
    _pb7_marked = []
    _pb7_results = {2: (False, "players online", True), 3: (False, "disk full", False),
                    4: RuntimeError("ssh dropped"), 5: (True, None, False), 7: ValueError("bad reply")}

    def _p7_marked(sid, remote, short, lgsm, keep, **kw):
        _pb7_marked.append((sid, keep, kw.get("force")))
        r = _pb7_results[sid]
        if isinstance(r, Exception):
            raise r
        return r
    _pb7._marked_backup = _p7_marked
    _pb7._button_backup_running = lambda sid: sid == 1
    _pb7.bk = _Over(_pb7_saved["bk"], game_prune_keep=lambda sid: (30, False) if sid == 5 else (sid + 10, True))
    _fb = _pb7_c.post("/api/panel/backup/full", json={"mode": "wait"})
    _fb_j = _fb.get_json() or {}
    check("panel_backup/full 'wait': the answer says busy servers back up once they empty",
          _fb.status_code == 200 and _fb_j.get("message", "").startswith("Backing up empty servers now"),
          "%s %r" % (_fb.status_code, _fb_j))
    eq("panel_backup/full: the recorded summary names every outcome, in order",
       _pb7_clock, ["1 server(s) backed up, 3 failed, 1 skipped (players online) — charlie: disk full; "
                    "delta: backup error (RuntimeError); kilo: backup error (ValueError) — will back up "
                    "once empty: bravo — already "
                    "being backed up from the server page: alpha — config.json could not be read, so "
                    "old backups were kept up to the maximum (30) rather than pruned to each "
                    "server's setting"])
    eq("panel_backup/full: the alert carries only the failures of servers not muted by a tag",
       _pb7_notes, [("backup_failed", "Backup failed",
                     "2 server backup(s) failed: charlie: disk full; kilo: backup error (ValueError)")])
    check("panel_backup/full 'wait': a busy server is QUEUED, and a backed-up one's queue is cleared",
          _pb7_fleet[1].backup_pending is True and _pb7_fleet[4].backup_pending is False
          and len(_pb7_db_commits) == 2,
          "bravo=%r echo=%r commits=%d" % (_pb7_fleet[1].backup_pending, _pb7_fleet[4].backup_pending,
                                          len(_pb7_db_commits)))
    eq("panel_backup/full: each server is pruned to ITS OWN keep; the in-flight and hostless are not run",
       _pb7_marked, [(2, 12, False), (3, 13, False), (4, 14, False), (5, 30, False), (7, 17, False)])
    check("panel_backup/full: the per-server status shows skipped as busy (ok=None), failures as failed",
          _pb7._game_backup_status.get(2, {}).get("busy") is True
          and _pb7._game_backup_status.get(2, {}).get("ok") is None
          and _pb7._game_backup_status.get(3, {}).get("ok") is False
          and _pb7._game_backup_status.get(3, {}).get("msg") == "disk full"
          and _pb7._game_backup_status.get(5, {}).get("msg") == "Backed up",
          repr(_pb7._game_backup_status))
    check("panel_backup/full: the lock is released when the run ends", not _pb7._full_backup_lock.locked())
    del _pb7_marked[:], _pb7_clock[:], _pb7_notes[:]
    _fb_now = _pb7_c.post("/api/panel/backup/full", json={"mode": "now"})
    check("panel_backup/full 'now': every server is forced, and the answer warns players are disconnected",
          (_fb_now.get_json() or {}).get("message", "").startswith("Backing up all servers now")
          and [f for _s, _k, f in _pb7_marked] == [True] * 5,
          "%r %r" % (_fb_now.get_json(), _pb7_marked))

    # A run that dies outright: an alert that says so, nothing recorded as a completed run.
    del _pb7_clock[:], _pb7_notes[:]

    class _P7Boom:
        @property
        def query(self):
            raise RuntimeError("database is locked")
    _pb7.GameServer = _P7Boom()
    _fb_die = _pb7_c.post("/api/panel/backup/full", json={})
    _pb7.GameServer = _P7GameServer
    check("panel_backup/full: a run that errors alerts 'Backup run failed' and records no summary",
          _fb_die.status_code == 200 and _pb7_notes == [("backup_failed", "Backup run failed",
                                                         "The panel backup run errored before completing.")]
          and _pb7_clock == [] and not _pb7._full_backup_lock.locked(),
          "notes=%r clock=%r locked=%r" % (_pb7_notes, _pb7_clock, _pb7._full_backup_lock.locked()))
    # The worker thread cannot start: the lock it was handed must not stay held.
    _pb7_thread["fail"] = True
    try:
        _fb_nothread = _pb7_c.post("/api/panel/backup/full", json={})
    finally:
        _pb7_thread["fail"] = False
    check("panel_backup/full: a thread that cannot start releases the lock (else every backup wedges)",
          _fb_nothread.status_code == 500 and not _pb7._full_backup_lock.locked(),
          "status=%s locked=%r" % (_fb_nothread.status_code, _pb7._full_backup_lock.locked()))

    # ── precheck: only hosted servers count; busy means a cached count above zero ──────────────
    _pb7._cached_player_count = {1: 3, 2: 0}.get
    _P7GameServer.query = _P7Query([_p7_gs(1, "alpha"), _p7_gs(2, "bravo"), _p7_gs(3, "charlie"),
                                    _p7_gs(9, "nohost", remote_id=None)])
    eq("panel_backup/precheck: counts hosted servers and names those with players",
       _pb7_c.get("/api/panel/backup/full/precheck").get_json(),
       {"total": 3, "busy": [{"name": "alpha", "players": 3}]})

    # ── on-demand backup of one server ──────────────────────────────────────────────────────────
    _pb7_games = {11: _p7_gs(11, "golf"), 12: _p7_gs(12, "hotel", installed=False)}
    _pb7.get_game = lambda sid: _pb7_games[sid] if sid in _pb7_games else _p7_flask.abort(404)
    _pb7._button_backup_running = lambda sid: False
    _g_uninst = _pb7_c.post("/api/panel/backup/game/12", json={})
    eq("panel_backup/game: a server that is not installed is refused (400)",
       (_g_uninst.status_code, (_g_uninst.get_json() or {}).get("message")), (400, "Server is not installed."))
    # NOT a blocking acquire: if a regression above leaked the lock, a blocking one waits forever and
    # the whole suite hangs instead of the leak failing its own check by name.
    _g_held = _pb7._full_backup_lock.acquire(timeout=2)
    try:
        _g_busy = _pb7_c.post("/api/panel/backup/game/11", json={})
    finally:
        if _g_held:
            _pb7._full_backup_lock.release()
    check("panel_backup/game: while another backup holds the lock it is refused, not queued",
          (_g_busy.get_json() or {}).get("success") is False
          and "already running" in (_g_busy.get_json() or {}).get("message", ""), repr(_g_busy.get_json()))
    _pb7.bk = _Over(_pb7_saved["bk"], game_prune_keep=_p7_raise(RuntimeError("config")))
    _g_nostart = _pb7_c.post("/api/panel/backup/game/11", json={})
    check("panel_backup/game: a failure before the hand-off is a 500 that releases the lock",
          _g_nostart.status_code == 500 and not _pb7._full_backup_lock.locked()
          and _pb7._game_backup_status.get(11, {}).get("msg") == "couldn't start the backup",
          "status=%s locked=%r st=%r" % (_g_nostart.status_code, _pb7._full_backup_lock.locked(),
                                         _pb7._game_backup_status.get(11)))
    _pb7.bk = _Over(_pb7_saved["bk"], game_prune_keep=lambda sid: (4, True))
    _pb7_rows.clear()            # the server vanished between the click and the worker
    _pb7_c.post("/api/panel/backup/game/11", json={})
    check("panel_backup/game worker: a server deleted meanwhile is reported, and the lock released",
          _pb7._game_backup_status.get(11, {}).get("msg") == "server is no longer available"
          and not _pb7._full_backup_lock.locked(), repr(_pb7._game_backup_status.get(11)))
    _pb7_rows[11] = _pb7_games[11]
    _pb7.run_game_backup = _p7_raise(RuntimeError("no route to host"))
    _pb7_c.post("/api/panel/backup/game/11", json={})
    check("panel_backup/game worker: a backup that raises is recorded as failed, naming the error",
          _pb7._game_backup_status.get(11, {}).get("ok") is False
          and _pb7._game_backup_status.get(11, {}).get("msg", "").startswith("backup error (RuntimeError)")
          and not _pb7._full_backup_lock.locked(), repr(_pb7._game_backup_status.get(11)))

    # ── one archive: delete and download go only through the host's own listing ────────────────
    _pb7_deleted = []
    _pb7.list_game_backups = lambda remote, short: [{"name": "a.tar.gz", "size": 3},
                                                    {"name": "map—pack.tar.gz", "size": 6}]
    _pb7.delete_game_backup = lambda remote, short, name: (_pb7_deleted.append(name), True)[1]
    del _pb7_log[:]
    _gd = _pb7_c.post("/api/panel/backup/game/11/delete", json={"name": "a.tar.gz"})
    check("panel_backup/game delete: a listed archive is deleted by its LISTED name, and audited",
          (_gd.get_json() or {}) == {"success": True, "message": "Deleted."} and _pb7_deleted == ["a.tar.gz"]
          and _pb7_log == [("game_backup_delete", "golf", "a.tar.gz", True)],
          "%r deleted=%r log=%r" % (_gd.get_json(), _pb7_deleted, _pb7_log))
    _pb7.delete_game_backup = lambda remote, short, name: False
    del _pb7_log[:]
    _gd2 = _pb7_c.post("/api/panel/backup/game/11/delete", json={"name": "a.tar.gz"})
    check("panel_backup/game delete: a delete the host refuses is a failure, audited as one",
          (_gd2.get_json() or {}) == {"success": False, "message": "Delete failed."}
          and _pb7_log == [("game_backup_delete", "golf", "a.tar.gz", False)], "%r %r" % (_gd2.get_json(), _pb7_log))
    _pb7.delete_game_backup = _p7_raise(RuntimeError("ssh"))
    _gd3 = _pb7_c.post("/api/panel/backup/game/11/delete", json={"name": "a.tar.gz"})
    eq("panel_backup/game delete: a delete that raises answers a generic failure (no exception text)",
       (_gd3.status_code, _gd3.get_json()), (200, {"success": False, "message": "Internal server error"}))
    _pb7.stream_game_backup = lambda remote, short, name: iter([b"PK", b"DATA"])
    _gdl = _pb7_c.get("/backup/game/11/download", query_string={"name": "map—pack.tar.gz"})
    check("panel_backup/game download: streams the listed archive with its size and a safe filename header",
          _gdl.status_code == 200 and _gdl.data == b"PKDATA" and _gdl.headers.get("Content-Length") == "6"
          and "filename*=UTF-8''map%E2%80%94pack.tar.gz" in _gdl.headers.get("Content-Disposition", ""),
          "%s %r %r" % (_gdl.status_code, _gdl.data[:20], dict(_gdl.headers)))
    eq("panel_backup/game download: a name the listing does not have is a 404",
       _pb7_c.get("/backup/game/11/download", query_string={"name": "../../etc/shadow"}).status_code, 404)
    _pb7.list_game_backups = _p7_raise(ConnectionError("host down"))
    _gdl2 = _pb7_c.get("/backup/game/11/download", query_string={"name": "a.tar.gz"})
    check("panel_backup/game download: a listing that RAISES is 502 'could not read', never 'not found'",
          _gdl2.status_code == 502 and b"Couldn't read this server's backups" in _gdl2.data,
          "%s %r" % (_gdl2.status_code, _gdl2.data[:80]))

    # ── per-server schedule: a junk field clears, an absent one is left alone ─────────────────
    _pb7_sched = []
    _pb7.bk = _Over(_pb7_saved["bk"], set_game_schedule=lambda sid, iv, kp: (
        _pb7_sched.append((sid, iv, kp)), {"interval_days": 1, "keep": 2})[1])
    _pb7_c.post("/api/panel/backup/game/11/schedule", data='{"interval": "weekly", "keep": Infinity}',
                content_type="application/json")
    _pb7_c.post("/api/panel/backup/game/11/schedule", json={"interval": "5"})
    eq("panel_backup/schedule: junk (and JSON Infinity) clears a field; an absent field is UNCHANGED",
       _pb7_sched, [(11, None, None), (11, 5, _pb7_saved["bk"].UNCHANGED)])

    # ── the panel's own backups ──────────────────────────────────────────────────────────────
    _pb7.GameServer = _P7Boom()
    _bl = _pb7_c.get("/api/panel/backups")
    _pb7.GameServer = _P7GameServer
    eq("panel_backup/list: a failure answers a generic error body, not a 500 page",
       (_bl.status_code, _bl.get_json()), (200, {"error": "Internal server error"}))
    # One server's row on that page, driven directly. A backup still being WRITTEN is partial, so
    # it counts toward neither the bytes on disk nor the next-size estimate (the largest finished
    # archive is the worst case) — counted, a 90 MB half-written tar reads as the size to plan for.
    # Nothing drove this: counting in-progress archives passed every suite.
    _gbr_bk = _pb7.bk
    _pb7.bk = _Over(_pb7_saved["bk"], get_game_schedule=lambda sid: {"interval_days": 1, "keep": 3})
    _gbr_row, _gbr_bytes = _pb7._game_backup_row(
        _p7_gs(21, "rowtest"), [{"size": 5}, {"size": 90, "in_progress": True}, {"size": 7}],
        {"free": 100, "total": 200})
    check("panel_backup/list row: an archive still being written counts toward neither total nor estimate",
          _gbr_bytes == 12 and _gbr_row["est_backup"] == 7 and _gbr_row["backups_unreadable"] is False
          and len(_gbr_row["backups"]) == 3 and _gbr_row["host"] == "host"
          and _gbr_row["disk"] == {"free": 100, "total": 200}
          and _gbr_row["schedule"] == {"interval_days": 1, "keep": 3}, repr((_gbr_bytes, _gbr_row)))
    _gbr_row, _gbr_bytes = _pb7._game_backup_row(_p7_gs(22, "unread"), None, {"free": 0, "total": 0})
    check("panel_backup/list row: a listing that could not be read is flagged, not an empty list",
          _gbr_row["backups_unreadable"] is True and _gbr_row["backups"] == [] and _gbr_bytes == 0
          and _gbr_row["est_backup"] == 0, repr((_gbr_bytes, _gbr_row)))
    _pb7.bk = _gbr_bk
    del _pb7_log[:]
    _pb7.bk = _Over(_pb7_saved["bk"], create_backup=lambda kind: (True, "panel-backup-x.tar.gz"))
    _bc1 = _pb7_c.post("/api/panel/backup").get_json()
    _pb7.bk = _Over(_pb7_saved["bk"], create_backup=lambda kind: (False, "Backup refused: cred_key"))
    _bc2 = _pb7_c.post("/api/panel/backup").get_json()
    _pb7.bk = _Over(_pb7_saved["bk"], create_backup=_p7_raise(RuntimeError("disk")))
    _bc3 = _pb7_c.post("/api/panel/backup").get_json()
    eq("panel_backup/create: success names the archive; a refusal passes its reason on; a raise is generic",
       [_bc1, _bc2, _bc3],
       [{"success": True, "message": "Backup created.", "name": "panel-backup-x.tar.gz"},
        {"success": False, "message": "Backup refused: cred_key", "name": ""},
        {"success": False, "message": "Internal server error"}])
    eq("panel_backup/create: the audit row's success is the backup's",
       [(a, d, s) for a, _t, d, s in _pb7_log],
       [("panel_backup_create", "panel-backup-x.tar.gz", True), ("panel_backup_create", "", False)])
    _pbd_file = os.path.join(_p7_tf.mkdtemp(prefix="p7-pbd-"), "panel-backup-20240101-000000-manual.tar.gz")
    with open(_pbd_file, "wb") as f:
        f.write(b"ARCHIVE")
    _pb7.bk = _Over(_pb7_saved["bk"], _safe_path=lambda n: (_p7_pl.Path(_pbd_file)
                                                            if n == os.path.basename(_pbd_file) else None))
    _pbd = _pb7_c.get("/api/panel/backup/download/panel-backup-20240101-000000-manual.tar.gz")
    _pbd_body = _pbd.data
    _pbd.close()
    check("panel_backup/download: a validated backup is sent as an attachment under its own name",
          _pbd.status_code == 200 and _pbd_body == b"ARCHIVE"
          and "panel-backup-20240101-000000-manual.tar.gz" in _pbd.headers.get("Content-Disposition", ""),
          "%s %r" % (_pbd.status_code, dict(_pbd.headers)))
    eq("panel_backup/download: anything _safe_path rejects is a 404",
       _pb7_c.get("/api/panel/backup/download/other.tar.gz").status_code, 404)
    _p7_sh.rmtree(os.path.dirname(_pbd_file), ignore_errors=True)

    # ── settings: the passphrase rule, and the passphrase never reaches a log ──────────────────
    _pb7_pp = []
    _pb7.bk = _Over(_pb7_saved["bk"], set_settings=lambda **k: {"enabled": True},
                    set_full_settings=lambda **k: {"interval_days": 7},
                    set_passphrase=_pb7_pp.append,
                    get_settings=lambda: {"enabled": True, "encrypt": bool(_pb7_pp and _pb7_pp[-1])})
    del _pb7_log[:]
    _ps_short = _pb7_c.post("/api/panel/backup/settings", json={"passphrase": "short"})  # nosec B105 - a fixture passphrase
    check("panel_backup/settings: a passphrase under the minimum is a 400 and is NOT set",
          _ps_short.status_code == 400 and _pb7_pp == [] and _pb7_log == [],
          "%s set=%r log=%r" % (_ps_short.status_code, _pb7_pp, _pb7_log))
    _ps_ok = _pb7_c.post("/api/panel/backup/settings", json={"passphrase": "correct horse battery"})  # nosec B105 - a fixture passphrase
    _ps_off = _pb7_c.post("/api/panel/backup/settings", json={"passphrase": ""})  # nosec B105 - no passphrase
    check("panel_backup/settings: a long passphrase is set and '' turns encryption off, each audited",
          _pb7_pp == ["correct horse battery", ""]
          and [(a, d) for a, _t, d, _s in _pb7_log if a == "panel_backup_encryption"]
          == [("panel_backup_encryption", "enabled"), ("panel_backup_encryption", "disabled")]
          and (_ps_ok.get_json() or {}).get("settings", {}).get("encrypt") is True
          and (_ps_off.get_json() or {}).get("settings", {}).get("encrypt") is False,
          "set=%r log=%r" % (_pb7_pp, _pb7_log))
    check("panel_backup/settings: the passphrase appears in no audit row",
          not any("horse" in d for _a, _t, d, _s in _pb7_log), repr(_pb7_log))

    # ── host maintenance endpoints that live in this module ─────────────────────────────────────
    del _pb7_log[:]
    _pb7.so = _Over(_pb7_saved["so"], generate_debug_report=_p7_raise(RuntimeError("x")),
                    unattended_upgrades_status=_p7_raise(RuntimeError("x")),
                    enable_unattended_upgrades=lambda: (True, "Automatic security updates are now enabled."),
                    os_run_update=lambda: (False, "Sudo access required."),
                    server_reboot=lambda d: (True, "Server will reboot in %s seconds." % d))
    _dr = _pb7_c.get("/api/panel/debug-report")
    _au = _pb7_c.get("/api/panel/auto-updates")
    eq("panel_backup/debug-report and auto-updates: a failure is a 500 with a generic error",
       [(_dr.status_code, _dr.get_json()), (_au.status_code, _au.get_json())],
       [(500, {"error": "Internal server error"}), (500, {"error": "Internal server error"})])
    _eau = _pb7_c.post("/api/panel/enable-auto-updates")
    _our = _pb7_c.post("/api/server-management/os-update-run")
    _rbt = _pb7_c.post("/api/server-management/reboot", json={"delay": 10})
    eq("panel_backup/host actions: outcomes pass through; a refused OS update is a 500",
       [(_eau.status_code, _eau.get_json()), (_our.status_code, _our.get_json()),
        (_rbt.status_code, _rbt.get_json())],
       [(200, {"success": True, "message": "Automatic security updates are now enabled."}),
        (500, {"success": False, "message": "Sudo access required."}),
        (200, {"success": True, "message": "Server will reboot in 10 seconds."})])
    eq("panel_backup/host actions: only what happened is audited (no row for the refused update)",
       [(a, d, s) for a, _t, d, s in _pb7_log],
       [("enable_auto_updates", "Automatic security updates are now enabled.", True),
        ("server_reboot", "delay=10s", True)])
    del _pb7_log[:]
    _pb7.so = _Over(_pb7_saved["so"], enable_unattended_upgrades=_p7_raise(RuntimeError("apt")),
                    os_run_update=lambda: (True, "OS update started in background."),
                    server_reboot=lambda d: (False, "Sudo access required for reboot."))
    _eau2 = _pb7_c.post("/api/panel/enable-auto-updates")
    _our2 = _pb7_c.post("/api/server-management/os-update-run")
    _rbt2 = _pb7_c.post("/api/server-management/reboot", json={})
    eq("panel_backup/host actions: the other half — a raise is a 500, a refused reboot is a 500",
       [(_eau2.status_code, (_eau2.get_json() or {}).get("success")), (_our2.status_code, _our2.get_json()),
        (_rbt2.status_code, _rbt2.get_json())],
       [(500, False), (200, {"success": True, "message": "OS update started in background."}),
        (500, {"success": False, "message": "Sudo access required for reboot."})])
    eq("panel_backup/host actions: ...and the audit has the update that started, not the reboot that did not",
       [a for a, _t, _d, _s in _pb7_log], ["os_update_run"])
except Exception as e:  # noqa: BLE001 - a harness failure must fail by name, not end the suite
    check("panel_backup: the route harness ran to the end", False, "raised %s: %s" % (type(e).__name__, e))
finally:
    for _k in _pb7_names:
        setattr(_pb7, _k, _pb7_saved[_k])
    _p7_auth.current_user = _pb7_auth_user
    _pb7._game_backup_status.clear()
    _pb7._game_backup_status.update(globals().get("_pb7_gbs_snap", {}))


# ══ panel/ops/system_ops.py ══════════════════════════════════════════════════════════════════════
# The panel host's own maintenance: the privileged-verb runner, self-update and branch switching,
# the panel's fail2ban jail, UFW deny bookkeeping, diagnostics and the debug report. _run, _run_verb
# and subprocess are stubbed ON system_ops for every call, and PANEL_DIR / the fail2ban file paths /
# config's data paths point into a temp dir, so nothing here executes a command or reads a real
# /etc file. `open` is shadowed on the module (a module global beats the builtin) where a /proc or
# /etc read has to fail on cue, and deleted again afterwards.
import shlex as _p7_shlex  # noqa: E402
import builtins as _p7_builtins  # noqa: E402
import platform as _p7_platform  # noqa: E402
from datetime import datetime as _p7_dt, timedelta as _p7_td, timezone as _p7_tz  # noqa: E402
from panel.security import privileged as _p7_priv  # noqa: E402

_so7_names = ("_run", "_run_verb", "_helper_present", "subprocess", "os", "time", "_git",
              "_is_git_checkout", "PANEL_DIR", "_is_system_service", "_tracked_branch",
              "_fetch_all_branches", "_launch_installer", "_write_root_file",
              "unattended_upgrades_status", "panel_fail2ban_status", "_F2B_PANEL_FILTER",
              "_F2B_PANEL_JAIL", "fail2ban_overview", "_fail2ban_jails", "ufw_blocked_ips",
              "detect_tailscale_interface", "panel_integrity", "panel_diagnostics", "panel_version",
              "panel_update_log", "_repo_slug", "fail2ban_unban", "_panel_login_proxied")
_so7_saved = {k: getattr(SO, k) for k in _so7_names}
_so7_state = {k: dict(getattr(SO, k)) for k in ("_last_cpu_stat", "_CPU_SAMPLE", "_HELPER_STATE",
                                                 "_update_cache", "_integrity_cache")}
_cfg7_names = ("load_config", "update_config", "DATA_DIR", "DB_PATH", "SECRET_FILE", "CRED_KEY_FILE")
_cfg7_saved = {k: getattr(_p7_cfgmod, k) for k in _cfg7_names}
_s7 = _p7_tf.mkdtemp(prefix="p7-so-")


def _p7_defined(mod, name, *roots):
    """Return `mod.name` as the module DEFINES it, or None if it cannot be found.

    Found by walking closures from `roots` (default: the current `mod.name`). Why a walk: by this
    point in the suite system_ops._run is NOT the function. part03's auto-updates block assigns
    `_so._run = _mk_run(1, "")` and never puts it back, part05 then runs tools/nosudo_runner.py's
    _install() over that (also never undone), and under tools/smoke-local.sh the runner's own
    wrapper sits at the bottom. part02 kept a reference to whatever _run was before any of that
    (`_orig_so_run`), which is why it is passed as a root.
    """
    todo, seen = list(roots) or [getattr(mod, name)], set()
    while todo:
        f = todo.pop()
        if id(f) in seen:
            continue
        seen.add(id(f))
        code = getattr(f, "__code__", None)
        if code is not None and code.co_filename == mod.__file__ and f.__name__ == name:
            return f
        todo.extend(_p7_cells(f))
    return None


def _p7_cells(f):
    """Return what `f`'s closure cells hold, skipping any cell that is still empty."""
    out = []
    for cell in (getattr(f, "__closure__", None) or ()):
        try:
            out.append(cell.cell_contents)
        except ValueError:  # nosec B112 - an empty cell holds nothing to walk
            continue
    return out


def _p7_run_by(table, default=("", "", 1), log=None):
    """A _run stub answering by the first (substring, answer) whose substring is in the command."""
    def _r(cmd, *a, **k):
        if log is not None:
            log.append((cmd, k.get("sudo", False)))
        for key, val in table:
            if key in cmd:
                if isinstance(val, Exception):
                    raise val
                return val
        return default
    return _r


def _p7_verb_by(table, default=("", "", 1), log=None):
    """A _run_verb stub answering by verb name; an answer may be a function of the args."""
    def _v(verb, args=(), timeout=30, merge_stderr=True):
        if log is not None:
            log.append((verb, list(args)))
        v = table.get(verb, default)
        if callable(v):
            v = v(list(args))
        if isinstance(v, Exception):
            raise v
        return v
    return _v


def _p7_sp_run(log, result=None, exc=None):
    """A subprocess.run stub: records (argv, kwargs), then raises `exc` or returns `result`."""
    def _r(argv, *a, **kw):
        log.append((argv, kw))
        if exc is not None:
            raise exc
        return result if result is not None else _p7_sp.CompletedProcess(argv, 0, "", "")
    return _r


def _p7_sp_popen(log, out=b"", err=b"", rc=0, exc=None, hang=False):
    """A subprocess.Popen stub for _run_verb's capped reader.

    Records (argv, kwargs) and each wait()'s timeout; raises `exc` from the constructor, or hands
    back a process whose pipes hold `out` / `err` and whose wait() answers `rc` — or runs out of
    time, when `hang`.
    """
    class _P7Proc:
        pid = -1

        def __init__(self, argv, *a, **kw):
            log.append((argv, kw))
            if exc is not None:
                raise exc
            self.stdout, self.stderr, self.stdin = _p7_io.BytesIO(out), _p7_io.BytesIO(err), None

        def wait(self, timeout=None):
            log.append(("wait", timeout))
            if hang:
                raise _p7_sp.TimeoutExpired("verb", timeout)
            return rc

        def kill(self):
            return None

        def communicate(self, timeout=None):
            return b"", b""
    return _P7Proc


def _p7_open_with(files, missing_raises=OSError):
    """Build an `open` for system_ops that answers the listed paths from `files`.

    A listed path answers its text (or raises, if the value is an exception); every other path
    goes to the real open.
    """
    def _o(path, *a, **k):
        if path in files:
            v = files[path]
            if isinstance(v, Exception):
                raise v
            return _p7_io.StringIO(v)
        return _p7_builtins.open(path, *a, **k)
    return _o


def _p7_so_reset():
    for _k in _so7_names:
        setattr(SO, _k, _so7_saved[_k])
    SO.__dict__.pop("open", None)


def _so7_setup():
    SO.time = _Over(_p7_time, sleep=lambda s: None)          # nothing below may really sleep
    SO._is_system_service = lambda: False


def _so7_run_verb_three_ways():
    # ── _run_verb: the three ways a command fails come back as values, never exceptions
    _sv = []
    SO._helper_present = lambda: False
    SO.os = _Over(os, geteuid=lambda: 0)                        # root: the tool runs directly
    # Popen, read through the transports' capped reader (see _collect_verb_output), not
    # subprocess.run: capture_output kept every byte a verb printed.
    SO.subprocess = _Over(_so7_saved["subprocess"],
                          Popen=_p7_sp_popen(_sv, b"out\n", b"err\n", 3))
    _v_merged = SO._run_verb("ufw-status", ["verbose"], timeout=9)
    _v_split = SO._run_verb("ufw-status", ["verbose"], timeout=9, merge_stderr=False)
    _sv_runs = [(a, k) for a, k in _sv if a != "wait"]
    check("so/_run_verb as root: runs the tool's own argv, no shell, stdin closed",
          [a for a, _k in _sv_runs] == [["ufw", "status", "verbose"]] * 2
          and _sv_runs[0][1].get("shell") is False
          and _sv_runs[0][1].get("stdin") == _p7_sp.DEVNULL
          and [k for a, k in _sv if a == "wait"] == [9, 9], repr(_sv[:2]))
    eq("so/_run_verb: stderr is merged into stdout by default, kept apart on request",
       (_v_merged, _v_split), (("out\nerr", "", 3), ("out", "err", 3)))
    _v_fail = []
    for _pk in ({"hang": True}, {"exc": FileNotFoundError("ufw")}, {"exc": OSError("EIO")}):
        SO.subprocess = _Over(_so7_saved["subprocess"], Popen=_p7_sp_popen([], **_pk))
        _v_fail.append(_p7_call(SO._run_verb, "ufw-status", ["verbose"]))
    eq("so/_run_verb: timeout, a missing tool and any other error each come back as rc -1",
       _v_fail, [("", "Command timed out", -1), ("", "Command not found", -1),
                 ("", "command execution error", -1)])
    SO.os, SO.subprocess = _so7_saved["os"], _so7_saved["subprocess"]
    SO._helper_present = _so7_saved["_helper_present"]


def _so7_run_shell_runner_itself():
    # ── _run: the shell runner itself (the definition, not a runner's wrapper)
    global _exc
    from unit.part02 import _orig_so_run as _p7_run_before_leaks  # noqa: E402
    _real_run = _p7_defined(SO, "_run", _p7_run_before_leaks, SO._run)
    if _real_run is None:
        skip("so/_run: sudo is prefixed only when not already root", "could not find system_ops._run's definition")
        skip("so/_run: timeout, missing binary and other errors are values", "could not find system_ops._run's definition")
    else:
        _rr = []
        SO.subprocess = _Over(_so7_saved["subprocess"],
                              run=_p7_sp_run(_rr, _p7_sp.CompletedProcess("x", 0, " hi \n", " e ")))
        SO.os = _Over(os, geteuid=lambda: 1000)
        _rr_user = _real_run("ufw status", sudo=True)
        SO.os = _Over(os, geteuid=lambda: 0)
        _real_run("ufw status", sudo=True)
        SO.os = _so7_saved["os"]
        check("so/_run: sudo is prefixed only when not already root, and output is stripped",
              [a for a, _k in _rr] == ["sudo ufw status", "ufw status"] and _rr_user == ("hi", "e", 0)
              and _rr[0][1].get("shell") is True and _rr[0][1].get("stdin") == _p7_sp.DEVNULL,
              repr(_rr))
        _rr_fail = []
        for _exc in (_p7_sp.TimeoutExpired("x", 1), FileNotFoundError("x"), ValueError("bad")):
            SO.subprocess = _Over(_so7_saved["subprocess"], run=_p7_sp_run([], exc=_exc))
            _rr_fail.append(_p7_call(_real_run, "true"))
        SO.subprocess = _so7_saved["subprocess"]
        eq("so/_run: timeout, missing binary and other errors are values, with no exception text",
           _rr_fail, [("", "Command timed out", -1), ("", "Command not found", -1),
                      ("", "command execution error", -1)])


def _so7_tracked_branch_helper_present():
    # ── _tracked_branch / _helper_present: a failed read picks the safe answer
    _p7_cfgmod.load_config = _p7_raise(OSError("EIO"))
    try:
        eq("so/_tracked_branch: an unreadable config follows the default branch", SO._tracked_branch(), "main")
    finally:
        _p7_cfgmod.load_config = _cfg7_saved["load_config"]
    SO._HELPER_STATE["present"] = None
    SO.os = _Over(os, path=_Over(os.path, isfile=_p7_raise(PermissionError("EACCES"))))
    try:
        _hp = _p7_call(SO._helper_present)
    finally:
        SO.os = _so7_saved["os"]
    check("so/_helper_present: a helper that cannot even be stat'ed is 'not present' (and cached)",
          _hp is False and SO._HELPER_STATE["present"] is False, repr(_hp))
    SO._HELPER_STATE.update(_so7_state["_HELPER_STATE"])


def _so7_live_metrics_from_proc():
    # ── live metrics from /proc: an unreadable /proc is flagged, never a confident zero
    global _lm0, _stat_txt
    _stat_txt = "cpu  100 0 100 800 0 0 0 0\ncpu0 50 0 50 400 0 0 0\ncpu1 50 0 50 400 0 0 0\n"
    _mem_txt = "MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
    SO._last_cpu_stat.update({"cpus": None, "ts": 0.0})
    SO.open = _p7_open_with({"/proc/stat": _stat_txt, "/proc/meminfo": _mem_txt})
    try:
        _lm = _p7_call(SO.live_metrics)
    finally:
        SO.__dict__.pop("open", None)
    check("so/live_metrics: a counter that did not move reads 0%, and memory is parsed to bytes",
          isinstance(_lm, dict) and _lm["read_ok"] is True and _lm["cpu_cores"] == [0.0, 0.0]
          and _lm["cpu_overall"] == 0.0 and _lm["ram_total"] == 1024000 and _lm["ram_percent"] == 75.0,
          repr(_lm))
    SO._last_cpu_stat.update({"cpus": None, "ts": 0.0})
    SO.open = _p7_open_with({"/proc/stat": OSError("EACCES"), "/proc/meminfo": OSError("EACCES")})
    _du_real = _p7_sh.disk_usage
    _p7_sh.disk_usage = _p7_raise(OSError("statvfs"))
    try:
        _lm0 = _p7_call(SO.live_metrics)
    finally:
        _p7_sh.disk_usage = _du_real
        SO.__dict__.pop("open", None)


def _so7_live_metrics_from_proc_2():
    check("so/live_metrics: nothing readable is read_ok=False with zeros — not an idle host",
          isinstance(_lm0, dict) and _lm0["read_ok"] is False and _lm0["core_count"] == 0
          and _lm0["ram_total"] == 0 and _lm0["disk_total"] == 0 and _lm0["disk_percent"] == 0,
          repr(_lm0))
    SO._last_cpu_stat.clear()
    SO._last_cpu_stat.update(_so7_state["_last_cpu_stat"])
    _junk_stat = "cpu  1 2 x 4 5 6 7 8\n"
    SO.open = _p7_open_with({"/proc/stat": _junk_stat})
    try:
        _jf = _p7_call(SO._read_cpu_jiffies)
        SO.open = _p7_open_with({"/proc/stat": OSError("gone")})
        _jf2 = _p7_call(SO._read_cpu_jiffies)
        _jf3 = _p7_call(SO._local_cpu_percent)
        SO._CPU_SAMPLE.update({"idle": 0, "total": 0})
        SO.open = _p7_open_with({"/proc/stat": _stat_txt})           # never advances
        _jf4 = _p7_call(SO._local_cpu_percent)
    finally:
        SO.__dict__.pop("open", None)
        SO._CPU_SAMPLE.clear()
        SO._CPU_SAMPLE.update(_so7_state["_CPU_SAMPLE"])
    eq("so/cpu%: an unparseable or unreadable /proc/stat is (0, 0), and the percent is unknown ('')",
       (_jf, _jf2, _jf3, _jf4), ((0, 0), (0, 0), "", ""))


def _so7_ufw_tailscale_reads():
    # ── UFW / Tailscale reads
    SO._run_verb = _p7_verb_by({"ufw-status": ("Status: active\n\nTo  Action  From\n--  ------  ----\n"
                                                "22/tcp                     ALLOW IN    Anywhere\n"
                                                "22/tcp (v6)                ALLOW IN    Anywhere (v6)\n", "", 0)})
    _us = _p7_call(SO.ufw_status)
    SO._run_verb = _so7_saved["_run_verb"]
    eq("so/ufw_status: the (v6) duplicate rows are not listed twice",
       (_us["enabled"], _us["rules"]) if isinstance(_us, dict) else _us,
       (True, [{"to": "22/tcp", "action": "ALLOW", "direction": "IN", "from": "Anywhere"}]))
    eq("so/ufw_allows_iface_in: no interface is never 'allowed'",
       SO.ufw_allows_iface_in([{"to": "Anywhere on ", "action": "ALLOW", "direction": "IN"}], ""), False)
    SO.detect_tailscale_interface = lambda: None
    _at_none = _p7_call(SO.ufw_allow_tailscale)
    SO.detect_tailscale_interface = _so7_saved["detect_tailscale_interface"]
    _at_log = []
    SO._run_verb = _p7_verb_by({"ufw-allow-iface": ("", "ERROR: Could not find a profile", 1)}, log=_at_log)
    _at_fail = _p7_call(SO.ufw_allow_tailscale, "tailscale0")
    SO._run_verb = _so7_saved["_run_verb"]
    eq("so/ufw_allow_tailscale: no interface refuses; a UFW error is passed back, not 'added'",
       (_at_none, _at_fail, _at_log),
       ((False, "Could not detect Tailscale interface. Is Tailscale running?"),
        (False, "ERROR: Could not find a profile"), [("ufw-allow-iface", ["tailscale0"])]))
    SO._run = _p7_run_by([("type wireguard", ("", "", 0)), ("grep -i tailscale", ("", "", 1)),
                          ("ip link show tailscale", ("", "", 0)),
                          ("tailscale status --json", ('{"TUN": true}', "", 0))])
    _dti_tun = _p7_call(SO.detect_tailscale_interface)
    SO._run = _p7_run_by([("type wireguard", ("", "", 0)), ("grep -i tailscale", ("", "", 1)),
                          ("ip link show tailscale", ("", "", 0)),
                          ("tailscale status --json", ('{"TUN": false}', "", 0))])
    _dti_none = _p7_call(SO.detect_tailscale_interface)
    SO._run = _p7_run_by([("status --json", ("not json", "", 0)), ("debug prefs", ("{truncated", "", 0))])
    _tss = _p7_call(SO.tailscale_ssh_status)
    SO._run = _so7_saved["_run"]
    eq("so/detect_tailscale_interface: tailscaled's own TUN flag names tailscale0; without it, nothing",
       (_dti_tun, _dti_none), ("tailscale0", None))
    eq("so/tailscale_ssh_status: unparseable status and prefs are 'not running, could not read'",
       _tss, {"enabled": False, "running": False, "error": "Could not read Tailscale prefs"})


def _so7_apt_history():
    # ── apt history
    _apt_hist = ("Upgrade: zlib1g:amd64 (1:1.2.11, 1:1.2.13)\nEnd-Date: 2024-04-30  06:00:03\n\n"
                 "Start-Date: 2024-05-01  06:00:01\nCommandline: apt-get install htop\n"
                 "Install: htop:amd64 (3.0.5-7build2)\nEnd-Date: 2024-05-01  06:00:03\n\n"
                 "Start-Date: 2024-05-02  06:00:01\nCommandline: /usr/bin/unattended-upgrade\n"
                 "Upgrade: libc6:amd64 (2.35-0ubuntu3.6, 2.35-0ubuntu3.7), openssl:amd64 (3.0.2, 3.0.2-1)\n")
    _ah_log = []
    SO.os = _Over(os, path=_Over(os.path, exists=lambda p: p == "/var/log/apt/history.log" or os.path.exists(p)))
    SO._run = _p7_run_by([("history.log", (_apt_hist, "", 0))], log=_ah_log)
    _ah = _p7_call(SO.os_update_log)
    SO.os, SO._run = _so7_saved["os"], _so7_saved["_run"]
    eq("so/os_update_log: records are split on Start-Date, the cut-off first one dropped, packages named",
       _ah, [{"start": "2024-05-01  06:00:01", "command": "apt-get install htop", "packages": ["htop"]},
             {"start": "2024-05-02  06:00:01", "command": "/usr/bin/unattended-upgrade",
              "packages": ["libc6", "openssl"]}])


def _so7_git_update_machinery_failure():
    # ── git: the update machinery's failure answers
    global _cus, _cus_nf
    _gl = []
    SO.subprocess = _Over(_so7_saved["subprocess"], run=_p7_sp_run(_gl, exc=_p7_sp.TimeoutExpired("git", 45)))
    _g_to = _p7_call(SO._git, ["fetch"])
    SO.subprocess = _Over(_so7_saved["subprocess"], run=_p7_sp_run([], exc=FileNotFoundError("git")))
    _g_nf = _p7_call(SO._git, ["fetch"])
    SO.subprocess = _so7_saved["subprocess"]
    check("so/_git: no shell, never prompts for credentials; a hang and a missing git are values",
          _g_to == ("", "git timed out", -1) and _g_nf == ("", "git not found", -1)
          and _gl and _gl[0][0][:3] == ["git", "-C", SO.PANEL_DIR]
          and _gl[0][1]["env"].get("GIT_TERMINAL_PROMPT") == "0" and "shell" not in _gl[0][1],
          "%r %r %r" % (_g_to, _g_nf, _gl[:1]))
    SO._is_git_checkout = lambda: True
    SO._git = lambda args, timeout=45: ("", "fatal", 128)
    _pc_fail = SO.panel_commit()
    _slug_fail = SO._repo_slug()
    SO._git = lambda args, timeout=45: (("abc1234", "", 0) if args[0] == "rev-parse" else (" M app.py", "", 0))
    _pc_dirty = SO.panel_commit()
    SO._repo_slug = lambda: None
    _ci_noslug = SO._remote_ci_state("abc1234")
    SO._repo_slug = _so7_saved["_repo_slug"]
    eq("so/git reads: a failed rev-parse is '', a dirty tree is '+', no origin slug is 'unknown' CI",
       (_pc_fail, _pc_dirty, _slug_fail, _ci_noslug), ("", "abc1234+", None, "unknown"))
    eq("so/_is_runtime_path: a './' prefix is dropped (dotdirs kept), and nothing is not runtime",
       [SO._is_runtime_path(p) for p in ("./app.py", "./.github/x.yml", "./", "  ")],
       [True, False, False, False])
    SO._git = lambda args, timeout=45: ("", "fatal: bad revision", 128)
    eq("so/_runtime_changelog: a log git refuses is no changes, not a crash", SO._runtime_changelog("HEAD..x"), [])
    SO._tracked_branch = lambda: "main"
    SO._git = lambda args, timeout=45: {"rev-parse": ("abc1234", "", 0), "fetch": ("", "", 0),
                                        "show-ref": ("", "", 1)}.get(args[0], ("", "", 0))
    _cus = _p7_call(SO._compute_update_status)
    SO._git = lambda args, timeout=45: {"rev-parse": ("abc1234", "", 0),
                                        "fetch": ("", "fatal: could not read Username", 128)}.get(args[0], ("", "", 0))
    _cus_nf = _p7_call(SO._compute_update_status)


def _so7_git_update_machinery_failure_2():
    global _k
    check("so/update status: a source it cannot fetch offers nothing from the stale tracking ref",
          isinstance(_cus_nf, dict) and _cus_nf.get("fetched") is False and _cus_nf.get("update_available") is False
          and _cus_nf.get("message", "").startswith("Couldn't reach the update source"), repr(_cus_nf))
    check("so/update status: a fetched source with no such branch is NOT 'up to date' and offers nothing",
          isinstance(_cus, dict) and _cus.get("fetched") is False and _cus.get("update_available") is False
          and _cus.get("message") == "The update source has no branch 'main' to compare against.",
          repr(_cus))
    SO._is_git_checkout = lambda: False
    eq("so/panel_self_update: not a git checkout is refused up front", SO.panel_self_update(),
       (False, "The panel isn't a git checkout, so it can't self-update."))
    for _k in ("_git", "_is_git_checkout", "_tracked_branch"):
        setattr(SO, _k, _so7_saved[_k])


def _so7_launch_installer_detached_updater():
    # ── _launch_installer: the detached updater, in a temp PANEL_DIR
    global _li, _li_sys, _pd
    _pd = os.path.join(_s7, "panel")
    os.makedirs(os.path.join(_pd, "data"))
    SO.PANEL_DIR = _pd
    eq("so/_launch_installer: no install.sh is refused",
       SO._launch_installer("abc1234", "main"),
       (False, "install.sh is missing, so the panel can't self-update safely."))
    open(os.path.join(_pd, "install.sh"), "w").close()
    eq("so/_launch_installer: an invalid branch is refused before anything is written",
       (SO._launch_installer("abc1234", "-x"), os.path.exists(os.path.join(_pd, "data", "self-update.sh"))),
       ((False, "Invalid branch name."), False))
    os.makedirs(os.path.join(_pd, "data", "self-update.log"))    # an old log it cannot unlink
    _li = []
    SO.subprocess = _Over(_so7_saved["subprocess"], run=_p7_sp_run(_li, _p7_sp.CompletedProcess([], 0, "", "")))
    SO._update_cache["ts"] = 123.0
    _li_ok = _p7_call(SO._launch_installer, "abc1234", "main")
    _li_script = os.path.join(_pd, "data", "self-update.sh")
    _li_text = open(_li_script).read() if os.path.exists(_li_script) else ""
    check("so/_launch_installer (user unit): launched detached via systemd-run --user, cache invalidated",
          isinstance(_li_ok, tuple) and _li_ok[0] is True and SO._update_cache["ts"] == 0.0
          and [a for a, _k in _li] == [["systemd-run", "--user", "--no-block", "--collect", "--unit",
                                        "panel-selfupdate", "/bin/bash", _li_script]],
          "%r %r" % (_li_ok, _li))
    check("so/_launch_installer: the wrapper pins the verified commit, the branch, and no OS upgrade",
          "export PANEL_UPDATE_REF=abc1234\n" in _li_text and "export PANEL_BRANCH=main\n" in _li_text
          and "export PANEL_NO_UPGRADE=1\n" in _li_text
          and (os.stat(_li_script).st_mode & 0o777) == 0o700, _li_text)
    SO._is_system_service = lambda: True
    SO._helper_present = lambda: False
    del _li[:]
    _li_sys = _p7_call(SO._launch_installer, "", "")


def _so7_launch_installer_detached_updater_2():
    check("so/_launch_installer (system unit, no helper): the launcher is sudo systemd-run",
          isinstance(_li_sys, tuple) and _li_sys[0] is True and _li and _li[0][0][:2] == ["sudo", "systemd-run"],
          "%r %r" % (_li_sys, _li[:1]))
    _li_verbs = []
    SO._helper_present = lambda: True
    SO._run_verb = _p7_verb_by({"panel-self-update": ("", "unknown verb", 2)}, log=_li_verbs)
    _li_helper = _p7_call(SO._launch_installer, "", "")
    SO._helper_present, SO._run_verb = _so7_saved["_helper_present"], _so7_saved["_run_verb"]
    eq("so/_launch_installer (helper): a verb the helper refuses is a failure; '-' stands for 'none'",
       (_li_helper, _li_verbs), ((False, "Could not start the updater — check the panel logs."),
                                 [("panel-self-update", ["-", "-"])]))
    SO._is_system_service = lambda: False
    SO.subprocess = _Over(_so7_saved["subprocess"], run=_p7_sp_run([], exc=OSError("no systemd-run")))
    eq("so/_launch_installer: a launcher that cannot run is a failure, not an exception",
       _p7_call(SO._launch_installer, "abc1234", "main"),
       (False, "Could not start the updater — check the panel logs."))
    SO.subprocess = _so7_saved["subprocess"]


def _so7_branches():
    # ── branches
    global _k
    SO._is_git_checkout = lambda: True
    SO._tracked_branch = lambda: "feature/x"
    SO._fetch_all_branches = lambda: None
    SO._git = lambda args, timeout=45: ("refs/remotes/origin/main\nrefs/remotes/origin/HEAD\nrefs/heads/local\n"
                                        "refs/remotes/origin/dev\nrefs/remotes/origin/-bad\n", "", 0)
    eq("so/list_panel_branches: only valid origin branches, and the tracked one is always offered first",
       SO.list_panel_branches(), (["feature/x", "main", "dev"], "feature/x"))
    eq("so/panel_switch_branch: an invalid name is refused", SO.panel_switch_branch("../x"),
       (False, "Invalid branch name."))
    SO._is_git_checkout = lambda: False
    eq("so/panel_switch_branch: not a checkout is refused", SO.panel_switch_branch("dev"),
       (False, "The panel isn't a git checkout, so it can't switch branches."))
    SO._is_git_checkout = lambda: True
    SO._git = lambda args, timeout=45: ("0123abc\trefs/heads/dev\n", "", 0)
    _p7_cfgmod.load_config = lambda: {}
    _p7_cfgmod.update_config = _p7_raise(OSError("read-only"))
    _sw_launch = []
    SO._launch_installer = lambda **k: (_sw_launch.append(k), (True, "started"))[1]
    try:
        _sw_nosave = _p7_call(SO.panel_switch_branch, "dev")
        _sw_writes = []

        def _p7_upd_once(fn):
            _sw_writes.append(fn)
            if len(_sw_writes) > 1:
                raise OSError("disk full")
        _p7_cfgmod.update_config = _p7_upd_once
        SO._launch_installer = lambda **k: (False, "install.sh is missing, so the panel can't self-update safely.")
        _sw_noroll = _p7_call(SO.panel_switch_branch, "dev")
    finally:
        _p7_cfgmod.load_config, _p7_cfgmod.update_config = _cfg7_saved["load_config"], _cfg7_saved["update_config"]
    check("so/panel_switch_branch: a branch selection that cannot be saved launches nothing",
          _sw_nosave == (False, "Could not save the branch selection.") and _sw_launch == [],
          "%r %r" % (_sw_nosave, _sw_launch))
    check("so/panel_switch_branch: a failed launch whose roll-back ALSO fails still reports the failure",
          _sw_noroll == (False, "install.sh is missing, so the panel can't self-update safely.")
          and len(_sw_writes) == 2, "%r writes=%d" % (_sw_noroll, len(_sw_writes)))
    for _k in ("_git", "_is_git_checkout", "_tracked_branch", "_fetch_all_branches", "_launch_installer"):
        setattr(SO, _k, _so7_saved[_k])


def _so7_restart_panel():
    # ── restart_panel
    SO.subprocess = _Over(_so7_saved["subprocess"], run=_p7_sp_run([], exc=OSError("no bus")))
    _rp_user = _p7_call(SO.restart_panel)
    SO.subprocess = _so7_saved["subprocess"]
    SO._is_system_service = lambda: True
    _rp_v = []
    SO._run_verb = _p7_verb_by({"panel-restart": ("", "a password is required", 1)}, log=_rp_v)
    _rp_sys = _p7_call(SO.restart_panel, 9999)
    SO._run_verb = _p7_verb_by({"panel-restart": RuntimeError("helper crashed")})
    _rp_raise = _p7_call(SO.restart_panel)
    SO._run_verb = _so7_saved["_run_verb"]
    SO._is_system_service = lambda: False
    _rp_msg = (False, "Could not restart the panel — check the panel logs.")
    eq("so/restart_panel: a launcher error, a refused verb and a raising verb are all reported failures",
       (_rp_user, _rp_sys, _rp_raise), (_rp_msg, _rp_msg, _rp_msg))
    eq("so/restart_panel: the delay handed across the boundary is clamped to 300",
       _rp_v, [("panel-restart", ["300"])])


def _so7_panel_repair_database():
    # ── panel_repair_database
    global _k
    eq("so/panel_repair_database: an install without its venv or db_maintenance is refused",
       SO.panel_repair_database(), (False, "The repair tool isn't available on this install."))
    os.makedirs(os.path.join(_pd, "venv", "bin"))
    open(os.path.join(_pd, "venv", "bin", "python"), "w").close()     # 'python', not 'python3'
    open(os.path.join(_pd, "db_maintenance.py"), "w").close()
    SO._is_system_service = lambda: True
    SO._helper_present = lambda: True
    _pr_v = []
    SO._run_verb = _p7_verb_by({"panel-db-repair": ("", "", 0)}, log=_pr_v)
    _pr_ok = _p7_call(SO.panel_repair_database)
    SO._run_verb = _p7_verb_by({"panel-db-repair": ("", "denied", 1)})
    _pr_no = _p7_call(SO.panel_repair_database)
    check("so/panel_repair_database (helper): the verb starts it; a refusal is reported as one",
          isinstance(_pr_ok, tuple) and _pr_ok[0] is True and _pr_v == [("panel-db-repair", [])]
          and _pr_no == (False, "Couldn't start the repair job — check the panel logs."),
          "%r %r %r" % (_pr_ok, _pr_v, _pr_no))
    SO._helper_present = lambda: False
    _pr_sp = []
    SO.subprocess = _Over(_so7_saved["subprocess"], run=_p7_sp_run(_pr_sp))
    _pr_leg = _p7_call(SO.panel_repair_database)
    _pr_want = ("sudo systemctl stop linuxgsm-panel.service; ( cd %s && %s %s update ); "
                "sudo systemctl start linuxgsm-panel.service"
                % (_p7_shlex.quote(_pd), _p7_shlex.quote(os.path.join(_pd, "venv", "bin", "python")),
                   _p7_shlex.quote(os.path.join(_pd, "db_maintenance.py"))))
    check("so/panel_repair_database (pre-helper): stop, repair with the venv's python, start — one detached unit",
          isinstance(_pr_leg, tuple) and _pr_leg[0] is True and _pr_sp
          and _pr_sp[0][0] == ["sudo", "systemd-run", "--collect", "--on-active=2", "bash", "-c", _pr_want],
          "%r %r" % (_pr_leg, _pr_sp[:1]))
    SO.subprocess = _Over(_so7_saved["subprocess"], run=_p7_sp_run([], exc=OSError("ENOENT")))
    eq("so/panel_repair_database: a launcher that cannot run is a failure",
       _p7_call(SO.panel_repair_database), (False, "Couldn't start the repair job — check the panel logs."))
    for _k in ("subprocess", "_run_verb", "_helper_present"):
        setattr(SO, _k, _so7_saved[_k])
    SO._is_system_service = lambda: False
    SO.PANEL_DIR = _so7_saved["PANEL_DIR"]


def _so7_lockout_guards_port_use():
    # ── lockout guards: port_in_use / host_has_ip
    SO._run = _p7_raise(RuntimeError("fork failed"))
    _piu = _p7_call(SO.port_in_use, 8080)
    SO._run = _p7_run_by([("ss -H", ("0.0.0.0:5000\n[::]:8080\n", "", 0))])
    _piu2 = (SO.port_in_use(8080), SO.port_in_use(8081))
    SO._run = _p7_run_by([("ip -o addr", ("garbage 10.9.8.7\n", "", 0))])
    _hhi = (SO.host_has_ip("10.9.8.7"), SO.host_has_ip("10.9.8.8"))
    SO._run = _p7_raise(RuntimeError("fork failed"))
    _hhi_raise = _p7_call(SO.host_has_ip, "192.0.2.77")      # TEST-NET-1: never a local address
    SO._run = _so7_saved["_run"]
    eq("so/port_in_use: a failed probe is 'free' (the restart is the backstop); a listener is found",
       (_piu, _piu2), (False, (True, False)))
    eq("so/host_has_ip: a junk token is skipped, the listed address is matched exactly",
       _hhi, (True, False))
    eq("so/host_has_ip: an address list that cannot be read asks the kernel — which says no",
       _hhi_raise, False)
    SO.open = _p7_open_with({"/proc/sys/net/ipv4/ip_nonlocal_bind": "1\n",
                             "/proc/sys/net/ipv6/ip_nonlocal_bind": OSError("ENOENT")})
    try:
        _nlb = (SO._nonlocal_bind_allowed(4), SO._nonlocal_bind_allowed(6))
    finally:
        SO.__dict__.pop("open", None)
    eq("so/_nonlocal_bind_allowed: '1' is on; an absent sysctl is the kernel default, off", _nlb, (True, False))


def _so7_self_update_log_outcome():
    # ── self-update log outcome
    eq("so/_update_log_outcome: no exit line is still running; exit 0 with no hold is 'done'",
       (SO._update_log_outcome(["=== panel self-update ==="])["outcome"],
        SO._update_log_outcome(["[+] Restarted", "=== installer exit 0 ==="])),
       ("running", {"finished": True, "exit_code": 0, "outcome": "done", "reason": ""}))


def _so7_integrity_repair():
    # ── integrity and repair
    global _k
    SO._is_git_checkout = lambda: True
    SO._git = lambda args, timeout=45: {"rev-parse": ("abc1234", "", 0),
                                        "diff": ("M\tapp.py\n\nD\tstatic/x.js\n", "", 0)}[args[0]]
    _ci = SO._compute_panel_integrity()
    eq("so/_compute_panel_integrity: blank lines are skipped, statuses named, sorted by path",
       (_ci["modified"], _ci["count"], _ci["clean"], _ci["verified"]),
       ([{"path": "app.py", "status": "modified"}, {"path": "static/x.js", "status": "deleted"}], 2, False, True))
    _rep_git = []
    SO.panel_integrity = lambda force=False: {"git": True, "verified": True, "modified": [{"path": "app.py"}]}
    SO._git = lambda args, timeout=45: (_rep_git.append(args), ("", "error: pathspec", 1))[1]
    eq("so/panel_repair: a checkout git refuses is a failure that restores nothing",
       (SO.panel_repair(), _rep_git), ((False, "Repair failed — see the panel logs.", []),
                                       [["checkout", "HEAD", "--", "app.py"]]))
    for _k in ("_git", "_is_git_checkout", "panel_integrity"):
        setattr(SO, _k, _so7_saved[_k])


def _so7_unattended_upgrades():
    # ── unattended upgrades
    global _k
    _ua_v, _ua_w = [], []
    SO._run_verb = _p7_verb_by({"apt-install": ("", "", 0)}, log=_ua_v)
    SO._write_root_file = lambda path, content: (_ua_w.append((path, content)), ("", "", 0))[1]
    SO.unattended_upgrades_status = lambda: {"enabled": True}
    _ua_on = SO.enable_unattended_upgrades()
    SO.unattended_upgrades_status = lambda: {"enabled": False}
    _ua_off = SO.enable_unattended_upgrades()
    for _k in ("_run_verb", "_write_root_file", "unattended_upgrades_status"):
        setattr(SO, _k, _so7_saved[_k])
    check("so/enable_unattended_upgrades: installs the package and writes the periodic config as root",
          _ua_v[:1] == [("apt-install", ["unattended-upgrades"])] and _ua_w
          and _ua_w[0][0] == "/etc/apt/apt.conf.d/20auto-upgrades"
          and 'APT::Periodic::Unattended-Upgrade "1";' in _ua_w[0][1], "%r %r" % (_ua_v, _ua_w))
    eq("so/enable_unattended_upgrades: success is confirmed by re-reading, not assumed",
       (_ua_on, _ua_off), ((True, "Automatic security updates are now enabled."),
                           (False, "Could not confirm automatic security updates were enabled — check the panel logs.")))


def _so7_panel_jail_files_read():
    # ── the panel jail's files, as read back
    global f
    SO._F2B_PANEL_FILTER = os.path.join(_s7, "filter.conf")
    SO._F2B_PANEL_JAIL = os.path.join(_s7, "jail.conf")
    _f2b_none = (SO._panel_f2b_filter_current(), SO._panel_f2b_jail_value("logpath"),
                 SO._panel_f2b_jail_ignoreip(), SO._panel_f2b_jail_port())
    with open(SO._F2B_PANEL_FILTER, "w") as f:
        f.write(SO._panel_f2b_filter_body())
    with open(SO._F2B_PANEL_JAIL, "w") as f:
        f.write("ignoreip\n" + SO._panel_f2b_jail_body("/srv/p/data/auth.log", 5443, ["203.0.113.5"],
                                                         allports=True))
    eq("so/f2b jail files: absent files read as None, not as an empty (healthy-looking) jail",
       _f2b_none, (None, None, None, None))
    eq("so/f2b jail files: port, logpath, banaction and ignoreip are read back as written",
       (SO._panel_f2b_filter_current() == SO._panel_f2b_filter_body(), SO._panel_f2b_jail_port(),
        SO._panel_f2b_jail_value("logpath"), SO._panel_f2b_jail_value("banaction"),
        SO._panel_f2b_jail_value("no-such-key"), SO._panel_f2b_jail_ignoreip()),
       (True, 5443, "/srv/p/data/auth.log", "iptables-allports", None,
        ["127.0.0.1/8", "::1", "203.0.113.5", "100.64.0.0/10", "fd7a:115c:a1e0::/48"]))
    SO._F2B_PANEL_FILTER, SO._F2B_PANEL_JAIL = _so7_saved["_F2B_PANEL_FILTER"], _so7_saved["_F2B_PANEL_JAIL"]
    _p7_cfgmod.load_config = _p7_raise(OSError("EIO"))
    try:
        eq("so/_panel_login_proxied: an unreadable config bans on ALL ports (the ban that surely applies)",
           SO._panel_login_proxied(), True)
    finally:
        _p7_cfgmod.load_config = _cfg7_saved["load_config"]


def _so7_write_root_file_helper():
    # ── _write_root_file: helper by NAME with the content on stdin, else base64 through sudo tee
    global _k
    _wr_sp, _wr_run = [], []
    SO._helper_present = lambda: True
    SO.subprocess = _Over(_so7_saved["subprocess"], run=_p7_sp_run(_wr_sp, _p7_sp.CompletedProcess([], 0, " ok ", "")))
    SO._run = _p7_run_by([], default=("", "", 0), log=_wr_run)
    _wr_h = SO._write_root_file(_so7_saved["_F2B_PANEL_JAIL"], "[jail]\nport = 1\n")
    check("so/_write_root_file (helper): the target goes by NAME and the content on stdin, never argv",
          _wr_h == ("ok", "", 0) and _wr_sp
          and _wr_sp[0][0] == _p7_priv.helper_argv("write-file", ["fail2ban-panel-jail"])
          and _wr_sp[0][1].get("input") == "[jail]\nport = 1\n" and _wr_sp[0][1].get("shell") is False
          and not _wr_run, "%r %r" % (_wr_sp, _wr_run))
    SO.subprocess = _Over(_so7_saved["subprocess"], run=_p7_sp_run([], exc=OSError("helper gone")))
    SO.os = _Over(os, geteuid=lambda: 1000)
    SO._write_root_file(_so7_saved["_F2B_PANEL_JAIL"], "x = $(reboot)\n")
    SO._helper_present = lambda: False
    SO._write_root_file("/etc/x y.conf", "a")
    SO.os = _Over(os, geteuid=lambda: 0)
    SO._write_root_file("/etc/z.conf", "b")
    for _k in ("_helper_present", "subprocess", "os", "_run"):
        setattr(SO, _k, _so7_saved[_k])
    _b64_x = _p7_b64.b64encode(b"x = $(reboot)\n").decode()
    eq("so/_write_root_file (fallback): content is base64 (inert to the shell), the path quoted, sudo only if needed",
       [c for c, _s in _wr_run],
       ["echo %s | base64 -d | sudo tee %s >/dev/null" % (_b64_x, _so7_saved["_F2B_PANEL_JAIL"]),
        "echo YQ== | base64 -d | sudo tee '/etc/x y.conf' >/dev/null",
        "echo Yg== | base64 -d | tee /etc/z.conf >/dev/null"])


def _so7_fail2ban_reads():
    # ── fail2ban reads
    SO._run = _p7_run_by([("command -v fail2ban-client", ("no", "", 0))])
    _fs_absent = SO.panel_fail2ban_status()
    _fo_absent = SO.fail2ban_overview()
    SO._run = _p7_run_by([("command -v fail2ban-client", ("yes", "", 0))])
    SO._run_verb = _p7_verb_by({"f2b-status-jail": ("", "Sorry but the jail does not exist", 255)})
    _fs_nojail = SO.panel_fail2ban_status()
    SO._run_verb = _p7_verb_by({"f2b-status-jail": ("Status for the jail: linuxgsm-panel\n"
                                                    "|  |- Currently banned: 3\n", "", 0)})
    _fs_on = SO.panel_fail2ban_status()
    eq("so/panel_fail2ban_status: absent / jail missing / active with its ban count",
       (_fs_absent, _fs_nojail, _fs_on, _fo_absent),
       ({"installed": False, "enabled": False, "banned": 0}, {"installed": True, "enabled": False, "banned": 0},
        {"installed": True, "enabled": True, "banned": 3}, {"installed": False, "jails": []}))
    _jd_text = ("Status for the jail: sshd\n|- Filter\n|  |- Currently failed: 1\n|  |- Total failed: 40\n"
                "`- Actions\n   |- Currently banned: 2\n   |- Total banned: 9\n"
                "   `- Banned IP list: 203.0.113.5 198.51.100.7\n")
    SO._run_verb = _p7_verb_by({"f2b-status": ("Status\n|- Number of jail: 3\n`- Jail list:\tsshd, "
                                               "linuxgsm-panel, bad jail!", "", 0),
                                "f2b-status-jail": lambda a: (_jd_text, "", 0) if a == ["sshd"] else ("", "", 1)})
    _jails = SO._fail2ban_jails()
    _jd_bad = SO.fail2ban_jail_detail("sshd; reboot")
    _ov = SO.fail2ban_overview()
    SO._run_verb = _p7_verb_by({"f2b-status": ("", "", 1)})
    _jails_fail = SO._fail2ban_jails()
    SO._run, SO._run_verb = _so7_saved["_run"], _so7_saved["_run_verb"]
    # A failed read is None, not []: [] is "no jails configured", which a stopped fail2ban is not.
    eq("so/_fail2ban_jails: only well-formed jail names; a failed read is None (unread), not none",
       (_jails, _jails_fail), (["sshd", "linuxgsm-panel"], None))
    eq("so/fail2ban_overview: each readable jail's counts and banned IPs; an unreadable jail is left out",
       (_jd_bad, _ov), (None, {"installed": True, "jails": [
           {"jail": "sshd", "currently_banned": 2, "total_banned": 9, "total_failed": 40,
            "banned_ips": ["203.0.113.5", "198.51.100.7"]}]}))


def _so7_ufw_deny_sources_rows():
    # ── _ufw_deny_sources: which rows are an all-ports block of an address
    # The OUT deny comes FIRST: below the ALLOW it would be dropped as shadowed anyway, and then the
    # direction test would not be what excluded it.
    _uds = SO._ufw_deny_sources(
        "Status: active\n"
        "[ 1] Anywhere                   DENY OUT    203.0.113.9\n"
        "[ 2] 22/tcp                     ALLOW IN    Anywhere\n"
        "[ 3] 80                         ALLOW IN    OpenSSH-profile\n"
        "[ 4] Anywhere                   DENY IN     notanaddress\n"
        "[ 5] Anywhere                   DENY IN     198.51.100.7               # panel-autoblock\n")
    eq("so/_ufw_deny_sources: outbound denies and unparseable sources are not blocks; a panel rule is",
       _uds, {"198.51.100.7": "panel-autoblock"})


def _so7_ufw_deny_ufw_raise():
    # ── _ufw_deny_with / _ufw_raise_shadowed_deny: the write sequences
    def _p7_ufw_runner(answers, log):
        def run(verb, args):
            log.append((verb, list(args)))
            return answers.pop(0) if answers else ("", "", 0)
        return run
    _uw = []
    eq("so/_ufw_deny_with: the same tag already present is left as it is — no write at all",
       (SO._ufw_deny_with("198.51.100.7", "panel-block", "panel-block", _p7_ufw_runner([], _uw)), _uw),
       ((True, "198.51.100.7 is already blocked."), []))
    _uw = []
    _uw_res = SO._ufw_deny_with("198.51.100.7", "panel-block", "panel-autoblock",
                                _p7_ufw_runner([("", "", 0), ("ERROR: couldn't\nupdate", "", 1)], _uw))
    eq("so/_ufw_deny_with: a re-tag whose insert fails PUTS THE OLD RULE BACK and reports the error",
       (_uw_res, _uw), ((False, "ERROR: couldn't update"),
                        [("ufw-delete-deny-ip", ["198.51.100.7"]),
                         ("ufw-deny-ip", ["198.51.100.7", "panel-block"]),
                         ("ufw-deny-ip", ["198.51.100.7", "panel-autoblock"])]))
    _uw = []
    _uw_move = SO._ufw_raise_shadowed_deny("198.51.100.8", {"action": "DENY", "comment": "panel-block!"},
                                           _p7_ufw_runner([], _uw))
    check("so/_ufw_raise_shadowed_deny: an operator comment that strips to a panel tag goes back untagged",
          _uw_move[0] is True and _uw == [("ufw-delete-deny-ip", ["198.51.100.8"]),
                                          ("ufw-deny-ip", ["198.51.100.8", ""])], "%r %r" % (_uw_move, _uw))
    _uw = []
    eq("so/_ufw_raise_shadowed_deny: a delete that fails stops there — nothing inserted",
       (SO._ufw_raise_shadowed_deny("198.51.100.8", {"action": "DENY", "comment": "mine"},
                                    _p7_ufw_runner([("", "", 1)], _uw)), _uw),
       ((False, "Could not move the existing deny rule for 198.51.100.8"),
        [("ufw-delete-deny-ip", ["198.51.100.8"])]))


def _so7_fail2ban_history_top_offenders():
    # ── fail2ban history: top offenders and the reconcile's counts
    _f2b_log = ("2024-05-01 12:00:00,000 fail2ban.filter  [1]: INFO    [sshd] Found 203.0.113.5\n"
                "2024-05-01 12:00:01,000 fail2ban.actions [1]: NOTICE  [sshd] Ban 203.0.113.5\n"
                "2024-05-01 12:00:02,000 fail2ban.filter  [1]: INFO    [linuxgsm-panel] Found 198.51.100.2\n"
                "2024-05-01 12:00:03,000 fail2ban.filter  [1]: INFO    [sshd] Found 203.0.113.5\n")
    _tv = []
    SO._run_verb = _p7_verb_by({"f2b-log-lines": (_f2b_log, "", 0)}, log=_tv)
    SO.fail2ban_overview = lambda: {"jails": [{"banned_ips": ["203.0.113.5"]}]}
    SO.ufw_blocked_ips = _p7_raise(RuntimeError("ufw"))
    _top = _p7_call(SO.fail2ban_top_ips, 20, "a week")
    SO.fail2ban_overview = _p7_raise(RuntimeError("f2b"))
    SO.ufw_blocked_ips = lambda shadowed=None: {"198.51.100.2": "panel-autoblock"}
    _top2 = _p7_call(SO.fail2ban_top_ips, 20, 7)
    _cut7 = (_p7_dt.now() - _p7_td(days=7)).strftime("%Y-%m-%d")
    eq("so/fail2ban_top_ips: ranked by attempts, annotated; junk `days` is 7; failed side reads blank",
       (_top, _tv[:1]),
       ([{"ip": "203.0.113.5", "attempts": 2, "bans": 1, "banned_now": True, "blocked": False, "jails": ["sshd"]},
         {"ip": "198.51.100.2", "attempts": 1, "bans": 0, "banned_now": False, "blocked": False,
          "jails": ["linuxgsm-panel"]}], [("f2b-log-lines", [_cut7])]))
    check("so/fail2ban_top_ips: an unreadable ban list does not drop the ranking or the block annotation",
          isinstance(_top2, list) and [r["banned_now"] for r in _top2] == [False, False]
          and [r["blocked"] for r in _top2] == [False, True], repr(_top2))
    del _tv[:]
    _ac = SO.fail2ban_attempt_counts("junk")
    SO._run_verb = _p7_verb_by({"f2b-log-lines": ("", "sudo: a password is required", 1)})
    _ac_fail = SO.fail2ban_attempt_counts(3)
    eq("so/fail2ban_attempt_counts: every offender counted; a FAILED read is None, never {}",
       (_ac, _tv, _ac_fail), ({"203.0.113.5": 2, "198.51.100.2": 1}, [("f2b-log-lines", [_cut7])], None))
    SO.fail2ban_overview, SO.ufw_blocked_ips = _so7_saved["fail2ban_overview"], _so7_saved["ufw_blocked_ips"]


def _so7_unbanning():
    # ── unbanning
    global _k
    _ub = []
    SO._fail2ban_jails = lambda: ["sshd", "linuxgsm-panel"]
    SO._run_verb = _p7_verb_by({"f2b-unban": lambda a: (_ub.append(a), ("", "", 0) if a[0] == "sshd"
                                                        else ("ERROR NOK: (203.0.113.5 is not banned)", "", 1))[1]})
    _unb = (SO.fail2ban_unban("sshd", "not-an-ip"), SO.fail2ban_unban("linuxgsm-panel", "203.0.113.5"))
    eq("so/fail2ban_unban: a bad address is refused before any command; a refused unban says why",
       (_unb, _ub), (((False, "Invalid IP address."), (False, "ERROR NOK: (203.0.113.5 is not banned)")),
                     [["linuxgsm-panel", "203.0.113.5"]]))
    del _ub[:]
    SO.fail2ban_overview = lambda: {"jails": [{"jail": "sshd", "banned_ips": ["203.0.113.5"]},
                                              {"jail": "recidive", "banned_ips": ["198.51.100.1"]},
                                              {"jail": "linuxgsm-panel", "banned_ips": ["203.0.113.5"]}]}
    _ue = SO.fail2ban_unban_ip_everywhere(" 203.0.113.5 ")
    SO.fail2ban_overview = _p7_raise(RuntimeError("f2b down"))
    _ue_down = SO.fail2ban_unban_ip_everywhere("203.0.113.5")
    eq("so/fail2ban_unban_ip_everywhere: only the jails that ban it, counting only real lifts",
       (_ue, sorted(a[0] for a in _ub), _ue_down, SO.fail2ban_unban_ip_everywhere("nope")),
       ((True, "lifted 203.0.113.5 from 1 jail(s)"), ["linuxgsm-panel", "sshd"],
        (True, "lifted 203.0.113.5 from 0 jail(s)"), (False, "Invalid IP address.")))
    for _k in ("_fail2ban_jails", "_run_verb", "fail2ban_overview"):
        setattr(SO, _k, _so7_saved[_k])


def _so7_raw_log_viewer():
    # ── the raw-log viewer
    global f
    _p7_cfgmod.DATA_DIR = _p7_pl.Path(_s7)
    try:
        _slt_none = SO.security_log_tail("panel")
        with open(os.path.join(_s7, "auth.log"), "w") as f:
            f.write("".join("line %d\n" % i for i in range(30)))
        _slt_panel = SO.security_log_tail("panel", lines=5)          # clamped up to 20
    finally:
        _p7_cfgmod.DATA_DIR = _cfg7_saved["DATA_DIR"]
    eq("so/security_log_tail(panel): a missing auth.log is '', and the tail is clamped to >= 20 lines",
       (_slt_none, _slt_panel), ("", "".join("line %d\n" % i for i in range(10, 30))))
    _slv = []
    SO._run_verb = _p7_verb_by({"log-tail": lambda a: ("", "", 1) if a[0] == "fail2ban" else ("auth1\nauth2", "", 0),
                                "journal": lambda a: ("x [sshd] Ban 1.2.3.4\ny [recidive] Ban 5.6.7.8", "", 0)
                                if a[0] == "fail2ban" else ("", "", 1)}, log=_slv)
    SO._fail2ban_jails = lambda: ["sshd", "recidive"]
    _slt_f2b = SO.security_log_tail("fail2ban", jail="sshd")
    _slt_f2b_any = SO.security_log_tail("fail2ban", jail="nosuch")
    _slt_ssh = SO.security_log_tail("ssh", lines=50)
    _slt_other = SO.security_log_tail("kern")
    SO._run_verb, SO._fail2ban_jails = _so7_saved["_run_verb"], _so7_saved["_fail2ban_jails"]
    eq("so/security_log_tail: the file first then the journal; a jail filter only for a real jail",
       (_slt_f2b, _slt_f2b_any, _slt_ssh, _slt_other),
       ("x [sshd] Ban 1.2.3.4", "x [sshd] Ban 1.2.3.4\ny [recidive] Ban 5.6.7.8", "auth1\nauth2", ""))
    eq("so/security_log_tail: ...asking for exactly those sources, in that order",
       _slv, [("log-tail", ["fail2ban", "4000"]), ("journal", ["fail2ban", "4000"]),
              ("log-tail", ["fail2ban", "4000"]), ("journal", ["fail2ban", "4000"]),
              ("journal", ["ssh", "100"]), ("log-tail", ["auth", "50"])])


def _so7_configure_ensure_panel_login():
    # ── configure / ensure the panel-login jail
    global _auth_new, _cf_ok, _cf_v, _cf_w
    _cf_v, _cf_w = [], []
    _blocker = os.path.join(_s7, "a-file")
    open(_blocker, "w").close()
    SO._run = _p7_run_by([("command -v fail2ban-client", ("no", "", 0))])
    SO._run_verb = _p7_verb_by({}, default=("", "", 0), log=_cf_v)
    SO._write_root_file = lambda p, c: (_cf_w.append((p, c)), ("", "", 0))[1]
    _cf_noinst = _p7_call(SO.configure_panel_fail2ban, os.path.join(_blocker, "sub", "auth.log"), 5000)
    check("so/configure_panel_fail2ban: fail2ban that will not install is a failure, and nothing is written",
          _cf_noinst == (False, "Couldn't install fail2ban on this host.")
          and [v for v, _a in _cf_v] == ["apt-update", "apt-install"] and _cf_w == [],
          "%r %r %r" % (_cf_noinst, _cf_v, _cf_w))
    _auth_new = os.path.join(_s7, "logs", "auth.log")
    del _cf_v[:]
    _st_seq = [{"enabled": False}, {"enabled": True}]
    SO._run = _p7_run_by([("command -v fail2ban-client", ("yes", "", 0))])
    SO._run_verb = _p7_verb_by({"f2b-reload": ("", "", 1)}, default=("", "", 0), log=_cf_v)
    SO.panel_fail2ban_status = lambda: _st_seq.pop(0) if _st_seq else {"enabled": True}
    SO._panel_login_proxied = lambda: False
    try:
        _cf_ok = _p7_call(SO.configure_panel_fail2ban, _auth_new, 5000, ["203.0.113.5"])
    finally:
        SO._panel_login_proxied = _so7_saved["_panel_login_proxied"]


def _so7_configure_ensure_panel_login_2():
    global _cf_down, _cf_down2, _st_late
    check("so/configure_panel_fail2ban: pre-creates the log, writes filter + jail, restarts if reload fails",
          isinstance(_cf_ok, tuple) and _cf_ok[0] is True and os.path.isfile(_auth_new)
          and [p for p, _c in _cf_w] == [_so7_saved["_F2B_PANEL_FILTER"], _so7_saved["_F2B_PANEL_JAIL"]]
          and "port = 5000\n" in _cf_w[1][1] and "logpath = %s\n" % _auth_new in _cf_w[1][1]
          and [v for v, _a in _cf_v] == ["service-enable-now", "f2b-reload", "service-restart"],
          "%r %r %r" % (_cf_ok, _cf_v, [p for p, _c in _cf_w]))
    del _cf_v[:], _cf_w[:]
    SO.panel_fail2ban_status = lambda: {"enabled": False}
    SO._run_verb = _p7_verb_by({"journal": ("noise\nERROR Failed during configuration: Have not found any log "
                                            "file for linuxgsm-panel jail\nmore noise", "", 0)},
                               default=("", "", 0), log=_cf_v)
    _cf_down = _p7_call(SO.configure_panel_fail2ban, _auth_new, 5000)
    SO._run_verb = _p7_verb_by({"f2b-status-jail": ("Sorry but the jail 'linuxgsm-panel' does not exist", "", 255)},
                               default=("", "", 0))
    _cf_down2 = _p7_call(SO.configure_panel_fail2ban, _auth_new, 5000)
    _st_late = [{"enabled": False}] * 6 + [{"enabled": True}]


def _so7_configure_ensure_panel_login_3():
    SO.panel_fail2ban_status = lambda: _st_late.pop(0) if _st_late else {"enabled": False}
    _cf_late_v = []
    SO._run_verb = _p7_verb_by({}, default=("", "", 0), log=_cf_late_v)
    _cf_late = _p7_call(SO.configure_panel_fail2ban, _auth_new, 5000)
    check("so/configure_panel_fail2ban: a jail that comes up only after the hard restart is a success",
          isinstance(_cf_late, tuple) and _cf_late[0] is True
          and [v for v, _a in _cf_late_v].count("service-restart") == 1, "%r %r" % (_cf_late, _cf_late_v))
    SO.panel_fail2ban_status = lambda: {"enabled": False}


def _so7_configure_ensure_panel_login_4():
    global _k
    check("so/configure_panel_fail2ban: a jail that never comes up is a failure that quotes the real reason",
          isinstance(_cf_down, tuple) and _cf_down[0] is False
          and _cf_down[1].startswith("Configured fail2ban, but the jail didn't come up.")
          and "Have not found any log file for linuxgsm-panel jail" in _cf_down[1] and "noise" not in _cf_down[1]
          and _cf_down2[1].endswith("Sorry but the jail 'linuxgsm-panel' does not exist")
          and [v for v, _a in _cf_v].count("service-restart") == 1,
          "%r / %r / %r" % (_cf_down, _cf_down2, _cf_v))
    SO.panel_fail2ban_status = lambda: {"installed": False}
    eq("so/ensure_panel_fail2ban: a junk port and an absent fail2ban are refusals",
       (SO.ensure_panel_fail2ban(_auth_new, "http"), SO.ensure_panel_fail2ban(_auth_new, 5000)),
       ((False, "Invalid web port."), (False, "fail2ban isn't installed on this host.")))
    for _k in ("_run", "_run_verb", "_write_root_file", "panel_fail2ban_status"):
        setattr(SO, _k, _so7_saved[_k])


def _so7_panel_diagnostics():
    # ── panel_diagnostics
    global _all_verbs, _d2, _d2s, _dg, _hv, _p7_cert, _p7_diag, _svc, f
    from cryptography import x509 as _p7_x509  # noqa: E402
    from cryptography.x509.oid import NameOID as _p7_oid  # noqa: E402
    from cryptography.hazmat.primitives import hashes as _p7_hashes, serialization as _p7_ser  # noqa: E402
    from cryptography.hazmat.primitives.asymmetric import ec as _p7_ec  # noqa: E402
    from panel.ops.debug_report import _src_db as _p7_srcdb, _src_systemd as _p7_srcsd  # noqa: E402
    _p7_key = _p7_ec.generate_private_key(_p7_ec.SECP256R1())

    def _p7_cert(start_days, end_days):
        _n = _p7_x509.Name([_p7_x509.NameAttribute(_p7_oid.COMMON_NAME, "p7")])
        _now = _p7_dt.now(_p7_tz.utc)
        return (_p7_x509.CertificateBuilder().subject_name(_n).issuer_name(_n)
                .public_key(_p7_key.public_key()).serial_number(7)
                .not_valid_before(_now + _p7_td(days=start_days))
                .not_valid_after(_now + _p7_td(days=end_days, hours=12))
                .sign(_p7_key, _p7_hashes.SHA256()).public_bytes(_p7_ser.Encoding.PEM))

    _dg = os.path.join(_s7, "diag")
    os.makedirs(os.path.join(_dg, "data", "ssl"))
    _svc = {"on": False}
    _hv = {"res": None, "exc": None}

    def _p7_unit():
        # The shared `systemctl show` (debug_report._src_systemd), as a healthy system unit for
        # this process, or as a bus that could not be read.
        if not _svc["on"]:
            return {"scope": None, "props": {}, "error": "unreadable"}
        return {"scope": "system", "error": None,
                "props": {"UnitFileState": "enabled", "ActiveState": "active",
                          "SubState": "running", "MainPID": str(os.getpid()),
                          "WorkingDirectory": _dg}}

    def _p7_diag(**over):
        """panel_diagnostics() with the given overrides; answers {check name: (level, detail)}."""
        _p7_cfgmod.DATA_DIR = _p7_pl.Path(over.get("data", os.path.join(_dg, "data")))
        _p7_cfgmod.DB_PATH = _p7_pl.Path(over.get("db", os.path.join(_dg, "data", "panel.db")))
        _p7_cfgmod.SECRET_FILE = _p7_pl.Path(over.get("secret", os.path.join(_dg, "data", "secret_key")))
        _p7_cfgmod.CRED_KEY_FILE = _p7_pl.Path(over.get("cred", os.path.join(_dg, "data", "cred_key")))
        _p7_cfgmod.load_config = over.get("load_config", lambda: {})
        SO.panel_integrity = lambda force=False: over["integ"]
        SO._helper_present = lambda: over.get("helper", False)
        SO.subprocess = _Over(_so7_saved["subprocess"], run=_p7_sp_run([], _hv["res"], _hv["exc"]))
        SO.unattended_upgrades_status = over.get("ua", lambda: {"enabled": True, "detail": "on"})
        SO.PANEL_DIR = over.get("panel_dir", _dg)
        # No path is hidden from git (the hidden-path check has its own checks in part21).
        SO._git = lambda args, timeout=45: ("H app.py", "", 0)
        SO._HELPER_PROBE["res"] = None          # each call is a fresh `sudo -n` probe
        _sd_saved, _db_saved = _p7_srcsd.unit_show, _p7_srcdb.integrity
        _p7_srcsd.unit_show = lambda timeout=5: _p7_unit()
        if "integrity" in over:
            _p7_srcdb.integrity = over["integrity"]
        SO.os = _Over(os, path=_Over(os.path, exists=lambda p: (
            (_svc["on"] and p == "/etc/systemd/system/linuxgsm-panel.service")
            if p.endswith("linuxgsm-panel.service") else os.path.exists(p))))
        try:
            _r = SO.panel_diagnostics()
        finally:
            _p7_srcsd.unit_show, _p7_srcdb.integrity = _sd_saved, _db_saved
            SO._HELPER_PROBE["res"] = None
            for _n in _cfg7_names:
                setattr(_p7_cfgmod, _n, _cfg7_saved[_n])
            for _n in ("panel_integrity", "_helper_present", "subprocess", "unattended_upgrades_status",
                       "PANEL_DIR", "os", "_git"):
                setattr(SO, _n, _so7_saved[_n])
        return {c["name"]: (c["level"], c["detail"]) for c in _r["checks"]}, _r["summary"]

    with open(os.path.join(_dg, "data", "secret_key"), "w") as f:
        f.write("s")
    _hv["res"] = _p7_sp.CompletedProcess([], 1, "", "")
    _d1, _d1s = _p7_diag(integ={"git": True, "verified": False, "message": "Couldn't run git"},
                         data=os.path.join(_dg, "nope"), db=os.path.join(_dg, "nope", "panel.db"),
                         secret=os.path.join(_dg, "data", "secret_key"), helper=True,
                         load_config=_p7_raise(OSError("EIO")), panel_dir=os.path.join(_dg, "nope"),
                         ua=_p7_raise(RuntimeError("dpkg")))
    eq("so/diagnostics: every probe that cannot answer is a warning or a failure, never 'ok'",
       {k: _d1[k][0] for k in _d1} if isinstance(_d1, dict) else _d1,
       {"File integrity": "warn", "Data directory": "fail", "Database": "fail", "Encryption keys": "ok",
        "Host credentials": "warn", "Privileged helper": "warn", "Configuration": "fail",
        "Disk space": "warn", "Service": "warn", "Automatic security updates": "warn"})
    check("so/diagnostics: ...the summary is 'fail', and a missing cred_key is explained as normal",
          _d1s == "fail" and "created when the first" in _d1["Encryption keys"][1]
          and _d1["Privileged helper"][1] == "Installed, but its verb table could not be read."
          and _d1["Configuration"][1] == "config.json could not be read or parsed."
          and _d1["Service"][1].startswith("systemd state unreadable (unreadable)")
          and _d1["Data directory"][1] == "data/ under the panel checkout does not exist.", repr(_d1))
    open(os.path.join(_dg, "data", "panel.db"), "w").close()               # empty database file
    with open(os.path.join(_dg, "data", "ssl", "cert.pem"), "wb") as f:
        f.write(_p7_cert(-30, 5))
    _svc["on"] = True
    _all_verbs = sorted(_p7_priv.verbs())
    _hv["res"] = _p7_sp.CompletedProcess([], 0, "\n".join(v + "\tdesc" for v in _all_verbs[5:]), "")
    _d2, _d2s = _p7_diag(integ={"git": True, "verified": True, "clean": False, "count": 3}, helper=True)


def _so7_panel_diagnostics_2():
    global _d3, _d3s, f
    check("so/diagnostics: tampered files, an empty DB, a stale helper and a near-expiry cert are each flagged",
          _d2["File integrity"] == ("fail", "3 panel file(s) differ from the installed version.")
          and _d2["Database"] == ("fail", "Database file is empty.")
          and _d2["Privileged helper"][0] == "fail" and ", ".join(_all_verbs[:4]) + ", …" in _d2["Privileged helper"][1]
          and _d2["TLS certificate"][0] == "warn" and _d2["TLS certificate"][1].endswith("Expires in 5 day(s).")
          and _d2["Service"][0] == "ok" and _d2["Data directory"][0] == "ok", repr(_d2))
    _p7_garbage(os.path.join(_dg, "data", "panel.db"))
    with open(os.path.join(_dg, "data", "ssl", "cert.pem"), "wb") as f:
        f.write(_p7_cert(-60, -4))
    open(os.path.join(_dg, "data", "cred_key"), "w").close()
    _hv["res"] = _p7_sp.CompletedProcess([], 0, "\n".join(v + "\tdesc" for v in _all_verbs), "")
    _d3, _d3s = _p7_diag(integ={"git": True, "verified": True, "clean": True, "current_sha": "abc1234"}, helper=True)


def _so7_panel_diagnostics_3():
    global _d4s, _d5s, f
    from panel.ops.system_ops import _DB_DAMAGED_TEXT as _p7_dmg  # noqa: E402
    # A file that is not a database at all is DAMAGE, read over a read-only connection off the hub
    # (it used to be "Couldn't run the integrity check", from a read-write connect that raised), and
    # with no rolling backup beside it a restart starts EMPTY -- the text says so rather than
    # promising a restore. An expired cert this process was not seen to boot with is a warning:
    # without the boot record nobody knows it is in use.
    check("so/diagnostics: a clean tree, a current helper; a corrupt DB fails, an expired cert of unknown use warns",
          _d3["File integrity"] == ("ok", "All panel files match the installed version (abc1234).")
          and _d3["Privileged helper"] == ("ok", "Installed and current (%d verbs)." % len(_all_verbs))
          and _d3["Database integrity"] == ("fail", _p7_dmg[None])
          and _d3["TLS certificate"][0] == "warn" and "Expired " in _d3["TLS certificate"][1]
          and "In use: unknown" in _d3["TLS certificate"][1]
          and _d3["Encryption keys"] == ("ok", "Session + credential keys present."), repr(_d3))
    with open(os.path.join(_dg, "data", "ssl", "cert.pem"), "wb") as f:
        f.write(_p7_cert(-1, 100))
    _hv["res"], _hv["exc"] = None, OSError("helper vanished")
    _d4, _d4s = _p7_diag(integ={"git": True, "verified": True, "clean": True, "current_sha": ""}, helper=True)
    with open(os.path.join(_dg, "data", "ssl", "cert.pem"), "wb") as f:
        f.write(b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")
    _d5, _d5s = _p7_diag(integ={"git": True, "verified": True, "clean": True, "current_sha": ""})
    # The card's own path reads the integrity check through debug_report._src_db (off the hub), and
    # what a restart will do is worded by the state of the rolling backup.
    _d6, _d6s = _p7_diag(integ={"git": True, "verified": True, "clean": True, "current_sha": ""},
                         integrity=lambda timeout=20: {"state": "damaged", "backup": "ok"})
    _d7, _d7s = _p7_diag(integ={"git": True, "verified": True, "clean": True, "current_sha": ""},
                         integrity=lambda timeout=20: {"state": "not_checked", "backup": None,
                                                       "detail_class": "OperationalError"})
    eq("so/diagnostics: a damaged database with a healthy backup says a restart restores it; one that "
       "could not be checked is a warning by class, never damage",
       (_d6.get("Database integrity"), _d6s, _d7.get("Database integrity")),
       (("fail", _p7_dmg["ok"]), "fail",
        ("warn", "Couldn't run the integrity check (OperationalError).")))
    check("so/diagnostics: ...and no wording promises a restore that may not happen",
          "restores from backup automatically" not in repr((_d3, _d6, _d7))
          and "starts EMPTY" in _p7_dmg[None], repr(_p7_dmg))
    eq("so/diagnostics: a valid cert, an unqueryable helper, and a cert that will not parse",
       (_d4["TLS certificate"][0], _d4["TLS certificate"][1].endswith("Valid for 100 more day(s)."),
        _d4["Privileged helper"], _d4["File integrity"][1], _d5["TLS certificate"]),
       ("ok", True, ("warn", "Installed, but could not be queried."),
        "All panel files match the installed version (?).", ("warn", "Present but couldn't be parsed.")))
    _hv["exc"] = None
    _svc["on"] = False


def _so7_generate_debug_report():
    # ── generate_debug_report
    global _p7_report, _rep, _rep_text
    import importlib.metadata as _p7_md  # noqa: E402
    _md_version = _p7_md.version
    _dr_db = _p7_db(os.path.join(_s7, "dr.db"))
    _dr_log = "\n".join("line %04d password=hunter2 ok" % i for i in range(400))
    _dr_upd = {"v": {"exists": False}}

    def _p7_report(journal_user="", journal_sys=_dr_log, update=None, **_k):
        _dr_upd["v"] = update if update is not None else {"exists": False}
        SO.panel_diagnostics = lambda: {"checks": [{"name": "X", "level": "ok", "detail": "fine"}]}
        SO.panel_version = lambda: "9.9.9"
        SO.panel_integrity = lambda force=False: {"current_sha": "abc1234"}
        SO._run = _p7_run_by([("uname -r", ("6.1.0-p7", "", 0)), ("journalctl --user", (journal_user, "", 0))])
        SO._run_verb = _p7_verb_by({"journal": (journal_sys, "", 0)})
        SO._git = lambda args, timeout=45: ("", "", 1)
        SO.panel_update_log = ((lambda: _dr_upd["v"]) if not isinstance(_dr_upd["v"], Exception)
                               else _p7_raise(_dr_upd["v"]))
        SO.open = _p7_open_with({"/etc/os-release": OSError("ENOENT")})
        _p7_cfgmod.load_config = _p7_raise(OSError("EIO"))
        _p7_cfgmod.DB_PATH = _p7_pl.Path(_dr_db)

        def _p7_ver(pkg):
            if pkg == "eventlet":
                raise _p7_md.PackageNotFoundError(pkg)
            return _md_version(pkg)
        _p7_md.version = _p7_ver
        try:
            return SO.generate_debug_report()
        finally:
            _p7_md.version = _md_version
            SO.__dict__.pop("open", None)
            for _n in ("panel_diagnostics", "panel_version", "panel_integrity", "_run", "_run_verb", "_git",
                       "panel_update_log"):
                setattr(SO, _n, _so7_saved[_n])
            for _n in _cfg7_names:
                setattr(_p7_cfgmod, _n, _cfg7_saved[_n])

    _rep = _p7_call(_p7_report)
    _rep_text = _rep["report"] if isinstance(_rep, dict) else str(_rep)
    _rep_log = _rep_text.split("### Recent log (redacted)\n```\n", 1)[-1].split("\n```", 1)[0]
    check("so/debug report: the OS falls back to the platform name; the DB health is read from the real file",
          ("- **OS**: %s\n" % _p7_platform.system()) in _rep_text and "- **health**: ok" in _rep_text
          and "- **Kernel**: 6.1.0-p7" in _rep_text, _rep_text[:600])
    check("so/debug report: the system journal is used when the user journal is empty, redacted",
          "hunter2" not in _rep_text and "password=[redacted]" in _rep_log and "line 0399" in _rep_log,
          _rep_log[-200:])
    check("so/debug report: a long log keeps its TAIL, cut on a line boundary",
          len(_rep_log) <= 8000 and _rep_log.startswith("line ") and "line 0000" not in _rep_log, _rep_log[:80])


def _so7_generate_debug_report_2():
    global _rep_none
    check("so/debug report: an uninstalled dependency is left out, the rest listed; no config section",
          "- **eventlet**" not in _rep_text and "- **flask**: " in _rep_text
          and "### Config (non-secret settings only)\n- (none)\n" in _rep_text
          and "- No panel update has been run through the panel yet." in _rep_text, _rep_text)
    check("so/debug report: the filename carries the commit",
          isinstance(_rep, dict) and _rep["filename"].startswith("linuxgsm-panel-debug-abc1234-")
          and _rep["filename"].endswith(".md"), repr(_rep.get("filename") if isinstance(_rep, dict) else _rep))
    _rep_none = _p7_call(_p7_report, journal_sys="")
    _dbm_ic = _dbm7.integrity_check
    _dbm7.integrity_check = _p7_raise(RuntimeError("locked"))
    try:
        _rep_noic = _p7_call(_p7_report)
    finally:
        _dbm7.integrity_check = _dbm_ic
    check("so/debug report: a DB health check that raises is left out, never reported as 'ok'",
          isinstance(_rep_noic, dict) and "- **health**" not in _rep_noic["report"]
          and "### Database\n" in _rep_noic["report"], str(_rep_noic)[:300])


def _so7_generate_debug_report_3():
    check("so/debug report: no journal anywhere says so rather than showing an empty block",
          isinstance(_rep_none, dict) and "```\n(no journal available)\n```" in _rep_none["report"],
          str(_rep_none)[:300])
    _outcomes = []
    for _upd in ({"exists": True, "lines": ["could not confirm health"]},
                 {"exists": True, "lines": ["Rolling back to abc"]},
                 {"exists": True, "lines": ["Update complete"]},
                 {"exists": True, "lines": ["step 3 of 9"], "outcome": "running"},
                 RuntimeError("log unreadable")):
        _r = _p7_call(_p7_report, update=_upd)
        _outcomes.append(_r["report"].split("### Last update\n", 1)[1].split("\n", 1)[0]
                         if isinstance(_r, dict) else str(_r))
    eq("so/debug report: the last update's outcome is named for each way it can end",
       _outcomes,
       ["- **Outcome**: FAILED — update broke health AND the automatic rollback couldn't confirm health",
        "- **Outcome**: FAILED — update failed its health check and was rolled back to the previous version",
        "- **Outcome**: succeeded",
        "- **Outcome**: unknown (in progress, or the log doesn't show a final outcome)",
        "- No panel update has been run through the panel yet."])


try:
    _so7_setup()
    _so7_run_verb_three_ways()
    _so7_run_shell_runner_itself()
    _so7_tracked_branch_helper_present()
    _so7_live_metrics_from_proc()
    _so7_live_metrics_from_proc_2()
    _so7_ufw_tailscale_reads()
    _so7_apt_history()
    _so7_git_update_machinery_failure()
    _so7_git_update_machinery_failure_2()
    _so7_launch_installer_detached_updater()
    _so7_launch_installer_detached_updater_2()
    _so7_branches()
    _so7_restart_panel()
    _so7_panel_repair_database()
    _so7_lockout_guards_port_use()
    _so7_self_update_log_outcome()
    _so7_integrity_repair()
    _so7_unattended_upgrades()
    _so7_panel_jail_files_read()
    _so7_write_root_file_helper()
    _so7_fail2ban_reads()
    _so7_ufw_deny_sources_rows()
    _so7_ufw_deny_ufw_raise()
    _so7_fail2ban_history_top_offenders()
    _so7_unbanning()
    _so7_raw_log_viewer()
    _so7_configure_ensure_panel_login()
    _so7_configure_ensure_panel_login_2()
    _so7_configure_ensure_panel_login_3()
    _so7_configure_ensure_panel_login_4()
    _so7_panel_diagnostics()
    _so7_panel_diagnostics_2()
    _so7_panel_diagnostics_3()
    _so7_generate_debug_report()
    _so7_generate_debug_report_2()
    _so7_generate_debug_report_3()
except Exception as e:  # noqa: BLE001 - a harness failure must fail by name, not end the suite
    import traceback as _p7_tb  # noqa: E402
    check("system_ops: the part10 harness ran to the end", False,
          "raised %s: %s @ %s" % (type(e).__name__, e, _p7_tb.format_exc()[-400:]))
finally:
    _p7_so_reset()
    for _k, _v in _so7_state.items():
        getattr(SO, _k).clear()
        getattr(SO, _k).update(_v)
    for _k in _cfg7_names:
        setattr(_p7_cfgmod, _k, _cfg7_saved[_k])
    _p7_sh.rmtree(_s7, ignore_errors=True)

for _n, _was in _p7_quiet.items():
    _p7_logging.getLogger(_n).disabled = _was


# ══════════════════════════════════════════════════════════════════════════════════════════════
# Sign-in and session binding (panel/security/auth.py, app._register_session, auth_routes)
# ══════════════════════════════════════════════════════════════════════════════════════════════
# Driven through the real user_loader on a throwaway app with an in-memory database: what a cookie
# is ACCEPTED as is the only thing these checks are about, so they ask load_user itself.
from types import SimpleNamespace as _p10_NS  # noqa: E402

from flask import Flask as _P10Flask, session as _p10_session  # noqa: E402

import app as _p10_app  # noqa: E402
from panel.db.models import User as _P10User, UserSession as _P10Sess, db as _p10_db  # noqa: E402
from panel.routes import _shared as _p10_shared  # noqa: E402
from panel.routes import auth_routes as _p10_ar  # noqa: E402
from panel.routes import server_files as _p10_sf  # noqa: E402
from panel.security import auth as _p10_auth  # noqa: E402

_p10a = _P10Flask("p10_auth")
_p10a.config.update(SECRET_KEY="p10-auth", SQLALCHEMY_DATABASE_URI="sqlite://",
                    SQLALCHEMY_TRACK_MODIFICATIONS=False, TESTING=True,
                    SESSION_PROTECTION="strong")
_p10_db.init_app(_p10a)
_p10_auth.init_auth(_p10a)
_p10_load = _p10_auth.login_manager._user_callback
_P10_UA = "Mozilla/5.0 (p10) Firefox/140.0"


def _p10_call(fn, *a, **k):
    """fn(*a, **k), or 'raised <Type>: <msg>' — so a regression fails by name."""
    try:
        return fn(*a, **k)
    except Exception as e:  # noqa: BLE001 - a regression fails by name
        return "raised %s: %s" % (type(e).__name__, e)


def _p10_as(ip, ua=_P10_UA, bind=None, path="/"):
    """A pushed request context from `ip` with `ua`; `bind` pre-seeds the Flask session's _bind."""
    ctx = _p10a.test_request_context(path, headers={"User-Agent": ua},
                                     environ_base={"REMOTE_ADDR": ip})
    ctx.push()
    if bind is not None:
        _p10_session["_bind"] = bind
    return ctx


def _p10_loads(login_id, ip, ua=_P10_UA, bound=False):
    """Whether load_user accepts `login_id` from `ip`/`ua` in a FRESH (cookie-less) session.

    A fresh session is what flask-login restores a remember cookie into: that is the replay.
    `bound`: the session instead already carries its "_bind", taken from this same client — a
    session cookie that came back with the request.
    """
    ctx = _p10_as(ip, ua)
    if bound:
        _p10_session["_bind"] = _p10_auth.session_fingerprint()
    try:
        return _p10_load(login_id) is not None
    finally:
        _p10_db.session.rollback()
        ctx.pop()


def _p10_fixture():
    """One user, and login-session rows recorded from an IPv4 client, an IPv6 one and none."""
    _p10_db.drop_all()
    _p10_db.create_all()
    u = _P10User(username="p10user", password_hash="x", is_active=True)
    _p10_db.session.add(u)
    _p10_db.session.commit()
    for sid, ip, ua in (("p10-v4", "203.0.113.9", _P10_UA),
                        ("p10-v6", "2001:db8:1:2::10", _P10_UA),
                        ("p10-norow", "", "")):
        _p10_db.session.add(_P10Sess(user_id=u.id, sid=sid, ip=ip, user_agent=ua, remember=True))
    _p10_db.session.commit()
    return u.id


def _p10_remember_cookie_binding(uid):
    lid = "%d:0:p10-v4" % uid
    check("session binding: a remember cookie restored from its own client is accepted (control)",
          _p10_loads(lid, "203.0.113.9"))
    # The finding: an empty session used to be bound to whoever sent it, so a remember cookie
    # copied off the victim's machine worked from any other one.
    check("session binding: a remember cookie replayed from ANOTHER address, session cookie "
          "dropped, is refused under strong", not _p10_loads(lid, "198.51.100.7"))
    check("session binding: ...and from the same address with another browser (User-Agent)",
          not _p10_loads(lid, "203.0.113.9", ua="curl/8.5"))
    lid6 = "%d:0:p10-v6" % uid
    check("session binding: an IPv6 client whose privacy address rotated inside its /64 still "
          "signs in", _p10_loads(lid6, "2001:db8:1:2::abcd"))
    check("session binding: ...but not from another /64", not _p10_loads(lid6, "2001:db8:1:3::10"))
    _p10a.config["SESSION_PROTECTION"] = "basic"
    try:
        check("session binding: 'basic' does not bind, so a roaming client stays signed in",
              _p10_loads(lid, "198.51.100.7"))
    finally:
        _p10a.config["SESSION_PROTECTION"] = "strong"
    # A row that recorded no client (written outside a request) keeps the old first-use binding
    # rather than refusing everyone: the Flask session's _bind is then the only record there is.
    ctx = _p10_as("198.51.100.7")
    try:
        _ok = _p10_load("%d:0:p10-norow" % uid) is not None
        _bound = _p10_session.get("_bind") == _p10_auth.session_fingerprint()
    finally:
        _p10_db.session.rollback()
        ctx.pop()
    check("session binding: a row with no recorded client falls back to binding on first use",
          _ok and _bound, repr((_ok, _bound)))
    # ...and the Flask-session binding still refuses a session cookie replayed with its _bind.
    ctx = _p10_as("198.51.100.7", bind="0" * 32)
    try:
        _cookie_ok = _p10_load("%d:0:p10-norow" % uid) is not None
    finally:
        _p10_db.session.rollback()
        ctx.pop()
    check("session binding: a session cookie bound to another client is still refused",
          not _cookie_ok)


def _p10_legacy_bare_id(uid):
    check("legacy cookie: a bare '<id>' is accepted while the account's auth_epoch is 0 (control)",
          _p10_loads(str(uid), "203.0.113.9", bound=True))
    with _p10a.app_context():
        check("legacy cookie: the console poller agrees (control)",
              _p10_sf._login_id_still_accepted(str(uid)) is not None)
        u = _p10_db.session.get(_P10User, uid)
        u.auth_epoch = 1                     # a password change / sign out everywhere / reset
        _p10_db.session.commit()
    check("legacy cookie: a bare '<id>' is REFUSED once the epoch has moved (it survived password "
          "changes and sign-out-everywhere)", not _p10_loads(str(uid), "203.0.113.9", bound=True))
    with _p10a.app_context():
        check("legacy cookie: ...and the console poller refuses it too",
              _p10_sf._login_id_still_accepted(str(uid)) is None)
        u = _p10_db.session.get(_P10User, uid)
        u.auth_epoch = 0
        _p10_db.session.commit()


def _p10_sidless_cookie_binding(uid):
    """A login with no per-device sid has no row to check the client against."""
    lid = "%d:0" % uid
    check("sid-less cookie: a session that already carries its binding keeps working (control)",
          _p10_loads(lid, "203.0.113.9", bound=True))
    check("sid-less cookie: ...and a bound one replayed from another address is still refused",
          not _p10_bound_elsewhere(lid))
    # The finding: its remember cookie, restored into an EMPTY session, was bound to whoever sent
    # it. Refused now; the person signs in once more and gets a per-device login.
    check("sid-less cookie: an '<id>:<epoch>' restored into an unbound session is refused under "
          "strong (it used to be bound to the replayer)", not _p10_loads(lid, "198.51.100.7"))
    check("sid-less cookie: ...and a bare pre-epoch '<id>' the same way",
          not _p10_loads(str(uid), "198.51.100.7"))
    _p10a.config["SESSION_PROTECTION"] = "basic"
    try:
        check("sid-less cookie: 'basic' is unchanged — accepted, unbound, from anywhere",
              _p10_loads(lid, "198.51.100.7"))
    finally:
        _p10a.config["SESSION_PROTECTION"] = "strong"


def _p10_bound_elsewhere(lid):
    """Whether load_user accepts `lid` in a session bound to some other client."""
    ctx = _p10_as("198.51.100.7", bind="0" * 32)
    try:
        return _p10_load(lid) is not None
    finally:
        _p10_db.session.rollback()
        ctx.pop()


def _p10_register_session_retry(uid):
    real = _p10_app.db
    calls = []

    def _flaky_commit():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database is locked")
        real.session.commit()

    ctx = _p10_as("203.0.113.9")
    try:
        u = _p10_db.session.get(_P10User, uid)
        _p10_app.db = _p10_NS(session=_p10_NS(add=real.session.add, commit=_flaky_commit,
                                              rollback=real.session.rollback))
        sid = _p10_call(_p10_app._register_session, u, False)
    finally:
        _p10_app.db = real
        _p10_db.session.rollback()
        ctx.pop()
    with _p10a.app_context():
        row = _P10Sess.query.filter_by(sid=str(sid or "-")).first()
        row_ip = row.ip if row is not None else None
    check("register session: a lock on the first write is retried, and the row is written",
          bool(sid) and len(calls) == 2 and row_ip == "203.0.113.9", repr((sid, calls, row_ip)))


def _p10_login_refused_without_row(uid):
    saved = {n: getattr(_p10_ar, n) for n in ("_register_session", "login_user",
                                                "render_template", "log_action")}
    logged_in = []
    ctx = _p10_as("203.0.113.9", path="/login")
    try:
        _p10_ar._register_session = lambda *a, **k: None
        _p10_ar.login_user = lambda *a, **k: logged_in.append(a)
        _p10_ar.render_template = lambda name, **kw: "rendered:" + name
        _p10_ar.log_action = lambda *a, **k: None
        u = _p10_db.session.get(_P10User, uid)
        out = _p10_call(_p10_ar._login_succeed,
                        _p10_NS(ip="203.0.113.9", key="203.0.113.9", now=0), u, True)
        _uid_in_session = _p10_session.get("_user_id")
    finally:
        for n, v in saved.items():
            setattr(_p10_ar, n, v)
        _p10_db.session.rollback()
        ctx.pop()
    check("login: a sign-in whose session row cannot be recorded is refused, not issued an "
          "unregistered '<id>:<epoch>' cookie",
          out == "rendered:login.html" and not logged_in and _uid_in_session is None,
          repr((out, logged_in, _uid_in_session)))


def _p10_held_chunked_body(uid):
    with _p10a.test_request_context("/", method="POST", headers={"Transfer-Encoding": "chunked"},
                                    environ_overrides={"wsgi.input_terminated": True},
                                    input_stream=_p7_io.BytesIO(b'{"a": 1}')):
        _chunked = _p10_auth._request_has_body()
    with _p10a.test_request_context("/", method="POST", data=b"x"):
        _sized = _p10_auth._request_has_body()
    with _p10a.test_request_context("/", method="GET"):
        _none = _p10_auth._request_has_body()
    check("held body: a CHUNKED body (no Content-Length) counts as a body to read before "
          "authorizing, like a sized one; a request with no body does not",
          _chunked is True and _sized is True and _none is False, repr((_chunked, _sized, _none)))
    # Driven: the pre-read happens in the hook itself, for a signed-in request.
    with _p10a.app_context():
        _p10_db.session.add(_P10Sess(user_id=uid, sid="p10-chunk", ip="127.0.0.1",
                                     user_agent=_P10_UA))
        _p10_db.session.commit()
    body = _p7_io.BytesIO(b'{"a": 1}')
    ctx = _p10a.test_request_context("/", method="POST",
                                     headers={"Transfer-Encoding": "chunked", "User-Agent": _P10_UA},
                                     environ_base={"REMOTE_ADDR": "127.0.0.1"},
                                     environ_overrides={"wsgi.input_terminated": True},
                                     input_stream=body)
    ctx.push()
    try:
        # Permanent, as every panel login is — flask-login's own "strong" clears a non-permanent
        # session that carries no identifier, before the panel's loader is ever asked.
        _p10_session.permanent = True
        _p10_session["_user_id"] = "%d:0:p10-chunk" % uid
        _res = _p10_call(_p10_auth.authorize_after_body)
        _consumed = body.tell() == len(b'{"a": 1}')
    finally:
        _p10_db.session.rollback()
        ctx.pop()
    check("held body: authorize_after_body reads a signed-in request's chunked body before any "
          "check runs", _res is None and _consumed, repr((_res, _consumed)))


def _p10_totp_step_race(uid):
    """Two sign-ins with one authenticator code: the second has read the step before the first
    committed. Staged in one transaction — the row already holds the spent step while the object
    this request loaded still says 0, which is what the loser of that race is holding."""
    saved = {n: getattr(_p10_ar, n) for n in ("verify_totp_step", "_login_fail",
                                                "_login_succeed")}
    seen = []
    ctx = _p10_as("203.0.113.9", path="/login")
    try:
        _p10_ar.verify_totp_step = lambda secret, code: 1000
        _p10_ar._login_fail = lambda attempt, msg, **kw: seen.append(("refused", kw.get("reason")))
        _p10_ar._login_succeed = lambda attempt, u, remember: seen.append(("signed in", None))
        u = _p10_db.session.get(_P10User, uid)
        u.last_totp_step = 0
        _p10_db.session.commit()
        u = _p10_db.session.get(_P10User, uid)
        _ = u.last_totp_step                               # loaded: 0, as the racing request read it
        _p10_db.session.query(_P10User).filter(_P10User.id == uid).update(
            {"last_totp_step": 1000}, synchronize_session=False)   # ...the winner's spend
        _p10_call(_p10_ar._login_totp_code, _p10_NS(), u, "123456")
        _p10_db.session.rollback()
        _p10_ar.verify_totp_step = lambda secret, code: 1001
        u = _p10_db.session.get(_P10User, uid)
        _p10_call(_p10_ar._login_totp_code, _p10_NS(), u, "654321")
        _p10_db.session.expire_all()
        _stored = _p10_db.session.get(_P10User, uid).last_totp_step
    finally:
        for n, v in saved.items():
            setattr(_p10_ar, n, v)
        _p10_db.session.rollback()
        ctx.pop()
    check("2FA login: a code whose step another sign-in spent after this one read it is refused "
          "(the spend is a compare-and-swap, not read-then-write)",
          seen[:1] == [("refused", "replayed 2FA code")], repr(seen))
    check("2FA login: ...while the next step still signs in and is recorded (control)",
          seen[1:] == [("signed in", None)] and _stored == 1001, repr((seen, _stored)))


def _p10_monitor_needs_restart():
    check("monitor: LinuxGSM `monitor` (it restarts a crashed or unresponsive server) needs "
          "RESTART_SERVER, not the view-only console permission",
          _p10_auth._perm_for_action("monitor") == _p10_auth.RESTART_SERVER
          and _p10_auth._perm_for_action("details") == _p10_auth.VIEW_CONSOLE)
    saved = (_p10_shared.current_user, _p10_shared.get_user_permissions)
    gs = _p10_NS(get_commands=lambda: [{"cmd": "monitor", "desc": "Monitor"},
                                       {"cmd": "details", "desc": "Details"}],
                 supports_update=True)
    try:
        _p10_shared.current_user = _p10_NS(is_superadmin=False)
        _p10_shared.get_user_permissions = lambda u: {_p10_auth.VIEW_CONSOLE}
        _view = [m["cmd"] for m in _p10_shared._server_action_buttons(None, gs)[1]]
        _p10_shared.get_user_permissions = lambda u: {_p10_auth.VIEW_CONSOLE,
                                                      _p10_auth.RESTART_SERVER}
        _restart = [m["cmd"] for m in _p10_shared._server_action_buttons(None, gs)[1]]
    finally:
        _p10_shared.current_user, _p10_shared.get_user_permissions = saved
    check("monitor: the maintenance menu hides the button from a view-only user and shows it to "
          "one who may restart", _view == ["details"] and _restart == ["monitor", "details"],
          repr((_view, _restart)))


try:
    with _p10a.app_context():
        _p10_uid = _p10_fixture()
    _p10_remember_cookie_binding(_p10_uid)
    _p10_legacy_bare_id(_p10_uid)
    _p10_sidless_cookie_binding(_p10_uid)
    _p10_register_session_retry(_p10_uid)
    _p10_login_refused_without_row(_p10_uid)
    _p10_held_chunked_body(_p10_uid)
    _p10_totp_step_race(_p10_uid)
    _p10_monitor_needs_restart()
except Exception as e:  # noqa: BLE001 - a harness failure must fail by name, not end the suite
    import traceback as _p10_tb  # noqa: E402
    check("auth: the part10 sign-in harness ran to the end", False,
          "raised %s: %s @ %s" % (type(e).__name__, e, _p10_tb.format_exc()[-600:]))
