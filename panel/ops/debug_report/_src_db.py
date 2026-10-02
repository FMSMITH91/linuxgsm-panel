"""Off-hub, read-only SQLite access for the report (R57, R58, R59, R60, R61, R43). Owner: builder B2.

integrity(timeout=20) -> {"state": "ok"|"damaged"|"not_checked", "detail_class": str|None,
                          "backup": None|"ok"|"damaged"|"missing"|"not_checked",
                          "detail": first quick_check message (<= 160 chars) or "",
                          "took": seconds or None}
    ONE quick_check per report on a `file:...?mode=ro` URI connection, run through eventlet.tpool
    when eventlet is patched (stdlib only inside the worker: no SQLAlchemy, no logging, no green
    locks). The backup file is checked only when the main check fails. 'not_checked' (locked, busy,
    unreadable -- db_maintenance.check_unreachable) is never 'damaged'. Cached for _CACHE_TTL
    seconds keyed by the database's mtime and size, so the Diagnostics card and a report a moment
    apart run one check between them.

run_ro(queries, timeout=10) -> {name: list_of_row_tuples | "error:<ExceptionClass>"}
    Each SQL in `queries` ({name: (sql, params)}) on one mode=ro connection in tpool. For counts,
    MIN()s and GROUP BYs on indexed columns; never select a value the report must not print.

BOTH ARE BOUNDED. tpool.execute has no timeout of its own, so the job runs in a thread of its own
and the caller waits for it at most `timeout` seconds. Past that, the job's connection is
interrupted (Connection.interrupt is the one call SQLite allows from another thread), which ends
the running statement with an OperationalError and frees the worker; the answer is then
'not_checked' / "error:Timeout". Nothing is killed: a killed greenlet parked in tpool leaves the
hub a listener (see the runner in __init__.py).
"""
import os
import pathlib
import sqlite3
import threading
import time

_CACHE_TTL = 60.0
_GRACE_S = 2.0           # how long to wait for an interrupted job to give its worker back
_DETAIL_MAX = 160
_cache = {"key": None, "at": 0.0, "res": None}


class Timeout(Exception):
    """The job did not finish inside its time limit and was interrupted."""


def _db_path():
    from panel.core import config as _cfg
    return str(_cfg.DB_PATH)


def _ro_uri(path):
    """The read-only URI form models._db_quick_check and db_maintenance use."""
    return pathlib.Path(path).absolute().as_uri() + "?mode=ro"


# ── the worker side: stdlib only ──────────────────────────────────────────────────────────────────
def _quick_check_job(path, holder):
    """('ok'|'bad'|'absent', first message) for `path`, or the exception the check raised.

    Mirrors models._db_quick_check (a unit check holds the two to the same answers): a missing or
    empty file is healthy, the connection is read-only (a read-write close on a file with a bad
    header deletes its -wal and -shm), and the error is handed back to be classified by the caller.
    """
    try:
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return ("absent", "")
        con = sqlite3.connect(_ro_uri(path), timeout=10, uri=True)
        holder["con"] = con
        try:
            row = con.execute("PRAGMA quick_check").fetchone()
        finally:
            holder["con"] = None
            con.close()
        if row and row[0] == "ok":
            return ("ok", "")
        return ("bad", str(row[0] if row else "no answer")[:_DETAIL_MAX])
    except Exception as exc:  # noqa: BLE001 - classified on the caller's side
        return exc


def _integrity_job(path, holder):
    """The main file's result, then the backup's only when the main one is not healthy."""
    main = _quick_check_job(path, holder)
    backup = None
    if isinstance(main, tuple) and main[0] == "bad" or isinstance(main, Exception):
        bpath = path + ".backup"
        backup = _quick_check_job(bpath, holder) if os.path.exists(bpath) else "missing"
    return main, backup


def _run_ro_job(path, queries, holder):
    """{name: rows | exception} for every query, on one read-only connection."""
    out = {}
    try:
        con = sqlite3.connect(_ro_uri(path), timeout=5, uri=True)
    except Exception as exc:  # noqa: BLE001 - every query reports the open failure
        return {name: exc for name in queries}
    holder["con"] = con
    try:
        for name, (sql, params) in queries.items():
            try:
                out[name] = con.execute(sql, tuple(params or ())).fetchall()
            except Exception as exc:  # noqa: BLE001 - one query's failure is its own answer
                out[name] = exc
    finally:
        holder["con"] = None
        con.close()
    return out


# ── the caller side ───────────────────────────────────────────────────────────────────────────────
def _off_hub(fn, *args):
    """fn(*args) in a tpool worker under eventlet, directly otherwise (auth.run_off_hub)."""
    from panel.security import auth as _auth
    return _auth.run_off_hub(fn, *args)


def _bounded(job, args, timeout):
    """job(*args, holder) off the hub, waited for at most `timeout` s; Timeout past that."""
    holder, box, done = {"con": None}, {}, threading.Event()

    def _go():
        try:
            box["res"] = _off_hub(job, *(args + (holder,)))
        except Exception as exc:  # noqa: BLE001 - handed back to the caller
            box["res"] = exc
        finally:
            done.set()

    threading.Thread(target=_go, name="debug-report-sqlite", daemon=True).start()
    if not done.wait(max(0.5, timeout)):
        con = holder.get("con")
        if con is not None:
            try:
                con.interrupt()
            except Exception:  # noqa: BLE001 - nothing more can be done for it  # nosec B110
                pass
        done.wait(_GRACE_S)
        raise Timeout("sqlite job exceeded %.0f s" % timeout)
    return box.get("res")


def _classify(res):
    """('ok'|'damaged'|'not_checked'|'absent', detail_class, detail) for one quick_check result."""
    from panel.db import models as _models
    if isinstance(res, tuple):
        kind, msg = res
        return ({"ok": "ok", "absent": "absent"}.get(kind, "damaged"), None, msg)
    if isinstance(res, sqlite3.DatabaseError) and _models._is_corruption_error(res):
        return ("damaged", type(res).__name__, "")
    return ("not_checked", type(res).__name__, "")


def _backup_state(res):
    if res is None:
        return None
    if res == "missing":
        return "missing"
    state = _classify(res)[0]
    return "missing" if state == "absent" else state


def _cache_key(path):
    try:
        st = os.stat(path)
        return (path, st.st_mtime_ns, st.st_size)
    except OSError:
        return (path, None, None)


def integrity(timeout=20):
    """One quick_check of the panel database (and its backup when the main check fails). See the
    module docstring for the shape. Never raises."""
    path = _db_path()
    key = _cache_key(path)
    if _cache["key"] == key and _cache["res"] is not None and \
            time.monotonic() - _cache["at"] < _CACHE_TTL:
        return dict(_cache["res"])
    t0 = time.monotonic()
    try:
        main, backup = _bounded(_integrity_job, (path,), timeout)
        state, cls, detail = _classify(main)
        res = {"state": "ok" if state == "absent" else state, "detail_class": cls,
               # what a restart would do with the backup matters only for a DAMAGED file
               "backup": _backup_state(backup) if state == "damaged" else None,
               "detail": detail, "took": time.monotonic() - t0}
    except Exception as exc:  # noqa: BLE001 - a timeout or a failed hand-off is "not checked"
        res = {"state": "not_checked", "detail_class": type(exc).__name__, "backup": None,
               "detail": "", "took": time.monotonic() - t0}
        return res      # not cached: the next caller tries again
    _cache.update(key=key, at=time.monotonic(), res=dict(res))
    return res


def run_ro(queries, timeout=10):
    """Run `queries` ({name: (sql, params)}) on one read-only connection, off the hub. Never raises;
    each answer is a list of row tuples or "error:<ExceptionClass>"."""
    if not queries:
        return {}
    path = _db_path()
    if not os.path.exists(path):
        return {name: "error:FileNotFoundError" for name in queries}
    try:
        got = _bounded(_run_ro_job, (path, dict(queries)), timeout)
    except Exception as exc:  # noqa: BLE001 - every query reports it
        return {name: "error:%s" % type(exc).__name__ for name in queries}
    out = {}
    for name in queries:
        val = (got or {}).get(name)
        if isinstance(val, Exception):
            out[name] = "error:%s" % type(val).__name__
        elif isinstance(val, list):
            out[name] = val
        else:
            out[name] = "error:NoAnswer"
    return out
