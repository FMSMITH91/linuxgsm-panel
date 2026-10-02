"""Off-hub, read-only SQLite access for the report (R57, R58, R59, R60, R61, R43). Owner: builder B2.

integrity(timeout=20) -> {"state": "ok"|"damaged"|"not_checked", "detail_class": str|None,
                          "backup": None|"ok"|"damaged"|"missing"|"not_checked"}
    ONE quick_check per report on a `file:...?mode=ro` URI connection, run through eventlet.tpool
    when eventlet is patched (stdlib only inside the worker: no SQLAlchemy, no logging, no green
    locks). The backup file is checked only when the main check fails. 'not_checked' (locked, busy,
    unreadable -- db_maintenance.check_unreachable) is never 'damaged'.

run_ro(queries, timeout=10) -> {name: list_of_row_tuples | "error:<ExceptionClass>"}
    Each SQL in `queries` ({name: (sql, params)}) on one mode=ro connection in tpool. For counts,
    MIN()s and GROUP BYs on indexed columns; never select a value the report must not print.
"""


def integrity(timeout=20):
    """Not implemented yet."""
    return {"state": "not_checked", "detail_class": "NotImplementedError", "backup": None}


def run_ro(queries, timeout=10):
    """Not implemented yet."""
    return {name: "error:NotImplementedError" for name in queries}
