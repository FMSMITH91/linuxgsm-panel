"""Debug-report section(s): diagnostics

Owner: builder B2. panel_diagnostics(), rendered sorted fail/warn/ok, with the R8-R14 fixes; its lines
also go in the public summary (summary_lines).

The section hands panel_diagnostics the two reads it shares with other sections, through the
report's memo: ONE read-only integrity check (R57; the Database section uses the same result) and
ONE `systemctl show` (R8; Panel process and unit drift use the same one).
"""
from panel.ops.debug_report import _src_db, _src_systemd
from panel.ops.debug_report._base import Result

# The memo keys every section uses for the shared reads.
MEMO_DB_INTEGRITY = "db.integrity"
MEMO_UNIT_SHOW = "systemd.unit_show"
_ORDER = {"fail": 0, "warn": 1, "ok": 2}


def shared_integrity(ctx):
    """The report's one integrity check (R57), bounded by what is left of the report's deadline."""
    return ctx.memo(MEMO_DB_INTEGRITY,
                    lambda: _src_db.integrity(timeout=max(1.0, min(20.0, ctx.remaining() - 1.0))))


def shared_unit(ctx):
    """The report's one `systemctl show` (R8, R15, R21)."""
    return ctx.memo(MEMO_UNIT_SHOW, _src_systemd.unit_show)


def section_diagnostics(ctx):
    """The panel's self-check, worst first. Every detail is fixed text, counts and repo paths."""
    from panel.ops import system_ops as so
    db_check = shared_integrity(ctx)
    unit = shared_unit(ctx)
    diag = so.panel_diagnostics(db_check=db_check, unit=unit)
    checks = sorted(diag.get("checks") or [], key=lambda c: _ORDER.get(c.get("level"), 3))
    res = Result()
    if not checks:
        res.add("- **Diagnostics**: no checks came back").find("unread", "Diagnostics",
                                                                  "no checks came back")
        return res
    for c in checks:
        res.add("- [%s] **%s**: %s" % (c["level"], c["name"], c["detail"]))
        if c["level"] in ("fail", "warn"):
            res.find(c["level"], "Diagnostics", c["name"])
    res.summary_lines = list(res.lines)
    return res
