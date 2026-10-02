"""The panel's debug report: what an operator pastes to a maintainer (or an AI) when something breaks,
and what the "Open a GitHub issue" button pre-fills. It must stay safe to post publicly.

generate() runs every section in SECTIONS, each under the contract in _base.py, and assembles:
  report      the full markdown (download / paste)
  summary     the public part: header, At a glance, Verdicts, Diagnostics, Hosts
  issue_body  the summary sized for a GitHub new-issue URL, the "describe the problem" prompt first
  issues_url, filename

Sections run in one of two modes:
  "request"  in the caller's greenlet, in order -- for what needs the app or request context.
  "worker"   concurrently, each in its own thread from the `threading` module (a green thread when
             eventlet has patched it, a native one in the tests and CLI), with the app context pushed
             when there is an app. They share one deadline. A worker still running at the deadline is
             NOT killed -- killing a greenlet parked in a green read leaves a hub listener behind --
             it is reported as timed out and its result, when it comes, is discarded. Every read a
             worker makes carries its own timeout, so it does end.

One report is built at a time: a second request while one is building waits for it and gets the
same result.
"""
import importlib
import threading
import time

from panel.ops.debug_report._base import Ctx, Result, LEVELS

DEADLINE_S = 20.0

# At most this many worker sections run at once (R3): each may hold a subprocess, and a report must
# not fan a dozen reads out at the same moment on the panel's one process.
MAX_WORKERS = 4

# (key, title, module, mode, part)
#   part "header": the report's header lines (assemble.py puts them at the top, not as a section).
#   part "summary": also in the public summary/issue body, in this order.
#   part "full": the full report only.
# A section's function is `section` in panel/ops/debug_report/<module>.py.
SECTIONS = (
    ("header", "Header", "header", "worker", "header"),
    ("diagnostics", "Diagnostics", "diagnostics", "worker", "summary"),
    ("hosts_brief", "Hosts & game servers", "hosts", "request", "summary"),
    ("process", "Panel process", "process", "worker", "full"),
    ("workers", "Background workers", "workers", "request", "full"),
    ("errors_since_start", "Errors since this process started", "errors", "request", "full"),
    ("install", "Install & privilege", "install", "worker", "full"),
    ("root_pieces", "Root-owned pieces & origin", "root_pieces", "worker", "full"),
    ("updates", "Updates", "updates", "worker", "full"),
    ("network", "Network & access", "network", "worker", "full"),
    ("access", "Sign-ins & accounts", "network", "request", "full"),
    ("hosts", "Hosts", "hosts", "request", "full"),
    ("servers", "Game servers", "servers", "request", "full"),
    ("console", "Live console", "servers", "request", "full"),
    ("database", "Database", "data", "worker", "full"),
    ("backups", "Panel backups & update snapshots", "data", "request", "full"),
    ("notifications", "Notifications", "notifications", "request", "full"),
    ("dependencies", "Dependencies", "header", "request", "full"),
    ("config", "Config (non-secret settings only)", "config_section", "request", "full"),
    ("journal_digest", "Errors in the journal", "logs", "worker", "full"),
    ("recent_log", "Recent log (redacted)", "logs", "worker", "full"),
)

_inflight_lock = threading.Lock()
_inflight = {"done": None, "result": None}


def _section_fn(module, key):
    """The function for section `key` in `module`: `section_<key>` if defined, else `section`."""
    mod = importlib.import_module("panel.ops.debug_report." + module)
    return getattr(mod, "section_" + key, None) or getattr(mod, "section")


def _run_one(ctx, key, module):
    """(status, seconds, Result-or-exception-class-name). Never raises."""
    t0 = time.monotonic()
    try:
        res = _section_fn(module, key)(ctx)
        if not isinstance(res, Result):
            raise TypeError("section %s returned %s" % (key, type(res).__name__))
        return ("ok", time.monotonic() - t0, res)
    except Exception as exc:  # noqa: BLE001 - one section's failure is reported, never fatal
        return ("error", time.monotonic() - t0, type(exc).__name__)


def _run_worker(ctx, key, module, slot, done, gate):
    """One worker section, once a slot under `gate` is free; past the deadline it never starts."""
    t0 = time.monotonic()
    try:
        if not gate.acquire(timeout=max(0.0, ctx.remaining())):
            slot[key] = ("timeout", time.monotonic() - t0, None)
            return
        try:
            if ctx.app is not None:
                with ctx.app.app_context():
                    slot[key] = _run_one(ctx, key, module)
            else:
                slot[key] = _run_one(ctx, key, module)
        finally:
            gate.release()
    except Exception as exc:  # noqa: BLE001 - the app context itself failed
        slot[key] = ("error", 0.0, type(exc).__name__)
    finally:
        done.set()


def _run_sections(ctx):
    """{key: (status, seconds, Result|class name)} for every section; a worker unfinished at the
    deadline is ("timeout", seconds_waited, None)."""
    results, waits = {}, []
    gate = threading.BoundedSemaphore(MAX_WORKERS)
    for key, _title, module, mode, _part in SECTIONS:
        if mode == "worker":
            done = threading.Event()
            threading.Thread(target=_run_worker, args=(ctx, key, module, results, done, gate),
                             name="debug-report-" + key, daemon=True).start()
            waits.append((key, done))
    for key, _title, module, mode, _part in SECTIONS:
        if mode == "request":
            results[key] = _run_one(ctx, key, module)
    for key, done in waits:
        done.wait(ctx.remaining())
    out = {}
    for key, _title, _module, _mode, _part in SECTIONS:
        out[key] = results.get(key) or ("timeout", time.monotonic() - ctx.started, None)
    return out


def _build(app=None, request_info=None):
    from panel.ops.debug_report import assemble, privacy
    ctx = Ctx(app=app, deadline_s=DEADLINE_S, request_info=request_info)
    # The name map first, in this (request) greenlet, where the app context is: the log sections
    # scrub their lines with it before selecting any, and they run as workers. It never raises: a
    # map that could not be built is reported by privacy.findings and the footer.
    privacy.prepare(ctx)
    return assemble.assemble(ctx, _run_sections(ctx))


def generate(app=None, request_info=None):
    """The report dict: {report, summary, issue_body, issues_url, filename}. One build at a time;
    a caller arriving while one builds waits for it and gets its result."""
    with _inflight_lock:
        running = _inflight["done"]
        if running is None:
            mine = threading.Event()
            _inflight["done"], _inflight["result"] = mine, None
    if running is not None:
        running.wait(DEADLINE_S + 15)
        res = _inflight.get("result")
        if res is not None:
            return res
        return _build(app, request_info)
    try:
        res = _build(app, request_info)
        _inflight["result"] = res
        return res
    finally:
        with _inflight_lock:
            _inflight["done"] = None
        mine.set()


__all__ = ["generate", "SECTIONS", "LEVELS"]
