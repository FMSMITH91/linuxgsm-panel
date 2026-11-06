"""Debug-report section(s): errors_since_start.

Owner: builder B3. The swallowed-error counter fed by the logging handler app.py attaches (R23, R24),
read from runtime_stats.

THE HANDLERS (attached once, by app.create_app() through attach_log_handlers):
  * a stderr handler at WARNING on the 'panel' and 'notifications' loggers, formatted
    '%(levelname)s %(name)s: %(message)s'. The panel configured no logging at all, so its warnings
    reached the journal bare, through logging.lastResort; attaching any handler to a chain turns
    lastResort off for that chain, which is why this one has to exist before the counter can.
  * the debug log, only when config.json says "debug_log": true (attach_debug_file): every DEBUG
    record of 'panel' and 'notifications' to data/debug.log, size-capped and owner-only.
  * the error counter, on 'panel', 'notifications' and Flask's app logger. It keeps a COUNT per
    "LEVEL|logger|template", where the template is record.msg (the unformatted text, never
    getMessage(): the arguments are where host and server names are), and in runtime_stats group
    "errors_last" the time and exception CLASS of the last one. Records it keeps: WARNING and above,
    and any record that carries exc_info (the loops swallow their failures at DEBUG with it).

'panel' and 'notifications' are set to DEBUG so those DEBUG records are made at all; the stderr
handler's own level keeps them out of the journal. Flask's app logger keeps its level; the counter is
attached to it at WARNING, after app.logger exists, so Flask still adds its own default handler and a
500's traceback still prints. panel.auth's file handler (propagate=False) is not touched.

Both handlers are safe to call from a native tpool thread: the stderr handler's lock is a NATIVE
RLock (a green one cannot be waited on from a native thread while a greenlet holds it), and the
counter takes no lock at all (a few GIL-atomic dict operations through runtime_stats; a lost
increment under a race is acceptable, a raise or a hang is not).
"""
import logging
import logging.handlers
import os
import sys
import time

from panel.core import runtime_stats
from panel.ops.debug_report._base import Result, ago, cut_words

AREA = "Errors since start"
FORMAT = "%(levelname)s %(name)s: %(message)s"
LOGGERS = ("panel", "notifications")
TEMPLATE_MAX = 200          # stored
SHOWN_MAX = 120             # printed
ROWS_MAX = 25
_MARK = "_panel_debug_report"


def _native_rlock():
    """An RLock from the real threading module, even after eventlet.monkey_patch()."""
    import threading
    patcher = sys.modules.get("eventlet.patcher")
    if patcher is None:
        # eventlet not loaded: nothing has been patched, so the stdlib's lock is the native one.
        return threading.RLock()
    try:
        return patcher.original("threading").RLock()
    except Exception:  # noqa: BLE001 - fall back to the stdlib's
        return threading.RLock()


class StderrHandler(logging.StreamHandler):
    """A StreamHandler on sys.stderr whose lock a native thread can wait on."""

    def __init__(self):
        """Write to the process's stderr at WARNING in FORMAT."""
        super().__init__(sys.stderr)
        self.setLevel(logging.WARNING)
        self.setFormatter(logging.Formatter(FORMAT))
        setattr(self, _MARK, "stderr")

    def createLock(self):
        """A native RLock (see the module docstring), not the green one monkey_patch would give."""
        self.lock = _native_rlock()


# The opt-in debug log (config "debug_log": true, read at start): every DEBUG record of the two
# loggers above, which the stderr handler keeps out of the journal. Those are where the panel's
# loops record what they did and why a step was skipped ("command list refresh failed for …",
# the bots' replies), so a fault on a test box can be traced from the file instead of guessed at.
# Capped: DEBUG_FILE_BYTES per file, DEBUG_FILE_BACKUPS older ones kept, so 20 MB at most. 0600
# in the 0700 data dir: records name hosts, servers and players.
DEBUG_FILE_NAME = "debug.log"
DEBUG_FILE_BYTES = 5 * 1024 * 1024
DEBUG_FILE_BACKUPS = 3
DEBUG_FILE_FORMAT = "%(asctime)s %(levelname)s %(name)s [%(threadName)s]: %(message)s"


class DebugFileHandler(logging.handlers.RotatingFileHandler):
    """The debug log: DEBUG and up to a size-capped file, owner-only, with a native lock."""

    def __init__(self, path):
        """Append to `path` at DEBUG in DEBUG_FILE_FORMAT, rotating at DEBUG_FILE_BYTES."""
        super().__init__(path, maxBytes=DEBUG_FILE_BYTES, backupCount=DEBUG_FILE_BACKUPS,
                         encoding="utf-8")
        self.setLevel(logging.DEBUG)
        self.setFormatter(logging.Formatter(DEBUG_FILE_FORMAT))
        setattr(self, _MARK, "debugfile")

    def createLock(self):
        """A native RLock, as StderrHandler's: tpool threads log too."""
        self.lock = _native_rlock()

    def _open(self):
        """Open the file (a new one after each rotation too) and make it the owner's alone."""
        stream = super()._open()
        try:
            os.chmod(self.baseFilename, 0o600)
        except OSError:
            pass
        return stream


def attach_debug_file(path):
    """Attach the debug log at `path` to LOGGERS, once per process. Returns what was attached now."""
    added = []
    handler = None
    for name in LOGGERS:
        lg = logging.getLogger(name)
        if _has(lg, "debugfile"):
            continue
        if handler is None:
            handler = DebugFileHandler(path)
        lg.addHandler(handler)
        lg.setLevel(logging.DEBUG)
        added.append(name + ":debugfile")
    return added


def error_key(record):
    """'LEVEL|logger|template': record.msg when it is text, else only its type's name."""
    msg = record.msg if isinstance(record.msg, str) else type(record.msg).__name__
    return "%s|%s|%s" % (record.levelname, record.name, cut_words(msg, TEMPLATE_MAX))


def _exc_class(record):
    exc = record.exc_info
    if isinstance(exc, tuple) and exc and exc[0] is not None:
        return getattr(exc[0], "__name__", "?")
    return None


class ErrorCounter(logging.Handler):
    """Counts warnings, errors and exc_info records into runtime_stats. Lock-free; never raises."""

    def __init__(self, level=logging.NOTSET):
        """A counter keeping records at `level` and above (and every one with exc_info)."""
        super().__init__(level)
        setattr(self, _MARK, "counter")

    def createLock(self):
        """No lock: emit() is a few GIL-atomic dict operations."""
        self.lock = None

    def handle(self, record):
        """Filter and emit without a lock (logging.Handler.handle would take one)."""
        if self.filter(record):
            self.emit(record)
        return True

    def emit(self, record):
        """Count the record, keyed by its template; remember the last one's exception class."""
        try:
            if record.levelno < logging.WARNING and not _exc_class(record):
                return
            key = error_key(record)
            runtime_stats.bump("errors", key)
            runtime_stats.put("errors_last", key, _exc_class(record))
        except Exception:  # noqa: BLE001 - a counter must never raise into the code that logged
            return


def _has(logger, kind):
    return any(getattr(h, _MARK, None) == kind for h in logger.handlers)


def attach_log_handlers(app_logger=None):
    """Attach the stderr handler and the counter, once per process. Returns what was attached now.

    `app_logger` is Flask's app.logger (already created, so Flask has added its default handler).
    """
    added = []
    for name in LOGGERS:
        lg = logging.getLogger(name)
        if not _has(lg, "stderr"):
            lg.addHandler(StderrHandler())
            added.append(name + ":stderr")
        if not _has(lg, "counter"):
            lg.addHandler(ErrorCounter())
            added.append(name + ":counter")
        lg.setLevel(logging.DEBUG)
    if app_logger is not None and not _has(app_logger, "counter"):
        app_logger.addHandler(ErrorCounter(logging.WARNING))
        added.append(app_logger.name + ":counter")
    return added


def detach_log_handlers(app_logger=None):
    """Remove what attach_log_handlers added (tests), and put the levels back to NOTSET."""
    for lg in [logging.getLogger(n) for n in LOGGERS] + ([app_logger] if app_logger else []):
        for h in [h for h in lg.handlers if getattr(h, _MARK, None)]:
            lg.removeHandler(h)
            if getattr(h, _MARK, None) == "debugfile":
                h.close()
    for name in LOGGERS:
        logging.getLogger(name).setLevel(logging.NOTSET)


def capturing():
    """Whether the counter is attached in this process."""
    return _has(logging.getLogger("panel"), "counter")


# ── the section ──────────────────────────────────────────────────────────────────────────────────
def _cell(text):
    """A template as a table cell: one line, no pipes, at most SHOWN_MAX characters."""
    return cut_words(" ".join(str(text).split()).replace("|", "/"), SHOWN_MAX)


def _row(key, count, last, ctx=None):
    level, name, template = (key.split("|", 2) + ["", ""])[:3]
    if ctx is not None:                 # scrubbed BEFORE the cell is cut (see cut_words)
        from panel.ops.debug_report import privacy
        template = privacy.scrub_text(ctx, template)
    at, exc = last if isinstance(last, tuple) else (None, None)
    return "| %s | %s | %s | %s | %d | %s |" % (
        _cell(level), _cell(name), _cell(template), _cell(exc or "–"), count,
        time.strftime("%H:%M", time.gmtime(at)) if at else "?")


def section_errors_since_start(ctx):
    """R24: what the counter saw since this process started, most frequent first."""
    res = Result()
    up = ago(time.time() - runtime_stats.started())
    lost = runtime_stats.lost()
    if lost:
        # The counters swallow their own errors so a loop never dies of them; say how many.
        res.add("- **Counter writes lost to an exception**: %d (the numbers in this report "
                "undercount by up to that)" % lost)
        res.find("warn", AREA, "%d instrumentation write(s) failed" % lost)
    if not capturing():
        res.add("- (no error capture: this process was not started through app.create_app, or "
                "predates the counter)")
        res.find("unread", AREA, "the error counter is not attached in this process")
        return res
    counts = runtime_stats.snapshot("errors")
    last = runtime_stats.snapshot("errors_last")
    dropped = counts.pop("_dropped", 0)
    rows = sorted(((k, v) for k, v in counts.items() if isinstance(v, int)), key=lambda kv: -kv[1])
    if not rows:
        res.add("- none since start (%s)" % up)
        return res
    _table(res, rows, last, dropped, up, ctx)
    if any(k.startswith(("ERROR|", "CRITICAL|")) for k, _v in rows):
        res.find("warn", AREA, "errors were logged since the process started")
    return res


def _table(res, rows, last, dropped, up, ctx=None):
    res.add("Process up %s; %d distinct messages, %d records." % (
        up, len(rows), sum(v for _k, v in rows)))
    res.add("")
    res.add("| level | logger | message template | exception | count | last (UTC) |")
    res.add("|---|---|---|---|---|---|")
    for key, count in rows[:ROWS_MAX]:
        res.add(_row(key, count, last.get(key), ctx))
    if len(rows) > ROWS_MAX or dropped:
        res.add("")
        res.add("- %d more not shown; %d further keys not stored (the counter keeps %d)" % (
            max(0, len(rows) - ROWS_MAX), dropped, runtime_stats._MAX_KEYS))
