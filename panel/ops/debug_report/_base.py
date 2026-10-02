"""The contract every debug-report section is written to.

A section is a function `fn(ctx) -> Result`. It reads what it needs, and returns markdown lines for
the full report, plus FINDINGS: the problems it saw, for the report's "At a glance" block and the
public GitHub issue. The runner (__init__.py) times every section, catches what it raises, and
prints a section that could not be read as exactly that -- never as "(none)" or 0, which read the
same as "nothing there" (empty-is-not-a-measurement).

Privacy is the rule every section is held to: the report is meant to be pasted on a PUBLIC issue.
A section prints counts, classes, booleans, ids, fixed-vocabulary tokens and exception CLASS names.
It never prints a host, address, account name, game-server name, path outside the checkout, URL,
token, or str(exc). The pseudonymiser in privacy.py runs over the finished text as a backstop, not
as the plan.

CROSS-MODULE CONTRACTS (who writes, who reads):
  app.config["PANEL_COMMIT"]    the commit this process loaded at start (app.py) -- header (R4)
  app.config["BOOT_BIND"], ["BOOT_PORT"]  what the server actually bound at boot (R19)
  app.config["BOOT_TLS"]        True/False/None: whether the panel itself serves TLS since boot (R20)
  app.config["BOOT_TLS_ERROR"]  exception CLASS name when TLS was configured but failed, else None
  app.config["BOOT_SERVE"]      "ok" | "failed:<fixed reason class>" | "not attempted" (R20)
  runtime_stats groups ("heartbeat" via beat(); the rest via bump()/put()):
    heartbeat   loop name -> {at, cadence, took, passes}           monitor loops etc. (R22)
    respawn     thread name -> count                               the supervisor (R22)
    errors      "LEVEL|logger|template" -> count, put() last time  logging handler (R24)
    privileged  "<verb>|<outcome token>" -> count                  _run_verb/_run_privileged (R25)
    ci_walk     sha7 -> (time, {state, failing:[names], pending:[names]}); "ratelimit" (R31)
    probe       "host:<id>" -> (time, {token, rc, ok_at, streak})  monitor probes (R48)
    console     "gs:<id>|<counter>" -> count / put()               console poller (R56)
    notify      "<channel>|<outcome>" -> count                     notification delivery (R63)
    bangate     "<counter>" -> count                               ProxiedBanGate (R44)
"""
import threading
import time

# A finding's level. "unread" is a section or check that could not be read: a problem in itself,
# never a pass.
LEVELS = ("fail", "warn", "unread", "ok")


def finding(level, area, text):
    """One At-a-glance line. `text` is fixed vocabulary: never a value read from the host."""
    if level not in LEVELS:
        raise ValueError("finding level %r" % (level,))
    return {"level": level, "area": area, "text": text}


class Result(object):
    """What a section returns.

    lines         markdown lines of the section's body in the full report.
    findings      finding() dicts for the At-a-glance block (ok ones are not shown there).
    verdict       one fixed-vocabulary line for the Verdicts block, or None.
    summary_lines lines that ALSO go in the public summary (the GitHub issue body). Keep them few.
    """

    def __init__(self, lines=None, findings=None, verdict=None, summary_lines=None):
        self.lines = list(lines or [])
        self.findings = list(findings or [])
        self.verdict = verdict
        self.summary_lines = list(summary_lines or [])

    def add(self, line):
        """Append one body line; returns self so a section can chain."""
        self.lines.append(line)
        return self

    def find(self, level, area, text):
        """Record a finding; returns self."""
        self.findings.append(finding(level, area, text))
        return self


def unread_line(what, exc):
    """'- **what**: could not be read (ExceptionClass)' -- the class only, never its message:
    sqlite, SQLAlchemy and OSError messages carry paths and bound parameters."""
    return "- **%s**: could not be read (%s)" % (what, type(exc).__name__)


def ago(seconds):
    """A compact age: '41 s', '12 m', '3 h 10 m', '2 d'. None/negative -> '?'."""
    if seconds is None or seconds < 0:
        return "?"
    s = int(seconds)
    if s < 120:
        return "%d s" % s
    if s < 7200:
        return "%d m" % (s // 60)
    if s < 172800:
        return "%d h %d m" % (s // 3600, (s % 3600) // 60)
    return "%d d" % (s // 86400)


class Ctx(object):
    """Per-report shared state: the deadline, the Flask app (or None), and a memo so a source two
    sections need (one `systemctl show`, one journal read, one tailscale status, one sqlite job) is
    read once per report."""

    def __init__(self, app=None, deadline_s=20.0, request_info=None):
        self.app = app
        self.started = time.monotonic()
        self.deadline = self.started + deadline_s
        self.request_info = request_info or {}
        self._memo = {}
        self._memo_lock = threading.Lock()

    def remaining(self):
        """Seconds left before the report's deadline (never negative)."""
        return max(0.0, self.deadline - time.monotonic())

    def memo(self, key, fn):
        """fn() once per report under `key`; later callers get the same value, or the same raise.

        Two sections asking at once both may compute it (the lock guards the dict, not the call:
        holding a lock across a subprocess would serialise every section behind the slowest)."""
        with self._memo_lock:
            if key in self._memo:
                ok, val = self._memo[key]
                if ok:
                    return val
                raise val
        try:
            val = fn()
        except Exception as exc:  # noqa: BLE001 - re-raised to every caller of this key
            with self._memo_lock:
                self._memo.setdefault(key, (False, exc))
            raise
        with self._memo_lock:
            self._memo.setdefault(key, (True, val))
            return self._memo[key][1] if self._memo[key][0] else val
