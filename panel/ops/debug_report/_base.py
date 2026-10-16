"""The contract every debug-report section is written to.

A section is a function `fn(ctx) -> Result`. It reads what it needs, and returns markdown lines for
the full report, plus FINDINGS: the problems it saw, for the report's "At a glance" block and the
public GitHub issue. The runner (__init__.py) times every section, catches what it raises, and
prints a section that could not be read as exactly that -- never as "(none)" or 0, which read the
same as "nothing there" (empty-is-not-a-measurement).

Privacy is the rule every section is held to: the report is meant to be pasted on a PUBLIC issue.
Security POSTURE -- what tells a reader which of this panel's defences is weak (2FA counts, invites
that grant superadmin, the setup-token file, the firewall's ways in, fail2ban jails that cannot ban)
-- never goes in it: a section records those with Result.posture()/posture_find(), and
assemble.py shows them only on the in-panel report page (_page_only there, POSTURE_RE below).
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
  app.config["BOOT_SERVE_LEFTOVERS"]  the panel's routes at other mounts, after that re-point:
                                "none" | "removed:<mount>,..." | "unread" | "failed:<reason class>"
                                | "not attempted" (R20)
  runtime_stats groups ("heartbeat" via beat(); the rest via bump()/put()):
    heartbeat   loop name -> {at, cadence, took, passes}           monitor loops etc. (R22)
    loop_start  loop name -> put(s to its first pass), when started  loops that sleep first (R22)
    respawn     thread name -> count                               the supervisor (R22)
    loopfail    loop name -> count of passes that raised           every beating loop (R22)
    errors      "LEVEL|logger|template" -> count                   logging handler (R24)
    errors_last "LEVEL|logger|template" -> put(exception class)    logging handler (R24)
    hub         "ticks", "lag_max" -> put()                        the hub-lag watch (R17)
    hub_lag     "m<minute bucket>" -> put((minute, lag s))         the hub-lag watch (R17)
    privileged  "<verb>|<outcome>", "via|<path>" -> count; "last|<outcome>" -> put(verb)  (R25)
    ci_walk     sha7 -> put({state, failing, pending}); "walk", "ratelimit" -> put()     (R31)
    console     "poller|watched" -> put(count)                     console poller (R56)
    notify      "<channel>|<outcome>" -> count, "<channel>|last_http" -> put()  delivery (R63)
    bangate     "refused" -> count, "last" -> put()                ProxiedBanGate (R44)
  NOT runtime_stats, because a deleted row's id must be forgotten (register_*_state):
    monitoring._probe_record      host id -> {ok, token, rc, at, ok_at, fail_since, streak} (R48)
    server_files._console_feed    server id -> {ticks, fails, streak, last_fail, pushed_at,
                                  rotations}                                               (R56)
  Shared reads, one per report through ctx.memo (call these, never the raw reader):
    _src_systemd.shared(ctx)          `systemctl show` (R8, R15, R21)
    _src_tailscale.shared_read(ctx) / shared_info(ctx)   Tailscale status (R36, R49, R72)
    diagnostics.shared_integrity(ctx) the one quick_check (R12, R57)
"""
import re
import threading
import time

# A finding's level. "unread" is a section or check that could not be read: a problem in itself,
# never a pass.
LEVELS = ("fail", "warn", "unread", "ok")

# The posture's own vocabulary: the labels and finding texts the sections print through posture()
# and posture_find(). assemble.py withholds any line of the downloadable file that matches, whichever
# section printed it and however (a posture line a new section adds with add() instead): the file is
# what the GitHub issue form asks to have attached publicly, and the issue's account names the owner.
# Fixed, English report vocabulary (the report is not translated), never a host's text.
POSTURE_RE = re.compile(
    r"\*\*2FA on\*\*|not every superadmin has 2FA|grant superadmin|setup token file|Must change password"
    r"|\*\*Ways in\*\*|default incoming|can never ban|which no jail can ban|jail file\*\*"
    r"|jail \(runtime\)\*\*|\*\*sshd jail\*\*|· jails:|without the panel-login jail"
    r"|does not watch this install's auth\.log|no failed login reaches fail2ban|fail2ban ignores them"
    r"|auth\.log handler attached|\*\*UFW\*\*: (?:active|inactive|not installed)"
    r"|\*\*fail2ban\*\*: (?:running|not installed)|UFW (?:active|inactive)|fail2ban running"
    r"|Defence tools|defence tool missing|\*\*Ban gate \(|ban gate's fail2ban set"
    r"|\*\*Funnel\*\*:|Funnel is ON in Serve|Funnel is on for the whole|through Tailscale Funnel"
    r"|Tailscale-Funnel-Request|\*\*tailscale_use_funnel\*\*|Tailscale \w+, Funnel (?:on|off)"
    r"|\*\*Session cookie\*\*|Secure cookies while|session cookie Secure|\*\*cookie_secure\*\*"
    r"|trust_proxy is on but the panel listens beyond loopback|Automatic security updates"
    r"|\*\*Tailscale operator\*\*|panel account is the operator")


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
    page_lines    security-posture lines: shown on the in-panel report page ONLY, never in the
                  downloaded file, the summary or the issue body.
    page_findings posture findings, likewise: never in At a glance.
    """

    def __init__(self, lines=None, findings=None, verdict=None, summary_lines=None):
        """A Result holding copies of the given lists (all empty by default)."""
        self.lines = list(lines or [])
        self.findings = list(findings or [])
        self.verdict = verdict
        self.summary_lines = list(summary_lines or [])
        self.page_lines = []
        self.page_findings = []

    def add(self, line):
        """Append one body line; returns self so a section can chain."""
        self.lines.append(line)
        return self

    def find(self, level, area, text):
        """Record a finding; returns self."""
        self.findings.append(finding(level, area, text))
        return self

    def posture(self, line):
        """Append one security-posture line, for the in-panel page only; returns self."""
        self.page_lines.append(line)
        return self

    def posture_find(self, level, area, text):
        """Record a security-posture finding, for the in-panel page only; returns self."""
        self.page_findings.append(finding(level, area, text))
        return self


def unread_line(what, exc):
    """'- **what**: could not be read (ExceptionClass)', naming the class only.

    Never the exception's message: sqlite, SQLAlchemy and OSError messages carry paths and bound
    parameters.
    """
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


def cut_words(text, limit):
    """`text` cut to at most `limit` characters at a word boundary, with '…' when cut.

    Free text is cut BEFORE the report's final privacy pass, which matches whole names and
    addresses: cut through the middle of one and the pass sees only a fragment it cannot match, so
    the fragment prints. Cutting at whitespace keeps every word either whole or gone; the caller
    scrubs first where it can (a name of several words can still be cut between two of them). One
    word longer than half the limit is cut through, rather than dropping the whole text.
    """
    text = str(text)
    if len(text) <= limit:
        return text
    cut = text[:max(0, limit - 1)]
    space = max(cut.rfind(" "), cut.rfind("\t"))
    return (cut[:space].rstrip() if space >= len(cut) // 2 else cut) + "…"


class Ctx(object):
    """Per-report shared state: the deadline, the Flask app (or None), and a memo.

    The memo is how a source two sections need (one `systemctl show`, one journal read, one
    tailscale status, one sqlite job) is read once per report.
    """

    def __init__(self, app=None, deadline_s=20.0, request_info=None):
        """A context whose deadline is `deadline_s` seconds from now."""
        self.app = app
        self.started = time.monotonic()
        self.deadline = self.started + deadline_s
        self.request_info = request_info or {}
        self._memo = {}
        self._running = {}          # key -> Event, while the first caller computes it
        self._memo_lock = threading.Lock()

    def remaining(self):
        """Seconds left before the report's deadline (never negative)."""
        return max(0.0, self.deadline - time.monotonic())

    def memo(self, key, fn, wait=None):
        """fn() once per report under `key`; later callers get the same value, or the same raise.

        Single-flight: a caller arriving while another computes the key waits for that answer (at
        most until the report's deadline) instead of starting a second read -- two worker sections
        start together, and a duplicate `systemctl show` or quick_check costs most exactly when the
        source is slow. The lock guards the dicts, never the call: holding it across a subprocess
        would serialise every section behind the slowest. A waiter waits until the deadline, or
        `wait` seconds when given, and then raises TimeoutError (its section is reported as
        unread); fn must not ask for its own key.
        """
        with self._memo_lock:
            if key in self._memo:
                return self._unwrap(key)
            running = self._running.get(key)
            if running is None:
                mine = self._running[key] = threading.Event()
        if running is not None:
            running.wait(self.remaining() if wait is None else wait)
            with self._memo_lock:
                if key in self._memo:
                    return self._unwrap(key)
            raise TimeoutError("memo %s still being read at the deadline" % (key,))
        entry = (False, RuntimeError("memo %s abandoned" % (key,)))   # a BaseException: no answer
        try:
            val = fn()
            entry = (True, val)
            return val
        except Exception as exc:  # noqa: BLE001 - re-raised to every caller of this key
            entry = (False, exc)
            raise
        finally:
            self._settle(key, mine, entry)

    def _unwrap(self, key):
        ok, val = self._memo[key]
        if ok:
            return val
        raise val

    def _settle(self, key, event, entry):
        with self._memo_lock:
            self._memo.setdefault(key, entry)
            self._running.pop(key, None)
        event.set()
