"""One browser page, driven over the DevTools protocol, with V8 coverage kept across navigations.

Coverage: Profiler.startPreciseCoverage with call counts and block detail, and a
Profiler.takePreciseCoverage before every navigation. A take RESETS V8's counters, so each take is
added to the file's running totals (v8_lcov.FileCounts) as it arrives.

WHY EVERY NAVIGATION IS HELD. When a document goes, V8 drops its scripts, and their counts with
them: a take after a reload reports only the new document's copy. Measured: a button pressed twice
and then a reload left one press in the report. goto() takes before it navigates, but most
navigations here are the page's own — a form posting and redirecting back, a control that reloads
— and each of those threw away everything the page had run since it loaded.

So the page is stopped at the moment it asks to leave, and the take happens then. helpers.js
listens for the Navigation API's `navigate` event, which a document fires for every navigation it
starts (a link, a form, a reload, an assignment to location) BEFORE the request goes out, and an
event-listener breakpoint pauses the page on it. While paused, the renderer still answers the
protocol, so the take arrives with the leaving document intact, and the page is resumed from the
take's reply. It cannot be done once the request is out: the browser holds every message for the
renderer until the navigation commits, and by then the old document is gone (a Fetch-domain hold
on the request was tried first, and hung that way).

Waiting: every request the page makes is tracked from the Network domain, and a step is over when
nothing has been in flight for a moment. Socket.IO's own long-poll is not counted — it is always in
flight — and neither is a request that has run for longer than STALE seconds (a download, a stream).

Reaching: every page the walk names must render as itself. One that redirects elsewhere or answers
an HTTP error is recorded in `unreached`, and run.py fails the run over it: a renamed route would
otherwise shrink the measurement without a word, and read as the code having lost coverage.
"""
import json
import os
import re
import time
import urllib.parse

import v8_lcov
from cdp import CDPError

HERE = os.path.dirname(os.path.abspath(__file__))
JS_URL_PATH = re.compile(r"^/static/js/([A-Za-z0-9_-]+\.js)$")
STALE = 8.0
MAX_AWAY = 20


def log(msg):
    """Print one line of progress, unbuffered, so a CI log shows where a run is."""
    print(msg, flush=True)


class LoginFailed(RuntimeError):
    """Signing in did not leave the login page."""


class Driver:
    """The page run.py drives: navigation, waiting, in-page steps and the coverage kept."""

    def __init__(self, cdp, base, user, password, sources):
        """Drive the page behind `cdp`, on the panel at `base`, signed in as `user`.

        `sources` is {"static/js/x.js": its text}: the files whose coverage is kept.
        """
        self.cdp = cdp
        self.base = base
        self.user = user
        self.password = password
        self.sources = sources
        self.counts = {}          # "static/js/x.js" -> v8_lcov.FileCounts
        self.loaded = set()       # the files some page loaded
        self.held = 0             # navigations held to take the leaving document's counts
        self.errors = []          # uncaught exceptions the pages threw: (url, line, text)
        self.unreached = []       # (page, why): pages of the walk that did not render as themselves
        self.loads = 0
        self.doc_status = 0       # HTTP status of the last document the page loaded
        self.chrome_done = False
        self.confirming = {}      # page path -> signatures of controls that asked to be confirmed
        self._inflight = {}
        with open(os.path.join(HERE, "helpers.js"), encoding="utf-8") as fh:
            self._helpers = fh.read()
        cdp.on_event = self._on_event

    def start(self):
        """Enable the domains the run reads, start coverage, and install the in-page helpers."""
        c = self.cdp
        for dom in ("Page", "Runtime", "Debugger", "Profiler", "Network"):
            c.call(dom + ".enable")
        # Every pause is this harness's own (the breakpoint below) and is resumed as soon as the
        # take is in; nothing else may stop the page, so pausing on exceptions stays off.
        c.call("Debugger.setPauseOnExceptions", {"state": "none"})
        self._prepare_counts()
        c.call("Profiler.startPreciseCoverage", {"callCount": True, "detailed": True})
        c.call("DOMDebugger.setEventListenerBreakpoint", {"eventName": "navigate"})
        # A page that opens a window would put that page's coverage in another target.
        c.call("Page.addScriptToEvaluateOnNewDocument",
               {"source": "window.open = function(){ return null; };"})
        # In every document, so a control that reloads the page leaves the helpers in place.
        c.call("Page.addScriptToEvaluateOnNewDocument", {"source": self._helpers})

    # ── events ─────────────────────────────────────────────────────────────────────────────────
    def _on_event(self, msg):
        m, p = msg["method"], msg.get("params", {})
        if m == "Network.requestWillBeSent":
            url = p.get("request", {}).get("url", "")
            if "/socket.io/" not in url and not url.startswith("data:"):
                self._inflight[p["requestId"]] = time.monotonic()
        elif m in ("Network.loadingFinished", "Network.loadingFailed"):
            self._inflight.pop(p.get("requestId"), None)
        elif m == "Network.responseReceived" and p.get("type") == "Document":
            self.doc_status = int(p.get("response", {}).get("status", 0) or 0)
        elif m == "Page.loadEventFired":
            self.loads += 1
        elif m == "Runtime.exceptionThrown":
            self._record_exception(p.get("exceptionDetails", {}))
        elif m == "Debugger.paused":
            self._hold_navigation()

    def _hold_navigation(self):
        """The page is about to leave: keep its counts while it is paused, then let it go on."""
        def taken(reply):
            self._keep(reply.get("result", {}))
            self.cdp.send("Debugger.resume")
        self.held += 1
        self.cdp.send("Profiler.takePreciseCoverage", on_reply=taken)

    def _record_exception(self, d):
        text = (d.get("exception") or {}).get("description") or d.get("text", "")
        self.errors.append((d.get("url", ""), d.get("lineNumber", -1) + 1,
                            (text.splitlines() or [""])[0][:200]))

    def busy(self):
        """Say whether a request the page made is still in flight (and not a stale one)."""
        now = time.monotonic()
        for rid, t0 in list(self._inflight.items()):
            if now - t0 > STALE:
                del self._inflight[rid]
        return bool(self._inflight)

    def settle(self, quiet=0.3, limit=6.0):
        """Read events until no request has been in flight for `quiet` seconds (at most `limit`)."""
        deadline = time.monotonic() + limit
        idle_since = None
        while time.monotonic() < deadline:
            self.cdp.pump(0.08)
            if self.busy():
                idle_since = None
            elif idle_since is None:
                idle_since = time.monotonic()
            elif time.monotonic() - idle_since >= quiet:
                break
        del self.cdp.events[:]

    def wait(self, seconds):
        """Let the page run for `seconds`, answering whatever it asks meanwhile."""
        self.cdp.pump(seconds)
        del self.cdp.events[:]

    # ── coverage ───────────────────────────────────────────────────────────────────────────────
    def _prepare_counts(self):
        """Ask V8 where each file can stop — its lines — by compiling it once, never running it."""
        for path, source in sorted(self.sources.items()):
            comp = self.cdp.call("Runtime.compileScript", {
                "expression": source, "persistScript": True, "sourceURL": "jscov:" + path})
            if comp.get("exceptionDetails") or not comp.get("scriptId"):
                raise CDPError("%s does not compile in this browser: %s"
                               % (path, comp.get("exceptionDetails")))
            start = {"scriptId": comp["scriptId"], "lineNumber": 0, "columnNumber": 0}
            locs = self.cdp.call("Debugger.getPossibleBreakpoints", {"start": start},
                                 timeout=60).get("locations", [])
            self.counts[path] = v8_lcov.FileCounts(
                [(x["lineNumber"], x.get("columnNumber", 0)) for x in locs], source)

    def _keep(self, result):
        for script in result.get("result", []):
            path = self.repo_path(script.get("url", ""))
            if path in self.counts:
                self.counts[path].add(script.get("functions", []))
                self.loaded.add(path)

    def snapshot(self):
        """Take V8's counts since the last take and add them to each file's totals."""
        try:
            self._keep(self.cdp.call("Profiler.takePreciseCoverage", timeout=60))
        except CDPError as e:
            log("  ! coverage: %s" % e)

    def hits(self):
        """Return {path: {line: hits}} for every file, loaded or not."""
        return {path: fc.hits() for path, fc in self.counts.items()}

    def repo_path(self, url):
        """Map a script URL to its repository path (static/js/x.js), or None if it is not one."""
        if not url.startswith(self.base):
            return None
        m = JS_URL_PATH.match(url[len(self.base):].split("?", 1)[0])
        return "static/js/" + m.group(1) if m else None

    # ── navigation ─────────────────────────────────────────────────────────────────────────────
    def url(self):
        """Return the page's current URL, or "" when the page cannot be asked."""
        try:
            return self.cdp.evaluate("location.href", timeout=10) or ""
        except CDPError:
            return ""

    def path(self):
        """Return the path part of the page's current URL."""
        return urllib.parse.urlsplit(self.url()).path

    def _wait_load(self, loads_before, timeout=30):
        deadline = time.monotonic() + timeout
        while self.loads == loads_before and time.monotonic() < deadline:
            self.cdp.pump(0.1)
        return self.loads != loads_before

    def goto(self, path, settle=True):
        """Navigate to `path` on the panel, signing in again if the session was lost."""
        self.snapshot()
        before = self.loads
        self.cdp.call("Page.navigate", {"url": self.base + path})
        if not self._wait_load(before):
            log("  ! %s: no load event in 30s" % path)
        if settle:
            self.settle(quiet=0.5, limit=8.0)
        if self.path().startswith("/login") and not path.startswith("/login"):
            log("  ! %s: signed out, signing in again" % path)
            self.login()
            return self.goto(path, settle)
        return True

    def js(self, expression, timeout=30):
        """Evaluate in the page and return the value, or None when it fails.

        A step that fails is logged and must not end the run: it only leaves its part of the code
        uncovered, which the report shows.
        """
        for attempt in (1, 2):
            try:
                return self.cdp.evaluate(expression, timeout=timeout)
            except CDPError as e:
                if attempt == 1 and "__jscov is not defined" in str(e):
                    self._reinstall_helpers()
                    continue
                log("  ! js: %s" % str(e)[:200])
                return None
        return None

    def _reinstall_helpers(self):
        try:
            self.cdp.evaluate(self._helpers, timeout=10, await_promise=False)
        except CDPError:
            pass

    def login(self):
        """Sign in through the login form, as a person would; raise LoginFailed if it does not land."""
        self.goto("/login", settle=False)
        self.settle(quiet=0.3, limit=4)
        self.js("__jscov.setValue(document.getElementById('username'), %s);"
                "__jscov.setValue(document.getElementById('password'), %s); true"
                % (json.dumps(self.user), json.dumps(self.password)))
        before = self.loads
        self.js("document.querySelector('form button[type=submit]').click(); true")
        self._wait_load(before)
        self.settle(quiet=0.5, limit=8)
        if self.path().startswith("/login") or not self.url().startswith(self.base):
            raise LoginFailed("signing in did not land: still at %r" % self.url())

    def reached(self, path, record=True):
        """Go to `path` and say whether it rendered as itself.

        A page that did not is recorded in `unreached` when `record` is set. The pass that confirms
        deletions does not record: a page it finds gone may be one an earlier OK deleted.
        """
        self.goto(path)
        want = path.split("#")[0].split("?")[0]
        why = ""
        if self.doc_status >= 400:
            why = "HTTP %d" % self.doc_status
        elif self.path() != want:
            why = "redirected to %s" % self.path()
        if why:
            log("  ! %s: %s; nothing to exercise" % (path, why))
            if record:
                self.unreached.append((path, why))
        return not why

    # ── exercising a page ──────────────────────────────────────────────────────────────────────
    def dialogs(self, accept=False):
        """Answer whatever the last step opened (OK only when accept is True)."""
        self.js("__jscov.settleDialogs(%s, %s)" % ("true" if accept else "false",
                                                    json.dumps(self.password)))

    def exercise(self, path, skip=(), accept=False, limit=250):
        """Fire every distinct control on the page once, and return how many were fired.

        Forms are filled in and submitted, any confirmation a control opens is answered, and the
        walk comes back to the page when a control navigated away. The sidebar and top bar are the
        same on every page, so they are pressed on the first page exercised only. A control whose
        press opened a confirmation is remembered for the page: the pass that presses OK
        (accept=True) presses those and nothing else, since everything else has already run.
        """
        want = path.split("#")[0].split("?")[0]
        only = sorted(self.confirming.get(want, ())) if accept else None
        if accept and not only:
            return 0
        if not self.reached(path, record=not accept):
            return 0
        opts = {"path": want, "done": [], "only": only, "skip": list(skip),
                "mainOnly": self.chrome_done, "accept": accept, "password": self.password}
        self.chrome_done = True
        return self._press_all(path, opts, limit)

    def _press_all(self, path, opts, limit):
        prev, away = None, 0
        for _ in range(limit):
            res = self.js("__jscov.step(%s)" % json.dumps(opts))
            if res is None:
                self.goto(path)
                continue
            if prev and res.get("dialogs"):
                self.confirming.setdefault(opts["path"], set()).add(prev)
            if res.get("path") != opts["path"]:
                # The last control navigated. Come back — a few times at most, so a page that
                # always leaves cannot hold the walk.
                away += 1
                if away > MAX_AWAY:
                    log("  ! %s: left the page %d times; moving on" % (path, away))
                    break
                self.goto(path)
                continue
            prev = res.get("sig")
            if not prev:
                break
            opts["done"].append(prev)
            self.settle(quiet=0.15, limit=2.5)
        return len(opts["done"])

    def run(self, script, timeout=90):
        """Run an async in-page step (a JS function body using the helpers) and let it settle."""
        res = self.js("(async () => { const J = window.__jscov; %s })()" % script, timeout=timeout)
        self.settle(quiet=0.3, limit=6.0)
        return res
