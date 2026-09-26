"""One browser page, driven over the DevTools protocol, with V8 coverage kept across navigations.

Coverage: Profiler.startPreciseCoverage with call counts and block detail, and a
Profiler.takePreciseCoverage before every navigation. A take RESETS V8's counters, so each take is
kept whole (per /static/js file) and v8_lcov sums them; taking one before the page goes means a
navigation that lands in a new renderer cannot take the old page's counts with it.

Waiting: every request the page makes is tracked from the Network domain, and a step is over when
nothing has been in flight for a moment. Socket.IO's own long-poll is not counted — it is always in
flight — and neither is a request that has run for longer than STALE seconds (a download, a stream).
"""
import json
import os
import re
import time
import urllib.parse

from cdp import CDPError

HERE = os.path.dirname(os.path.abspath(__file__))
JS_URL_PATH = re.compile(r"^/static/js/([A-Za-z0-9_-]+\.js)$")
STALE = 8.0


def log(msg):
    print(msg, flush=True)


class LoginFailed(RuntimeError):
    pass


class Driver:
    def __init__(self, cdp, base, user, password):
        self.cdp = cdp
        self.base = base
        self.user = user
        self.password = password
        self.takes = {}           # "static/js/x.js" -> [functions of each take]
        self.errors = []          # uncaught exceptions the pages threw: (url, line, text)
        self.loads = 0
        self.chrome_done = False
        self.confirming = {}      # page path -> signatures of controls that asked to be confirmed
        self._inflight = {}
        with open(os.path.join(HERE, "helpers.js"), encoding="utf-8") as fh:
            self._helpers = fh.read()
        cdp.on_event = self._on_event

    def start(self):
        c = self.cdp
        for dom in ("Page", "Runtime", "Debugger", "Profiler", "Network"):
            c.call(dom + ".enable")
        c.call("Debugger.setSkipAllPauses", {"skip": True})
        c.call("Profiler.startPreciseCoverage", {"callCount": True, "detailed": True})
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
        elif m == "Page.loadEventFired":
            self.loads += 1
        elif m == "Runtime.exceptionThrown":
            d = p.get("exceptionDetails", {})
            text = (d.get("exception") or {}).get("description") or d.get("text", "")
            self.errors.append((d.get("url", ""), d.get("lineNumber", -1) + 1,
                                (text.splitlines() or [""])[0][:200]))

    def busy(self):
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
        self.cdp.pump(seconds)
        del self.cdp.events[:]

    # ── coverage ───────────────────────────────────────────────────────────────────────────────
    def snapshot(self):
        try:
            res = self.cdp.call("Profiler.takePreciseCoverage", timeout=60)
        except CDPError as e:
            log("  ! coverage: %s" % e)
            return
        for script in res.get("result", []):
            path = self.repo_path(script.get("url", ""))
            if path:
                self.takes.setdefault(path, []).append(script.get("functions", []))

    def repo_path(self, url):
        if not url.startswith(self.base):
            return None
        m = JS_URL_PATH.match(url[len(self.base):].split("?", 1)[0])
        return "static/js/" + m.group(1) if m else None

    # ── navigation ─────────────────────────────────────────────────────────────────────────────
    def url(self):
        try:
            return self.cdp.evaluate("location.href", timeout=10) or ""
        except CDPError:
            return ""

    def path(self):
        return urllib.parse.urlsplit(self.url()).path

    def _wait_load(self, loads_before, timeout=30):
        deadline = time.monotonic() + timeout
        while self.loads == loads_before and time.monotonic() < deadline:
            self.cdp.pump(0.1)
        return self.loads != loads_before

    def goto(self, path, settle=True):
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
        """Evaluate in the page; an error is logged and returns None — a step that fails must not
        end the run, only leave its part of the code uncovered."""
        for attempt in (1, 2):
            try:
                return self.cdp.evaluate(expression, timeout=timeout)
            except CDPError as e:
                if attempt == 1 and "__jscov is not defined" in str(e):
                    try:
                        self.cdp.evaluate(self._helpers, timeout=10, await_promise=False)
                    except CDPError:
                        pass
                    continue
                log("  ! js: %s" % str(e)[:200])
                return None

    def login(self):
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

    # ── exercising a page ──────────────────────────────────────────────────────────────────────
    def dialogs(self, accept=False):
        """Answer whatever the last step opened (OK only when accept is True)."""
        self.js("__jscov.settleDialogs(%s, %s)" % ("true" if accept else "false",
                                                    json.dumps(self.password)))

    def exercise(self, path, skip=(), accept=False, limit=250):
        """Fire every distinct control on the page once — forms filled in and submitted — answering
        any confirmation it opens, and come back to the page when one navigated away. Returns how
        many were fired.

        The sidebar and top bar are the same on every page, so they are pressed on the first page
        exercised only. A control whose press opened a confirmation is remembered for the page:
        the pass that presses OK (accept=True) presses those and nothing else, since everything
        else has already run."""
        self.goto(path)
        want = path.split("#")[0].split("?")[0]
        if self.path() != want:
            log("  ! %s: redirected to %s; nothing to exercise" % (path, self.path()))
            return 0
        main_only = self.chrome_done
        self.chrome_done = True
        only = sorted(self.confirming.get(want, ())) if accept else None
        if accept and not only:
            return 0
        done, prev, away = [], None, 0
        for _ in range(limit):
            res = self.js("__jscov.step(%s)" % json.dumps({
                "path": want, "done": done, "only": only, "skip": list(skip),
                "mainOnly": main_only, "accept": accept, "password": self.password}))
            if res is None:
                self.goto(path)
                continue
            if prev and res.get("dialogs"):
                self.confirming.setdefault(want, set()).add(prev)
            if res.get("path") != want:
                # The last control navigated. Come back — a few times at most, so a page that
                # always leaves cannot hold the walk.
                away += 1
                if away > 20:
                    log("  ! %s: left the page %d times; moving on" % (path, away))
                    break
                self.goto(path)
                continue
            prev = res.get("sig")
            if not prev:
                break
            done.append(prev)
            self.settle(quiet=0.15, limit=2.5)
        return len(done)

    def run(self, script, timeout=60):
        """Run an async in-page step (a JS function body using the helpers) and let it settle."""
        res = self.js("(async () => { const J = window.__jscov; %s })()" % script, timeout=timeout)
        self.settle(quiet=0.3, limit=6.0)
        return res
