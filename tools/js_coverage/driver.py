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
import urllib.request

import v8_lcov
from cdp import CDPError

HERE = os.path.dirname(os.path.abspath(__file__))
# Under the panel's mount, when it has one (Tailscale Serve at /lgsm puts every asset there).
JS_URL_PATH = re.compile(r"^(?:/[A-Za-z0-9_.-]+)?/static/js/([A-Za-z0-9_-]+\.js)$")
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
        self.flow_errors = []     # (page, flow, error): flows that broke (walk.py goes on)
        self.loads = 0
        self.doc_status = 0       # HTTP status of the last document the page loaded
        self.chrome_done = False
        self.tree = ""            # the throwaway tree the panel runs in (Session sets it)
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
    # The events the driver reads, and the method each one goes to; every other event is ignored.
    _EVENT_HANDLERS = {"Network.requestWillBeSent": "_request_sent",
                       "Network.loadingFinished": "_request_ended",
                       "Network.loadingFailed": "_request_ended",
                       "Network.responseReceived": "_response_received",
                       "Page.loadEventFired": "_load_fired",
                       "Runtime.exceptionThrown": "_exception_thrown",
                       "Debugger.paused": "_paused"}

    def _on_event(self, msg):
        handler = self._EVENT_HANDLERS.get(msg["method"])
        if handler is not None:
            getattr(self, handler)(msg.get("params", {}))

    def _request_sent(self, p):
        url = p.get("request", {}).get("url", "")
        if "/socket.io/" not in url and not url.startswith("data:"):
            self._inflight[p["requestId"]] = time.monotonic()

    def _request_ended(self, p):
        self._inflight.pop(p.get("requestId"), None)

    def _response_received(self, p):
        if p.get("type") == "Document":
            self.doc_status = int(p.get("response", {}).get("status", 0) or 0)

    def _load_fired(self, _p):
        self.loads += 1

    def _exception_thrown(self, p):
        self._record_exception(p.get("exceptionDetails", {}))

    def _paused(self, _p):
        self._hold_navigation()

    def _hold_navigation(self):
        """Keep a leaving page's counts while it is paused, then let it go on."""
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

    def goto(self, path, settle=True, sign_in=True):
        """Navigate to `path` on the panel, signing in again (once) if the session was lost."""
        self.snapshot()
        before = self.loads
        self.cdp.call("Page.navigate", {"url": self.base + path})
        if not self._wait_load(before):
            log("  ! %s: no load event in 30s" % path)
        if settle:
            self.settle(quiet=0.5, limit=8.0)
        if sign_in and self.path().startswith("/login") and not path.startswith("/login"):
            log("  ! %s: signed out, signing in again" % path)
            self.login()
            return self.goto(path, settle, sign_in=False)
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
            # Not reported here: js(), the only caller, retries its expression straight after, and
            # a reinstall that failed makes that retry fail too, which js() logs ("! js: ...").
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
        if self.path() != want:
            # Once more: the page this walk just left can still be finishing what its last
            # control started (a confirmed form posts after its dialog closes), and that
            # navigation lands after ours.
            self.wait(1.0)
            self.goto(path)
        why = ""
        if self.doc_status >= 400:
            why = "HTTP %d" % self.doc_status
        elif self.path() != want:
            why = "redirected to %s" % self.path()
        if not why:
            why = self._uncounted_scripts()
        if why:
            log("  ! %s: %s; nothing to exercise" % (path, why))
            if record:
                self.unreached.append((path, why))
        return not why

    def _uncounted_scripts(self):
        """Name any panel script this page loads that the coverage would not be counted for.

        A page whose scripts arrive under a URL repo_path() does not know (a new mount, a new
        asset scheme) would be walked in full and measured as nothing, with every other check
        still passing: the walk once went on for twenty pages that way after the setup wizard
        moved the panel under /lgsm.
        """
        srcs = self.js("Array.from(document.scripts).map(s => s.src)"
                       ".filter(u => u.indexOf('/static/js/') >= 0)") or []
        lost = [u for u in srcs if not self.repo_path(u)]
        return ("its scripts would not be counted: %s" % ", ".join(lost[:3])) if lost else ""

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
        # The last step answered a dialog; what its OK starts (a form posting, a reload) has to
        # land here, not on the next page.
        self.settle(quiet=0.5, limit=4.0)
        return len(opts["done"])

    def run(self, script, timeout=90):
        """Run an async in-page step and let it settle.

        `script` is a JS function body; it sees the helpers as `J` and the account's password as
        `PW` (for the dialogs that ask for it).
        """
        res = self.js("(async () => { const J = window.__jscov; const PW = %s; %s })()"
                      % (json.dumps(self.password), script), timeout=timeout)
        self.settle(quiet=0.3, limit=6.0)
        return res

    # ── input the page cannot make itself ─────────────────────────────────────────────────────
    # Real input events, from the browser: a synthetic PointerEvent has no active pointer, so
    # setPointerCapture throws on it, and a synthetic drop carries no files a page can walk.
    def _mouse(self, kind, x, y, buttons=0):
        self.cdp.call("Input.dispatchMouseEvent", {
            "type": kind, "x": x, "y": y, "button": "left", "buttons": buttons,
            "clickCount": 0 if kind == "mouseMoved" else 1, "pointerType": "mouse"})

    def drag(self, selector, dx, dy, index=0, steps=8):
        """Press on the `index`th `selector`, move by (dx, dy) in steps, and release it."""
        at = self.js("__jscov.centre(%s, %d)" % (json.dumps(selector), index))
        if not at:
            return False
        x, y = at
        self._mouse("mouseMoved", x, y)
        self._mouse("mousePressed", x, y, buttons=1)
        for k in range(1, steps + 1):
            self._mouse("mouseMoved", x + dx * k / steps, y + dy * k / steps, buttons=1)
        self._mouse("mouseReleased", x + dx, y + dy)
        self.settle(quiet=0.3, limit=4.0)
        return True

    def keys(self, text):
        """Type `text` as key presses into whatever has focus; a newline presses Enter."""
        for ch in text:
            if ch == "\n":
                down = {"key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13, "text": "\r"}
            else:
                down = {"key": ch, "text": ch}
            self.cdp.call("Input.dispatchKeyEvent", dict(down, type="keyDown"))
            self.cdp.call("Input.dispatchKeyEvent", {"type": "keyUp", "key": down["key"]})
        self.settle(quiet=0.2, limit=2.0)

    def drop_files(self, selector, paths):
        """Drag files and folders from disk onto `selector`, as from a file manager."""
        at = self.js("__jscov.centre(%s, 0)" % json.dumps(selector))
        if not at:
            return False
        data = {"items": [], "files": list(paths), "dragOperationsMask": 1}
        for kind in ("dragEnter", "dragOver", "drop"):
            self.cdp.call("Input.dispatchDragEvent",
                          {"type": kind, "x": at[0], "y": at[1], "data": data})
        self.settle(quiet=0.5, limit=6.0)
        return True

    def second_session(self):
        """Sign in once more from outside the browser, so the account has two sessions.

        The cookie is carried by hand: the panel marks it Secure, which a browser honours on
        loopback over plain HTTP and Python's cookie jar does not.
        """
        with urllib.request.urlopen(self.base + "/login", timeout=10) as r:  # nosec B310 - loopback
            page = r.read().decode("utf-8", "replace")
            cookies = [c.split(";", 1)[0] for c in r.headers.get_all("Set-Cookie") or []]
        m = re.search(r'window\.CSRF = "([^"]+)"', page)
        if not m or not cookies:
            log("  ! second session: no CSRF token or session cookie on /login")
            return False
        body = urllib.parse.urlencode({"username": self.user, "password": self.password,
                                       "csrf_token": m.group(1)}).encode()
        req = urllib.request.Request(self.base + "/login", data=body, headers={
            "Cookie": "; ".join(cookies), "User-Agent": "js-coverage second session"})
        with urllib.request.urlopen(req, timeout=10) as r:  # nosec B310 - loopback only
            return r.status == 200

    def world(self, **state):
        """Change what the fake hosts answer from now on (fake_host.world), e.g. tailscale="off"."""
        path = os.path.join(self.tree, "jscov-world.json")
        try:
            with open(path, encoding="utf-8") as fh:
                now = json.load(fh)
        except (OSError, ValueError):
            now = {}
        now.update(state)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(now, fh)
