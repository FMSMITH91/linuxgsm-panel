#!/usr/bin/env python3
"""Measure how much of the panel's own JavaScript (static/js/*.js) a real browser runs.

    python tools/js_coverage/run.py --out lcov.info [--summary js-coverage.txt] [--chrome PATH]

Boots a seeded panel (serve.py) in a throwaway copy of this tree, drives headless Chrome through
its pages and their controls over the DevTools protocol, and records V8's precise block coverage
of every /static/js/*.js the pages load. Writes LCOV with repository paths (static/js/<file>.js),
which is what Codacy is sent beside the Python report, and a per-file summary.

EXITS NON-ZERO, rather than writing an empty report, when the panel did not boot, the sign-in did
not land, Chrome could not be driven, a page the walk names did not render as itself, or no file
ran a single line — a report of nothing would read as "0% covered" and look like a measurement.

Every static/js file is in the report, loaded or not: a file no page loaded is compiled (never run)
at the end so its lines are counted, all of them missed. Leaving it out would hide it from the
total, which is the one number this exists to make honest.

Needs only what the panel already installs (websocket-client, in requirements.txt) and a Chrome or
Chromium: --chrome, $CHROME, or the first of google-chrome / chromium on PATH. Nothing is
downloaded. The browser gets a throwaway profile, and downloads are refused.
"""
import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess  # nosec B404 - starts the panel and the browser, both fixed argv lists
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import v8_lcov  # noqa: E402
from cdp import CDP, CDPError  # noqa: E402
from driver import Driver, LoginFailed  # noqa: E402
from walk import walk  # noqa: E402

MARKER = ".js-coverage-throwaway"
# Never copied into the throwaway tree: the real data dir (root only: lgsm/data is code), VCS and
# environments, and other agents' worktrees.
_SKIP_ANYWHERE = {".git", ".venv", "venv", "node_modules", ".claude", "__pycache__"}
_SKIP_AT_ROOT = {"data"}
IN_CI = os.environ.get("GITHUB_ACTIONS") == "true"
CHROME_NAMES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")

# Exit codes: 2 the run could not measure (no browser, no panel, no sign-in, a page not reached);
# 3 it measured and nothing ran.
EXIT_SETUP, EXIT_EMPTY = 2, 3


class Abort(Exception):
    """The run cannot produce a measurement; `code` is the exit status to leave with."""

    def __init__(self, msg, code=EXIT_SETUP):
        """Carry the message and the exit status."""
        super().__init__(msg)
        self.code = code


def log(msg):
    """Print one line of progress, unbuffered."""
    print(msg, flush=True)


def fail(msg, code=EXIT_SETUP):
    """Report `msg` as an error (an annotation in CI) and exit with `code`."""
    log(("::error::%s" % msg) if IN_CI else ("ERROR: %s" % msg))
    sys.exit(code)


def js_files(root=ROOT):
    """Return the names of the panel's own scripts: static/js/*.js, not the vendored ones."""
    d = os.path.join(root, "static", "js")
    return sorted(f for f in os.listdir(d) if f.endswith(".js"))


def _keep_dir(rel, name):
    return name not in _SKIP_ANYWHERE and not (rel == "." and name in _SKIP_AT_ROOT)


def copy_tree(dst):
    """Copy this checkout into `dst`, minus data/, VCS and environments, and mark it throwaway."""
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel = os.path.relpath(dirpath, ROOT)
        dirnames[:] = [d for d in dirnames if _keep_dir(rel, d)]
        out = os.path.join(dst, rel)
        os.makedirs(out, exist_ok=True)
        for f in filenames:
            src = os.path.join(dirpath, f)
            if not os.path.islink(src):
                shutil.copy2(src, os.path.join(out, f))
    with open(os.path.join(dst, MARKER), "w", encoding="utf-8"):
        pass


def free_port():
    """Return a loopback port nothing is listening on."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_ok(url, timeout=2):
    """Say whether `url` (on loopback) answers 200."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # nosec B310 - loopback only
            return r.status == 200
    except OSError:
        return False


def find_chrome(explicit):
    """Return the browser to drive: `explicit`, $CHROME, or the first Chrome/Chromium on PATH."""
    for c in (explicit, os.environ.get("CHROME")) + CHROME_NAMES:
        if c and os.path.isfile(c):
            return c
        if c and shutil.which(c):
            return shutil.which(c)
    return None


def _chrome_args(binary, profile):
    return [binary, "--headless=new", "--remote-debugging-port=0", "--user-data-dir=" + profile,
            "--no-first-run", "--no-default-browser-check", "--disable-extensions",
            "--disable-background-networking", "--disable-sync", "--disable-component-update",
            "--disable-default-apps", "--mute-audio", "--no-sandbox", "--disable-gpu",
            # One renderer for the whole run: a navigation that swapped processes would take the
            # coverage counters of the page it left with it.
            "--disable-features=BackForwardCache,Translate,MediaRouter",
            "--window-size=1280,900", "about:blank"]


def _devtools_port(proc, port_file, deadline):
    while time.monotonic() < deadline and proc.poll() is None:
        try:
            with open(port_file, encoding="utf-8") as fh:
                return int(fh.readline().strip())
        except (OSError, ValueError):
            time.sleep(0.2)
    return None


def start_chrome(binary, profile, tmp):
    """Start the browser headless on a throwaway profile; return (process, DevTools port)."""
    # Its own TMPDIR, inside the run's directory: Chrome leaves its singleton socket there, and
    # the whole directory is removed at the end.
    proc = subprocess.Popen(_chrome_args(binary, profile),  # nosec B603 - fixed argv, no shell
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            env=dict(os.environ, TMPDIR=tmp))
    port = _devtools_port(proc, os.path.join(profile, "DevToolsActivePort"),
                          time.monotonic() + 30)
    if port is not None:
        return proc, port
    err = proc.stderr.read().decode(errors="replace")[-600:] if proc.poll() is not None else ""
    proc.kill()
    raise Abort("Chrome (%s) did not open its DevTools port. %s" % (binary, err))


def devtools_json(port, path):
    """GET one of the browser's DevTools JSON endpoints."""
    url = "http://127.0.0.1:%d%s" % (port, path)
    with urllib.request.urlopen(url, timeout=5) as r:  # nosec B310 - loopback only
        return json.load(r)


# ── the panel ──────────────────────────────────────────────────────────────────────────────────
def start_panel(tree, work, user, password):
    """Boot serve.py in `tree` on a free port; return (process, base URL) once it answers."""
    port = free_port()
    env = dict(os.environ, JS_COVERAGE_USER=user, JS_COVERAGE_PASSWORD=password,
               PYTHONUNBUFFERED="1")
    panel_log = os.path.join(work, "panel.log")
    with open(panel_log, "w", encoding="utf-8") as lf:
        panel = subprocess.Popen(  # nosec B603 - fixed argv: this interpreter, two repo files
            [sys.executable, os.path.join(tree, "tools", "nosudo_runner.py"),
             os.path.join(tree, "tools", "js_coverage", "serve.py"), str(port)],
            cwd=tree, env=env, stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
    base = "http://127.0.0.1:%d" % port
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and panel.poll() is None and not http_ok(base + "/healthz"):
        time.sleep(0.5)
    if not http_ok(base + "/healthz"):
        with open(panel_log, encoding="utf-8", errors="replace") as fh:
            log(fh.read()[-3000:])
        stop(panel, group=True)
        raise Abort("the panel did not boot (no /healthz on %s)" % base)
    return panel, base


def stop(proc, group=False):
    """End `proc` (its whole session when `group`), killing it if it does not go in 10s."""
    if proc is None or proc.poll() is not None:
        return
    try:
        if group:
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(10)
    except (OSError, subprocess.TimeoutExpired):
        proc.kill()


class Session:
    """A throwaway tree, a seeded panel in it, and a browser signed in to it — torn down on exit.

    `with Session(chrome) as d:` gives the signed-in Driver. run.py measures with it; it is also
    what a developer uses to look at a page while working on the walk.
    """

    def __init__(self, chrome, keep=False):
        """Prepare a session for the browser at `chrome`; `keep` leaves the tree for reading."""
        self.chrome, self.keep = chrome, keep
        self.work = tempfile.mkdtemp(prefix="jscov-")
        self.tree = os.path.join(self.work, "tree")
        self.panel = self.browser = self.browser_cdp = None

    def __enter__(self):
        """Copy the tree, boot the panel, start the browser and sign in; return the Driver."""
        try:
            return self._open()
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _open(self):
        copy_tree(self.tree)
        user, password = "jscov", secrets.token_urlsafe(24)
        self.panel, base = start_panel(self.tree, self.work, user, password)
        log("panel up on %s (%s)" % (base, self.tree))
        profile = os.path.join(self.work, "profile")
        os.makedirs(profile)
        self.browser, dport = start_chrome(self.chrome, profile, self.work)
        version = devtools_json(dport, "/json/version")
        log("browser: %s" % version.get("Browser"))
        # Downloads refused, browser-wide: a Download button must not write into anyone's home.
        self.browser_cdp = CDP(version["webSocketDebuggerUrl"])
        self.browser_cdp.call("Browser.setDownloadBehavior", {"behavior": "deny"})
        pages = [t for t in devtools_json(dport, "/json/list") if t.get("type") == "page"]
        if not pages:
            raise Abort("Chrome has no page target to drive")
        d = Driver(CDP(pages[0]["webSocketDebuggerUrl"]), base, user, password, sources())
        d.tree = self.tree
        try:
            d.start()
        except CDPError as e:
            raise Abort("the browser could not be set up to measure: %s" % e) from None
        try:
            d.login()
        except LoginFailed as e:
            raise Abort("%s — every page would be measured as the login form" % e) from None
        return d

    def __exit__(self, *_exc):
        """Close the browser and the panel, and remove the tree unless asked to keep it."""
        if self.browser_cdp is not None:
            self.browser_cdp.close()
        stop(self.browser)
        stop(self.panel, group=True)
        if self.keep:
            log("kept: %s" % self.work)
        else:
            shutil.rmtree(self.work, ignore_errors=True)
        return False


# ── the report ─────────────────────────────────────────────────────────────────────────────────
def sources(root=ROOT):
    """Return {"static/js/x.js": its text} for every file the report covers."""
    out = {}
    for name in js_files(root):
        with open(os.path.join(root, "static", "js", name), encoding="utf-8") as fh:
            out["static/js/" + name] = fh.read()
    return out


def measure(d):
    """Take the last counts and return {path: {line: hits}} for every static/js file."""
    d.snapshot()
    return d.hits()


def _pct(hit, lines):
    return 100.0 * hit / lines if lines else 0.0


def summary_text(files, loaded, errors, held=0):
    """The per-file table (lines, hit, cover, largest missed runs), a TOTAL, and page errors."""
    rows, tf, th = [], 0, 0
    for path in sorted(files):
        hits = files[path]
        f, h = len(hits), sum(1 for v in hits.values() if v)
        tf, th = tf + f, th + h
        spans = ", ".join("%d-%d" % (a, b) if a != b else str(a)
                          for a, b, _n in v8_lcov.missed_spans(hits, 3))
        rows.append("%-34s %5d %5d %6.1f%%%s  %s" % (
            path, f, h, _pct(h, f), "" if path in loaded else "  (never loaded)", spans))
    lines = ["%-34s %5s %5s %7s  %s" % ("file", "lines", "hit", "cover", "largest missed runs")]
    lines += rows
    lines.append("%-34s %5d %5d %6.1f%%" % ("TOTAL", tf, th, _pct(th, tf)))
    lines.append("(%d navigations held to keep the leaving page's counts)" % held)
    if errors:
        lines += ["", "Uncaught exceptions the pages threw (%d):" % len(set(errors))]
        for u, ln, t in sorted(set(errors))[:40]:
            where = u.split("/static/", 1)[-1] if "/static/" in u else u
            lines.append("  %s:%s  %s" % (where, ln, t))
    return "\n".join(lines) + "\n", th


def write_reports(files, text, out, summary_path):
    """Write the LCOV to `out` and, when asked, the summary to `summary_path`."""
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(v8_lcov.to_lcov(files))
    if summary_path:
        with open(summary_path, "w", encoding="utf-8") as fh:
            fh.write(text)


def measure_and_report(d, out, summary_path):
    """Write the reports; raise Abort when nothing ran or a page the walk names was not reached."""
    files = measure(d)
    text, hit = summary_text(files, d.loaded, d.errors, d.held)
    write_reports(files, text, out, summary_path)
    log(text)
    if hit == 0:
        raise Abort("no line of static/js ran: the coverage is empty", EXIT_EMPTY)
    if d.unreached:
        raise Abort("the walk did not reach %d page(s) it names — a renamed or removed route? %s"
                    % (len(d.unreached), "; ".join("%s (%s)" % u for u in d.unreached)))
    return files


def parse_args(argv):
    """The command line: where the reports go, which browser, and what to keep or walk."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--out", default="lcov.info")
    ap.add_argument("--summary", default="")
    ap.add_argument("--chrome", default="")
    ap.add_argument("--keep", action="store_true", help="keep the throwaway tree and logs")
    ap.add_argument("--only", default="", help="comma-separated page paths: walk just these "
                                               "(for working on the walk itself)")
    return ap.parse_args(argv)


def main(argv=None):
    """Run the whole measurement; return 0, or exit non-zero with the reason."""
    args = parse_args(argv)
    # A stop from outside (a cancelled job, ^C) still runs the Session's teardown: the panel and
    # the browser would outlive this process otherwise.
    signal.signal(signal.SIGTERM, lambda *_a: sys.exit(143))
    chrome = find_chrome(args.chrome)
    if not chrome:
        fail("no Chrome/Chromium found (--chrome, $CHROME, %s)" % ", ".join(CHROME_NAMES))
    try:
        with Session(chrome, keep=args.keep) as d:
            walk(d, only=[p for p in args.only.split(",") if p] or None)
            measure_and_report(d, args.out, args.summary)
    except Abort as e:
        fail(str(e), e.code)
    return 0


if __name__ == "__main__":
    sys.exit(main())
