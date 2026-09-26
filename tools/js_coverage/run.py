#!/usr/bin/env python3
"""Measure how much of the panel's own JavaScript (static/js/*.js) a real browser runs.

    python tools/js_coverage/run.py --out lcov.info [--summary js-coverage.txt] [--chrome PATH]

Boots a seeded panel (serve.py) in a throwaway copy of this tree, drives headless Chrome through
its pages and their controls over the DevTools protocol, and records V8's precise block coverage
of every /static/js/*.js the pages load. Writes LCOV with repository paths (static/js/<file>.js),
which is what Codacy is sent beside the Python report, and a per-file summary.

EXITS NON-ZERO, rather than writing an empty report, when the panel did not boot, the sign-in did
not land, Chrome could not be driven, or no file ran a single line — a report of nothing would
read as "0% covered" and look like a measurement.

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


def log(msg):
    print(msg, flush=True)


def fail(msg, code=2):
    log(("::error::%s" % msg) if IN_CI else ("ERROR: %s" % msg))
    sys.exit(code)


def js_files(root=ROOT):
    d = os.path.join(root, "static", "js")
    return sorted(f for f in os.listdir(d) if f.endswith(".js"))


def copy_tree(dst):
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel = os.path.relpath(dirpath, ROOT)
        dirnames[:] = [d for d in dirnames if d not in _SKIP_ANYWHERE
                       and not (rel == "." and d in _SKIP_AT_ROOT)]
        out = os.path.join(dst, rel)
        os.makedirs(out, exist_ok=True)
        for f in filenames:
            src = os.path.join(dirpath, f)
            if os.path.islink(src):
                continue
            shutil.copy2(src, os.path.join(out, f))
    open(os.path.join(dst, MARKER), "w").close()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_ok(url, timeout=2):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # nosec B310 - loopback only
            return r.status == 200
    except OSError:
        return False


def find_chrome(explicit):
    for c in (explicit, os.environ.get("CHROME"), "google-chrome", "google-chrome-stable",
              "chromium", "chromium-browser"):
        if c and (os.path.isfile(c) or shutil.which(c)):
            return c if os.path.isfile(c) else shutil.which(c)
    return None


def start_chrome(binary, profile, tmp):
    args = [binary, "--headless=new", "--remote-debugging-port=0", "--user-data-dir=" + profile,
            "--no-first-run", "--no-default-browser-check", "--disable-extensions",
            "--disable-background-networking", "--disable-sync", "--disable-component-update",
            "--disable-default-apps", "--mute-audio", "--no-sandbox", "--disable-gpu",
            # One renderer for the whole run: a navigation that swapped processes would take the
            # coverage counters of the page it left with it.
            "--disable-features=BackForwardCache,Translate,MediaRouter",
            "--window-size=1280,900", "about:blank"]
    # Its own TMPDIR, inside the run's directory: Chrome leaves its singleton socket there, and
    # the whole directory is removed at the end.
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,  # nosec B603
                            env=dict(os.environ, TMPDIR=tmp))
    port_file = os.path.join(profile, "DevToolsActivePort")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            with open(port_file) as fh:
                port = int(fh.readline().strip())
            return proc, port
        except (OSError, ValueError):
            time.sleep(0.2)
    err = proc.stderr.read().decode(errors="replace")[-600:] if proc.poll() is not None else ""
    proc.kill()
    fail("Chrome (%s) did not open its DevTools port. %s" % (binary, err))


def devtools_json(port, path):
    with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=5) as r:  # nosec B310
        return json.load(r)


def report(d, out, summary_path):
    """Locations for every static/js file, from V8 itself, then LCOV and the summary."""
    d.snapshot()
    d.cdp.call("Page.navigate", {"url": "about:blank"})
    d.cdp.pump(0.5)
    files = {}
    for name in js_files():
        path = "static/js/" + name
        with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
            source = fh.read()
        try:
            comp = d.cdp.call("Runtime.compileScript", {"expression": source, "persistScript": True,
                                                        "sourceURL": "jscov:" + name})
        except CDPError as e:
            fail("%s could not be compiled to count its lines: %s" % (path, e))
        if comp.get("exceptionDetails") or not comp.get("scriptId"):
            fail("%s does not compile in this browser: %s" % (path, comp.get("exceptionDetails")))
        locs = d.cdp.call("Debugger.getPossibleBreakpoints",
                          {"start": {"scriptId": comp["scriptId"], "lineNumber": 0, "columnNumber": 0}},
                          timeout=60).get("locations", [])
        files[path] = v8_lcov.line_hits([(x["lineNumber"], x.get("columnNumber", 0)) for x in locs],
                                        source, d.takes.get(path, []))
    lcov = v8_lcov.to_lcov(files)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(lcov)
    rows, tf, th = [], 0, 0
    for path in sorted(files):
        hits = files[path]
        f, h = len(hits), sum(1 for v in hits.values() if v)
        tf, th = tf + f, th + h
        spans = ", ".join("%d-%d" % (a, b) if a != b else str(a)
                          for a, b, _n in v8_lcov.missed_spans(hits, 3))
        rows.append("%-34s %5d %5d %6.1f%%%s  %s" % (
            path, f, h, 100.0 * h / f if f else 0.0,
            "" if path in d.takes else "  (never loaded)", spans))
    lines = ["%-34s %5s %5s %7s  %s" % ("file", "lines", "hit", "cover", "largest missed runs")]
    lines += rows
    lines.append("%-34s %5d %5d %6.1f%%" % ("TOTAL", tf, th, 100.0 * th / tf if tf else 0.0))
    if d.errors:
        lines.append("")
        lines.append("Uncaught exceptions the pages threw (%d):" % len(d.errors))
        for u, ln, t in sorted(set(d.errors))[:40]:
            lines.append("  %s:%s  %s" % (u.split("/static/", 1)[-1] if "/static/" in u else u, ln, t))
    text = "\n".join(lines) + "\n"
    if summary_path:
        with open(summary_path, "w", encoding="utf-8") as fh:
            fh.write(text)
    log(text)
    if th == 0:
        fail("no line of static/js ran: the coverage is empty", code=3)
    return files


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default="lcov.info")
    ap.add_argument("--summary", default="")
    ap.add_argument("--chrome", default="")
    ap.add_argument("--keep", action="store_true", help="keep the throwaway tree and logs")
    ap.add_argument("--only", default="", help="comma-separated page paths: walk just these "
                                               "(for working on the walk itself)")
    args = ap.parse_args(argv)
    # A stop from outside (a cancelled job, ^C) still runs the finally below: the panel and the
    # browser are in their own sessions and would outlive this process otherwise.
    signal.signal(signal.SIGTERM, lambda *_a: sys.exit(143))

    chrome = find_chrome(args.chrome)
    if not chrome:
        fail("no Chrome/Chromium found (--chrome, $CHROME, google-chrome, chromium)")
    work = tempfile.mkdtemp(prefix="jscov-")
    tree, profile = os.path.join(work, "tree"), os.path.join(work, "profile")
    os.makedirs(profile)
    panel = browser = None
    try:
        copy_tree(tree)
        port = free_port()
        user, password = "jscov", secrets.token_urlsafe(24)
        env = dict(os.environ, JS_COVERAGE_USER=user, JS_COVERAGE_PASSWORD=password,
                   PYTHONUNBUFFERED="1")
        panel_log = os.path.join(work, "panel.log")
        with open(panel_log, "w") as lf:
            panel = subprocess.Popen(  # nosec B603 - fixed argv: this interpreter, two repo files
                [sys.executable, os.path.join(tree, "tools", "nosudo_runner.py"),
                 os.path.join(tree, "tools", "js_coverage", "serve.py"), str(port)],
                cwd=tree, env=env, stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
        base = "http://127.0.0.1:%d" % port
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and panel.poll() is None and not http_ok(base + "/healthz"):
            time.sleep(0.5)
        if not http_ok(base + "/healthz"):
            with open(panel_log, errors="replace") as fh:
                tail = fh.read()[-3000:]
            log(tail)
            fail("the panel did not boot (no /healthz on %s)" % base)
        log("panel up on %s (%s)" % (base, tree))

        browser, dport = start_chrome(chrome, profile, work)
        version = devtools_json(dport, "/json/version")
        log("browser: %s" % version.get("Browser"))
        # Downloads refused, browser-wide: a Download button must not write into anyone's home.
        bc = CDP(version["webSocketDebuggerUrl"])
        bc.call("Browser.setDownloadBehavior", {"behavior": "deny"})
        pages = [t for t in devtools_json(dport, "/json/list") if t.get("type") == "page"]
        if not pages:
            fail("Chrome has no page target to drive")
        d = Driver(CDP(pages[0]["webSocketDebuggerUrl"]), base, user, password)
        d.start()
        try:
            d.login()
        except LoginFailed as e:
            fail("%s — every page would be measured as the login form" % e)
        walk(d, only=[p for p in args.only.split(",") if p] or None)
        report(d, args.out, args.summary)
        bc.close()
        return 0
    finally:
        for p in (browser, panel):
            if p is not None and p.poll() is None:
                try:
                    if p is panel:
                        os.killpg(p.pid, 15)
                    else:
                        p.terminate()
                    p.wait(10)
                except (OSError, subprocess.TimeoutExpired):
                    p.kill()
        if args.keep:
            log("kept: %s" % work)
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
