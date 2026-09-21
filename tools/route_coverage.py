#!/usr/bin/env python3
"""Which route bodies does no suite execute?

    ./.venv/bin/python tools/route_coverage.py

Runs every suite under coverage in a THROWAWAY tree and prints the routes whose view function was
never entered — not "weakly tested", not entered at all. A route's first executable statement
(decorators and docstring skipped) is the line it looks for.

Three reasons it works the way it does:

* **A throwaway tree, like tools/smoke-local.sh.** The suites refuse to run against a real install,
  and DATA_DIR is a fixed path derived from the package's own location with no env override — so
  the only safe way to run them is somewhere that is not the repo.

* **data/ is cleared before EVERY suite.** Three suites bail out with "SKIP: ... already exists"
  and **exit 0** when they find a database. Sharing one tree across suites therefore let the first
  suite's DB disable four of the others, and the run reported a SMALLER untested set than the
  truth — a measurement that flatters. So this clears data/ each time and refuses to report at all
  if any suite prints SKIP or produces no tally.

* **What the number is not.** tests/url_map_baseline.json already pins every route's guard chain,
  so a decorator cannot silently disappear. An entry here is *behaviour untested*, not
  *authorization unverified*. Read the body before calling anything a finding.
"""
import ast
import inspect
import json
import os
import shutil
import subprocess  # nosec B404 - runs this repo's own suites in a temp dir, argv lists, no shell
import sys
import tempfile

SUITES = ("unit", "smoke", "rbac", "url_map", "template_actions",
          "input_validation", "manage", "setup_wizard", "perf_budget")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(REPO, ".venv", "bin", "python")


def _copy_worktree(dest):
    """The working tree as git sees it — tracked plus not-yet-committed, .gitignore respected.
    Exactly what smoke-local.sh copies, so a suite you just wrote is included."""
    listing = subprocess.run(  # nosec B603 B607 - git, on PATH, fixed argv, no shell
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO, capture_output=True, check=True)
    names = [n for n in listing.stdout.split(b"\0") if n]
    tar = subprocess.Popen(["tar", "--null", "-T", "-", "-cf", "-"],  # nosec B603 B607
                           cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    untar = subprocess.Popen(["tar", "-xf", "-", "-C", dest],  # nosec B603 B607
                             stdin=tar.stdout)
    tar.stdout.close()
    tar.stdin.write(b"\0".join(names) + b"\0")
    tar.stdin.close()
    untar.wait()
    tar.wait()


def _run_suites(work):
    """Run each suite under coverage. Returns a list of (suite, ok, note)."""
    results = []
    for suite in SUITES:
        shutil.rmtree(os.path.join(work, "data"), ignore_errors=True)
        proc = subprocess.run(  # nosec B603  # nosemgrep - argv list, no shell; PY is this
            # repo's own venv interpreter and the suite name comes from the fixed SUITES tuple.
            [PY, "-m", "coverage", "run", "--parallel-mode", "--source=.",
             "--omit=./tests/*,./tools/*,./.venv/*",
             "tools/nosudo_runner.py", "tests/%s_test.py" % suite],
            cwd=work, capture_output=True, text=True)
        out = proc.stdout + proc.stderr
        tally = ""
        for line in out.splitlines():
            if "checks passed" in line or "rules checked" in line:
                tally = line.strip()
        skipped = any(ln.startswith("SKIP:") for ln in out.splitlines())
        ok = proc.returncode == 0 and not skipped and bool(tally)
        note = tally if ok else ("SKIPPED" if skipped else
                                 "rc=%d, no tally" % proc.returncode)
        results.append((suite, ok, note))
        print("  %-18s %s" % (suite, note))
    return results


def _first_body_line(fn):
    """The first executable line of fn, past its decorators and docstring."""
    try:
        src, start = inspect.getsourcelines(fn)
    except (OSError, TypeError):
        return None
    indent = len(src[0]) - len(src[0].lstrip())
    text = "".join(line[indent:] if len(line) > indent else line for line in src)
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) \
               and isinstance(body[0].value, ast.Constant) \
               and isinstance(body[0].value.value, str):
                body = body[1:]
            return start + body[0].lineno - 1 if body else None
    return None


def _executed(cov_files, relpath):
    for key in (relpath, "./" + relpath):
        if key in cov_files:
            return set(cov_files[key].get("executed_lines", []))
    for key, data in cov_files.items():
        if key.replace("./", "").endswith(relpath):
            return set(data.get("executed_lines", []))
    return None


def _report(work, cov_path):
    """Import the app INSIDE the throwaway tree — create_app() creates data/ wherever it runs."""
    sys.path.insert(0, work)
    os.chdir(work)
    shutil.rmtree(os.path.join(work, "data"), ignore_errors=True)
    with open(cov_path, encoding="utf-8") as fh:
        cov_files = json.load(fh).get("files", {})
    from app import create_app                                       # noqa: E402
    app = create_app()
    cold, total = [], 0
    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        view = app.view_functions.get(rule.endpoint)
        if view is None:
            continue
        fn = inspect.unwrap(view)          # past login_required / permission_required (@wraps)
        try:
            path = os.path.relpath(inspect.getsourcefile(fn), work)
        except (TypeError, ValueError):
            continue
        line = _first_body_line(fn)
        ran = _executed(cov_files, path)
        if line is None or ran is None:
            continue
        total += 1
        if line not in ran:
            methods = ",".join(sorted(rule.methods - {"HEAD", "OPTIONS"}))
            cold.append((methods, str(rule), "%s:%d" % (path, line)))
    print("\nroutes analysed    : %d" % total)
    print("entered by a suite : %d" % (total - len(cold)))
    print("entered by NOTHING : %d\n" % len(cold))
    for methods, rule, where in sorted(cold, key=lambda r: (r[0] != "GET", r[1])):
        print("  %-7s %-52s %s" % (methods, rule, where))
    return len(cold)


def main():
    if not os.path.exists(PY):
        print("no interpreter at %s" % PY, file=sys.stderr)
        return 2
    work = tempfile.mkdtemp(prefix="lgsm-routecov-")
    print("work tree: %s" % work)
    try:
        _copy_worktree(work)
        results = _run_suites(work)
        bad = [s for s, ok, _ in results if not ok]
        if bad:
            # Loud, not a footnote: a skipped suite makes the answer look BETTER than it is.
            print("\nrefusing to report — these suites did not run: %s" % ", ".join(bad),
                  file=sys.stderr)
            return 1
        subprocess.run([PY, "-m", "coverage", "combine"],  # nosec B603  # nosemgrep - argv list
                       cwd=work, capture_output=True)
        cov_path = os.path.join(work, "route-cov.json")
        subprocess.run([PY, "-m", "coverage", "json", "-o", cov_path],  # nosec B603 # nosemgrep
                       cwd=work, capture_output=True)
        if not os.path.exists(cov_path):
            print("coverage produced no JSON", file=sys.stderr)
            return 1
        _report(work, cov_path)
        return 0
    finally:
        # _report() chdir'd INTO the tree it is about to delete; step out first so the cleanup is
        # not removing the working directory out from under itself.
        os.chdir(REPO)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
