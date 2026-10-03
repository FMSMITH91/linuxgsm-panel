#!/usr/bin/env python3
"""Wait until code scanning holds one commit's analysis in every category the alert gates read.

Both alert gates (codeql.yml's pr-alerts and codeql-alerts.yml) read a ref's OPEN ALERTS, and a ref's
alert set is the newest analysis in each category. Five categories feed it, from two workflows that
nothing orders: CodeQL's three languages (codeql.yml) and Bandit and Semgrep (security-code.yml). So
"the ref has an analysis" says nothing about THIS commit: the previous push's Semgrep result stays on
the ref until this push's lands, and a gate that read the alerts in between judged the old one and
passed (PR #385: the gate read refs/pull/385/merge 13 s before that commit's Semgrep analysis
landed). This waits until every category's newest analysis is the commit's own, and fails naming the
categories that never arrived. "No analysis" is never read as "no alerts".

The list endpoint has no commit filter (GitHub's REST description documents only tool_name,
tool_guid, ref, pr, sarif_id, sort, direction and paging), so each row's commit_sha is compared here.
ONE page of the newest 100 is read: it always holds a just-analysed commit's rows, and `gh api
--paginate --jq` would apply a filter to each page separately.

A scheduled run (codeql-alerts.yml judges those too) analyses the branch's head again with the one
workflow that was scheduled. Its own categories must be the commit's; the other workflow's may be an
earlier commit's, as long as that analysis is older than this commit's own (the push that would have
re-run it changed nothing either workflow scans: they share one paths-ignore list).

Usage:
    code_scanning_analyses.py --ref REF --sha SHA [--event EVENT] [--workflow PATH]
                              [--tries N] [--interval SECONDS]

Exit status: 0 every category's newest analysis is SHA's; 1 a category has no analysis of SHA (or
the list could not be read); 3 the ref has moved on, a later commit's analysis is the newest in some
category, so its alerts say nothing about SHA.
"""
import argparse
import json
import os
import subprocess  # nosec B404 - gh with a fixed argv, no shell
import sys
import time

# Every category the alert gates wait for, and the workflow that uploads it. tests/unit (part26)
# holds this to codeql.yml's language matrix and security-code.yml's upload-sarif categories, both
# ways. ClusterFuzzLite's category is NOT here: it uploads only when a pull request touches fuzzed
# code, about ten minutes later, and the required "fuzz the diff" job already fails on a crash.
CATEGORIES = {
    "/language:python": "codeql.yml",
    "/language:javascript-typescript": "codeql.yml",
    "/language:actions": "codeql.yml",
    "bandit": "security-code.yml",
    "semgrep": "security-code.yml",
}

MISSING, MOVED = 1, 3


def own_categories(event, workflow):
    """Return the categories that must be this commit's own analysis.

    All of them, except on a scheduled run: that re-analyses with one workflow only.
    """
    name = os.path.basename(workflow or "")
    if event == "schedule" and name in CATEGORIES.values():
        return {c for c, w in CATEGORIES.items() if w == name}
    return set(CATEGORIES)


def _first_rows(rows, sha):
    """Return (each category's newest row, each category's newest row for `sha`)."""
    newest, mine = {}, {}
    for row in rows:
        cat = row.get("category")
        newest.setdefault(cat, row)
        if row.get("commit_sha") == sha:
            mine.setdefault(cat, row)
    return newest, mine


def assess(rows, sha, own):
    """Return (missing, moved): categories with no analysis of `sha`, and those a later one replaced.

    `rows` is the ref's analyses, newest first. A category is moved when `sha` has an analysis in it
    that is not the newest; or, outside `own`, when its newest analysis is someone else's and was
    made after `sha`'s own (a later commit's). It is missing when `sha` has none and that cannot be
    decided yet.
    """
    newest, mine = _first_rows(rows, sha)
    floor = min((mine[c].get("created_at") or "" for c in own if c in mine), default="")
    states = {cat: _state(newest.get(cat), cat in mine, cat in own, sha, floor) for cat in CATEGORIES}
    return ([c for c in CATEGORIES if states[c] == "missing"],
            [c for c in CATEGORIES if states[c] == "moved"])


def _state(top, has_own_row, must_be_own, sha, floor):
    """Return "ok", "missing" or "moved" for one category; `top` is its newest row (or None)."""
    if has_own_row:
        return "ok" if top.get("commit_sha") == sha else "moved"
    if must_be_own or top is None or not floor:
        return "missing"
    return "moved" if (top.get("created_at") or "") > floor else "ok"


def read_rows(repo, ref):
    """Return the newest 100 analyses of `ref`, newest first, or None when they could not be read."""
    path = ("repos/%s/code-scanning/analyses?ref=%s&per_page=100&sort=created&direction=desc"
            % (repo, ref))
    try:
        res = subprocess.run(["gh", "api", path], capture_output=True, text=True,  # nosec B603 B607
                             timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        print("could not run gh: %s" % e)
        return None
    if res.returncode != 0:
        print("gh api failed (%d): %s" % (res.returncode, res.stderr.strip()[:300]))
        return None
    try:
        rows = json.loads(res.stdout)
    except ValueError:
        print("gh api answered something that is not JSON: %r" % res.stdout[:200])
        return None
    return rows if isinstance(rows, list) else None


def describe(rows, sha, missing, moved):
    """Return one line per category: whose analysis is the newest, and what that means for `sha`."""
    newest, _ = _first_rows(rows or [], sha)
    out = []
    for cat in CATEGORIES:
        top = newest.get(cat) or {}
        state = "MISSING" if cat in missing else "MOVED ON" if cat in moved else "ok"
        out.append("  %-34s %-8s newest: %s %s" % (cat, state, (top.get("commit_sha") or "none")[:10],
                                                   top.get("created_at") or ""))
    return out


def wait(repo, ref, sha, own, tries, interval):
    """Poll until no category is missing; return (exit status, last rows read, missing, moved).

    A moved-on category ends the wait at once: the ref's alerts are already a later commit's.
    """
    rows, missing, moved = None, list(CATEGORIES), []
    for attempt in range(max(1, tries)):
        if attempt:
            time.sleep(interval)
        rows = read_rows(repo, ref)
        if rows is None:
            continue
        missing, moved = assess(rows, sha, own)
        if moved:
            return MOVED, rows, missing, moved
        if not missing:
            return 0, rows, missing, moved
    return MISSING, rows, missing, moved


def main(argv=None):
    """Wait, print what each category holds, and exit 0, 1 (missing) or 3 (moved on)."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--ref", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--event", default="")
    ap.add_argument("--workflow", default="")
    ap.add_argument("--tries", type=int, default=30)
    ap.add_argument("--interval", type=float, default=10.0)
    a = ap.parse_args(argv)
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not repo or len(a.sha) != 40:
        print("::error::need GITHUB_REPOSITORY and a full commit sha (got %r)" % a.sha)
        return MISSING
    own = own_categories(a.event, a.workflow)
    rc, rows, missing, moved = wait(repo, a.ref, a.sha, own, a.tries, a.interval)
    print("Code-scanning analyses on %s, for %s:" % (a.ref, a.sha[:10]))
    print("\n".join(describe(rows, a.sha, missing, moved)))
    if rows is None:
        print("::error::could not read the code-scanning analyses of %s, so nothing was judged." % a.ref)
    elif rc == MISSING:
        print("::error::no analysis of %s on %s for: %s. Refusing to read its alerts as clean."
              % (a.sha, a.ref, ", ".join(missing)))
    elif rc == MOVED:
        print("::warning::%s has moved on: a later commit's analysis is the newest for %s, so its "
              "alerts say nothing about %s." % (a.ref, ", ".join(moved), a.sha))
    return rc


if __name__ == "__main__":
    sys.exit(main())
