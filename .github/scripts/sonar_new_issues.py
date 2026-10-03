#!/usr/bin/env python3
"""Fail a pull request that adds any SonarCloud issue, as Codacy's check already does for its own.

SonarCloud's check is its quality gate, and on the free plan that is "Sonar way", which cannot be
replaced: it fails on a new bug, vulnerability or unreviewed hotspot, but lets code smells through
while the new code still rates A for maintainability. Those then sat on main as open issues. This
waits for SonarCloud's analysis of the pull request's head commit and fails if it found anything new,
naming each issue. SonarCloud's API answers anonymously for this public project.

--branch mode judges a long-lived branch (main) instead, for .github/workflows/sonar-main-issues.yml.
A pull request's analysis reports new issues on new code only: "the first analysis of the target
branch after the merge can report new issues on old code that the pull request analysis did not
report" (https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/pull-request-analysis/),
and such an issue is backdated into overall code, which main's "Sonar way" gate does not judge. So
a change that makes an UNCHANGED line wrong, or a rule SonarCloud rolls out, lands on main with every
check green. This waits for SonarCloud's analysis of the commit, reads every open issue on the
branch, and fails on any that is not in KNOWN_OPEN. It also fails when a KNOWN_OPEN issue is
missing: the positive control that the read returned the branch's issues at all.

Usage:
    sonar_new_issues.py --pr NUMBER --sha HEAD_SHA [--timeout SECONDS]
    sonar_new_issues.py --branch main [--sha COMMIT] [--timeout SECONDS]
    sonar_new_issues.py --self-test
"""
import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request

PROJECT = "FMSMITH91_linuxgsm-panel"
API = "https://sonarcloud.io/api/"
# The open issues main is known to carry, by issue key, each with why it stays. Removing one when it
# is fixed or Accepted is part of that change: the --branch check fails while one is missing.
KNOWN_OPEN = {
    "AaDejKLMfWz637hiAQny": "docker:S6471 in .clusterfuzzlite/Dockerfile: the fuzz image runs as "
                            "root, which is ClusterFuzzLite's build contract. A Dockerfile has no "
                            "NOSONAR, and the owner declined to Accept it in SonarCloud (2026-09-29).",
}


def _get(path, **params):
    url = API + path + "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=30) as resp:  # nosec B310 - a fixed https host
        return json.load(resp)


def analysis_of(pr_list, pr, sha):
    """The pull request's entry in project_pull_requests/list when it is the analysis of `sha`."""
    for entry in pr_list.get("pullRequests", []):
        if str(entry.get("key")) == str(pr) and (entry.get("commit") or {}).get("sha") == sha:
            return entry
    return None


def verdict(entry, issues):
    """Return the problems with an analysed pull request: every new issue, as a line each.

    The counts in the entry are the pull request's own (bugs, vulnerabilities, code smells); the
    issue list names them. A count with no issue listed still fails, so a paging gap cannot pass.
    """
    status = (entry or {}).get("status") or {}
    counted = sum(int(status.get(k) or 0) for k in ("bugs", "vulnerabilities", "codeSmells"))
    lines = ["%s:%s %s %s: %s" % ((i.get("component") or "").split(":", 1)[-1], i.get("line", "?"),
                                  i.get("severity", "?"), i.get("rule", "?"), i.get("message", ""))
             for i in issues]
    if counted and not lines:
        lines = ["SonarCloud counts %d new issue(s) on this pull request" % counted]
    if status.get("qualityGateStatus") not in (None, "OK"):
        lines.append("SonarCloud's quality gate is %s" % status.get("qualityGateStatus"))
    return lines


def run(pr, sha, timeout):
    """Wait for SonarCloud's analysis of `sha`, then return (problems, waited seconds)."""
    start, entry = time.time(), None
    while entry is None:
        try:
            entry = analysis_of(_get("project_pull_requests/list", project=PROJECT), pr, sha)
        except OSError as e:
            print("SonarCloud did not answer (%s); retrying" % e)
        if entry is None:
            if time.time() - start > timeout:
                return (["SonarCloud had not analysed %s after %ds" % (sha[:12], timeout)],
                        int(time.time() - start))
            time.sleep(20)
    issues = _get("issues/search", componentKeys=PROJECT, pullRequest=pr, resolved="false",
                  ps=100).get("issues", [])
    return verdict(entry, issues), int(time.time() - start)


def branch_entry(branch_list, branch):
    """The branch's entry in project_branches/list, or None."""
    return next((b for b in branch_list.get("branches", []) if b.get("name") == branch), None)


def analysed(analyses, sha):
    """Whether project_analyses/search lists an analysis of `sha` (newer ones may follow it)."""
    return any(a.get("revision") == sha for a in analyses.get("analyses", []))


def _issue_line(i):
    return "%s:%s %s %s: %s [%s]" % ((i.get("component") or "").split(":", 1)[-1], i.get("line", "?"),
                                     i.get("severity", "?"), i.get("rule", "?"), i.get("message", ""),
                                     i.get("key", "?"))


def branch_verdict(entry, issues, total, known):
    """Return the problems with a branch's open issues: one line each, empty when it is as known.

    Every open issue whose key is not in `known` fails, named. Every key in `known` that is not
    open fails too: either the read returned none of the branch's issues, or that one was fixed or
    Accepted and KNOWN_OPEN still lists it. So does a list shorter than SonarCloud's own counts.
    """
    lines = [_issue_line(i) for i in issues if i.get("key") not in known]
    lines += _missing_known(issues, known)
    status = (entry or {}).get("status") or {}
    counted = sum(int(status.get(k) or 0) for k in ("bugs", "vulnerabilities", "codeSmells"))
    if max(total, counted) > len(issues):
        lines.append("SonarCloud counts %d open issue(s) on the branch but returned %d"
                     % (max(total, counted), len(issues)))
    return lines


def _missing_known(issues, known):
    """One line for each issue in `known` that `issues` does not hold (the positive control)."""
    keys = {i.get("key") for i in issues}
    return ["the known open issue %s is not in SonarCloud's list (%s). If it was fixed or "
            "Accepted, remove it from KNOWN_OPEN in .github/scripts/sonar_new_issues.py; if not, "
            "the read returned less than the branch holds" % (k, why)
            for k, why in sorted(known.items()) if k not in keys]


def _open_issues(branch):
    """Every open issue on `branch` and SonarCloud's total, paging until the total is read.

    Kept once per key: a list that shifted between pages must not make up the count with repeats.
    """
    issues, total = {}, 0
    for page in range(1, 21):                 # bounded: 20 pages of 500 is far past plausible
        got = _get("issues/search", componentKeys=PROJECT, branch=branch, resolved="false",
                   ps=500, p=page)
        total = int((got.get("paging") or {}).get("total", got.get("total", 0)) or 0)
        for i in got.get("issues", []):
            issues.setdefault(i.get("key"), i)
        if not got.get("issues") or len(issues) >= total:
            break
    return list(issues.values()), total


def _wait_for_branch(branch, sha, timeout):
    """Wait until SonarCloud has analysed `sha` on `branch`: (entry, None) or (None, why)."""
    start = time.time()
    while True:
        try:
            entry = branch_entry(_get("project_branches/list", project=PROJECT), branch)
            if entry and (sha is None or analysed(
                    _get("project_analyses/search", project=PROJECT, branch=branch, ps=50), sha)):
                return entry, None
        except OSError as e:
            print("SonarCloud did not answer (%s); retrying" % e)
        if time.time() - start > timeout:
            return None, "SonarCloud had not analysed %s on %s after %ds" % (
                (sha or "any commit")[:12], branch, timeout)
        time.sleep(20)


def run_branch(branch, sha, timeout, known=None):
    """Wait for SonarCloud's analysis of `sha` on `branch`, then return (problems, judged sha)."""
    entry, why = _wait_for_branch(branch, sha, timeout)
    if why:
        return [why], ""
    judged = (entry.get("commit") or {}).get("sha") or "?"
    issues, total = _open_issues(branch)
    return branch_verdict(entry, issues, total, KNOWN_OPEN if known is None else known), judged


def _branch_cases():
    """Self-test cases for --branch mode, each True when the code gets it right."""
    sha, known = "c" * 40, {"K1": "why"}
    entry = {"name": "main", "commit": {"sha": sha}, "status": {"vulnerabilities": 1}}
    kept = {"key": "K1", "component": PROJECT + ":.clusterfuzzlite/Dockerfile", "line": 10,
            "severity": "MINOR", "rule": "docker:S6471", "message": "root"}
    new = {"key": "K2", "component": PROJECT + ":panel/x.py", "line": 3, "severity": "MAJOR",
           "rule": "python:S1481", "message": "Remove the unused local variable"}
    analyses = {"analyses": [{"revision": "d" * 40}, {"revision": sha}]}
    return {
        "branch: the branch's entry is found by name":
            branch_entry({"branches": [{"name": "x"}, entry]}, "main") is entry,
        "branch: an analysis of this commit is found behind a newer one": analysed(analyses, sha),
        "branch: a commit not yet analysed is not": not analysed(analyses, "e" * 40),
        "branch: only the known issue open passes": branch_verdict(entry, [kept], 1, known) == [],
        "branch: an issue on an unchanged line, not known, fails, named":
            branch_verdict(entry, [kept, new], 2, known)
            == ["panel/x.py:3 MAJOR python:S1481: Remove the unused local variable [K2]"],
        "branch: the known issue missing fails (the read returned nothing)":
            len(branch_verdict(entry, [], 0, known)) == 2,
        "branch: a list shorter than SonarCloud's total fails":
            branch_verdict(entry, [kept], 3, known) != [],
    }


def self_test():
    """Check the matching and the verdict against canned API answers."""
    sha = "a" * 40
    pr_list = {"pullRequests": [
        {"key": "7", "commit": {"sha": "b" * 40}, "status": {"codeSmells": 1}},
        {"key": "8", "commit": {"sha": sha}, "status": {"qualityGateStatus": "OK", "bugs": 0,
                                                         "vulnerabilities": 0, "codeSmells": 0}}]}
    smell = {"component": PROJECT + ":panel/x.py", "line": 3, "severity": "MINOR",
             "rule": "python:S1481", "message": "Remove the unused local variable"}
    cases = {
        "the analysis of an older commit is not the head's": (analysis_of(pr_list, "7", sha) is None),
        "the head's analysis is found": (analysis_of(pr_list, "8", sha) is not None),
        "a clean analysis passes": (verdict(analysis_of(pr_list, "8", sha), []) == []),
        "a code smell under a passing gate fails, named":
            (verdict({"status": {"qualityGateStatus": "OK", "codeSmells": 1}}, [smell])
             == ["panel/x.py:3 MINOR python:S1481: Remove the unused local variable"]),
        "a count with no issue listed still fails":
            (verdict({"status": {"qualityGateStatus": "OK", "bugs": 1}}, []) != []),
        "a failed gate fails": (verdict({"status": {"qualityGateStatus": "ERROR"}}, []) != []),
    }
    cases.update(_branch_cases())
    bad = [name for name, ok in cases.items() if not ok]
    for name in bad:
        print("SELF-TEST FAIL " + name)
    print("self-test: %d of %d cases right" % (len(cases) - len(bad), len(cases)))
    return 1 if bad else 0


def main_branch(branch, sha, timeout):
    """--branch mode: judge the branch's open issues at SonarCloud's analysis of `sha`."""
    if not (re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", branch or "")
            and (sha is None or re.fullmatch(r"[0-9a-f]{40}", sha))):
        print("::error::need --branch <name> and, if given, --sha <40-hex commit>")
        return 2
    start = time.time()
    problems, judged = run_branch(branch, sha, timeout)
    for p in problems:
        print("::error::%s" % p)
    if not judged:
        read = "no analysis read"
    elif sha in (None, judged):
        read = "read at its analysis of %s" % judged[:12]
    else:
        read = "read at its analysis of %s, a newer commit than %s" % (judged[:12], sha[:12])
    print("SonarCloud: %d problem(s) with the open issues on %s, %s (%d known open issue(s) "
          "expected; waited %ds)" % (len(problems), branch, read, len(KNOWN_OPEN),
                                     int(time.time() - start)))
    return 1 if problems else 0


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--pr")
    ap.add_argument("--branch")
    ap.add_argument("--sha")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args(argv[1:])
    if a.self_test:
        return self_test()
    if a.branch is not None:
        return main_branch(a.branch, a.sha or None, a.timeout)
    if not (a.pr and re.fullmatch(r"[0-9]{1,7}", a.pr) and a.sha
            and re.fullmatch(r"[0-9a-f]{40}", a.sha)):
        print("::error::need --pr <number> and --sha <40-hex commit>")
        return 2
    problems, waited = run(a.pr, a.sha, a.timeout)
    for p in problems:
        print("::error::%s" % p)
    print("SonarCloud: %d new issue(s) on pull request %s at %s (waited %ds for its analysis)"
          % (len(problems), a.pr, a.sha[:12], waited))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
