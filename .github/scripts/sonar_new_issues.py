#!/usr/bin/env python3
"""Fail a pull request that adds any SonarCloud issue, as Codacy's check already does for its own.

SonarCloud's check is its quality gate, and on the free plan that is "Sonar way", which cannot be
replaced: it fails on a new bug, vulnerability or unreviewed hotspot, but lets code smells through
while the new code still rates A for maintainability. Those then sat on main as open issues. This
waits for SonarCloud's analysis of the pull request's head commit and fails if it found anything new,
naming each issue. SonarCloud's API answers anonymously for this public project.

Usage:
    sonar_new_issues.py --pr NUMBER --sha HEAD_SHA [--timeout SECONDS]
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
    bad = [name for name, ok in cases.items() if not ok]
    for name in bad:
        print("SELF-TEST FAIL " + name)
    print("self-test: %d of %d cases right" % (len(cases) - len(bad), len(cases)))
    return 1 if bad else 0


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--pr")
    ap.add_argument("--sha")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args(argv[1:])
    if a.self_test:
        return self_test()
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
