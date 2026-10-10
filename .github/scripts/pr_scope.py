#!/usr/bin/env python3
"""Decide whether a pull request changes ONLY documentation, so its heavy checks can pass at once.

Every check a pull request must pass (.github/required-checks.txt) runs on every pull request with
no path filter: a required check whose workflow did not run holds the pull request forever. So a
README edit ran the whole test matrix, coverage, CodeQL, Bandit, Semgrep, pip-audit, Lighthouse and
the rest. Each of those jobs now runs this first, as its scope step (after checking it out), and
skips its later STEPS when the answer is "docs only". A step, not the job: the job still concludes
success under its own name, which is what the required check reads. fuzz.yml and cflite_pr.yml do
the same with their own allowlists, inline, before any checkout.

DOCS-ONLY is exactly the push `paths-ignore` list ci.yml, codeql.yml, security-code.yml and
zizmor.yml share (and that the panel's update gate applies, system_ops._ci_path_ignored): a pull
request is docs-only when EVERY path it changes, and every previous path of a renamed file, is one
of them. tests/unit (part14 and part50) holds the three lists equal.

FAILS OPEN. Anything this cannot establish is "not docs-only", and everything runs:
  - an event that is not a pull request (a push to main, the schedules, a manual run);
  - a file list that cannot be read, or that is not the whole list (GitHub lists at most 3000
    files; the count must equal the pull request's changed_files);
  - a pull request whose head is no longer the commit this run is for (a later push: its own run
    decides for it), so a decision is never taken from a newer or older file list;
  - a pull request with no files at all.
It reads the pull request's WHOLE file list at its head, never one commit's: a docs-only first
commit followed by a code commit is a code change.

Usage:
    pr_scope.py --event EVENT [--repo OWNER/NAME --pr N --head-sha SHA]

Writes `docs_only=true|false` to $GITHUB_OUTPUT (when set) and says why on stdout. Always exits 0
when it could decide either way; the steps it gates read `docs_only != 'true'` as "run", so a
missing or garbled output runs them too.
"""
import argparse
import json
import os
import re
import subprocess  # nosec B404 - gh with a fixed argv, no shell
import sys

# The docs-only paths: the paths-ignore list, as the panel's _ci_path_ignored reads it. GitHub's
# '**/*.md' matches a .md file at any depth, the root included, and 'docs/**' everything under docs/.
DOCS_ONLY_PATTERNS = ("**/*.md", "docs/**", "LICENSE", ".gitignore", ".gitattributes", ".editorconfig")
DOCS_ONLY_FILES = frozenset(p for p in DOCS_ONLY_PATTERNS if "*" not in p)

_REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}\Z")
_PR_RE = re.compile(r"[1-9][0-9]{0,8}\Z")
_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")


def is_doc(path):
    """Whether `path` is one of the docs-only paths ('**/*.md', 'docs/**', or one of the files)."""
    return isinstance(path, str) and bool(path) and (
        path.endswith(".md") or path.startswith("docs/") or path in DOCS_ONLY_FILES)


def docs_only(paths):
    """Whether `paths` is non-empty and every one of them is a docs-only path."""
    paths = list(paths)
    return bool(paths) and all(is_doc(p) for p in paths)


def _gh(args):
    """Run `gh api` with `args`; return its stdout, or None when it did not succeed."""
    try:
        res = subprocess.run(["gh", "api"] + args, capture_output=True,  # nosec B603 B607
                             text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        print("could not run gh: %s" % e)
        return None
    if res.returncode != 0:
        print("gh api failed (%d): %s" % (res.returncode, res.stderr.strip()[:300]))
        return None
    return res.stdout


def read_paths(repo, pr, head_sha):
    """Return every path the pull request changes (and each renamed file's old path), or None.

    None whenever the answer is not certain: the list could not be read, it is not the pull
    request's whole list, or the pull request's head is not `head_sha`.
    """
    meta = _gh(["--", "repos/%s/pulls/%d" % (repo, pr)])
    try:
        meta = json.loads(meta) if meta is not None else None
        head, count = meta["head"]["sha"], int(meta["changed_files"])
    except (ValueError, TypeError, KeyError):
        print("the pull request could not be read")
        return None
    if head != head_sha:
        print("the pull request's head is %s, not this run's %s" % (str(head)[:10], head_sha[:10]))
        return None
    out = _gh(["--paginate", "--jq", ".[] | [.filename, .previous_filename]", "--",
               "repos/%s/pulls/%d/files?per_page=100" % (repo, pr)])
    if out is None:
        return None
    files, paths = 0, []
    try:
        for line in out.splitlines():
            if not line.strip():
                continue
            name, old = json.loads(line)
            files += 1
            paths.append(name)
            if old is not None:
                paths.append(old)
    except (ValueError, TypeError):
        print("the file list is not what gh api returns")
        return None
    if files != count:
        print("read %d files of the %d the pull request changes" % (files, count))
        return None
    return paths


def decide(event, repo, pr, head_sha):
    """Return (docs_only, why)."""
    if event != "pull_request":
        return False, "not a pull request (%s): everything runs" % (event or "no event")
    if not (_REPO_RE.match(repo or "") and _PR_RE.match(str(pr or "")) and _SHA_RE.match(head_sha or "")):
        return False, "no valid repository, pull request number and head commit: everything runs"
    paths = read_paths(repo, int(pr), head_sha)
    if paths is None:
        return False, "the pull request's file list could not be established: everything runs"
    if not paths:
        return False, "the pull request changes no file: everything runs"
    if not docs_only(paths):
        code = sorted({p for p in paths if not is_doc(p)})
        shown = ", ".join(code[:5]) + (" and %d more" % (len(code) - 5) if len(code) > 5 else "")
        return False, "the pull request changes %s: everything runs" % shown
    return True, ("DOCS-ONLY: all %d paths the pull request changes are documentation (%s), so this "
                  "job skips its steps that only read code" % (len(paths), ", ".join(DOCS_ONLY_PATTERNS)))


def main(argv=None):
    """Decide, write docs_only to $GITHUB_OUTPUT, and say why."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--event", default="")
    ap.add_argument("--repo", default="")
    ap.add_argument("--pr", default="")
    ap.add_argument("--head-sha", default="")
    a = ap.parse_args(argv)
    only, why = decide(a.event, a.repo, a.pr, a.head_sha)
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write("docs_only=%s\n" % ("true" if only else "false"))
    print(("::notice::" if only else "") + why)
    return 0


if __name__ == "__main__":
    sys.exit(main())
