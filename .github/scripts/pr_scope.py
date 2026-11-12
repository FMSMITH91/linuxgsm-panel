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

PER JOB (--job NAME). Some jobs measure only part of the repository: coverage runs the suites
over the panel's code, js coverage and Lighthouse drive the panel in a browser. With --job it also
writes `skip=true|false`: true when every path the pull request changes is documentation or on that
job's list in JOB_IRRELEVANT, paths that cannot change what the job measures (another workflow, a
CI tool's lockfile it does not install, a scanner's configuration, and for the browser jobs the test
suites). A path on no list counts as a change to the job, so a new kind of file runs everything.
This script, reuse_pr_result.py and the job's own workflow are never on a list. The same fail-open
cases as above write skip=false.

Usage:
    pr_scope.py --event EVENT [--repo OWNER/NAME --pr N --head-sha SHA] [--job NAME]

Writes `docs_only=true|false` (and with --job, `skip=true|false`) to $GITHUB_OUTPUT (when set) and
says why on stdout. Always exits 0 when it could decide either way; the steps it gates read
`docs_only != 'true'` / `skip != 'true'` as "run", so a missing or garbled output runs them too.
"""
import argparse
import json
import os
import re
import string
import subprocess  # nosec B404 - gh with a fixed argv, no shell
import sys

# The docs-only paths: the paths-ignore list, as the panel's _ci_path_ignored reads it. GitHub's
# '**/*.md' matches a .md file at any depth, the root included, and 'docs/**' everything under docs/.
# Not .gitattributes: it decides the bytes git checks out (eol conversion of every .sh and .py,
# -text on the fuzz corpus), so a change to it alone is a change to what every later run builds.
DOCS_ONLY_PATTERNS = ("**/*.md", "docs/**", "LICENSE", ".gitignore", ".editorconfig")
DOCS_ONLY_FILES = frozenset(p for p in DOCS_ONLY_PATTERNS if "*" not in p)

_REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}\Z")
_PR_RE = re.compile(r"[1-9][0-9]{0,8}\Z")
_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
# The characters an owner/name slug may hold, each mapped to itself: the slug handed to gh is
# REBUILT from this table, character by character, so no text from the command line reaches gh's
# argv (a regex match alone validates the text but still passes it on), and the pull request
# number goes through int(). Anything the table lacks makes the slug None, and everything runs.
_SLUG_CHARS = {c: c for c in string.ascii_letters + string.digits + "-._/"}


def safe_slug(repo):
    """`repo` rebuilt from _SLUG_CHARS when it is an owner/name slug, else None."""
    if not _REPO_RE.match(repo or ""):
        return None
    try:
        return "".join(_SLUG_CHARS[c] for c in repo)
    except KeyError:
        return None


# ── Per job: paths that cannot change what the job measures ──────────────────────────────────────
# Glob patterns over the repository path: `**` matches across directories, `*` within one. Every
# workflow file is on each list except the job's own, which JOB_WORKFLOW names.
_ALWAYS_RUN = (".github/scripts/pr_scope.py", ".github/scripts/reuse_pr_result.py")
# Read by a scanner or a bot alone, never by the panel or its test suites' measured code.
_SCANNER_AND_BOT = (".codacy.yaml", ".prospector.yaml", ".semgrepignore", ".sonarcloud.properties",
                    ".github/gitleaks.toml", ".github/codeql/**", ".github/actionlint.yaml",
                    ".github/codacy-accepted-errors.json", ".github/dependabot.yml",
                    ".github/renovate.json", ".github/lighthouserc.json", ".clusterfuzzlite/**")
# Lockfiles of tools the measuring jobs do not install (each job's own is put back by _JOB_KEEP).
_OTHER_LOCKS = (".github/ci-requirements/**", ".github/ci-requirements-checks/**",
                "tools/gamedig/package.json", "tools/gamedig/package-lock.json",
                "tools/gamedig/osv-scanner.toml", "panel/static/vendor/package.json",
                "panel/static/vendor/package-lock.json", "panel/install/requirements*.in",
                "panel/install/osv-scanner.toml")
# What the browser jobs never load: the test suites, the other tools, the CI's own scripts, and
# the installer-side shell scripts and lists (the panel they drive is served from the checkout).
_NOT_IN_A_BROWSER = ("tests/**", "tools/**", ".github/scripts/**", "install.sh", "panel/install/*.sh",
                     "panel/install/update-stops")
JOB_WORKFLOW = {"coverage": ".github/workflows/ci.yml", "js coverage": ".github/workflows/ci.yml",
                "lighthouse": ".github/workflows/lighthouse.yml"}
JOB_IRRELEVANT = {
    "coverage": _SCANNER_AND_BOT + _OTHER_LOCKS,
    "js coverage": _SCANNER_AND_BOT + _OTHER_LOCKS + _NOT_IN_A_BROWSER,
    "lighthouse": _SCANNER_AND_BOT + _OTHER_LOCKS + _NOT_IN_A_BROWSER,
}
# Put back: what each job installs or runs from inside an otherwise irrelevant directory.
_JOB_KEEP = {
    "coverage": (".github/ci-requirements/coverage.in", ".github/ci-requirements/coverage.txt"),
    "js coverage": ("tools/js_coverage/**", "tools/nosudo_runner.py"),  # run.py starts serve.py under it
    "lighthouse": ("tools/lhci_serve.py", "tools/lhci-login.js", ".github/lighthouserc.json"),
}


def _glob_re(pattern):
    """A regex for one glob: `**/` any directories (or none), `**` anything, `*` and `?` within a name."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(out + r"\Z")


def _matches(path, patterns):
    return any(_glob_re(p).match(path) for p in patterns)


def irrelevant_to(job, path):
    """Whether `path` cannot change what `job` measures (documentation always cannot)."""
    if job not in JOB_IRRELEVANT or not isinstance(path, str) or not path:
        return False
    if path in _ALWAYS_RUN or _matches(path, _JOB_KEEP.get(job, ())):
        return False
    # Every workflow but the job's own: that one decides what the job does.
    if is_doc(path) or (path.startswith(".github/workflows/") and path != JOB_WORKFLOW[job]):
        return True
    return _matches(path, JOB_IRRELEVANT[job])


def job_skips(job, paths):
    """Whether `paths` is non-empty and none of them can change what `job` measures."""
    paths = list(paths)
    return bool(paths) and all(irrelevant_to(job, p) for p in paths)


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


def _head_and_count(slug, number):
    """The pull request's head commit and its changed_files count, or None when unreadable."""
    meta = _gh(["--", "repos/%s/pulls/%d" % (slug, number)])
    try:
        meta = json.loads(meta) if meta is not None else None
        return meta["head"]["sha"], int(meta["changed_files"])
    except (ValueError, TypeError, KeyError):
        print("the pull request could not be read")
        return None


def _parse_rows(out):
    """(how many files, their paths and each renamed file's old path) from gh's rows, or None."""
    files, paths = 0, []
    try:
        for line in out.splitlines():
            if not line.strip():
                continue
            name, old = json.loads(line)
            files += 1
            paths.extend([name] if old is None else [name, old])
    except (ValueError, TypeError):
        print("the file list is not what gh api returns")
        return None
    return files, paths


def read_paths(repo, pr, head_sha):
    """Return every path the pull request changes (and each renamed file's old path), or None.

    None whenever the answer is not certain: the list could not be read, it is not the pull
    request's whole list, or the pull request's head is not `head_sha`.
    """
    slug, number = safe_slug(repo), int(pr)
    if slug is None or number < 1:
        print("not an owner/name slug and a pull request number")
        return None
    meta = _head_and_count(slug, number)
    if meta is None:
        return None
    if meta[0] != head_sha:
        print("the pull request's head is %s, not this run's %s" % (str(meta[0])[:10], head_sha[:10]))
        return None
    out = _gh(["--paginate", "--jq", ".[] | [.filename, .previous_filename]", "--",
               "repos/%s/pulls/%d/files?per_page=100" % (slug, number)])
    rows = _parse_rows(out) if out is not None else None
    if rows is None:
        return None
    if rows[0] != meta[1]:
        print("read %d files of the %d the pull request changes" % (rows[0], meta[1]))
        return None
    return rows[1]


def valid(repo, pr, head_sha):
    """Whether `repo`, `pr` and `head_sha` are an owner/name slug, a PR number and a commit id."""
    return bool(_REPO_RE.match(repo or "") and _PR_RE.match(str(pr or ""))
                and _SHA_RE.match(head_sha or ""))


def _not_docs(paths):
    """The paths that are not documentation, as text: the first five, and how many more."""
    code = sorted({p for p in paths if not is_doc(p)})
    more = " and %d more" % (len(code) - 5) if len(code) > 5 else ""
    return ", ".join(code[:5]) + more


def _paths_or_why(event, repo, pr, head_sha):
    """(the pull request's paths, None), or (None, why everything runs)."""
    if event != "pull_request":
        return None, "not a pull request (%s): everything runs" % (event or "no event")
    if not valid(repo, pr, head_sha):
        return None, "no valid repository, pull request number and head commit: everything runs"
    paths = read_paths(repo, int(pr), head_sha)
    if paths is None:
        return None, "the pull request's file list could not be established: everything runs"
    if not paths:
        return None, "the pull request changes no file: everything runs"
    return paths, None


def decide(event, repo, pr, head_sha, paths=None):
    """Return (docs_only, why). `paths`, when given, is the file list already read."""
    if paths is None:
        paths, why = _paths_or_why(event, repo, pr, head_sha)
        if paths is None:
            return False, why
    if not docs_only(paths):
        return False, "the pull request changes %s: everything runs" % _not_docs(paths)
    return True, ("DOCS-ONLY: all %d paths the pull request changes are documentation (%s), so this "
                  "job skips its steps that only read code" % (len(paths), ", ".join(DOCS_ONLY_PATTERNS)))


def decide_job(job, paths):
    """Return (skip, why) for `job` over the pull request's `paths` (None: it could not be read)."""
    if job not in JOB_IRRELEVANT:
        return False, "no list for job %r: it runs" % job
    if paths is None:
        return False, "the pull request's file list could not be established: it runs"
    hit = sorted({p for p in paths if not irrelevant_to(job, p)})
    if hit:
        more = " and %d more" % (len(hit) - 5) if len(hit) > 5 else ""
        return False, "%s: the pull request changes %s%s, so it runs" % (job, ", ".join(hit[:5]), more)
    return job_skips(job, paths), ("%s SKIPS: none of the %d paths the pull request changes can change "
                                   "what it measures (.github/scripts/pr_scope.py JOB_IRRELEVANT)"
                                   % (job, len(paths)))


def main(argv=None):
    """Decide, write docs_only to $GITHUB_OUTPUT, and say why."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--event", default="")
    ap.add_argument("--repo", default="")
    ap.add_argument("--pr", default="")
    ap.add_argument("--head-sha", default="")
    ap.add_argument("--job", default="")
    a = ap.parse_args(argv)
    paths, why = _paths_or_why(a.event, a.repo, a.pr, a.head_sha)
    only, why = (False, why) if paths is None else decide(a.event, a.repo, a.pr, a.head_sha, paths)
    lines = ["docs_only=%s" % ("true" if only else "false")]
    print(("::notice::" if only else "") + why)
    if a.job:
        skip, jwhy = decide_job(a.job, paths)
        lines.append("skip=%s" % ("true" if skip else "false"))
        print(("::notice::" if skip else "") + jwhy)
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write("".join(ln + "\n" for ln in lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
