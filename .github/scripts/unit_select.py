#!/usr/bin/env python3
"""Decide which unit parts a pull request's unit shards run: the parts its change can affect, or all of them.

The decision itself is tests/unit/impact.py's `select` (its docstring says what is selected and what
makes everything run); this script gathers its inputs on a CI runner:
  - the pull request's WHOLE file list at this run's head, with each file's status and a renamed
    file's old path (REST "List pull requests files"; the count must equal changed_files, as in
    pr_scope.py, whose gh runner and slug check this reuses);
  - its labels, read with it: `full-tests` runs everything;
  - the newest impact map main's CI made (the `unit-impact-map` artifact, which coverage-verdict
    uploads on a push to main only), taken only from a run that this repository's own push to main
    started, of .github/workflows/ci.yml;
  - what main changed since the map's commit (REST "Compare two commits", map commit to the pull
    request's base), so a part or an import main added after the map still selects;
  - the tree under test, for the parts' import graph and the code's import graph.

RUNS EVERYTHING whenever any of that is not certain: an event that is not a pull request (a push to
main, a manual run), a label, a file list that cannot be read whole, no map, a map from anywhere
else, too old or unreadable, or any error here. Main is never selected: every push to main runs the
whole suite, so a part skipped on a pull request still runs before a commit can be released.

Usage:
    unit_select.py --event EVENT [--repo OWNER/NAME --pr N --head-sha SHA]

Writes `parts=<space-separated part names>` (empty: everything runs) to $GITHUB_OUTPUT when set, and
says why on stdout. Always exits 0; an empty or missing answer runs everything.
"""
import argparse
import datetime
import importlib.util
import io
import json
import os
import re
import subprocess  # nosec B404 - gh with a fixed argv, no shell
import sys
import zipfile

LABEL = "full-tests"
ARTIFACT = "unit-impact-map"
MAP_FILE = "unit-impact-map.json"
MAX_BYTES = 32 * 1024 * 1024
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
STATUS = {"added": "A", "removed": "D", "modified": "M", "renamed": "R", "copied": "C", "changed": "M",
          "unchanged": "M"}


def _load(name, path):
    """A module from a file of this checkout, by path."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_PR_SCOPE = _load("pr_scope_for_unit_select", os.path.join(_HERE, "pr_scope.py"))


def _gh_bytes(args):
    """`gh api` with `args`, its stdout as bytes (an artifact's zip), or None when it did not succeed."""
    try:
        res = subprocess.run(["gh", "api"] + args, capture_output=True, timeout=120, check=False)  # nosec B603 B607
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout if res.returncode == 0 and len(res.stdout) <= MAX_BYTES else None


def changes(slug, number, head_sha):
    """([(status, path, old path)], its label names, its base commit) at `head_sha`, or None when not certain."""
    meta = _PR_SCOPE._gh(["--", "repos/%s/pulls/%d" % (slug, number)])
    try:
        meta = json.loads(meta)
        if meta["head"]["sha"] != head_sha:
            print("the pull request's head is not this run's commit")
            return None
        count = int(meta["changed_files"])
        labels = {lab["name"] for lab in meta["labels"]}
        base = meta["base"]["sha"]
    except (TypeError, ValueError, KeyError):
        print("the pull request could not be read")
        return None
    out = _PR_SCOPE._gh(["--paginate", "--jq", ".[] | [.status, .filename, .previous_filename]", "--",
                         "repos/%s/pulls/%d/files?per_page=100" % (slug, number)])
    rows = []
    try:
        for line in (out or "").splitlines():
            if line.strip():
                status, name, old = json.loads(line)
                rows.append((STATUS[status], name, old))
    except (ValueError, TypeError, KeyError):
        print("the file list is not what gh api returns")
        return None
    if not rows or len(rows) != count:
        print("read %d files of the %d the pull request changes" % (len(rows), count))
        return None
    return rows, labels, base


def _from_main(slug, run_id):
    """Whether run `run_id` is this repository's own push to main, of ci.yml."""
    run = _PR_SCOPE._gh(["--", "repos/%s/actions/runs/%d" % (slug, run_id)])
    try:
        run = json.loads(run)
        return (run["event"] == "push" and run["head_branch"] == "main" and run["path"] == ".github/workflows/ci.yml"
                and run["head_repository"]["full_name"] == slug and run["repository"]["full_name"] == slug)
    except (TypeError, ValueError, KeyError):
        return False


def _artifact_map(slug, art):
    """The map inside artifact `art` when it is a live one of a push to main of ci.yml; None otherwise."""
    if art["expired"] or art["name"] != ARTIFACT or not 0 < int(art["size_in_bytes"]) <= MAX_BYTES:
        return None
    if not _from_main(slug, int(art["workflow_run"]["id"])):
        return None
    blob = _gh_bytes(["--", "repos/%s/actions/artifacts/%d/zip" % (slug, int(art["id"]))])
    with zipfile.ZipFile(io.BytesIO(blob or b"")) as zf:
        if zf.getinfo(MAP_FILE).file_size > MAX_BYTES:
            return None
        return json.loads(zf.read(MAP_FILE).decode("utf-8"))


def newest_map(slug):
    """The newest impact map a push to main uploaded, or None."""
    out = _PR_SCOPE._gh(["--", "repos/%s/actions/artifacts?name=%s&per_page=20" % (slug, ARTIFACT)])
    try:
        arts = sorted(json.loads(out)["artifacts"], key=lambda a: a.get("created_at") or "", reverse=True)
        for art in arts:
            imap = _artifact_map(slug, art)
            if imap is not None:
                return imap
    except (TypeError, ValueError, KeyError, zipfile.BadZipFile):
        print("the artifact list, or an artifact in it, could not be read")
        return None
    print("no %s artifact from a push to main" % ARTIFACT)
    return None


_SHA = re.compile(r"[0-9a-f]{40}")


def since_map(slug, commit, base):
    """The paths main changed from the map's commit to the pull request's base; None when not certain.

    REST "Compare two commits": `identical` is nothing, `ahead` lists the files (at most 300 per answer,
    so a full page is not certain); anything else (the map is not an ancestor of the base) is None.
    """
    if not all(isinstance(c, str) and _SHA.fullmatch(c) for c in (commit, base)):
        return None
    try:
        cmp_ = json.loads(_PR_SCOPE._gh(["--", "repos/%s/compare/%s...%s" % (slug, commit, base)]))
        files = [] if cmp_["status"] == "identical" else cmp_["files"]
        if cmp_["status"] not in ("identical", "ahead") or len(files) >= 300:
            return None
        return _paths_of(files)
    except (TypeError, ValueError, KeyError):
        return None


def _paths_of(files):
    """Every path a compare answer's files name: each file, and each renamed file's old path."""
    return {p for f in files for p in (f["filename"], f.get("previous_filename")) if p}


def unit_parts(root):
    """The runner's _PARTS, read from tests/unit_test.py's text (the runner is not imported here)."""
    with open(os.path.join(root, "tests", "unit_test.py"), encoding="utf-8") as fh:
        src = fh.read()
    i = src.index("\n_PARTS = (")
    return tuple(re.findall(r'"(part\d+)"', src[i:src.index(")", i)]))


def decide(event, repo, pr, head_sha, root=_ROOT, now=None):
    """(selected part names or None, why)."""
    if event != "pull_request":
        return None, "not a pull request (%s): every part runs" % (event or "no event")
    if not _PR_SCOPE.valid(repo, pr, head_sha):
        return None, "no valid repository, pull request number and head commit: every part runs"
    slug, number = _PR_SCOPE.safe_slug(repo), int(pr)
    got = changes(slug, number, head_sha)
    if got is None:
        return None, "the pull request's file list could not be established: every part runs"
    rows, labels, base = got
    if LABEL in labels:
        return None, "the pull request carries the %s label: every part runs" % LABEL
    imap = newest_map(slug)
    if imap is None:
        return None, "no impact map from main: every part runs"
    impact = _load("impact_for_unit_select", os.path.join(root, "tests", "unit", "impact.py"))
    shard = _load("shard_for_unit_select", os.path.join(root, "tests", "unit", "shard.py"))
    parts = unit_parts(root)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return impact.select(rows, parts, shard.import_graph(parts, root), imap, now, impact.importers(root),
                         since_map(slug, imap.get("commit"), base))


def main(argv=None):
    """Write `parts=` for the unit shards; never fails the job."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--event", default="")
    ap.add_argument("--repo", default="")
    ap.add_argument("--pr", default="")
    ap.add_argument("--head-sha", default="")
    a = ap.parse_args(argv)
    try:
        selected, why = decide(a.event, a.repo, a.pr, a.head_sha)
    except Exception as e:  # pylint: disable=broad-except  # any doubt runs everything
        selected, why = None, "the selection failed (%s): every part runs" % type(e).__name__
    names = "" if selected is None else " ".join(sorted(selected, key=lambda p: int(p[4:])))
    print("unit parts: %s" % (why if selected is None else "%d selected (%s): %s" % (len(selected), why, names)))
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write("parts=%s\n" % names)
    return 0


if __name__ == "__main__":
    sys.exit(main())
