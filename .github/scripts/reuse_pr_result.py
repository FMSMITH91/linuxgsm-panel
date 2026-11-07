#!/usr/bin/env python3
"""Decide whether a push to main may reuse the merged pull request's passing result for one job.

A pull request merges into main only after its required checks pass, and the merge (a squash, as a
rule) is a NEW commit on main whose files are, almost always, exactly the files the pull request's
head held. The push then ran every job again on the same bytes. The jobs cannot simply stop running
on main: installed panels offer a commit only when it carries passing check runs with these names
(panel/ops/system_ops.py, _CI_REQUIRED), and deploy.yml's verify step waits for the same names. So
each such job still runs on main, under its own name, and this decides whether its expensive steps
may be skipped: REUSE when the pull request already passed this very job on this very tree, FULL
otherwise.

REUSE needs every one of these; anything else is FULL:
  1. The event is a push to exactly refs/heads/main, for a commit id, in an owner/name repository.
  2. GitHub lists exactly one pull request for the pushed commit (REST "List pull requests
     associated with a commit"), and that pull request, read on its own, is merged, into main of
     this repository, with merge_commit_sha equal to the pushed commit.
  3. main has an active non_fast_forward rule (REST "Get rules for a branch"): main only moves
     forward, the premise of point 4.
  4. Locally, with git: the pushed commit's tree is the pull request head's tree, and the head
     contains the pushed commit's first parent (the main the merge was made on).
     Why that is the tree the pull request's run tested: a pull_request run tests GitHub's merge of
     the head into the base AS IT WAS THEN (refs/pull/<n>/merge). main only moves forward, so that
     base is an ancestor of the merge's first parent, which the head contains; the base is then an
     ancestor of the head, and merging an ancestor into the head changes nothing: the tested tree
     is the head's tree, which is the pushed commit's.
  5. The pull request's head carries a check run named exactly like this job, from the GitHub
     Actions app (id 15368), produced by a pull_request run of this same workflow file for that
     head; EVERY such check run completed with success (a re-run after a failure is not judged:
     everything runs), and in each one the job's own work steps (--work-step) concluded success.
     The last part means the pull request really ran the work: a documentation-only pull request's
     jobs pass by skipping it (.github/scripts/pr_scope.py), and that pass is never reused.

FAILS SAFE. Any API or git error, an answer not in the shape GitHub documents, more rows than one
page holds, or input that is not what the workflow passes: FULL, and everything runs. It never makes
a job pass that would have run; at worst it runs one that need not have.

Documentation read for this:
  https://docs.github.com/en/rest/commits/commits#list-pull-requests-associated-with-a-commit
  https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request
  https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch
  https://docs.github.com/en/rest/checks/runs#list-check-runs-for-a-git-reference
  https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-repository
  https://docs.github.com/en/rest/actions/workflow-jobs#get-a-job-for-a-workflow-run
  https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
    (push: GITHUB_SHA is the tip commit pushed to the ref; pull_request: GITHUB_SHA is the merge
    commit of refs/pull/<n>/merge)

Usage:
    reuse_pr_result.py --event EVENT --ref REF --repo OWNER/NAME --sha SHA --workflow PATH
                       --check-name NAME --work-step STEP [--work-step STEP ...]

Writes `reuse=true|false` to $GITHUB_OUTPUT (when set), and on REUSE also `pr=<number>` and
`run_id=<the pull request run's id>` (the coverage jobs copy that run's report). Says why on stdout.
Always exits 0; the steps it gates read `reuse != 'true'` as "run", so a missing or garbled answer
runs them.
"""
import argparse
import importlib.util
import json
import os
import re
import string
import subprocess  # nosec B404 - git and gh with fixed argv, no shell
import sys
import urllib.parse


def _load_pr_scope():
    """pr_scope.py, beside this file: its gh runner and its owner/name slug rebuilding."""
    spec = importlib.util.spec_from_file_location(
        "pr_scope_for_reuse", os.path.join(os.path.dirname(os.path.abspath(__file__)), "pr_scope.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_PR_SCOPE = _load_pr_scope()
gh_api, safe_slug = _PR_SCOPE._gh, _PR_SCOPE.safe_slug

# The GitHub Actions app: every check run a workflow job makes is this app's. Read off the check
# runs (`app.id`, slug github-actions), and named in .github/required-checks.txt.
ACTIONS_APP_ID = 15368
MAIN_REF = "refs/heads/main"
_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
# A job name as the workflows write them (the matrix names hold a middle dot), and a workflow file
# under .github/workflows.
_NAME_CHARS = string.ascii_letters + string.digits + " .,:/()+_·-"
_NAME_RE = re.compile(r"[%s]{1,100}\Z" % re.escape(_NAME_CHARS))
_WORKFLOW_RE = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]{1,80}\.ya?ml\Z")
# As pr_scope.py does for the slug: a commit id or job name handed to gh or git is REBUILT from a
# table of the characters it may hold, so no text from the command line or from an API answer
# reaches their argv (a regex match validates the text but still passes it on).
_HEX = {c: c for c in "0123456789abcdef"}
_NAME_TABLE = {c: c for c in _NAME_CHARS}


def _rebuilt(text, pattern, table):
    """`text` rebuilt from `table` when it matches `pattern`, else None."""
    if not isinstance(text, str) or not pattern.match(text):
        return None
    try:
        return "".join(table[c] for c in text)
    except KeyError:
        return None


class Full(Exception):
    """A reason this job runs in full."""


def _api(path):
    """The JSON GitHub answered for `path`, or Full when gh failed or the answer is not JSON."""
    out = gh_api(["--", path])
    if out is None:
        raise Full("GitHub did not answer %s" % path.split("?")[0])
    try:
        return json.loads(out)
    except ValueError:
        raise Full("GitHub's answer for %s is not JSON" % path.split("?")[0]) from None


def _git(args):
    """git's stdout for `args` (stripped), or Full when it did not succeed."""
    try:
        res = subprocess.run(["git"] + args, capture_output=True, text=True,  # nosec B603 B607
                             timeout=300, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        raise Full("could not run git: %s" % e) from None
    if res.returncode != 0:
        raise Full("git %s failed (%d)" % (args[0], res.returncode))
    return res.stdout.strip()


def _is_id(v):
    """Whether `v` is a positive integer id (JSON true is not one)."""
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def _one_pr(rows):
    """The number of the only pull request in `rows`, else Full."""
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise Full("the pushed commit is not associated with exactly one pull request")
    if not _is_id(rows[0].get("number")):
        raise Full("the pull request's number is not a number")
    return rows[0]["number"]


def _pr_problems(pr, slug, sha):
    """What keeps pull request `pr` from being the one merged into main as `sha` ([] when nothing)."""
    base = pr.get("base") or {}
    base_repo = str((base.get("repo") or {}).get("full_name")).lower()
    return [why for bad, why in (
        (pr.get("merged") is not True, "is not merged"),
        (pr.get("state") != "closed", "is not closed"),
        (base.get("ref") != "main", "was not merged into main"),
        (base_repo != slug.lower(), "was not merged into this repository"),
        (pr.get("merge_commit_sha") != sha, "was merged as another commit than the pushed one"),
        (not _SHA_RE.match(str((pr.get("head") or {}).get("sha"))), "has no head commit id"),
    ) if bad]


def merged_pr(slug, sha):
    """(number, head sha) of the one pull request merged into main as `sha`, else Full."""
    number = _one_pr(_api("repos/%s/commits/%s/pulls?per_page=100" % (slug, sha)))
    pr = _api("repos/%s/pulls/%d" % (slug, number))
    problems = _pr_problems(pr, slug, sha) if isinstance(pr, dict) else ["could not be read"]
    if problems:
        raise Full("pull request #%d %s" % (number, "; ".join(problems)))
    return number, _rebuilt(pr["head"]["sha"], _SHA_RE, _HEX)


def main_moves_forward(slug):
    """Full unless main has an active non_fast_forward rule (no force push can move it back)."""
    rules = _api("repos/%s/rules/branches/main?per_page=100" % slug)
    if not isinstance(rules, list) or not any(
            isinstance(r, dict) and r.get("type") == "non_fast_forward" for r in rules):
        raise Full("main has no non_fast_forward rule, so its history could have been rewritten")


def _first_parent(sha):
    """The pushed commit's first parent, read from the commit object itself.

    From the object, not `sha^1`: the job's checkout is shallow (depth 1), and git answers `sha^1`
    of a shallow commit as if it had none, though the object still names its parents.
    """
    for line in _git(["cat-file", "commit", sha]).split("\n"):
        if not line:
            break
        if line.startswith("parent ") and _SHA_RE.match(line[7:]):
            return line[7:]
    raise Full("the pushed commit has no parent")


def same_tree(sha, head):
    """The tree id both commits share, when the head also contains the pushed commit's parent."""
    if _git(["rev-parse", "--verify", "HEAD^{commit}"]) != sha:
        raise Full("the checkout is not the pushed commit")
    parent = _first_parent(sha)
    # The head and its history, by id: the pull request's branch may be gone already. Into a shallow
    # checkout this brings the head's whole line, and leaves HEAD as shallow as it was.
    _git(["fetch", "--no-tags", "--quiet", "origin", head])
    tree, head_tree = (_git(["rev-parse", "--verify", c + "^{tree}"]) for c in (sha, head))
    if tree != head_tree:
        raise Full("the pushed tree %s is not the pull request head's %s" % (tree[:12], head_tree[:12]))
    try:
        _git(["merge-base", "--is-ancestor", parent, head])
    except Full:
        raise Full("the pull request's head does not contain %s, the main it was merged on"
                   % parent[:12]) from None
    return tree


def _pr_runs(slug, head, workflow):
    """{check suite id: run id} of the pull_request runs of `workflow` for `head`."""
    body = _api("repos/%s/actions/runs?head_sha=%s&event=pull_request&per_page=100" % (slug, head))
    runs = body.get("workflow_runs") if isinstance(body, dict) else None
    if not isinstance(runs, list) or body.get("total_count") != len(runs):
        raise Full("the pull request's workflow runs are not one whole page")
    return {r.get("check_suite_id"): r.get("id") for r in runs if isinstance(r, dict)
            and r.get("path") == workflow and r.get("event") == "pull_request"
            and r.get("head_sha") == head and isinstance(r.get("id"), int)}


def _named_checks(slug, head, name):
    """The check runs named `name` on `head`, all of them (not only the latest), from Actions."""
    body = _api("repos/%s/commits/%s/check-runs?check_name=%s&filter=all&app_id=%d&per_page=100"
                % (slug, head, urllib.parse.quote(name, safe=""), ACTIONS_APP_ID))
    runs = body.get("check_runs") if isinstance(body, dict) else None
    if not isinstance(runs, list) or body.get("total_count") != len(runs):
        raise Full("the pull request head's check runs are not one whole page")
    return [r for r in runs if _is_actions_check(r, name, head)]


def _is_actions_check(row, name, head):
    """Whether check-run `row` is an Actions job named `name` on `head`."""
    return isinstance(row, dict) and _is_id(row.get("id")) and all((
        row.get("name") == name, row.get("head_sha") == head,
        (row.get("app") or {}).get("id") == ACTIONS_APP_ID))


def _is_job_of(job, check, run_id, head):
    """Whether `job` (a job read by the check run's id) is that check run, in run `run_id`."""
    return isinstance(job, dict) and all((
        job.get("run_id") == run_id, job.get("head_sha") == head, job.get("name") == check["name"],
        str(job.get("check_run_url")).endswith("/check-runs/%d" % check["id"])))


def _work_ran(slug, check, run_id, head, work_steps):
    """Full unless the job behind `check` is that run's, and every work step concluded success."""
    job = _api("repos/%s/actions/jobs/%d" % (slug, check["id"]))
    if not _is_job_of(job, check, run_id, head):
        raise Full("check run %d is not a job of run %d" % (check["id"], run_id))
    done = {s.get("name"): s.get("conclusion") for s in job.get("steps") or [] if isinstance(s, dict)}
    missed = [s for s in work_steps if done.get(s) != "success"]
    if missed:
        raise Full("the pull request's job did not run %s (a documentation-only pass, or a step "
                   "renamed since)" % "; ".join(missed))


def pr_passed(slug, head, name, workflow, work_steps):
    """The run id of the pull request's passing `name` job of `workflow` on `head`, else Full."""
    suites = _pr_runs(slug, head, workflow)
    checks = [c for c in _named_checks(slug, head, name)
              if (c.get("check_suite") or {}).get("id") in suites]
    if not checks:
        raise Full("the pull request head has no '%s' check from a pull_request run of %s"
                   % (name, workflow))
    failed = [c["id"] for c in checks
              if c.get("status") != "completed" or c.get("conclusion") != "success"]
    if failed:
        raise Full("a '%s' check on the pull request head did not pass (%s)" % (name, failed))
    for c in checks:
        _work_ran(slug, c, suites[c["check_suite"]["id"]], head, work_steps)
    newest = max(checks, key=lambda c: str(c.get("completed_at")))
    return suites[newest["check_suite"]["id"]]


def valid(a):
    """Whether the arguments are what the workflows pass; a reason when they are not."""
    for bad, why in (
            (a.event != "push", "not a push (%s)" % (a.event or "no event")),
            (a.ref != MAIN_REF, "not a push to %s (%s)" % (MAIN_REF, a.ref or "no ref")),
            (safe_slug(a.repo) is None, "no valid repository"),
            (not _SHA_RE.match(a.sha or ""), "no valid commit"),
            (not _WORKFLOW_RE.match(a.workflow or ""), "no valid workflow file"),
            (not _NAME_RE.match(a.check_name or ""), "no valid job name"),
            (not a.work_step or not all(_NAME_RE.match(s) for s in a.work_step), "no valid work step")):
        if bad:
            return why
    return ""


def decide(a):
    """Return (reuse, why, outputs)."""
    bad = valid(a)
    if bad:
        return False, bad + ": everything runs", {}
    slug, sha = safe_slug(a.repo), _rebuilt(a.sha, _SHA_RE, _HEX)
    name = _rebuilt(a.check_name, _NAME_RE, _NAME_TABLE)
    try:
        number, head = merged_pr(slug, sha)
        main_moves_forward(slug)
        run_id = pr_passed(slug, head, name, a.workflow, a.work_step)
        tree = same_tree(sha, head)
    except Full as e:
        return False, "%s: everything runs" % e, {}
    return True, ("REUSE: verified on PR #%d (same tree %s), '%s' passed there in run %d, so "
                  "this job skips its steps" % (number, tree, name, run_id)), \
        {"pr": str(number), "run_id": str(run_id)}


def main(argv=None):
    """Decide, write reuse (and on REUSE pr and run_id) to $GITHUB_OUTPUT, and say why."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    for opt in ("--event", "--ref", "--repo", "--sha", "--workflow", "--check-name"):
        ap.add_argument(opt, default="")
    ap.add_argument("--work-step", action="append", default=[])
    a = ap.parse_args(argv)
    reuse, why, outputs = decide(a)
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write("reuse=%s\n" % ("true" if reuse else "false"))
            for k, v in outputs.items():
                fh.write("%s=%s\n" % (k, v))
    print(("::notice::" if reuse else "") + why)
    return 0


if __name__ == "__main__":
    sys.exit(main())
