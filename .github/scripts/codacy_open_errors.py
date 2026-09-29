#!/usr/bin/env python3
"""Fail when main carries an Error-level Codacy issue that is not on the accepted list.

Run by .github/workflows/codacy-alerts.yml; see the long note at the top of that file for why the
gate exists and why it is scheduled rather than triggered by a push. Runnable by hand too:

    python .github/scripts/codacy_open_errors.py

Exit 0 = clean (or nothing but accepted issues). Exit 1 = something unreviewed is on main.
Exit 0 with a warning = the API could not be reached, or answered 5xx, 429 or 408; an outage or a
rate limit at Codacy is not a reason to fail the build, and the next scheduled run will catch what
this one missed. Any other answer it cannot read (another 4xx, a redirect, a body that is not JSON,
JSON that is not the object it expects) exits 1.
"""
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

ORG, REPO = "gh/FMSMITH91", "linuxgsm-panel"
API = ("https://app.codacy.com/api/v3/analysis/organizations/%s/repositories/%s"
       "/issues/search?limit=100" % (ORG, REPO))
ROOT = pathlib.Path(__file__).resolve().parent.parent      # .github/
ACCEPTED_FILE = ROOT / "codacy-accepted-errors.json"
# 4xx statuses that mean "not NOW", not "not this request": a rate limit and a request timeout. This
# runs daily from shared GitHub runner IPs against the anonymous API and can page up to 20 POSTs,
# so a 429 is weather, not a verdict — failing on it sent the operator to check an endpoint and a
# filter shape that were fine, and a gate that cries wolf gets ignored.
TRANSIENT_HTTP = frozenset((408, 429))


def _read_page(page):
    """One decoded page as (its issues, or None when it has no list; the next cursor).

    Raises ValueError, saying what is wrong, for JSON that is not {"data": [...], "pagination":
    {...}}. A JSON list, a `data` that is not a list of objects or a `pagination` that is not an
    object used to escape as an AttributeError traceback from the first `.get` that met it: the
    run did fail, but its log said nothing about why.
    """
    if not isinstance(page, dict):
        raise ValueError("a JSON %s where an object was expected" % type(page).__name__)
    data, pagination = page.get("data"), page.get("pagination") or {}
    if data is not None and not (isinstance(data, list)
                                 and all(isinstance(i, dict) for i in data)):
        raise ValueError("a `data` that is not a list of issues")
    if not isinstance(pagination, dict):
        raise ValueError("a `pagination` that is not an object")
    return data, pagination.get("cursor")


def fetch_errors():
    """Every Error-level issue Codacy currently reports for the default branch.

    Pages through the cursor rather than trusting one response to hold them all — a gate that
    silently reads only the first page reports "clean" the moment the list grows past it.

    Returns (issues, answered). `answered` is False when no page carried a `data` key at all —
    "the API told us nothing" is not the same claim as "there are no issues", and reporting the
    second on the strength of the first is the failure this gate exists to prevent. Its sibling
    codeql-alerts.yml states the rule outright: "'No analysis' is never treated as 'no alerts'."
    A repo that has not been analysed, an endpoint that moved, a filter shape that changed, or
    anonymous access being withdrawn all yield a 200 with nothing useful in it. A page that is
    JSON but not the object read here raises ValueError from _read_page, as a non-JSON one does.
    """
    out, cursor, answered = [], None, False
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    token = os.environ.get("CODACY_API_TOKEN")
    if token:
        headers["api-token"] = token
    for _ in range(20):                       # bounded: 20 pages x 100 is far more than plausible
        url = API + ("&cursor=%s" % cursor if cursor else "")
        req = urllib.request.Request(
            url, data=json.dumps({"levels": ["Error"]}).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:   # nosec B310 - constant https host
            data, cursor = _read_page(json.loads(resp.read().decode("utf-8", "replace")))
        if data is not None:
            answered = True          # a real, well-formed result set — even an empty one
        out.extend(data or [])
        if not cursor:
            break
    return out, answered


def _load_allow():
    """The accepted list, keyed for lookup against what Codacy reports."""
    accepted = json.loads(ACCEPTED_FILE.read_text(encoding="utf-8")).get("accepted", [])
    # Keyed on (file, pattern, the source line itself) — NOT the line NUMBER, which moves with
    # every edit above it and would make the list go stale on contact.
    #
    # The source line matters: without it, one accepted entry covers every hit of that rule in the
    # file. system_ops.py has two hits of the same Opengrep rule — the pre-helper `shell=True`
    # fallback, which is genuinely accepted, and an argv-based call that was simply missing a
    # suppression. A (file, pattern) key waved the second one through on the back of the first,
    # which is the exact failure this gate exists to prevent. Including the line also means that
    # EDITING an accepted line re-opens it for review, which is the right default for a standing
    # security exception.
    return {(a["filePath"], a["patternId"], " ".join(a["lineText"].split())): a
            for a in accepted}


def _fetch_or_exit_code():
    """Fetch the issues: (issues, None), or (None, exit code) when the API gave no usable answer."""
    try:
        issues, answered = fetch_errors()
    except urllib.error.HTTPError as exc:
        # ONLY a 5xx, a 429 or a 408 is an outage, and stays non-fatal: each says "not now", and
        # the next run re-asks (TRANSIENT_HTTP). Everything else is the API answering, and the
        # answer is "not this request": 401/403/404 (the repository went private, anonymous
        # access was withdrawn, the endpoint moved), but equally 400/422 (the `levels` filter
        # changed shape), 410 (the endpoint was retired), 307/308 (it moved — urllib does not
        # follow a redirect on a POST, it raises). This used to fail only on 401/403/404 and
        # print a ::warning:: for the rest — and this workflow is schedule-only, so a warning
        # nobody reads let it report green daily, forever, which is the scenario codacy-alerts.yml
        # names.
        if exc.code >= 500 or exc.code in TRANSIENT_HTTP:
            print("::warning::the Codacy API errored or rate-limited (HTTP %d) — not failing the "
                  "build; the next scheduled run will re-check." % exc.code)
            return None, 0
        print("::error::the Codacy API refused the request (HTTP %d) for %s/%s — refusing to "
              "report it clean. Check the endpoint, the filter shape, and whether anonymous "
              "access is still allowed." % (exc.code, ORG, REPO))
        return None, 1
    except ValueError as exc:
        # A 200 whose body is not JSON (an HTML error or login page, a changed content type) is
        # the API answering in a shape this gate cannot read — the same claim as `not answered`
        # below, and fatal for the same reason. It used to share the "could not reach" branch.
        # So is JSON that is not the object _read_page reads, on ANY page: a bad later page means
        # the issues were not all read, and a partial read is not "clean".
        what = ("something that is not JSON (%s)" % type(exc).__name__
                if isinstance(exc, json.JSONDecodeError) else exc)
        print("::error::the Codacy API answered with %s for %s/%s — refusing to report it clean."
              % (what, ORG, REPO))
        return None, 1
    except (urllib.error.URLError, OSError) as exc:
        # No answer at all — DNS, a refused connection, a timeout. An outage, not a verdict.
        print("::warning::could not reach the Codacy API (%s) — not failing the build; the next "
              "scheduled run will re-check." % type(exc).__name__)
        return None, 0
    if not answered:
        # A 200 that carried no `data` at all. Distinct from the unreachable case above, which is
        # an outage and is deliberately not fatal: this is the API answering in a shape this gate
        # cannot read, and reporting "nothing unreviewed" from it would be inventing the answer.
        print("::error::the Codacy API returned no issue list for %s/%s — refusing to report it "
              "clean. Check the endpoint, the filter shape, and whether the repository is still "
              "being analysed." % (ORG, REPO))
        return None, 1
    return issues, None


def _split_unreviewed(issues, allow):
    """The issues no accepted entry covers, and the set of keys every issue had."""
    unreviewed, seen = [], set()
    for i in issues:
        key = (i.get("filePath"), (i.get("patternInfo") or {}).get("id"),
               " ".join((i.get("lineText") or "").split()))
        seen.add(key)
        if key not in allow:
            unreviewed.append(i)
    return unreviewed, seen


def _unreviewed_table(unreviewed):
    """The summary's lines for the unreviewed issues: a table and the fix hint, or the all-clear."""
    if not unreviewed:
        return ["Nothing unreviewed. :white_check_mark:"]
    lines = ["| file | line | tool | rule | message |", "| --- | --- | --- | --- | --- |"]
    for i in unreviewed:
        pi, ti = i.get("patternInfo") or {}, i.get("toolInfo") or {}
        lines.append("| `%s` | %s | %s | `%s` | %s |"
                     % (i.get("filePath"), i.get("lineNumber"), ti.get("name"),
                        (pi.get("id") or "").split(".")[-1], (i.get("message") or "")[:90]))
    _fix_hint = ("Fix it, or — if it is deliberate — add it to "
                 "`.github/codacy-accepted-errors.json` **with a reason**.")
    return lines + ["", _fix_hint]


def _stale_lines(allow, seen):
    """The summary's lines for accepted entries that no longer match any issue (none if all do)."""
    # An accepted entry that no longer matches anything is dead weight, and a stale allow-list is
    # how a real finding gets waved through later. Say so, without failing the run.
    stale = [k for k in allow if k not in seen]
    if not stale:
        return []
    return (["", "**Accepted entries that no longer match any issue** (remove them):", ""]
            + ["- `%s` / `%s`\n  (was: `%s`)" % (f, p.split(".")[-1], t) for f, p, t in stale])


def _publish(out):
    """Print the summary, and append it to the job summary when the runner provides one."""
    print(out)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(out + "\n")


def main():
    """Compare main's Error-level issues with the accepted list; the exit code is the verdict."""
    allow = _load_allow()

    issues, rc = _fetch_or_exit_code()
    if issues is None:
        return rc

    unreviewed, seen = _split_unreviewed(issues, allow)

    summary = [
        "### Error-level Codacy issues on `main`", "",
        "%d reported · %d accepted · **%d unreviewed**"
        % (len(issues), len(issues) - len(unreviewed), len(unreviewed)), "",
    ]
    summary += _unreviewed_table(unreviewed)
    summary += _stale_lines(allow, seen)

    _publish("\n".join(summary))

    if unreviewed:
        print("::error::main has %d unreviewed Error-level Codacy issue(s) — see the job summary."
              % len(unreviewed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
