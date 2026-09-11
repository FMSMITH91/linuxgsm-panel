#!/usr/bin/env python3
"""Fail when main carries an Error-level Codacy issue that is not on the accepted list.

Run by .github/workflows/codacy-alerts.yml; see the long note at the top of that file for why the
gate exists and why it is scheduled rather than triggered by a push. Runnable by hand too:

    python .github/scripts/codacy_open_errors.py

Exit 0 = clean (or nothing but accepted issues). Exit 1 = something unreviewed is on main.
Exit 0 with a warning = the API could not be reached; an outage at Codacy is not a reason to fail
the build, and the next scheduled run will catch what this one missed.
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


def fetch_errors():
    """Every Error-level issue Codacy currently reports for the default branch.

    Pages through the cursor rather than trusting one response to hold them all — a gate that
    silently reads only the first page reports "clean" the moment the list grows past it."""
    out, cursor = [], None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    token = os.environ.get("CODACY_API_TOKEN")
    if token:
        headers["api-token"] = token
    for _ in range(20):                       # bounded: 20 pages x 100 is far more than plausible
        url = API + ("&cursor=%s" % cursor if cursor else "")
        req = urllib.request.Request(
            url, data=json.dumps({"levels": ["Error"]}).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:   # nosec B310 - constant https host
            page = json.loads(resp.read().decode("utf-8", "replace"))
        out.extend(page.get("data") or [])
        cursor = (page.get("pagination") or {}).get("cursor")
        if not cursor:
            break
    return out


def main():
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
    allow = {(a["filePath"], a["patternId"], " ".join(a["lineText"].split())): a
             for a in accepted}

    try:
        issues = fetch_errors()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print("::warning::could not reach the Codacy API (%s) — not failing the build; the next "
              "scheduled run will re-check." % type(exc).__name__)
        return 0

    unreviewed, seen = [], set()
    for i in issues:
        key = (i.get("filePath"), (i.get("patternInfo") or {}).get("id"),
               " ".join((i.get("lineText") or "").split()))
        seen.add(key)
        if key not in allow:
            unreviewed.append(i)

    summary = [
        "### Error-level Codacy issues on `main`", "",
        "%d reported · %d accepted · **%d unreviewed**"
        % (len(issues), len(issues) - len(unreviewed), len(unreviewed)), "",
    ]
    if unreviewed:
        summary += ["| file | line | tool | rule | message |", "| --- | --- | --- | --- | --- |"]
        for i in unreviewed:
            pi, ti = i.get("patternInfo") or {}, i.get("toolInfo") or {}
            summary.append("| `%s` | %s | %s | `%s` | %s |"
                           % (i.get("filePath"), i.get("lineNumber"), ti.get("name"),
                              (pi.get("id") or "").split(".")[-1], (i.get("message") or "")[:90]))
        summary += ["", "Fix it, or — if it is deliberate — add it to "
                    "`.github/codacy-accepted-errors.json` **with a reason**."]
    else:
        summary.append("Nothing unreviewed. :white_check_mark:")

    # An accepted entry that no longer matches anything is dead weight, and a stale allow-list is
    # how a real finding gets waved through later. Say so, without failing the run.
    stale = [k for k in allow if k not in seen]
    if stale:
        summary += ["", "**Accepted entries that no longer match any issue** (remove them):", ""]
        summary += ["- `%s` / `%s`\n  (was: `%s`)" % (f, p.split(".")[-1], t) for f, p, t in stale]

    out = "\n".join(summary)
    print(out)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(out + "\n")

    if unreviewed:
        print("::error::main has %d unreviewed Error-level Codacy issue(s) — see the job summary."
              % len(unreviewed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
