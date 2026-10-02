"""Assemble the sections' results into the report, the public summary and the issue body.

Owner: builder B1 (R1 At a glance + Verdicts, R2 issue-body sizing, R3 timing in headings, R7 a
section that could not be read says so, R72 the privacy pass over everything).

R7 is enforced here for every section, whoever wrote it: a section that raised, timed out, or
returned nothing at all (or only '(none)') prints '(could not be read: ...)' in its heading and an
[unread] line in At a glance. It is never left out and never shown as empty.

Everything public passes through privacy.scrub; the issue body is cut from the SCRUBBED summary,
by whole lines, so a URL never carries anything the summary would not.
"""
import re
import time
from urllib.parse import quote

from panel.ops.debug_report._base import LEVELS

# A GitHub new-issue URL is a GET; past about 8 KB of URL, GitHub refuses it. The body is encoded
# into the query string, so the budget is on the WHOLE encoded URL. Python's quote(safe="") encodes
# a superset of what encodeURIComponent does, so a body that fits here fits in the browser too.
ISSUE_URL_MAX = 8000
ISSUE_TITLE = "Debug report"
ISSUE_PROMPT = ("**Describe the problem here** (what you did, what you expected, what happened). "
                "Attach the downloaded debug report for the full detail.\n\n---\n")
REPORT_MAX_CHARS = 60000
GLANCE_MAX_ITEMS = 7          # plus the heading: the block stays at 8 lines or fewer
_ORDER = {lvl: i for i, lvl in enumerate(LEVELS)}
_EMPTY_LINES = frozenset(("", "- (none)", "(none)", "- none", "none"))


def _clean(text):
    """`text` with lone surrogates replaced: encodeURIComponent throws on them (R2)."""
    return text.encode("utf-8", "replace").decode("utf-8")


# ── R7: every section's result is checked, whoever wrote it ────────────────────────────────────
def _valid_finding(f):
    return (isinstance(f, dict) and f.get("level") in LEVELS and isinstance(f.get("area"), str)
            and isinstance(f.get("text"), str))


def _enforce_one(res):
    """(status, Result-or-class) for one section that returned: R7's rules applied."""
    if not all(_valid_finding(f) for f in res.findings):
        return "error", "MalformedFinding"
    if not all(ln.strip() in _EMPTY_LINES for ln in res.lines):
        return "ok", res
    if not res.verdict and not res.findings:
        return "error", "EmptyResult"
    # A body that would read as "nothing there": print what the section found instead.
    res.lines = ["- [%s] %s: %s" % (f["level"], f["area"], f["text"]) for f in res.findings] \
        or res.lines
    return "ok", res


def enforce(results):
    """Results with every empty or malformed section turned into one that could not be read."""
    out = {}
    for key, (status, sec, res) in results.items():
        if status == "ok":
            status, res = _enforce_one(res)
        out[key] = (status, sec, res)
    return out


def _heading(title, status, seconds, detail, deadline):
    if status == "ok":
        return "### %s _(read in %.2f s)_" % (title, seconds)
    if status == "timeout":
        return "### %s _(timed out after the report's %.0f s budget; not shown)_" % (title, deadline)
    return "### %s _(could not be read: %s after %.1f s)_" % (title, detail, seconds)


# ── R1: At a glance and Verdicts ───────────────────────────────────────────────────────────────
def _glance_items(sections, results, extra):
    items = [(f["level"], f["area"], f["text"]) for f in extra if f["level"] != "ok"]
    for key, title, _module, _mode, _part in sections:
        status, _sec, res = results[key]
        if status != "ok":
            items.append(("unread", title, "could not be read" if status == "error"
                          else "timed out"))
            continue
        items.extend((f["level"], f["area"], f["text"]) for f in res.findings if f["level"] != "ok")
    items.sort(key=lambda it: _ORDER.get(it[0], 9))
    return items


def glance(sections, results, extra=()):
    """At a glance: every non-ok finding, fail first, each unread section; 8 lines at most."""
    items = _glance_items(sections, results, list(extra))
    problems = sum(1 for it in items if it[0] in ("fail", "warn"))
    unread = sum(1 for it in items if it[0] == "unread")
    head = "### At a glance: %d problem%s, %d unreadable" % (problems, "" if problems == 1 else "s",
                                                             unread)
    if not items:
        return [head, "- no problems found by any section"]
    shown = items if len(items) <= GLANCE_MAX_ITEMS else items[:GLANCE_MAX_ITEMS - 1]
    lines = [head] + ["- [%s] %s: %s" % it for it in shown]
    if len(shown) < len(items):
        lines.append("- … and %d more in the full report" % (len(items) - len(shown)))
    return lines


def _verdicts(sections, results):
    out = []
    for key, _title, _module, _mode, _part in sections:
        status, _sec, res = results[key]
        if status == "ok" and isinstance(res.verdict, str) and res.verdict:
            out.append("- " + res.verdict)
    return out


# ── R3: the header and the build time ──────────────────────────────────────────────────────────
def _header(ctx, results):
    """(header lines, header findings): the header section's, or a minimal one when it failed."""
    status, _sec, res = results.get("header", ("error", 0.0, "MissingHeader"))
    if status == "ok":
        return list(res.lines), list(res.findings)
    from panel.ops.debug_report._base import finding
    return (["- **Generated**: %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "- **Header**: %s" % ("timed out" if status == "timeout"
                                   else "could not be read (%s)" % res)],
            [finding("unread", "Header", "could not be read" if status == "error" else "timed out")])


def _slowest(sections, results):
    timed = [(results[key][1], title) for key, title, _m, _mode, _p in sections
             if results[key][0] != "timeout"]
    timed.sort(reverse=True)
    return ", ".join("%s %.2f s" % (title, sec) for sec, title in timed[:3])


# ── R2: the issue body ─────────────────────────────────────────────────────────────────────────
def _enc_len(text):
    return len(quote(text.encode("utf-8", "replace"), safe=""))


def issue_body(summary, issues_url, must_keep=0, problems=0):
    """The prompt, then whole summary lines until prefix + encoded body would pass ISSUE_URL_MAX.

    `must_keep`: the number of leading summary lines (header and At a glance) without which a
    prefill is useless; when even those do not fit, the body is the prompt and a problem count.
    """
    prefix = "%s?labels=debug&title=%s&body=" % (issues_url, quote(ISSUE_TITLE, safe=""))
    budget = ISSUE_URL_MAX - len(prefix)
    lines = summary.rstrip("\n").split("\n")
    out, used = ISSUE_PROMPT, _enc_len(ISSUE_PROMPT)
    for i, line in enumerate(lines):
        cost = _enc_len(line + "\n")
        note = "\n_(summary truncated: %d of %d lines; attach the downloaded report)_\n" % (
            i, len(lines))
        if used + cost + _enc_len(note) > budget:
            if i < must_keep:
                return ISSUE_PROMPT + "Problems: %d; see the attached report.\n" % problems
            return out + note
        out += line + "\n"
        used += cost
    return out


# ── the whole report ───────────────────────────────────────────────────────────────────────────
def _cap(report):
    """The report cut at REPORT_MAX_CHARS on a line boundary, an open code fence closed."""
    if len(report) <= REPORT_MAX_CHARS:
        return report
    cut = report[:REPORT_MAX_CHARS]
    cut = cut[:cut.rfind("\n") + 1]
    if cut.count("```") % 2:
        cut += "```\n"
    return cut + "\n_(report cut at %d characters)_\n" % REPORT_MAX_CHARS


def _parts(ctx, sections, results):
    """(summary section lines, full-report section lines) with R3 headings."""
    summary, full = [], []
    for key, title, _module, _mode, part in sections:
        if part == "header":
            continue
        status, sec, res = results[key]
        heading = _heading(title, status, sec, res if status == "error" else None,
                           ctx.deadline - ctx.started)
        if part == "summary":
            shown = (res.summary_lines or res.lines) if status == "ok" else []
            summary += [heading] + shown + [""]
        else:
            full += [heading] + (res.lines if status == "ok" else []) + [""]
    return summary, full


def _glance_or_fallback(sections, results, extra):
    try:
        return glance(sections, results, extra)
    except Exception as exc:  # noqa: BLE001 - R1: fall back, and say so
        return ["### At a glance",
                "- [unread] At a glance: could not be assembled (%s)" % type(exc).__name__]


def _filename(ctx):
    from panel.ops.debug_report import header
    sha = header._running_commit(ctx) or ctx.memo("head_sha", header._head_sha) or "unknown"
    sha = re.sub(r"[^0-9a-f+]", "", sha)[:41] or "unknown"
    return "linuxgsm-panel-debug-%s-%s.md" % (sha, time.strftime("%Y%m%d-%H%M%S"))


def assemble(ctx, results):
    """{report, summary, issue_body, issues_url, filename} from {key: (status, s, Result|cls)}."""
    from panel.ops import system_ops as so
    from panel.ops.debug_report import SECTIONS, privacy
    results = enforce(results)
    head, head_findings = _header(ctx, results)
    head.append("- **Report built in**: %.2f s · slowest: %s"
                % (time.monotonic() - ctx.started, _slowest(SECTIONS, results) or "n/a"))
    privacy.finish(ctx, wait=min(5.0, ctx.remaining() + 2.0))
    glance_lines = _glance_or_fallback(SECTIONS, results, head_findings + privacy.findings(ctx))
    verdicts = _verdicts(SECTIONS, results)
    top = ["## LinuxGSM Panel debug report", ""] + head + [""] + glance_lines + [""]
    must_keep = len(top)
    if verdicts:
        top += ["### Verdicts"] + verdicts + [""]
    summary_secs, full_secs = _parts(ctx, SECTIONS, results)
    summary = "\n".join(top + summary_secs)
    report = summary + "\n" + "\n".join(full_secs)
    summary = _clean(privacy.scrub(ctx, summary))
    report = _cap(_clean(privacy.scrub(ctx, report)))
    if privacy.prepare(ctx).pattern_error:
        summary += "\n- [fail] Privacy: pattern redaction failed; section bodies withheld\n"
    report += "\n" + "\n".join(privacy.footer(ctx)) + (
        "\n\n<!-- Generated by the panel. Review before sharing. -->\n")
    issues_url = so._github_issues_url()
    problems = sum(1 for ln in glance_lines if ln.startswith(("- [fail]", "- [warn]")))
    return {"report": report, "summary": summary,
            "issue_body": _clean(issue_body(summary, issues_url, must_keep, problems)),
            "issues_url": issues_url, "filename": _filename(ctx)}
