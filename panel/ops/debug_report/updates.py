"""Debug-report section(s): updates.

Owner: builder B2. cached update status (R30), CI gate detail (R31), tracked branch (R32), last run
outcome (R33), history (R34), installer warnings (R35), redacted self-update log tail.

NOTHING HERE FETCHES. The update status is read from system_ops._update_cache as the last check
left it (never panel_update_status(), which fetches on a cold cache, and never under _update_lock,
which a running check holds across a fetch and up to 25 GitHub requests). The CI detail is what
that check recorded in runtime_stats. Git reads are local, with full ref names and timeouts.

Free text from the self-update log is reduced before it is printed: the origin warning to R28's
category (install.sh prints the URL, which can carry user:token@), a full commit id in the
installer's own messages shortened to 12 characters (a 40-hex id is one "long token"), then the
report's privacy pass: paths normalised FIRST (<data>, <panel-lib>, <gamedig>), URL userinfo and
_redact's secret rules, then names and IP addresses by class. Without the report's ctx (a direct
caller), URL userinfo is stripped, _redact applied and every IPv4 address masked as [ip]. The
assembler's privacy pass runs over it all again.
"""
import datetime as _dt
import os
import re
import time

from panel.ops.debug_report._base import Result, ago, cut_words

_SHA_RE = re.compile(r"^[0-9a-f]{7,40}\Z")
_CI_STATES = ("passing", "pending", "failing", "unknown", "unverified")
_STALE_CACHE_S = 35 * 60
_LINE_MAX = 160
_REASON_MAX = 120
_TAIL_LINES = 25
_HISTORY_MAX = 10
_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15}://)[^/\s]+@")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_ORIGIN_WARN = "[!] This checkout's git origin is"
# The lines of an installer run worth keeping whatever their place in the log (R35): its warnings
# and errors always, and its key lines when the printed tail does not already show them.
_WARN_PREFIXES = ("[!]", "[ERROR]")
_KEEP_PREFIXES = _WARN_PREFIXES + ("✓ sudo grant:", "Keeping ", "Updating to verified commit",
                                   "✓ Code updated (")
# A full commit id in install.sh's own messages (_choose_update_target's 'pin'/'stay'/'hold' lines
# and its warnings), shortened: 40 hex characters are one "long token" to _redact. Anchored to those
# message forms, so a 40-hex value anywhere else is still redacted.
_INSTALLER_SHA_RE = re.compile(r"((?:verified|pinned) commit |^\s*Keeping |stays at |pinned to, |"
                               r"contained by it \()([0-9a-f]{40})(?![0-9a-f])")
_REFLOG_ACTIONS = ("reset", "pull", "checkout", "commit", "merge", "rebase", "clone",
                   "cherry-pick", "fetch", "branch")
# panel_self_update's and panel_switch_branch's messages, as fixed categories chosen IN SQL, so no
# free text (the detail column, the actor's name) ever reaches Python.
_HISTORY_SQL = (
    "SELECT action, success, timestamp, "
    "CASE WHEN user_id IS NOT NULL THEN 'web' WHEN username LIKE 'telegram:%' THEN 'telegram' "
    "WHEN username LIKE 'discord:%' THEN 'discord' ELSE 'system' END, "
    "CASE WHEN detail LIKE 'Update started%' THEN 'started' "
    "WHEN detail LIKE 'Switching to%' THEN 'switch started' "
    "WHEN detail LIKE 'This update is blocked%' THEN 'refused: checks failed' "
    "WHEN detail LIKE 'This update is still being verified%' THEN 'refused: still being verified' "
    "WHEN detail LIKE 'The panel is already up to date%' THEN 'refused: already up to date' "
    "WHEN detail LIKE 'Could not start the updater%' THEN 'launcher failed' "
    "WHEN detail LIKE 'Couldn''t check the update%' THEN 'refused: status check failed' "
    "ELSE NULL END "
    "FROM audit_log WHERE action IN ('panel_self_update', 'panel_switch_branch') "
    "ORDER BY timestamp DESC LIMIT 10")


def _so():
    from panel.ops import system_ops as so
    return so


def _utc(t):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else "?"


def _sha7(val):
    val = str(val or "").strip().lower()
    return val[:7] if _SHA_RE.match(val) else "?"


def clean_line(line, category="unreadable", ctx=None):
    """One line of installer or git output, safe to print: see the module docstring.

    With the report's ctx it goes through the privacy pass BEFORE it is cut: a name cut in half is
    a fragment the final pass cannot match.
    """
    so = _so()
    text = str(line or "")
    if text.startswith(_ORIGIN_WARN):
        return ("[!] This checkout's git origin is not the repository install.sh trusts (%s)"
                % category)
    text = _INSTALLER_SHA_RE.sub(lambda m: m.group(1) + m.group(2)[:12], text)
    if ctx is None:
        text = so._redact(_USERINFO_RE.sub(r"\1[userinfo]@", text))
        return cut_words(_IPV4_RE.sub("[ip]", text), _LINE_MAX)
    from panel.ops.debug_report import privacy
    return cut_words(privacy.scrub_early(ctx, text), _LINE_MAX)


# ── R30: the cached status ────────────────────────────────────────────────────────────────────────
def _fetch_age():
    so = _so()
    try:
        return time.time() - os.stat(os.path.join(so.PANEL_DIR, ".git", "FETCH_HEAD")).st_mtime
    except OSError:
        return None


def _rules_line():
    so = _so()
    rules = so._local_update_rules()
    if not rules:
        return "UNREADABLE (every change counts as runtime)"
    return "parsed, %d runtime / %d noise" % (len(rules.get("runtime") or []),
                                              len(rules.get("noise") or []))


def _announced():
    """The commit the last 'update available' notification named; 'none' when unset or ''.

    The update check writes "" once the announced update is installed, so "none" is the usual
    resting state; '?' is kept for a value that is there but is not a commit id.
    """
    from panel.core import config as cfg
    try:
        val = cfg.load_config().get("panel_update_announced")
        return _sha7(val) if val else "none"
    except Exception as exc:  # noqa: BLE001
        return "could not be read (%s)" % type(exc).__name__


def _remote_words(data, branch):
    """'origin/main 3af77a4', or the offered commit named as such.

    On the update-available path the status's remote_sha is the OFFERED commit (target_sha[:7]),
    which is below origin's tip while newer commits are still being verified.
    """
    remote = _sha7(data.get("remote_sha"))
    target = data.get("target_sha")
    if not (data.get("update_available") and target and remote == _sha7(target)):
        return "origin/%s %s" % (branch, remote)
    newer = data.get("newer_unverified")
    if newer == 0:
        return "offered %s (origin/%s's tip)" % (remote, branch)
    if isinstance(newer, int):
        return "offered %s (%d newer on origin/%s, not yet verified)" % (remote, newer, branch)
    return "offered %s" % remote


def _gate_words(data, branch, ci):
    """The CI gate line's text: what the check asked CI, or why it asked nothing."""
    behind = data.get("behind_tip", data.get("behind"))
    if not data.get("target_sha"):
        if behind == 0:
            return ("not consulted: HEAD is not behind origin/%s, nothing newer to verify"
                    % branch)
        return "not consulted (the check did not get that far)"
    unverified = not data.get("update_available") and data.get("ci_state") != "passing"
    newer = data.get("newer_unverified")
    docs = data.get("docs_only")
    return "ci_state=%s · %s %s · newer_unverified %s · docs_only: %s" % (
        ci, "newest unverified tip" if unverified else "target", _sha7(data.get("target_sha")),
        "n/a" if newer is None else newer, "n/a" if docs is None else ("yes" if docs else "no"))


def _status_lines(data, res):
    so = _so()
    branch = data.get("branch") if so._valid_branch(data.get("branch")) else "?"
    ci = data.get("ci_state") if data.get("ci_state") in _CI_STATES else "n/a"
    res.add("- **Card shows**: %s (update_available: %s)" % (
        "Update available" if data.get("update_available") else "You're up to date",
        "yes" if data.get("update_available") else "no"))
    res.add("- **Tracked**: %s · HEAD %s · %s · behind %s (first parent)" % (
        branch, _sha7(data.get("current_sha")), _remote_words(data, branch),
        data.get("behind_tip", data.get("behind", "?"))))
    res.add("- **CI gate**: " + _gate_words(data, branch, ci))
    if data.get("fetched") is False:
        res.add("- **Fetch**: the last check could not fetch the update source")
        res.find("warn", "Updates", "the last update check could not fetch")


def _cache_lines(res):
    """R30: the status as the last check computed it, with no new check."""
    so = _so()
    data, ts = so._update_cache.get("data"), so._update_cache.get("ts") or 0
    if not data:
        from panel.ops.debug_report import workers
        res.add("- **Card shows**: (not computed since the panel started; update check: %s)"
                % workers.first_pass_words("update-check", time.time()))
        return None
    age = time.time() - ts
    _status_lines(data, res)
    stale = ""
    if age > _STALE_CACHE_S:
        stale = " · older than the 30-min check interval: the update-check thread may be stuck"
        res.find("warn", "Updates", "the update check has not run for over 35 minutes")
    res.add("- **Checked**: %s ago · last fetch (FETCH_HEAD mtime) %s ago · update in progress: "
            "%s%s" % (ago(age), ago(_fetch_age()), "yes" if so._update_in_progress() else "no",
                      stale))
    res.add("- **update-paths.txt**: %s" % _rules_line())
    res.add("- **Last 'update available' notification**: %s" % _announced())
    return data


# ── R31: what the CI gate recorded ────────────────────────────────────────────────────────────────
def _names(vals):
    return ", ".join("'%s'" % v for v in vals) if vals else "none"


def _walked(snap, walk):
    """[(sha7, state, entry)] of the commits this walk asked about, in walk order."""
    out = []
    for sha in walk.get("commits") or []:
        ent = snap.get(sha)
        if isinstance(ent, tuple) and ent[0] >= (walk.get("started") or 0) - 1:
            out.append((sha, (ent[1] or {}).get("state"), ent[1] or {}))
    return out


def _walk_lines(snap, res):
    walk_ent = snap.get("walk")
    if not isinstance(walk_ent, tuple):
        res.add("- **CI gate detail**: (no CI detail recorded: not behind, a non-default branch, "
                "or not checked since start)")
        return
    t, walk = walk_ent
    walked = _walked(snap, walk)
    res.add("- **Walked** (%s ago): %s → %s" % (
        ago(time.time() - t), " · ".join("%s %s" % (s, st) for s, st, _e in walked) or "nothing",
        ("offered %s" % walk["offered"]) if walk.get("offered") else "nothing offered"))
    held = next(((s, e) for s, st, e in walked if st != "passing"), None)
    if held:
        s, e = held
        res.add("- **Held by**: %s %s: failing %s · pending %s · required but absent %s" % (
            s, e.get("state"), _names(e.get("failing")), _names(e.get("pending")),
            _names(e.get("absent"))))


def _rate_lines(snap, res):
    ent = snap.get("ratelimit")
    if not isinstance(ent, tuple):
        res.add("- **GitHub checks API**: not asked since start")
        return
    t, r = ent
    limited = r.get("code") in (403, 429) or r.get("remaining") == 0
    res.add("- **GitHub checks API**: last answer HTTP %s at %s · remaining %s/%s, resets %s%s" % (
        r.get("code") or "?", time.strftime("%H:%MZ", time.gmtime(t)),
        "?" if r.get("remaining") is None else r.get("remaining"),
        "?" if r.get("limit") is None else r.get("limit"),
        time.strftime("%H:%MZ", time.gmtime(r["reset"])) if r.get("reset") else "?",
        " → 'pending' here is the rate limit, not CI" if limited else ""))
    if limited:
        res.find("warn", "Updates", "GitHub's API rate limit is holding the CI gate at pending")


def _bot_line(res):
    from panel.services.bots import commands
    spent = list(getattr(commands._UPDATE_GATE, "_spent", ()))
    now = time.monotonic()
    used = sum(1 for t in spent if now - t < commands._BOT_CHECK_WINDOW)
    res.add("- **Chat-bot forced checks this hour**: %d/%d"
            % (used, commands._BOT_FORCED_CHECKS_PER_HOUR))


def _ci_lines(res):
    from panel.core import runtime_stats as rs
    snap = rs.snapshot("ci_walk")
    _walk_lines(snap, res)
    _rate_lines(snap, res)
    _bot_line(res)


# ── R32: the tracked branch and the checkout ─────────────────────────────────────────────────────
def _branch_config_line(res):
    so = _so()
    from panel.core import config as cfg
    raw = cfg.load_config().get("panel_branch")
    if not raw:
        return "main (panel_branch unset, so the default)"
    raw = str(raw)
    if not so._valid_branch(raw):
        res.find("warn", "Updates", "the configured branch is invalid, so main is used")
        return "config value is invalid (%d characters), so main is used" % len(raw)
    if raw.strip() == so._DEFAULT_BRANCH:
        return "main"
    return "'%s' (opt-in test branch: updates are NOT CI-gated)" % raw.strip()


def _on_branch(head, ref):
    """Where HEAD stands against the fetched branch: full refs, no fetch."""
    so = _so()
    _, _, rc = so._git(["merge-base", "--is-ancestor", "HEAD", ref], timeout=10)
    if rc == 1:
        return "NOT on the tracked branch"
    if rc != 0:
        return "unknown (no fetched %s)" % ref
    out, _, frc = so._git(["rev-list", "--first-parent", "--max-count=500", ref], timeout=10)
    if frc != 0:
        return "an ancestor (first-parent line not read)"
    return "on its first-parent line" if head in out.split() else "an ancestor only (not first-parent)"


def _checkout_state():
    so = _so()
    integ = so.panel_integrity()
    if not integ.get("verified"):
        return "not verified"
    return "clean" if integ.get("clean") else "%d tracked file(s) modified (see File integrity)" \
        % integ.get("count", 0)


def _checkout_lines(res):
    so = _so()
    res.add("- **Tracked branch**: %s" % _branch_config_line(res))
    if so._update_in_progress():
        res.add("- **Checkout**: not read while an update runs (install.sh is moving its refs)")
        return
    head, _, rc = so._git(["rev-parse", "HEAD"], timeout=10)
    head = (head or "").strip()
    if rc != 0 or not _SHA_RE.match(head):
        res.add("- **Checkout**: (git failed)")
        res.find("unread", "Updates", "the checkout could not be read")
        return
    shallow, _, src = so._git(["rev-parse", "--is-shallow-repository"], timeout=10)
    res.add("- **Checkout**: HEAD %s, %s · shallow: %s" % (
        head[:7], _checkout_state(), (shallow or "").strip() if src == 0 else "unknown"))
    branch = so._tracked_branch()
    where = _on_branch(head, so._REMOTE_TRACKING + branch)
    res.add("- **HEAD vs origin/%s (last fetch)**: %s" % (branch, where))
    if where.startswith("NOT"):
        res.find("warn", "Updates", "the checkout is not on the tracked branch")


# ── R33: the last run ─────────────────────────────────────────────────────────────────────────────
def _failed_outcome(upd, text, category, ctx=None):
    code = upd.get("exit_code")
    if code == 124:
        return "FAILED — the installer was stopped after 30 minutes (exit 124)" + (
            ", even though 'Health check passed' was logged" if "Health check passed" in text
            else "")
    if "could not confirm health" in text:
        return ("FAILED — update broke health AND the automatic rollback couldn't confirm health "
                "(exit %s)" % code)
    if "failed its health check and was rolled back" in text or "Rolling back" in text:
        return ("FAILED — update failed its health check and was rolled back to the previous "
                "version (exit %s)" % code)
    return "FAILED — the installer stopped (exit %s): %s" % (
        code, cut_words(clean_line(upd.get("reason") or "see the log below", category, ctx),
                        _REASON_MAX))


def _ok_outcome(upd, lines, category, ctx=None):
    outcome = upd.get("outcome")
    if outcome == "held":
        return "NOT UPDATED — " + cut_words(clean_line(upd.get("reason"), category, ctx),
                                            _REASON_MAX)
    if outcome == "current":
        return "nothing to install — " + cut_words(clean_line(upd.get("reason"), category, ctx),
                                                   _REASON_MAX)
    if any("Rolling back" in ln for ln in lines):
        return "ROLLED BACK? exit 0, but the log says the update was rolled back"
    done = next((ln for ln in reversed(lines) if ln.startswith("✓ Update complete")), "")
    return "succeeded" + (" — " + cut_words(clean_line(done[2:], category, ctx), _REASON_MAX) if done else
                          " (exit 0: the run went through the restart)")


def run_outcome(upd, mtime, category="unreadable", now=None, ctx=None):
    """(level, outcome text) for a self-update log: the EXIT STATUS first, text markers second.

    A log with no exit line that stopped being written _UPDATE_STALE_LOG ago is a run that DIED.
    """
    so = _so()
    lines = upd.get("lines") or []
    if upd.get("exit_code") is None:
        if mtime and ((now or time.time()) - mtime) > so._UPDATE_STALE_LOG:
            return "fail", ("DIED — the log stopped at %s with no exit line (a reboot or kill "
                            "mid-update); check the snapshot in data/.backups" % _utc(mtime))
        return "ok", "running (no exit line yet)"
    if upd.get("exit_code") != 0:
        return "fail", _failed_outcome(upd, "\n".join(lines), category, ctx)
    return "ok", _ok_outcome(upd, lines, category, ctx)


def _log_mtime():
    so = _so()
    try:
        return os.stat(so._update_log_path()).st_mtime
    except OSError:
        return None


def _last_run_lines(res, category, ctx=None):
    so = _so()
    upd = so.panel_update_log()
    if not upd.get("exists"):
        res.add("- **Last run**: no self-update log (updates run over SSH or by deploy do not "
                "write one; see Update history)")
        return None, "none"
    mtime = _log_mtime()
    level, text = run_outcome(upd, mtime, category, ctx=ctx)
    res.add("- **Last run**: %s (log mtime; %s ago) · exit %s" % (
        _utc(mtime), ago(time.time() - mtime) if mtime else "?",
        "none" if upd.get("exit_code") is None else upd.get("exit_code")))
    res.add("- **Outcome**: %s" % text)
    if level == "fail":
        res.find("fail", "Updates", "the last self-update DIED mid-run" if text.startswith("DIED")
                 else "the last self-update FAILED")
    return upd, text.split(" ", 1)[0]


# ── R35: installer warnings, from the tail already read ──────────────────────────────────────────
def installer_said(lines, category="unreadable", ctx=None, shown_from=None):
    """The warning, error and grant lines of a run (with an [ERROR]'s continuation lines).

    `shown_from`: the index from which the report prints the log's own tail. A key line that is
    not a warning (the grant, 'Keeping', 'Updating to verified commit', 'Code updated') is left
    out from there on: the tail already shows it. A warning is always kept.
    """
    out, in_error = [], False
    for i, ln in enumerate(lines):
        s = ln.strip()
        if in_error and ln[:1].isspace() and s:
            out.append("  " + clean_line(s, category, ctx))
            continue
        in_error = s.startswith("[ERROR]")
        shown = shown_from is not None and i >= shown_from
        if s.startswith(_WARN_PREFIXES) or (s.startswith(_KEEP_PREFIXES) and not shown):
            out.append(clean_line(s, category, ctx))
    return out[-20:]


def _tail_lines(res, upd, category, ctx=None):
    """The installer's warnings, then the log's last lines, each reduced by clean_line.

    `res` first: _guard calls fn(res, *args).
    """
    lines = upd.get("lines") or []
    said = installer_said(lines, category, ctx, shown_from=max(0, len(lines) - _TAIL_LINES))
    res.add("- **Installer said**:" + ("" if said else " (no warnings)"))
    res.lines += ["  " + ln for ln in said]
    # a log line of three backticks would close the fence early
    tail = [clean_line(ln, category, ctx).replace("`" * 3, "'" * 3) for ln in
            lines[-_TAIL_LINES:]]
    res.add("```")
    res.lines += tail or ["(empty)"]
    res.add("```")


# ── R34: history ──────────────────────────────────────────────────────────────────────────────────
def _audit_epoch(ts):
    try:
        return _dt.datetime.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=_dt.timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def _audit_history():
    """[(epoch, text, is_launch)] for the panel's own update launches, or a fixed reason."""
    from panel.ops.debug_report import _src_db
    rows = _src_db.run_ro({"h": (_HISTORY_SQL, ())}).get("h")
    if isinstance(rows, str):
        return rows
    out = []
    for action, success, ts, origin, what in rows:
        t = _audit_epoch(ts)
        verb = "self-update" if action == "panel_self_update" else "branch switch"
        out.append((t, "%s · %s · %s%s" % (verb, origin, "ok" if success else "REFUSED",
                                            (" (%s)" % what) if what else " (detail withheld)"),
                    bool(success)))
    return out


def _reflog_history():
    """[(epoch, text, keyword)] of HEAD's moves: sha and the action keyword, never the subject."""
    so = _so()
    out, _, rc = so._git(["log", "-g", "-n", "15", "--date=unix", "--format=%h%x09%gd%x09%gs",
                          "HEAD"], timeout=5)
    if rc != 0:
        return "error:git"
    rows = []
    for line in (out or "").splitlines():
        sha, _, rest = line.partition("\t")
        selector, _, subject = rest.partition("\t")
        m = re.search(r"@\{(\d+)\}", selector)
        word = re.match(r"([a-z-]+)", subject or "")
        kw = word.group(1) if word and word.group(1) in _REFLOG_ACTIONS else "other"
        rows.append((int(m.group(1)) if m else None, "HEAD %s → %s (git reflog)" % (kw, _sha7(sha)),
                     kw))
    return rows


def _outside_note(t, launches):
    """' → updated outside the panel' for a HEAD move with no panel launch in the 2 h before it."""
    if t is None or any(lt is not None and 0 <= t - lt <= 7200 for lt in launches):
        return ""
    return " · no panel launch near it → updated outside the panel (deploy, or install.sh over SSH)"


def _history_rows(audit, reflog):
    launches = [t for t, _x, ok in audit if ok] if isinstance(audit, list) else []
    rows = [(t, text) for t, text, _ok in audit] if isinstance(audit, list) else []
    for t, text, kw in (reflog if isinstance(reflog, list) else []):
        rows.append((t, text + (_outside_note(t, launches) if kw in ("reset", "pull") else "")))
    rows.sort(key=lambda r: r[0] or 0, reverse=True)
    return rows[:_HISTORY_MAX]


def _pending_bots():
    from panel.core import config as cfg
    c = cfg.load_config()
    return [b for b in ("telegram", "discord") if c.get("%s_pending_update" % b)]


def _history_lines(res):
    audit, reflog = _audit_history(), _reflog_history()
    res.add("- **Update history** (newest first, UTC):")
    if isinstance(audit, str):
        res.add("  - audit log: could not be read (%s)" % audit.split(":", 1)[-1])
    if isinstance(reflog, str):
        res.add("  - git reflog: could not be read")
    rows = _history_rows(audit, reflog)
    res.lines += ["  - %s  %s" % (_utc(t)[:-4] if t else "?", text) for t, text in rows]
    if not rows and not isinstance(audit, str) and not isinstance(reflog, str):
        res.add("  - none recorded")
    pending = _pending_bots()
    if pending:
        res.add("  - pending bot report: %s" % ", ".join(pending))
    res.add("  - _a rolled-back update restores .git from its snapshot, so its reflog entry is "
            "gone; the snapshot (under Panel backups) is the record_")


def _guard(res, fn, *args):
    try:
        return fn(res, *args)
    except Exception as exc:  # noqa: BLE001 - one part's failure is printed as such
        res.add("- **%s**: could not be read (%s)" % (fn.__name__.strip("_"), type(exc).__name__))
        res.find("unread", "Updates", "a part of the update state could not be read")
        return None


def _verdict(data, run_word):
    if data is None:
        card = "not checked since start"
    else:
        card = "update available" if data.get("update_available") else "up to date"
    return "Update: card says %s · last self-update: %s" % (card, {
        "FAILED": "FAILED", "DIED": "DIED mid-run", "NOT": "held", "nothing": "nothing to install",
        "succeeded": "succeeded", "ROLLED": "rolled back?", "running": "running",
        "none": "no log"}.get(run_word, "unknown"))


def section_updates(ctx):
    """Updates: the cached status, the CI gate's record, the branch, the last run and history."""
    so = _so()
    res = Result()
    try:
        category = so.origin_category()
    except Exception:  # noqa: BLE001
        category = "unreadable"
    data = _guard(res, _cache_lines)
    _guard(res, _ci_lines)
    _guard(res, _checkout_lines)
    run = _guard(res, _last_run_lines, category, ctx) or (None, "unknown")
    if run[0] is not None:
        _guard(res, _tail_lines, run[0], category, ctx)
    _guard(res, _history_lines)
    res.verdict = _verdict(data, run[1])
    return res
