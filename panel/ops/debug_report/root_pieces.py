"""Debug-report section(s): root_pieces

Owner: builder B2. helper fresh check + privileged-call counters (R25), root-owned pieces vs the commit
they belong to (R27), origin category (R28), host prerequisites (R29).

Nothing here runs anything as root, executes a root-owned file, or writes: the installed pieces
are READ and hashed (system_ops.root_piece_state, shared with the Diagnostics helper check), git
runs as the panel account in its own checkout, and every path is printed as yes/no or by its
basename -- never the directory it lives in, panel.conf's values, or origin's URL.
"""
import os
import re
import shutil
import time

from panel.ops.debug_report._base import Result

_SHA_RE = re.compile(r"^[0-9a-f]{7,40}\Z")
_ORIGIN_TEXT = {
    "canonical-https": "canonical repository, https form: root's pieces refresh from it",
    "canonical-other-form": ("canonical repository in a form install.sh does not accept (ssh, a "
                             "port, another spelling): install.sh treats it as UNTRUSTED and "
                             "withholds the helper, installer, db_maintenance and gamedig on "
                             "every update"),
    "fork": "not the canonical repository (a fork or another host): root's pieces are withheld",
    "unreadable": "unreadable (git failed); install.sh would treat it as untrusted",
}
# The tools install.sh keeps in place (install-update-parity) and the ones the panel runs.
_HOST_TOOLS = ("git", "curl", "wget", "cron", "ufw", "fail2ban-client", "systemd-run", "sudo",
               "node", "npm", "jq")
_HELPER_SECURE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"      # the helper's CHILD_PATH
_RECOVER_LINK = "/usr/local/bin/linuxgsm-panel-recover"


def _so():
    from panel.ops import system_ops as so
    return so


def _hhmm(t):
    return time.strftime("%H:%MZ", time.gmtime(t)) if isinstance(t, (int, float)) else "?"


# ── R25 ───────────────────────────────────────────────────────────────────────────────────────────
def _cached_word(val):
    return {True: "yes", False: "NO", None: "not asked yet"}.get(val, "?")


def _helper_lines(res):
    """On disk now (a fresh stat) beside what this process cached at its first privileged call."""
    so = _so()
    from panel.ops.ssh_manager import _core as smc
    on_disk = smc.helper_on_disk()
    cached = so._HELPER_STATE.get("present")
    if cached is None:
        cached = smc._HELPER_STATE.get("present")
    line = "- **Helper**: on disk now: %s · this process is using it: %s" % (
        "yes" if on_disk else "no", _cached_word(cached))
    if on_disk and cached is False:
        line += " (cached as absent at start; restart the panel)"
        res.find("warn", "Privilege", "helper placed after the panel started; restart the panel")
    res.add(line)


def _priv_counts(snap):
    """({outcome: n}, {path: n}, {outcome: (time, verb)}) from runtime_stats' privileged group."""
    outcomes, via, last = {}, {}, {}
    for key, val in snap.items():
        head, _, tail = str(key).partition("|")
        if head == "via" and isinstance(val, int):
            via[tail] = via.get(tail, 0) + val
        elif head == "last" and isinstance(val, tuple):
            last[tail] = val
        elif tail and isinstance(val, int):
            outcomes[tail] = outcomes.get(tail, 0) + val
    return outcomes, via, last


def _privileged_lines(res):
    from panel.core import runtime_stats as rs
    outcomes, via, last = _priv_counts(rs.snapshot("privileged"))
    if not outcomes:
        res.add("- **Privileged calls since start**: none yet")
        return
    res.add("- **Privileged calls since start**: %s · ok %d · refused by sudo %d · 'unknown verb' "
            "%d · timed out %d · failed %d" % (
                " · ".join("via %s %d" % (p, n) for p, n in sorted(via.items())) or "via ?",
                outcomes.get("ok", 0), outcomes.get("refused", 0),
                outcomes.get("unknown_verb", 0), outcomes.get("timeout", 0),
                outcomes.get("failed", 0)))
    for outcome, label in (("refused", "sudo refusal"), ("timeout", "timeout"),
                           ("unknown_verb", "'unknown verb'")):
        if outcome in last:
            t, verb = last[outcome]
            res.add("- **Last %s**: %s at %s" % (label, verb, _hhmm(t)))
    if outcomes.get("refused"):
        res.find("warn", "Privilege", "privileged calls were refused by sudo since start")
    if outcomes.get("unknown_verb"):
        res.find("warn", "Privilege", "the helper refused verbs this version uses")


# ── R27 ───────────────────────────────────────────────────────────────────────────────────────────
def _older_commit(rel, blob):
    """The newest commits on HEAD's history whose `rel` was `blob`, or a fixed reason."""
    so = _so()
    if so._update_in_progress():
        return "not looked up while an update runs"
    out, _, rc = so._git(["log", "--format=%h", "-n", "2", "--find-object=" + blob, "HEAD",
                          "--", rel], timeout=10)
    shas = [s for s in (out or "").split() if _SHA_RE.match(s)]
    if rc != 0:
        return "history could not be searched"
    return ("matches %s" % shas[0]) if shas else "no commit on this branch has it"


def _piece_line(name, piece, res):
    state = piece.get("state")
    if state == "same":
        return "= HEAD's %s" % piece.get("rel")
    if state == "differs":
        res.find("warn", "Root-owned pieces", "%s differs from this commit" % name)
        return "DIFFERS from HEAD: %s" % _older_commit(piece.get("rel"), piece.get("blob") or "")
    return {"missing": "missing", "unreadable": "unreadable (permission)",
            "unknown": "not compared (git ls-tree failed)"}.get(state, "?")


def _panel_conf_line():
    """Whether root's panel.conf records THIS checkout as panel_dir: yes/no, never its value."""
    so = _so()
    path = os.path.join(so._root_dir(), "panel.conf")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read(65536)
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unreadable (permission)"
    m = re.search(r"(?m)^panel_dir=([^\n]*)", text)
    if not m:
        return "has no panel_dir"
    return "panel_dir is this checkout: %s" % (
        "yes" if so._same_dir(m.group(1).strip(), so.PANEL_DIR) else "NO")


def _read_root_ref(root_git, ref):
    """A ref of root's own clone, as a loose file or a packed-refs line (read, never run)."""
    try:
        with open(os.path.join(root_git, ref), encoding="ascii", errors="replace") as fh:
            val = fh.read(100).strip()
        return val if _SHA_RE.match(val) else None
    except FileNotFoundError:
        pass
    with open(os.path.join(root_git, "packed-refs"), encoding="ascii", errors="replace") as fh:
        for line in fh:
            sha, _, name = line.strip().partition(" ")
            if name == ref and _SHA_RE.match(sha):
                return sha
    return None


def _floor_line():
    """Root's source floor (the newest trusted commit root staged from) and whether HEAD has it."""
    so = _so()
    try:
        with open(os.path.join(so._root_dir(), ".source-floor"), encoding="ascii",
                  errors="replace") as fh:
            floor = fh.read(100).strip().lower()
    except FileNotFoundError:
        return "none recorded"
    except OSError:
        return "unreadable (permission)"
    if not _SHA_RE.match(floor):
        return "not a commit id"
    _, _, rc = so._git(["merge-base", "--is-ancestor", floor, "HEAD"], timeout=10)
    return "%s (HEAD contains it: %s)" % (floor[:7], {0: "yes", 1: "NO"}.get(rc, "unknown"))


def _tip_line():
    so = _so()
    try:
        tip = _read_root_ref(os.path.join(so._root_dir(), ".source.git"), "refs/root-src/tip")
    except FileNotFoundError:
        return "none fetched"
    except OSError:
        return "unreadable (permission)"
    return tip[:7] if tip else "none fetched"


def _launcher_line():
    """What a self-update runs here: _launch_installer's own predicate, never _launch_installer
    (which removes the update log and writes the wrapper)."""
    so = _so()
    if so._is_system_service() and so._helper_present():
        return "the root-owned install.sh via `sudo -n panel-helper panel-self-update`"
    if so._is_system_service():
        return "this checkout's install.sh via `sudo systemd-run` (the pre-helper fallback)"
    return "this checkout's install.sh via `systemd-run --user`"


def _pieces_lines(res):
    so = _so()
    pieces = so.root_piece_state()
    res.add("- **Root-owned pieces**: " + " · ".join(
        "**%s** %s" % (name, _piece_line(name, pieces.get(name) or {}, res))
        for name, _rel in so._ROOT_PIECES))
    from panel.security import privileged as priv
    res.add("- **panel.conf**: %s · **gamedig tree** present: %s · **linuxgsm-panel-recover**: %s"
            % (_panel_conf_line(), "yes" if os.path.isdir(priv.GAMEDIG_DIR) else "no",
               "yes" if os.path.lexists(_RECOVER_LINK) else "no"))
    res.add("- **Root's source floor**: %s · root's fetched tip: %s" % (_floor_line(), _tip_line()))
    res.add("- **A self-update here runs**: %s" % _launcher_line())


# ── R28 ───────────────────────────────────────────────────────────────────────────────────────────
def _origin_lines(res):
    so = _so()
    cat = so.origin_category()
    readable = so._repo_slug() is not None
    res.add("- **Origin**: %s · CI gate can read it: %s" % (
        _ORIGIN_TEXT.get(cat, "?"), "yes" if readable else "NO (every commit is 'unknown')"))
    if cat != "canonical-https":
        res.find("warn", "Origin", "origin is not the repository install.sh trusts (%s)" % cat)


# ── R29 ───────────────────────────────────────────────────────────────────────────────────────────
def _search_path():
    """The PATH the panel's own processes see, plus the helper's and cron's: a tool is missing
    only when it is on none of the paths something here runs it from."""
    from panel.ops.ssh_manager import _core as smc
    parts = []
    for p in (os.environ.get("PATH", ""), _HELPER_SECURE_PATH, smc.CRON_TOOL_PATH):
        parts += [d for d in p.split(os.pathsep) if d and d not in parts]
    return os.pathsep.join(parts)


def _gamedig_present():
    from panel.ops.ssh_manager import _core as smc
    from panel.security import privileged as priv
    tree = os.path.join(priv.GAMEDIG_DIR, "current", "node_modules", ".bin", "gamedig")
    return os.path.exists(tree) or shutil.which("gamedig", path=smc.CRON_TOOL_PATH) is not None


def _tools_lines(res):
    path = _search_path()
    have = [(t, shutil.which(t, path=path) is not None) for t in _HOST_TOOLS]
    have.append(("gamedig", _gamedig_present()))
    res.add("- **Host tools**: " + " ".join("%s %s" % (t, "✓" if ok else "✗") for t, ok in have))
    missing = [t for t, ok in have if not ok]
    if missing:
        res.find("warn", "Host tools", "missing: " + ", ".join(missing))


def section_root_pieces(ctx):
    """Install & privilege, the root-owned half: helper, privileged calls, pieces, origin, tools."""
    res = Result()
    for part in (_helper_lines, _privileged_lines, _pieces_lines, _origin_lines, _tools_lines):
        try:
            part(res)
        except Exception as exc:  # noqa: BLE001 - one line's failure is printed as such
            res.add("- **%s**: could not be read (%s)" % (part.__name__.strip("_").replace(
                "_lines", ""), type(exc).__name__))
            res.find("unread", "Root-owned pieces", "a part could not be read")
    return res
