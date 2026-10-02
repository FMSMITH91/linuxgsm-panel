"""Debug-report header (a worker section) and the Dependencies section.

Owner: builder B1.
section_header: generated time (R3), panel version, the commit this PROCESS runs vs the checkout's
HEAD with RESTART PENDING and the tracked branch (R4, R32's one header token), OS / kernel /
Python, host clock zone + NTP + locale (R5). The assembler puts its lines at the top of the report
and its findings in At a glance.
header_lines(ctx): the same lines, for a caller outside the runner.
section_dependencies: requirements.txt pins vs installed vs loaded (R64).
"""
import os
import re
import sys
import time

from panel.ops.debug_report._base import Result, ago

_MODULE_STAT_CAP = 400
_LOCALE_KEYS = ("LANG", "LC_ALL", "LC_MESSAGES", "TZ")
_LOCALE_VALUE_RE = re.compile(r"[\w.@:+/-]{1,64}\Z")
_FALLBACK_DEPS = ("flask", "flask-socketio", "python-socketio", "paramiko", "sqlalchemy",
                  "cryptography", "eventlet")
# Modules whose loaded __version__ is compared with the version on disk, and their distributions.
_LOADED = (("eventlet", "eventlet"), ("greenlet", "greenlet"), ("sqlalchemy", "sqlalchemy"),
           ("paramiko", "paramiko"), ("cryptography", "cryptography"),
           ("engineio", "python-engineio"), ("socketio", "python-socketio"))
_PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]{0,100})(?:\[[^\]]{0,200}\])?==([^\s;\\]{1,64})"
                     r"[ \t]*(?:;([^\\#\n]{1,300}))?")


# ── process start and commits (R4) ──────────────────────────────────────────────────────────────
def _process_start():
    """The start of this process as a Unix time, from /proc/self/stat and /proc/stat, or None."""
    try:
        with open("/proc/self/stat", encoding="ascii", errors="replace") as f:
            stat = f.read()
        ticks = int(stat[stat.rindex(")") + 2:].split()[19])
        with open("/proc/stat", encoding="ascii", errors="replace") as f:
            btime = next(int(ln.split()[1]) for ln in f if ln.startswith("btime "))
        return btime + ticks / float(os.sysconf("SC_CLK_TCK"))
    except (OSError, ValueError, IndexError, StopIteration):
        return None


def _changed_modules(started):
    """Repo-relative paths of loaded panel modules modified on disk after `started` (capped)."""
    from panel.ops import system_ops as so
    root = os.path.realpath(so.PANEL_DIR) + os.sep
    changed, stats = [], 0
    for mod in list(sys.modules.values()):
        path = getattr(mod, "__file__", None)
        if not path or stats >= _MODULE_STAT_CAP:
            continue
        real = os.path.realpath(path)
        if not real.startswith(root) or os.sep + ".venv" + os.sep in real:
            continue
        stats += 1
        try:
            if os.stat(real).st_mtime > started:
                changed.append(real[len(root):])
        except OSError:
            continue
    return sorted(changed)


def _head_sha():
    from panel.ops import system_ops as so
    if not so._is_git_checkout():
        return None
    out, _, rc = so._git(["rev-parse", "--short", "HEAD"], timeout=5)
    out = (out or "").strip()
    return out if rc == 0 and re.fullmatch(r"[0-9a-f]{4,40}", out) else None


def _running_commit(ctx):
    """The commit this process loaded at start (app.config PANEL_COMMIT), or None."""
    app = ctx.app
    val = app.config.get("PANEL_COMMIT") if app is not None else None
    return val if isinstance(val, str) and re.fullmatch(r"[0-9a-f]{4,40}\+?", val) else None


def _branch():
    from panel.ops import system_ops as so
    try:
        return so._tracked_branch()
    except Exception as exc:  # noqa: BLE001 - said, never guessed
        return "unreadable (%s)" % type(exc).__name__


def _start_text(started):
    if not started:
        return "process start unreadable"
    return "%s, up %s" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
                          ago(time.time() - started))


def _restart_pending(res, running, head, started):
    changed = _changed_modules(started) if started else []
    listed = ""
    if changed:
        listed = " (%s%s)" % (", ".join(changed[:5]), ", …" if len(changed) > 5 else "")
    res.add("- **RESTART PENDING**: this process runs %s; the checkout is at %s; %d loaded "
            "module(s) changed on disk since start%s" % (running, head, len(changed), listed))
    res.find("warn", "Panel process", "restart pending: the running code is not the checkout")


def _commit_lines(ctx, res):
    running, head = _running_commit(ctx), ctx.memo("head_sha", _head_sha)
    started = _process_start()
    known = bool(running and head)
    res.add("- **Running commit**: %s (loaded at start, %s) · **Checkout HEAD**: %s%s · "
            "**Tracked branch**: %s" % (
                running or "unknown", _start_text(started),
                head or "unknown (not a git checkout, or git failed)",
                ", same" if known and running.rstrip("+") == head else "", _branch()))
    if known and running.rstrip("+") != head:
        _restart_pending(res, running, head, started)


# ── clock and locale (R5) ───────────────────────────────────────────────────────────────────────
def _zone_name():
    """The host's zone name from /etc/timezone or the /etc/localtime link; None if unreadable."""
    try:
        with open("/etc/timezone", encoding="utf-8") as f:
            name = f.read(128).strip()
        if re.fullmatch(r"[\w+/-]{1,64}", name):
            return name
    except OSError:
        pass                                 # not every distribution has it; try the link
    try:
        target = os.readlink("/etc/localtime")
    except OSError:
        return None
    m = re.search(r"zoneinfo/([\w+/-]{1,64})\Z", target)
    return m.group(1) if m else None


def _ntp(ctx):
    from panel.ops import system_ops as so
    out, _, rc = so._debug_run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                               timeout=min(3.0, max(0.5, ctx.remaining())))
    val = (out or "").strip().lower()
    if rc == 0 and val in ("yes", "no"):
        return val
    return None


def _locale():
    parts = []
    for key in _LOCALE_KEYS:
        val = os.environ.get(key)
        if val is None:
            parts.append("%s unset" % key)
        else:
            parts.append("%s=%s" % (key, val if _LOCALE_VALUE_RE.match(val) else "(set, unusual)"))
    return " · ".join(parts)


def _clock_lines(ctx, res):
    zone, ntp = _zone_name(), _ntp(ctx)
    res.add("- **Host clock**: %s (%s) · NTP synchronized: %s · journal times below are host-local"
            % (zone or "timezone unreadable", time.strftime("UTC%z"),
               ntp if ntp else "NTP state unknown"))
    res.add("- **Locale**: %s · filesystem encoding %s" % (_locale(), sys.getfilesystemencoding()))
    if ntp == "no":
        res.find("warn", "Host clock", "NTP is not synchronized (2FA codes and log times drift)")


def section_header(ctx):
    """The report's header lines (a worker: it runs git, timedatectl and /proc reads)."""
    from panel.ops import system_ops as so
    res = Result()
    res.add("- **Generated**: %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    try:
        res.add("- **Panel version**: %s" % so.panel_version())
    except Exception as exc:  # noqa: BLE001
        res.add("- **Panel version**: could not be read (%s)" % type(exc).__name__)
    _commit_lines(ctx, res)
    res.add("- **OS**: %s" % so._debug_os_name())
    res.add("- **Kernel**: %s" % (os.uname().release if hasattr(os, "uname") else "unknown"))
    res.add("- **Python**: %d.%d.%d" % sys.version_info[:3])
    _clock_lines(ctx, res)
    return res


def header_lines(ctx):
    """The header's lines (section_header's), for a caller outside the runner."""
    return section_header(ctx).lines


# ── Dependencies (R64) ──────────────────────────────────────────────────────────────────────────
def _norm_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _dist_entry(dist):
    """(normalised name, version) of one distribution, or None when its metadata is unreadable."""
    try:
        return _norm_name(dist.metadata["Name"] or ""), dist.version
    except Exception:  # noqa: BLE001 - one broken metadata file is one missing entry
        return None


def _installed():
    """{normalised distribution name: version}, from ONE pass over the installed distributions."""
    from importlib import metadata
    out = {}
    for entry in filter(None, map(_dist_entry, metadata.distributions())):
        out.setdefault(*entry)
    return out


def _pins():
    """[(name, locked version, marker or None)] from the checkout's requirements.txt."""
    from panel.ops import system_ops as so
    with open(os.path.join(so.PANEL_DIR, "requirements.txt"), encoding="utf-8") as f:
        text = f.read(1 << 20)
    pins = []
    for line in text.splitlines():
        m = _PIN_RE.match(line.strip())
        if m:
            pins.append((m.group(1), m.group(2), (m.group(3) or "").strip() or None))
    if not pins:
        raise ValueError("no pins")
    return pins


def _marker_applies(marker):
    """True / False for an environment marker; None when it cannot be evaluated here."""
    if not marker:
        return True
    try:
        from packaging.markers import Marker
        return bool(Marker(marker).evaluate())
    except Exception:  # noqa: BLE001 - packaging missing or the marker malformed: say so
        return None


def _compare(pins, installed):
    match, differ, missing, skipped, unknown = 0, [], [], 0, []
    for name, locked, marker in pins:
        applies = _marker_applies(marker)
        if applies is False:
            skipped += 1
            continue
        have = installed.get(_norm_name(name))
        if applies is None:
            unknown.append(name)
        elif have is None:
            missing.append("%s (lock %s)" % (name, locked))
        elif have != locked:
            differ.append("%s %s installed, lock %s" % (name, have, locked))
        else:
            match += 1
    return match, differ, missing, skipped, unknown


def _lock_lines(res, installed):
    pins = _pins()
    match, differ, missing, skipped, unknown = _compare(pins, installed)
    required = len(pins) - skipped
    res.add("- %d/%d match the lockfile (requirements.txt)%s" % (
        match, required, "; %d not required here (environment marker)" % skipped if skipped else ""))
    if differ:
        res.add("- **%d differ**: %s" % (len(differ), " · ".join(differ)))
    if missing:
        res.add("- **%d missing**: %s" % (len(missing), " · ".join(missing)))
    if unknown:
        res.add("- marker not evaluated here: %s" % ", ".join(unknown))
    if differ or missing:
        res.find("warn", "Dependencies", "%d package(s) differ from the lockfile, %d missing"
                 % (len(differ), len(missing)))


def _fallback_lines(res, installed, exc):
    res.add("- lockfile comparison unavailable: requirements.txt not readable (%s)"
            % type(exc).__name__)
    for pkg in _FALLBACK_DEPS:
        res.add("- **%s**: %s" % (pkg, installed.get(_norm_name(pkg)) or "not installed"))


def _loaded_lines(res, installed):
    drift, compared = [], 0
    for mod, dist in _LOADED:
        loaded = getattr(sys.modules.get(mod), "__version__", None)
        disk = installed.get(_norm_name(dist))
        if not isinstance(loaded, str) or not disk:
            continue
        compared += 1
        if loaded != disk:
            drift.append("%s loaded %s, on disk %s" % (mod, loaded, disk))
    if drift:
        res.add("- **loaded ≠ on disk** (pip ran after start, restart pending): %s"
                % " · ".join(drift))
        res.find("warn", "Dependencies", "loaded package versions differ from disk (restart pending)")
    else:
        res.add("- loaded = on disk for the %d loaded modules that report a version" % compared)


def section_dependencies(ctx):
    """requirements.txt pins vs what is installed, and what is loaded vs what is on disk."""
    res = Result()
    installed = _installed()
    try:
        _lock_lines(res, installed)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        _fallback_lines(res, installed, exc)
    _loaded_lines(res, installed)
    return res
