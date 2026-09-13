"""LinuxGSM's own data files — fetched and cached, not vendored.

`serverlist.csv` (every game LinuxGSM supports) and `ubuntu-24.04.csv` (the apt packages each game
needs) belong to LinuxGSM, not to this panel. They used to be committed here, which froze the
panel's game list at whatever LinuxGSM shipped on the day the copy was taken: by the time this
replaced them the bundled list was already two games behind upstream, and the only way to add a
newly-supported game was a panel release.

They are fetched from LinuxGSM's repository instead and cached under `data/`, which is writable,
git-ignored and survives an update. Nothing here raises: a caller that cannot get the data gets an
empty result and `status()` explains why, so the UI can say so instead of rendering an empty menu.

On the offline case, deliberately: a host that cannot reach GitHub cannot install a game server
either — SteamCMD fetches the game itself — so a panel that cannot refresh this list is already
unable to do the thing the list is for. That is what makes a network-backed list acceptable where
a network-backed *config* would not be.
"""
import csv
import io
import os
import threading
import time
import urllib.request
from pathlib import Path

# LinuxGSM's canonical copies. Fixed host, fixed paths — nothing here is caller-supplied.
_BASE = "https://raw.githubusercontent.com/GameServerManagers/LinuxGSM/master/lgsm/data/"
SERVERLIST = "serverlist.csv"
# LinuxGSM ships a package list PER DISTRO RELEASE — ubuntu-22.04.csv, ubuntu-26.04.csv,
# debian-12.csv, rocky-9.csv and twenty more. This is only the fallback for a host whose own file
# LinuxGSM does not publish; `deps()` is given the host's real one.
DEPS = "ubuntu-24.04.csv"
# A distro slug is interpolated into the URL above, and it comes from the REMOTE host's
# /etc/os-release — which is attacker-influenceable if that host is compromised. So it has to match
# LinuxGSM's own filename shape exactly and nothing else: no slashes, no dots beyond a version, no
# traversal, nothing that could address a different path on the server.
_OS_SLUG_RE = __import__("re").compile(r"^[a-z][a-z0-9]{1,15}-[0-9]{1,2}(?:\.[0-9]{1,2})?$")


def deps_name(os_slug):
    """The data file for a distro slug ('ubuntu-22.04' -> 'ubuntu-22.04.csv'), or the default when
    the slug is missing or not the shape LinuxGSM uses."""
    if os_slug and _OS_SLUG_RE.match(os_slug):
        return os_slug + ".csv"
    return DEPS

# Refetch once a week. LinuxGSM adds games steadily but not daily, and a stale-by-days list is a
# far smaller problem than hammering GitHub from every panel on every boot.
MAX_AGE_SECONDS = 7 * 24 * 3600
_TIMEOUT = 10

_CACHE_DIR = Path(__file__).parent / "data" / "lgsm"
_lock = threading.Lock()
_mem = {}          # name -> parsed value, so repeated reads do not re-open the file
_last_error = {}   # name -> str, for status()


def cache_path(name):
    return _CACHE_DIR / name


def _looks_like(name, text):
    """Is this actually the file we asked for?

    A fetch can succeed and still return something useless — a captive portal's login page, an
    error page, a truncated body. Caching that would replace the game list with garbage and the
    panel would have no way to tell. So the shape is checked BEFORE anything is written.
    """
    if not text or len(text) < 200:
        return False
    head = text.lstrip()[:200].lower()
    if name == SERVERLIST:
        return head.startswith("shortname,") and "gameservername" in head and text.count("\n") > 20
    # Every other file we ask for is a per-distro package list, and they all start with the 'all'
    # row. Keyed on the shape rather than on one filename, since there are two dozen of them.
    return head.startswith("all,") and text.count("\n") > 20


def _fetch(name):
    """Download one file and return its text, or None. Never raises."""
    req = urllib.request.Request(_BASE + name, headers={"User-Agent": "linuxgsm-panel"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # nosec B310 - fixed https host
            if getattr(resp, "status", 200) != 200:
                _last_error[name] = "HTTP %s" % resp.status
                return None
            text = resp.read(4 * 1024 * 1024).decode("utf-8", errors="replace")
    except Exception as e:
        _last_error[name] = e.__class__.__name__
        return None
    if not _looks_like(name, text):
        _last_error[name] = "the response was not %s" % name
        return None
    return text


def _write_cache(name, text):
    """Write the cache atomically, so a crash mid-write cannot leave a half a game list behind."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = cache_path(name).with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, cache_path(name))


def _age(name):
    try:
        return time.time() - cache_path(name).stat().st_mtime
    except OSError:
        return None


def _text(name, allow_fetch=True):
    """The file's text: the cache when it is present and fresh, otherwise a fetch, otherwise
    whatever stale copy we have. A stale list beats no list."""
    age = _age(name)
    if age is not None and age < MAX_AGE_SECONDS:
        try:
            return cache_path(name).read_text(encoding="utf-8")
        except OSError:
            pass
    if allow_fetch:
        fresh = _fetch(name)
        if fresh is not None:
            try:
                _write_cache(name, fresh)
            except OSError as e:
                _last_error[name] = "could not write the cache (%s)" % e.__class__.__name__
            _last_error.pop(name, None)
            return fresh
    if age is not None:          # the fetch failed, but an older copy is still on disk
        try:
            return cache_path(name).read_text(encoding="utf-8")
        except OSError:
            pass
    return None


def serverlist(allow_fetch=True):
    """Rows of serverlist.csv as dicts, or [] when it cannot be had."""
    with _lock:
        if "serverlist" in _mem:
            return _mem["serverlist"]
        text = _text(SERVERLIST, allow_fetch)
        rows = []
        if text:
            try:
                rows = [r for r in csv.DictReader(io.StringIO(text))]
            except Exception:
                rows = []
        if rows:
            _mem["serverlist"] = rows
        return rows


def deps(os_slug=None, allow_fetch=True):
    """The package list for a distro, as {key: [packages]}, or {} when it cannot be had.

    `os_slug` is the host's own '<id>-<version>' from /etc/os-release. A host running Ubuntu 22.04
    was previously given 24.04's package list, because the filename was hard-coded — which is the
    sort of thing that installs a package that does not exist on that release and takes the whole
    apt transaction down with it.

    A distro LinuxGSM does not publish simply 404s, and the caller falls back to the default.
    """
    name = deps_name(os_slug)
    key = "deps:" + name
    with _lock:
        if key in _mem:
            return _mem[key]
        text = _text(name, allow_fetch)
        if text is None and name != DEPS:
            text = _text(DEPS, allow_fetch)      # this distro is not one LinuxGSM ships a list for
        out = {}
        for line in (text or "").splitlines():
            parts = [p.strip() for p in line.strip().split(",") if p.strip()]
            if parts:
                out[parts[0]] = parts[1:]
        if out:
            _mem[key] = out
        return out


def status():
    """What the UI needs to explain itself: whether we have data, how old, and what went wrong."""
    ages = {n: _age(n) for n in (SERVERLIST, DEPS)}
    return {
        "have_serverlist": bool(serverlist(allow_fetch=False)),
        "cached": {n: (None if a is None else int(a)) for n, a in ages.items()},
        "errors": dict(_last_error),
    }


def refresh(force=True):
    """Re-fetch both files now. Returns True if the game list ended up populated."""
    with _lock:
        _mem.clear()
        if force:
            for n in (SERVERLIST, DEPS):
                fresh = _fetch(n)
                if fresh is not None:
                    try:
                        _write_cache(n, fresh)
                        _last_error.pop(n, None)
                    except OSError as e:
                        _last_error[n] = "could not write the cache (%s)" % e.__class__.__name__
    return bool(serverlist())


def warm():
    """Populate the cache off the request path, so the first page load is not waiting on GitHub."""
    def _run():
        try:
            serverlist()
            deps()          # the default list; a host's own is fetched when it is first needed
        except Exception:   # nosec B110 - warming is best-effort; status() reports the failure
            pass
    threading.Thread(target=_run, daemon=True, name="lgsm-data-warm").start()
