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
import logging
import os
import re
import threading
import time
import urllib.request

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
_OS_SLUG_RE = re.compile(r"^[a-z][a-z0-9]{1,15}-[0-9]{1,2}(?:\.[0-9]{1,2})?\Z")

# The same package lists AT A RELEASE. LinuxGSM, on its default branch, fetches every module and
# data file from the tag its own script's `version=` names, not from master (fn_fetch_file_github
# in lgsm/modules/core_dl.sh: "to prevent version mixing"); only update-lgsm reads master. So a
# game account on an older release asks for the packages THAT release lists, and they can differ
# from master's: v26.1.0 lists openjdk-21-jre for five Java games where master has -25-.
_RELEASE_BASE = "https://raw.githubusercontent.com/GameServerManagers/LinuxGSM/%s/lgsm/data/"
# A release tag and nothing else ('v26.1.0'). It is read from a game account's own script, which
# that account can edit, and becomes a URL path segment; so it is LinuxGSM's tag shape exactly.
# ASCII digits, because \d also matches other scripts' digits; fullmatch, because `$` would let a
# trailing newline through.
_RELEASE_TAG_RE = re.compile(r"v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")
_log = logging.getLogger(__name__)


def release_tag(value):
    """`value` when it is a LinuxGSM release tag ('v26.1.0'), else None."""
    if isinstance(value, str) and _RELEASE_TAG_RE.fullmatch(value):
        return value
    return None


def deps_name(os_slug):
    """Name the data file for a distro slug ('ubuntu-22.04' -> 'ubuntu-22.04.csv').

    Returns the default when the slug is missing or not the shape LinuxGSM uses.
    """
    if os_slug and _OS_SLUG_RE.match(os_slug):
        return os_slug + ".csv"
    return DEPS


# Refetch once a week. LinuxGSM adds games steadily but not daily, and a stale-by-days list is a
# far smaller problem than hammering GitHub from every panel on every boot.
MAX_AGE_SECONDS = 7 * 24 * 3600
_TIMEOUT = 10

from panel import REPO_ROOT as _ROOT   # the cache belongs in the gitignored data/, at the root
_CACHE_DIR = _ROOT / "data" / "lgsm"
_lock = threading.Lock()
_mem = {}          # name -> (expires_at, parsed value), so repeated reads do not re-open the file
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


def _download(url, name):
    """GET one of LinuxGSM's files: (text, None), or (None, why). Never raises."""
    req = urllib.request.Request(url, headers={"User-Agent": "linuxgsm-panel"})
    try:
        # `url` is _BASE or _RELEASE_BASE, fixed https://raw.githubusercontent.com URLs, with a
        # validated release tag and a LinuxGSM filename filled in.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # nosec B310 - fixed https host
            if getattr(resp, "status", 200) != 200:
                return None, "HTTP %s" % resp.status
            text = resp.read(4 * 1024 * 1024).decode("utf-8", errors="replace")
    except Exception as e:
        return None, e.__class__.__name__
    if not _looks_like(name, text):
        return None, "the response was not %s" % name
    return text, None


def _fetch(name):
    """Download one file from master and return its text, or None. Never raises."""
    text, why = _download(_BASE + name, name)
    if why:
        _last_error[name] = why
    return text


def _fetch_release(tag, name):
    """Download one data file at release `tag` (validated by the caller), or None. Never raises.

    Its failures are logged, not recorded for status(), which reports the panel's own copies.
    """
    text, why = _download(_RELEASE_BASE % tag + name, name)
    if why:
        _log.warning("LinuxGSM %s at %s could not be fetched: %s", name, tag, why)
    return text


def _write_cache(name, text):
    """Write the cache atomically, so a crash mid-write cannot leave a half a game list behind.

    The temp name is this writer's own. Fetches no longer run under _lock, so two readers can
    refetch the same file at once; with one shared "<name>.tmp", one's os.replace took the file
    the other was still writing, and the other's replace then failed on a missing name.
    """
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = cache_path("%s.%d.%d.tmp" % (name, os.getpid(), threading.get_ident()))
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, cache_path(name))


def _age(name):
    try:
        return time.time() - cache_path(name).stat().st_mtime
    except OSError:
        return None


def _text(name, allow_fetch=True):
    """Return the file's text, from the freshest source that answers.

    That is the cache when it is present and fresh, otherwise a fetch, otherwise whatever stale
    copy we have. A stale list beats no list.
    """
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
                _last_error.pop(name, None)
            except OSError as e:
                # ...and NOT popped on the next line regardless, which is what this did: the
                # cache-write error was recorded and immediately discarded, so a read-only data/
                # (every boot re-fetching, nothing ever persisting) was invisible in status().
                _last_error[name] = "could not write the cache (%s)" % e.__class__.__name__
            return fresh
    if age is not None:          # the fetch failed, but an older copy is still on disk
        try:
            return cache_path(name).read_text(encoding="utf-8")
        except OSError:
            pass
    return None


# A refetch that failed is tried again after this long, not a week later. The copy it fell back to
# is served meanwhile.
_RETRY_SECONDS = 3600
# Keys whose re-read is running right now, outside _lock (see _memoised).
_inflight = set()
# Bumped (under _lock) whenever the memo is dropped because the files under it were rewritten —
# refresh(), refresh_deps(). A re-read that began before the bump read the OLD file, and must not
# store it: _age() would now report the NEW file's age, and the old list would be kept a week.
_generation = [0]


def _memoised(key, load, allow_fetch):
    """The parsed copy under `key` while it is due to be served, else `load()` -> (value, file).

    It used to be served for the life of the process: serverlist() and deps() returned `_mem[...]`
    as soon as it was filled and never looked at the file's age again, so MAX_AGE_SECONDS applied
    only to the first read after a start or a refresh(). A panel up for two months offered the game
    list and package lists from the day it started, and a game LinuxGSM added meanwhile never
    reached the install menu.

    A copy read from a fresh file lives until that file is due for its weekly refetch. One read
    after a refetch failed (a stale file, or a fetch that could not be written) lives
    _RETRY_SECONDS. A stale file read with fetching NOT allowed (status()) is not kept, so the next
    read that may fetch still does. A re-read that comes back EMPTY keeps serving the copy it had —
    a stale list beats no list — rather than emptying the install menu of a running panel.

    `load()` runs OUTSIDE _lock. serverlist() and deps() held the lock across it, and it can be a
    GitHub fetch with a 10-second timeout: with GitHub unreachable, every request that needed the
    game list — the dashboard, the install page, every one of them — queued behind that one fetch,
    for up to ten seconds each, once an hour. Now the lock covers only the memo itself: a caller
    that finds a copy being re-read by someone else is served that copy at once, and the result
    is stored compare-and-set — only if the memo is still the one this call saw, so a slow re-read
    never overwrites a newer copy (a refresh(), or another caller's) that landed meanwhile.
    """
    with _lock:
        hit = _mem.get(key)
        if hit is not None and (time.time() < hit[0] or key in _inflight):
            return hit[1]
        _inflight.add(key)
        gen = _generation[0]
    try:
        value, name = load()
        age = _age(name) if value else None
    except BaseException:
        with _lock:
            _inflight.discard(key)
        raise
    with _lock:
        return _lgd_settle(key, hit, value, age, gen, allow_fetch)


def _lgd_settle(key, hit, value, age, gen, allow_fetch):
    """_memoised's compare-and-set, under _lock: the copy to serve once `load()` has returned."""
    _inflight.discard(key)
    cur = _mem.get(key)
    if cur is not None and cur is not hit:
        return cur[1]
    if gen != _generation[0]:
        return value if value else (hit[1] if hit is not None else value)
    return _memo_store(key, hit, value, age, allow_fetch)


def _memo_store(key, hit, value, age, allow_fetch):
    """_memoised's store, under _lock: keep `value` (or `hit`'s copy when it is empty) and return it."""
    if not value:
        if hit is None:
            return value
        value = hit[1]
        age = None
    if age is not None and age < MAX_AGE_SECONDS:
        _mem[key] = (time.time() + MAX_AGE_SECONDS - age, value)
    elif allow_fetch:
        _mem[key] = (time.time() + _RETRY_SECONDS, value)
    return value


def _load_serverlist(allow_fetch):
    text = _text(SERVERLIST, allow_fetch)
    rows = []
    if text:
        try:
            rows = [r for r in csv.DictReader(io.StringIO(text))]
        except Exception:
            rows = []
    return rows, SERVERLIST


def serverlist(allow_fetch=True):
    """Rows of serverlist.csv as dicts, or [] when it cannot be had.

    While a parsed copy is being served, every call returns the SAME list object, so a caller that
    derives something from it (app.load_game_list) can tell a re-read (a new object) from a
    repeat.
    """
    return _memoised("serverlist", lambda: _load_serverlist(allow_fetch), allow_fetch)


def deps(os_slug=None, allow_fetch=True):
    """The package list for a distro, as {key: [packages]}, or {} when it cannot be had.

    `os_slug` is the host's own '<id>-<version>' from /etc/os-release. A host running Ubuntu 22.04
    was previously given 24.04's package list, because the filename was hard-coded — which is the
    sort of thing that installs a package that does not exist on that release and takes the whole
    apt transaction down with it.

    A distro LinuxGSM does not publish simply 404s, and the caller falls back to the default.
    """
    name = deps_name(os_slug)

    def _load():
        text, source = _text(name, allow_fetch), name
        if text is None and name != DEPS:
            # this distro is not one LinuxGSM ships a list for
            text, source = _text(DEPS, allow_fetch), DEPS
        return _parse_deps(text), source

    return _memoised("deps:" + name, _load, allow_fetch)


def _parse_deps(text):
    """A package-list CSV as {key: [packages]}; the first field of each line is its key."""
    out = {}
    for line in (text or "").splitlines():
        parts = [p.strip() for p in line.strip().split(",") if p.strip()]
        if parts:
            out[parts[0]] = parts[1:]
    return out


# The two lookups below run only when an install has just refused a package name, and a refusal
# can repeat on every retry of every install. So each goes to the network at most once per
# _RETRY_SECONDS for the same file, whatever asks: key -> when it last went.
_attempted = {}


def _may_attempt(key):
    """True, and the attempt recorded, unless `key` went to the network within _RETRY_SECONDS."""
    now = time.time()
    last = _attempted.get(key)
    if last is not None and 0 <= now - last < _RETRY_SECONDS:
        return False
    _attempted[key] = now
    return True


def refresh_deps(os_slug=None):
    """Fetch this distro's package list from master NOW, past the weekly cache; {} if not fetched.

    For a name the cached copy refuses: LinuxGSM may have listed it since that copy was taken, up to
    a week ago. A fetched copy replaces the cache, so deps() serves it from then on. Rate-limited
    (see _may_attempt): a name that is simply not LinuxGSM's costs one fetch an hour, not one per
    retry, and a throttled or failed refresh answers {} so the caller refuses as before.
    """
    name = deps_name(os_slug)
    with _lock:
        if not _may_attempt("master/" + name):
            return {}
    # Outside the lock: a page reading the game list must not wait on an install's fetch.
    fresh = _fetch(name)
    if fresh is None:
        return {}
    with _lock:
        try:
            _write_cache(name, fresh)
            _last_error.pop(name, None)
            _mem.pop("deps:" + name, None)
            _generation[0] += 1
        except OSError as e:
            _last_error[name] = "could not write the cache (%s)" % e.__class__.__name__
    return _parse_deps(fresh)


# (tag, file) -> parsed list. A release's files do not change, so a list fetched once is kept for
# the life of the process; a failed fetch is retried under _may_attempt's limit.
_releases = {}


def deps_at_release(os_slug, tag):
    """Read the package list LinuxGSM published for a distro AT RELEASE `tag`; {} if not had.

    `tag` comes from a game account's own script (hosts.lgsm_release), so that account chooses
    which of LinuxGSM's releases is read, never what the list says: the text comes from LinuxGSM's
    repository, and anything that is not a plain release tag fetches nothing.
    """
    tag = release_tag(tag)
    if tag is None:
        return {}
    name = deps_name(os_slug)
    with _lock:
        hit = _releases.get((tag, name))
        if hit is not None or not _may_attempt(tag + "/" + name):
            return hit or {}
    text = _fetch_release(tag, name)        # outside the lock, as in refresh_deps
    if text is None:
        return {}
    with _lock:
        hit = _releases[(tag, name)] = _parse_deps(text)
    return hit


def status():
    """What the UI needs to explain itself: whether we have data, how old, and what went wrong.

    `reason` is the one-line form for a page to print. This function had NO CALLERS at all while
    two comments — this module's header and app.load_game_list's docstring — both said the install
    page surfaced it; the page showed a fixed generic warning and never asked. install_server.html
    reads it now.
    """
    ages = {n: _age(n) for n in (SERVERLIST, DEPS)}
    errs = dict(_last_error)
    reason = ""
    if errs:
        # The serverlist is the one the menu is built from; name it first if both failed.
        _first = SERVERLIST if SERVERLIST in errs else sorted(errs)[0]
        reason = "%s: %s" % (_first, errs[_first])
    return {
        "have_serverlist": bool(serverlist(allow_fetch=False)),
        "cached": {n: (None if a is None else int(a)) for n, a in ages.items()},
        "errors": errs,
        "reason": reason,
    }


def refresh(force=True):
    """Re-fetch both files now. Returns True if the FETCH succeeded — not merely if a list exists.

    `return bool(serverlist())` read the CACHE back, which is populated by every previous run, so
    this answered True with every network fetch failing. The route turns that into
    `{"success": true, "message": "Loaded 30 games."}` and an audit row saying the refresh worked:
    a superadmin pressing Retry because a newly-supported game is missing is told it loaded, and
    the list is unchanged.
    """
    ok = True
    # The fetches OUTSIDE _lock, as in _memoised: this held it across two of them, so a Retry
    # pressed while GitHub was unreachable stalled every page that read the game list for up to
    # twenty seconds. The memo is dropped after the new files are written, so the serverlist()
    # below reads them — and a re-read already running when it was dropped cannot put its older
    # copy back (_memoised stores only over the memo it saw).
    if force:
        for n in (SERVERLIST, DEPS):
            fresh = _fetch(n)
            if fresh is None:
                ok = False
                continue
            try:
                _write_cache(n, fresh)
                _last_error.pop(n, None)
            except OSError as e:
                _last_error[n] = "could not write the cache (%s)" % e.__class__.__name__
                ok = False
    with _lock:
        _mem.clear()
        _generation[0] += 1
    return ok and bool(serverlist())


def warm():
    """Populate the cache off the request path, so the first page load is not waiting on GitHub."""
    def _run():
        try:
            serverlist()
            deps()          # the default list; a host's own is fetched when it is first needed
        except Exception:   # nosec B110 - warming is best-effort; status() reports the failure
            pass
    threading.Thread(target=_run, daemon=True, name="lgsm-data-warm").start()
