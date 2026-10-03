"""Process-lifetime counters, last-values and heartbeats, for the debug report to read.

Written from the panel's loops (the monitor, the console poller, notification delivery, the
privileged-call path, ...) and read only by panel/ops/debug_report. Every writer here is a few dict
operations wrapped so that it CANNOT raise into its caller: an exception added to a loop's body kills
that loop for good, so instrumentation must never be the thing that does it. Lost increments under a
race are acceptable; a raise is not. No locks: a writer may run in a greenlet, a native tpool thread
or a plain thread, and a green lock cannot be waited on from a native thread.

KEYS ARE FIXED IDENTIFIERS OR DB IDS. Never a host, address, account, game-server name, path or
message text: the report prints keys as they are, and is meant for a public issue. Each group keeps
at most _MAX_KEYS keys; past that, new keys are counted in "_dropped" and not stored.
"""
import time

_MAX_KEYS = 200
_GROUPS = {}            # group -> {key: value}
_STARTED = time.time()  # when this module was first imported: about when the process started


def _group(group):
    g = _GROUPS.get(group)
    if g is None:
        g = _GROUPS.setdefault(group, {})
    return g


def _room(g, key):
    """Whether `key` may be stored in `g` (already there, or the group is not full)."""
    if key in g or len(g) < _MAX_KEYS:
        return True
    g["_dropped"] = g.get("_dropped", 0) + 1
    return False


def bump(group, key, n=1):
    """Add `n` to counter `key` of `group`."""
    try:
        g = _group(group)
        if _room(g, key):
            g[key] = g.get(key, 0) + n
    except Exception:  # noqa: BLE001 - instrumentation must never raise into a loop
        pass


def put(group, key, value):
    """Record `value` (a number, bool, fixed token, or a small tuple/dict of those) as the latest
    for `key`, with the wall-clock time it was recorded."""
    try:
        g = _group(group)
        if _room(g, key):
            g[key] = (time.time(), value)
    except Exception:  # noqa: BLE001
        pass


def evict(group, keep, keep_keys=()):
    """Drop the oldest put() entries of `group` until at most `keep` remain, `keep_keys` aside.

    For a group whose keys keep arriving (a commit per key): without it, the group fills to
    _MAX_KEYS and every NEW key is dropped from then on, the opposite of what a reader wants.
    """
    try:
        g = _group(group)
        timed = sorted((v[0], k) for k, v in list(g.items())
                       if k not in keep_keys and k != "_dropped" and isinstance(v, tuple))
        for _t, k in timed[:max(0, len(timed) - keep)]:
            g.pop(k, None)
    except Exception:  # noqa: BLE001 - instrumentation must never raise into a loop
        return


def beat(name, cadence_s=None, took_s=None):
    """A loop finished a pass: when, how often it is meant to run, and how long the pass took."""
    try:
        g = _group("heartbeat")
        if _room(g, name):
            prev = g.get(name) or {}
            g[name] = {"at": time.time(), "cadence": cadence_s, "took": took_s,
                       "passes": prev.get("passes", 0) + 1}
    except Exception:  # noqa: BLE001
        pass


def snapshot(group):
    """A copy of `group` ({} when nothing was recorded). Safe to iterate."""
    try:
        return dict(_GROUPS.get(group) or {})
    except Exception:  # noqa: BLE001 - a dict resized mid-copy by another thread
        return {}


def groups():
    """The names of every group recorded so far."""
    return sorted(_GROUPS)


def started():
    """Wall-clock time this module was imported (about when the process started)."""
    return _STARTED
