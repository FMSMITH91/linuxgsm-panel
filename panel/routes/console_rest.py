"""The live console's idle cost: a quiet log is read every few seconds, and a page's 30 s window of it is not re-read.

Every read of a watched console is one `sudo -u <account>` on the host: ~19 ms of CPU, 12 of them
sudo's own, and three journal lines (the command, and PAM's session opened and closed). An open
console on a quiet server read its unchanged log 29 times a minute: 0.56 CPU s and 88 journal lines
a minute per watched console, for nothing.

So once _IDLE_TICKS reads in a row have found nothing new, the console rests: its log is read every
_REST_SECONDS instead of on every 2 s pass. It is straight back to every pass on any of these:

* the log grew (or was rotated, or a read failed and then worked) — what a console is for;
* a line was typed into it, from the page or by any panel feature (_core.console_sent): the reply
  is wanted now;
* the panel said something in it (_console_push wakes it): an action began or ended, a start, stop
  or restart;
* a page coming back to it asked to be caught up (wake_for_catchups, as the poller answers it).

While output flows nothing changes: every pass reads it, exactly as before. What a rest can cost is
the first line after a quiet spell of _IDLE_TICKS passes or more, which is shown up to _REST_SECONDS
after it was written instead of up to 2 s.

Each open page also asks /api/console for the log's last lines every 30 s, one more read per page
each time. While the poller is watching that console it already knows whether the log has changed:
a read of its that found the log just where a window read left it, begun after that window read
ended, says the log was still that window's inode and size then. So the window is answered again
from that read (cached_window) instead of being read again. It is the reply the host gave, as
read; nothing about how it is used changes, and it is the log as the poller last found it, which
it reads at least every _REST_SECONDS. A change to the log (it grew, it was rotated or truncated),
no good poller read for _VOUCH_SECONDS, or a console nobody is watching, and the next window read
goes to the host as before.
"""
import time

from panel.core.panel_state import _console_offsets, register_server_state
from panel.ops import ssh_manager as _sm

# Reads in a row that found nothing new before a console rests (one per 2 s pass: 6 s of quiet).
_IDLE_TICKS = 3
# How often a resting console's log is read.
_REST_SECONDS = 6.0
# How recent the poller's read must be for a window read to be answered again (cached_window): a
# poller whose reads have failed for longer vouches for nothing.
_VOUCH_SECONDS = 3 * _REST_SECONDS

# server id -> when the panel last said something in that console (see wake).
_woken = register_server_state({})

# server id -> the last /api/console window read: (lines asked for, when it ended, (inode, size)
# of the log it read, its reply). See cached_window.
_windows = register_server_state({})
# server id -> when the poller's last read that found the log exactly where its offsets are began
# (see seen).
_seen = register_server_state({})


def wake(server_id):
    """Read this console on the next pass: the panel just said something in it."""
    _woken[server_id] = time.time()


def wake_for_catchups(server_id, reqs, watching):
    """Wake this console when one of the catch-ups `reqs` ({socket id: request}) is from a page still `watching`.

    The poller answers them (and drops them from its map) before the tick, so _resting, which looks
    for a pending one in that map, never sees them: the wake is said here instead.
    """
    if any(sid in watching for sid in reqs):
        wake(server_id)


def _resting(state, gs, server_id, pending):
    """True when this pass may skip the console's read (see the module docstring)."""
    if state is None or state.get("idle", 0) < _IDLE_TICKS:
        return False
    since = state.get("read_at", 0.0)
    sent = _sm._core.console_sent.get((getattr(gs.remote, "id", None), gs.short_name), 0.0)
    if max(sent, _woken.get(server_id, 0.0)) >= since or pending.get(server_id):
        state["idle"] = 0
        return False
    return time.time() - since < _REST_SECONDS


def tick(tick_fn, pending, app, socketio, gs, server_id):
    """Run the console poller's tick_fn for this console unless it is resting.

    `pending` is the poller's map of catch-ups pages have asked for. Whether the read found anything
    is told by where the poller stands in the log before and after it (inode and offset). The tick
    returns True when its read found the log exactly where the offsets say (seen), and a new chain
    after it is a rotated or truncated log (forget_window).
    """
    state = _console_offsets.get(server_id)
    if _resting(state, gs, server_id, pending):
        return
    if state is not None:
        state["read_at"] = time.time()
    was, began = _place(state), clock()
    if tick_fn(app, socketio, gs, server_id) is True:
        seen(server_id, began)
    _after_tick(server_id, state, was)


def _place(state):
    """(inode, offset, chain) of the poller's offsets for a console, all None when it has none."""
    s = state or {}
    return s.get("ino"), s.get("pos"), s.get("chain")


def _after_tick(server_id, state, was):
    """Count a read that found nothing new toward the rest, and drop a kept window of a rotated log.

    `state` is the offsets before the tick (the tick changes them in place) and `was` their place then.
    """
    after = _console_offsets.get(server_id)
    if after is None:
        return
    if after is state and _place(after)[:2] == was[:2]:
        after["idle"] = after.get("idle", 0) + 1
    else:
        after["idle"] = 0
    if state is not None and after.get("chain") != was[2]:
        forget_window(server_id)    # rotated or truncated: a kept window read is not of this log


def clock():
    """The time the window reads and the poller's reads are compared by (seen, keep_window)."""
    return time.time()


def seen(server_id, started):
    """Record that a poller read begun at `started` found this console's log where its offsets say.

    Only for a read that found the log at exactly that inode and size: nothing new in it, or a first
    look that recorded its end.
    """
    _seen[server_id] = started


def keep_window(server_id, want, place, reply):
    """Keep a window read of `want` lines that has just ended and read the log up to `place`.

    `place` is (inode, size) and `reply` the read's (out, rc). A newer kept read is not replaced.
    """
    ended = clock()
    got = _windows.get(server_id)
    if got is None or got[1] <= ended:
        _windows[server_id] = (want, ended, tuple(place), reply)


def forget_window(server_id):
    """Drop the kept window read: the poller found the log rotated or truncated, so it is not this log.

    Truncated and written back to the same size, the inode and size would match it again.
    """
    _windows.pop(server_id, None)


def window_read(gs, want, keep, place, read):
    """/api/console's window read of `want` lines: (out, rc), the kept one while cached_window vouches for it.

    `read()` reads it from the host as (out, err, rc); `place(out)` is _shared._console_window_place.
    `keep`: whether a good read is kept for the next poll (only the page's 30 s size is).
    """
    sid = getattr(gs, "id", None)
    hit = cached_window(sid, want) if sid is not None else None
    if hit is not None:
        return hit
    out, _err, rc = read()
    at, rest, _newlines = place(out)
    if keep and sid is not None and rc == 0 and at is not None and rest.startswith("B") and rest.endswith("E"):
        keep_window(sid, want, at[1:], (out, rc))
    return out, rc


def cached_window(server_id, want):
    """The kept window read's reply (out, rc) while the poller vouches the log has not changed, else None.

    It does when its offsets are the kept read's inode and size, and a read of its that found the
    log there began after the kept read ended and within the last _VOUCH_SECONDS.
    """
    got, saw, state = _windows.get(server_id), _seen.get(server_id), _console_offsets.get(server_id)
    if got is None or saw is None or state is None or got[0] != want or saw <= got[1]:
        return None
    if clock() - saw > _VOUCH_SECONDS or (state.get("ino"), state.get("pos")) != got[2]:
        return None
    return got[3]
