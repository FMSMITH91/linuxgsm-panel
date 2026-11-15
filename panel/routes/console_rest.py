"""The live console's idle back-off: a log that has stopped growing is read every few seconds, not every 2 s.

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
* a page coming back to it asked to be caught up.

While output flows nothing changes: every pass reads it, exactly as before. What a rest can cost is
the first line after a quiet spell of _IDLE_TICKS passes or more, which is shown up to _REST_SECONDS
after it was written instead of up to 2 s.
"""
import time

from panel.core.panel_state import _console_offsets, register_server_state
from panel.ops import ssh_manager as _sm

# Reads in a row that found nothing new before a console rests (one per 2 s pass: 6 s of quiet).
_IDLE_TICKS = 3
# How often a resting console's log is read.
_REST_SECONDS = 6.0

# server id -> when the panel last said something in that console (see wake).
_woken = register_server_state({})


def wake(server_id):
    """Read this console on the next pass: the panel just said something in it."""
    _woken[server_id] = time.time()


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
    is told by where the poller stands in the log before and after it (inode and offset), so the
    tick itself is unchanged.
    """
    state = _console_offsets.get(server_id)
    if _resting(state, gs, server_id, pending):
        return
    if state is not None:
        state["read_at"] = time.time()
    before = (state or {}).get("ino"), (state or {}).get("pos")
    tick_fn(app, socketio, gs, server_id)
    after = _console_offsets.get(server_id)
    if after is not None and after is state and (after.get("ino"), after.get("pos")) == before:
        after["idle"] = after.get("idle", 0) + 1
    elif after is not None:
        after["idle"] = 0
