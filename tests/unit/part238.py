"""Part 238 of the unit suite: an idle console's 30 s window reads are answered from the last one.

Each open server page asks /api/console for the log's last 250 lines every 30 s. While the console
poller watches that console it already reads the log every 2-6 s, so a window read is answered again
from the last one only when a poller read, begun after that window read ended, found the log at that
window's inode and size. Held here, through the route on a real server row and the poller's own pass
(console_rest.tick):

* two pages polling a quiet console read the log once between them, and get the same lines and the
  same place (`at`) as that read;
* a line written since is read again, and shown, once the poller has read it; a window read with no
  poller read after it, a poller whose reads have failed for 18 s, a rotated log and a console
  nobody watches all read again;
* a window of another size (Load older's 2000 lines) always reads, and does not replace the kept one;
* masking runs on every answer, the kept one too.

HOW IT RUNS. read_as_game_user is stubbed on its definition site behind part12's tripwire; the
commands it is handed run for real, with bash, against this part's own log file.
"""
import os
import shutil as _shutil238
import subprocess as _sp238  # nosec B404 - runs bash on this part's own fixtures
import tempfile as _tf238
from types import SimpleNamespace as NS

from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_delete_server, _p9_json,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from panel.core import panel_state as _pstate238
from panel.db.models import GameServer as _GameServer238, db as _db238
from panel.routes import console_rest as _crest238, server_files as _sf238

_TMP238 = _tf238.mkdtemp(prefix="lgsm-unit-p238-")
_TRIP238 = len(_P9_TRIPPED)
# A secret's value as a game prints it after its flag: masked on every answer.
_WORD238 = "zq7-unit-238"


class _Host238:
    """read_as_game_user against this part's log, run by bash; counts each kind of console read."""

    def __init__(self, real, log):
        self.real, self.log = real, log
        self.reads = {"window": 0, "poll": 0, "look": 0}
        self.fail_poll = False

    def __call__(self, server, user, sh, timeout=30, selfname=None):
        if "__LGSMP_W0_B__" in sh:
            return "", "", 1                # the console-secrets config read: the flag pattern masks
        kind = "window" if "exec 3<" in sh else "poll" if "S=$(stat" in sh else "look"
        self.reads[kind] += 1
        if kind == "poll" and self.fail_poll:
            return "", "SSH command timed out", -1
        p = _sp238.run(["bash", "-c", sh.replace(self.real, self.log)], capture_output=True, text=True,
                       timeout=30, check=False)  # nosec B603 B607
        return p.stdout, p.stderr, p.returncode


def _write238(path, text, mode="a"):
    with open(path, mode, encoding="utf-8") as fh:
        fh.write(text)


class _Rig238:
    """A real server row, its log, the stubbed host, and the poller's passes on a fake 2 s clock."""

    def __init__(self):
        self.sid = _p9_new_server(P9_HOST, "crc238", "mc", 25238)
        with _p9.app_context():
            real = _db238.session.get(_GameServer238, self.sid).console_log
        self.log = os.path.join(_TMP238, "crc238-console.log")
        _write238(self.log, "boot\nstarted -adminpassword %s\n" % _WORD238, "w")
        self.host, self.clock = _Host238(real, self.log), [5000.0]
        _p9_patch(_sf238, "_host_timezone_cached", lambda *a, **k: "")
        _p9_patch_sm("read_as_game_user", self.host)
        _p9_patch(_crest238, "time", NS(time=lambda: self.clock[0]))
        _p9_patch(_p9.socketio, "emit", lambda event, data=None, **k: None)
        self.client = _p9_client(P9_ADMIN)

    def get(self, lines=None):
        """GET /api/console as a page does: (window reads it made, its lines, its place)."""
        before = self.host.reads["window"]
        q = "" if lines is None else "?lines=%d" % lines
        body = _p9_json(self.client.get("/api/console/%d%s" % (self.sid, q)))
        return self.host.reads["window"] - before, [r["line"] for r in body.get("lines", [])], body.get("at")

    def passes(self, n):
        """`n` poller passes 2 s apart, through console_rest.tick as the poller runs them."""
        with _p9.app_context():
            gs = _db238.session.get(_GameServer238, self.sid)
            for _ in range(n):
                self.clock[0] += 2.0
                _crest238.tick(_sf238._console_tick, _sf238._console_catchups, _p9, _p9.socketio, gs, self.sid)

    def close(self):
        for m in (_sf238._console_offsets, _sf238._console_partial, _pstate238._console_backlog,
                  _crest238._windows, _crest238._seen, _crest238._woken):
            m.pop(self.sid, None)
        _p9_delete_server(self.sid)


def _quiet238(rig):
    """Two pages polling a quiet console: one window read between them, the same answer each time."""
    first = rig.get()
    rig.passes(1)        # the poller's first look at the log, after the read: it vouches for it
    again = [rig.get(), rig.get(), rig.get()]
    eq("console window: two pages polling a quiet, watched console read the log once between them; each "
       "later poll gets the same lines and the same place as that read",
       ([n for n, _l, _a in [first] + again], [(lines, at) for _n, lines, at in again]),
       ([1, 0, 0, 0], [first[1:]] * 3))
    check("console window: ...and the kept answer is masked like a read one", first[1][-1:] ==
          ["started -adminpassword ********"] and all(_WORD238 not in str(r) for r in again), repr(again))
    return first


def _grown238(rig, first):
    """A line written since is read and shown once the poller has read it; no poller read, no reuse."""
    _write238(rig.log, "player joined\n")
    rig.passes(3)
    grown = rig.get()
    unvouched = rig.get()
    rig.passes(3)
    vouched = rig.get()
    _write238(rig.log, "player left\n")
    rig.passes(1)                    # the poller reads the new line; it has not found the log idle since
    moved = rig.get()
    eq("console window: after the log grew and the poller read it, the next poll reads again and shows the "
       "new line at its new place",
       (grown[0], grown[1][-1:], grown[2] != first[2]), (1, ["player joined"], True))
    eq("console window: a poll with no poller read since the last window read reads again; after the "
       "poller's next read that found the log unchanged, the poll is answered from the kept read",
       (unvouched[0], vouched[0], vouched[1:]), (1, 0, unvouched[1:]))
    eq("console window: once the poller has read past the kept read's end, the next poll reads again",
       (moved[0], moved[1][-1:]), (1, ["player left"]))
    rig.passes(3)
    size = os.path.getsize(rig.log)
    _write238(rig.log, "cut\n", "w")              # truncated in place: the same inode
    rig.passes(4)
    _write238(rig.log, "z" * (size - 5) + "\n")   # and written back to the kept read's size exactly
    rig.passes(5)                                 # read, then found idle there: the kept read's place
    regrown = rig.get()
    eq("console window: a log truncated and written back to the kept read's inode and size is read again",
       (regrown[0], regrown[1][:1]), (1, ["cut"]))


def _failed238(rig):
    """A poller whose reads have failed for longer than _VOUCH_SECONDS vouches for nothing."""
    rig.get()
    rig.passes(3)
    vouched = rig.get()[0]           # a poller read found the log unchanged after the window read
    rig.host.fail_poll = True
    rig.passes(10)
    failed = rig.get()
    rig.host.fail_poll = False
    rig.passes(3)
    eq("console window: a poll answered from the kept read reads the log itself once the poller's reads have "
       "failed for 20 s; once they work again it is answered from the kept read",
       (vouched, failed[0], rig.get()[0]), (0, 1, 0))


def _sized238(rig):
    """Load older's 2000 lines always read and do not replace the kept 250."""
    rig.get()
    rig.passes(3)
    older = [rig.get(2000)[0], rig.get(2000)[0]]
    eq("console window: a window of another size (2000 lines) reads every time, and the kept 250-line "
       "window is still answered after it", (older, rig.get()[0]), ([1, 1], 0))


def _rotated238(rig):
    """A rotated log and a console nobody watches read again."""
    os.replace(rig.log, rig.log + ".old")
    _write238(rig.log, "new log line\n", "w")
    rig.passes(3)
    rotated = rig.get()
    rig.passes(3)
    _sf238._forget_unwatched_consoles([])
    unwatched = rig.get()
    eq("console window: after the log was rotated the poll reads the new log", (rotated[0], rotated[1]),
       (1, ["new log line"]))
    eq("console window: a console nobody watches (the poller dropped its place) is read on every poll",
       (unwatched[0], rig.get()[0]), (1, 1))


try:
    _p9_restore_all()
    _p9_arm(who="part238")
    _rig238 = _Rig238()
    try:
        _first238 = _quiet238(_rig238)
        _grown238(_rig238, _first238)
        _failed238(_rig238)
        _sized238(_rig238)
        _rotated238(_rig238)
    finally:
        _rig238.close()
finally:
    _p9_restore_all()
    _shutil238.rmtree(_TMP238, ignore_errors=True)

check("part238: nothing reached a real transport", len(_P9_TRIPPED) == _TRIP238, repr(_P9_TRIPPED[_TRIP238:]))
