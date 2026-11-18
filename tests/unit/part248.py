"""Part 248 of the unit suite: server actions, the console and backups.

1. LinuxGSM's output is read in time linear in its length: the players-online, update-busy, wipe,
   backup-failure and not-installed lines, the `details` secret labels, the debug report's key=value
   scrub and the release notes' links. A line of one tag (or key word) repeated with no phrase after
   it took time growing with its square (the key=value scrub with its cube); judged on growth.

HOW IT RUNS. Every caller is called in-process on invented text; the one that reads a host has its
game-account shell stubbed. Nothing reaches a host or data/.
"""

import sys
from types import SimpleNamespace as _NS248

from unit.part01 import check, eq
from unit.part12 import _p9_patch_sm, _p9_restore_all
from unit.part187 import _r42m_growth, _r42m_grows_linearly
from panel.ops import system_ops as _so248
from panel.ops.ssh_manager import game as _game248
from panel.routes import _shared as _sh248, server_detail as _sd248
from panel.services import lgsm_players as _lgp248, lgsm_releases as _rel248, wipe_schedule as _wipe248

_app248 = sys.modules["app"]

# ── 1. linear reads of LinuxGSM's output ─────────────────────────────────────────────────────────
_R30_HOST = _NS248(id=248, display_name="this host", name="local", is_local=True, auth_method="local")
_r30_shell_out = {"text": ""}


def _r30_installed_call(text):
    """A callable running _looks_installed over `details` output `text` -> its verdict."""
    def call():
        _r30_shell_out["text"] = text
        return _sh248._looks_installed(_app248, _R30_HOST, "r30game", "rustserver")
    return call


def _r30_call(fn, text):
    """A callable running fn(text)."""
    return lambda: fn(text)


# Each: (what, the caller over a text, the repeated unit, its size, the answer a real line still gets).
_R30_REAL_STOP = "[ INFO ] Stopping rustserver: 3 players are on the server: stop prevented\n"
_R30_CASES = (
    ("a stop's players-online line", lambda t: _lgp248.outcome(t + "\n" + _R30_REAL_STOP, "stop"), "[ INFO ] ", 4000,
     {"code": "lgsm_refused", "kind": "stop", "players": 3}),
    ("an update's busy line", lambda t: _lgp248.outcome(t + "\n[ INFO ] Updating rustserver: Checking update: "
                                                        "Update is already running (PID 1)", "update"),
     "[ INFO ] ", 4000, {"code": "lgsm_busy", "kind": "update"}),
    ("a wipe's not-required line", lambda t: _wipe248.judge(t + "\n[  OK  ] Wipe not required\n", 0, "full-wipe")[0],
     "[ OK ] ", 4000, "nothing"),
    ("a wipe's start and unstopped lines", lambda t: _wipe248.judge(
        t.replace("[ OK ] ", "[ START ] ") + "\n" + t.replace("[ OK ] ", "[ FAIL ] ") + "\n[ START ] Full wipe\n"
        "Success! Full wipe complete\n", 0, "full-wipe")[0], "[ OK ] ", 3000, "wiped"),
    ("a backup's in-progress FAIL", lambda t: _game248._bkverify_text_failed(t + "\nBackup in progress ... FAIL", ""),
     "in progress ", 4000, True),
    ("the not-installed check", lambda t: _r30_installed_call(t + "\nserverfiles missing")(),
     "serverfiles ", 4000, False),
    ("details' secret labels", lambda t: _sd248._dtl_mask_labelled(t + "\nRCON password: s3cr3t-r30\n")[1],
     "password ", 4000, {"s3cr3t-r30"}),
    ("the debug report's key=value scrub", lambda t: "s3cr3t-r30" in _so248._redact(t + " token=s3cr3t-r30"),
     "password-", 100, False),
    ("a release note's links", lambda t: _rel248.plain("[the notes](https://example.invalid/n) " + t)[:9],
     "[", 8000, "the notes"),
)
_r30_grow = {}
_p9_patch_sm("shell_as_game_user", lambda *a, **k: (_r30_shell_out["text"], "", 0))
try:
    for _r30_what, _r30_fn, _r30_unit, _r30_n, _r30_want in _R30_CASES:
        _r30_grow[_r30_what] = (_r42m_growth(lambda k, _f=_r30_fn, _u=_r30_unit: _r30_call(_f, _u * k), _r30_n),
                                _r30_want)
finally:
    _p9_restore_all()
for _r30_what, (_r30_got, _r30_want) in _r30_grow.items():
    check("lgsm output r30: %s over a line of its tag (or key word) repeated is read in time that grows linearly "
          "with it (4x the line, under 8x the time), and the real line after it still gives its answer" % _r30_what,
          _r42m_grows_linearly(_r30_got) and _r30_got[2] == (_r30_want, _r30_want),
          "x%.1f %.3fs %r" % _r30_got)
eq("lgsm output r30: the players-online line still reads with other tags before it on the same line",
   _lgp248.outcome("[ INFO ] a [ INFO ] Stopping x: 12 players are on the server: restart postponed", "restart"),
   {"code": "lgsm_postponed", "kind": "restart", "players": 12})
eq("lgsm output r30: the key=value scrub still keeps a hyphen-led key and masks only its value",
   _so248._redact("--db-password=hunter2r30 next"), "--db-password=[redacted] next")


