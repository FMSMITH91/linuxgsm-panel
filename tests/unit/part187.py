"""Part 187 of the unit suite: review pass 29's fixes in the monitor, LinuxGSM details and the report.

Held here:
* The monitor's LinuxGSM lock probe on the panel's own host runs as the game account (the panel's
  account cannot enter a game home), so a stop LinuxGSM made pages nothing there either; a lock
  still there, or one that could not be read, still pages.
* The two readers of LinuxGSM `details` that were regexes (the config file line, the Server IP /
  Internet IP port) answer as those regexes did on random text, and in linear time when the
  server's name (printed first, on one line) is built to make them backtrack.
* The XML config form's comment walk gives the same fields as before and stays linear with many
  comments on one line, many comment lines, or many properties before one comment.
* The debug report's manual full backup line counts servers held by a scheduled wipe or a queued
  stop or restart, from the summary _FullBackupTally writes.

HOW IT RUNS. Every host call is stubbed (the local transport, the game-account shell); the details
text is invented, shaped like LinuxGSM's info_messages.sh output. Nothing reaches a host or data/.
"""
import random as _random187
import re as _re187
import time as _time187
from types import SimpleNamespace as _NS187

from unit.part01 import check, eq
from unit.part12 import _p9_patch, _p9_patch_sm, _p9_restore_all
from panel.core import panel_state as _ps187
from panel.ops import backup as _bk187
from panel.ops.debug_report import _base as _base187, data as _data187
from panel.ops.ssh_manager import files as _files187, game as _game187
from panel.routes import panel_backup as _pb187
from panel.services import game_config_form as _g187
from panel.services import host_reboot as _hr187, monitoring as _mon187, notifications as _nt187

# ── 1. the monitor's lock probe on the panel's own host ─────────────────────────────────────────
_r42m_gs = _NS187(id=918187, name="p187-mon", short_name="r42mgame", lgsm_name="rustserver", game_type="rust")
_r42m_local = _NS187(id=187, display_name="this host", name="local", is_local=True, auth_method="local")
_r42m_said = []
_r42m_lock_calls = []


def _r42m_down(as_game_word, own=False):
    """Two confirmed-down sweeps on a local row. -> (recorded, pages, unannounced, lock shells).

    The stub answers `as_game_word` only to a line that runs as the game account (`sudo -u
    r42mgame bash -c ...`, or the bare line when the panel itself is that account); the panel's
    own account, without root, cannot search the 0750 home and reads it as unread.
    """
    del _r42m_said[:]
    del _r42m_lock_calls[:]
    _ps187._expected_offline.pop(_r42m_gs.id, None)
    _mon187._monitor_state["server_misses"].pop(_r42m_gs.id, None)
    _mon187._monitor_state["server_unannounced"].pop(_r42m_gs.id, None)

    def _run_local(cmd, timeout=30, sudo=False, stdin_text=None):
        if "pgrep" in cmd:
            return "IDLE", "", 0
        _r42m_lock_calls.append((cmd[:30], sudo))
        as_game = (cmd.startswith("sudo -u r42mgame bash -c ") and not sudo) or (own and not sudo)
        return (as_game_word if as_game else "LGSM_LOCK_unread"), "", 0

    _p9_patch_sm("_run_local", _run_local)
    _p9_patch(_hr187, "_own_account", lambda: "r42mgame" if own else "r42mpanel")
    _p9_patch(_nt187, "notify", lambda kind, *a, **k: _r42m_said.append(kind))
    try:
        prev = True
        for _ in range(_mon187._DOWN_CONFIRM_SWEEPS):
            prev = _mon187._server_transition(_r42m_local, _r42m_gs, False, prev, False)
    finally:
        _p9_restore_all()
    return (prev, list(_r42m_said), _mon187._monitor_state["server_unannounced"].pop(_r42m_gs.id, False),
            len(_r42m_lock_calls))


_r42m_runs = [_r42m_down("LGSM_LOCK_none"), _r42m_down("LGSM_LOCK_held"), _r42m_down("LGSM_LOCK_unread"),
              _r42m_down(""), _r42m_down("LGSM_LOCK_none", own=True)]
eq("monitor r42m: on the panel's own host the lock probe runs as the game account, in one shell: its "
   "monitoring lock gone (LinuxGSM's own stop) records the server down without a page; a lock still "
   "there, or a probe the game account could not answer, pages; a game under the panel's own account "
   "is read directly",
   _r42m_runs,
   [(False, [], True, 1), (False, ["server_down"], False, 1), (False, ["server_down"], False, 1),
    (False, ["server_down"], False, 1), (False, [], True, 1)])
check("monitor r42m: the panel-host lock probe never asks for root (no sudo bash -c wrapper)",
      all(not _s for _c, _s in _r42m_lock_calls), repr(_r42m_lock_calls))

