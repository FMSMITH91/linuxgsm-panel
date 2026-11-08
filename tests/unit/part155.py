"""Part 155 of the unit suite: scheduled wipes, FastDL and the other game operations (review 1107 B).

Held here:
* FastDL is not run when the account's LinuxGSM release could not be read: on v26.5.0 the old
  all-Y answers delete ${webdir}/fastdl, so the run is refused and said in the console.

HOW IT RUNS. Routes and workers on part12's app with its transport tripwire armed and every host
call stubbed. Nothing reaches a host or data/.
"""
from unit.part01 import check
from unit.part12 import (P9_GS, _P9_TRIPPED, _p9, _p9_arm, _p9_patch, _p9_patch_sm, _p9_restore_all)
from panel.ops.ssh_manager import hosts as _hosts155, game as _game155
from panel.routes import server_detail as _sd155

_TRIP155_START = len(_P9_TRIPPED)

# ── 1. FastDL with an unread LinuxGSM release ───────────────────────────────────────────────────
_fd155 = {"runs": [], "said": [], "began": []}
try:
    _p9_arm(who="part155")
    _p9_patch(_hosts155, "lgsm_versions", lambda server, account, selfname: (None, None))
    _fd_unread155 = _game155.fastdl_answers(None, "u155", "csserver", "cs")
    _p9_patch(_hosts155, "lgsm_versions", lambda server, account, selfname: ("v26.4.0", None))
    _fd_modsunread155 = _game155.fastdl_answers(None, "u155", "csserver", "cs")
    _p9_patch_sm("fastdl_answers", lambda server, user, selfname, game_type: None)
    _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: (
        _fd155["runs"].append(action), ("", "", 0))[1])
    _p9_patch(_sd155, "_begin_action_tail", lambda app, sid, action, *a, **k: _fd155["began"].append(action))
    _p9_patch(_sd155, "_end_action_tail", lambda *a, **k: None)
    _p9_patch(_sd155, "_console_push", lambda app, sid, text, ts=None: _fd155["said"].append((sid, str(text))))
    with _p9.app_context():
        _fd_out155 = _sd155._run_teed(_p9, None, P9_GS, "u155", "fastdl", "csserver")
finally:
    _p9_restore_all()
check("fastdl_answers: a release that could not be read, or modules unread under a pre-v26.5.0 script, "
      "gives no answers (None), never the eight Y's that delete the FastDL folder on v26.5.0",
      _fd_unread155 is None and _fd_modsunread155 is None, repr((_fd_unread155, _fd_modsunread155)))
check("FastDL run with an unread release: LinuxGSM is never run, the run fails with the reason, and the "
      "console says it was not run",
      _fd155["runs"] == [] and _fd155["began"] == [] and _fd_out155[2] != 0
      and "FastDL was not run" in _fd_out155[1]
      and len(_fd155["said"]) == 1 and _fd155["said"][0][0] == P9_GS
      and _fd155["said"][0][1].startswith("[panel] fastdl: FastDL was not run"),
      repr((_fd155, _fd_out155)))

check("part155: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP155_START, repr(_P9_TRIPPED[_TRIP155_START:]))
