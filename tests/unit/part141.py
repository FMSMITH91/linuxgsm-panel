"""Part 141 of the unit suite: what LinuxGSM v26.5.0 changed under the panel (lgsm-2605).

From a review of LinuxGSM v26.5.0 (2026-11-04) against v26.4.0 and the panel. Held here:

* FastDL: on v26.5.0 "Rebuild Fastdl directory from scratch?" is answered N, so the run is
  incremental and keeps files LinuxGSM did not write; older releases keep their Y's.

HOW IT RUNS. Pure functions with their host reads stubbed on the defining submodule; routes on
part12's app with its transport tripwire armed and every host call stubbed. Nothing reaches a host or data/.
"""
import os

from unit.part01 import check
from unit.part05 import _root
from unit.part12 import P9_GS, _P9_TRIPPED, _p9, _p9_arm, _p9_patch, _p9_patch_sm, _p9_restore_all
from panel.ops.ssh_manager import _core as _smc141, files as _files141
from panel.ops.ssh_manager import game as _game141, hosts as _hosts141
from panel.routes import server_detail as _sd141
from panel.services import lgsm_data as _lgd141, lgsm_players as _lgp141

_TRIP141_START = len(_P9_TRIPPED)


def _read141(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ── 1. FastDL's answers, per release ────────────────────────────────────────────────────────────
check("release_at_least: compares LinuxGSM tags as numbers, and an unread or odd one is never newer",
      _lgd141.release_at_least("v26.5.0", (26, 5, 0)) and _lgd141.release_at_least("v26.10.0", (26, 5, 0))
      and _lgd141.release_at_least("v27.0.0", (26, 5, 0))
      and not _lgd141.release_at_least("v26.4.0", (26, 5, 0))
      and not _lgd141.release_at_least(None, (26, 5, 0))
      and not _lgd141.release_at_least("26.5.0", (26, 5, 0))
      and not _lgd141.release_at_least("v26.5.0-rc1", (26, 5, 0)))

_fd141 = {"tag": "v26.5.0", "vals": {"webdir": ""}, "probe": ("LG265_DIR\n", "", 0), "probed": []}


def _fd_probe141(server, user, sh, timeout=30, selfname=None):
    _fd141["probed"].append(sh)
    return _fd141["probe"]


def _fd_answers141(game_type, tag="v26.5.0", vals=None, probe=("LG265_DIR\n", "", 0)):
    _fd141.update(tag=tag, vals={"webdir": ""} if vals is None else vals, probe=probe, probed=[])
    return _game141.fastdl_answers(None, "u141", "%sserver" % game_type, game_type)


try:
    _p9_patch(_hosts141, "lgsm_release", lambda server, account, selfname: _fd141["tag"])
    _p9_patch(_files141, "lgsm_get_values", lambda server, user, selfname, keys: _fd141["vals"])
    _p9_patch(_smc141, "read_as_game_user", _fd_probe141)
    _fd_res141 = {
        "old_cs": _fd_answers141("cs", tag="v26.4.0"), "unread_gmod": _fd_answers141("gmod", tag=None),
        "cs_dir": _fd_answers141("cs"), "gmod_dir": _fd_answers141("gmod"),
        "cs_none": _fd_answers141("cs", probe=("LG265_NODIR\n", "", 0)),
        "gmod_none": _fd_answers141("gmod", probe=("LG265_NODIR\n", "", 0)),
        "cs_failed": _fd_answers141("cs", probe=("", "timed out", -1)),
    }
    check("fastdl up to v26.4.0, or a release that could not be read: the eight Y's it always had "
          "(every prompt there wants Y, and up to v26.3.0 one with no answer left loops for ever)",
          _fd_res141["old_cs"] == ["Y"] * 8 and _fd_res141["unread_gmod"] == ["Y"] * 8, repr(_fd_res141))
    check("fastdl on v26.5.0 with its directory there: N to 'Rebuild from scratch?' (the incremental run), "
          "then gmod's 'Force clients' Y, then 'Continue?' Y, and nothing more",
          _fd_res141["cs_dir"] == ["N", "Y"] and _fd_res141["gmod_dir"] == ["N", "Y", "Y"], repr(_fd_res141))
    check("fastdl on v26.5.0 with no directory yet: no rebuild question is asked, so no leading N "
          "(it would land on 'Force clients' or 'Continue?')",
          _fd_res141["cs_none"] == ["Y"] and _fd_res141["gmod_none"] == ["Y", "Y"], repr(_fd_res141))
    check("fastdl on v26.5.0, directory read failed: answered as no directory (a directory that is there "
          "then ends at 'Continue?' with exit 2 before anything is cleared, never N to 'Continue?')",
          _fd_res141["cs_failed"] == ["Y"], repr(_fd_res141))
    _fd_answers141("cs")
    _fd_def141 = list(_fd141["probed"])
    _fd_answers141("cs", vals={"webdir": "${rootdir}/web"})
    _fd_root141 = list(_fd141["probed"])
    _fd_odd141 = _fd_answers141("cs", vals={"webdir": "$HOME/web"})
    check("fastdl: the directory probed is LinuxGSM's ${webdir}/fastdl, ${rootdir}/public_html by default, "
          "the account's home as rootdir",
          len(_fd_def141) == 1 and "[ -d /home/u141/public_html/fastdl ]" in _fd_def141[0]
          and len(_fd_root141) == 1 and "[ -d /home/u141/web/fastdl ]" in _fd_root141[0], repr((_fd_def141, _fd_root141)))
    check("fastdl: a webdir only LinuxGSM's bash could expand is not guessed at (no probe, no rebuild N)",
          _fd_odd141 == ["Y"] and _fd141["probed"] == [], repr((_fd_odd141, _fd141["probed"])))
finally:
    _p9_restore_all()

# ...and the caller: the FastDL button's run is given exactly those answers.
_fdruns141 = []
try:
    _p9_arm(who="part141")
    _p9_patch(_lgp141, "warn_minutes", lambda *a, **k: 0)
    _p9_patch_sm("fastdl_answers", lambda server, user, selfname, game_type: ["ANS", game_type])
    _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: (
        _fdruns141.append((action, k.get("answers"))), ("", "", 0))[1])
    _p9_patch(_sd141, "_begin_action_tail", lambda *a, **k: None)
    _p9_patch(_sd141, "_end_action_tail", lambda *a, **k: None)
    with _p9.app_context():
        _sd141._run_teed(_p9, None, P9_GS, "u141", "fastdl", "gmodserver")
        _sd141._run_teed(_p9, None, P9_GS, "u141", "update", "gmodserver")
finally:
    _p9_restore_all()
check("fastdl's run passes the account's own answers (game type from its script name); other long "
      "actions get none",
      _fdruns141 == [("fastdl", ["ANS", "gmod"]), ("update", None)], repr(_fdruns141))


check("part141: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP141_START, repr(_P9_TRIPPED[_TRIP141_START:]))
