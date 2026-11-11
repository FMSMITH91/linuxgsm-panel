"""Part 141 of the unit suite: what LinuxGSM v26.5.0 changed under the panel (lgsm-2605).

From a review of LinuxGSM v26.5.0 (2026-11-04) against v26.4.0 and the panel. Held here:

* FastDL: on v26.5.0 "Rebuild Fastdl directory from scratch?" is answered N, so the run is
  incremental and keeps files LinuxGSM did not write; older releases keep their Y's.
* A second update while one runs (#5095): LinuxGSM exits 0 with "Update is already running", which
  is said as that, never as an update that finished, in the console, the audit log, the chat bots
  and the cron table.

HOW IT RUNS. Pure functions with their host reads stubbed on the defining submodule; routes on
part12's app with its transport tripwire armed and every host call stubbed; the cron table's shell
under bash over a scratch directory. Nothing reaches a host or data/.
"""
import os
import shutil as _shutil141
import subprocess as _sp141  # nosec B404 - bash over this part's own scratch files, fixed argv
import tempfile as _tf141

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client, _p9_drain,
                         _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_set)
from panel.ops.ssh_manager import _core as _smc141, cron as _cron141, files as _files141
from panel.ops.ssh_manager import game as _game141, hosts as _hosts141
from panel.routes import _shared as _sh141, server_detail as _sd141
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


def _fd_answers141(game_type, tag="v26.5.0", vals=None, probe=("LG265_DIR\n", "", 0), unread=False,
                   mods="same"):
    _fd141.update(tag=tag, vals=None if unread else ({"webdir": ""} if vals is None else vals),
                  probe=probe, probed=[], mods=tag if mods == "same" else mods)
    return _game141.fastdl_answers(None, "u141", "%sserver" % game_type, game_type)


try:
    _p9_patch(_hosts141, "lgsm_versions", lambda server, account, selfname: (_fd141["tag"], _fd141["mods"]))
    _p9_patch(_files141, "lgsm_get_values", lambda server, user, selfname, keys: _fd141["vals"])
    _p9_patch(_smc141, "read_as_game_user", _fd_probe141)
    _fd_res141 = {
        "old_cs": _fd_answers141("cs", tag="v26.4.0"), "unread_gmod": _fd_answers141("gmod", tag=None),
        "cs_dir": _fd_answers141("cs"), "gmod_dir": _fd_answers141("gmod"),
        "cs_none": _fd_answers141("cs", probe=("LG265_NODIR\n", "", 0)),
        "gmod_none": _fd_answers141("gmod", probe=("LG265_NODIR\n", "", 0)),
        "cs_failed": _fd_answers141("cs", probe=("", "timed out", -1)),
    }
    check("fastdl up to v26.4.0: the eight Y's it always had (every prompt there wants Y, and up to "
          "v26.3.0 one with no answer left loops for ever); a release that could not be read gets no "
          "answers at all (None: not run, since on v26.5.0 the first Y deletes the directory)",
          _fd_res141["old_cs"] == ["Y"] * 8 and _fd_res141["unread_gmod"] is None, repr(_fd_res141))
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
    # The modules are the account's, shared by its instances: update-lgsm from one moves them all.
    _fd_mix141 = {"newmods": _fd_answers141("cs", tag="v26.4.0", mods="v26.5.0"),
                  "oldmix": _fd_answers141("gmod", tag="v26.3.0", mods="v26.4.0"),
                  "modsunread": _fd_answers141("cs", tag="v26.4.0", mods=None),
                  "newscript": _fd_answers141("cs", tag="v26.5.0", mods="v26.4.0")}
    check("fastdl: a v26.4.0 script on v26.5.0 modules (another instance ran update-lgsm) gets v26.5.0's "
          "answers, as does any mismatch (LinuxGSM then runs update-lgsm first, to the newest release); "
          "modules that could not be read under an older script are not guessed at (None: not run)",
          _fd_mix141["newmods"] == ["N", "Y"] and _fd_mix141["oldmix"] == ["N", "Y", "Y"]
          and _fd_mix141["modsunread"] is None and _fd_mix141["newscript"] == ["N", "Y"],
          repr(_fd_mix141))
    _fd_unread141 = _fd_answers141("cs", unread=True)
    check("fastdl: a config that could not be read is not taken as the default webdir (no probe, no "
          "rebuild N)", _fd_unread141 == ["Y"] and _fd141["probed"] == [],
          repr((_fd_unread141, _fd141["probed"])))
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

# ── 2. a second update while one runs ───────────────────────────────────────────────────────────
# v26.5.0 check_update_lock.sh, piped (plain) and on a terminal (its colours and \r repaints).
_E = "\x1b"
_BUSY141 = "[ INFO ] Updating vhserver: Checking update: Update is already running (PID 12855) ... INFO\n"
_BUSY_TTY141 = ("%s[1m\r%s[K[%s[0m .... %s[0m]%s[0m Updating vhserver: Checking update%s[0m ... CHECKING"
                "%s[1m\r%s[K[%s[36m INFO %s[0m]%s[0m Updating vhserver: Checking update: Update is already "
                "running (PID 12855)%s[0m ... %s[36mINFO%s[0m\n" % ((_E,) * 14))
_UPD_OK141 = ("[  OK  ] Updating vhserver: Checking for update: SteamCMD\n\nNo update available\n"
              "* Local build: 123\n")
_GAME_SAYS141 = "player42: Update is already running lol\n"
check("outcome: LinuxGSM's 'Update is already running' is lgsm_busy, piped or on a terminal",
      _lgp141.outcome(_BUSY141, "update") == {"code": "lgsm_busy", "kind": "update"}
      and _lgp141.outcome_of(_BUSY_TTY141, 0, "validate") == {"code": "lgsm_busy", "kind": "update"}
      and _lgp141.outcome_of(_BUSY141, 0, "wu") == {"code": "lgsm_busy", "kind": "update"},
      repr((_lgp141.outcome(_BUSY141, "update"), _lgp141.outcome(_BUSY_TTY141, "validate"))))
# A start with updateonstart="on" runs the same update check (command_start.sh) and starts anyway.
_START_BUSY141 = _BUSY141 + "[  OK  ] Starting vhserver: Valheim\n"
_START_PP141 = ("[ INFO ] Restarting vhserver: 2 players are on the server: restart postponed until the "
                "server is empty\n" + _BUSY141)
check("outcome: the busy line inside a start's or restart's output (updateonstart) is not lgsm_busy: "
      "the start ran, and a restart's own postponement is still what is said",
      _lgp141.outcome_of(_START_BUSY141, 0, "start") is None
      and _lgp141.outcome_of(_START_BUSY141, 0, "restart") is None
      and _lgp141.outcome_of(_START_BUSY141, 0) is None
      and (_lgp141.outcome_of(_START_PP141, 0, "restart") or {}).get("code") != "lgsm_busy",
      repr((_lgp141.outcome_of(_START_BUSY141, 0, "start"), _lgp141.outcome_of(_START_PP141, 0, "restart"))))
check("outcome: an ordinary update, a non-zero exit, and the words outside LinuxGSM's INFO tag are not",
      _lgp141.outcome(_UPD_OK141) is None and _lgp141.outcome_of(_BUSY141, 1) is None
      and _lgp141.outcome(_GAME_SAYS141) is None)
_busy_msg141 = _lgp141.outcome_message({"code": "lgsm_busy", "kind": "update"}, "validate")
check("outcome_message: busy says the action was not run because an update is already running",
      str(_busy_msg141).startswith("'validate' not run: an update of this server is already running"),
      str(_busy_msg141))

_bsruns141 = []
_bsout141 = [(_BUSY141, "", 0)]
_bspushed141 = []
_bsinval141 = []
_bsdone141 = []
try:
    _p9_arm(who="part141")
    _p9_patch(_lgp141, "warn_minutes", lambda *a, **k: 0)
    _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: (_bsruns141.append(action),
                                                                          _bsout141[0])[1])
    _p9_patch_sm("_invalidate_port_scan", lambda rid: _bsinval141.append(("ports", rid)))
    _p9_patch_sm("invalidate_game_version", lambda rid, s: _bsinval141.append(("version", rid)))
    _p9_patch_sm("set_game_priority", lambda *a, **k: None)
    _p9_patch(_sh141, "_drain_action_to_end", lambda app, remote, sid, entry: None)
    _p9_patch(_sh141, "_console_push", lambda app, sid, line: _bspushed141.append(line))
    _p9_set(P9_GS, status="online", restart_pending=False, stop_pending=False, autostart=True)
    _complete_before141 = _p9_audit("update_complete").id
    _A141 = _p9_client(P9_ADMIN)
    _A141.post("/api/server/%d/action" % P9_GS, json={"action": "update"})
    _p9_drain()
    _busy_row141 = _p9_audit("lgsm_busy")
    check("update while another runs: no update_complete row; an lgsm_busy row (not a success) says it",
          _bsruns141 == ["update"] and _p9_audit("update_complete").id == _complete_before141
          and _busy_row141.id is not None and _busy_row141.success is False
          and "update: 'update' not run: an update of this server is already running" in _busy_row141.detail,
          repr((_bsruns141, _busy_row141)))
    check("update while another runs: the console says so, never 'finished successfully'",
          any("[panel] update: 'update' not run" in x for x in _bspushed141)
          and not any("finished successfully" in x for x in _bspushed141), repr(_bspushed141))
    check("update while another runs: the version and port caches are kept (nothing changed on disk)",
          _bsinval141 == [], repr(_bsinval141))
    # The chat bots: their callback hears neither success nor failure, with the panel's sentence.
    _bsruns141.clear()
    _bsout141[0] = (_BUSY141.replace("vhserver", "gmodserver"), "", 0)
    with _p9.app_context():
        _gs141 = _sh141.db.session.get(_sh141.GameServer, P9_GS)
        _sd141._run_action(_p9, _gs141, _gs141.remote, "validate", None, origin="telegram:x",
                           on_done=lambda ok, d: _bsdone141.append((ok, d)))
    _p9_drain()
    check("validate from a chat bot while an update runs: told as neither success nor failure, saying why",
          _bsruns141 == ["validate"] and _bsdone141 and _bsdone141[-1][0] is None
          and _bsdone141[-1][1].startswith("'validate' not run: an update"), repr((_bsruns141, _bsdone141)))
    # ...and an ordinary update still finishes as one.
    _bsout141[0] = (_UPD_OK141, "", 0)
    _A141.post("/api/server/%d/action" % P9_GS, json={"action": "update"})
    _p9_drain()
    check("an ordinary update: still update_complete success, and its version cache dropped",
          _p9_audit("update_complete").success is True and any(k == "version" for k, _r in _bsinval141),
          repr(_bsinval141))
finally:
    _p9_restore_all()

# The cron table: the recorder's shell itself, run under bash over a scratch .lgsm-cron directory.
_cron_sh141 = []
_saved_sh141 = _smc141.shell_as_game_user
try:
    _smc141.shell_as_game_user = lambda s, u, c, **k: (_cron_sh141.append(c), ("", "", 0))[1]
    _cron141._read_cron_status(type("Srv", (), {"id": 9141})(), "vhserver")
finally:
    _smc141.shell_as_game_user = _saved_sh141
_bash141 = _shutil141.which("bash")
_cd141 = "cd %s " % _smc141._quote("/home/vhserver/.lgsm-cron")
check("cron table: the recorder's shell was captured, opening with its cd (what the run below rewrites)",
      len(_cron_sh141) == 1 and _cd141 in _cron_sh141[0], repr(_cron_sh141)[:300])
if _bash141 and len(_cron_sh141) == 1 and _cd141 in _cron_sh141[0]:
    _cdir141 = _tf141.mkdtemp(prefix="part141-cron-")
    try:
        for _jid, _rc, _log in (("busy", 0, _BUSY141), ("pp", 0, "[ INFO ] Stopping vhserver: 2 players are on "
                                                       "the server: stop prevented\n" + _BUSY141),
                                ("ok", 0, _UPD_OK141), ("failed", 1, _BUSY141)):
            with open(os.path.join(_cdir141, _jid + ".status"), "w", encoding="utf-8") as _fh:
                _fh.write("%d 1 2\n" % _rc)
            with open(os.path.join(_cdir141, _jid + ".log"), "w", encoding="utf-8") as _fh:
                _fh.write(_log)
        _cmd141 = _cron_sh141[0].replace(_cd141, "cd %s " % _smc141._quote(_cdir141))
        _cout141 = _sp141.run([_bash141, "-c", _cmd141], capture_output=True, text=True, check=False,  # nosec B603
                              env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C.UTF-8"}).stdout
    finally:
        _shutil141.rmtree(_cdir141, ignore_errors=True)
    _saved_sh141 = _smc141.shell_as_game_user
    try:
        _smc141.shell_as_game_user = lambda s, u, c, **k: (_cout141, "", 0)
        _cst141 = _cron141._read_cron_status(type("Srv", (), {"id": 9141})(), "vhserver")
    finally:
        _smc141.shell_as_game_user = _saved_sh141
    check("cron table: an update LinuxGSM skipped for another one is 'busy', not OK and not postponed; "
          "players-online stays postponed, an ordinary run and a failed one are neither",
          _cst141.get("busy", {}).get("busy") is True and _cst141["busy"].get("postponed") is False
          and _cst141["busy"]["ok"] is True
          and _cst141.get("pp", {}).get("postponed") is True and _cst141["pp"].get("busy") is False
          and _cst141.get("ok", {}).get("busy") is False and _cst141["ok"].get("postponed") is False
          and _cst141.get("failed", {}).get("busy") is False, repr((_cout141, _cst141)))
else:
    skip("cron table: the busy grep over LinuxGSM's output", "bash is not installed")
_upd_cmd141 = "cd /home/vhserver && ./vhserver update"
_mon_cmd141 = "cd /home/vhserver && ./vhserver monitor"
_st141 = {_cron141._cron_job_id(c): {"last_run": 5, "ok": True, "error": "", "busy": True, "postponed": False}
          for c in (_upd_cmd141, _mon_cmd141, "cd /home/vhserver && ./vhserver restart",
                    "cd /home/vhserver && ./vhserver u")}
_rows141 = [_cron141._cron_job_row("15 5 * * * " + c, "vhserver", "vhserver", _st141, {})
            for c in (_upd_cmd141, _mon_cmd141, "cd /home/vhserver && ./vhserver restart",
                      "cd /home/vhserver && ./vhserver u")]
check("cron table: the update job's row carries busy; LinuxGSM's monitor job never does (its own "
      "postponed update is the monitor doing its job)",
      _rows141[0].get("busy") is True and _rows141[1].get("busy") is False, repr(_rows141))
check("cron table: a scheduled restart whose log holds the busy line (updateonstart) is not 'busy'; "
      "the update's alias u is",
      _rows141[2].get("busy") is False and _rows141[3].get("busy") is True, repr(_rows141[2:]))
_srvjs141 = _read141("panel", "static", "js", "server_files.js")
check("cron table's page: a busy run shows its own 'Not run' badge, before the OK one",
      "j.ok === true && j.busy" in _srvjs141
      and _srvjs141.index("j.ok === true && j.busy") < _srvjs141.index("else if(j.ok === true){"))


# ── 3. the backup's archive name without "Completed:" ───────────────────────────────────────────
# v26.5.0's piped output of a backup of a running server (the restart replaces the held
# "Completed:" line) and of one that prunes; v26.4.0's, where the line is there.
_BK_ARC141 = "vhserver-2026-11-04-120000.tar.zst"
_BK_RESTART141 = "[  OK  ] Starting vhserver: LinuxGSM\n"
_BK_PRUNE141 = "[  OK  ] Backup vhserver: Pruning\n"
_BK_OLD141 = ("%s[1m\r%s[K[%s[32m  OK  %s[0m]%s[0m Backup vhserver: Completed: %s[3m%s%s[0m, total size 1.0G"
              % (_E, _E, _E, _E, _E, _E, _BK_ARC141, _E))
_bkcmds141 = []
_saved_sh141 = _smc141.shell_as_game_user
try:
    _smc141.shell_as_game_user = lambda s, u, c, **k: (_bkcmds141.append(c), ("", "", 1))[1]
    _bk_old_name141 = _game141._bkverify_name(None, "vhserver", "vhserver", (100, {}), _BK_OLD141)
    _bk_old_cmds141 = list(_bkcmds141)
    _game141._lg265_bk_after(None, "vhserver", "vhserver")
finally:
    _smc141.shell_as_game_user = _saved_sh141
check("backup name up to v26.4.0: read from its 'Completed:' line, with no host read",
      _bk_old_name141 == _BK_ARC141 and _bk_old_cmds141 == [], repr((_bk_old_name141, _bk_old_cmds141)))
_bkhome141 = "/home/vhserver"
if _bash141 and len(_bkcmds141) == 1 and _bkhome141 in _bkcmds141[0]:
    _bkdir141 = _tf141.mkdtemp(prefix="part141-bk-")
    try:
        os.makedirs(os.path.join(_bkdir141, "lgsm", "backup"))
        os.makedirs(os.path.join(_bkdir141, "log", "script"))
        for _n in (_BK_ARC141, "vhserver-2026-11-04-120001.tar.zst", "vhserver-2026-11-03-120000.tar.zst"):
            with open(os.path.join(_bkdir141, "lgsm", "backup", _n), "w", encoding="utf-8") as _fh:
                _fh.write("x")
        _sl141 = os.path.join(_bkdir141, "log", "script")
        # The backup's own log, rotated by the restart's start, and an older one naming another archive.
        with open(os.path.join(_sl141, "vhserver-script-2026-11-03-12:00:30.log"), "w", encoding="utf-8") as _fh:
            _fh.write("Nov 03 12:00:10.001 vhserver: BACKUP: PASS: Backup created: "
                      "vhserver-2026-11-03-120000.tar.zst, total size 1.0G\n")
        with open(os.path.join(_sl141, "vhserver-script-2026-11-04-12:00:30.log"), "w", encoding="utf-8") as _fh:
            _fh.write("Nov 04 12:00:10.001 vhserver: BACKUP: PASS: Backup created: %s, total size 1.0G\n"
                      "Nov 04 12:00:30.001 vhserver: START: INFO: Rotating log files\n" % _BK_ARC141)
        with open(os.path.join(_sl141, "vhserver-script.log"), "w", encoding="utf-8") as _fh:
            _fh.write("Nov 04 12:00:31.001 vhserver: START: PASS: Started vhserver\n")
        for _i, _n in enumerate(("vhserver-script-2026-11-03-12:00:30.log", "vhserver-script-2026-11-04-12:00:30.log",
                                 "vhserver-script.log")):
            os.utime(os.path.join(_sl141, _n), (1792900000 + _i * 100, 1792900000 + _i * 100))
        _bkout141 = _sp141.run([_bash141, "-c", _bkcmds141[0].replace(_bkhome141, _bkdir141)],  # nosec B603
                               capture_output=True, text=True, check=False,
                               env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C.UTF-8"}).stdout
    finally:
        _shutil141.rmtree(_bkdir141, ignore_errors=True)
    _before141 = (100, {"vhserver-2026-11-03-120000.tar.zst": 50})
    _bkv141 = []
    _saved141 = (_smc141.shell_as_game_user, _game141._r13b_bkverify_code)
    try:
        _smc141.shell_as_game_user = lambda s, u, c, **k: (_bkout141, "", 0)
        _game141._r13b_bkverify_code = lambda server, user, name, started: _bkv141.append(name)
        _bk_names141 = [_game141._bkverify_name(None, "vhserver", "vhserver", _before141, o)
                        for o in (_BK_RESTART141, _BK_PRUNE141)]
        _bk_why141 = _game141._bkverify_unconfirmed(None, "vhserver", "vhserver", _before141, _BK_RESTART141)
        # An older backup's log line (the archive the earlier listing already had) is never this run's.
        _bk_stale141 = _game141._bkverify_name(
            None, "vhserver", "vhserver", (100, {_BK_ARC141: 50, "vhserver-2026-11-03-120000.tar.zst": 50}),
            _BK_RESTART141)
    finally:
        _smc141.shell_as_game_user, _game141._r13b_bkverify_code = _saved141
    check("backup name on v26.5.0 with no 'Completed:' line (restart, prune): LinuxGSM's script log names "
          "it, from the copy the restart rotated, though two archives are new",
          _bk_names141 == [_BK_ARC141, _BK_ARC141], repr((_bk_names141, _bkout141)))
    check("backup name from the script log: that archive is the one checked, and it confirms the backup",
          _bkv141 == [_BK_ARC141] and _bk_why141 is None, repr((_bkv141, _bk_why141)))
    check("backup name: a log line naming an archive the earlier listing already had is not this run's "
          "(the one new archive is)", _bk_stale141 == "vhserver-2026-11-04-120001.tar.zst", repr(_bk_stale141))
else:
    check("backup name: the after-listing's shell was captured, under the account's home", False,
          repr(_bkcmds141)[:300])

# ── 5. querymode 3 is gamedig only ──────────────────────────────────────────────────────────────
# command_monitor.sh fn_monitor_loop: 2 = gamedig then gsquery, 3 = gamedig only, 4 = gsquery,
# 5 = tcp; check_players_online.sh counts with gamedig for 2 and 3. fivem's _default.cfg (v26.5.0):
# querymode="3", querytype="gta5f", its port in server.cfg.
_qm141 = {m: _cron141._lgsm_gamedig_target({"querymode": m, "querytype": "gta5f"}, 30120)
          for m in ("1", "2", "3", "4", "5")}
check("LinuxGSM query: querymodes 2 and 3 are gamedig (type and port), 1, 4 and 5 are not",
      _qm141 == {"1": None, "2": ("gta5f", "30120"), "3": ("gta5f", "30120"), "4": None, "5": None},
      repr(_qm141))
_qcmd141 = []
try:
    _p9_patch(_cron141, "_read_lgsm_query_settings", lambda server, user, selfname: {
        "querymode": "3", "querytype": "gta5f", "queryport": "", "port": ""})
    _p9_patch(_cron141, "_gamedig_reply", lambda server, user, cmd: (_qcmd141.append(cmd), {"c": 4, "ok": True})[1])
    _p9_patch(_smc141, "_gamedig_host", lambda server: "192.0.2.10")
    _qn141 = _cron141.player_count_via_lgsm_query(type("Srv", (), {"id": 9141})(), "fivemserver", "fivemserver",
                                                  fallback_port=30120)
finally:
    _p9_restore_all()
check("player count: a querymode-3 game (fivem) is counted with gamedig at LinuxGSM's type and the "
      "panel's port", _qn141 == 4 and len(_qcmd141) == 1 and "--type gta5f " in _qcmd141[0]
      and ":30120 " in _qcmd141[0], repr((_qn141, _qcmd141)))

# ── 6. LinuxGSM v26.5.0's new games ─────────────────────────────────────────────────────────────
from panel.db import models as _models141  # noqa: E402
from panel.routes import manage_servers as _ms141  # noqa: E402
_sn141 = set(_ln.strip() for _ln in _read141("tests", "unit", "lgsm_shortnames.txt").splitlines()
             if _ln.strip() and not _ln.startswith("#"))
check("shortnames fixture: v26.5.0's serverlist, with its six new games",
      {"bfe", "cswon", "fivem", "hlwon", "luanti", "orar"} <= _sn141 and len(_sn141) == 150
      and "(tag v26.5.0)" in _read141("tests", "unit", "lgsm_shortnames.txt"), len(_sn141))
check("install port: orar and luanti get their own default (their startparameters use ${port}), fivem and "
      "bfe the form's hint, the WON2 servers 27015",
      [_ms141._desired_install_port(g, "27015") for g in ("orar", "luanti", "fivem", "bfe", "hlwon", "cswon")]
      == [1234, 30000, 30120, 18451, 27015, 27015])
check("player warnings: hlwon and cswon take LinuxGSM's `say` (GoldSrc, console interactive); fivem, "
      "luanti, orar and bfe have no warn command",
      {"hlwon", "cswon"} <= _lgp141.WARN_GAMES
      and not {"fivem", "luanti", "orar", "bfe"} & _lgp141.WARN_GAMES)
check("Update: the WON2 servers have none (core_getopt.sh), even before their command list is read",
      _models141.GameServer(game_type="hlwon", commands="[]").supports_update is False
      and _models141.GameServer(game_type="cswon", commands="[]").supports_update is False
      and _models141.GameServer(game_type="fivem", commands="[]").supports_update is True)

_fin141 = []
try:
    _p9_patch(_ms141, "_audit_install", lambda *a, **k: None)
    for _gt in ("fivem", "cs"):
        _job141 = type("J", (), {"short_name": _gt + "server",
                                 "finish": lambda self, msg, warn=False: _fin141.append((str(msg), warn))})()
        _ms141._report_not_started(_job141, type("G", (), {"game_type": _gt, "port": 30120, "name": _gt})(),
                                   1, "")
finally:
    _p9_restore_all()
check("install of FiveM that did not start: the result names the Cfx.re licence key; another game's does not",
      len(_fin141) == 2 and "sv_licenseKey" in _fin141[0][0] and _fin141[0][1] is True
      and "sv_licenseKey" not in _fin141[1][0], repr(_fin141))
_sf_tpl141 = _read141("panel", "templates", "server_files.html")
check("Config tab: FiveM's licence-key note, only on a FiveM server",
      "{% if server.game_type == 'fivem' %}" in _sf_tpl141
      and _sf_tpl141.index("{% if server.game_type == 'fivem' %}") < _sf_tpl141.index('id="lg265-fivem-key"')
      < _sf_tpl141.index("{% endif %}", _sf_tpl141.index("{% if server.game_type == 'fivem' %}")))

# ── 4. a command list update-lgsm has grown (v26.5.0's QuakeWorld `update`) ─────────────────────
_mc141 = []
try:
    _p9_patch(_smc141, "_rewrite_crontab", lambda server, user, grep_args, add_lines, **k: (
        _mc141.append((grep_args, list(add_lines))), (True, "ok"))[1])
    _smc141.add_maintenance_cron(None, "qwserver", "qwserver", {"update", "monitor", "check-update"})
    _smc141.install_game_cron(None, "qwserver", "qwserver", {"monitor", "update", "update-lgsm", "mods-update"})
finally:
    _p9_restore_all()
_upd_line141 = "15 5 * * * " + _cron141._record_managed_cmd("qwserver",
                                                              "cd /home/qwserver && ./qwserver update")
check("add_maintenance_cron: only the command gained is scheduled, as install_game_cron schedules it, "
      "never monitor (the Autostart switch), and only that command's line is replaced",
      len(_mc141) == 2 and _mc141[0][1] == [_upd_line141] and "(update)( |$)" in _mc141[0][0]
      and "monitor" not in _mc141[0][0] and _upd_line141 in _mc141[1][1] and len(_mc141[1][1]) == 4
      and _mc141[1][1][0].startswith("*/5 * * * * "), repr(_mc141))

_QW_OLD141 = [{"cmd": "start", "short": "st", "desc": "Start the server."},
              {"cmd": "update-lgsm", "short": "ul", "desc": "Check and apply any LinuxGSM updates."}]
_QW_NEW141 = _QW_OLD141 + [{"cmd": "update", "short": "u", "desc": "Check and apply any server updates."},
                           {"cmd": "check-update", "short": "cu", "desc": "Check if a gameserver update is available"}]
_rf141 = {"list": _QW_NEW141, "added": [], "refusal": None}
with _p9.app_context():
    _cmds_before141 = _sh141.db.session.get(_sh141.GameServer, P9_GS).commands

class _Lg265StopLoop(BaseException):
    """Ends a `while True` loop under test: NOT an Exception, so the loop's own handlers pass it on.

    A StopIteration thrown through a generator worked on 3.12+ and became RuntimeError on 3.10
    (PEP 479), which killed the unit suite on the 22.04 runner.
    """


def _lg265_stop_sleep(_seconds):
    """The stand-in clock's sleep: one pass of the loop, then stop."""
    raise _Lg265StopLoop()


try:
    _p9_arm(who="part141")
    _p9_patch_sm("list_server_commands", lambda remote, user, selfname=None: list(_rf141["list"]))
    _p9_patch_sm("add_maintenance_cron", lambda remote, user, selfname, cmds: (
        _rf141["added"].append(set(cmds)), (True, "ok"))[1])
    _p9_patch(_sh141, "game_account_write_refusal", lambda *a, **k: _rf141["refusal"])

    def _rf_run141(old, answer, refusal=None):
        _rf141.update(list=answer, refusal=refusal, added=[])
        with _p9.app_context():
            _g = _sh141.db.session.get(_sh141.GameServer, P9_GS)
            _g.set_commands(old)
            _sh141.db.session.commit()
            _got = _sh141.lg265_refresh_commands(_g)
            return _got, [c["cmd"] for c in _sh141.db.session.get(_sh141.GameServer, P9_GS).get_commands()], \
                list(_rf141["added"])
    _rf_grew141 = _rf_run141(_QW_OLD141, _QW_NEW141)
    _rf_empty141 = _rf_run141(_QW_OLD141, [])
    _rf_same141 = _rf_run141(_QW_NEW141, _QW_NEW141)
    _rf_first141 = _rf_run141([], _QW_NEW141)
    _rf_refused141 = _rf_run141(_QW_OLD141, _QW_NEW141, refusal="the host's sudo login")
    check("command refresh: a list that gained update is stored and update scheduled (not check-update, "
          "not monitor)", _rf_grew141 == ({"update"}, ["start", "update-lgsm", "update", "check-update"],
                                          [{"update"}]), repr(_rf_grew141))
    check("command refresh: an empty answer (a failed read) keeps the stored list and schedules nothing",
          _rf_empty141 == (set(), ["start", "update-lgsm"], []), repr(_rf_empty141))
    check("command refresh: an unchanged list writes nothing", _rf_same141[0] == set() and _rf_same141[2] == [],
          repr(_rf_same141))
    check("command refresh: a list never read before is stored, and scheduling is left to the install's cron",
          _rf_first141 == (set(), ["start", "update-lgsm", "update", "check-update"], []), repr(_rf_first141))
    check("command refresh: an account the panel may not write as gets its list, and no crontab write",
          _rf_refused141[0] == set() and _rf_refused141[2] == [] and "update" in _rf_refused141[1],
          repr(_rf_refused141))
    # ...and the server page's Refresh button, which stores the list itself.
    _rf141.update(list=_QW_NEW141, refusal=None, added=[])
    with _p9.app_context():
        _g = _sh141.db.session.get(_sh141.GameServer, P9_GS)
        _g.set_commands(_QW_OLD141)
        _sh141.db.session.commit()
    _rf_btn141 = _p9_client(P9_ADMIN).post("/server/%d/refresh-commands" % P9_GS).status_code
    with _p9.app_context():
        _rf_btn_cmds141 = [c["cmd"] for c in _sh141.db.session.get(_sh141.GameServer, P9_GS).get_commands()]
    check("command refresh from the Refresh button: the list is stored and the update it gained is "
          "scheduled (it was left to a daily pass that then saw nothing new)",
          _rf141["added"] == [{"update"}] and "update" in _rf_btn_cmds141 and _rf_btn141 in (200, 302),
          repr((_rf_btn141, _rf141["added"], _rf_btn_cmds141)))

    # ...and its two callers: a panel update-lgsm that exited 0, and the daily maintenance pass.
    _rfcalls141 = []
    _p9_patch(_sd141, "lg265_refresh_commands", lambda gs: _rfcalls141.append(("action", gs.id)) or set())
    _p9_patch(_sh141, "lg265_refresh_commands", lambda gs: _rfcalls141.append(("pass", gs.id)) or set())
    _ul_rc141 = [0]
    _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: ("", "", _ul_rc141[0]))
    _p9_patch(_sd141, "_after_power_action", lambda *a, **k: None)
    with _p9.app_context():
        _g141 = _sh141.db.session.get(_sh141.GameServer, P9_GS)
        _sd141._run_sync_action(_p9, _g141, _g141.remote, "update-lgsm", None, None)
        _ul_rc141[0] = 1
        _sd141._run_sync_action(_p9, _g141, _g141.remote, "update-lgsm", None, None)
        _ul_rc141[0] = 0
        _sd141._run_sync_action(_p9, _g141, _g141.remote, "details", None, None)
    check("update-lgsm from the panel: the command list is read again after an exit 0 only, and not after "
          "other actions", _rfcalls141 == [("action", P9_GS)], repr(_rfcalls141))
    _rfcalls141.clear()
    import app as _app141  # noqa: E402
    _sh141.lg265_refresh_pass(_p9, _app141._still_in_db)
    check("the daily refresh pass reads every installed server's command list again",
          ("pass", P9_GS) in _rfcalls141, repr(_rfcalls141))
    _ntw141 = []
    _p9_patch(_app141, "_node_tools_cron_pass", lambda app: _ntw141.append("cron"))
    _p9_patch(_sh141, "lg265_refresh_pass", lambda app, still_in_db: _ntw141.append("refresh"))
    # The loop's own clock only (a namespace in place of the module), so no other thread's sleep
    # is touched: its sleep ends the daily loop after one pass.
    _p9_patch(_app141, "time", type("_Clock141", (), {"time": staticmethod(lambda: 0.0),
                                                      "sleep": staticmethod(_lg265_stop_sleep)})())
    try:
        _app141._node_tools_cron_watch(_p9)
    except _Lg265StopLoop:
        pass   # raised by the stand-in sleep above: the one pass is done
    check("the daily node-tools loop runs the command-list refresh after the cron pass",
          _ntw141 == ["cron", "refresh"], repr(_ntw141))
finally:
    _p9_restore_all()
    with _p9.app_context():
        _sh141.db.session.get(_sh141.GameServer, P9_GS).commands = _cmds_before141
        _sh141.db.session.commit()

# ── 8. Action Half-Life on ReHLDS (#5150): an install from before needs one force-update ─────────
_AHL_OUT141 = ("[ WARN ] Starting ahlserver: ReHLDS requires the steam_legacy branch: run ./ahlserver "
               "force-update\n[  OK  ] Starting ahlserver: Action Half-Life\n")
_ahl_out141 = [_AHL_OUT141]
_ahl_push141 = []
try:
    _p9_arm(who="part141")
    _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: (_ahl_out141[0], "", 0))
    _p9_patch_sm("_invalidate_port_scan", lambda rid: None)
    _p9_patch_sm("set_game_priority", lambda *a, **k: None)
    _p9_patch_sm("_remote_listening_ports", lambda remote: None)   # the button's port check (part175)
    _p9_patch(_sd141, "_console_push", lambda app, sid, line, ts=None: _ahl_push141.append((sid, line)))
    _p9_patch(_sh141, "_console_push", lambda app, sid, line, ts=None: _ahl_push141.append((sid, line)))
    with _p9.app_context():
        _g141 = _sh141.db.session.get(_sh141.GameServer, P9_GS)
        _ahl_sync141 = str(_sd141._run_sync_action(_p9, _g141, _g141.remote, "start", None, None)[1])
        _ahl_stop141 = str(_sd141._run_sync_action(_p9, _g141, _g141.remote, "stop", None, None)[1])
        _ahl_out141[0] = "[  OK  ] Starting ahlserver: Action Half-Life\n"
        _ahl_plain141 = str(_sd141._run_sync_action(_p9, _g141, _g141.remote, "start", None, None)[1])
    _ahl_out141[0] = _AHL_OUT141
    _p9_set(P9_GS, status="offline", restart_pending=False, stop_pending=False)
    _p9_client(P9_ADMIN).post("/api/server/%d/action" % P9_GS, json={"action": "start"})
    _p9_drain()
finally:
    _p9_restore_all()
_AHL_NOTE141 = str(_sd141._LG265_AHL_NOTE)
check("AHL start: fix_ahl.sh's steam_legacy warning becomes the one-line note naming force-update, after "
      "the start's own outcome", _ahl_sync141.endswith(_AHL_NOTE141) and "succeeded" in _ahl_sync141
      and "run force-update once (Maintenance menu)" in _AHL_NOTE141, repr(_ahl_sync141))
check("AHL start: no note on a start without the warning, nor on a stop", _AHL_NOTE141 not in _ahl_plain141
      and _AHL_NOTE141 not in _ahl_stop141, repr((_ahl_plain141, _ahl_stop141)))
check("AHL start from the button (run in the background): the note is said in the server's console",
      (P9_GS, "[panel] start: " + _AHL_NOTE141) in _ahl_push141, repr(_ahl_push141))
import json as _json141  # noqa: E402
_ahl_tr141 = {lang: _json141.loads(_read141("panel", "translations", lang, "lg265.json")).get(_AHL_NOTE141)
              for lang in ("es", "fr")}
check("AHL note: es and fr translate it (a value of their own, not empty and not the English)",
      all(isinstance(v, str) and v.strip() and v != _AHL_NOTE141 for v in _ahl_tr141.values()),
      repr(_ahl_tr141))

check("part141: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP141_START, repr(_P9_TRIPPED[_TRIP141_START:]))
