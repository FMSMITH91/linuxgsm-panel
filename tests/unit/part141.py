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
      _lgp141.outcome(_BUSY141) == {"code": "lgsm_busy", "kind": "update"}
      and _lgp141.outcome_of(_BUSY_TTY141, 0) == {"code": "lgsm_busy", "kind": "update"},
      repr((_lgp141.outcome(_BUSY141), _lgp141.outcome(_BUSY_TTY141))))
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
          for c in (_upd_cmd141, _mon_cmd141)}
_rows141 = [_cron141._cron_job_row("15 5 * * * " + c, "vhserver", "vhserver", _st141, {})
            for c in (_upd_cmd141, _mon_cmd141)]
check("cron table: the update job's row carries busy; LinuxGSM's monitor job never does (its own "
      "postponed update is the monitor doing its job)",
      _rows141[0].get("busy") is True and _rows141[1].get("busy") is False, repr(_rows141))
_srvjs141 = _read141("static", "js", "server_files.js")
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

check("part141: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP141_START, repr(_P9_TRIPPED[_TRIP141_START:]))
