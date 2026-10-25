"""Part 138 of the unit suite: LinuxGSM v26.4.0 compatibility (lgsm-2604).

LinuxGSM v26.4.0 (2026-10-18) added in-game player warnings before a stop (`warnplayerstimer`) and
made `stoponlyifnoplayers` postpone updates and backups as well as stops and restarts. Read from its
source and measured on the test host: a stop with a one-minute timer and players on took 66 s; a
stop, restart, update or backup kept from its work by players EXITS 0 and says so only in its
output. Held here:

* LinuxGSM's own output, captured on the test host, read as what it was: refused or postponed, and
  nothing read that way from an ordinary stop.
* The warning timer reaches every panel path that stops a server with a timeout (Stop/Restart,
  queued actions, long actions, the clean reboot, uninstall, backups), and an unread config keeps
  the old budget.
* A postponed or refused action is never audited, announced or told to a chat bot as a success or
  a failure; a postponed backup is not "not confirmed" and alerts nothing, and the panel's
  scheduled backup leaves a backup LinuxGSM holds to LinuxGSM.
* The config editor's two controls: offered only on v26.4.0+, the warning only on games LinuxGSM
  can warn on, values validated; the TF2 -norestart notice; workshop-update in the Maintenance menu.
* The reboot dialog's per-server warning lines.

HOW IT RUNS. Pure helpers with their host reads stubbed; routes on part12's app with its transport
tripwire armed; the page scripts in node. Nothing reaches a host or data/.
"""
import os
import subprocess as _sp138  # nosec B404 - grep over this part's own fixtures, fixed argv
import shutil as _shutil138
import time as _time138

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client,
                         _p9_drain, _p9_json, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_set)
from unit.part47 import _cut47, _node47
from panel.ops.ssh_manager import _core as _smc138, cron as _cron138, files as _files138, game as _game138
from panel.routes import _shared as _sh138, server_detail as _sd138, server_files as _sf138
from panel.services import host_reboot as _hr138, lgsm_players as _lgp138, monitoring as _mon138

_TRIP138_START = len(_P9_TRIPPED)


def _read138(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ── LinuxGSM's output, as the test host printed it (v26.4.0, two stand-in players online) ───────
_E = "\x1b"
_OUT_STOP138 = ("%s[1m\n%s[K[%s[0m .... %s[0m]%s[0m Stopping codserver: %s[0m%s[1m\n%s[K[%s[36m INFO %s[0m]"
                "%s[0m Stopping codserver: 2 players are on the server: stop prevented%s[0m\n" % ((_E,) * 12))
_OUT_RESTART138 = ("%s[1m\n%s[K[%s[36m INFO %s[0m]%s[0m Restarting codserver: 2 players are on the server: "
                   "restart postponed%s[0m\n" % ((_E,) * 6))
_OUT_BACKUP138 = ("%s[1m\n%s[K[%s[93m WARN %s[0m]%s[0m Backup codserver: codserver will be restarted%s[0m\n"
                  % ((_E,) * 6) + _OUT_STOP138
                  + "%s[1m\n%s[K[%s[36m INFO %s[0m]%s[0m Stopping codserver: Backup postponed until the "
                    "server is empty%s[0m\n" % ((_E,) * 6))
_OUT_UPDATE138 = (_OUT_STOP138.replace("codserver", "gmodserver")
                  + "%s[K[%s[36m INFO %s[0m]%s[0m Stopping gmodserver: Update postponed until the server "
                    "is empty%s[0m\n" % ((_E,) * 5))
_OUT_WARNSTOP138 = ("%s[K[%s[36m INFO %s[0m]%s[0m Stopping codserver: Warning players: stopping in 1 "
                    "minute(s)%s[0m\n%s[K[%s[32m  OK  %s[0m]%s[0m Stopping codserver: Graceful: sending "
                    "\"quit\": 2%s[0m ... %s[32mOK%s[0m\n" % ((_E,) * 12))

_oc138 = {k: _lgp138.outcome(v) for k, v in (("stop", _OUT_STOP138), ("restart", _OUT_RESTART138),
                                              ("backup", _OUT_BACKUP138), ("update", _OUT_UPDATE138),
                                              ("warn", _OUT_WARNSTOP138), ("empty", ""))}
check("LinuxGSM output: a stop kept from its work by players is read as refused, with the count",
      _oc138["stop"] == {"code": "lgsm_refused", "kind": "stop", "players": 2}, repr(_oc138["stop"]))
check("LinuxGSM output: a restart, a backup and an update kept by players are each read as postponed "
      "(they leave a request LinuxGSM's monitor runs)",
      _oc138["restart"] == {"code": "lgsm_postponed", "kind": "restart", "players": 2}
      and _oc138["backup"] == {"code": "lgsm_postponed", "kind": "backup", "players": 2}
      and _oc138["update"] == {"code": "lgsm_postponed", "kind": "update", "players": 2}, repr(_oc138))
check("LinuxGSM output: a stop that warned and then stopped, and no output at all, are read as done",
      _oc138["warn"] is None and _oc138["empty"] is None, repr(_oc138))
check("LinuxGSM output: the phrase outside LinuxGSM's INFO tag (a game's own console text) is not read",
      _lgp138.outcome("[ OK ] chat: 2 players are on the server: stop prevented\n") is None)

# ── the warning timer ───────────────────────────────────────────────────────────────────────────
check("warnplayerstimer: read as LinuxGSM reads it — digits are minutes, anything else is off",
      [_lgp138.warn_minutes_value(v) for v in ("15", '"5"', "", "abc", "-1", "٣", None, "0")]
      == [15, 5, 0, 0, 0, 0, 0, 0])

_srv138 = type("Srv", (), {"id": 9138})()
_reads138 = []


def _vals138(answer):
    def _get(server, user, selfname, keys):
        _reads138.append((user, selfname, tuple(keys)))
        return answer
    return _get


_saved_get138 = _files138.lgsm_get_values
try:
    _lgp138._lg264_cache.clear()
    _files138.lgsm_get_values = _vals138({"warnplayerstimer": "5"})
    _al138 = {a: _lgp138.allowance_seconds(_srv138, "u1", "s1", a)
              for a in ("stop", "restart", "update", "backup", "workshop-update", "force-update",
                        "validate", "start")}
    _n_reads138 = len(_reads138)
    _again138 = _lgp138.allowance_seconds(_srv138, "u1", "s1", "stop")
    check("warning allowance: a 5-minute timer gives stop, restart, update, backup and workshop-update "
          "300 s plus slack; force-update, validate and start never warn and get none",
          all(_al138[a] == 5 * 60 + _lgp138._LG264_WARN_SLACK
              for a in ("stop", "restart", "update", "backup", "workshop-update"))
          and _al138["force-update"] == _al138["validate"] == _al138["start"] == 0, repr(_al138))
    check("warning allowance: the timer is read once and cached, from the merged LinuxGSM config",
          _n_reads138 == 1 and len(_reads138) == 1 and _again138 == _al138["stop"]
          and _reads138[0] == ("u1", "s1", ("warnplayerstimer", "stoponlyifnoplayers")), repr(_reads138))
    _lgp138._lg264_cache.clear()
    _files138.lgsm_get_values = _vals138(None)
    check("warning allowance: a config that could not be read keeps the caller's own budget (adds 0), "
          "and is not cached as 'off'",
          _lgp138.timeout_for(_srv138, "u2", "s2", "stop", 60) == 60 and not _lgp138._lg264_cache,
          repr(_lgp138._lg264_cache))
    _files138.lgsm_get_values = _vals138({"warnplayerstimer": "99999"})
    check("warning allowance: a hand-written timer past a day is held to a day",
          _lgp138.allowance_seconds(_srv138, "u3", "s3", "stop") == 24 * 3600 + _lgp138._LG264_WARN_SLACK)
finally:
    _files138.lgsm_get_values = _saved_get138
    _lgp138._lg264_cache.clear()


def _with_minutes138(minutes):
    return lambda *a, **k: minutes


# ── the clean reboot's stop of one server ───────────────────────────────────────────────────────
_job138 = object.__new__(_hr138._Job)
_job138.remote = _srv138
_job138.job = {"mode": "when_empty"}
_runs138 = []
_shells138 = []
_saved138 = (_lgp138.warn_minutes, _smc138.run_as_game_user, _hr138.probe_server, _smc138.shell_as_game_user)
try:
    _smc138.shell_as_game_user = lambda remote, user, sh, **k: (_shells138.append((user, sh, k.get("timeout"))),
                                                                ("Graceful: sending \"quit\": 2 ... OK", "", 0))[1]
    _lgp138.warn_minutes = _with_minutes138(10)
    _smc138.run_as_game_user = lambda remote, user, action, **k: (_runs138.append((action, k["timeout"])),
                                                                   (_OUT_STOP138, "", 0))[1]
    _hr138.probe_server = lambda remote, e: {"session": 1}
    _e138 = {"id": 1, "user": "codserver", "selfname": "codserver", "game_type": "cod", "name": "cod"}
    _job138._stop_one(_e138)
    check("reboot (wait for empty): a stop LinuxGSM refuses is not forced (players joined: the plan bounces)",
          _shells138 == [], repr(_shells138))
    check("reboot: a server's stop is given STOP_BUDGET plus its warnplayerstimer (10 min)",
          _runs138 == [("stop", _hr138.STOP_BUDGET + 600 + _lgp138._LG264_WARN_SLACK)], repr(_runs138))
    check("reboot: a stop LinuxGSM refused (players on, stoponlyifnoplayers) is recorded as refused, and "
          "the server as still running",
          _e138["stop"] == "still_running" and _e138["lgsm_refused"] is True, repr(_e138))
    _job138.entries, _job138.unread, _job138.disconnected = [dict(_e138, owner="monitor")], 0, 2
    _ann138 = _job138._announce_text(0)
    check("reboot: the announcement says LinuxGSM refused to stop it and the shutdown ended it",
          "LinuxGSM refused to stop 1" in _ann138 and "the shutdown ended it" in _ann138, _ann138)
    _runs138.clear()
    _lgp138.warn_minutes = _with_minutes138(None)
    _e138t = dict(_e138, game_type="sdtd")
    _job138._stop_one(_e138t)
    check("reboot: an unread timer keeps the old budget (the telnet games' 600 s here), never less",
          _runs138 == [("stop", _hr138.STOP_BUDGET_TELNET)], repr(_runs138))
    # A forced reboot ("now", players on): LinuxGSM's own stop with stoponlyifnoplayers set aside.
    _runs138.clear()
    _lgp138.warn_minutes = _with_minutes138(10)
    _job138.job = {"mode": "now"}
    _hr138.probe_server = lambda remote, e: {"session": 0}
    _e138f = dict(_e138)
    _job138._stop_one(_e138f)
    _bud138 = _hr138.STOP_BUDGET + 600 + _lgp138._LG264_WARN_SLACK
    check("forced reboot: a stop LinuxGSM refused (stoponlyifnoplayers) is run again as LinuxGSM's own stop "
          "with the setting readonly off, with the warning's budget, and the server is stopped — not left "
          "to the shutdown",
          _runs138 == [("stop", _bud138)]
          and _shells138 == [("codserver", "cd /home/codserver && readonly stoponlyifnoplayers=off"
                                           " && source ./codserver stop 2>&1", _bud138)]
          and _e138f["stop"] == "stopped" and _e138f["lgsm_refused"] is False, repr((_runs138, _shells138)))
    _runs138.clear()
    _shells138.clear()
    _smc138.run_as_game_user = lambda remote, user, action, **k: (_runs138.append((action, k["timeout"])),
                                                                   (_OUT_WARNSTOP138, "", 0))[1]
    _job138._stop_one(dict(_e138))
    check("forced reboot: ...a stop LinuxGSM did not refuse is not run a second time",
          _runs138 == [("stop", _bud138)] and _shells138 == [], repr((_runs138, _shells138)))
finally:
    (_lgp138.warn_minutes, _smc138.run_as_game_user, _hr138.probe_server,
     _smc138.shell_as_game_user) = _saved138

# The bypass itself, in bash (the CI runners' 5.1-5.3, this machine's): an instance script that
# sources a cfg setting stoponlyifnoplayers="on" sees "off", and carries on past the refused assignment.
_bash138 = _shutil138.which("bash")
if _bash138:
    import tempfile as _tf138
    _d138 = _tf138.mkdtemp()
    with open(os.path.join(_d138, "fakeserver"), "w", encoding="utf-8") as _fh:
        _fh.write('source "$(dirname "${BASH_SOURCE[0]}")/x.cfg"\necho "cmd=$1 stoponlyifnoplayers=${stoponlyifnoplayers}"\n')
    with open(os.path.join(_d138, "x.cfg"), "w", encoding="utf-8") as _fh:
        _fh.write('stoponlyifnoplayers="on"\n')
    _rb138 = _sp138.run([_bash138, "-c", _lgp138._LG264_FORCED_STOP % (_d138, "fakeserver")],  # nosec B603 - fixed fixture
                        capture_output=True, text=True, check=False, env={"PATH": os.defpath})
    _plain138 = _sp138.run([_bash138, "-c", "cd %s && source ./fakeserver stop" % _d138],  # nosec B603 - fixed fixture
                           capture_output=True, text=True, check=False, env={"PATH": os.defpath})
    check("forced-reboot stop: bash keeps the readonly value through the instance cfg's own assignment and "
          "runs on (without it the cfg's \"on\" wins)",
          "cmd=stop stoponlyifnoplayers=off" in _rb138.stdout and "readonly variable" in _rb138.stdout
          and "stoponlyifnoplayers=on" in _plain138.stdout, repr((_rb138.stdout, _plain138.stdout)))
else:
    skip("forced-reboot stop: the readonly bypass in bash", "bash is not installed")

# Players are warned once: where LinuxGSM has a warning timer on a game it can warn on, the panel's own
# 60 s countdown leaves that server out.
_saved_pw138 = _lgp138.warn_minutes
try:
    _wm138 = {"gmodserver": 5, "csgoserver": 0}       # tf2server and any other: unread (None)
    _lgp138.warn_minutes = lambda remote, user, selfname, fresh=False: _wm138.get(user)
    with _p9.app_context():
        _rows138 = [{"id": g.id, "name": g.name} for g in _sh138.GameServer.query.all()]
        _types138 = {g.id: (g.game_type, g.short_name) for g in _sh138.GameServer.query.all()}
        _pw138 = _lgp138.panel_warned(_srv138, _rows138)
    _left138 = {_types138[r["id"]][1] for r in _pw138}
    _gone138 = {_types138[r["id"]][1] for r in _rows138} - _left138
    check("forced reboot: no double warning — a server LinuxGSM warns (a timer on a game it can warn on) is "
          "left out of the panel's 60 s countdown; one with no timer, an unread timer, or a game LinuxGSM "
          "cannot warn on keeps the panel's",
          "gmodserver" in _gone138 and {"csgoserver", "tf2server"} <= _left138
          and _gone138 == {sn for gt, sn in _types138.values() if _wm138.get(sn) and gt in _lgp138.WARN_GAMES}
          and _lgp138.panel_warned(_srv138, []) == [], repr((_left138, _gone138, _types138)))
finally:
    _lgp138.warn_minutes = _saved_pw138
check("forced reboot: the job's countdown is the panel_warned rows (LinuxGSM's own warning wins)",
      "warn = _lgp.panel_warned(self.remote, warnable(census))" in _read138("panel", "services", "host_reboot.py"))

# The stop phase's own cap grows by the longest account's warnings (serial within an account).
_sp_src138 = _read138("panel", "services", "host_reboot.py")
_saved_wb138 = _lgp138.warn_minutes
try:
    _lgp138.warn_minutes = lambda server, user, selfname, fresh=False: {"a": 2, "b": 1, "c": 10}[selfname]
    _wb138 = _lgp138.reboot_warn_budget(_srv138, {"u1": [{"user": "u1", "selfname": "a"},
                                                         {"user": "u1", "selfname": "b"}],
                                                  "u2": [{"user": "u2", "selfname": "c"}]})
finally:
    _lgp138.warn_minutes = _saved_wb138
check("reboot: the stop phase's deadline adds the longest account's summed warnings (one account's "
      "servers stop one after another), and the job uses it",
      _wb138 == 10 * 60 + _lgp138._LG264_WARN_SLACK
      and _lgp138.reboot_warn_budget(_srv138, {}) == 0
      and "STOP_PHASE_CAP + _lgp.reboot_warn_budget(self.remote, groups)" in _sp_src138, repr(_wb138))

# The reboot dialog's per-server fields, from the preview.
_saved_wm138 = (_lgp138.warn_minutes,)
try:
    _lgp138.warn_minutes = _with_minutes138(7)
    _p9_patch(_lgp138, "settings", lambda *a, **k: {"minutes": 7, "stop_only": True})
    _p9_patch_sm("moderation_caps", lambda gt: {"say": gt == "cs"})
    _gs138 = type("GS", (), {"short_name": "a", "lgsm_name": "a", "game_type": "cs"})()
    _wf138 = _lgp138.reboot_warn_fields(_srv138, _gs138, {"session": 1})
    _wf138s = _lgp138.reboot_warn_fields(_srv138, _gs138, {"session": 0})
    _gs138.game_type = "rust"
    _wf138b = _lgp138.reboot_warn_fields(_srv138, _gs138, {"session": 1})
    check("reboot preview: a running server carries its warning minutes, whether LinuxGSM can warn on its "
          "game, and whether the panel's own 60 s countdown reaches it",
          _wf138 == {"warn_minutes": 7, "stop_only_if_empty": True, "warn_supported": True, "say": True}
          and _wf138b == {"warn_minutes": 7, "stop_only_if_empty": True, "warn_supported": False,
                          "say": False} and _wf138s == {},
          repr((_wf138, _wf138b, _wf138s)))
finally:
    _lgp138.warn_minutes = _saved_wm138[0]
    _p9_restore_all()

# ── the expected-offline window starts when the stop does ───────────────────────────────────────
_mon138_before = dict(_mon138._expected_offline), dict(_mon138._expected_stop)
try:
    _t0 = _time138.time()
    _mon138._mark_expected_offline(913801, "restart", extra=900)
    check("monitor: a restart that first warns for 15 min is expected offline from then, not from the click",
          _mon138._expected_offline[913801] >= _t0 + 900 and _mon138._offline_expected(913801))
    _mon138._mark_expected_offline(913802, "stop", extra=900)
    check("monitor: a warned stop's quiet window is still a Stop's (stays down, never paged)",
          _mon138._stop_expected(913802))
    _mon138._mark_expected_offline(913803, "restart")
    check("monitor: with no warning (extra 0) the window starts at the click, as before",
          _t0 <= _mon138._expected_offline[913803] <= _time138.time())
finally:
    for _k in (913801, 913802, 913803):
        _mon138._expected_offline.pop(_k, None)
        _mon138._expected_stop.pop(_k, None)
check("monitor: those marks touched only their own servers' entries (the maps are as they were)",
      (dict(_mon138._expected_offline), dict(_mon138._expected_stop)) == _mon138_before)

# ── Stop / Restart / Update from the panel: timeouts, audit rows, console, chat bots ────────────
_sdruns138 = []
_sdout138 = [("", "", 0)]
_pushed138 = []
_done138 = []


def _sdrun138(remote, user, action, **k):
    _sdruns138.append((action, k.get("timeout")))
    return _sdout138[0]


try:
    _p9_arm(who="part138")
    _p9_patch(_lgp138, "warn_minutes", _with_minutes138(2))
    _p9_patch_sm("run_as_game_user", _sdrun138)
    _p9_patch_sm("_invalidate_port_scan", lambda rid: None)
    _p9_patch_sm("invalidate_game_version", lambda rid, s: None)
    _p9_patch_sm("set_game_priority", lambda *a, **k: None)
    _p9_patch(_sh138, "_drain_action_to_end", lambda app, remote, sid, entry: None)
    _p9_patch(_sh138, "_console_push", lambda app, sid, line: _pushed138.append(line))
    _p9_set(P9_GS, status="online", restart_pending=False, stop_pending=True, autostart=True)
    _A138 = _p9_client(P9_ADMIN)

    # Stop, refused by LinuxGSM.
    _sdout138[0] = (_OUT_STOP138, "", 0)
    _r138 = _A138.post("/api/server/%d/action" % P9_GS, json={"action": "stop"})
    check("Stop: the click is accepted at once (the stop runs in the background, warning first)",
          _r138.status_code == 200 and (_r138.get_json() or {}).get("success") is True, repr(_r138.get_json()))
    _p9_drain()
    _ref138 = _p9_audit("lgsm_refused")
    check("Stop: the stop is given its 60 s plus the 2-minute warning",
          _sdruns138 == [("stop", 60 + 120 + _lgp138._LG264_WARN_SLACK)], repr(_sdruns138))
    check("Stop refused by LinuxGSM: audited as lgsm_refused (not 'stop_server' success), saying why",
          _ref138.id is not None and _ref138.success is False
          and "Stop refused: players are online" in _ref138.detail
          and _p9_audit("stop_server").detail.find("stop prevented") < 0, repr(_ref138))
    with _p9.app_context():
        _gs138r = _sh138.db.session.get(_sh138.GameServer, P9_GS)
        _pend138 = _gs138r.stop_pending
    check("Stop refused: a queued 'stop when empty' is kept (the refused stop did nothing)", _pend138 is True)

    # Restart, postponed: the chat bot's callback hears neither success nor failure.
    _sdruns138.clear()
    _sdout138[0] = (_OUT_RESTART138, "", 0)
    with _p9.app_context():
        _gs138r = _sh138.db.session.get(_sh138.GameServer, P9_GS)
        _sd138._run_action(_p9, _gs138r, _gs138r.remote, "restart", None, origin="telegram:x",
                           on_done=lambda ok, d: _done138.append((ok, d)))
    _p9_drain()
    check("Restart: given its 90 s plus the warning, and postponed is told to the bot as neither "
          "success nor failure, with the panel's sentence",
          _sdruns138 == [("restart", 90 + 120 + _lgp138._LG264_WARN_SLACK)]
          and _done138 and _done138[-1][0] is None and _done138[-1][1].startswith("Restart postponed"),
          repr((_sdruns138, _done138)))
    check("Restart postponed: audited as lgsm_postponed, not a failure",
          _p9_audit("lgsm_postponed").success is True
          and "restart: Restart postponed" in _p9_audit("lgsm_postponed").detail)

    # Update (a long action), postponed: its console says so, and no update_complete row.
    _sdruns138.clear()
    _pushed138.clear()
    _complete_before138 = _p9_audit("update_complete").id
    _sdout138[0] = (_OUT_UPDATE138, "", 0)
    _A138.post("/api/server/%d/action" % P9_GS, json={"action": "update"})
    _p9_drain()
    check("Update: the long action's 30 min is given the warning on top",
          _sdruns138 == [("update", 1800 + 120 + _lgp138._LG264_WARN_SLACK)], repr(_sdruns138))
    check("Update postponed: the console says it was postponed, never 'finished successfully'",
          any("[panel] update: Update postponed" in x for x in _pushed138)
          and not any("finished successfully" in x for x in _pushed138), repr(_pushed138))
    check("Update postponed: no update_complete row; an lgsm_postponed row says it",
          _p9_audit("update_complete").id == _complete_before138
          and "update: Update postponed" in _p9_audit("lgsm_postponed").detail)

    # Autostart off: the sentence does not promise LinuxGSM's monitor will run it.
    _p9_set(P9_GS, autostart=False)
    _A138.post("/api/server/%d/action" % P9_GS, json={"action": "update"})
    _p9_drain()
    check("Update postponed with Autostart off: says the monitor will not run it, not that LinuxGSM will",
          "Autostart is off for this server" in _p9_audit("lgsm_postponed").detail
          and any("Autostart is off" in x for x in _pushed138), _p9_audit("lgsm_postponed").detail)
    _p9_set(P9_GS, autostart=True, stop_pending=False)

    # An ordinary stop (warned, then stopped) is still a success.
    _sdout138[0] = (_OUT_WARNSTOP138, "", 0)
    _A138.post("/api/server/%d/action" % P9_GS, json={"action": "stop"})
    _p9_drain()
    check("Stop that warned and then stopped: still 'stop_server' success",
          _p9_audit("stop_server").success is True and "Graceful" in _p9_audit("stop_server").detail)

    # workshop-update is a runnable long action now, refused by LinuxGSM with players on.
    _p9_set(P9_GS, status="online")
    _sdout138[0] = (_OUT_STOP138, "", 0)
    _sdruns138.clear()
    _d138 = _A138.post("/api/server/%d/action" % P9_GS, json={"action": "workshop-update"}).get_json() or {}
    _p9_drain()
    check("workshop-update: runs as a long action (with the warning allowance) and a refusal says it "
          "was not applied", _d138.get("success") is True
          and _sdruns138 == [("workshop-update", 1800 + 120 + _lgp138._LG264_WARN_SLACK)]
          and "Workshop update not applied" in _p9_audit("lgsm_refused").detail, repr((_d138, _sdruns138)))

    # The queued 'restart when empty' that LinuxGSM postpones: LinuxGSM owns it when its monitor runs.
    _sdout138[0] = (_OUT_RESTART138, "", 0)
    _sdruns138.clear()
    with _p9.app_context():
        _gs138r = _sh138.db.session.get(_sh138.GameServer, P9_GS)
        _gs138r.restart_pending = True
        _sh138.db.session.commit()
        _qok138 = _sh138._run_queued_action(_p9, _gs138r)
        _qpend138 = _gs138r.restart_pending
    check("queued restart: given the warning allowance; postponed by LinuxGSM with Autostart on, the "
          "panel's queue is cleared (both would restart it) and it is not a success",
          _sdruns138 == [("restart", 90 + 120 + _lgp138._LG264_WARN_SLACK)]
          and _qok138 is False and _qpend138 is False, repr((_sdruns138, _qok138, _qpend138)))
    _sdout138[0] = (_OUT_STOP138, "", 0)
    with _p9.app_context():
        _gs138r = _sh138.db.session.get(_sh138.GameServer, P9_GS)
        _gs138r.stop_pending, _gs138r.restart_pending = True, False
        _sh138.db.session.commit()
        _sh138._run_queued_action(_p9, _gs138r)
        _qpend138 = _gs138r.stop_pending
        _gs138r.stop_pending = False
        _sh138.db.session.commit()
    check("queued stop refused by LinuxGSM: stays queued for the next empty tick", _qpend138 is True)
finally:
    _p9_restore_all()

# The chat bots: a None outcome is its own reply.
for _bot138 in ("telegram", "discord"):
    _bsrc138 = _read138("panel", "services", "bots", _bot138 + ".py")
    check("%s bot: an action LinuxGSM postponed or refused is replied to as such (⏳), before the success "
          "branch" % _bot138, "if ok is None:" in _bsrc138
          and _bsrc138.index("if ok is None:") < _bsrc138.index("finished.\" % (name, action)"))

# ── backups: LinuxGSM's postponed backup is neither a failure nor run twice ─────────────────────
_bk138 = {"probe": "-\t0\t1\t" + _game138._LG264_BK_END, "runs": [], "pruned": 0, "listing": []}


def _bk_shell138(server, user, cmd, timeout=30, selfname=None):
    if "backup-request.lock" in cmd:
        return _bk138["probe"] + "\n", "", 0
    return "", "", 0


_saved_bk138 = (_smc138.shell_as_game_user, _smc138.run_as_game_user, _game138._backup_players_online,
                _cron138._ensure_backup_headroom, _game138._backup_space_refusal, _game138._bkpart_listing,
                _game138._bkprune_after_success, _cron138.list_game_backups, _lgp138.warn_minutes)
try:
    _smc138.shell_as_game_user = _bk_shell138
    _smc138.run_as_game_user = lambda s, u, a, **k: (_bk138["runs"].append((a, k.get("timeout"))),
                                                     (_OUT_BACKUP138, "", 0))[1]
    _game138._backup_players_online = lambda *a: None
    _cron138._ensure_backup_headroom = lambda *a: ""
    _game138._backup_space_refusal = lambda *a: None
    _game138._bkpart_listing = lambda *a: None
    _game138._bkprune_after_success = lambda *a: _bk138.__setitem__("pruned", _bk138["pruned"] + 1)
    _cron138.list_game_backups = lambda *a, **k: list(_bk138["listing"])
    _lgp138.warn_minutes = _with_minutes138(3)
    _r = _game138.run_game_backup(_srv138, "codserver", "codserver", 2, game_type="cod")
    check("backup postponed by LinuxGSM: skipped (not failed, not 'not confirmed'), its message says "
          "LinuxGSM runs it, and the run had the warning allowance",
          _r[0] is False and _r[2] is True and str(_r[1]).startswith("Backup postponed: players are online")
          and _lgp138.note_code(_r[1]) == "lgsm_postponed"
          and _bk138["runs"] == [("backup", 3600 + 180 + _lgp138._LG264_WARN_SLACK)], repr((_r, _bk138)))
    _bk138["runs"].clear()
    _bk138["probe"] = "1792911269\t1\t1\t" + _game138._LG264_BK_END
    _r = _game138.run_game_backup(_srv138, "codserver", "codserver", 2, game_type="cod", force=True)
    _game138._lg264_bk_waiting.clear()
    check("backup with LinuxGSM's request pending and its monitor running: left to LinuxGSM (nothing run, "
          "even forced), carrying the request time and LinuxGSM's own alert",
          _r[2] is True and _bk138["runs"] == [] and _r[1].code == "lgsm_postponed"
          and _r[1].requested == 1792911269 and _r[1].alerted is True, repr(_r))
    _bk138["probe"] = "1792911269\t0\t0\t" + _game138._LG264_BK_END
    _bk138["runs"].clear()
    _game138.run_game_backup(_srv138, "codserver", "codserver", 2, game_type="cod")
    check("backup with a request but no monitor to run it (Autostart's cron or the monitoring lock "
          "missing): the panel backs it up itself", _bk138["runs"] and _bk138["runs"][0][0] == "backup",
          repr(_bk138["runs"]))
    # Seen waiting (the deferral above records it), then gone with an archive written after it.
    _bk138["probe"] = "1792911269\t0\t1\t" + _game138._LG264_BK_END
    _game138.run_game_backup(_srv138, "codserver", "codserver", 2, game_type="cod")
    _bk138["runs"].clear()
    _bk138["probe"] = "-\t0\t1\t" + _game138._LG264_BK_END
    _bk138["listing"] = [{"name": "codserver-x.tar.zst", "created": 1792911300, "size": 1}]
    _pr0 = _bk138["pruned"]
    _r = _game138.run_game_backup(_srv138, "codserver", "codserver", 2, game_type="cod")
    check("backup: LinuxGSM's request seen, then gone with an archive written after it, is LinuxGSM's "
          "backup — a success, pruned, and nothing run a second time",
          _r[0] is True and _r[2] is False and _r[1].code == "lgsm_done" and _bk138["runs"] == []
          and _bk138["pruned"] == _pr0 + 1, repr(_r))
    _game138.run_game_backup(_srv138, "codserver", "codserver", 2, game_type="cod")
    check("backup: ...once only: the next backup runs", bool(_bk138["runs"]), repr(_bk138["runs"]))
    _bk138["probe"] = "1792911269\t0\t1\t" + _game138._LG264_BK_END
    _game138.run_game_backup(_srv138, "codserver", "codserver", 2, game_type="cod")
    _bk138["probe"] = "-\t0\t1\t" + _game138._LG264_BK_END
    _bk138["listing"] = [{"name": "codserver-x.tar.zst", "created": 1792911000, "size": 1}]
    _bk138["runs"].clear()
    _game138.run_game_backup(_srv138, "codserver", "codserver", 2, game_type="cod")
    check("backup: ...but an archive OLDER than the request is not it: the backup runs",
          bool(_bk138["runs"]), repr(_bk138["runs"]))
    _bk138["probe"] = "garbage"
    _bk138["runs"].clear()
    _game138.run_game_backup(_srv138, "codserver", "codserver", 2, game_type="cod")
    check("backup: an unread request probe decides nothing (the backup runs as before)",
          bool(_bk138["runs"]), repr(_bk138["runs"]))
finally:
    (_smc138.shell_as_game_user, _smc138.run_as_game_user, _game138._backup_players_online,
     _cron138._ensure_backup_headroom, _game138._backup_space_refusal, _game138._bkpart_listing,
     _game138._bkprune_after_success, _cron138.list_game_backups, _lgp138.warn_minutes) = _saved_bk138

# The panel's scheduled sweep: no "Scheduled backup failed", the card says LinuxGSM holds it.
_note138 = _lgp138.note(_lgp138.BACKUP_QUEUED, "lgsm_postponed", requested=1792911269, alerted=True)
_alerts138 = []
try:
    _p9_arm(who="part138")
    _p9_patch(_sh138, "run_game_backup", lambda *a, **k: (False, _note138, True))
    _p9_patch(_sh138.bk, "get_game_schedule", lambda sid: {"interval_days": 1, "last": 1.0, "keep": 2})
    _p9_patch(_sh138.bk, "game_backup_due", lambda sid: True)
    _p9_patch(_sh138.bk, "overdue_alerted", lambda sid: None)
    _p9_patch(_sh138.bk, "mark_overdue_alerted", lambda sid, v: None)
    _p9_patch(_sh138, "_alert_backup", lambda app, gs, title, body: _alerts138.append(title))
    _p9_patch(_sh138, "_lg264_lgsm_alerted", lambda gs, reason: True)
    with _p9.app_context():
        _gsb138 = _sh138.db.session.get(_sh138.GameServer, P9_GS)
        _tgt138 = (_gsb138.id, _gsb138.remote, _gsb138.short_name, _gsb138.lgsm_name, _gsb138.name,
                   _gsb138.game_type, _gsb138.port, _gsb138.query_type, _sh138.row_birth(_gsb138))
        _sh138._back_up_if_due(_p9, _tgt138)
    _st138 = _sh138._game_backup_status.get(P9_GS) or {}
    check("scheduled backup held by LinuxGSM: the card's status carries code lgsm_postponed (no 'Back up "
          "anyway') and LinuxGSM's sentence, and it stays due (no clock, no failure row)",
          _st138.get("code") == "lgsm_postponed" and _st138.get("busy") is True
          and _st138.get("msg") == str(_lgp138.BACKUP_QUEUED), repr(_st138))
    check("scheduled backup held by LinuxGSM, overdue, LinuxGSM already alerted through its own channel: "
          "audited, not alerted a second time", _alerts138 == []
          and _p9_audit("scheduled_backup_overdue").id is not None, repr(_alerts138))
    _p9_patch(_sh138, "_lg264_lgsm_alerted", lambda gs, reason: False)
    _p9_patch(_sh138.bk, "get_game_schedule", lambda sid: {"interval_days": 1, "last": 2.0, "keep": 2})
    _p9_patch(_sh138, "_overdue_reported", {})
    with _p9.app_context():
        _sh138._back_up_if_due(_p9, _tgt138)
    check("...and when LinuxGSM has not alerted (or has no alert on), the panel's overdue alert goes out",
          _alerts138 == ["Scheduled backup overdue"], repr(_alerts138))
    _p9_patch(_sh138, "run_game_backup",
              lambda *a, **k: (True, _lgp138.note(_lgp138.BACKUP_DONE_BY_LGSM, "lgsm_done"), False))
    with _p9.app_context():
        _sh138._back_up_if_due(_p9, _tgt138)
    _st138 = _sh138._game_backup_status.get(P9_GS) or {}
    check("scheduled backup: LinuxGSM's finished backup is recorded as this server's backup, a success",
          _st138.get("ok") is True and "code" not in _st138 and _p9_audit("scheduled_backup").success is True
          and "Backed up by LinuxGSM" in _p9_audit("scheduled_backup").detail, repr(_st138))
finally:
    _p9_restore_all()
    _sh138._game_backup_status.pop(P9_GS, None)

_saved_gv138 = _files138.lgsm_get_values
try:
    _gsx = type("G", (), {"remote": _srv138, "short_name": "a", "lgsm_name": "a"})()
    _files138.lgsm_get_values = lambda *a, **k: {"discordalert": "on"}
    _n_al = _lgp138.note(_lgp138.BACKUP_QUEUED, "lgsm_postponed", alerted=True)
    _n_no = _lgp138.note(_lgp138.BACKUP_QUEUED, "lgsm_postponed", alerted=False)
    _a1 = _sh138._lg264_lgsm_alerted(_gsx, _n_al)
    _a2 = _sh138._lg264_lgsm_alerted(_gsx, _n_no)
    _files138.lgsm_get_values = lambda *a, **k: {"discordalert": "off"}
    _a3 = _sh138._lg264_lgsm_alerted(_gsx, _n_al)
    _files138.lgsm_get_values = lambda *a, **k: None
    _a4 = _sh138._lg264_lgsm_alerted(_gsx, _n_al)
    check("LinuxGSM's own backup-postponed alert counts only when it was sent AND one of its alert "
          "channels is on; an unread config counts as not alerted",
          (_a1, _a2, _a3, _a4) == (True, False, False, False), repr((_a1, _a2, _a3, _a4)))
finally:
    _files138.lgsm_get_values = _saved_gv138

_bkjs138 = _read138("static", "js", "remote_manage_backups.js")
_cut_bk138 = _cut47(_bkjs138, "function bkBusyHtml(") + "\n" + _cut47(_bkjs138, "function bkGameStatus(")
_prog_bk138 = ("global.escapeHtml = s => String(s); global._da = () => '';\n" + _cut_bk138 + "\n"
               "console.log(JSON.stringify([bkGameStatus({id: 1}, {busy: true, code: 'lgsm_postponed', msg: 'X'}),"
               " bkGameStatus({id: 1}, {busy: true, msg: 'Y'})]));")
_obk138 = _node47(_prog_bk138)
if _obk138 is None:
    skip("backup card: LinuxGSM-held backup shown without 'Back up anyway'", "node is not installed")
else:
    check("backup card: a backup LinuxGSM holds shows its message without 'Back up anyway'; a panel skip "
          "still offers it", isinstance(_obk138, list) and "Back up anyway" not in _obk138[0]
          and "X" in _obk138[0] and "Back up anyway" in _obk138[1], repr(_obk138))

# ── the config editor: two controls, where they do something ────────────────────────────────────
def _cfg138(supported=True, stop="off", warn="0", querymode="2", sp="", sp_set=False):
    groups = [{"section": "LinuxGSM", "settings": [{"key": k, "value": v} for k, v in (
        ("stoponlyifnoplayers", stop), ("warnplayerstimer", warn), ("maxbackups", "4"))]}]
    return {"groups": groups, "raw": "", "players": {
        "supported": supported, "stoponlyifnoplayers": stop, "warnplayerstimer": warn,
        "querymode": querymode, "startparameters": sp, "startparameters_set": sp_set}}


def _gs_cfg138(game):
    return type("G", (), {"remote": _srv138, "short_name": "a", "lgsm_name": "a", "game_type": game})()


def _keys138(d):
    return [x["key"] for g in d["groups"] for x in g["settings"]]


_saved_rem138 = _lgp138.remember
try:
    _lgp138.remember = lambda *a, **k: None
    _v1 = _lgp138.config_view(_gs_cfg138("gmod"), _cfg138(stop="on", warn="5"))
    _v2 = _lgp138.config_view(_gs_cfg138("rust"), _cfg138(warn="0", querymode="1"))
    _v3 = _lgp138.config_view(_gs_cfg138("rust"), _cfg138(warn="5"))
    _v4 = _lgp138.config_view(_gs_cfg138("gmod"), _cfg138(supported=False))
    _v5 = _lgp138.config_view(_gs_cfg138("tf2"), _cfg138(sp="-game tf +map x", sp_set=True))
    _v6 = _lgp138.config_view(_gs_cfg138("tf2"), _cfg138(sp="-game tf -norestart", sp_set=True))
    _v7 = _lgp138.config_view(_gs_cfg138("tf2"), _cfg138(sp="-game tf", sp_set=False))
finally:
    _lgp138.remember = _saved_rem138
check("config editor: on v26.4.0+ a game LinuxGSM can warn on gets both controls, with their values, and "
      "both keys leave the generic list (edited in one place)",
      _v1["players"] == {"supported": True, "stop_only_if_empty": True, "warn_supported": True,
                         "warn_minutes": 5, "warn_max": 60, "can_count": True}
      and _keys138(_v1) == ["maxbackups"], repr(_v1))
check("config editor: a game LinuxGSM cannot warn on gets no warning control (an unset timer leaves the "
      "list too), and querymode 1 is said: LinuxGSM cannot count its players",
      _v2["players"]["warn_supported"] is False and _v2["players"]["can_count"] is False
      and _keys138(_v2) == ["maxbackups"], repr(_v2))
check("config editor: ...but a timer already set on such a game stays in the generic list, so it can be cleared",
      _keys138(_v3) == ["warnplayerstimer", "maxbackups"], repr(_keys138(_v3)))
check("config editor: before v26.4.0 (no warnplayerstimer in _default.cfg) nothing changes",
      _v4["players"] == {"supported": False} and len(_keys138(_v4)) == 3, repr(_v4))
check("config editor: TF2 with its own startparameters lacking -norestart gets the notice; with it, or "
      "with no override, it does not", _v5["tf2_norestart"] is True and _v6["tf2_norestart"] is False
      and _v7["tf2_norestart"] is False, repr((_v5.get("tf2_norestart"), _v6.get("tf2_norestart"))))
check("config read: 'supported' is warnplayerstimer in the instance's _default.cfg; the override is read "
      "from the instance or common config",
      _files138._lg264_player_settings({"warnplayerstimer": "2"}, {"warnplayerstimer": "0"}, {}, {})["supported"]
      is True and _files138._lg264_player_settings({}, {}, {}, {})["supported"] is False
      and _files138._lg264_player_settings({"startparameters": "x"}, {}, {}, {"startparameters": "x"})
      ["startparameters_set"] is True)

_bad138 = {}
with _p9.test_request_context():
    for _label, _settings in (("on", {"stoponlyifnoplayers": "on"}), ("yes", {"stoponlyifnoplayers": "yes"}),
                              ("15", {"warnplayerstimer": "15"}), ("int15", {"warnplayerstimer": 15}),
                              ("61", {"warnplayerstimer": "61"}), ("neg", {"warnplayerstimer": "-1"}),
                              ("arabic", {"warnplayerstimer": "٣"}), ("float", {"warnplayerstimer": 1.5}),
                              ("bool", {"warnplayerstimer": True}), ("lead0", {"warnplayerstimer": "005"})):
        _bad138[_label] = (_lgp138.bad_setting(_settings), _settings)
check("config save: stoponlyifnoplayers only on/off; warnplayerstimer a whole number of minutes 0-60 "
      "(written as LinuxGSM reads it); anything else refused with a reason",
      _bad138["on"][0] is None and _bad138["yes"][0] and _bad138["15"][0] is None
      and _bad138["int15"] == (None, {"warnplayerstimer": "15"}) and _bad138["lead0"] == (None, {"warnplayerstimer": "5"})
      and all(_bad138[k][0] for k in ("61", "neg", "arabic", "float", "bool")), repr(_bad138))

# Through the route: a refused value writes nothing; a save drops the cached timer.
_writes138 = []
_forgot138 = []
try:
    _p9_arm(who="part138")
    _p9_patch(_files138, "_read_instance_cfg_lines", lambda *a, **k: ['port="1"'])
    _p9_patch(_files138, "_write_file_as_user",
              lambda server, user, path, content, selfname: (_writes138.append(content.decode()), (True, ""))[1])
    _p9_patch(_sf138, "_write_refused", lambda gs, action: None)
    _p9_patch(_lgp138, "forget", lambda *a: _forgot138.append(a[1:]))
    _A138 = _p9_client(P9_ADMIN)
    _r1 = _p9_json(_A138.post("/api/server/%d/config" % P9_GS, json={"settings": {"warnplayerstimer": "90"}}))
    _r1b = _p9_json(_A138.post("/api/server/%d/config" % P9_GS, json={"settings": {"stoponlyifnoplayers": "1"}}))
    _r2 = _p9_json(_A138.post("/api/server/%d/config" % P9_GS, json={"settings": {"warnplayerstimer": "010"}}))
    check("config save (every writer of the instance cfg): a warning time out of range, or a switch that is "
          "not on/off, is refused with its reason and writes nothing; a good one is written as LinuxGSM reads "
          "it and the cached timer is forgotten",
          _r1.get("success") is False and "0 to 60" in _r1.get("message", "")
          and _r1b.get("success") is False and _r2.get("success") is True
          and _writes138 == ['port="1"\nwarnplayerstimer="10"\n'] and len(_forgot138) == 1,
          repr((_r1, _r1b, _r2, _writes138, _forgot138)))
finally:
    _p9_restore_all()

# ── cron: a job LinuxGSM postponed is not "OK" ──────────────────────────────────────────────────
_saved_sh138 = _smc138.shell_as_game_user
try:
    _cron_cmds138 = []
    _smc138.shell_as_game_user = lambda s, u, c, **k: (_cron_cmds138.append(c),
                                                       ("aa\t0\t1\t2\t\t1\nbb\t0\t1\t2\t\t0\ncc\t1\t1\t2\t\t0\n", "", 0))[1]
    _cst138 = _cron138._read_cron_status(_srv138, "codserver")
finally:
    _smc138.shell_as_game_user = _saved_sh138
check("cron status: a run that exited 0 having been postponed is marked postponed; the others are not",
      _cst138["aa"]["postponed"] is True and _cst138["bb"]["postponed"] is False
      and _cst138["cc"]["postponed"] is False and _cst138["aa"]["ok"] is True, repr(_cst138))
_grep138 = _shutil138.which("grep")
if _grep138:
    _hits138 = [_sp138.run([_grep138, "-qE", _cron138._LG264_CRON_POSTPONED_ERE], input=t, text=True,  # nosec B603 - grep on fixtures
                           check=False).returncode == 0
                for t in (_OUT_STOP138, _OUT_RESTART138, _OUT_BACKUP138, _OUT_UPDATE138, _OUT_WARNSTOP138)]
    check("cron status: the grep it runs on the job's raw log (colour codes and all) finds every "
          "postponed/refused run from the test host and not an ordinary stop",
          _hits138 == [True, True, True, True, False] and _cron138._LG264_CRON_POSTPONED_ERE in _cron_cmds138[0]
          .replace("'", ""), repr(_hits138))
else:
    skip("cron status: the postponed grep over real LinuxGSM output", "grep is not installed")

# ── workshop-update in the Maintenance menu ─────────────────────────────────────────────────────
import app as _app138  # noqa: E402
from panel.security import privileged as _priv138  # noqa: E402
with _p9.test_request_context():
    import flask_login as _fl138
    with _p9.app_context():
        _admin138 = _sh138.db.session.get(_sd138.User, P9_ADMIN)
        _fl138.login_user(_admin138)
        _fakegs138 = type("G", (), {"supports_update": True, "get_commands": lambda self: [
            {"cmd": "workshop-update", "desc": "Install and update Steam Workshop mods."},
            {"cmd": "backup", "desc": "Create backup archives of the server."}]})()
        _menu138 = _sh138._server_action_buttons(_p9, _fakegs138)[1]
check("Maintenance menu: workshop-update is offered where LinuxGSM lists it, with its own description",
      {"cmd": "workshop-update", "desc": "Install and update Steam Workshop mods."} in _menu138, repr(_menu138))
_helper138 = _read138("tools", "panel-helper")
check("workshop-update: runnable, a long (background) action, allowed by the helper and the panel's "
      "lgsm-command list, scoped like the other maintenance actions",
      "workshop-update" in _app138.RUNNABLE_ACTIONS and "workshop-update" in _app138.LONG_ACTIONS
      and "workshop-update" in _priv138.LGSM_ACTIONS and '"workshop-update")' in _helper138
      and "workshop-update" in _smc138.SCOPED_LGSM_ACTIONS)
_tpl138 = _read138("templates", "_server_actions.html")
check("Maintenance menu: workshop-update asks for confirmation first, like update and backup",
      "'fastdl','workshop-update'] else 'false'" in _tpl138)

# ── the pages' scripts ──────────────────────────────────────────────────────────────────────────
_nags138 = _read138("static", "js", "nags.js")
_prog_nags138 = (
    "global.window = global;\n"
    "window.tf = (s, v) => s.replace(/\\{(\\w+)\\}/g, (m, k) => v && k in v ? v[k] : m);\n"
    "function El(tag){ this.tag = tag; this.children = []; this.attrs = {}; this.textContent = ''; }\n"
    "El.prototype.appendChild = function(c){ this.children.push(c); c.parentNode = this; return c; };\n"
    "El.prototype.setAttribute = function(k, v){ this.attrs[k] = v; };\n"
    "Object.defineProperty(El.prototype, 'lastChild', {get(){ return this.children[this.children.length - 1]; }});\n"
    "global.document = {createElement: t => new El(t), createTextNode: t => ({text: t})};\n"
    "function text(e){ return e.text != null ? e.text : (e.textContent || '') + e.children.map(text).join(''); }\n"
    + _cut47(_nags138, "function _rbEl(") + "\n" + _cut47(_nags138, "function _rbName(") + "\n"
    + _cut47(_nags138, "function _rbRow(") + "\n" + _cut47(_nags138, "function _rbWarnWord(") + "\n"
    + _cut47(_nags138, "function _rbWarnNotes(") + "\n"
    "function run(servers, busy){ const body = new El('div');"
    " _rbWarnNotes({plan: {servers: servers}, players: {busy: busy}, body: body});"
    " return body.children.map(c => ({tag: c.tag, text: text(c)})); }\n"
    "const S = (id, m, sup, say, so) => ({id: id, name: 'srv' + id, session: 1, warn_minutes: m,"
    " warn_supported: sup, say: say, stop_only_if_empty: so === undefined ? false : so});\n"
    "console.log(JSON.stringify({\n"
    " three: run([S(1, 5, true, true), S(2, 0, true, true), S(3, 0, false, false), S(9, 5, true, true)],"
    " [{id: 1}, {id: 2}, {id: 3}]),\n"
    " four: run([S(1, 5, true, true), S(2, 0, true, false), S(3, null, true, true), S(4, 0, false, true)],"
    " [{id: 1}, {id: 2}, {id: 3}, {id: 4}]),\n"
    " none: run([S(1, 5, true, true)], []),\n"
    " refuse: run([S(1, 5, true, true, true)], [{id: 1}])\n"
    "}));")
_on138 = _node47(_prog_nags138)
if _on138 is None:
    skip("reboot dialog: per-server warning lines", "node is not installed")
else:
    _t3 = " ".join(x["text"] for x in (_on138.get("three") or []))
    _t4 = " ".join(x["text"] for x in (_on138.get("four") or []))
    check("reboot dialog (Reboot now, players on): one line per server with players — its LinuxGSM warning "
          "and that the reboot waits for it, or that it has none and where to set one; a server without "
          "players is not listed", "srv1 — LinuxGSM warns its players for 5 min first, instead of the panel’s 60 s; the reboot waits for it" in _t3
          and "srv2 — only the panel’s 60 s warning: no LinuxGSM warning is set" in _t3
          and "srv3 — no in-game warning: this game can’t show one" in _t3 and "srv9" not in _t3
          and [x["tag"] for x in _on138["three"]] == ["div", "ul"], repr(_on138))
    check("reboot dialog: more than three servers fold under a summary; an unread timer and a game the "
          "panel can warn but LinuxGSM cannot are said as such; no players, no lines",
          [x["tag"] for x in _on138["four"]] == ["details"]
          and "srv2 — no in-game warning: none is set" in _t4
          and "srv3 — its LinuxGSM warning time could not be read" in _t4
          and "srv4 — only the panel’s 60 s warning: its console can’t show LinuxGSM’s" in _t4
          and _on138["none"] == [], repr(_on138))
    check("reboot dialog: a server with Only stop when empty on says the reboot sets it aside and still "
          "stops it cleanly, after its warning line",
          "srv1 — LinuxGSM warns its players for 5 min first, instead of the panel’s 60 s; the reboot waits "
          "for it. Its Only stop when empty is set aside for this reboot, so it is still stopped cleanly."
          in " ".join(x["text"] for x in (_on138.get("refuse") or [])), repr(_on138))
check("reboot dialog: the warning lines are drawn in the players-online view only (Reboot when empty "
      "has no players to warn)", _nags138.count("_rbWarnNotes(ctx);") == 1
      and "_rbWarnNotes(ctx);" in _cut47(_nags138, "function _rbPlayers("))

_sfjs138 = _read138("static", "js", "server_files.js")
_prog_sf138 = ("global.window = global; window.escapeHtml = s => String(s);\n"
               "function esc(s){ return window.escapeHtml(s); }\n"
               + _cut47(_sfjs138, "function _lg264PlayersHtml(") + "\n"
               + _cut47(_sfjs138, "function _lg264Tf2Html(") + "\n"
               "console.log(JSON.stringify({\n"
               " both: _lg264PlayersHtml({supported: true, stop_only_if_empty: true, warn_supported: true,"
               " warn_minutes: 5, warn_max: 60, can_count: true}),\n"
               " nowarn: _lg264PlayersHtml({supported: true, stop_only_if_empty: false, warn_supported: false,"
               " warn_minutes: 0, warn_max: 60, can_count: false}),\n"
               " old: _lg264PlayersHtml({supported: false}),\n"
               " tf2: _lg264Tf2Html({tf2_norestart: true}), notf2: _lg264Tf2Html({})}));")
_osf138 = _node47(_prog_sf138)
if _osf138 is None:
    skip("config editor: the player controls' markup", "node is not installed")
else:
    check("config editor: the controls save through the settings form (data-key, data-orig), the timer is "
          "a 0-60 number, and the select shows the current value",
          'data-key="stoponlyifnoplayers" data-orig="on"' in _osf138["both"]
          and '<option value="on" selected>' in _osf138["both"]
          and 'data-key="warnplayerstimer" min="0" max="60" step="1" data-orig="5" value="5"' in _osf138["both"]
          and "counts down in-game" in _osf138["both"], repr(_osf138))
    check("config editor: no warning control where LinuxGSM cannot warn (said in one line), the "
          "can't-count note, nothing before v26.4.0, and the TF2 notice only when asked for",
          "warnplayerstimer" not in _osf138["nowarn"] and "can’t show LinuxGSM’s in-game warnings" in _osf138["nowarn"]
          and "can’t count players" in _osf138["nowarn"] and _osf138["old"] == ""
          and "-norestart" in _osf138["tf2"] and _osf138["notf2"] == "", repr(_osf138))
check("config editor: the settings form saves and re-baselines every [data-key] control, selects "
      "included", _sfjs138.count("document.querySelectorAll('#cfg-groups [data-key]')") == 2
      and "#cfg-groups input[data-key]" not in _sfjs138)
check("cron list: a job LinuxGSM postponed shows 'Postponed', not 'OK'",
      "if(j.ok === true && j.postponed)" in _sfjs138 and ">Postponed</span>" in _sfjs138)

check("part138: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP138_START, repr(_P9_TRIPPED[_TRIP138_START:]))
