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
import tempfile as _tf138
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
    _files138.lgsm_get_values = _vals138({"warnplayerstimer": "5", "stoponlyifnoplayersallcommands": "on"})
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
          and _reads138[0] == ("u1", "s1", ("warnplayerstimer", "stoponlyifnoplayers",
                                            "stoponlyifnoplayersallcommands")), repr(_reads138))
    _lgp138._lg264_cache.clear()
    _files138.lgsm_get_values = _vals138(None)
    check("warning allowance: a config that could not be read keeps the caller's own budget (adds 0), "
          "and is not cached as 'off'",
          _lgp138.timeout_for(_srv138, "u2", "s2", "stop", 60) == 60 and not _lgp138._lg264_cache,
          repr(_lgp138._lg264_cache))
    _lgp138._lg264_cache.clear()
    _files138.lgsm_get_values = _vals138({"warnplayerstimer": "3", "stoponlyifnoplayers": "on",
                                                 "stoponlyifnoplayersallcommands": "on"})
    _st138a = (_lgp138.settings(_srv138, "u4", "s4"), _lgp138.stop_only_if_empty(_srv138, "u4", "s4"))
    _files138.lgsm_get_values = _vals138({"warnplayerstimer": "", "stoponlyifnoplayers": "off",
                                                 "stoponlyifnoplayersallcommands": "on"})
    _st138b = (_lgp138.settings(_srv138, "u5", "s5"), _lgp138.stop_only_if_empty(_srv138, "u5", "s5"))
    _files138.lgsm_get_values = _vals138(None)
    _st138c = _lgp138.stop_only_if_empty(_srv138, "u6", "s6")
    check("player settings: one read gives the timer and whether stoponlyifnoplayers is on; unread is None "
          "(unknown), never off", _st138a == ({"minutes": 3, "stop_only": True, "supported": True}, True)
          and _st138b == ({"minutes": 0, "stop_only": False, "supported": True}, False) and _st138c is None,
          repr((_st138a, _st138b, _st138c)))
    _files138.lgsm_get_values = _vals138({"warnplayerstimer": "99999", "stoponlyifnoplayersallcommands": "on"})
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
_job138.bounce = _job138.bounce_joined = False
_job138.bounce_unread = ""
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
    check("reboot: a server's stop is given STOP_BUDGET plus its warnplayerstimer (10 min), with room for one "
          "other LinuxGSM command's countdown and its stop and start first",
          _runs138 == [("stop", 2 * _hr138.STOP_BUDGET + 2 * (600 + _lgp138._LG264_WARN_SLACK))], repr(_runs138))
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
    _bud138 = 2 * _hr138.STOP_BUDGET + 2 * (600 + _lgp138._LG264_WARN_SLACK)
    check("forced reboot: a stop LinuxGSM refused (stoponlyifnoplayers) is run again as LinuxGSM's own stop "
          "with the setting readonly off, with the warning's budget, and the server is stopped — not left "
          "to the shutdown",
          _runs138 == [("stop", _bud138)]
          and _shells138 == [("codserver", "cd /home/codserver && export TERM=xterm && readonly "
                                           "stoponlyifnoplayers=off && source ./codserver stop 2>&1", _bud138)]
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
    _d138 = _tf138.mkdtemp()
    with open(os.path.join(_d138, "fakeserver"), "w", encoding="utf-8") as _fh:
        _fh.write('source "$(dirname "${BASH_SOURCE[0]}")/x.cfg"\necho "cmd=$1 stoponlyifnoplayers=${stoponlyifnoplayers}"\n')
    with open(os.path.join(_d138, "x.cfg"), "w", encoding="utf-8") as _fh:
        _fh.write('stoponlyifnoplayers="on"\n')
    _rb138 = _sp138.run([_bash138, "-c", _lgp138._lg264_forced_sh("u138", "fakeserver").replace(  # nosec B603 - fixture
        "cd /home/u138", "cd " + _d138, 1)],
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
_saved_lw138 = _lgp138.warn_minutes
try:
    _lgp138.warn_minutes = lambda remote, user, selfname, fresh=False: {"a": 5, "b": 0}.get(user)
    _lw138 = [_lgp138.lgsm_warns(_srv138, type("G", (), {"game_type": gt, "short_name": sn, "lgsm_name": sn})())
              for gt, sn in (("gmod", "a"), ("rust", "a"), ("gmod", "b"), ("gmod", "c"))]
finally:
    _lgp138.warn_minutes = _saved_lw138
check("LinuxGSM warns a server itself only with a timer AND a game it can warn on (rust cannot); no timer "
      "or an unread one is the panel's to warn", _lw138 == [True, False, False, False], repr(_lw138))
check("forced reboot: the job's countdown is the panel_warned rows (LinuxGSM's own warning wins)",
      "warn = _lgp.panel_warned(self.remote, warnable(census))" in _read138("panel", "services", "host_reboot.py"))

# The stop phase's own cap grows by the longest account's warnings (serial within an account).
_sp_src138 = _read138("panel", "services", "host_reboot.py")
_saved_wb138 = _lgp138.warn_minutes
try:
    _lgp138.warn_minutes = lambda server, user, selfname, fresh=False: {"a": 2, "b": 1, "c": 10}[selfname]
    _wb138 = _lgp138.reboot_warn_budget(_srv138, [[[{"user": "u1", "selfname": "a"}, {"user": "u1", "selfname": "b"}],
                                                   [{"user": "u2", "selfname": "c"}]]], 4, lambda e: 180)
finally:
    _lgp138.warn_minutes = _saved_wb138
check("reboot: the stop phase's deadline adds the warnings as the accounts run them — one account's servers "
      "one after another, the accounts side by side (here the 10-minute one is the longest)",
      _wb138 == 2 * (10 * 60 + _lgp138._LG264_WARN_SLACK) + 180
      and _lgp138.reboot_warn_budget(_srv138, [], 4, lambda e: 180) == 0, repr(_wb138))

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
          _wf138 == {"warn_minutes": 7, "stop_only_if_empty": True, "warn_supported": True, "say": True,
                     "lgsm_supported": True, "lgsm_counts": True}
          and _wf138b == {"warn_minutes": 7, "stop_only_if_empty": True, "warn_supported": False,
                          "say": False, "lgsm_supported": True, "lgsm_counts": True} and _wf138s == {},
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
                         "warn_minutes": 5, "warn_max": 60, "can_count": True, "list_unreliable": False}
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
    + _cut47(_nags138, "function _rbWarnLgsm(") + "\n" + _cut47(_nags138, "function _rbWarnPanel(") + "\n"
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

# ══ The adversarial review of #461 (lg264f) ══════════════════════════════════════════════════════
import re as _re_lg  # noqa: E402
import threading as _th_m3  # noqa: E402
# M1: a wait-for-empty reboot whose stop LinuxGSM refuses (a player joined between the panel's count
# and LinuxGSM's) bounces back to waiting; it never leaves that server to the shutdown.
_saved_m1 = (_smc138.run_as_game_user, _hr138.probe_server, _lgp138.warn_minutes, _smc138.shell_as_game_user)
try:
    _smc138.run_as_game_user = lambda remote, user, action, **k: (_OUT_STOP138, "", 0)
    _smc138.shell_as_game_user = lambda remote, user, sh, **k: ("", "sudo: a password is required", 1)
    _hr138.probe_server = lambda remote, e: {"session": 1}
    _lgp138.warn_minutes = _with_minutes138(0)
    _jm1 = object.__new__(_hr138._Job)
    _jm1.remote, _jm1.job = _srv138, {"mode": "when_empty"}
    _jm1.bounce = _jm1.bounce_joined = False
    _jm1.bounce_unread = ""
    _em1 = {"id": 1, "user": "codserver", "selfname": "codserver", "game_type": "cod", "name": "cod"}
    _jm1._stop_one(_em1)
    check("M1 reboot (wait for empty): a stop LinuxGSM refused for players is a player joining — the plan "
          "bounces back to waiting (rolled back), not left to the shutdown",
          _jm1.bounce is True and _jm1.bounce_joined is True and _em1["stop"] == "still_running", repr(_em1))
    # L1: forced ("now"), and the forced run answers nothing: the first run's refusal is kept.
    _jm1.job, _jm1.bounce, _jm1.bounce_joined = {"mode": "now"}, False, False
    _em1b = dict(_em1)
    _jm1._stop_one(_em1b)
    check("L1 forced reboot: a forced stop that answered nothing (a sudo refusal) keeps LinuxGSM's refusal of "
          "the first run in the record, and a forced reboot does not bounce",
          _em1b["lgsm_refused"] is True and _em1b["stop"] == "still_running" and _jm1.bounce is False, repr(_em1b))
finally:
    (_smc138.run_as_game_user, _hr138.probe_server, _lgp138.warn_minutes, _smc138.shell_as_game_user) = _saved_m1
check("M1: a stop the rescan made, refused for a player who joined, also bounces before the reboot is sent",
      "self._rescan()\n        if self._bounced():" in _read138("panel", "services", "host_reboot.py")
      and "if self._past_deadline() or self.bounce:" in _read138("panel", "services", "host_reboot.py"))

# M2: games whose player LIST LinuxGSM cannot count keep the panel's own countdown, and say so.
_saved_m2 = _lgp138.warn_minutes
try:
    _lgp138.warn_minutes = _with_minutes138(5)
    _m2 = {gt: _lgp138.lgsm_warns(_srv138, _gs_cfg138(gt)) for gt in ("mcb", "mc", "pmc", "wmc", "cs2", "csgo",
                                                                       "gmod", "cod")}
finally:
    _lgp138.warn_minutes = _saved_m2
check("M2 forced reboot: on Minecraft Bedrock/Java and CS2/CS:GO (a player list LinuxGSM can find empty with "
      "players on) LinuxGSM's warning is not relied on, so the panel's 60 s countdown stays; Garry's Mod and "
      "CoD keep LinuxGSM's", _m2 == {"mcb": False, "mc": False, "pmc": False, "wmc": False, "cs2": False,
                                     "csgo": False, "gmod": True, "cod": True}, repr(_m2))
_saved_rem_m2 = _lgp138.remember
try:
    _lgp138.remember = lambda *a, **k: None
    _vm2 = _lgp138.config_view(_gs_cfg138("mcb"), _cfg138(warn="5"))
finally:
    _lgp138.remember = _saved_rem_m2
check("M2 config editor: a game whose list LinuxGSM cannot count is marked so (the page says Only stop when "
      "empty may not hold and the warning may not run)", _vm2["players"].get("list_unreliable") is True
      and _vm2["players"].get("can_count") is True and _v1["players"].get("list_unreliable") is False, repr(_vm2))
try:
    _p9_patch(_lgp138, "settings", lambda *a, **k: {"minutes": 5, "stop_only": True, "supported": True})
    _p9_patch_sm("moderation_caps", lambda gt: {"say": True})
    _wfm2 = _lgp138.reboot_warn_fields(_srv138, _gs_cfg138("mcb"), {"session": 1})
    _p9_patch(_lgp138, "settings", lambda *a, **k: {"minutes": 0, "stop_only": False, "supported": False})
    _wfl5 = _lgp138.reboot_warn_fields(_srv138, _gs_cfg138("gmod"), {"session": 1})
finally:
    _p9_restore_all()
check("M2/L5 reboot preview: a game LinuxGSM cannot count says so (lgsm_counts), and a LinuxGSM before "
      "v26.4.0 says it has no warning (lgsm_supported)",
      _wfm2["lgsm_counts"] is False and _wfm2["lgsm_supported"] is True
      and _wfl5["lgsm_supported"] is False and _wfl5["lgsm_counts"] is True, repr((_wfm2, _wfl5)))
_prog_m2 = _prog_nags138.split("console.log(JSON.stringify({")[0] + (
    "console.log(JSON.stringify({"
    " count: run([Object.assign(S(1, 5, true, true), {lgsm_counts: false}),"
    " Object.assign(S(2, 5, true, false), {lgsm_counts: false})], [{id: 1}, {id: 2}]),"
    " old: run([Object.assign(S(3, 0, true, true), {lgsm_supported: false})], [{id: 3}])}));")
_om2 = _node47(_prog_m2)
if _om2 is None:
    skip("M2/L5 reboot dialog lines", "node is not installed")
else:
    _tm2 = " ".join(x["text"] for x in (_om2.get("count") or []))
    _tl5 = " ".join(x["text"] for x in (_om2.get("old") or []))
    check("M2 reboot dialog: where LinuxGSM cannot always count the players it never says LinuxGSM warns them "
          "(the panel's 60 s countdown is the warning)",
          "srv1 — the panel’s 60 s warning: LinuxGSM can’t always count this game’s players" in _tm2
          and "srv2 — no sure in-game warning" in _tm2 and "LinuxGSM warns its players" not in _tm2, repr(_om2))
    check("L5 reboot dialog: before LinuxGSM v26.4.0 it does not point to a setting that page hides",
          "srv3 — only the panel’s 60 s warning: this LinuxGSM has no warning of its own" in _tl5
          and "Files & Config" not in _tl5, repr(_om2))
_prog_m2sf = _prog_sf138.split("console.log(JSON.stringify({")[0] + (
    "console.log(JSON.stringify({ul: _lg264PlayersHtml({supported: true, warn_supported: true, warn_minutes: 0,"
    " warn_max: 60, can_count: true, list_unreliable: true}), ok: _lg264PlayersHtml({supported: true,"
    " warn_supported: true, warn_minutes: 0, warn_max: 60, can_count: true, list_unreliable: false})}));")
_om2sf = _node47(_prog_m2sf)
if _om2sf is None:
    skip("M2 config editor note", "node is not installed")
else:
    check("M2 config editor: a game whose player list can come back empty is told LinuxGSM then stops it "
          "anyway, with no warning; other games are not",
          "list the server can leave empty" in _om2sf["ul"] and "list the server can leave empty" not in _om2sf["ok"],
          repr(_om2sf))

# M3: Cancel during the stop phase calls LinuxGSM's own countdown off (its Ctrl-C), at once.
_bash_m3 = _shutil138.which("bash")
_envbin_m3 = _shutil138.which("env")
if _bash_m3 and _envbin_m3:
    _dm3 = _tf138.mkdtemp()
    os.makedirs(os.path.join(_dm3, "lgsm", "lock"))
    with open(os.path.join(_dm3, "fakeserver"), "w", encoding="utf-8") as _fh:
        _fh.write("trap 'echo CANCELLED; rm -f lgsm/lock/fakeserver-warning.lock; exit 0' INT\n"
                  "echo $$ > lgsm/lock/fakeserver-warning.lock\n"
                  "for i in $(seq 300); do sleep 0.1; done\necho STOPPED\n")

    def _m3_run(cmd):
        # A test shell that is sent Ctrl-C must start with SIGINT at its default (CI ignores it).
        p = _sp138.Popen([_envbin_m3, "--default-signal=INT", _bash_m3, "./fakeserver", cmd],  # nosec B603 - fixture
                         cwd=_dm3, stdout=_sp138.PIPE, text=True)
        for _ in range(100):
            if os.path.exists(os.path.join(_dm3, "lgsm", "lock", "fakeserver-warning.lock")):
                break
            _time138.sleep(0.05)
        sh = _lgp138.interrupt_sh("u138", "fakeserver").replace("cd /home/u138", "cd '%s'" % _dm3, 1)
        r = _sp138.run([_bash_m3, "-c", sh], capture_output=True, text=True, check=False,  # nosec B603 - fixture
                       env={"PATH": os.defpath})
        t0 = _time138.monotonic()
        if "LG264_INTERRUPTED" not in r.stdout:
            p.kill()
        out = p.communicate(timeout=60)[0]
        _lock_m3 = os.path.join(_dm3, "lgsm", "lock", "fakeserver-warning.lock")
        if os.path.exists(_lock_m3):     # the trap removes it; a killed run leaves it
            os.unlink(_lock_m3)
        return r.stdout, out, _time138.monotonic() - t0

    _m3stop = _m3_run("stop")
    _m3restart = _m3_run("restart")
    check("M3 Cancel: the reboot's own stop counting down is sent LinuxGSM's Ctrl-C (its trap tells the players "
          "the stop is cancelled and ends the command) and ends within seconds, not at the countdown's end",
          "LG264_INTERRUPTED" in _m3stop[0] and "CANCELLED" in _m3stop[1] and "STOPPED" not in _m3stop[1]
          and _m3stop[2] < 10, repr(_m3stop))
    check("M3 Cancel: another command's countdown (a restart) is not the reboot's to call off",
          "LG264_INTERRUPTED" not in _m3restart[0] and "CANCELLED" not in _m3restart[1], repr(_m3restart))
    with open(os.path.join(_dm3, "lgsm", "lock", "fakeserver-warning.lock"), "w", encoding="utf-8") as _fh:
        _fh.write("-1\n")
    _m3bad = _sp138.run([_bash_m3, "-c", _lgp138.interrupt_sh("u138", "fakeserver").replace(  # nosec B603 - fixture
        "cd /home/u138", "cd '%s'" % _dm3, 1)], capture_output=True, text=True, check=False, env={"PATH": os.defpath})
    check("M3 Cancel: a warning lock that is not a pid signals nothing",
          _m3bad.returncode == 0 and _m3bad.stdout == "", repr(_m3bad))
else:
    skip("M3 Cancel: LinuxGSM's Ctrl-C to the reboot's countdown", "bash or env is not installed")

_m3calls = []
_m3ents = [{"id": 1, "name": "a", "user": "ua", "selfname": "sa", "in_stop": True},
           {"id": 2, "name": "b", "user": "ub", "selfname": "sb", "in_stop": False},
           {"id": 3, "name": "c", "user": "uc", "selfname": "sc", "in_stop": True}]
_m3off = _lgp138.interrupt_countdowns(_srv138, _m3ents, lambda remote, user, sh, **k: (
    _m3calls.append((user, k.get("selfname"))), ("LG264_INTERRUPTED\n" if user == "ua" else "", "", 0))[1])
check("M3 Cancel: only the stops still running are asked, as their own accounts; the names called off come back",
      _m3calls == [("ua", "sa"), ("uc", "sc")] and _m3off == ["a"], repr((_m3calls, _m3off)))

_m3gate = _th_m3.Event()
_m3log = []
_m3flag = []


def _m3_group(grp):
    _m3log.append(("start", grp[0]))
    if grp[0] == "slow":
        _m3gate.wait(20)
    _m3log.append(("end", grp[0]))


def _m3_cancel():
    _m3log.append(("cancel",))
    _m3gate.set()


_m3t = _th_m3.Timer(0.3, lambda: _m3flag.append(True))
_m3t.start()
_lgp138.run_stop_passes([[["slow"], ["fast"]], [["later"]]], _m3_group, 4, lambda: bool(_m3flag), _m3_cancel)
_m3t.cancel()
check("M3 Cancel: the stop phase acts on a Cancel while a stop is still running (its countdown is called off "
      "then, not after it), once; and a pass starts only when the one before has ended",
      _m3log.count(("cancel",)) == 1 and _m3log.index(("cancel",)) < _m3log.index(("end", "slow"))
      and _m3log.index(("start", "later")) > _m3log.index(("end", "slow")), repr(_m3log))
_saved_m3s = (_smc138.run_as_game_user, _lgp138.warn_minutes)
_m3seen = []
try:
    _lgp138.warn_minutes = _with_minutes138(0)
    _em3 = {"id": 1, "user": "u", "selfname": "s"}
    _smc138.run_as_game_user = lambda *a, **k: (_m3seen.append(_em3.get("in_stop")), ("", "", 0))[1]
    _lgp138.reboot_stop(_srv138, _em3, 180)
finally:
    (_smc138.run_as_game_user, _lgp138.warn_minutes) = _saved_m3s
check("M3: a reboot's stop is marked in flight while it runs (what Cancel calls off), and not after",
      _m3seen == [True] and _em3["in_stop"] is False, repr((_m3seen, _em3)))
try:
    with _hr138._hr_lock:
        _hr138._host_reboots[913899] = {"phase": "stopping", "sent": None}
    _rm3 = type("R", (), {"id": 913899, "name": "h", "display_name": "h"})()
    _cm3 = _hr138.cancel(_rm3, None)
    with _hr138._hr_lock:
        _hr138._host_reboots[913899] = {"phase": "warning", "sent": None}
    _cm3b = _hr138.cancel(_rm3, None)
finally:
    with _hr138._hr_lock:
        _hr138._host_reboots.pop(913899, None)
check("M3 Cancel reply: while servers are being stopped it says a LinuxGSM countdown under way is called off "
      "and its players told, and that a stop already under way finishes first; before that, the short reply",
      "countdown under way is called off" in str(_cm3[1]["message"])
      and "finishes first" in str(_cm3[1]["message"])
      and "countdown" not in str(_cm3b[1]["message"]), repr((_cm3, _cm3b)))

# M4: the census sees another command's countdown, and a restart in flight.
check("M4 probe: the WARN line is read; a live warning means a LinuxGSM countdown",
      _hr138.parse_probe("SESSION=1\nWARN=1\nPROBE_OK\n")["warn"] == 1
      and _hr138.parse_probe("SESSION=1\nWARN=0\nPROBE_OK\n")["warn"] == 0
      and _hr138.parse_probe("garbage")["warn"] is None)
if _bash_m3:
    _dm4 = _tf138.mkdtemp()
    os.makedirs(os.path.join(_dm4, "lgsm", "lock"))

    def _m4_warn(lock_text):
        with open(os.path.join(_dm4, "lgsm", "lock", "s138-warning.lock"), "w", encoding="utf-8") as fh:
            fh.write(lock_text)
        sh = _hr138._probe_sh("u138", "s138").replace("cd /home/u138", "cd '%s'" % _dm4, 1)
        r = _sp138.run([_bash_m3, "-c", sh], capture_output=True, text=True, check=False,  # nosec B603 - fixture
                       env={"PATH": os.defpath})
        return _hr138._probe_values(r.stdout.splitlines()).get("WARN")

    _dead_m4 = _sp138.run([_bash_m3, "-c", "echo $$"], capture_output=True, text=True,  # nosec B603 - fixture
                          check=False).stdout.strip()
    _m4w = (_m4_warn("%d\n" % os.getpid()), _m4_warn(_dead_m4 + "\n"), _m4_warn("-1\n"), _m4_warn(""))
    check("M4 probe: WARN=1 only while the warning lock's pid is alive; a dead pid, a non-pid or an empty lock is 0",
          _m4w == ("1", "0", "0", "0"), repr(_m4w))
else:
    skip("M4 probe: the warning lock read in bash", "bash is not installed")
check("M4 probe: a LinuxGSM restart in flight is maintenance a reboot does not cut through",
      _re_lg.search(_hr138._cmd_pattern("s138", _hr138._MAINT_CMDS), "/bin/bash /home/u138/s138 restart")
      is not None)
try:
    _p9_patch(_hr138._mon, "_host_reachable", lambda remote: True)
    _p9_patch(_hr138, "_row_blockers", lambda rows: [])
    _p9_patch(_hr138, "_host_blockers", lambda remote: [])
    _p9_patch(_hr138, "_count_players", lambda running, primaries: ([], []))
    _p9_patch(_hr138._mon, "_batched_slots", lambda rows: {})
    with _p9.app_context():
        _gs_m4 = _sh138.db.session.get(_sh138.GameServer, P9_GS)
        _others_m4 = [g.id for g in _sh138.GameServer.query.filter_by(remote_id=_gs_m4.remote_id).all()]
        _pr_m4 = {i: {"session": 0} for i in _others_m4}
        _pr_m4[P9_GS] = {"session": 1, "maint": 0, "warn": 1}
        _hs_m4 = _hr138.host_player_state(_gs_m4.remote, probes=_pr_m4)
        _pr_m4[P9_GS] = {"session": 1, "maint": 1, "warn": 0}
        _hs_m4b = _hr138.host_player_state(_gs_m4.remote, probes=_pr_m4)
finally:
    _p9_restore_all()
check("M4 census: a server LinuxGSM is counting down on blocks the reboot (lgsm_warning), as maintenance does",
      _hs_m4["state"] == "blocked" and [b["kind"] for b in _hs_m4["blockers"]] == ["lgsm_warning"]
      and [b["kind"] for b in _hs_m4b["blockers"]] == ["maintenance"], repr((_hs_m4, _hs_m4b)))
check("M4: the blocker is worded (in the reboot's sentence and the dialog's list)",
      "LinuxGSM's player warning countdown on x"
      in str(_hr138._blocked_sentence([_hr138._blocker("lgsm_warning", "x")]))
      and "lgsm_warning: 'LinuxGSM is counting down to a stop or restart'" in _nags138)

# M5 + L10: the stop phase's budget follows the pool, pass by pass.
_saved_m5 = _lgp138.warn_minutes
try:
    _lgp138.warn_minutes = lambda server, user, selfname, fresh=False: {"w": 60, "n": 0}[selfname[0]]
    _ents_m5 = [{"user": "u%d" % i, "selfname": "w%d" % i, "game_type": "gmod"} for i in range(9)]
    _passes_m5 = _lgp138.stop_passes(_srv138, _ents_m5)
    _b_m5 = _lgp138.reboot_warn_budget(_srv138, _passes_m5, 4, lambda e: 180)
    _mix_m5 = [{"user": "a", "selfname": "w1", "game_type": "gmod"}, {"user": "a", "selfname": "n1", "game_type": "gmod"},
               {"user": "b", "selfname": "n2", "game_type": "mcb"}, {"user": "c", "selfname": "w2", "game_type": "mcb"}]
    _pm_m5 = _lgp138.stop_passes(_srv138, _mix_m5)
finally:
    _lgp138.warn_minutes = _saved_m5
_one_m5 = 2 * (60 * 60 + _lgp138._LG264_WARN_SLACK) + 180
check("M5 reboot: nine accounts with players and a 60-minute timer on four workers take three rounds — the "
      "stop phase's budget is the pool's schedule, not the longest account",
      _b_m5 == 3 * _one_m5 and _lgp138.schedule_seconds([5, 1, 1, 1, 1], 4) == 5
      and _lgp138.schedule_seconds([1, 1, 1, 1, 1], 4) == 2 and _lgp138.schedule_seconds([], 4) == 0, repr(_b_m5))
check("L10 reboot: the servers the panel's own 60 s countdown warned (LinuxGSM does not warn them) stop in a "
      "first pass, before any LinuxGSM countdown; each account's servers still one after another",
      [[[e["selfname"] for e in g] for g in p] for p in _pm_m5] == [[["n1"], ["n2"], ["w2"]], [["w1"]]],
      repr(_pm_m5))
check("M5/L10: the job runs those passes with that budget",
      "_lgp.reboot_warn_budget(self.remote, passes, STOP_WORKERS, _stop_budget)" in _sp_src138
      and "_lgp.run_stop_passes(passes," in _sp_src138 and "ex.map(lambda grp: self._stop_group" not in _sp_src138)

# M6 + L8: the Stop button's refused outcome reaches the console, and its quiet window ends.
_pushed_m6 = []
try:
    _p9_arm(who="part138")
    _p9_patch(_lgp138, "warn_minutes", _with_minutes138(2))
    _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: (
        _OUT_STOP138 if action == "stop" else _OUT_RESTART138, "", 0))
    _p9_patch_sm("_invalidate_port_scan", lambda rid: None)
    _p9_patch(_sd138, "_console_push", lambda app, sid, line: _pushed_m6.append((sid, line)))
    _p9_patch(_sh138, "_console_push", lambda app, sid, line: _pushed_m6.append((sid, line)))
    _p9_set(P9_GS, status="online", restart_pending=False, stop_pending=False, autostart=True)
    _A_m6 = _p9_client(P9_ADMIN)
    _A_m6.post("/api/server/%d/action" % P9_GS, json={"action": "stop"})
    _p9_drain()
    _win_stop_m6 = (P9_GS in _mon138._expected_offline, P9_GS in _mon138._expected_stop)
    _A_m6.post("/api/server/%d/action" % P9_GS, json={"action": "restart"})
    _p9_drain()
    _win_restart_m6 = P9_GS in _mon138._expected_offline
    _mon138._expected_offline[P9_GS] = float("inf")
    _mon138._end_offline_window(P9_GS)
    _inf_m6 = _mon138._expected_offline.get(P9_GS)
finally:
    _p9_restore_all()
    _mon138._expected_offline.pop(P9_GS, None)
    _mon138._expected_stop.pop(P9_GS, None)
check("M6 Stop button: a stop LinuxGSM refused is said in the server's console, as a [panel] line",
      any(sid == P9_GS and line.startswith("[panel] stop: Stop refused: players are online") for sid, line in _pushed_m6),
      repr(_pushed_m6))
check("M6 Restart button: a restart LinuxGSM postponed is said in the console too",
      any(line.startswith("[panel] restart: Restart postponed") for _, line in _pushed_m6), repr(_pushed_m6))
check("L8: a refused stop and a postponed restart end their quiet window (warning allowance and all), so a "
      "crash of the server that stayed up pages; a reboot plan's hold is kept",
      _win_stop_m6 == (False, False) and _win_restart_m6 is False and _inf_m6 == float("inf"),
      repr((_win_stop_m6, _win_restart_m6, _inf_m6)))

# L2 + L3: an unread request does not say Autostart is off; a held backup does not claim players are on.
_saved_l2 = (_smc138.shell_as_game_user,)
try:
    _smc138.shell_as_game_user = lambda *a, **k: ("", "timed out", -1)
    _l2 = _game138._lg264_bk_after(_srv138, "codserver", "codserver", _OUT_BACKUP138)
finally:
    (_smc138.shell_as_game_user,) = _saved_l2
check("L2 backup postponed, its request unread: neither 'Autostart is off' nor a promise — it says what it "
      "depends on", _l2 is not None and "Autostart is off" not in str(_l2[1])
      and "if the server's Autostart is on" in str(_l2[1]) and _l2[2] is True, repr(_l2))
check("L3: LinuxGSM's held backup is described without claiming players are online now (the monitor's own "
      "backup may be running, or have failed)", "players are online" not in str(_lgp138.BACKUP_QUEUED)
      and "postponed backup" in str(_lgp138.BACKUP_QUEUED))

# L4: the monitor's own "restart postponed" is the monitor doing its job, not a postponed job.
_row_l4 = {cmd: (_cron138._cron_job_row("*/5 * * * * " + cmd, "codserver", "codserver",
                                        {_cron138._cron_job_id(cmd): {"postponed": True, "ok": True, "last_run": 1,
                                                                      "rc": 0, "error": ""}}, {}) or {}).get("postponed")
           for cmd in ("/home/codserver/codserver monitor", "/home/codserver/codserver restart")}
check("L4 cron list: the Autostart monitor's run is not 'Postponed'; a restart job LinuxGSM postponed is",
      _row_l4 == {"/home/codserver/codserver monitor": False, "/home/codserver/codserver restart": True}, repr(_row_l4))

# L6: a hand-written timer of thousands of digits reads as the cap, never raises.
try:
    _l6 = _lgp138.warn_minutes_value("1" * 5000)
except ValueError as _exc_l6:
    _l6 = repr(_exc_l6)[:80]
check("L6 warnplayerstimer: 5000 digits read as the longest the panel allows for, not a ValueError (the editor's "
      "read and every reboot of the host went through here)",
      _l6 == _lgp138._LG264_ALLOWANCE_CAP_MIN and _lgp138.warn_minutes_value("15") == 15, repr(_l6))

# L5: before v26.4.0 a hand-set timer is off.
_saved_l5 = _files138.lgsm_get_values
try:
    _lgp138._lg264_cache.clear()
    _files138.lgsm_get_values = _vals138({"warnplayerstimer": "5", "stoponlyifnoplayers": "on"})
    _l5 = _lgp138.settings(_srv138, "u9", "s9")
finally:
    _files138.lgsm_get_values = _saved_l5
    _lgp138._lg264_cache.clear()
check("L5: on a LinuxGSM before v26.4.0 (no stoponlyifnoplayersallcommands) a hand-set timer and switch are "
      "off: the panel keeps its own countdown and budgets nothing",
      _l5 == {"minutes": 0, "stop_only": False, "supported": False}, repr(_l5))

# L7: the uninstall's stop does not count down for minutes inside the request.
_l7 = []
try:
    _p9_arm(who="part138")
    _p9_patch_sm("shell_as_game_user", lambda remote, user, sh, **k: (_l7.append(("sh", sh, k.get("timeout"))),
                                                                       ("Graceful ... OK", "", 0))[1])
    _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: (_l7.append(("run", action, k.get("timeout"))),
                                                                         ("", "", 0))[1])
    _p9_patch_sm("run_privileged", lambda *a, **k: ("", "", 0))
    from panel.routes import manage_servers as _ms_l7  # noqa: E402
    _ms_l7._stop_game_processes(_srv138, "codserver", "codserver")
    _l7a = list(_l7)
    _l7.clear()
    _p9_patch_sm("shell_as_game_user", lambda remote, user, sh, **k: (_l7.append(("sh", sh, k.get("timeout"))),
                                                                       ("", "sudo: refused", 1))[1])
    _ms_l7._stop_game_processes(_srv138, "codserver", "codserver")
    _l7b = list(_l7)
finally:
    _p9_restore_all()
check("L7 uninstall: the stop is LinuxGSM's own, with its warning and players check set aside, in 60 s — "
      "never a countdown of warnplayerstimer minutes inside the request",
      _l7a and _l7a[0][0] == "sh" and "readonly stoponlyifnoplayers=off warnplayerstimer=0" in _l7a[0][1]
      and "source ./codserver stop" in _l7a[0][1] and _l7a[0][2] == 60 and not any(x[0] == "run" for x in _l7a),
      repr(_l7a))
check("L7 uninstall: a shell the account refuses falls back to the plain stop, as before",
      [x[0] for x in _l7b if x[0] in ("sh", "run")][:2] == ["sh", "run"] and ("run", "stop", 60) in _l7b, repr(_l7b))

# L9: a commented-out monitor line in the crontab is no monitor.
_bash_l9 = _shutil138.which("bash")
if _bash_l9:
    _dl9 = _tf138.mkdtemp()
    os.makedirs(os.path.join(_dl9, "home", "lgsm", "lock"))
    os.makedirs(os.path.join(_dl9, "bin"))
    open(os.path.join(_dl9, "home", "lgsm", "lock", "s-monitoring.lock"), "w", encoding="utf-8").close()
    _cmd_l9 = []
    _saved_l9 = _smc138.shell_as_game_user
    try:
        _smc138.shell_as_game_user = lambda s, u, c, **k: (_cmd_l9.append(c), ("", "", 1))[1]
        _game138._lg264_bk_request(_srv138, "u", "s")
    finally:
        _smc138.shell_as_game_user = _saved_l9

    def _l9_monitor(crontab_text):
        with open(os.path.join(_dl9, "bin", "crontab"), "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\ncat <<'EOF'\n%s\nEOF\n" % crontab_text.replace("/home/u", _dl9 + "/home"))
        os.chmod(os.path.join(_dl9, "bin", "crontab"), 0o700)  # nosemgrep: insecure-file-permissions - a stand-in this part runs
        r = _sp138.run([_bash_l9, "-c", _cmd_l9[0].replace("/home/u", _dl9 + "/home")],  # nosec B603 - fixture
                       capture_output=True, text=True, check=False,
                       env={"PATH": os.path.join(_dl9, "bin") + ":" + os.defpath})
        return (r.stdout.split("\t") + ["", "", ""])[2]

    _l9 = (_l9_monitor("*/5 * * * * /home/u/s monitor > /dev/null 2>&1"),
           _l9_monitor("#*/5 * * * * /home/u/s monitor > /dev/null 2>&1"),
           _l9_monitor("  # */5 * * * * /home/u/s monitor"))
    check("L9 backup: a crontab whose monitor line is commented out runs no monitor (the panel backs up "
          "itself); the live line still counts", _l9 == ("1", "0", "0"), repr(_l9))
else:
    skip("L9 backup: the crontab read in bash", "bash is not installed")

check("part138: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP138_START, repr(_P9_TRIPPED[_TRIP138_START:]))
