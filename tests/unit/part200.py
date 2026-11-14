"""Part 200 of the unit suite: Minecraft Bedrock's player count, read from its console log.

Held here:
* The tally (bedrock.bedrock_count_sh) run by sh over real log texts in a temp home, with a
  stand-in tmux: joins less leaves per player, never below zero for one player (a leave with no
  join before it does not cancel another join); the offline-mode "Player Connected" form; a typed
  line echoed into the log is not a join or a leave; only this run's lines (after "Server
  started.") count; no start line is unread (N), a join it cannot read is unread (B), no LinuxGSM
  session is D; CRLF and LF logs alike.
* bedrock.bedrock_slots: one command as the account, its reply read strictly (a single tally line,
  then server.properties' max-players, server-name and level-name), anything else is failed.
* The callers: cron.player_count and player_slots read Bedrock's log before any gamedig query, ask
  gamedig only when the log is unread, and never when LinuxGSM sees no session; the status poll
  keeps Bedrock out of the batched gamedig query and caches the log's count, which /api/servers
  serves; the world reset's "wait until empty" waits for players the log counts and runs when it
  counts none; the hourly restart-when-empty line counts the log, fits cron's 999-character command
  for the longest account name, and an older Bedrock line heals to it.

HOW IT RUNS. The tally runs under sh in a temp folder with a stand-in tmux on PATH. Everything else
drives part12's app with its transport tripwire armed and every host call stubbed. Times are fixed.
Nothing reaches a host or data/.
"""
import os as _os200
import shutil as _shutil200
import subprocess as _sp200  # nosec B404 - sh over the count this part builds, in a temp folder
import tempfile as _tf200

from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_delete_server,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part183 import _GONE183, _NOW183, _cfg_texts183, _last183
from panel.core import panel_state as _ps200
from panel.ops.ssh_manager import _core as _core200, bedrock as _bd200, cron as _cron200
from panel.routes import _shared as _shr200, api as _api200, wipe_schedule as _wr200
from panel.services import lgsm_players as _lgp200, monitoring as _mon200, wipe_schedule as _ws200

_trips200 = len(_P9_TRIPPED)

# ── 1. the tally, run by sh over real log texts ─────────────────────────────────────────────────
_T200 = "[2026-11-13 15:%02d:00:001 INFO] "
_LOG200 = [
    "NO LOG FILE! - setting up server logging...",
    _T200 % 0 + "Starting Server",
    _T200 % 1 + "Server started.",
    _T200 % 2 + "Player connected: Steve Two, xuid: 2535412345678901",
    _T200 % 3 + "Player Spawned: Steve Two xuid: 2535412345678901, pfid: 1a2b3c4d5e6f7a8b",
    _T200 % 4 + "Player Connected: Alex, xuid: , pfid: c31902da495f4549",
    _T200 % 5 + "Player disconnected: Alex, xuid: , pfid: c31902da495f4549",
    _T200 % 6 + "Player disconnected: Ghost, xuid: 2535400000000001, pfid: 0a",
    _T200 % 7 + "Player connected: Ghost, xuid: 2535400000000001",
    "Player disconnected: Steve Two, xuid: 2535412345678901",
    "say " + _T200 % 8 + "Player disconnected: Ghost, xuid: 2535400000000001",
    "Player disconnected: Steve Two, xuid: 2535412345678901 (typed, with INFO] Player in it)",
]
_LEAVE200 = [_T200 % 9 + "Player disconnected: Steve Two, xuid: 2535412345678901, pfid: 1a",
             _T200 % 10 + "Player disconnected: Ghost, xuid: 2535400000000001, pfid: 0a"]


def _exe200(path, body):
    _os200.makedirs(_os200.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n" + body)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- owner-only, a temp stand-in
    _os200.chmod(path, 0o700)  # nosec B103


def _count200(lines, up=True, uid=True, eol="\r\n", log=True):
    """What bedrock_count_sh prints for a console log of `lines`, run by sh in a temp home."""
    tmp = _tf200.mkdtemp(prefix="p200-")
    home = _os200.path.join(tmp, "home")
    try:
        _os200.makedirs(_os200.path.join(home, "lgsm", "data"))
        _os200.makedirs(_os200.path.join(home, "log", "console"))
        sock = "mcbserver"
        if uid:
            with open(_os200.path.join(home, "lgsm", "data", "mcbserver.uid"), "w", encoding="utf-8") as fh:
                fh.write("ab12cd34")
            sock = "mcbserver-ab12cd34"
        if log:
            with open(_os200.path.join(home, "log", "console", "mcbserver-console.log"), "w",
                      encoding="utf-8", newline="") as fh:
                fh.write("".join(ln + eol for ln in lines))
        _exe200(_os200.path.join(tmp, "stubs", "tmux"),
                '[ "$2" = "%s" ] && echo mcbserver\nexit 0\n' % (sock if up else "none"))
        env = dict(_os200.environ, PATH=_os200.path.join(tmp, "stubs") + ":" + _os200.environ.get("PATH", "/usr/bin:/bin"))
        res = _sp200.run(["sh", "-c", _bd200.bedrock_count_sh("mcbserver")], cwd=home, env=env,  # nosec B603 B607
                         capture_output=True, text=True, timeout=60, check=False)
        return res.stdout.strip()
    finally:
        _shutil200.rmtree(tmp, ignore_errors=True)


eq("bedrock tally: joins less leaves per player: a leave before its own join and a typed or echoed line do "
   "not count, the offline-mode 'Player Connected' form does (CRLF log)", _count200(_LOG200), "OK 2")
eq("bedrock tally: ...the same log with LF line ends", _count200(_LOG200, eol="\n"), "OK 2")
check("bedrock tally: each line is cut to 256 bytes before grep and awk read it, so no line is held whole",
      "timeout 20 cut -b 1-256 -- log/console/mcbserver-console.log 2>/dev/null|grep -aE"
      in _bd200.bedrock_count_sh("mcbserver"), _bd200.bedrock_count_sh("mcbserver")[:200])
eq("bedrock tally: everyone left is a counted 0", _count200(_LOG200 + _LEAVE200), "OK 0")
eq("bedrock tally: one player joined twice and left once is still on",
   _count200(_LOG200[:4] + [_T200 % 11 + "Player connected: Steve Two, xuid: 2535412345678901"] + _LEAVE200[:1]),
   "OK 1")
eq("bedrock tally: a log without this run's start line (cleared, or console logging off) is unread, not 0",
   _count200(_LOG200[3:]), "N")
eq("bedrock tally: ...as is a missing log", _count200([], log=False), "N")
eq("bedrock tally: a join line it cannot read (no xuid, or past the 256-byte cut) is unread, not one fewer",
   (_count200(_LOG200[:3] + [_T200 % 2 + "Player connected: Nobody"]),
    _count200(_LOG200[:3] + [_T200 % 2 + "Player connected: " + "x" * 250 + ", xuid: 1"])), ("B", "B"))
eq("bedrock tally: joins before a later 'Server started.' are not this run's",
   _count200(_LOG200[:4] + [_T200 % 20 + "Server started."]), "OK 0")
eq("bedrock tally: no LinuxGSM session (on the uid socket, or the bare one without a uid file) is D",
   (_count200(_LOG200, up=False), _count200(_LOG200, uid=False)), ("D", "OK 2"))

# ── 2. bedrock_slots: one command, its reply read strictly ──────────────────────────────────────
_PROPS200 = "max-players=10\r\nserver-name=My   Bedrock\nlevel-name=Bedrock level\n"


def _slots200(reply, user="p200mcb"):
    """What bedrock_slots answers, and [(user, sh, selfname)] sent, with the account's shell answering `reply`."""
    sent = []

    def _shell(server, u, sh, **k):
        sent.append((u, sh, k.get("selfname")))
        if isinstance(reply, Exception):
            raise reply
        return reply, "", 0
    try:
        _p9_patch_sm("shell_as_game_user", _shell)
        return _bd200.bedrock_slots(None, user), sent
    finally:
        _p9_restore_all()


_ok200, _ok_sent200 = _slots200("mcbp:OK 3\n" + _PROPS200)
eq("bedrock slots: a counted log, with server.properties' capacity, name (blanks collapsed) and level",
   _ok200, ("ok", 3, 10, "My Bedrock", "Bedrock level"))
check("bedrock slots: ...from ONE command, as the account, in its home, naming the script",
      len(_ok_sent200) == 1 and _ok_sent200[0][0] == "p200mcb" and _ok_sent200[0][2] == "mcbserver"
      and _ok_sent200[0][1].startswith("cd /home/p200mcb || exit 3; ")
      and _bd200.bedrock_count_sh("mcbserver") in _ok_sent200[0][1], repr(_ok_sent200))
eq("bedrock slots: no session is down; no start line or an unreadable join is unread",
   [_slots200(r)[0][0] for r in ("mcbp:D\n", "mcbp:N\n" + _PROPS200, "mcbp:B\n")], ["down", "unread", "unread"])
eq("bedrock slots: no tally line, two of them, a malformed one, or a transport error is failed (unknown)",
   [_slots200(r)[0] for r in ("", "mcbp:OK 3\nmcbp:OK 4\n", "mcbp:OK -1\n", "mcbp:OK 3 x\n", ConnectionError("x"))],
   [("failed", None, None, None, None)] * 5)
_bad200 = _slots200("mcbp:OK 1\n", user="root")
check("bedrock slots: an account name the panel refuses sends nothing", _bad200 == (("failed", None, None, None, None), []),
      repr(_bad200))
eq("bedrock slots: a capacity that is not a plain number is no capacity",
   _slots200("mcbp:OK 1\nmax-players=ten\n")[0][2], None)

# ── 3. cron.player_count / player_slots: the log first, gamedig only when it is unread ──────────


def _pc200(reply, game_type="mcb", gamedig='{"c":4,"ok":true}', fn="player_count"):
    """What cron.<fn> answers, and [commands sent], for one server; the bedrock read answers `reply`."""
    sent = []

    def _shell(server, u, sh, **k):
        sent.append(sh)
        if "mcbp:" in sh:
            return reply, "", 0
        return (gamedig if "gamedig --type" in sh else ""), "", 0
    try:
        _p9_patch_sm("shell_as_game_user", _shell)
        _p9_patch_sm("_gamedig_host", lambda server: "192.0.2.20")
        srv = type("Srv", (), {"id": 920001})()
        return getattr(_cron200, fn)(srv, "p200mcb", game_type, 19132, None), sent
    finally:
        _p9_restore_all()


_pc_ok200 = _pc200("mcbp:OK 3\n" + _PROPS200)
_pc_un200 = _pc200("mcbp:N\n")
_pc_dn200 = _pc200("mcbp:D\n")
_pc_gm200 = _pc200("", game_type="gmod")
_pc_fail200 = _pc200("")
check("player count (mcb): a read that did not answer with a tally asks gamedig, as before",
      _pc_fail200[0] == 4 and len(_pc_fail200[1]) == 2 and "gamedig --type mbe" in _pc_fail200[1][1],
      repr(_pc_fail200))
check("player count (mcb): the console log's count, and no gamedig query at all",
      _pc_ok200[0] == 3 and len(_pc_ok200[1]) == 1 and "gamedig" not in _pc_ok200[1][0], repr(_pc_ok200))
check("player count (mcb): an unread log falls back to gamedig's mbe (a RakNet server still answers it)",
      _pc_un200[0] == 4 and len(_pc_un200[1]) == 2 and "gamedig --type mbe 192.0.2.20:19132" in _pc_un200[1][1],
      repr(_pc_un200))
check("player count (mcb): no LinuxGSM session is unknown, and gamedig is not asked",
      _pc_dn200[0] is None and len(_pc_dn200[1]) == 1, repr(_pc_dn200))
check("player count: another game is not read from a console log",
      _pc_gm200[0] == 4 and len(_pc_gm200[1]) == 1 and "mcbp:" not in _pc_gm200[1][0], repr(_pc_gm200))
_cron200._game_map_cache.pop((920001, 19132), None)
_ps_ok200 = _pc200("mcbp:OK 3\n" + _PROPS200, fn="player_slots")
_map200 = _cron200._cached_map((920001, 19132))
_cron200._game_map_cache.pop((920001, 19132), None)
check("player slots (mcb): count, capacity and name from one read, and the level fills the map cache",
      _ps_ok200[0] == (3, 10, "My Bedrock") and len(_ps_ok200[1]) == 1 and _map200 == "Bedrock level",
      repr((_ps_ok200, _map200)))
eq("player slots (mcb): no session is (None, None, None) without a gamedig query",
   _pc200("mcbp:D\n", fn="player_slots"), ((None, None, None), [_bd200.bedrock_read_sh("p200mcb", "mcbserver")]))

# ── 4. the status poll and /api/servers ─────────────────────────────────────────────────────────
_mcb_sid200 = _p9_new_server(P9_HOST, "p200mcb", "mcb", 19132, name="p200-mcb", status="online")
_gm_sids200 = [_p9_new_server(P9_HOST, "p200gm%d" % i, "gmod", 27015 + i, name="p200-gm%d" % i, status="online")
               for i in (1, 2)]
_poll200 = {"batches": [], "reads": 0}


def _poll_shell200(server, user, sh, **k):
    if "mcbp:" in sh:
        _poll200["reads"] += 1
        return "mcbp:OK 2\n" + _PROPS200, "", 0
    return "", "", 1


def _poll_batch200(remote, acct, targets):
    _poll200["batches"].append([t[0] for t in targets])
    return {t[0]: (None, None, None) for t in targets}


try:
    _p9_arm(who="part200")
    _p9_patch_sm("shell_as_game_user", _poll_shell200)
    _p9_patch_sm("_gamedig_host", lambda server: "192.0.2.20")
    _p9_patch(_mon200, "sm_player_slots_batch", _poll_batch200)
    _p9_patch(_mon200, "_batch_account", lambda remote, rows: "p200gm1")
    _p9_patch(_mon200, "sm_player_count_via_lgsm_query", lambda *a, **k: None)
    _p9_patch(_mon200, "sm_get_server_status", lambda *a, **k: "online")
    _p9_patch(_mon200, "lgsm_get_values", lambda *a, **k: {})
    _p9_patch(_api200, "_scan_listening_ports", lambda servers: [])
    _mon200._batch_failed_at.pop(P9_HOST, None)
    _mon200._refresh_player_counts(_p9)
    _poll200["cache"] = dict(_ps200._player_counts.get(_mcb_sid200) or {})
    _poll200["api"] = [r for r in (_p9_client(P9_ADMIN).get("/api/servers").get_json() or [])
                       if isinstance(r, dict) and r.get("id") == _mcb_sid200]
finally:
    _p9_restore_all()
check("status poll (mcb): the console log's count and server.properties' capacity and name are cached",
      _poll200["cache"].get("count") == 2 and _poll200["cache"].get("max") == 10
      and _poll200["cache"].get("name") == "My Bedrock" and _poll200["reads"] == 1, repr(_poll200))
check("status poll (mcb): Bedrock is kept out of its host's batched gamedig query, which the others still share",
      _poll200["batches"] and all(_mcb_sid200 not in b for b in _poll200["batches"])
      and any(set(_gm_sids200) <= set(b) for b in _poll200["batches"]), repr(_poll200["batches"]))
check("dashboard API: /api/servers serves the Bedrock server's counted players, capacity and name",
      len(_poll200["api"]) == 1 and _poll200["api"][0].get("players") == 2
      and _poll200["api"][0].get("max_players") == 10 and _poll200["api"][0].get("game_name") == "My Bedrock",
      repr(_poll200["api"]))
for _sid200 in _gm_sids200:
    _p9_delete_server(_sid200)
_ps200._player_counts.pop(_mcb_sid200, None)

# ── 5. the world reset's "wait until empty" ─────────────────────────────────────────────────────
_MCBV200 = {"startparameters": "", "extraparams": "", "executabledir": "${serverfiles}"}


def _sweep200(reply, wait_empty=True):
    """One sweep of a due Bedrock reset with the log read answering `reply`. Returns what happened."""
    got = {"cmds": [], "reads": 0}
    with _p9.app_context():
        from panel.db.models import GameServer, db
        gs = db.session.get(GameServer, _mcb_sid200)
        entry = dict(_ws200.identity(gs), kind="reset", preset="custom", at="", cron="0 3 * * *", tz="UTC",
                     wait_empty=wait_empty, anchor=_NOW183 - 7200, pending_since=_NOW183 - 3600,
                     backed_up=int(_NOW183 - 3500), tried=0, wait="")
    _ws200.put(_mcb_sid200, entry)

    def _shell(remote, user, sh, **k):
        if "mcbp:" in sh:
            got["reads"] += 1
            return reply, "", 0
        if "gamedig --type" in sh:
            return "", "", 1
        got["cmds"].append("status" if "echo __WWR_UP__" in sh else "delete")
        return ("__WWR_UP__\n" if "echo __WWR_UP__" in sh else _GONE183), "", 0

    def _run(remote, user, action, **k):
        got["cmds"].append(action)
        return ("[  OK  ] Stopping mcbserver" if action == "stop" else "[  OK  ] Starting"), "", 0
    try:
        _p9_arm(who="part200")
        _p9_patch(_shr200, "_marked_backup", lambda *a, **k: (got["cmds"].append("backup"), (True, "Backed up", False))[1])
        _p9_patch(_shr200, "_alert_backup", lambda *a, **k: None)
        _p9_patch(_shr200, "_reboot_holds", lambda gs: False)
        _p9_patch(_lgp200, "allowance_seconds", lambda *a, **k: 0)
        _p9_patch_sm("run_as_game_user", _run)
        _p9_patch_sm("shell_as_game_user", _shell)
        _p9_patch_sm("_gamedig_host", lambda server: "192.0.2.20")
        _p9_patch_sm("read_file", lambda *a, **k: ("level-name=Bedrock level\n", None))
        _p9_patch_sm("lgsm_cfg_texts", lambda *a, **k: _cfg_texts183(_MCBV200))
        _wr200.sweep(_p9, now=_NOW183)
        got["entry"] = dict(_ws200.get(_mcb_sid200) or {})
        return got
    finally:
        _p9_restore_all()
        _ws200.put(_mcb_sid200, None)
        _mon200._end_offline_window(_mcb_sid200)


_sw_on200 = _sweep200("mcbp:OK 2\n")
_sw_empty200 = _sweep200("mcbp:OK 0\n")
_sw_unread200 = _sweep200("mcbp:N\n")
check("world reset sweep (mcb): players the console log counts keep it waiting, nothing stopped",
      _sw_on200["cmds"] == ["status"] and _sw_on200["reads"] == 1
      and "2 player(s) online" in (_sw_on200["entry"].get("wait") or ""), repr(_sw_on200))
check("world reset sweep (mcb): a log that counts nobody lets the reset run: stop, backup, delete, start",
      _sw_empty200["cmds"] == ["status", "stop", "backup", "delete", "start"]
      and _last183(_sw_empty200).get("ok") is True, repr(_sw_empty200))
check("world reset sweep (mcb): an unread log with no gamedig answer still waits for a count",
      _sw_unread200["cmds"] == ["status"]
      and "could not be counted" in (_sw_unread200["entry"].get("wait") or ""), repr(_sw_unread200))

# ── 6. the hourly restart-when-empty line ───────────────────────────────────────────────────────
_U32_200 = "m" + "c" * 31          # the longest account name the panel creates (validation.LINUX_USER_RE)


def _written200(user, game_type="mcb"):
    """The flag line, check line and address lookups as set_daily_restart writes them for `user`."""
    cap, looks = {}, []
    try:
        _p9_patch(_core200, "_rewrite_crontab", lambda s, u, grep, add, extra_pre="": (cap.update(add=list(add)), (True, "ok"))[1])
        _p9_patch(_core200, "_gamedig_host", lambda server: looks.append(server) or "203.0.113.5")
        _core200.set_daily_restart(None, user, "mcbserver", game_type=game_type, port=19132, enabled=True)
    finally:
        _p9_restore_all()
    add = cap.get("add") or ["", ""]
    return add[0], add[1], len(looks)


def _upgrade200(listing, user, **kw):
    """What one cron upgrade pass over `listing` returns, and the lines it wrote (or None)."""
    cap = {}
    try:
        _p9_patch(_core200, "run_command", lambda s, c, **k: (listing, "", 0))
        _p9_patch(_core200, "_rewrite_crontab", lambda s, u, grep, add, extra_pre="": (cap.update(add=list(add)), (True, "ok"))[1])
        _p9_patch(_core200, "_gamedig_host", lambda server: "203.0.113.5")
        return _cron200.upgrade_managed_cron_tracking(None, user, "mcbserver", **kw), cap.get("add")
    finally:
        _p9_restore_all()


_line200 = _written200(_U32_200)[1]
_cmd200 = _line200.split(None, 5)[5] if _line200.count(" ") >= 5 else ""
check("hourly restart (mcb): the check counts the console log, restarts only on a counted 'OK 0', asks no gamedig",
      _line200.startswith("10 * * * * ") and _bd200.bedrock_count_sh("mcbserver") in _line200
      and 'if [ "$P" = "OK 0" ]; then /home/%s/mcbserver restart' % _U32_200 in _line200
      and "gamedig" not in _line200, _line200)
check("hourly restart (mcb): the command fits cron's 999 characters (MAX_COMMAND 1000, the rest is cut "
      "without a word) for a 32-character account", 0 < len(_cmd200) <= 999, str(len(_cmd200)))
_long200 = _written200("m" * 64)[1]
check("hourly restart (mcb): a line that would not fit (a 64-character account) keeps gamedig's query at the "
      "host's address instead of being cut", "gamedig --type mbe 203.0.113.5:19132" in _long200
      and "mcbp" not in _long200 and "OK 0" not in _long200 and len(_long200.split(None, 5)[5]) <= 999, _long200)
check("hourly restart (mcb): today's Bedrock line is a shape the cron upgrade recognises",
      any(r.match(_cmd200) for r in _cron200._restart_check_res(_U32_200, "mcbserver")), _cmd200[:120])
_old200 = "10 * * * * " + _core200.daily_restart_check_cmd("p200mcb", "mcbserver", "mbe", "203.0.113.5", 19132)
_new200 = _written200("p200mcb")[1]
_heal200 = _upgrade200(_old200, "p200mcb", game_type="mcb", port=19132)
_keep200 = _upgrade200(_new200, "p200mcb", game_type="mcb", port=19132)
_keep_unknown200 = _upgrade200(_new200, "p200mcb")
check("hourly restart (mcb): a Bedrock line written with gamedig's mbe query heals to the console-log count",
      "gamedig --type mbe" in _old200 and _heal200 == (True, [_new200]), repr(_heal200))
check("hourly restart (mcb): ...and today's line is left alone, also by a pass that knows neither game nor port",
      _keep200 == (False, None) and _keep_unknown200 == (False, None), repr((_keep200, _keep_unknown200)))
check("hourly restart: another game's line still queries gamedig at the host's address",
      "gamedig --type garrysmod 203.0.113.5:19132" in _written200("p200gm", game_type="gmod")[1], "")

_p9_delete_server(_mcb_sid200)
eq("bedrock players: nothing this part drove reached a real transport (part12's tripwire, armed)",
   _P9_TRIPPED[_trips200:], [])
