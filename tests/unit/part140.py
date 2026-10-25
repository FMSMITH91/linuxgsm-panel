"""Part 140 of the unit suite: what LinuxGSM's releases up to v26.4.0 changed under the panel.

From a review of LinuxGSM's changelog (v24.2.0 to v26.4.0) against the panel. Held here:

* The install's OS guard: the serverlist's os column is not a cap (v26.4.0 left cod, cod2, coduo
  and mohaa on ubuntu-24.04 although they run on 26.04); LinuxGSM's own check_deps.sh refusal is.
* The ports `details` lists that players need (Satisfactory's ReliableMessaging, ARK's and Conan's
  raw UDP, Mordhau's beacon, The Isle's queue, TeamSpeak's file transfer, MTA's resource HTTP), and
  the admin ones that stay shut (TeamSpeak's ServerQuery, RCON, telnet, web admin).
* The panel's cron lines in the `cd /home/<u> && ./<s> <cmd>` form every LinuxGSM monitor
  recognises, and the old full-path lines migrated in place.
* Project Zomboid's admin password: never left at LinuxGSM's CHANGE_ME by an install, and a one-click
  fix for one that is.
* Valheim's -crossplay: no player count is not an empty server for a backup.
* Retired games (scpslsm, ps): still discovered and imported, and no weekly update-lgsm that can
  only fail.
* Default ports and moderation for the games LinuxGSM added; the CS:GO App ID note.
* LinuxGSM's command aliases in the maintenance and in-flight probes, and `start`'s exit code 2.

HOW IT RUNS. Pure functions directly; routes on part12's app with its transport tripwire armed and
every host call stubbed. Nothing reaches a host or data/.
"""
import os
import re as _re140

from unit.part01 import check
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client,
                         _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
import app as _app140
from panel.routes import manage_servers as _ms140

_TRIP140_START = len(_P9_TRIPPED)


def _read140(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ── 1. the os column is not a cap; LinuxGSM's check_deps refusal is ─────────────────────────────
# v26.4.0's serverlist: 138 games on ubuntu-26.04, cod/cod2/coduo/mohaa on ubuntu-24.04, btl and onset
# on ubuntu-20.04. LinuxGSM (#5069) runs the four on 26.04; its check_deps.sh refuses btl and onset
# above Ubuntu 20.04 / Debian 11, and nothing else.
_rows140 = ([{"shortname": "g%d" % i, "gameservername": "g%dserver" % i, "gamename": "Game %d" % i,
              "os": "ubuntu-26.04"} for i in range(138)]
            + [{"shortname": sn, "gameservername": sn + "server", "gamename": sn.upper(),
                "os": "ubuntu-24.04"} for sn in ("cod", "cod2", "coduo", "mohaa")]
            + [{"shortname": sn, "gameservername": sn + "server", "gamename": sn.upper(),
                "os": "ubuntu-20.04"} for sn in ("btl", "onset")])


def _flagged140(rows):
    saved = dict(_app140._GAME_LIST_CACHE)
    real = _app140.lgsm_data.serverlist
    try:
        _app140._GAME_LIST_CACHE.clear()
        _app140._GAME_LIST_CACHE["games"] = None
        _app140.lgsm_data.serverlist = lambda *a, **k: rows
        return {g["shortname"]: g["legacy_os"] for g in _app140.load_game_list() if g["legacy_os"]}
    finally:
        _app140.lgsm_data.serverlist = real
        _app140._GAME_LIST_CACHE.clear()
        _app140._GAME_LIST_CACHE.update(saved)


_fl140 = _flagged140(_rows140)
check("os cap: on v26.4.0's serverlist only btl and onset carry a cap (20.04); cod, cod2, coduo and "
      "mohaa, left on ubuntu-24.04 in the os column, carry none",
      _fl140 == {"btl": "ubuntu-20.04", "onset": "ubuntu-20.04"}, repr(_fl140))


def _refusal140(game, host_os):
    """_os_cap_refusal for `game` on a host whose os-release reads `host_os` -> True when refused."""
    try:
        _p9_arm(who="part140")
        _p9_patch_sm("host_os_slug", lambda r: host_os)
        with _p9.test_request_context("/", headers={"Accept": "application/json"}):
            return _ms140._os_cap_refusal(object(), game) is not None
    finally:
        _p9_restore_all()


_cap_cases140 = (
    ("cod", "ubuntu-26.04", False), ("mohaa", "ubuntu-26.04", False), ("coduo", "debian-13", False),
    ("bf1942", "ubuntu-26.04", False), ("btl", "ubuntu-26.04", True), ("onset", "ubuntu-24.04", True),
    ("btl", "ubuntu-20.04", False), ("btl", "debian-12", True), ("onset", "debian-11", False),
    ("btl", None, False), ("gmod", "ubuntu-26.04", False))
_cap_got140 = [(g, h, _refusal140(g, h)) for g, h, _w in _cap_cases140]
check("os cap: the install refuses exactly what LinuxGSM refuses — cod/mohaa/coduo/bf1942 install on "
      "Ubuntu 26.04 and Debian 13, btl/onset are refused above Ubuntu 20.04 and Debian 11, an unreadable "
      "host fails open",
      [w for _g, _h, w in _cap_cases140] == [got for _g, _h, got in _cap_got140], repr(_cap_got140))


# ── 2. the port rows players need, and only those ────────────────────────────────────────────────
# Each table is the rows LinuxGSM v26.4.0's info_messages.sh prints for that game, in its order.
from panel.ops.ssh_manager import _core as _smc140, game as _smg140  # noqa: E402

_PORT_TABLES140 = {
    "sf": (("Game", 7777, "udp"), ("Server API", 7777, "tcp"), ("ReliableMessaging", 8888, "tcp")),
    "ark": (("Game", 7777, "udp"), ("RAW UDP Socket", 7778, "udp"), ("Query", 27015, "udp"),
            ("RCON", 27020, "tcp")),
    "ce": (("Game", 7777, "udp"), ("Raw UDP", 7778, "udp"), ("Query", 27015, "udp")),
    "mh": (("Game", 7777, "udp"), ("Query", 27015, "udp"), ("Beacon", 15000, "udp")),
    "ti": (("Game", 7777, "udp"), ("Queue", 10000, "tcp"), ("RCON", 8888, "tcp")),
    "ts3": (("Voice", 9987, "udp"), ("Query", 10011, "tcp"), ("Query (SSH)", 10022, "tcp"),
            ("Query (http)", 10080, "tcp"), ("Query (https)", 10443, "tcp"),
            ("File Transfer", 30033, "tcp"), ("Telnet", 10011, "tcp")),
    "arma3": (("Game", 2302, "udp"), ("Voice", 2302, "udp"), ("Query", 2303, "udp"),
              ("Steam", 2304, "udp"), ("Voice (unused)", 2305, "udp"), ("BattleEye", 2306, "udp")),
    "mta": (("Game", 22003, "udp"), ("Query", 22126, "udp"), ("HTTP", 22005, "tcp")),
    "pc": (("Game", 27015, "udp"), ("Query", 27016, "udp"), ("Steam", 8766, "udp"),
           ("API", 9000, "tcp"), ("HTTP", 9000, "tcp")),
    "rust": (("Game", 28015, "udp"), ("Query", 28017, "udp"), ("RCON", 28016, "tcp"),
             ("App", 28082, "tcp")),
    "sdtd": (("Game", 26900, "tcp"), ("Game", 26900, "udp"), ("Game+2", 26902, "udp"),
             ("Web Interface", 8080, "tcp"), ("Telnet", 8081, "tcp")),
    "unreal": (("Game", 7777, "udp"), ("LAN Beacon", 8777, "udp"), ("Web Interface", 8076, "tcp")),
    "gmod": (("Game", 27015, "udp"), ("Game", 27015, "tcp"), ("Client", 27005, "udp"),
             ("SourceTV", 27020, "udp"), ("Steam", 26901, "udp")),
    "dst": (("Game: Server", 10999, "udp"), ("Game: Master", 10888, "udp"), ("Steam", 27018, "udp"),
            ("Steam: Auth", 8766, "udp")),
}
_PORT_WANT140 = {
    "sf": [7777, 8888], "ark": [7777, 7778, 27015], "ce": [7777, 7778, 27015],
    "mh": [7777, 15000, 27015], "ti": [7777, 10000], "ts3": [9987, 30033], "arma3": [2302, 2303],
    "mta": [22003, 22005, 22126], "pc": [27015, 27016], "rust": [28015, 28017],
    "sdtd": [26900, 26902], "unreal": [7777], "gmod": [27015], "dst": [10999],
}


def _details140(rows):
    return ("Server IP:\tp140.example.invalid:%d\nDESCRIPTION  PORT   PROTOCOL  LISTEN\n" % rows[0][1]
            + "".join("%s\t%d\t%s\t1\n" % r for r in rows) + "\n")


_rag140 = _smc140.run_as_game_user
_ports_got140 = {}
try:
    for _gt140, _rows in _PORT_TABLES140.items():
        _smc140.run_as_game_user = (lambda text: lambda *a, **k: (text, "", 0))(_details140(_rows))
        _ports_got140[_gt140] = _smg140.detect_game_ports(object(), "u", _gt140 + "server",
                                                          game_type=_gt140)["open_ports"]
finally:
    _smc140.run_as_game_user = _rag140
for _gt140, _want in _PORT_WANT140.items():
    check("player ports: %s opens exactly %s" % (_gt140, _want), _ports_got140.get(_gt140) == _want,
          "%s opened %s" % (_gt140, _ports_got140.get(_gt140)))

# Every caller that OPENS ports says which game it is: without game_type, TeamSpeak's ServerQuery
# rows read as server-browser queries again.
for _rel140, _n140 in ((("panel", "routes", "manage_servers.py"), 2), (("panel", "routes", "remote_vps.py"), 1)):
    _src140 = _read140(*_rel140)
    check("player ports: %s passes the game type to every detect_game_ports call that opens ports"
          % "/".join(_rel140),
          len(_re140.findall(r"detect_game_ports\([^)]*game_type=gs\.game_type", _src140)) == _n140,
          "found %d" % len(_re140.findall(r"detect_game_ports\([^)]*game_type=gs\.game_type", _src140)))


# ── 3. the panel's cron lines in the form every LinuxGSM monitor recognises ─────────────────────
import shlex as _shlex140  # noqa: E402
import subprocess as _sp140  # noqa: E402  # nosec B404 - argv lists, local stand-ins only
import tempfile as _tf140  # noqa: E402
import time as _time140  # noqa: E402
from panel.ops.ssh_manager import cron as _smcron140  # noqa: E402

_writes140 = []
_rw140 = _smc140._rewrite_crontab
try:
    _smc140._rewrite_crontab = lambda server, user, grep_args, add, *a, **k: (
        _writes140.append((grep_args, list(add))), (True, ""))[1]
    _smc140.install_game_cron(object(), "p140u", "p140server",
                              {"monitor", "update", "mods-update", "update-lgsm"})
    _smc140.set_autostart(object(), "p140u", True, "p140server")
    _smc140.install_game_cron(object(), "p140ps", "psserver", {"monitor", "update", "update-lgsm"})
finally:
    _smc140._rewrite_crontab = _rw140
_inst140, _auto140, _ps140 = (_writes140 + [("", [])] * 3)[:3]
_cores140 = [_smcron140._unwrap_cron_command(ln.split(None, 5)[5])[0] for ln in _inst140[1]]
check("cron form: install_game_cron schedules every LinuxGSM command as `cd /home/<u> && ./<s> <cmd>`",
      _cores140 == ["cd /home/p140u && ./p140server " + c
                    for c in ("monitor", "mods-update", "update", "update-lgsm")], repr(_cores140))
check("cron form: ...and so does the Autostart switch's monitor line",
      [_smcron140._unwrap_cron_command(ln.split(None, 5)[5])[0] for ln in _auto140[1]]
      == ["cd /home/p140u && ./p140server monitor"], repr(_auto140[1]))


def _grep_keeps140(grep_args, lines):
    """What `grep <grep_args>` (the writer's filter, as the host's grep runs it) keeps of `lines`."""
    p = _sp140.run(["grep"] + _shlex140.split(grep_args), input="\n".join(lines) + "\n",
                   capture_output=True, text=True, check=False, env={"LC_ALL": "C.UTF-8", "PATH": os.defpath})
    return p.stdout.splitlines()


_old_lines140 = [
    "*/5 * * * * " + _smcron140._record_managed_cmd("p140u", "/home/p140u/p140server monitor"),
    "15 5 * * * " + _smcron140._record_managed_cmd("p140u", "/home/p140u/p140server update"),
    "30 5 * * 0 /home/p140u/p140server update-lgsm > /dev/null 2>&1",
]
_kept140 = ["0 3 * * * /home/p140u/backup.sh", "*/5 * * * * /home/p140u/p140server-2 monitor > /dev/null 2>&1"]
check("cron form: install_game_cron's rewrite removes the old full-path lines AND its own new ones, and "
      "keeps an operator's line and a neighbouring script's",
      _grep_keeps140(_inst140[0], _old_lines140 + _inst140[1] + _kept140) == _kept140,
      repr(_grep_keeps140(_inst140[0], _old_lines140 + _inst140[1] + _kept140)))
check("cron form: ...and the Autostart switch's rewrite removes both forms of the monitor line only",
      _grep_keeps140(_auto140[0], _old_lines140[:1] + _auto140[1] + _old_lines140[1:2])
      == _old_lines140[1:2], repr(_grep_keeps140(_auto140[0], _old_lines140[:1] + _auto140[1])))
check("cron form: the Autostart switch reads both forms of the monitor line as Autostart",
      _smcron140._cron_role("cd /home/p140u && ./p140server monitor", "p140u", "p140server") == "autostart"
      and _smcron140._cron_role("/home/p140u/p140server monitor", "p140u", "p140server") == "autostart"
      and _smcron140._cron_role("cd /home/p140u && ./p140server-2 monitor", "p140u", "p140server") == "")
check("cron form: a monitor line rescheduled in the editor stays visible (inline recorder, not base64), so "
      "the Autostart switch can still find and remove it",
      _smcron140._wrap_cron_command(object(), "p140u", "cd /home/p140u && ./p140server monitor")
      == _smcron140._record_managed_cmd("p140u", "cd /home/p140u && ./p140server monitor"))

# The migration: the daily upgrade pass rewrites the panel's own full-path lines in place.
_up140 = _smcron140._CronUpgrade(
    user="p140u", simple_cores=set(), flag="/home/p140u/.restart-pending", bare="gamedig ",
    pathed="PATH=x gamedig ", checks=[], restart_now=lambda f: None,
    migrate={"/home/p140u/p140server " + c: "cd /home/p140u && ./p140server " + c
             for c in _smcron140.LGC_CRON_CMDS}, drop=set())
_edited140 = ("15 5 * * * " + _smcron140._record_managed_cmd("p140u", "/home/p140u/p140server update")
              .replace("p140server update >", "p140server update --force >"))
_user_job140 = "0 4 * * * /home/p140u/.lgsm-cron/run abcdef012345 " + "L2hvbWUvcDE0MHUvcDE0MHNlcnZlciB1cGRhdGU="
_new140, _changed140 = _smcron140._upgrade_cron_lines(
    "\n".join(_old_lines140 + [_edited140, _user_job140]), _up140)
check("cron migration: the panel's monitor/update lines (recorded or bare) move to the `cd && ./` form "
      "with their schedules",
      _changed140 and [ln.split(None, 5)[:5] for ln in _new140[:3]]
      == [ln.split(None, 5)[:5] for ln in _old_lines140]
      and [_smcron140._unwrap_cron_command(ln.split(None, 5)[5])[0] for ln in _new140[:3]]
      == ["cd /home/p140u && ./p140server " + c for c in ("monitor", "update", "update-lgsm")],
      repr(_new140[:3]))
check("cron migration: ...while a recorded line whose command was edited, and an operator's own job, "
      "stay byte for byte", _new140[3:] == [_edited140, _user_job140], repr(_new140[3:]))
check("cron migration: a second pass over the migrated crontab changes nothing",
      _smcron140._upgrade_cron_lines("\n".join(_new140), _up140)[1] is False)

# What the form is FOR: LinuxGSM up to v26.3.0 sees a running update only as `/bin/bash ./<s> update`
# (pgrep -fcx). Run both forms the way cron does (`sh -c <line>`) and ask that exact question.
_d140 = _tf140.mkdtemp(prefix="p140cron")
_s140 = "p140lgc%dserver" % os.getpid()
with open(os.path.join(_d140, _s140), "w", encoding="utf-8") as _fh140:
    _fh140.write("#!/bin/bash\nsleep 4\n")
os.chmod(os.path.join(_d140, _s140), 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions - a test stand-in in a private temp dir


def _monitor_sees140(line):
    proc = _sp140.Popen(["sh", "-c", line], stdout=_sp140.DEVNULL, stderr=_sp140.DEVNULL)
    try:
        seen = False
        for _i in range(30):
            got = _sp140.run(["pgrep", "-fcx", "/bin/bash ./%s update" % _s140], capture_output=True,
                             text=True, check=False).stdout.strip()
            if got not in ("", "0"):
                seen = True
                break
            _time140.sleep(0.1)
        return seen
    finally:
        proc.kill()
        proc.wait()
        _sp140.run(["pkill", "-f", "%s update" % _s140], check=False)


_new_seen140 = _monitor_sees140("cd %s && ./%s update > /dev/null 2>&1" % (_d140, _s140))
_old_seen140 = _monitor_sees140("%s/%s update > /dev/null 2>&1" % (_d140, _s140))
check("cron form: LinuxGSM <= v26.3.0's monitor test finds an update started the new way, and did not "
      "find one started by full path (the race this closes)", _new_seen140 and not _old_seen140,
      "new form seen %s, old form seen %s" % (_new_seen140, _old_seen140))
check("cron form: a game LinuxGSM retired (psserver) gets no weekly update-lgsm, which can only fail; "
      "its other lines are written as usual",
      [_smcron140._unwrap_cron_command(ln.split(None, 5)[5])[0] for ln in _ps140[1]]
      == ["cd /home/p140ps && ./psserver " + c for c in ("monitor", "update")], repr(_ps140[1]))
_up_ps140 = _smcron140._cron_upgrade_pass(object(), "p140ps", "psserver", (None, None, None))
_new_ps140, _ch_ps140 = _smcron140._upgrade_cron_lines("\n".join([
    "*/5 * * * * " + _smcron140._record_managed_cmd("p140ps", "/home/p140ps/psserver monitor"),
    "30 5 * * 0 " + _smcron140._record_managed_cmd("p140ps", "/home/p140ps/psserver update-lgsm"),
    "30 5 * * 0 " + _smcron140._record_managed_cmd("p140ps", "cd /home/p140ps && ./psserver update-lgsm")]),
    _up_ps140)
check("cron migration: for a retired game the pass removes the panel's update-lgsm lines (either form) "
      "and migrates the rest",
      _ch_ps140 and [_smcron140._unwrap_cron_command(ln.split(None, 5)[5])[0] for ln in _new_ps140]
      == ["cd /home/p140ps && ./psserver monitor"], repr(_new_ps140))


# ── 4. Project Zomboid's admin password ───────────────────────────────────────────────────────
from panel.ops.ssh_manager import files as _smf140  # noqa: E402

_pzw140 = []


def _pz_try140(current):
    """lgc_pz_set_admin_password over a config whose adminpassword reads `current` (None: unread)."""
    del _pzw140[:]
    get, put = _smf140.lgsm_get_values, _smf140.lgsm_write_config
    try:
        _smf140.lgsm_get_values = lambda *a, **k: None if current is None else {"adminpassword": current}
        _smf140.lgsm_write_config = lambda s, u, n, upd: (_pzw140.append(dict(upd)), (True, ""))[1]
        return _smf140.lgc_pz_set_admin_password(object(), "p140pz", "pzserver")
    finally:
        _smf140.lgsm_get_values, _smf140.lgsm_write_config = get, put


_pz_def140 = _pz_try140("CHANGE_ME")
_pw140 = (_pzw140[0].get("adminpassword") if _pzw140 else "") or ""
check("pz admin: LinuxGSM's CHANGE_ME is replaced by a random password of 20 letters and digits (no blank "
      "or leading '-', which startparameters would split or read as an option), and nothing else is written",
      _pz_def140 == (True, "") and len(_pzw140) == 1 and list(_pzw140[0]) == ["adminpassword"]
      and _re140.fullmatch(r"[A-Za-z0-9]{20}", _pw140) is not None, repr((_pz_def140, len(_pw140))))
check("pz admin: ...a different one every time",
      (_pz_try140("CHANGE_ME"), _pzw140[0]["adminpassword"])[1] != _pw140)
check("pz admin: a password the operator chose is never replaced, and an unread config writes nothing",
      _pz_try140("their-own") == (False, _smf140.LGC_PZ_ALREADY_SET) and not _pzw140
      and _pz_try140(None) == (False, _smf140.LGSM_CONFIG_UNREAD) and not _pzw140)

from types import SimpleNamespace as _NS140  # noqa: E402

_pz_calls140 = []
_pz_real140 = _smf140.lgc_pz_set_admin_password
_pz_said140 = []
try:
    _smf140.lgc_pz_set_admin_password = lambda r, u, n, **k: (_pz_calls140.append((u, n)), (True, ""))[1]
    _job_pz140 = _NS140(short_name="p140pz", lgsm_name="pzserver",
                        finish=lambda msg, warn=False: _pz_said140.append((str(msg), warn)))
    _ms140._lgc_seed_pz_admin(_job_pz140, object(), _NS140(game_type="pz"))
    _job_css140 = _NS140(short_name="p140css", lgsm_name="cssserver", finish=None)
    _ms140._lgc_seed_pz_admin(_job_css140, object(), _NS140(game_type="css"))
    _ms140._lgc_noting(_job_pz140).finish("p140pz installed and started")
    _smf140.lgc_pz_set_admin_password = lambda r, u, n, **k: (False, "x")
    _job_pzf140 = _NS140(short_name="p140pz", lgsm_name="pzserver",
                         finish=lambda msg, warn=False: _pz_said140.append((str(msg), warn)))
    _ms140._lgc_seed_pz_admin(_job_pzf140, object(), _NS140(game_type="pz"))
    _ms140._lgc_noting(_job_pzf140).finish("p140pz installed and started")
finally:
    _smf140.lgc_pz_set_admin_password = _pz_real140
check("pz install: step 5 sets the random password for Project Zomboid only, and the install's last word "
      "says where it is (not what it is), as a success",
      _pz_calls140 == [("p140pz", "pzserver")] and not hasattr(_job_css140, "lgc_note")
      and _pz_said140[:1] == [("p140pz installed and started " + str(_ms140.LGC_PZ_ADMIN_SET), False)],
      repr(_pz_said140))
check("pz install: ...and when the write failed, the install says the password is still CHANGE_ME, as a "
      "warning", len(_pz_said140) == 2 and _pz_said140[1][1] is True
      and str(_ms140.LGC_PZ_ADMIN_NOT_SET) in _pz_said140[1][0], repr(_pz_said140))

# The page's half: the config read says when the password is still CHANGE_ME, and the fix route.
from panel.routes import server_files as _sf140  # noqa: E402

_pz_sid140 = _p9_new_server(P9_HOST, "p140pz", "pz", 16261)
_css_sid140 = _p9_new_server(P9_HOST, "p140css", "css", 27115)
_pz_route_calls140 = []
try:
    _p9_arm(who="part140")
    _cfg_now140 = {"v": "CHANGE_ME"}
    _p9_patch(_sf140, "lgsm_read_config", lambda r, u, n: {
        "settings": [{"key": "adminpassword", "value": _cfg_now140["v"]}], "groups": [], "raw": ""})
    _p9_patch(_sf140, "_write_refused", lambda gs, action, detail="": None)
    _p9_patch_sm("lgc_pz_set_admin_password",
                 lambda r, u, n, **k: (_pz_route_calls140.append(u), (True, ""))[1])
    _c140 = _p9_client(P9_ADMIN)
    _g1 = _c140.get("/api/server/%d/config" % _pz_sid140).get_json() or {}
    _cfg_now140["v"] = "aB3dE5gH7jK9mN2pQ4sT"
    _g2 = _c140.get("/api/server/%d/config" % _pz_sid140).get_json() or {}
    _g3 = _c140.get("/api/server/%d/config" % _css_sid140).get_json() or {}
    _r1 = _c140.post("/api/server/%d/pz-admin-password" % _pz_sid140, json={})
    _r1j = _r1.get_json() or {}
    _aud140 = _p9_audit("edit_config")
    _r2 = _c140.post("/api/server/%d/pz-admin-password" % _css_sid140, json={})
finally:
    _p9_restore_all()
    _p9_delete_server(_pz_sid140)
    _p9_delete_server(_css_sid140)
check("pz page: the config read flags a Project Zomboid server still on CHANGE_ME, not one with its own "
      "password, and adds nothing for another game",
      _g1.get("lgc_pz_default_admin") is True and _g2.get("lgc_pz_default_admin") is False
      and "lgc_pz_default_admin" not in _g3, repr((_g1.get("lgc_pz_default_admin"),
                                                  _g2.get("lgc_pz_default_admin"), sorted(_g3))))
check("pz page: the fix sets the password through the panel's one writer, says so, and puts no password "
      "in the reply or the audit row",
      _r1.status_code == 200 and _r1j.get("success") is True and _pz_route_calls140 == ["p140pz"]
      and set(_r1j) == {"success", "message"} and _aud140.detail == "adminpassword set to a random value"
      and _aud140.success is True, repr((_r1.status_code, _r1j, _aud140)))
check("pz page: ...and refuses a server that is not Project Zomboid, without writing",
      _r2.status_code == 400 and _pz_route_calls140 == ["p140pz"], repr(_r2.status_code))
_sfjs140 = _read140("static", "js", "server_files.js")
_sfhtml140 = _read140("templates", "server_files.html")
check("pz page: the Config tab carries the warning and its button for Project Zomboid only, and loadConfig "
      "shows it from the read's flag",
      "{% if server.game_type == 'pz' %}" in _sfhtml140 and 'id="lgc-pz-admin"' in _sfhtml140
      and 'data-action="lgcPzAdminFix"' in _sfhtml140
      and "pzw.style.display = d.lgc_pz_default_admin ? '' : 'none';" in _sfjs140
      and "/pz-admin-password'" in _sfjs140)


# ── 5. Valheim with -crossplay: an uncounted server is not an empty one ─────────────────────────
def _vh_skip140(game, count, startparameters, state):
    """_backup_players_online for `game` whose gamedig count is `count`, config and run state as given."""
    pc, gv, sh = _smcron140.player_count, _smf140.lgsm_get_values, _smc140.shell_as_game_user
    try:
        _smcron140.player_count = lambda *a, **k: count
        _smf140.lgsm_get_values = lambda *a, **k: (None if startparameters is None
                                                   else {"startparameters": startparameters})
        _smc140.shell_as_game_user = lambda *a, **k: (state, "", 0 if state else -1)
        return _smg140._backup_players_online(object(), "p140vh", game, 2456, None, "vhserver")
    finally:
        _smcron140.player_count, _smf140.lgsm_get_values, _smc140.shell_as_game_user = pc, gv, sh


_XP140 = "-name '${servername}' -port ${port} -world ${worldname} -crossplay -instanceid ${instanceid}"
_vh_cases140 = (
    ("vh", None, _XP140, "LGC_UP", True, "running, -crossplay, no count"),
    ("vh", None, None, "LGC_UP", True, "running, config unread (LinuxGSM's default is -crossplay)"),
    ("vh", None, _XP140, "", True, "-crossplay, run state unread"),
    ("vh", None, _XP140, "LGC_DOWN", False, "stopped"),
    ("vh", None, _XP140.replace(" -crossplay", ""), "LGC_UP", False, "Steam-only (no -crossplay)"),
    ("vh", 0, _XP140, "LGC_UP", False, "a counted zero"),
    ("css", None, _XP140, "LGC_UP", False, "another game's unknown count (unchanged)"),
)
for _g, _c, _sp, _st, _want, _why in _vh_cases140:
    _got = _vh_skip140(_g, _c, _sp, _st)
    check("vh crossplay backup: %s -> %s" % (_why, "skipped" if _want else "backs up"),
          (_got == _smg140.LGC_VH_CROSSPLAY_SKIP) if _want else _got is None, repr(_got))
check("vh crossplay backup: run_game_backup hands the script name to the player check",
      "_backup_players_online(server, user, game_type, port, query_type, selfname)"
      in _read140("panel", "ops", "ssh_manager", "game.py"))


# ── 6. retired games: still discovered and imported ─────────────────────────────────────────────
from panel.routes import discover as _disc140  # noqa: E402

check("retired games: psserver and scpslsmserver still map to a game type (ps, scpslsm)",
      _app140.lgsm_name_to_game_type("psserver") == "ps"
      and _app140.lgsm_name_to_game_type("scpslsmserver") == "scpslsm"
      and _app140.lgsm_name_to_game_type("nosuchserver") is None)
_lgl_real140 = _disc140.load_game_list
try:
    _disc140.load_game_list = lambda: [{"shortname": "squad44", "name": "Squad 44"},
                                       {"shortname": "scpsl", "name": "SCP: Secret Laboratory"}]
    _names140 = _disc140._lgc_import_names()
    _list140, _content140 = _disc140._discovered_listing(
        [{"user": "p140ps", "lgsm_name": "psserver"}, {"user": "p140sl", "lgsm_name": "scpslsmserver"}],
        set(), _names140)
finally:
    _disc140.load_game_list = _lgl_real140
check("retired games: the scan lists an existing Post Scriptum and SCP:SL ServerMod install for import, "
      "each named as retired with its replacement",
      [(e["user"], e["game_type"]) for e in _list140] == [("p140ps", "ps"), ("p140sl", "scpslsm")]
      and "retired by LinuxGSM in v25.1.0" in _list140[0]["game_name"] and "Squad 44" in _list140[0]["game_name"]
      and "SCP: Secret Laboratory" in _list140[1]["game_name"] and "v26.4.0" in _list140[1]["game_name"],
      repr(_list140))
check("retired games: ...and the import accepts them as game types (stored under their own name)",
      {"ps", "scpslsm"} <= set(_names140) and _names140["ps"] == "Post Scriptum")


# ── 7. LinuxGSM's new games: default ports and moderation ───────────────────────────────────────
_new_ports140 = {"hyt": 5520, "rsdw": 7777, "ce": 7777, "sm": 8777, "hz": 7777, "jk3": 29070}
check("new games: the install asks for each game's LinuxGSM default port, not 27015",
      {g: _ms140._desired_install_port(g, "27015") for g in _new_ports140} == _new_ports140,
      repr({g: _ms140._desired_install_port(g, "27015") for g in _new_ports140}))
check("new games: Jedi Academy (OpenJK) is moderated as idTech3 — kick and say by slot, no ban",
      _smg140.game_engine("jk3") == "idtech3"
      and _smg140.moderation_caps("jk3") == {"kick": True, "ban": False, "say": True},
      repr(_smg140.moderation_caps("jk3")))


# ── 8. the CS:GO App ID note ────────────────────────────────────────────────────────────────────
check("csgo: the Config tab tells a CS:GO server that a GSLT made for App ID 730 stops working after "
      "LinuxGSM's switch to 4465480",
      "{% if server.game_type == 'csgo' %}" in _sfhtml140
      and "A Game Server Login Token (gslt) made for App ID 730 stops working after the switch" in _sfhtml140)


# ── 10. LinuxGSM's command aliases, and `start`'s exit code 2 ───────────────────────────────────
from panel.services import host_reboot as _hr140, monitoring as _mon140  # noqa: E402

_mcmd140 = []
_bw140 = _mon140._r28a_busy_words
try:
    _mon140._r28a_busy_words = lambda remote, cmd: (_mcmd140.append(cmd), ["IDLE"])[1]
    _mon140._lgsm_maintenance_running(object(), _NS140(short_name="p140vh", lgsm_name="vhserver",
                                                       game_type="vh", name="p140vh"))
finally:
    _mon140._r28a_busy_words = _bw140
_mpat140 = _shlex140.split(_mcmd140[0])[4] if _mcmd140 else ""
_maint_pat140 = _hr140._cmd_pattern("vhserver", _hr140._MAINT_CMDS)
_lines140 = {"/bin/bash ./vhserver u": True, "/bin/bash /home/x/vhserver fu": True,
             "/bin/bash ./vhserver b": True, "/bin/bash ./vhserver update": True,
             "/bin/bash ./vhserver ur": True, "/bin/bash ./vhserver details": False,
             "/bin/bash ./vhserver s": False, "/bin/bash ./vhserver monitor": False,
             "/bin/bash ./myvhserver u": False}
for _pat, _who in ((_mpat140, "the monitor's maintenance probe"), (_maint_pat140, "the reboot's maintenance probe")):
    _got = {ln: bool(_re140.search(_pat, ln)) for ln in _lines140}
    check("aliases: %s sees `./vhserver u`, `fu`, `b`, `ur` as the commands they are, and not details, "
          "sponsor (`s`), monitor or another script" % _who, _got == _lines140,
          repr((_pat, {k: v for k, v in _got.items() if v != _lines140[k]})))


def _start140(rc, session, said="Missing dependencies required to run SteamCMD"):
    o = (_hr140._open_start, _hr140._sm.run_as_game_user, _hr140.probe_server)
    try:
        _hr140._open_start = lambda *a, **k: None
        _p9_patch_sm("run_as_game_user", lambda *a, **k: (said, "", rc))
        _hr140.probe_server = lambda *a, **k: {"session": session}
        return _hr140.safe_start(object(), {"user": "p140vh", "selfname": "vhserver"})[0]
    finally:
        _p9_restore_all()
        _hr140._open_start, _hr140.probe_server = o[0], o[2]


check("start rc 2: LinuxGSM's generic ERROR (here: missing SteamCMD dependencies) with no session is a "
      "failed start, not 'already running'; with a session it started; LinuxGSM's own 'is already "
      "running' is still running",
      (_start140(2, 0), _start140(2, 1), _start140(0, 0), _start140(2, 0, "csserver is already running"))
      == ("failed", "started", "started", "running"),
      repr((_start140(2, 0), _start140(2, 1), _start140(2, 0, "csserver is already running"))))

check("part140: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP140_START, repr(_P9_TRIPPED[_TRIP140_START:]))
