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
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client, _p9_row,
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
    p = _sp140.run(["grep"] + _shlex140.split(grep_args),  # nosec B603 B607 - grep on test text
                   input="\n".join(lines) + "\n",
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
_icr140 = _smcron140._install_cron_runner
try:
    # The base64 runner's install would reach the host; a line that goes that way is answered None.
    _smcron140._install_cron_runner = lambda *a, **k: 1
    _wrapped140 = _smcron140._wrap_cron_command(object(), "p140u", "cd /home/p140u && ./p140server monitor")
finally:
    _smcron140._install_cron_runner = _icr140
check("cron form: a monitor line rescheduled in the editor stays visible (inline recorder, not base64), so "
      "the Autostart switch can still find and remove it",
      _wrapped140 == _smcron140._record_managed_cmd("p140u", "cd /home/p140u && ./p140server monitor"),
      repr(_wrapped140))

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
os.chmod(os.path.join(_d140, _s140), 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions


def _monitor_sees140(line):
    proc = _sp140.Popen(["sh", "-c", line],  # nosec B603 B607 - a sleeping stand-in in a private temp dir
                        stdout=_sp140.DEVNULL, stderr=_sp140.DEVNULL)
    try:
        seen = False
        for _i in range(30):
            got = _sp140.run(["pgrep", "-fcx", "/bin/bash ./%s update" % _s140],  # nosec B603 B607
                             capture_output=True,
                             text=True, check=False).stdout.strip()
            if got not in ("", "0"):
                seen = True
                break
            _time140.sleep(0.1)
        return seen
    finally:
        proc.kill()
        proc.wait()
        _sp140.run(["pkill", "-f", "%s update" % _s140], check=False)  # nosec B603 B607


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
import ast as _ast140  # noqa: E402


def _calls_in140(src, fn):
    """Names called inside function `fn` of module source `src` (AST, so a comment is not a call)."""
    node = next(n for n in _ast140.walk(_ast140.parse(src)) if isinstance(n, _ast140.FunctionDef) and n.name == fn)
    return {c.func.id if isinstance(c.func, _ast140.Name) else getattr(c.func, "attr", "")
            for c in _ast140.walk(node) if isinstance(c, _ast140.Call)}


_ms_src140 = _read140("panel", "routes", "manage_servers.py")
check("pz install: the install's step 5 calls the admin-password step, and its last word goes through "
      "_lgc_noting", "_lgc_seed_pz_admin" in _calls_in140(_ms_src140, "_configure_server")
      and "_lgc_noting" in _calls_in140(_ms_src140, "_configure_and_start"))
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

    def _frames140(server, user, inner, **k):
        """lgsm_read_config's framed read: _default.cfg says CHANGE_ME, the instance cfg _cfg_now140."""
        import base64 as _b64

        def fr(tag, text):
            return "__LGSMP_%s_B__%s__LGSMP_%s_E__" % (tag, _b64.b64encode(text.encode()).decode(), tag)
        inst = "" if _cfg_now140["v"] == "CHANGE_ME" else 'adminpassword="%s"\n' % _cfg_now140["v"]
        return (fr("DEFAULT", '#### Server Settings ####\nadminpassword="CHANGE_ME"\n') + fr("COMMON", "")
                + fr("SECRETS_COMMON", "") + fr("SECRETS_INSTANCE", "") + fr("INSTANCE", inst), "", 0)
    _p9_patch(_smc140, "shell_as_game_user", _frames140)
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
    _list140 = _disc140._discovered_listing(
        [{"user": "p140ps", "lgsm_name": "psserver"}, {"user": "p140sl", "lgsm_name": "scpslsmserver"}],
        set(), _names140)[0]
finally:
    _disc140.load_game_list = _lgl_real140
check("retired games: the scan lists an existing Post Scriptum and SCP:SL ServerMod install for import, "
      "each named as retired with its replacement",
      [(e["user"], e["game_type"]) for e in _list140] == [("p140ps", "ps"), ("p140sl", "scpslsm")]
      and "retired by LinuxGSM in v25.1.0" in _list140[0]["game_name"] and "Squad 44" in _list140[0]["game_name"]
      and "SCP: Secret Laboratory" in _list140[1]["game_name"] and "v26.4.0" in _list140[1]["game_name"],
      repr(_list140))
_lgl_real140 = _disc140.load_game_list
try:
    _disc140.load_game_list = lambda: [{"shortname": "squad44", "name": "Squad 44"}]
    with _p9.app_context():
        _picked140, _skipped140 = _disc140._import_selection(
            P9_HOST, [{"user": "p140ps", "game_type": "ps"}, {"user": "p140zz", "game_type": "zz"}],
            {"p140ps": {"ps": None}, "p140zz": {"zz": None}})
finally:
    _disc140.load_game_list = _lgl_real140
check("retired games: ...and the import accepts a retired game type the scan found (stored under its own "
      "name), while a game type nobody knows is still skipped",
      _picked140 == [("p140ps", "ps", None)] and _skipped140 == ["p140zz"]
      and _names140["ps"] == "Post Scriptum", repr((_picked140, _skipped140)))


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
      and "a gslt made for App ID 730 stops working after the switch" in _sfhtml140)


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

# The backup request's monitor read (game._lg264_bk_request, from #461) asks whether the crontab runs
# the Autostart monitor. It must see the `cd /home/<u> && ./<s> monitor` line this branch writes and
# migrates to, or every migrated server reads as "Autostart off" and LinuxGSM's postponed backup as
# one nobody will run. Its shell is run in bash against a stand-in crontab.
_dbk140 = _tf140.mkdtemp(prefix="p140bk")
os.makedirs(os.path.join(_dbk140, "home", "lgsm", "lock"))
os.makedirs(os.path.join(_dbk140, "bin"))
open(os.path.join(_dbk140, "home", "lgsm", "lock", "s-monitoring.lock"), "w", encoding="utf-8").close()
_bkcmd140 = []
_bksh140 = _smc140.shell_as_game_user
try:
    _smc140.shell_as_game_user = lambda s, u, c, **k: (_bkcmd140.append(c), ("", "", 1))[1]
    _smg140._lg264_bk_request(object(), "u", "s")
finally:
    _smc140.shell_as_game_user = _bksh140


def _bk_monitor140(line):
    with open(os.path.join(_dbk140, "bin", "crontab"), "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\ncat <<'EOF'\n%s\nEOF\n" % line.replace("/home/u", _dbk140 + "/home"))
    os.chmod(os.path.join(_dbk140, "bin", "crontab"), 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    r = _sp140.run(["bash", "-c", _bkcmd140[0].replace("/home/u", _dbk140 + "/home")],  # nosec B603 B607 - fixture
                   capture_output=True, text=True, check=False,
                   env={"PATH": os.path.join(_dbk140, "bin") + ":" + os.defpath})
    return (r.stdout.split("\t") + ["", "", ""])[2]


_bk_lines140 = {
    "*/5 * * * * " + _smcron140._record_managed_cmd("u", _smcron140.lgc_cron_core("u", "s", "monitor")): "1",
    "*/5 * * * * " + _smcron140._record_managed_cmd("u", "/home/u/s monitor"): "1",
    "*/5 * * * * /home/u/s monitor": "1",
    "*/5 * * * * cd /home/u && ./s m > /dev/null 2>&1": "1",
    "#*/5 * * * * cd /home/u && ./s monitor": "0",
    "*/5 * * * * cd /home/u && ./s update": "0",
    "*/5 * * * * cd /home/u && ./ss monitor": "0",
    "*/5 * * * * /home/u/s mods-update": "0"}
_bk_got140 = {ln: _bk_monitor140(ln) for ln in _bk_lines140} if _bkcmd140 else {}
check("cron form: LinuxGSM's postponed backup counts the Autostart monitor in the panel's `cd && ./` form, "
      "the old full path and the `m` alias, and not a commented line, another command or another script",
      _bk_got140 == _bk_lines140,
      repr({k: v for k, v in _bk_got140.items() if v != _bk_lines140.get(k)} or _bkcmd140))
check("cron form: a scheduled-tasks row running the monitor by its `m` alias is not read as postponed",
      _smcron140._lg264_runs_monitor("cd /home/u && ./s m")
      and _smcron140._lg264_runs_monitor("cd /home/u && ./s monitor")
      and not _smcron140._lg264_runs_monitor("cd /home/u && ./s mods-update"))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# The adversarial review of #462: what the fixes above left open
# ════════════════════════════════════════════════════════════════════════════════════════════════
# ── 11. L1: no game type is no ServerQuery ──────────────────────────────────────────────────────
_rag_l1_140 = _smc140.run_as_game_user
try:
    _smc140.run_as_game_user = lambda *a, **k: (_details140(_PORT_TABLES140["ts3"]), "", 0)
    _l1_open140 = _smg140.detect_game_ports(object(), "u", "ts3server")["open_ports"]
finally:
    _smc140.run_as_game_user = _rag_l1_140
check("player ports: a detect_game_ports call that does not say which game it is opens none of "
      "TeamSpeak's ServerQuery rows (10011, 10022, 10080, 10443) — only what is a player port whatever "
      "the game", _l1_open140 == [9987, 30033], repr(_l1_open140))
check("player ports: ...a Query row with no game type is not a player port, with one it is (Source's)",
      _smg140._lgc_player_port("Query", None) is False and _smg140._lgc_player_port("Query", "css") is True)


# ── 12. M1: TeamSpeak 3's ServerQuery rules an older panel opened are closed, once ───────────────
from panel.ops.ssh_manager import hosts as _smh140  # noqa: E402
from panel.services import game_ports as _gp140  # noqa: E402
from panel.db.models import AuditLog as _AL140, GameServer as _GS140, db as _db140  # noqa: E402


class _Fw140:
    """A ufw rule table at the level hosts.py reads it (firewall.remote_ufw_status's groups).

    Each rule: (port_num, proto_label, action, comment, extra fields). Deletes by number, refused when
    the key at that number is not the one the caller expects, exactly as the verb is.
    """

    def __init__(self, rules, readable=True):
        self.groups = []
        for i, (port, proto, action, comment, extra) in enumerate(rules):
            g = {"key": "k%d" % i, "port_num": str(port), "proto_label": proto, "action": action,
                 "comment": comment, "scope": "Any address", "is_iface": False, "direction": "IN",
                 "port_label": "%s%s" % (port, "" if proto == "BOTH" else "/" + proto.lower())}
            g.update(extra)
            self.groups.append(g)
        self.readable, self.reads, self.deleted = readable, 0, []

    def status(self, _server):
        self.reads += 1
        if not self.readable:
            return {"unreachable": True}
        for n, g in enumerate(self.groups, 1):
            g["nums"] = [n]
        return {"installed": True, "enabled": True, "groups": list(self.groups)}

    def delete(self, _server, num, force=False, expect_key=None):
        if force or not 1 <= num <= len(self.groups) or self.groups[num - 1]["key"] != expect_key:
            return False, "moved"
        self.deleted.append(self.groups.pop(num - 1)["key"])
        return True, "deleted"

    def left(self):
        return sorted(g["key"] for g in self.groups)


# The details LinuxGSM prints for the server: its SSH ServerQuery moved onto 22 (SSH's: protected) and
# its HTTP one onto 10080, which another panel server's block holds.
_TS3_TABLE140 = (("Voice", 9987, "udp"), ("Query", 10011, "tcp"), ("Query (SSH)", 22, "tcp"),
                 ("Query (http)", 10080, "tcp"), ("Query (https)", 10443, "tcp"),
                 ("File Transfer", 30033, "tcp"), ("Telnet", 10011, "tcp"))
_TS3_RULES140 = (
    (10011, "TCP", "ALLOW", "p140ts3", {}),                         # k0  the old panel's: goes
    (10011, "BOTH", "ALLOW", "p140ts3", {}),                        # k1  goes
    (10022, "TCP", "ALLOW", "p140ts3", {}),                         # k2  TeamSpeak's default SSH port: goes
    (10443, "TCP", "ALLOW", "p140ts3", {"is_iface": True}),         # k3  on an interface (tailscale0): stays
    (10011, "TCP", "ALLOW", "", {}),                                # k4  untagged (the operator's): stays
    (10011, "TCP", "ALLOW", "p140other", {}),                       # k5  another name: stays
    (10011, "TCP", "DENY", "p140ts3", {}),                          # k6  a DENY: stays
    (22, "TCP", "ALLOW", "p140ts3", {}),                            # k7  SSH's port: stays
    (10080, "TCP", "ALLOW", "p140ts3", {}),                         # k8  in another server's block: stays
    (9987, "UDP", "ALLOW", "p140ts3", {}),                          # k9  voice, players': stays
    (30033, "TCP", "ALLOW", "p140ts3", {}),                         # k10 file transfer, players': stays
    (10443, "TCP", "ALLOW", "p140ts3", {"scope": "10.0.0.0/8"}),    # k11 from one network: stays
)


def _ts3_close140(fw, table=_TS3_TABLE140, siblings=None):
    """lgc_close_ts3_serverquery over `fw`, `details` answering `table` (None: unanswered)."""
    saved = (_smc140.run_as_game_user, _smh140.firewall.remote_ufw_status, _smh140.remote_ufw_delete_rule,
             _smh140.protected_host_ports)
    try:
        _smc140.run_as_game_user = lambda *a, **k: (("", "", -1) if table is None
                                                    else (_details140(table), "", 0))
        _smh140.firewall.remote_ufw_status = fw.status
        _smh140.remote_ufw_delete_rule = fw.delete
        _smh140.protected_host_ports = lambda server: {22}
        gs = _NS140(remote=object(), short_name="p140ts3", lgsm_name="ts3server")
        return _gp140.lgc_close_ts3_serverquery(gs, {10080: "p140next"} if siblings is None else siblings)
    finally:
        (_smc140.run_as_game_user, _smh140.firewall.remote_ufw_status, _smh140.remote_ufw_delete_rule,
         _smh140.protected_host_ports) = saved


_fw140 = _Fw140(_TS3_RULES140)
_ts3r140 = _ts3_close140(_fw140)
check("ts3 ServerQuery: the panel's own public ALLOWs on ServerQuery ports (this details' and TeamSpeak's "
      "defaults) are removed, and it says which ports",
      _ts3r140 == (True, [10011, 10022], "") and sorted(_fw140.deleted) == ["k0", "k1", "k2"],
      repr((_ts3r140, _fw140.deleted)))
check("ts3 ServerQuery: ...and nothing else: no untagged or other name's rule, no DENY, no interface or "
      "one-network rule, nothing on SSH's port or in another server's block, not the players' voice and "
      "file-transfer ports", _fw140.left() == ["k10", "k11", "k3", "k4", "k5", "k6", "k7", "k8", "k9"],
      repr(_fw140.left()))
_fw_u140 = _Fw140(_TS3_RULES140, readable=False)
_ts3u140 = _ts3_close140(_fw_u140)
check("ts3 ServerQuery: a firewall that cannot be read is not 'done', and says so",
      _ts3u140[0] is False and _ts3u140[1] == [] and "could not be read" in _ts3u140[2]
      and not _fw_u140.deleted, repr(_ts3u140))
_fw_d140 = _Fw140(_TS3_RULES140)
_ts3d140 = _ts3_close140(_fw_d140, table=None)
check("ts3 ServerQuery: with no details (its own voice and file ports unknown) nothing is touched, and "
      "it is not 'done'", _ts3d140 == (False, [], "LinuxGSM's details could not be read")
      and _fw_d140.reads == 0, repr(_ts3d140))

# ...and over ufw's own `status numbered` text (0.36.2's layout, v4 rows and their v6 twins), through the
# real parser and the real guarded delete (ufw-delete-num-if names the rule it means).
_UFW_HDR140 = ("Status: active\n\n     To                         Action      From\n"
               "     --                         ------      ----\n")
_ufw_rows140 = [
    ("Anywhere on tailscale0", "ALLOW IN", "Anywhere", ""), ("10011/tcp", "ALLOW IN", "Anywhere", "p140ts3"),
    ("10022/tcp", "ALLOW IN", "Anywhere", "p140ts3"), ("9987/udp", "ALLOW IN", "Anywhere", "p140ts3"),
    ("10011/tcp", "ALLOW IN", "Anywhere", ""), ("10011", "ALLOW IN", "Anywhere", "p140other"),
    ("10443/tcp", "ALLOW IN", "10.0.0.0/8", "p140ts3"),
    ("Anywhere (v6) on tailscale0", "ALLOW IN", "Anywhere (v6)", ""),
    ("10011/tcp (v6)", "ALLOW IN", "Anywhere (v6)", "p140ts3"),
    ("10022/tcp (v6)", "ALLOW IN", "Anywhere (v6)", "p140ts3"),
    ("9987/udp (v6)", "ALLOW IN", "Anywhere (v6)", "p140ts3"), ("10011/tcp (v6)", "ALLOW IN", "Anywhere (v6)", "")]


def _ufw_text140():
    return _UFW_HDR140 + "".join("[%2d] %-26s %-11s %-26s%s\n" % (i, t, a, f, ("# " + c) if c else "")
                                 for i, (t, a, f, c) in enumerate(_ufw_rows140, 1))


def _ufw_verb140(server, verb, args=(), **k):
    if verb == "ufw-status":
        return _ufw_text140(), "", 0
    if verb == "ufw-delete-num-if":
        n = int(args[0])
        got = [" ".join(r.split("]", 1)[1].split()) for r in _ufw_text140().splitlines()
               if r.startswith("[") and int(r[1:r.index("]")]) == n]
        if got != [args[1]]:
            return "ufw-delete-num-if: rule %s is no longer the rule that was checked" % n, "", 3
        del _ufw_rows140[n - 1]
        return "Rule deleted", "", 0
    return "", "", 0


_ufw_saved140 = (_smc140.run_privileged, _smc140.run_command, _smc140.run_as_game_user, _smh140.protected_host_ports)
try:
    _smc140.run_privileged = _ufw_verb140
    _smc140.run_command = lambda *a, **k: ("", "", 0)
    _smc140.run_as_game_user = lambda *a, **k: (_details140(_TS3_TABLE140), "", 0)
    _smh140.protected_host_ports = lambda server: {22}
    _ufw_res140 = _gp140.lgc_close_ts3_serverquery(
        _NS140(remote=_NS140(id=914002, name="vps", host="p140.example.invalid", port=22, username="root",
                             auth_method="tailscale", auth_credential="", host_key="", is_local=False,
                             sudo_enabled=True), short_name="p140ts3", lgsm_name="ts3server"), {})
finally:
    (_smc140.run_privileged, _smc140.run_command, _smc140.run_as_game_user,
     _smh140.protected_host_ports) = _ufw_saved140
check("ts3 ServerQuery: over ufw's own status text, the tagged 10011 and 10022 allows go in both families "
      "(v4 and v6), and the tailscale0 rules, the untagged and other-name allows, the one-network rule and "
      "the voice port stay", _ufw_res140 == (True, [10011, 10022], "")
      and [r[0] for r in _ufw_rows140] == [
          "Anywhere on tailscale0", "9987/udp", "10011/tcp", "10011", "10443/tcp",
          "Anywhere (v6) on tailscale0", "9987/udp (v6)", "10011/tcp (v6)"], repr((_ufw_res140, _ufw_rows140)))

# The daily pass: once per server, recorded on the row; a failure audited once, then logged only.
_ts3_sid140 = _p9_new_server(P9_HOST, "p140ts3", "ts3", 9987)
_ts3b_sid140 = _p9_new_server(P9_HOST, "p140ts3b", "ts3", 9997)
_ts3nb_sid140 = _p9_new_server(P9_HOST, "p140nb", "css", 10080)     # holds 10080: its block
_ts3_fw140 = {"p140ts3": _Fw140(_TS3_RULES140), "p140ts3b": _Fw140(_TS3_RULES140, readable=False)}
_ts3_pass140 = {}


def _ts3_heal140():
    from panel.routes.manage_servers import sibling_port_blocks as _spb140
    saved = (_smc140.run_as_game_user, _smh140.firewall.remote_ufw_status, _smh140.remote_ufw_delete_rule,
             _smh140.protected_host_ports)
    cur = {}

    def details(server, user, *a, **k):
        cur["u"] = user
        return _details140(_TS3_TABLE140), "", 0
    try:
        _smc140.run_as_game_user = details

        def status(server):
            return _ts3_fw140[cur["u"]].status(server)

        def delete(server, num, **k):
            return _ts3_fw140[cur["u"]].delete(server, num, **k)
        _smh140.firewall.remote_ufw_status = status
        _smh140.remote_ufw_delete_rule = delete
        _smh140.protected_host_ports = lambda server: {22}
        with _p9.app_context():
            _gp140.lgc_heal_ts3_serverquery(_spb140)
    finally:
        (_smc140.run_as_game_user, _smh140.firewall.remote_ufw_status, _smh140.remote_ufw_delete_rule,
         _smh140.protected_host_ports) = saved


def _ts3_audits140():
    with _p9.app_context():
        return [(a.target, a.success, a.detail) for a in _AL140.query.filter_by(action="sync_ports")
                .filter(_AL140.target.in_(["p140ts3", "p140ts3b"])).order_by(_AL140.id).all()]


try:
    _p9_arm(who="part140")
    _ts3_heal140()
    _ts3_pass140["first"] = (_p9_row(_ts3_sid140).lgc_ts3_query, _p9_row(_ts3b_sid140).lgc_ts3_query,
                             _ts3_audits140(), sorted(_ts3_fw140["p140ts3"].deleted))
    _reads140 = (_ts3_fw140["p140ts3"].reads, _ts3_fw140["p140ts3b"].reads)
    _ts3_heal140()
    _ts3_pass140["second"] = (_p9_row(_ts3b_sid140).lgc_ts3_query, _ts3_audits140(),
                              _ts3_fw140["p140ts3"].reads == _reads140[0],
                              _ts3_fw140["p140ts3b"].reads > _reads140[1])
finally:
    _p9_restore_all()
    _p9_delete_server(_ts3_sid140)
    _p9_delete_server(_ts3b_sid140)
    _p9_delete_server(_ts3nb_sid140)
_f140 = _ts3_pass140.get("first") or (None, None, [], [])
check("ts3 ServerQuery heal: the daily pass closes a TeamSpeak server's ServerQuery rules, records it on the "
      "row, and audits what it closed — not the one in another panel server's block (10080)",
      _f140[0] == "done" and _f140[3] == ["k0", "k1", "k2"]
      and ("p140ts3", True, "TeamSpeak 3 ServerQuery (its admin console): closed the panel's firewall "
           "rules on 10011, 10022") in _f140[2], repr(_f140))
check("ts3 ServerQuery heal: ...one whose firewall could not be read is audited as a failure saying so, and "
      "is not recorded as done", _f140[1] == "failed"
      and [a for a in _f140[2] if a[0] == "p140ts3b"][:1] == [
          ("p140ts3b", False, [a[2] for a in _f140[2] if a[0] == "p140ts3b"][0])]
      and "could not be read" in str([a[2] for a in _f140[2] if a[0] == "p140ts3b"]), repr(_f140))
_s140 = _ts3_pass140.get("second") or (None, [], False, False)
check("ts3 ServerQuery heal: a second pass leaves a done server alone (no firewall read), retries the "
      "failed one, and does not audit its failure again",
      _s140[0] == "failed" and _s140[2] is True and _s140[3] is True and _s140[1] == _f140[2], repr(_s140))
_app_src140 = _read140("app.py")
check("ts3 ServerQuery heal: the daily background pass runs it, on every host the panel has",
      "lgc_ts3_heal_pass" in _calls_in140(_app_src140, "_node_tools_cron_pass")
      and "lgc_heal_ts3_serverquery" in _calls_in140(_read140("panel", "services", "game_ports.py"),
                                                     "lgc_ts3_heal_pass"))


# ── 13. M2: a Valheim on -crossplay is backed up once it has skipped a whole interval ─────────────
from panel.routes import _shared as _sh140  # noqa: E402
from panel.db.models import row_birth as _rb140  # noqa: E402
from panel.core.panel_state import _game_backup_status as _gbs140  # noqa: E402

_VHX140 = _smg140.LGC_VH_CROSSPLAY_SKIP


def _vh_sched140(sid, overdue_days, reason=_VHX140, queued_days=None, interval=1):
    """Run one scheduled (or, with queued_days, queued) backup of Valheim row `sid`.

    Its crossplay check answers `reason`. -> (the runs' force flags, the status left, the outcomes
    recorded, whether it is still queued).
    """
    runs, outcomes = [], []

    def runner(remote, user, selfname, keep, force=False, **k):
        runs.append(force)
        return (True, "", False) if force else (False, reason, True)
    now = _time140.time()
    _p9_arm(who="part140")
    _p9_patch(_sh140, "run_game_backup", runner)
    _p9_patch(_sh140.bk, "get_game_schedule", lambda s: {"interval_days": 0 if queued_days is not None
                                                         else interval, "keep": 2,
                                                         "last": now - (1 + overdue_days) * 86400,
                                                         "overridden": True})
    _p9_patch(_sh140.bk, "game_backup_due", lambda s: True)
    _p9_patch(_sh140.bk, "queued_since", lambda s: now - (queued_days or 0) * 86400)
    _p9_patch(_sh140, "_record_game_clock", lambda *a, **k: outcomes.append("clock"))
    _p9_patch(_sh140, "_record_backup_outcome",
              lambda app, sid_, g, ok, why, *a, **k: outcomes.append((ok, str(why))))
    _p9_patch(_sh140, "_report_overdue_skip", lambda *a, **k: outcomes.append("overdue"))
    _p9_patch(_sh140, "_report_long_queue", lambda *a, **k: outcomes.append("queue-wait"))
    _p9_patch(_sh140, "_lg264_lgsm_alerted", lambda *a, **k: False)
    try:
        with _p9.app_context():
            gs = _db140.session.get(_GS140, sid)
            if queued_days is None:
                _sh140._back_up_if_due(_p9, (sid, gs.remote, gs.short_name, gs.lgsm_name, gs.name, "vh",
                                             2456, None, _rb140(gs)))
            else:
                gs.backup_pending = True
                _db140.session.commit()
                _sh140._back_up_queued(_p9, gs)
            pending = bool(_db140.session.get(_GS140, sid).backup_pending)
    finally:
        _p9_restore_all()
    return runs, dict(_gbs140.get(sid) or {}), outcomes, pending


_vh_sid140 = _p9_new_server(P9_HOST, "p140vh", "vh", 2456)
try:
    _vh_over140 = _vh_sched140(_vh_sid140, 1.1)
    _vh_due140 = _vh_sched140(_vh_sid140, 0.5)
    _vh_players140 = _vh_sched140(_vh_sid140, 3, reason="2 player(s) online — backup skipped so nobody gets "
                                                        "disconnected")
    _vh_queued140 = _vh_sched140(_vh_sid140, 0, queued_days=8)
    _vh_queued_new140 = _vh_sched140(_vh_sid140, 0, queued_days=2)
finally:
    _p9_restore_all()
    _p9_delete_server(_vh_sid140)
_VHA140 = _smg140.LGC_VH_BACKED_UP_ANYWAY
check("vh crossplay backup: a whole interval past due, the scheduled sweep backs it up anyway (forced), says "
      "why on the card and in the audit, and moves the clock — no overdue report for it",
      _vh_over140[0] == [False, True] and _vh_over140[1].get("ok") is True
      and _vh_over140[1].get("msg") == _VHA140 and (True, _VHA140) in _vh_over140[2]
      and "clock" in _vh_over140[2] and "overdue" not in _vh_over140[2], repr(_vh_over140))
check("vh crossplay backup: ...not before: half an interval past due it is still skipped, and nothing is "
      "forced", _vh_due140[0] == [False] and _vh_due140[1].get("busy") is True
      and _vh_due140[1].get("msg") == _VHX140, repr(_vh_due140))
check("vh crossplay backup: a server whose players WERE counted is never forced, however overdue",
      _vh_players140[0] == [False] and "overdue" in _vh_players140[2], repr(_vh_players140))
check("vh crossplay backup: a 'wait until empty' queue on it is backed up anyway after a whole interval "
      "(the default, its schedule being off), and leaves the queue",
      _vh_queued140[0] == [False, True] and _vh_queued140[1].get("msg") == _VHA140
      and _vh_queued140[3] is False, repr(_vh_queued140))
check("vh crossplay backup: ...a queue two days old still waits", _vh_queued_new140[0] == [False]
      and _vh_queued_new140[3] is True, repr(_vh_queued_new140))


# ── 14. L5: a crashed Valheim (started.lock left, no session) is down ─────────────────────────────
_dvh140 = _tf140.mkdtemp(prefix="p140vhup")
os.makedirs(os.path.join(_dvh140, "bin"))
os.makedirs(os.path.join(_dvh140, "home", "lgsm", "lock"))
os.makedirs(os.path.join(_dvh140, "tmux"))


def _vh_up140(lock, sessions):
    """_lgc_vh_up_sh run by bash over a stand-in home and tmux: {socket: [session names]}."""
    lockf = os.path.join(_dvh140, "home", "lgsm", "lock", "vhserver-started.lock")
    if lock:
        open(lockf, "w", encoding="utf-8").close()
    elif os.path.exists(lockf):
        os.remove(lockf)
    for f in os.listdir(os.path.join(_dvh140, "tmux")):
        os.remove(os.path.join(_dvh140, "tmux", f))
    for sock in sessions:
        open(os.path.join(_dvh140, "tmux", sock), "w", encoding="utf-8").close()
    table = "".join("%s) printf '%%s\\n' %s;; " % (sock, " ".join(names) or "''")
                    for sock, names in sessions.items())
    with open(os.path.join(_dvh140, "bin", "tmux"), "w", encoding="utf-8") as fh:
        fh.write("#!/bin/bash\n[ \"$1\" = -L ] || exit 1\ncase \"$2\" in %s*) exit 1;; esac\n" % table)
    os.chmod(os.path.join(_dvh140, "bin", "tmux"), 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    sh = _smg140._lgc_vh_up_sh("p140vh", "vhserver").replace("/home/p140vh", os.path.join(_dvh140, "home"))
    # The account's tmux socket directory, whatever the shell names it, is the stand-in's.
    sh = _re140.sub(r"\S*/tmux-\$\(id -u\)", lambda _m: os.path.join(_dvh140, "tmux"), sh)
    r = _sp140.run(["bash", "-c", sh], capture_output=True, text=True, check=False,  # nosec B603 B607 - fixture
                   env={"PATH": os.path.join(_dvh140, "bin") + ":" + os.defpath})
    return r.stdout.strip()


_vh_up_cases140 = (
    (True, {"vhserver-7f3a": ["vhserver"]}, "LGC_UP", "lock and a live session"),
    (True, {}, "LGC_DOWN", "lock left by a crash, no session"),
    (True, {"vhserver-7f3a": ["vhserver-2"]}, "LGC_DOWN", "lock, only another instance's session"),
    (True, {"vhserver": ["vhserver"]}, "LGC_UP", "lock and a session on the bare (pre-uid) socket"),
    (False, {"vhserver-7f3a": ["vhserver"]}, "LGC_DOWN", "a session but no lock (stopped by LinuxGSM)"),
)
for _lk140, _ss140, _want140, _why140 in _vh_up_cases140:
    _got140 = _vh_up140(_lk140, _ss140)
    check("vh crossplay backup: running is the started.lock AND a live session — %s -> %s"
          % (_why140, _want140), _got140 == _want140, repr(_got140))

_vh_sent140 = []
_vh_saved140 = (_smf140.lgsm_get_values, _smc140.shell_as_game_user)
try:
    _smf140.lgsm_get_values = lambda *a, **k: {"startparameters": _XP140}
    _smc140.shell_as_game_user = lambda s, u, cmd, **k: (_vh_sent140.append(cmd), ("LGC_DOWN", "", 0))[1]
    _vh_down140 = _smg140._lgc_vh_crossplay_skip(object(), "p140vh", "vhserver")
finally:
    _smf140.lgsm_get_values, _smc140.shell_as_game_user = _vh_saved140
check("vh crossplay backup: the backup's run-state read is that lock-and-session test, and its LGC_DOWN lets "
      "the backup run", _vh_sent140 == [_smg140._lgc_vh_up_sh("p140vh", "vhserver")] and _vh_down140 is None,
      repr((_vh_sent140, _vh_down140)))

# ── 15. L3: the install's Project Zomboid note says what happened ────────────────────────────────
_pz_notes140 = {}
for _k140, _ans140 in (("set", (True, "")), ("kept", (False, _smf140.LGC_PZ_ALREADY_SET)),
                       ("unread", (False, _smf140.LGSM_CONFIG_UNREAD)), ("failed", (False, "write failed")),
                       ("raised", None)):
    _said_pz140 = []
    _real_pz140 = _smf140.lgc_pz_set_admin_password
    try:
        _smf140.lgc_pz_set_admin_password = (
            (lambda a: lambda r, u, n, **k: a)(_ans140) if _ans140 is not None
            else lambda r, u, n, **k: (_ for _ in ()).throw(ConnectionError("down")))
        _jpz140 = _NS140(short_name="p140pz", lgsm_name="pzserver",
                         finish=lambda msg, warn=False: _said_pz140.append((str(msg), warn)))
        _ms140._lgc_seed_pz_admin(_jpz140, object(), _NS140(game_type="pz"))
        _ms140._lgc_noting(_jpz140).finish("p140pz installed and started")
    finally:
        _smf140.lgc_pz_set_admin_password = _real_pz140
    _pz_notes140[_k140] = _said_pz140[0] if _said_pz140 else None
_pz_want140 = {"set": (_ms140.LGC_PZ_ADMIN_SET, False), "kept": (_ms140.LGC_PZ_ADMIN_KEPT, False),
               "unread": (_ms140.LGC_PZ_ADMIN_UNREAD, True), "failed": (_ms140.LGC_PZ_ADMIN_NOT_SET, True),
               "raised": (_ms140.LGC_PZ_ADMIN_NOT_SET, True)}
for _k140, (_s140w, _w140) in _pz_want140.items():
    check("pz install: step 5's note when the password %s says only that, %s" % (
        _k140, "as a warning" if _w140 else "not as a warning"),
        _pz_notes140.get(_k140) == ("p140pz installed and started " + str(_s140w), _w140),
        repr(_pz_notes140.get(_k140)))
check("pz install: ...only a failed write says the password is still CHANGE_ME",
      "CHANGE_ME:" not in str(_ms140.LGC_PZ_ADMIN_KEPT) + str(_ms140.LGC_PZ_ADMIN_UNREAD)
      and "is not known" in str(_ms140.LGC_PZ_ADMIN_UNREAD))


# ── 16. L4: the admin password's read and write are one step under the cfg's lock ────────────────
import threading as _th140  # noqa: E402

_cfg_writes140 = []
_lock_seen140 = {}
_saved_l4_140 = (_smf140.lgsm_get_values, _smf140._read_instance_cfg_lines, _smf140._write_file_as_user)
_srv_l4_140 = _NS140(id=914001, host="p140.example.invalid", port=22, is_local=False, auth_method="key")


def _save_l4_140():
    _smf140.lgsm_write_config(_srv_l4_140, "p140pz", "pzserver", {"adminpassword": "TheirOwn1"})


def _get_l4_140(*a, **k):
    """The PZ fix's read: an operator's save is sent in the middle of it."""
    t = _th140.Thread(target=_save_l4_140, daemon=True)
    t.start()
    # A sleep, not join(0.5): under eventlet's monkey-patching a timed join raises its Timeout.
    _time140.sleep(0.5)
    _lock_seen140["save done during the read"] = not t.is_alive()
    _lock_seen140["thread"] = t
    return {"adminpassword": "CHANGE_ME"}


try:
    _smf140.lgsm_get_values = _get_l4_140
    _smf140._read_instance_cfg_lines = lambda *a, **k: ['adminpassword="CHANGE_ME"']
    _smf140._write_file_as_user = lambda s, u, path, data, *a, **k: (
        _cfg_writes140.append(_re140.search(r'adminpassword="([^"]*)"', data.decode()).group(1)), (True, ""))[1]
    _l4_ok140 = _smf140.lgc_pz_set_admin_password(_srv_l4_140, "p140pz", "pzserver")
    _waited140 = 0
    while _lock_seen140["thread"].is_alive() and _waited140 < 50:
        _time140.sleep(0.1)
        _waited140 += 1
finally:
    (_smf140.lgsm_get_values, _smf140._read_instance_cfg_lines, _smf140._write_file_as_user) = _saved_l4_140
check("pz admin: a settings save sent while the fix has read CHANGE_ME waits for the fix's write, so the "
      "operator's password lands last and is not overwritten by a random one",
      _l4_ok140 == (True, "") and _lock_seen140.get("save done during the read") is False
      and len(_cfg_writes140) == 2 and _cfg_writes140[1] == "TheirOwn1", repr((_l4_ok140, _lock_seen140,
                                                                              _cfg_writes140)))


# ── 17. L6 / L7: the cron upgrade says what it does, and keeps each job's last run ─────────────────
check("cron migration: the docstrings say that an operator's line of the panel's shape is migrated too, "
      "and that the retired-game drop removes lines",
      "never matches" not in (_smcron140._lgc_managed_core.__doc__ or "")
      and "indistinguishable" in (_smcron140._lgc_managed_core.__doc__ or "")
      and "nothing is added or removed" not in (_smcron140.upgrade_managed_cron_tracking.__doc__ or "")
      and "update-lgsm" in (_smcron140.upgrade_managed_cron_tracking.__doc__ or ""))
_old_up140 = "/home/p140u/p140server update"
_new_up140 = "cd /home/p140u && ./p140server update"
_old_jid140, _new_jid140 = _smcron140._cron_job_id(_old_up140), _smcron140._cron_job_id(_new_up140)
_ps_old140 = "/home/p140ps/psserver update-lgsm"
_tab140 = "\n".join(["15 5 * * * " + _smcron140._record_managed_cmd("p140u", _old_up140),
                     "0 4 * * * /home/p140u/p140server monitor"])
_shells140, _rewrites140 = [], []
_saved_l7_140 = (_smc140.run_privileged, _smc140._rewrite_crontab, _smc140.shell_as_game_user)
try:
    _smc140.run_privileged = lambda s, verb, args, **k: (_tab140, "", 0)
    _smc140._rewrite_crontab = lambda s, u, g, add, *a, **k: (_rewrites140.append(list(add)), (True, ""))[1]
    _smc140.shell_as_game_user = lambda s, u, cmd, **k: (_shells140.append(cmd), ("", "", 0))[1]
    _l7_changed140 = _smcron140.upgrade_managed_cron_tracking(object(), "p140u", "p140server")
finally:
    (_smc140.run_privileged, _smc140._rewrite_crontab, _smc140.shell_as_game_user) = _saved_l7_140
check("cron migration: the upgrade moves a migrated job's run history to its new job id (and only "
      "that: an unrecorded line has none)",
      _l7_changed140 is True and len(_shells140) == 1 and _old_jid140 in _shells140[0]
      and _new_jid140 in _shells140[0] and _shells140[0].count(" mv -- ") == 2, repr(_shells140))
_dcr140 = _tf140.mkdtemp(prefix="p140lgscron")
_dcr_dir140 = os.path.join(_dcr140, ".lgsm-cron")
os.makedirs(_dcr_dir140)
for _n140, _body140 in ((_old_jid140 + ".log", "old log"), (_old_jid140 + ".status", "0 1 2"),
                        ("aaaaaaaaaaaa.log", "dropped"), ("aaaaaaaaaaaa.status", "1 1 1"),
                        ("bbbbbbbbbbbb.status", "old"), ("cccccccccccc.status", "newer")):
    with open(os.path.join(_dcr_dir140, _n140), "w", encoding="utf-8") as _fh140:
        _fh140.write(_body140)
_cmds140 = []
_saved_sg140 = _smc140.shell_as_game_user
try:
    _smc140.shell_as_game_user = lambda s, u, cmd, **k: (_cmds140.append(cmd), ("", "", 0))[1]
    _smcron140._lgc_carry_cron_state(object(), "p140u", {_old_jid140: _new_jid140, "aaaaaaaaaaaa": None,
                                                         "bbbbbbbbbbbb": "cccccccccccc"})
finally:
    _smc140.shell_as_game_user = _saved_sg140
_r140 = _sp140.run(["bash", "-c", _cmds140[0].replace("/home/p140u", _dcr140)],  # nosec B603 B607 - fixture
                   capture_output=True, text=True, check=False)


def _cat140(name):
    p = os.path.join(_dcr_dir140, name)
    return open(p, encoding="utf-8").read() if os.path.exists(p) else None


check("cron migration: the old id's .log and .status become the new id's, a dropped job's are removed, "
      "and a newer file the new id already has is kept",
      _r140.returncode == 0 and _cat140(_new_jid140 + ".log") == "old log"
      and _cat140(_new_jid140 + ".status") == "0 1 2" and _cat140(_old_jid140 + ".log") is None
      and _cat140("aaaaaaaaaaaa.log") is None and _cat140("aaaaaaaaaaaa.status") is None
      and _cat140("cccccccccccc.status") == "newer" and _cat140("bbbbbbbbbbbb.status") == "old",
      repr((_r140.returncode, sorted(os.listdir(_dcr_dir140)))))
_moved_ps140 = _smcron140._lgc_moved_job_ids(
    "30 5 * * 0 " + _smcron140._record_managed_cmd("p140ps", _ps_old140),
    _smcron140._cron_upgrade_pass(object(), "p140ps", "psserver", (None, None, None)))
check("cron migration: a retired game's dropped update-lgsm line has its history removed with it",
      _moved_ps140 == {_smcron140._cron_job_id(_ps_old140): None}, repr(_moved_ps140))


# ── 18. L11: every Autostart check reads the operator's ways of writing the monitor line ──────────
_variants140 = ("cd /home/p140u/ && ./p140server monitor", "cd /home/p140u; ./p140server monitor",
                "cd /home/p140u && ./p140server m", "/home/p140u/p140server monitor")
check("autostart: the Scheduled Tasks role and the reboot's has_autostart_line read `cd /home/<u>/ && ./<s> "
      "monitor`, `cd /home/<u>; ./<s> monitor` and the `m` alias as the Autostart line",
      all(_smcron140._cron_role(v, "p140u", "p140server") == "autostart" for v in _variants140)
      and _hr140.has_autostart_line(["*/5 * * * * cd /home/p140u; ./p140server monitor"], "p140u", "p140server")
      and _smcron140._cron_role("cd /home/p140u; ./p140server update", "p140u", "p140server") == "",
      repr([_smcron140._cron_role(v, "p140u", "p140server") for v in _variants140]))
_ops_lines140 = ["*/5 * * * * " + v for v in _variants140] + [
    "*/5 * * * * cd /home/p140u; ./p140server monitor > /dev/null 2>&1"]
check("autostart: switching Autostart off removes every one of those lines, a bare one ending the line "
      "included, and keeps the update and a neighbour's",
      _grep_keeps140(_auto140[0], _ops_lines140 + _kept140 + ["15 5 * * * cd /home/p140u; ./p140server update"])
      == _kept140 + ["15 5 * * * cd /home/p140u; ./p140server update"],
      repr(_grep_keeps140(_auto140[0], _ops_lines140 + _kept140)))
_bk_variants140 = {"*/5 * * * * cd /home/u/ && ./s monitor": "1", "*/5 * * * * cd /home/u; ./s monitor": "1",
                   "*/5 * * * * cd /home/u;./s m": "1", "*/5 * * * * cd /home/u; ./s update": "0"}
_bk_vgot140 = {ln: _bk_monitor140(ln) for ln in _bk_variants140} if _bkcmd140 else {}
check("autostart: LinuxGSM's postponed backup counts those monitor lines too",
      _bk_vgot140 == _bk_variants140, repr(_bk_vgot140))


# ── 19. L8: the install picker greys a capped game out per the HOST's distro, Debian included ─────
_saved_gl140 = dict(_app140._GAME_LIST_CACHE)
_real_sl140 = _app140.lgsm_data.serverlist
try:
    _app140._GAME_LIST_CACHE.clear()
    _app140._GAME_LIST_CACHE["games"] = None
    _app140.lgsm_data.serverlist = lambda *a, **k: _rows140
    _caps140 = {g["shortname"]: g["legacy_caps"] for g in _app140.load_game_list() if g["legacy_caps"]}
finally:
    _app140.lgsm_data.serverlist = _real_sl140
    _app140._GAME_LIST_CACHE.clear()
    _app140._GAME_LIST_CACHE.update(_saved_gl140)
check("os cap: the picker's game list carries each capped game's cap on every distro LinuxGSM caps it on",
      _caps140 == {"btl": "debian-11 ubuntu-20.04", "onset": "debian-11 ubuntu-20.04"}, repr(_caps140))
check("os cap: ...and the install page puts it on the option for the script",
      'data-legacy-caps="{{ g.legacy_caps }}"' in _read140("templates", "install_server.html"))
from unit.part75 import _cut_or75, _js75, _run_js75  # noqa: E402

_name_l8_140 = "install page: a capped game is greyed out per the host's distro (Debian too)"
_out_l8_140 = _run_js75(_name_l8_140, (
    "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = '';\n"
    "global.tf = (s, v) => s.replace('{os}', v.os);\n"
    "function mkOpt(value, os, caps, text){ const a = {'data-legacy-os': os, 'data-legacy-caps': caps};\n"
    "  return {value, textContent: text, disabled: false, getAttribute: k => (k in a ? a[k] : null),\n"
    "  hasAttribute: k => k in a, setAttribute: (k, v) => { a[k] = v; }, removeAttribute: k => { delete a[k]; }}; }\n"
    "const btl = mkOpt('btl', 'ubuntu-20.04', 'debian-11 ubuntu-20.04', 'BATTALION: Legacy (ubuntu-20.04)');\n"
    "const sel = {value: '', options: [btl]}, host = {value: '1'};\n"
    "const slug = {'1': 'debian-12', '2': 'debian-11', '3': 'ubuntu-22.04', '4': 'ubuntu-20.04',\n"
    "              '5': 'arch-rolling', '6': 'debian'};\n"
    "global.fetch = (u) => Promise.resolve({ok: true,\n"
    "  json: () => Promise.resolve({os_slug: slug[u.split('/')[3]]})});\n"
    "global.document = {getElementById: id => ({'game-type-select': sel, 'remote-select': host})[id] || null};\n"
    + "".join(_cut_or75(_js75("manage_servers.js"), "function %s(" % _f140) + "\n" for _f140 in (
        "_capForHost", "_osOlder", "_osVersionParts", "_osVersionBelow", "_withoutParenNote",
        "_hostStillSelected", "filterGamesForHost"))
    + "(async () => { const got = {};\n"
    "  for (const h of ['1', '2', '3', '4', '5', '6']) { host.value = h; filterGamesForHost(); await settle();\n"
    "    got[slug[h]] = [btl.textContent, btl.disabled]; }\n"
    "  console.log(JSON.stringify(got)); })();\n"))
if _out_l8_140 is not None:
    check("install page: btl is greyed out on Debian 12 ('needs debian 11') and Ubuntu 22.04, selectable on "
          "Debian 11 and Ubuntu 20.04, and an unknown distro or a Debian with no version fails open",
          _out_l8_140 == {
              "debian-12": ["BATTALION: Legacy (needs debian 11)", True],
              "debian-11": ["BATTALION: Legacy (ubuntu-20.04)", False],
              "ubuntu-22.04": ["BATTALION: Legacy (needs ubuntu 20.04)", True],
              "ubuntu-20.04": ["BATTALION: Legacy (ubuntu-20.04)", False],
              "arch-rolling": ["BATTALION: Legacy (ubuntu-20.04)", False],
              "debian": ["BATTALION: Legacy (ubuntu-20.04)", False]}, repr(_out_l8_140))


# ── 20. L9: the CS:GO note only where it applies ─────────────────────────────────────────────────
def _csgo_note140(instance):
    """lgsm_read_config's lgc_csgo_appid_note for a csgoserver whose instance cfg is `instance`."""
    import base64 as _b64

    def fr(tag, text):
        return "__LGSMP_%s_B__%s__LGSMP_%s_E__" % (tag, _b64.b64encode(text.encode()).decode(), tag)
    saved = _smc140.shell_as_game_user
    try:
        _smc140.shell_as_game_user = lambda *a, **k: (
            fr("DEFAULT", '#### Server Settings ####\ngslt=""\nclientappid="4465480"\n') + fr("COMMON", "")
            + fr("SECRETS_COMMON", "") + fr("SECRETS_INSTANCE", "") + fr("INSTANCE", instance), "", 0)
        return (_smf140.lgsm_read_config(object(), "p140cs", "csgoserver") or {}).get("lgc_csgo_appid_note")
    finally:
        _smc140.shell_as_game_user = saved


_tok140 = "gslt=" + '"' + "P140" + "TOKEN" + '"\n'
_csgo_cases140 = ((_tok140, True, "a gslt, LinuxGSM's default App ID 4465480"),
                  (_tok140 + 'clientappid="730"\n', False, "a gslt, clientappid 730 (csgo_legacy)"),
                  (_tok140 + 'clientappid=""\n', False, "a gslt, clientappid unmanaged"),
                  ("", False, "no gslt"))
for _inst140, _want140, _why140 in _csgo_cases140:
    _got140 = _csgo_note140(_inst140)
    check("csgo: the App ID note shows %s for %s" % ("" if _want140 else "nothing", _why140),
          _got140 is _want140, repr(_got140))
check("csgo: the note is hidden until the config read says it applies",
      'id="lgc-csgo-appid"' in _sfhtml140 and "csw.style.display = d.lgc_csgo_appid_note ? '' : 'none';"
      in _read140("static", "js", "server_files.js")
      and _re140.search(r'id="lgc-csgo-appid"[^>]*style="display:none;"', _sfhtml140) is not None)


# ── 21. L10: every game whose LinuxGSM config sets another port gets it, not 27015 ───────────────
# The `port=` of each one's _default.cfg at LinuxGSM v26.4.0 (config-default/config-lgsm/<s>server).
_l10_ports140 = {"btl": 7777, "ck": 1234, "cmw": 7777, "dayz": 2302, "dodr": 7777, "hcu": 7777, "hw": 12871,
                 "inss": 27102, "mohaa": 12203, "ohd": 7777, "pvr": 7777, "pw": 8211, "q4": 28004,
                 "qw": 27500, "sbots": 7777, "scpsl": 7777, "sf": 7777, "sof2": 20100, "squad44": 10027,
                 "tf": 5001, "ti": 7777, "tu": 7777, "ut": 7777, "ut3": 7777, "wf": 44400, "wurm": 3724}
_l10_got140 = {g: _ms140._desired_install_port(g, "27015") for g in _l10_ports140}
check("default ports: the 26 games whose LinuxGSM config sets a port other than 27015 are offered it",
      _l10_got140 == _l10_ports140, repr({g: p for g, p in _l10_got140.items() if p != _l10_ports140[g]}))


# ── 22. L2: MTA's HTTP port stays open, and the operator is told it also serves the web admin ────
_mta_rows140 = [{"desc": d, "port": p, "proto": pr} for d, p, pr in _PORT_TABLES140["mta"]]
_mta_notes140 = [str(n) for n in _smg140.lgc_admin_port_notes("mta", _mta_rows140, [22003, 22005, 22126])]
check("mta: opening its HTTP port (22005) comes with a note that it also serves MTA's web admin over plain "
      "HTTP, and to give admin accounts a strong password",
      _mta_notes140 == [_smg140.LGC_MTA_HTTP_NOTE.format(port=22005)]
      and 22005 in _ports_got140.get("mta", []), repr(_mta_notes140))
check("mta: ...no note when that port was not opened, or for another game",
      _smg140.lgc_admin_port_notes("mta", _mta_rows140, [22003]) == []
      and _smg140.lgc_admin_port_notes("onset", [{"desc": "HTTP", "port": 8080}], [8080]) == [])
check("mta: 'Open all ports' and the install both say it",
      "lgc_admin_port_notes" in _calls_in140(_read140("panel", "routes", "remote_vps.py"), "_rv_sync_ports_run")
      and "lgc_admin_port_notes" in _calls_in140(_ms_src140, "_open_game_ports"))


check("part140: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP140_START, repr(_P9_TRIPPED[_TRIP140_START:]))
