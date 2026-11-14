"""Part 203 of the unit suite: the scheduled world reset for Valheim (vh) and Project Zomboid (pz).

Held here:
* The start parameters are read the way LinuxGSM starts the server: its config, its reload of
  startparameters (every setting expanded with its final value), extraparams added, then the shell's
  split of the whole string. LinuxGSM's own default configs (vhserver, pzserver) read; a trailing
  comment on an ordinary setting is read as bash reads it, never on startparameters; another
  setting's line that only expands a key does not count as setting it, but `${key:=…}` and
  arithmetic do; a value that expands another setting, a shell expansion or `#`/`~`, and words a
  password could add are refused.
* Valheim: -world exactly once, -savedir exactly once and inside the account's home; the plan is
  <savedir>/worlds_local/<world> plus that world's pre-1.0 files. Project Zomboid: -servername exactly
  once, nothing moving ~/Zomboid (cachedir, user.home) in the start parameters or ProjectZomboid64.json.
* The host command against scratch homes shaped like the test servers' recorded layouts: the world
  goes, the lists, settings, accounts, other worlds and backups stay; a symlinked folder, a world
  without its save marker, a busy save folder, a missing folder are refused, nothing deleted.
* The sweep through the app: state, stop, backup, delete, start for both; a root-capable game account
  ends the reset untouched, one the host could not be asked about waits; a ProjectZomboid64.json
  that moves the folder ends it, one not read waits. Project Zomboid's players are counted by gamedig.
* The card: both offered with their own text; the player box unticked for Valheim, ticked for Zomboid.

HOW IT RUNS. part12's app with its transport tripwire armed and every host call stubbed (part183's
sweep helper); host commands run under local bash in a temp folder (part183's helper). Times are
fixed, never the wall clock. Nothing reaches a host or data/. Hosts and passwords are invented.
"""
import os as _os203
import subprocess as _sp203  # nosec B404 - stand-in holders for the busy test, in a temp folder
from types import SimpleNamespace as _NS203

from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9_arm, _p9_client, _p9_delete_server, _p9_new_server,
                         _p9_patch, _p9_patch_sm, _p9_restore_all)
import unit.part183 as _p183
from unit.part183 import _host183, _is_delete183, _last183, _sweep_case183
from panel.core import i18n as _i18n203
from panel.ops.ssh_manager import _core as _core203, cron as _cron203
from panel.routes import _shared as _sh203, server_detail as _sd203, server_files as _sf203
from panel.services import wipe_schedule as _ws203, world_reset as _wwr203

_trips203 = len(_P9_TRIPPED)

# ── 1. LinuxGSM's own configs (master, 2026-11), the lines that matter, passwords invented ──────
_VH_DEFAULT203 = (
    'servername="LinuxGSM"\n'
    'serverpassword="" # Minimum password length is 5.\n'
    'port="2456"\nworldname="${selfname}"\npublic="1"\nsavedir="$HOME/.config/unity3d/IronGate/Valheim"\n'
    'logFile=""\nsaveinterval="1800" # Auto-save in seconds.\nbackups="4"\nbackupshort="7200"\n'
    'backuplong="43200"\ninstanceid="1"\nworldmodifiers=""\n'
    'startparameters="-name \'${servername}\' -password ${serverpassword} -port ${port} -world ${worldname} '
    '-public ${public} -savedir \'${savedir}\' -saveinterval ${saveinterval} -backups ${backups} -backupshort '
    '${backupshort} -backuplong ${backuplong} -crossplay -instanceid ${instanceid} ${logFile:+ -logFile '
    '\'${logFile}\'} ${worldmodifiers:+ ${worldmodifiers}}"\n'
    'extraparams=""\n'
    'lgsmlogdate="${lgsmlogdir}/${selfname}-script-$(date \'+%Y-%m-%d-%H:%M:%S\').log"\n'
    'executabledir="${serverfiles}"\nexecutable="./valheim_server.x86_64"\n')
_PZ_DEFAULT203 = ('adminpassword="CHANGE_ME"\n'
                  'startparameters="-servername ${selfname} -adminpassword ${adminpassword}"\n'
                  'extraparams=""\nexecutabledir="${serverfiles}"\nexecutable="./start-server.sh"\n'
                  'servercfgdir="${HOME}/Zomboid/Server"\n')


def _vh203(inst="", secrets='serverpassword="p203-invented"\n', default=_VH_DEFAULT203):
    return [default, "", "", inst, secrets]


def _pz203(inst="", secrets='adminpassword="p203Invented9"\n', default=_PZ_DEFAULT203):
    return [default, "", "", inst, secrets]


def _words203(texts, user="vhserver"):
    return _wwr203.start_words(texts, user, user)


_vhw203, _vhwhy203 = _words203(_vh203('public="0"\n'))
eq("world reset vh: LinuxGSM's default Valheim start is read as its start shell splits it (the quoted name one "
   "word, the password and instance values put in, the empty logFile/worldmodifiers parts gone)",
   (_vhw203, _vhwhy203),
   (["-name", "LinuxGSM", "-password", "p203-invented", "-port", "2456", "-world", "vhserver", "-public", "0",
     "-savedir", "/home/vhserver/.config/unity3d/IronGate/Valheim", "-saveinterval", "1800", "-backups", "4",
     "-backupshort", "7200", "-backuplong", "43200", "-crossplay", "-instanceid", "1"], None))
_vhset203 = _words203(_vh203('servername="My Viking Hall"\nlogFile="/home/vhserver/log/v.log"\n'
                             'worldmodifiers="-preset hard -modifier raids none"\n'))[0] or []
check("world reset vh: ${logFile:+ -logFile '${logFile}'} and ${worldmodifiers:+ ...} come in when set, and a "
      "quoted name with blanks stays one word",
      "My Viking Hall" in _vhset203 and _vhset203[-7:] == ["-logFile", "/home/vhserver/log/v.log", "-preset", "hard",
                                                          "-modifier", "raids", "none"], repr(_vhset203))
eq("world reset vh: extraparams is added after startparameters, as LinuxGSM's reload adds it",
   (_words203(_vh203('extraparams="-instanceid 2"\n'))[0] or [])[-2:], ["-instanceid", "2"])
eq("world reset pz: LinuxGSM's default Project Zomboid start is read (servername from selfname)",
   _words203(_pz203(), "pzserver"), (["-servername", "pzserver", "-adminpassword", "p203Invented9"], None))

_BAD_START203 = {
    "a command substitution": _vh203('startparameters="-world $(cat w)"\n'),
    "an expansion with a default (${x:-y})": _vh203('startparameters="-world ${worldname:-x}"\n'),
    "a password that the shell would expand ($)": _vh203(secrets='serverpassword="pa$$word1"\n'),
    "a value that expands another setting": _vh203('worldname="${servername}"\n'),
    "command syntax a value puts in (;)": _vh203(secrets='serverpassword="pass;word"\n'),
    "an unquoted # (the start shell drops the rest)": _vh203(secrets='serverpassword="#hidden"\n'),
    "an unquoted ~ (the start shell expands it)": _vh203('worldname="~v"\n'),
    "a quote the name opens and never closes": _vh203('servername="Bob\'s hall"\n'),
    "a double quote put in by a value": _vh203('servername="say \\"hi\\""\n'),
    "a trailing comment on startparameters itself (the reload's sed keeps it)":
        _vh203('startparameters="-world x" # mine\n'),
}
for _why203, _texts203 in _BAD_START203.items():
    check("world reset start parameters: %s is refused" % _why203, _words203(_texts203)[0] is None,
          repr(_words203(_texts203)))
check("world reset config: another setting's line that sets the key (${port:=1}, arithmetic) is still a "
      "form the panel refuses; one that only expands it is not",
      _wwr203.cfg_values(['x="${port:=27015}"\nport="1"\n'], ["port"])[0] is None
      and _wwr203.cfg_values(['x="$((port=5))"\nport="1"\n'], ["port"])[0] is None
      and _wwr203.cfg_values(['x="-port ${port} $port ${port:+-p}"\nport="1"\n'], ["port"])[0] == {"port": "1"}
      and _wwr203.cfg_values(['export port="1"\n'], ["port"])[0] is None, "")


# ── 2. what each game's start parameters say about its world ────────────────────────────────────
def _vhl203(**over):
    words = list(_vhw203)
    for k, v in over.items():
        words[words.index("-" + k) + 1] = v
    return _wwr203.vh_layout(words, "vhserver")


eq("world reset vh: the world is <savedir>/worlds_local/<world>, with the world's pre-1.0 .fwl/.db (and .old) "
   "files beside it, each held to its own test",
   _vhl203()[0], {"dir": "", "base": ".config/unity3d/IronGate/Valheim/worlds_local",
                  "remove": ["vhserver", "vhserver.fwl", "vhserver.db", "vhserver.fwl.old", "vhserver.db.old"],
                  "loose": ["vhserver.fwl", "vhserver.db", "vhserver.fwl.old", "vhserver.db.old"], "globs": [],
                  "create": None, "world": "_main.*.fwl2"})
_VH_BAD203 = {
    "-savedir outside the account's home": _vhl203(savedir="/srv/valheim"),
    "-savedir with a '..' part": _vhl203(savedir="/home/vhserver/../other/v"),
    "-savedir with a doubled slash": _vhl203(savedir="/home/vhserver//v"),
    "-savedir the home itself": _vhl203(savedir="/home/vhserver"),
    "a world name with a slash": _vhl203(world="a/b"),
    "a world name '..'": _vhl203(world=".."),
    "-world given twice (a password '-world x' adds one)":
        _wwr203.vh_layout(_vhw203 + ["-world", "other"], "vhserver"),
    "-World in another case": _wwr203.vh_layout(_vhw203 + ["-World", "other"], "vhserver"),
    "--savedir with two dashes": _wwr203.vh_layout(_vhw203 + ["--savedir", "/home/vhserver/x"], "vhserver"),
    "no -savedir (the folder would be the game's guess)":
        _wwr203.vh_layout([w for w in _vhw203 if w != "-savedir"], "vhserver"),
    "-world with no value": _wwr203.vh_layout(["-world"], "vhserver"),
}
for _why203, _res203 in _VH_BAD203.items():
    check("world reset vh: %s is refused" % _why203, _res203[0] is None and _res203[1], repr(_res203))

_pzw203 = ["-servername", "pzserver", "-adminpassword", "p203Invented9"]
eq("world reset pz: the save is ~/Zomboid/Saves/Multiplayer/<servername>, held to map_t.bin",
   _wwr203.pz_layout(_pzw203)[0], {"dir": "", "base": "Zomboid/Saves/Multiplayer", "remove": ["pzserver"],
                                   "globs": [], "create": None, "world": "map_t.bin"})
_PZ_BAD203 = {
    "-cachedir=": _pzw203 + ["-cachedir=/srv/z"],
    "-Ddeployment.user.cachedir": _pzw203 + ["-Ddeployment.user.cachedir=/srv/z"],
    "-Duser.home": _pzw203 + ["-Duser.home=/srv"],
    "a password that adds -cachedir": ["-servername", "pzserver", "-adminpassword", "x", "-CacheDir=/srv"],
    "no -servername": ["-adminpassword", "x"],
    "two -servername": _pzw203 + ["-servername", "other"],
}
for _why203, _w203 in _PZ_BAD203.items():
    check("world reset pz: start parameters with %s are refused" % _why203, _wwr203.pz_layout(_w203)[0] is None,
          repr(_wwr203.pz_layout(_w203)))
_PZJSON203 = ('{"mainClass": "zombie/network/GameServer", "classpath": ["java/.", "java/projectzomboid.jar"], '
              '"vmArgs": ["-Djava.awt.headless=true", "-Xmx2g", "-Dzomboid.steam=1", "-XX:+UseZGC"]}')
check("world reset pz: ProjectZomboid64.json with only LinuxGSM's/the game's own options passes; cachedir, "
      "user.home or a \\u escape there is refused",
      _wwr203.pz_json_problem(_PZJSON203) is None
      and _wwr203.pz_json_problem(_PZJSON203.replace("-Xmx2g", "-Ddeployment.user.cachedir=/srv")) is not None
      and _wwr203.pz_json_problem(_PZJSON203.replace("-Xmx2g", "-Duser.home=/srv")) is not None
      and _wwr203.pz_json_problem(_PZJSON203.replace("-Xmx2g", "-Ddeployment.user.\\u0063achedir=/x")) is not None,
      "")
check("world reset vh/pz: a server not started LinuxGSM's way (another executable, executabledir or a "
      "preexecutable) is refused",
      all(_wwr203._wwr_exe_problem(dict({"executabledir": "${serverfiles}", "executable": "./start-server.sh"}, **o),
                                   "./start-server.sh") is not None
          for o in ({"executable": "./start-server.sh -cachedir=/x"}, {"executabledir": "/srv"},
                    {"preexecutable": "env"}))
      and _wwr203._wwr_exe_problem({"executabledir": "${serverfiles}", "executable": "./start-server.sh"},
                                   "./start-server.sh") is None, "")

# ── 3. the host command against scratch homes (the test servers' recorded layouts) ──────────────
_VHP203 = _vhl203()[0]
_PZP203 = _wwr203.pz_layout(_pzw203)[0]
_VD203 = ".config/unity3d/IronGate/Valheim/"
_W203 = _VD203 + "worlds_local/"
_VH_FILES203 = ("serverfiles/valheim_server.x86_64", _VD203 + "adminlist.txt", _VD203 + "bannedlist.txt",
                _VD203 + "permittedlist.txt", _VD203 + "prefs", _W203 + "vhserver/_main.1.fwl2",
                _W203 + "vhserver/_main.1.db2", _W203 + "vhserver/_main.1.chunks", _W203 + "vhserver/_main.1.ok",
                _W203 + "vhserver/00_00__0_1.chunk", _W203 + "vhserver.fwl", _W203 + "vhserver.db",
                _W203 + "other/_main.0.fwl2", _W203 + "vhserver_backup_auto-20261114/_main.0.fwl2")
_vh203run = _host183(_VHP203, _VH_FILES203)
eq("world reset host (vh): the world folder and its pre-1.0 files go; the lists, prefs, another world and the "
   "server's own backup folder stay",
   _vh203run[0], sorted(["serverfiles/valheim_server.x86_64", _VD203 + "adminlist.txt", _VD203 + "bannedlist.txt",
                         _VD203 + "permittedlist.txt", _VD203 + "prefs", _W203 + "other/_main.0.fwl2",
                         _W203 + "vhserver_backup_auto-20261114/_main.0.fwl2"]))
eq("world reset host (vh): ...done, three removed", _wwr203.outcome(_vh203run[1], _vh203run[2], _VHP203),
   ("done", "world deleted (3 removed)"))

_PZ_FILES203 = ("serverfiles/start-server.sh", "Zomboid/Saves/Multiplayer/pzserver/map_t.bin",
                "Zomboid/Saves/Multiplayer/pzserver/players.db", "Zomboid/Saves/Multiplayer/pzserver/vehicles.db",
                "Zomboid/Saves/Multiplayer/pzserver/map_worldgen.bin", "Zomboid/Saves/Multiplayer/pzserver/zpop/x",
                "Zomboid/Saves/Multiplayer/other/map_t.bin", "Zomboid/db/pzserver.db", "Zomboid/Server/pzserver.ini",
                "Zomboid/Server/pzserver_SandboxVars.lua", "Zomboid/Server/pzserver_spawnregions.lua",
                "Zomboid/backups/startup/backup_1.zip", "Zomboid/mods/m.txt")
_pz203run = _host183(_PZP203, _PZ_FILES203)
eq("world reset host (pz): the save folder goes; accounts/whitelist db, settings, another save, mods and the "
   "game's backups stay",
   _pz203run[0], sorted(["serverfiles/start-server.sh", "Zomboid/Saves/Multiplayer/other/map_t.bin",
                         "Zomboid/db/pzserver.db", "Zomboid/Server/pzserver.ini",
                         "Zomboid/Server/pzserver_SandboxVars.lua", "Zomboid/Server/pzserver_spawnregions.lua",
                         "Zomboid/backups/startup/backup_1.zip", "Zomboid/mods/m.txt"]))
eq("world reset host (pz): ...done", _wwr203.outcome(_pz203run[1], _pz203run[2], _PZP203)[0], "done")

_nofwl203 = _host183(_VHP203, ("serverfiles/x", _W203 + "vhserver/notes.txt", _W203 + "vhserver.fwl"))
_dirfwl203 = _host183(_VHP203, ("serverfiles/x", _W203 + "vhserver/_main.1.fwl2", _W203 + "vhserver.db/x"))
_nomap203 = _host183(_PZP203, ("serverfiles/x", "Zomboid/Saves/Multiplayer/pzserver/notes.txt"))
check("world reset host: a folder without the game's save marker (Valheim _main.<N>.fwl2, Zomboid map_t.bin), or "
      "a pre-1.0 Valheim name that is a folder, is refused, nothing deleted",
      all("__WWR_NOTWORLD__" in r[1] and "__WWR_GONE__" not in r[1] for r in (_nofwl203, _dirfwl203, _nomap203))
      and _W203 + "vhserver.fwl" in _nofwl203[0] and _W203 + "vhserver/_main.1.fwl2" in _dirfwl203[0]
      and "Zomboid/Saves/Multiplayer/pzserver/notes.txt" in _nomap203[0]
      and _wwr203.outcome(_nomap203[1], _nomap203[2], _PZP203)
      == ("refused", "a path the reset would delete does not look like this game's world save; nothing was deleted"),
      repr((_nofwl203[:3], _dirfwl203[:3], _nomap203[:3])))

_baselink203 = _host183(_VHP203, ("serverfiles/x", _VD203 + "adminlist.txt"), links=[(_W203.rstrip("/"), "@OUT")])
_worldlink203 = _host183(_PZP203, ("serverfiles/x", "Zomboid/db/pzserver.db", "Zomboid/Saves/Multiplayer/other/map_t.bin"),
                         links=[("Zomboid/Saves/Multiplayer/pzserver", "@OUT")])
check("world reset host: a world folder's parent (worlds_local) or the save itself as a symlink is refused, "
      "the target untouched",
      "__WWR_LINK__" in _baselink203[1] and _baselink203[5] and "__WWR_LINK__" in _worldlink203[1] and _worldlink203[5]
      and _wwr203.outcome(_baselink203[1], _baselink203[2], _VHP203)[1]
      == "part of the world is a symbolic link or outside its folder; nothing was deleted",
      repr((_baselink203[:3], _worldlink203[:3])))
_nobase203 = _host183(_PZP203, ("serverfiles/x", "Zomboid/db/pzserver.db"))
eq("world reset host: no save folder at all is 'nothing found', named by the folder it looked in",
   _wwr203.outcome(_nobase203[1], _nobase203[2], _PZP203),
   ("refused", "no world was found in ~/Zomboid/Saves/Multiplayer (looked for: pzserver); nothing was deleted"))
_up203 = _host183(_PZP203, _PZ_FILES203, up=True)
check("world reset host (pz): a server LinuxGSM's test still finds running is refused, nothing deleted",
      "__WWR_RUNNING__" in _up203[1] and "Zomboid/Saves/Multiplayer/pzserver/map_t.bin" in _up203[0], repr(_up203[:3]))


def _save_holder203(home, hold):
    """A process of the account holding a file open in the Zomboid save folder (outside serverfiles)."""
    if not hold:
        return None
    path = _os203.path.join(home, "Zomboid", "Saves", "Multiplayer", "pzserver", "players.db")
    return _sp203.Popen(["bash", "-c", 'exec 3<"$1"; exec sleep "$2"', "x", path, str(hold[1])],  # nosec B603 B607
                        cwd="/")


_held_by183 = _p183._holder183
try:
    _p183._holder183 = _save_holder203
    _busy203 = _host183(_PZP203, _PZ_FILES203, hold=("file", 30), busy_polls=1)
finally:
    _p183._holder183 = _held_by183
check("world reset host (pz): a process with a file open in the save folder (outside serverfiles) after the "
      "wait is refused, nothing deleted",
      "__WWR_BUSY__" in _busy203[1] and "Zomboid/Saves/Multiplayer/pzserver/players.db" in _busy203[0],
      repr(_busy203[:3]))

# ── 4. the sweep, through the app ────────────────────────────────────────────────────────────────
_vh_sid203 = _p9_new_server(P9_HOST, "vhserver", "vh", 2456, name="p203-vh")
_pz_sid203 = _p9_new_server(P9_HOST, "pzserver", "pz", 16261, name="p203-pz")


def _pzread203(json_answer=(_PZJSON203, None)):
    asked = []

    def _read(path):
        asked.append(path)
        return json_answer if path == "serverfiles/ProjectZomboid64.json" else (None, "File not found")
    _read.asked = asked
    return _read


_vhok203 = _sweep_case183(_vh_sid203, cfg=_vh203('public="0"\n'), wait_empty=False)
_vhc203 = _vhok203["cmds"]
check("world reset sweep (vh): state, stop, backup, the delete of worlds_local/vhserver (and its pre-1.0 "
      "files), start; done",
      len(_vhc203) == 5 and _vhc203[:3] == ["status", "stop", "backup"] and _is_delete183(_vhc203[3])
      and "set -- vhserver vhserver.fwl vhserver.db vhserver.fwl.old vhserver.db.old" in _vhc203[3]
      and "/home/vhserver/.config/unity3d/IronGate/Valheim/worlds_local" in _vhc203[3]
      and _vhc203[4] == "start" and _last183(_vhok203).get("ok") is True and _vhok203["players_asked"] == 0,
      repr(_vhok203))
_vhcount203 = _sweep_case183(_vh_sid203, cfg=_vh203(), players=None)
check("world reset sweep (vh): with 'wait until empty' ticked, a Valheim whose players cannot be counted "
      "(-crossplay) waits, nothing stopped",
      _vhcount203["cmds"] == ["status"] and _vhcount203["entry"].get("pending_since")
      and "could not be counted" in (_vhcount203["entry"].get("wait") or ""), repr(_vhcount203))
_vhbad203 = _sweep_case183(_vh_sid203, cfg=_vh203('savedir="/srv/valheim"\n'))
check("world reset sweep (vh): a -savedir outside the account's home ends the reset, server untouched, alerted",
      _vhbad203["cmds"] == [] and _last183(_vhbad203).get("ok") is False
      and "-savedir is not a plain folder" in (_last183(_vhbad203).get("detail") or "")
      and _vhbad203["alerts"] == ["Scheduled wipe did not run"], repr(_vhbad203))

_pzr203 = _pzread203()
_pzok203 = _sweep_case183(_pz_sid203, cfg=_pz203(), read=_pzr203, players=0)
_pzc203 = _pzok203["cmds"]
check("world reset sweep (pz): ProjectZomboid64.json read, players counted (0), state, stop, backup, the "
      "delete of Saves/Multiplayer/pzserver, start; done",
      _pzr203.asked == ["serverfiles/ProjectZomboid64.json"] and _pzok203["players_asked"] == 1
      and len(_pzc203) == 5 and _pzc203[:3] == ["status", "stop", "backup"] and _is_delete183(_pzc203[3])
      and "set -- pzserver" in _pzc203[3] and "/home/pzserver/Zomboid/Saves/Multiplayer" in _pzc203[3]
      and _pzc203[4] == "start" and _last183(_pzok203).get("ok") is True, repr(_pzok203))
_pzmove203 = _sweep_case183(_pz_sid203, cfg=_pz203(), read=_pzread203(
    (_PZJSON203.replace("-Xmx2g", "-Ddeployment.user.cachedir=/srv/z"), None)))
_pzunread203 = _sweep_case183(_pz_sid203, cfg=_pz203(), read=_pzread203((None, "Could not read that file — the host did not answer.")))
_pzgone203 = _sweep_case183(_pz_sid203, cfg=_pz203(), read=_pzread203((None, "File not found")))
check("world reset sweep (pz): a ProjectZomboid64.json that moves the game's folder, or is not there, ends the "
      "reset untouched; one that could not be read waits",
      _pzmove203["cmds"] == [] and _last183(_pzmove203).get("ok") is False
      and "ProjectZomboid64.json sets cachedir" in (_last183(_pzmove203).get("detail") or "")
      and _pzgone203["cmds"] == [] and _last183(_pzgone203).get("ok") is False
      and _pzunread203["cmds"] == [] and _pzunread203["entry"].get("pending_since")
      and "could not be read" in (_pzunread203["entry"].get("wait") or ""), repr((_pzmove203, _pzunread203)))

# The guard's real sentences, from a remote no other check uses (its verdict cache is per remote).
_REMOTE203 = _NS203(id=-203, host="p203-guard.invalid", username="p203")
try:
    _p9_patch(_sh203, "privileged_accounts", lambda remote, users: None)
    _UNASKED203 = _sh203.game_account_write_refusal(_REMOTE203, "p203a")
    _p9_patch(_sh203, "privileged_accounts", lambda remote, users: {u: "it is in the sudo group" for u in users})
    _ROOTY203 = _sh203.game_account_write_refusal(_REMOTE203, "p203b")
finally:
    _p9_restore_all()
_pzr2_203 = _pzread203()
_rooty203 = _sweep_case183(_pz_sid203, cfg=_pz203(), read=_pzr2_203, guard=_ROOTY203)
_unasked203 = _sweep_case183(_pz_sid203, cfg=_pz203(), guard=_UNASKED203)
check("world reset sweep: a game account that can become root ends the reset before anything is read, "
      "stopped or deleted (alerted); one the host could not be asked about waits",
      isinstance(_ROOTY203, _i18n203.Sentence) and _rooty203["cmds"] == [] and _pzr2_203.asked == []
      and _last183(_rooty203).get("ok") is False and _rooty203["alerts"] == ["Scheduled wipe did not run"]
      and _unasked203["cmds"] == [] and _unasked203["entry"].get("pending_since")
      and "could not be checked" in (_unasked203["entry"].get("wait") or ""), repr((_rooty203, _unasked203)))
eq("world reset: Project Zomboid's players are counted by gamedig's projectzomboid type (its game port answers "
   "it), so every player check counts them",
   (_core203.GAMEDIG_TYPE.get("pz"), _cron203._gamedig_type("pz")), ("projectzomboid", "projectzomboid"))

# ── 5. the card ──────────────────────────────────────────────────────────────────────────────────
_BODY203 = {"enabled": True, "kind": "reset", "preset": "custom", "cron": "0 5 * * *", "tz": "UTC"}
_r203 = {}
try:
    _p9_arm(who="part203")
    _A203 = _p9_client(P9_ADMIN)
    for _g203, _s203 in (("vh", _vh_sid203), ("pz", _pz_sid203)):
        _r203["save_" + _g203] = _A203.post("/api/server/%d/wipe-schedule" % _s203, json=_BODY203).status_code
        _r203["kind_" + _g203] = (_ws203.get(_s203) or {}).get("kind")
        _r203["map_" + _g203] = _A203.post("/api/server/%d/wipe-schedule" % _s203,
                                           json=dict(_BODY203, kind="map")).status_code
    _p9_patch(_sd203, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd203, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch(_sf203, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch_sm("run_command", lambda *a, **k: ("", "", 1))
    _r203["pages"] = {g: _A203.get("/server/%d/files" % s).get_data(as_text=True)
                      for g, s in (("vh", _vh_sid203), ("pz", _pz_sid203))}
finally:
    _p9_restore_all()
    _ws203.put(_vh_sid203, None)
    _ws203.put(_pz_sid203, None)
check("world reset route: Valheim and Project Zomboid get a reset card; `reset` is saved, map/full refused",
      all(_r203["save_" + g] == 200 and _r203["kind_" + g] == "reset" and _r203["map_" + g] == 400
          for g in ("vh", "pz")), repr(_r203))
_pg203 = _r203.get("pages", {})
check("world reset page: Valheim's card names worlds_local and the kept lists and says -crossplay cannot be "
      "counted, its player box unticked; Zomboid's names the save folder, the kept accounts and Seed, ticked",
      'id="wipe-kind" value="reset"' in _pg203.get("vh", "") and 'id="wipe-wait">' in _pg203.get("vh", "")
      and "folder in worlds_local (the one -world names, under -savedir)" in _pg203.get("vh", "")
      and "started with -crossplay" in _pg203.get("vh", "")
      and 'id="wipe-wait" checked' in _pg203.get("pz", "")
      and "Zomboid/Saves/Multiplayer that -servername names" in _pg203.get("pz", "")
      and "change Seed there for a different one" in _pg203.get("pz", ""), "")

for _sid203 in (_vh_sid203, _pz_sid203):
    _p9_delete_server(_sid203)
eq("world reset (vh, pz): nothing this part drove reached a real transport (part12's tripwire, armed)",
   _P9_TRIPPED[_trips203:], [])
